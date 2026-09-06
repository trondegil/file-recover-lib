//! Filesystem-aware recovery for HFS+ / HFSX volumes (Mac-formatted media).
//!
//! HFS+ keeps every file and folder in the **catalog file**, a B-tree whose leaf
//! nodes hold one record per object (its name, CNID, and the data fork's first
//! eight extents inline). When a file is deleted, its catalog record is removed
//! from the leaf node and the records after it are shifted down — but the bytes
//! of the removed record usually remain in the node's *free space* until the
//! node is next rewritten, and the data fork's allocation blocks stay put until
//! reused. This is the HFS+ analogue of ext directory-slack recovery.
//!
//! This backend reads the catalog file, walks every leaf node, and scans the
//! free space below the live records for stale **file records** that pass a
//! strict structural check. For each one it reconstructs the file with its
//! original name and **folder path** (rebuilt from the live folder hierarchy via
//! each record's parent CNID), following the eight extents stored inline in the
//! catalog record and, for a file fragmented beyond them, the remaining extents
//! from the **extents-overflow B-tree** (keyed by the file's CNID).
//!
//! ## The journal
//!
//! That free-space scavenging is what a bare HFS+ volume offers. A **journaled**
//! volume (every Mac since 10.3 formats one) is different in practice: the
//! real-image corpus showed that macOS rewrites a leaf node cleanly when a
//! record is removed, so nothing is left in the node's free space. What does
//! survive is the **journal**: a circular buffer of whole-block copies of every
//! metadata block written recently, including catalog leaf nodes as they were
//! *before* the deletion. This backend therefore also scans the journal for
//! stale catalog leaf nodes and treats any file record in them whose CNID is
//! no longer live as a deleted file, keeping the newest copy of each. It is
//! the HFS+ analogue of the ext4 jbd2 fallback.
//!
//! ## What this cannot do
//!
//! A file whose tail extents are not recorded in the extents-overflow tree —
//! because that tree was itself rewritten after deletion — cannot be fully
//! reconstructed and is reported as skipped rather than written truncated.
//! Files whose catalog record has already been overwritten in the node's free
//! space are gone — fall back to `scan` (carving).

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::hash;
use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// The HFS+ volume header sits 1024 bytes into the volume.
const VOLUME_HEADER_OFFSET: u64 = 1024;
const SIG_HFSPLUS: u16 = 0x482B; // "H+"
const SIG_HFSX: u16 = 0x4858; // "HX"
/// B-tree leaf node kind (`kBTLeafNode`), stored as an `i8`.
const KIND_LEAF: i8 = -1;
/// `kHFSPlusFolderRecord`.
const RECORD_FOLDER: u16 = 0x0001;
/// `kHFSPlusFileRecord`.
const RECORD_FILE: u16 = 0x0002;
/// Root folder CNID; the smallest valid parent for a user object's parent is 2.
const ROOT_FOLDER_ID: u32 = 2;
/// Largest catalog key (`kHFSPlusCatalogKeyMaximumLength`).
const MAX_CATALOG_KEY: u16 = 516;
/// Seconds between the HFS+ epoch (1904-01-01) and the Unix epoch.
const HFS_TO_UNIX_EPOCH: u32 = 2_082_844_800;
/// Cap on the catalog bytes read into memory, to bound work/allocations.
const MAX_CATALOG: usize = 64 * 1024 * 1024;
/// Cap on the allocation bitmap bytes read into memory, to bound allocations.
const MAX_BITMAP: usize = 256 * 1024 * 1024;
/// `kHFSVolumeJournaledBit` in the volume header attributes.
const ATTR_JOURNALED: u32 = 1 << 13;
/// `kJIJournalInFSMask`: the journal lives inside this volume.
const JI_JOURNAL_IN_FS: u32 = 1;
/// Cap on the journal bytes scanned, to bound work on a huge volume (the
/// journal is at most 512 MiB on real volumes; a stale node is never bigger
/// than a few KiB, so scanning is cheap per byte).
const MAX_JOURNAL: u64 = 512 * 1024 * 1024;
/// Journal scan chunk size; stale nodes can start on any 512-byte boundary.
const JOURNAL_CHUNK: usize = 4 * 1024 * 1024;

/// A parsed HFS+/HFSX volume.
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    block_size: u64,
    total_blocks: u64,
    /// Allocation-block extents of the catalog file (start, count), inline only.
    catalog_extents: Vec<(u32, u32)>,
    catalog_size: u64,
    /// Allocation-block extents of the allocation file (the volume bitmap),
    /// inline only. Empty when the fork could not be parsed plausibly.
    allocation_extents: Vec<(u32, u32)>,
    /// Allocation-block extents of the extents-overflow B-tree file, inline
    /// only. Empty when the fork is absent or implausible.
    extents_overflow_extents: Vec<(u32, u32)>,
    extents_overflow_size: u64,
    hfsx: bool,
    /// Byte range (offset within the volume, length) of the journal buffer on a
    /// journaled volume whose journal is in the volume itself.
    journal: Option<(u64, u64)>,
    /// Volume creation time (`createDate`), Unix seconds; `None` when unset.
    created: Option<u64>,
    /// Volume last-modification time (`modifyDate`), Unix seconds; `None` when
    /// unset.
    written: Option<u64>,
}

/// Seconds between the HFS epoch (1904-01-01) and the Unix epoch (1970-01-01).
const HFS_EPOCH_OFFSET: u32 = 2_082_844_800;

/// Convert an HFS+ date (seconds since 1904-01-01) to Unix seconds, or `None`
/// when the field is unset or predates the Unix epoch.
fn hfs_time(secs: u32) -> Option<u64> {
    if secs == 0 || secs < HFS_EPOCH_OFFSET {
        None
    } else {
        Some((secs - HFS_EPOCH_OFFSET) as u64)
    }
}

/// Additional data-fork extents keyed by file CNID, recovered from the
/// extents-overflow B-tree and already concatenated in fork order. These are
/// the 9th-and-later extents of a file fragmented beyond the eight stored
/// inline in its catalog record.
type OverflowExtents = HashMap<u32, Vec<(u32, u32)>>;

/// One parsed extents-overflow leaf record: `(forkType, fileID, startBlock,
/// extents)`.
type ExtentRecord = (u8, u32, u32, Vec<(u32, u32)>);

/// Pending overflow runs for one file before ordering: `(startBlock key,
/// extents)` pairs, sorted by key and flattened into [`OverflowExtents`].
type PendingRuns = Vec<(u32, Vec<(u32, u32)>)>;

/// Old HFS master-directory-block signature (`"BD"`). When such a volume embeds
/// an HFS+ volume (the "HFS wrapper" used on old Mac media and hybrid CDs), it is
/// transparently followed to the embedded volume.
const SIG_HFS: u16 = 0x4244;

/// Resolve the actual HFS+ volume-header offset for `vol_offset`: `vol_offset`
/// itself when an HFS+/HFSX signature sits there, or the **embedded** volume's
/// offset when `vol_offset` holds an old HFS `BD` wrapper around an HFS+ volume.
/// `None` when neither.
fn hfsplus_offset(src: &Source, vol_offset: u64) -> Option<u64> {
    let mut mdb = [0u8; 512];
    if src
        .read_at(vol_offset + VOLUME_HEADER_OFFSET, &mut mdb)
        .unwrap_or(0)
        < 512
    {
        return None;
    }
    match u16::from_be_bytes([mdb[0], mdb[1]]) {
        SIG_HFSPLUS | SIG_HFSX => Some(vol_offset),
        SIG_HFS => {
            // Old HFS master directory block. `drEmbedSigWord` (0x7C) is "H+"
            // when it wraps an HFS+ volume; `drAlBlkSiz` (0x14) and `drAlBlSt`
            // (0x1C) plus the embedded extent's start block (0x7E) locate it.
            if u16::from_be_bytes([mdb[0x7C], mdb[0x7D]]) != SIG_HFSPLUS {
                return None;
            }
            let al_blk_siz =
                u32::from_be_bytes([mdb[0x14], mdb[0x15], mdb[0x16], mdb[0x17]]) as u64;
            let al_bl_st = u16::from_be_bytes([mdb[0x1C], mdb[0x1D]]) as u64;
            let embed_start = u16::from_be_bytes([mdb[0x7E], mdb[0x7F]]) as u64;
            let embedded = vol_offset
                .checked_add(al_bl_st.checked_mul(512)?)?
                .checked_add(embed_start.checked_mul(al_blk_siz)?)?;
            let mut sig = [0u8; 2];
            if src
                .read_at(embedded + VOLUME_HEADER_OFFSET, &mut sig)
                .unwrap_or(0)
                < 2
            {
                return None;
            }
            matches!(u16::from_be_bytes(sig), SIG_HFSPLUS | SIG_HFSX).then_some(embedded)
        }
        _ => None,
    }
}

/// Does `vol_offset` carry an HFS+/HFSX volume — directly, or embedded in an old
/// HFS wrapper?
pub fn is_hfsplus(src: &Source, vol_offset: u64) -> bool {
    hfsplus_offset(src, vol_offset).is_some()
}

impl Volume {
    /// Parse the volume header at `offset` (following an HFS wrapper to the
    /// embedded HFS+ volume when present).
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let offset = hfsplus_offset(src, offset).unwrap_or(offset);
        let mut vh = [0u8; 512];
        if src.read_at(offset + VOLUME_HEADER_OFFSET, &mut vh)? < 512 {
            bail!("HFS+ volume header truncated");
        }
        let sig = be16(&vh, 0);
        let hfsx = match sig {
            SIG_HFSPLUS => false,
            SIG_HFSX => true,
            _ => bail!("not an HFS+ volume"),
        };

        let block_size = be32(&vh, 40) as u64;
        if !block_size.is_power_of_two() || !(512..=65536).contains(&block_size) {
            bail!("implausible HFS+ allocation block size {block_size}");
        }
        let total_blocks = be32(&vh, 44) as u64;
        if total_blocks == 0 {
            bail!("HFS+ volume reports zero blocks");
        }

        // Catalog file fork data starts 272 bytes into the volume header:
        // logicalSize @272, totalBlocks @284, extents @288 (8 x start,count).
        let catalog_size = be64(&vh, 272);
        let mut catalog_extents = Vec::new();
        for i in 0..8 {
            let o = 288 + i * 8;
            let start = be32(&vh, o);
            let count = be32(&vh, o + 4);
            if count == 0 {
                break;
            }
            // Reject extents that fall outside the volume.
            if start as u64 >= total_blocks
                || start as u64 + count as u64 > total_blocks.saturating_add(1)
            {
                bail!("HFS+ catalog extent out of range");
            }
            catalog_extents.push((start, count));
        }
        if catalog_extents.is_empty() {
            bail!("HFS+ catalog file has no extents");
        }

        // Allocation file fork (the volume bitmap) at offset 112: extents @128
        // (8 x start,count). Parsed non-fatally — a volume that recovers files
        // but whose bitmap is implausible should still work, just without
        // free-space carving. Any out-of-range extent clears the whole set.
        let mut allocation_extents = Vec::new();
        for i in 0..8 {
            let o = 128 + i * 8;
            let start = be32(&vh, o);
            let count = be32(&vh, o + 4);
            if count == 0 {
                break;
            }
            if start as u64 >= total_blocks
                || start as u64 + count as u64 > total_blocks.saturating_add(1)
            {
                allocation_extents.clear();
                break;
            }
            allocation_extents.push((start, count));
        }

        // Extents-overflow file fork at offset 192: logicalSize @192, extents
        // @208 (8 x start,count). It records the 9th-and-later extents of
        // fragmented forks. Parsed non-fatally — without it, only the eight
        // inline catalog extents are followed.
        let extents_overflow_size = be64(&vh, 192);
        let mut extents_overflow_extents = Vec::new();
        for i in 0..8 {
            let o = 208 + i * 8;
            let start = be32(&vh, o);
            let count = be32(&vh, o + 4);
            if count == 0 {
                break;
            }
            if start as u64 >= total_blocks
                || start as u64 + count as u64 > total_blocks.saturating_add(1)
            {
                extents_overflow_extents.clear();
                break;
            }
            extents_overflow_extents.push((start, count));
        }

        // createDate @ 0x10 and modifyDate @ 0x14, both big-endian seconds since
        // the HFS epoch (1904). modifyDate is GMT; createDate is, per the HFS+
        // spec, stored in local time, so it can be off by the volume's timezone.
        let created = hfs_time(be32(&vh, 0x10));
        let written = hfs_time(be32(&vh, 0x14));

        // A journaled volume points (attributes bit 13, journalInfoBlock @12)
        // at a JournalInfoBlock: flags @0, then device signature (32 bytes),
        // then the journal's byte offset @36 and size @44, all big-endian.
        // Parsed non-fatally: without it, only the catalog is scanned.
        let vol_bytes = block_size * total_blocks;
        let mut journal = None;
        let jib = be32(&vh, 12) as u64;
        if be32(&vh, 4) & ATTR_JOURNALED != 0 && jib > 0 && jib < total_blocks {
            let mut info = [0u8; 52];
            if src.read_at(offset + jib * block_size, &mut info)? == 52
                && be32(&info, 0) & JI_JOURNAL_IN_FS != 0
            {
                let joff = be64(&info, 36);
                let jsize = be64(&info, 44);
                if jsize > 0 && joff < vol_bytes && jsize <= vol_bytes - joff {
                    journal = Some((joff, jsize.min(MAX_JOURNAL)));
                }
            }
        }

        Ok(Volume {
            offset,
            block_size,
            total_blocks,
            catalog_extents,
            catalog_size,
            allocation_extents,
            extents_overflow_extents,
            extents_overflow_size,
            hfsx,
            journal,
            created,
            written,
        })
    }

    /// Volume creation time (`createDate`) as Unix seconds, or `None` when unset.
    pub fn created_time(&self) -> Option<u64> {
        self.created
    }

    /// Volume last-modification time (`modifyDate`) as Unix seconds, or `None`.
    pub fn written_time(&self) -> Option<u64> {
        self.written
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.total_blocks.saturating_mul(self.block_size)
    }

    /// The allocation block size in bytes.
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    /// Absolute byte ranges of the volume's free (unallocated) space, derived
    /// from the allocation file (the volume bitmap). Each bit maps one
    /// allocation block, **most-significant bit first** (bit 7 of byte 0 is
    /// block 0). Returns an empty vec when the bitmap could not be read; bits
    /// past the end of the bitmap (or blocks with no bit) are treated as
    /// allocated, never free.
    pub fn free_extents(&self, src: &Source) -> Result<Vec<(u64, u64)>> {
        if self.allocation_extents.is_empty() {
            return Ok(Vec::new());
        }
        let bitmap = self.read_allocation_bitmap(src)?;

        let mut free: Vec<(u64, u64)> = Vec::new();
        for b in 0..self.total_blocks {
            let byte = (b / 8) as usize;
            let bit = (b % 8) as u32;
            let allocated = bitmap
                .get(byte)
                .map(|&v| v & (0x80 >> bit) != 0)
                .unwrap_or(true);
            if allocated {
                continue;
            }
            let start = self.offset + b * self.block_size;
            match free.last_mut() {
                Some(last) if last.0 + last.1 == start => last.1 += self.block_size,
                _ => free.push((start, self.block_size)),
            }
        }
        Ok(free)
    }

    /// Read the allocation file (volume bitmap) into memory via its inline
    /// extents, bounded by [`MAX_BITMAP`].
    fn read_allocation_bitmap(&self, src: &Source) -> Result<Vec<u8>> {
        let extents_bytes: u64 = self
            .allocation_extents
            .iter()
            .map(|&(_, c)| c as u64 * self.block_size)
            .sum();
        let want = extents_bytes.min(MAX_BITMAP as u64) as usize;

        let mut buf = Vec::with_capacity(want.min(1 << 20));
        let mut block = vec![0u8; self.block_size as usize];
        'outer: for &(start, count) in &self.allocation_extents {
            for b in 0..count as u64 {
                if buf.len() >= want {
                    break 'outer;
                }
                let off = self.offset + (start as u64 + b) * self.block_size;
                let n = src.read_at(off, &mut block)?;
                if n == 0 {
                    break 'outer;
                }
                buf.extend_from_slice(&block[..n]);
            }
        }
        buf.truncate(want);
        Ok(buf)
    }

    /// `"HFS+"` or `"HFSX"`.
    pub fn fs_label(&self) -> &'static str {
        if self.hfsx {
            "HFSX"
        } else {
            "HFS+"
        }
    }

    /// Recover all deleted files into `out_dir`.
    pub fn recover_deleted(
        &self,
        src: &Source,
        out_dir: &Path,
        opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        let catalog = self.read_catalog(src)?;
        let node_size = node_size(&catalog)?;
        let total_nodes = catalog.len() / node_size;

        // Pass 1: collect the CNIDs of files that are still live (so a stale copy
        // of a record for a file that still exists is not mistaken for deleted),
        // and index every live folder by CNID to rebuild original paths.
        let mut live: HashSet<u32> = HashSet::new();
        let mut folders: HashMap<u32, (String, u32)> = HashMap::new();
        for idx in 0..total_nodes {
            let node = &catalog[idx * node_size..(idx + 1) * node_size];
            if node_kind(node) != KIND_LEAF {
                continue;
            }
            for off in live_record_offsets(node, node_size) {
                if let Some(rec) = parse_file_record(node, off, self) {
                    live.insert(rec.file_id);
                } else if let Some((cnid, name, parent)) = parse_folder_record(node, off, self) {
                    folders.insert(cnid, (name, parent));
                }
            }
        }

        // Additional extents for fragmented files live in the extents-overflow
        // B-tree; read it once so each recovered file can follow its tail.
        let overflow = self.read_extents_overflow(src);

        // Pass 2: scan each leaf node's free space for stale file records.
        let mut candidates: Vec<FileRecord> = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();
        for idx in 0..total_nodes {
            let node = &catalog[idx * node_size..(idx + 1) * node_size];
            if node_kind(node) != KIND_LEAF {
                continue;
            }
            let (free_start, free_end) = free_space(node, node_size);
            let mut off = free_start;
            while off + 2 <= free_end {
                let rec = match parse_file_record(node, off, self) {
                    Some(r) => r,
                    None => {
                        off += 2; // catalog structures are 2-byte aligned
                        continue;
                    }
                };
                off += 2;
                if live.contains(&rec.file_id) || !seen.insert(rec.file_id) {
                    continue;
                }
                candidates.push(rec);
            }
        }

        // Pass 3: stale leaf nodes in the journal. Each holds the records as
        // they were when that copy was written, so a record for a CNID that is
        // no longer live is a deleted file. Folder records seen only there name
        // folders that were deleted along with their contents.
        if let Some((joff, jlen)) = self.journal {
            let mut newest: HashMap<u32, FileRecord> = HashMap::new();
            self.scan_journal(src, joff, jlen, node_size, |node| {
                for off in live_record_offsets(node, node_size) {
                    if let Some(rec) = parse_file_record(node, off, self) {
                        if live.contains(&rec.file_id) || seen.contains(&rec.file_id) {
                            continue;
                        }
                        let replace = newest
                            .get(&rec.file_id)
                            .map(|old| rec.mod_date >= old.mod_date)
                            .unwrap_or(true);
                        if replace {
                            newest.insert(rec.file_id, rec);
                        }
                    } else if let Some((cnid, name, parent)) = parse_folder_record(node, off, self)
                    {
                        folders.entry(cnid).or_insert((name, parent));
                    }
                }
            })?;
            let mut from_journal: Vec<FileRecord> = newest.into_values().collect();
            from_journal.sort_by_key(|r| r.file_id);
            candidates.extend(from_journal);
        }

        let vol_bytes = self.size();
        let mut stats = RecoverStats::default();
        for rec in candidates {
            let rel = resolve_path(&folders, rec.parent_id).join(sanitize_component(&rec.name));
            let size = rec.logical_size;
            if !opts.size_ok(size) {
                continue;
            }
            if !opts.time_ok(crate::times::from_unix(hfs_to_unix(rec.mod_date))) {
                continue;
            }
            if !opts.name_ok(&rec.name) {
                continue;
            }
            if size == 0 || size > vol_bytes {
                stats.record_skipped(rel, size);
                continue;
            }
            if opts.dry_run {
                stats.record_recovered(rel, size, None);
                continue;
            }
            match self.write_file(src, out_dir, &rel, &rec, &overflow) {
                Some((written, digest)) if written == size => {
                    stats.record_recovered(rel, size, Some(digest))
                }
                _ => stats.record_skipped(rel, size),
            }
        }
        Ok(stats)
    }

    /// Walk the journal buffer in chunks and call `f` with every byte range
    /// that looks like a complete catalog leaf node. The journal is a ring of
    /// block copies whose transaction headers are in the writing machine's
    /// byte order, so rather than replaying it the scan simply looks for node
    /// descriptors at 512-byte boundaries and checks their record-offset
    /// array: a real node's offsets start at 14 and rise strictly, and random
    /// bytes almost never do.
    fn scan_journal(
        &self,
        src: &Source,
        joff: u64,
        jlen: u64,
        node_size: usize,
        mut f: impl FnMut(&[u8]),
    ) -> Result<()> {
        let mut buf = vec![0u8; JOURNAL_CHUNK + node_size];
        let mut pos = 0u64;
        while pos < jlen {
            let want = ((jlen - pos) as usize).min(JOURNAL_CHUNK + node_size);
            let n = src.read_at(self.offset + joff + pos, &mut buf[..want])?;
            if n < node_size {
                break;
            }
            // Only starts within the first JOURNAL_CHUNK bytes are this chunk's;
            // the overlap exists so a node straddling the boundary is complete.
            let last_start = n.saturating_sub(node_size).min(JOURNAL_CHUNK - 1);
            let mut off = 0;
            while off <= last_start {
                let node = &buf[off..off + node_size];
                if looks_like_leaf_node(node, node_size) {
                    f(node);
                }
                off += 512;
            }
            if n < want {
                break;
            }
            pos += JOURNAL_CHUNK as u64;
        }
        Ok(())
    }

    /// Read the catalog file into memory by following its inline extents.
    fn read_catalog(&self, src: &Source) -> Result<Vec<u8>> {
        let extents_bytes: u64 = self
            .catalog_extents
            .iter()
            .map(|&(_, c)| c as u64 * self.block_size)
            .sum();
        let want = if self.catalog_size > 0 {
            self.catalog_size.min(extents_bytes)
        } else {
            extents_bytes
        }
        .min(MAX_CATALOG as u64) as usize;

        let mut buf = Vec::with_capacity(want.min(1 << 20));
        let mut block = vec![0u8; self.block_size as usize];
        'outer: for &(start, count) in &self.catalog_extents {
            for b in 0..count as u64 {
                if buf.len() >= want {
                    break 'outer;
                }
                let off = self.offset + (start as u64 + b) * self.block_size;
                let n = src.read_at(off, &mut block)?;
                if n == 0 {
                    break 'outer;
                }
                buf.extend_from_slice(&block[..n]);
            }
        }
        buf.truncate(want);
        if buf.len() < 512 {
            bail!("HFS+ catalog too small to contain a B-tree header");
        }
        Ok(buf)
    }

    /// Reconstruct a file's bytes from its data-fork extents: the eight stored
    /// inline in the catalog record, followed by any from the extents-overflow
    /// B-tree (`overflow`) for a fragmented file. Returns `None` if the combined
    /// extents still do not cover the whole logical size.
    fn read_file_data(
        &self,
        src: &Source,
        rec: &FileRecord,
        overflow: &OverflowExtents,
    ) -> Option<Vec<u8>> {
        let mut extents = rec.extents.clone();
        if let Some(extra) = overflow.get(&rec.file_id) {
            extents.extend_from_slice(extra);
        }
        let mut data: Vec<u8> =
            Vec::with_capacity(rec.logical_size.min(MAX_CATALOG as u64) as usize);
        let mut remaining = rec.logical_size;
        for &(start, count) in &extents {
            if remaining == 0 {
                break;
            }
            let ext_bytes = count as u64 * self.block_size;
            let to_read = ext_bytes.min(remaining);
            let base = self.offset + start as u64 * self.block_size;
            let mut got = 0u64;
            let mut chunk = vec![0u8; self.block_size as usize];
            while got < to_read {
                let want = (to_read - got).min(self.block_size) as usize;
                let n = src.read_at(base + got, &mut chunk[..want]).ok()?;
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&chunk[..n]);
                got += n as u64;
            }
            remaining = remaining.saturating_sub(got);
            if got < to_read {
                break;
            }
        }
        if remaining > 0 {
            return None; // extents (inline + overflow) did not cover the file
        }
        Some(data)
    }

    /// Read the extents-overflow B-tree and index its **data-fork** extent
    /// records by file CNID, each file's extents concatenated in fork order
    /// (ascending start-block key). Returns an empty map when the tree is
    /// absent, unreadable, or holds no usable records — recovery then falls
    /// back to inline extents only.
    fn read_extents_overflow(&self, src: &Source) -> OverflowExtents {
        let mut out = OverflowExtents::new();
        if self.extents_overflow_extents.is_empty() {
            return out;
        }
        let tree = match self.read_fork(
            src,
            &self.extents_overflow_extents,
            self.extents_overflow_size,
        ) {
            Ok(t) if t.len() >= 512 => t,
            _ => return out,
        };
        let node_size = match node_size(&tree) {
            Ok(n) => n,
            Err(_) => return out,
        };
        let total_nodes = tree.len() / node_size;

        // Gather (startBlock key, extents) per file across all leaf records.
        let mut by_file: HashMap<u32, PendingRuns> = HashMap::new();
        for idx in 0..total_nodes {
            let node = &tree[idx * node_size..(idx + 1) * node_size];
            if node_kind(node) != KIND_LEAF {
                continue;
            }
            for off in live_record_offsets(node, node_size) {
                if let Some((fork, file_id, start_block, extents)) =
                    parse_extent_record(node, off, self)
                {
                    if fork != 0 || extents.is_empty() {
                        continue; // data fork only
                    }
                    by_file
                        .entry(file_id)
                        .or_default()
                        .push((start_block, extents));
                }
            }
        }
        for (file_id, mut recs) in by_file {
            recs.sort_by_key(|&(sb, _)| sb);
            let flat: Vec<(u32, u32)> = recs.into_iter().flat_map(|(_, e)| e).collect();
            out.insert(file_id, flat);
        }
        out
    }

    /// Read a fork described by inline `extents` into memory, bounded by
    /// `logical_size` (when non-zero) and [`MAX_CATALOG`].
    fn read_fork(
        &self,
        src: &Source,
        extents: &[(u32, u32)],
        logical_size: u64,
    ) -> Result<Vec<u8>> {
        let extents_bytes: u64 = extents
            .iter()
            .map(|&(_, c)| c as u64 * self.block_size)
            .sum();
        let want = if logical_size > 0 {
            logical_size.min(extents_bytes)
        } else {
            extents_bytes
        }
        .min(MAX_CATALOG as u64) as usize;

        let mut buf = Vec::with_capacity(want.min(1 << 20));
        let mut block = vec![0u8; self.block_size as usize];
        'outer: for &(start, count) in extents {
            for b in 0..count as u64 {
                if buf.len() >= want {
                    break 'outer;
                }
                let off = self.offset + (start as u64 + b) * self.block_size;
                let n = src.read_at(off, &mut block)?;
                if n == 0 {
                    break 'outer;
                }
                buf.extend_from_slice(&block[..n]);
            }
        }
        buf.truncate(want);
        Ok(buf)
    }

    fn write_file(
        &self,
        src: &Source,
        out_dir: &Path,
        rel: &Path,
        rec: &FileRecord,
        overflow: &OverflowExtents,
    ) -> Option<(u64, [u8; 32])> {
        let data = self.read_file_data(src, rec, overflow)?;
        let (_target, mut out) = crate::recover::create_output_file(out_dir, rel).ok()?;
        out.write_all(&data).ok()?;
        out.flush().ok();
        let mtime = crate::times::from_unix(hfs_to_unix(rec.mod_date));
        let atime = crate::times::from_unix(hfs_to_unix(rec.access_date));
        crate::times::apply(&out, mtime, atime);
        Some((data.len() as u64, hash::digest(&data)))
    }
}

/// A file record extracted from the catalog (the fields recovery needs).
struct FileRecord {
    name: String,
    file_id: u32,
    /// CNID of the folder containing this file (the catalog key's parentID),
    /// used to rebuild the original folder path.
    parent_id: u32,
    logical_size: u64,
    mod_date: u32,
    access_date: u32,
    extents: Vec<(u32, u32)>,
}

/// Parse and strictly validate a catalog **file** record beginning at `off`
/// within `node`. The strict checks let the same parser drive the free-space
/// scan: random bytes almost never satisfy all of them.
fn parse_file_record(node: &[u8], off: usize, vol: &Volume) -> Option<FileRecord> {
    let key_len = be16(node, off);
    if !(6..=MAX_CATALOG_KEY).contains(&key_len) {
        return None;
    }
    let parent_id = be32(node, off + 2);
    if parent_id < ROOT_FOLDER_ID {
        return None;
    }
    let name_len = be16(node, off + 6);
    // The catalog key length is exactly parentID(4) + nodeName(2 + 2*name_len).
    if name_len == 0 || name_len > 255 || key_len != 6 + 2 * name_len {
        return None;
    }
    let key_end = off + 2 + key_len as usize;
    // The record data must fit: HFSPlusCatalogFile is 248 bytes, but we only
    // need through the data fork (offset 88 + 80 = 168).
    if key_end + 168 > node.len() {
        return None;
    }
    if be16(node, key_end) != RECORD_FILE {
        return None;
    }

    let file_id = be32(node, key_end + 8);
    if file_id == 0 {
        return None;
    }
    let mod_date = be32(node, key_end + 16); // contentModDate
    let access_date = be32(node, key_end + 24);

    // Data fork at key_end + 88: logicalSize @88, extents @104.
    let logical_size = be64(node, key_end + 88);
    if logical_size == 0 || logical_size > vol.size() {
        return None;
    }
    let mut extents = Vec::new();
    for i in 0..8 {
        let o = key_end + 104 + i * 8;
        let start = be32(node, o);
        let count = be32(node, o + 4);
        if count == 0 {
            break;
        }
        if start as u64 >= vol.total_blocks
            || start as u64 + count as u64 > vol.total_blocks.saturating_add(1)
        {
            return None;
        }
        extents.push((start, count));
    }
    if extents.is_empty() {
        return None;
    }

    let name = decode_name(node, off, name_len);

    Some(FileRecord {
        name,
        file_id,
        parent_id,
        logical_size,
        mod_date,
        access_date,
        extents,
    })
}

/// Decode a catalog key's UTF-16BE node name (`name_len` units at `off + 8`).
fn decode_name(node: &[u8], off: usize, name_len: u16) -> String {
    let mut units = Vec::with_capacity(name_len as usize);
    for i in 0..name_len as usize {
        units.push(be16(node, off + 8 + i * 2));
    }
    char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

/// Parse a catalog **folder** record at `off`: returns `(folderID, name,
/// parentID)`. Used to rebuild the live folder hierarchy so deleted files can
/// be restored under their original paths.
fn parse_folder_record(node: &[u8], off: usize, _vol: &Volume) -> Option<(u32, String, u32)> {
    let key_len = be16(node, off);
    if !(6..=MAX_CATALOG_KEY).contains(&key_len) {
        return None;
    }
    let parent_id = be32(node, off + 2);
    if parent_id == 0 {
        return None;
    }
    let name_len = be16(node, off + 6);
    if name_len == 0 || name_len > 255 || key_len != 6 + 2 * name_len {
        return None;
    }
    let key_end = off + 2 + key_len as usize;
    // HFSPlusCatalogFolder: recordType @0, folderID @8.
    if key_end + 16 > node.len() || be16(node, key_end) != RECORD_FOLDER {
        return None;
    }
    let folder_id = be32(node, key_end + 8);
    if folder_id == 0 {
        return None;
    }
    Some((folder_id, decode_name(node, off, name_len), parent_id))
}

/// Parse an extents-overflow leaf record at `off`: an `HFSPlusExtentKey`
/// (fixed 10-byte key: forkType, pad, fileID, startBlock) followed by an
/// `HFSPlusExtentRecord` (eight start/count pairs). Returns
/// `(forkType, fileID, startBlock, extents)`, rejecting any record with an
/// out-of-range extent.
fn parse_extent_record(node: &[u8], off: usize, vol: &Volume) -> Option<ExtentRecord> {
    let key_len = be16(node, off);
    if key_len != 10 {
        return None; // HFSPlusExtentKey length is fixed
    }
    let fork_type = *node.get(off + 2)?;
    let file_id = be32(node, off + 4);
    if file_id == 0 {
        return None;
    }
    let start_block = be32(node, off + 8);
    let data = off + 2 + key_len as usize; // record data follows the key
    if data + 64 > node.len() {
        return None;
    }
    let mut extents = Vec::new();
    for i in 0..8 {
        let o = data + i * 8;
        let start = be32(node, o);
        let count = be32(node, o + 4);
        if count == 0 {
            break;
        }
        if start as u64 >= vol.total_blocks
            || start as u64 + count as u64 > vol.total_blocks.saturating_add(1)
        {
            return None;
        }
        extents.push((start, count));
    }
    Some((fork_type, file_id, start_block, extents))
}

/// B-tree node descriptor: record kind is an `i8` at offset 8.
fn node_kind(node: &[u8]) -> i8 {
    node.get(8).map(|&b| b as i8).unwrap_or(0)
}

/// Read the node size from the B-tree header record in node 0
/// (BTHeaderRec.nodeSize is a `u16` at offset 14 + 18 = 32).
fn node_size(catalog: &[u8]) -> Result<usize> {
    let ns = be16(catalog, 32) as usize;
    if !ns.is_power_of_two() || !(512..=32768).contains(&ns) || catalog.len() < ns {
        bail!("implausible HFS+ catalog node size {ns}");
    }
    Ok(ns)
}

/// Offsets of the live records in a leaf node (`numRecords` entries from the
/// offset array at the end of the node).
fn live_record_offsets(node: &[u8], node_size: usize) -> Vec<usize> {
    let num = be16(node, 10) as usize;
    let mut offsets = Vec::with_capacity(num);
    for i in 0..num {
        let p = node_size - 2 * (i + 1);
        let off = be16(node, p) as usize;
        if (14..node_size).contains(&off) {
            offsets.push(off);
        }
    }
    offsets
}

/// Whether `node` is plausibly a complete catalog leaf node: leaf kind, height
/// 1, a reserved word of zero, and a record-offset array whose entries start at
/// 14 (right after the descriptor), rise strictly, and stay clear of the array
/// itself. Used to pick stale nodes out of the journal without replaying it.
fn looks_like_leaf_node(node: &[u8], node_size: usize) -> bool {
    if node.len() < node_size || node_kind(node) != KIND_LEAF || node[9] != 1 {
        return false;
    }
    let num = be16(node, 10) as usize;
    // Every record is at least a key length + minimal key + record type.
    if num == 0 || num > node_size / 24 || be16(node, 12) != 0 {
        return false;
    }
    let array_start = node_size - 2 * (num + 1);
    let mut prev = 0usize;
    for i in 0..=num {
        let off = be16(node, node_size - 2 * (i + 1)) as usize;
        let expect_first = i == 0 && off != 14;
        if expect_first || off <= prev || off > array_start {
            return false;
        }
        prev = off;
    }
    true
}

/// The free-space byte range of a leaf node: from the end of the last live
/// record up to the start of the record-offset array.
fn free_space(node: &[u8], node_size: usize) -> (usize, usize) {
    let num = be16(node, 10) as usize;
    // offset[numRecords] points at the start of free space.
    let free_start = be16(node, node_size - 2 * (num + 1)) as usize;
    let offset_array = node_size - 2 * (num + 1);
    let start = free_start.clamp(14, node_size);
    (start, offset_array.min(node_size))
}

fn hfs_to_unix(date: u32) -> u32 {
    date.saturating_sub(HFS_TO_UNIX_EPOCH)
}

fn be16(b: &[u8], o: usize) -> u16 {
    match b.get(o..o + 2) {
        Some(s) => u16::from_be_bytes([s[0], s[1]]),
        None => 0,
    }
}
fn be32(b: &[u8], o: usize) -> u32 {
    match b.get(o..o + 4) {
        Some(s) => u32::from_be_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}
fn be64(b: &[u8], o: usize) -> u64 {
    match b.get(o..o + 8) {
        Some(s) => u64::from_be_bytes(s.try_into().unwrap()),
        None => 0,
    }
}

/// Rebuild the folder path of a deleted file from its parent CNID, walking the
/// live-folder map (CNID -> (name, parentID)) up to the root folder. Stops at an
/// unknown parent (a deleted ancestor folder) so the file lands under whatever
/// of its path survives, and is cycle-bounded against a corrupt hierarchy.
fn resolve_path(folders: &HashMap<u32, (String, u32)>, parent_id: u32) -> PathBuf {
    let mut components = Vec::new();
    let mut cur = parent_id;
    let mut guard = 0;
    while cur != ROOT_FOLDER_ID && guard < 256 {
        match folders.get(&cur) {
            Some((name, parent)) => {
                components.push(sanitize_component(name));
                cur = *parent;
            }
            None => break,
        }
        guard += 1;
    }
    components.iter().rev().collect()
}

fn sanitize_component(name: &str) -> String {
    // HFS+ stores a `/` in a name as `:` (the classic Mac OS separator), so a
    // colon here is a slash and is neutralised the same way.
    crate::recover::sanitize_component(&name.replace(':', "_"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("hfs.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn follows_an_hfs_wrapper_to_the_embedded_hfsplus() {
        let mut v = vec![0u8; 8192];
        // Old HFS master directory block at offset 1024: "BD", drAlBlkSiz=512
        // (0x14), drAlBlSt=4 sectors (0x1C), embed "H+" (0x7C), start block 2.
        let mdb = 1024;
        v[mdb..mdb + 2].copy_from_slice(&SIG_HFS.to_be_bytes());
        v[mdb + 0x14..mdb + 0x18].copy_from_slice(&512u32.to_be_bytes());
        v[mdb + 0x1C..mdb + 0x1E].copy_from_slice(&4u16.to_be_bytes());
        v[mdb + 0x7C..mdb + 0x7E].copy_from_slice(&SIG_HFSPLUS.to_be_bytes());
        v[mdb + 0x7E..mdb + 0x80].copy_from_slice(&2u16.to_be_bytes());
        // Embedded offset = 4*512 + 2*512 = 3072; its header sits at +1024.
        let embedded = 4 * 512 + 2 * 512;
        v[embedded + 1024..embedded + 1026].copy_from_slice(&SIG_HFSPLUS.to_be_bytes());

        let (_t, src) = source_of(&v);
        assert!(is_hfsplus(&src, 0));
        assert_eq!(hfsplus_offset(&src, 0), Some(embedded as u64));
    }

    #[test]
    fn direct_and_non_hfsplus_offsets() {
        // Direct HFS+ at the volume start.
        let mut v = vec![0u8; 2048];
        v[1024..1026].copy_from_slice(&SIG_HFSPLUS.to_be_bytes());
        let (_t, src) = source_of(&v);
        assert_eq!(hfsplus_offset(&src, 0), Some(0));
        // Neither HFS+ nor a wrapper.
        let (_t, src) = source_of(&vec![0u8; 2048]);
        assert!(!is_hfsplus(&src, 0));
    }

    fn test_vol() -> Volume {
        Volume {
            offset: 0,
            block_size: 512,
            total_blocks: 64,
            catalog_extents: vec![(8, 2)],
            catalog_size: 1024,
            allocation_extents: vec![],
            extents_overflow_extents: vec![],
            extents_overflow_size: 0,
            hfsx: false,
            journal: None,
            created: None,
            written: None,
        }
    }

    /// Build a minimal valid catalog file record (key + HFSPlusCatalogFile) at
    /// the start of a buffer.
    fn build_record(name: &str, size: u64, start: u32, count: u32) -> Vec<u8> {
        let name16: Vec<u16> = name.encode_utf16().collect();
        let key_len = 6 + 2 * name16.len();
        let mut buf = vec![0u8; key_len + 2 + 248 + 16];
        buf[0..2].copy_from_slice(&(key_len as u16).to_be_bytes());
        buf[2..6].copy_from_slice(&2u32.to_be_bytes()); // parentID
        buf[6..8].copy_from_slice(&(name16.len() as u16).to_be_bytes());
        for (i, &u) in name16.iter().enumerate() {
            buf[8 + i * 2..10 + i * 2].copy_from_slice(&u.to_be_bytes());
        }
        let rec = 2 + key_len;
        buf[rec..rec + 2].copy_from_slice(&RECORD_FILE.to_be_bytes());
        buf[rec + 8..rec + 12].copy_from_slice(&16u32.to_be_bytes()); // fileID
        buf[rec + 88..rec + 96].copy_from_slice(&size.to_be_bytes());
        buf[rec + 104..rec + 108].copy_from_slice(&start.to_be_bytes());
        buf[rec + 108..rec + 112].copy_from_slice(&count.to_be_bytes());
        buf
    }

    #[test]
    fn parses_a_valid_file_record() {
        let buf = build_record("hello.txt", 1234, 12, 3);
        let rec = parse_file_record(&buf, 0, &test_vol()).expect("should parse");
        assert_eq!(rec.name, "hello.txt");
        assert_eq!(rec.file_id, 16);
        assert_eq!(rec.logical_size, 1234);
        assert_eq!(rec.extents, vec![(12, 3)]);
    }

    #[test]
    fn rejects_zeroed_and_patterned_bytes() {
        let vol = test_vol();
        assert!(parse_file_record(&[0u8; 512], 14, &vol).is_none());
        let patterned: Vec<u8> = (0..512u32).map(|i| (i.wrapping_mul(7)) as u8).collect();
        // No offset in a deterministic non-record buffer should validate.
        assert!((0..400).all(|off| parse_file_record(&patterned, off, &vol).is_none()));
    }

    #[test]
    fn rejects_a_record_with_an_out_of_range_extent() {
        // start block beyond total_blocks (64) must be rejected.
        let buf = build_record("x", 100, 9999, 1);
        assert!(parse_file_record(&buf, 0, &test_vol()).is_none());
    }

    #[test]
    fn rejects_a_record_larger_than_the_volume() {
        let buf = build_record("x", 1 << 40, 12, 1);
        assert!(parse_file_record(&buf, 0, &test_vol()).is_none());
    }

    #[test]
    fn node_size_must_be_a_sane_power_of_two() {
        let mut cat = vec![0u8; 4096];
        cat[32..34].copy_from_slice(&777u16.to_be_bytes()); // not a power of two
        assert!(node_size(&cat).is_err());
        cat[32..34].copy_from_slice(&4096u16.to_be_bytes());
        assert_eq!(node_size(&cat).unwrap(), 4096);
    }

    #[test]
    fn parses_an_extents_overflow_record() {
        // key (len 10): forkType=0, pad, fileID=16, startBlock=8; the record
        // data (extent descriptors) follows at off + 2 + 10 = 12.
        let mut buf = vec![0u8; 12 + 64];
        buf[0..2].copy_from_slice(&10u16.to_be_bytes()); // key length
        buf[2] = 0; // data fork
        buf[4..8].copy_from_slice(&16u32.to_be_bytes()); // fileID
        buf[8..12].copy_from_slice(&8u32.to_be_bytes()); // startBlock
        buf[12..16].copy_from_slice(&20u32.to_be_bytes()); // extent 0 start
        buf[16..20].copy_from_slice(&2u32.to_be_bytes()); // extent 0 count
        buf[20..24].copy_from_slice(&30u32.to_be_bytes()); // extent 1 start
        buf[24..28].copy_from_slice(&1u32.to_be_bytes()); // extent 1 count

        let (fork, file_id, start_block, extents) =
            parse_extent_record(&buf, 0, &test_vol()).expect("should parse");
        assert_eq!(fork, 0);
        assert_eq!(file_id, 16);
        assert_eq!(start_block, 8);
        assert_eq!(extents, vec![(20, 2), (30, 1)]);
    }

    #[test]
    fn rejects_an_extents_overflow_record_with_a_bad_key_or_extent() {
        let vol = test_vol();
        // Wrong key length.
        let mut bad_key = vec![0u8; 14 + 64];
        bad_key[0..2].copy_from_slice(&8u16.to_be_bytes());
        assert!(parse_extent_record(&bad_key, 0, &vol).is_none());
        // Extent beyond the volume (total_blocks = 64).
        let mut bad_ext = vec![0u8; 12 + 64];
        bad_ext[0..2].copy_from_slice(&10u16.to_be_bytes());
        bad_ext[4..8].copy_from_slice(&16u32.to_be_bytes());
        bad_ext[12..16].copy_from_slice(&9999u32.to_be_bytes());
        bad_ext[16..20].copy_from_slice(&1u32.to_be_bytes());
        assert!(parse_extent_record(&bad_ext, 0, &vol).is_none());
    }

    #[test]
    fn resolves_nested_and_partial_folder_paths() {
        let mut folders: HashMap<u32, (String, u32)> = HashMap::new();
        folders.insert(20, ("Users".to_string(), ROOT_FOLDER_ID));
        folders.insert(21, ("alice".to_string(), 20));
        folders.insert(22, ("Photos".to_string(), 21));

        // Full chain up to the root folder.
        assert_eq!(
            resolve_path(&folders, 22),
            PathBuf::from("Users").join("alice").join("Photos")
        );
        // A file directly in the root has no path components.
        assert_eq!(resolve_path(&folders, ROOT_FOLDER_ID), PathBuf::new());
        // An unknown parent (deleted ancestor) yields an empty/partial path
        // rather than looping or panicking.
        assert_eq!(resolve_path(&folders, 999), PathBuf::new());
    }

    #[test]
    fn parses_a_folder_record() {
        // key: parentID=2, name="Docs"; record: recordType=folder, folderID=100.
        let name: Vec<u16> = "Docs".encode_utf16().collect();
        let key_len = 6 + 2 * name.len();
        let mut buf = vec![0u8; key_len + 2 + 88];
        buf[0..2].copy_from_slice(&(key_len as u16).to_be_bytes());
        buf[2..6].copy_from_slice(&2u32.to_be_bytes()); // parentID
        buf[6..8].copy_from_slice(&(name.len() as u16).to_be_bytes());
        for (i, &u) in name.iter().enumerate() {
            buf[8 + i * 2..10 + i * 2].copy_from_slice(&u.to_be_bytes());
        }
        let rec = 2 + key_len;
        buf[rec..rec + 2].copy_from_slice(&RECORD_FOLDER.to_be_bytes());
        buf[rec + 8..rec + 12].copy_from_slice(&100u32.to_be_bytes());

        let (cnid, fname, parent) =
            parse_folder_record(&buf, 0, &test_vol()).expect("should parse");
        assert_eq!(cnid, 100);
        assert_eq!(fname, "Docs");
        assert_eq!(parent, 2);
        // A file record (wrong recordType) must not parse as a folder.
        let file = build_record("x.txt", 10, 12, 1);
        assert!(parse_folder_record(&file, 0, &test_vol()).is_none());
    }
}
