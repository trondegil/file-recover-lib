//! Filesystem-aware recovery for exFAT volumes.
//!
//! exFAT is the default filesystem for SD/SDXC cards larger than 32 GB and for
//! most modern cameras, so it is an important complement to [`crate::fat`].
//!
//! ## How exFAT deletion works
//!
//! Directories are made of 32-byte entries grouped into "entry sets". Each
//! entry's first byte is a type code whose high bit (`0x80`) is the **InUse**
//! flag. Deleting a file simply **clears that bit** on every entry of its set;
//! the name, attributes, first cluster, and data length are all left intact.
//! Unlike FAT, no part of the name is lost.
//!
//! exFAT also avoids the per-file FAT chain whenever a file is stored
//! contiguously: the stream-extension entry carries a `NoFatChain` flag plus the
//! first cluster and exact byte length. That makes contiguous deleted files
//! trivially and reliably recoverable — we just read `DataLength` bytes from the
//! first cluster. Fragmented files fall back to following the FAT (when its
//! chain survived the delete).

use std::collections::HashSet;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::hash::HashingWriter;
use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// A parsed exFAT volume.
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    bytes_per_sector: u64,
    sectors_per_cluster: u64,
    fat_offset_sectors: u64,
    cluster_heap_offset_sectors: u64,
    cluster_count: u32,
    root_cluster: u32,
    volume_length_sectors: u64,
    /// Volume label (from the root directory's `0x83` entry), empty when unset.
    label: String,
    /// Volume serial number (`VolumeSerialNumber`), 0 when unset.
    serial: u32,
    /// Whether the volume is marked dirty (`VolumeFlags` bit 1).
    dirty: bool,
}

const ENTRY_SIZE: usize = 32;
// Entry type codes with the InUse bit (0x80) masked off.
const TYPE_FILE: u8 = 0x05; // 0x85 File Directory Entry
const TYPE_STREAM: u8 = 0x40; // 0xC0 Stream Extension
const TYPE_NAME: u8 = 0x41; // 0xC1 File Name
const INUSE_BIT: u8 = 0x80;
const ATTR_DIRECTORY: u16 = 0x10;
const FLAG_NO_FAT_CHAIN: u8 = 0x02;
const MAX_DIR_DEPTH: usize = 64;
const MAX_DIR_BYTES: u64 = 64 * 1024 * 1024;

/// Does this sector look like an exFAT volume boot record?
pub fn is_exfat_vbr(s: &[u8]) -> bool {
    s.len() >= 11 && &s[3..11] == b"EXFAT   "
}

impl Volume {
    /// Parse and validate the exFAT boot sector at `offset`.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut boot = [0u8; 512];
        if src.read_at(offset, &mut boot)? < 512 {
            bail!("could not read boot sector at offset {offset}");
        }
        if !is_exfat_vbr(&boot) {
            bail!("not an exFAT volume at offset {offset}");
        }

        let fat_offset_sectors =
            u32::from_le_bytes([boot[80], boot[81], boot[82], boot[83]]) as u64;
        let cluster_heap_offset_sectors =
            u32::from_le_bytes([boot[88], boot[89], boot[90], boot[91]]) as u64;
        let cluster_count = u32::from_le_bytes([boot[92], boot[93], boot[94], boot[95]]);
        let root_cluster = u32::from_le_bytes([boot[96], boot[97], boot[98], boot[99]]);
        let volume_length_sectors = u64::from_le_bytes([
            boot[72], boot[73], boot[74], boot[75], boot[76], boot[77], boot[78], boot[79],
        ]);
        let bytes_per_sector_shift = boot[108];
        let sectors_per_cluster_shift = boot[109];
        // VolumeSerialNumber: u32 at offset 100.
        let serial = u32::from_le_bytes([boot[100], boot[101], boot[102], boot[103]]);
        // VolumeFlags: u16 at offset 106; bit 1 (0x0002) is the VolumeDirty flag.
        let dirty = u16::from_le_bytes([boot[106], boot[107]]) & 0x0002 != 0;

        if !(9..=12).contains(&bytes_per_sector_shift) {
            bail!("implausible exFAT bytes-per-sector shift {bytes_per_sector_shift}");
        }
        // The spec caps a cluster at 32 MiB: bytes-per-sector + sectors-per-
        // cluster shifts must total <= 25. This also bounds per-cluster allocs.
        if bytes_per_sector_shift + sectors_per_cluster_shift > 25 {
            bail!("implausible exFAT cluster size shift {sectors_per_cluster_shift}");
        }

        let mut vol = Volume {
            offset,
            bytes_per_sector: 1u64 << bytes_per_sector_shift,
            sectors_per_cluster: 1u64 << sectors_per_cluster_shift,
            fat_offset_sectors,
            cluster_heap_offset_sectors,
            cluster_count,
            root_cluster,
            volume_length_sectors,
            label: String::new(),
            serial,
            dirty,
        };
        vol.label = vol.read_label(src);
        Ok(vol)
    }

    fn cluster_bytes(&self) -> u64 {
        self.sectors_per_cluster * self.bytes_per_sector
    }

    fn volume_end(&self) -> u64 {
        self.offset.saturating_add(
            self.volume_length_sectors
                .saturating_mul(self.bytes_per_sector),
        )
    }

    fn max_valid_cluster(&self) -> u32 {
        self.cluster_count.saturating_add(1) // clusters are numbered 2..=cluster_count+1
    }

    /// Absolute byte offset of a data cluster.
    fn cluster_offset(&self, cluster: u32) -> u64 {
        let sector = self.cluster_heap_offset_sectors.saturating_add(
            (cluster as u64)
                .saturating_sub(2)
                .saturating_mul(self.sectors_per_cluster),
        );
        self.offset
            .saturating_add(sector.saturating_mul(self.bytes_per_sector))
    }

    /// Next cluster in the FAT chain, or `None` at end/free/bad/out-of-range.
    fn next_cluster(&self, src: &Source, cluster: u32) -> Result<Option<u32>> {
        let off = self
            .offset
            .saturating_add(
                self.fat_offset_sectors
                    .saturating_mul(self.bytes_per_sector),
            )
            .saturating_add(cluster as u64 * 4);
        let mut b = [0u8; 4];
        if src.read_at(off, &mut b)? < 4 {
            return Ok(None);
        }
        let v = u32::from_le_bytes(b);
        if v < 2 || v > self.max_valid_cluster() || v == 0xFFFF_FFF7 || v == 0xFFFF_FFFF {
            Ok(None)
        } else {
            Ok(Some(v))
        }
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.volume_length_sectors
            .saturating_mul(self.bytes_per_sector)
    }

    /// The cluster (allocation unit) size in bytes.
    pub fn cluster_size(&self) -> u64 {
        self.bytes_per_sector
            .saturating_mul(self.sectors_per_cluster)
    }

    /// The volume label, empty when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The volume serial number as `XXXX-XXXX` (the form Windows `vol` and
    /// `blkid` show), or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        if self.serial == 0 {
            None
        } else {
            Some(format!(
                "{:04X}-{:04X}",
                self.serial >> 16,
                self.serial & 0xFFFF
            ))
        }
    }

    /// Whether the volume was cleanly unmounted (the `VolumeDirty` flag is clear).
    pub fn is_clean(&self) -> bool {
        !self.dirty
    }

    /// Read the volume label from the root directory's Volume Label entry
    /// (`0x83`: a character count then up to 11 UTF-16LE units). Empty on any
    /// read error or when no label is set.
    fn read_label(&self, src: &Source) -> String {
        let root = match self.read_directory(src, self.root_cluster, None, false) {
            Ok(r) => r,
            Err(_) => return String::new(),
        };
        for e in root.chunks_exact(ENTRY_SIZE) {
            match e[0] {
                0x00 => break, // end of directory
                0x83 => {
                    let count = (e[1] as usize).min(11);
                    let units: Vec<u16> = (0..count)
                        .map(|i| u16::from_le_bytes([e[2 + i * 2], e[3 + i * 2]]))
                        .collect();
                    return char::decode_utf16(units)
                        .map(|r| r.unwrap_or('\u{FFFD}'))
                        .collect();
                }
                _ => {}
            }
        }
        String::new()
    }

    /// Absolute byte ranges of the volume's **free** clusters, merged where
    /// contiguous, from the exFAT Allocation Bitmap (a `0x81` entry in the root
    /// directory points to it). A clear bit means the cluster is free, so
    /// carving those ranges recovers deleted data without re-finding live files.
    /// The allocation bitmap, read once: one bit per cluster from cluster 2,
    /// set when allocated. `None` when the root directory has no bitmap entry.
    fn read_bitmap(&self, src: &Source) -> Result<Option<Vec<u8>>> {
        let root = self.read_directory(src, self.root_cluster, None, false)?;
        let mut bitmap_loc: Option<(u32, u64)> = None;
        for e in root.chunks_exact(ENTRY_SIZE) {
            match e[0] {
                0x00 => break, // end of directory
                0x81 if e[1] & 0x01 == 0 => {
                    let first = u32::from_le_bytes([e[20], e[21], e[22], e[23]]);
                    let len = u64::from_le_bytes([
                        e[24], e[25], e[26], e[27], e[28], e[29], e[30], e[31],
                    ]);
                    bitmap_loc = Some((first, len));
                    break;
                }
                _ => {}
            }
        }
        let Some((first, len)) = bitmap_loc else {
            return Ok(None);
        };
        if first < 2 || first > self.max_valid_cluster() {
            return Ok(None);
        }
        const MAX_BITMAP: u64 = 256 * 1024 * 1024;
        let mut bitmap = vec![0u8; len.min(MAX_BITMAP) as usize];
        let n = src.read_at(self.cluster_offset(first), &mut bitmap)?;
        bitmap.truncate(n);
        Ok(Some(bitmap))
    }

    /// Whether the bitmap marks `cluster` allocated. Past the bitmap's end
    /// counts as allocated, so a short read never invites a blind read.
    fn cluster_allocated(bitmap: &[u8], cluster: u32) -> bool {
        let i = cluster.saturating_sub(2) as usize;
        bitmap
            .get(i / 8)
            .map(|b| b & (1 << (i % 8)) != 0)
            .unwrap_or(true)
    }

    pub fn free_extents(&self, src: &Source) -> Result<Vec<(u64, u64)>> {
        // The Allocation Bitmap is described by a directory entry in the root.
        let root = self.read_directory(src, self.root_cluster, None, false)?;
        let mut bitmap_loc: Option<(u32, u64)> = None;
        for e in root.chunks_exact(ENTRY_SIZE) {
            match e[0] {
                0x00 => break, // end of directory
                // Allocation Bitmap entry; flags bit 0 selects the bitmap (0 =
                // the first, primary one).
                0x81 if e[1] & 0x01 == 0 => {
                    let first = u32::from_le_bytes([e[20], e[21], e[22], e[23]]);
                    let len = u64::from_le_bytes([
                        e[24], e[25], e[26], e[27], e[28], e[29], e[30], e[31],
                    ]);
                    bitmap_loc = Some((first, len));
                    break;
                }
                _ => {}
            }
        }
        let (first, len) = match bitmap_loc {
            Some(x) => x,
            None => return Ok(Vec::new()), // no bitmap found; treat as unknown
        };
        if first < 2 || first > self.max_valid_cluster() {
            return Ok(Vec::new());
        }

        // The bitmap is a contiguous run in the cluster heap; read it directly.
        const MAX_BITMAP: u64 = 256 * 1024 * 1024;
        let mut bitmap = vec![0u8; len.min(MAX_BITMAP) as usize];
        let n = src.read_at(self.cluster_offset(first), &mut bitmap)?;
        bitmap.truncate(n);

        let cb = self.cluster_bytes();
        let mut out: Vec<(u64, u64)> = Vec::new();
        for i in 0..self.cluster_count as u64 {
            // A bit past the end of what we read is treated as allocated (safe).
            let allocated = bitmap
                .get((i / 8) as usize)
                .map(|b| b & (1 << (i % 8)) != 0)
                .unwrap_or(true);
            if !allocated {
                let start = self.cluster_offset(2 + i as u32);
                match out.last_mut() {
                    Some(last) if last.0 + last.1 == start => last.1 += cb,
                    _ => out.push((start, cb)),
                }
            }
        }
        Ok(out)
    }

    /// Recover all deleted files into `out_dir`.
    pub fn recover_deleted(
        &self,
        src: &Source,
        out_dir: &Path,
        opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        let mut deleted = Vec::new();
        self.walk(src, &mut deleted)?;

        let mut stats = RecoverStats::default();
        // The allocation bitmap, read once: a deleted file's chain may be
        // gone, but the clusters still allocated to other files say where it
        // cannot be.
        let bitmap = self.read_bitmap(src).unwrap_or(None);
        for df in deleted {
            if !opts.size_ok(df.data_length) {
                continue;
            }
            if !opts.time_ok(df.mtime) {
                continue;
            }
            if !opts.name_ok(crate::recover::file_name_of(&df.path)) {
                continue;
            }
            if !self.valid_extent(&df) {
                stats.record_skipped(df.path.clone(), df.data_length);
                continue;
            }
            if opts.dry_run {
                stats.record_recovered(df.path.clone(), df.data_length, None);
                continue;
            }
            match self.write_file(src, out_dir, &df, bitmap.as_deref()) {
                Ok((written, digest)) if written > 0 || df.data_length == 0 => {
                    // The report carries the bytes written: the entry's length
                    // unless the clusters ran out.
                    stats.record_recovered(df.path.clone(), written, Some(digest))
                }
                _ => stats.record_skipped(df.path.clone(), df.data_length),
            }
        }
        Ok(stats)
    }

    fn valid_extent(&self, df: &DeletedFile) -> bool {
        if df.data_length == 0 {
            return false; // nothing to recover
        }
        if df.first_cluster < 2 || df.first_cluster > self.max_valid_cluster() {
            return false;
        }
        if df.data_length
            > self
                .volume_length_sectors
                .saturating_mul(self.bytes_per_sector)
        {
            return false;
        }
        // For contiguous files the whole extent must fit inside the volume.
        if df.no_fat_chain {
            let start = self.cluster_offset(df.first_cluster);
            if start.saturating_add(df.data_length) > self.volume_end() {
                return false;
            }
        }
        true
    }

    /// Stream a recovered file to disk, following the FAT chain when present and
    /// falling back to a contiguous read otherwise.
    fn write_file(
        &self,
        src: &Source,
        out_dir: &Path,
        df: &DeletedFile,
        bitmap: Option<&[u8]>,
    ) -> Result<(u64, [u8; 32])> {
        let (_target, file) = crate::recover::create_output_file(out_dir, &df.path)?;
        let mut out = HashingWriter::new(file);

        let written = if df.no_fat_chain {
            self.copy_contiguous(src, df.first_cluster, df.data_length, &mut out)?
        } else {
            match self.copy_chain(src, df, &mut out)? {
                w if w >= df.data_length => w,
                // Chain was incomplete (freed by the delete). Restart from the
                // first cluster, stepping over clusters the bitmap still shows
                // allocated to live files: a file written into the gaps
                // between them comes back whole that way (the corpus's
                // `fragmented` scenario). A fresh file and hasher discard the
                // partial chain's bytes.
                _ => {
                    // Rewind the file we created rather than reopening the
                    // path, so nothing swapped in at that name is followed.
                    let (mut file, _) = out.into_parts();
                    file.set_len(0)?;
                    file.seek(SeekFrom::Start(0))?;
                    out = HashingWriter::new(file);
                    self.copy_skipping_allocated(src, df, bitmap, &mut out)?
                }
            }
        };
        out.flush().ok();
        let (out, digest) = out.into_parts();
        crate::times::apply(&out, df.mtime, df.atime);
        Ok((written, digest))
    }

    fn copy_contiguous(
        &self,
        src: &Source,
        first_cluster: u32,
        len: u64,
        out: &mut impl Write,
    ) -> Result<u64> {
        let mut remaining = len;
        let mut pos = self.cluster_offset(first_cluster);
        // Size the copy buffer to the file, capped at 1 MiB.
        let buf_len = (len as usize).clamp(1, 1024 * 1024);
        let mut buf = vec![0u8; buf_len];
        while remaining > 0 {
            let want = (remaining as usize).min(buf.len());
            let n = src.read_at(pos, &mut buf[..want])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            remaining -= n as u64;
            pos += n as u64;
        }
        Ok(len - remaining)
    }

    /// Read `len` bytes from `first_cluster` onward, skipping any cluster the
    /// bitmap marks allocated (without a bitmap this is a contiguous read).
    fn copy_skipping_allocated(
        &self,
        src: &Source,
        df: &DeletedFile,
        bitmap: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<u64> {
        let cb = self.cluster_bytes();
        let max = self.max_valid_cluster();
        let len = df.data_length;
        let mut remaining = len;
        let mut buf = vec![0u8; cb as usize];
        let has_map = bitmap.is_some();
        let is_free = |c: u32| {
            bitmap
                .map(|b| !Self::cluster_allocated(b, c))
                .unwrap_or(true)
        };
        let mut walk = crate::recover::FreeWalk::new(df.first_cluster, max, is_free);
        let mut jpeg =
            crate::recover::looks_like_jpeg_name(&df.path).then(crate::jpegscan::JpegScan::new);
        const MAX_TRIES: u32 = 4096;
        let mut tries = 0u32;
        let mut written = 0u64;
        let mut cluster = Some(df.first_cluster).filter(|&c| c >= 2 && c <= max);
        while remaining > 0 {
            let Some(c) = cluster else { break };
            let want = remaining.min(cb) as usize;
            let n = src.read_at(self.cluster_offset(c), &mut buf[..want])?;
            if n == 0 {
                break;
            }
            if let Some(state) = &jpeg {
                match state.accept(&buf[..n]) {
                    Some(next) => jpeg = Some(next),
                    None if written == 0 => jpeg = None,
                    None if has_map && tries < MAX_TRIES => {
                        tries += 1;
                        cluster = walk.next_after(c, true);
                        continue;
                    }
                    None => jpeg = None,
                }
            }
            out.write_all(&buf[..n])?;
            written += n as u64;
            remaining -= n as u64;
            tries = 0;
            cluster = walk.next_after(c, has_map);
        }
        Ok(len - remaining)
    }

    fn copy_chain(&self, src: &Source, df: &DeletedFile, out: &mut impl Write) -> Result<u64> {
        let cb = self.cluster_bytes();
        let mut remaining = df.data_length;
        let mut cluster = df.first_cluster;
        let mut written = 0u64;
        let mut buf = vec![0u8; cb as usize];
        let mut guard = HashSet::new();
        while remaining > 0 {
            if cluster < 2 || cluster > self.max_valid_cluster() || !guard.insert(cluster) {
                break;
            }
            let want = (remaining.min(cb)) as usize;
            let n = src.read_at(self.cluster_offset(cluster), &mut buf[..want])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            written += n as u64;
            remaining -= n as u64;
            match self.next_cluster(src, cluster)? {
                Some(next) => cluster = next,
                None => break,
            }
        }
        Ok(written)
    }

    /// Walk live directories from the root, collecting deleted files.
    fn walk(&self, src: &Source, out: &mut Vec<DeletedFile>) -> Result<()> {
        let mut visited: HashSet<u32> = HashSet::new();
        // (first cluster, byte length or None, contiguous?, path, depth,
        // whether the directory itself is deleted)
        let mut stack: Vec<(u32, Option<u64>, bool, PathBuf, usize, bool)> =
            vec![(self.root_cluster, None, false, PathBuf::new(), 0, false)];

        while let Some((cluster, len, contiguous, path, depth, deleted_dir)) = stack.pop() {
            if !visited.insert(cluster) {
                continue;
            }
            let bytes = match self.read_directory(src, cluster, len, contiguous) {
                Ok(b) => b,
                Err(_) => continue,
            };
            for item in parse_entry_sets(&bytes) {
                // Deleted directories are descended as well: removing a folder
                // tree marks its entries deleted before the folder itself, and
                // the folder's clusters keep them until reused. The stream
                // extension survives deletion, so the length and the
                // contiguity flag still say how to read it. Windows discards
                // the children's markers with the folder, so under a deleted
                // folder every entry counts as deleted.
                let gone = item.deleted || deleted_dir;
                if item.is_dir {
                    if depth < MAX_DIR_DEPTH
                        && item.first_cluster >= 2
                        && item.first_cluster <= self.max_valid_cluster()
                        && !visited.contains(&item.first_cluster)
                    {
                        let child = path.join(sanitize_component(&item.name));
                        stack.push((
                            item.first_cluster,
                            Some(item.data_length),
                            item.no_fat_chain,
                            child,
                            depth + 1,
                            gone,
                        ));
                    }
                } else if gone {
                    out.push(DeletedFile {
                        path: path.join(sanitize_component(&item.name)),
                        first_cluster: item.first_cluster,
                        data_length: item.data_length,
                        no_fat_chain: item.no_fat_chain,
                        mtime: item.mtime,
                        atime: item.atime,
                    });
                }
            }
        }
        Ok(())
    }

    /// Read a directory's raw bytes, contiguously or via the FAT chain.
    fn read_directory(
        &self,
        src: &Source,
        first_cluster: u32,
        len: Option<u64>,
        contiguous: bool,
    ) -> Result<Vec<u8>> {
        let cb = self.cluster_bytes();
        let mut buf = Vec::new();

        if contiguous {
            // Subdirectory with a known contiguous extent.
            let total = len.unwrap_or(cb);
            let mut remaining = total;
            let mut pos = self.cluster_offset(first_cluster);
            while remaining > 0 && (buf.len() as u64) < MAX_DIR_BYTES {
                let want = (remaining.min(cb)) as usize;
                let mut chunk = vec![0u8; want];
                let n = src.read_at(pos, &mut chunk)?;
                chunk.truncate(n);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk);
                remaining -= n as u64;
                pos += n as u64;
            }
            return Ok(buf);
        }

        // Root directory or fragmented subdirectory: follow the FAT chain.
        let mut cluster = first_cluster;
        let mut guard = HashSet::new();
        loop {
            if cluster < 2 || cluster > self.max_valid_cluster() || !guard.insert(cluster) {
                break;
            }
            if buf.len() as u64 + cb > MAX_DIR_BYTES {
                break;
            }
            let mut chunk = vec![0u8; cb as usize];
            let n = src.read_at(self.cluster_offset(cluster), &mut chunk)?;
            chunk.truncate(n);
            buf.extend_from_slice(&chunk);
            if let Some(limit) = len {
                if buf.len() as u64 >= limit {
                    buf.truncate(limit as usize);
                    break;
                }
            }
            match self.next_cluster(src, cluster)? {
                Some(next) => cluster = next,
                None => break,
            }
        }
        Ok(buf)
    }
}

/// A deleted file to recover.
struct DeletedFile {
    path: PathBuf,
    first_cluster: u32,
    data_length: u64,
    no_fat_chain: bool,
    mtime: Option<std::time::SystemTime>,
    atime: Option<std::time::SystemTime>,
}

/// A parsed file/dir entry set.
struct Item {
    name: String,
    deleted: bool,
    is_dir: bool,
    first_cluster: u32,
    data_length: u64,
    no_fat_chain: bool,
    mtime: Option<std::time::SystemTime>,
    atime: Option<std::time::SystemTime>,
}

/// Parse a directory's bytes into file/directory entry sets.
fn parse_entry_sets(bytes: &[u8]) -> Vec<Item> {
    let mut items = Vec::new();
    let total = bytes.len() / ENTRY_SIZE;
    let entry = |i: usize| &bytes[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE];

    let mut i = 0;
    while i < total {
        let e = entry(i);
        let type_code = e[0] & !INUSE_BIT;

        if type_code != TYPE_FILE {
            i += 1;
            continue;
        }
        let deleted = e[0] & INUSE_BIT == 0;
        let secondary_count = e[1] as usize;
        let attrs = u16::from_le_bytes([e[4], e[5]]);
        let is_dir = attrs & ATTR_DIRECTORY != 0;
        // Timestamps live in the primary File entry (modified at 0x0C, accessed
        // at 0x10), packed in the DOS-style exFAT format.
        let mtime = crate::times::from_exfat(u32::from_le_bytes([e[12], e[13], e[14], e[15]]));
        let atime = crate::times::from_exfat(u32::from_le_bytes([e[16], e[17], e[18], e[19]]));

        // The set is this entry plus `secondary_count` following entries.
        if secondary_count == 0 || i + secondary_count >= total {
            i += 1;
            continue;
        }
        let stream = entry(i + 1);
        if stream[0] & !INUSE_BIT != TYPE_STREAM {
            i += 1;
            continue;
        }
        let flags = stream[1];
        let no_fat_chain = flags & FLAG_NO_FAT_CHAIN != 0;
        let name_length = stream[3] as usize;
        let first_cluster = u32::from_le_bytes([stream[20], stream[21], stream[22], stream[23]]);
        let data_length = u64::from_le_bytes([
            stream[24], stream[25], stream[26], stream[27], stream[28], stream[29], stream[30],
            stream[31],
        ]);

        // Name entries are the remaining secondary entries.
        let mut name_units: Vec<u16> = Vec::with_capacity(name_length);
        for j in 2..=secondary_count {
            let ne = entry(i + j);
            if ne[0] & !INUSE_BIT != TYPE_NAME {
                break;
            }
            for pair in ne[2..ENTRY_SIZE].chunks_exact(2) {
                name_units.push(u16::from_le_bytes([pair[0], pair[1]]));
            }
        }
        name_units.truncate(name_length);
        let name = String::from_utf16_lossy(&name_units);

        if !name.is_empty() {
            items.push(Item {
                name,
                deleted,
                is_dir,
                first_cluster,
                data_length,
                no_fat_chain,
                mtime,
                atime,
            });
        }
        i += 1 + secondary_count;
    }
    items
}

/// Make a single path component safe to write to disk.
fn sanitize_component(name: &str) -> String {
    crate::recover::sanitize_component(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_bits_are_cluster_minus_two_lsb_first() {
        // Bit 0 of byte 0 is cluster 2; bit 3 of byte 1 is cluster 13.
        let bitmap = [0b0000_0001u8, 0b0000_1000];
        assert!(Volume::cluster_allocated(&bitmap, 2));
        assert!(!Volume::cluster_allocated(&bitmap, 3));
        assert!(Volume::cluster_allocated(&bitmap, 13));
        assert!(!Volume::cluster_allocated(&bitmap, 12));
        // Past the bitmap counts as allocated: never a blind read.
        assert!(Volume::cluster_allocated(&bitmap, 18));
        assert!(Volume::cluster_allocated(&bitmap, 1_000_000));
        // Cluster numbers below 2 do not underflow.
        let _ = Volume::cluster_allocated(&bitmap, 0);
    }

    /// An entry set: file entry, stream extension, and enough name entries.
    fn entry_set(
        name: &str,
        in_use: bool,
        is_dir: bool,
        first: u32,
        len: u64,
        no_chain: bool,
    ) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let name_entries = units.len().div_ceil(15);
        let mut set = vec![0u8; (2 + name_entries) * ENTRY_SIZE];
        let flag = if in_use { INUSE_BIT } else { 0 };
        set[0] = TYPE_FILE | flag;
        set[1] = (1 + name_entries) as u8;
        set[4..6].copy_from_slice(&(if is_dir { 0x10u16 } else { 0x20 }).to_le_bytes());
        set[32] = TYPE_STREAM | flag;
        set[33] = 0x01 | if no_chain { 0x02 } else { 0 };
        set[35] = units.len() as u8;
        set[40..48].copy_from_slice(&len.to_le_bytes());
        set[52..56].copy_from_slice(&first.to_le_bytes());
        set[56..64].copy_from_slice(&len.to_le_bytes());
        for (k, chunk) in units.chunks(15).enumerate() {
            let base = (2 + k) * ENTRY_SIZE;
            set[base] = TYPE_NAME | flag;
            for (j, u) in chunk.iter().enumerate() {
                set[base + 2 + j * 2..base + 4 + j * 2].copy_from_slice(&u.to_le_bytes());
            }
        }
        set
    }

    #[test]
    fn parses_deleted_and_live_entry_sets_with_long_names() {
        let mut dir = Vec::new();
        dir.extend_from_slice(&entry_set(
            "a rather long file name.jpeg",
            false,
            false,
            40,
            123_456,
            false,
        ));
        dir.extend_from_slice(&entry_set("Bilder", true, true, 50, 4096, true));
        dir.extend_from_slice(&[0u8; ENTRY_SIZE]);
        let items = parse_entry_sets(&dir);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "a rather long file name.jpeg");
        assert!(items[0].deleted);
        assert!(!items[0].is_dir);
        assert_eq!(items[0].first_cluster, 40);
        assert_eq!(items[0].data_length, 123_456);
        assert!(!items[0].no_fat_chain);
        assert_eq!(items[1].name, "Bilder");
        assert!(!items[1].deleted);
        assert!(items[1].is_dir);
        assert!(items[1].no_fat_chain);
    }

    #[test]
    fn a_truncated_entry_set_is_dropped_not_panicked() {
        let set = entry_set("x.bin", false, false, 40, 10, true);
        // Cut after the file entry: no stream, no name.
        let items = parse_entry_sets(&set[..ENTRY_SIZE]);
        assert!(items.is_empty());
        // Garbage of the right length.
        let items = parse_entry_sets(&[0xC1u8; 96]);
        assert!(items.is_empty());
    }

    #[test]
    fn sanitize_goes_through_the_shared_rules() {
        assert_eq!(sanitize_component("a/b"), "a_b");
        assert_eq!(sanitize_component(""), "_recovered");
    }
}
