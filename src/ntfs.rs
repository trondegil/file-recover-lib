//! Filesystem-aware recovery for NTFS volumes.
//!
//! NTFS describes every file and directory with a record in the **Master File
//! Table (MFT)**. Each record holds *attributes* such as `$FILE_NAME` (the name
//! and parent directory) and `$DATA` (the contents, either stored inline when
//! small or described by *data runs* pointing at clusters elsewhere).
//!
//! ## How NTFS deletion works
//!
//! Deleting a file clears the **in-use** flag (`0x01`) in its MFT record's
//! header. The record — including the name and the `$DATA` data runs — survives
//! until the MFT slot is reused. Recovery therefore scans the MFT for records
//! that are *not* in use but still parse cleanly, and rebuilds each file from
//! its surviving attributes.
//!
//! Unlike FAT/exFAT, NTFS records the full list of cluster runs for a file, so
//! this backend can reconstruct **fragmented** files correctly (as long as the
//! record's run list is intact).
//!
//! ## Nameless records
//!
//! Windows leaves the whole record intact, name included. The Linux `ntfs3`
//! driver does not: the real-image corpus showed it stripping `$FILE_NAME`
//! from a deleted record while keeping `$DATA` and its runs. Such a record
//! still describes the file's exact bytes, so it is recovered anyway, under
//! `_unnamed/mft-<record>.<ext>` with the extension identified from the
//! content — still better than carving, which would guess at the length.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::hash::HashingWriter;
use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// A list of cluster runs: each is (absolute LCN, or `None` for a sparse run;
/// length in clusters).
type Runs = Vec<(Option<i64>, u64)>;

/// A parsed NTFS volume.
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    bytes_per_sector: u64,
    cluster_size: u64,
    record_size: u64,
    /// Total volume size in bytes.
    volume_size: u64,
    /// Data runs of `$MFT` itself.
    mft_runs: Runs,
    /// Number of records in the MFT.
    record_count: u64,
    /// Volume label (`$VOLUME_NAME` of `$Volume`), empty when unset.
    label: String,
    /// Volume serial number (8 bytes at boot-sector offset 0x48).
    serial: u64,
    /// Whether the volume was cleanly unmounted (`$VOLUME_INFORMATION` dirty bit
    /// clear); `None` when the attribute is absent.
    clean: Option<bool>,
    /// Volume creation time from `$Volume`'s `$STANDARD_INFORMATION`, Unix
    /// seconds; `None` when unreadable.
    created: Option<u64>,
    /// Volume last-modification time from `$Volume`'s `$STANDARD_INFORMATION`,
    /// Unix seconds; `None` when unreadable.
    written: Option<u64>,
}

const ATTR_STANDARD_INFO: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_VOLUME_NAME: u32 = 0x60;
const ATTR_VOLUME_INFORMATION: u32 = 0x70;
const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFF_FFFF;
/// MFT record of `$Volume`, which carries the volume label.
const VOLUME_RECORD: u64 = 3;
const FLAG_IN_USE: u16 = 0x01;
const FLAG_DIRECTORY: u16 = 0x02;
const ROOT_RECORD: u64 = 5;
const MAX_PATH_DEPTH: usize = 64;
/// Safety cap on how many MFT records to scan.
const MAX_RECORDS: u64 = 8_000_000;

/// Does this sector look like an NTFS volume boot record?
pub fn is_ntfs_vbr(s: &[u8]) -> bool {
    s.len() >= 11 && &s[3..11] == b"NTFS    "
}

impl Volume {
    /// Parse and validate the NTFS boot sector at `offset`.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut boot = [0u8; 512];
        if src.read_at(offset, &mut boot)? < 512 {
            bail!("could not read boot sector at offset {offset}");
        }
        if !is_ntfs_vbr(&boot) {
            bail!("not an NTFS volume at offset {offset}");
        }

        let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]) as u64;
        let spc_raw = boot[13];
        // SectorsPerCluster: a literal count, or (when > 0x80) a negative power
        // of two giving the cluster size directly.
        let sectors_per_cluster = if spc_raw <= 0x80 {
            spc_raw as u64
        } else {
            // Values above 0x80 encode a negative power of two; the exponent
            // must stay well within a u64 to be plausible.
            let exp = 256 - spc_raw as u32;
            if exp >= 32 {
                bail!("implausible NTFS sectors-per-cluster shift {exp}");
            }
            1u64 << exp
        };
        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            bail!("invalid NTFS BPB (zero sector/cluster size)");
        }
        let cluster_size = bytes_per_sector.saturating_mul(sectors_per_cluster);

        let total_sectors = u64::from_le_bytes([
            boot[40], boot[41], boot[42], boot[43], boot[44], boot[45], boot[46], boot[47],
        ]);
        let volume_size = total_sectors.saturating_mul(bytes_per_sector);

        let mft_cluster = u64::from_le_bytes([
            boot[48], boot[49], boot[50], boot[51], boot[52], boot[53], boot[54], boot[55],
        ]);
        let clusters_per_record = boot[64] as i8;
        let record_size = if clusters_per_record >= 0 {
            (clusters_per_record as u64).saturating_mul(cluster_size)
        } else {
            let exp = (-clusters_per_record) as u32;
            if exp >= 32 {
                bail!("implausible NTFS record-size shift {exp}");
            }
            1u64 << exp
        };
        // Bound the record size so a corrupt value cannot trigger a huge alloc.
        if !(42..=(1 << 20)).contains(&record_size) {
            bail!("implausible NTFS record size {record_size}");
        }

        // Read MFT record 0 ($MFT) to learn the MFT's own extent.
        let mft_start = offset.saturating_add(mft_cluster.saturating_mul(cluster_size));
        let mut rec0 = vec![0u8; record_size as usize];
        if src.read_at(mft_start, &mut rec0)? < record_size as usize {
            bail!("could not read $MFT record 0");
        }
        apply_fixup(&mut rec0, bytes_per_sector as usize);
        if &rec0[0..4] != b"FILE" {
            bail!("$MFT record 0 is not a FILE record");
        }

        let (mft_runs, mft_size) =
            mft_data_extent(&rec0, cluster_size).context("parsing $MFT $DATA runs")?;
        let record_count = (mft_size / record_size).min(MAX_RECORDS);

        // Volume serial number: 8 bytes at offset 0x48.
        let serial = u64::from_le_bytes([
            boot[72], boot[73], boot[74], boot[75], boot[76], boot[77], boot[78], boot[79],
        ]);

        let mut vol = Volume {
            offset,
            bytes_per_sector,
            cluster_size,
            record_size,
            volume_size,
            mft_runs,
            record_count,
            label: String::new(),
            serial,
            clean: None,
            created: None,
            written: None,
        };
        vol.label = vol.read_volume_label(src).unwrap_or_default();
        vol.clean = vol.read_dirty(src);
        (vol.created, vol.written) = vol.read_times(src);
        Ok(vol)
    }

    /// The volume label, empty when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The volume serial number as 16 uppercase hex digits (the form `blkid`
    /// shows for NTFS), or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        if self.serial == 0 {
            None
        } else {
            Some(format!("{:016X}", self.serial))
        }
    }

    /// Whether the volume was cleanly unmounted: the `$VOLUME_INFORMATION` flags
    /// (MFT record 3) have the dirty bit clear. `None` when the attribute is
    /// absent or unreadable.
    pub fn is_clean(&self) -> Option<bool> {
        self.clean
    }

    /// Read the volume label from `$Volume`'s `$VOLUME_NAME` attribute (MFT
    /// record 3): a resident attribute whose content is the name in UTF-16LE.
    fn read_volume_label(&self, src: &Source) -> Option<String> {
        let rec = self.read_record(src, VOLUME_RECORD).ok()??;
        let content = resident_attr_content(&rec, ATTR_VOLUME_NAME)?;
        if content.len() < 2 {
            return None;
        }
        let units: Vec<u16> = content
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name: String = char::decode_utf16(units)
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Read the volume dirty state from `$Volume`'s `$VOLUME_INFORMATION`
    /// attribute: a u16 flags field at content offset 8, bit 0 (`0x0001`) is the
    /// "dirty" flag. Returns whether the volume is clean (dirty bit clear).
    fn read_dirty(&self, src: &Source) -> Option<bool> {
        let rec = self.read_record(src, VOLUME_RECORD).ok()??;
        let content = resident_attr_content(&rec, ATTR_VOLUME_INFORMATION)?;
        // Content: 8 reserved bytes, major/minor version (1 each), then flags.
        let flags = u16::from_le_bytes([*content.get(10)?, *content.get(11)?]);
        Some(flags & 0x0001 == 0)
    }

    /// Volume creation and last-modification times from `$Volume`'s
    /// `$STANDARD_INFORMATION` (MFT record 3): two 8-byte Windows FILETIMEs at
    /// content offsets 0x00 (created) and 0x08 (modified). Returns
    /// `(created, written)` as Unix seconds, each `None` when unreadable.
    fn read_times(&self, src: &Source) -> (Option<u64>, Option<u64>) {
        let parse = || -> Option<(Option<u64>, Option<u64>)> {
            let rec = self.read_record(src, VOLUME_RECORD).ok()??;
            let content = resident_attr_content(&rec, ATTR_STANDARD_INFO)?;
            let ft = |o: usize| -> Option<u64> {
                let b = content.get(o..o + 8)?;
                let t = crate::times::from_filetime(u64::from_le_bytes(b.try_into().ok()?))?;
                Some(t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs())
            };
            Some((ft(0x00), ft(0x08)))
        };
        parse().unwrap_or((None, None))
    }

    /// Volume creation time (`$Volume` `$STANDARD_INFORMATION`) as Unix seconds.
    pub fn created_time(&self) -> Option<u64> {
        self.created
    }

    /// Volume last-modification time (`$Volume` `$STANDARD_INFORMATION`) as Unix
    /// seconds.
    pub fn written_time(&self) -> Option<u64> {
        self.written
    }

    /// Read MFT record `index`, with fixups applied.
    fn read_record(&self, src: &Source, index: u64) -> Result<Option<Vec<u8>>> {
        let start = index * self.record_size;
        let mut rec = read_runs_range(
            src,
            self.offset,
            self.cluster_size,
            &self.mft_runs,
            start,
            self.record_size,
        )?;
        if rec.len() < self.record_size as usize {
            return Ok(None);
        }
        if &rec[0..4] != b"FILE" || !apply_fixup(&mut rec, self.bytes_per_sector as usize) {
            return Ok(None);
        }
        Ok(Some(rec))
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.volume_size
    }

    /// The cluster (allocation unit) size in bytes.
    pub fn cluster_size(&self) -> u64 {
        self.cluster_size
    }

    /// Absolute byte ranges of the volume's **free** clusters, merged where
    /// contiguous, from the `$Bitmap` metadata file (MFT record 6). A clear bit
    /// means the cluster is free, so carving those ranges recovers deleted data
    /// without re-finding clusters still allocated to live files.
    pub fn free_extents(&self, src: &Source) -> Result<Vec<(u64, u64)>> {
        const BITMAP_RECORD: u64 = 6;
        const MAX_BITMAP: u64 = 256 * 1024 * 1024;

        let rec = match self.read_record(src, BITMAP_RECORD)? {
            Some(r) => r,
            None => return Ok(Vec::new()),
        };
        let data = match parse_record(&rec).and_then(|p| p.data) {
            Some(d) => d,
            None => return Ok(Vec::new()),
        };
        let bitmap = match data.kind {
            DataKind::Resident(bytes) => bytes,
            DataKind::NonResident(runs) => {
                let want = data.size.min(MAX_BITMAP);
                read_runs_range(src, self.offset, self.cluster_size, &runs, 0, want)?
            }
        };

        let total_clusters = self.volume_size / self.cluster_size;
        let mut out: Vec<(u64, u64)> = Vec::new();
        for c in 0..total_clusters {
            // A bit past the bitmap we read is treated as allocated (safe).
            let allocated = bitmap
                .get((c / 8) as usize)
                .map(|b| b & (1 << (c % 8)) != 0)
                .unwrap_or(true);
            if !allocated {
                let start = self.offset + c * self.cluster_size;
                match out.last_mut() {
                    Some(last) if last.0 + last.1 == start => last.1 += self.cluster_size,
                    _ => out.push((start, self.cluster_size)),
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
        let mut stats = RecoverStats::default();

        for index in 0..self.record_count {
            let rec = match self.read_record(src, index) {
                Ok(Some(r)) => r,
                _ => continue,
            };
            let flags = u16::from_le_bytes([rec[22], rec[23]]);
            if flags & FLAG_IN_USE != 0 || flags & FLAG_DIRECTORY != 0 {
                continue; // only deleted, non-directory records
            }

            let parsed = match parse_record(&rec) {
                Some(p) => p,
                None => continue,
            };
            let data = match parsed.data {
                Some(d) => d,
                None => continue,
            };
            // A record stripped of its name (the Linux ntfs3 driver does this)
            // is still worth its exact data; it just cannot be placed by path.
            let nameless = parsed.file_name.is_none();
            let (name, parent) = parsed
                .file_name
                .unwrap_or_else(|| (format!("mft-{index}.bin"), 0));
            if !opts.size_ok(data.size) {
                continue;
            }
            if !opts.time_ok(parsed.mtime) {
                continue;
            }
            if !nameless && !opts.name_ok(&name) {
                continue;
            }

            let rel = if nameless {
                // Nothing to recover from an empty, nameless record.
                if data.size == 0 {
                    continue;
                }
                Path::new("_unnamed").join(&name)
            } else {
                self.resolve_path(src, parent, &name)
            };
            if opts.dry_run {
                stats.record_recovered(rel, data.size, None);
                continue;
            }
            let times = (parsed.mtime, parsed.atime);
            match self.write_file(src, out_dir, &rel, &data, times) {
                Ok((written, digest)) if written > 0 || data.size == 0 => {
                    let rel = if nameless {
                        self.rename_by_content(out_dir, &rel)
                    } else {
                        rel
                    };
                    if nameless && !opts.name_ok(crate::recover::file_name_of(&rel)) {
                        let _ = fs::remove_file(out_dir.join(&rel));
                        continue;
                    }
                    // The report carries the bytes written, which is the
                    // claimed size unless a run ran off the end of the source.
                    stats.record_recovered(rel, written, Some(digest))
                }
                _ => stats.record_skipped(rel, data.size),
            }
        }
        Ok(stats)
    }

    /// Give a nameless recovered file (`mft-N.bin`) the extension its content
    /// identifies as, when it does. Returns the path the file ended up at.
    fn rename_by_content(&self, out_dir: &Path, rel: &Path) -> PathBuf {
        let full = out_dir.join(rel);
        let mut head = vec![0u8; 64 * 1024];
        let n = match fs::File::open(&full).and_then(|mut f| {
            use std::io::Read;
            f.read(&mut head)
        }) {
            Ok(n) => n,
            Err(_) => return rel.to_path_buf(),
        };
        let Some(det) = crate::identify::identify(&head[..n]) else {
            return rel.to_path_buf();
        };
        let renamed = rel.with_extension(det.ext);
        let target = unique_path(out_dir, &renamed);
        match fs::rename(&full, &target) {
            Ok(()) => target
                .strip_prefix(out_dir)
                .unwrap_or(&renamed)
                .to_path_buf(),
            Err(_) => rel.to_path_buf(),
        }
    }

    /// Write a recovered file's data (resident inline, or from cluster runs).
    fn write_file(
        &self,
        src: &Source,
        out_dir: &Path,
        rel: &Path,
        data: &DataAttr,
        times: (Option<std::time::SystemTime>, Option<std::time::SystemTime>),
    ) -> Result<(u64, [u8; 32])> {
        let (_target, file) = crate::recover::create_output_file(out_dir, rel)?;
        let mut out = HashingWriter::new(file);

        let written = match &data.kind {
            DataKind::Resident(bytes) => {
                out.write_all(bytes)?;
                bytes.len() as u64
            }
            DataKind::NonResident(runs) => {
                let mut remaining = data.size;
                let mut written = 0u64;
                // Size the copy buffer to the file, capped at 1 MiB.
                let buf_len = (data.size as usize).clamp(1, 1024 * 1024);
                let mut buf = vec![0u8; buf_len];
                for &(lcn, count) in runs {
                    if remaining == 0 {
                        break;
                    }
                    let run_bytes = count.saturating_mul(self.cluster_size);
                    let take = run_bytes.min(remaining);
                    match lcn {
                        None => {
                            // Sparse run: emit zeros.
                            let mut left = take;
                            for b in buf.iter_mut() {
                                *b = 0;
                            }
                            while left > 0 {
                                let n = (left as usize).min(buf.len());
                                out.write_all(&buf[..n])?;
                                left -= n as u64;
                            }
                        }
                        Some(l) if l >= 0 => {
                            let mut pos = self
                                .offset
                                .saturating_add((l as u64).saturating_mul(self.cluster_size));
                            let mut left = take;
                            while left > 0 {
                                let want = (left as usize).min(buf.len());
                                let n = src.read_at(pos, &mut buf[..want])?;
                                if n == 0 {
                                    break;
                                }
                                out.write_all(&buf[..n])?;
                                pos += n as u64;
                                left -= n as u64;
                            }
                            if left > 0 {
                                // The run reaches past the source: what was
                                // read is all there is. Counting the rest
                                // would report a size the file does not have.
                                written += take - left;
                                break;
                            }
                        }
                        Some(_) => break, // negative absolute LCN: corrupt
                    }
                    written += take;
                    remaining -= take;
                }
                written
            }
        };
        out.flush().ok();
        let (out, digest) = out.into_parts();
        crate::times::apply(&out, times.0, times.1);
        Ok((written, digest))
    }

    /// Resolve a deleted file's path by climbing parent directory records.
    fn resolve_path(&self, src: &Source, parent: u64, name: &str) -> PathBuf {
        let mut components = vec![sanitize_component(name)];
        let mut current = parent & 0x0000_FFFF_FFFF_FFFF; // low 48 bits = record number
        let mut seen = HashSet::new();

        for _ in 0..MAX_PATH_DEPTH {
            if current == ROOT_RECORD || !seen.insert(current) {
                break;
            }
            let rec = match self.read_record(src, current) {
                Ok(Some(r)) => r,
                _ => break,
            };
            let parsed = match parse_record(&rec) {
                Some(p) => p,
                None => break,
            };
            match parsed.file_name {
                Some((pname, pparent)) => {
                    components.push(sanitize_component(&pname));
                    current = pparent & 0x0000_FFFF_FFFF_FFFF;
                }
                None => break,
            }
        }

        components.reverse();
        components.iter().collect()
    }
}

/// Parsed contents of one MFT record we care about.
struct ParsedRecord {
    /// Best file name and its parent reference.
    file_name: Option<(String, u64)>,
    data: Option<DataAttr>,
    /// Modified / accessed times from `$STANDARD_INFORMATION`, if present.
    mtime: Option<std::time::SystemTime>,
    atime: Option<std::time::SystemTime>,
}

struct DataAttr {
    size: u64,
    kind: DataKind,
}

enum DataKind {
    Resident(Vec<u8>),
    NonResident(Runs),
}

/// Return the content of the first **resident** attribute of type `want` in a
/// fixed-up FILE record `rec`, or `None` if there is no such resident attribute.
fn resident_attr_content(rec: &[u8], want: u32) -> Option<&[u8]> {
    if rec.len() < 24 || &rec[0..4] != b"FILE" {
        return None;
    }
    let mut offset = u16::from_le_bytes([rec[20], rec[21]]) as usize;
    while offset + 16 <= rec.len() {
        let attr_type = u32::from_le_bytes([
            rec[offset],
            rec[offset + 1],
            rec[offset + 2],
            rec[offset + 3],
        ]);
        if attr_type == ATTR_END {
            break;
        }
        let attr_len = u32::from_le_bytes([
            rec[offset + 4],
            rec[offset + 5],
            rec[offset + 6],
            rec[offset + 7],
        ]) as usize;
        if attr_len < 24 || offset + attr_len > rec.len() {
            break;
        }
        // rec[offset + 8] == 0 marks a resident attribute.
        if attr_type == want && rec[offset + 8] == 0 {
            let content_len = u32::from_le_bytes([
                rec[offset + 16],
                rec[offset + 17],
                rec[offset + 18],
                rec[offset + 19],
            ]) as usize;
            let content_off = u16::from_le_bytes([rec[offset + 20], rec[offset + 21]]) as usize;
            let start = offset + content_off;
            let end = start.checked_add(content_len)?;
            return rec.get(start..end);
        }
        offset += attr_len;
    }
    None
}

/// Parse the attributes of an MFT record we want to recover.
fn parse_record(rec: &[u8]) -> Option<ParsedRecord> {
    if rec.len() < 24 {
        return None;
    }
    let first_attr = u16::from_le_bytes([rec[20], rec[21]]) as usize;
    let mut offset = first_attr;
    let mut best_name: Option<(String, u64, u8)> = None; // (name, parent, namespace)
    let mut data: Option<DataAttr> = None;
    let mut mtime = None;
    let mut atime = None;

    // Need at least the 16-byte fixed attribute header to read safely.
    while offset + 16 <= rec.len() {
        let attr_type = u32::from_le_bytes([
            rec[offset],
            rec[offset + 1],
            rec[offset + 2],
            rec[offset + 3],
        ]);
        if attr_type == ATTR_END {
            break;
        }
        let attr_len = u32::from_le_bytes([
            rec[offset + 4],
            rec[offset + 5],
            rec[offset + 6],
            rec[offset + 7],
        ]) as usize;
        if attr_len < 16 || offset + attr_len > rec.len() {
            break;
        }
        let non_resident = rec[offset + 8] != 0;
        let name_length = rec[offset + 9] as usize;

        if attr_type == ATTR_STANDARD_INFO && !non_resident && attr_len >= 22 {
            // $STANDARD_INFORMATION holds the authoritative timestamps.
            let content_off = u16::from_le_bytes([rec[offset + 20], rec[offset + 21]]) as usize;
            let base = offset + content_off;
            if base + 0x20 <= offset + attr_len {
                let read_ft = |o: usize| {
                    u64::from_le_bytes([
                        rec[o],
                        rec[o + 1],
                        rec[o + 2],
                        rec[o + 3],
                        rec[o + 4],
                        rec[o + 5],
                        rec[o + 6],
                        rec[o + 7],
                    ])
                };
                mtime = crate::times::from_filetime(read_ft(base + 0x08));
                atime = crate::times::from_filetime(read_ft(base + 0x18));
            }
        } else if attr_type == ATTR_FILE_NAME && !non_resident {
            if let Some((name, parent, namespace)) =
                parse_file_name(&rec[offset..offset + attr_len])
            {
                // Prefer Win32 names (namespace != 2 = DOS), then the longest.
                let better = match &best_name {
                    None => true,
                    Some((bn, _, bns)) => namespace != 2 && (*bns == 2 || name.len() > bn.len()),
                };
                if better {
                    best_name = Some((name, parent, namespace));
                }
            }
        } else if attr_type == ATTR_DATA && name_length == 0 {
            // The unnamed $DATA attribute is the main file content.
            data = parse_data(&rec[offset..offset + attr_len], non_resident);
        }

        offset += attr_len;
    }

    Some(ParsedRecord {
        file_name: best_name.map(|(n, p, _)| (n, p)),
        data,
        mtime,
        atime,
    })
}

/// Parse a resident `$FILE_NAME` attribute into (name, parent ref, namespace).
fn parse_file_name(attr: &[u8]) -> Option<(String, u64, u8)> {
    // Resident attribute header is 24 bytes; need its content length/offset.
    if attr.len() < 24 {
        return None;
    }
    let content_len = u32::from_le_bytes([attr[16], attr[17], attr[18], attr[19]]) as usize;
    let content_off = u16::from_le_bytes([attr[20], attr[21]]) as usize;
    if content_off + content_len > attr.len() || content_len < 0x42 {
        return None;
    }
    let c = &attr[content_off..content_off + content_len];
    let parent = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
    let name_chars = c[0x40] as usize;
    let namespace = c[0x41];
    let name_bytes = 0x42 + name_chars * 2;
    if name_bytes > c.len() {
        return None;
    }
    let units: Vec<u16> = c[0x42..0x42 + name_chars * 2]
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    let name = String::from_utf16_lossy(&units);
    if name.is_empty() {
        None
    } else {
        Some((name, parent, namespace))
    }
}

/// Parse a `$DATA` attribute (resident content or non-resident runs).
fn parse_data(attr: &[u8], non_resident: bool) -> Option<DataAttr> {
    if !non_resident {
        // Resident attribute header is 24 bytes.
        if attr.len() < 24 {
            return None;
        }
        let content_len = u32::from_le_bytes([attr[16], attr[17], attr[18], attr[19]]) as usize;
        let content_off = u16::from_le_bytes([attr[20], attr[21]]) as usize;
        if content_off + content_len > attr.len() {
            return None;
        }
        Some(DataAttr {
            size: content_len as u64,
            kind: DataKind::Resident(attr[content_off..content_off + content_len].to_vec()),
        })
    } else {
        // Non-resident header runs to offset 64 (run list offset @32, real
        // size @48).
        if attr.len() < 56 {
            return None;
        }
        let run_offset = u16::from_le_bytes([attr[32], attr[33]]) as usize;
        let real_size = u64::from_le_bytes([
            attr[48], attr[49], attr[50], attr[51], attr[52], attr[53], attr[54], attr[55],
        ]);
        if run_offset >= attr.len() {
            return None;
        }
        let runs = decode_data_runs(&attr[run_offset..]);
        if runs.is_empty() {
            return None;
        }
        Some(DataAttr {
            size: real_size,
            kind: DataKind::NonResident(runs),
        })
    }
}

/// Extract the `$MFT` `$DATA` runs and total size from record 0.
fn mft_data_extent(rec0: &[u8], _cluster_size: u64) -> Result<(Runs, u64)> {
    let parsed = parse_record(rec0).context("parsing $MFT record")?;
    match parsed.data {
        Some(DataAttr {
            size,
            kind: DataKind::NonResident(runs),
        }) => Ok((runs, size)),
        _ => bail!("$MFT $DATA is missing or resident"),
    }
}

/// Decode an NTFS data-run list into (absolute LCN or None, length) pairs.
fn decode_data_runs(data: &[u8]) -> Runs {
    let mut runs = Vec::new();
    let mut i = 0;
    let mut prev_lcn: i64 = 0;
    while i < data.len() {
        let header = data[i];
        if header == 0 {
            break;
        }
        i += 1;
        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = (header >> 4) as usize;
        if len_bytes == 0 || i + len_bytes + off_bytes > data.len() {
            break;
        }
        let mut length: u64 = 0;
        for k in 0..len_bytes {
            length |= (data[i + k] as u64) << (8 * k);
        }
        i += len_bytes;

        if off_bytes == 0 {
            runs.push((None, length)); // sparse
        } else {
            let mut off: i64 = 0;
            for k in 0..off_bytes {
                off |= (data[i + k] as i64) << (8 * k);
            }
            // Sign-extend the signed LCN delta.
            let shift = 64 - 8 * off_bytes as u32;
            off = (off << shift) >> shift;
            i += off_bytes;
            prev_lcn += off;
            runs.push((Some(prev_lcn), length));
        }
    }
    runs
}

/// Read `len` bytes starting at logical byte `start` across a run list.
fn read_runs_range(
    src: &Source,
    vol_offset: u64,
    cluster_size: u64,
    runs: &Runs,
    start: u64,
    len: u64,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(len as usize);
    let mut skip = start;
    let mut need = len;

    for &(lcn, count) in runs {
        if need == 0 {
            break;
        }
        let run_bytes = count * cluster_size;
        if skip >= run_bytes {
            skip -= run_bytes;
            continue;
        }
        let avail = run_bytes - skip;
        let take = avail.min(need);
        match lcn {
            None => out.resize(out.len() + take as usize, 0), // sparse
            Some(l) if l >= 0 => {
                // Read straight into the output buffer (no per-call temp).
                let disk = vol_offset
                    .saturating_add((l as u64).saturating_mul(cluster_size))
                    .saturating_add(skip);
                let base = out.len();
                out.resize(base + take as usize, 0);
                let n = src.read_at(disk, &mut out[base..])?;
                if (n as u64) < take {
                    out.truncate(base + n); // short read at end of source
                }
            }
            Some(_) => break,
        }
        need -= take;
        skip = 0;
    }
    Ok(out)
}

/// Apply the NTFS Update Sequence Array fixups in place. Every sector tail
/// must hold the update sequence number the array starts with: the driver
/// writes it there last, so a tail that differs is a torn write and the
/// record's attributes cannot be trusted. Returns `false` for such a
/// record, leaving it unchanged. A record with no array is left as it is.
fn apply_fixup(rec: &mut [u8], bytes_per_sector: usize) -> bool {
    if rec.len() < 8 {
        return true;
    }
    let usa_off = u16::from_le_bytes([rec[4], rec[5]]) as usize;
    let usa_count = u16::from_le_bytes([rec[6], rec[7]]) as usize;
    if usa_count == 0 || usa_off + 2 > rec.len() {
        return true;
    }
    let usn = [rec[usa_off], rec[usa_off + 1]];
    for i in 1..usa_count {
        let usa_pos = usa_off + i * 2;
        let sector_end = i * bytes_per_sector;
        if usa_pos + 2 > rec.len() || sector_end < 2 || sector_end > rec.len() {
            break;
        }
        if [rec[sector_end - 2], rec[sector_end - 1]] != usn {
            return false;
        }
    }
    for i in 1..usa_count {
        let usa_pos = usa_off + i * 2;
        let sector_end = i * bytes_per_sector;
        if usa_pos + 2 > rec.len() || sector_end < 2 || sector_end > rec.len() {
            break;
        }
        let val = [rec[usa_pos], rec[usa_pos + 1]];
        rec[sector_end - 2] = val[0];
        rec[sector_end - 1] = val[1];
    }
    true
}

/// Make a single path component safe to write to disk.
fn sanitize_component(name: &str) -> String {
    crate::recover::sanitize_component(name)
}

/// Build a non-colliding output path by appending a counter if needed.
fn unique_path(out_dir: &Path, rel: &Path) -> PathBuf {
    crate::recover::unique_path(out_dir, rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_runs_basic() {
        // header 0x11: 1 length byte, 1 offset byte. len=5, lcn=+10.
        let runs = decode_data_runs(&[0x11, 0x05, 0x0A, 0x00]);
        assert_eq!(runs, vec![(Some(10), 5)]);
    }

    #[test]
    fn decode_runs_sparse() {
        // header 0x01: 1 length byte, 0 offset bytes => sparse (hole).
        let runs = decode_data_runs(&[0x01, 0x03, 0x00]);
        assert_eq!(runs, vec![(None, 3)]);
    }

    #[test]
    fn decode_runs_negative_delta() {
        // Second run's offset 0xFF sign-extends to -1 (relative to the first).
        let runs = decode_data_runs(&[0x11, 0x04, 0x0A, 0x11, 0x02, 0xFF, 0x00]);
        assert_eq!(runs, vec![(Some(10), 4), (Some(9), 2)]);
    }

    #[test]
    fn decode_runs_multibyte_length() {
        // header 0x12: 2 length bytes, 1 offset byte. len=0x0100=256, lcn=10.
        let runs = decode_data_runs(&[0x12, 0x00, 0x01, 0x0A, 0x00]);
        assert_eq!(runs, vec![(Some(10), 256)]);
    }

    #[test]
    fn fixup_restores_sector_tails() {
        let mut rec = vec![0u8; 1024];
        rec[4..6].copy_from_slice(&48u16.to_le_bytes()); // USA offset
        rec[6..8].copy_from_slice(&3u16.to_le_bytes()); // USA count (1 + 2 sectors)
        rec[48] = 0x01; // USN
        rec[49] = 0x02;
        rec[50] = 0xAA; // USA[1]
        rec[51] = 0xBB;
        rec[52] = 0xCC; // USA[2]
        rec[53] = 0xDD;
        // The sector tails hold the sequence number, as written last.
        rec[510] = 0x01;
        rec[511] = 0x02;
        rec[1022] = 0x01;
        rec[1023] = 0x02;

        assert!(apply_fixup(&mut rec, 512));
        assert_eq!(&rec[510..512], &[0xAA, 0xBB]);
        assert_eq!(&rec[1022..1024], &[0xCC, 0xDD]);
    }

    #[test]
    fn fixup_rejects_a_torn_record_and_leaves_it_untouched() {
        let mut rec = vec![0u8; 1024];
        rec[4..6].copy_from_slice(&48u16.to_le_bytes());
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        rec[48..50].copy_from_slice(&[0x01, 0x02]);
        rec[50..52].copy_from_slice(&[0xAA, 0xBB]);
        rec[52..54].copy_from_slice(&[0xCC, 0xDD]);
        rec[510..512].copy_from_slice(&[0x01, 0x02]);
        rec[1022..1024].copy_from_slice(&[0x01, 0x03]); // stale: an older USN
        let before = rec.clone();
        assert!(!apply_fixup(&mut rec, 512));
        assert_eq!(rec, before, "a rejected record is not half-patched");
    }
}
