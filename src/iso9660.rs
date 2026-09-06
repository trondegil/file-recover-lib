//! ISO 9660 volume detection and file extraction (data CD/DVD discs and `.iso`
//! images).
//!
//! ISO 9660 is the classic optical-disc filesystem. Unlike UDF, its directory
//! structure is simple and read-only, so `unearth` both recognises it (in
//! `info`/`list_volumes`, with size and label) *and* extracts its files with
//! their original names and folder paths — which is far better than carving,
//! which loses both. Extraction walks the directory tree from the Primary Volume
//! Descriptor, or from the **Joliet** Supplementary Volume Descriptor when one
//! is present, so the long, Unicode (UCS-2) filenames that Windows-authored
//! discs use are recovered intact. On non-Joliet discs, **Rock Ridge** `NM`
//! entries (the POSIX-name extension used by Linux/macOS-authored media) are
//! decoded too, including names that spill into Rock Ridge continuation (`CE`)
//! areas, so even very long POSIX names are recovered in full. Files whose data
//! is split across several **multi-extent** directory records (how ISO 9660
//! stores files larger than ~4 GiB) are reassembled into one output file. A disc
//! carrying an **El Torito** boot record is reported as bootable, with the boot
//! platform(s) (BIOS / UEFI) read from its boot catalog.
//!
//! Detection reads the **Volume Descriptor Set** at sector 16 (byte offset
//! 32768): a series of 2048-byte descriptors each `{ type: u8, id: "CD001",
//! version: u8, ... }`. The **Primary Volume Descriptor** (type 1) carries the
//! volume identifier (label), the volume size (block count × block size), and
//! the root directory record. A UDF disc with an ISO bridge is detected as UDF
//! first (it has the additional `NSR` descriptor), so this only claims pure
//! ISO 9660.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::hash::HashingWriter;
use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// The Volume Descriptor Set begins at sector 16 with 2048-byte sectors.
const VDS_OFFSET: u64 = 16 * 2048;
const VD_SIZE: u64 = 2048;
const BOOT_RECORD: u8 = 0;
const PRIMARY: u8 = 1;
const SUPPLEMENTARY: u8 = 2;
const TERMINATOR: u8 = 255;
/// The boot-system identifier of an El Torito Boot Record descriptor (offset 7).
const EL_TORITO_ID: &[u8] = b"EL TORITO SPECIFICATION";
/// Bound the directory walk against malformed or hostile images.
const MAX_DEPTH: usize = 64;
const MAX_ENTRIES: u64 = 5_000_000;
/// Largest single directory extent we will read into memory.
const MAX_DIR_BYTES: u64 = 32 * 1024 * 1024;
/// Most `CE` continuation areas to follow for one name (a loop guard).
const MAX_CE_FOLLOW: usize = 8;

/// A multi-extent file being accumulated during the directory walk: its relative
/// path, the `(lba, byte length)` extents gathered so far, and the recording
/// time from its first directory record.
type PendingFile = (PathBuf, Vec<(u64, u64)>, Option<std::time::SystemTime>);

/// A recognised ISO 9660 volume.
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    label: String,
    block_size: u64,
    root_lba: u64,
    root_len: u64,
    /// Directory names are UCS-2 (Joliet) rather than short ISO 9660 identifiers.
    joliet: bool,
    /// A description of the disc's El Torito boot record (e.g.
    /// `"El Torito (BIOS, UEFI)"`), or `None` when the disc is not bootable.
    boot: Option<String>,
    /// Volume creation time from the PVD, Unix seconds; `None` when unset.
    created: Option<u64>,
    /// Volume modification time from the PVD, Unix seconds; `None` when unset.
    written: Option<u64>,
}

/// Recognise an ISO 9660 volume at `offset` by finding its Primary Volume
/// Descriptor. Returns `None` when no `CD001` Primary descriptor is present.
pub fn detect(src: &Source, offset: u64) -> Option<Volume> {
    let base = offset.checked_add(VDS_OFFSET)?;
    let mut primary: Option<Volume> = None;
    let mut joliet_root: Option<(u64, u64)> = None;
    let mut boot: Option<String> = None;
    for i in 0..16u64 {
        let pos = base.checked_add(i * VD_SIZE)?;
        let mut d = [0u8; 256];
        if src.read_at(pos, &mut d).ok()? < d.len() {
            break;
        }
        if &d[1..6] != b"CD001" {
            break; // not a volume descriptor: the set has ended
        }
        match d[0] {
            BOOT_RECORD if &d[7..7 + EL_TORITO_ID.len()] == EL_TORITO_ID => {
                boot = Some(read_el_torito(src, offset, &d));
            }
            PRIMARY => {
                let mut v = parse_primary(offset, src, &d);
                // Volume creation (offset 813) and modification (830) date/time
                // fields are 17 bytes each, beyond the 256 bytes read above.
                let mut dates = [0u8; 34];
                if src.read_at(pos + 813, &mut dates).unwrap_or(0) >= 34 {
                    v.created = crate::times::iso9660_datetime(&dates[0..17]);
                    v.written = crate::times::iso9660_datetime(&dates[17..34]);
                }
                primary = Some(v);
            }
            SUPPLEMENTARY if is_joliet(&d) => joliet_root = Some(root_record(&d)),
            TERMINATOR => break,
            _ => {} // non-Joliet supplementary / non-El-Torito boot: keep scanning
        }
    }
    let mut vol = primary?;
    // Prefer the Joliet directory tree: its names are the full Unicode names.
    if let Some((lba, len)) = joliet_root {
        vol.root_lba = lba;
        vol.root_len = len;
        vol.joliet = true;
    }
    vol.boot = boot;
    Some(vol)
}

/// Whether a Supplementary Volume Descriptor declares Joliet via its escape
/// sequences field (offset 88): `%/@`, `%/C`, or `%/E` for UCS-2 levels 1–3.
fn is_joliet(svd: &[u8]) -> bool {
    matches!(&svd[88..91], b"%/@" | b"%/C" | b"%/E")
}

/// Extent LBA and data length of the root Directory Record embedded at offset
/// 156 of a (primary or supplementary) volume descriptor.
fn root_record(vd: &[u8]) -> (u64, u64) {
    let r = &vd[156..];
    let lba = u32::from_le_bytes([r[2], r[3], r[4], r[5]]) as u64;
    let len = u32::from_le_bytes([r[10], r[11], r[12], r[13]]) as u64;
    (lba, len)
}

/// Build a [`Volume`] from a Primary Volume Descriptor's bytes.
fn parse_primary(offset: u64, src: &Source, pvd: &[u8]) -> Volume {
    // Volume Space Size (block count) is a both-endian u32 at offset 80; the
    // little-endian half is first. Logical Block Size is a both-endian u16 at
    // offset 128. Total size = block count × block size.
    let blocks = u32::from_le_bytes([pvd[80], pvd[81], pvd[82], pvd[83]]) as u64;
    let block_size = u16::from_le_bytes([pvd[128], pvd[129]]) as u64;
    let computed = blocks.checked_mul(block_size).unwrap_or(0);
    let size = if computed == 0 {
        src.size.saturating_sub(offset)
    } else {
        computed
    };
    // Volume Identifier: 32 d-characters at offset 40, space/NUL padded.
    let raw = &pvd[40..72];
    let end = raw
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |p| p + 1);
    let label = String::from_utf8_lossy(&raw[..end]).trim().to_string();
    let (root_lba, root_len) = root_record(pvd);
    Volume {
        offset,
        size,
        label,
        block_size,
        root_lba,
        root_len,
        joliet: false,
        boot: None,
        created: None,
        written: None,
    }
}

/// Read the El Torito boot catalog referenced by the Boot Record descriptor `d`
/// and describe the boot platforms, e.g. `"El Torito (BIOS, UEFI)"`. Falls back
/// to `"El Torito"` if the catalog can't be read or no platform resolves.
fn read_el_torito(src: &Source, offset: u64, d: &[u8]) -> String {
    let plain = || "El Torito".to_string();
    // Boot System Use: the boot catalog's LBA is a u32 (LE) at offset 71.
    let cat_lba = u32::from_le_bytes([d[71], d[72], d[73], d[74]]) as u64;
    let Some(cat_byte) = cat_lba
        .checked_mul(2048)
        .and_then(|b| offset.checked_add(b))
    else {
        return plain();
    };
    let mut cat = [0u8; 2048];
    if src.read_at(cat_byte, &mut cat).unwrap_or(0) < 64 {
        return plain();
    }
    // The validation entry: header id 1, ending in the 0x55 0xAA key.
    if cat[0] != 1 || cat[30] != 0x55 || cat[31] != 0xAA {
        return plain();
    }
    let mut platforms: Vec<&'static str> = Vec::new();
    // The validation entry's platform is the one the default entry boots.
    push_platform(&mut platforms, cat[1]);
    // Section headers (0x90 = more follow, 0x91 = last) each name a platform and
    // count the section entries that follow them; walk past those to the next.
    let mut pos = 64; // skip the validation entry and the default entry
    for _ in 0..64 {
        if pos + 32 > cat.len() {
            break;
        }
        let id = cat[pos];
        if id != 0x90 && id != 0x91 {
            break;
        }
        push_platform(&mut platforms, cat[pos + 1]);
        let entries = u16::from_le_bytes([cat[pos + 2], cat[pos + 3]]) as usize;
        pos += 32 + entries * 32;
        if id == 0x91 {
            break; // final header
        }
    }
    format!("El Torito ({})", platforms.join(", "))
}

/// Add a platform name for an El Torito platform id, avoiding duplicates.
fn push_platform(platforms: &mut Vec<&'static str>, platform_id: u8) {
    let name = match platform_id {
        0x00 => "BIOS",
        0x01 => "PowerPC",
        0x02 => "Mac",
        0xEF => "UEFI",
        _ => "other",
    };
    if !platforms.contains(&name) {
        platforms.push(name);
    }
}

impl Volume {
    /// Parse an ISO 9660 volume at `offset`, failing if it is not one.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        match detect(src, offset) {
            Some(v) => Ok(v),
            None => bail!("not a recognised ISO 9660 volume"),
        }
    }

    /// Size of the volume in bytes (block count × block size from the PVD).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The logical block size in bytes (from the PVD, normally 2048).
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    /// Volume creation time (PVD) as Unix seconds, or `None` when unset.
    pub fn created_time(&self) -> Option<u64> {
        self.created
    }

    /// Volume modification time (PVD) as Unix seconds, or `None` when unset.
    pub fn written_time(&self) -> Option<u64> {
        self.written
    }

    /// Filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "ISO 9660"
    }

    /// The volume identifier from the Primary Volume Descriptor (may be empty).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// A short description of the disc's boot capability (e.g.
    /// `"El Torito (BIOS, UEFI)"`), or `None` when the disc is not bootable.
    pub fn boot_info(&self) -> Option<&str> {
        self.boot.as_deref()
    }

    /// Extract every file from the volume into `out_dir`, preserving names and
    /// folder paths by walking the directory tree from the root record. (ISO
    /// 9660 is read-only, so "recover" here means extract the live files; the
    /// method name matches the other backends for a uniform dispatch.)
    pub fn recover_deleted(
        &self,
        src: &Source,
        out_dir: &Path,
        opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        let mut stats = RecoverStats::default();
        // A sane block size is required to translate LBAs to byte offsets.
        if !(512..=65536).contains(&self.block_size) || self.root_len == 0 {
            return Ok(stats);
        }
        let vol_end = self.offset.saturating_add(self.size).min(src.size);

        let mut visited: HashSet<u64> = HashSet::new();
        let mut entries = 0u64;
        // Stack of directories to walk: (extent LBA, byte length, relative path,
        // depth).
        let mut stack: Vec<(u64, u64, PathBuf, usize)> =
            vec![(self.root_lba, self.root_len, PathBuf::new(), 0)];

        while let Some((lba, len, rel, depth)) = stack.pop() {
            if !visited.insert(lba) || entries >= MAX_ENTRIES {
                continue; // already walked, or run-away guard tripped
            }
            let Some(dir) = self.read_extent(src, lba, len, vol_end) else {
                continue; // extent out of bounds or unreadable
            };

            let mut pos = 0usize;
            // Extents of a multi-extent file in progress: such a file's data is
            // split across several consecutive directory records that share one
            // name, all but the last flagged "more extents to follow" (file-flag
            // bit 7). `None` between files.
            let mut pending: Option<PendingFile> = None;
            while pos < dir.len() {
                let rec_len = dir[pos] as usize;
                if rec_len == 0 {
                    // Records do not span sectors; a zero length is padding to
                    // the next logical block.
                    let next = (pos / self.block_size as usize + 1) * self.block_size as usize;
                    pos = next;
                    continue;
                }
                if pos + rec_len > dir.len() || rec_len < 33 {
                    break;
                }
                entries += 1;
                let rec = &dir[pos..pos + rec_len];
                pos += rec_len;

                let name_len = rec[32] as usize;
                if 33 + name_len > rec.len() {
                    continue;
                }
                let name_bytes = &rec[33..33 + name_len];
                // The "." and ".." entries use single bytes 0x00 and 0x01.
                if name_len == 1 && (name_bytes[0] == 0 || name_bytes[0] == 1) {
                    continue;
                }
                let child_lba = u32::from_le_bytes([rec[2], rec[3], rec[4], rec[5]]) as u64;
                let child_len = u32::from_le_bytes([rec[10], rec[11], rec[12], rec[13]]) as u64;
                let flags = rec[25];
                let is_dir = flags & 0x02 != 0;
                let more_extents = flags & 0x80 != 0;

                // A continuation record of a multi-extent file already in
                // progress: append its extent (the name comes from the first
                // record) and flush once the final record clears the flag.
                if let Some((_, extents, _)) = pending.as_mut() {
                    if !is_dir {
                        extents.push((child_lba, child_len));
                        if !more_extents {
                            let (frel, fexts, fmtime) = pending.take().unwrap();
                            self.recover_file(
                                src, out_dir, &fexts, frel, fmtime, vol_end, opts, &mut stats,
                            );
                        }
                        continue;
                    }
                    // Malformed: a directory record interrupts the sequence.
                    // Flush what we have, then handle this record normally.
                    let (frel, fexts, fmtime) = pending.take().unwrap();
                    self.recover_file(
                        src, out_dir, &fexts, frel, fmtime, vol_end, opts, &mut stats,
                    );
                }

                // Prefer a Rock Ridge POSIX name (Linux/Unix discs) over the
                // short ISO identifier; Joliet (Windows) already has long names.
                let name = match (
                    self.joliet,
                    self.rock_ridge_name(src, rec, name_len, vol_end),
                ) {
                    (false, Some(rr)) => sanitize_component(&rr),
                    _ => decode_name(name_bytes, is_dir, self.joliet),
                };
                let child_rel = rel.join(&name);

                if is_dir {
                    if depth + 1 < MAX_DEPTH {
                        stack.push((child_lba, child_len, child_rel, depth + 1));
                    }
                    continue;
                }
                // Recording date/time: a 7-byte field at record offset 18.
                let mtime = crate::times::from_iso9660_dir(&rec[18..25]);
                if more_extents {
                    // First record of a multi-extent file: start accumulating
                    // its extents; later records append until one clears the flag.
                    pending = Some((child_rel, vec![(child_lba, child_len)], mtime));
                    continue;
                }
                self.recover_file(
                    src,
                    out_dir,
                    &[(child_lba, child_len)],
                    child_rel,
                    mtime,
                    vol_end,
                    opts,
                    &mut stats,
                );
            }
            // Flush a multi-extent file whose final record never arrived.
            if let Some((frel, fexts, fmtime)) = pending.take() {
                self.recover_file(
                    src, out_dir, &fexts, frel, fmtime, vol_end, opts, &mut stats,
                );
            }
        }
        Ok(stats)
    }

    /// Read a directory extent (`lba`/`len`) into memory, or `None` if it falls
    /// outside the volume or is implausibly large.
    fn read_extent(&self, src: &Source, lba: u64, len: u64, vol_end: u64) -> Option<Vec<u8>> {
        if len == 0 || len > MAX_DIR_BYTES {
            return None;
        }
        let start = self.offset.checked_add(lba.checked_mul(self.block_size)?)?;
        if start < self.offset || start.checked_add(len)? > vol_end {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        let n = src.read_at(start, &mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }

    /// Extract one file into `out_dir`, recording it in `stats` (or counting it
    /// for a dry run). `extents` is `(lba, byte length)` pairs; a normal file has
    /// one, a multi-extent file has several that are concatenated in order.
    #[allow(clippy::too_many_arguments)]
    fn recover_file(
        &self,
        src: &Source,
        out_dir: &Path,
        extents: &[(u64, u64)],
        rel: PathBuf,
        mtime: Option<std::time::SystemTime>,
        vol_end: u64,
        opts: &RecoverOptions,
        stats: &mut RecoverStats,
    ) {
        let total = extents
            .iter()
            .fold(0u64, |acc, &(_, len)| acc.saturating_add(len));
        if !opts.size_ok(total) || !opts.name_ok(crate::recover::file_name_of(&rel)) {
            return;
        }
        // Translate each extent to a byte range and validate it lies inside the
        // volume before trusting any of it.
        let mut byte_extents = Vec::with_capacity(extents.len());
        for &(lba, len) in extents {
            match self.offset.checked_add(lba.saturating_mul(self.block_size)) {
                Some(s) if s >= self.offset && s.saturating_add(len) <= vol_end => {
                    byte_extents.push((s, len));
                }
                _ => {
                    stats.record_skipped(rel, total);
                    return;
                }
            }
        }
        if opts.dry_run {
            stats.record_recovered(rel, total, None);
            return;
        }
        match write_file(src, out_dir, &rel, &byte_extents, mtime) {
            Ok(digest) => stats.record_recovered(rel, total, Some(digest)),
            Err(_) => stats.record_skipped(rel, total),
        }
    }

    /// Extract a Rock Ridge POSIX name from a directory record's System Use area,
    /// following `CE` continuation areas (read via `src`) when the `NM` name
    /// overflows the record. Returns `None` when there is no Rock Ridge name (so
    /// the caller falls back to the ISO 9660 identifier).
    fn rock_ridge_name(
        &self,
        src: &Source,
        rec: &[u8],
        name_len: usize,
        vol_end: u64,
    ) -> Option<String> {
        // The System Use area begins after the file identifier, padded so it
        // starts on an even offset (a pad byte is present when the name length
        // is even).
        let start = 33 + name_len + usize::from(name_len % 2 == 0);
        if start >= rec.len() {
            return None;
        }
        let mut name = String::new();
        let mut complete = false;
        let mut area: Vec<u8> = rec[start..].to_vec();
        // Parse the in-record area, then follow each `CE` continuation in turn,
        // bounded so a self-referential chain can't loop forever.
        for _ in 0..=MAX_CE_FOLLOW {
            let next = scan_susp_area(&area, &mut name, &mut complete);
            match next {
                Some((lba, off, len)) if !complete => {
                    let Some(buf) = self.read_continuation(src, lba, off, len, vol_end) else {
                        break;
                    };
                    area = buf;
                }
                _ => break,
            }
        }
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Read a SUSP continuation area: `len` bytes at byte `offset` within logical
    /// block `lba`. `None` if it falls outside the volume or is implausibly large.
    fn read_continuation(
        &self,
        src: &Source,
        lba: u64,
        offset: usize,
        len: usize,
        vol_end: u64,
    ) -> Option<Vec<u8>> {
        if len == 0 || len as u64 > MAX_DIR_BYTES {
            return None;
        }
        let base = self.offset.checked_add(lba.checked_mul(self.block_size)?)?;
        let start = base.checked_add(offset as u64)?;
        if start < self.offset || start.checked_add(len as u64)? > vol_end {
            return None;
        }
        let mut buf = vec![0u8; len];
        let n = src.read_at(start, &mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }
}

/// Scan one SUSP System Use area: append each `NM` (alternate name) fragment to
/// `name`, and return the location of a `CE` continuation area to follow next
/// (logical block, byte offset, length) if one is present. Sets `complete` once
/// an `NM` entry without the CONTINUE flag ends the name, so the caller stops
/// following continuations. An `ST` entry terminates the area early.
fn scan_susp_area(
    area: &[u8],
    name: &mut String,
    complete: &mut bool,
) -> Option<(u64, usize, usize)> {
    let mut pos = 0usize;
    let mut ce = None;
    while pos + 4 <= area.len() {
        let su_len = area[pos + 2] as usize;
        if su_len < 4 || pos + su_len > area.len() {
            break;
        }
        match &area[pos..pos + 2] {
            b"NM" if su_len >= 5 => {
                let flags = area[pos + 4];
                // Skip the "current" (.) and "parent" (..) name entries.
                if flags & 0x06 == 0 {
                    name.push_str(&String::from_utf8_lossy(&area[pos + 5..pos + su_len]));
                    // Bit 0 (CONTINUE) set means the name spills into a later
                    // `NM` entry, possibly in a continuation area.
                    if flags & 0x01 == 0 {
                        *complete = true;
                    }
                }
            }
            b"CE" if su_len >= 28 => {
                // BLOCK LOCATION, OFFSET, and LENGTH are each 8-byte both-endian
                // (ISO 9660 7.3.3) fields; read the little-endian half of each.
                let lba = u32::from_le_bytes([
                    area[pos + 4],
                    area[pos + 5],
                    area[pos + 6],
                    area[pos + 7],
                ]) as u64;
                let off = u32::from_le_bytes([
                    area[pos + 12],
                    area[pos + 13],
                    area[pos + 14],
                    area[pos + 15],
                ]) as usize;
                let len = u32::from_le_bytes([
                    area[pos + 20],
                    area[pos + 21],
                    area[pos + 22],
                    area[pos + 23],
                ]) as usize;
                ce = Some((lba, off, len));
            }
            b"ST" => break,
            _ => {}
        }
        pos += su_len;
    }
    ce
}

/// Decode a directory-record file identifier: UCS-2 big-endian for Joliet, else
/// ASCII d-characters. Strips the `;version` suffix and a single trailing `.`
/// from files, and sanitises the result into a safe path component.
fn decode_name(bytes: &[u8], is_dir: bool, joliet: bool) -> String {
    let mut s = if joliet {
        // Joliet names are UCS-2 (UTF-16) big-endian.
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    };
    if !is_dir {
        if let Some(semi) = s.find(';') {
            s.truncate(semi);
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
    sanitize_component(&s)
}

/// Stream a sequence of byte `extents` (`(start, len)`) into `out_dir/rel` as one
/// file, concatenated in order, returning the SHA-256 of the written bytes. A
/// normal file has a single extent; a multi-extent file has several.
fn write_file(
    src: &Source,
    out_dir: &Path,
    rel: &Path,
    extents: &[(u64, u64)],
    mtime: Option<std::time::SystemTime>,
) -> Result<[u8; 32]> {
    let (_target, file) = crate::recover::create_output_file(out_dir, rel)?;
    let mut out = HashingWriter::new(file);

    let mut buf = vec![0u8; 1024 * 1024];
    for &(start, len) in extents {
        let mut remaining = len;
        let mut pos = start;
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
    }
    out.flush().ok();
    let (file, digest) = out.into_parts();
    // Preserve the file's recording date from the directory record.
    crate::times::apply(&file, mtime, None);
    Ok(digest)
}

/// Map a name to a safe single path component (no separators or control chars).
fn sanitize_component(name: &str) -> String {
    crate::recover::sanitize_component(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("i.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    /// Write a volume descriptor of `vtype` (with the `CD001` identifier) at
    /// sector `16 + index`, returning its byte offset for further field writes.
    fn put_descriptor(v: &mut [u8], index: u64, vtype: u8) -> usize {
        let off = (VDS_OFFSET + index * VD_SIZE) as usize;
        v[off] = vtype;
        v[off + 1..off + 6].copy_from_slice(b"CD001");
        v[off + 6] = 1;
        off
    }

    /// Write a directory record at `buf[at..]` and return its length.
    fn put_record(
        buf: &mut [u8],
        at: usize,
        lba: u32,
        len: u32,
        is_dir: bool,
        name: &[u8],
    ) -> usize {
        let rec_len = 33 + name.len() + (name.len() % 2 == 0) as usize; // padded to even
        buf[at] = rec_len as u8;
        buf[at + 2..at + 6].copy_from_slice(&lba.to_le_bytes());
        buf[at + 10..at + 14].copy_from_slice(&len.to_le_bytes());
        // Recording date/time (offset 18): 2021-01-01 00:00:00 GMT.
        buf[at + 18] = 121; // year - 1900
        buf[at + 19] = 1; // month
        buf[at + 20] = 1; // day
        buf[at + 25] = if is_dir { 0x02 } else { 0 };
        buf[at + 32] = name.len() as u8;
        buf[at + 33..at + 33 + name.len()].copy_from_slice(name);
        rec_len
    }

    /// Write a directory record with a Rock Ridge `NM` entry in its System Use
    /// area, returning its length.
    fn put_record_rr(
        buf: &mut [u8],
        at: usize,
        lba: u32,
        len: u32,
        name: &[u8],
        rr_name: &[u8],
    ) -> usize {
        let su = 33 + name.len() + (name.len() % 2 == 0) as usize; // system-use start
        let nm = 5 + rr_name.len(); // NM entry length
        let rec_len = su + nm + ((su + nm) % 2); // pad whole record to even
        buf[at] = rec_len as u8;
        buf[at + 2..at + 6].copy_from_slice(&lba.to_le_bytes());
        buf[at + 10..at + 14].copy_from_slice(&len.to_le_bytes());
        buf[at + 32] = name.len() as u8;
        buf[at + 33..at + 33 + name.len()].copy_from_slice(name);
        // NM entry: "NM", length, version, flags, name.
        let e = at + su;
        buf[e] = b'N';
        buf[e + 1] = b'M';
        buf[e + 2] = nm as u8;
        buf[e + 3] = 1;
        buf[e + 4] = 0; // flags
        buf[e + 5..e + 5 + rr_name.len()].copy_from_slice(rr_name);
        rec_len
    }

    #[test]
    fn detects_primary_with_size_and_label() {
        let mut v = vec![0u8; (VDS_OFFSET + 4 * VD_SIZE) as usize];
        let off = put_descriptor(&mut v, 0, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&100u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&2048u16.to_le_bytes());
        v[off + 40..off + 40 + 11].copy_from_slice(b"UBUNTU_2204");

        let (_t, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        assert_eq!(vol.fs_label(), "ISO 9660");
        assert_eq!(vol.size(), 100 * 2048);
        assert_eq!(vol.label(), "UBUNTU_2204");
        assert_eq!(vol.boot_info(), None, "no boot record => not bootable");
    }

    #[test]
    fn detects_el_torito_bootable() {
        const BS: usize = 2048;
        let mut v = vec![0u8; 22 * BS];
        let off = put_descriptor(&mut v, 0, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&100u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&2048u16.to_le_bytes());
        // A Boot Record descriptor (type 0) with the El Torito identifier and a
        // pointer to the boot catalog at LBA 19.
        let boff = put_descriptor(&mut v, 1, BOOT_RECORD);
        v[boff + 7..boff + 7 + EL_TORITO_ID.len()].copy_from_slice(EL_TORITO_ID);
        v[boff + 71..boff + 75].copy_from_slice(&19u32.to_le_bytes());

        // Boot catalog at LBA 19: validation entry (BIOS), default entry, then a
        // final section header for UEFI with one section entry.
        let c = 19 * BS;
        v[c] = 1; // validation header id
        v[c + 1] = 0x00; // platform: BIOS
        v[c + 30] = 0x55;
        v[c + 31] = 0xAA;
        v[c + 32] = 0x88; // default entry: bootable
        v[c + 64] = 0x91; // final section header
        v[c + 65] = 0xEF; // platform: UEFI
        v[c + 66..c + 68].copy_from_slice(&1u16.to_le_bytes()); // one section entry

        let (_t, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        assert_eq!(vol.boot_info(), Some("El Torito (BIOS, UEFI)"));
    }

    #[test]
    fn el_torito_without_catalog_is_plain() {
        let mut v = vec![0u8; (VDS_OFFSET + 4 * VD_SIZE) as usize];
        let off = put_descriptor(&mut v, 0, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&100u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&2048u16.to_le_bytes());
        // A boot record with the El Torito id but a catalog pointer to nowhere.
        let boff = put_descriptor(&mut v, 1, BOOT_RECORD);
        v[boff + 7..boff + 7 + EL_TORITO_ID.len()].copy_from_slice(EL_TORITO_ID);

        let (_t, src) = source_of(&v);
        assert_eq!(detect(&src, 0).unwrap().boot_info(), Some("El Torito"));
    }

    #[test]
    fn rejects_non_iso_data() {
        let (_t, src) = source_of(&vec![0u8; (VDS_OFFSET + 4 * VD_SIZE) as usize]);
        assert!(detect(&src, 0).is_none());
        assert!(Volume::parse(&src, 0).is_err());
    }

    #[test]
    fn extracts_files_with_names_and_paths() {
        const BS: usize = 2048;
        // Layout: sector 16 = PVD; sector 18 = root dir; sector 19 = subdir;
        // sector 20 = HELLO.TXT data; sector 21 = NOTE.TXT data.
        let total = 22 * BS;
        let mut v = vec![0u8; total];

        let payload_hello = b"hello iso";
        let payload_note = b"a note in a subdir";
        v[20 * BS..20 * BS + payload_hello.len()].copy_from_slice(payload_hello);
        v[21 * BS..21 * BS + payload_note.len()].copy_from_slice(payload_note);

        // Root directory (sector 18): ".", "..", HELLO.TXT;1, SUB (dir).
        let root = 18 * BS;
        let mut p = root;
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x00]);
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x01]);
        p += put_record(
            &mut v,
            p,
            20,
            payload_hello.len() as u32,
            false,
            b"HELLO.TXT;1",
        );
        let _ = put_record(&mut v, p, 19, BS as u32, true, b"SUB");

        // Subdirectory (sector 19): ".", "..", NOTE.TXT;1.
        let sub = 19 * BS;
        let mut q = sub;
        q += put_record(&mut v, q, 19, BS as u32, true, &[0x00]);
        q += put_record(&mut v, q, 18, BS as u32, true, &[0x01]);
        let _ = put_record(
            &mut v,
            q,
            21,
            payload_note.len() as u32,
            false,
            b"NOTE.TXT;1",
        );

        // PVD (sector 16): block size, volume size, and the root record at +156.
        let off = put_descriptor(&mut v, 0, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&22u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&(BS as u16).to_le_bytes());
        // Root directory record embedded in the PVD: extent = sector 18.
        put_record(&mut v, off + 156, 18, BS as u32, true, &[0x00]);

        let (tmp, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        let out = tmp.path().join("out");
        let stats = vol
            .recover_deleted(&src, &out, &RecoverOptions::default())
            .unwrap();

        assert_eq!(stats.recovered, 2, "two files extracted");
        assert_eq!(std::fs::read(out.join("HELLO.TXT")).unwrap(), payload_hello);
        // The recording date (2021-01-01) is preserved on the extracted file.
        let mtime = std::fs::metadata(out.join("HELLO.TXT"))
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(mtime, 18628 * 86400);
        assert_eq!(
            std::fs::read(out.join("SUB").join("NOTE.TXT")).unwrap(),
            payload_note,
            "file recovered under its subdirectory path"
        );
    }

    /// Encode a string as UCS-2 big-endian, as Joliet stores names.
    fn ucs2_be(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
    }

    #[test]
    fn joliet_long_names_are_preferred() {
        const BS: usize = 2048;
        // sector 16 = PVD, 17 = Joliet SVD, 18 = primary root, 19 = Joliet root,
        // 20 = file data.
        let total = 22 * BS;
        let mut v = vec![0u8; total];
        let payload = b"joliet payload";
        v[20 * BS..20 * BS + payload.len()].copy_from_slice(payload);

        // Primary root (sector 18): the short 8.3 name.
        let mut p = 18 * BS;
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x00]);
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x01]);
        let _ = put_record(
            &mut v,
            p,
            20,
            payload.len() as u32,
            false,
            b"MYPHOT~1.JPG;1",
        );

        // Joliet root (sector 19): the full Unicode name (UCS-2 BE).
        let mut q = 19 * BS;
        q += put_record(&mut v, q, 19, BS as u32, true, &[0x00]);
        q += put_record(&mut v, q, 18, BS as u32, true, &[0x01]);
        let jname = ucs2_be("My Photo.jpg;1");
        let _ = put_record(&mut v, q, 20, payload.len() as u32, false, &jname);

        // PVD (sector 16): root at sector 18.
        let off = put_descriptor(&mut v, 0, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&22u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&(BS as u16).to_le_bytes());
        put_record(&mut v, off + 156, 18, BS as u32, true, &[0x00]);

        // Joliet SVD (sector 17): escape sequence "%/E" and root at sector 19.
        let soff = put_descriptor(&mut v, 1, SUPPLEMENTARY);
        v[soff + 88..soff + 91].copy_from_slice(b"%/E");
        v[soff + 128..soff + 130].copy_from_slice(&(BS as u16).to_le_bytes());
        put_record(&mut v, soff + 156, 19, BS as u32, true, &[0x00]);

        let (tmp, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        let out = tmp.path().join("out");
        let stats = vol
            .recover_deleted(&src, &out, &RecoverOptions::default())
            .unwrap();

        assert_eq!(stats.recovered, 1);
        // The Joliet long name is used, not the short MYPHOT~1.JPG.
        assert_eq!(std::fs::read(out.join("My Photo.jpg")).unwrap(), payload);
    }

    #[test]
    fn rock_ridge_names_are_used_on_non_joliet_discs() {
        const BS: usize = 2048;
        // sector 16 = PVD, 18 = root dir, 20 = file data.
        let total = 22 * BS;
        let mut v = vec![0u8; total];
        let payload = b"rock ridge payload";
        v[20 * BS..20 * BS + payload.len()].copy_from_slice(payload);

        // Root (sector 18): ".", "..", then a file with a short name plus a
        // Rock Ridge NM entry carrying the real POSIX name.
        let mut p = 18 * BS;
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x00]);
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x01]);
        let _ = put_record_rr(
            &mut v,
            p,
            20,
            payload.len() as u32,
            b"NOTES.TXT;1",
            b"My Notes (draft).txt",
        );

        // PVD (sector 16), no Joliet SVD.
        let off = put_descriptor(&mut v, 0, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&22u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&(BS as u16).to_le_bytes());
        put_record(&mut v, off + 156, 18, BS as u32, true, &[0x00]);

        let (tmp, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        let out = tmp.path().join("out");
        let stats = vol
            .recover_deleted(&src, &out, &RecoverOptions::default())
            .unwrap();

        assert_eq!(stats.recovered, 1);
        // The Rock Ridge name wins over the short NOTES.TXT.
        assert_eq!(
            std::fs::read(out.join("My Notes (draft).txt")).unwrap(),
            payload
        );
    }

    #[test]
    fn rock_ridge_names_follow_ce_continuation() {
        const BS: usize = 2048;
        // sector 16 = PVD, 18 = root dir, 20 = file data, 21 = CE continuation.
        let total = 22 * BS;
        let mut v = vec![0u8; total];
        let payload = b"continued name payload";
        v[20 * BS..20 * BS + payload.len()].copy_from_slice(payload);

        let part1 = b"My very "; // in the record's NM (CONTINUE set)
        let part2 = b"long file name.txt"; // in the CE continuation area's NM

        // Root (sector 18): ".", "..", then a file whose Rock Ridge name spills
        // out of the record into a CE continuation area.
        let mut p = 18 * BS;
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x00]);
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x01]);

        // Build the file record by hand: short name + NM(CONTINUE, part1) + CE.
        let name: &[u8] = b"LONG.TXT;1";
        let su = 33 + name.len() + (name.len() % 2 == 0) as usize;
        let nm_len = 5 + part1.len();
        let body = su + nm_len + 28; // + a 28-byte CE entry
        let rec_len = body + (body % 2);
        let at = p;
        v[at] = rec_len as u8;
        v[at + 2..at + 6].copy_from_slice(&20u32.to_le_bytes());
        v[at + 10..at + 14].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        v[at + 32] = name.len() as u8;
        v[at + 33..at + 33 + name.len()].copy_from_slice(name);
        // NM (CONTINUE) entry holding the first half of the name.
        let e = at + su;
        v[e] = b'N';
        v[e + 1] = b'M';
        v[e + 2] = nm_len as u8;
        v[e + 3] = 1;
        v[e + 4] = 0x01; // CONTINUE: the name spills into the next NM
        v[e + 5..e + 5 + part1.len()].copy_from_slice(part1);
        // CE entry pointing at sector 21, offset 0, covering the trailing NM.
        let c = e + nm_len;
        let cont_len = 5 + part2.len();
        v[c] = b'C';
        v[c + 1] = b'E';
        v[c + 2] = 28;
        v[c + 3] = 1;
        v[c + 4..c + 8].copy_from_slice(&21u32.to_le_bytes()); // BLOCK LOCATION (LE half)
        v[c + 12..c + 16].copy_from_slice(&0u32.to_le_bytes()); // OFFSET (LE half)
        v[c + 20..c + 24].copy_from_slice(&(cont_len as u32).to_le_bytes()); // LENGTH (LE half)

        // Continuation area (sector 21, offset 0): the trailing NM (no CONTINUE).
        let k = 21 * BS;
        v[k] = b'N';
        v[k + 1] = b'M';
        v[k + 2] = cont_len as u8;
        v[k + 3] = 1;
        v[k + 4] = 0x00;
        v[k + 5..k + 5 + part2.len()].copy_from_slice(part2);

        // PVD (sector 16), no Joliet SVD.
        let off = put_descriptor(&mut v, 0, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&22u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&(BS as u16).to_le_bytes());
        put_record(&mut v, off + 156, 18, BS as u32, true, &[0x00]);

        let (tmp, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        let out = tmp.path().join("out");
        let stats = vol
            .recover_deleted(&src, &out, &RecoverOptions::default())
            .unwrap();

        assert_eq!(stats.recovered, 1);
        // The full name is reassembled from the record's NM and the CE area's NM.
        assert_eq!(
            std::fs::read(out.join("My very long file name.txt")).unwrap(),
            payload
        );
    }

    #[test]
    fn multi_extent_files_are_concatenated() {
        const BS: usize = 2048;
        // sector 16 = PVD, 18 = root dir, 20 = data extent A, 21 = data extent B.
        let total = 22 * BS;
        let mut v = vec![0u8; total];
        let part_a = b"first half of a big file";
        let part_b = b"-second half of a big file";
        v[20 * BS..20 * BS + part_a.len()].copy_from_slice(part_a);
        v[21 * BS..21 * BS + part_b.len()].copy_from_slice(part_b);

        // Root (sector 18): ".", "..", then one file in two records — the first
        // flagged multi-extent (more data follows), the second the final extent.
        let mut p = 18 * BS;
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x00]);
        p += put_record(&mut v, p, 18, BS as u32, true, &[0x01]);
        let a_at = p;
        p += put_record(&mut v, p, 20, part_a.len() as u32, false, b"BIG.DAT;1");
        v[a_at + 25] |= 0x80; // multi-extent: data continues in the next record
        let _ = put_record(&mut v, p, 21, part_b.len() as u32, false, b"BIG.DAT;1");

        // PVD (sector 16), no Joliet SVD.
        let off = put_descriptor(&mut v, 0, PRIMARY);
        v[off + 80..off + 84].copy_from_slice(&22u32.to_le_bytes());
        v[off + 128..off + 130].copy_from_slice(&(BS as u16).to_le_bytes());
        put_record(&mut v, off + 156, 18, BS as u32, true, &[0x00]);

        let (tmp, src) = source_of(&v);
        let vol = detect(&src, 0).unwrap();
        let out = tmp.path().join("out");
        let stats = vol
            .recover_deleted(&src, &out, &RecoverOptions::default())
            .unwrap();

        // One file, not two fragments; both extents concatenated in order.
        assert_eq!(stats.recovered, 1);
        let mut expected = part_a.to_vec();
        expected.extend_from_slice(part_b);
        assert_eq!(std::fs::read(out.join("BIG.DAT")).unwrap(), expected);
    }
}
