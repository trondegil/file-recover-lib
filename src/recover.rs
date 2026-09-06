//! Unified entry point for filesystem-aware undelete.
//!
//! Detects the filesystem of each volume in a source and dispatches to the
//! appropriate recovery backend ([`crate::fat`], [`crate::exfat`],
//! [`crate::ntfs`], [`crate::ext4`], or [`crate::hfsplus`]), so the `undelete`
//! command can treat every supported filesystem the same way. APFS containers
//! ([`crate::apfs`]), Btrfs volumes ([`crate::btrfs`]), ReFS volumes
//! ([`crate::refs`]), XFS volumes ([`crate::xfs`]), and F2FS volumes
//! ([`crate::f2fs`]) are recognised for reporting but not recovered from
//! metadata — their copy-on-write, log-structured, or zero-on-delete design
//! leaves no stale metadata to scavenge, so carving (`scan`) is the fallback
//! there. LVM2 physical volumes ([`crate::lvm`]) are likewise recognised and
//! reported, but their logical volumes are not mapped, so a whole-source `scan`
//! is the way to recover the filesystems inside them.
//! UDF volumes ([`crate::udf`]) are likewise recognised and reported but carved
//! rather than recovered from metadata. ISO 9660 discs ([`crate::iso9660`]:
//! optical media and `.iso` images) are read-only, so their files *are* extracted
//! with original names and paths by walking the directory tree. Encrypted
//! containers
//! ([`crate::encrypted`]: LUKS, BitLocker) are recognised so the user is told to
//! unlock them first; nothing can be read until then.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{bail, Result};

use crate::source::Source;
use crate::{
    apfs, bcachefs, befs, btrfs, cramfs, encrypted, erofs, exfat, ext4, f2fs, fat, gfs2, hfs,
    hfsplus, iso9660, jfs, lvm, mdraid, minix, nilfs2, ntfs, ocfs2, refs, reiserfs, romfs, swap,
    udf, ufs, xfs,
};

/// Options controlling a recovery run.
#[derive(Clone, Default)]
pub struct RecoverOptions {
    /// Ignore deleted files smaller than this many bytes.
    pub min_size: u64,
    /// Ignore deleted files larger than this many bytes (`None` = no cap).
    pub max_size: Option<u64>,
    /// Only recover files modified at or after this time (`None` = no bound).
    pub modified_after: Option<SystemTime>,
    /// Only recover files modified at or before this time (`None` = no bound).
    pub modified_before: Option<SystemTime>,
    /// Only recover files whose name matches one of these glob patterns
    /// (case-insensitive, `*` and `?`). Empty means no name filter.
    pub names: Vec<String>,
    /// Skip files whose name matches one of these glob patterns (applied after
    /// `names`). Empty means no exclusion.
    pub exclude_names: Vec<String>,
    /// Report what would be recovered without writing any files.
    pub dry_run: bool,
}

impl RecoverOptions {
    /// Whether a file named `name` passes the name filters: it must match an
    /// include pattern (or there are none) and must not match any exclude
    /// pattern.
    pub fn name_ok(&self, name: &str) -> bool {
        let included = self.names.is_empty() || self.names.iter().any(|p| glob_match(p, name));
        let excluded = self.exclude_names.iter().any(|p| glob_match(p, name));
        included && !excluded
    }

    /// Whether a file modified at `mtime` falls within the configured time
    /// window. A file whose timestamp is unknown (`None`) is kept, so a filter
    /// never silently drops files a filesystem can't date (e.g. a wiped inode).
    pub fn time_ok(&self, mtime: Option<SystemTime>) -> bool {
        if self.modified_after.is_none() && self.modified_before.is_none() {
            return true;
        }
        match mtime {
            Some(t) => {
                self.modified_after.map_or(true, |a| t >= a)
                    && self.modified_before.map_or(true, |b| t <= b)
            }
            None => true,
        }
    }

    /// Whether a file of `size` bytes falls within the configured size window.
    pub fn size_ok(&self, size: u64) -> bool {
        size >= self.min_size && self.max_size.map_or(true, |max| size <= max)
    }
}

/// The final path component of `p` as a string (empty if it has none). Used to
/// match a recovered file's name against the `--name` filters.
/// Make one recovered path component safe to create on the machine we are
/// running on, without changing it more than that.
///
/// Everywhere: path separators, NUL, and control characters become `_`, and
/// an empty, `.`, or `..` component becomes `_recovered`. On Windows the
/// characters its filesystems refuse (`< > : " | ? *`) become `_` too, a
/// trailing dot or space is trimmed, and the reserved device names (`CON`,
/// `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`, with or without an
/// extension) get an underscore in front. A file recovered from an ext4
/// disk as `report:final?.txt` must still be writable there.
pub fn sanitize_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            let windows_reserved = matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*');
            if c == '/'
                || c == '\\'
                || c == '\0'
                || c.is_control()
                || (cfg!(windows) && windows_reserved)
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    let mut trimmed = cleaned.trim();
    if cfg!(windows) {
        trimmed = trimmed.trim_end_matches(['.', ' ']);
    }
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return "_recovered".to_string();
    }
    if cfg!(windows) && is_windows_reserved(trimmed) {
        return format!("_{trimmed}");
    }
    trimmed.to_string()
}

/// Whether `name` (ignoring any extension and case) is a Windows device name.
fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0')
}

/// Walks the free clusters a deleted file can occupy, for FAT and exFAT: from
/// its start cluster onward, skipping clusters the allocation map shows in
/// use by live files, and wrapping once to the first free cluster when the
/// end of the volume is reached (allocators hand out clusters from a moving
/// pointer that wraps). Never revisits a cluster: after the wrap it stops
/// before the start cluster.
pub struct FreeWalk<F: Fn(u32) -> bool> {
    is_free: F,
    /// Highest valid cluster number.
    max: u32,
    start: u32,
    wrapped: bool,
}

impl<F: Fn(u32) -> bool> FreeWalk<F> {
    /// `is_free(cluster)` answers from the FAT or bitmap. When no map is
    /// available, pass a function that always returns true: the walk is then
    /// a plain contiguous read that does not wrap.
    pub fn new(start: u32, max: u32, is_free: F) -> Self {
        FreeWalk {
            is_free,
            max,
            start,
            wrapped: false,
        }
    }

    /// The next candidate cluster after `after`, or `None` when the volume
    /// (and the one permitted wrap) is exhausted.
    pub fn next_after(&mut self, after: u32, can_wrap: bool) -> Option<u32> {
        let mut c = after.checked_add(1)?;
        loop {
            let stop = if self.wrapped {
                self.start
            } else {
                self.max + 1
            };
            while c < stop && !(self.is_free)(c) {
                c += 1;
            }
            if c < stop {
                return Some(c);
            }
            if self.wrapped || !can_wrap {
                return None;
            }
            self.wrapped = true;
            c = 2;
        }
    }
}

/// Whether a recovered path names a JPEG, so its clusters can be checked
/// against JPEG structure while reassembling it.
pub fn looks_like_jpeg_name(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("jpg") || e.eq_ignore_ascii_case("jpeg"))
        .unwrap_or(false)
}

/// Keep a recovered relative path inside the output directory whatever its
/// components say: only normal components survive, so `..`, a root, or a
/// drive prefix can never lead outside. The per-component sanitizers already
/// prevent this; this is the second line of defence that turns a future
/// sanitizer bug into a dropped component rather than a file outside the
/// folder.
pub fn confine(rel: &Path) -> PathBuf {
    rel.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(n) => Some(n),
            _ => None,
        })
        .collect()
}

/// Join a recovered relative path onto the output directory, confined (see
/// [`confine`]), and make it unique by appending a counter if a file is
/// already there.
pub fn unique_path(out_dir: &Path, rel: &Path) -> PathBuf {
    let rel = confine(rel);
    let rel = if rel.as_os_str().is_empty() {
        PathBuf::from("_recovered")
    } else {
        rel
    };
    // `symlink_metadata`, not `exists`: a dangling symlink is still something
    // at that path, and must not be written through.
    let occupied = |p: &Path| std::fs::symlink_metadata(p).is_ok();
    let candidate = out_dir.join(&rel);
    if !occupied(&candidate) {
        return candidate;
    }
    let stem = rel
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let ext = rel.extension().map(|e| e.to_string_lossy().to_string());
    let parent = rel.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    for i in 1.. {
        let name = match &ext {
            Some(e) => format!("{stem}_{i}.{e}"),
            None => format!("{stem}_{i}"),
        };
        let candidate = out_dir.join(&parent).join(name);
        if !occupied(&candidate) {
            return candidate;
        }
    }
    unreachable!()
}

/// Create the file a recovered path will be written to, inside `out_dir`.
///
/// This is the one place recovered bytes get a file: every undelete backend
/// and the carver go through it. The relative path is confined (see
/// [`confine`]), each parent directory is created as a real directory (a
/// symlink already sitting at one of those names is refused rather than
/// followed, so a link planted in the output tree cannot redirect a write
/// outside it), and the file itself is opened with `create_new`, which
/// fails on anything already at that path, a symlink included, instead of
/// truncating or following it. A taken name gets a `_N` counter, as
/// [`unique_path`] would give it. Returns the path that was created and the
/// open, empty file.
///
/// The parent check is check-then-act, so a link swapped in between the
/// check and the create could still be followed by `create_dir`; the final
/// component has no such window because `create_new` is atomic.
pub fn create_output_file(out_dir: &Path, rel: &Path) -> Result<(PathBuf, std::fs::File)> {
    use std::io::ErrorKind;
    let rel = confine(rel);
    let rel = if rel.as_os_str().is_empty() {
        PathBuf::from("_recovered")
    } else {
        rel
    };
    // The output directory itself may be whatever the user chose, a symlink
    // included; only the components under it are ours to police.
    std::fs::create_dir_all(out_dir)
        .map_err(|e| anyhow::anyhow!("creating {}: {e}", out_dir.display()))?;
    let mut dir = out_dir.to_path_buf();
    if let Some(parent) = rel.parent() {
        for comp in parent.components() {
            dir.push(comp);
            // Two tries: the second handles a directory that appeared between
            // the check and the create.
            for attempt in 0..2 {
                match std::fs::symlink_metadata(&dir) {
                    Ok(m) if m.file_type().is_symlink() => bail!(
                        "refusing to write through {}: it is a symbolic link inside the output directory",
                        dir.display()
                    ),
                    Ok(m) if m.is_dir() => break,
                    Ok(_) => bail!(
                        "cannot create directory {}: a file is in the way",
                        dir.display()
                    ),
                    Err(e) if e.kind() == ErrorKind::NotFound => {
                        match std::fs::create_dir(&dir) {
                            Ok(()) => break,
                            Err(e) if e.kind() == ErrorKind::AlreadyExists && attempt == 0 => {}
                            Err(e) => bail!("creating {}: {e}", dir.display()),
                        }
                    }
                    Err(e) => bail!("inspecting {}: {e}", dir.display()),
                }
            }
        }
    }
    let file_name = rel
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "_recovered".to_string());
    let (stem, ext) = match (rel.file_stem(), rel.extension()) {
        (Some(s), Some(e)) => (
            s.to_string_lossy().into_owned(),
            Some(e.to_string_lossy().into_owned()),
        ),
        _ => (file_name.clone(), None),
    };
    for i in 0u64.. {
        let name = match (i, &ext) {
            (0, _) => file_name.clone(),
            (i, Some(e)) => format!("{stem}_{i}.{e}"),
            (i, None) => format!("{stem}_{i}"),
        };
        let candidate = dir.join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(f) => return Ok((candidate, f)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => bail!("creating {}: {e}", candidate.display()),
        }
    }
    unreachable!()
}

pub fn file_name_of(p: &Path) -> &str {
    p.file_name().and_then(|s| s.to_str()).unwrap_or("")
}

/// Format 16 raw bytes as a canonical UUID (`8-4-4-4-12`), or `None` when all
/// zero (unset). Unlike a GPT GUID, a filesystem UUID is stored big-endian, so
/// the bytes are emitted in order with no field swapping.
pub(crate) fn format_uuid(b: &[u8]) -> Option<String> {
    if b.len() < 16 || b[..16].iter().all(|&x| x == 0) {
        return None;
    }
    let h: String = b[..16].iter().map(|x| format!("{x:02x}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

/// Case-insensitive glob match supporting `*` (any run, including empty) and `?`
/// (exactly one character). Used for the `--name` recovery filter.
fn glob_match(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.to_lowercase().chars().collect();
    let txt: Vec<char> = name.to_lowercase().chars().collect();
    // Iterative backtracking: `star` remembers the last `*` position so we can
    // retry matching it against one more character on a mismatch.
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while t < txt.len() {
        if p < pat.len() && (pat[p] == '?' || pat[p] == txt[t]) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == '*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

/// One file the recovery considered, for reporting.
pub struct RecoveredFile {
    /// Path relative to the volume root.
    pub path: PathBuf,
    pub size: u64,
    /// Whether the data was successfully recovered (false = skipped/corrupt).
    pub recovered: bool,
    /// SHA-256 of the recovered bytes, when they were written. `None` for
    /// skipped files and for dry runs (where nothing is read or written).
    pub sha256: Option<[u8; 32]>,
}

/// Outcome of recovering deleted files from one volume.
#[derive(Default)]
pub struct RecoverStats {
    pub recovered: u64,
    pub bytes_recovered: u64,
    /// Entries that looked deleted but failed validation (bad cluster/size).
    pub skipped: u64,
    /// Per-file records (populated for the recovery report).
    pub files: Vec<RecoveredFile>,
}

impl RecoverStats {
    /// Record a successfully recovered file. `sha256` is the digest of the
    /// written bytes, or `None` for a dry run.
    pub fn record_recovered(&mut self, path: PathBuf, size: u64, sha256: Option<[u8; 32]>) {
        self.recovered += 1;
        self.bytes_recovered += size;
        self.files.push(RecoveredFile {
            path,
            size,
            recovered: true,
            sha256,
        });
    }

    /// Record a deleted entry that could not be recovered.
    pub fn record_skipped(&mut self, path: PathBuf, size: u64) {
        self.skipped += 1;
        self.files.push(RecoveredFile {
            path,
            size,
            recovered: false,
            sha256: None,
        });
    }
}

/// A detected, recoverable volume of a known filesystem type.
pub enum Volume {
    Fat(fat::Volume),
    Exfat(exfat::Volume),
    Ntfs(ntfs::Volume),
    Ext(ext4::Volume),
    Hfs(hfsplus::Volume),
    Apfs(apfs::Volume),
    Btrfs(btrfs::Volume),
    Refs(refs::Volume),
    Xfs(xfs::Volume),
    F2fs(f2fs::Volume),
    Reiserfs(reiserfs::Volume),
    Jfs(jfs::Volume),
    Nilfs2(nilfs2::Volume),
    Gfs2(gfs2::Volume),
    Ocfs2(ocfs2::Volume),
    Minix(minix::Volume),
    Bcachefs(bcachefs::Volume),
    Befs(befs::Volume),
    Ufs(ufs::Volume),
    Erofs(erofs::Volume),
    Cramfs(cramfs::Volume),
    Romfs(romfs::Volume),
    Lvm(lvm::Volume),
    Mdraid(mdraid::Volume),
    HfsStd(hfs::Volume),
    Swap(swap::Volume),
    Encrypted(encrypted::Volume),
    Udf(udf::Volume),
    Iso(iso9660::Volume),
}

impl Volume {
    /// Byte offset of the volume within the source.
    pub fn offset(&self) -> u64 {
        match self {
            Volume::Fat(v) => v.offset,
            Volume::Exfat(v) => v.offset,
            Volume::Ntfs(v) => v.offset,
            Volume::Ext(v) => v.offset,
            Volume::Hfs(v) => v.offset,
            Volume::Apfs(v) => v.offset,
            Volume::Btrfs(v) => v.offset,
            Volume::Refs(v) => v.offset,
            Volume::Xfs(v) => v.offset,
            Volume::F2fs(v) => v.offset,
            Volume::Reiserfs(v) => v.offset,
            Volume::Jfs(v) => v.offset,
            Volume::Nilfs2(v) => v.offset,
            Volume::Gfs2(v) => v.offset,
            Volume::Ocfs2(v) => v.offset,
            Volume::Minix(v) => v.offset,
            Volume::Bcachefs(v) => v.offset,
            Volume::Befs(v) => v.offset,
            Volume::Ufs(v) => v.offset,
            Volume::Erofs(v) => v.offset,
            Volume::Cramfs(v) => v.offset,
            Volume::Romfs(v) => v.offset,
            Volume::Lvm(v) => v.offset,
            Volume::Mdraid(v) => v.offset,
            Volume::HfsStd(v) => v.offset,
            Volume::Swap(v) => v.offset,
            Volume::Encrypted(v) => v.offset,
            Volume::Udf(v) => v.offset,
            Volume::Iso(v) => v.offset,
        }
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        match self {
            Volume::Fat(v) => v.size(),
            Volume::Exfat(v) => v.size(),
            Volume::Ntfs(v) => v.size(),
            Volume::Ext(v) => v.size(),
            Volume::Hfs(v) => v.size(),
            Volume::Apfs(v) => v.size(),
            Volume::Btrfs(v) => v.size(),
            Volume::Refs(v) => v.size(),
            Volume::Xfs(v) => v.size(),
            Volume::F2fs(v) => v.size(),
            Volume::Reiserfs(v) => v.size(),
            Volume::Jfs(v) => v.size(),
            Volume::Nilfs2(v) => v.size(),
            Volume::Gfs2(v) => v.size(),
            Volume::Ocfs2(v) => v.size(),
            Volume::Minix(v) => v.size(),
            Volume::Bcachefs(v) => v.size(),
            Volume::Befs(v) => v.size(),
            Volume::Ufs(v) => v.size(),
            Volume::Erofs(v) => v.size(),
            Volume::Cramfs(v) => v.size(),
            Volume::Romfs(v) => v.size(),
            Volume::Lvm(v) => v.size(),
            Volume::Mdraid(v) => v.size(),
            Volume::HfsStd(v) => v.size(),
            Volume::Swap(v) => v.size(),
            Volume::Encrypted(v) => v.size(),
            Volume::Udf(v) => v.size(),
            Volume::Iso(v) => v.size(),
        }
    }

    /// Short human-readable filesystem label, e.g. `"FAT16"` or `"exFAT"`.
    pub fn fs_label(&self) -> String {
        match self {
            Volume::Fat(v) => format!("{:?}", v.fat_type),
            Volume::Exfat(_) => "exFAT".to_string(),
            Volume::Ntfs(_) => "NTFS".to_string(),
            Volume::Ext(_) => "ext2/3/4".to_string(),
            Volume::Hfs(v) => v.fs_label().to_string(),
            Volume::Apfs(v) => v.fs_label().to_string(),
            Volume::Btrfs(v) => v.fs_label().to_string(),
            Volume::Refs(v) => v.fs_label().to_string(),
            Volume::Xfs(v) => v.fs_label().to_string(),
            Volume::F2fs(v) => v.fs_label().to_string(),
            Volume::Reiserfs(v) => v.fs_label().to_string(),
            Volume::Jfs(v) => v.fs_label().to_string(),
            Volume::Nilfs2(v) => v.fs_label().to_string(),
            Volume::Gfs2(v) => v.fs_label().to_string(),
            Volume::Ocfs2(v) => v.fs_label().to_string(),
            Volume::Minix(v) => v.fs_label().to_string(),
            Volume::Bcachefs(v) => v.fs_label().to_string(),
            Volume::Befs(v) => v.fs_label().to_string(),
            Volume::Ufs(v) => v.fs_label().to_string(),
            Volume::Erofs(v) => v.fs_label().to_string(),
            Volume::Cramfs(v) => v.fs_label().to_string(),
            Volume::Romfs(v) => v.fs_label().to_string(),
            Volume::Lvm(v) => v.fs_label().to_string(),
            Volume::Mdraid(v) => v.fs_label(),
            Volume::HfsStd(v) => v.fs_label().to_string(),
            Volume::Swap(v) => v.fs_label().to_string(),
            Volume::Encrypted(v) => v.fs_label().to_string(),
            Volume::Udf(v) => v.fs_label().to_string(),
            Volume::Iso(v) => v.fs_label().to_string(),
        }
    }

    /// The path the volume was last mounted on, when the filesystem records it
    /// (currently ext's `s_last_mounted`, e.g. `/` or `/home`) — useful for
    /// identifying which volume a recovered image came from. `None` otherwise.
    pub fn last_mounted(&self) -> Option<String> {
        match self {
            Volume::Ext(v) => v.last_mounted().map(str::to_string),
            _ => None,
        }
    }

    /// The precise on-disk format version, when the backend can refine its
    /// family label — currently the ext variant (`"ext2"`, `"ext3"`, or
    /// `"ext4"`), distinguished from the `"ext2/3/4"` family by the superblock
    /// feature flags. `None` for filesystems with no such sub-version.
    pub fn fs_version(&self) -> Option<&'static str> {
        match self {
            Volume::Ext(v) => Some(v.version()),
            _ => None,
        }
    }

    /// The filesystem's creation time as Unix seconds, when the backend records
    /// one — ext's `s_mkfs_time`, NTFS's `$Volume` `$STANDARD_INFORMATION`
    /// creation time, HFS+'s `createDate`, an ISO 9660 PVD creation date, or
    /// NILFS2's `s_ctime`. `None` otherwise.
    pub fn created_time(&self) -> Option<u64> {
        match self {
            Volume::Ext(v) => v.created_time(),
            Volume::Ntfs(v) => v.created_time(),
            Volume::Hfs(v) => v.created_time(),
            Volume::Iso(v) => v.created_time(),
            Volume::Nilfs2(v) => v.created_time(),
            Volume::Erofs(v) => v.created_time(),
            _ => None,
        }
    }

    /// The filesystem's last-write time as Unix seconds, when the backend records
    /// one — ext's `s_wtime`, NTFS's `$Volume` `$STANDARD_INFORMATION`
    /// modification time, HFS+'s `modifyDate`, an ISO 9660 PVD modification
    /// date, NILFS2's `s_wtime`, or JFS's `s_time`. `None` otherwise.
    pub fn written_time(&self) -> Option<u64> {
        match self {
            Volume::Ext(v) => v.written_time(),
            Volume::Ntfs(v) => v.written_time(),
            Volume::Hfs(v) => v.written_time(),
            Volume::Iso(v) => v.written_time(),
            Volume::Nilfs2(v) => v.written_time(),
            Volume::Jfs(v) => v.written_time(),
            _ => None,
        }
    }

    /// Inode usage as `(used, total)` — roughly how many files and directories
    /// the volume holds — when the backend tracks it (ext's
    /// `s_inodes_count`/`s_free_inodes_count`, XFS's `sb_icount`/`sb_ifree`).
    /// `None` for filesystems with no fixed inode accounting.
    pub fn inode_usage(&self) -> Option<(u64, u64)> {
        match self {
            Volume::Ext(v) => Some(v.inode_usage()),
            Volume::Xfs(v) => Some(v.inode_usage()),
            _ => None,
        }
    }

    /// The volume's allocation-unit size in bytes — the cluster size (FAT,
    /// exFAT, NTFS, ReFS, OCFS2) or block size (ext, HFS+, APFS, XFS, F2FS,
    /// Btrfs, ISO 9660, ReiserFS, JFS, NILFS2, GFS2, Minix, bcachefs, BeFS) the
    /// filesystem allocates space in. Useful for recovery: carving aligns to it
    /// and it bounds per-file slack. `None` for backends with no such unit
    /// (LVM/swap/encrypted/UDF) or when the geometry is implausible.
    pub fn alloc_unit(&self) -> Option<u64> {
        let unit = match self {
            Volume::Fat(v) => v.cluster_size(),
            Volume::Exfat(v) => v.cluster_size(),
            Volume::Ntfs(v) => v.cluster_size(),
            Volume::Ext(v) => v.block_size(),
            Volume::Hfs(v) => v.block_size(),
            Volume::Apfs(v) => v.block_size(),
            Volume::Btrfs(v) => v.geometry().0 as u64,
            Volume::Refs(v) => return v.cluster_size(),
            Volume::Xfs(v) => v.block_size() as u64,
            Volume::F2fs(v) => v.block_size() as u64,
            Volume::Reiserfs(v) => v.block_size(),
            Volume::Jfs(v) => v.block_size(),
            Volume::Nilfs2(v) => v.block_size(),
            Volume::Gfs2(v) => v.block_size(),
            Volume::Ocfs2(v) => v.block_size(),
            Volume::Minix(v) => v.block_size(),
            Volume::Bcachefs(v) => v.block_size(),
            Volume::Befs(v) => v.block_size(),
            Volume::Ufs(v) => v.block_size(),
            Volume::Erofs(v) => v.block_size(),
            Volume::Cramfs(v) => v.block_size(),
            Volume::Iso(v) => v.block_size(),
            _ => return None,
        };
        if unit == 0 {
            None
        } else {
            Some(unit)
        }
    }

    /// Names of sub-volumes contained in this volume: APFS volumes inside a
    /// container, or Btrfs subvolumes. Other filesystems have none.
    pub fn contained_volumes(&self) -> Vec<String> {
        match self {
            Volume::Apfs(v) => v.volume_names().to_vec(),
            Volume::Btrfs(v) => v.subvolumes().to_vec(),
            _ => Vec::new(),
        }
    }

    /// The user-set filesystem label (FAT, exFAT, NTFS, ext, or Btrfs), when
    /// set. `None` when there is no label or the filesystem does not expose one.
    pub fn volume_label(&self) -> Option<String> {
        let label = match self {
            Volume::Fat(v) => v.label(),
            Volume::Exfat(v) => v.label(),
            Volume::Ntfs(v) => v.label(),
            Volume::Ext(v) => v.label(),
            Volume::Btrfs(v) => v.label(),
            Volume::Xfs(v) => v.label(),
            Volume::F2fs(v) => v.label(),
            Volume::Reiserfs(v) => v.label(),
            Volume::Jfs(v) => v.label(),
            Volume::Nilfs2(v) => v.label(),
            Volume::Erofs(v) => v.label(),
            Volume::Cramfs(v) => v.label(),
            Volume::Romfs(v) => v.label(),
            Volume::Gfs2(v) => v.label(),
            Volume::Ocfs2(v) => v.label(),
            Volume::Bcachefs(v) => v.label(),
            Volume::Befs(v) => v.label(),
            Volume::Mdraid(v) => v.label(),
            Volume::HfsStd(v) => v.label(),
            Volume::Swap(v) => v.label(),
            Volume::Encrypted(v) => v.label(),
            Volume::Iso(v) => v.label(),
            _ => "",
        };
        if label.is_empty() {
            None
        } else {
            Some(label.to_string())
        }
    }

    /// The volume's identifier — the `UUID=` value `/etc/fstab` and `blkid` use.
    /// For ext / XFS / F2FS / Btrfs this is the filesystem UUID; for FAT / exFAT
    /// / NTFS it is the volume serial number in the conventional form
    /// (`XXXX-XXXX` for FAT/exFAT, 16 hex digits for NTFS). `None` for
    /// filesystems without a stable identifier.
    pub fn volume_uuid(&self) -> Option<String> {
        match self {
            Volume::Ext(v) => v.uuid(),
            Volume::Xfs(v) => v.uuid(),
            Volume::F2fs(v) => v.uuid(),
            Volume::Reiserfs(v) => v.uuid(),
            Volume::Jfs(v) => v.uuid(),
            Volume::Nilfs2(v) => v.uuid(),
            Volume::Erofs(v) => v.uuid(),
            Volume::Gfs2(v) => v.uuid(),
            Volume::Ocfs2(v) => v.uuid(),
            Volume::Bcachefs(v) => v.uuid(),
            Volume::Btrfs(v) => v.uuid(),
            Volume::Fat(v) => v.uuid(),
            Volume::Exfat(v) => v.uuid(),
            Volume::Ntfs(v) => v.uuid(),
            Volume::Mdraid(v) => v.uuid(),
            Volume::Swap(v) => v.uuid(),
            Volume::Encrypted(v) => v.uuid(),
            _ => None,
        }
    }

    /// A short description of the volume's boot capability (e.g. an El Torito
    /// bootable ISO), or `None` when it is not bootable / has no boot concept.
    pub fn boot_info(&self) -> Option<String> {
        match self {
            Volume::Iso(v) => v.boot_info().map(str::to_string),
            _ => None,
        }
    }

    /// Whether the volume was cleanly unmounted (`Some(true)`) or is marked dirty
    /// / inconsistent (`Some(false)`) — a sign the filesystem may need a check and
    /// that recovery may be less reliable. `None` for backends without the flag.
    pub fn is_clean(&self) -> Option<bool> {
        match self {
            Volume::Ext(v) => Some(v.is_clean()),
            Volume::Exfat(v) => Some(v.is_clean()),
            Volume::Ntfs(v) => v.is_clean(),
            Volume::Reiserfs(v) => Some(v.is_clean()),
            Volume::Nilfs2(v) => Some(v.is_clean()),
            _ => None,
        }
    }

    /// Absolute byte ranges of the volume's free (unallocated) space, if this
    /// backend can compute it. Carving only these ranges recovers deleted
    /// content without re-finding files that are still allocated. Returns
    /// `None` for filesystems whose allocation map is not yet parsed.
    pub fn free_extents(&self, src: &Source) -> Option<Vec<(u64, u64)>> {
        match self {
            Volume::Fat(v) => v.free_extents(src).ok(),
            Volume::Exfat(v) => v.free_extents(src).ok(),
            Volume::Ext(v) => v.free_extents(src).ok(),
            Volume::Ntfs(v) => v.free_extents(src).ok(),
            Volume::Hfs(v) => v.free_extents(src).ok(),
            _ => None,
        }
    }

    /// Total free (unallocated) bytes in the volume, for reporting. Uses the
    /// allocation map (the sum of [`Self::free_extents`]) when available, and
    /// otherwise the free/used counts recorded in the superblock (XFS, Btrfs,
    /// ReiserFS, NILFS2, BeFS).
    /// Unlike `free_extents`, this is just a count — it does not enable
    /// free-space (`--unallocated`) carving. `None` when unknown.
    pub fn free_space(&self, src: &Source) -> Option<u64> {
        if let Some(ex) = self.free_extents(src) {
            return Some(ex.iter().map(|(_, len)| len).sum());
        }
        match self {
            Volume::Xfs(v) => Some(v.free_bytes()),
            Volume::Btrfs(v) => Some(v.free_bytes()),
            Volume::Reiserfs(v) => Some(v.free_bytes()),
            Volume::Nilfs2(v) => Some(v.free_bytes()),
            Volume::Befs(v) => Some(v.free_bytes()),
            _ => None,
        }
    }

    /// Recover all deleted files from this volume into `out_dir`.
    pub fn recover_deleted(
        &self,
        src: &Source,
        out_dir: &Path,
        opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        match self {
            Volume::Fat(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Exfat(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Ntfs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Ext(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Hfs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Apfs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Btrfs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Refs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Xfs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::F2fs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Reiserfs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Jfs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Nilfs2(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Gfs2(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Ocfs2(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Minix(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Bcachefs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Befs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Ufs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Erofs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Cramfs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Romfs(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Lvm(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Mdraid(v) => v.recover_deleted(src, out_dir, opts),
            Volume::HfsStd(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Swap(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Encrypted(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Udf(v) => v.recover_deleted(src, out_dir, opts),
            Volume::Iso(v) => v.recover_deleted(src, out_dir, opts),
        }
    }
}

/// How well a capability is covered for one filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Support {
    Yes,
    Partial,
    No,
}

impl Support {
    pub fn as_str(self) -> &'static str {
        match self {
            Support::Yes => "yes",
            Support::Partial => "partial",
            Support::No => "no",
        }
    }
}

/// What the tool can do for one filesystem. The rows are the source of truth
/// for the feature matrix in the README and in `unearth info --features`, and
/// [`Volume::capability`] maps every detected volume to one, so the matrix
/// cannot drift from the code: a new `Volume` variant does not compile until
/// it has a row.
#[derive(Clone, Copy, Debug)]
pub struct Capability {
    /// The name shown in the matrix, e.g. `"NTFS"`.
    pub filesystem: &'static str,
    /// Recognised by `info` and the partition walk.
    pub detect: Support,
    /// Reports label, UUID, size, and times in `info` / `list_volumes`.
    pub list_volumes: Support,
    /// Restores deleted files with names from filesystem metadata.
    pub undelete: Support,
    /// Reassembles a fragmented file from its metadata (not just a contiguous run).
    pub fragmentation: Support,
    /// One line on the biggest caveat, for the matrix.
    pub note: &'static str,
}

const fn cap(
    filesystem: &'static str,
    detect: Support,
    list_volumes: Support,
    undelete: Support,
    fragmentation: Support,
    note: &'static str,
) -> Capability {
    Capability {
        filesystem,
        detect,
        list_volumes,
        undelete,
        fragmentation,
        note,
    }
}

use Support::{No, Partial, Yes};

const CAP_FAT: Capability = cap(
    "FAT12/16/32",
    Yes,
    Yes,
    Yes,
    Partial,
    "a file written around live files is reassembled from the FAT, including one that wrapped to the volume start; not one whose neighbour was deleted after it. Deleted folders followed; Windows' zeroed high cluster word recovered",
);
const CAP_EXFAT: Capability = cap(
    "exFAT",
    Yes,
    Yes,
    Yes,
    Partial,
    "a surviving FAT chain is followed; otherwise reassembled around allocated clusters from the bitmap, with the same limit as FAT. Deleted folders followed",
);
const CAP_NTFS: Capability = cap(
    "NTFS",
    Yes,
    Yes,
    Yes,
    Yes,
    "files deleted by Linux ntfs3 lose their name and land in _unnamed/",
);
const CAP_EXT: Capability = cap(
    "ext2/3/4",
    Yes,
    Yes,
    Yes,
    Yes,
    "names and extents come from the journal on modern kernels; gone once it wraps",
);
const CAP_HFSPLUS: Capability = cap(
    "HFS+/HFSX",
    Yes,
    Yes,
    Yes,
    Yes,
    "records come from the journal on macOS-formatted disks; names are in decomposed Unicode",
);
const CAP_APFS: Capability = cap("APFS", Yes, Yes, No, No, "copy-on-write; use scan");
const CAP_BTRFS: Capability = cap("Btrfs", Yes, Yes, No, No, "copy-on-write; use scan");
const CAP_REFS: Capability = cap("ReFS", Yes, Yes, No, No, "use scan");
const CAP_XFS: Capability = cap("XFS", Yes, Yes, No, No, "a current kernel zeroes a freed inode entirely (corpus-verified), so only the log could give the data map; use scan");
const CAP_F2FS: Capability = cap("F2FS", Yes, Yes, No, No, "use scan");
const CAP_REISERFS: Capability = cap("ReiserFS", Yes, Yes, No, No, "use scan");
const CAP_JFS: Capability = cap("JFS", Yes, Yes, No, No, "use scan");
const CAP_NILFS2: Capability = cap("NILFS2", Yes, Yes, No, No, "use scan");
const CAP_GFS2: Capability = cap("GFS2", Yes, Yes, No, No, "use scan");
const CAP_OCFS2: Capability = cap("OCFS2", Yes, Yes, No, No, "use scan");
const CAP_MINIX: Capability = cap("Minix", Yes, Yes, No, No, "use scan");
const CAP_BCACHEFS: Capability = cap("bcachefs", Yes, Yes, No, No, "use scan");
const CAP_BEFS: Capability = cap("BeFS", Yes, Yes, No, No, "use scan");
const CAP_UFS: Capability = cap("UFS", Yes, Yes, No, No, "use scan");
const CAP_EROFS: Capability = cap(
    "EROFS",
    Yes,
    Yes,
    No,
    No,
    "read-only image format; use scan",
);
const CAP_CRAMFS: Capability = cap(
    "cramfs",
    Yes,
    Yes,
    No,
    No,
    "read-only image format; use scan",
);
const CAP_ROMFS: Capability = cap(
    "romfs",
    Yes,
    Yes,
    No,
    No,
    "read-only image format; use scan",
);
const CAP_LVM: Capability = cap(
    "LVM physical volume",
    Yes,
    Yes,
    No,
    No,
    "container; scan, or activate the volume group and recover the logical volumes",
);
const CAP_MDRAID: Capability = cap(
    "Linux RAID member",
    Yes,
    Yes,
    No,
    No,
    "container; scan, or assemble the array first",
);
const CAP_HFSSTD: Capability = cap("HFS (Mac OS Standard)", Yes, Yes, No, No, "use scan");
const CAP_SWAP: Capability = cap(
    "Linux swap",
    Yes,
    Yes,
    No,
    No,
    "no files; scan for what was paged out",
);
const CAP_ENCRYPTED: Capability = cap(
    "BitLocker / LUKS",
    Yes,
    Yes,
    No,
    No,
    "detected only; unlock the volume first, then recover from the decrypted device",
);
const CAP_UDF: Capability = cap("UDF", Yes, Yes, No, No, "optical media; use scan");
const CAP_ISO: Capability = cap("ISO 9660", Yes, Yes, No, No, "read-only media; use scan");

/// Every filesystem the tool knows, in matrix order.
pub fn capability_matrix() -> &'static [Capability] {
    &[
        CAP_FAT,
        CAP_EXFAT,
        CAP_NTFS,
        CAP_EXT,
        CAP_HFSPLUS,
        CAP_APFS,
        CAP_BTRFS,
        CAP_REFS,
        CAP_XFS,
        CAP_F2FS,
        CAP_REISERFS,
        CAP_JFS,
        CAP_NILFS2,
        CAP_GFS2,
        CAP_OCFS2,
        CAP_MINIX,
        CAP_BCACHEFS,
        CAP_BEFS,
        CAP_UFS,
        CAP_EROFS,
        CAP_CRAMFS,
        CAP_ROMFS,
        CAP_LVM,
        CAP_MDRAID,
        CAP_HFSSTD,
        CAP_SWAP,
        CAP_ENCRYPTED,
        CAP_UDF,
        CAP_ISO,
    ]
}

/// The matrix as a Markdown table, the exact text the README carries.
pub fn capability_markdown() -> String {
    let mut out = String::from(
        "| Filesystem | Detect | List volumes | Undelete | Fragmented files | Notes |
|---|---|---|---|---|---|
",
    );
    for c in capability_matrix() {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |
",
            c.filesystem,
            c.detect.as_str(),
            c.list_volumes.as_str(),
            c.undelete.as_str(),
            c.fragmentation.as_str(),
            c.note
        ));
    }
    out
}

/// The matrix as a plain-text table for the terminal.
pub fn capability_text() -> String {
    let mut out = format!(
        "{:<22} {:<7} {:<13} {:<9} {:<11} {}
",
        "FILESYSTEM", "DETECT", "LIST VOLUMES", "UNDELETE", "FRAGMENTED", "NOTES"
    );
    for c in capability_matrix() {
        out.push_str(&format!(
            "{:<22} {:<7} {:<13} {:<9} {:<11} {}
",
            c.filesystem,
            c.detect.as_str(),
            c.list_volumes.as_str(),
            c.undelete.as_str(),
            c.fragmentation.as_str(),
            c.note
        ));
    }
    out
}

impl Volume {
    /// The capability row for this volume's filesystem. Exhaustive on purpose.
    pub fn capability(&self) -> &'static Capability {
        match self {
            Volume::Fat(_) => &CAP_FAT,
            Volume::Exfat(_) => &CAP_EXFAT,
            Volume::Ntfs(_) => &CAP_NTFS,
            Volume::Ext(_) => &CAP_EXT,
            Volume::Hfs(_) => &CAP_HFSPLUS,
            Volume::Apfs(_) => &CAP_APFS,
            Volume::Btrfs(_) => &CAP_BTRFS,
            Volume::Refs(_) => &CAP_REFS,
            Volume::Xfs(_) => &CAP_XFS,
            Volume::F2fs(_) => &CAP_F2FS,
            Volume::Reiserfs(_) => &CAP_REISERFS,
            Volume::Jfs(_) => &CAP_JFS,
            Volume::Nilfs2(_) => &CAP_NILFS2,
            Volume::Gfs2(_) => &CAP_GFS2,
            Volume::Ocfs2(_) => &CAP_OCFS2,
            Volume::Minix(_) => &CAP_MINIX,
            Volume::Bcachefs(_) => &CAP_BCACHEFS,
            Volume::Befs(_) => &CAP_BEFS,
            Volume::Ufs(_) => &CAP_UFS,
            Volume::Erofs(_) => &CAP_EROFS,
            Volume::Cramfs(_) => &CAP_CRAMFS,
            Volume::Romfs(_) => &CAP_ROMFS,
            Volume::Lvm(_) => &CAP_LVM,
            Volume::Mdraid(_) => &CAP_MDRAID,
            Volume::HfsStd(_) => &CAP_HFSSTD,
            Volume::Swap(_) => &CAP_SWAP,
            Volume::Encrypted(_) => &CAP_ENCRYPTED,
            Volume::Udf(_) => &CAP_UDF,
            Volume::Iso(_) => &CAP_ISO,
        }
    }
}

/// Detect every supported volume in `src`: a bare volume at offset 0, or the
/// volumes referenced by a GPT or legacy MBR partition table.
pub fn detect(src: &Source) -> Result<Vec<Volume>> {
    let mut sector0 = [0u8; 512];
    if src.read_at(0, &mut sector0)? < 512 {
        bail!("source too small to contain a filesystem");
    }

    // 1. A bare filesystem placed directly at offset 0 (no partition table).
    if let Some(v) = try_parse_volume(src, 0)? {
        return Ok(vec![v]);
    }

    // 2. A GUID Partition Table (GPT).
    let gpt = detect_gpt(src)?;
    if !gpt.is_empty() {
        return Ok(gpt);
    }

    // 3. A legacy MBR partition table. An extended entry (type 0x05/0x0F/0x85)
    // is a container: its logical partitions hang off a chain of Extended
    // Boot Records, each naming one partition and the next record.
    let mut volumes = Vec::new();
    if sector0[510] == 0x55 && sector0[511] == 0xAA {
        for i in 0..4 {
            let base = 446 + i * 16;
            let kind = sector0[base + 4];
            let lba_start = u32::from_le_bytes([
                sector0[base + 8],
                sector0[base + 9],
                sector0[base + 10],
                sector0[base + 11],
            ]);
            if lba_start == 0 {
                continue;
            }
            if crate::partition::is_extended_mbr(kind) {
                let mut logical = Vec::new();
                crate::partition::walk_ebr_chain(src, lba_start as u64, &mut logical);
                for p in logical {
                    if let Some(v) = try_parse_volume(src, p.start)? {
                        push_unique(&mut volumes, v);
                    }
                }
                continue;
            }
            if let Some(v) = try_parse_volume(src, lba_start as u64 * 512)? {
                push_unique(&mut volumes, v);
            }
        }
    }

    // 4. An Apple Partition Map (older Mac disks, hybrid CDs) — checked after
    // GPT/MBR since those are more specific.
    if volumes.is_empty() {
        for p in crate::partition::read_apm(src).unwrap_or_default() {
            if let Some(v) = try_parse_volume(src, p.start)? {
                push_unique(&mut volumes, v);
            }
        }
    }

    if volumes.is_empty() {
        bail!("no FAT, exFAT, NTFS, ReFS, ext2/3/4, XFS, F2FS, ReiserFS, JFS, NILFS2, GFS2, OCFS2, Minix, bcachefs, BeFS, UFS, EROFS, cramfs, romfs, HFS, HFS+, APFS, Btrfs, LVM2, Linux MD/RAID, Linux swap, APM, UDF, ISO 9660, or encrypted (LUKS/BitLocker) volume found");
    }
    Ok(volumes)
}

/// Add `v` unless a volume at the same offset is already listed: two table
/// entries naming one start (an overlapping or duplicated entry) describe one
/// volume, and recovering it twice would double every file.
fn push_unique(volumes: &mut Vec<Volume>, v: Volume) {
    if !volumes.iter().any(|x| x.offset() == v.offset()) {
        volumes.push(v);
    }
}

/// Scan the whole source for filesystem signatures at `step`-aligned offsets,
/// returning every volume found — including ones with no partition-table entry
/// (lost or orphaned partitions). After a hit, the scan skips past that volume's
/// body so its interior is not re-probed. `progress` is called with the current
/// offset as the scan advances (for a progress indicator).
pub fn scan_lost_volumes(
    src: &Source,
    step: u64,
    mut progress: impl FnMut(u64),
) -> Result<Vec<Volume>> {
    // Backstop so a tiny `step` on a huge device cannot loop forever.
    const MAX_PROBES: u64 = 16_000_000;
    let step = step.max(512);
    let mut found = Vec::new();
    let mut offset = 0u64;
    let mut probes = 0u64;
    while offset < src.size && probes < MAX_PROBES {
        progress(offset);
        probes += 1;
        if let Some(v) = try_parse_volume(src, offset)? {
            // Skip past the volume body, aligned up to the next step boundary,
            // so its interior bytes are not mistaken for nested volumes.
            let end = offset.saturating_add(v.size().max(step));
            found.push(v);
            offset = end.div_ceil(step).saturating_mul(step);
        } else {
            offset = match offset.checked_add(step) {
                Some(o) => o,
                None => break,
            };
        }
    }
    Ok(found)
}

/// Try to recognise a supported filesystem at `offset`, by signature. Returns
/// `None` if nothing matches (e.g. an empty or unsupported partition).
fn try_parse_volume(src: &Source, offset: u64) -> Result<Option<Volume>> {
    let mut boot = [0u8; 512];
    if src.read_at(offset, &mut boot)? < 512 {
        return Ok(None);
    }
    // Encrypted containers (LUKS/BitLocker) carry no readable filesystem; detect
    // them first so a BitLocker boot sector is not mistaken for FAT/NTFS.
    if let Some(v) = encrypted::detect(src, offset) {
        return Ok(Some(Volume::Encrypted(v)));
    }
    if exfat::is_exfat_vbr(&boot) {
        if let Ok(v) = exfat::Volume::parse(src, offset) {
            return Ok(Some(Volume::Exfat(v)));
        }
    }
    if ntfs::is_ntfs_vbr(&boot) {
        if let Ok(v) = ntfs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Ntfs(v)));
        }
    }
    if refs::is_refs(src, offset) {
        if let Ok(v) = refs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Refs(v)));
        }
    }
    if ext4::is_ext_volume(src, offset) {
        if let Ok(v) = ext4::Volume::parse(src, offset) {
            return Ok(Some(Volume::Ext(v)));
        }
    }
    if hfsplus::is_hfsplus(src, offset) {
        if let Ok(v) = hfsplus::Volume::parse(src, offset) {
            return Ok(Some(Volume::Hfs(v)));
        }
    }
    // Pure old HFS (after hfsplus, which claims HFS+ wrappers).
    if hfs::is_hfs(src, offset) {
        if let Ok(v) = hfs::Volume::parse(src, offset) {
            return Ok(Some(Volume::HfsStd(v)));
        }
    }
    if apfs::is_apfs(src, offset) {
        if let Ok(v) = apfs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Apfs(v)));
        }
    }
    if btrfs::is_btrfs(src, offset) {
        if let Ok(v) = btrfs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Btrfs(v)));
        }
    }
    if xfs::is_xfs(src, offset) {
        if let Ok(v) = xfs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Xfs(v)));
        }
    }
    if f2fs::is_f2fs(src, offset) {
        if let Ok(v) = f2fs::Volume::parse(src, offset) {
            return Ok(Some(Volume::F2fs(v)));
        }
    }
    // ReiserFS keeps its superblock 64 KiB (3.6) or 8 KiB (3.5) in, well past the
    // boot sector, so it cannot be confused with the VBR filesystems above.
    if reiserfs::is_reiserfs(src, offset) {
        if let Ok(v) = reiserfs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Reiserfs(v)));
        }
    }
    // JFS keeps its aggregate superblock 32 KiB in, also past the boot sector.
    if jfs::is_jfs(src, offset) {
        if let Ok(v) = jfs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Jfs(v)));
        }
    }
    // NILFS2 keeps its superblock 1 KiB in (past the boot sector); the 2-byte
    // magic is guarded by a revision check inside the detector.
    if nilfs2::is_nilfs2(src, offset) {
        if let Ok(v) = nilfs2::Volume::parse(src, offset) {
            return Ok(Some(Volume::Nilfs2(v)));
        }
    }
    // GFS2 keeps its superblock 64 KiB in, with a strong 4-byte magic.
    if gfs2::is_gfs2(src, offset) {
        if let Ok(v) = gfs2::Volume::parse(src, offset) {
            return Ok(Some(Volume::Gfs2(v)));
        }
    }
    // OCFS2's superblock inode lives at 2x the block size (past the boot sector),
    // probed across the supported block sizes inside the detector.
    if ocfs2::is_ocfs2(src, offset) {
        if let Ok(v) = ocfs2::Volume::parse(src, offset) {
            return Ok(Some(Volume::Ocfs2(v)));
        }
    }
    // Minix keeps its superblock in the second 1 KiB block (past the boot sector).
    if minix::is_minix(src, offset) {
        if let Ok(v) = minix::Volume::parse(src, offset) {
            return Ok(Some(Volume::Minix(v)));
        }
    }
    // bcachefs keeps its superblock 4 KiB in, with a strong 16-byte magic.
    if bcachefs::is_bcachefs(src, offset) {
        if let Ok(v) = bcachefs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Bcachefs(v)));
        }
    }
    // BeFS keeps its superblock 512 B in (past the boot block), with dual magics.
    if befs::is_befs(src, offset) {
        if let Ok(v) = befs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Befs(v)));
        }
    }
    // UFS keeps its superblock 8 KiB (UFS1) or 64 KiB (UFS2) in, magic at 0x55C.
    if ufs::is_ufs(src, offset) {
        if let Ok(v) = ufs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Ufs(v)));
        }
    }
    // EROFS keeps its superblock 1 KiB in, with a 4-byte magic.
    if erofs::is_erofs(src, offset) {
        if let Ok(v) = erofs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Erofs(v)));
        }
    }
    // cramfs has its superblock at offset 0, but a dual magic+signature, so it
    // cannot be confused with the boot-sector filesystems checked above.
    if cramfs::is_cramfs(src, offset) {
        if let Ok(v) = cramfs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Cramfs(v)));
        }
    }
    // romfs has an 8-byte magic at offset 0.
    if romfs::is_romfs(src, offset) {
        if let Ok(v) = romfs::Volume::parse(src, offset) {
            return Ok(Some(Volume::Romfs(v)));
        }
    }
    if lvm::is_lvm(src, offset) {
        if let Ok(v) = lvm::Volume::parse(src, offset) {
            return Ok(Some(Volume::Lvm(v)));
        }
    }
    // An MD/RAID member carries its superblock at the device start (1.1) or 4 KiB
    // in (1.2); detect it before the filesystems so a member is recognised as
    // part of an array rather than by any stale signature in its reserved area.
    if mdraid::is_mdraid(src, offset) {
        if let Ok(v) = mdraid::Volume::parse(src, offset) {
            return Ok(Some(Volume::Mdraid(v)));
        }
    }
    // A swap area's first 1 KiB is reserved (`bootbits`) and can hold a stale
    // disklabel, so check the swap magic (at `page_size - 10`) before the
    // boot-sector filesystems to avoid misreading leftover bytes as FAT/NTFS.
    if swap::is_swap(src, offset) {
        if let Ok(v) = swap::Volume::parse(src, offset) {
            return Ok(Some(Volume::Swap(v)));
        }
    }
    if fat::looks_like_fat_vbr(&boot) {
        if let Ok(v) = fat::Volume::parse(src, offset) {
            return Ok(Some(Volume::Fat(v)));
        }
    }
    // UDF carries no boot-sector signature; its marker is the Volume Recognition
    // Sequence at sector 16, so it is checked last (and only reported, not
    // recovered).
    if let Some(v) = udf::detect(src, offset) {
        return Ok(Some(Volume::Udf(v)));
    }
    // ISO 9660 (plain data discs) shares the sector-16 descriptor area but lacks
    // the UDF `NSR` marker, so it is checked after UDF.
    if let Some(v) = iso9660::detect(src, offset) {
        return Ok(Some(Volume::Iso(v)));
    }
    Ok(None)
}

/// Detect volumes via a GPT, supporting 512- and 4096-byte logical sectors.
/// The primary header at LBA 1 is used when it is intact; otherwise the
/// backup header at the last LBA, which carries its own copy of the entry
/// array, so a disk whose first sectors were overwritten still lists its
/// partitions. Returns an empty vec when the source is not GPT-partitioned.
fn detect_gpt(src: &Source) -> Result<Vec<Volume>> {
    for sector_size in [512u64, 4096] {
        if let Some(volumes) = detect_gpt_at(src, sector_size, sector_size)? {
            return Ok(volumes);
        }
        if let Some(backup) = src.size.checked_sub(sector_size) {
            if backup >= sector_size {
                if let Some(volumes) = detect_gpt_at(src, sector_size, backup)? {
                    return Ok(volumes);
                }
            }
        }
    }
    Ok(vec![])
}

/// Read the GPT header at byte offset `hdr_off` and probe every partition
/// its entry array names. `None` when there is no usable header there.
fn detect_gpt_at(src: &Source, sector_size: u64, hdr_off: u64) -> Result<Option<Vec<Volume>>> {
    let mut hdr = [0u8; 92];
    if src.read_at(hdr_off, &mut hdr)? < 92 || &hdr[0..8] != b"EFI PART" {
        return Ok(None);
    }
    let entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(hdr[80..84].try_into().unwrap()) as u64;
    let entry_size = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as u64;
    if !(128..=4096).contains(&entry_size) {
        return Ok(None);
    }
    let num_entries = num_entries.min(1024); // guard against corruption
    let Some(array_start) = entry_lba.checked_mul(sector_size) else {
        return Ok(None);
    };

    let mut volumes = Vec::new();
    let mut entry = vec![0u8; entry_size as usize];
    for i in 0..num_entries {
        let off = array_start.saturating_add(i.saturating_mul(entry_size));
        if src.read_at(off, &mut entry)? < entry_size as usize {
            break;
        }
        // An all-zero type GUID marks an unused entry.
        if entry[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        let start_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        if start_lba == 0 {
            continue;
        }
        if let Some(v) = try_parse_volume(src, start_lba.saturating_mul(sector_size))? {
            push_unique(&mut volumes, v);
        }
    }
    Ok(Some(volumes))
}

/// Parse a single volume at an explicit byte offset, trying each backend.
pub fn parse_at(src: &Source, offset: u64) -> Result<Volume> {
    if let Some(v) = encrypted::detect(src, offset) {
        return Ok(Volume::Encrypted(v));
    }
    if let Ok(v) = exfat::Volume::parse(src, offset) {
        return Ok(Volume::Exfat(v));
    }
    if let Ok(v) = ntfs::Volume::parse(src, offset) {
        return Ok(Volume::Ntfs(v));
    }
    if refs::is_refs(src, offset) {
        if let Ok(v) = refs::Volume::parse(src, offset) {
            return Ok(Volume::Refs(v));
        }
    }
    if ext4::is_ext_volume(src, offset) {
        if let Ok(v) = ext4::Volume::parse(src, offset) {
            return Ok(Volume::Ext(v));
        }
    }
    if hfsplus::is_hfsplus(src, offset) {
        if let Ok(v) = hfsplus::Volume::parse(src, offset) {
            return Ok(Volume::Hfs(v));
        }
    }
    if hfs::is_hfs(src, offset) {
        if let Ok(v) = hfs::Volume::parse(src, offset) {
            return Ok(Volume::HfsStd(v));
        }
    }
    if apfs::is_apfs(src, offset) {
        if let Ok(v) = apfs::Volume::parse(src, offset) {
            return Ok(Volume::Apfs(v));
        }
    }
    if btrfs::is_btrfs(src, offset) {
        if let Ok(v) = btrfs::Volume::parse(src, offset) {
            return Ok(Volume::Btrfs(v));
        }
    }
    if xfs::is_xfs(src, offset) {
        if let Ok(v) = xfs::Volume::parse(src, offset) {
            return Ok(Volume::Xfs(v));
        }
    }
    if f2fs::is_f2fs(src, offset) {
        if let Ok(v) = f2fs::Volume::parse(src, offset) {
            return Ok(Volume::F2fs(v));
        }
    }
    if reiserfs::is_reiserfs(src, offset) {
        if let Ok(v) = reiserfs::Volume::parse(src, offset) {
            return Ok(Volume::Reiserfs(v));
        }
    }
    if jfs::is_jfs(src, offset) {
        if let Ok(v) = jfs::Volume::parse(src, offset) {
            return Ok(Volume::Jfs(v));
        }
    }
    if nilfs2::is_nilfs2(src, offset) {
        if let Ok(v) = nilfs2::Volume::parse(src, offset) {
            return Ok(Volume::Nilfs2(v));
        }
    }
    if gfs2::is_gfs2(src, offset) {
        if let Ok(v) = gfs2::Volume::parse(src, offset) {
            return Ok(Volume::Gfs2(v));
        }
    }
    if ocfs2::is_ocfs2(src, offset) {
        if let Ok(v) = ocfs2::Volume::parse(src, offset) {
            return Ok(Volume::Ocfs2(v));
        }
    }
    if minix::is_minix(src, offset) {
        if let Ok(v) = minix::Volume::parse(src, offset) {
            return Ok(Volume::Minix(v));
        }
    }
    if bcachefs::is_bcachefs(src, offset) {
        if let Ok(v) = bcachefs::Volume::parse(src, offset) {
            return Ok(Volume::Bcachefs(v));
        }
    }
    if befs::is_befs(src, offset) {
        if let Ok(v) = befs::Volume::parse(src, offset) {
            return Ok(Volume::Befs(v));
        }
    }
    if ufs::is_ufs(src, offset) {
        if let Ok(v) = ufs::Volume::parse(src, offset) {
            return Ok(Volume::Ufs(v));
        }
    }
    if erofs::is_erofs(src, offset) {
        if let Ok(v) = erofs::Volume::parse(src, offset) {
            return Ok(Volume::Erofs(v));
        }
    }
    if cramfs::is_cramfs(src, offset) {
        if let Ok(v) = cramfs::Volume::parse(src, offset) {
            return Ok(Volume::Cramfs(v));
        }
    }
    if romfs::is_romfs(src, offset) {
        if let Ok(v) = romfs::Volume::parse(src, offset) {
            return Ok(Volume::Romfs(v));
        }
    }
    if lvm::is_lvm(src, offset) {
        if let Ok(v) = lvm::Volume::parse(src, offset) {
            return Ok(Volume::Lvm(v));
        }
    }
    if mdraid::is_mdraid(src, offset) {
        if let Ok(v) = mdraid::Volume::parse(src, offset) {
            return Ok(Volume::Mdraid(v));
        }
    }
    if swap::is_swap(src, offset) {
        if let Ok(v) = swap::Volume::parse(src, offset) {
            return Ok(Volume::Swap(v));
        }
    }
    let v = fat::Volume::parse(src, offset)?;
    Ok(Volume::Fat(v))
}

#[cfg(test)]
mod tests {
    use super::RecoverOptions;

    #[test]
    fn size_ok_applies_the_min_and_max_window() {
        // Default: no bounds, everything passes.
        let any = RecoverOptions::default();
        assert!(any.size_ok(0));
        assert!(any.size_ok(u64::MAX));

        // A min and max together define an inclusive window.
        let windowed = RecoverOptions {
            min_size: 100,
            max_size: Some(1000),
            ..Default::default()
        };
        assert!(!windowed.size_ok(99), "below the floor is rejected");
        assert!(windowed.size_ok(100), "the floor is inclusive");
        assert!(windowed.size_ok(1000), "the cap is inclusive");
        assert!(!windowed.size_ok(1001), "above the cap is rejected");
    }

    #[test]
    fn glob_match_handles_stars_and_question_marks() {
        use super::glob_match;
        assert!(glob_match("*.jpg", "photo.jpg"));
        assert!(glob_match("*.JPG", "photo.jpg"), "case-insensitive");
        assert!(glob_match("IMG_???.png", "img_042.png"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(glob_match("report.pdf", "report.pdf"));
        assert!(!glob_match("*.jpg", "photo.png"));
        assert!(!glob_match("IMG_???.png", "img_42.png"), "? is exactly one");
        assert!(!glob_match("a*b", "axxc"));
    }

    #[test]
    fn name_ok_matches_any_pattern_or_passes_when_empty() {
        let none = RecoverOptions::default();
        assert!(
            none.name_ok("whatever.bin"),
            "no patterns: everything passes"
        );

        let filtered = RecoverOptions {
            names: vec!["*.jpg".to_string(), "*.png".to_string()],
            ..Default::default()
        };
        assert!(filtered.name_ok("a.jpg"));
        assert!(filtered.name_ok("b.PNG"));
        assert!(!filtered.name_ok("c.gif"));
    }

    #[test]
    fn name_ok_applies_excludes() {
        // Exclude-only: everything passes except matches.
        let ex = RecoverOptions {
            exclude_names: vec!["*.tmp".to_string(), "Thumbs.db".to_string()],
            ..Default::default()
        };
        assert!(ex.name_ok("photo.jpg"));
        assert!(!ex.name_ok("cache.tmp"));
        assert!(!ex.name_ok("thumbs.db"), "case-insensitive exclude");

        // Excludes are applied after includes (exclude wins on overlap).
        let both = RecoverOptions {
            names: vec!["*.txt".to_string()],
            exclude_names: vec!["draft*".to_string()],
            ..Default::default()
        };
        assert!(both.name_ok("notes.txt"));
        assert!(
            !both.name_ok("draft.txt"),
            "excluded even though it matches include"
        );
        assert!(!both.name_ok("photo.jpg"), "not an include match");
    }

    #[test]
    fn capability_matrix_lists_every_variant_once() {
        let names: Vec<&str> = super::capability_matrix()
            .iter()
            .map(|c| c.filesystem)
            .collect();
        let mut dedup = names.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(names.len(), dedup.len(), "duplicate row: {names:?}");
        let md = super::capability_markdown();
        assert!(md.starts_with("| Filesystem |"));
        assert_eq!(md.lines().count(), names.len() + 2);
        // Undelete is only claimed for the five filesystems with a real-image corpus.
        let yes: Vec<&str> = super::capability_matrix()
            .iter()
            .filter(|c| c.undelete == super::Support::Yes)
            .map(|c| c.filesystem)
            .collect();
        assert_eq!(
            yes,
            ["FAT12/16/32", "exFAT", "NTFS", "ext2/3/4", "HFS+/HFSX"]
        );
    }

    #[test]
    fn free_walk_skips_allocated_and_wraps_once() {
        // Clusters 2..=9; 4 and 5 allocated; start at 7.
        let allocated = [4u32, 5];
        let mut w = super::FreeWalk::new(7, 9, |c| !allocated.contains(&c));
        assert_eq!(w.next_after(7, true), Some(8));
        assert_eq!(w.next_after(8, true), Some(9));
        // End of volume: wrap to the first free cluster, 2.
        assert_eq!(w.next_after(9, true), Some(2));
        assert_eq!(w.next_after(2, true), Some(3));
        // 4 and 5 are allocated, 6 is free, then the start cluster stops it.
        assert_eq!(w.next_after(3, true), Some(6));
        assert_eq!(w.next_after(6, true), None);
        // Without permission to wrap, the volume end is the end.
        let mut w = super::FreeWalk::new(7, 9, |_| true);
        assert_eq!(w.next_after(9, false), None);
    }

    #[test]
    fn output_paths_stay_inside_the_output_directory() {
        use std::path::{Path, PathBuf};
        let out = Path::new("/recovered");
        assert_eq!(
            super::confine(Path::new("a/b.txt")),
            PathBuf::from("a/b.txt")
        );
        assert_eq!(
            super::confine(Path::new("../../etc/passwd")),
            PathBuf::from("etc/passwd")
        );
        assert_eq!(
            super::confine(Path::new("/etc/passwd")),
            PathBuf::from("etc/passwd")
        );
        assert_eq!(super::confine(Path::new("a/../../b")), PathBuf::from("a/b"));
        assert!(super::unique_path(out, Path::new("../x")).starts_with(out));
        assert!(super::unique_path(out, Path::new("..")).starts_with(out));
        assert_eq!(
            super::unique_path(out, Path::new("..")),
            out.join("_recovered")
        );
    }

    #[test]
    fn sanitize_component_is_portable() {
        assert_eq!(super::sanitize_component("a/b"), "a_b");
        assert_eq!(super::sanitize_component("a\\b"), "a_b");
        assert_eq!(super::sanitize_component("tab\tname"), "tab_name");
        assert_eq!(super::sanitize_component(""), "_recovered");
        assert_eq!(super::sanitize_component(".."), "_recovered");
        assert_eq!(super::sanitize_component("  spaced  "), "spaced");
        if cfg!(windows) {
            assert_eq!(
                super::sanitize_component("report:final?.txt"),
                "report_final_.txt"
            );
            assert_eq!(super::sanitize_component("CON"), "_CON");
            assert_eq!(super::sanitize_component("com1.txt"), "_com1.txt");
            assert_eq!(super::sanitize_component("trailing."), "trailing");
        } else {
            assert_eq!(
                super::sanitize_component("report:final?.txt"),
                "report:final?.txt"
            );
            assert_eq!(super::sanitize_component("CON"), "CON");
        }
        assert!(super::is_windows_reserved("NUL"));
        assert!(super::is_windows_reserved("lpt9.log"));
        assert!(!super::is_windows_reserved("COM0"));
        assert!(!super::is_windows_reserved("CONSOLE"));
    }
}
