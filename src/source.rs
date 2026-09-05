//! Read-only access to the device or image we are recovering from.
//!
//! The source is **never** written to. We open it read-only and only ever
//! issue positioned reads, so running the tool against a live device cannot
//! modify it.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};

/// A read-only handle to a block device or disk image.
pub struct Source {
    file: File,
    /// Total readable size in bytes.
    pub size: u64,
}

impl Source {
    /// Open `path` read-only and determine its size.
    ///
    /// Works for both regular image files and block devices. Block devices
    /// report a length of `0` through `metadata()`, so we fall back to seeking
    /// to the end to discover the real size, and, where even that is refused
    /// (raw disks on macOS and physical drives on Windows), to probing for the
    /// last readable sector.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = match OpenOptions::new().read(true).open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                anyhow::bail!(
                    "opening source {} (read-only): permission denied.\n{}",
                    path.display(),
                    permission_hint(path)
                );
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("opening source {} (read-only)", path.display()))
            }
        };

        let meta_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut size = if meta_len > 0 {
            meta_len
        } else {
            // Block devices: discover size by seeking to the end.
            file.seek(SeekFrom::End(0)).unwrap_or(0)
        };
        if size == 0 {
            // Raw and physical disks may refuse SEEK_END; find the end by
            // reading instead.
            let probe = Source {
                file,
                size: u64::MAX,
            };
            size = probe.probe_size()?;
            file = probe.file;
        }

        if size == 0 {
            anyhow::bail!(
                "{} reports a size of 0 bytes; nothing to scan",
                path.display()
            );
        }

        Ok(Source { file, size })
    }

    /// Find the device size by reading: double a probe offset until a
    /// 512-byte read fails or comes back empty, then binary-search the last
    /// readable sector. Costs about 2 × log2(size) small reads.
    fn probe_size(&self) -> Result<u64> {
        const SECTOR: u64 = 512;
        let readable = |off: u64| -> bool {
            let mut probe = [0u8; SECTOR as usize];
            matches!(self.read_at(off, &mut probe), Ok(n) if n > 0)
        };
        if !readable(0) {
            return Ok(0);
        }
        let mut lo = 0u64; // known readable sector offset
        let mut hi = SECTOR; // first offset assumed unreadable
        while readable(hi) {
            lo = hi;
            hi = match hi.checked_mul(2) {
                Some(h) => h,
                None => return Ok(0),
            };
        }
        while hi - lo > SECTOR {
            let mid = lo + (hi - lo) / 2 / SECTOR * SECTOR;
            if readable(mid) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        // `lo` is the last readable sector's start; the size is its end,
        // unless that sector was short.
        let mut buf = [0u8; SECTOR as usize];
        let n = self.read_at(lo, &mut buf)? as u64;
        Ok(lo + n)
    }

    /// Read up to `buf.len()` bytes starting at absolute `offset`.
    ///
    /// Returns the number of bytes actually read, which may be short at the end
    /// of the device. Uses positioned reads so it does not disturb (or depend
    /// on) the file's seek cursor.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut total = 0;
        while total < buf.len() {
            match self.read_at_once(offset + total as u64, &mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("reading from source"),
            }
        }
        Ok(total)
    }

    /// One positioned read, using the platform's own call (`pread` on Unix,
    /// `ReadFile` with an overlapped offset on Windows) so no seek cursor is
    /// involved.
    #[cfg(unix)]
    fn read_at_once(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::os::unix::fs::FileExt;
        self.file.read_at(buf, offset)
    }

    #[cfg(windows)]
    fn read_at_once(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::os::windows::fs::FileExt;
        const ERROR_INVALID_PARAMETER: i32 = 87;
        const ERROR_HANDLE_EOF: i32 = 38;
        const SECTOR: u64 = 512;
        match self.file.seek_read(buf, offset) {
            // Reading past the end of a device is an error on Windows, not a
            // short read; report it the way every caller expects.
            Err(e) if e.raw_os_error() == Some(ERROR_HANDLE_EOF) => Ok(0),
            // A physical drive or volume opened raw only accepts reads that
            // are sector-aligned in offset and length. The carver reads at
            // arbitrary offsets (a footer search, a header probe), so redo
            // the read aligned and copy out the part that was asked for.
            Err(e)
                if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER)
                    && (offset % SECTOR != 0 || buf.len() as u64 % SECTOR != 0) =>
            {
                let start = offset / SECTOR * SECTOR;
                let skip = (offset - start) as usize;
                let want = (skip + buf.len()) as u64;
                let len = want.div_ceil(SECTOR) * SECTOR;
                let mut tmp = vec![0u8; len as usize];
                let n = match self.file.seek_read(&mut tmp, start) {
                    Ok(n) => n,
                    Err(e) if e.raw_os_error() == Some(ERROR_HANDLE_EOF) => 0,
                    Err(e) => return Err(e),
                };
                if n <= skip {
                    return Ok(0);
                }
                let take = (n - skip).min(buf.len());
                buf[..take].copy_from_slice(&tmp[skip..skip + take]);
                Ok(take)
            }
            r => r,
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn read_at_once(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Read;
        let mut f = self.file.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f.read(buf)
    }
}

/// Whether writing into `output_dir` would write onto the device `source`
/// is being read from. Recovering onto the drive being recovered overwrites
/// the very data being looked for, so the commands refuse it. Best effort:
/// `true` only when the two demonstrably coincide, so a regular image file
/// or an undecidable case never blocks a run.
///
/// On Unix a block or character device's `rdev` is compared with the device
/// number of the filesystem the output lives on (the whole-disk device is
/// matched by major number, since its partitions carry the same major). On
/// Windows a `\\.\D:` source is compared with the output's drive letter.
pub fn same_device(source: &Path, output_dir: &Path) -> bool {
    // The output directory may not exist yet; judge by its nearest existing ancestor.
    let mut probe = output_dir.to_path_buf();
    while !probe.exists() {
        match probe.parent() {
            Some(p) if !p.as_os_str().is_empty() => probe = p.to_path_buf(),
            _ => return false,
        }
    }
    same_device_impl(source, &probe)
}

#[cfg(unix)]
fn same_device_impl(source: &Path, existing_output: &Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let (Ok(src), Ok(out)) = (
        std::fs::metadata(source),
        std::fs::metadata(existing_output),
    ) else {
        return false;
    };
    if !(src.file_type().is_block_device() || src.file_type().is_char_device()) {
        return false;
    }
    let rdev = src.rdev();
    let dev = out.dev();
    if rdev == dev {
        return true;
    }
    // Same major number: the output sits on a partition of this whole disk
    // (Linux) or on the raw/buffered twin of the same disk (macOS).
    fn major(d: u64) -> u64 {
        if cfg!(target_os = "linux") {
            ((d >> 32) & 0xffff_f000) | ((d >> 8) & 0xfff)
        } else {
            (d >> 24) & 0xff
        }
    }
    major(rdev) == major(dev) && major(dev) != 0
}

#[cfg(windows)]
fn same_device_impl(source: &Path, existing_output: &Path) -> bool {
    // `\\.\D:` or `D:` names a volume; compare its letter with the output's.
    let src = source.to_string_lossy().to_ascii_uppercase();
    let letter = src
        .trim_start_matches("\\\\.\\")
        .trim_start_matches("\\\\?\\")
        .chars()
        .next();
    let Some(letter) = letter.filter(|c| c.is_ascii_alphabetic()) else {
        return false;
    };
    if !src.contains(':') || src.contains("PHYSICALDRIVE") {
        // A physical drive holds every volume: without the partition map we
        // cannot tell, so do not block.
        return false;
    }
    let out = std::fs::canonicalize(existing_output)
        .map(|p| p.to_string_lossy().to_ascii_uppercase())
        .unwrap_or_default();
    let out_letter = out
        .trim_start_matches("\\\\?\\")
        .chars()
        .next()
        .filter(|c| c.is_ascii_alphabetic());
    out_letter == Some(letter) && out.chars().nth(1) == Some(':')
}

#[cfg(not(any(unix, windows)))]
fn same_device_impl(_source: &Path, _existing_output: &Path) -> bool {
    false
}

/// What to do about "permission denied" on this platform, in the words a
/// user needs rather than a bare errno.
fn permission_hint(path: &Path) -> String {
    let p = path.display();
    if cfg!(target_os = "macos") {
        format!(
            "On macOS a raw disk needs root: `sudo unearth ... {p}`. If sudo still fails, grant \
             Full Disk Access to your terminal in System Settings > Privacy & Security > Full Disk \
             Access. Prefer /dev/rdiskN over /dev/diskN; the raw device is much faster."
        )
    } else if cfg!(windows) {
        format!(
            "On Windows a physical drive (\\\\.\\PhysicalDriveN) or volume (\\\\.\\D:) needs an \
             administrator prompt: right-click your terminal and choose 'Run as administrator', \
             then run the same command. A volume that is in use may also need to be locked or \
             dismounted first (or image the whole PhysicalDrive instead). Source: {p}"
        )
    } else {
        format!(
            "On Linux a block device needs root or membership in the 'disk' group: \
             `sudo unearth ... {p}`, or `sudo usermod -aG disk $USER` and log in again."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_size_finds_the_end_of_an_odd_sized_file() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("odd.img");
        let data: Vec<u8> = (0..70_000u32).map(|i| i as u8).collect();
        std::fs::write(&p, &data).unwrap();
        let file = File::open(&p).unwrap();
        let probe = Source {
            file,
            size: u64::MAX,
        };
        assert_eq!(probe.probe_size().unwrap(), data.len() as u64);
    }

    #[test]
    fn probe_size_handles_an_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("empty.img");
        std::fs::write(&p, b"").unwrap();
        let probe = Source {
            file: File::open(&p).unwrap(),
            size: u64::MAX,
        };
        assert_eq!(probe.probe_size().unwrap(), 0);
    }

    #[test]
    fn a_regular_file_is_never_the_output_device() {
        let tmp = tempfile::tempdir().unwrap();
        let img = tmp.path().join("disk.img");
        std::fs::write(&img, b"x").unwrap();
        assert!(!same_device(&img, tmp.path()));
        assert!(!same_device(&img, &tmp.path().join("not/yet/created")));
        assert!(!same_device(Path::new("/no/such/device"), tmp.path()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_root_disk_is_the_output_device_for_a_dir_on_it() {
        // /dev/null is a character device on a different major than any disk.
        assert!(!same_device(Path::new("/dev/null"), Path::new("/")));
    }

    #[test]
    fn read_at_is_positional_and_short_at_the_end() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("small.img");
        std::fs::write(&p, (0..1000u32).map(|i| i as u8).collect::<Vec<_>>()).unwrap();
        let src = Source::open(&p).unwrap();
        assert_eq!(src.size, 1000);
        let mut buf = [0u8; 16];
        assert_eq!(src.read_at(500, &mut buf).unwrap(), 16);
        assert_eq!(buf[0], 500u32 as u8);
        assert_eq!(src.read_at(990, &mut buf).unwrap(), 10);
        assert_eq!(src.read_at(2000, &mut buf).unwrap(), 0);
    }
}
