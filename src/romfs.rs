//! romfs (ROM File System) **detection** — no metadata undelete.
//!
//! romfs is a tiny, uncompressed read-only Linux filesystem used for small
//! initrds and embedded systems. Being read-only it has no deleted files to
//! scavenge, so this module only *recognises* a romfs volume — reporting its
//! size and volume name so `info` / `list_volumes` show it instead of leaving it
//! unrecognised — and leaves extraction to `scan` (carving).
//!
//! The header is at offset 0: the 8-byte magic `-rom1fs-`, then the full image
//! size and a checksum (both big-endian), then a NUL-terminated volume name.
//! romfs is defined big-endian on every platform.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// The 8-byte magic at offset 0.
const MAGIC: &[u8; 8] = b"-rom1fs-";
/// Byte offsets within the header.
const SIZE_OFFSET: usize = 0x08; // big-endian u32: full image size
const NAME_OFFSET: usize = 0x10; // NUL-terminated volume name
/// We read this much of the header to cover the magic, size, and a bounded name.
const HEADER_LEN: usize = NAME_OFFSET + 64;

/// A recognised romfs volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    /// Volume name, empty when unset.
    label: String,
}

/// The header checksum covers this much of the image: the big-endian 32-bit
/// words of the first 512 bytes (or the whole image when smaller) sum to
/// zero, the checksum field included.
const CHECKSUM_SPAN: usize = 512;

/// Does a romfs header sit at `vol_offset`? The magic alone is eight bytes,
/// but a magic with random bytes behind it is not a volume: the header
/// checksum must hold too.
pub fn is_romfs(src: &Source, vol_offset: u64) -> bool {
    let mut head = [0u8; CHECKSUM_SPAN];
    let n = src.read_at(vol_offset, &mut head).unwrap_or(0);
    n >= NAME_OFFSET && head[0..8] == *MAGIC && checksum_ok(&head[..n])
}

/// Whether the romfs header checksum holds over `head` (the first 512 bytes
/// of the image, or all of it if shorter). `mkfs` picks the checksum field
/// so the big-endian word sum wraps to zero.
fn checksum_ok(head: &[u8]) -> bool {
    let recorded = u32::from_be_bytes(head[SIZE_OFFSET..SIZE_OFFSET + 4].try_into().unwrap());
    let span = head
        .len()
        .min(CHECKSUM_SPAN)
        .min(recorded.max(NAME_OFFSET as u32) as usize);
    let sum = head[..span]
        .chunks(4)
        .map(|w| {
            let mut b = [0u8; 4];
            b[..w.len()].copy_from_slice(w);
            u32::from_be_bytes(b)
        })
        .fold(0u32, |acc, w| acc.wrapping_add(w));
    sum == 0
}

impl Volume {
    /// Parse the romfs header at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut head = [0u8; CHECKSUM_SPAN];
        // A short read is fine as long as it covers the magic and size.
        let n = src.read_at(offset, &mut head)?;
        if n < NAME_OFFSET || &head[0..8] != MAGIC {
            bail!("not a romfs volume");
        }
        if !checksum_ok(&head[..n]) {
            bail!("romfs header checksum does not hold");
        }
        let hdr = &head[..n.min(HEADER_LEN)];
        let n = hdr.len();
        let recorded =
            u32::from_be_bytes(hdr[SIZE_OFFSET..SIZE_OFFSET + 4].try_into().unwrap()) as u64;
        // Fall back to the source span when the recorded size is zero or exceeds
        // what the source can hold.
        let fallback = src.size.saturating_sub(offset);
        let size = if recorded > 0 && recorded <= fallback.max(NAME_OFFSET as u64) {
            recorded
        } else {
            fallback
        };
        // The volume name is NUL-terminated within the bytes we read.
        let raw = &hdr[NAME_OFFSET..n.max(NAME_OFFSET)];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let label = String::from_utf8_lossy(&raw[..end]).into_owned();
        Ok(Volume {
            offset,
            size,
            label,
        })
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "romfs"
    }

    /// The volume name, or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// romfs is read-only, so there are no deleted files to undelete; always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from a romfs volume.
    pub fn recover_deleted(
        &self,
        _src: &Source,
        _out_dir: &Path,
        _opts: &RecoverOptions,
    ) -> Result<RecoverStats> {
        Ok(RecoverStats::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a romfs volume of `total` bytes, with the header checksum set
    /// the way `genromfs` sets it.
    fn romfs_image(size: u32, name: &str, total: usize) -> Vec<u8> {
        let mut v = vec![0u8; total];
        v[0..8].copy_from_slice(MAGIC);
        v[SIZE_OFFSET..SIZE_OFFSET + 4].copy_from_slice(&size.to_be_bytes());
        let nb = name.as_bytes();
        v[NAME_OFFSET..NAME_OFFSET + nb.len()].copy_from_slice(nb);
        let span = total
            .min(CHECKSUM_SPAN)
            .min(size.max(NAME_OFFSET as u32) as usize);
        let sum = v[..span]
            .chunks(4)
            .map(|w| {
                let mut b = [0u8; 4];
                b[..w.len()].copy_from_slice(w);
                u32::from_be_bytes(b)
            })
            .fold(0u32, |acc, w| acc.wrapping_add(w));
        v[12..16].copy_from_slice(&(0u32.wrapping_sub(sum)).to_be_bytes());
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("romfs.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_size_and_name() {
        let (_t, src) = source_of(&romfs_image(90 * 1024, "boot", 256 * 1024));
        assert!(is_romfs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "romfs");
        assert_eq!(v.size(), 90 * 1024);
        assert_eq!(v.label(), "boot");
    }

    #[test]
    fn falls_back_to_span_on_implausible_size() {
        let (_t, src) = source_of(&romfs_image(0xFFFF_FFFF, "x", 64 * 1024));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.size(), 64 * 1024);
    }

    /// The magic with a wrong checksum is random data wearing a magic, not a
    /// volume: it must not be reported, whatever the size field says.
    #[test]
    fn rejects_a_magic_whose_checksum_does_not_hold() {
        let mut v = romfs_image(90 * 1024, "boot", 256 * 1024);
        v[12] ^= 0x01;
        let (_t, src) = source_of(&v);
        assert!(!is_romfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }

    #[test]
    fn rejects_non_romfs() {
        let (_t, src) = source_of(&vec![0u8; 64 * 1024]);
        assert!(!is_romfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
