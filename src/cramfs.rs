//! cramfs (Compressed ROM File System) **detection** — no metadata undelete.
//!
//! cramfs is a small compressed read-only Linux filesystem, long used for
//! initrds, embedded systems, and router/appliance firmware. Being read-only and
//! compressed it has no deleted files to scavenge, so this module only
//! *recognises* a cramfs volume — reporting its size and label so `info` /
//! `list_volumes` show it instead of leaving it unrecognised — and leaves
//! extraction to `scan` (carving).
//!
//! The superblock is at offset 0 and is identified by the magic `0x28CD3D45`
//! plus the ASCII signature `Compressed ROMFS` at offset 0x10 — together an
//! unambiguous match. Images may be big- or little-endian; the byte order is
//! taken from the magic.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// `magic` (u32) at superblock offset 0.
const MAGIC: u32 = 0x28CD_3D45;
/// The ASCII signature at offset 0x10 confirms the magic.
const SIGNATURE: &[u8; 16] = b"Compressed ROMFS";
/// Byte offsets within the superblock.
const SIZE_OFFSET: usize = 0x04; // u32: total image size in bytes
const FLAGS_OFFSET: usize = 0x08; // u32: feature flags
const FUTURE_OFFSET: usize = 0x0C; // u32: reserved, always zero
/// Every flag bit a kernel knows; a set bit outside these is not cramfs.
const SUPPORTED_FLAGS: u32 = 0x0000_0FFF;
const SIGNATURE_OFFSET: usize = 0x10; // 16 bytes
const NAME_OFFSET: usize = 0x30; // 16 bytes, NUL-padded
/// We read this much of the superblock to cover every field above.
const HEADER_LEN: usize = NAME_OFFSET + 16;
/// cramfs compresses in fixed 4 KiB blocks.
const BLOCK_SIZE: u64 = 4096;

/// A recognised cramfs volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    /// Volume name, empty when unset.
    label: String,
}

/// The byte order of a cramfs superblock at `hdr`, or `None` if it is not one.
/// `Some(true)` is big-endian. The magic and the signature must both match,
/// and the fields between them must be ones `mkcramfs` writes: the reserved
/// word is zero and no unknown flag bit is set, so a magic and signature
/// pasted over random bytes is not taken for a volume.
fn byte_order(hdr: &[u8]) -> Option<bool> {
    if &hdr[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16] != SIGNATURE {
        return None;
    }
    let m = hdr[0..4].try_into().unwrap();
    let big = if u32::from_le_bytes(m) == MAGIC {
        false
    } else if u32::from_be_bytes(m) == MAGIC {
        true
    } else {
        return None;
    };
    let rd = |o: usize| {
        let a = hdr[o..o + 4].try_into().unwrap();
        if big {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };
    if rd(FUTURE_OFFSET) != 0 || rd(FLAGS_OFFSET) & !SUPPORTED_FLAGS != 0 {
        return None;
    }
    Some(big)
}

/// Does a cramfs superblock sit at `vol_offset`?
pub fn is_cramfs(src: &Source, vol_offset: u64) -> bool {
    let mut hdr = [0u8; HEADER_LEN];
    src.read_at(vol_offset, &mut hdr).unwrap_or(0) >= HEADER_LEN && byte_order(&hdr).is_some()
}

impl Volume {
    /// Parse the cramfs superblock at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(offset, &mut hdr)? < HEADER_LEN {
            bail!("cramfs superblock truncated");
        }
        let Some(big) = byte_order(&hdr) else {
            bail!("not a cramfs volume");
        };
        let a = hdr[SIZE_OFFSET..SIZE_OFFSET + 4].try_into().unwrap();
        let recorded = if big {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        } as u64;
        // Fall back to the source span when the recorded size is zero or exceeds
        // what the source can hold.
        let fallback = src.size.saturating_sub(offset);
        let size = if recorded > 0 && recorded <= fallback.max(BLOCK_SIZE) {
            recorded
        } else {
            fallback
        };
        let raw = &hdr[NAME_OFFSET..NAME_OFFSET + 16];
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

    /// Block size in bytes (cramfs compresses in fixed 4 KiB blocks).
    pub fn block_size(&self) -> u64 {
        BLOCK_SIZE
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "cramfs"
    }

    /// The volume name, or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// cramfs is read-only, so there are no deleted files to undelete; always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from a cramfs volume.
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

    /// Build a cramfs volume of `total` bytes.
    fn cramfs_image(size: u32, name: &str, big: bool, total: usize) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let m = if big {
            MAGIC.to_be_bytes()
        } else {
            MAGIC.to_le_bytes()
        };
        v[0..4].copy_from_slice(&m);
        let s = if big {
            size.to_be_bytes()
        } else {
            size.to_le_bytes()
        };
        v[SIZE_OFFSET..SIZE_OFFSET + 4].copy_from_slice(&s);
        v[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].copy_from_slice(SIGNATURE);
        let nb = name.as_bytes();
        v[NAME_OFFSET..NAME_OFFSET + nb.len()].copy_from_slice(nb);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("cramfs.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_little_endian_size_and_name() {
        let (_t, src) = source_of(&cramfs_image(120 * 1024, "rootfs", false, 256 * 1024));
        assert!(is_cramfs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "cramfs");
        assert_eq!(v.size(), 120 * 1024);
        assert_eq!(v.block_size(), 4096);
        assert_eq!(v.label(), "rootfs");
    }

    #[test]
    fn detects_big_endian() {
        let (_t, src) = source_of(&cramfs_image(64 * 1024, "fw", true, 256 * 1024));
        assert!(is_cramfs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.size(), 64 * 1024);
        assert_eq!(v.label(), "fw");
    }

    #[test]
    fn rejects_a_superblock_with_unknown_flags_or_reserved_bits() {
        let good = cramfs_image(120 * 1024, "rootfs", false, 256 * 1024);
        let (_t, src) = source_of(&good);
        assert!(is_cramfs(&src, 0));
        let mut flags = good.clone();
        flags[FLAGS_OFFSET + 2] = 0x10; // bit 20: no kernel defines it
        let (_t, src) = source_of(&flags);
        assert!(!is_cramfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
        let mut future = good;
        future[FUTURE_OFFSET] = 1;
        let (_t, src) = source_of(&future);
        assert!(!is_cramfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }

    #[test]
    fn rejects_magic_without_signature() {
        // The magic alone, without the ASCII signature, is not enough.
        let mut v = vec![0u8; 64 * 1024];
        v[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        let (_t, src) = source_of(&v);
        assert!(!is_cramfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
