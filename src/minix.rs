//! Minix filesystem **detection** — no metadata undelete.
//!
//! The Minix filesystem is the one the earliest Linux ran on, and it survives on
//! boot floppies, small/embedded media, and RAM disks. Three on-disk versions
//! exist (v1, v2, v3); all keep their superblock in the second 1 KiB block, but
//! the magic sits at a version-dependent offset. The format is minimal and long
//! superseded, so this module only *recognises* a Minix volume — reporting its
//! version and size so `info` / `list_volumes` show it instead of leaving it
//! unrecognised — and leaves recovery to `scan` (carving). Minix has no on-disk
//! volume label or UUID, so none is reported.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// The superblock sits in the second 1 KiB block.
const SB_OFFSET: u64 = 1024;
/// Field offsets within the superblock block (little-endian throughout).
const NZONES_V1_OFFSET: usize = 0x02; // u16: zone count (v1)
const LOG_ZONE_OFFSET: usize = 0x0A; // u16: log2(zone size / block size)
const MAGIC_V12_OFFSET: usize = 0x10; // u16: v1/v2 magic
const ZONES_V23_OFFSET: usize = 0x14; // u32: zone count (v2 and v3)
const MAGIC_V3_OFFSET: usize = 0x18; // u16: v3 magic
const BLOCKSIZE_V3_OFFSET: usize = 0x1C; // u16: block size (v3)
/// We read this much of the block to cover every field above.
const HEADER_LEN: usize = 0x20;
/// The v1/v2 block size is fixed at 1 KiB.
const BLOCK_SIZE: u64 = 1024;

/// Minix magic numbers, by on-disk version (the two values per classic version
/// distinguish 14- from 30-character filenames).
const MAGIC_V1: u16 = 0x137F;
const MAGIC_V1_30: u16 = 0x138F;
const MAGIC_V2: u16 = 0x2468;
const MAGIC_V2_30: u16 = 0x2478;
const MAGIC_V3: u16 = 0x4D5A;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Version {
    V1,
    V2,
    V3,
}

/// A recognised Minix volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    /// Block size in bytes.
    block_size: u64,
    version: Version,
}

/// Classify the superblock block bytes as a Minix version, or `None`.
fn classify(hdr: &[u8]) -> Option<Version> {
    let m12 = u16::from_le_bytes(
        hdr[MAGIC_V12_OFFSET..MAGIC_V12_OFFSET + 2]
            .try_into()
            .unwrap(),
    );
    let m3 = u16::from_le_bytes(
        hdr[MAGIC_V3_OFFSET..MAGIC_V3_OFFSET + 2]
            .try_into()
            .unwrap(),
    );
    if m12 == MAGIC_V1 || m12 == MAGIC_V1_30 {
        Some(Version::V1)
    } else if m12 == MAGIC_V2 || m12 == MAGIC_V2_30 {
        Some(Version::V2)
    } else if m3 == MAGIC_V3 {
        Some(Version::V3)
    } else {
        None
    }
}

/// Does a Minix superblock sit at `vol_offset`?
pub fn is_minix(src: &Source, vol_offset: u64) -> bool {
    let Some(at) = vol_offset.checked_add(SB_OFFSET) else {
        return false;
    };
    let mut hdr = [0u8; HEADER_LEN];
    src.read_at(at, &mut hdr).unwrap_or(0) >= HEADER_LEN
        && classify(&hdr).is_some_and(|v| geometry_ok(&hdr, v))
}

/// Whether the superblock's layout fields describe a filesystem `mkfs` could
/// have written. The magic is two bytes, which random data matches once in
/// 32 Ki probes, so it cannot carry detection on its own; the bitmap block
/// counts, the first data zone, and the zone-size shift can. The v1/v2
/// superblock keeps `s_imap_blocks`, `s_zmap_blocks`, `s_firstdatazone`, and
/// `s_log_zone_size` at 4, 6, 8, and 0xA; v3 widens `s_ninodes` and keeps
/// them at 6, 8, 0xA, and 0xC.
fn geometry_ok(hdr: &[u8], version: Version) -> bool {
    let u16_at = |o: usize| u16::from_le_bytes([hdr[o], hdr[o + 1]]) as u64;
    let u32_at = |o: usize| u32::from_le_bytes(hdr[o..o + 4].try_into().unwrap()) as u64;
    let (ninodes, imap, zmap, first_data, log, zones) = match version {
        Version::V1 => (
            u16_at(0),
            u16_at(4),
            u16_at(6),
            u16_at(8),
            u16_at(0xA),
            u16_at(NZONES_V1_OFFSET),
        ),
        Version::V2 => (
            u16_at(0),
            u16_at(4),
            u16_at(6),
            u16_at(8),
            u16_at(0xA),
            u32_at(ZONES_V23_OFFSET),
        ),
        Version::V3 => (
            u32_at(0),
            u16_at(6),
            u16_at(8),
            u16_at(0xA),
            u16_at(0xC),
            u32_at(ZONES_V23_OFFSET),
        ),
    };
    if version == Version::V3 {
        let bs = u16_at(BLOCKSIZE_V3_OFFSET);
        if !(1024..=65536).contains(&bs) || !bs.is_power_of_two() {
            return false;
        }
    }
    // Every volume has inodes, both bitmaps, and data zones after the
    // boot block, superblock, and bitmaps; zone sizes past 256 KiB do not
    // exist.
    ninodes > 0
        && imap > 0
        && zmap > 0
        && zones > 0
        && log <= 8
        && first_data >= 2 + imap + zmap
        && first_data < zones
}

impl Volume {
    /// Parse the Minix superblock at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let at = offset
            .checked_add(SB_OFFSET)
            .ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(at, &mut hdr)? < HEADER_LEN {
            bail!("Minix superblock truncated");
        }
        let Some(version) = classify(&hdr) else {
            bail!("not a Minix volume");
        };
        if !geometry_ok(&hdr, version) {
            bail!("implausible Minix geometry");
        }
        let log = u16::from_le_bytes(
            hdr[LOG_ZONE_OFFSET..LOG_ZONE_OFFSET + 2]
                .try_into()
                .unwrap(),
        );
        let zones_v23 = u32::from_le_bytes(
            hdr[ZONES_V23_OFFSET..ZONES_V23_OFFSET + 4]
                .try_into()
                .unwrap(),
        ) as u64;
        let size = match version {
            Version::V1 => {
                let zones = u16::from_le_bytes(
                    hdr[NZONES_V1_OFFSET..NZONES_V1_OFFSET + 2]
                        .try_into()
                        .unwrap(),
                ) as u64;
                zones.checked_shl(10 + log as u32).unwrap_or(0)
            }
            Version::V2 => zones_v23.checked_shl(10 + log as u32).unwrap_or(0),
            Version::V3 => {
                let bs = u16::from_le_bytes(
                    hdr[BLOCKSIZE_V3_OFFSET..BLOCKSIZE_V3_OFFSET + 2]
                        .try_into()
                        .unwrap(),
                ) as u64;
                // A v3 block size of zero is implausible; fall back to 1 KiB.
                zones_v23.saturating_mul(if bs == 0 { BLOCK_SIZE } else { bs })
            }
        };
        // Fall back to the source span when the computed size is zero or exceeds
        // what the source can hold.
        let fallback = src.size.saturating_sub(offset);
        let size = if size > 0 && size <= fallback.max(BLOCK_SIZE) {
            size
        } else {
            fallback
        };
        // v1/v2 use a fixed 1 KiB block; v3 records its own block size.
        let block_size = match version {
            Version::V1 | Version::V2 => BLOCK_SIZE,
            Version::V3 => {
                let bs = u16::from_le_bytes(
                    hdr[BLOCKSIZE_V3_OFFSET..BLOCKSIZE_V3_OFFSET + 2]
                        .try_into()
                        .unwrap(),
                ) as u64;
                if bs == 0 {
                    BLOCK_SIZE
                } else {
                    bs
                }
            }
        };
        Ok(Volume {
            offset,
            size,
            block_size,
            version,
        })
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Block size in bytes.
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    /// Short filesystem label, including the on-disk version.
    pub fn fs_label(&self) -> &'static str {
        match self.version {
            Version::V1 => "Minix",
            Version::V2 => "Minix v2",
            Version::V3 => "Minix v3",
        }
    }

    /// Minix metadata undelete is not supported (see the module docs); always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from a Minix volume.
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

    /// The layout fields every version shares in spirit: 32 inodes, one
    /// block per bitmap, first data zone right after them.
    fn layout(v: &mut [u8], ninodes_off: usize, imap_off: usize) {
        let sb = SB_OFFSET as usize;
        v[sb + ninodes_off..sb + ninodes_off + 2].copy_from_slice(&32u16.to_le_bytes());
        v[sb + imap_off..sb + imap_off + 2].copy_from_slice(&1u16.to_le_bytes());
        v[sb + imap_off + 2..sb + imap_off + 4].copy_from_slice(&1u16.to_le_bytes());
        v[sb + imap_off + 4..sb + imap_off + 6].copy_from_slice(&5u16.to_le_bytes());
    }

    /// Build a v1/v2 Minix volume (magic at 0x10).
    fn minix_v12(magic: u16, nzones_v1: u16, zones_v2: u32, log: u16, total: usize) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let sb = SB_OFFSET as usize;
        layout(&mut v, 0, 4);
        v[sb + NZONES_V1_OFFSET..sb + NZONES_V1_OFFSET + 2]
            .copy_from_slice(&nzones_v1.to_le_bytes());
        v[sb + LOG_ZONE_OFFSET..sb + LOG_ZONE_OFFSET + 2].copy_from_slice(&log.to_le_bytes());
        v[sb + MAGIC_V12_OFFSET..sb + MAGIC_V12_OFFSET + 2].copy_from_slice(&magic.to_le_bytes());
        v[sb + ZONES_V23_OFFSET..sb + ZONES_V23_OFFSET + 4]
            .copy_from_slice(&zones_v2.to_le_bytes());
        v
    }

    /// Build a v3 Minix volume (magic at 0x18).
    fn minix_v3(zones: u32, blocksize: u16, total: usize) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let sb = SB_OFFSET as usize;
        layout(&mut v, 0, 6);
        v[sb + ZONES_V23_OFFSET..sb + ZONES_V23_OFFSET + 4].copy_from_slice(&zones.to_le_bytes());
        v[sb + MAGIC_V3_OFFSET..sb + MAGIC_V3_OFFSET + 2].copy_from_slice(&MAGIC_V3.to_le_bytes());
        v[sb + BLOCKSIZE_V3_OFFSET..sb + BLOCKSIZE_V3_OFFSET + 2]
            .copy_from_slice(&blocksize.to_le_bytes());
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("minix.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_v1() {
        // 200 zones of 1 KiB.
        let (_t, src) = source_of(&minix_v12(MAGIC_V1, 200, 0, 0, 512 * 1024));
        assert!(is_minix(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "Minix");
        assert_eq!(v.size(), 200 * 1024);
    }

    #[test]
    fn detects_v2_with_30_char_magic() {
        // v2 uses the 32-bit zone count; 100 zones of 1 KiB.
        let (_t, src) = source_of(&minix_v12(MAGIC_V2_30, 0, 100, 0, 512 * 1024));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "Minix v2");
        assert_eq!(v.size(), 100 * 1024);
    }

    #[test]
    fn detects_v3() {
        // v3 stores its own block size; 80 zones of 4 KiB.
        let (_t, src) = source_of(&minix_v3(80, 4096, 512 * 1024));
        assert!(is_minix(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "Minix v3");
        assert_eq!(v.size(), 80 * 4096);
    }

    /// A bare magic in otherwise random bytes must not become a volume, so
    /// each layout field is checked: one wrong field is enough to refuse.
    #[test]
    fn rejects_a_magic_with_implausible_geometry() {
        let sb = SB_OFFSET as usize;
        let good = minix_v12(MAGIC_V1, 200, 0, 0, 512 * 1024);
        let (_t, src) = source_of(&good);
        assert!(is_minix(&src, 0));
        let broken: Vec<(&str, usize, u16)> = vec![
            ("no inodes", 0, 0),
            ("no inode bitmap", 4, 0),
            ("no zone bitmap", 6, 0),
            ("first data zone before the bitmaps", 8, 3),
            ("first data zone past the end", 8, 200),
            ("zone shift too large", 0xA, 9),
        ];
        for (what, off, value) in broken {
            let mut v = good.clone();
            v[sb + off..sb + off + 2].copy_from_slice(&value.to_le_bytes());
            let (_t, src) = source_of(&v);
            assert!(!is_minix(&src, 0), "{what}");
            assert!(Volume::parse(&src, 0).is_err(), "{what}");
        }
        // v3: the block size must be a power of two from 1 KiB to 64 KiB.
        let mut v3 = minix_v3(80, 3000, 512 * 1024);
        let (_t, src) = source_of(&v3);
        assert!(!is_minix(&src, 0), "v3 odd block size");
        v3[sb + BLOCKSIZE_V3_OFFSET..sb + BLOCKSIZE_V3_OFFSET + 2]
            .copy_from_slice(&4096u16.to_le_bytes());
        let (_t, src) = source_of(&v3);
        assert!(is_minix(&src, 0));
    }

    #[test]
    fn rejects_non_minix() {
        let (_t, src) = source_of(&vec![0u8; 64 * 1024]);
        assert!(!is_minix(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
