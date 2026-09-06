//! BeFS (Be File System) **detection** — no metadata undelete.
//!
//! BeFS is the 64-bit journaling filesystem of BeOS, and the native filesystem of
//! Haiku, its modern open-source successor. Its B+tree metadata is unlike the
//! filesystems already handled here, and the on-disk layout is specialised, so
//! this module only *recognises* a BeFS volume — reporting its name and size so
//! `info` / `list_volumes` show it instead of leaving it unrecognised — and
//! leaves recovery to `scan` (carving).
//!
//! The superblock sits 512 bytes into the volume (just past the boot block). It
//! can be stored big- or little-endian (BeFS ran on PowerPC and x86); the byte
//! order is resolved from the first magic, and the second magic is then checked
//! in the same order to guard against a false positive.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// The superblock sits 512 bytes into the volume.
const SB_OFFSET: u64 = 512;
/// `magic1` (`BFS1`) and `magic2`, used together to identify the superblock.
const MAGIC1: u32 = 0x4246_5331;
const MAGIC2: u32 = 0xDD12_1031;
/// Byte offsets within the superblock.
const NAME_OFFSET: usize = 0x00; // 32 bytes, NUL-padded
const MAGIC1_OFFSET: usize = 0x20; // u32
const BLOCK_SIZE_OFFSET: usize = 0x28; // u32
const NUM_BLOCKS_OFFSET: usize = 0x30; // u64
const USED_BLOCKS_OFFSET: usize = 0x38; // u64
const MAGIC2_OFFSET: usize = 0x44; // u32
/// We read this much of the superblock to cover every field above.
const HEADER_LEN: usize = MAGIC2_OFFSET + 4;

/// A recognised BeFS volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    /// Allocation block size in bytes.
    block_size: u64,
    /// Free (unallocated) bytes (`num_blocks − used_blocks` × block size).
    free_bytes: u64,
    /// Volume name, empty when unset.
    label: String,
}

fn rd_u32(b: &[u8], big_endian: bool) -> u32 {
    let a = b[..4].try_into().unwrap();
    if big_endian {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    }
}

/// The byte order of a BeFS superblock at `hdr`, or `None` if `hdr` is not one.
/// `Some(true)` is big-endian, `Some(false)` little-endian.
fn byte_order(hdr: &[u8]) -> Option<bool> {
    for big in [false, true] {
        if rd_u32(&hdr[MAGIC1_OFFSET..], big) == MAGIC1
            && rd_u32(&hdr[MAGIC2_OFFSET..], big) == MAGIC2
        {
            return Some(big);
        }
    }
    None
}

/// Does a BeFS superblock sit at `vol_offset`? Both magics must match and
/// the block size must be one BeFS uses.
pub fn is_befs(src: &Source, vol_offset: u64) -> bool {
    let Some(at) = vol_offset.checked_add(SB_OFFSET) else {
        return false;
    };
    let mut hdr = [0u8; HEADER_LEN];
    if src.read_at(at, &mut hdr).unwrap_or(0) < HEADER_LEN {
        return false;
    }
    let Some(big) = byte_order(&hdr) else {
        return false;
    };
    let block_size = rd_u32(&hdr[BLOCK_SIZE_OFFSET..], big);
    block_size.is_power_of_two() && (1024..=8192).contains(&block_size)
}

impl Volume {
    /// Parse the BeFS superblock at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let at = offset
            .checked_add(SB_OFFSET)
            .ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(at, &mut hdr)? < HEADER_LEN {
            bail!("BeFS superblock truncated");
        }
        let Some(big) = byte_order(&hdr) else {
            bail!("not a BeFS volume");
        };
        let block_size = rd_u32(&hdr[BLOCK_SIZE_OFFSET..], big) as u64;
        let num_blocks = {
            let a = hdr[NUM_BLOCKS_OFFSET..NUM_BLOCKS_OFFSET + 8]
                .try_into()
                .unwrap();
            if big {
                u64::from_be_bytes(a)
            } else {
                u64::from_le_bytes(a)
            }
        };
        // BeFS block sizes are powers of two from 1 KiB to 8 KiB; anything
        // else is the two magics over bytes that are not a superblock.
        if !block_size.is_power_of_two() || !(1024..=8192).contains(&block_size) {
            bail!("implausible BeFS geometry");
        }
        let used_blocks = {
            let a = hdr[USED_BLOCKS_OFFSET..USED_BLOCKS_OFFSET + 8]
                .try_into()
                .unwrap();
            if big {
                u64::from_be_bytes(a)
            } else {
                u64::from_le_bytes(a)
            }
        };
        let free_bytes = num_blocks
            .saturating_sub(used_blocks)
            .saturating_mul(block_size);
        // Fall back to the source span when the recorded size overflows or exceeds
        // what the source can hold.
        let fallback = src.size.saturating_sub(offset);
        let size = num_blocks
            .checked_mul(block_size)
            .filter(|&b| b > 0 && b <= fallback.max(block_size))
            .unwrap_or(fallback);
        let raw = &hdr[NAME_OFFSET..NAME_OFFSET + 32];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let label = String::from_utf8_lossy(&raw[..end]).into_owned();
        Ok(Volume {
            offset,
            size,
            block_size,
            free_bytes,
            label,
        })
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Allocation block size in bytes.
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    /// Free (unallocated) bytes in the volume.
    pub fn free_bytes(&self) -> u64 {
        self.free_bytes
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "BeFS"
    }

    /// The volume name, or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// BeFS metadata undelete is not supported (see the module docs); always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from a BeFS volume.
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

    /// Build a BeFS volume of `total` bytes with a superblock at 512 B.
    fn befs_image(
        name: &str,
        block_size: u32,
        num_blocks: u64,
        big: bool,
        total: usize,
    ) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let sb = SB_OFFSET as usize;
        let nb = name.as_bytes();
        v[sb + NAME_OFFSET..sb + NAME_OFFSET + nb.len()].copy_from_slice(nb);
        let (m1, m2, bs, n) = if big {
            (
                MAGIC1.to_be_bytes(),
                MAGIC2.to_be_bytes(),
                block_size.to_be_bytes(),
                num_blocks.to_be_bytes(),
            )
        } else {
            (
                MAGIC1.to_le_bytes(),
                MAGIC2.to_le_bytes(),
                block_size.to_le_bytes(),
                num_blocks.to_le_bytes(),
            )
        };
        v[sb + MAGIC1_OFFSET..sb + MAGIC1_OFFSET + 4].copy_from_slice(&m1);
        v[sb + MAGIC2_OFFSET..sb + MAGIC2_OFFSET + 4].copy_from_slice(&m2);
        v[sb + BLOCK_SIZE_OFFSET..sb + BLOCK_SIZE_OFFSET + 4].copy_from_slice(&bs);
        v[sb + NUM_BLOCKS_OFFSET..sb + NUM_BLOCKS_OFFSET + 8].copy_from_slice(&n);
        // Mark a quarter of the blocks used, for the free-space report.
        let used = num_blocks / 4;
        let u = if big {
            used.to_be_bytes()
        } else {
            used.to_le_bytes()
        };
        v[sb + USED_BLOCKS_OFFSET..sb + USED_BLOCKS_OFFSET + 8].copy_from_slice(&u);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("befs.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_little_endian_with_name_and_size() {
        // 256 blocks of 1 KiB = 256 KiB.
        let (_t, src) = source_of(&befs_image("Haiku", 1024, 256, false, 512 * 1024));
        assert!(is_befs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "BeFS");
        assert_eq!(v.label(), "Haiku");
        assert_eq!(v.size(), 256 * 1024);
        // 256 blocks, a quarter (64) used → 192 free blocks of 1 KiB.
        assert_eq!(v.free_bytes(), 192 * 1024);
    }

    #[test]
    fn detects_big_endian() {
        // The PowerPC byte order must be recognised too.
        let (_t, src) = source_of(&befs_image("BeOS", 2048, 64, true, 512 * 1024));
        assert!(is_befs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.label(), "BeOS");
        assert_eq!(v.size(), 64 * 2048);
    }

    #[test]
    fn rejects_non_befs_and_bad_second_magic() {
        let (_t, src) = source_of(&vec![0u8; 64 * 1024]);
        assert!(!is_befs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // The first magic without the matching second magic is rejected.
        let mut v = befs_image("x", 1024, 16, false, 64 * 1024);
        let sb = SB_OFFSET as usize;
        v[sb + MAGIC2_OFFSET..sb + MAGIC2_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        let (_t, src) = source_of(&v);
        assert!(!is_befs(&src, 0));
    }

    /// Both magics over a block size BeFS never uses is not a volume.
    #[test]
    fn rejects_magics_with_an_impossible_block_size() {
        for bs in [0u32, 1000, 512, 16384] {
            let (_t, src) = source_of(&befs_image("x", bs, 16, false, 64 * 1024));
            assert!(!is_befs(&src, 0), "block size {bs}");
            assert!(Volume::parse(&src, 0).is_err(), "block size {bs}");
        }
    }
}
