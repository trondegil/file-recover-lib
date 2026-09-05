//! XFS **detection**, geometry, and filesystem label (no metadata undelete).
//!
//! XFS is the high-performance journaling filesystem common on Linux servers and
//! NAS appliances (it is the RHEL/CentOS default). Modern XFS (v5) zeroes an
//! inode's data-extent list when a file is unlinked, so there is no stale
//! mapping left to scavenge — metadata-based undelete is not tractable the way
//! it is for FAT/exFAT/NTFS/ext/HFS+. The real-image corpus confirmed this on a
//! Linux 7.0 kernel: every freed inode had its mode, size, extent count, and
//! extent area zeroed. The names survive as unused entries in the directory
//! blocks; the data map would have to come from the XFS log, which is a parser
//! of its own and is left for later. This module therefore *recognises* an XFS
//! volume and reports its size and **label** (so `info` / `list_volumes` surface
//! it and the user knows to fall back to `scan`), but recovers nothing itself.
//!
//! Detection reads the primary superblock at the start of the volume: a 32-bit
//! big-endian magic `XFSB`, the block size and block count (from which the
//! volume size is derived), and the 12-byte filesystem label. XFS stores all
//! superblock fields big-endian.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{RecoverOptions, RecoverStats};
use crate::source::Source;

/// `sb_magicnum` ("XFSB") at offset 0 of the superblock.
const MAGIC: &[u8; 4] = b"XFSB";
/// `sb_blocksize` (big-endian u32) at offset 4.
const BLOCKSIZE_OFFSET: usize = 4;
/// `sb_dblocks` (big-endian u64) at offset 8: total filesystem blocks.
const DBLOCKS_OFFSET: usize = 8;
/// `sb_uuid` (16 bytes) at offset 0x20: the filesystem UUID.
const UUID_OFFSET: usize = 0x20;
/// `sb_fname[12]` at offset 0x6C: the filesystem label.
const LABEL_OFFSET: usize = 0x6C;
const LABEL_LEN: usize = 12;
/// `sb_icount` (big-endian u64) at offset 0x80: allocated inodes.
const ICOUNT_OFFSET: usize = 0x80;
/// `sb_ifree` (big-endian u64) at offset 0x88: free inodes.
const IFREE_OFFSET: usize = 0x88;
/// `sb_fdblocks` (big-endian u64) at offset 0x90: free data blocks.
const FDBLOCKS_OFFSET: usize = 0x90;
/// We read this many bytes of the superblock to cover every field above.
const HEADER_LEN: usize = FDBLOCKS_OFFSET + 8;

/// A recognised XFS volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    block_size: u32,
    label: String,
    uuid: Option<String>,
    /// Allocated inodes (`sb_icount`).
    icount: u64,
    /// Free inodes (`sb_ifree`).
    ifree: u64,
    /// Free data blocks (`sb_fdblocks`).
    fdblocks: u64,
}

/// Does the superblock at `vol_offset` carry the XFS magic (`XFSB`)?
pub fn is_xfs(src: &Source, vol_offset: u64) -> bool {
    let mut magic = [0u8; 4];
    if src.read_at(vol_offset, &mut magic).unwrap_or(0) < 4 {
        return false;
    }
    &magic == MAGIC
}

impl Volume {
    /// Parse the XFS superblock at `offset`, failing if it is not one.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let mut sb = [0u8; HEADER_LEN];
        if src.read_at(offset, &mut sb)? < HEADER_LEN {
            bail!("XFS superblock truncated");
        }
        if &sb[0..4] != MAGIC {
            bail!("not an XFS volume");
        }
        let block_size = u32::from_be_bytes(
            sb[BLOCKSIZE_OFFSET..BLOCKSIZE_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        if !block_size.is_power_of_two() || !(512..=65536).contains(&block_size) {
            bail!("implausible XFS block size {block_size}");
        }
        let dblocks =
            u64::from_be_bytes(sb[DBLOCKS_OFFSET..DBLOCKS_OFFSET + 8].try_into().unwrap());
        if dblocks == 0 {
            bail!("XFS reports zero blocks");
        }
        let size = dblocks
            .checked_mul(block_size as u64)
            .unwrap_or_else(|| src.size.saturating_sub(offset));
        // sb_fname is a fixed 12-byte field, NUL-padded.
        let raw = &sb[LABEL_OFFSET..LABEL_OFFSET + LABEL_LEN];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(LABEL_LEN);
        let label = String::from_utf8_lossy(&raw[..end]).trim().to_string();
        let uuid = crate::recover::format_uuid(&sb[UUID_OFFSET..UUID_OFFSET + 16]);
        let icount = u64::from_be_bytes(sb[ICOUNT_OFFSET..ICOUNT_OFFSET + 8].try_into().unwrap());
        let ifree = u64::from_be_bytes(sb[IFREE_OFFSET..IFREE_OFFSET + 8].try_into().unwrap());
        let fdblocks =
            u64::from_be_bytes(sb[FDBLOCKS_OFFSET..FDBLOCKS_OFFSET + 8].try_into().unwrap());
        Ok(Volume {
            offset,
            size,
            block_size,
            label,
            uuid,
            icount,
            ifree,
            fdblocks,
        })
    }

    /// Free space in bytes (`sb_fdblocks` × block size), capped at the volume
    /// size so a corrupt count cannot exceed it.
    pub fn free_bytes(&self) -> u64 {
        self.fdblocks
            .saturating_mul(self.block_size as u64)
            .min(self.size)
    }

    /// Total size of the volume in bytes (block count × block size).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Inode usage as `(used, total)` — the allocated inodes minus the free
    /// ones, out of the allocated total.
    pub fn inode_usage(&self) -> (u64, u64) {
        (self.icount.saturating_sub(self.ifree), self.icount)
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "XFS"
    }

    /// The user-set filesystem label (`sb_fname`), or an empty string when none.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// XFS block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// The filesystem UUID (`sb_uuid`), or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// XFS metadata undelete is not supported (see the module docs); this always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from an XFS volume.
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

    /// Build a minimal XFS superblock (big-endian) with the given geometry/label.
    fn superblock(block_size: u32, dblocks: u64, label: &str) -> Vec<u8> {
        let mut v = vec![0u8; 512];
        v[0..4].copy_from_slice(MAGIC);
        v[BLOCKSIZE_OFFSET..BLOCKSIZE_OFFSET + 4].copy_from_slice(&block_size.to_be_bytes());
        v[DBLOCKS_OFFSET..DBLOCKS_OFFSET + 8].copy_from_slice(&dblocks.to_be_bytes());
        v[ICOUNT_OFFSET..ICOUNT_OFFSET + 8].copy_from_slice(&128u64.to_be_bytes());
        v[IFREE_OFFSET..IFREE_OFFSET + 8].copy_from_slice(&40u64.to_be_bytes());
        v[FDBLOCKS_OFFSET..FDBLOCKS_OFFSET + 8].copy_from_slice(&1000u64.to_be_bytes());
        let bytes = label.as_bytes();
        v[LABEL_OFFSET..LABEL_OFFSET + bytes.len()].copy_from_slice(bytes);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("v.img");
        std::fs::write(&p, bytes).unwrap();
        let src = Source::open(&p).unwrap();
        (tmp, src)
    }

    #[test]
    fn detects_sizes_and_labels_a_volume() {
        let mut sb = superblock(4096, 2560, "data");
        sb[UUID_OFFSET..UUID_OFFSET + 16].copy_from_slice(&[0x11; 16]);
        let (_t, src) = source_of(&sb);
        assert!(is_xfs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "XFS");
        assert_eq!(v.size(), 4096 * 2560);
        assert_eq!(v.block_size(), 4096);
        assert_eq!(v.label(), "data");
        assert_eq!(v.uuid().unwrap(), "11111111-1111-1111-1111-111111111111");
        // 128 inodes allocated, 40 free => 88 used.
        assert_eq!(v.inode_usage(), (88, 128));
        // 1000 free blocks × 4096 = free space in bytes.
        assert_eq!(v.free_bytes(), 1000 * 4096);
    }

    #[test]
    fn rejects_bad_magic_and_geometry() {
        // No magic.
        let (_t, src) = source_of(&vec![0u8; 512]);
        assert!(!is_xfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // Magic present but a non-power-of-two block size.
        let (_t, src) = source_of(&superblock(5000, 2560, ""));
        assert!(Volume::parse(&src, 0).is_err());

        // Magic present but zero blocks.
        let (_t, src) = source_of(&superblock(4096, 0, ""));
        assert!(Volume::parse(&src, 0).is_err());
    }

    #[test]
    fn empty_label_is_blank() {
        let (_t, src) = source_of(&superblock(512, 100, ""));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.label(), "");
        assert_eq!(v.size(), 512 * 100);
    }
}
