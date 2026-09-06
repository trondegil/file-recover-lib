//! JFS (IBM Journaled File System) **detection** — no metadata undelete.
//!
//! JFS came from IBM's AIX/OS2 and was ported to Linux; it is journaling, but its
//! on-disk inode/directory B+tree structure is unlike the ext family and the
//! Linux port is now rarely deployed. This module only *recognises* a JFS volume
//! — reporting its size, label, and UUID so `info` / `list_volumes` show it
//! instead of leaving it unrecognised — and leaves recovery to `scan` (carving).
//!
//! The primary aggregate superblock lives at a fixed 32 KiB into the volume and
//! opens with the ASCII magic `JFS1`. Field offsets and the size/label/UUID
//! interpretation follow what `libblkid` reads.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{format_uuid, RecoverOptions, RecoverStats};
use crate::source::Source;

/// The primary aggregate superblock sits 32 KiB into the volume.
const SB_OFFSET: u64 = 32768;
/// `s_magic` ("JFS1") at superblock offset 0.
const MAGIC: &[u8; 4] = b"JFS1";
/// Byte offsets within the superblock (matching `libblkid`'s `jfs_super_block`).
const SIZE_OFFSET: usize = 0x08; // u64: aggregate size in s_pbsize blocks
const BSIZE_OFFSET: usize = 0x10; // u32: aggregate (allocation) block size in bytes
const PBSIZE_OFFSET: usize = 0x18; // u32: physical (hardware/LVM) block size in bytes
const TIME_OFFSET: usize = 0x58; // u32: s_time.tv_sec (last updated, Unix seconds)
const UUID_OFFSET: usize = 0x88; // 16 bytes
const LABEL_OFFSET: usize = 0x98; // 16 bytes, NUL-padded
/// We read this much of the superblock to cover every field above.
const HEADER_LEN: usize = LABEL_OFFSET + 16;

/// A recognised JFS volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    /// Aggregate (allocation) block size in bytes.
    block_size: u64,
    /// Last-updated time (`s_time`) as Unix seconds, `None` when unset.
    written: Option<u64>,
    /// Filesystem label (`s_label`), empty when unset.
    label: String,
    /// Filesystem UUID (`s_uuid`), `None` when unset.
    uuid: Option<String>,
}

/// Does a JFS aggregate superblock sit at `vol_offset`? The magic must be
/// backed by block sizes JFS uses, so a magic over random bytes is not one.
pub fn is_jfs(src: &Source, vol_offset: u64) -> bool {
    let Some(at) = vol_offset.checked_add(SB_OFFSET) else {
        return false;
    };
    let mut hdr = [0u8; PBSIZE_OFFSET + 4];
    if src.read_at(at, &mut hdr).unwrap_or(0) < hdr.len() || &hdr[0..4] != MAGIC {
        return false;
    }
    let block_size =
        u32::from_le_bytes(hdr[BSIZE_OFFSET..BSIZE_OFFSET + 4].try_into().unwrap()) as u64;
    let pbsize =
        u32::from_le_bytes(hdr[PBSIZE_OFFSET..PBSIZE_OFFSET + 4].try_into().unwrap()) as u64;
    geometry_ok(block_size, pbsize)
}

/// JFS aggregates use a physical block size of 512 B to 4 KiB and an
/// allocation block size from that up to 64 KiB, both powers of two.
fn geometry_ok(block_size: u64, pbsize: u64) -> bool {
    pbsize.is_power_of_two()
        && (512..=4096).contains(&pbsize)
        && block_size.is_power_of_two()
        && (pbsize..=65536).contains(&block_size)
}

impl Volume {
    /// Parse the JFS superblock at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let at = offset
            .checked_add(SB_OFFSET)
            .ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(at, &mut hdr)? < HEADER_LEN {
            bail!("JFS superblock truncated");
        }
        if &hdr[0..4] != MAGIC {
            bail!("not a JFS volume");
        }
        let blocks = u64::from_le_bytes(hdr[SIZE_OFFSET..SIZE_OFFSET + 8].try_into().unwrap());
        let pbsize =
            u32::from_le_bytes(hdr[PBSIZE_OFFSET..PBSIZE_OFFSET + 4].try_into().unwrap()) as u64;
        let block_size =
            u32::from_le_bytes(hdr[BSIZE_OFFSET..BSIZE_OFFSET + 4].try_into().unwrap()) as u64;
        if blocks == 0 || !geometry_ok(block_size, pbsize) {
            bail!("implausible JFS geometry");
        }
        // Fall back to the source span if the recorded size overflows or exceeds
        // what the source can hold.
        let fallback = src.size.saturating_sub(offset);
        let size = blocks
            .checked_mul(pbsize)
            .filter(|&b| b <= fallback.max(pbsize))
            .unwrap_or(fallback);
        let time = u32::from_le_bytes(hdr[TIME_OFFSET..TIME_OFFSET + 4].try_into().unwrap());
        let written = (time != 0).then_some(time as u64);
        let uuid = format_uuid(&hdr[UUID_OFFSET..UUID_OFFSET + 16]);
        let raw = &hdr[LABEL_OFFSET..LABEL_OFFSET + 16];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let label = String::from_utf8_lossy(&raw[..end]).into_owned();
        Ok(Volume {
            offset,
            size,
            block_size,
            written,
            label,
            uuid,
        })
    }

    /// Total size of the volume in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Aggregate (allocation) block size in bytes.
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    /// Last-updated time as Unix seconds, `None` when unset.
    pub fn written_time(&self) -> Option<u64> {
        self.written
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "JFS"
    }

    /// The filesystem label (`s_label`), or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The filesystem UUID (`s_uuid`), or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// JFS metadata undelete is not supported (see the module docs); always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from a JFS volume.
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

    /// Build a JFS volume of `total` bytes with a superblock at 32 KiB.
    fn jfs_image(blocks: u64, pbsize: u32, uuid: &[u8; 16], label: &str, total: usize) -> Vec<u8> {
        let mut v = vec![0u8; total];
        let sb = SB_OFFSET as usize;
        v[sb..sb + 4].copy_from_slice(MAGIC);
        v[sb + SIZE_OFFSET..sb + SIZE_OFFSET + 8].copy_from_slice(&blocks.to_le_bytes());
        v[sb + BSIZE_OFFSET..sb + BSIZE_OFFSET + 4].copy_from_slice(&4096u32.to_le_bytes());
        v[sb + PBSIZE_OFFSET..sb + PBSIZE_OFFSET + 4].copy_from_slice(&pbsize.to_le_bytes());
        v[sb + TIME_OFFSET..sb + TIME_OFFSET + 4].copy_from_slice(&1_600_000_000u32.to_le_bytes());
        v[sb + UUID_OFFSET..sb + UUID_OFFSET + 16].copy_from_slice(uuid);
        let lb = label.as_bytes();
        v[sb + LABEL_OFFSET..sb + LABEL_OFFSET + lb.len()].copy_from_slice(lb);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("jfs.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_size_label_and_uuid() {
        let uuid = [
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let (_t, src) = source_of(&jfs_image(128, 512, &uuid, "archive", 256 * 1024));
        assert!(is_jfs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "JFS");
        assert_eq!(v.size(), 128 * 512);
        assert_eq!(v.block_size(), 4096);
        assert_eq!(v.written_time(), Some(1_600_000_000));
        assert_eq!(v.label(), "archive");
        assert_eq!(
            v.uuid().as_deref(),
            Some("fedcba98-7654-3210-fedc-ba9876543210")
        );
    }

    #[test]
    fn missing_uuid_and_label_report_as_absent() {
        let (_t, src) = source_of(&jfs_image(64, 1024, &[0u8; 16], "", 256 * 1024));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.size(), 64 * 1024);
        assert_eq!(v.uuid(), None);
        assert_eq!(v.label(), "");
    }

    #[test]
    fn rejects_non_jfs_and_falls_back_on_bad_size() {
        let (_t, src) = source_of(&vec![0u8; 64 * 1024]);
        assert!(!is_jfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // A block count that overflows the source falls back to the span.
        let (_t, src) = source_of(&jfs_image(u64::MAX, 512, &[0u8; 16], "", 64 * 1024));
        assert_eq!(Volume::parse(&src, 0).unwrap().size(), 64 * 1024);
    }

    /// A magic over block sizes JFS never uses is not a superblock.
    #[test]
    fn rejects_a_magic_with_impossible_block_sizes() {
        for pbsize in [0u32, 3000, 8192, 256] {
            let (_t, src) = source_of(&jfs_image(100, pbsize, &[0u8; 16], "", 64 * 1024));
            assert!(!is_jfs(&src, 0), "pbsize {pbsize}");
            assert!(Volume::parse(&src, 0).is_err(), "pbsize {pbsize}");
        }
        // The allocation block size must be a power of two at least pbsize.
        let mut v = jfs_image(100, 512, &[0u8; 16], "", 64 * 1024);
        let sb = SB_OFFSET as usize;
        v[sb + BSIZE_OFFSET..sb + BSIZE_OFFSET + 4].copy_from_slice(&3000u32.to_le_bytes());
        let (_t, src) = source_of(&v);
        assert!(!is_jfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());
    }
}
