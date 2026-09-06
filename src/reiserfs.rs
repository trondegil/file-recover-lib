//! ReiserFS **detection** — no metadata undelete.
//!
//! ReiserFS (Hans Reiser's journaling filesystem) was the default on SUSE and a
//! popular choice on Linux through the 2000s. Its on-disk structure — a single
//! balanced tree keyed by packed object/offset keys — is unlike the ext family,
//! and the format is now long deprecated (removed from the mainline kernel in
//! 6.13), so this module only *recognises* a ReiserFS volume — reporting its
//! size, label, and UUID so `info` / `list_volumes` show it instead of leaving
//! it unrecognised — and leaves recovery to `scan` (carving).
//!
//! The superblock location and magic distinguish the two on-disk formats:
//! **3.6** (`ReIsEr2Fs`, or `ReIsEr3Fs` when the journal is relocated) lives
//! 64 KiB into the volume, while the older **3.5** (`ReIsErFs`) lives 8 KiB in.
//! Only the 3.6 superblock carries a UUID and label.

use std::path::Path;

use anyhow::{bail, Result};

use crate::recover::{format_uuid, RecoverOptions, RecoverStats};
use crate::source::Source;

/// Candidate superblock locations: 3.6 at 64 KiB, then the older 3.5 at 8 KiB.
const SB_OFFSETS: [u64; 2] = [65536, 8192];
/// Byte offsets within the superblock.
const BLOCK_COUNT_OFFSET: usize = 0x00; // u32
const FREE_BLOCKS_OFFSET: usize = 0x04; // u32
const BLOCKSIZE_OFFSET: usize = 0x2C; // u16
const UMOUNT_STATE_OFFSET: usize = 0x32; // u16: 1 = cleanly unmounted
/// `s_umount_state` value for a cleanly unmounted volume.
const UMOUNT_CLEAN: u16 = 1;
const MAGIC_OFFSET: usize = 0x34; // char[10]
const UUID_OFFSET: usize = 0x54; // 16 bytes (3.6 only)
const LABEL_OFFSET: usize = 0x64; // 16 bytes, NUL-padded (3.6 only)
/// We read this much of the superblock to cover every field above.
const HEADER_LEN: usize = LABEL_OFFSET + 16;

/// A recognised ReiserFS volume (detection only; no metadata undelete).
pub struct Volume {
    /// Byte offset of the volume within the source.
    pub offset: u64,
    size: u64,
    /// Allocation block size in bytes.
    block_size: u64,
    /// Free (unallocated) bytes (`s_free_blocks` × block size).
    free_bytes: u64,
    /// Whether the volume was cleanly unmounted (`s_umount_state` == 1).
    clean: bool,
    /// Filesystem label (`s_label`), empty when unset or on a 3.5 volume.
    label: String,
    /// Filesystem UUID (`s_uuid`), `None` when unset or on a 3.5 volume.
    uuid: Option<String>,
}

/// Which ReiserFS on-disk format a magic string names, and whether it carries the
/// 3.6 UUID/label fields. `None` if the bytes are not a ReiserFS magic.
fn magic_kind(field: &[u8]) -> Option<bool> {
    if field.starts_with(b"ReIsEr2Fs") || field.starts_with(b"ReIsEr3Fs") {
        Some(true) // 3.6: has UUID and label.
    } else if field.starts_with(b"ReIsErFs") {
        Some(false) // 3.5: no UUID/label.
    } else {
        None
    }
}

/// The superblock offset carrying a ReiserFS magic at `vol_offset`, with whether
/// it is the 3.6 layout — or `None` if there is no ReiserFS superblock.
fn sb_offset(src: &Source, vol_offset: u64) -> Option<(u64, bool)> {
    for &sb in &SB_OFFSETS {
        let at = vol_offset.checked_add(sb)?;
        let mut magic = [0u8; 10];
        if src
            .read_at(at + MAGIC_OFFSET as u64, &mut magic)
            .unwrap_or(0)
            < 10
        {
            continue;
        }
        if let Some(v36) = magic_kind(&magic) {
            return Some((at, v36));
        }
    }
    None
}

/// Does a ReiserFS superblock sit at `vol_offset`? The magic must be backed
/// by a block size ReiserFS uses, so a magic over random bytes is not one.
pub fn is_reiserfs(src: &Source, vol_offset: u64) -> bool {
    let Some((sb, _)) = sb_offset(src, vol_offset) else {
        return false;
    };
    let mut bs = [0u8; 2];
    if src
        .read_at(sb + BLOCKSIZE_OFFSET as u64, &mut bs)
        .unwrap_or(0)
        < 2
    {
        return false;
    }
    let blocksize = u16::from_le_bytes(bs) as u64;
    blocksize.is_power_of_two() && (512..=65536).contains(&blocksize)
}

impl Volume {
    /// Parse the ReiserFS superblock at `offset`, failing if there is none.
    pub fn parse(src: &Source, offset: u64) -> Result<Volume> {
        let Some((sb, v36)) = sb_offset(src, offset) else {
            bail!("not a ReiserFS volume");
        };
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(sb, &mut hdr)? < HEADER_LEN {
            bail!("ReiserFS superblock truncated");
        }
        let block_count = u32::from_le_bytes(
            hdr[BLOCK_COUNT_OFFSET..BLOCK_COUNT_OFFSET + 4]
                .try_into()
                .unwrap(),
        ) as u64;
        let blocksize = u16::from_le_bytes(
            hdr[BLOCKSIZE_OFFSET..BLOCKSIZE_OFFSET + 2]
                .try_into()
                .unwrap(),
        ) as u64;
        // The block size is a power of two from 512 B to 64 KiB; a magic
        // over anything else is not a superblock.
        if block_count == 0 || !blocksize.is_power_of_two() || !(512..=65536).contains(&blocksize) {
            bail!("implausible ReiserFS geometry");
        }
        // Fall back to the source span if the recorded size overflows or exceeds
        // what the source can hold.
        let fallback = src.size.saturating_sub(offset);
        let size = block_count
            .checked_mul(blocksize)
            .filter(|&b| b <= fallback.max(blocksize))
            .unwrap_or(fallback);
        // UUID and label exist only on the 3.6 layout.
        let (uuid, label) = if v36 {
            let uuid = format_uuid(&hdr[UUID_OFFSET..UUID_OFFSET + 16]);
            let raw = &hdr[LABEL_OFFSET..LABEL_OFFSET + 16];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let label = String::from_utf8_lossy(&raw[..end]).into_owned();
            (uuid, label)
        } else {
            (None, String::new())
        };
        let free_blocks = u32::from_le_bytes(
            hdr[FREE_BLOCKS_OFFSET..FREE_BLOCKS_OFFSET + 4]
                .try_into()
                .unwrap(),
        ) as u64;
        let umount_state = u16::from_le_bytes(
            hdr[UMOUNT_STATE_OFFSET..UMOUNT_STATE_OFFSET + 2]
                .try_into()
                .unwrap(),
        );
        Ok(Volume {
            offset,
            size,
            block_size: blocksize,
            free_bytes: free_blocks.saturating_mul(blocksize),
            clean: umount_state == UMOUNT_CLEAN,
            label,
            uuid,
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

    /// Whether the volume was cleanly unmounted.
    pub fn is_clean(&self) -> bool {
        self.clean
    }

    /// Short filesystem label.
    pub fn fs_label(&self) -> &'static str {
        "ReiserFS"
    }

    /// The filesystem label (`s_label`), or an empty string when unset.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The filesystem UUID (`s_uuid`), or `None` when unset.
    pub fn uuid(&self) -> Option<String> {
        self.uuid.clone()
    }

    /// ReiserFS metadata undelete is not supported (see the module docs); always
    /// returns an empty result so a mixed disk's other volumes still recover.
    /// Use `scan` (carving) to recover data from a ReiserFS volume.
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

    /// Build a ReiserFS volume of `total` bytes with a superblock at `sb`.
    fn reiserfs_image(
        sb: usize,
        magic: &[u8],
        block_count: u32,
        blocksize: u16,
        uuid: &[u8; 16],
        label: &str,
        total: usize,
    ) -> Vec<u8> {
        let mut v = vec![0u8; total];
        v[sb + BLOCK_COUNT_OFFSET..sb + BLOCK_COUNT_OFFSET + 4]
            .copy_from_slice(&block_count.to_le_bytes());
        // Mark half the blocks free, for the free-space report.
        v[sb + FREE_BLOCKS_OFFSET..sb + FREE_BLOCKS_OFFSET + 4]
            .copy_from_slice(&(block_count / 2).to_le_bytes());
        // Cleanly unmounted.
        v[sb + UMOUNT_STATE_OFFSET..sb + UMOUNT_STATE_OFFSET + 2]
            .copy_from_slice(&UMOUNT_CLEAN.to_le_bytes());
        v[sb + BLOCKSIZE_OFFSET..sb + BLOCKSIZE_OFFSET + 2]
            .copy_from_slice(&blocksize.to_le_bytes());
        v[sb + MAGIC_OFFSET..sb + MAGIC_OFFSET + magic.len()].copy_from_slice(magic);
        v[sb + UUID_OFFSET..sb + UUID_OFFSET + 16].copy_from_slice(uuid);
        let lb = label.as_bytes();
        v[sb + LABEL_OFFSET..sb + LABEL_OFFSET + lb.len()].copy_from_slice(lb);
        v
    }

    fn source_of(bytes: &[u8]) -> (tempfile::TempDir, Source) {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("reiserfs.img");
        std::fs::write(&p, bytes).unwrap();
        (tmp, Source::open(&p).unwrap())
    }

    #[test]
    fn detects_a_3_6_volume_with_uuid_and_label() {
        let uuid = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        let (_t, src) = source_of(&reiserfs_image(
            65536,
            b"ReIsEr2Fs",
            64,
            4096,
            &uuid,
            "backup",
            512 * 1024,
        ));
        assert!(is_reiserfs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "ReiserFS");
        assert_eq!(v.size(), 64 * 4096);
        assert_eq!(v.free_bytes(), 32 * 4096);
        assert!(v.is_clean());
        assert_eq!(v.label(), "backup");
        assert_eq!(
            v.uuid().as_deref(),
            Some("01234567-89ab-cdef-0123-456789abcdef")
        );
    }

    #[test]
    fn detects_an_old_3_5_volume_without_uuid_or_label() {
        // The 3.5 superblock lives 8 KiB in and carries no UUID/label.
        let (_t, src) = source_of(&reiserfs_image(
            8192,
            b"ReIsErFs",
            32,
            4096,
            &[0xff; 16],
            "ignored",
            256 * 1024,
        ));
        assert!(is_reiserfs(&src, 0));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.size(), 32 * 4096);
        assert_eq!(v.uuid(), None);
        assert_eq!(v.label(), "");
    }

    #[test]
    fn relocated_journal_magic_is_recognised() {
        let (_t, src) = source_of(&reiserfs_image(
            65536,
            b"ReIsEr3Fs",
            16,
            4096,
            &[0u8; 16],
            "",
            256 * 1024,
        ));
        let v = Volume::parse(&src, 0).unwrap();
        assert_eq!(v.fs_label(), "ReiserFS");
        // All-zero UUID and empty label report as absent.
        assert_eq!(v.uuid(), None);
        assert_eq!(v.label(), "");
    }

    #[test]
    fn rejects_non_reiserfs_and_falls_back_on_bad_size() {
        let (_t, src) = source_of(&vec![0u8; 128 * 1024]);
        assert!(!is_reiserfs(&src, 0));
        assert!(Volume::parse(&src, 0).is_err());

        // A block count that overflows the source falls back to the span.
        let (_t, src) = source_of(&reiserfs_image(
            65536,
            b"ReIsEr2Fs",
            u32::MAX,
            4096,
            &[0u8; 16],
            "",
            128 * 1024,
        ));
        assert_eq!(Volume::parse(&src, 0).unwrap().size(), 128 * 1024);
    }

    /// A magic over a block size ReiserFS never uses is not a superblock,
    /// however the size field reads.
    #[test]
    fn rejects_a_magic_with_an_impossible_block_size() {
        for bs in [0u16, 3000, 256] {
            let (_t, src) = source_of(&reiserfs_image(
                65536,
                b"ReIsEr2Fs",
                100,
                bs,
                &[0u8; 16],
                "",
                128 * 1024,
            ));
            assert!(!is_reiserfs(&src, 0), "block size {bs}");
            assert!(Volume::parse(&src, 0).is_err(), "block size {bs}");
        }
    }
}
