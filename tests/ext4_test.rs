//! Integration test: build a minimal ext4-style volume by hand (superblock,
//! one block group, inode table with extent-based inodes, and directory blocks
//! containing stale/deleted entries in their slack), then verify recovery
//! restores names, paths, and contents.

mod common;

use unearth::ext4;
use unearth::recover::{self, RecoverOptions};
use unearth::source::Source;

const BS: usize = 1024; // block size
const INODE_SIZE: usize = 128;
const INODES_PER_GROUP: u32 = 32;
const TOTAL_BLOCKS: usize = 32;

// Block layout.
const GDT_BLOCK: usize = 2;
const INODE_TABLE_BLOCK: usize = 5;
const ROOT_DIR_BLOCK: usize = 9;
const LOGS_DIR_BLOCK: usize = 10;
const PHOTO_BLOCK: usize = 11;
const APPLOG_BLOCK: usize = 12;

fn inode_offset(ino: u32) -> usize {
    INODE_TABLE_BLOCK * BS + (ino as usize - 1) * INODE_SIZE
}

fn write_superblock(img: &mut [u8]) {
    let sb = 1024; // superblock starts at byte 1024
    img[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes()); // inodes_count
    img[sb + 4..sb + 8].copy_from_slice(&(TOTAL_BLOCKS as u32).to_le_bytes()); // blocks_count_lo
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes()); // first_data_block
    img[sb + 0x18..sb + 0x1C].copy_from_slice(&0u32.to_le_bytes()); // log_block_size => 1024
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes()); // blocks_per_group
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&INODES_PER_GROUP.to_le_bytes()); // inodes_per_group
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes()); // magic
    img[sb + 0x30..sb + 0x34].copy_from_slice(&1_700_000_000u32.to_le_bytes()); // s_wtime
    img[sb + 0x3A..sb + 0x3C].copy_from_slice(&0x0001u16.to_le_bytes()); // s_state: clean
    img[sb + 0x108..sb + 0x10C].copy_from_slice(&1_600_000_000u32.to_le_bytes()); // s_mkfs_time
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes()); // inode_size
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x0042u32.to_le_bytes()); // incompat: FILETYPE | EXTENTS
    img[sb + 0x88..sb + 0x88 + 5].copy_from_slice(b"/home"); // s_last_mounted
    img[sb + 0x10..sb + 0x14].copy_from_slice(&20u32.to_le_bytes()); // s_free_inodes_count
}

fn write_gdt(img: &mut [u8]) {
    let d = GDT_BLOCK * BS;
    img[d + 8..d + 12].copy_from_slice(&(INODE_TABLE_BLOCK as u32).to_le_bytes());
    // inode table
}

/// Build a 128-byte inode using a single extent that maps logical block 0 to
/// the given physical block.
fn write_inode(img: &mut [u8], ino: u32, mode: u16, links: u16, dtime: u32, size: u32, block: u32) {
    let o = inode_offset(ino);
    let mut n = [0u8; INODE_SIZE];
    n[0..2].copy_from_slice(&mode.to_le_bytes());
    n[4..8].copy_from_slice(&size.to_le_bytes());
    n[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
    n[0x1A..0x1C].copy_from_slice(&links.to_le_bytes());
    n[0x20..0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes()); // EXTENTS_FL

    // Extent header + one leaf extent in i_block (offset 0x28).
    let ib = 0x28;
    n[ib..ib + 2].copy_from_slice(&0xF30Au16.to_le_bytes()); // magic
    n[ib + 2..ib + 4].copy_from_slice(&1u16.to_le_bytes()); // entries
    n[ib + 4..ib + 6].copy_from_slice(&4u16.to_le_bytes()); // max
    n[ib + 6..ib + 8].copy_from_slice(&0u16.to_le_bytes()); // depth (leaf)
    let ext = ib + 12;
    n[ext..ext + 4].copy_from_slice(&0u32.to_le_bytes()); // logical block 0
    n[ext + 4..ext + 6].copy_from_slice(&1u16.to_le_bytes()); // length 1
    n[ext + 6..ext + 8].copy_from_slice(&0u16.to_le_bytes()); // start hi
    n[ext + 8..ext + 12].copy_from_slice(&block.to_le_bytes()); // start lo

    img[o..o + INODE_SIZE].copy_from_slice(&n);
}

/// Write a directory entry (with FILETYPE) into `block` at `off`.
fn write_dirent(
    img: &mut [u8],
    block: usize,
    off: usize,
    ino: u32,
    rec_len: u16,
    name: &str,
    ftype: u8,
) {
    let p = block * BS + off;
    img[p..p + 4].copy_from_slice(&ino.to_le_bytes());
    img[p + 4..p + 6].copy_from_slice(&rec_len.to_le_bytes());
    img[p + 6] = name.len() as u8;
    img[p + 7] = ftype;
    img[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
}

#[test]
fn free_extents_reads_the_block_bitmap() {
    let mut img = vec![0u8; TOTAL_BLOCKS * BS];
    write_superblock(&mut img);
    // Group descriptor: inode table at block 5, block bitmap at (unused) block 3.
    let d = GDT_BLOCK * BS;
    img[d + 8..d + 12].copy_from_slice(&(INODE_TABLE_BLOCK as u32).to_le_bytes());
    img[d..d + 4].copy_from_slice(&3u32.to_le_bytes()); // bg_block_bitmap

    // Block bitmap at block 3: blocks 1..=31 allocated, except block 11 free.
    // Bit i corresponds to block (first_data_block + i) = 1 + i.
    let bmp = 3 * BS;
    img[bmp..bmp + 4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    img[bmp + 1] &= !(1 << 2); // clear bit 10 => block 11 is free

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("ext.img");
    std::fs::write(&p, &img).unwrap();
    let src = Source::open(&p).unwrap();
    let vol = ext4::Volume::parse(&src, 0).unwrap();

    let free = vol.free_extents(&src).unwrap();
    let covered = |block: u64| {
        let off = block * BS as u64;
        free.iter().any(|&(s, l)| off >= s && off < s + l)
    };
    assert!(covered(11), "block 11 is free");
    assert!(!covered(5), "block 5 (inode table) is allocated");
    assert!(!covered(2), "block 2 (group descriptors) is allocated");
}

#[test]
fn recovers_deleted_ext4_files() {
    let mut img = vec![0u8; TOTAL_BLOCKS * BS];
    write_superblock(&mut img);
    write_gdt(&mut img);

    // Inodes.
    write_inode(&mut img, 2, 0x41ED, 3, 0, BS as u32, ROOT_DIR_BLOCK as u32); // root dir
    write_inode(&mut img, 13, 0x41ED, 2, 0, BS as u32, LOGS_DIR_BLOCK as u32); // logs dir (live)
    write_inode(&mut img, 12, 0x81A4, 1, 0, 0, 0); // readme (live regular, unused)

    let photo: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
    write_inode(
        &mut img,
        11,
        0x81A4,
        0,
        12345,
        photo.len() as u32,
        PHOTO_BLOCK as u32,
    ); // deleted
    img[PHOTO_BLOCK * BS..PHOTO_BLOCK * BS + photo.len()].copy_from_slice(&photo);

    let applog = b"deleted log line one\ndeleted log line two\n";
    write_inode(
        &mut img,
        14,
        0x81A4,
        0,
        12345,
        applog.len() as u32,
        APPLOG_BLOCK as u32,
    ); // deleted
    img[APPLOG_BLOCK * BS..APPLOG_BLOCK * BS + applog.len()].copy_from_slice(applog);

    // Root directory: ".", "..", live "logs", and (hidden in logs's slack) a
    // stale entry for the deleted "photo.raw".
    write_dirent(&mut img, ROOT_DIR_BLOCK, 0, 2, 12, ".", 2);
    write_dirent(&mut img, ROOT_DIR_BLOCK, 12, 2, 12, "..", 2);
    write_dirent(
        &mut img,
        ROOT_DIR_BLOCK,
        24,
        13,
        (BS - 24) as u16,
        "logs",
        2,
    );
    write_dirent(&mut img, ROOT_DIR_BLOCK, 40, 11, 24, "photo.raw", 1); // stale (deleted)

    // logs directory: ".", "..", live "readme", and a stale "app.log".
    write_dirent(&mut img, LOGS_DIR_BLOCK, 0, 13, 12, ".", 2);
    write_dirent(&mut img, LOGS_DIR_BLOCK, 12, 2, 12, "..", 2);
    write_dirent(
        &mut img,
        LOGS_DIR_BLOCK,
        24,
        12,
        (BS - 24) as u16,
        "readme",
        1,
    );
    write_dirent(&mut img, LOGS_DIR_BLOCK, 40, 14, 16, "app.log", 1); // stale (deleted)

    // Write the image and run recovery.
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();

    let volumes = recover::detect(&source).unwrap();
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0].fs_label(), "ext2/3/4");
    // The superblock advertises the EXTENTS incompat feature, so it classifies
    // as ext4.
    assert_eq!(volumes[0].fs_version(), Some("ext4"));
    // log_block_size 0 => 1 KiB allocation blocks.
    assert_eq!(volumes[0].alloc_unit(), Some(1024));
    assert_eq!(volumes[0].created_time(), Some(1_600_000_000));
    assert_eq!(volumes[0].written_time(), Some(1_700_000_000));
    assert_eq!(volumes[0].last_mounted().as_deref(), Some("/home"));
    // 32 inodes total, 20 free => 12 used.
    assert_eq!(volumes[0].inode_usage(), Some((12, 32)));

    let vol = ext4::Volume::parse(&source, 0).unwrap();
    assert!(vol.is_clean(), "s_state clean bit set");
    assert_eq!(vol.version(), "ext4");
    let stats = vol
        .recover_deleted(
            &source,
            &out_dir,
            &unearth::recover::RecoverOptions::default(),
        )
        .unwrap();
    assert_eq!(stats.recovered, 2, "photo.raw and logs/app.log");

    assert_eq!(std::fs::read(out_dir.join("photo.raw")).unwrap(), photo);
    assert_eq!(
        std::fs::read(out_dir.join("logs").join("app.log")).unwrap(),
        applog
    );
}

// --- Classic indirect block maps (ext2/ext3 style) -------------------------

fn indirect_payload() -> Vec<u8> {
    (0..14_000u32)
        .map(|i| (i.wrapping_mul(7) % 251) as u8)
        .collect()
}

fn source_in(tmp: &tempfile::TempDir, bytes: &[u8]) -> Source {
    let p = tmp.path().join("ext2.img");
    std::fs::write(&p, bytes).unwrap();
    Source::open(&p).unwrap()
}

/// A file mapped by direct pointers and a single-indirect block, with unused
/// blocks between its data blocks, comes back byte for byte.
#[test]
fn recovers_a_file_through_a_single_indirect_block() {
    let payload = indirect_payload();
    let tmp = tempfile::tempdir().unwrap();
    let src = source_in(&tmp, &common::ext_indirect_volume("big.bin", &payload));
    let vol = ext4::Volume::parse(&src, 0).unwrap();
    assert_eq!(vol.version(), "ext2");
    let out = tmp.path().join("out");
    let stats = vol
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1);
    assert_eq!(std::fs::read(out.join("big.bin")).unwrap(), payload);
    assert_eq!(stats.files[0].size, payload.len() as u64);
}

#[test]
fn dry_run_reports_the_indirect_file_with_its_size() {
    let payload = indirect_payload();
    let tmp = tempfile::tempdir().unwrap();
    let src = source_in(&tmp, &common::ext_indirect_volume("big.bin", &payload));
    let vol = ext4::Volume::parse(&src, 0).unwrap();
    let out = tmp.path().join("out");
    let stats = vol
        .recover_deleted(
            &src,
            &out,
            &RecoverOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(stats.recovered, 1);
    assert_eq!(stats.files.len(), 1);
    assert_eq!(stats.files[0].size, payload.len() as u64);
    assert_eq!(stats.files[0].path, std::path::PathBuf::from("big.bin"));
    assert!(!out.exists(), "a dry run writes nothing");
}

/// With the image cut just before the indirect block, the tail of the map is
/// gone: the file is refused or comes back short, never zero-padded to size.
#[test]
fn a_truncated_indirect_block_never_yields_a_padded_file() {
    let payload = indirect_payload();
    let mut img = common::ext_indirect_volume("big.bin", &payload);
    img.truncate(common::EXT_INDIRECT_BLOCK * 1024);
    let tmp = tempfile::tempdir().unwrap();
    let src = source_in(&tmp, &img);
    let vol = ext4::Volume::parse(&src, 0).unwrap();
    let out = tmp.path().join("out");
    let stats = vol
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    let file = out.join("big.bin");
    if file.exists() {
        let got = std::fs::read(&file).unwrap();
        assert!(got.len() < payload.len(), "must not be padded to full size");
        assert_eq!(
            got[..],
            payload[..got.len()],
            "what came back is the file's own prefix"
        );
        let row = stats.files.iter().find(|f| f.recovered).unwrap();
        assert_eq!(
            row.size,
            got.len() as u64,
            "the report says what was written"
        );
    } else {
        assert_eq!(stats.recovered, 0);
        assert_eq!(stats.skipped, 1);
    }
}
