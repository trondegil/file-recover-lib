//! Integration test: build a minimal FAT12 volume by hand, "delete" a file in
//! it, and verify filesystem-aware recovery restores its name and contents.

mod common;

use std::path::PathBuf;

use unearth::fat;
use unearth::source::Source;

const BPS: usize = 512; // bytes per sector
const SPC: usize = 1; // sectors per cluster
const RESERVED: usize = 1; // boot sector only
const NUM_FATS: usize = 1;
const FAT_SECTORS: usize = 1;
const ROOT_ENTRIES: usize = 16; // 16 * 32 = 512 bytes => 1 sector
const TOTAL_SECTORS: usize = 103; // keeps cluster count < 4085 => FAT12

const ROOT_DIR_SECTOR: usize = RESERVED + NUM_FATS * FAT_SECTORS; // sector 2
const FIRST_DATA_SECTOR: usize = ROOT_DIR_SECTOR + 1; // sector 3 (root dir is 1 sector)

fn cluster_sector(cluster: usize) -> usize {
    FIRST_DATA_SECTOR + (cluster - 2) * SPC
}

/// Write the BPB fields a FAT12 boot sector needs for our parser.
fn write_bpb(img: &mut [u8]) {
    img[0] = 0xEB; // jump
    img[1] = 0x3C;
    img[2] = 0x90;
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    img[13] = SPC as u8;
    img[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    img[16] = NUM_FATS as u8;
    img[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    img[19..21].copy_from_slice(&(TOTAL_SECTORS as u16).to_le_bytes());
    img[22..24].copy_from_slice(&(FAT_SECTORS as u16).to_le_bytes());
    // BS_VolID (serial) for FAT12/16 is at offset 0x27.
    img[0x27..0x2B].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
}

/// Build a deleted short 8.3 entry. `name8` and `ext3` must be pre-padded.
fn deleted_short_entry(name8: &[u8; 8], ext3: &[u8; 3], cluster: u16, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..8].copy_from_slice(name8);
    e[8..11].copy_from_slice(ext3);
    e[0] = 0xE5; // deletion marker overwrites the first name byte
    e[11] = 0x00; // attributes: a normal file
    e[20..22].copy_from_slice(&0u16.to_le_bytes()); // cluster high
    e[26..28].copy_from_slice(&cluster.to_le_bytes()); // cluster low
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// Build a (deleted) LFN entry carrying up to 13 UTF-16 chars.
fn deleted_lfn_entry(seq: u8, chars: &str) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0] = seq; // caller passes 0xE5 to mark deleted
    e[11] = 0x0F; // LFN attribute
    e[13] = 0x00; // checksum (ignored for deleted entries)

    let mut units: Vec<u16> = chars.encode_utf16().collect();
    units.push(0x0000); // terminator
    while units.len() < 13 {
        units.push(0xFFFF); // padding
    }
    let ranges = [1usize..11, 14..26, 28..32];
    let mut k = 0;
    for r in ranges {
        for pair in e[r].chunks_exact_mut(2) {
            pair.copy_from_slice(&units[k].to_le_bytes());
            k += 1;
        }
    }
    e
}

#[test]
fn recovers_deleted_fat_file_with_long_name() {
    let mut img = vec![0u8; TOTAL_SECTORS * BPS];
    write_bpb(&mut img);

    // Deleted file "photo.dat", 600 bytes, contiguous starting at cluster 3.
    let payload: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
    let start_cluster = 3usize;
    let data_off = cluster_sector(start_cluster) * BPS;
    img[data_off..data_off + payload.len()].copy_from_slice(&payload);

    // Root directory: an LFN entry followed by the deleted short entry.
    let root_off = ROOT_DIR_SECTOR * BPS;
    let lfn = deleted_lfn_entry(0xE5, "photo.dat");
    let short = deleted_short_entry(
        b"PHOTO   ",
        b"DAT",
        start_cluster as u16,
        payload.len() as u32,
    );
    img[root_off..root_off + 32].copy_from_slice(&lfn);
    img[root_off + 32..root_off + 64].copy_from_slice(&short);

    // Write the image and run recovery.
    let tmp = tempfile::tempdir().unwrap();
    let img_path: PathBuf = tmp.path().join("card.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();
    let volumes = fat::detect_volumes(&source).unwrap();
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0].fat_type, fat::FatType::Fat12);
    assert_eq!(volumes[0].uuid().as_deref(), Some("1234-5678"));
    assert_eq!(volumes[0].cluster_size(), (BPS * SPC) as u64);

    let stats = volumes[0]
        .recover_deleted(
            &source,
            &out_dir,
            &unearth::recover::RecoverOptions::default(),
        )
        .unwrap();
    assert_eq!(stats.recovered, 1, "should recover the deleted file");

    // The long name should be reconstructed exactly, with original contents.
    let recovered = std::fs::read(out_dir.join("photo.dat")).unwrap();
    assert_eq!(
        recovered, payload,
        "recovered bytes must match the original"
    );
}

#[test]
fn skips_short_name_first_char() {
    // Same as above but with no LFN entry: the leading char is lost to the
    // deletion marker, so the recovered name uses '_' in its place.
    let mut img = vec![0u8; TOTAL_SECTORS * BPS];
    write_bpb(&mut img);

    let payload: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
    let start_cluster = 2usize;
    let data_off = cluster_sector(start_cluster) * BPS;
    img[data_off..data_off + payload.len()].copy_from_slice(&payload);

    let root_off = ROOT_DIR_SECTOR * BPS;
    let short = deleted_short_entry(
        b"NOTES   ",
        b"TXT",
        start_cluster as u16,
        payload.len() as u32,
    );
    img[root_off..root_off + 32].copy_from_slice(&short);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("card.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();
    let volumes = fat::detect_volumes(&source).unwrap();
    let stats = volumes[0]
        .recover_deleted(
            &source,
            &out_dir,
            &unearth::recover::RecoverOptions::default(),
        )
        .unwrap();
    assert_eq!(stats.recovered, 1);

    // First char unknown -> "_OTES.TXT".
    let recovered = std::fs::read(out_dir.join("_OTES.TXT")).unwrap();
    assert_eq!(recovered, payload);
}

/// A folder removed as a whole: its own entry is deleted, and its cluster still
/// lists the deleted files inside. They must come back under the folder.
#[test]
fn recovers_files_from_a_deleted_folder() {
    let payload = b"inside a folder that was deleted";
    let img = common::fat32_deleted_dir_volume(b"PHOTOS  ", b"IMG_0001", b"JPG", payload);
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("fat.img");
    std::fs::write(&p, &img).unwrap();
    let src = unearth::source::Source::open(&p).unwrap();
    let vols = unearth::recover::detect(&src).unwrap();
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &unearth::recover::RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1);
    // The first character of each short name is lost to the deletion marker.
    let got = std::fs::read(out.join("_HOTOS").join("_MG_0001.JPG")).unwrap();
    assert_eq!(got, payload);
}

/// Windows frees a deleted folder's cluster without writing back the deletion
/// markers of the files inside, so they still look live. Everything under a
/// deleted folder must count as deleted regardless.
#[test]
fn recovers_files_windows_left_looking_live_in_a_deleted_folder() {
    let payload = b"child entry still looks live";
    let img = common::fat32_windows_deleted_dir_volume(b"PHOTOS  ", b"IMG_0002", b"JPG", payload);
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("fat.img");
    std::fs::write(&p, &img).unwrap();
    let src = unearth::source::Source::open(&p).unwrap();
    let vols = unearth::recover::detect(&src).unwrap();
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &unearth::recover::RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1);
    let got = std::fs::read(out.join("_HOTOS").join("IMG_0002.JPG")).unwrap();
    assert_eq!(got, payload);
}

/// Windows zeroes the high 16 bits of a deleted FAT32 entry's start cluster.
/// On a volume with more than 65,536 clusters the file must be found again.
#[test]
fn recovers_a_file_past_cluster_65535_with_the_high_word_zeroed() {
    let payload: Vec<u8> = (0..3000u32).map(|i| (i % 253) as u8).collect();
    let img = common::fat32_highword_volume(b"DATA    ", b"BIN", &payload);
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("fat.img");
    std::fs::write(&p, &img).unwrap();
    let src = unearth::source::Source::open(&p).unwrap();
    let vols = unearth::recover::detect(&src).unwrap();
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &unearth::recover::RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1);
    assert_eq!(std::fs::read(out.join("_ATA.BIN")).unwrap(), payload);
}

fn recover_one(img: Vec<u8>) -> Vec<u8> {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("fat.img");
    std::fs::write(&p, &img).unwrap();
    let src = unearth::source::Source::open(&p).unwrap();
    let vols = unearth::recover::detect(&src).unwrap();
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &unearth::recover::RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1);
    std::fs::read(out.join("_ILE.BIN")).unwrap()
}

/// A deleted file written into the gaps between live files comes back whole:
/// the FAT says which clusters still belong to live files, and the read steps
/// over them. The file's own chain was cleared by the delete.
#[test]
fn reassembles_a_file_written_around_live_clusters() {
    let payload: Vec<u8> = (0..(4 * 512 - 7) as u32).map(|i| (i % 253) as u8).collect();
    let got = recover_one(common::fat32_fragmented_volume(
        b"FILE    ",
        b"BIN",
        &payload,
        false,
    ));
    assert_eq!(got, payload);
}

/// A file that started in the last free stretch of the volume continues in
/// the first free gap, as a next-fit allocator lays it out.
#[test]
fn follows_the_allocator_wrap_to_the_start_of_the_volume() {
    let payload: Vec<u8> = (0..(4 * 512 - 7) as u32).map(|i| (i % 249) as u8).collect();
    let got = recover_one(common::fat32_fragmented_volume(
        b"FILE    ",
        b"BIN",
        &payload,
        true,
    ));
    assert_eq!(got, payload);
}

/// A JPEG whose next free cluster holds a stranger's data: the allocation map
/// cannot tell, but JPEG structure rejects `FF 7A` in scan data, so the read
/// steps over the decoy and the photo comes back byte-for-byte.
#[test]
fn jpeg_structure_steps_over_a_free_decoy_cluster() {
    // SOI, APP0, SOS (1-byte header), then scan data with no FF bytes, then EOI.
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00];
    jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x03, 0x01]);
    jpeg.extend((0..1100u32).map(|i| (i % 200) as u8 + 1));
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    let img = common::fat32_jpeg_decoy_volume(&jpeg);
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("fat.img");
    std::fs::write(&p, &img).unwrap();
    let src = unearth::source::Source::open(&p).unwrap();
    let vols = unearth::recover::detect(&src).unwrap();
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &unearth::recover::RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1);
    assert_eq!(std::fs::read(out.join("_HOTO.JPG")).unwrap(), jpeg);
}
