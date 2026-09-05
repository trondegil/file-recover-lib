//! Integration test: build a minimal exFAT volume by hand, "delete" a file in
//! it (clearing the InUse bits), and verify recovery restores its full name and
//! contents.

use unearth::exfat;
use unearth::recover;
use unearth::source::Source;

const BPS_SHIFT: u8 = 9; // 512-byte sectors
const SPC_SHIFT: u8 = 0; // 1 sector per cluster => 512-byte clusters
const BPS: usize = 1 << BPS_SHIFT;
const CLUSTER: usize = BPS << SPC_SHIFT;

const FAT_OFFSET: usize = 8; // sectors
const CLUSTER_HEAP_OFFSET: usize = 16; // sectors
const CLUSTER_COUNT: u32 = 32;
const ROOT_CLUSTER: u32 = 2;
const VOLUME_SECTORS: u64 = (CLUSTER_HEAP_OFFSET as u64) + CLUSTER_COUNT as u64;

fn cluster_byte_offset(cluster: u32) -> usize {
    (CLUSTER_HEAP_OFFSET + (cluster as usize - 2)) * BPS
}

fn write_boot(img: &mut [u8]) {
    img[0] = 0xEB;
    img[1] = 0x76;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"EXFAT   ");
    img[72..80].copy_from_slice(&VOLUME_SECTORS.to_le_bytes());
    img[80..84].copy_from_slice(&(FAT_OFFSET as u32).to_le_bytes());
    img[88..92].copy_from_slice(&(CLUSTER_HEAP_OFFSET as u32).to_le_bytes());
    img[92..96].copy_from_slice(&CLUSTER_COUNT.to_le_bytes());
    img[96..100].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
    img[100..104].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // VolumeSerialNumber
    img[106..108].copy_from_slice(&0x0002u16.to_le_bytes()); // VolumeFlags: dirty
    img[108] = BPS_SHIFT;
    img[109] = SPC_SHIFT;
    img[110] = 1; // number of FATs
    img[510] = 0x55;
    img[511] = 0xAA;
}

/// Write a 32-bit FAT entry for `cluster`.
fn write_fat(img: &mut [u8], cluster: u32, value: u32) {
    let off = FAT_OFFSET * BPS + cluster as usize * 4;
    img[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

/// Build a deleted file entry set (File + Stream + Name entries) with the
/// InUse bit cleared on every entry.
fn deleted_file_set(name: &str, first_cluster: u32, data_length: u64, contiguous: bool) -> Vec<u8> {
    let name_units: Vec<u16> = name.encode_utf16().collect();
    let name_entries = name_units.len().div_ceil(15);
    let secondary_count = 1 + name_entries; // stream + name entries

    let mut set = vec![0u8; (1 + secondary_count) * 32];

    // File directory entry (0x85 -> deleted 0x05).
    set[0] = 0x05;
    set[1] = secondary_count as u8;
    // attributes (offset 4): 0 = regular file.

    // Stream extension entry (0xC0 -> deleted 0x40).
    let s = 32;
    set[s] = 0x40;
    set[s + 1] = 0x01 | if contiguous { 0x02 } else { 0x00 }; // AllocationPossible | NoFatChain
    set[s + 3] = name_units.len() as u8; // name length in chars
    set[s + 8..s + 16].copy_from_slice(&data_length.to_le_bytes()); // valid data length
    set[s + 20..s + 24].copy_from_slice(&first_cluster.to_le_bytes());
    set[s + 24..s + 32].copy_from_slice(&data_length.to_le_bytes());

    // File name entries (0xC1 -> deleted 0x41).
    for (k, chunk) in name_units.chunks(15).enumerate() {
        let base = (2 + k) * 32;
        set[base] = 0x41;
        for (j, &u) in chunk.iter().enumerate() {
            let off = base + 2 + j * 2;
            set[off..off + 2].copy_from_slice(&u.to_le_bytes());
        }
    }
    set
}

#[test]
fn recovers_deleted_exfat_file() {
    let mut img = vec![0u8; VOLUME_SECTORS as usize * BPS];
    write_boot(&mut img);

    // Root directory occupies cluster 2; mark it end-of-chain in the FAT.
    write_fat(&mut img, ROOT_CLUSTER, 0xFFFF_FFFF);

    // Deleted, contiguous file "vacation report.pdf" starting at cluster 3.
    let payload: Vec<u8> = (0..700u32).map(|i| (i % 251) as u8).collect();
    let first_cluster = 3u32;
    let data_off = cluster_byte_offset(first_cluster);
    img[data_off..data_off + payload.len()].copy_from_slice(&payload);

    let set = deleted_file_set(
        "vacation report.pdf",
        first_cluster,
        payload.len() as u64,
        true,
    );
    let root_off = cluster_byte_offset(ROOT_CLUSTER);
    img[root_off..root_off + set.len()].copy_from_slice(&set);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("card.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();

    // Detection should classify this as exFAT.
    let volumes = recover::detect(&source).unwrap();
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0].fs_label(), "exFAT");

    // Recover directly through the exfat backend.
    let vol = exfat::Volume::parse(&source, 0).unwrap();
    assert_eq!(vol.uuid().as_deref(), Some("1234-5678"));
    assert!(!vol.is_clean(), "VolumeDirty flag set");
    let stats = vol
        .recover_deleted(
            &source,
            &out_dir,
            &unearth::recover::RecoverOptions::default(),
        )
        .unwrap();
    assert_eq!(stats.recovered, 1, "should recover the deleted file");

    // Full long name preserved (exFAT loses no characters on delete).
    let recovered = std::fs::read(out_dir.join("vacation report.pdf")).unwrap();
    assert_eq!(
        recovered, payload,
        "recovered bytes must match the original"
    );
}

#[test]
fn reads_the_volume_label() {
    let mut img = vec![0u8; VOLUME_SECTORS as usize * BPS];
    write_boot(&mut img);
    write_fat(&mut img, ROOT_CLUSTER, 0xFFFF_FFFF);

    // A Volume Label entry (0x83) at the start of the root directory: a
    // character count then up to 11 UTF-16LE units.
    let label = "MY CARD";
    let units: Vec<u16> = label.encode_utf16().collect();
    let root_off = cluster_byte_offset(ROOT_CLUSTER);
    img[root_off] = 0x83;
    img[root_off + 1] = units.len() as u8;
    for (i, &u) in units.iter().enumerate() {
        img[root_off + 2 + i * 2..root_off + 4 + i * 2].copy_from_slice(&u.to_le_bytes());
    }

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("card.img");
    std::fs::write(&img_path, &img).unwrap();
    let source = Source::open(&img_path).unwrap();

    assert_eq!(exfat::Volume::parse(&source, 0).unwrap().label(), "MY CARD");
    assert_eq!(
        recover::detect(&source).unwrap()[0]
            .volume_label()
            .as_deref(),
        Some("MY CARD")
    );
}

#[test]
fn recovers_file_in_subdirectory() {
    let mut img = vec![0u8; VOLUME_SECTORS as usize * BPS];
    write_boot(&mut img);

    // Root dir at cluster 2 (EOC). A live subdirectory "DCIM" at cluster 4,
    // contiguous, 1 cluster. The deleted file's data is at cluster 5.
    write_fat(&mut img, ROOT_CLUSTER, 0xFFFF_FFFF);

    let payload: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let file_cluster = 5u32;
    let data_off = cluster_byte_offset(file_cluster);
    img[data_off..data_off + payload.len()].copy_from_slice(&payload);

    // Root contains a live directory entry set for "DCIM" -> cluster 4.
    let mut dir_set = deleted_file_set("DCIM", 4, CLUSTER as u64, true);
    // Make it live (set InUse) and a directory.
    dir_set[0] = 0x85; // File entry in use
    dir_set[4] = 0x10; // directory attribute
    dir_set[32] = 0xC0; // stream entry in use
    for k in 0..(dir_set.len() / 32 - 2) {
        dir_set[(2 + k) * 32] = 0xC1; // name entries in use
    }
    let root_off = cluster_byte_offset(ROOT_CLUSTER);
    img[root_off..root_off + dir_set.len()].copy_from_slice(&dir_set);

    // The subdirectory (cluster 4) contains the deleted file.
    let file_set = deleted_file_set("clip.mov", file_cluster, payload.len() as u64, true);
    let sub_off = cluster_byte_offset(4);
    img[sub_off..sub_off + file_set.len()].copy_from_slice(&file_set);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("card.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();
    let vol = exfat::Volume::parse(&source, 0).unwrap();
    let stats = vol
        .recover_deleted(
            &source,
            &out_dir,
            &unearth::recover::RecoverOptions::default(),
        )
        .unwrap();
    assert_eq!(stats.recovered, 1);

    let recovered = std::fs::read(out_dir.join("DCIM").join("clip.mov")).unwrap();
    assert_eq!(recovered, payload);
}

/// An Allocation Bitmap directory entry (0x81) pointing at `first_cluster`.
fn bitmap_entry(first_cluster: u32, length: u64) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0] = 0x81; // Allocation Bitmap, in use
    e[1] = 0; // flags: the first (primary) bitmap
    e[20..24].copy_from_slice(&first_cluster.to_le_bytes());
    e[24..32].copy_from_slice(&length.to_le_bytes());
    e
}

#[test]
fn free_extents_reports_unallocated_clusters() {
    let mut img = vec![0u8; VOLUME_SECTORS as usize * BPS];
    write_boot(&mut img);
    // Root directory (cluster 2) and the Allocation Bitmap (cluster 4) are both
    // end-of-chain.
    write_fat(&mut img, ROOT_CLUSTER, 0xFFFF_FFFF);
    write_fat(&mut img, 4, 0xFFFF_FFFF);

    // Root holds a single Allocation Bitmap entry → cluster 4, 4 bytes (covers
    // the 32 clusters of this volume).
    let root_off = cluster_byte_offset(ROOT_CLUSTER);
    img[root_off..root_off + 32].copy_from_slice(&bitmap_entry(4, 4));

    // Bitmap: bit (cluster - 2). Mark cluster 2 (root) and cluster 4 (bitmap)
    // allocated; everything else — including cluster 3 — free.
    let bmp_off = cluster_byte_offset(4);
    img[bmp_off] = 0b0000_0101; // bits 0 and 2 set

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("card.img");
    std::fs::write(&img_path, &img).unwrap();
    let source = Source::open(&img_path).unwrap();
    let vol = exfat::Volume::parse(&source, 0).unwrap();

    let free = vol.free_extents(&source).unwrap();
    let covered = |c: u32| {
        let off = cluster_byte_offset(c) as u64;
        free.iter().any(|&(s, l)| off >= s && off < s + l)
    };
    assert!(covered(3), "cluster 3 is unallocated");
    assert!(!covered(2), "cluster 2 (root) is allocated");
    assert!(!covered(4), "cluster 4 (bitmap) is allocated");
}

/// A deleted file whose FAT chain was cleared, written around a cluster that
/// is still allocated to a live file: the read must step over the allocated
/// cluster (the bitmap says it cannot be ours) and come back whole.
#[test]
fn reassembles_a_fragmented_file_around_an_allocated_cluster() {
    let mut img = vec![0u8; VOLUME_SECTORS as usize * BPS];
    write_boot(&mut img);
    write_fat(&mut img, ROOT_CLUSTER, 0xFFFF_FFFF);
    write_fat(&mut img, 4, 0xFFFF_FFFF); // bitmap
    write_fat(&mut img, 7, 0xFFFF_FFFF); // a live file's single cluster

    // Bitmap at cluster 4: clusters 2, 4, and 7 allocated (bits are cluster-2).
    let root_off = cluster_byte_offset(ROOT_CLUSTER);
    img[root_off..root_off + 32].copy_from_slice(&bitmap_entry(4, 4));
    let bm = cluster_byte_offset(4);
    img[bm] = 0b0010_0101; // clusters 2, 4, 7

    // The deleted file's data: clusters 6, 8, 9 (three full clusters minus a
    // few bytes), chain cleared, NoFatChain clear (it was not contiguous).
    let payload: Vec<u8> = (0..(3 * CLUSTER - 5) as u32)
        .map(|i| (i % 251) as u8)
        .collect();
    let (c6, rest) = payload.split_at(CLUSTER);
    let (c8, c9) = rest.split_at(CLUSTER);
    for (cluster, bytes) in [(6u32, c6), (8, c8), (9, c9)] {
        let off = cluster_byte_offset(cluster);
        img[off..off + bytes.len()].copy_from_slice(bytes);
    }
    // The live file's cluster 7 holds something else entirely.
    let off7 = cluster_byte_offset(7);
    img[off7..off7 + CLUSTER].fill(0xEE);

    let set = deleted_file_set("split.bin", 6, payload.len() as u64, false);
    img[root_off + 32..root_off + 32 + set.len()].copy_from_slice(&set);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("card.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");
    let source = Source::open(&img_path).unwrap();
    let vol = exfat::Volume::parse(&source, 0).unwrap();
    let stats = vol
        .recover_deleted(
            &source,
            &out_dir,
            &unearth::recover::RecoverOptions::default(),
        )
        .unwrap();
    assert_eq!(stats.recovered, 1);
    assert_eq!(std::fs::read(out_dir.join("split.bin")).unwrap(), payload);
}
