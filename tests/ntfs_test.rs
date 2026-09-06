//! Integration test: build a minimal NTFS volume (boot sector + a small MFT)
//! by hand, mark file records as deleted, and verify recovery restores names,
//! folder paths, and contents — for resident, non-resident, and nested files.

use unearth::ntfs;
use unearth::recover;
use unearth::source::Source;

const BPS: usize = 512;
const SPC: usize = 1;
const CLUSTER: usize = BPS * SPC;
const RECORD: usize = 1024; // 2 sectors per MFT record

const MFT_CLUSTER: usize = 4; // MFT starts at cluster 4
const MFT_RECORDS: usize = 16; // 16 records => 32 clusters
const TOTAL_CLUSTERS: usize = 64;

fn mft_byte(record: usize) -> usize {
    MFT_CLUSTER * CLUSTER + record * RECORD
}

fn cluster_byte(cluster: usize) -> usize {
    cluster * CLUSTER
}

fn write_boot(img: &mut [u8]) {
    img[0] = 0xEB;
    img[1] = 0x52;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"NTFS    ");
    img[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    img[13] = SPC as u8;
    img[40..48].copy_from_slice(&(TOTAL_CLUSTERS as u64).to_le_bytes()); // total sectors (spc=1)
    img[48..56].copy_from_slice(&(MFT_CLUSTER as u64).to_le_bytes()); // $MFT cluster
    img[64] = (-10i8) as u8; // clusters-per-record => 2^10 = 1024 bytes
    img[72..80].copy_from_slice(&0x1A2B_3C4D_5E6F_7A8Bu64.to_le_bytes()); // volume serial
    img[510] = 0x55;
    img[511] = 0xAA;
}

/// Pad an attribute to a multiple of 8 bytes.
fn pad8(mut a: Vec<u8>) -> Vec<u8> {
    while a.len() % 8 != 0 {
        a.push(0);
    }
    a
}

/// Build a resident `$FILE_NAME` (0x30) attribute.
fn filename_attr(name: &str, parent_record: u64, namespace: u8) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut content = vec![0u8; 0x42 + units.len() * 2];
    content[0..8].copy_from_slice(&parent_record.to_le_bytes()); // parent ref (seq 0)
    content[0x40] = units.len() as u8;
    content[0x41] = namespace;
    for (i, &u) in units.iter().enumerate() {
        content[0x42 + i * 2..0x42 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }

    let mut attr = vec![0u8; 24];
    attr[0..4].copy_from_slice(&0x30u32.to_le_bytes());
    attr[8] = 0; // resident
    attr[10..12].copy_from_slice(&24u16.to_le_bytes()); // name offset
    attr[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes()); // content length
    attr[20..22].copy_from_slice(&24u16.to_le_bytes()); // content offset
    attr.extend_from_slice(&content);
    let attr = pad8(attr);
    let len = attr.len() as u32;
    let mut attr = attr;
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr
}

/// Build a resident `$VOLUME_NAME` (0x60) attribute holding `label` as UTF-16LE.
fn volume_name_attr(label: &str) -> Vec<u8> {
    let mut content = Vec::new();
    for u in label.encode_utf16() {
        content.extend_from_slice(&u.to_le_bytes());
    }
    let mut attr = vec![0u8; 24];
    attr[0..4].copy_from_slice(&0x60u32.to_le_bytes());
    attr[8] = 0; // resident
    attr[10..12].copy_from_slice(&24u16.to_le_bytes()); // name offset
    attr[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes());
    attr[20..22].copy_from_slice(&24u16.to_le_bytes()); // content offset
    attr.extend_from_slice(&content);
    let attr = pad8(attr);
    let len = attr.len() as u32;
    let mut attr = attr;
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr
}

/// Build a resident `$VOLUME_INFORMATION` (0x70) attribute; `dirty` sets the
/// volume-dirty flag (content offset 10, bit 0).
fn volume_info_attr(dirty: bool) -> Vec<u8> {
    let mut content = vec![0u8; 12];
    content[8] = 3; // major version
    content[9] = 1; // minor version
    let flags: u16 = if dirty { 0x0001 } else { 0 };
    content[10..12].copy_from_slice(&flags.to_le_bytes());
    let mut attr = vec![0u8; 24];
    attr[0..4].copy_from_slice(&0x70u32.to_le_bytes());
    attr[8] = 0; // resident
    attr[10..12].copy_from_slice(&24u16.to_le_bytes()); // name offset
    attr[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes());
    attr[20..22].copy_from_slice(&24u16.to_le_bytes()); // content offset
    attr.extend_from_slice(&content);
    let mut attr = pad8(attr);
    let len = attr.len() as u32;
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr
}

/// Build a resident `$STANDARD_INFORMATION` (0x10) attribute carrying the four
/// FILETIMEs; `created`/`modified` are given as Windows FILETIME (100 ns ticks
/// since 1601-01-01).
fn std_info_attr(created: u64, modified: u64) -> Vec<u8> {
    let mut content = vec![0u8; 48];
    content[0x00..0x08].copy_from_slice(&created.to_le_bytes());
    content[0x08..0x10].copy_from_slice(&modified.to_le_bytes());
    content[0x10..0x18].copy_from_slice(&modified.to_le_bytes()); // mft change
    content[0x18..0x20].copy_from_slice(&created.to_le_bytes()); // access
    let mut attr = vec![0u8; 24];
    attr[0..4].copy_from_slice(&0x10u32.to_le_bytes());
    attr[8] = 0; // resident
    attr[10..12].copy_from_slice(&24u16.to_le_bytes()); // name offset
    attr[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes());
    attr[20..22].copy_from_slice(&24u16.to_le_bytes()); // content offset
    attr.extend_from_slice(&content);
    let mut attr = pad8(attr);
    let len = attr.len() as u32;
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr
}

/// Build a resident `$DATA` (0x80) attribute holding `content` inline.
fn data_resident(content: &[u8]) -> Vec<u8> {
    let mut attr = vec![0u8; 24];
    attr[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    attr[8] = 0; // resident
    attr[10..12].copy_from_slice(&24u16.to_le_bytes());
    attr[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes());
    attr[20..22].copy_from_slice(&24u16.to_le_bytes());
    attr.extend_from_slice(content);
    let attr = pad8(attr);
    let len = attr.len() as u32;
    let mut attr = attr;
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr
}

/// Build a non-resident `$DATA` (0x80) attribute with the given run list bytes.
fn data_nonresident(real_size: u64, runs: &[u8]) -> Vec<u8> {
    let run_offset = 64usize;
    let mut attr = vec![0u8; run_offset];
    attr[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    attr[8] = 1; // non-resident
    attr[32..34].copy_from_slice(&(run_offset as u16).to_le_bytes()); // data run offset
    attr[40..48].copy_from_slice(&real_size.to_le_bytes()); // allocated size
    attr[48..56].copy_from_slice(&real_size.to_le_bytes()); // real size
    attr[56..64].copy_from_slice(&real_size.to_le_bytes()); // initialized size
    attr.extend_from_slice(runs);
    let attr = pad8(attr);
    let len = attr.len() as u32;
    let mut attr = attr;
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr
}

/// Assemble a 1024-byte MFT record from a flags value and attributes.
fn build_record(flags: u16, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut rec = vec![0u8; RECORD];
    rec[0..4].copy_from_slice(b"FILE");
    rec[4..6].copy_from_slice(&48u16.to_le_bytes()); // USA offset
    rec[6..8].copy_from_slice(&3u16.to_le_bytes()); // USA count (1 + 2 sectors)
    rec[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence number
    rec[18..20].copy_from_slice(&1u16.to_le_bytes()); // hard link count
    rec[20..22].copy_from_slice(&56u16.to_le_bytes()); // first attribute offset
    rec[22..24].copy_from_slice(&flags.to_le_bytes());
    rec[28..32].copy_from_slice(&(RECORD as u32).to_le_bytes()); // allocated size

    let mut off = 56;
    for a in attrs {
        rec[off..off + a.len()].copy_from_slice(a);
        off += a.len();
    }
    rec[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // end marker
    rec[28..32].copy_from_slice(&((off + 8) as u32).to_le_bytes()); // used size
                                                                    // Update sequence array, as the driver writes it: the USN at USA[0], the
                                                                    // bytes each sector tail really held at USA[1..], and the USN written
                                                                    // over every sector tail so a torn write can be detected.
    let usn = USN.to_le_bytes();
    for sector in 1..=2 {
        let tail = sector * BPS - 2;
        let original = [rec[tail], rec[tail + 1]];
        rec[48 + sector * 2..48 + sector * 2 + 2].copy_from_slice(&original);
        rec[tail..tail + 2].copy_from_slice(&usn);
    }
    rec[48..50].copy_from_slice(&usn);
    rec
}

/// The update sequence number every fixture record carries.
const USN: u16 = 0x0A0B;

const FLAG_IN_USE: u16 = 0x01;
const FLAG_DIR: u16 = 0x02;

#[test]
fn free_extents_reads_the_bitmap() {
    let mut img = vec![0u8; TOTAL_CLUSTERS * CLUSTER];
    write_boot(&mut img);

    // Record 0: $MFT (non-resident $DATA over 32 clusters from LCN 4).
    let mft_runs = [0x11u8, MFT_RECORDS as u8 * 2, MFT_CLUSTER as u8, 0x00];
    let rec0 = build_record(
        FLAG_IN_USE,
        &[data_nonresident((MFT_RECORDS * RECORD) as u64, &mft_runs)],
    );
    let o = mft_byte(0);
    img[o..o + RECORD].copy_from_slice(&rec0);

    // Record 6: $Bitmap with a resident $DATA holding the cluster bitmap (64
    // clusters = 8 bytes). All allocated except cluster 50 (bit 50: byte 6, bit 2).
    let mut bitmap = vec![0xFFu8; 8];
    bitmap[6] &= !(1 << 2);
    let rec6 = build_record(FLAG_IN_USE, &[data_resident(&bitmap)]);
    let o = mft_byte(6);
    img[o..o + RECORD].copy_from_slice(&rec6);

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("ntfs.img");
    std::fs::write(&p, &img).unwrap();
    let src = Source::open(&p).unwrap();
    let vol = ntfs::Volume::parse(&src, 0).unwrap();

    let free = vol.free_extents(&src).unwrap();
    let covered = |c: u64| {
        let off = c * CLUSTER as u64;
        free.iter().any(|&(s, l)| off >= s && off < s + l)
    };
    assert!(covered(50), "cluster 50 is free");
    assert!(!covered(4), "cluster 4 ($MFT) is allocated");
    assert!(!covered(0), "cluster 0 (boot) is allocated");
}

#[test]
fn reads_the_volume_label() {
    let mut img = vec![0u8; TOTAL_CLUSTERS * CLUSTER];
    write_boot(&mut img);

    // Record 0: $MFT (non-resident $DATA over 32 clusters from LCN 4).
    let mft_runs = [0x11u8, MFT_RECORDS as u8 * 2, MFT_CLUSTER as u8, 0x00];
    let rec0 = build_record(
        FLAG_IN_USE,
        &[data_nonresident((MFT_RECORDS * RECORD) as u64, &mft_runs)],
    );
    let o = mft_byte(0);
    img[o..o + RECORD].copy_from_slice(&rec0);

    // Record 3: $Volume with $STANDARD_INFORMATION (timestamps), a $VOLUME_NAME,
    // and a dirty $VOLUME_INFORMATION.
    let created_unix = 1_600_000_000u64;
    let modified_unix = 1_700_000_000u64;
    let to_filetime = |unix: u64| (unix + 11_644_473_600) * 10_000_000;
    let rec3 = build_record(
        FLAG_IN_USE,
        &[
            std_info_attr(to_filetime(created_unix), to_filetime(modified_unix)),
            volume_name_attr("MY NTFS DISK"),
            volume_info_attr(true),
        ],
    );
    let o = mft_byte(3);
    img[o..o + RECORD].copy_from_slice(&rec3);

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("ntfs.img");
    std::fs::write(&p, &img).unwrap();
    let src = Source::open(&p).unwrap();

    let vol = ntfs::Volume::parse(&src, 0).unwrap();
    assert_eq!(vol.label(), "MY NTFS DISK");
    assert_eq!(vol.is_clean(), Some(false), "dirty bit set");
    assert_eq!(vol.created_time(), Some(created_unix));
    assert_eq!(vol.written_time(), Some(modified_unix));
    assert_eq!(
        recover::detect(&src).unwrap()[0].volume_label().as_deref(),
        Some("MY NTFS DISK")
    );
}

#[test]
fn recovers_deleted_ntfs_files() {
    let mut img = vec![0u8; TOTAL_CLUSTERS * CLUSTER];
    write_boot(&mut img);

    // Record 0: $MFT, in use, non-resident $DATA describing the MFT extent
    // (32 clusters starting at LCN 4).
    let mft_runs = [0x11u8, MFT_RECORDS as u8 * 2, MFT_CLUSTER as u8, 0x00];
    let rec0 = build_record(
        FLAG_IN_USE,
        &[data_nonresident((MFT_RECORDS * RECORD) as u64, &mft_runs)],
    );
    let o = mft_byte(0);
    img[o..o + RECORD].copy_from_slice(&rec0);

    // Record 6: deleted file "report.txt" in root, resident data.
    let report = b"hello from a deleted NTFS file\n";
    let rec6 = build_record(
        0, // deleted (in-use bit clear)
        &[filename_attr("report.txt", 5, 1), data_resident(report)],
    );
    let o = mft_byte(6);
    img[o..o + RECORD].copy_from_slice(&rec6);

    // Record 7: deleted file "photo.jpg" in root, non-resident data at cluster
    // 36 (2 clusters), 700 bytes.
    let payload: Vec<u8> = (0..700u32).map(|i| (i % 251) as u8).collect();
    let file_lcn = 36usize;
    let d = cluster_byte(file_lcn);
    img[d..d + payload.len()].copy_from_slice(&payload);
    let runs = [0x11u8, 0x02, file_lcn as u8, 0x00];
    let rec7 = build_record(
        0,
        &[
            filename_attr("photo.jpg", 5, 1),
            data_nonresident(payload.len() as u64, &runs),
        ],
    );
    let o = mft_byte(7);
    img[o..o + RECORD].copy_from_slice(&rec7);

    // Record 8: live directory "Docs" in root.
    let rec8 = build_record(FLAG_IN_USE | FLAG_DIR, &[filename_attr("Docs", 5, 1)]);
    let o = mft_byte(8);
    img[o..o + RECORD].copy_from_slice(&rec8);

    // Record 9: deleted file "notes.txt" inside "Docs" (parent = record 8).
    let notes = b"nested note contents";
    let rec9 = build_record(0, &[filename_attr("notes.txt", 8, 1), data_resident(notes)]);
    let o = mft_byte(9);
    img[o..o + RECORD].copy_from_slice(&rec9);

    // Write the image and run recovery.
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();

    let volumes = recover::detect(&source).unwrap();
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0].fs_label(), "NTFS");

    let vol = ntfs::Volume::parse(&source, 0).unwrap();
    assert_eq!(vol.uuid().as_deref(), Some("1A2B3C4D5E6F7A8B"));
    let stats = vol
        .recover_deleted(
            &source,
            &out_dir,
            &unearth::recover::RecoverOptions::default(),
        )
        .unwrap();
    assert_eq!(stats.recovered, 3, "report.txt, photo.jpg, Docs/notes.txt");

    assert_eq!(std::fs::read(out_dir.join("report.txt")).unwrap(), report);
    assert_eq!(std::fs::read(out_dir.join("photo.jpg")).unwrap(), payload);
    assert_eq!(
        std::fs::read(out_dir.join("Docs").join("notes.txt")).unwrap(),
        notes
    );
}

/// A deleted record with `$DATA` but no `$FILE_NAME` (what the Linux ntfs3
/// driver leaves behind) is recovered under `_unnamed/`, with the extension
/// identified from its content when possible.
#[test]
fn recovers_nameless_records_by_content() {
    let mut img = vec![0u8; TOTAL_CLUSTERS * CLUSTER];
    write_boot(&mut img);
    let mft_runs = [0x11u8, MFT_RECORDS as u8 * 2, MFT_CLUSTER as u8, 0x00];
    let rec0 = build_record(
        FLAG_IN_USE,
        &[data_nonresident((MFT_RECORDS * RECORD) as u64, &mft_runs)],
    );
    let o = mft_byte(0);
    img[o..o + RECORD].copy_from_slice(&rec0);

    // Record 12: a nameless deleted JPEG; record 13: nameless deleted text.
    let mut jpeg = vec![
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00,
    ];
    jpeg.extend_from_slice(&[0x11; 40]);
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    let text = b"plain text with no signature".to_vec();
    for (idx, content) in [(12usize, &jpeg), (13usize, &text)] {
        let rec = build_record(0, &[std_info_attr(0, 0), data_resident(content)]);
        let o = mft_byte(idx);
        img[o..o + RECORD].copy_from_slice(&rec);
    }

    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("ntfs.img");
    std::fs::write(&p, &img).unwrap();
    let src = Source::open(&p).unwrap();
    let vol = ntfs::Volume::parse(&src, 0).unwrap();
    let out = tmp.path().join("out");
    let stats = vol
        .recover_deleted(&src, &out, &unearth::recover::RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 2);
    assert_eq!(
        std::fs::read(out.join("_unnamed/mft-12.jpg")).unwrap(),
        jpeg
    );
    assert_eq!(
        std::fs::read(out.join("_unnamed/mft-13.bin")).unwrap(),
        text
    );
}

/// Boot sector plus the `$MFT` record; `records` are `(index, record)` pairs
/// dropped into the MFT.
fn ntfs_image_with(records: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let mut img = vec![0u8; TOTAL_CLUSTERS * CLUSTER];
    write_boot(&mut img);
    let mft_runs = [0x11u8, MFT_RECORDS as u8 * 2, MFT_CLUSTER as u8, 0x00];
    let rec0 = build_record(
        FLAG_IN_USE,
        &[data_nonresident((MFT_RECORDS * RECORD) as u64, &mft_runs)],
    );
    let o = mft_byte(0);
    img[o..o + RECORD].copy_from_slice(&rec0);
    for (index, rec) in records {
        let o = mft_byte(*index);
        img[o..o + RECORD].copy_from_slice(rec);
    }
    img
}

/// Fill every cluster from 40 up with its own index, so a recovered file
/// shows exactly which clusters, in which order, it was read from.
fn stamp_clusters(img: &mut [u8]) {
    for c in 40..TOTAL_CLUSTERS {
        img[cluster_byte(c)..cluster_byte(c + 1)].fill(c as u8);
    }
}

fn recover(img: &[u8]) -> (tempfile::TempDir, unearth::recover::RecoverStats) {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("ntfs.img");
    std::fs::write(&p, img).unwrap();
    let src = Source::open(&p).unwrap();
    let vol = ntfs::Volume::parse(&src, 0).unwrap();
    let stats = vol
        .recover_deleted(
            &src,
            &tmp.path().join("out"),
            &unearth::recover::RecoverOptions::default(),
        )
        .unwrap();
    (tmp, stats)
}

/// A run list that goes forward, then backward (a signed delta), then
/// through a sparse hole, then forward again, ending mid-cluster: the bytes
/// must come out in run order with the hole as zeros and nothing past
/// `real_size`.
#[test]
fn signed_and_sparse_data_runs_are_reassembled_in_order() {
    // 50..=52, then 40..=41 (delta -10, one signed byte 0xF6), then two
    // sparse clusters (offset width 0), then 60 (delta +20 from 40).
    let runs = [
        0x11u8, 3, 50, // len 3 at LCN 50
        0x11, 2, 0xF6, // len 2 at LCN 50 - 10 = 40
        0x01, 2, // len 2, sparse
        0x11, 1, 20, // len 1 at LCN 40 + 20 = 60
        0x00,
    ];
    let real_size = 8 * CLUSTER as u64 - 100;
    let rec = build_record(
        0,
        &[
            filename_attr("runs.bin", 5, 1),
            data_nonresident(real_size, &runs),
        ],
    );
    let mut img = ntfs_image_with(&[(6, rec)]);
    stamp_clusters(&mut img);

    let mut expected = Vec::new();
    for c in [50u8, 51, 52, 40, 41] {
        expected.extend(std::iter::repeat(c).take(CLUSTER));
    }
    expected.extend(std::iter::repeat(0u8).take(2 * CLUSTER));
    expected.extend(std::iter::repeat(60u8).take(CLUSTER - 100));
    assert_eq!(expected.len() as u64, real_size);

    let (tmp, stats) = recover(&img);
    assert_eq!(stats.recovered, 1);
    let got = std::fs::read(tmp.path().join("out").join("runs.bin")).unwrap();
    assert_eq!(got.len() as u64, real_size);
    assert_eq!(got, expected);
    assert_eq!(stats.files[0].size, real_size);
}

/// A run that reaches past the end of the volume cannot be padded up to the
/// claimed size: the file comes out short (or not at all) and the report
/// row carries the length that was actually written.
#[test]
fn a_run_past_the_volume_end_is_not_padded_to_real_size() {
    // Four clusters from LCN 62 on a 64-cluster volume: two exist, two do not.
    let runs = [0x11u8, 4, 62, 0x00];
    let real_size = 4 * CLUSTER as u64;
    let rec = build_record(
        0,
        &[
            filename_attr("over.bin", 5, 1),
            data_nonresident(real_size, &runs),
        ],
    );
    let mut img = ntfs_image_with(&[(6, rec)]);
    stamp_clusters(&mut img);

    let (tmp, stats) = recover(&img);
    let out = tmp.path().join("out").join("over.bin");
    let row = stats
        .files
        .iter()
        .find(|f| f.path.ends_with("over.bin"))
        .expect("a report row for the file");
    if row.recovered {
        let got = std::fs::read(&out).unwrap();
        assert!(
            (got.len() as u64) < real_size,
            "must not be padded to the claimed size"
        );
        assert_eq!(got, [vec![62u8; CLUSTER], vec![63u8; CLUSTER]].concat());
        assert_eq!(
            row.size,
            got.len() as u64,
            "the report row says what was written"
        );
    } else {
        assert!(!out.exists(), "a skipped file leaves nothing behind");
    }
}

/// A record whose sector tails do not carry the update sequence number was
/// torn mid-write: its attributes cannot be trusted and it is rejected.
#[test]
fn a_record_with_mismatched_fixups_is_rejected() {
    let payload: Vec<u8> = (0..700u32).map(|i| (i % 251) as u8).collect();
    let runs = [0x11u8, 2, 40, 0x00];
    let rec = build_record(
        0,
        &[
            filename_attr("torn.bin", 5, 1),
            data_nonresident(payload.len() as u64, &runs),
        ],
    );
    // First the intact record recovers, proving the fixture is otherwise sound.
    let mut img = ntfs_image_with(&[(6, rec.clone())]);
    let d = cluster_byte(40);
    img[d..d + payload.len()].copy_from_slice(&payload);
    let (tmp, stats) = recover(&img);
    assert_eq!(stats.recovered, 1);
    assert_eq!(
        std::fs::read(tmp.path().join("out").join("torn.bin")).unwrap(),
        payload
    );

    // Now the second sector's tail holds a stale sequence number.
    let mut torn = rec;
    torn[2 * BPS - 2..2 * BPS].copy_from_slice(&0x9999u16.to_le_bytes());
    let mut img = ntfs_image_with(&[(6, torn)]);
    img[d..d + payload.len()].copy_from_slice(&payload);
    let (tmp, stats) = recover(&img);
    assert_eq!(stats.recovered, 0, "a torn record must not be parsed");
    assert!(!tmp.path().join("out").join("torn.bin").exists());
}
