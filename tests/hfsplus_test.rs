//! HFS+ undelete: recover a deleted file from a catalog leaf node's free space.

mod common;

use unearth::recover::{self, RecoverOptions, RecoverStats};
use unearth::source::Source;

fn write_img(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::write(&img, bytes).unwrap();
    (tmp, img)
}

#[test]
fn detects_and_recovers_a_deleted_file() {
    let payload = b"the quick brown fox jumps over the lazy dog";
    let (tmp, img) = write_img(&common::hfsplus_volume("notes.txt", payload));
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "HFS+");

    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();

    assert_eq!(stats.recovered, 1);
    assert_eq!(stats.bytes_recovered, payload.len() as u64);
    assert_eq!(std::fs::read(out.join("notes.txt")).unwrap(), payload);
}

#[test]
fn recovers_a_multi_block_file_byte_for_byte() {
    // Larger than one 512-byte allocation block, so the extent spans blocks.
    let payload: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    let (tmp, img) = write_img(&common::hfsplus_volume("data.bin", &payload));
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();

    assert_eq!(stats.recovered, 1);
    assert_eq!(std::fs::read(out.join("data.bin")).unwrap(), payload);
}

#[test]
fn dry_run_reports_without_writing() {
    let (tmp, img) = write_img(&common::hfsplus_volume("secret.dat", b"hello hfs+"));
    let src = Source::open(&img).unwrap();
    let vols = recover::detect(&src).unwrap();

    let out = tmp.path().join("out");
    let opts = RecoverOptions {
        min_size: 0,
        max_size: None,
        modified_after: None,
        modified_before: None,
        names: Vec::new(),
        exclude_names: Vec::new(),
        dry_run: true,
    };
    let stats = vols[0].recover_deleted(&src, &out, &opts).unwrap();

    assert_eq!(stats.recovered, 1);
    assert!(!out.exists(), "dry run must not write files");
}

#[test]
fn restores_the_original_folder_path() {
    // The deleted file lived inside a live folder "Documents"; recovery should
    // rebuild that path from the catalog's folder hierarchy.
    let payload = b"nested file body";
    let (tmp, img) = write_img(&common::hfsplus_nested_volume(
        "Documents",
        "memo.txt",
        payload,
    ));
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();

    assert_eq!(stats.recovered, 1);
    assert_eq!(
        std::fs::read(out.join("Documents").join("memo.txt")).unwrap(),
        payload
    );
}

#[test]
fn recovers_a_fragmented_file_via_the_extents_overflow_tree() {
    // The file's tail lives in a non-contiguous extent recorded only in the
    // extents-overflow B-tree, not inline in the catalog record.
    let payload: Vec<u8> = (0..800u32).map(|i| (i % 251) as u8).collect();
    let (tmp, img) = write_img(&common::hfsplus_fragmented_volume("split.bin", &payload));
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();

    assert_eq!(stats.recovered, 1, "the fragmented file is fully recovered");
    assert_eq!(std::fs::read(out.join("split.bin")).unwrap(), payload);
}

#[test]
fn free_extents_reads_the_allocation_bitmap() {
    // The builder marks the volume header, allocation, catalog, and data blocks
    // allocated (MSB-first) and leaves the rest free.
    let (_tmp, img) = write_img(&common::hfsplus_volume("notes.txt", b"hi"));
    let src = Source::open(&img).unwrap();
    let vol = unearth::hfsplus::Volume::parse(&src, 0).unwrap();

    // createDate / modifyDate decode from the HFS epoch to Unix seconds.
    assert_eq!(vol.created_time(), Some(1_600_000_000));
    assert_eq!(vol.written_time(), Some(1_700_000_000));

    let free = vol.free_extents(&src).unwrap();
    let bs = 512u64;
    let covered = |block: u64| {
        let off = block * bs;
        free.iter().any(|&(s, l)| off >= s && off < s + l)
    };
    assert!(covered(11), "block 11 is free");
    assert!(!covered(2), "block 2 (volume header) is allocated");
    assert!(!covered(8), "block 8 (catalog) is allocated");
    assert!(!covered(12), "block 12 (file data) is allocated");
}

#[test]
fn unicode_name_is_preserved() {
    let (tmp, img) = write_img(&common::hfsplus_volume("café — not.txt", b"unicode body"));
    let src = Source::open(&img).unwrap();
    let vols = recover::detect(&src).unwrap();

    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1);
    // The ':' separator is the only character HFS+ forbids; the rest survive.
    assert_eq!(
        std::fs::read(out.join("café — not.txt")).unwrap(),
        b"unicode body"
    );
}

/// A journaled volume where macOS scrubbed the deleted record from the live
/// leaf node: the only copy of it is the older node in the journal.
#[test]
fn recovers_from_a_stale_node_in_the_journal() {
    let payload = b"recovered from the hfs+ journal";
    let (tmp, img) = write_img(&common::hfsplus_journaled_volume("journal.txt", payload));
    let src = Source::open(&img).unwrap();
    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols[0].fs_label(), "HFS+");

    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1, "the journal copy must be found");
    assert_eq!(std::fs::read(out.join("journal.txt")).unwrap(), payload);
}

// --- Malformed extents-overflow records --------------------------------------

/// The bytes a file made of these blocks (in logical order) holds, cut at
/// `size`: every block is stamped with its index by the fixture.
fn stamped(blocks: &[u8], size: usize) -> Vec<u8> {
    let mut v: Vec<u8> = blocks
        .iter()
        .flat_map(|&b| std::iter::repeat(b).take(512))
        .collect();
    v.truncate(size);
    v
}

fn undelete_overflow(
    records: &[(u32, Vec<(u32, u32)>)],
    size: u64,
) -> (Option<Vec<u8>>, RecoverStats) {
    let (tmp, img) = write_img(&common::hfsplus_overflow_volume("frag.bin", size, records));
    let src = Source::open(&img).unwrap();
    let vols = recover::detect(&src).unwrap();
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    (std::fs::read(out.join("frag.bin")).ok(), stats)
}

/// Inline block 14, then overflow records for logical blocks 1 and 2..3.
const SIZE: u64 = 4 * 512 - 10;
fn good_records() -> Vec<(u32, Vec<(u32, u32)>)> {
    vec![(1, vec![(16, 1)]), (2, vec![(18, 2)])]
}

#[test]
fn overflow_records_in_key_order_rebuild_the_file_to_its_eof() {
    let (got, stats) = undelete_overflow(&good_records(), SIZE);
    assert_eq!(stats.recovered, 1);
    assert_eq!(got.unwrap(), stamped(&[14, 16, 18, 19], SIZE as usize));
}

/// Each malformed tree either refuses the file or yields a short prefix of
/// it: never a full-size file assembled from the wrong blocks.
fn assert_not_a_wrong_full_file(what: &str, got: Option<Vec<u8>>, stats: &RecoverStats) {
    let right = stamped(&[14, 16, 18, 19], SIZE as usize);
    match got {
        None => assert_eq!(stats.recovered, 0, "{what}: refused"),
        Some(bytes) => {
            assert!(
                bytes == right || bytes.len() < right.len(),
                "{what}: a full-size file with the wrong blocks"
            );
            assert_eq!(
                &bytes[..],
                &right[..bytes.len()],
                "{what}: not the file's own prefix"
            );
        }
    }
}

#[test]
fn overflow_records_out_of_order_do_not_scramble_the_file() {
    let mut records = good_records();
    records.reverse();
    let (got, stats) = undelete_overflow(&records, SIZE);
    assert_not_a_wrong_full_file("out of order", got, &stats);
}

#[test]
fn a_missing_middle_overflow_record_does_not_close_the_gap_with_other_blocks() {
    let records = vec![(2, vec![(18, 2)])];
    let (got, stats) = undelete_overflow(&records, SIZE);
    assert_not_a_wrong_full_file("missing middle", got, &stats);
}

#[test]
fn two_overflow_records_for_one_range_do_not_both_get_used() {
    let records = vec![(1, vec![(16, 1)]), (1, vec![(22, 1)]), (2, vec![(18, 2)])];
    let (got, stats) = undelete_overflow(&records, SIZE);
    assert_not_a_wrong_full_file("duplicate range", got, &stats);
}

#[test]
fn an_overflow_record_beyond_the_volume_is_not_read() {
    let end = common::HFS_OVERFLOW_TOTAL_BLOCKS as u32;
    let records = vec![(1, vec![(16, 1)]), (2, vec![(end - 1, 3)])];
    let (got, stats) = undelete_overflow(&records, SIZE);
    assert_not_a_wrong_full_file("beyond the volume", got, &stats);
}
