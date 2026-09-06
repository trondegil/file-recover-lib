//! End-to-end CLI tests: run the built `unearth` binary and check exit
//! codes, output, and side effects on the filesystem.

mod common;

use std::path::Path;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_unearth")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run unearth")
}

#[test]
fn list_types_succeeds() {
    let out = run(&["list-types"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("jpg"));
    assert!(stdout.contains("sqlite"));
    // Grouped by category.
    assert!(stdout.contains("by category"));
    assert!(stdout.contains("IMAGE"));
    assert!(stdout.contains("ARCHIVE"));
}

#[test]
fn unknown_type_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("x.img");
    std::fs::write(&img, vec![0u8; 1024]).unwrap();
    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "--type",
        "xyz",
        "-o",
        tmp.path().join("out").to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "unknown type should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown file type"), "stderr: {stderr}");
}

#[test]
fn missing_source_fails() {
    let out = run(&["scan", "/no/such/path.img", "-o", "/tmp/whatever"]);
    assert!(!out.status.success());
}

#[test]
fn image_copies_a_source_exactly() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("disk.img");
    let out_img = tmp.path().join("copy.img");
    let summary = tmp.path().join("summary.json");

    let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();

    let out = run(&[
        "image",
        src.to_str().unwrap(),
        out_img.to_str().unwrap(),
        "--no-sparse",
        "--quiet",
        "--summary",
        summary.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "image should succeed on a good source"
    );
    assert_eq!(std::fs::read(&out_img).unwrap(), data);

    let report = std::fs::read_to_string(&summary).unwrap();
    assert!(report.contains("\"command\": \"image\""));
    assert!(report.contains("\"bad_regions\": 0"));
}

#[test]
fn image_hash_records_the_image_digest() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("disk.img");
    let out_img = tmp.path().join("copy.img");
    let summary = tmp.path().join("summary.json");

    let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();

    let out = run(&[
        "image",
        src.to_str().unwrap(),
        out_img.to_str().unwrap(),
        "--no-sparse",
        "--quiet",
        "--hash",
        "--summary",
        summary.to_str().unwrap(),
    ]);
    assert!(out.status.success());

    // For a clean, full copy the image equals the source, so its digest is the
    // source's digest. It is printed and recorded in the summary.
    let expected = unearth::hash::to_hex(&unearth::hash::digest(&data));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("SHA-256: {expected}")),
        "stdout: {stdout}"
    );
    let report = std::fs::read_to_string(&summary).unwrap();
    assert!(
        report.contains(&format!("\"sha256\": \"{expected}\"")),
        "summary: {report}"
    );
}

#[test]
fn image_writes_a_map_and_resume_completes() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("disk.img");
    let out_img = tmp.path().join("copy.img");
    let map = tmp.path().join("copy.map");

    let data: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();

    // First run writes the image and a map recording it finished.
    let out = run(&[
        "image",
        src.to_str().unwrap(),
        out_img.to_str().unwrap(),
        "--no-sparse",
        "--quiet",
        "--map",
        map.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert_eq!(std::fs::read(&out_img).unwrap(), data);
    let map_text = std::fs::read_to_string(&map).unwrap();
    assert!(
        map_text.contains(&format!("pos {}", data.len())),
        "{map_text}"
    );

    // Resuming an already-complete copy is a no-op that still succeeds and leaves
    // the image intact.
    let out = run(&[
        "image",
        src.to_str().unwrap(),
        out_img.to_str().unwrap(),
        "--no-sparse",
        "--quiet",
        "--map",
        map.to_str().unwrap(),
        "--resume",
    ]);
    assert!(out.status.success());
    assert_eq!(std::fs::read(&out_img).unwrap(), data);
}

#[test]
fn image_accepts_retry_bad_and_records_it() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("disk.img");
    let out_img = tmp.path().join("copy.img");
    let summary = tmp.path().join("summary.json");

    let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();

    // A healthy source has nothing to retry, but the flag must be wired through.
    let out = run(&[
        "image",
        src.to_str().unwrap(),
        out_img.to_str().unwrap(),
        "--no-sparse",
        "--quiet",
        "--retry-bad",
        "2",
        "--summary",
        summary.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert_eq!(std::fs::read(&out_img).unwrap(), data);
    let report = std::fs::read_to_string(&summary).unwrap();
    assert!(report.contains("\"retry_bad\": 2"), "{report}");
    assert!(report.contains("\"retry_passes\": 0"), "{report}");
}

#[test]
fn image_copies_only_the_requested_range() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("disk.img");
    let out_img = tmp.path().join("slice.img");

    let data: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
    std::fs::write(&src, &data).unwrap();

    let out = run(&[
        "image",
        src.to_str().unwrap(),
        out_img.to_str().unwrap(),
        "--no-sparse",
        "--quiet",
        "--start",
        "2048",
        "--end",
        "4096",
    ]);
    assert!(out.status.success());
    assert_eq!(std::fs::read(&out_img).unwrap(), data[2048..4096]);
}

#[test]
fn info_reports_no_volume_on_garbage() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("garbage.img");
    std::fs::write(&img, vec![0u8; 4096]).unwrap();
    let out = run(&["info", img.to_str().unwrap()]);
    // `info` exits 0 even when nothing is found, printing a message.
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No supported volumes"), "stdout: {stdout}");
}

#[test]
fn scan_recovers_embedded_file() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let jpeg = common::jpeg(&vec![0x41u8; 2000]);
    let mut data = vec![0u8; 1000];
    data.extend_from_slice(&jpeg);
    data.extend_from_slice(&vec![0u8; 1000]);
    std::fs::write(&img, &data).unwrap();

    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "-q",
    ]);
    assert!(out.status.success());
    let recovered: Vec<_> = std::fs::read_dir(&out_dir).unwrap().collect();
    assert_eq!(recovered.len(), 1, "should carve one jpeg");
}

#[test]
fn scan_type_accepts_a_comma_list() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let jpeg = common::jpeg(&vec![0x41u8; 2000]);
    let mut data = vec![0u8; 1000];
    data.extend_from_slice(&jpeg);
    data.extend_from_slice(&vec![0u8; 1000]);
    std::fs::write(&img, &data).unwrap();

    // A comma-separated list (here a category plus an extension) is accepted in
    // one --type value; the "image" category covers jpg.
    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--type",
        "image,zip",
        "-q",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let recovered: Vec<_> = std::fs::read_dir(&out_dir).unwrap().collect();
    assert_eq!(
        recovered.len(),
        1,
        "the jpeg is carved via the image category"
    );
}

#[test]
fn scan_exclude_drops_a_type() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");

    let jpeg = common::jpeg(&vec![0x41u8; 1500]);
    let mut data = vec![0u8; 500];
    data.extend_from_slice(&jpeg);
    data.extend_from_slice(&vec![0u8; 500]);
    std::fs::write(&img, &data).unwrap();

    // Without exclusion, scanning the image category recovers the jpeg.
    let out_kept = tmp.path().join("kept");
    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_kept.to_str().unwrap(),
        "--type",
        "image",
        "-q",
    ]);
    assert!(out.status.success());
    assert_eq!(std::fs::read_dir(&out_kept).unwrap().count(), 1);

    // Excluding jpg from the image category leaves nothing to recover here.
    let out_excl = tmp.path().join("excl");
    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_excl.to_str().unwrap(),
        "--type",
        "image",
        "--exclude",
        "jpg",
        "-q",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let n = std::fs::read_dir(&out_excl).map(|d| d.count()).unwrap_or(0);
    assert_eq!(n, 0, "jpg excluded, nothing recovered");
}

#[test]
fn scan_organize_groups_files_by_type() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let report = tmp.path().join("manifest.csv");

    let jpeg = common::jpeg(&vec![0x41u8; 2000]);
    let mut data = vec![0u8; 1000];
    data.extend_from_slice(&jpeg);
    std::fs::write(&img, &data).unwrap();

    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--organize",
        "--report",
        report.to_str().unwrap(),
        "-q",
    ]);
    assert!(out.status.success());

    // The carved JPEG lands in a `jpg/` subdirectory, not the flat output dir.
    let jpg_dir = out_dir.join("jpg");
    assert!(jpg_dir.is_dir(), "expected a jpg/ subdirectory");
    let in_jpg: Vec<_> = std::fs::read_dir(&jpg_dir).unwrap().collect();
    assert_eq!(in_jpg.len(), 1);
    let carved = std::fs::read(in_jpg[0].as_ref().unwrap().path()).unwrap();
    assert_eq!(carved, jpeg);

    // The manifest records the `jpg/` prefix so `verify` can resolve it.
    let manifest = std::fs::read_to_string(&report).unwrap();
    assert!(manifest.contains("jpg/"), "manifest: {manifest}");
}

#[test]
fn recover_runs_undelete_then_dedup_carve() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    // An ext volume with a deleted JPEG (recoverable by name; kept within one
    // 1 KiB block so the test helper's single-extent inode restores it intact),
    // plus a *different* JPEG planted in the slack after it (only by carving).
    let jpeg_named = common::jpeg(&vec![0x41u8; 800]);
    let jpeg_carved = common::jpeg(&vec![0x42u8; 1500]);
    let mut img = common::ext_volume("photo.jpg", &jpeg_named);
    img.extend_from_slice(&vec![0u8; 500]);
    img.extend_from_slice(&jpeg_carved);
    img.extend_from_slice(&vec![0u8; 500]);
    std::fs::write(&img_path, &img).unwrap();
    let report = tmp.path().join("manifest.csv");

    let out = run(&[
        "recover",
        img_path.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "-q",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Undelete restored the named JPEG under named/.
    assert_eq!(
        std::fs::read(out_dir.join("named").join("photo.jpg")).unwrap(),
        jpeg_named
    );

    // Carving added only the planted JPEG: the named one is deduped away because
    // undelete already recovered that exact content.
    let carved: Vec<Vec<u8>> = std::fs::read_dir(out_dir.join("carved"))
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(carved.len(), 1, "only the slack JPEG should be carved");
    assert_eq!(carved[0], jpeg_carved);

    // The combined manifest lists both passes and is verifiable against the
    // output directory.
    let manifest = std::fs::read_to_string(&report).unwrap();
    assert!(manifest.contains("named/photo.jpg"), "{manifest}");
    assert!(manifest.contains("carved/"), "{manifest}");
    let verify = run(&[
        "verify",
        report.to_str().unwrap(),
        "--base",
        out_dir.to_str().unwrap(),
    ]);
    assert!(
        verify.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verify.stdout)
    );
}

#[test]
fn recover_dry_run_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let jpeg_named = common::jpeg(&vec![0x41u8; 800]);
    let jpeg_carved = common::jpeg(&vec![0x42u8; 1500]);
    let mut img = common::ext_volume("photo.jpg", &jpeg_named);
    img.extend_from_slice(&vec![0u8; 500]);
    img.extend_from_slice(&jpeg_carved);
    img.extend_from_slice(&vec![0u8; 500]);
    std::fs::write(&img_path, &img).unwrap();

    let out = run(&[
        "recover",
        img_path.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--dry-run",
        "-q",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The preview reports what would be recovered...
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Dry run"), "{stdout}");
    // ...but nothing is written: no output tree at all.
    assert!(
        !out_dir.exists() || std::fs::read_dir(&out_dir).unwrap().next().is_none(),
        "dry run must not write any files"
    );
}

#[test]
fn recover_unallocated_skips_live_clusters() {
    // Geometry of common::fat32_volume: 512-byte sectors, 32 reserved + 512 FAT
    // sectors, so the data region starts at sector 544 and the FAT at byte 16384.
    const BPS: usize = 512;
    const FIRST_DATA: usize = 544;
    const FAT_BASE: usize = 32 * BPS;
    let cluster_off = |c: usize| (FIRST_DATA + (c - 2)) * BPS;

    let jpeg_free = common::jpeg(&vec![0x41u8; 400]); // lives in free cluster 3
    let jpeg_alloc = common::jpeg(&vec![0x42u8; 400]); // lives in allocated cluster 4

    // The builder plants jpeg_free in cluster 3 (left free in the FAT).
    let mut img = common::fat32_volume(b"PHOTO   ", b"JPG", &jpeg_free);
    // Remove the deleted directory entry, so undelete finds nothing and the only
    // way to recover jpeg_free is by carving cluster 3 (which is unallocated).
    let root = cluster_off(2);
    for b in &mut img[root..root + 32] {
        *b = 0;
    }
    // Mark cluster 4 allocated (EOC) and put a *live* JPEG there; --unallocated
    // must skip it.
    let fat4 = FAT_BASE + 4 * 4;
    img[fat4..fat4 + 4].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    let c4 = cluster_off(4);
    img[c4..c4 + jpeg_alloc.len()].copy_from_slice(&jpeg_alloc);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    std::fs::write(&img_path, &img).unwrap();

    let out = run(&[
        "recover",
        img_path.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--unallocated",
        "-q",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Only the free-cluster JPEG is carved; the allocated one is skipped.
    let carved: Vec<Vec<u8>> = std::fs::read_dir(out_dir.join("carved"))
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(
        carved.len(),
        1,
        "only the unallocated JPEG should be carved"
    );
    assert_eq!(carved[0], jpeg_free);
    assert!(
        !carved.contains(&jpeg_alloc),
        "the live cluster must be skipped"
    );
}

#[test]
fn scan_unallocated_skips_live_clusters() {
    // Same FAT32 geometry as recover_unallocated_skips_live_clusters: a JPEG in
    // free cluster 3 should be carved; a live JPEG in allocated cluster 4 skipped.
    const BPS: usize = 512;
    const FIRST_DATA: usize = 544;
    const FAT_BASE: usize = 32 * BPS;
    let cluster_off = |c: usize| (FIRST_DATA + (c - 2)) * BPS;

    let jpeg_free = common::jpeg(&vec![0x41u8; 400]);
    let jpeg_alloc = common::jpeg(&vec![0x42u8; 400]);

    let mut img = common::fat32_volume(b"PHOTO   ", b"JPG", &jpeg_free);
    let root = cluster_off(2);
    for b in &mut img[root..root + 32] {
        *b = 0;
    }
    let fat4 = FAT_BASE + 4 * 4;
    img[fat4..fat4 + 4].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    let c4 = cluster_off(4);
    img[c4..c4 + jpeg_alloc.len()].copy_from_slice(&jpeg_alloc);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    std::fs::write(&img_path, &img).unwrap();

    let out = run(&[
        "scan",
        img_path.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--unallocated",
        "-q",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let carved: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(
        carved.len(),
        1,
        "only the unallocated JPEG should be carved"
    );
    assert_eq!(carved[0], jpeg_free);
    assert!(!carved.contains(&jpeg_alloc));
}

#[test]
fn scan_unallocated_rejects_resume() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::write(&img, common::fat32_volume(b"PHOTO   ", b"JPG", b"x")).unwrap();
    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        tmp.path().join("out").to_str().unwrap(),
        "--unallocated",
        "--resume",
        "-q",
    ]);
    assert!(!out.status.success(), "should reject the flag combination");
}

#[test]
fn undelete_dry_run_with_report_writes_no_files() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("ext.img");
    let out_dir = tmp.path().join("out");
    let report = tmp.path().join("report.csv");

    std::fs::write(&img, common::ext_volume("notes.txt", b"hello world")).unwrap();

    let out = run(&[
        "undelete",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--dry-run",
        "--report",
        report.to_str().unwrap(),
    ]);
    assert!(out.status.success());

    // Dry run writes a report but no recovered files / output dir.
    assert!(
        !Path::new(&out_dir).exists(),
        "dry run must not create output"
    );
    let csv = std::fs::read_to_string(&report).unwrap();
    assert!(csv.contains("filesystem,volume_offset,path,size,recovered"));
    assert!(csv.contains("notes.txt"));
}

#[test]
fn scan_report_manifest_carries_matching_sha256() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let report = tmp.path().join("carved.json");

    let jpeg = common::jpeg(&vec![0x41u8; 2000]);
    let mut data = vec![0u8; 1000];
    data.extend_from_slice(&jpeg);
    std::fs::write(&img, &data).unwrap();

    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "-q",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Exactly one file is carved; its digest in the manifest must match a fresh
    // hash of the bytes on disk, and the manifest must name its type and offset.
    let entries: Vec<_> = std::fs::read_dir(&out_dir).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let carved = std::fs::read(entries[0].as_ref().unwrap().path()).unwrap();
    assert_eq!(carved, jpeg, "carved bytes match the planted JPEG");
    let expected = unearth::hash::to_hex(&unearth::hash::digest(&carved));

    let json = std::fs::read_to_string(&report).unwrap();
    assert!(
        json.contains(&format!("\"sha256\": \"{expected}\"")),
        "manifest missing digest {expected}: {json}"
    );
    assert!(json.contains("\"type\": \"jpg\""), "manifest: {json}");
    // The JPEG starts 1000 bytes into the image.
    assert!(json.contains("\"offset\": 1000"), "manifest: {json}");
}

#[test]
fn report_manifest_carries_matching_sha256() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let report = tmp.path().join("manifest.json");

    let content = b"hash me for the recovery manifest";
    std::fs::write(&img, common::ext_volume("notes.txt", content)).unwrap();

    let out = run(&[
        "undelete",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The digest in the report must match a fresh hash of the recovered file.
    let recovered = std::fs::read(out_dir.join("notes.txt")).unwrap();
    assert_eq!(recovered, content);
    let expected = unearth::hash::to_hex(&unearth::hash::digest(&recovered));

    let json = std::fs::read_to_string(&report).unwrap();
    assert!(
        json.contains(&format!("\"sha256\": \"{expected}\"")),
        "report missing expected digest {expected}: {json}"
    );
}

#[test]
fn info_json_lists_volumes() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::write(&img, common::ext_volume("notes.txt", b"hello world")).unwrap();

    // Without --deleted: the count is null.
    let out = run(&["info", img.to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"filesystem\": \"ext2/3/4\""), "{json}");
    assert!(json.contains("\"deleted\": null"), "{json}");
    assert!(json.contains("\"volumes\""), "{json}");

    // With --deleted: the recoverable count is reported.
    let out = run(&["info", img.to_str().unwrap(), "--json", "--deleted"]);
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"deleted\": 1"), "{json}");
}

#[test]
fn info_json_on_garbage_has_empty_volumes() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::write(&img, vec![0u8; 4096]).unwrap();

    let out = run(&["info", img.to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"volumes\": []"), "{json}");
}

#[test]
fn completions_emit_a_script() {
    let out = run(&["completions", "bash"]);
    assert!(out.status.success());
    let script = String::from_utf8_lossy(&out.stdout);
    // The bash completion script references the binary name and registers it.
    assert!(script.contains("unearth"), "{script}");
    assert!(script.contains("complete "), "{script}");

    // An invalid shell is rejected.
    assert!(!run(&["completions", "not-a-shell"]).status.success());
}

#[test]
fn identify_detects_type_by_content() {
    let tmp = tempfile::tempdir().unwrap();
    // A JPEG given a misleading .bin extension.
    let jpeg = common::jpeg(&[0x41u8; 100]);
    let f = tmp.path().join("mystery.bin");
    std::fs::write(&f, &jpeg).unwrap();

    let out = run(&["identify", f.to_str().unwrap()]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("jpg"), "{text}");

    let out = run(&["identify", f.to_str().unwrap(), "--json"]);
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"identified\":true"), "{json}");
    assert!(json.contains("\"type\":\"jpg\""), "{json}");
    assert!(json.contains("\"category\":\"image\""), "{json}");
    assert!(json.contains("\"validated\":true"), "{json}");

    // Unknown content is reported as such.
    let g = tmp.path().join("blob.bin");
    std::fs::write(&g, b"not a known file type at all").unwrap();
    let out = run(&["identify", g.to_str().unwrap(), "--json"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"identified\":false"));
}

#[test]
fn identify_handles_multiple_files() {
    let tmp = tempfile::tempdir().unwrap();
    let jpg = tmp.path().join("a.bin");
    std::fs::write(&jpg, common::jpeg(&[0x41u8; 50])).unwrap();
    let unknown = tmp.path().join("b.bin");
    std::fs::write(&unknown, b"plain text, no signature").unwrap();

    // Text: one line per file, each prefixed with its path.
    let out = run(&["identify", jpg.to_str().unwrap(), unknown.to_str().unwrap()]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("a.bin"), "{text}");
    assert!(text.contains("jpg"), "{text}");
    assert!(text.contains("b.bin: unknown"), "{text}");

    // JSON: an array with one object per file.
    let out = run(&[
        "identify",
        "--json",
        jpg.to_str().unwrap(),
        unknown.to_str().unwrap(),
    ]);
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.trim_start().starts_with('['), "array output: {json}");
    assert!(json.contains("\"type\":\"jpg\""), "{json}");
    assert!(json.contains("\"identified\":false"), "{json}");
}

#[test]
fn triage_summarizes_a_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("rec");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("a.jpg"), vec![1u8; 100]).unwrap();
    std::fs::write(dir.join("b.jpg"), vec![1u8; 100]).unwrap(); // duplicate of a.jpg
    std::fs::write(dir.join("c.png"), vec![9u8; 30]).unwrap();

    // Human output mentions the counts and the duplicate set.
    let out = run(&["triage", dir.to_str().unwrap()]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("3 file(s)"), "{text}");
    assert!(text.contains("duplicate set"), "{text}");

    // JSON output is machine-readable.
    let out = run(&["triage", dir.to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"total_files\":3"), "{json}");
    assert!(json.contains("\"duplicate_sets\":1"), "{json}");
    assert!(json.contains("\"jpg\""), "{json}");
    // The mismatch/corrupt arrays are always present; these files have no valid
    // JPEG/PNG magic, so they show up under "corrupt".
    assert!(json.contains("\"corrupt\""), "{json}");
}

#[test]
fn scan_writes_run_summary() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let summary = tmp.path().join("summary.json");

    let jpeg = common::jpeg(&vec![0x41u8; 2500]);
    let mut data = vec![0u8; 800];
    data.extend_from_slice(&jpeg);
    std::fs::write(&img, &data).unwrap();

    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--summary",
        summary.to_str().unwrap(),
        "-q",
    ]);
    assert!(out.status.success());

    let json = std::fs::read_to_string(&summary).unwrap();
    assert!(json.contains("\"command\": \"scan\""), "{json}");
    assert!(json.contains("\"files_recovered\": 1"), "{json}");
    assert!(json.contains("\"per_type\""), "{json}");
    assert!(json.contains("\"jpg\": 1"), "{json}");
    assert!(json.contains("\"timestamp_unix\""), "{json}");
}

#[test]
fn verify_detects_intact_and_tampered_files() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let report = tmp.path().join("carved.csv");

    let jpeg = common::jpeg(&vec![0x42u8; 3000]);
    let mut data = vec![0u8; 500];
    data.extend_from_slice(&jpeg);
    std::fs::write(&img, &data).unwrap();

    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "-q",
    ]);
    assert!(out.status.success());

    // A fresh recovery verifies clean.
    let out = run(&[
        "verify",
        report.to_str().unwrap(),
        "--base",
        out_dir.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "verify should pass on intact files: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 OK"));

    // Tamper with the recovered file; verify must now fail and flag it.
    let carved = std::fs::read_dir(&out_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(&carved, b"corrupted contents").unwrap();

    let out = run(&[
        "verify",
        report.to_str().unwrap(),
        "--base",
        out_dir.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "verify must fail on a tampered file");
    assert!(String::from_utf8_lossy(&out.stdout).contains("MISMATCH"));
}

#[test]
fn undelete_offset_override_recovers() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    // Place an ext volume 1 MiB into the image; auto-detect won't find it, but
    // an explicit --offset will.
    let vol = common::ext_volume("data.bin", b"recover me via offset");
    let off = 1024 * 1024usize;
    let mut disk = vec![0u8; off + vol.len()];
    disk[off..off + vol.len()].copy_from_slice(&vol);
    std::fs::write(&img, &disk).unwrap();

    let out = run(&[
        "undelete",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--offset",
        &off.to_string(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(out_dir.join("data.bin")).unwrap(),
        b"recover me via offset"
    );
}

// --- The source is never a destination ---------------------------------

/// Every file argument a command writes, run with `dest` as its value.
fn writing_commands<'a>(
    src: &'a str,
    out: &'a str,
    copy: &'a str,
    dest: &'a str,
) -> Vec<Vec<&'a str>> {
    vec![
        vec!["image", src, dest, "--quiet"],
        vec!["image", src, copy, "--map", dest, "--quiet"],
        vec!["image", src, copy, "--summary", dest, "--quiet"],
        vec!["scan", src, "-o", out, "--report", dest],
        vec!["scan", src, "-o", out, "--checkpoint", dest],
        vec!["scan", src, "-o", out, "--summary", dest],
        vec!["undelete", src, "-o", out, "--report", dest],
        vec!["recover", src, "-o", out, "--report", dest],
    ]
}

/// An image whose contents a scan would write out (one JPEG), so a run that
/// got as far as writing would leave a trace.
fn source_image() -> Vec<u8> {
    let mut data = vec![0u8; 4096];
    data.extend_from_slice(&common::jpeg(&vec![0x5Au8; 3000]));
    data.resize(16384, 0);
    data
}

fn assert_refused_without_writing(args: &[&str], src: &Path, data: &[u8], out: &Path, copy: &Path) {
    let res = run(args);
    assert!(
        !res.status.success(),
        "{args:?} must fail: stderr {}",
        String::from_utf8_lossy(&res.stderr)
    );
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(
        stderr.contains("source") && stderr.contains("refusing"),
        "{args:?} must say why: {stderr}"
    );
    assert_eq!(
        std::fs::read(src).unwrap(),
        data,
        "{args:?} changed the source"
    );
    assert!(!out.exists(), "{args:?} wrote output before refusing");
    assert!(!copy.exists(), "{args:?} wrote the image before refusing");
}

/// Naming the source itself as the thing to write, directly or via a
/// relative spelling of the same path, is refused before anything is written.
#[test]
fn the_source_path_itself_is_refused_as_a_destination() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("disk.img");
    let data = source_image();
    std::fs::write(&src, &data).unwrap();
    let out = tmp.path().join("out");
    let copy = tmp.path().join("copy.img");
    let (s, o, c) = (
        src.to_str().unwrap(),
        out.to_str().unwrap(),
        copy.to_str().unwrap(),
    );

    for args in writing_commands(s, o, c, s) {
        assert_refused_without_writing(&args, &src, &data, &out, &copy);
    }
    // The same file spelled relative to the working directory.
    for args in writing_commands(s, o, c, "disk.img") {
        let res = Command::new(bin())
            .current_dir(tmp.path())
            .args(&args)
            .output()
            .unwrap();
        assert!(!res.status.success(), "{args:?} (relative alias) must fail");
        assert_eq!(
            std::fs::read(&src).unwrap(),
            data,
            "{args:?} changed the source"
        );
        assert!(
            !out.exists() && !copy.exists(),
            "{args:?} wrote before refusing"
        );
    }
}

/// A hard link or symlink to the source is the source: writing to it would
/// truncate the very bytes being read.
#[cfg(unix)]
#[test]
fn an_alias_of_the_source_is_refused_as_a_destination() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("disk.img");
    let data = source_image();
    std::fs::write(&src, &data).unwrap();
    let hard = tmp.path().join("hard.img");
    let sym = tmp.path().join("sym.img");
    std::fs::hard_link(&src, &hard).unwrap();
    std::os::unix::fs::symlink(&src, &sym).unwrap();
    let out = tmp.path().join("out");
    let copy = tmp.path().join("copy.img");
    let (s, o, c) = (
        src.to_str().unwrap(),
        out.to_str().unwrap(),
        copy.to_str().unwrap(),
    );

    for alias in [&hard, &sym] {
        for args in writing_commands(s, o, c, alias.to_str().unwrap()) {
            assert_refused_without_writing(&args, &src, &data, &out, &copy);
        }
    }
    // And the other way round: reading through the alias, writing the original.
    for alias in [&hard, &sym] {
        for args in writing_commands(alias.to_str().unwrap(), o, c, s) {
            assert_refused_without_writing(&args, &src, &data, &out, &copy);
        }
    }
}

// --- Option interactions ------------------------------------------------------

fn manifest_rows(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .skip(1)
        .map(str::to_string)
        .collect()
}

/// `--resume` after a run stopped by `--max-files`, with `--dedup` and
/// `--report`: the duplicate is dropped, and the manifest rows name exactly
/// the files that exist.
#[test]
fn resume_with_dedup_and_report_completes_the_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let checkpoint = tmp.path().join("scan.checkpoint");
    let report = tmp.path().join("manifest.csv");

    let a = common::jpeg(&vec![0x41u8; 1500]);
    let b = common::jpeg(&vec![0x42u8; 1800]);
    let mut data = vec![0u8; 1024];
    for j in [&a, &a, &b] {
        data.extend_from_slice(j);
        data.extend_from_slice(&[0u8; 1024]);
    }
    std::fs::write(&img, &data).unwrap();

    // First run stops after one file and leaves a checkpoint.
    let first = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--checkpoint",
        checkpoint.to_str().unwrap(),
        "--max-files",
        "1",
        "--dedup",
        "-q",
    ]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(std::fs::read_dir(&out_dir).unwrap().count(), 1);

    let second = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--checkpoint",
        checkpoint.to_str().unwrap(),
        "--resume",
        "--dedup",
        "--report",
        report.to_str().unwrap(),
        "-q",
    ]);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let mut files: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    files.sort();
    let mut want = vec![a.clone(), b.clone()];
    want.sort();
    assert_eq!(
        files, want,
        "the duplicate of `a` was dropped across the resume"
    );
    let rows = manifest_rows(&report);
    assert_eq!(rows.len(), 2, "{rows:?}");
    for row in &rows {
        let name = row.split(',').next().unwrap();
        assert!(
            out_dir.join(name).exists(),
            "manifest names a missing file: {row}"
        );
    }
}

/// `--dry-run` with `--name` and `--modified-after` reports exactly what the
/// same filters write in a real run.
#[test]
fn dry_run_with_name_and_time_filters_reports_what_a_real_run_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("ext.img");
    let mut vol = common::ext_volume_multi(&[
        ("old.txt", b"too old"),
        ("new.txt", b"new and matching"),
        ("new.log", b"new but not matching"),
    ]);
    // Inodes 11..13 sit in the inode table at block 5; mtime is at 0x10.
    // `old.txt` is from 1990, the two `new.*` files from 2023. (An mtime of
    // zero would count as unknown and pass every time filter.)
    for (ino, mtime) in [
        (11u32, 631_152_000u32),
        (12, 1_700_000_000),
        (13, 1_700_000_000),
    ] {
        let o = 5 * 1024 + (ino as usize - 1) * 128 + 0x10;
        vol[o..o + 4].copy_from_slice(&mtime.to_le_bytes());
    }
    std::fs::write(&img, &vol).unwrap();

    let dry_report = tmp.path().join("dry.csv");
    let dry = run(&[
        "undelete",
        img.to_str().unwrap(),
        "-o",
        tmp.path().join("dry_out").to_str().unwrap(),
        "--dry-run",
        "--name",
        "*.txt",
        "--modified-after",
        "2000-01-01",
        "--report",
        dry_report.to_str().unwrap(),
    ]);
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    assert!(!tmp.path().join("dry_out").exists());

    let real_out = tmp.path().join("real_out");
    let real_report = tmp.path().join("real.csv");
    let real = run(&[
        "undelete",
        img.to_str().unwrap(),
        "-o",
        real_out.to_str().unwrap(),
        "--name",
        "*.txt",
        "--modified-after",
        "2000-01-01",
        "--report",
        real_report.to_str().unwrap(),
    ]);
    assert!(
        real.status.success(),
        "{}",
        String::from_utf8_lossy(&real.stderr)
    );

    let written: Vec<String> = std::fs::read_dir(&real_out)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(written, vec!["new.txt".to_string()]);
    assert_eq!(
        std::fs::read(real_out.join("new.txt")).unwrap(),
        b"new and matching"
    );

    let dry_rows = manifest_rows(&dry_report);
    let real_rows = manifest_rows(&real_report);
    assert_eq!(dry_rows.len(), 1, "{dry_rows:?}");
    assert_eq!(real_rows.len(), 1, "{real_rows:?}");
    // Same path and size; the real row carries the digest the dry one lacks.
    let strip = |r: &str| r.rsplit_once(',').map(|(a, _)| a.to_string()).unwrap();
    assert_eq!(strip(&dry_rows[0]), strip(&real_rows[0]));
    assert!(dry_rows[0].contains("new.txt"));
    let dry_stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(dry_stdout.contains("Would recover 1 "), "{dry_stdout}");
}

/// `--organize` with two files that would take one name: carved names are
/// counter-prefixed, so both land in the type folder under distinct names,
/// and the manifest resolves to both.
#[test]
fn organize_keeps_two_same_type_files_apart() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");
    let report = tmp.path().join("manifest.csv");
    let a = common::jpeg(&vec![0x51u8; 1200]);
    let b = common::jpeg(&vec![0x52u8; 1300]);
    let mut data = vec![0u8; 512];
    data.extend_from_slice(&a);
    data.extend_from_slice(&[0u8; 512]);
    data.extend_from_slice(&b);
    std::fs::write(&img, &data).unwrap();

    let out = run(&[
        "scan",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--organize",
        "--report",
        report.to_str().unwrap(),
        "-q",
    ]);
    assert!(out.status.success());
    let jpg_dir = out_dir.join("jpg");
    let mut names: Vec<String> = std::fs::read_dir(&jpg_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2);
    assert_ne!(names[0], names[1]);
    let mut files: Vec<Vec<u8>> = names
        .iter()
        .map(|n| std::fs::read(jpg_dir.join(n)).unwrap())
        .collect();
    files.sort();
    let mut want = vec![a, b];
    want.sort();
    assert_eq!(files, want);
    let rows = manifest_rows(&report);
    assert_eq!(rows.len(), 2);
    for row in &rows {
        let name = row.split(',').next().unwrap();
        assert!(name.starts_with("jpg/"), "{row}");
        assert!(out_dir.join(name).exists(), "{row}");
    }
}

/// `--unallocated` with `--volume N` on a two-volume disk: only the chosen
/// volume's free space is carved, and only its file is undeleted.
#[test]
fn unallocated_with_volume_selects_one_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    // Two FAT32 volumes on an MBR disk. Each holds a deleted file in cluster 3
    // (free), and a JPEG planted in free cluster 5 for carving.
    const BPS: usize = 512;
    const FIRST_DATA: usize = 544;
    let cluster_off = |c: usize| (FIRST_DATA + (c - 2)) * BPS;
    let jpeg0 = common::jpeg(&vec![0x61u8; 700]);
    let jpeg1 = common::jpeg(&vec![0x62u8; 800]);
    let mut v0 = common::fat32_volume(b"ONE     ", b"TXT", b"file on volume one");
    let mut v1 = common::fat32_volume(b"TWO     ", b"TXT", b"file on volume two");
    let c5 = cluster_off(5);
    v0[c5..c5 + jpeg0.len()].copy_from_slice(&jpeg0);
    v1[c5..c5 + jpeg1.len()].copy_from_slice(&jpeg1);
    let lba0 = 64usize;
    let lba1 = lba0 + v0.len() / BPS + 64;
    let mut disk = vec![0u8; lba1 * BPS + v1.len()];
    disk[lba0 * BPS..lba0 * BPS + v0.len()].copy_from_slice(&v0);
    disk[lba1 * BPS..lba1 * BPS + v1.len()].copy_from_slice(&v1);
    disk[510] = 0x55;
    disk[511] = 0xAA;
    for (i, lba) in [lba0, lba1].iter().enumerate() {
        let p = 446 + i * 16;
        disk[p + 4] = 0x0C;
        disk[p + 8..p + 12].copy_from_slice(&(*lba as u32).to_le_bytes());
        disk[p + 12..p + 16].copy_from_slice(&((v0.len() / BPS) as u32).to_le_bytes());
    }
    std::fs::write(&img, &disk).unwrap();

    let out = run(&[
        "recover",
        img.to_str().unwrap(),
        "-o",
        out_dir.to_str().unwrap(),
        "--unallocated",
        "--volume",
        "1",
        "-q",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let named: Vec<Vec<u8>> = walk_files(&out_dir.join("named"));
    assert_eq!(
        named,
        vec![b"file on volume two".to_vec()],
        "only volume 1's file"
    );
    let carved: Vec<Vec<u8>> = walk_files(&out_dir.join("carved"));
    assert_eq!(carved, vec![jpeg1], "only volume 1's free space");
}

fn walk_files(dir: &Path) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(std::fs::read(p).unwrap());
            }
        }
    }
    out.sort();
    out
}
