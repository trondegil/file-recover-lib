//! ISO 9660 (data CD/DVD discs and `.iso` images) is recognised by
//! `detect`/`info` — with its size and volume label — and its files are
//! extracted with their names and folder paths (see the unit tests in
//! `src/iso9660.rs` for the directory-walk extraction itself).

mod common;

use std::process::Command;

use unearth::recover::{self, RecoverOptions};
use unearth::source::Source;

#[test]
fn detect_reports_iso9660_with_size_and_label() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disc.iso");
    std::fs::write(&img, common::iso_image(50, "MY_DISC")).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "ISO 9660");
    assert_eq!(vols[0].size(), 50 * 2048);
    assert_eq!(vols[0].volume_label().as_deref(), Some("MY_DISC"));
    // 2021-01-01 12:00:00 UTC = 18628 days + 12 h.
    assert_eq!(vols[0].created_time(), Some(18628 * 86400 + 12 * 3600));

    // This image has no root directory tree, so there is nothing to extract.
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 0);
}

#[test]
fn info_cli_lists_an_iso9660_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disc.iso");
    std::fs::write(&img, common::iso_image(50, "MY_DISC")).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args(["info", img.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ISO 9660"), "stdout: {stdout}");
    assert!(stdout.contains("MY_DISC"), "stdout: {stdout}");
}
