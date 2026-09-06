//! UDF (optical/USB media) is recognised by `detect`/`info` and surfaced to the
//! user, but it is not recovered from metadata — `undelete` finds nothing and
//! carving is the fallback.

mod common;

use std::process::Command;

use unearth::recover::{self, RecoverOptions};
use unearth::source::Source;

#[test]
fn detect_reports_udf_but_recovers_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disc.img");
    let data = common::udf_image();
    std::fs::write(&img, &data).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "UDF");
    assert_eq!(vols[0].size(), data.len() as u64);

    // Recognised, but metadata undelete yields nothing (no error, no files).
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 0);
}

#[test]
fn info_cli_lists_a_udf_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disc.img");
    std::fs::write(&img, common::udf_image()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args(["info", img.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("UDF"), "stdout: {stdout}");
}
