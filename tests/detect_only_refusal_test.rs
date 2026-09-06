//! `undelete` on a source whose only volume is recognised but not recoverable
//! from metadata must say so, name the filesystem, point at `scan`, exit
//! non-zero, and write nothing.

mod common;

use std::process::Command;

fn assert_refused(image: &[u8], fs_name: &str) {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("vol.img");
    std::fs::write(&img, image).unwrap();
    let out_dir = tmp.path().join("out");
    let out = Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args([
            "undelete",
            img.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "{fs_name}: detect-only undelete must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(fs_name),
        "{fs_name}: must name the filesystem: {stderr}"
    );
    assert!(
        stderr.contains("unearth scan"),
        "{fs_name}: must point at scan: {stderr}"
    );
    assert!(
        stderr.contains("info --features"),
        "{fs_name}: must point at the matrix: {stderr}"
    );
    let written: Vec<_> = std::fs::read_dir(&out_dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    assert!(written.is_empty(), "{fs_name}: wrote {written:?}");
}

#[test]
fn undelete_refuses_btrfs() {
    assert_refused(&common::btrfs_volume("photos", 1 << 30), "Btrfs");
}

#[test]
fn undelete_refuses_xfs() {
    assert_refused(&common::xfs_volume("data", 4096, 64), "XFS");
}

#[test]
fn undelete_refuses_iso9660() {
    assert_refused(&common::iso_image(50, "MY_DISC"), "ISO 9660");
}

#[test]
fn undelete_refuses_udf() {
    assert_refused(&common::udf_image(), "UDF");
}

#[test]
fn undelete_refuses_an_encrypted_container() {
    assert_refused(&common::luks_image(2), "LUKS2");
    assert_refused(&common::bitlocker_image(), "BitLocker");
}
