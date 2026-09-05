//! APFS is recognised by `detect`/`info` (and surfaced to the user), but it is
//! not recovered from metadata — `undelete` finds nothing and carving is the
//! fallback.

use std::process::Command;

use unearth::recover::{self, RecoverOptions};
use unearth::source::Source;

/// A minimal APFS container superblock (`nx_superblock_t`).
fn apfs_container(block_size: u32, block_count: u64) -> Vec<u8> {
    let total = block_size as usize * block_count as usize;
    let mut v = vec![0u8; total.max(4096)];
    v[24..28].copy_from_slice(&0x0001u32.to_le_bytes()); // o_type = NX_SUPERBLOCK
    v[32..36].copy_from_slice(b"NXSB"); // nx_magic
    v[36..40].copy_from_slice(&block_size.to_le_bytes());
    v[40..48].copy_from_slice(&block_count.to_le_bytes());
    v
}

/// A fuller APFS container whose object map resolves each named volume: a
/// container superblock (block 0) → object map (block 1) → its B-tree root
/// (block 2) → one volume superblock per name (blocks 3, 4, ...).
fn apfs_container_with_volumes(names: &[&str]) -> Vec<u8> {
    const BS: usize = 4096;
    let block_count = 3 + names.len();
    let mut v = vec![0u8; block_count * BS];
    let put32 = |v: &mut [u8], o: usize, x: u32| v[o..o + 4].copy_from_slice(&x.to_le_bytes());
    let put64 = |v: &mut [u8], o: usize, x: u64| v[o..o + 8].copy_from_slice(&x.to_le_bytes());
    let put16 = |v: &mut [u8], o: usize, x: u16| v[o..o + 2].copy_from_slice(&x.to_le_bytes());

    // Block 0: container superblock.
    put32(&mut v, 24, 0x0001); // o_type = NX_SUPERBLOCK
    v[32..36].copy_from_slice(b"NXSB");
    put32(&mut v, 36, BS as u32);
    put64(&mut v, 40, block_count as u64);
    put64(&mut v, 160, 1); // nx_omap_oid -> block 1
    put32(&mut v, 180, names.len() as u32); // nx_max_file_systems
    for i in 0..names.len() {
        put64(&mut v, 184 + i * 8, 1024 + i as u64); // nx_fs_oid[i] (virtual)
    }

    // Block 1: object map (omap_phys_t) -> B-tree root at block 2.
    put64(&mut v, BS + 48, 2); // om_tree_oid

    // Block 2: B-tree root+leaf node mapping each virtual fs OID to a paddr.
    let nb = 2 * BS;
    put16(&mut v, nb + 32, 0x0007); // btn_flags = ROOT | LEAF | FIXED_KV_SIZE
    put16(&mut v, nb + 34, 0); // btn_level = 0
    put32(&mut v, nb + 36, names.len() as u32); // btn_nkeys
    put16(&mut v, nb + 40, 0); // btn_table_space.off
    put16(&mut v, nb + 42, (names.len() * 4) as u16); // btn_table_space.len
    let toc = nb + 56;
    let key_base = nb + 56 + names.len() * 4;
    let val_area_end = BS - 40; // root node: minus btree_info trailer
    for i in 0..names.len() {
        let k = (i * 16) as u16;
        let v_off = ((i + 1) * 16) as u16; // value back-offset from val_area_end
        put16(&mut v, toc + i * 4, k);
        put16(&mut v, toc + i * 4 + 2, v_off);
        // omap_key { ok_oid, ok_xid }
        put64(&mut v, key_base + i * 16, 1024 + i as u64);
        put64(&mut v, key_base + i * 16 + 8, 1);
        // omap_val { ov_flags, ov_size, ov_paddr } at val_area_end - v_off
        let val_pos = nb + val_area_end - v_off as usize;
        put32(&mut v, val_pos, 0);
        put32(&mut v, val_pos + 4, BS as u32);
        put64(&mut v, val_pos + 8, (3 + i) as u64); // paddr -> block 3 + i
    }

    // Blocks 3..: one volume superblock per name.
    for (i, name) in names.iter().enumerate() {
        let vb = (3 + i) * BS;
        v[vb + 32..vb + 36].copy_from_slice(b"APSB");
        let bytes = name.as_bytes();
        v[vb + 704..vb + 704 + bytes.len()].copy_from_slice(bytes);
    }
    v
}

#[test]
fn enumerates_volume_names_via_the_object_map() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("c.img");
    let names = ["Macintosh HD", "Macintosh HD - Data", "Preboot"];
    std::fs::write(&img, apfs_container_with_volumes(&names)).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "APFS");
    assert_eq!(vols[0].contained_volumes(), names);
}

#[test]
fn info_cli_shows_contained_apfs_volumes() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("c.img");
    std::fs::write(
        &img,
        apfs_container_with_volumes(&["Macintosh HD", "Recovery"]),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args(["info", img.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Macintosh HD"), "stdout: {stdout}");
    assert!(stdout.contains("Recovery"), "stdout: {stdout}");
}

#[test]
fn detect_reports_apfs_but_recovers_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("c.img");
    std::fs::write(&img, apfs_container(4096, 8)).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "APFS");
    assert_eq!(vols[0].size(), 4096 * 8);

    // Recognised, but metadata undelete yields nothing (no error, no files).
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 0);
}

#[test]
fn info_cli_lists_an_apfs_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("c.img");
    std::fs::write(&img, apfs_container(4096, 8)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args(["info", img.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("APFS"), "stdout: {stdout}");
}

/// `undelete` on a source whose only volume is detect-only must say so and
/// exit non-zero: "0 files, exit 0" would read as "nothing to recover".
#[test]
fn undelete_cli_refuses_a_detect_only_volume_with_a_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("c.img");
    std::fs::write(&img, apfs_container(4096, 8)).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args([
            "undelete",
            img.to_str().unwrap(),
            "-o",
            tmp.path().join("out").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "detect-only undelete must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unearth scan"),
        "must point at scan: {stderr}"
    );
    assert!(
        stderr.contains("info --features"),
        "must point at the matrix: {stderr}"
    );
}
