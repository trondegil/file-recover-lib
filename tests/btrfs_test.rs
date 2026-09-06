//! Btrfs is recognised by `detect`/`info` (with its label and size), but it is
//! not recovered from metadata — `undelete` finds nothing and carving is the
//! fallback (copy-on-write reclaims old tree nodes).

mod common;

use std::process::Command;

use unearth::recover::{self, RecoverOptions};
use unearth::source::Source;

const SB_OFFSET: usize = 0x1_0000; // primary superblock at 64 KiB
const MAGIC: usize = 64;
const TOTAL_BYTES: usize = 112;
const SECTORSIZE: usize = 144;
const NODESIZE_OFF: usize = 148;
const LABEL: usize = 299;

// --- Subvolume enumeration fixture ---------------------------------------

const NODESIZE: usize = 4096;
const HEADER: usize = 101;
const CHUNK_PHYS: u64 = 0x2_0000;
const ROOT_PHYS: u64 = 0x2_1000;
const CHUNK_LOGICAL: u64 = 0x10_0000;
const ROOT_LOGICAL: u64 = 0x10_1000;

fn p16(v: &mut [u8], o: usize, x: u16) {
    v[o..o + 2].copy_from_slice(&x.to_le_bytes());
}
fn p32(v: &mut [u8], o: usize, x: u32) {
    v[o..o + 4].copy_from_slice(&x.to_le_bytes());
}
fn p64(v: &mut [u8], o: usize, x: u64) {
    v[o..o + 8].copy_from_slice(&x.to_le_bytes());
}

/// A `btrfs_chunk` (single stripe) mapping a logical range of `length` to the
/// physical device offset `phys`.
fn chunk_item(length: u64, phys: u64) -> Vec<u8> {
    let mut c = vec![0u8; 48 + 32];
    p64(&mut c, 0, length);
    p16(&mut c, 44, 1); // num_stripes
    p64(&mut c, 48, 1); // stripe devid
    p64(&mut c, 56, phys); // stripe offset
    c
}

/// A `btrfs_root_ref` carrying a subvolume name.
fn root_ref(name: &str) -> Vec<u8> {
    let mut d = vec![0u8; 18 + name.len()];
    p64(&mut d, 0, 256); // dirid
    p64(&mut d, 8, 1); // sequence
    p16(&mut d, 16, name.len() as u16);
    d[18..].copy_from_slice(name.as_bytes());
    d
}

/// Assemble a leaf node: header + item array (growing from the front) + item
/// data (packed from the end), as Btrfs lays out a level-0 node.
fn leaf_node(items: &[(u64, u8, u64, Vec<u8>)]) -> Vec<u8> {
    let mut node = vec![0u8; NODESIZE];
    p32(&mut node, 96, items.len() as u32); // nritems
    node[100] = 0; // level (leaf)
    let mut top = NODESIZE - HEADER; // data area size; data packs downward
    for (i, (oid, ktype, koff, data)) in items.iter().enumerate() {
        let item = HEADER + i * 25;
        p64(&mut node, item, *oid);
        node[item + 8] = *ktype;
        p64(&mut node, item + 9, *koff);
        top -= data.len();
        p32(&mut node, item + 17, top as u32); // data offset (from header end)
        p32(&mut node, item + 21, data.len() as u32); // data size
        node[HEADER + top..HEADER + top + data.len()].copy_from_slice(data);
    }
    node
}

/// A Btrfs volume with a real (synthetic) chunk tree and root tree, so the
/// subvolume names resolve through the full logical→physical walk.
fn btrfs_with_subvolumes(label: &str, subvols: &[&str]) -> Vec<u8> {
    let img_len = ROOT_PHYS as usize + NODESIZE;
    let mut v = vec![0u8; img_len];
    let sb = SB_OFFSET;

    v[sb + MAGIC..sb + MAGIC + 8].copy_from_slice(b"_BHRfS_M");
    p64(&mut v, sb + TOTAL_BYTES, img_len as u64);
    p64(&mut v, sb + 80, ROOT_LOGICAL); // root tree
    p64(&mut v, sb + 88, CHUNK_LOGICAL); // chunk tree
    p32(&mut v, sb + SECTORSIZE, 4096);
    p32(&mut v, sb + NODESIZE_OFF, NODESIZE as u32);
    let lb = label.as_bytes();
    v[sb + LABEL..sb + LABEL + lb.len()].copy_from_slice(lb);

    // System-chunk array (offset 811): one chunk mapping the chunk tree's
    // logical address to CHUNK_PHYS.
    let p = sb + 811;
    p64(&mut v, p, 256); // disk_key objectid (FIRST_CHUNK_TREE)
    v[p + 8] = 228; // disk_key type (CHUNK_ITEM)
    p64(&mut v, p + 9, CHUNK_LOGICAL); // disk_key offset (logical)
    let boot = chunk_item(0x1000, CHUNK_PHYS);
    v[p + 17..p + 17 + boot.len()].copy_from_slice(&boot);
    p32(&mut v, sb + 160, (17 + boot.len()) as u32); // sys_chunk_array_size

    // Chunk tree node: one CHUNK_ITEM mapping the root tree's logical address.
    let chunk_node = leaf_node(&[(256, 228, ROOT_LOGICAL, chunk_item(0x1000, ROOT_PHYS))]);
    v[CHUNK_PHYS as usize..CHUNK_PHYS as usize + NODESIZE].copy_from_slice(&chunk_node);

    // Root tree node: one ROOT_REF per subvolume.
    let items: Vec<(u64, u8, u64, Vec<u8>)> = subvols
        .iter()
        .enumerate()
        .map(|(i, name)| (5u64, 156u8, 256 + i as u64, root_ref(name)))
        .collect();
    let root_node = leaf_node(&items);
    v[ROOT_PHYS as usize..ROOT_PHYS as usize + NODESIZE].copy_from_slice(&root_node);
    v
}

#[test]
fn enumerates_subvolumes_through_the_chunk_and_root_trees() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("b.img");
    let subvols = ["home", "snapshots", "@var"];
    std::fs::write(&img, btrfs_with_subvolumes("pool", &subvols)).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "Btrfs");
    assert_eq!(vols[0].volume_label().as_deref(), Some("pool"));
    assert_eq!(vols[0].contained_volumes(), subvols);
}

#[test]
fn detect_reports_btrfs_with_label_but_recovers_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("b.img");
    std::fs::write(&img, common::btrfs_volume("photos", 1 << 30)).unwrap();
    let src = Source::open(&img).unwrap();

    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_label(), "Btrfs");
    assert_eq!(vols[0].size(), 1 << 30);
    assert_eq!(vols[0].volume_label().as_deref(), Some("photos"));

    // Recognised, but metadata undelete yields nothing.
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 0);
}

#[test]
fn info_cli_shows_the_btrfs_label() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("b.img");
    std::fs::write(&img, common::btrfs_volume("backups", 1 << 30)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args(["info", img.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Btrfs"), "stdout: {stdout}");
    assert!(stdout.contains("backups"), "stdout: {stdout}");
}
