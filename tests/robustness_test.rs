//! Robustness tests: malformed, random, and truncated input must never panic —
//! every parser should return `Ok`/`Err` (or empty results), not crash.

use std::path::Path;

use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::recover::{self, RecoverOptions};
use unearth::signatures;
use unearth::source::Source;

/// Tiny deterministic xorshift PRNG so failures reproduce.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
}

fn run_all(src: &Source, out_dir: &Path) {
    // Detection / parsing must not panic.
    let _ = recover::detect(src);
    let _ = recover::parse_at(src, 0);

    // Carving must not panic and must not write outside the (small) buffer.
    let sigs = signatures::select(&[]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.to_path_buf(),
        start: 0,
        end: None,
        min_size: 0,
        max_size: None,
        max_files: Some(50),
        allow_nested: false,
        validate: true,
        dedup: false,
        progress: false,
        checkpoint: None,
        resume: false,
        organize: false,
        dry_run: false,
        align: 1,
    };
    let _ = carver::carve(src, &sigs, &opts, &NoProgress);
}

#[test]
fn never_panics_on_random_and_planted_input() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("fuzz.img");
    let out_dir = tmp.path().join("out");
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);

    for iter in 0..400u64 {
        let len = 1024 + (rng.next() % 8192) as usize;
        let mut buf = rng.bytes(len);

        // Periodically plant a filesystem/partition magic so the real parser
        // internals run against otherwise-garbage data.
        match iter % 7 {
            1 if len > 11 => buf[3..11].copy_from_slice(b"NTFS    "),
            2 if len > 11 => buf[3..11].copy_from_slice(b"EXFAT   "),
            3 if len > 0x43A => {
                buf[0x438..0x43A].copy_from_slice(&0xEF53u16.to_le_bytes()); // ext magic
            }
            4 if len > 512 => {
                buf[0] = 0xEB; // FAT-ish boot record
                buf[11..13].copy_from_slice(&512u16.to_le_bytes());
                buf[13] = 1;
                buf[16] = 2;
                buf[510] = 0x55;
                buf[511] = 0xAA;
            }
            5 if len > 600 => {
                buf[510] = 0x55; // MBR signature
                buf[511] = 0xAA;
                buf[512..520].copy_from_slice(b"EFI PART"); // GPT header
            }
            _ => {}
        }

        std::fs::write(&img_path, &buf).unwrap();
        let src = Source::open(&img_path).unwrap();
        run_all(&src, &out_dir);
    }
}

/// Build a minimal valid ext4 volume with one deleted file (slack entry).
fn minimal_ext() -> Vec<u8> {
    const BS: usize = 1024;
    const ISIZE: usize = 128;
    const ITAB: usize = 5;
    const ROOT: usize = 9;
    const DATA: usize = 11;
    let mut v = vec![0u8; 32 * BS];
    let sb = 1024;
    v[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 4..sb + 8].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    v[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    v[sb + 0x28..sb + 0x2C].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    v[sb + 0x58..sb + 0x5A].copy_from_slice(&(ISIZE as u16).to_le_bytes());
    v[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes());
    v[2 * BS + 8..2 * BS + 12].copy_from_slice(&(ITAB as u32).to_le_bytes());

    let mut inode = |ino: u32, mode: u16, links: u16, dtime: u32, size: u32, block: u32| {
        let o = ITAB * BS + (ino as usize - 1) * ISIZE;
        v[o..o + 2].copy_from_slice(&mode.to_le_bytes());
        v[o + 4..o + 8].copy_from_slice(&size.to_le_bytes());
        v[o + 0x14..o + 0x18].copy_from_slice(&dtime.to_le_bytes());
        v[o + 0x1A..o + 0x1C].copy_from_slice(&links.to_le_bytes());
        v[o + 0x20..o + 0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes());
        let ib = o + 0x28;
        v[ib..ib + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
        v[ib + 2..ib + 4].copy_from_slice(&1u16.to_le_bytes());
        v[ib + 4..ib + 6].copy_from_slice(&4u16.to_le_bytes());
        v[ib + 16..ib + 18].copy_from_slice(&1u16.to_le_bytes());
        v[ib + 20..ib + 24].copy_from_slice(&block.to_le_bytes());
    };
    inode(2, 0x41ED, 3, 0, BS as u32, ROOT as u32);
    inode(11, 0x81A4, 0, 12345, 200, DATA as u32);

    let mut dirent = |block: usize, off: usize, ino: u32, rl: u16, name: &str, ft: u8| {
        let p = block * BS + off;
        v[p..p + 4].copy_from_slice(&ino.to_le_bytes());
        v[p + 4..p + 6].copy_from_slice(&rl.to_le_bytes());
        v[p + 6] = name.len() as u8;
        v[p + 7] = ft;
        v[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
    };
    dirent(ROOT, 0, 2, 12, ".", 2);
    dirent(ROOT, 12, 2, (BS - 12) as u16, "..", 2);
    dirent(ROOT, 28, 11, 24, "file.bin", 1);
    v
}

#[test]
fn never_panics_on_truncated_volume() {
    let full = minimal_ext();
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("trunc.img");
    let out_dir = tmp.path().join("out");

    // Truncate the valid image at many lengths; recovery must stay panic-free.
    let mut len = 0usize;
    while len <= full.len() {
        std::fs::write(&img_path, &full[..len]).unwrap();
        if let Ok(src) = Source::open(&img_path) {
            if let Ok(volumes) = recover::detect(&src) {
                for vol in &volumes {
                    let _ = vol.recover_deleted(
                        &src,
                        &out_dir,
                        &RecoverOptions {
                            min_size: 0,
                            max_size: None,
                            modified_after: None,
                            modified_before: None,
                            names: Vec::new(),
                            exclude_names: Vec::new(),
                            dry_run: true,
                        },
                    );
                }
            }
            run_all(&src, &out_dir);
        }
        len += 137; // stride across all structures
    }
}

// --- Reachable cycles and extreme geometry ---------------------------------------

mod common;

use std::sync::mpsc;
use std::time::Duration;

/// Run detection, undelete, and a capped carve on `image` on its own thread;
/// it must finish within five seconds and write only under the output
/// directory.
fn must_finish(what: &str, image: Vec<u8>) {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &image).unwrap();
    let out_dir = tmp.path().join("out");
    let (tx, rx) = mpsc::channel();
    let (img2, out2) = (img_path.clone(), out_dir.clone());
    std::thread::spawn(move || {
        let src = Source::open(&img2).unwrap();
        if let Ok(volumes) = recover::detect(&src) {
            for vol in &volumes {
                let _ = vol.recover_deleted(&src, &out2, &RecoverOptions::default());
            }
        }
        run_all(&src, &out2);
        tx.send(()).ok();
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "{what}: did not finish within five seconds"
    );
    for e in std::fs::read_dir(tmp.path()).unwrap().flatten() {
        let p = e.path();
        assert!(
            p == img_path || p == out_dir,
            "{what}: wrote outside the output directory: {}",
            p.display()
        );
    }
}

#[test]
fn a_fat_directory_chain_that_loops_terminates() {
    let mut img =
        common::fat32_deleted_dir_volume(b"OLDDIR  ", b"NOTE    ", b"TXT", b"looping chain");
    // The root directory's FAT entry points back at itself.
    let fat_base = 32 * 512;
    img[fat_base + 2 * 4..fat_base + 2 * 4 + 4].copy_from_slice(&2u32.to_le_bytes());
    // And the deleted folder's cluster chains to the root, which chains to itself.
    img[fat_base + 3 * 4..fat_base + 3 * 4 + 4].copy_from_slice(&2u32.to_le_bytes());
    must_finish("FAT chain loop", img);
}

#[test]
fn an_exfat_bitmap_claiming_more_clusters_than_the_volume_terminates() {
    // A minimal exFAT volume: 32 clusters of 512 bytes, root at cluster 2, the
    // allocation bitmap entry claiming u64::MAX bytes at cluster 4.
    let sectors = 16 + 32;
    let mut img = vec![0u8; sectors * 512];
    img[0] = 0xEB;
    img[1] = 0x76;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"EXFAT   ");
    img[72..80].copy_from_slice(&(sectors as u64).to_le_bytes());
    img[80..84].copy_from_slice(&8u32.to_le_bytes()); // FAT offset
    img[88..92].copy_from_slice(&16u32.to_le_bytes()); // cluster heap offset
    img[92..96].copy_from_slice(&32u32.to_le_bytes()); // cluster count
    img[96..100].copy_from_slice(&2u32.to_le_bytes()); // root cluster
    img[108] = 9;
    img[109] = 0;
    img[110] = 1;
    img[510] = 0x55;
    img[511] = 0xAA;
    let root = 16 * 512;
    img[root] = 0x81; // allocation bitmap entry
    img[root + 20..root + 24].copy_from_slice(&4u32.to_le_bytes());
    img[root + 24..root + 32].copy_from_slice(&u64::MAX.to_le_bytes());
    must_finish("exFAT oversized bitmap", img);
}

#[test]
fn an_hfsplus_leaf_linked_to_itself_terminates() {
    let mut img = common::hfsplus_volume("self.txt", b"leaf node links to itself");
    // Catalog node 1 (the leaf) at block 9: fLink and bLink both name node 1.
    let n1 = 9 * 512;
    img[n1..n1 + 4].copy_from_slice(&1u32.to_be_bytes());
    img[n1 + 4..n1 + 8].copy_from_slice(&1u32.to_be_bytes());
    must_finish("HFS+ fLink self-loop", img);
}

#[test]
fn an_ntfs_mft_run_covering_itself_and_beyond_terminates() {
    // Boot sector plus an $MFT record whose data run starts at cluster 0 (the
    // boot sector and itself) and claims 255 clusters of a 64-cluster volume.
    let mut img = vec![0u8; 64 * 512];
    img[0] = 0xEB;
    img[1] = 0x52;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"NTFS    ");
    img[11..13].copy_from_slice(&512u16.to_le_bytes());
    img[13] = 1;
    img[40..48].copy_from_slice(&64u64.to_le_bytes());
    img[48..56].copy_from_slice(&4u64.to_le_bytes());
    img[64] = (-10i8) as u8;
    img[510] = 0x55;
    img[511] = 0xAA;
    let rec = 4 * 512;
    img[rec..rec + 4].copy_from_slice(b"FILE");
    img[rec + 4..rec + 6].copy_from_slice(&48u16.to_le_bytes());
    img[rec + 6..rec + 8].copy_from_slice(&3u16.to_le_bytes());
    img[rec + 20..rec + 22].copy_from_slice(&56u16.to_le_bytes());
    img[rec + 22..rec + 24].copy_from_slice(&1u16.to_le_bytes());
    img[rec + 28..rec + 32].copy_from_slice(&1024u32.to_le_bytes());
    // $DATA, non-resident, run list [len 255 at LCN 0].
    let a = rec + 56;
    img[a..a + 4].copy_from_slice(&0x80u32.to_le_bytes());
    img[a + 4..a + 8].copy_from_slice(&72u32.to_le_bytes());
    img[a + 8] = 1;
    img[a + 32..a + 34].copy_from_slice(&64u16.to_le_bytes());
    img[a + 48..a + 56].copy_from_slice(&(255u64 * 512).to_le_bytes());
    img[a + 64..a + 67].copy_from_slice(&[0x11, 0xFF, 0x00]);
    img[a + 72..a + 76].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    must_finish("NTFS $MFT run over itself", img);
}

#[test]
fn an_ext4_extent_index_pointing_at_its_own_block_terminates() {
    let mut img = common::ext_volume("loop.bin", &[0x5A; 900]);
    // Inode 11's extent tree: depth 1, one index entry naming block 12, and
    // block 12 holds the same index naming block 12 again.
    let inode = 5 * 1024 + 10 * 128;
    let ib = inode + 0x28;
    let mut node = [0u8; 24];
    node[0..2].copy_from_slice(&0xF30Au16.to_le_bytes());
    node[2..4].copy_from_slice(&1u16.to_le_bytes());
    node[4..6].copy_from_slice(&4u16.to_le_bytes());
    node[6..8].copy_from_slice(&1u16.to_le_bytes()); // depth 1
    node[12..16].copy_from_slice(&0u32.to_le_bytes()); // logical block 0
    node[16..20].copy_from_slice(&12u32.to_le_bytes()); // leaf lo = block 12
    img[ib..ib + 24].copy_from_slice(&node);
    img[12 * 1024..12 * 1024 + 24].copy_from_slice(&node);
    must_finish("ext4 extent self-reference", img);
}

#[test]
fn a_gpt_claiming_u32_max_entries_terminates() {
    let vol = common::ext_volume("gpt.txt", b"behind a huge entry count");
    let mut img = common::gpt_disk(&vol, 512, 64);
    img[512 + 80..512 + 84].copy_from_slice(&u32::MAX.to_le_bytes());
    let last = img.len() - 512;
    img[last + 80..last + 84].copy_from_slice(&u32::MAX.to_le_bytes());
    must_finish("GPT u32::MAX entries", img);
}

#[test]
fn a_directory_listing_its_own_parent_as_a_child_terminates() {
    let mut img = common::ext_volume_multi(&[("file.txt", b"in the root")]);
    // A live dirent "loop" in the root naming the root's own inode as a directory.
    let root = 9 * 1024;
    let off = root + 28 + 24; // after the stale entry the builder placed
    img[off..off + 4].copy_from_slice(&2u32.to_le_bytes());
    img[off + 4..off + 6].copy_from_slice(&16u16.to_le_bytes());
    img[off + 6] = 4;
    img[off + 7] = 2;
    img[off + 8..off + 12].copy_from_slice(b"loop");
    must_finish("directory lists its parent", img);
}
