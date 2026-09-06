//! Partition-table shapes detection must cope with: logical partitions in
//! an MBR extended chain, a wiped primary GPT header, an entry that points
//! past the end of the source, and two entries that name one volume.

mod common;

use unearth::recover::{self, RecoverOptions};
use unearth::source::Source;

const SS: usize = 512;

fn put_mbr_entry(sec: &mut [u8], slot: usize, kind: u8, lba: u32, sectors: u32) {
    let e = 446 + slot * 16;
    sec[e + 4] = kind;
    sec[e + 8..e + 12].copy_from_slice(&lba.to_le_bytes());
    sec[e + 12..e + 16].copy_from_slice(&sectors.to_le_bytes());
    sec[510] = 0x55;
    sec[511] = 0xAA;
}

fn source_of(tmp: &tempfile::TempDir, bytes: &[u8]) -> Source {
    let p = tmp.path().join("disk.img");
    std::fs::write(&p, bytes).unwrap();
    Source::open(&p).unwrap()
}

fn recover_all(src: &Source, vols: &[recover::Volume], out: &std::path::Path) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    for (i, v) in vols.iter().enumerate() {
        let dir = out.join(format!("v{i}"));
        v.recover_deleted(src, &dir, &RecoverOptions::default())
            .unwrap();
        let mut stack = vec![dir];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                if e.path().is_dir() {
                    stack.push(e.path());
                } else {
                    got.push(std::fs::read(e.path()).unwrap());
                }
            }
        }
    }
    got
}

/// Two logical partitions in an extended container. Entry 0 of each EBR is
/// the logical partition, its LBA relative to that EBR; entry 1 links to the
/// next EBR, its LBA relative to the start of the extended partition.
#[test]
fn logical_partitions_in_an_mbr_extended_chain_are_detected() {
    const EXT_BASE: usize = 64; // the extended container starts here
    const EBR2_REL: usize = 256; // second EBR, relative to EXT_BASE
    const LOGICAL_REL: usize = 64; // each logical partition, relative to its EBR
    let vol_a = common::ext_volume("first.txt", b"in the first logical partition");
    let vol_b = common::ext_volume("second.txt", b"in the second logical partition");
    let vol_sectors = vol_a.len() / SS;
    let a_lba = EXT_BASE + LOGICAL_REL;
    let ebr2_lba = EXT_BASE + EBR2_REL;
    let b_lba = ebr2_lba + LOGICAL_REL;
    let total = b_lba + vol_sectors + 8;
    let mut disk = vec![0u8; total * SS];

    // MBR: one primary entry, the extended container (type 0x05).
    put_mbr_entry(
        &mut disk,
        0,
        0x05,
        EXT_BASE as u32,
        (total - EXT_BASE) as u32,
    );
    // EBR 1 at EXT_BASE: logical A at +LOGICAL_REL, next EBR at base+EBR2_REL.
    {
        let sec = &mut disk[EXT_BASE * SS..(EXT_BASE + 1) * SS];
        put_mbr_entry(sec, 0, 0x83, LOGICAL_REL as u32, vol_sectors as u32);
        put_mbr_entry(
            sec,
            1,
            0x05,
            EBR2_REL as u32,
            (LOGICAL_REL + vol_sectors) as u32,
        );
    }
    // EBR 2: logical B at +LOGICAL_REL; entry 1 zero ends the chain.
    {
        let sec = &mut disk[ebr2_lba * SS..(ebr2_lba + 1) * SS];
        put_mbr_entry(sec, 0, 0x83, LOGICAL_REL as u32, vol_sectors as u32);
    }
    disk[a_lba * SS..a_lba * SS + vol_a.len()].copy_from_slice(&vol_a);
    disk[b_lba * SS..b_lba * SS + vol_b.len()].copy_from_slice(&vol_b);

    let tmp = tempfile::tempdir().unwrap();
    let src = source_of(&tmp, &disk);
    let vols = recover::detect(&src).unwrap();
    let mut offsets: Vec<u64> = vols.iter().map(|v| v.offset()).collect();
    offsets.sort();
    assert_eq!(
        offsets,
        vec![(a_lba * SS) as u64, (b_lba * SS) as u64],
        "both logical partitions at their absolute offsets"
    );
    let mut got = recover_all(&src, &vols, &tmp.path().join("out"));
    got.sort();
    assert_eq!(
        got,
        vec![
            b"in the first logical partition".to_vec(),
            b"in the second logical partition".to_vec()
        ]
    );
}

#[test]
fn a_wiped_primary_gpt_header_falls_back_to_the_backup() {
    for sector in [512usize, 4096] {
        let vol = common::ext_volume("keep.txt", b"still here via the backup header");
        let mut disk = common::gpt_disk(&vol, sector, 64);
        // Wipe LBA 1 (the primary header) entirely.
        disk[sector..2 * sector].fill(0);

        let tmp = tempfile::tempdir().unwrap();
        let src = source_of(&tmp, &disk);
        let vols = recover::detect(&src).unwrap();
        assert_eq!(vols.len(), 1, "sector {sector}");
        assert_eq!(vols[0].offset(), (64 * sector) as u64);
        let got = recover_all(&src, &vols, &tmp.path().join("out"));
        assert_eq!(got, vec![b"still here via the backup header".to_vec()]);
    }
}

#[test]
fn an_entry_past_the_end_of_the_source_is_skipped_without_error() {
    let vol = common::ext_volume("near.txt", b"the partition that exists");
    let lba = 64usize;
    let mut disk = vec![0u8; lba * SS + vol.len()];
    put_mbr_entry(&mut disk, 0, 0x83, lba as u32, (vol.len() / SS) as u32);
    put_mbr_entry(&mut disk, 1, 0x83, 1_000_000, 2048); // far beyond the image
    disk[lba * SS..lba * SS + vol.len()].copy_from_slice(&vol);

    let tmp = tempfile::tempdir().unwrap();
    let src = source_of(&tmp, &disk);
    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].offset(), (lba * SS) as u64);
    let got = recover_all(&src, &vols, &tmp.path().join("out"));
    assert_eq!(got, vec![b"the partition that exists".to_vec()]);
}

#[test]
fn overlapping_entries_naming_one_volume_recover_it_once() {
    let vol = common::ext_volume("once.txt", b"one volume, two table entries");
    let lba = 64usize;
    let mut disk = vec![0u8; lba * SS + vol.len()];
    let sectors = (vol.len() / SS) as u32;
    put_mbr_entry(&mut disk, 0, 0x83, lba as u32, sectors);
    put_mbr_entry(&mut disk, 1, 0x07, lba as u32, sectors); // same start, other type
    disk[lba * SS..lba * SS + vol.len()].copy_from_slice(&vol);

    let tmp = tempfile::tempdir().unwrap();
    let src = source_of(&tmp, &disk);
    let vols = recover::detect(&src).unwrap();
    let got = recover_all(&src, &vols, &tmp.path().join("out"));
    assert_eq!(
        got,
        vec![b"one volume, two table entries".to_vec()],
        "the file must come back exactly once ({} volumes detected)",
        vols.len()
    );
}
