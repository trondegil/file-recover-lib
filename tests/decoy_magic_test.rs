//! Filesystem magics planted in random data around a real FAT32 volume. A
//! partition walk must report only the table's volume; a lost-volume scan
//! must still find the real volume, and anything else it reports must parse
//! to sane geometry rather than a bare magic with garbage behind it.

mod common;

use unearth::recover;
use unearth::source::Source;

const DECOY_LEN: usize = 128 * 1024;
const FAT_OFFSET: usize = 2 * 1024 * 1024;

/// Deterministic pseudo-random bytes (xorshift64), so a run is repeatable.
fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    let mut v = Vec::with_capacity(len);
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(len);
    v
}

/// One detect-only magic at the offset its parser reads it from, in a block
/// of random bytes.
fn decoys() -> Vec<(&'static str, Vec<u8>)> {
    let mut out = Vec::new();
    let mut block = |name: &'static str, seed: u64, plant: &dyn Fn(&mut [u8])| {
        let mut b = random_bytes(seed, DECOY_LEN);
        plant(&mut b);
        out.push((name, b));
    };
    block("minix", 1, &|b| {
        b[1024 + 0x10..1024 + 0x12].copy_from_slice(&0x137Fu16.to_le_bytes())
    });
    block("romfs", 2, &|b| b[0..8].copy_from_slice(b"-rom1fs-"));
    block("befs", 3, &|b| {
        b[512 + 0x20..512 + 0x24].copy_from_slice(&0x4246_5331u32.to_le_bytes());
        b[512 + 0x44..512 + 0x48].copy_from_slice(&0xDD12_1031u32.to_le_bytes());
    });
    block("cramfs", 4, &|b| {
        b[0..4].copy_from_slice(&0x28CD_3D45u32.to_le_bytes());
        b[0x10..0x20].copy_from_slice(b"Compressed ROMFS");
    });
    block("reiserfs", 5, &|b| {
        b[65536 + 0x34..65536 + 0x34 + 9].copy_from_slice(b"ReIsEr2Fs")
    });
    block("xfs", 6, &|b| b[0..4].copy_from_slice(b"XFSB"));
    block("ufs", 7, &|b| {
        b[8192 + 0x55C..8192 + 0x560].copy_from_slice(&0x0001_1954u32.to_le_bytes())
    });
    block("jfs", 8, &|b| b[32768..32772].copy_from_slice(b"JFS1"));
    out
}

const FAT_PAYLOAD: &[u8] = b"the real file on the real FAT32 volume";

/// The image: sector 0 (an MBR naming the FAT volume, or zeros), decoy
/// blocks from sector 1, the FAT32 volume at `FAT_OFFSET`, then the decoys
/// again after it.
fn image(with_mbr: bool) -> Vec<u8> {
    let fat = common::fat32_volume(b"REAL    ", b"TXT", FAT_PAYLOAD);
    let decoys = decoys();
    let tail = FAT_OFFSET + fat.len();
    let mut v = vec![0u8; tail + 512 + decoys.len() * DECOY_LEN];
    for (i, (_, block)) in decoys.iter().enumerate() {
        let before = 512 + i * DECOY_LEN;
        v[before..before + DECOY_LEN].copy_from_slice(block);
        let after = tail + 512 + i * DECOY_LEN;
        v[after..after + DECOY_LEN].copy_from_slice(block);
    }
    v[FAT_OFFSET..tail].copy_from_slice(&fat);
    if with_mbr {
        let e = 446;
        v[e + 4] = 0x0C;
        v[e + 8..e + 12].copy_from_slice(&((FAT_OFFSET / 512) as u32).to_le_bytes());
        v[e + 12..e + 16].copy_from_slice(&((fat.len() / 512) as u32).to_le_bytes());
        v[510] = 0x55;
        v[511] = 0xAA;
    }
    v
}

fn source_of(tmp: &tempfile::TempDir, bytes: &[u8]) -> Source {
    let p = tmp.path().join("disk.img");
    std::fs::write(&p, bytes).unwrap();
    Source::open(&p).unwrap()
}

#[test]
fn a_partition_walk_reports_only_the_tabled_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let src = source_of(&tmp, &image(true));
    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1, "one volume from the table");
    assert!(
        matches!(vols[0], recover::Volume::Fat(_)),
        "{}",
        vols[0].fs_label()
    );
    assert_eq!(vols[0].offset(), FAT_OFFSET as u64);
}

#[test]
fn a_lost_volume_scan_finds_the_real_volume_and_reports_no_garbage() {
    let tmp = tempfile::tempdir().unwrap();
    let img = image(false);
    let src = source_of(&tmp, &img);
    let vols = recover::scan_lost_volumes(&src, 512, |_| {}).unwrap();
    let described: Vec<String> = vols
        .iter()
        .map(|v| format!("{} at {} size {}", v.fs_label(), v.offset(), v.size()))
        .collect();
    eprintln!("lost-volume scan reported: {described:?}");
    let fat: Vec<&recover::Volume> = vols
        .iter()
        .filter(|v| matches!(v, recover::Volume::Fat(_)))
        .collect();
    assert_eq!(
        fat.len(),
        1,
        "the FAT volume is reported once: {described:?}"
    );
    assert_eq!(fat[0].offset(), FAT_OFFSET as u64, "{described:?}");
    // Whatever else was reported must be a volume whose geometry made sense,
    // not a bare magic: it re-parses at that offset with a size that fits.
    for v in vols
        .iter()
        .filter(|v| !matches!(v, recover::Volume::Fat(_)))
    {
        let again = recover::parse_at(&src, v.offset()).unwrap_or_else(|e| {
            panic!("{} at {} does not re-parse: {e}", v.fs_label(), v.offset())
        });
        assert_eq!(again.fs_label(), v.fs_label());
        assert!(again.size() > 0, "{described:?}");
        assert!(
            v.offset() + again.size() <= img.len() as u64,
            "{} at {} claims {} bytes past the source end",
            v.fs_label(),
            v.offset(),
            again.size()
        );
    }
}

/// A Minix magic inside a FAT file's data, at the offset a probe would read
/// it from, changes nothing: the FAT volume is still what is found and the
/// file still comes back byte for byte.
#[test]
fn a_decoy_magic_inside_file_data_does_not_disturb_undelete() {
    let mut payload = random_bytes(99, 1500);
    payload[1024 + 0x10..1024 + 0x12].copy_from_slice(&0x137Fu16.to_le_bytes());
    let tmp = tempfile::tempdir().unwrap();
    let src = source_of(&tmp, &common::fat32_volume(b"DECOY   ", b"BIN", &payload));
    let vols = recover::detect(&src).unwrap();
    assert_eq!(vols.len(), 1);
    assert!(matches!(vols[0], recover::Volume::Fat(_)));
    let out = tmp.path().join("out");
    let stats = vols[0]
        .recover_deleted(&src, &out, &recover::RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1);
    assert_eq!(std::fs::read(out.join("_ECOY.BIN")).unwrap(), payload);
    // A lost-volume scan skips the volume body, so the decoy inside is never probed.
    let found = recover::scan_lost_volumes(&src, 512, |_| {}).unwrap();
    assert_eq!(found.len(), 1);
    assert!(matches!(found[0], recover::Volume::Fat(_)));
}
