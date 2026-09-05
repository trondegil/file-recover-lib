//! Carving tests for JPEG 2000 (`jp2`), TrueType collections (`ttc`), and
//! Windows animated cursors (`ani`) — each recovered byte-for-byte.

use std::io::Write;

use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::signatures;
use unearth::source::Source;

fn filler(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// A TTC with one member font that has a single table; table offsets are
/// measured from the start of the file.
fn make_ttc() -> Vec<u8> {
    let mut v = b"ttcf".to_vec();
    v.extend_from_slice(&1u16.to_be_bytes()); // major version
    v.extend_from_slice(&0u16.to_be_bytes()); // minor version
    v.extend_from_slice(&1u32.to_be_bytes()); // numFonts
    v.extend_from_slice(&16u32.to_be_bytes()); // offset to font 0 directory
                                               // Font directory at offset 16.
    v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // sfnt version
    v.extend_from_slice(&1u16.to_be_bytes()); // numTables
    v.extend_from_slice(&16u16.to_be_bytes()); // searchRange = 16 * 2^floor(log2 1)
    v.extend_from_slice(&0u16.to_be_bytes()); // entrySelector = floor(log2 1)
    v.extend_from_slice(&0u16.to_be_bytes()); // rangeShift = 1*16 - searchRange
                                              // One table record at offset 28: data at offset 44, length 12.
    v.extend_from_slice(b"cmap");
    v.extend_from_slice(&0u32.to_be_bytes()); // checksum
    v.extend_from_slice(&44u32.to_be_bytes()); // offset
    v.extend_from_slice(&12u32.to_be_bytes()); // length
    assert_eq!(v.len(), 44);
    v.extend_from_slice(&[0xAB; 12]); // table data
    v
}

/// A JPEG 2000 file: the 12-byte signature box, an ftyp box, then a codestream
/// box (the ISO box walk sums them).
fn make_jp2(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![
        0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
    ];
    let mut ftyp = Vec::new();
    ftyp.extend_from_slice(b"jp2 "); // brand
    ftyp.extend_from_slice(&0u32.to_be_bytes()); // minor version
    ftyp.extend_from_slice(b"jp2 "); // compatibility
    v.extend_from_slice(&((8 + ftyp.len()) as u32).to_be_bytes());
    v.extend_from_slice(b"ftyp");
    v.extend_from_slice(&ftyp);
    v.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
    v.extend_from_slice(b"jp2c");
    v.extend_from_slice(payload);
    v
}

/// A Windows animated cursor: a RIFF container with the `ACON` form.
fn make_ani(data: &[u8]) -> Vec<u8> {
    let mut v = b"RIFF".to_vec();
    v.extend_from_slice(&((4 + data.len()) as u32).to_le_bytes()); // "ACON" + data
    v.extend_from_slice(b"ACON");
    v.extend_from_slice(data);
    v
}

#[test]
fn recovers_jp2_ttc_and_ani() {
    let ttc = make_ttc();
    let jp2 = make_jp2(&filler(1, 200));
    let ani = make_ani(&filler(2, 120));

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    let planted = [&ttc, &jp2, &ani];
    img.write_all(&filler(100, 500)).unwrap();
    for (i, p) in planted.iter().enumerate() {
        img.write_all(p).unwrap();
        img.write_all(&filler(200 + i as u64, 400)).unwrap();
    }
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&[]).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.clone(),
        start: 0,
        end: None,
        min_size: 0,
        max_size: None,
        max_files: None,
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
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();

    assert_eq!(stats.files_recovered, 3, "ttc, jp2, ani");
    for ext in ["ttc", "jp2", "ani"] {
        assert_eq!(stats.per_type.get(ext), Some(&1), "missing {ext}");
    }

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![ttc, jp2, ani];
    originals.sort();
    assert_eq!(recovered, originals, "recovered bytes must match originals");
}
