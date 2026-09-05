//! Carving tests for the font / metafile / MIDI signatures: TTF, OTF, WOFF,
//! WOFF2, EMF, and MIDI. Each is embedded with a deterministic length into a
//! synthetic image and recovered byte-for-byte.

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

/// A minimal SFNT font: a 12-byte header, one 16-byte table-directory record,
/// then the table data (the file is padded to a 4-byte boundary).
fn make_sfnt(version: &[u8; 4], table: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(version);
    v.extend_from_slice(&1u16.to_be_bytes()); // numTables
    v.extend_from_slice(&16u16.to_be_bytes()); // searchRange = 16 * 2^floor(log2 1)
    v.extend_from_slice(&0u16.to_be_bytes()); // entrySelector = floor(log2 1)
    v.extend_from_slice(&0u16.to_be_bytes()); // rangeShift = 1*16 - searchRange
    let table_off = 28u32; // 12-byte header + one 16-byte record
    v.extend_from_slice(b"cmap");
    v.extend_from_slice(&0u32.to_be_bytes()); // checksum
    v.extend_from_slice(&table_off.to_be_bytes());
    v.extend_from_slice(&(table.len() as u32).to_be_bytes());
    v.extend_from_slice(table);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

/// A minimal WOFF/WOFF2 web font: the magic, then the total length as a
/// big-endian u32 at offset 8, then filler so a byte comparison is meaningful.
fn make_woff(magic: &[u8; 4], total: usize) -> Vec<u8> {
    let mut v = vec![0u8; total];
    v[0..4].copy_from_slice(magic);
    v[8..12].copy_from_slice(&(total as u32).to_be_bytes());
    for (i, b) in v.iter_mut().enumerate().skip(12) {
        *b = (i % 251) as u8;
    }
    v
}

/// A minimal EMF: an `EMR_HEADER` (record type 1, size 88) with the " EMF"
/// signature at offset 40 and the total byte count at offset 48.
fn make_emf(total: usize) -> Vec<u8> {
    let mut v = vec![0u8; total];
    v[0..4].copy_from_slice(&1u32.to_le_bytes()); // iType = EMR_HEADER
    v[4..8].copy_from_slice(&88u32.to_le_bytes()); // nSize
    v[40..44].copy_from_slice(b" EMF"); // dSignature
    v[48..52].copy_from_slice(&(total as u32).to_le_bytes()); // nBytes
    for (i, b) in v.iter_mut().enumerate().skip(52) {
        *b = (i % 241) as u8;
    }
    v
}

/// A minimal Standard MIDI file: an `MThd` header (format 0, one track) and a
/// single `MTrk` chunk holding an end-of-track meta event.
fn make_midi() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"MThd");
    v.extend_from_slice(&6u32.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes()); // format 0
    v.extend_from_slice(&1u16.to_be_bytes()); // ntrks
    v.extend_from_slice(&96u16.to_be_bytes()); // division
    let track = [0x00u8, 0xFF, 0x2F, 0x00]; // end-of-track meta event
    v.extend_from_slice(b"MTrk");
    v.extend_from_slice(&(track.len() as u32).to_be_bytes());
    v.extend_from_slice(&track);
    v
}

#[test]
fn recovers_font_metafile_and_midi_types() {
    let ttf = make_sfnt(&[0x00, 0x01, 0x00, 0x00], &filler(1, 30));
    let otf = make_sfnt(b"OTTO", &filler(2, 26));
    let woff = make_woff(b"wOFF", 64);
    let woff2 = make_woff(b"wOF2", 72);
    let emf = make_emf(120);
    let midi = make_midi();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    let planted = [&ttf, &otf, &woff, &woff2, &emf, &midi];
    img.write_all(&filler(100, 500)).unwrap();
    for (i, p) in planted.iter().enumerate() {
        img.write_all(p).unwrap();
        img.write_all(&filler(200 + i as u64, 300)).unwrap();
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

    assert_eq!(stats.files_recovered, 6, "ttf, otf, woff, woff2, emf, midi");
    for ext in ["ttf", "otf", "woff", "woff2", "emf", "mid"] {
        assert_eq!(stats.per_type.get(ext), Some(&1), "missing {ext}");
    }

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![ttf, otf, woff, woff2, emf, midi];
    originals.sort();
    assert_eq!(recovered, originals, "recovered bytes must match originals");
}
