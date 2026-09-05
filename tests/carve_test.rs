//! Integration test: build a synthetic disk image with embedded files and
//! verify the carver recovers them byte-for-byte.

use std::io::Write;
use std::path::PathBuf;

use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::signatures;
use unearth::source::Source;

/// Deterministic pseudo-random filler so the image looks like real noisy media.
fn filler(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn make_jpeg(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

fn make_png(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    // IHDR chunk: length(13) + "IHDR" + 13-byte header + CRC (validators only
    // check the length, type, and dimensions, so a dummy CRC is fine here).
    v.extend_from_slice(&13u32.to_be_bytes());
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&64u32.to_be_bytes()); // width
    v.extend_from_slice(&64u32.to_be_bytes()); // height
    v.extend_from_slice(&[8, 6, 0, 0, 0]); // bit depth, colour type, etc.
    v.extend_from_slice(&[0, 0, 0, 0]); // CRC placeholder
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
    v
}

fn make_bmp(payload: &[u8]) -> Vec<u8> {
    // 14-byte BITMAPFILEHEADER + 40-byte BITMAPINFOHEADER + payload. The total
    // size is a LE u32 at offset 2 (the carver's extent strategy).
    let dib = 40u32;
    let pixel_off = 14 + dib;
    let total = pixel_off + payload.len() as u32;
    let mut v = vec![b'B', b'M'];
    v.extend_from_slice(&total.to_le_bytes()); // file size (offset 2)
    v.extend_from_slice(&0u32.to_le_bytes()); // reserved
    v.extend_from_slice(&pixel_off.to_le_bytes()); // pixel-array offset
    v.extend_from_slice(&dib.to_le_bytes()); // DIB header size (offset 14)
    v.extend_from_slice(&64i32.to_le_bytes()); // width
    v.extend_from_slice(&64i32.to_le_bytes()); // height
    v.extend_from_slice(&1u16.to_le_bytes()); // planes
    v.extend_from_slice(&24u16.to_le_bytes()); // bits per pixel
    v.extend_from_slice(&[0u8; 24]); // rest of BITMAPINFOHEADER
    v.extend_from_slice(payload);
    v
}

#[test]
fn recovers_embedded_files() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path: PathBuf = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let jpeg = make_jpeg(&filler(1, 5000));
    let png = make_png(&filler(2, 8000));
    let bmp = make_bmp(&filler(3, 3000));

    // Lay the files out between regions of random "free space".
    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 4096)).unwrap();
    img.write_all(&jpeg).unwrap();
    img.write_all(&filler(11, 1234)).unwrap();
    img.write_all(&png).unwrap();
    img.write_all(&filler(12, 777)).unwrap();
    img.write_all(&bmp).unwrap();
    img.write_all(&filler(13, 4096)).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&[]).unwrap(); // all types
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
    assert_eq!(stats.files_recovered, 3, "should recover jpeg, png, bmp");

    // Collect recovered files and match them against originals by content.
    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();

    let mut originals = vec![jpeg, png, bmp];
    originals.sort();

    assert_eq!(recovered, originals, "recovered bytes must match originals");
}

#[test]
fn type_filter_limits_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let jpeg = make_jpeg(&filler(1, 1000));
    let png = make_png(&filler(2, 1000));

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(10, 512)).unwrap();
    img.write_all(&jpeg).unwrap();
    img.write_all(&filler(11, 512)).unwrap();
    img.write_all(&png).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["png".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1);
    assert_eq!(stats.per_type.get("png"), Some(&1));
}

#[test]
fn unknown_type_is_rejected() {
    let err = signatures::select(&["xyz".to_string()]).unwrap_err();
    assert!(err.to_string().contains("unknown file type"));
}

#[test]
fn footer_search_terminates_without_a_footer() {
    // Regression: a footer-type magic (JPEG) followed by data with no `FF D9`
    // footer used to spin `find_footer` forever once the search reached the end
    // of the buffer (the tail read advanced position by zero). It must instead
    // terminate and recover nothing.
    let tmp = tempfile::tempdir().unwrap();
    let img: PathBuf = tmp.path().join("disk.img");
    let out = tmp.path().join("out");

    let mut data = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG SOI, no EOI anywhere
    data.extend(std::iter::repeat(0x00).take(5000));
    std::fs::write(&img, &data).unwrap();

    let source = Source::open(&img).unwrap();
    let sigs = signatures::select(&["jpg".to_string()]).unwrap();
    let opts = CarveOptions {
        output_dir: out,
        start: 0,
        end: None,
        min_size: 0,
        max_size: None,
        max_files: None,
        allow_nested: false,
        validate: false,
        dedup: false,
        progress: false,
        checkpoint: None,
        resume: false,
        organize: false,
        dry_run: false,
        align: 1,
    };
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 0, "no footer => nothing recovered");
}

/// The PDF footer allowance is for a line ending after `%%EOF`. Only CR/LF
/// bytes may be absorbed; whatever follows the file on disk must not be, or the
/// carved bytes (and their hash) differ from the original. Found by the
/// real-image corpus.
#[test]
fn pdf_footer_absorbs_only_a_line_ending() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path: PathBuf = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let bare = b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n%%EOF".to_vec();
    let mut lf = bare.clone();
    lf.push(b'\n');
    let mut crlf = bare.clone();
    crlf.extend_from_slice(b"\r\n");

    let mut img = std::fs::File::create(&img_path).unwrap();
    for pdf in [&bare, &lf, &crlf] {
        img.write_all(pdf).unwrap();
        // Non-line-ending bytes right after each file, then padding.
        img.write_all(b"XYZ").unwrap();
        img.write_all(&filler(7, 4096)).unwrap();
    }
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["pdf".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 3);

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![bare, lf, crlf];
    originals.sort();
    assert_eq!(
        recovered, originals,
        "each PDF must end exactly where it did"
    );
}

/// A run of little-endian counting `u16`s (an exFAT up-case table, or any
/// identity lookup table) begins `00 00 01 00`, which is the ICO magic. The
/// directory entries that follow have impossible plane/bit-depth values and
/// point at data that is not a DIB or PNG, so it must not carve — on a real
/// exFAT card it came out as a 2 MiB "icon" that hid every file after it.
#[test]
fn counting_table_is_not_an_icon() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path: PathBuf = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img: Vec<u8> = Vec::new();
    for i in 0..0x10000u32 {
        img.extend_from_slice(&(i as u16).to_le_bytes());
    }
    // A real file behind the table that a false icon would swallow.
    let jpeg = make_jpeg(&filler(4, 3000));
    img.extend_from_slice(&jpeg);
    img.extend_from_slice(&filler(5, 2048));
    std::fs::write(&img_path, &img).unwrap();

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["ico".to_string(), "jpg".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "only the JPEG should carve");
    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered, vec![jpeg]);
}

/// The bytes an HFS+ journal header starts with (`00 01 00 00` then small
/// counters) are the TrueType magic followed by a nonsense table directory.
/// The binary-search fields do not match the table count, so it must not
/// carve — on a real Mac volume it came out as a 42 MiB "font" hiding
/// everything behind it.
#[test]
fn journal_header_is_not_a_font() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path: PathBuf = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x10, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x7e,
        0x00, 0x00,
    ];
    img.resize(4096, 0);
    let jpeg = make_jpeg(&filler(6, 3000));
    img.extend_from_slice(&jpeg);
    img.extend_from_slice(&filler(8, 4096));
    std::fs::write(&img_path, &img).unwrap();

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["ttf".to_string(), "jpg".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "only the JPEG should carve");
}
