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

/// The zero-run fast path must not jump over a magic whose leading bytes are
/// zero: an icon (`00 00 01 00`) placed right at the end of a long run of
/// zeros, and one straddling a 64-byte block boundary, must both still carve,
/// as must an ordinary file after megabytes of zeros.
#[test]
fn zero_run_skipping_misses_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let img_path: PathBuf = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    // A minimal real icon: header, one entry, a 40-byte DIB.
    let mut ico = vec![0x00, 0x00, 0x01, 0x00, 0x01, 0x00];
    ico.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0]);
    ico.extend_from_slice(&(40u32 + 64).to_le_bytes());
    ico.extend_from_slice(&22u32.to_le_bytes());
    let mut dib = vec![0u8; 40];
    dib[0..4].copy_from_slice(&40u32.to_le_bytes());
    ico.extend_from_slice(&dib);
    ico.extend_from_slice(&filler(3, 64));

    let jpeg = make_jpeg(&filler(9, 5000));
    let mut img = vec![0u8; 3 * 1024 * 1024];
    // Icons at offsets that land the magic inside and across 64-byte blocks.
    for &off in &[100_000usize, 200_061, 300_063] {
        img[off..off + ico.len()].copy_from_slice(&ico);
    }
    let j = 2 * 1024 * 1024 + 777;
    img[j..j + jpeg.len()].copy_from_slice(&jpeg);
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
    assert_eq!(stats.files_recovered, 4, "three icons and one JPEG");
    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![ico.clone(), ico.clone(), ico, jpeg];
    originals.sort();
    assert_eq!(recovered, originals);
}

/// Every carved file carries a confidence grade: a JPEG (validated header,
/// footer-found length) is verified; a WAV (no structural validator, length
/// from its RIFF size field) is plausible. The counts add up to the files.
#[test]
fn carved_files_are_graded_by_confidence() {
    use unearth::carver::Confidence;
    let tmp = tempfile::tempdir().unwrap();
    let img_path: PathBuf = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let jpeg = make_jpeg(&filler(21, 4000));
    let mut wav = b"RIFF".to_vec();
    let body = filler(22, 3000);
    wav.extend_from_slice(&((4 + 8 + body.len()) as u32).to_le_bytes());
    wav.extend_from_slice(b"WAVEdata");
    wav.extend_from_slice(&(body.len() as u32).to_le_bytes());
    wav.extend_from_slice(&body);

    let mut img = filler(30, 2048);
    img.extend_from_slice(&jpeg);
    img.extend_from_slice(&filler(31, 2048));
    img.extend_from_slice(&wav);
    img.extend_from_slice(&filler(32, 2048));
    std::fs::write(&img_path, &img).unwrap();

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["jpg".to_string(), "wav".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 2);
    assert_eq!(stats.verified + stats.plausible + stats.truncated, 2);
    let grade = |ext: &str| {
        stats
            .files
            .iter()
            .find(|f| f.ext == ext)
            .map(|f| f.confidence)
            .unwrap()
    };
    assert_eq!(grade("jpg"), Confidence::Verified);
    assert_eq!(grade("wav"), Confidence::Plausible);
    assert_eq!(stats.verified, 1);
    assert_eq!(stats.plausible, 1);
}

// --- Grading negatives ---------------------------------------------------------

fn carve_with(img: &[u8], types: &[&str], max_size: Option<u64>) -> carver::CarveStats {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("disk.img");
    std::fs::write(&p, img).unwrap();
    let source = Source::open(&p).unwrap();
    let sigs =
        signatures::select(&types.iter().map(|t| t.to_string()).collect::<Vec<_>>()).unwrap();
    let opts = CarveOptions {
        output_dir: tmp.path().join("out"),
        start: 0,
        end: None,
        min_size: 0,
        max_size,
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
    carver::carve(&source, &sigs, &opts, &NoProgress).unwrap()
}

/// A JPEG with no EOI has no length the format vouches for, so it is not
/// carved at all, `--max-size` or not: a cap is not a footer. The truncated
/// grade belongs to formats whose structure walk runs into the cap.
#[test]
fn a_jpeg_without_an_eoi_is_not_carved_even_under_a_size_cap() {
    let mut img = filler(40, 1024);
    img.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
    img.extend((0..20_000u32).map(|i| (i % 251) as u8)); // never 0xFF
    let stats = carve_with(&img, &["jpg"], Some(8000));
    assert_eq!(stats.files_recovered, 0);
    assert_eq!(stats.truncated, 0);
}

#[test]
fn a_png_with_a_valid_iend_is_verified() {
    let mut img = filler(41, 1024);
    let png = make_png(&filler(42, 3000));
    img.extend_from_slice(&png);
    img.extend_from_slice(&filler(43, 1024));
    let stats = carve_with(&img, &["png"], None);
    assert_eq!(stats.files_recovered, 1);
    assert_eq!(stats.files[0].size, png.len() as u64);
    assert_eq!(stats.files[0].confidence, carver::Confidence::Verified);
    assert_eq!(
        (stats.verified, stats.plausible, stats.truncated),
        (1, 0, 0)
    );
}

/// A size-field format with no structural validator (WAV) is plausible: the
/// length came from the format, but nothing checked the header beyond its
/// magic.
#[test]
fn a_size_field_format_without_a_validator_is_plausible() {
    let body = filler(44, 2000);
    let mut wav = b"RIFF".to_vec();
    wav.extend_from_slice(&((4 + 8 + body.len()) as u32).to_le_bytes());
    wav.extend_from_slice(b"WAVEdata");
    wav.extend_from_slice(&(body.len() as u32).to_le_bytes());
    wav.extend_from_slice(&body);
    let mut img = filler(45, 1024);
    img.extend_from_slice(&wav);
    img.extend_from_slice(&filler(46, 1024));
    let stats = carve_with(&img, &["wav"], None);
    assert_eq!(stats.files_recovered, 1);
    assert_eq!(stats.files[0].size, wav.len() as u64);
    assert_eq!(stats.files[0].confidence, carver::Confidence::Plausible);
    assert_eq!(
        (stats.verified, stats.plausible, stats.truncated),
        (0, 1, 0)
    );
}

/// The end-of-run counts are the grades, tallied: one of each here.
#[test]
fn end_of_run_counts_match_the_grades() {
    let png = make_png(&filler(47, 1500));
    let body = filler(48, 1500);
    let mut wav = b"RIFF".to_vec();
    wav.extend_from_slice(&((4 + 8 + body.len()) as u32).to_le_bytes());
    wav.extend_from_slice(b"WAVEdata");
    wav.extend_from_slice(&(body.len() as u32).to_le_bytes());
    wav.extend_from_slice(&body);
    // An ISO-BMFF file whose mdat box claims more than the source holds: the
    // box walk runs into the source end and the grade says so.
    let mut mp4 = Vec::new();
    mp4.extend_from_slice(&16u32.to_be_bytes());
    mp4.extend_from_slice(b"ftypisom");
    mp4.extend_from_slice(&0u32.to_be_bytes());
    mp4.extend_from_slice(&(8 + 9000u32).to_be_bytes());
    mp4.extend_from_slice(b"mdat");
    mp4.extend_from_slice(&filler(49, 3000)); // 6000 bytes short of its claim

    let mut img = filler(50, 1024);
    img.extend_from_slice(&png);
    img.extend_from_slice(&filler(51, 1024));
    img.extend_from_slice(&wav);
    img.extend_from_slice(&filler(52, 1024));
    img.extend_from_slice(&mp4);
    let stats = carve_with(&img, &["png", "wav", "mp4"], None);
    assert_eq!(stats.files_recovered, 3);
    let mut grades: Vec<(String, carver::Confidence)> = stats
        .files
        .iter()
        .map(|f| (f.ext.clone(), f.confidence))
        .collect();
    grades.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        grades,
        vec![
            ("mp4".to_string(), carver::Confidence::Truncated),
            ("png".to_string(), carver::Confidence::Verified),
            ("wav".to_string(), carver::Confidence::Plausible),
        ]
    );
    assert_eq!(
        (stats.verified, stats.plausible, stats.truncated),
        (1, 1, 1)
    );
}
