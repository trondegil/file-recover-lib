//! The carver reads the source in 8 MiB chunks with an overlap. Where a file's
//! structure falls relative to a chunk boundary must make no difference: the
//! same files, byte for byte, come out whatever the layout's offset.

mod common;

use std::collections::BTreeSet;

use unearth::carver::{self, CarveOptions, Confidence, NoProgress};
use unearth::hash;
use unearth::signatures;
use unearth::source::Source;

const MIB: usize = 1024 * 1024;
const CHUNK: usize = 8 * MIB;

/// Bytes that never contain 0xFF (so a JPEG payload holds no marker) and no
/// signature the carver knows in the positions that matter.
fn payload(seed: u32, len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| ((i.wrapping_mul(seed | 1)) % 251) as u8)
        .collect()
}

fn jpeg(p: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(p);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

fn png(p: &[u8]) -> Vec<u8> {
    let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend_from_slice(&13u32.to_be_bytes()); // IHDR length: bytes 8..12
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&64u32.to_be_bytes());
    v.extend_from_slice(&64u32.to_be_bytes());
    v.extend_from_slice(&[8, 6, 0, 0, 0]);
    v.extend_from_slice(&[0, 0, 0, 0]);
    v.extend_from_slice(p);
    v.extend_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
    v
}

fn zip(p: &[u8]) -> Vec<u8> {
    let mut v = vec![0x50, 0x4B, 0x03, 0x04];
    v.extend_from_slice(p);
    let eocd_off = v.len() as u32;
    v.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // EOCD: the last 22 bytes
    let mut rem = [0u8; 18];
    rem[12..16].copy_from_slice(&eocd_off.to_le_bytes());
    v.extend_from_slice(&rem);
    v
}

fn bmff(p: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&16u32.to_be_bytes());
    v.extend_from_slice(b"ftyp");
    v.extend_from_slice(b"isom"); // brand: bytes 8..12
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&((8 + p.len()) as u32).to_be_bytes());
    v.extend_from_slice(b"mdat");
    v.extend_from_slice(p);
    v
}

struct Planted {
    at: usize,
    bytes: Vec<u8>,
}

/// The layout, before any shift: each planted structure sits so that one of
/// the shifts 0, 1, 511, 512, 4095 puts it across the 8 MiB or 16 MiB chunk
/// boundary, and a final JPEG ends exactly at the end of the source.
fn layout() -> Vec<Planted> {
    let z = zip(&payload(3, 3000));
    let f = bmff(&payload(5, 2000));
    let p = png(&payload(7, 2500));
    let end = jpeg(&payload(11, 3500));
    vec![
        // EOCD (last 22 bytes) at 8M-512-11 .. 8M-512+11: across 8 MiB at shift 512.
        Planted {
            at: CHUNK - 512 + 11 - z.len(),
            bytes: z,
        },
        // SOI at 8M-1 .. 8M+2: across 8 MiB at shift 0.
        Planted {
            at: CHUNK - 1,
            bytes: jpeg(&payload(1, 4000)),
        },
        // ftyp brand (bytes 8..12) at 16M-4097 .. 16M-4093: across 16 MiB at shift 4095.
        Planted {
            at: 2 * CHUNK - 4095 - 10,
            bytes: f,
        },
        // IHDR length (bytes 8..12) at 16M-2 .. 16M+2: across 16 MiB at shift 0.
        Planted {
            at: 2 * CHUNK - 10,
            bytes: p,
        },
        // Footer exactly at the end of the 20 MiB source.
        Planted {
            at: 20 * MIB - end.len(),
            bytes: end,
        },
    ]
}

fn image(shift: usize) -> Vec<u8> {
    let mut v = vec![0u8; 20 * MIB + shift];
    for p in layout() {
        v[shift + p.at..shift + p.at + p.bytes.len()].copy_from_slice(&p.bytes);
    }
    v
}

fn opts(out: std::path::PathBuf) -> CarveOptions {
    CarveOptions {
        output_dir: out,
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
    }
}

/// `(sha256, size, grade)` per carved file: the identity of the run.
type Carved = BTreeSet<(String, u64, &'static str)>;

fn carve_all(img: &[u8]) -> (Carved, carver::CarveStats) {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("disk.img");
    std::fs::write(&p, img).unwrap();
    let src = Source::open(&p).unwrap();
    let sigs = signatures::select(&[]).unwrap();
    let stats = carver::carve(&src, &sigs, &opts(tmp.path().join("out")), &NoProgress).unwrap();
    let set = stats
        .files
        .iter()
        .map(|f| (hash::to_hex(&f.sha256), f.size, f.confidence.as_str()))
        .collect();
    (set, stats)
}

#[test]
fn the_carved_set_does_not_depend_on_where_chunk_boundaries_fall() {
    let expected: BTreeSet<(String, u64)> = layout()
        .iter()
        .map(|p| (hash::to_hex(&hash::digest(&p.bytes)), p.bytes.len() as u64))
        .collect();
    assert_eq!(expected.len(), 5);
    let (baseline, _) = carve_all(&image(0));
    for shift in [0usize, 1, 511, 512, 4095] {
        let (got, stats) = carve_all(&image(shift));
        let identities: BTreeSet<(String, u64)> =
            got.iter().map(|(h, s, _)| (h.clone(), *s)).collect();
        assert_eq!(
            identities,
            expected,
            "shift {shift}: carved {:?}",
            stats
                .files
                .iter()
                .map(|f| (&f.ext, f.offset, f.size))
                .collect::<Vec<_>>()
        );
        assert_eq!(stats.files_recovered, 5, "shift {shift}: no duplicates");
        assert_eq!(got, baseline, "shift {shift}: grades differ from shift 0");
        // The footer of the last file sits exactly at the end of the source,
        // which is not a truncation.
        let end = stats
            .files
            .iter()
            .find(|f| f.offset == (shift + layout()[4].at) as u64)
            .expect("the file ending at the source end");
        assert_eq!(end.confidence, Confidence::Verified, "shift {shift}");
        assert_eq!(stats.truncated, 0, "shift {shift}");
    }
}

/// A footer-delimited file cut off by the end of the source has no length
/// the format can vouch for, and the carver does not guess one: nothing is
/// written (the regression test `footer_search_terminates_without_a_footer`
/// pins the same for a JPEG with no EOI anywhere). A structure-walked file
/// cut off the same way is carved to the source end and graded truncated.
#[test]
fn a_file_cut_off_by_the_end_of_the_source_is_truncated_or_left() {
    // JPEG: EOI beyond the source end.
    let mut img = vec![0u8; 3 * MIB];
    let whole = jpeg(&payload(13, 6000));
    let cut = &whole[..whole.len() - 1000];
    let at = img.len() - cut.len();
    img[at..].copy_from_slice(cut);
    let (_, stats) = carve_all(&img);
    assert_eq!(
        stats.files_recovered, 0,
        "no footer, no length, nothing written"
    );

    // ISO-BMFF: the mdat box claims more than the source holds.
    let mut img = vec![0u8; 3 * MIB];
    let whole = bmff(&payload(17, 5000));
    let cut = &whole[..whole.len() - 1000];
    let at = img.len() - cut.len();
    img[at..].copy_from_slice(cut);
    let (_, stats) = carve_all(&img);
    assert_eq!(stats.files_recovered, 1);
    assert_eq!(
        stats.files[0].size,
        cut.len() as u64,
        "carved to the source end"
    );
    assert_eq!(stats.files[0].confidence, Confidence::Truncated);
    assert_eq!(stats.truncated, 1);
    assert_eq!(stats.verified, 0);
}
