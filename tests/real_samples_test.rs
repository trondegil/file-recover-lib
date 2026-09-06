//! Real files, made by real tools (see `tests/samples/make.sh`), planted in
//! filler and carved back: one file per sample, same length, same SHA-256,
//! and the grade the carver's validators can give it. The hashes here are
//! those of the committed samples; regenerate the samples and this table
//! together.

use std::path::Path;

use unearth::carver::{self, CarveOptions, Confidence, NoProgress};
use unearth::hash;
use unearth::signatures;
use unearth::source::Source;

/// `(file, carved extension, sha256, grade)`. Formats with a structural
/// validator in `validate.rs` (JPEG, PNG, GIF, PDF, SQLite) are verified;
/// the rest have a length from their own structure but no header check
/// beyond the magic, so they are plausible.
const SAMPLES: &[(&str, &str, &str, Confidence)] = &[
    (
        "sample.jpg",
        "jpg",
        "6be0c69660e7dd23de46903961f74c8b018935f11fb4b440327383258ef31416",
        Confidence::Verified,
    ),
    (
        "sample.png",
        "png",
        "799a2db5792a18edf671a2e42a07971b4bc0d786571073b7b1bd2c8f55f6025a",
        Confidence::Verified,
    ),
    (
        "sample.gif",
        "gif",
        "834b195d489526946ec529e263d714d7d644eccff582c0c11275a7ad201f0809",
        Confidence::Verified,
    ),
    (
        "sample.pdf",
        "pdf",
        "f70e14b07dfaa0ad07ef58d0d222ef8e5b5407aad80b9ba312258b02e6d22879",
        Confidence::Verified,
    ),
    (
        "sample.zip",
        "zip",
        "e8413a353f3bf9a5cb9b0a5813798c90d0626e8dae2dfb433a4686788f70faf6",
        Confidence::Plausible,
    ),
    (
        "sample.wav",
        "wav",
        "1ac72639e36df2878c3afd33f0b52b48cb1276891b830ba5e2a5eb292cdc185c",
        Confidence::Plausible,
    ),
    (
        "sample.mp4",
        "mp4",
        "e835b0caae30c86b8d6c6f6c92c2858db754e2dcd25f9041ca3d553ea3c54bcd",
        Confidence::Plausible,
    ),
    (
        "sample.sqlite",
        "sqlite",
        "27a860473646c52fccdae1e39a089681656b546b6591308604a033937ba544d1",
        Confidence::Verified,
    ),
    (
        "sample.cfbf",
        "ole",
        "1843c77004c23b3f6354b43c7b6bf4dd7104fd6495367fbde6a095d667a4d2c4",
        Confidence::Plausible,
    ),
];

fn filler(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i + seed) % 251) as u8).collect()
}

#[test]
fn every_committed_sample_matches_its_recorded_hash() {
    for (file, _, sha, _) in SAMPLES {
        let bytes = std::fs::read(Path::new("tests/samples").join(file)).unwrap();
        assert!(bytes.len() <= 24 * 1024, "{file} is over 24 KiB");
        assert_eq!(
            hash::to_hex(&hash::digest(&bytes)),
            *sha,
            "{file} changed; rerun make.sh and update the table"
        );
    }
}

#[test]
fn each_real_sample_is_carved_whole_with_its_grade() {
    let sigs = signatures::select(&[]).unwrap();
    for (i, (file, ext, sha, grade)) in SAMPLES.iter().enumerate() {
        let bytes = std::fs::read(Path::new("tests/samples").join(file)).unwrap();
        // The trailing filler must not start with CR or LF: a PDF's footer
        // allowance takes a line ending after `%%EOF`, and a following LF
        // is indistinguishable from the file's own. Seeds from 100 keep the
        // first trailing byte clear of both.
        let mut img = filler(2048, i);
        img.extend_from_slice(&bytes);
        img.extend_from_slice(&filler(2048, 100 + i));

        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("disk.img");
        std::fs::write(&p, &img).unwrap();
        let src = Source::open(&p).unwrap();
        let out = tmp.path().join("out");
        let opts = CarveOptions {
            output_dir: out.clone(),
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
        let stats = carver::carve(&src, &sigs, &opts, &NoProgress).unwrap();
        let carved: Vec<_> = stats
            .files
            .iter()
            .map(|f| (f.ext.clone(), f.offset, f.size, f.confidence))
            .collect();
        assert_eq!(stats.files_recovered, 1, "{file}: carved {carved:?}");
        let f = &stats.files[0];
        assert_eq!(f.ext, *ext, "{file}: {carved:?}");
        assert_eq!(f.offset, 2048, "{file}");
        assert_eq!(f.size, bytes.len() as u64, "{file}: length");
        assert_eq!(hash::to_hex(&f.sha256), *sha, "{file}: bytes");
        assert_eq!(f.confidence, *grade, "{file}: grade");
        let written = std::fs::read(out.join(&f.name)).unwrap();
        assert_eq!(written, bytes, "{file}: bytes on disk");
    }
}
