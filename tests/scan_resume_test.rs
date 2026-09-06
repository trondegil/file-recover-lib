//! A carving scan interrupted partway through resumes from its checkpoint,
//! recovering the remaining files without redoing the earlier ones.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};

use unearth::carver::{self, CarveOptions, NoProgress, ProgressSink};
use unearth::source::Source;

const MIB: usize = 1024 * 1024;

/// Cancels the scan after the first chunk, simulating an interruption.
struct CancelAfterFirstChunk {
    updates: AtomicU64,
}

impl ProgressSink for CancelAfterFirstChunk {
    fn update(&self, _scanned: u64) {
        self.updates.fetch_add(1, Ordering::Relaxed);
    }
    fn cancelled(&self) -> bool {
        // The carver issues an initial progress update before the loop, then one
        // per chunk; cancel after the first chunk (the second update).
        self.updates.load(Ordering::Relaxed) >= 2
    }
}

/// Build an image (~18 MiB, larger than several scan chunks) with three JPEGs at
/// the given byte offsets.
fn image_with_jpegs(offsets: &[usize], jpegs: &[Vec<u8>]) -> Vec<u8> {
    image_of(18 * MIB, offsets, jpegs)
}

/// An image of `total` bytes with the given JPEGs planted at their offsets.
fn image_of(total: usize, offsets: &[usize], jpegs: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0u8; total];
    for (off, jpeg) in offsets.iter().zip(jpegs) {
        v[*off..*off + jpeg.len()].copy_from_slice(jpeg);
    }
    v
}

fn opts(out: &std::path::Path, checkpoint: &std::path::Path, resume: bool) -> CarveOptions {
    CarveOptions {
        output_dir: out.to_path_buf(),
        start: 0,
        end: None,
        min_size: 0,
        max_size: None,
        max_files: None,
        allow_nested: false,
        validate: true,
        dedup: false,
        progress: false,
        checkpoint: Some(checkpoint.to_path_buf()),
        resume,
        organize: false,
        dry_run: false,
        align: 1,
    }
}

#[test]
fn interrupted_scan_resumes_from_checkpoint() {
    let jpegs = vec![
        common::jpeg(&vec![0x11u8; 2000]),
        common::jpeg(&vec![0x22u8; 2000]),
        common::jpeg(&vec![0x33u8; 2000]),
    ];
    let offsets = [MIB, 9 * MIB, 17 * MIB];
    let img = image_with_jpegs(&offsets, &jpegs);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let out = tmp.path().join("out");
    let checkpoint = tmp.path().join("scan.checkpoint");
    let source = Source::open(&img_path).unwrap();

    // First run is interrupted after the first 8 MiB chunk: it recovers only the
    // JPEG near the start and writes a checkpoint.
    let sink = CancelAfterFirstChunk {
        updates: AtomicU64::new(0),
    };
    let first =
        carver::carve(&source, &all_sigs(), &opts(&out, &checkpoint, false), &sink).unwrap();
    assert_eq!(first.files_recovered, 1, "only the first JPEG so far");
    assert!(checkpoint.exists(), "checkpoint written on interruption");

    // Resume: the remaining two JPEGs are recovered, and the manifest covers all
    // three (the checkpoint carried the first run's row forward).
    let second = carver::carve(
        &source,
        &all_sigs(),
        &opts(&out, &checkpoint, true),
        &NoProgress,
    )
    .unwrap();
    assert_eq!(second.files_recovered, 3, "all three after resume");
    assert_eq!(second.files.len(), 3, "manifest complete across resume");
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 3);

    // Every planted JPEG came back byte-for-byte.
    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = jpegs.clone();
    originals.sort();
    assert_eq!(recovered, originals);
}

#[test]
fn completed_scan_checkpoint_makes_resume_a_noop() {
    let jpegs = vec![common::jpeg(&vec![0x44u8; 2000])];
    let img = image_with_jpegs(&[2 * MIB], &jpegs);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let out = tmp.path().join("out");
    let checkpoint = tmp.path().join("scan.checkpoint");
    let source = Source::open(&img_path).unwrap();

    // A full run writes a checkpoint at the end (pos == end).
    let full = carver::carve(
        &source,
        &all_sigs(),
        &opts(&out, &checkpoint, false),
        &NoProgress,
    )
    .unwrap();
    assert_eq!(full.files_recovered, 1);

    // Resuming a completed scan scans nothing new and recovers no extra files.
    let again = carver::carve(
        &source,
        &all_sigs(),
        &opts(&out, &checkpoint, true),
        &NoProgress,
    )
    .unwrap();
    assert_eq!(
        again.files_recovered, 1,
        "resume after completion is a no-op"
    );
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);
}

fn all_sigs() -> Vec<&'static unearth::signatures::Signature<'static>> {
    unearth::signatures::select(&[]).unwrap()
}

// --- A resumed scan equals an uninterrupted one -------------------------------

/// Cancels after `chunks` chunks have been scanned.
struct CancelAfter {
    chunks: u64,
    updates: AtomicU64,
}

impl ProgressSink for CancelAfter {
    fn update(&self, _scanned: u64) {
        self.updates.fetch_add(1, Ordering::Relaxed);
    }
    fn cancelled(&self) -> bool {
        self.updates.load(Ordering::Relaxed) > self.chunks
    }
}

/// What a run produced: the output files by content, the duplicate count,
/// and the manifest rows.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    files: Vec<Vec<u8>>,
    duplicates: u64,
    rows: Vec<(String, u64, u64, String, &'static str)>,
}

fn outcome(stats: &carver::CarveStats, out: &std::path::Path) -> Outcome {
    let mut files: Vec<Vec<u8>> = std::fs::read_dir(out)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    files.sort();
    let mut rows: Vec<_> = stats
        .files
        .iter()
        .map(|f| {
            (
                f.name.clone(),
                f.offset,
                f.size,
                unearth::hash::to_hex(&f.sha256),
                f.confidence.as_str(),
            )
        })
        .collect();
    rows.sort();
    Outcome {
        files,
        duplicates: stats.duplicates,
        rows,
    }
}

fn dedup_opts(out: &std::path::Path, checkpoint: &std::path::Path, resume: bool) -> CarveOptions {
    CarveOptions {
        dedup: true,
        ..opts(out, checkpoint, resume)
    }
}

#[test]
fn a_resumed_scan_matches_an_uninterrupted_one() {
    // Duplicates on both sides of the chunk boundaries, and one file that
    // spans the first checkpoint position (8 MiB).
    let a = common::jpeg(&vec![0x11u8; 2000]);
    let d = common::jpeg(&vec![0x44u8; 2500]);
    let jpegs = vec![
        a.clone(),
        a.clone(),
        common::jpeg(&vec![0x33u8; 3000]),
        d.clone(),
        d.clone(),
    ];
    // Four chunks (8, 8, 8, and 2 MiB), so a cancel after chunk 1, 2, or 3
    // always leaves work behind.
    const TOTAL: usize = 26 * MIB;
    let offsets = [MIB, 5 * MIB, 8 * MIB - 1000, 12 * MIB, 17 * MIB];
    let img = image_of(TOTAL, &offsets, &jpegs);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let source = Source::open(&img_path).unwrap();

    let straight_out = tmp.path().join("straight");
    let straight_cp = tmp.path().join("straight.checkpoint");
    let straight = carver::carve(
        &source,
        &all_sigs(),
        &dedup_opts(&straight_out, &straight_cp, false),
        &NoProgress,
    )
    .unwrap();
    let want = outcome(&straight, &straight_out);
    assert_eq!(want.files.len(), 3, "three distinct files");
    assert_eq!(want.duplicates, 2);
    assert_eq!(want.rows.len(), 3);

    for chunks in 1..=3u64 {
        let out = tmp.path().join(format!("resumed{chunks}"));
        let cp = tmp.path().join(format!("resumed{chunks}.checkpoint"));
        let first = carver::carve(
            &source,
            &all_sigs(),
            &dedup_opts(&out, &cp, false),
            &CancelAfter {
                chunks,
                updates: AtomicU64::new(0),
            },
        )
        .unwrap();
        assert!(
            first.bytes_scanned < TOTAL as u64,
            "cancel after {chunks} chunk(s) must stop before the end: {}",
            first.bytes_scanned
        );
        let second = carver::carve(
            &source,
            &all_sigs(),
            &dedup_opts(&out, &cp, true),
            &NoProgress,
        )
        .unwrap();
        assert_eq!(
            outcome(&second, &out),
            want,
            "cancel after {chunks} chunk(s): resumed run differs"
        );
    }
}
