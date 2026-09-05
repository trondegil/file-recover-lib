//! Real-image corpus test (ROADMAP step 1).
//!
//! Runs `undelete` and `scan` against disk images that were formatted and
//! populated by real operating systems (see `corpus/README.md`), and measures
//! *recall*: the fraction of the documented deleted files that came back
//! byte-for-byte. Each image carries a recorded baseline; the test fails if
//! recall on any image drops below it, so a regression from 96% to 90% is
//! visible rather than hidden behind a pass/fail.
//!
//! The images live outside git. They are looked up in `corpus/images/` (or
//! `$UNEARTH_CORPUS_DIR`) and, when missing, downloaded from the release
//! tarball pinned in `corpus/corpus.lock`. Without images the test prints a
//! notice and passes, unless `UNEARTH_CORPUS_REQUIRED=1` (CI) makes that a
//! failure.
//!
//! Environment:
//! - `UNEARTH_CORPUS_DIR`      where the images are (default `corpus/images`)
//! - `UNEARTH_CORPUS_REQUIRED` fail instead of skipping when images are missing
//! - `UNEARTH_CORPUS_OFFLINE`  never download
//! - `UNEARTH_CORPUS_RECORD`   write measured recall back as the new baseline
//! - `UNEARTH_CORPUS_ONLY`     substring filter on image names

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use unearth::hash;
use unearth::json::{self, Json};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_unearth")
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false)
}

// --- manifests ------------------------------------------------------------------

struct ImageEntry {
    name: String,
    file: String,
    size: u64,
    sha256: String,
    expected: PathBuf,
}

struct Lock {
    tarball_url: Option<String>,
    tarball_sha256: Option<String>,
    images: Vec<ImageEntry>,
}

fn str_field(j: &Json, key: &str) -> Option<String> {
    j.get(key).and_then(Json::as_str).map(str::to_string)
}

fn read_lock() -> Lock {
    let path = repo().join("corpus/corpus.lock");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let j = json::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let tarball = j.get("tarball");
    let images = j
        .get("images")
        .and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .map(|i| ImageEntry {
            name: str_field(i, "name").expect("image name"),
            file: str_field(i, "file").expect("image file"),
            size: i.get("size").and_then(Json::as_u64).expect("image size"),
            sha256: str_field(i, "sha256").expect("image sha256"),
            expected: repo().join(str_field(i, "expected").expect("expected path")),
        })
        .collect();
    Lock {
        tarball_url: tarball.and_then(|t| str_field(t, "url")),
        tarball_sha256: tarball.and_then(|t| str_field(t, "sha256")),
        images,
    }
}

struct ExpectedFile {
    path: String,
    sha256: String,
    /// Modification time (Unix seconds) the file had on the volume, when the
    /// image was built with times recorded.
    mtime: Option<u64>,
    intact: bool,
    carvable: bool,
}

struct Expected {
    doc: Json,
    filesystem: String,
    files: Vec<ExpectedFile>,
    baseline_undelete: Option<f64>,
    baseline_scan: Option<f64>,
}

fn read_expected(path: &Path) -> Expected {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc = json::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let files = doc
        .get("files")
        .and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .map(|f| ExpectedFile {
            path: str_field(f, "path").expect("file path"),
            sha256: str_field(f, "sha256").expect("file sha256"),
            mtime: f.get("mtime").and_then(Json::as_u64),
            intact: str_field(f, "expect").as_deref() == Some("intact"),
            carvable: f.get("carvable").and_then(Json::as_bool).unwrap_or(false),
        })
        .collect();
    let num = |k: &str| match doc.get("baseline").and_then(|b| b.get(k)) {
        Some(Json::Num(n)) => Some(*n),
        _ => None,
    };
    Expected {
        baseline_undelete: num("undelete"),
        baseline_scan: num("scan"),
        filesystem: str_field(&doc, "filesystem").unwrap_or_default(),
        doc,
        files,
    }
}

// --- files on disk ----------------------------------------------------------------

fn sha256_of(path: &Path) -> String {
    let mut f = fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut h = hash::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    hash::to_hex(&h.finalize())
}

/// A recovered file: path relative to the output directory, its SHA-256, and
/// its modification time as Unix seconds.
struct Recovered {
    path: String,
    sha256: String,
    mtime: Option<u64>,
}

/// Every regular file under `dir`.
fn hash_tree(dir: &Path) -> Vec<Recovered> {
    let mut out = Vec::new();
    fn walk(base: &Path, dir: &Path, out: &mut Vec<Recovered>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(base, &p, out);
            } else if p.is_file() {
                let rel = p
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let mtime = fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                out.push(Recovered {
                    path: rel,
                    sha256: sha256_of(&p),
                    mtime,
                });
            }
        }
    }
    walk(dir, dir, &mut out);
    out
}

/// Whether a recovered file's modification time matches the one recorded for
/// it. NTFS, ext4, and HFS+ store UTC, so 2 seconds of slack covers rounding.
/// FAT and exFAT store local time with no zone, and the tool reads it as UTC,
/// so a difference that is a whole number of quarter hours (up to 14 hours)
/// is the building machine's zone, not a recovery error.
fn mtime_matches(fs: &str, got: u64, want: u64) -> bool {
    let delta = got.abs_diff(want);
    if delta <= 2 {
        return true;
    }
    if matches!(fs, "fat32" | "exfat") && delta <= 14 * 3600 {
        let rem = delta % 900;
        return rem <= 2 || rem >= 898;
    }
    false
}

// --- corpus acquisition -----------------------------------------------------------------

fn images_dir() -> PathBuf {
    std::env::var_os("UNEARTH_CORPUS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo().join("corpus/images"))
}

/// Download and unpack the release tarball into `dir`. Uses the system `curl`
/// and `tar` so the crate itself stays free of network code. Returns an error
/// message rather than panicking, so an offline developer machine just skips.
fn fetch_tarball(lock: &Lock, dir: &Path) -> Result<(), String> {
    let url = lock
        .tarball_url
        .as_deref()
        .ok_or("lock has no tarball url")?;
    let want = lock
        .tarball_sha256
        .as_deref()
        .ok_or("lock has no tarball sha256")?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tgz = dir.join("corpus.tar.gz");
    eprintln!("corpus: downloading {url}");
    let st = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(&tgz)
        .arg(url)
        .status()
        .map_err(|e| format!("running curl: {e}"))?;
    if !st.success() {
        return Err(format!("curl failed with {st}"));
    }
    let got = sha256_of(&tgz);
    if got != want {
        let _ = fs::remove_file(&tgz);
        return Err(format!("tarball sha256 {got} != locked {want}"));
    }
    let st = Command::new("tar")
        .arg("-xzf")
        .arg(&tgz)
        .arg("-C")
        .arg(dir)
        .status()
        .map_err(|e| format!("running tar: {e}"))?;
    let _ = fs::remove_file(&tgz);
    if !st.success() {
        return Err(format!("tar failed with {st}"));
    }
    Ok(())
}

// --- measuring one image --------------------------------------------------------------

struct Measurement {
    expected_intact: usize,
    undelete_hits: usize,
    /// (files whose recorded time was checked, files whose time was right)
    times_checked: usize,
    times_right: usize,
    time_failures: Vec<String>,
    undelete_maybe_hits: usize,
    undelete_name_hits: usize,
    expected_carvable: usize,
    scan_hits: usize,
    undelete_recall: f64,
    scan_recall: f64,
}

fn ratio(hits: usize, total: usize) -> f64 {
    if total == 0 {
        1.0
    } else {
        hits as f64 / total as f64
    }
}

fn run(args: &[&str]) -> std::process::Output {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("run unearth");
    assert!(
        out.status.success(),
        "unearth {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn measure(image: &Path, expected: &Expected, work: &Path) -> Measurement {
    let undelete_dir = work.join("undelete");
    let scan_dir = work.join("scan");
    run(&[
        "undelete",
        image.to_str().unwrap(),
        "-o",
        undelete_dir.to_str().unwrap(),
    ]);
    run(&[
        "scan",
        image.to_str().unwrap(),
        "-o",
        scan_dir.to_str().unwrap(),
        "--quiet",
    ]);

    let undeleted = hash_tree(&undelete_dir);
    let undeleted_hashes: HashSet<&str> = undeleted.iter().map(|r| r.sha256.as_str()).collect();
    let carved: HashSet<String> = hash_tree(&scan_dir).into_iter().map(|r| r.sha256).collect();

    // A name match is informational: FAT loses the first character of a short
    // name to the deletion marker, and the output may sit under `volume_N/`.
    let name_matches = |want: &str| {
        let want_name = want.rsplit('/').next().unwrap_or(want).to_lowercase();
        undeleted.iter().any(|r| {
            let p = &r.path;
            let got = p.rsplit('/').next().unwrap_or(p).to_lowercase();
            // Compare by character: names are not ASCII.
            got == want_name
                || (got.chars().count() == want_name.chars().count()
                    && got.chars().skip(1).eq(want_name.chars().skip(1)))
        })
    };

    let mut m = Measurement {
        expected_intact: 0,
        undelete_hits: 0,
        times_checked: 0,
        times_right: 0,
        time_failures: Vec::new(),
        undelete_maybe_hits: 0,
        undelete_name_hits: 0,
        expected_carvable: 0,
        scan_hits: 0,
        undelete_recall: 0.0,
        scan_recall: 0.0,
    };
    for f in &expected.files {
        let hit = undeleted_hashes.contains(f.sha256.as_str());
        // A file that came back by name must also have its time back.
        if let (true, Some(want)) = (hit, f.mtime) {
            let got = undeleted
                .iter()
                .find(|r| r.sha256 == f.sha256)
                .and_then(|r| r.mtime);
            m.times_checked += 1;
            match got {
                Some(got) if mtime_matches(&expected.filesystem, got, want) => m.times_right += 1,
                Some(got) => m.time_failures.push(format!(
                    "{}: mtime {got} (recorded {want}, off by {}s)",
                    f.path,
                    got as i64 - want as i64
                )),
                None => m
                    .time_failures
                    .push(format!("{}: mtime unreadable", f.path)),
            }
        }
        if f.intact {
            m.expected_intact += 1;
            m.undelete_hits += hit as usize;
            if f.carvable {
                m.expected_carvable += 1;
                m.scan_hits += carved.contains(&f.sha256) as usize;
            }
        } else {
            m.undelete_maybe_hits += hit as usize;
        }
        m.undelete_name_hits += name_matches(&f.path) as usize;
    }
    m.undelete_recall = ratio(m.undelete_hits, m.expected_intact);
    m.scan_recall = ratio(m.scan_hits, m.expected_carvable);
    m
}

fn record_baseline(path: &Path, expected: &Expected, m: &Measurement) {
    let mut doc = expected.doc.clone();
    if let Json::Obj(map) = &mut doc {
        let mut b = BTreeMap::new();
        b.insert("undelete".to_string(), Json::Num(round4(m.undelete_recall)));
        b.insert("scan".to_string(), Json::Num(round4(m.scan_recall)));
        map.insert("baseline".to_string(), Json::Obj(b));
    }
    fs::write(path, doc.to_pretty_string()).unwrap();
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

fn pct(x: f64) -> String {
    format!("{:5.1}%", x * 100.0)
}

fn baseline_str(b: Option<f64>) -> String {
    b.map(pct).unwrap_or_else(|| "   -  ".to_string())
}

// --- the test -------------------------------------------------------------------------

/// Ignored by default because it needs the images and takes a minute or two in
/// release mode (far longer in debug). Run it with
/// `cargo test --release --test corpus_test -- --ignored --nocapture`.
#[test]
#[ignore]
fn corpus_recall() {
    let lock = read_lock();
    let required = env_flag("UNEARTH_CORPUS_REQUIRED");
    let record = env_flag("UNEARTH_CORPUS_RECORD");
    let only = std::env::var("UNEARTH_CORPUS_ONLY").unwrap_or_default();
    if lock.images.is_empty() {
        eprintln!("corpus: corpus.lock lists no images; nothing to do");
        assert!(!required, "corpus required but corpus.lock lists no images");
        return;
    }

    let dir = images_dir();
    let missing: Vec<&ImageEntry> = lock
        .images
        .iter()
        .filter(|i| !dir.join(&i.file).is_file())
        .collect();
    if !missing.is_empty() && !env_flag("UNEARTH_CORPUS_OFFLINE") {
        if let Err(e) = fetch_tarball(&lock, &dir) {
            eprintln!("corpus: could not download images: {e}");
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let mut failures: Vec<String> = Vec::new();
    let mut skipped = 0usize;
    let mut improved = 0usize;
    eprintln!();
    eprintln!(
        "{:<34} {:>7} {:>9} {:>8} | {:>7} {:>9} {:>8}   notes",
        "image", "deleted", "undelete", "baseline", "carvable", "scan", "baseline"
    );
    for entry in &lock.images {
        if !only.is_empty() && !entry.name.contains(&only) {
            continue;
        }
        let image = dir.join(&entry.file);
        if !image.is_file() {
            skipped += 1;
            if required {
                failures.push(format!("{}: image {} missing", entry.name, image.display()));
            }
            continue;
        }
        let size = image.metadata().unwrap().len();
        if size != entry.size {
            failures.push(format!(
                "{}: image size {size} != locked {}",
                entry.name, entry.size
            ));
            continue;
        }
        let sha = sha256_of(&image);
        if sha != entry.sha256 {
            failures.push(format!(
                "{}: image sha256 {sha} != locked {} (stale or corrupt image)",
                entry.name, entry.sha256
            ));
            continue;
        }

        let expected = read_expected(&entry.expected);
        let work = tmp.path().join(&entry.name);
        let m = measure(&image, &expected, &work);

        let mut notes = Vec::new();
        if m.times_checked > 0 {
            notes.push(format!("times {}/{}", m.times_right, m.times_checked));
        }
        if m.undelete_maybe_hits > 0 {
            notes.push(format!(
                "+{} overwritten-but-recovered",
                m.undelete_maybe_hits
            ));
        }
        if m.undelete_name_hits < expected.files.len() {
            notes.push(format!(
                "names {}/{}",
                m.undelete_name_hits,
                expected.files.len()
            ));
        }
        let mut status = String::new();
        match (expected.baseline_undelete, expected.baseline_scan) {
            // Recording replaces the baseline, so nothing to compare against.
            _ if record => {}
            (Some(bu), Some(bs)) => {
                // Baselines are stored to four decimals, so allow that much slack.
                const TOL: f64 = 5e-4;
                let below = |got: f64, base: f64| got + TOL < base;
                if below(m.undelete_recall, bu) {
                    status = format!(
                        "undelete recall fell {} -> {}",
                        pct(bu),
                        pct(m.undelete_recall)
                    );
                } else if below(m.scan_recall, bs) {
                    status = format!("scan recall fell {} -> {}", pct(bs), pct(m.scan_recall));
                } else if m.undelete_recall > bu + TOL || m.scan_recall > bs + TOL {
                    improved += 1;
                    notes.push("improved; re-record to ratchet".to_string());
                }
            }
            _ => {
                status = "no baseline recorded (run with UNEARTH_CORPUS_RECORD=1)".to_string();
            }
        }
        if record {
            record_baseline(&entry.expected, &expected, &m);
            notes.push("recorded".to_string());
        }
        eprintln!(
            "{:<34} {:>7} {:>4}/{:<4} {:>8} | {:>8} {:>4}/{:<4} {:>8}   {}{}",
            entry.name,
            expected.files.len(),
            m.undelete_hits,
            m.expected_intact,
            baseline_str(expected.baseline_undelete),
            m.expected_carvable,
            m.scan_hits,
            m.expected_carvable,
            baseline_str(expected.baseline_scan),
            notes.join("; "),
            if status.is_empty() {
                String::new()
            } else {
                format!("  FAIL: {status}")
            }
        );
        if !status.is_empty() {
            failures.push(format!("{}: {status}", entry.name));
        }
        for tf in &m.time_failures {
            failures.push(format!("{}: {tf}", entry.name));
        }
    }
    // Every "yes" under undelete in the feature matrix must have at least one
    // real image behind it that recovers something by metadata.
    let mut ran: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
    for entry in &lock.images {
        if let Ok(text) = fs::read_to_string(&entry.expected) {
            if let Ok(doc) = json::parse(&text) {
                let fs_name = str_field(&doc, "filesystem").unwrap_or_default();
                let recall = match doc.get("baseline").and_then(|b| b.get("undelete")) {
                    Some(Json::Num(n)) => *n,
                    _ => 0.0,
                };
                let best = ran.entry(fs_name).or_insert(0.0);
                if recall > *best {
                    *best = recall;
                }
            }
        }
    }
    for cap in unearth::recover::capability_matrix() {
        if cap.undelete != unearth::recover::Support::Yes {
            continue;
        }
        // Matrix names to corpus filesystem tags.
        let tags: &[&str] = match cap.filesystem {
            "FAT12/16/32" => &["fat32", "fat16", "fat12"],
            "exFAT" => &["exfat"],
            "NTFS" => &["ntfs"],
            "ext2/3/4" => &["ext4", "ext3", "ext2"],
            "HFS+/HFSX" => &["hfsplus"],
            other => panic!("no corpus tag for matrix row {other}"),
        };
        let best = tags
            .iter()
            .filter_map(|t| ran.get(*t))
            .cloned()
            .fold(0.0, f64::max);
        if best <= 0.0 {
            failures.push(format!(
                "{}: the feature matrix says undelete is supported, but no corpus image with a recorded undelete baseline above zero backs it",
                cap.filesystem
            ));
        }
    }

    eprintln!();
    if skipped > 0 {
        eprintln!(
            "corpus: {skipped} image(s) not present under {} (set UNEARTH_CORPUS_REQUIRED=1 to fail)",
            dir.display()
        );
    }
    if improved > 0 {
        eprintln!("corpus: {improved} image(s) beat their baseline; run with UNEARTH_CORPUS_RECORD=1 to ratchet");
    }
    assert!(
        failures.is_empty(),
        "corpus regressions:\n  {}",
        failures.join("\n  ")
    );
}
