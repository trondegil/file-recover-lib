//! Replay every crashing input the fuzzers ever found, so a fixed crash stays
//! fixed. Files live in `tests/fuzz_regressions/<target>/`; the directory a
//! file sits in says which code path it exercised (see `fuzz/README.md`).

use std::path::Path;

use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::recover::{self, RecoverOptions};
use unearth::source::Source;
use unearth::{custom, identify, json, manifest, signatures};

fn inputs(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fuzz_regressions")
        .join(target);
    let Ok(rd) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut out: Vec<(String, Vec<u8>)> = rd
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| {
            (
                e.file_name().to_string_lossy().to_string(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

fn source_of(tmp: &Path, data: &[u8]) -> Option<Source> {
    if data.is_empty() {
        return None;
    }
    let p = tmp.join("input.img");
    std::fs::write(&p, data).unwrap();
    Source::open(&p).ok()
}

fn carve_opts(out: &Path) -> CarveOptions {
    CarveOptions {
        output_dir: out.to_path_buf(),
        start: 0,
        end: None,
        min_size: 0,
        max_size: None,
        max_files: Some(64),
        allow_nested: true,
        validate: true,
        dedup: false,
        progress: false,
        checkpoint: None,
        resume: false,
        organize: false,
        dry_run: true,
        align: 1,
    }
}

#[test]
fn filesystems_regressions() {
    let tmp = tempfile::tempdir().unwrap();
    let opts = RecoverOptions {
        dry_run: true,
        ..RecoverOptions::default()
    };
    for (name, data) in inputs("filesystems") {
        let Some(src) = source_of(tmp.path(), &data) else { continue };
        let out = tmp.path().join("out");
        if let Ok(vols) = recover::detect(&src) {
            for v in vols {
                let _ = v.recover_deleted(&src, &out, &opts);
                let _ = v.free_extents(&src);
            }
        }
        if let Ok(v) = recover::parse_at(&src, 0) {
            let _ = v.recover_deleted(&src, &out, &opts);
        }
        eprintln!("filesystems/{name}: ok");
    }
}

#[test]
fn carve_regressions() {
    let tmp = tempfile::tempdir().unwrap();
    let sigs = signatures::select(&["all".to_string()]).unwrap();
    for (name, data) in inputs("carve") {
        let Some(src) = source_of(tmp.path(), &data) else { continue };
        let _ = carver::carve(&src, &sigs, &carve_opts(&tmp.path().join("out")), &NoProgress);
        eprintln!("carve/{name}: ok");
    }
}

#[test]
fn json_regressions() {
    for (name, data) in inputs("json") {
        if let Ok(text) = std::str::from_utf8(&data) {
            if let Ok(v) = json::parse(text) {
                assert_eq!(json::parse(&v.to_string()).unwrap(), v, "{name}");
            }
        }
    }
}

#[test]
fn custom_spec_regressions() {
    let tmp = tempfile::tempdir().unwrap();
    for (name, data) in inputs("custom_spec") {
        let Some(nl) = data.iter().position(|&b| b == b'\n') else { continue };
        let Ok(text) = std::str::from_utf8(&data[..nl]) else { continue };
        let Ok(value) = json::parse(text) else { continue };
        let Ok(specs) = custom::from_json(&value) else { continue };
        let Some(src) = source_of(tmp.path(), &data[nl + 1..]) else { continue };
        let owned: Vec<_> = specs.iter().map(|s| s.to_signature()).collect();
        let sigs: Vec<&signatures::Signature> = owned.iter().collect();
        let _ = carver::carve(&src, &sigs, &carve_opts(&tmp.path().join("out")), &NoProgress);
        eprintln!("custom_spec/{name}: ok");
    }
}

#[test]
fn identify_and_manifest_regressions() {
    for (_, data) in inputs("identify") {
        let _ = identify::identify(&data);
    }
    for (_, data) in inputs("manifest") {
        if let Ok(text) = std::str::from_utf8(&data) {
            let _ = manifest::parse(text, false);
            let _ = manifest::parse(text, true);
        }
    }
}
