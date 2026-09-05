#![no_main]
//! The carver with every built-in signature: magic matching, every per-format
//! length walk, and the validators, in dry-run mode so nothing is written.

mod common;

use libfuzzer_sys::fuzz_target;
use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::signatures;

fuzz_target!(|data: &[u8]| {
    let Some(src) = common::source_of(data) else { return };
    let sigs = signatures::select(&["all".to_string()]).unwrap();
    let opts = CarveOptions {
        output_dir: std::env::temp_dir().join("unearth-fuzz-never-written"),
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
    };
    let _ = carver::carve(&src, &sigs, &opts, &NoProgress);
});
