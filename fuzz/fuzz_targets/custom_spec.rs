#![no_main]
//! Custom carver specs from an MCP client: parse, build the signature, and
//! carve a small buffer with it. A malformed spec must be an error, never a
//! panic, and a valid one must never over-read.

mod common;

use libfuzzer_sys::fuzz_target;
use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::{custom, json};

fuzz_target!(|data: &[u8]| {
    // First line: the spec array as JSON; the rest: bytes to carve.
    let Some(nl) = data.iter().position(|&b| b == b'\n') else { return };
    let Ok(text) = std::str::from_utf8(&data[..nl]) else { return };
    let Ok(value) = json::parse(text) else { return };
    let Ok(specs) = custom::from_json(&value) else { return };
    let Some(src) = common::source_of(&data[nl + 1..]) else { return };
    let owned: Vec<_> = specs.iter().map(|s| s.to_signature()).collect();
    let sigs: Vec<&unearth::signatures::Signature> = owned.iter().collect();
    let opts = CarveOptions {
        output_dir: std::env::temp_dir().join("unearth-fuzz-never-written"),
        start: 0,
        end: None,
        min_size: 0,
        max_size: None,
        max_files: Some(16),
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
