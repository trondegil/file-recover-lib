#![no_main]
//! Manifest parsing (CSV and JSON reports fed back to `verify`).

use libfuzzer_sys::fuzz_target;
use unearth::manifest;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let _ = manifest::parse(text, false);
    let _ = manifest::parse(text, true);
});
