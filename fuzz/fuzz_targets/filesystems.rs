#![no_main]
//! Every filesystem parser, driven by volume detection and a forced parse at
//! offset 0, then a dry-run undelete of whatever was detected. Must never
//! panic, whatever the bytes.

mod common;

use libfuzzer_sys::fuzz_target;
use unearth::recover::{self, RecoverOptions};

fuzz_target!(|data: &[u8]| {
    let Some(src) = common::source_of(data) else { return };
    let opts = RecoverOptions {
        dry_run: true,
        ..RecoverOptions::default()
    };
    let out = std::env::temp_dir().join("unearth-fuzz-never-written");
    if let Ok(vols) = recover::detect(&src) {
        for v in vols {
            let _ = v.recover_deleted(&src, &out, &opts);
            let _ = v.free_extents(&src);
        }
    }
    if let Ok(v) = recover::parse_at(&src, 0) {
        let _ = v.recover_deleted(&src, &out, &opts);
    }
});
