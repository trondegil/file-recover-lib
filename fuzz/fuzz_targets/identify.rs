#![no_main]
//! Content-based type identification over arbitrary leading bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = unearth::identify::identify(data);
});
