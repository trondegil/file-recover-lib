#![no_main]
//! The JSON parser behind the MCP server: arbitrary client bytes must parse or
//! fail, never panic or overflow the stack, and a parsed value must
//! round-trip through the serializer.

use libfuzzer_sys::fuzz_target;
use unearth::json;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(v) = json::parse(text) {
        let again = json::parse(&v.to_string()).expect("serialized JSON must parse");
        assert_eq!(again, v);
        let _ = json::parse(&v.to_pretty_string()).expect("pretty JSON must parse");
    }
});
