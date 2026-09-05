//! End-to-end test for runtime-injected custom carvers. A synthetic "WDG1"
//! file — a 4-byte magic followed by a little-endian u32 total-size field and a
//! body — is embedded in an image, and a custom carver described purely as JSON
//! (as an MCP client would inject via `scan`'s `custom_carvers`) recovers it
//! byte-for-byte at the exact declared length.

use std::io::Write;

use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::source::Source;
use unearth::{custom, json};

fn filler(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// A "WDG1" file: magic, a little-endian u32 holding the total file length at
/// offset 4, then `body_len` bytes of payload.
fn make_widget(body_len: usize) -> Vec<u8> {
    let total = 8 + body_len;
    let mut v = Vec::with_capacity(total);
    v.extend_from_slice(b"WDG1");
    v.extend_from_slice(&(total as u32).to_le_bytes());
    v.extend(filler(42, body_len));
    v
}

#[test]
fn recovers_a_file_via_injected_custom_carver() {
    let widget = make_widget(92); // 100-byte file total
    assert_eq!(widget.len(), 100);

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&filler(1, 500)).unwrap();
    img.write_all(&widget).unwrap();
    img.write_all(&filler(2, 500)).unwrap();
    img.flush().unwrap();
    drop(img);

    // The carver spec exactly as it would arrive over MCP: magic "WDG1"
    // (57 44 47 31), total size from a little-endian u32 at offset 4.
    let spec = json::parse(
        r#"[{"name":"Widget","ext":"wdg","magic":"57 44 47 31","max_size":1048576,
            "length":{"strategy":"size_field","offset":4,"width":32,"endian":"le"}}]"#,
    )
    .unwrap();
    let specs = custom::from_json(&spec).expect("valid custom carver");
    assert_eq!(specs.len(), 1);
    let owned: Vec<_> = specs.iter().map(|c| c.to_signature()).collect();
    assert_eq!(owned[0].ext, "wdg");
    let sigs: Vec<&unearth::signatures::Signature> = owned.iter().collect();

    let source = Source::open(&img_path).unwrap();
    let opts = CarveOptions {
        output_dir: out_dir.clone(),
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
    let stats = carver::carve(&source, &sigs, &opts, &NoProgress).unwrap();
    assert_eq!(stats.files_recovered, 1, "one widget recovered");

    let recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], widget, "recovered bytes match exactly");

    // The recovered file carries the custom extension.
    let name = std::fs::read_dir(&out_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .into_string()
        .unwrap();
    assert!(name.ends_with(".wdg"), "extension is .wdg, got {name}");
}
