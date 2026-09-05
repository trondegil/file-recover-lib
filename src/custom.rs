//! Runtime-injected **custom carvers**.
//!
//! Beyond the built-in [`crate::signatures::SIGNATURES`] table, a caller can
//! describe extra carvers at run time — a magic number plus a declarative rule
//! for how long each match is — and have `scan` use them without a rebuild.
//! This is exposed through the MCP `scan` tool's `custom_carvers` argument (see
//! [`crate::mcp`]).
//!
//! To preserve the crate's central guarantee — *never emit a wrong length* — a
//! custom carver cannot carry arbitrary length logic. It must resolve to one of
//! a few declarative strategies, each of which computes an **exact** size and is
//! bounds-checked against the scan limit exactly like a built-in extent:
//!
//! * `fixed` — every match is exactly `size` bytes.
//! * `size_field` — the size is an unsigned integer stored in the header at
//!   `offset`, `width` bits wide (8/16/32/64), little- or big-endian, taken as
//!   `value * mul + add`.
//! * `footer` — the file ends `trailing` bytes after a terminator byte sequence
//!   (`marker`), found by scanning forward within the size cap.
//!
//! A spec is validated up front and only then materialised. Because the size is
//! always computed by the same bounds-checked machinery as the built-ins, the
//! worst a malformed or over-eager spec can do is fail to match or produce a
//! plausibly-sized carve — it can never over-read the source or emit a length
//! past the cap.
//!
//! Specs are parsed into an owned [`Spec`], and [`Spec::to_signature`] lends a
//! [`Signature`] that borrows from it for the duration of one scan. Nothing is
//! leaked: an earlier version gave every custom carver a `'static` lifetime by
//! leaking it, so a long-running agent session that started many scans grew
//! without bound.

use crate::json::Json;
use crate::signatures::{Extent, Signature};

/// Upper bound on a custom carver's `max_size`. Keeps `file_start + max_size`
/// from overflowing in the carver and bounds a runaway carve; 1 TiB is far
/// beyond any real file yet nowhere near `u64` overflow for any real source.
pub const MAX_SIZE_CAP: u64 = 1 << 40;

/// The declarative length rule of a custom carver, owned (pre-leak).
#[derive(Clone, Debug, PartialEq)]
pub enum Length {
    /// Every match is exactly this many bytes.
    Fixed(u64),
    /// Size = `value * mul + add`, where `value` is the unsigned integer at
    /// `offset`, `width` bits wide, in the chosen byte order.
    SizeField {
        offset: usize,
        width: u8,
        big_endian: bool,
        mul: u64,
        add: u64,
    },
    /// The file ends `trailing` bytes after the terminator `marker`.
    Footer { marker: Vec<u8>, trailing: u64 },
}

/// A validated custom-carver spec, owned so the error path leaks nothing.
#[derive(Clone, Debug, PartialEq)]
pub struct Spec {
    pub name: String,
    pub ext: String,
    pub magic: Vec<u8>,
    pub magic_offset: u64,
    pub secondary: Option<(usize, Vec<u8>)>,
    pub max_size: u64,
    pub length: Length,
}

impl Spec {
    /// Parse and validate one spec from its JSON object, returning a descriptive
    /// error (never a panic) on any malformed field. Nothing is leaked here.
    pub fn parse(item: &Json) -> Result<Spec, String> {
        let name = req_str(item, "name")?.to_string();
        let ext = req_str(item, "ext")?.to_string();
        validate_ext(&ext)?;

        let magic = parse_hex(req_str(item, "magic")?).map_err(|e| format!("magic: {e}"))?;
        if magic.is_empty() {
            return Err("magic must have at least one byte".into());
        }

        let magic_offset = opt_u64(item, "magic_offset").unwrap_or(0);

        let max_size = opt_u64(item, "max_size").ok_or("max_size is required")?;
        if max_size == 0 || max_size > MAX_SIZE_CAP {
            return Err(format!("max_size must be between 1 and {MAX_SIZE_CAP}"));
        }

        let secondary = match item.get("secondary") {
            Some(sec) => {
                let offset = opt_u64(sec, "offset").ok_or("secondary.offset is required")? as usize;
                let bytes = parse_hex(req_str(sec, "bytes")?)
                    .map_err(|e| format!("secondary.bytes: {e}"))?;
                if bytes.is_empty() {
                    return Err("secondary.bytes must be non-empty".into());
                }
                Some((offset, bytes))
            }
            None => None,
        };

        let length = parse_length(item.get("length").ok_or("length is required")?)?;

        Ok(Spec {
            name,
            ext,
            magic,
            magic_offset,
            secondary,
            max_size,
            length,
        })
    }

    /// Materialise the spec as a `'static` [`Signature`] for the carve path,
    /// leaking its owned buffers so they live for the rest of the process.
    /// Build the carver signature for this spec, borrowing its buffers. The
    /// spec must outlive the scan that uses the signature, and nothing is
    /// leaked: when the scan's job drops its specs, the carver goes with them.
    pub fn to_signature(&self) -> Signature<'_> {
        let extent = match &self.length {
            Length::Fixed(size) => Extent::Fixed { size: *size },
            Length::SizeField {
                offset,
                width,
                big_endian,
                mul,
                add,
            } => Extent::SizeField {
                offset: *offset,
                width: *width,
                big_endian: *big_endian,
                mul: *mul,
                add: *add,
            },
            Length::Footer { marker, trailing } => Extent::Footer {
                marker,
                trailing: *trailing,
            },
        };
        Signature {
            name: &self.name,
            ext: &self.ext,
            magic: &self.magic,
            magic_offset: self.magic_offset,
            secondary: self
                .secondary
                .as_ref()
                .map(|(off, bytes)| (*off, bytes.as_slice())),
            extent,
            max_size: self.max_size,
        }
    }
}

/// Parse an array of custom-carver specs (as passed to the MCP `scan` tool).
/// Each becomes a signature with [`Spec::to_signature`] for as long as the
/// spec lives. Returns a descriptive error identifying the offending entry.
pub fn from_json(value: &Json) -> Result<Vec<Spec>, String> {
    let arr = value.as_array().ok_or("custom_carvers must be an array")?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let spec = Spec::parse(item).map_err(|e| format!("custom_carvers[{i}]: {e}"))?;
        out.push(spec);
    }
    Ok(out)
}

/// Parse the `length` object into a [`Length`], validating the strategy fields.
fn parse_length(l: &Json) -> Result<Length, String> {
    match req_str(l, "strategy")? {
        "fixed" => {
            let size = opt_u64(l, "size").ok_or("fixed length needs 'size'")?;
            if size == 0 {
                return Err("fixed 'size' must be greater than 0".into());
            }
            Ok(Length::Fixed(size))
        }
        "size_field" => {
            let offset = opt_u64(l, "offset").ok_or("size_field needs 'offset'")? as usize;
            let width = opt_u64(l, "width").ok_or("size_field needs 'width'")?;
            if !matches!(width, 8 | 16 | 32 | 64) {
                return Err("size_field 'width' must be 8, 16, 32, or 64".into());
            }
            let big_endian = match opt_str(l, "endian").unwrap_or("le") {
                "le" | "little" => false,
                "be" | "big" => true,
                other => return Err(format!("endian must be 'le' or 'be', got '{other}'")),
            };
            let mul = opt_u64(l, "mul").unwrap_or(1);
            if mul == 0 {
                return Err("size_field 'mul' must be greater than 0".into());
            }
            let add = opt_u64(l, "add").unwrap_or(0);
            Ok(Length::SizeField {
                offset,
                width: width as u8,
                big_endian,
                mul,
                add,
            })
        }
        "footer" => {
            let marker = parse_hex(req_str(l, "marker")?).map_err(|e| format!("marker: {e}"))?;
            if marker.is_empty() {
                return Err("footer needs a non-empty 'marker'".into());
            }
            let trailing = opt_u64(l, "trailing").unwrap_or(0);
            Ok(Length::Footer { marker, trailing })
        }
        other => Err(format!("unknown length strategy '{other}'")),
    }
}

/// The extension names carved files; reject anything that could escape the
/// output directory or is unreasonable, keeping it to a short filesystem-safe
/// token.
fn validate_ext(ext: &str) -> Result<(), String> {
    if ext.is_empty() || ext.len() > 16 {
        return Err("ext must be 1..=16 characters".into());
    }
    if !ext
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("ext may only contain ASCII letters, digits, '_' or '-'".into());
    }
    Ok(())
}

/// Decode a hex string into bytes, ignoring ASCII whitespace and `:` separators
/// and an optional `0x` prefix, so `"89 50 4E"`, `"89:50:4e"`, and `"0x89504E"`
/// all work.
fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let mut cleaned: String = s
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();
    if let Some(rest) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        cleaned = rest.to_string();
    }
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    if cleaned.len() % 2 != 0 {
        return Err("hex string must have an even number of digits".into());
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex digit '{}'", c as char)),
    }
}

fn req_str<'a>(obj: &'a Json, key: &str) -> Result<&'a str, String> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("'{key}' is required and must be a string"))
}

fn opt_str<'a>(obj: &'a Json, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(|v| v.as_str())
}

fn opt_u64(obj: &Json, key: &str) -> Option<u64> {
    obj.get(key).and_then(|v| v.as_u64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn spec(src: &str) -> Result<Spec, String> {
        Spec::parse(&json::parse(src).unwrap())
    }

    #[test]
    fn parses_a_fixed_carver() {
        let s = spec(
            r#"{"name":"Widget","ext":"wdg","magic":"57 44 47 31","max_size":4096,
                "length":{"strategy":"fixed","size":512}}"#,
        )
        .unwrap();
        assert_eq!(s.name, "Widget");
        assert_eq!(s.ext, "wdg");
        assert_eq!(s.magic, vec![0x57, 0x44, 0x47, 0x31]);
        assert_eq!(s.magic_offset, 0);
        assert_eq!(s.max_size, 4096);
        assert_eq!(s.length, Length::Fixed(512));
    }

    #[test]
    fn parses_a_size_field_carver_with_defaults_and_secondary() {
        let s = spec(
            r#"{"name":"Blob","ext":"blob","magic":"0xBLOBBAD","magic_offset":4,
                "secondary":{"offset":8,"bytes":"AA BB"},"max_size":1000000,
                "length":{"strategy":"size_field","offset":4,"width":32}}"#,
        );
        // "BLOBBAD" is not valid hex, so this must be an error, not a panic.
        assert!(s.is_err());

        let s = spec(
            r#"{"name":"Blob","ext":"blob","magic":"CA FE","magic_offset":4,
                "secondary":{"offset":8,"bytes":"AA BB"},"max_size":1000000,
                "length":{"strategy":"size_field","offset":4,"width":32,"endian":"be","mul":2,"add":16}}"#,
        )
        .unwrap();
        assert_eq!(s.magic_offset, 4);
        assert_eq!(s.secondary, Some((8, vec![0xAA, 0xBB])));
        assert_eq!(
            s.length,
            Length::SizeField {
                offset: 4,
                width: 32,
                big_endian: true,
                mul: 2,
                add: 16
            }
        );
        // size_field defaults: little-endian, mul 1, add 0.
        let d = spec(
            r#"{"name":"D","ext":"d","magic":"01 02","max_size":100,
                "length":{"strategy":"size_field","offset":0,"width":16}}"#,
        )
        .unwrap();
        assert_eq!(
            d.length,
            Length::SizeField {
                offset: 0,
                width: 16,
                big_endian: false,
                mul: 1,
                add: 0
            }
        );
    }

    #[test]
    fn parses_a_footer_carver() {
        let s = spec(
            r#"{"name":"Doc","ext":"doc9","magic":"25 50","max_size":100,
                "length":{"strategy":"footer","marker":"0A 25 25 45 4F 46","trailing":1}}"#,
        )
        .unwrap();
        assert_eq!(
            s.length,
            Length::Footer {
                marker: vec![0x0A, 0x25, 0x25, 0x45, 0x4F, 0x46],
                trailing: 1
            }
        );
    }

    #[test]
    fn rejects_bad_specs() {
        // Missing max_size.
        assert!(spec(
            r#"{"name":"x","ext":"x","magic":"AB","length":{"strategy":"fixed","size":1}}"#
        )
        .is_err());
        // Empty magic.
        assert!(spec(
            r#"{"name":"x","ext":"x","magic":"","max_size":10,"length":{"strategy":"fixed","size":1}}"#
        )
        .is_err());
        // max_size over the cap.
        let over = format!(
            r#"{{"name":"x","ext":"x","magic":"AB","max_size":{},"length":{{"strategy":"fixed","size":1}}}}"#,
            MAX_SIZE_CAP + 1
        );
        assert!(spec(&over).is_err());
        // Bad width.
        assert!(spec(
            r#"{"name":"x","ext":"x","magic":"AB","max_size":10,"length":{"strategy":"size_field","offset":0,"width":24}}"#
        )
        .is_err());
        // Unknown strategy.
        assert!(spec(
            r#"{"name":"x","ext":"x","magic":"AB","max_size":10,"length":{"strategy":"bogus"}}"#
        )
        .is_err());
        // Ext with a path separator.
        assert!(spec(
            r#"{"name":"x","ext":"../etc","magic":"AB","max_size":10,"length":{"strategy":"fixed","size":1}}"#
        )
        .is_err());
        // Odd-length hex magic.
        assert!(spec(
            r#"{"name":"x","ext":"x","magic":"ABC","max_size":10,"length":{"strategy":"fixed","size":1}}"#
        )
        .is_err());
    }

    #[test]
    fn from_json_reports_offending_index() {
        let arr = json::parse(
            r#"[{"name":"ok","ext":"ok","magic":"AB CD","max_size":10,"length":{"strategy":"fixed","size":4}},
               {"name":"bad","ext":"bad","magic":"AB","length":{"strategy":"fixed","size":4}}]"#,
        )
        .unwrap();
        let err = from_json(&arr).unwrap_err();
        assert!(err.contains("custom_carvers[1]"), "got: {err}");
    }

    #[test]
    fn to_signature_carries_fields_through() {
        let owned = spec(
            r#"{"name":"Widget","ext":"wdg","magic":"57 44 47 31","max_size":4096,
                "length":{"strategy":"fixed","size":512}}"#,
        )
        .unwrap();
        let sig = owned.to_signature();
        assert_eq!(sig.ext, "wdg");
        assert_eq!(sig.magic, &[0x57, 0x44, 0x47, 0x31]);
        assert!(matches!(sig.extent, Extent::Fixed { size: 512 }));
        assert_eq!(sig.max_size, 4096);
    }

    #[test]
    fn hex_parsing_accepts_separators_and_prefix() {
        assert_eq!(parse_hex("89 50 4E").unwrap(), vec![0x89, 0x50, 0x4E]);
        assert_eq!(parse_hex("89:50:4e").unwrap(), vec![0x89, 0x50, 0x4E]);
        assert_eq!(parse_hex("0x89504E").unwrap(), vec![0x89, 0x50, 0x4E]);
        assert!(parse_hex("8G").is_err());
    }
}
