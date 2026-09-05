//! A tiny, dependency-free JSON value type with a parser and serializer.
//!
//! The rest of the crate writes JSON by hand where the shape is fixed (reports,
//! summaries, `info --json`). The MCP server, however, has to *parse* arbitrary
//! client requests, so this module provides a small but complete JSON
//! implementation in keeping with the project's no-extra-dependency approach.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// A parsed JSON value. Objects preserve nothing about key order (a `BTreeMap`
/// keeps them sorted), which is fine for JSON-RPC.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    /// Look up a key in an object value.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) if *n >= 0.0 && n.is_finite() => Some(*n as u64),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => {
                if n.fract() == 0.0 && n.is_finite() && n.abs() < 1e15 {
                    let _ = write!(out, "{}", *n as i64);
                } else {
                    let _ = write!(out, "{n}");
                }
            }
            Json::Str(s) => write_escaped(s, out),
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Json::Obj(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_escaped(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

impl Json {
    /// Serialize to indented, human-readable JSON: two-space indent, one
    /// element or member per line, keys in sorted order, trailing newline.
    /// Used for files people read and diff (the test-corpus manifests).
    pub fn to_pretty_string(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out.push('\n');
        out
    }

    fn write_pretty(&self, out: &mut String, depth: usize) {
        fn indent(out: &mut String, depth: usize) {
            for _ in 0..depth {
                out.push_str("  ");
            }
        }
        match self {
            Json::Arr(a) if !a.is_empty() => {
                out.push_str("[\n");
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push_str(",\n");
                    }
                    indent(out, depth + 1);
                    v.write_pretty(out, depth + 1);
                }
                out.push('\n');
                indent(out, depth);
                out.push(']');
            }
            Json::Obj(m) if !m.is_empty() => {
                out.push_str("{\n");
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push_str(",\n");
                    }
                    indent(out, depth + 1);
                    write_escaped(k, out);
                    out.push_str(": ");
                    v.write_pretty(out, depth + 1);
                }
                out.push('\n');
                indent(out, depth);
                out.push('}');
            }
            other => other.write(out),
        }
    }
}

impl std::fmt::Display for Json {
    /// Serialize to compact JSON.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = String::new();
        self.write(&mut out);
        f.write_str(&out)
    }
}

fn write_escaped(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parse a JSON document. Returns an error message on malformed input.
pub fn parse(input: &str) -> Result<Json, String> {
    let mut p = Parser {
        chars: input.chars().collect(),
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.chars.len() {
        return Err("trailing characters after JSON value".to_string());
    }
    Ok(v)
}

/// Nesting deeper than this is refused. Each level costs a stack frame, so an
/// unbounded depth lets a request a few thousand levels deep overflow the
/// stack and kill the MCP server; 128 is far beyond any real request.
const MAX_DEPTH: usize = 128;

struct Parser {
    chars: Vec<char>,
    pos: usize,
    /// Current nesting of arrays and objects.
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            Some('{') => self.nested(Parser::object),
            Some('[') => self.nested(Parser::array),
            Some('"') => Ok(Json::Str(self.string()?)),
            Some('t') | Some('f') => self.boolean(),
            Some('n') => self.null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(format!("unexpected character '{c}'")),
            None => Err("unexpected end of input".to_string()),
        }
    }

    /// Parse a container one level down, refusing to go past `MAX_DEPTH`.
    fn nested(&mut self, f: fn(&mut Parser) -> Result<Json, String>) -> Result<Json, String> {
        if self.depth >= MAX_DEPTH {
            return Err(format!("nesting deeper than {MAX_DEPTH} levels"));
        }
        self.depth += 1;
        let r = f(self);
        self.depth -= 1;
        r
    }

    fn expect(&mut self, word: &str) -> Result<(), String> {
        for want in word.chars() {
            if self.next() != Some(want) {
                return Err(format!("expected '{word}'"));
            }
        }
        Ok(())
    }

    fn null(&mut self) -> Result<Json, String> {
        self.expect("null")?;
        Ok(Json::Null)
    }

    fn boolean(&mut self) -> Result<Json, String> {
        if self.peek() == Some('t') {
            self.expect("true")?;
            Ok(Json::Bool(true))
        } else {
            self.expect("false")?;
            Ok(Json::Bool(false))
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
        {
            self.pos += 1;
        }
        let s: String = self.chars[start..self.pos].iter().collect();
        s.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("invalid number '{s}'"))
    }

    fn string(&mut self) -> Result<String, String> {
        if self.next() != Some('"') {
            return Err("expected string".to_string());
        }
        let mut out = String::new();
        loop {
            match self.next() {
                None => return Err("unterminated string".to_string()),
                Some('"') => return Ok(out),
                Some('\\') => match self.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('b') => out.push('\x08'),
                    Some('f') => out.push('\x0c'),
                    Some('u') => out.push(self.unicode_escape()?),
                    _ => return Err("invalid escape".to_string()),
                },
                Some(c) => out.push(c),
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let mut code = 0u32;
        for _ in 0..4 {
            let c = self.next().ok_or("truncated \\u escape")?;
            let d = c.to_digit(16).ok_or("invalid \\u escape")?;
            code = code * 16 + d;
        }
        // Surrogate pairs are not handled; map them to the replacement char.
        char::from_u32(code).ok_or_else(|| "invalid unicode code point".to_string())
    }

    fn array(&mut self) -> Result<Json, String> {
        self.pos += 1; // consume '['
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(Json::Arr(out));
        }
        loop {
            out.push(self.value()?);
            self.skip_ws();
            match self.next() {
                Some(',') => self.skip_ws(),
                Some(']') => return Ok(Json::Arr(out)),
                _ => return Err("expected ',' or ']'".to_string()),
            }
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.pos += 1; // consume '{'
        let mut out = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(Json::Obj(out));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            if self.next() != Some(':') {
                return Err("expected ':' after object key".to_string());
            }
            let val = self.value()?;
            out.insert(key, val);
            self.skip_ws();
            match self.next() {
                Some(',') => {}
                Some('}') => return Ok(Json::Obj(out)),
                _ => return Err("expected ',' or '}'".to_string()),
            }
        }
    }
}

/// Convenience for building an object from key/value pairs.
pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Convenience for a string value.
pub fn s(v: impl Into<String>) -> Json {
    Json::Str(v.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let cases = [
            "null",
            "true",
            "false",
            "42",
            "-7",
            "3.5",
            "\"hi\"",
            "[]",
            "{}",
            "[1,2,3]",
            "{\"a\":1,\"b\":[true,null,\"x\"]}",
        ];
        for c in cases {
            let v = parse(c).unwrap();
            assert_eq!(v.to_string(), c, "round-trip {c}");
        }
    }

    #[test]
    fn parses_escapes_and_whitespace() {
        let v = parse("  { \"k\" : \"a\\nb\\t\\\"c\\\"\" } ").unwrap();
        assert_eq!(v.get("k").unwrap().as_str(), Some("a\nb\t\"c\""));
    }

    #[test]
    fn unicode_escape() {
        let v = parse("\"\\u0041\\u00e9\"").unwrap();
        assert_eq!(v.as_str(), Some("Aé"));
    }

    #[test]
    fn accessors() {
        let v = parse("{\"n\":10,\"b\":true,\"s\":\"x\",\"a\":[1,2]}").unwrap();
        assert_eq!(v.get("n").unwrap().as_u64(), Some(10));
        assert_eq!(v.get("b").unwrap().as_bool(), Some(true));
        assert_eq!(v.get("s").unwrap().as_str(), Some("x"));
        assert_eq!(v.get("a").unwrap().as_array().unwrap().len(), 2);
        assert_eq!(v.get("missing"), None);
    }

    #[test]
    fn refuses_absurd_nesting_without_overflowing() {
        let deep = "[".repeat(100_000) + &"]".repeat(100_000);
        let err = parse(&deep).unwrap_err();
        assert!(err.contains("nesting deeper"), "{err}");
        let nested_objects = "{\"a\":".repeat(5_000) + "1" + &"}".repeat(5_000);
        assert!(parse(&nested_objects).is_err());
        // The limit itself is fine.
        let ok = "[".repeat(128) + &"]".repeat(128);
        assert!(parse(&ok).is_ok());
        let too_deep = "[".repeat(129) + &"]".repeat(129);
        assert!(parse(&too_deep).is_err());
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse("{").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("nul").is_err());
        assert!(parse("1 2").is_err());
        assert!(parse("\"unterminated").is_err());
    }

    #[test]
    fn escapes_control_chars_when_writing() {
        let j = Json::Str("tab\tnewline\n".to_string());
        assert_eq!(j.to_string(), "\"tab\\tnewline\\n\"");
    }

    #[test]
    fn pretty_prints_and_round_trips() {
        let v = parse("{\"b\":[1,{\"x\":null}],\"a\":\"s\",\"e\":[],\"o\":{}}").unwrap();
        let pretty = v.to_pretty_string();
        assert_eq!(
            pretty,
            "{\n  \"a\": \"s\",\n  \"b\": [\n    1,\n    {\n      \"x\": null\n    }\n  ],\n  \"e\": [],\n  \"o\": {}\n}\n"
        );
        assert_eq!(parse(&pretty).unwrap(), v);
    }
}
