//! Lightweight structural validation of carved files.
//!
//! Signature carving matches only a handful of magic bytes, so a magic that
//! occurs by coincidence inside unrelated data produces a bogus "file". These
//! validators inspect a recovered file's header for the fixed structural fields
//! the format guarantees and reject candidates that cannot be real.
//!
//! They are deliberately **conservative**: a check returns [`Validity::Invalid`]
//! only on a definite structural violation, and returns [`Validity::Unknown`]
//! (which the carver accepts) whenever there is not enough data or no validator
//! exists for the type. The goal is to drop obvious garbage without ever
//! discarding a genuine file.

use crate::signatures::Signature;

/// Verdict for a carved file's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// The header matches the format's fixed structure.
    Valid,
    /// The header violates the format; the magic match is almost certainly
    /// coincidental.
    Invalid,
    /// Not enough information to decide. Treated as acceptable.
    Unknown,
}

impl Validity {
    /// Whether the carver should keep a file with this verdict. Only a definite
    /// [`Validity::Invalid`] is rejected.
    pub fn accept(self) -> bool {
        !matches!(self, Validity::Invalid)
    }
}

/// Number of leading bytes the validators need to inspect. The carver reads at
/// most this many bytes of each candidate before deciding.
pub const HEADER_LEN: usize = 64;

/// Validate the leading bytes of a carved file of type `sig`.
///
/// `data` holds up to [`HEADER_LEN`] bytes from the start of the candidate file
/// (fewer if the file is shorter).
pub fn validate(sig: &Signature, data: &[u8]) -> Validity {
    match sig.ext {
        "jpg" => jpeg(data),
        "png" => png(data),
        "gif" => gif(data),
        "bmp" => bmp(data),
        "sqlite" => sqlite(data),
        "elf" => elf(data),
        "emf" => emf(data),
        "mid" => midi(data),
        "pdf" => pdf(data),
        "tif" => tiff(data),
        "cab" => cab(data),
        "wasm" => wasm(data),
        "dex" => dex(data),
        "psd" => psd(data),
        "ogg" => ogg(data),
        "flv" => flv(data),
        "tar" => tar(data),
        "cpio" => cpio(data),
        "squashfs" => squashfs(data),
        // No structural check for the remaining types; their length strategy
        // (footer search, atom walk, etc.) already rejects most spurious hits.
        _ => Validity::Unknown,
    }
}

/// Photoshop: the `8BPS` magic is followed by a version of 1 (PSD) or 2 (PSB)
/// and six reserved bytes that must be zero.
fn psd(d: &[u8]) -> Validity {
    if d.len() < 12 {
        return Validity::Unknown;
    }
    let ver = u16::from_be_bytes([d[4], d[5]]);
    if (ver == 1 || ver == 2) && d[6..12].iter().all(|&b| b == 0) {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// Ogg: the `OggS` capture pattern is followed by a stream-structure version of
/// zero (the only version defined).
fn ogg(d: &[u8]) -> Validity {
    if d.len() < 5 {
        return Validity::Unknown;
    }
    if d[4] == 0 {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// FLV: after the `FLV\x01` magic, the type-flags byte uses only the audio (bit
/// 0) and video (bit 2) bits, and the data offset is the fixed 9-byte header.
fn flv(d: &[u8]) -> Validity {
    if d.len() < 9 {
        return Validity::Unknown;
    }
    let data_offset = u32::from_be_bytes([d[5], d[6], d[7], d[8]]);
    if d[4] & 0xFA == 0 && data_offset == 9 {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// PDF: the `%PDF` magic is followed by a `-N.M` version (e.g. `%PDF-1.7`).
fn pdf(d: &[u8]) -> Validity {
    if d.len() < 8 {
        return Validity::Unknown;
    }
    if d[4] == b'-' && d[5].is_ascii_digit() && d[6] == b'.' && d[7].is_ascii_digit() {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// TIFF: the byte order and version (42 classic, 43 BigTIFF) come from the
/// magic; the first-IFD offset must point past the header.
fn tiff(d: &[u8]) -> Validity {
    if d.len() < 8 {
        return Validity::Unknown;
    }
    let le = d[0] == b'I';
    let u16a = |a: usize| {
        let b = [d[a], d[a + 1]];
        if le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }
    };
    match u16a(2) {
        42 => {
            let b = [d[4], d[5], d[6], d[7]];
            let ifd = if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            };
            if ifd >= 8 {
                Validity::Valid
            } else {
                Validity::Invalid
            }
        }
        43 => {
            if d.len() < 16 {
                return Validity::Unknown;
            }
            let b: [u8; 8] = d[8..16].try_into().unwrap();
            let ifd = if le {
                u64::from_le_bytes(b)
            } else {
                u64::from_be_bytes(b)
            };
            // Offset size is 8 bytes, the next u16 is 0, and the IFD follows the
            // 16-byte BigTIFF header.
            if u16a(4) == 8 && u16a(6) == 0 && ifd >= 16 {
                Validity::Valid
            } else {
                Validity::Invalid
            }
        }
        _ => Validity::Invalid,
    }
}

/// Microsoft Cabinet: the three reserved header fields must be zero and the
/// major version must be 1.
fn cab(d: &[u8]) -> Validity {
    if d.len() < 26 {
        return Validity::Unknown;
    }
    let res = |o: usize| u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]);
    if res(4) == 0 && res(12) == 0 && res(20) == 0 && d[25] == 1 {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// WebAssembly: the `\0asm` magic is followed by a little-endian version of 1.
fn wasm(d: &[u8]) -> Validity {
    if d.len() < 8 {
        return Validity::Unknown;
    }
    if u32::from_le_bytes([d[4], d[5], d[6], d[7]]) == 1 {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// Android DEX: the `dex\n` magic is followed by a 3-digit version and a NUL.
fn dex(d: &[u8]) -> Validity {
    if d.len() < 8 {
        return Validity::Unknown;
    }
    if d[4].is_ascii_digit() && d[5].is_ascii_digit() && d[6].is_ascii_digit() && d[7] == 0 {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// JPEG: the SOI magic `FF D8 FF` is immediately followed by a marker code. A
/// real stream's first marker is an APPn/DQT/DHT/COM/SOFn — never padding
/// (`0xFF`), a stuffed zero (`0x00`), or another SOI/EOI.
fn jpeg(d: &[u8]) -> Validity {
    if d.len() < 4 {
        return Validity::Unknown;
    }
    let marker = d[3];
    if (0xC0..=0xFE).contains(&marker) && marker != 0xD8 && marker != 0xD9 {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// PNG: the 8-byte signature must be followed by an `IHDR` chunk — a length of
/// exactly 13, the `IHDR` type, then non-zero width and height (big-endian).
fn png(d: &[u8]) -> Validity {
    if d.len() < 24 {
        return Validity::Unknown;
    }
    if u32::from_be_bytes([d[8], d[9], d[10], d[11]]) != 13 || &d[12..16] != b"IHDR" {
        return Validity::Invalid;
    }
    let w = u32::from_be_bytes([d[16], d[17], d[18], d[19]]);
    let h = u32::from_be_bytes([d[20], d[21], d[22], d[23]]);
    if w == 0 || h == 0 {
        return Validity::Invalid;
    }
    Validity::Valid
}

/// GIF: after the 6-byte `GIF87a`/`GIF89a` header comes the logical screen
/// descriptor, whose canvas width and height (little-endian) are non-zero.
fn gif(d: &[u8]) -> Validity {
    if d.len() < 10 {
        return Validity::Unknown;
    }
    let w = u16::from_le_bytes([d[6], d[7]]);
    let h = u16::from_le_bytes([d[8], d[9]]);
    if w == 0 || h == 0 {
        return Validity::Invalid;
    }
    Validity::Valid
}

/// BMP: past the 14-byte file header sits the DIB header, whose first field is
/// its own size — one of a small set of standard values.
fn bmp(d: &[u8]) -> Validity {
    if d.len() < 18 {
        return Validity::Unknown;
    }
    // BITMAPCOREHEADER(12), BITMAPINFOHEADER(40), V2(52), V3(56), V4(108), V5(124).
    const KNOWN: [u32; 6] = [12, 40, 52, 56, 108, 124];
    let dib = u32::from_le_bytes([d[14], d[15], d[16], d[17]]);
    if KNOWN.contains(&dib) {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// SQLite: the database header has several bytes fixed by the file format —
/// the read/write format versions are 1 or 2, and the payload fractions are the
/// constants 64/32/32. A coincidental "SQLite format 3\0" almost never has all
/// of these right.
fn sqlite(d: &[u8]) -> Validity {
    if d.len() < 24 {
        return Validity::Unknown;
    }
    let write_ver = d[18];
    let read_ver = d[19];
    if !(1..=2).contains(&write_ver) || !(1..=2).contains(&read_ver) {
        return Validity::Invalid;
    }
    if d[21] != 64 || d[22] != 32 || d[23] != 32 {
        return Validity::Invalid;
    }
    Validity::Valid
}

/// ELF: after the `\x7FELF` magic, the identification bytes are tightly
/// constrained — class is 32/64-bit (1/2), data encoding is LE/BE (1/2), and
/// the ELF version is 1.
fn elf(d: &[u8]) -> Validity {
    if d.len() < 7 {
        return Validity::Unknown;
    }
    if !(1..=2).contains(&d[4]) || !(1..=2).contains(&d[5]) || d[6] != 1 {
        return Validity::Invalid;
    }
    Validity::Valid
}

/// EMF: the file begins with an `EMR_HEADER` record — record type `1`
/// (little-endian u32 at offset 0) and a record size of at least 88 bytes.
/// (The " EMF" signature that anchors the magic lives at offset 40.)
fn emf(d: &[u8]) -> Validity {
    if d.len() < 8 {
        return Validity::Unknown;
    }
    let itype = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
    let nsize = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
    if itype != 1 || nsize < 88 {
        return Validity::Invalid;
    }
    Validity::Valid
}

/// MIDI: the `MThd` header chunk has a big-endian length of exactly 6, a format
/// of 0, 1, or 2, and at least one track.
fn midi(d: &[u8]) -> Validity {
    if d.len() < 12 {
        return Validity::Unknown;
    }
    if u32::from_be_bytes([d[4], d[5], d[6], d[7]]) != 6 {
        return Validity::Invalid;
    }
    let format = u16::from_be_bytes([d[8], d[9]]);
    let ntrks = u16::from_be_bytes([d[10], d[11]]);
    if format > 2 || ntrks == 0 {
        return Validity::Invalid;
    }
    Validity::Valid
}

/// tar: the first 512-byte header carries the `ustar` magic at offset 257 and a
/// header checksum at offset 148 (octal) equal to the sum of all header bytes
/// with the checksum field taken as ASCII spaces. The full 512-byte header is
/// needed, so shorter input is `Unknown` (accepted) — the carver's length walk
/// verifies the checksum of every header anyway.
fn tar(d: &[u8]) -> Validity {
    if d.len() < 512 {
        return Validity::Unknown;
    }
    if &d[257..262] != b"ustar" {
        return Validity::Invalid;
    }
    let stored = match tar_octal(&d[148..156]) {
        Some(v) => v,
        None => return Validity::Invalid,
    };
    let sum: u64 = d[..512]
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                0x20
            } else {
                b as u64
            }
        })
        .sum();
    if sum == stored {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// SquashFS: the version-4 superblock has major version 4 (offset 28) and a
/// block size (offset 12) that equals `1 << block_log` (offset 22).
fn squashfs(d: &[u8]) -> Validity {
    if d.len() < 30 {
        return Validity::Unknown;
    }
    let block_size = u32::from_le_bytes([d[12], d[13], d[14], d[15]]);
    let block_log = u16::from_le_bytes([d[22], d[23]]);
    let s_major = u16::from_le_bytes([d[28], d[29]]);
    if s_major == 4 && (12..=20).contains(&block_log) && block_size == 1u32 << block_log {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// cpio (newc): the 6-byte magic is `070701` or `070702`, and the header fields
/// that follow are 8-hex-digit ASCII. Check every byte from the end of the magic
/// to the end of the 110-byte header (or the data we have) is an ASCII hex digit.
fn cpio(d: &[u8]) -> Validity {
    if d.len() < 14 {
        return Validity::Unknown;
    }
    if &d[0..5] != b"07070" || (d[5] != b'1' && d[5] != b'2') {
        return Validity::Invalid;
    }
    let end = d.len().min(110);
    if d[6..end].iter().all(|b| b.is_ascii_hexdigit()) {
        Validity::Valid
    } else {
        Validity::Invalid
    }
}

/// Parse a tar octal numeric field (space/NUL padded); an all-padding field is 0.
fn tar_octal(field: &[u8]) -> Option<u64> {
    let digits: Vec<u8> = field.iter().copied().filter(|&b| b != 0).collect();
    let text = std::str::from_utf8(&digits).ok()?.trim();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::{select, Signature};

    fn sig(ext: &str) -> &'static Signature<'static> {
        let all = select(&[]).unwrap();
        all.into_iter().find(|s| s.ext == ext).unwrap()
    }

    #[test]
    fn jpeg_marker_check() {
        assert_eq!(
            validate(sig("jpg"), &[0xFF, 0xD8, 0xFF, 0xE0]),
            Validity::Valid
        );
        assert_eq!(
            validate(sig("jpg"), &[0xFF, 0xD8, 0xFF, 0xDB]),
            Validity::Valid
        );
        // 0x00, padding 0xFF, and a stray SOI/EOI are all bogus first markers.
        assert_eq!(
            validate(sig("jpg"), &[0xFF, 0xD8, 0xFF, 0x00]),
            Validity::Invalid
        );
        assert_eq!(
            validate(sig("jpg"), &[0xFF, 0xD8, 0xFF, 0xFF]),
            Validity::Invalid
        );
        assert_eq!(
            validate(sig("jpg"), &[0xFF, 0xD8, 0xFF, 0xD9]),
            Validity::Invalid
        );
        // Too short to judge => accepted.
        assert_eq!(validate(sig("jpg"), &[0xFF, 0xD8]), Validity::Unknown);
    }

    #[test]
    fn png_ihdr_check() {
        let mut good = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        good.extend_from_slice(&13u32.to_be_bytes());
        good.extend_from_slice(b"IHDR");
        good.extend_from_slice(&64u32.to_be_bytes()); // width
        good.extend_from_slice(&64u32.to_be_bytes()); // height
        assert_eq!(validate(sig("png"), &good), Validity::Valid);

        // Random bytes where IHDR should be => rejected.
        let mut bad = good.clone();
        bad[12..16].copy_from_slice(b"junk");
        assert_eq!(validate(sig("png"), &bad), Validity::Invalid);

        // Zero dimensions => rejected.
        let mut zero = good.clone();
        zero[16..20].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(validate(sig("png"), &zero), Validity::Invalid);
    }

    #[test]
    fn bmp_dib_size_check() {
        let mut v = vec![b'B', b'M'];
        v.extend_from_slice(&100u32.to_le_bytes()); // file size
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        v.extend_from_slice(&54u32.to_le_bytes()); // pixel offset
        v.extend_from_slice(&40u32.to_le_bytes()); // DIB header size
        assert_eq!(validate(sig("bmp"), &v), Validity::Valid);

        let mut bad = v.clone();
        bad[14..18].copy_from_slice(&999u32.to_le_bytes());
        assert_eq!(validate(sig("bmp"), &bad), Validity::Invalid);
    }

    #[test]
    fn sqlite_fixed_fields_check() {
        let mut v = vec![0u8; 24];
        v[0..16].copy_from_slice(b"SQLite format 3\0");
        v[18] = 1;
        v[19] = 1;
        v[21] = 64;
        v[22] = 32;
        v[23] = 32;
        assert_eq!(validate(sig("sqlite"), &v), Validity::Valid);

        // All-zero fixed fields (a coincidental magic) => rejected.
        let mut bad = v.clone();
        bad[21] = 0;
        assert_eq!(validate(sig("sqlite"), &bad), Validity::Invalid);
    }

    #[test]
    fn elf_identification_check() {
        // \x7FELF + class=2 (64-bit), data=1 (LE), version=1.
        assert_eq!(
            validate(sig("elf"), &[0x7F, b'E', b'L', b'F', 2, 1, 1]),
            Validity::Valid
        );
        // Bad class / data / version are all rejected.
        assert_eq!(
            validate(sig("elf"), &[0x7F, b'E', b'L', b'F', 9, 1, 1]),
            Validity::Invalid
        );
        assert_eq!(
            validate(sig("elf"), &[0x7F, b'E', b'L', b'F', 2, 1, 2]),
            Validity::Invalid
        );
        assert_eq!(
            validate(sig("elf"), &[0x7F, b'E', b'L', b'F']),
            Validity::Unknown
        );
    }

    #[test]
    fn emf_header_check() {
        let mut v = vec![0u8; 52];
        v[0..4].copy_from_slice(&1u32.to_le_bytes()); // EMR_HEADER
        v[4..8].copy_from_slice(&88u32.to_le_bytes()); // nSize
        assert_eq!(validate(sig("emf"), &v), Validity::Valid);

        // Wrong record type, or an implausibly small header, are rejected.
        let mut bad = v.clone();
        bad[0..4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(validate(sig("emf"), &bad), Validity::Invalid);
        let mut small = v.clone();
        small[4..8].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(validate(sig("emf"), &small), Validity::Invalid);
    }

    #[test]
    fn midi_header_check() {
        let mut v = b"MThd".to_vec();
        v.extend_from_slice(&6u32.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // format
        v.extend_from_slice(&1u16.to_be_bytes()); // ntrks
        v.extend_from_slice(&96u16.to_be_bytes()); // division
        assert_eq!(validate(sig("mid"), &v), Validity::Valid);

        // A header length other than 6, or zero tracks, is rejected.
        let mut bad_len = v.clone();
        bad_len[4..8].copy_from_slice(&10u32.to_be_bytes());
        assert_eq!(validate(sig("mid"), &bad_len), Validity::Invalid);
        let mut no_tracks = v.clone();
        no_tracks[10..12].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(validate(sig("mid"), &no_tracks), Validity::Invalid);
    }

    #[test]
    fn unknown_types_accepted() {
        // A type with no structural validator is always accepted (Unknown).
        assert_eq!(validate(sig("rtf"), b"{\\rtf1 garbage"), Validity::Unknown);
        assert_eq!(
            validate(sig("zip"), &[0x50, 0x4B, 0x03, 0x04]),
            Validity::Unknown
        );
    }

    #[test]
    fn pdf_version_check() {
        assert_eq!(validate(sig("pdf"), b"%PDF-1.7\n"), Validity::Valid);
        assert_eq!(validate(sig("pdf"), b"%PDF-2.0\n"), Validity::Valid);
        // "%PDF" with no version is a coincidental match.
        assert_eq!(validate(sig("pdf"), b"%PDFxxxx"), Validity::Invalid);
        assert_eq!(validate(sig("pdf"), b"%PDF"), Validity::Unknown);
    }

    #[test]
    fn tiff_ifd_offset_check() {
        // Classic little-endian TIFF: version 42, first IFD at offset 8.
        let mut le = vec![0x49, 0x49, 0x2A, 0x00];
        le.extend_from_slice(&8u32.to_le_bytes());
        assert_eq!(validate(sig("tif"), &le), Validity::Valid);
        // An IFD offset inside the header is impossible.
        let mut bad = vec![0x49, 0x49, 0x2A, 0x00];
        bad.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(validate(sig("tif"), &bad), Validity::Invalid);
        // Big-endian classic TIFF.
        let mut be = vec![0x4D, 0x4D, 0x00, 0x2A];
        be.extend_from_slice(&8u32.to_be_bytes());
        assert_eq!(validate(sig("tif"), &be), Validity::Valid);
    }

    #[test]
    fn cab_reserved_fields_check() {
        let mut v = vec![0u8; 26];
        v[0..4].copy_from_slice(b"MSCF");
        v[25] = 1; // versionMajor
        assert_eq!(validate(sig("cab"), &v), Validity::Valid);
        // A non-zero reserved field is a coincidental match.
        let mut bad = v.clone();
        bad[4] = 0xFF;
        assert_eq!(validate(sig("cab"), &bad), Validity::Invalid);
    }

    #[test]
    fn wasm_and_dex_version_checks() {
        let mut wasm = vec![0x00, 0x61, 0x73, 0x6D];
        wasm.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(validate(sig("wasm"), &wasm), Validity::Valid);
        let mut bad_wasm = vec![0x00, 0x61, 0x73, 0x6D];
        bad_wasm.extend_from_slice(&7u32.to_le_bytes());
        assert_eq!(validate(sig("wasm"), &bad_wasm), Validity::Invalid);

        assert_eq!(validate(sig("dex"), b"dex\n035\0"), Validity::Valid);
        assert_eq!(validate(sig("dex"), b"dex\nXXX\0"), Validity::Invalid);
    }

    #[test]
    fn psd_version_and_reserved_check() {
        let mut v = vec![b'8', b'B', b'P', b'S'];
        v.extend_from_slice(&1u16.to_be_bytes()); // version 1 (PSD)
        v.extend_from_slice(&[0u8; 6]); // reserved
        assert_eq!(validate(sig("psd"), &v), Validity::Valid);
        // A non-zero reserved field is a coincidental match.
        let mut bad = v.clone();
        bad[6] = 1;
        assert_eq!(validate(sig("psd"), &bad), Validity::Invalid);
        // An unknown version is rejected.
        let mut bad_ver = v.clone();
        bad_ver[4..6].copy_from_slice(&9u16.to_be_bytes());
        assert_eq!(validate(sig("psd"), &bad_ver), Validity::Invalid);
    }

    #[test]
    fn ogg_version_check() {
        assert_eq!(validate(sig("ogg"), b"OggS\0"), Validity::Valid);
        assert_eq!(validate(sig("ogg"), b"OggS\x01"), Validity::Invalid);
    }

    #[test]
    fn flv_header_check() {
        // FLV\x01, flags = audio+video (0x05), data offset = 9.
        let mut v = vec![0x46, 0x4C, 0x56, 0x01, 0x05];
        v.extend_from_slice(&9u32.to_be_bytes());
        assert_eq!(validate(sig("flv"), &v), Validity::Valid);
        // A reserved flag bit set is bogus.
        let mut bad_flags = v.clone();
        bad_flags[4] = 0x02;
        assert_eq!(validate(sig("flv"), &bad_flags), Validity::Invalid);
        // A data offset other than 9 is bogus.
        let mut bad_off = v.clone();
        bad_off[5..9].copy_from_slice(&13u32.to_be_bytes());
        assert_eq!(validate(sig("flv"), &bad_off), Validity::Invalid);
    }

    /// A 512-byte ustar header with a correct checksum.
    fn tar_header() -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..5].copy_from_slice(b"a.txt");
        h[124..136].copy_from_slice(b"00000000005 "); // size 5 (octal)
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        for b in &mut h[148..156] {
            *b = b' ';
        }
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    #[test]
    fn tar_checksum_check() {
        let good = tar_header();
        assert_eq!(validate(sig("tar"), &good), Validity::Valid);
        // A corrupted checksum field is rejected.
        let mut bad = good.clone();
        bad[148..156].copy_from_slice(b"999999\0 ");
        assert_eq!(validate(sig("tar"), &bad), Validity::Invalid);
        // The ustar magic missing is rejected.
        let mut no_magic = good.clone();
        no_magic[257..262].copy_from_slice(b"XXXXX");
        assert_eq!(validate(sig("tar"), &no_magic), Validity::Invalid);
        // Too short to inspect the 512-byte header: accepted (Unknown).
        assert_eq!(validate(sig("tar"), &good[..64]), Validity::Unknown);
    }

    #[test]
    fn cpio_hex_field_check() {
        // newc magic + all-hex fields is valid.
        let mut good = b"070701".to_vec();
        good.extend(std::iter::repeat(b'0').take(104));
        assert_eq!(validate(sig("cpio"), &good), Validity::Valid);
        // The CRC variant magic is accepted too.
        let mut crc = b"070702".to_vec();
        crc.extend(std::iter::repeat(b'A').take(104));
        assert_eq!(validate(sig("cpio"), &crc), Validity::Valid);
        // A non-hex byte in the header is rejected.
        let mut bad = good.clone();
        bad[20] = b'Z';
        assert_eq!(validate(sig("cpio"), &bad), Validity::Invalid);
        // A wrong magic is rejected.
        let mut wrong = good.clone();
        wrong[5] = b'7'; // "070707" (old format, not newc)
        assert_eq!(validate(sig("cpio"), &wrong), Validity::Invalid);
    }

    #[test]
    fn squashfs_superblock_check() {
        let mut sb = vec![0u8; 48];
        sb[0..4].copy_from_slice(b"hsqs");
        sb[12..16].copy_from_slice(&(1u32 << 17).to_le_bytes()); // block_size
        sb[22..24].copy_from_slice(&17u16.to_le_bytes()); // block_log
        sb[28..30].copy_from_slice(&4u16.to_le_bytes()); // s_major = 4
        assert_eq!(validate(sig("squashfs"), &sb), Validity::Valid);
        // block_size inconsistent with block_log is rejected.
        let mut bad = sb.clone();
        bad[12..16].copy_from_slice(&4096u32.to_le_bytes());
        assert_eq!(validate(sig("squashfs"), &bad), Validity::Invalid);
        // A non-4 major version is rejected (different superblock layout).
        let mut v3 = sb.clone();
        v3[28..30].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(validate(sig("squashfs"), &v3), Validity::Invalid);
    }
}
