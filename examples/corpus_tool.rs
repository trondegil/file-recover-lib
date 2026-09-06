//! Helper for the real-image test corpus (see `corpus/README.md`).
//!
//! The corpus recipes run this on each platform to:
//!
//! 1. `plan`   — generate a deterministic set of files (real JPEG/PNG/BMP/PDF/WAV
//!    headers around unique, compressible payloads) plus an ordered
//!    list of copy/delete operations for one scenario;
//! 2. `expect` — after the recipe has applied that plan to a freshly formatted
//!    volume, record the SHA-256 of every file that ended up deleted,
//!    and the image's own size and SHA-256, as `corpus/expected/*.json`;
//! 3. `lock`   — assemble `corpus/corpus.lock` from the expected files.
//!
//! It only uses the standard library plus the crate's own hash and JSON
//! modules, so it builds everywhere the crate does.
//!
//! Run with `cargo run --example corpus_tool -- <command> ...`.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use unearth::hash;
use unearth::json::{self, Json};

const USAGE: &str = "\
usage:
  corpus_tool plan <scenario> <stage-dir> <plan-file> [--volume-size BYTES] [--seed N] \\
      [--plan-version N]
  corpus_tool scenarios
  corpus_tool expect --stage DIR --plan FILE --image FILE --name NAME \\
      --filesystem FS --platform OS --source TEXT --scenario NAME --out FILE \\
      [--extents FILE]
  corpus_tool live --expected FILE [--seed N] [--volume-size BYTES]
  corpus_tool lock --expected DIR --out FILE [--release TAG] \\
      [--tarball-name NAME --tarball-url URL --tarball-sha256 HEX]
  corpus_tool sha256 <file>

The plan file lists one operation per line, tab-separated:
  copy\t<relative path>              copy <stage-dir>/<path> onto the volume
  fill\t<relative path>              copy, but tolerate a full volume (drop the file)
  delete\t<relative path>\t<intact|maybe>   delete it (rm -f when maybe)
  rmdir\t<relative path>             remove a (now empty) directory
  sync                               flush the volume to disk
`intact` means the file's data is expected to survive on disk; `maybe` means the
scenario deliberately overwrites it, so recovery is best-effort.
`--extents` names a file of `<path>\t<extent count>` lines, one per deleted
file, as the recipe recorded it before the delete (Linux: filefrag).
`live` regenerates an image's staged files from its scenario and seed and adds
the files that were still present at the end of the plan (path, size, SHA-256)
to its expected file, so a carve that matches no deleted file can be told from
one that matches a live file.";

type Res<T> = Result<T, String>;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("plan") => cmd_plan(&args[1..]),
        Some("scenarios") => {
            for s in SCENARIOS {
                println!("{s}");
            }
            Ok(())
        }
        Some("expect") => cmd_expect(&args[1..]),
        Some("live") => cmd_live(&args[1..]),
        Some("lock") => cmd_lock(&args[1..]),
        Some("sha256") => cmd_sha256(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = r {
        eprintln!("corpus_tool: {e}");
        std::process::exit(1);
    }
}

// --- argument parsing ----------------------------------------------------------

/// Split `args` into positionals and `--key value` options.
fn parse_args(args: &[String]) -> (Vec<String>, BTreeMap<String, String>) {
    let mut pos = Vec::new();
    let mut opts = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(key) = args[i].strip_prefix("--") {
            let val = args.get(i + 1).cloned().unwrap_or_default();
            opts.insert(key.to_string(), val);
            i += 2;
        } else {
            pos.push(args[i].clone());
            i += 1;
        }
    }
    (pos, opts)
}

fn need<'a>(opts: &'a BTreeMap<String, String>, key: &str) -> Res<&'a str> {
    opts.get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing --{key}\n{USAGE}"))
}

// --- deterministic content -------------------------------------------------------

/// xorshift64: tiny, deterministic, good enough for filler bytes.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1) ^ 0x9E37_79B9_7F4A_7C15)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
    /// Uniform in `lo..=hi`.
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Jpg,
    Png,
    Bmp,
    Pdf,
    Wav,
    Txt,
    Bin,
}

impl Kind {
    fn ext(self) -> &'static str {
        match self {
            Kind::Jpg => "jpg",
            Kind::Png => "png",
            Kind::Bmp => "bmp",
            Kind::Pdf => "pdf",
            Kind::Wav => "wav",
            Kind::Txt => "txt",
            Kind::Bin => "bin",
        }
    }
    /// Whether the carver has a signature for this type, so `scan` is expected
    /// to bring the file back byte-for-byte when it is contiguous on disk.
    fn carvable(self) -> bool {
        !matches!(self, Kind::Txt | Kind::Bin)
    }
    fn from_ext(ext: &str) -> Option<Kind> {
        Some(match ext {
            "jpg" => Kind::Jpg,
            "png" => Kind::Png,
            "bmp" => Kind::Bmp,
            "pdf" => Kind::Pdf,
            "wav" => Kind::Wav,
            "txt" => Kind::Txt,
            "bin" => Kind::Bin,
            _ => return None,
        })
    }
}

/// Payload of `len` bytes made of 512-byte sectors. Each sector starts with a
/// 16-character hex stamp unique to (file, sector), followed by a block of
/// pseudo-random bytes that is the same for every sector of the file. That
/// makes every sector on disk distinct — a mis-ordered or mis-sized recovery
/// changes the hash — while keeping the images compressible for distribution.
///
/// `forbid` lists byte values that must not appear in the filler, so a payload
/// can never fake the footer marker of the format wrapping it.
fn payload(file_seed: u64, len: usize, forbid: &[u8]) -> Vec<u8> {
    let mut rng = Rng::new(file_seed);
    let block: Vec<u8> = (0..496)
        .map(|_| {
            let mut b = rng.byte();
            while forbid.contains(&b) {
                b = b.wrapping_add(1);
            }
            b
        })
        .collect();
    let mut out = Vec::with_capacity(len);
    let mut sector = 0u32;
    while out.len() < len {
        let stamp = format!("{:08x}{:08x}", (file_seed & 0xFFFF_FFFF) as u32, sector);
        out.extend_from_slice(stamp.as_bytes());
        out.extend_from_slice(&block);
        sector += 1;
    }
    out.truncate(len);
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Build a file of `kind` whose total length is exactly `size` bytes. Headers
/// and footers are real enough for the carver (and its validators) to accept
/// and to compute the exact length from.
fn make_file(kind: Kind, size: usize, seed: u64) -> Vec<u8> {
    match kind {
        Kind::Jpg => {
            // SOI, APP0/JFIF, a COM segment, entropy-ish body with no 0xFF, EOI.
            let head: Vec<u8> = vec![
                0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            ];
            let size = size.max(head.len() + 2);
            let body = payload(seed, size - head.len() - 2, &[0xFF]);
            let mut v = head;
            v.extend_from_slice(&body);
            v.extend_from_slice(&[0xFF, 0xD9]);
            v
        }
        Kind::Png => {
            // Signature, IHDR, one IDAT holding the payload, IEND. Chunk CRCs
            // are real so a stricter reader still sees a well-formed container.
            let min = 8 + 25 + 12 + 12;
            let size = size.max(min);
            let idat_len = size - min;
            let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
            let side = ((idat_len as f64).sqrt() as u32).max(1);
            let mut ihdr = b"IHDR".to_vec();
            ihdr.extend_from_slice(&side.to_be_bytes());
            ihdr.extend_from_slice(&side.to_be_bytes());
            ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
            push_chunk(&mut v, &ihdr);
            let mut idat = b"IDAT".to_vec();
            idat.extend_from_slice(&payload(seed, idat_len, &[]));
            push_chunk(&mut v, &idat);
            push_chunk(&mut v, b"IEND");
            v
        }
        Kind::Bmp => {
            let size = size.max(54 + 4);
            let pixels = size - 54;
            let width = 64u32;
            let rows = (pixels / (width as usize * 3)).max(1) as u32;
            let mut v = b"BM".to_vec();
            v.extend_from_slice(&(size as u32).to_le_bytes());
            v.extend_from_slice(&[0, 0, 0, 0]);
            v.extend_from_slice(&54u32.to_le_bytes());
            v.extend_from_slice(&40u32.to_le_bytes());
            v.extend_from_slice(&width.to_le_bytes());
            v.extend_from_slice(&rows.to_le_bytes());
            v.extend_from_slice(&1u16.to_le_bytes());
            v.extend_from_slice(&24u16.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
            v.extend_from_slice(&(pixels as u32).to_le_bytes());
            v.extend_from_slice(&2835u32.to_le_bytes());
            v.extend_from_slice(&2835u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&payload(seed, pixels, &[]));
            v
        }
        Kind::Pdf => {
            // Real writers end with `%%EOF`, `%%EOF\n`, or `%%EOF\r\n`; use all
            // three so the carver's line-ending handling is exercised.
            let head = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n1 0 obj\n<< /Length 0 >>\nstream\n";
            let eol: &[u8] = match seed % 3 {
                0 => b"",
                1 => b"\n",
                _ => b"\r\n",
            };
            let mut tail = b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF".to_vec();
            tail.extend_from_slice(eol);
            let size = size.max(head.len() + tail.len());
            let mut v = head.to_vec();
            v.extend_from_slice(&payload(seed, size - head.len() - tail.len(), b"%"));
            v.extend_from_slice(&tail);
            v
        }
        Kind::Wav => {
            let size = size.max(44);
            let data = size - 44;
            let mut v = b"RIFF".to_vec();
            v.extend_from_slice(&((size - 8) as u32).to_le_bytes());
            v.extend_from_slice(b"WAVEfmt ");
            v.extend_from_slice(&16u32.to_le_bytes());
            v.extend_from_slice(&1u16.to_le_bytes()); // PCM
            v.extend_from_slice(&2u16.to_le_bytes()); // stereo
            v.extend_from_slice(&44100u32.to_le_bytes());
            v.extend_from_slice(&176400u32.to_le_bytes());
            v.extend_from_slice(&4u16.to_le_bytes());
            v.extend_from_slice(&16u16.to_le_bytes());
            v.extend_from_slice(b"data");
            v.extend_from_slice(&(data as u32).to_le_bytes());
            v.extend_from_slice(&payload(seed, data, &[]));
            v
        }
        Kind::Txt => {
            // Readable prose-like lines so the file looks like a document, with
            // a per-line stamp so no two lines (or files) are alike.
            const WORDS: &[&str] = &[
                "recovery", "sector", "cluster", "inode", "journal", "volume", "carve", "hash",
                "delete", "restore", "image", "disk", "format", "entry", "extent", "record",
            ];
            let mut rng = Rng::new(seed);
            let mut s = String::new();
            let mut line = 0u32;
            while s.len() < size {
                s.push_str(&format!(
                    "{:08x}-{:06x}:",
                    (seed & 0xFFFF_FFFF) as u32,
                    line
                ));
                for _ in 0..12 {
                    s.push(' ');
                    s.push_str(WORDS[rng.range(0, WORDS.len() as u64 - 1) as usize]);
                }
                s.push('\n');
                line += 1;
            }
            let mut v = s.into_bytes();
            v.truncate(size);
            v
        }
        Kind::Bin => payload(seed, size, &[]),
    }
}

fn push_chunk(v: &mut Vec<u8>, type_and_data: &[u8]) {
    v.extend_from_slice(&((type_and_data.len() - 4) as u32).to_be_bytes());
    v.extend_from_slice(type_and_data);
    v.extend_from_slice(&crc32(type_and_data).to_be_bytes());
}

// --- scenarios ----------------------------------------------------------------------

const SCENARIOS: &[&str] = &[
    "baseline",
    "deeptree",
    "longnames",
    "nonascii",
    "fragmented",
    "nearlyfull",
    "overwritten",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Expect {
    Intact,
    Maybe,
}

impl Expect {
    fn as_str(self) -> &'static str {
        match self {
            Expect::Intact => "intact",
            Expect::Maybe => "maybe",
        }
    }
    fn parse(s: &str) -> Res<Expect> {
        match s {
            "intact" => Ok(Expect::Intact),
            "maybe" => Ok(Expect::Maybe),
            _ => Err(format!("bad expectation '{s}' (want intact|maybe)")),
        }
    }
}

#[derive(Debug)]
enum Op {
    Copy(String),
    /// Copy that may fail with a full volume: used to pack a volume to the
    /// brim so that later writes are forced into the gaps deletions leave.
    Fill(String),
    Delete(String, Expect),
    Rmdir(String),
    Sync,
}

/// A scenario: the files to stage and the ordered operations to perform.
struct Plan {
    files: Vec<(String, Kind, usize)>,
    ops: Vec<Op>,
}

impl Plan {
    fn new() -> Self {
        Plan {
            files: Vec::new(),
            ops: Vec::new(),
        }
    }
    /// Stage a file and copy it onto the volume.
    fn add(&mut self, path: &str, kind: Kind, size: usize) {
        self.files.push((path.to_string(), kind, size));
        self.ops.push(Op::Copy(path.to_string()));
    }
    fn fill(&mut self, path: &str, kind: Kind, size: usize) {
        self.files.push((path.to_string(), kind, size));
        self.ops.push(Op::Fill(path.to_string()));
    }
    fn delete(&mut self, path: &str, e: Expect) {
        self.ops.push(Op::Delete(path.to_string(), e));
    }
    fn rmdir(&mut self, path: &str) {
        self.ops.push(Op::Rmdir(path.to_string()));
    }
    fn sync(&mut self) {
        self.ops.push(Op::Sync);
    }
}

const KB: usize = 1024;
const MB: usize = 1024 * KB;

/// A size that is deliberately not sector- or cluster-aligned, so an exact
/// recovery has to honour the recorded length rather than round up.
fn odd_size(rng: &mut Rng, lo: usize, hi: usize) -> usize {
    let s = rng.range(lo as u64, hi as u64) as usize;
    s | 1
}

/// The scenario definitions change over time; an image records the version
/// it was built from, so its staged files can be regenerated later. Version
/// 1 is the first corpus build. Version 2 overfills the `fragmented` volume
/// and adds the small control file deleted last.
const PLAN_VERSION: u32 = 2;

fn scenario(name: &str, volume_size: u64, seed: u64, version: u32) -> Res<Plan> {
    let mut rng = Rng::new(seed);
    let mut p = Plan::new();
    let kinds = [
        Kind::Jpg,
        Kind::Png,
        Kind::Bmp,
        Kind::Pdf,
        Kind::Wav,
        Kind::Txt,
        Kind::Bin,
    ];
    match name {
        "baseline" => {
            // A typical small card: photos and documents in a couple of folders,
            // a third of them deleted.
            for i in 0..8 {
                let k = if i % 3 == 2 { Kind::Png } else { Kind::Jpg };
                let s = odd_size(&mut rng, 200 * KB, 1200 * KB);
                p.add(&format!("DCIM/IMG_{:04}.{}", 1000 + i, k.ext()), k, s);
            }
            for i in 0..4 {
                p.add(
                    &format!("docs/report-{}.pdf", 2021 + i),
                    Kind::Pdf,
                    odd_size(&mut rng, 40 * KB, 600 * KB),
                );
            }
            p.add(
                "docs/notes.txt",
                Kind::Txt,
                odd_size(&mut rng, 2 * KB, 30 * KB),
            );
            p.add("docs/todo.txt", Kind::Txt, odd_size(&mut rng, 100, 2 * KB));
            p.add("logo.bmp", Kind::Bmp, odd_size(&mut rng, 50 * KB, 300 * KB));
            p.add(
                "banner.bmp",
                Kind::Bmp,
                odd_size(&mut rng, 50 * KB, 300 * KB),
            );
            p.add(
                "audio/take1.wav",
                Kind::Wav,
                odd_size(&mut rng, 300 * KB, 900 * KB),
            );
            p.add(
                "audio/take2.wav",
                Kind::Wav,
                odd_size(&mut rng, 300 * KB, 900 * KB),
            );
            p.add(
                "firmware.bin",
                Kind::Bin,
                odd_size(&mut rng, 100 * KB, 400 * KB),
            );
            p.add("tiny.txt", Kind::Txt, 7);
            p.sync();
            let paths: Vec<String> = p.files.iter().map(|f| f.0.clone()).collect();
            for (i, path) in paths.iter().enumerate() {
                if i % 3 == 1 {
                    p.delete(path, Expect::Intact);
                }
            }
            p.sync();
        }
        "deeptree" => {
            // Files at every level of a three-deep tree; one whole subtree is
            // removed recursively, plus a couple of files elsewhere.
            let dirs = [
                "",
                "projects/",
                "projects/2024/",
                "projects/2024/q1/",
                "projects/2024/q2/",
                "projects/archive/",
                "projects/archive/old/",
            ];
            let mut n = 0;
            for d in dirs {
                for j in 0..3 {
                    let k = kinds[n % kinds.len()];
                    n += 1;
                    let s = odd_size(&mut rng, 10 * KB, 500 * KB);
                    p.add(&format!("{d}file-{n:02}-{j}.{}", k.ext()), k, s);
                }
            }
            p.sync();
            let doomed: Vec<String> = p
                .files
                .iter()
                .map(|f| f.0.clone())
                .filter(|f| f.starts_with("projects/2024/q1/"))
                .collect();
            for f in &doomed {
                p.delete(f, Expect::Intact);
            }
            p.rmdir("projects/2024/q1");
            let first = p.files[0].0.clone();
            let deepest = p.files.last().unwrap().0.clone();
            p.delete(&first, Expect::Intact);
            p.delete(&deepest, Expect::Intact);
            p.sync();
        }
        "longnames" => {
            // Names from 60 to 200 characters: several long-name entries per
            // file on FAT, and near the 255 limit elsewhere.
            let stem = "a-very-long-file-name-that-keeps-going-and-going";
            for i in 0..10 {
                let k = kinds[i % 5];
                let target = 60 + i * 15;
                let mut name = String::new();
                let mut j = 0;
                while name.len() < target {
                    name.push_str(&format!("{stem}-{j}-"));
                    j += 1;
                }
                name.truncate(target);
                let path = format!("{name}-{i}.{}", k.ext());
                let s = odd_size(&mut rng, 20 * KB, 400 * KB);
                p.add(&path, k, s);
            }
            p.sync();
            let paths: Vec<String> = p.files.iter().map(|f| f.0.clone()).collect();
            for (i, path) in paths.iter().enumerate() {
                if i % 2 == 0 {
                    p.delete(path, Expect::Intact);
                }
            }
            p.sync();
        }
        "nonascii" => {
            let names = [
                "Bilder/Ålesund sommer 2024 – ferie.jpg",
                "Bilder/blåbær og jordbær.png",
                "Bilder/Größe & Übung.bmp",
                "写真/桜の木.jpg",
                "写真/東京タワー.pdf",
                "Документы/отчёт за год.pdf",
                "Ελλάδα/Αθήνα.wav",
                "emoji 🌍🚀.bin",
                "café résumé.txt",
                "한글 파일.txt",
            ];
            for n in names {
                let ext = n.rsplit('.').next().unwrap();
                let k = Kind::from_ext(ext).unwrap();
                let s = odd_size(&mut rng, 10 * KB, 400 * KB);
                p.add(n, k, s);
            }
            p.sync();
            for (i, n) in names.iter().enumerate() {
                if i % 2 == 0 {
                    p.delete(n, Expect::Intact);
                }
            }
            p.sync();
        }
        "fragmented" => {
            // Pack the volume with alternating spacer/keeper pairs until it is
            // full (the last pairs may not fit; that is fine), delete the
            // spacers, and write files bigger than any single gap. They have
            // to fragment, on every allocator. Deleting those is the real
            // test; a contiguous keeper is deleted too as a control.
            let pair = MB;
            // More pairs than the volume can hold: `fill` tolerates the
            // copies that fail, and only a volume packed to the brim forces
            // the big files into the gaps. Version 1 stopped at 97 percent,
            // which left XFS (512 MiB, with room to spare) a contiguous
            // tail: that build's "fragmented" XFS image had one extent per
            // file.
            let pairs = if version >= 2 {
                (volume_size as usize) / (2 * pair) + 2
            } else {
                (volume_size as usize) * 97 / 100 / (2 * pair)
            };
            for i in 0..pairs {
                p.fill(&format!("spacer-{i:02}.bin"), Kind::Bin, pair - 4096 + 511);
                let k = if i % 2 == 0 { Kind::Jpg } else { Kind::Png };
                p.fill(&format!("keep-{i:02}.{}", k.ext()), k, pair - 4096 + 1);
            }
            p.sync();
            for i in 0..pairs {
                p.delete(&format!("spacer-{i:02}.bin"), Expect::Maybe);
            }
            p.sync();
            p.add("big-0.jpg", Kind::Jpg, 3 * MB + 3);
            p.add("big-1.pdf", Kind::Pdf, 4 * MB + 5);
            p.add("big-2.png", Kind::Png, 5 * MB + 7);
            p.sync();
            // A small file written after the big ones lands in a gap past
            // their last fragments, so no fragmented file's carve can swallow
            // it (a fragmented file's footer search runs to its last
            // fragment and takes everything between). Deleted last, it is
            // the one file scan is expected to bring back whole here, which
            // keeps the scan floor above zero. `keep-03.png` sits among the
            // big files' fragments and is only a control for undelete.
            if version >= 2 {
                p.add("last-small.jpg", Kind::Jpg, 200 * KB + 1);
                p.sync();
            }
            p.delete("big-0.jpg", Expect::Intact);
            p.delete("big-1.pdf", Expect::Intact);
            p.delete("big-2.png", Expect::Intact);
            p.delete("keep-03.png", Expect::Intact);
            if version >= 2 {
                p.delete("last-small.jpg", Expect::Intact);
            }
            p.sync();
        }
        "nearlyfull" => {
            // Fill about three quarters of the volume (leaving room for the
            // filesystem's own metadata, journal, and reserved blocks), then
            // delete every third file.
            let budget = (volume_size as usize) * 3 / 4;
            let mut used = 0;
            let mut i = 0;
            while used + 1200 * KB < budget {
                let k = kinds[i % 5];
                let s = odd_size(&mut rng, 600 * KB, 1100 * KB);
                p.add(
                    &format!("full/{k:?}-{i:03}.{}", k.ext()).to_lowercase(),
                    k,
                    s,
                );
                used += s;
                i += 1;
            }
            p.sync();
            let paths: Vec<String> = p.files.iter().map(|f| f.0.clone()).collect();
            for (i, path) in paths.iter().enumerate() {
                if i % 3 == 0 {
                    p.delete(path, Expect::Intact);
                }
            }
            p.sync();
        }
        "overwritten" => {
            // Write the victims first, pack the rest of the volume full, delete
            // the victims, and write new data into the only free space left:
            // their clusters. The victims are best-effort; a third file deleted
            // after the overwrite must still come back whole.
            p.add("old-photo.jpg", Kind::Jpg, 3 * MB + 1);
            p.add("old-report.pdf", Kind::Pdf, 2 * MB + 3);
            p.add("survivor.png", Kind::Png, 500 * KB + 5);
            let fillers = (volume_size as usize) * 97 / 100 / MB;
            for i in 0..fillers {
                let k = kinds[i % 5];
                p.fill(&format!("filler/{i:02}.{}", k.ext()), k, MB - 4096 + 1);
            }
            p.sync();
            p.delete("old-photo.jpg", Expect::Maybe);
            p.delete("old-report.pdf", Expect::Maybe);
            p.sync();
            p.add("new-data.bin", Kind::Bin, 4 * MB + 9);
            p.add("new-notes.txt", Kind::Txt, 200 * KB + 11);
            p.sync();
            p.delete("survivor.png", Expect::Intact);
            p.sync();
        }
        other => {
            return Err(format!(
                "unknown scenario '{other}' (one of: {})",
                SCENARIOS.join(", ")
            ))
        }
    }
    Ok(p)
}

// --- commands ----------------------------------------------------------------------------

fn cmd_plan(args: &[String]) -> Res<()> {
    let (pos, opts) = parse_args(args);
    if pos.len() != 3 {
        return Err(USAGE.to_string());
    }
    let volume_size: u64 = opts
        .get("volume-size")
        .map(|s| s.parse().map_err(|_| "bad --volume-size".to_string()))
        .transpose()?
        .unwrap_or(64 * MB as u64);
    let seed: u64 = opts
        .get("seed")
        .map(|s| s.parse().map_err(|_| "bad --seed".to_string()))
        .transpose()?
        .unwrap_or(1);
    let version: u32 = opts
        .get("plan-version")
        .map(|s| s.parse().map_err(|_| "bad --plan-version".to_string()))
        .transpose()?
        .unwrap_or(PLAN_VERSION);
    let plan = scenario(&pos[0], volume_size, seed, version)?;
    let stage = Path::new(&pos[1]);
    fs::create_dir_all(stage).map_err(|e| format!("creating {}: {e}", stage.display()))?;
    let mut total = 0usize;
    for (i, (path, kind, size)) in plan.files.iter().enumerate() {
        let file_seed = seed
            .wrapping_mul(1_000_003)
            .wrapping_add(i as u64 + 1)
            .wrapping_mul(0x2545_F491_4F6C_DD1D);
        let data = make_file(*kind, *size, file_seed);
        let dst = stage.join(path);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("creating {}: {e}", parent.display()))?;
        }
        fs::write(&dst, &data).map_err(|e| format!("writing {}: {e}", dst.display()))?;
        // A distinct, deterministic modification time per file, so the test
        // can check that recovery restores it. Recipes copy with the time
        // preserved (`cp -p`, Copy-Item), so this is what lands on the volume.
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(stage_mtime(i));
        fs::File::options()
            .write(true)
            .open(&dst)
            .and_then(|f| f.set_modified(mtime))
            .map_err(|e| format!("setting mtime on {}: {e}", dst.display()))?;
        total += data.len();
    }
    let mut text = format!("# plan-version {version}\n");
    for op in &plan.ops {
        match op {
            Op::Copy(p) => text.push_str(&format!("copy\t{p}\n")),
            Op::Fill(p) => text.push_str(&format!("fill\t{p}\n")),
            Op::Delete(p, e) => text.push_str(&format!("delete\t{p}\t{}\n", e.as_str())),
            Op::Rmdir(p) => text.push_str(&format!("rmdir\t{p}\n")),
            Op::Sync => text.push_str("sync\n"),
        }
    }
    fs::write(&pos[2], text).map_err(|e| format!("writing {}: {e}", pos[2]))?;
    eprintln!(
        "staged {} files ({} bytes) for scenario '{}' into {}; plan: {}",
        plan.files.len(),
        total,
        pos[0],
        stage.display(),
        pos[2]
    );
    Ok(())
}

/// The modification time stamped on the `i`th staged file: 2024-03-15 10:00
/// UTC plus 61 seconds per file, so every file's time is distinct, even on
/// FAT's 2-second resolution, and far from any build or test date.
fn stage_mtime(i: usize) -> u64 {
    1_710_496_800 + i as u64 * 61
}

/// The plan version a plan file was written with (its `# plan-version N`
/// header); 1 for a plan from before the header existed.
fn plan_version_of(text: &str) -> u32 {
    text.lines()
        .find_map(|l| l.strip_prefix("# plan-version "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(1)
}

fn read_plan(path: &Path) -> Res<Vec<Op>> {
    let text = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let mut ops = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let op = match (f[0], f.len()) {
            ("copy", 2) => Op::Copy(f[1].to_string()),
            ("fill", 2) => Op::Fill(f[1].to_string()),
            ("delete", 3) => Op::Delete(f[1].to_string(), Expect::parse(f[2])?),
            ("rmdir", 2) => Op::Rmdir(f[1].to_string()),
            ("sync", 1) => Op::Sync,
            _ => {
                return Err(format!(
                    "{}:{}: bad plan line '{line}'",
                    path.display(),
                    n + 1
                ))
            }
        };
        ops.push(op);
    }
    Ok(ops)
}

fn sha256_file(path: &Path) -> Res<(u64, String)> {
    let mut f = fs::File::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
    let mut h = hash::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0u64;
    loop {
        let r = f
            .read(&mut buf)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        if r == 0 {
            break;
        }
        h.update(&buf[..r]);
        n += r as u64;
    }
    Ok((n, hash::to_hex(&h.finalize())))
}

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn s(v: &str) -> Json {
    Json::Str(v.to_string())
}

fn n(v: u64) -> Json {
    Json::Num(v as f64)
}

fn cmd_expect(args: &[String]) -> Res<()> {
    let (_, o) = parse_args(args);
    let stage = Path::new(need(&o, "stage")?);
    let plan_path = Path::new(need(&o, "plan")?);
    let ops = read_plan(plan_path)?;
    let plan_version = plan_version_of(
        &fs::read_to_string(plan_path)
            .map_err(|e| format!("reading {}: {e}", plan_path.display()))?,
    );
    let image = Path::new(need(&o, "image")?);
    let name = need(&o, "name")?;
    let out = need(&o, "out")?;
    // Extent counts the recipe recorded before each delete, when the
    // platform can report them.
    let extents: BTreeMap<String, u64> = match o.get("extents") {
        Some(path) => fs::read_to_string(path)
            .map_err(|e| format!("reading {path}: {e}"))?
            .lines()
            .filter_map(|l| {
                let (p, n) = l.split_once('\t')?;
                Some((p.to_string(), n.trim().parse().ok()?))
            })
            .collect(),
        None => BTreeMap::new(),
    };

    // Replay the plan: a file counts as deleted if its last operation was a
    // delete (a re-copy after a delete makes it live again).
    let mut state: BTreeMap<String, Option<Expect>> = BTreeMap::new();
    for op in &ops {
        match op {
            Op::Copy(p) | Op::Fill(p) => {
                state.insert(p.clone(), None);
            }
            Op::Delete(p, e) => {
                if !state.contains_key(p) {
                    return Err(format!("plan deletes '{p}' before copying it"));
                }
                state.insert(p.clone(), Some(*e));
            }
            Op::Rmdir(_) | Op::Sync => {}
        }
    }
    let mut files = Vec::new();
    let mut live = 0u64;
    for (path, st) in &state {
        let Some(expect) = st else {
            live += 1;
            continue;
        };
        let staged = stage.join(path);
        let (size, sha) = sha256_file(&staged)?;
        let ext = path.rsplit('.').next().unwrap_or("");
        let carvable = Kind::from_ext(ext).map(Kind::carvable).unwrap_or(false);
        let mtime = fs::metadata(&staged)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .ok_or_else(|| format!("reading mtime of {}", staged.display()))?;
        let mut entry = vec![
            ("path", s(path)),
            ("size", n(size)),
            ("sha256", s(&sha)),
            ("mtime", n(mtime)),
            ("expect", s(expect.as_str())),
            ("carvable", Json::Bool(carvable)),
        ];
        if let Some(count) = extents.get(path) {
            entry.push(("extents", n(*count)));
        }
        files.push(obj(entry));
    }
    if files.is_empty() {
        return Err("plan deletes nothing".to_string());
    }
    let (img_size, img_sha) = sha256_file(image)?;
    let image_file = image
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or("bad image path")?;

    // Keep a previously recorded baseline if the expected file already exists,
    // so rebuilding an image does not silently drop its recall floor.
    let previous = fs::read_to_string(out)
        .ok()
        .and_then(|t| json::parse(&t).ok())
        .and_then(|j| j.get("baseline").cloned());

    let mut doc = vec![
        ("name", s(name)),
        ("filesystem", s(need(&o, "filesystem")?)),
        ("platform", s(need(&o, "platform")?)),
        ("source", s(need(&o, "source")?)),
        ("scenario", s(need(&o, "scenario")?)),
        ("plan_version", n(plan_version as u64)),
        (
            "image",
            obj(vec![
                ("file", s(image_file)),
                ("size", n(img_size)),
                ("sha256", s(&img_sha)),
            ]),
        ),
        ("live_files", n(live)),
        ("files", Json::Arr(files)),
    ];
    if let Some(b) = previous {
        doc.push(("baseline", b));
    }
    fs::write(out, obj(doc).to_pretty_string()).map_err(|e| format!("writing {out}: {e}"))?;
    eprintln!(
        "wrote {out} ({} deleted files, {live} live)",
        state.len() as u64 - live
    );
    Ok(())
}

/// Regenerate an image's staged files in memory from its scenario and seed,
/// check the deleted files still hash as recorded (so the regeneration is
/// the one the image was built from), and record the files that were live at
/// the end of the plan under `live`.
fn cmd_live(args: &[String]) -> Res<()> {
    let (_, o) = parse_args(args);
    let path = need(&o, "expected")?;
    let text = fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    let doc = json::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    let scenario_name = doc
        .get("scenario")
        .and_then(Json::as_str)
        .ok_or("expected file has no scenario")?
        .to_string();
    let filesystem = doc
        .get("filesystem")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string();
    let seed: u64 = o
        .get("seed")
        .map(|s| s.parse().map_err(|_| "bad --seed".to_string()))
        .transpose()?
        .unwrap_or(1);
    // The recipes build 64 MiB volumes, except XFS, which refuses anything
    // under 300 MB and gets 512 MiB.
    let default_size = if filesystem == "xfs" {
        512 * MB as u64
    } else {
        64 * MB as u64
    };
    let volume_size: u64 = o
        .get("volume-size")
        .map(|s| s.parse().map_err(|_| "bad --volume-size".to_string()))
        .transpose()?
        .unwrap_or(default_size);
    // An expected file from before plan versions existed came from version 1.
    let plan_version = doc.get("plan_version").and_then(Json::as_u64).unwrap_or(1) as u32;
    let plan = scenario(&scenario_name, volume_size, seed, plan_version)?;

    let mut state: BTreeMap<String, Option<Expect>> = BTreeMap::new();
    for op in &plan.ops {
        match op {
            Op::Copy(p) | Op::Fill(p) => {
                state.insert(p.clone(), None);
            }
            Op::Delete(p, e) => {
                state.insert(p.clone(), Some(*e));
            }
            Op::Rmdir(_) | Op::Sync => {}
        }
    }
    let mut hashes: BTreeMap<String, (u64, String)> = BTreeMap::new();
    for (i, (p, kind, size)) in plan.files.iter().enumerate() {
        let file_seed = seed
            .wrapping_mul(1_000_003)
            .wrapping_add(i as u64 + 1)
            .wrapping_mul(0x2545_F491_4F6C_DD1D);
        let data = make_file(*kind, *size, file_seed);
        hashes.insert(
            p.clone(),
            (data.len() as u64, hash::to_hex(&hash::digest(&data))),
        );
    }
    // The recorded deleted files must be the regenerated ones.
    for f in doc.get("files").and_then(Json::as_array).unwrap_or(&[]) {
        let p = f.get("path").and_then(Json::as_str).unwrap_or("");
        let want = f.get("sha256").and_then(Json::as_str).unwrap_or("");
        match hashes.get(p) {
            Some((_, got)) if got == want => {}
            Some(_) => {
                let why = "does not hash as recorded; wrong seed or volume size?";
                return Err(format!("{path}: regenerated '{p}' {why}"));
            }
            None => return Err(format!("{path}: '{p}' is not in the regenerated plan")),
        }
    }
    let mut live = Vec::new();
    for (p, st) in &state {
        if st.is_none() {
            let (size, sha) = &hashes[p];
            live.push(obj(vec![
                ("path", s(p)),
                ("size", n(*size)),
                ("sha256", s(sha)),
            ]));
        }
    }
    let count = live.len();
    let Json::Obj(mut map) = doc else {
        return Err(format!("{path}: not an object"));
    };
    map.insert("live".to_string(), Json::Arr(live));
    map.entry("plan_version".to_string())
        .or_insert(n(plan_version as u64));
    fs::write(path, Json::Obj(map).to_pretty_string())
        .map_err(|e| format!("writing {path}: {e}"))?;
    eprintln!("{path}: recorded {count} live files");
    Ok(())
}

fn cmd_lock(args: &[String]) -> Res<()> {
    let (_, o) = parse_args(args);
    let dir = Path::new(need(&o, "expected")?);
    let out = need(&o, "out")?;
    let existing = fs::read_to_string(out)
        .ok()
        .and_then(|t| json::parse(&t).ok());
    let inherit = |key: &str, sub: Option<&str>| -> Option<Json> {
        let e = existing.as_ref()?;
        match sub {
            Some(k) => e.get(key)?.get(k).cloned(),
            None => e.get(key).cloned(),
        }
    };

    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    entries.sort();
    let mut images = Vec::new();
    for path in &entries {
        let text =
            fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        let j = json::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let img = j
            .get("image")
            .ok_or_else(|| format!("{}: no image", path.display()))?;
        let field = |k: &str| {
            j.get(k)
                .cloned()
                .ok_or_else(|| format!("{}: missing '{k}'", path.display()))
        };
        images.push(obj(vec![
            ("name", field("name")?),
            ("filesystem", field("filesystem")?),
            ("platform", field("platform")?),
            ("source", field("source")?),
            ("scenario", field("scenario")?),
            ("file", img.get("file").cloned().unwrap_or(Json::Null)),
            ("size", img.get("size").cloned().unwrap_or(Json::Null)),
            ("sha256", img.get("sha256").cloned().unwrap_or(Json::Null)),
            (
                "expected",
                s(&format!(
                    "corpus/expected/{}",
                    path.file_name().unwrap().to_string_lossy()
                )),
            ),
            (
                "deleted_files",
                n(j.get("files")
                    .and_then(|f| f.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0) as u64),
            ),
        ]));
    }

    let opt_or = |key: &str, inherited: Option<Json>| -> Json {
        o.get(key).map(|v| s(v)).or(inherited).unwrap_or(Json::Null)
    };
    let tarball = obj(vec![
        (
            "name",
            opt_or("tarball-name", inherit("tarball", Some("name"))),
        ),
        (
            "url",
            opt_or("tarball-url", inherit("tarball", Some("url"))),
        ),
        (
            "sha256",
            opt_or("tarball-sha256", inherit("tarball", Some("sha256"))),
        ),
    ]);
    let doc = obj(vec![
        ("version", n(1)),
        ("release", opt_or("release", inherit("release", None))),
        ("tarball", tarball),
        ("images", Json::Arr(images)),
    ]);
    fs::write(out, doc.to_pretty_string()).map_err(|e| format!("writing {out}: {e}"))?;
    eprintln!("wrote {out} ({} images)", entries.len());
    Ok(())
}

fn cmd_sha256(args: &[String]) -> Res<()> {
    for a in args {
        let (size, sha) = sha256_file(Path::new(a))?;
        println!("{sha}  {size}  {a}");
    }
    Ok(())
}
