//! Carving tests for the formats added on top of the originals: the ISO-BMFF
//! brands (AVIF, Canon CR3, JPEG XL, 3GP) and ELF objects. Each is embedded in
//! a synthetic image and recovered byte-for-byte.

use std::io::Write;

use unearth::carver::{self, CarveOptions, NoProgress};
use unearth::signatures;
use unearth::source::Source;

fn filler(seed: u64, n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i as u64 + seed) % 251) as u8).collect()
}

/// A minimal ISO base-media file: a 16-byte `ftyp` box with `brand`, then an
/// `mdat` box wrapping the payload.
fn iso_bmff(brand: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&16u32.to_be_bytes());
    v.extend_from_slice(b"ftyp");
    v.extend_from_slice(brand);
    v.extend_from_slice(&0u32.to_be_bytes()); // minor version
    let mdat = (8 + payload.len()) as u32;
    v.extend_from_slice(&mdat.to_be_bytes());
    v.extend_from_slice(b"mdat");
    v.extend_from_slice(payload);
    v
}

/// A minimal 64-bit little-endian ELF whose section-header table (the file's
/// end) holds `shnum` entries of 64 bytes, starting right after the header.
fn elf64(shnum: u16) -> Vec<u8> {
    let entsize: u16 = 64;
    let shoff: u64 = 64;
    let size = 64 + shnum as usize * entsize as usize;
    let mut v = vec![0u8; size];
    v[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    v[4] = 2; // 64-bit
    v[5] = 1; // little-endian
    v[6] = 1; // version
    v[0x28..0x30].copy_from_slice(&shoff.to_le_bytes()); // e_shoff
    v[0x3A..0x3C].copy_from_slice(&entsize.to_le_bytes()); // e_shentsize
    v[0x3C..0x3E].copy_from_slice(&shnum.to_le_bytes()); // e_shnum
    for (i, b) in v.iter_mut().enumerate().skip(64) {
        *b = (i % 251) as u8;
    }
    v
}

#[test]
fn recovers_brands_and_elf() {
    let avif = iso_bmff(b"avif", &filler(1, 1800));
    let cr3 = iso_bmff(b"crx ", &filler(2, 2200));
    let jxl = iso_bmff(b"jxl ", &filler(3, 1500));
    let g3p = iso_bmff(b"3gp4", &filler(4, 2600));
    let elf = elf64(3); // 64 + 3*64 = 256 bytes

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    for (gap, file) in [
        (1000usize, &avif),
        (300, &cr3),
        (300, &jxl),
        (300, &g3p),
        (300, &elf),
    ] {
        img.write_all(&vec![0u8; gap]).unwrap();
        img.write_all(file).unwrap();
    }
    // Trailing noise so the last atom/section walk stops cleanly.
    img.write_all(&vec![0u8; 1000]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&[]).unwrap();
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
    assert_eq!(stats.files_recovered, 5, "avif, cr3, jxl, 3gp, elf");

    for ext in ["avif", "cr3", "jxl", "3gp", "elf"] {
        assert_eq!(stats.per_type.get(ext), Some(&1), "missing {ext}");
    }

    let mut recovered: Vec<Vec<u8>> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    recovered.sort();
    let mut originals = vec![avif, cr3, jxl, g3p, elf];
    originals.sort();
    assert_eq!(recovered, originals, "recovered bytes must match originals");
}

/// A minimal PE32+ executable with two sections and no certificate overlay.
/// Layout: 64-byte DOS header (e_lfanew = 64), PE sig + COFF header, a 112-byte
/// optional header (PE32+ magic, NumberOfRvaAndSizes = 0), then the section
/// table. The file ends at the furthest `PointerToRawData + SizeOfRawData`.
fn pe_exe() -> Vec<u8> {
    let opt_size: usize = 112;
    let headers = 64 + 4 + 20 + opt_size + 2 * 40; // dos + sig + coff + opt + 2 sections
    let s0_ptr = headers; // first section's raw data
    let s0_size = 200usize;
    let s1_ptr = s0_ptr + s0_size;
    let s1_size = 100usize;
    let total = s1_ptr + s1_size;

    let mut v = vec![0u8; total];
    v[0..2].copy_from_slice(b"MZ");
    v[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes()); // e_lfanew

    let pe = 64usize;
    v[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    v[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine = x64
    v[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections
    v[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());

    let opt = coff + 20;
    v[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
    v[opt + 108..opt + 112].copy_from_slice(&0u32.to_le_bytes()); // NumberOfRvaAndSizes

    let mut section = |i: usize, size_raw: u32, ptr_raw: u32| {
        let s = opt + opt_size + i * 40;
        v[s + 16..s + 20].copy_from_slice(&size_raw.to_le_bytes());
        v[s + 20..s + 24].copy_from_slice(&ptr_raw.to_le_bytes());
    };
    section(0, s0_size as u32, s0_ptr as u32);
    section(1, s1_size as u32, s1_ptr as u32);

    for (i, b) in v.iter_mut().enumerate().skip(s0_ptr) {
        *b = (i % 251) as u8;
    }
    v
}

#[test]
fn recovers_pe_executable() {
    let exe = pe_exe();

    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&vec![0u8; 700]).unwrap();
    img.write_all(&exe).unwrap();
    img.write_all(&vec![0u8; 700]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&["exe".to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one PE executable");
    assert_eq!(stats.per_type.get("exe"), Some(&1));

    let recovered = std::fs::read_dir(&out_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(
        std::fs::read(recovered).unwrap(),
        exe,
        "byte-for-byte match"
    );
}

/// Build a minimal little-endian classic TIFF whose single IFD points (via a
/// StripOffsets/StripByteCounts pair) at a block of image data. When `cr2` is
/// set, the IFD is placed at offset 16 and a `CR\x02\x00` marker is written at
/// offset 8, matching the Canon CR2 header. The file ends where the strip ends.
fn tiff_le(image: &[u8], cr2: bool) -> Vec<u8> {
    let n_entries: u16 = 4;
    let ifd_off: usize = if cr2 { 16 } else { 8 };
    let ifd_len = 2 + n_entries as usize * 12 + 4;
    let strip_off = ifd_off + ifd_len; // image data right after the IFD
    let total = strip_off + image.len();

    let mut v = vec![0u8; total];
    v[0..2].copy_from_slice(b"II");
    v[2..4].copy_from_slice(&42u16.to_le_bytes());
    v[4..8].copy_from_slice(&(ifd_off as u32).to_le_bytes());
    if cr2 {
        v[8..12].copy_from_slice(b"CR\x02\x00");
    }

    v[ifd_off..ifd_off + 2].copy_from_slice(&n_entries.to_le_bytes());
    let mut entry = |idx: usize, tag: u16, typ: u16, count: u32, value: u32| {
        let e = ifd_off + 2 + idx * 12;
        v[e..e + 2].copy_from_slice(&tag.to_le_bytes());
        v[e + 2..e + 4].copy_from_slice(&typ.to_le_bytes());
        v[e + 4..e + 8].copy_from_slice(&count.to_le_bytes());
        v[e + 8..e + 12].copy_from_slice(&value.to_le_bytes());
    };
    entry(0, 256, 4, 1, 64); // ImageWidth (LONG)
    entry(1, 257, 4, 1, image.len() as u32 / 64); // ImageLength
    entry(2, 273, 4, 1, strip_off as u32); // StripOffsets -> image data
    entry(3, 279, 4, 1, image.len() as u32); // StripByteCounts
    let next = ifd_off + 2 + n_entries as usize * 12;
    v[next..next + 4].copy_from_slice(&0u32.to_le_bytes()); // no next IFD

    v[strip_off..strip_off + image.len()].copy_from_slice(image);
    v
}

fn carve_one(file: &[u8], ext: &str) -> Vec<u8> {
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    let out_dir = tmp.path().join("out");

    let mut img = std::fs::File::create(&img_path).unwrap();
    img.write_all(&vec![0u8; 600]).unwrap();
    img.write_all(file).unwrap();
    img.write_all(&vec![0u8; 600]).unwrap();
    img.flush().unwrap();
    drop(img);

    let source = Source::open(&img_path).unwrap();
    let sigs = signatures::select(&[ext.to_string()]).unwrap();
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
    assert_eq!(stats.files_recovered, 1, "one {ext}");
    assert_eq!(stats.per_type.get(ext), Some(&1));
    std::fs::read(
        std::fs::read_dir(&out_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path(),
    )
    .unwrap()
}

#[test]
fn recovers_tiff() {
    let tif = tiff_le(&filler(7, 4000), false);
    assert_eq!(carve_one(&tif, "tif"), tif, "TIFF byte-for-byte");
}

#[test]
fn recovers_cr2_via_secondary_tag() {
    let cr2 = tiff_le(&filler(8, 5000), true);
    // The "CR" tag at offset 8 selects the cr2 signature over generic TIFF.
    assert_eq!(carve_one(&cr2, "cr2"), cr2, "CR2 byte-for-byte");
}

/// Build a minimal little-endian BigTIFF: a 16-byte header (magic 43, 8-byte
/// offsets), one IFD with an 8-byte count, 20-byte entries, and 8-byte offsets,
/// whose StripOffsets/StripByteCounts point at a block of image data.
fn bigtiff_le(image: &[u8]) -> Vec<u8> {
    let n_entries: u64 = 4;
    let ifd_off: usize = 16;
    let ifd_len = 8 + n_entries as usize * 20 + 8; // count + entries + next-IFD
    let strip_off = ifd_off + ifd_len;
    let total = strip_off + image.len();

    let mut v = vec![0u8; total];
    v[0..2].copy_from_slice(b"II");
    v[2..4].copy_from_slice(&43u16.to_le_bytes()); // BigTIFF magic
    v[4..6].copy_from_slice(&8u16.to_le_bytes()); // offset byte size
    v[6..8].copy_from_slice(&0u16.to_le_bytes()); // reserved
    v[8..16].copy_from_slice(&(ifd_off as u64).to_le_bytes()); // first IFD offset

    v[ifd_off..ifd_off + 8].copy_from_slice(&n_entries.to_le_bytes());
    let mut entry = |idx: usize, tag: u16, typ: u16, count: u64, value: u64| {
        let e = ifd_off + 8 + idx * 20;
        v[e..e + 2].copy_from_slice(&tag.to_le_bytes());
        v[e + 2..e + 4].copy_from_slice(&typ.to_le_bytes());
        v[e + 4..e + 12].copy_from_slice(&count.to_le_bytes());
        v[e + 12..e + 20].copy_from_slice(&value.to_le_bytes());
    };
    entry(0, 256, 4, 1, 64); // ImageWidth (LONG)
    entry(1, 257, 4, 1, image.len() as u64 / 64); // ImageLength
    entry(2, 273, 16, 1, strip_off as u64); // StripOffsets (LONG8) -> image
    entry(3, 279, 16, 1, image.len() as u64); // StripByteCounts (LONG8)
    let next = ifd_off + 8 + n_entries as usize * 20;
    v[next..next + 8].copy_from_slice(&0u64.to_le_bytes()); // no next IFD

    v[strip_off..strip_off + image.len()].copy_from_slice(image);
    v
}

#[test]
fn recovers_bigtiff() {
    let big = bigtiff_le(&filler(9, 6400));
    assert_eq!(carve_one(&big, "tif"), big, "BigTIFF byte-for-byte");
}

/// Encode `value` as an EBML variable-length integer of `len` bytes, including
/// the leading length-marker bit.
fn ebml_vint(value: u64, len: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; len as usize];
    for i in 0..len as usize {
        bytes[len as usize - 1 - i] = (value >> (8 * i)) as u8;
    }
    bytes[0] |= 1u8 << (8 - len);
    bytes
}

/// A minimal Matroska/WebM file: an empty EBML header element followed by a
/// known-size Segment wrapping the payload.
fn mkv(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x1A, 0x45, 0xDF, 0xA3]); // EBML header ID
    v.extend_from_slice(&ebml_vint(0, 1)); // header data size = 0
    v.extend_from_slice(&[0x18, 0x53, 0x80, 0x67]); // Segment ID
    v.extend_from_slice(&ebml_vint(payload.len() as u64, 8)); // 8-byte segment size
    v.extend_from_slice(payload);
    v
}

#[test]
fn recovers_matroska() {
    let video = mkv(&filler(11, 7000));
    assert_eq!(carve_one(&video, "mkv"), video, "MKV byte-for-byte");
}

/// Build one Ogg page: the 27-byte header, a lacing segment table sized to the
/// body, then the body.
fn ogg_page(header_type: u8, serial: u32, seqno: u32, body: &[u8]) -> Vec<u8> {
    let mut segs = Vec::new();
    let mut remaining = body.len();
    loop {
        if remaining >= 255 {
            segs.push(255u8);
            remaining -= 255;
        } else {
            segs.push(remaining as u8);
            break;
        }
    }
    let mut v = Vec::new();
    v.extend_from_slice(b"OggS");
    v.push(0); // version
    v.push(header_type);
    v.extend_from_slice(&0u64.to_le_bytes()); // granule position
    v.extend_from_slice(&serial.to_le_bytes());
    v.extend_from_slice(&seqno.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // CRC (ignored by the carver)
    v.push(segs.len() as u8);
    v.extend_from_slice(&segs);
    v.extend_from_slice(body);
    v
}

/// A two-page Ogg bitstream (BOS then EOS).
fn ogg(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    let mut v = ogg_page(0x02, 1, 0, b1); // begin-of-stream
    v.extend(ogg_page(0x04, 1, 1, b2)); // end-of-stream
    v
}

#[test]
fn recovers_ogg() {
    let audio = ogg(&filler(12, 600), &filler(13, 3000));
    assert_eq!(carve_one(&audio, "ogg"), audio, "Ogg byte-for-byte");
}

const ASF_HEADER_GUID: [u8; 16] = [
    0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
];
const ASF_DATA_GUID: [u8; 16] = [
    0x36, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
];

/// One ASF object: its 16-byte GUID, a 64-bit size covering the whole object,
/// then the payload.
fn asf_obj(guid: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut v = guid.to_vec();
    v.extend_from_slice(&(24 + payload.len() as u64).to_le_bytes());
    v.extend_from_slice(payload);
    v
}

#[test]
fn recovers_asf() {
    let mut wmv = asf_obj(&ASF_HEADER_GUID, &filler(14, 500));
    wmv.extend(asf_obj(&ASF_DATA_GUID, &filler(15, 4000)));
    assert_eq!(carve_one(&wmv, "asf"), wmv, "ASF byte-for-byte");
}

/// Encode an unsigned LEB128 integer (only the small single-/double-byte cases
/// the test needs).
fn leb128(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        out.push(b);
        if value == 0 {
            break;
        }
    }
    out
}

/// A minimal WebAssembly module: the 8-byte header then sections of
/// `(id, content)`.
fn wasm(sections: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut v = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    for (id, content) in sections {
        v.push(*id);
        v.extend(leb128(content.len() as u64));
        v.extend_from_slice(content);
    }
    v
}

#[test]
fn recovers_wasm() {
    let module = wasm(&[(1, filler(16, 100)), (10, filler(17, 5000))]);
    assert_eq!(carve_one(&module, "wasm"), module, "WASM byte-for-byte");
}

/// A minimal Windows icon: a directory of `images`, each placed right after the
/// directory, with size and offset recorded per entry.
/// Each image is stored as a DIB: a BITMAPINFOHEADER (40 bytes, its size in
/// the first field) followed by the pixel payload, as real icons are.
fn ico(payloads: &[Vec<u8>]) -> Vec<u8> {
    let images: Vec<Vec<u8>> = payloads
        .iter()
        .map(|p| {
            let mut v = vec![0u8; 40];
            v[0..4].copy_from_slice(&40u32.to_le_bytes());
            v.extend_from_slice(p);
            v
        })
        .collect();
    let images = &images;
    let count = images.len();
    let dir_end = 6 + count * 16;
    let total = dir_end + images.iter().map(|i| i.len()).sum::<usize>();
    let mut v = vec![0u8; total];
    v[2..4].copy_from_slice(&1u16.to_le_bytes()); // type = icon
    v[4..6].copy_from_slice(&(count as u16).to_le_bytes());
    let mut off = dir_end;
    for (i, img) in images.iter().enumerate() {
        let e = 6 + i * 16;
        v[e] = 32; // width
        v[e + 1] = 32; // height
        v[e + 8..e + 12].copy_from_slice(&(img.len() as u32).to_le_bytes());
        v[e + 12..e + 16].copy_from_slice(&(off as u32).to_le_bytes());
        v[off..off + img.len()].copy_from_slice(img);
        off += img.len();
    }
    v
}

#[test]
fn recovers_ico() {
    let icon = ico(&[filler(18, 1200), filler(19, 800)]);
    assert_eq!(carve_one(&icon, "ico"), icon, "ICO byte-for-byte");
}
