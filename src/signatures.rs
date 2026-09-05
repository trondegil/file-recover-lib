//! Known file-type signatures and the strategy used to find where each
//! recovered file ends.
//!
//! Carving works by locating a *header* (a magic byte sequence) on the raw
//! device, then determining the file's length with one of a few strategies:
//!
//! * [`Extent::Footer`] — scan forward for a trailing marker (JPEG, PNG, ...).
//! * [`Extent::HeaderSizeLe32`] — read a little-endian u32 size field (BMP, CAB,
//!   little-endian DPX, TRX firmware).
//! * [`Extent::RiffSize`] — RIFF container size at offset 4, plus the 8-byte
//!   chunk header (WAV, AVI, WEBP).
//! * [`Extent::FormSize`] — IFF "FORM" container size (big-endian) at offset 4,
//!   plus the 8-byte chunk header (AIFF, AIFF-C).
//! * [`Extent::Sqlite`] — page size × page count from the SQLite header.
//! * [`Extent::SevenZip`] — next-header offset + size from the 7z header.
//! * [`Extent::Mp4Atoms`] — walk the ISO base-media box/atom structure (MP4,
//!   MOV, HEIC, AVIF, CR3, ...).
//! * [`Extent::Elf`] — read the ELF header's section-header-table location to
//!   find where the file ends.
//! * [`Extent::Pe`] — walk a PE/COFF section table (and the certificate
//!   overlay) to find where a Windows executable ends.
//! * [`Extent::Tiff`] — walk the TIFF IFD chain (and sub-IFDs, strip/tile
//!   arrays) to find the end of a TIFF or TIFF-based raw image.
//! * [`Extent::Ebml`] — read the Matroska/WebM segment size (or walk its
//!   top-level elements) to find where the container ends.
//! * [`Extent::Ogg`] — walk the chain of Ogg pages (each sized by its segment
//!   table) to the end of the bitstream.
//! * [`Extent::Asf`] — walk the top-level ASF objects (WMV/WMA), each a GUID
//!   plus a 64-bit size, to the end of the container.
//! * [`Extent::Wasm`] — walk a WebAssembly module's sections (LEB128-sized) to
//!   the end of the module.
//! * [`Extent::IcoCur`] — take the furthest `offset + size` across an ICO/CUR
//!   image directory.
//! * [`Extent::HeaderSizeBe32`] — read a big-endian u32 size field (WOFF fonts,
//!   big-endian DPX, Cineon, device-tree blobs, Android DTBO images).
//! * [`Extent::Sfnt`] — walk a TrueType/OpenType font's table directory.
//! * [`Extent::Midi`] — walk a Standard MIDI file's `MThd`/`MTrk` chunks.
//! * [`Extent::Flv`] — walk a Flash Video tag chain.
//! * [`Extent::Pcap`] / [`Extent::Pcapng`] — walk a network-capture file's
//!   packet records / blocks.
//! * [`Extent::Ttc`] — walk a TrueType Collection's member font directories.
//! * [`Extent::Rar`] — walk a RAR archive's block chain (v4 and v5) to the
//!   end-of-archive block.
//! * [`Extent::Zstd`] — walk a Zstandard frame's data blocks to the last block
//!   (plus the optional content checksum).
//! * [`Extent::Lz4`] — walk an LZ4 frame's data blocks to the end mark (plus
//!   optional block/content checksums).
//! * [`Extent::Psd`] — sum a Photoshop document's header, length-prefixed
//!   sections, and image data (raw or RLE).
//! * [`Extent::Wmf`] — read a Windows Metafile's `mtSize` (total size in words).
//! * [`Extent::Djvu`] — read a DjVu document's IFF `FORM` length.
//! * [`Extent::Evtx`] — size a Windows Event Log from its chunk count.
//! * [`Extent::Rtf`] — match an RTF document's outer `{ ... }` group.
//! * [`Extent::Mp3`] — walk MPEG audio frames from an ID3v2 tag to the end.
//! * [`Extent::MachO`] — sum a Mach-O binary's segments and link-edit tables.
//! * [`Extent::Regf`] — Windows registry hive: base block + hive-bins data.
//! * [`Extent::Aac`] — walk ADTS AAC audio frames to the end of the stream.
//! * [`Extent::Dex`] — Android Dalvik executable: `file_size` header field.
//! * [`Extent::Icc`] — ICC colour profile: total size in the profile header.
//! * [`Extent::Ar`] — Unix `ar` archive (`.a`/`.deb`): walk the member chain.
//! * [`Extent::Shp`] — ESRI Shapefile: total length (in 16-bit words) in header.
//! * [`Extent::Blend`] — Blender file: walk the block chain to the `ENDB` block.
//! * [`Extent::Nes`] — iNES / NES 2.0 ROM: size from the PRG/CHR bank counts.
//! * [`Extent::Gameboy`] — Game Boy / Color ROM: size from the header size byte.
//! * [`Extent::Wad`] — Doom WAD: end from the lump count and directory offset.
//! * [`Extent::Au`] — Sun/NeXT `.au` audio: data offset plus data size in header.
//! * [`Extent::Genesis`] — Sega Mega Drive / Genesis ROM: end address in header.
//! * [`Extent::Voc`] — Creative Voice audio: walk the block chain to the end.
//! * [`Extent::Amr`] — AMR audio: walk fixed-size speech frames to the end.
//! * [`Extent::PsxExe`] — PlayStation executable: 2 KiB header plus text size.
//! * [`Extent::AndroidSparse`] — Android sparse image: sum the chunk sizes.
//! * [`Extent::Mp3Raw`] — MP3 anchored on a frame sync (no ID3v2 tag).
//! * [`Extent::Wim`] — Windows Imaging (WIM): furthest resource-table extent.
//! * [`Extent::Swf`] — uncompressed Flash movie (`FWS`): `FileLength` at offset 4.
//! * [`Extent::Cfbf`] — OLE2 compound file: walk the FAT to the last used sector.
//! * [`Extent::Pst`] — Outlook data file (PST/OST): `ibFileEof` in the header.
//! * [`Extent::Tar`] — `tar` archive: walk the 512-byte member chain to the
//!   zero-block terminator.
//! * [`Extent::Cpio`] — `cpio` archive (newc): walk the entry chain to the
//!   `TRAILER!!!` entry.
//! * [`Extent::Squashfs`] — SquashFS image: `bytes_used` from the superblock.
//! * [`Extent::Iso9660`] — ISO 9660 disc image: volume space size × logical
//!   block size from the primary volume descriptor.
//! * [`Extent::Flic`] — Autodesk FLIC animation: the total size stored in the
//!   header's first field.
//! * [`Extent::WavPack`] — WavPack lossless audio: walk the `wvpk` block chain
//!   to the last whole block.
//! * [`Extent::Ape`] — Monkey's Audio: sum the segment byte counts in the
//!   descriptor.
//! * [`Extent::AppleSingle`] — AppleSingle/AppleDouble: the largest entry
//!   offset-plus-length in the entry table.
//! * [`Extent::SunRaster`] — Sun raster image: 32-byte header + colormap length
//!   + image-data length.
//! * [`Extent::Dsf`] — DSF (DSD audio): the total file size stored in the DSD
//!   chunk.
//! * [`Extent::Dsdiff`] — DSDIFF (DSD audio): the FRM8 form size plus its
//!   12-byte header.
//! * [`Extent::Pcf`] — PCF bitmap font: the largest table offset-plus-size in
//!   the table of contents.
//! * [`Extent::UImage`] — U-Boot uImage: the 64-byte header plus the image-data
//!   size field.
//! * [`Extent::QuakePak`] — Quake PAK archive: the directory offset plus its
//!   length.
//! * [`Extent::Md2`] — Quake II model: the end-of-file offset in the header.
//! * [`Extent::Ivf`] — IVF (AV1/VP9): walk the frame count from the header.
//! * [`Extent::Zim`] — ZIM archive: the checksum position plus the trailing
//!   MD5.
//! * [`Extent::Gguf`] — GGUF model: walk the metadata and tensor tables to the
//!   aligned end of the tensor data.
//! * [`Extent::BootImg`] — Android boot image: sum the page-rounded sections.
//! * [`Extent::Ktx2`] — KTX2 GPU texture: the largest section offset-plus-length
//!   across the level index and data descriptors.
//! * [`Extent::Qoa`] — QOA audio: walk the frame chain for the header's sample
//!   count.
//! * [`Extent::VendorBoot`] — Android vendor_boot image: sum the page-rounded
//!   sections.
//! * [`Extent::Npy`] — NumPy array: the header plus `product(shape) × itemsize`.
//! * [`Extent::Journal`] — systemd journal: the header size plus the arena size.
//! * [`Extent::UnityFs`] — Unity asset bundle: the total-size field after the
//!   version strings.
//! * [`Extent::Raf`] — Fuji RAF raw: the largest section offset-plus-length in
//!   the header.
//! * [`Extent::Vpk`] — Valve VPK archive: the sum of the section sizes in the
//!   v2 header.
//! * [`Extent::Las`] — LAS point cloud: the point-data offset plus
//!   `point_count × record_length`.
//! * [`Extent::GodotPck`] — Godot asset pack: walk the directory to the last
//!   file's end.
//! * [`Extent::E57`] — E57 point cloud: the physical file length in the header.
//! * [`Extent::Rf64`] — RF64/BW64 audio: the 64-bit RIFF size from the `ds64`
//!   chunk.
//! * [`Extent::Nifti`] — NIfTI neuroimaging volume: the data offset plus
//!   `product(dims) × bytes-per-voxel`.
//! * [`Extent::Usdc`] — USD crate scene: the largest section end in the table of
//!   contents.
//! * [`Extent::Avro`] — Avro container: walk the data blocks by their
//!   sync marker.
//! * [`Extent::Hdf5`] — HDF5 data file: the end-of-file address in the
//!   superblock.
//! * [`Extent::Dds`] — DDS texture: the header plus the computed mip-chain size.
//! * [`Extent::Astc`] — ASTC texture: the 16-byte header plus 16 bytes per
//!   block.
//! * [`Extent::Glb`] — glTF binary 3D model: the total-length field in the
//!   header, confirmed by a chunk walk.
//! * [`Extent::Erofs`] — EROFS filesystem image: the block count in the
//!   superblock times the block size.
//! * [`Extent::Ktx1`] — KTX (v1) GPU texture: the header plus the mip levels,
//!   each sized by its own explicit `imageSize` field.
//! * [`Extent::Exr`] — OpenEXR image: the chunk offset table (whose first entry
//!   reveals its own length) walked to the last chunk.
//! * [`Extent::Mcap`] — MCAP log: the record stream walked to the footer record
//!   plus the trailing magic.
//! * [`Extent::Bsp`] — Source-engine BSP map: the furthest lump end in the
//!   64-entry lump directory.
//! * [`Extent::Qoi`] — QOI image: the chunk stream decoded to the pixel count,
//!   then the 8-byte end marker.
//! * [`Extent::Rpm`] — RPM package: the lead and padded signature header plus
//!   the header/payload size recorded in the signature.
//! * [`Extent::Farbfeld`] — farbfeld image: a fixed header plus
//!   `width × height × 8` bytes of pixel data.
//! * [`Extent::Y4m`] — YUV4MPEG2 stream: the fixed-size frames walked from the
//!   header's dimensions and colourspace.
//! * [`Extent::Pvr`] — PVR v3 texture: the header, metadata, and the
//!   block-compressed mip chain.
//! * [`Extent::Blp`] — BLP2 texture: the furthest mipmap end in the 16-entry
//!   offset/length directory.
//! * [`Extent::Grib2`] — GRIB2 weather data: the per-message total-length fields
//!   walked (each validated by its `7777` end marker).
//! * [`Extent::F2fs`] — F2FS filesystem image: the block count in the superblock
//!   times the block size.
//! * [`Extent::Btrfs`] — btrfs filesystem image: the `total_bytes` field in the
//!   superblock (single-device images).
//! * [`Extent::Xfs`] — XFS filesystem image: the data-block count in the
//!   superblock times the block size.
//! * [`Extent::Exfat`] — exFAT filesystem image: the volume length in the boot
//!   sector times the sector size.
//! * [`Extent::Apfs`] — APFS container image: the block count in the container
//!   superblock times the block size.
//! * [`Extent::Refs`] — ReFS filesystem image: the sector count in the boot
//!   record times the sector size.
//! * [`Extent::Ntfs`] — NTFS filesystem image: the total-sectors field in the
//!   boot sector times the sector size.
//! * [`Extent::Swap`] — Linux swap area: the last-page index in the header times
//!   the page size.
//! * [`Extent::Romfs`] — romfs image: the full-image-size field in the header.
//! * [`Extent::Cramfs`] — cramfs image: the total-size field in the superblock.
//! * [`Extent::Jfs`] — JFS filesystem image: the aggregate block count in the
//!   superblock times the physical block size.
//! * [`Extent::Ufs`] — UFS1 filesystem image: the fragment count in the
//!   superblock times the fragment size.
//! * [`Extent::Befs`] — BeFS filesystem image: the block count in the superblock
//!   times the block size.
//! * [`Extent::HfsPlus`] — HFS+ filesystem image: the block count in the volume
//!   header times the block size.
//! * [`Extent::Reiserfs`] — ReiserFS filesystem image: the block count in the
//!   superblock times the block size.
//!
//! Adding a new file type is just a matter of appending a [`Signature`] to
//! [`SIGNATURES`].

/// How to determine the length of a carved file once its header is found.
#[derive(Clone, Copy, Debug)]
pub enum Extent {
    /// Search forward for `marker`; the file ends at the end of the marker,
    /// plus up to `trailing` CR/LF bytes for a format whose marker is
    /// conventionally followed by a line ending (PDF's `%%EOF`).
    Footer {
        marker: &'static [u8],
        trailing: u64,
    },
    /// The total file size is stored as a little-endian u32 at `offset` bytes
    /// into the file (relative to the file start).
    HeaderSizeLe32 { offset: usize },
    /// RIFF container: total size = (little-endian u32 at offset 4) + 8.
    RiffSize,
    /// IFF "FORM" container (AIFF/AIFF-C, and other EA-IFF-85 types): total size
    /// = (big-endian u32 at offset 4) + 8. The big-endian sibling of
    /// [`Extent::RiffSize`].
    FormSize,
    /// SQLite database: total size = page_size × page_count (big-endian fields
    /// in the file header).
    Sqlite,
    /// 7-Zip archive: total size = 32 + NextHeaderOffset + NextHeaderSize
    /// (little-endian u64 fields in the signature header).
    SevenZip,
    /// Parse the ISO base-media (MP4/QuickTime/HEIF) box structure to sum atoms.
    Mp4Atoms,
    /// ELF object: total size = section-header-table offset + entry count ×
    /// entry size (the section header table normally ends the file). Handles
    /// 32/64-bit and either byte order from the ELF identification bytes.
    Elf,
    /// PE (Windows EXE/DLL): follow the DOS stub to the PE header, then take the
    /// largest `PointerToRawData + SizeOfRawData` across the section table, also
    /// accounting for an appended certificate (Authenticode) overlay.
    Pe,
    /// TIFF / TIFF-based raw (CR2, NEF, DNG, ARW, ...): walk the IFD chain and
    /// sub-IFDs, taking the furthest extent of all field data and the strip/tile
    /// image arrays. Handles little- and big-endian.
    Tiff,
    /// Matroska / WebM (EBML): take the Segment element's declared size, or, for
    /// an unknown-size Segment, sum its top-level child elements.
    Ebml,
    /// Ogg (Vorbis/Opus/Theora): walk consecutive `OggS` pages, each sized by
    /// its segment table, to the end of the bitstream.
    Ogg,
    /// ASF (WMV/WMA/ASF): walk the top-level objects, each a 16-byte GUID plus a
    /// 64-bit little-endian size, stopping at the first unrecognised object.
    Asf,
    /// WebAssembly: after the 8-byte header, walk the sections (each a 1-byte id
    /// and an unsigned LEB128 size) to the end of the module.
    Wasm,
    /// ICO / CUR: the icon directory lists each image's size and offset; the
    /// file ends at the furthest `offset + size`.
    IcoCur,
    /// The total file size is stored as a big-endian u32 at `offset` bytes into
    /// the file (e.g. WOFF/WOFF2 web fonts store their length at offset 8).
    HeaderSizeBe32 { offset: usize },
    /// SFNT font (TrueType/OpenType): walk the table directory, taking the
    /// furthest `offset + length` (padded to 4 bytes) across all tables.
    Sfnt,
    /// Standard MIDI file: an `MThd` header chunk followed by `MTrk` chunks, each
    /// a 4-byte tag and a big-endian u32 length; walk them to the end.
    Midi,
    /// Flash Video (FLV): a 9-byte header then a chain of tags, each an 11-byte
    /// tag header (with a 24-bit big-endian data size) plus a trailing 4-byte
    /// previous-tag-size field; walk them to the end.
    Flv,
    /// libpcap capture: a 24-byte global header (whose magic also gives the byte
    /// order) followed by packet records, each a 16-byte header with a captured
    /// length; walk the records to the end.
    Pcap,
    /// pcapng capture: a chain of blocks, each carrying its own total length as a
    /// u32 (byte order from the first Section Header Block); walk them to the end.
    Pcapng,
    /// TrueType Collection (`ttcf`): a header listing each member font's table
    /// directory; walk every font's tables to the furthest `offset + length`.
    Ttc,
    /// RAR archive (v4 and v5): walk the block chain — each block carries its
    /// own header and data sizes — to the end-of-archive marker block. Handles
    /// both the classic v4 layout and the v5 variable-length-integer layout.
    Rar,
    /// Zstandard frame: parse the frame header, then walk the data blocks (each
    /// a 3-byte header giving its size and a last-block flag) to the final
    /// block, adding the 4-byte content checksum when the header flags one.
    Zstd,
    /// LZ4 frame: parse the frame descriptor, then walk the data blocks (each a
    /// 4-byte size prefix) to the zero-sized end mark, accounting for optional
    /// per-block and content checksums.
    Lz4,
    /// Photoshop document (PSD/PSB): a fixed header, three length-prefixed
    /// sections (colour-mode data, image resources, layer & mask info), then the
    /// image data whose size is computed from the dimensions for raw storage or
    /// summed from the per-scanline byte counts for PackBits (RLE).
    Psd,
    /// Windows Metafile (WMF): the metafile header records its total size in
    /// 16-bit words (`mtSize`); the file ends there, after the 22-byte placeable
    /// header when one is present.
    Wmf,
    /// DjVu document (`AT&TFORM` + IFF `FORM`): the big-endian FORM length at
    /// offset 8 covers everything after it, so the file ends at `12 + length`.
    Djvu,
    /// Windows Event Log (`ElfFile\0`): a 4096-byte file header records the
    /// number of 64 KiB chunks, so the file ends at `4096 + chunks * 65536`.
    Evtx,
    /// Rich Text Format: the document is one big `{ ... }` group, so the file
    /// ends where the opening brace's match closes. Backslash escapes (`\{`,
    /// `\}`, `\\`) are honoured. (Embedded `\bin` binary blobs, which are
    /// uncommon, are not specially skipped.)
    Rtf,
    /// MPEG audio (MP3): anchored on an ID3v2 tag, skip the tag (using its
    /// synchsafe size, plus a footer when flagged) and walk the MPEG audio
    /// frames — each header encoding version/layer/bitrate/sample-rate, from
    /// which the frame length is computed — to the end of the stream, including
    /// a trailing 128-byte ID3v1 (`TAG`) tag when present.
    Mp3,
    /// Mach-O binary (macOS/iOS executables, dylibs, bundles): parse the header
    /// to read the load commands, then take the furthest extent of every
    /// `LC_SEGMENT`/`LC_SEGMENT_64` (`fileoff + filesize`) and link-edit table
    /// (symbol/string tables and `dataoff + datasize` blobs such as the code
    /// signature, which normally ends the file). Handles 32/64-bit and either
    /// byte order from the magic. Fat/universal binaries (`0xCAFEBABE`, which
    /// collides with Java class files) are not carved.
    MachO,
    /// Windows registry hive (`regf`): the 4096-byte base block records the
    /// total size of the hive-bins data area at offset 0x28, so the file ends at
    /// `4096 + hive_bins_data_size`. The version and file-type fields are checked
    /// to reject a coincidental magic.
    Regf,
    /// AAC audio in an ADTS stream: each 7-byte (or 9-byte with CRC) frame
    /// header carries a 13-bit frame length, so the stream is walked frame to
    /// frame to its end. Frames are validated (sync word, fixed layer bits, a
    /// valid and consistent sample-rate index) and several consecutive frames
    /// are required, so the short sync word cannot trigger a false carve.
    Aac,
    /// Android Dalvik executable (`dex\n`): the header stores the total file
    /// size as a little-endian u32 at offset 0x20, so the file ends there. The
    /// endian tag (0x12345678 at 0x28) and header size (0x70 at 0x24) are
    /// checked to reject a coincidental magic.
    Dex,
    /// ICC colour profile: the 128-byte profile header opens with the total
    /// profile size as a big-endian u32 at offset 0, and carries the `acsp`
    /// file signature at offset 36 (the magic anchors there). The size must be
    /// at least the header size and a multiple of 4 (profiles are 4-byte
    /// padded), which rejects a coincidental `acsp` match.
    Icc,
    /// Unix `ar` archive (Debian `.deb` packages and `.a` static libraries):
    /// after the `!<arch>\n` global header, walk the member chain. Each member
    /// has a 60-byte header ending in the `` `\n `` sentinel (validated to find
    /// the archive's end) and carrying its data size as a decimal field; member
    /// data is padded to an even length.
    Ar,
    /// ESRI Shapefile (`.shp`/`.shx`): the 100-byte header stores the total file
    /// length as a big-endian u32 at offset 24, counted in 16-bit words, so the
    /// file ends at `length * 2`. The file code (9994 at offset 0) and version
    /// (1000 at offset 28) are checked to reject a coincidental magic.
    Shp,
    /// Blender file (`.blend`): a 12-byte header (`BLENDER` + pointer-size and
    /// endianness flags + version) followed by a chain of file blocks, each with
    /// a header carrying its data size; walk the chain to the terminating `ENDB`
    /// block, which gives an exact end. The pointer-size and endianness flags are
    /// validated to reject a coincidental magic.
    Blend,
    /// iNES / NES 2.0 ROM (`NES\x1a`): the 16-byte header records the PRG and
    /// CHR ROM bank counts, so the file ends at `16 + trainer + prg * 16384 +
    /// chr * 8192` (the trainer is an optional 512 bytes). NES 2.0 extends the
    /// bank counts with high bits; ROMs using the exponent bank form or carrying
    /// an indeterminate miscellaneous-ROM area are rejected.
    Nes,
    /// Game Boy / Game Boy Color ROM, anchored on the 48-byte Nintendo logo at
    /// offset 0x104 (which the boot ROM verifies, so it is an exact magic). The
    /// ROM size is encoded at offset 0x148 as `32 KiB << code` (codes 0–8); the
    /// header checksum at 0x14D is verified to reject a coincidental logo match.
    /// The rare unofficial size codes are not computed and are rejected.
    Gameboy,
    /// Doom WAD archive (`IWAD`/`PWAD`): the 12-byte header records the lump
    /// count and the byte offset of the lump directory. The Doom engine writes
    /// the directory last, so the file ends at `directory_offset + lumps * 16`
    /// (each directory entry is 16 bytes). The lump count and directory offset
    /// are range-checked to reject a coincidental `IWAD`/`PWAD` match.
    Wad,
    /// Sun/NeXT `.au` (`.snd`) audio: the big-endian header records the byte
    /// offset of the audio data and its length, so the file ends at
    /// `data_offset + data_size`. A data size of `0xFFFFFFFF` means the length is
    /// unknown (streamed), so those are not carved. The data offset and encoding
    /// code are range-checked to reject a coincidental `.snd` match.
    Au,
    /// Sega Mega Drive / Genesis ROM, anchored on the `SEGA` signature in the
    /// cartridge header at offset 0x100. The header records the ROM's start and
    /// end addresses (big-endian u32 at 0x1A0 / 0x1A4); a ROM is mapped from
    /// address 0, so the file ends at `end_address + 1`. The start address (must
    /// be 0) and a plausible end address guard the short `SEGA` match. This is
    /// the plain (non-interleaved) ROM layout; the interleaved `.smd` format
    /// carries a 512-byte header instead and is not matched.
    Genesis,
    /// Creative Voice File (`.voc`): after the header (whose size is recorded at
    /// offset 0x14) the audio is a chain of data blocks, each a 1-byte type then
    /// a 3-byte little-endian length then that many bytes. A type-0 block
    /// terminates the file, so the chain is walked to the terminator. The
    /// 20-byte ASCII magic makes a false match effectively impossible.
    Voc,
    /// AMR (Adaptive Multi-Rate) narrowband audio — mobile-phone voice recordings
    /// — identified by the `#!AMR\n` magic. The stream is a run of speech frames,
    /// each a one-byte table-of-contents octet whose frame-type bits select a
    /// fixed frame size; the frames are walked to the first invalid octet or the
    /// end. The 6-byte magic makes a false anchor unlikely.
    Amr,
    /// PlayStation (PS1) executable (`PS-X EXE`): a fixed 2 KiB (0x800) header
    /// followed by the program text. The text-section size is a little-endian u32
    /// at offset 0x1C, so the file ends at `0x800 + text_size`. PlayStation
    /// sections are 2 KiB-aligned, so a non-zero, 0x800-aligned text size guards
    /// the match alongside the 8-byte magic.
    PsxExe,
    /// Android sparse image (`.simg`, the format `fastboot` and factory images
    /// use): a file header followed by `total_chunks` chunks, each chunk header
    /// recording its own whole on-disk size (`total_sz`). Summing those from the
    /// header end gives the file length. The header sizes and chunk count are
    /// range-checked to reject a coincidental magic.
    AndroidSparse,
    /// MP3 anchored directly on an MPEG (Layer III) frame sync, for the many
    /// MP3s that carry only an ID3v1 trailer or no tag at all (the [`Extent::Mp3`]
    /// anchor needs an ID3v2 tag). The frame chain is walked like [`Extent::Mp3`];
    /// because the sync is only 11 bits, a longer run of consecutive valid frames
    /// is required to avoid a false carve.
    Mp3Raw,
    /// JPEG image: scan for the End-of-Image marker (`FF D9`), but track nested
    /// Start-of-Image markers (`FF D8`, e.g. an embedded EXIF thumbnail) so the
    /// file ends at the *outer* image's `FF D9` rather than a thumbnail's. Within
    /// JPEG entropy data `FF` is only ever followed by `00` or `D0`–`D7`, so
    /// scanning for `FF D8`/`FF D9` is unambiguous for well-formed images.
    Jpeg,
    /// ZIP archive (and the many ZIP-based formats: DOCX/XLSX/PPTX, ODT, JAR,
    /// APK, EPUB): locate the End-of-Central-Directory record (`PK\x05\x06`) and
    /// end the file after it and its declared comment. The EOCD records the
    /// central directory's offset and size, so the record whose geometry matches
    /// this archive is chosen — this skips the EOCD of a ZIP nested inside the
    /// archive (which would otherwise truncate it) and rejects a coincidental
    /// marker.
    Zip,
    /// GIF image: walk the block stream — the logical-screen descriptor and any
    /// colour tables, then image (`0x2C`) and extension (`0x21`) blocks with
    /// their length-prefixed sub-block chains — to the trailer (`0x3B`). This
    /// finds the true end rather than stopping at a `00 3B` byte pair that occurs
    /// by chance inside the LZW image data.
    Gif,
    /// Windows Imaging Format (WIM/ESD): the 208-byte header carries a resource
    /// header (offset + size) for the offset/lookup table, XML data, boot
    /// metadata, and integrity table. The file ends at the furthest
    /// `offset + size` of these — one of them (normally the integrity table or
    /// XML data) is the last structure in the file. The header size field
    /// (0xD0) is checked to reject a coincidental magic.
    Wim,
    /// Uncompressed Flash movie (`FWS`): the 8-byte header stores the total file
    /// length as a little-endian u32 at offset 4. Only the uncompressed variant
    /// is carved — the compressed `CWS`/`ZWS` variants store the *uncompressed*
    /// length there, which is not the on-disk size. The version byte and a
    /// minimum length are checked to reject a coincidental magic.
    Swf,
    /// Compound File Binary Format (OLE2 — legacy `.doc`/`.xls`/`.ppt`/`.msi`).
    /// The 512-byte header records the sector size (`1 << shift` at offset 30,
    /// either 512 or 4096), the number of FAT sectors, and a DIFAT array
    /// listing them (the first 109 in the header, the rest via a DIFAT-sector
    /// chain). The file is a whole number of sectors; its length is found by
    /// reading the FAT and taking the highest sector index that is not marked
    /// free, so the file ends at `(max_used_sector + 2) * sector_size`.
    Cfbf,
    /// Outlook data file (PST/OST). The NDB header records the file's own end
    /// offset (`ibFileEof`) directly: a little-endian u64 at offset 0xB8 in the
    /// Unicode format (`wVer` >= 23). The ANSI format (`wVer` 14/15) stores a
    /// 32-bit `ibFileEof` at a different offset and is not carved. The version
    /// and the `SM` client signature are checked to reject a coincidental magic.
    Pst,
    /// POSIX/GNU `tar` archive (`ustar`). Each member is a 512-byte header block
    /// (carrying the member's size as an octal field at offset 124) followed by
    /// its data padded up to a multiple of 512; the archive ends with the two
    /// all-zero blocks that mark end-of-archive. The chain is walked from one
    /// `ustar` header to the next, validating each header's checksum, so the file
    /// ends exactly at the zero terminator rather than at a coincidental `ustar`.
    Tar,
    /// `cpio` archive, "new ASCII" format (`070701`, and `070702` with CRC) —
    /// the format used by Linux initramfs images and RPM payloads. Each entry is
    /// a 110-byte ASCII header (every field 8 hex digits) carrying the name and
    /// file sizes, then the NUL-terminated name and the file data, each padded to
    /// a 4-byte boundary. The chain is walked entry by entry to the `TRAILER!!!`
    /// entry that marks end-of-archive, giving an exact end.
    Cpio,
    /// SquashFS image (`hsqs`) — the read-only compressed filesystem used by Snap
    /// packages, AppImages, live media, and router/IoT firmware. The version-4
    /// superblock records `bytes_used` (a little-endian u64 at offset 40), the
    /// exact size of the image, so the file ends there. The major version (4) and
    /// the block-size/`block_log` consistency are checked to reject a coincidental
    /// magic.
    Squashfs,
    /// ISO 9660 disc image (`.iso`) — the standard CD/DVD filesystem, also used
    /// for distro installers and optical-media backups. The primary volume
    /// descriptor sits at logical sector 16 (byte offset 0x8000) and is keyed by
    /// the `CD001` standard identifier. It records the volume space size (a
    /// both-endian u32 logical-block count at offset 80) and the logical block
    /// size (a both-endian u16 at offset 128, normally 2048); their product is
    /// the exact image length. The descriptor type (1) and version (1) are
    /// checked to reject a coincidental magic.
    Iso9660,
    /// Autodesk FLIC animation (`.fli`/`.flc`) — the palette-animation format
    /// from Autodesk Animator and Animator Pro, still seen in old games and
    /// demos. The 128-byte header opens with the total file size as a
    /// little-endian u32 at offset 0, followed by the format magic (`0xAF11`
    /// FLI or `0xAF12` FLC) at offset 4. The size field gives the exact end.
    /// The colour depth (8 or 0), frame count, and frame dimensions are
    /// range-checked to reject a coincidental magic.
    Flic,
    /// WavPack lossless audio (`.wv`) — the open-source hybrid lossless codec.
    /// The stream is a chain of blocks, each opening with a 32-byte header: the
    /// `wvpk` magic, a little-endian u32 `ckSize` at offset 4 (the block size in
    /// bytes minus 8), and a little-endian u16 format version at offset 8. The
    /// chain is walked — each block advances `ckSize + 8` bytes — until the next
    /// position no longer begins with `wvpk`, so the file ends at the last whole
    /// block. The first block's version (a 4.x bitstream) is checked to reject a
    /// coincidental magic.
    WavPack,
    /// Monkey's Audio (`.ape`) — a popular lossless codec. Files from version
    /// 3.98 onward open with an `APE_DESCRIPTOR`: the `MAC ` magic, a u16
    /// version (×1000) at offset 4, then a run of little-endian u32 byte counts
    /// for each segment — the descriptor, header, seek table, WAV header, APE
    /// frame data (a 64-bit value split low at offset 0x18 and high at 0x1C),
    /// and terminating data. Their sum is the exact file length. The version
    /// (≥ 3980) and a sane descriptor size are checked to reject a coincidental
    /// magic; pre-3.98 files, which lack the descriptor, are not carved.
    Ape,
    /// AppleSingle / AppleDouble container (RFC 1740) — the format macOS uses to
    /// store a file's resource fork and metadata on non-Apple filesystems (the
    /// familiar `._name` files inside ZIP/tar archives and on FAT/SMB volumes).
    /// A big-endian header carries a magic (`0x00051600` AppleSingle or
    /// `0x00051607` AppleDouble), a version (`0x00010000`/`0x00020000`), 16
    /// filler bytes, and a u16 entry count at offset 0x18. Each 12-byte entry
    /// that follows holds an id, a u32 offset, and a u32 length; the file ends at
    /// the largest offset-plus-length. The magic, version, and a bounded entry
    /// count reject a coincidental match.
    AppleSingle,
    /// Sun raster image (`.ras`/`.sun`) — the classic raster format from SunOS.
    /// The 32-byte big-endian header (magic `0x59A66A95`) records the image-data
    /// length at offset 0x10 and the colormap length at offset 0x1C, so the file
    /// is `32 + maplength + length` bytes. The depth (1/8/24/32), image type
    /// (≤ 5), colormap type (≤ 2), and non-zero geometry are checked to reject a
    /// coincidental magic.
    SunRaster,
    /// DSF (`.dsf`) — the Sony DSD Stream File format used for high-resolution
    /// 1-bit (SACD-style) audio. The file opens with a DSD chunk: the `DSD `
    /// magic, a little-endian u64 chunk size (always 28) at offset 4, the total
    /// file size as a little-endian u64 at offset 0x0C, and a metadata pointer.
    /// The total-size field gives the exact end. The chunk size (28) and the
    /// `fmt ` chunk that must follow at offset 28 reject a coincidental magic.
    Dsf,
    /// DSDIFF (`.dff`) — the Philips "DSD Interchange File Format" for 1-bit
    /// audio, an IFF-style container with 64-bit sizes. The outer chunk is a
    /// `FRM8` whose big-endian u64 data size at offset 4 covers everything after
    /// it, so the file is `12 + size` bytes. The `DSD ` form type required at
    /// offset 0x0C rejects a coincidental `FRM8` match.
    Dsdiff,
    /// PCF bitmap font (`.pcf`) — the X11 Portable Compiled Font used for the
    /// classic console/terminal bitmap fonts on Linux/Unix. A `\x01fcp` magic is
    /// followed by a little-endian u32 table count and that many 16-byte table
    /// entries (type, format, size at offset 8, data offset at offset 12). The
    /// file ends at the largest data offset-plus-size. The magic, a bounded
    /// table count, and offsets that fall past the table of contents reject a
    /// coincidental magic.
    Pcf,
    /// U-Boot legacy image (`.uimage`) — the boot-image wrapper produced by
    /// `mkimage` for U-Boot, ubiquitous in router/IoT firmware. A 64-byte
    /// big-endian header opens with the magic `0x27051956` and records the
    /// image-data size as a u32 at offset 0x0C, so the file is `64 + size`
    /// bytes. The distinctive magic and a non-zero size reject a coincidental
    /// match.
    UImage,
    /// Quake PAK archive (`.pak`) — the asset-bundle format from id Software's
    /// Quake engine (and games built on it). A `PACK` magic is followed by a
    /// little-endian u32 directory offset at offset 4 and a little-endian u32
    /// directory length at offset 8. The directory of 64-byte entries sits at
    /// the end of the file, so the length is `dir_offset + dir_length`. A
    /// directory length that is a multiple of 64 and an offset past the header
    /// reject a coincidental magic.
    QuakePak,
    /// Quake II model (`.md2`) — the animated mesh format from id Software's
    /// Quake II (and many games and mods built on it). A 68-byte little-endian
    /// header opens with the `IDP2` magic and version 8, and its final field at
    /// offset 0x40 (`ofs_end`) is the exact file size. The magic and version
    /// reject a coincidental match.
    Md2,
    /// IVF (`.ivf`) — the simple container that wraps raw AV1, VP9, and VP8
    /// bitstreams, produced by modern web-video encoders and codec test suites.
    /// A 32-byte little-endian header opens with the `DKIF` magic, version 0,
    /// and a header length of 32, and records the frame count as a u32 at offset
    /// 0x18. Each frame is a 12-byte header (a u32 size and a u64 timestamp)
    /// followed by the frame data, so the file is walked frame by frame to the
    /// end. The magic, version, and header length reject a coincidental match.
    Ivf,
    /// ZIM archive (`.zim`) — the openZIM/Kiwix container for offline web
    /// content (offline Wikipedia and other educational corpora). An 80-byte
    /// little-endian header opens with the `ZIM\x04` magic and stores the
    /// checksum position as a u64 at offset 0x48. A 16-byte MD5 checksum is the
    /// last thing in the file, so the length is `checksumPos + 16`. The magic
    /// and a checksum position past the header reject a coincidental match.
    Zim,
    /// GGUF (`.gguf`) — the container for llama.cpp / ggml model weights, the
    /// dominant on-disk format for local large language models. A little-endian
    /// header (the `GGUF` magic, a u32 version, a u64 tensor count, and a u64
    /// metadata KV count) is followed by the metadata table and the tensor-info
    /// table; the tensor data section begins at the next `general.alignment`
    /// boundary after the infos, and the file ends at the largest tensor offset
    /// plus its byte size (computed from the fixed ggml block constants). A file
    /// using a tensor type whose layout is not known is skipped rather than
    /// mis-sized. The magic, a supported version, and bounded counts reject a
    /// coincidental match.
    Gguf,
    /// Android boot image (`boot.img`) — the kernel/ramdisk container flashed to
    /// Android devices, a common phone-forensics recovery target. The `ANDROID!`
    /// magic is followed by section sizes that are each rounded up to the page
    /// size, so the file is the sum of the header page and the page-rounded
    /// kernel, ramdisk, and any additional sections. Header versions 0–2 store a
    /// page size and (v1) a recovery-DTBO and (v2) a DTB section; versions 3–4
    /// use a fixed 4096-byte page and (v4) a boot signature. Versions beyond
    /// those are skipped rather than mis-sized. The 8-byte magic makes false
    /// positives negligible.
    BootImg,
    /// KTX2 texture (`.ktx2`) — the current Khronos GPU-texture container (glTF
    /// `KHR_texture_basisu`, WebGPU, game engines). After the 12-byte magic the
    /// 80-byte header records a level count and byte offset/length pairs for the
    /// data-format descriptor, key/value data, and supercompression global data,
    /// followed by a level index of `byteOffset`/`byteLength`/uncompressed
    /// triples. The file ends at the largest section offset-plus-length. The long
    /// magic and a bounded level count reject a coincidental match.
    Ktx2,
    /// QOA audio (`.qoa`) — the "Quite OK Audio" format, a modern minimal lossy
    /// codec. An 8-byte header (`qoaf` magic and a big-endian u32 total sample
    /// count) is followed by frames, each holding up to 5120 samples per channel
    /// and recording its own size as a big-endian u16 at offset 6 of its 8-byte
    /// frame header. The frames are walked for the sample-derived frame count to
    /// the end of the file. The magic, a non-zero sample count, and a valid first
    /// frame reject a coincidental match.
    Qoa,
    /// Android vendor_boot image (`vendor_boot.img`) — the GKI-era partition
    /// (Android 11+) holding the vendor ramdisk and DTB, a phone-forensics
    /// recovery target. After the `VNDRBOOT` magic a header records the page
    /// size (0x0C), the vendor-ramdisk size (0x18), the header size (0x830), and
    /// the DTB size (0x834); version 4 adds a vendor-ramdisk-table size (0x840)
    /// and a bootconfig size (0x84C). Each section is rounded up to the page
    /// size, so the file is the sum of the page-rounded header, vendor ramdisk,
    /// DTB, and (v4) table and bootconfig. Only header versions 3–4 are sized;
    /// others are skipped. The 8-byte magic makes false positives negligible.
    VendorBoot,
    /// NumPy array (`.npy`) — the standard `numpy.save` on-disk format,
    /// ubiquitous in machine-learning and scientific-Python data. After the
    /// `\x93NUMPY` magic and a version, a little-endian header length precedes an
    /// ASCII header dict describing the `descr` (dtype) and `shape`. The file is
    /// the header plus `product(shape) × itemsize`. Only fixed-size numeric and
    /// byte dtypes are sized; object, structured, and unicode dtypes are skipped
    /// rather than mis-sized. The magic and a parseable header reject a
    /// coincidental match.
    Npy,
    /// systemd journal (`.journal`) — the binary log format under
    /// `/var/log/journal` on every modern Linux system, a common forensics
    /// target. After the `LPKSHHRH` magic the header records a little-endian u64
    /// header size at offset 0x58 and arena size at offset 0x60; the arena
    /// follows the header, so the file is `header_size + arena_size`. The 8-byte
    /// magic, a sane header size, and a non-zero arena reject a coincidental
    /// match.
    Journal,
    /// Unity asset bundle (`.unity3d`) — the `UnityFS` container that ships the
    /// assets of virtually every Unity game, a common game-asset recovery
    /// target. The header is the `UnityFS\0` signature, a big-endian u32 format
    /// version, two null-terminated version strings (the Unity version and
    /// revision), then the total file size as a big-endian i64. That size field
    /// gives the exact end. The magic, a sane version, and terminated version
    /// strings reject a coincidental match.
    UnityFs,
    /// Fuji RAF raw image (`.raf`) — the raw photo format from Fujifilm's
    /// mirrorless cameras, a common photo-recovery target. After the 16-byte
    /// `FUJIFILMCCD-RAW ` magic the header records big-endian u32 offset/length
    /// pairs for the embedded JPEG (0x54/0x58), the CFA header (0x5C/0x60), and
    /// the CFA raw data (0x64/0x68); the file ends at the largest offset plus
    /// length. The 16-byte magic makes false positives negligible.
    Raf,
    /// Valve VPK archive (`.vpk`) — the pak format used by Source and Source 2
    /// games (CS2, Dota 2, Half-Life: Alyx), a common game-asset recovery
    /// target. The version-2 header (magic `0x55AA1234`) records the tree size
    /// and the file-data, archive-MD5, other-MD5, and signature section sizes,
    /// so the file is the 28-byte header plus their sum. Only version 2 (which
    /// carries all the section sizes) is sized; version 1 is skipped. The magic
    /// and version reject a coincidental match.
    Vpk,
    /// LAS point cloud (`.las`) — the LiDAR point-cloud format used in
    /// surveying, GIS, and autonomous-vehicle datasets. After the `LASF` magic
    /// the public header block records the offset to point data (0x60), the
    /// point record length (0x69), and the point count (a u32 at 0x6B, or a u64
    /// at 0xFF in LAS 1.4), so the file is `offset + count × record_length`.
    /// Compressed (LAZ) files, waveform point formats, and LAS 1.4 files with
    /// extended VLRs — whose size can't be derived this simply — are skipped
    /// rather than mis-sized.
    Las,
    /// Godot asset pack (`.pck`) — the resource bundle for Godot Engine games,
    /// covering pack format v1 (Godot 3) and v2 (Godot 4). After the `GDPC`
    /// magic the header carries the format version, a v2 `file_base`, and a file
    /// count, followed by directory entries (a length-prefixed path, a u64
    /// offset and size, an MD5, and a v2 flags word). The file ends at the
    /// largest `file_base + offset + size`. The magic, a supported version, and a
    /// bounded file count reject a coincidental match.
    GodotPck,
    /// E57 point cloud (`.e57`) — the ASTM E2807 format for 3D laser-scan and
    /// imaging data, used in surveying, BIM, and robotics. The 48-byte header
    /// opens with the `ASTM-E57` signature and stores the physical file length
    /// as a little-endian u64 at offset 0x10, which is the exact size. The
    /// 8-byte magic makes false positives negligible.
    E57,
    /// RF64 / BW64 audio (`.rf64`) — the EBU extension of WAV for files larger
    /// than 4 GiB (broadcast and field recording), where the classic 32-bit RIFF
    /// size overflows. The `RF64` magic is followed by a `0xFFFFFFFF` size
    /// placeholder, the `WAVE` form type, and a `ds64` chunk whose first field is
    /// the true 64-bit RIFF size at offset 0x14; the file is that size plus 8.
    /// The three anchor strings reject a coincidental match.
    Rf64,
    /// NIfTI-1 neuroimaging volume (`.nii`) — the standard format for MRI/fMRI
    /// and other volumetric medical imaging, ubiquitous in research and clinical
    /// pipelines. The 348-byte little-endian header ends with the `n+1\0` magic
    /// at offset 344 and records the dimensions (a `short[8]` at 0x28), the bits
    /// per voxel (0x48), and the data offset (a float at 0x6C). The file is the
    /// data offset plus `product(dims) × bytes-per-voxel`. The `sizeof_hdr` of
    /// 348, the magic, and sane dimensions/bit depth reject a coincidental match;
    /// big-endian volumes are skipped.
    Nifti,
    /// USD crate scene (`.usdc`) — Pixar's binary Universal Scene Description,
    /// the standard for 3D scene interchange in film/VFX and NVIDIA Omniverse.
    /// The bootstrap header (`PXR-USDC` magic) stores a table-of-contents offset
    /// as a u64 at 0x10; the table is a u64 section count followed by 32-byte
    /// sections (a 16-byte name, a u64 start, and a u64 size). The file ends at
    /// the largest section start-plus-size (or the end of the table). The 8-byte
    /// magic and a bounded section count reject a coincidental match.
    Usdc,
    /// Apache Avro object container (`.avro`) — the row-oriented data format used
    /// throughout modern data engineering (Kafka, Hadoop, data lakes). After the
    /// `Obj\x01` magic a metadata map (variable-length "blocks") is followed by a
    /// 16-byte sync marker, then data blocks — each an object count, a byte size,
    /// the block data, and a copy of the sync marker. The blocks are walked,
    /// verifying the sync marker after each, to the last valid block. The magic
    /// and the per-block sync-marker check reject a coincidental match.
    Avro,
    /// HDF5 data file (`.h5`) — the dominant scientific/ML container (Keras
    /// models, scientific datasets, NetCDF-4). The 8-byte `\x89HDF\r\n\x1a\n`
    /// signature opens a superblock whose end-of-file address is the exact file
    /// size, stored as a little-endian offset at a version-dependent position
    /// (superblock versions 0/1/2/3). Files with a non-8-byte offset size or an
    /// unrecognised superblock version are skipped rather than mis-sized.
    Hdf5,
    /// DDS texture (`.dds`) — the DirectDraw Surface GPU-texture format used
    /// throughout games and 3D tools. The 128-byte header (magic `DDS `) records
    /// the width, height, mip-map count, and pixel format; the file is the header
    /// plus the mip-chain size, computed from the block size of the compressed
    /// format (DXT1/3/5, BC4/5) or the bit depth of an uncompressed one.
    /// DX10-extended, cubemap, and volume textures — whose size needs more than
    /// this — are skipped rather than mis-sized.
    Dds,
    /// ASTC texture (`.astc`) — the Adaptive Scalable Texture Compression format
    /// used by modern mobile GPUs and Vulkan. The 16-byte header (magic
    /// `0x5CA1AB13`) records the block dimensions and the texture dimensions;
    /// every ASTC block is exactly 16 bytes, so the file is `16 + block_count ×
    /// 16` where the block count is `ceil(x/bx) × ceil(y/by) × ceil(z/bz)`. The
    /// magic and sane block/texture dimensions reject a coincidental match.
    Astc,
    /// glTF binary 3D model (`.glb`) — the binary container for glTF 2.0, the
    /// standard runtime format for 3D assets (games, AR/VR, `<model-viewer>`).
    /// The 12-byte header is `glTF` magic, a `u32` version, and a `u32` total
    /// length covering the whole file. Chunks follow, each an 8-byte
    /// (`length`, `type`) preamble plus padded data. The length field gives the
    /// size directly; walking the chunks and confirming they sum to exactly
    /// that length (with a leading `JSON` chunk) rejects a coincidental match.
    Glb,
    /// EROFS filesystem image (`.erofs`/`.img`) — the Enhanced Read-Only File
    /// System used for Android 10+ `system`/`vendor` partitions and container
    /// images. Its superblock sits at a fixed offset of 1024 bytes (magic
    /// `0xE0F5E1E2`) and records the block-size shift (`blkszbits`, defaulting
    /// to 12 = 4 KiB when zero) and the total block count (`blocks`). The image
    /// length is `blocks << blkszbits`. The magic at the fixed superblock offset
    /// plus a sane block-size shift make a false match negligible.
    Erofs,
    /// KTX (version 1) GPU texture (`.ktx`) — the original Khronos texture
    /// container (WebGL/three.js, Android GPU textures, older glTF). After the
    /// 12-byte «KTX 11» identifier and a fixed 64-byte header comes the
    /// key/value data, then one block per mip level, each introduced by its own
    /// `imageSize` field and padded to a 4-byte boundary. Because every level's
    /// byte count is stored explicitly, no pixel-format table is needed. Only
    /// ordinary non-array, single-face textures are sized (array and cubemap
    /// layouts, whose per-face padding is ambiguous, are skipped). Multi-byte
    /// fields honour the header's endianness flag.
    Ktx1,
    /// OpenEXR image (`.exr`) — the ILM/Academy high-dynamic-range format that
    /// is the standard for film and VFX compositing. After the 4-byte magic and
    /// a version/flags word comes a list of attributes terminated by an empty
    /// name, then a chunk offset table of one `u64` per scanline block. The
    /// table's first entry equals `header_end + count × 8`, which reveals the
    /// table length without decoding the compression; the last entry locates
    /// the final chunk, whose own `dataSize` field gives the file end. Only
    /// single-part scanline images are sized — tiled, deep, and multi-part
    /// files (flagged in the version word) are skipped rather than mis-sized.
    Exr,
    /// MCAP log (`.mcap`) — the modern container for robotics and
    /// autonomous-vehicle recordings (ROS 2, Foxglove). After the 8-byte magic
    /// the file is a stream of records, each a 1-byte opcode, a `u64` length,
    /// and that many payload bytes. Walking the records by their length to the
    /// footer record (opcode `0x02`), then adding the footer payload and the
    /// 8-byte trailing magic, gives the exact end — no reliance on the trailing
    /// magic (which is identical to the leading one) for detection.
    Mcap,
    /// Source-engine BSP map (`.bsp`) — the compiled level format for Valve's
    /// Source games (CS:GO, Team Fortress 2, Portal 2, Garry's Mod) and their
    /// modding communities. After the `VBSP` magic and a `u32` version comes a
    /// directory of 64 lumps, each recording a file offset and length. The file
    /// end is the furthest `offset + length` across the directory (never less
    /// than the 1036-byte header). The `VBSP` magic and a sane version reject a
    /// coincidental match.
    Bsp,
    /// QOI image (`.qoi`) — the "Quite OK Image" format (2021), a fast lossless
    /// codec adopted across game engines and image tooling. The 14-byte header
    /// (`qoif` magic, width/height, channels, colourspace) is followed by a
    /// stream of chunks and an 8-byte end marker. Because every chunk's byte
    /// size is fixed by its tag (independent of pixel values), the stream can be
    /// decoded to count exactly `width × height` pixels — locating the end
    /// without searching for the marker, which may itself appear in pixel data.
    Qoi,
    /// RPM package (`.rpm`) — the package format of Fedora, RHEL, openSUSE, and
    /// related distributions. After a 96-byte lead comes a signature header (an
    /// 8-byte-padded `header` structure) whose `RPMSIGTAG_SIZE`/`LONGSIZE` tag
    /// records the combined size of the main header and the payload. The file
    /// length is `96 + padded signature header + that size`. The `0xEDABEEDB`
    /// lead magic and the `0x8EADE8` header magic reject a coincidental match.
    Rpm,
    /// farbfeld image (`.ff`) — the deliberately minimal lossless image format
    /// from the suckless project. The 16-byte header is the `farbfeld` magic, a
    /// big-endian `u32` width, and a big-endian `u32` height; the pixel data is
    /// exactly `width × height` RGBA pixels of four 16-bit channels, i.e. 8
    /// bytes each. The file length is therefore `16 + width × height × 8`.
    Farbfeld,
    /// YUV4MPEG2 stream (`.y4m`) — the uncompressed raw-video interchange format
    /// piped between modern encoders and tools (FFmpeg, the AV1/VP9/x264/x265
    /// reference encoders). A one-line header (`YUV4MPEG2` plus space-delimited
    /// `W`/`H`/`C`… parameters, ending in `\n`) fixes the per-frame byte size
    /// from the width, height, and colourspace. Each frame is a `FRAME…\n`
    /// line plus that many bytes; walking the frames to the end gives an exact
    /// length. Only the 8-bit `mono`/`420`/`422`/`444` colourspaces are sized;
    /// higher bit depths and alpha variants are skipped rather than mis-sized.
    Y4m,
    /// PVR v3 texture (`.pvr`) — the PowerVR texture container from Imagination's
    /// PVRTexTool, widely used in iOS and Android game development. The 52-byte
    /// header (magic `0x03525650`) records the pixel format, dimensions, mip
    /// count, and metadata size; the file is the header plus that metadata plus
    /// the mip chain. Only plain 2D textures in the 4×4-block codecs whose block
    /// size is unambiguous (BC1–BC7, ETC1/ETC2, EAC) are sized; PVRTC (with its
    /// minimum-size rule), ASTC, uncompressed formats, and array/cube/volume
    /// textures are skipped rather than mis-sized.
    Pvr,
    /// BLP2 texture (`.blp`) — the Blizzard texture format used by World of
    /// Warcraft. After the `BLP2` magic and a header of encoding flags and
    /// dimensions comes a directory of 16 mipmap offsets and 16 mipmap lengths.
    /// The file end is the furthest `offset + length` across that directory
    /// (never less than the 148-byte header). The `BLP2` magic and sane
    /// dimensions reject a coincidental match.
    Blp,
    /// GRIB2 weather data (`.grib2`) — the WMO gridded-binary format that is the
    /// backbone of modern meteorology and climate data (NOAA, ECMWF, NASA). A
    /// file is one or more self-delimiting messages, each opening with `GRIB`, a
    /// reserved field, a discipline byte, an edition byte (`2`), and a 64-bit
    /// big-endian total length, and closing with a `7777` end marker. Messages
    /// are walked by their length — each validated by its trailing `7777` — to
    /// the end of the run, giving an exact size across concatenated messages.
    Grib2,
    /// F2FS filesystem image (`.f2fs`) — the Flash-Friendly File System, the
    /// default internal-storage filesystem on most modern Android phones. Its
    /// superblock sits at a fixed offset of 1024 bytes (magic `0xF2F52010`) and
    /// records the block-size shift (`log_blocksize` at 0x10) and the total
    /// block count (`block_count` at 0x24). The image length is
    /// `block_count << log_blocksize`. The magic at the fixed superblock offset
    /// plus a sane block size make a false match negligible.
    F2fs,
    /// btrfs filesystem image (`.btrfs`) — the copy-on-write Linux filesystem
    /// that is the default on Fedora Workstation and openSUSE and is used by
    /// Synology NAS units. Its superblock sits at a fixed offset of 64 KiB
    /// (magic `_BHRfS_M` at +64) and records `total_bytes` at +112. For a
    /// single-device image (`num_devices == 1`) that field is the image length.
    /// The magic plus power-of-two sector/node sizes reject a coincidental
    /// match; multi-device filesystems are skipped rather than over-sized.
    Btrfs,
    /// XFS filesystem image (`.xfs`) — the high-performance journaling
    /// filesystem that is the default on RHEL, CentOS, and Rocky Linux. Its
    /// superblock opens the volume with the big-endian `XFSB` magic, a `u32`
    /// block size at offset 4, and a `u64` total data-block count at offset 8.
    /// The image length is `sb_dblocks × sb_blocksize`. The magic plus a
    /// power-of-two block size reject a coincidental match.
    Xfs,
    /// exFAT filesystem image (`.exfat`) — the Microsoft filesystem that is the
    /// default on SD/SDXC cards over 32 GB, most cameras, and many phones and
    /// USB drives. Its boot sector opens with `EXFAT   ` at offset 3 and records
    /// `VolumeLength` (in sectors) at offset 72 and `BytesPerSectorShift` at
    /// offset 108. The image length is `VolumeLength << BytesPerSectorShift`.
    /// The 8-byte magic plus sane sector/cluster shifts reject a coincidental
    /// match. (`scan` carves the whole volume; `undelete` recovers named files.)
    Exfat,
    /// APFS container image (`.apfs`) — the Apple File System, the default on
    /// every Mac, iPhone, and iPad since 2017. Its container superblock opens
    /// the volume with an `obj_phys_t` header and the `NXSB` magic at offset 32,
    /// followed by a `u32` block size (offset 36) and a `u64` block count
    /// (offset 40). The image length is `block_count × block_size`. The magic at
    /// the fixed offset plus a power-of-two block size reject a coincidental
    /// match.
    Apfs,
    /// ReFS filesystem image (`.refs`) — Microsoft's copy-on-write Resilient
    /// File System (Windows Server, Storage Spaces, and the Dev Drive feature on
    /// Windows 11). Its boot record carries the `ReFS` file-system signature at
    /// offset 3 and the `FSRS` structure identifier at offset 0x10, then a `u64`
    /// sector count at 0x18 and a `u32` bytes-per-sector at 0x20. The image
    /// length is `NumberOfSectors × BytesPerSector`. The two signatures plus a
    /// power-of-two sector size reject a coincidental match.
    Refs,
    /// NTFS filesystem image (`.ntfs`) — the dominant Windows filesystem. Its
    /// boot sector opens with an `NTFS    ` OEM signature at offset 3 and records
    /// `BytesPerSector` (a `u16` at offset 11) and `TotalSectors` (a `u64` at
    /// offset 0x28). The image length is `TotalSectors × BytesPerSector`. The
    /// 8-byte signature plus a power-of-two sector size reject a coincidental
    /// match. (`scan` carves the whole volume; `undelete` recovers named files.)
    Ntfs,
    /// Linux swap area (`.swap`) — a formatted swap partition or file, a key
    /// forensics artifact because it holds paged-out process memory. The first
    /// page is a header: a `u32` version at offset 1024, a `u32` `last_page`
    /// (the highest page index) at offset 1028, and the ASCII `SWAPSPACE2` magic
    /// at `page_size − 10`. Matching the magic at offset 4086 fixes the page
    /// size at 4 KiB (the common case), so the area length is
    /// `(last_page + 1) × 4096`. The 10-byte magic and a version of 1 reject a
    /// coincidental match.
    Swap,
    /// romfs image (`.romfs`) — the tiny read-only filesystem long used for
    /// Linux initramfs and embedded/boot images. The header opens with the
    /// 8-byte `-rom1fs-` magic and then a big-endian `u32` full-image-size field
    /// at offset 8, which is the image length directly. The 8-byte magic makes a
    /// false match negligible.
    Romfs,
    /// cramfs image (`.cramfs`) — the small compressed read-only Linux
    /// filesystem long used in firmware and embedded/boot images. The superblock
    /// carries the `0x28CD3D45` magic at offset 0 (little- or big-endian) and the
    /// 16-byte `Compressed ROMFS` signature at offset 0x10, with the total image
    /// size as a `u32` at offset 4 (same endianness as the magic), which is the
    /// image length directly. The 16-byte signature makes a false match
    /// negligible.
    Cramfs,
    /// JFS filesystem image (`.jfs`) — IBM's Journaled File System (from AIX/OS2,
    /// ported to Linux). Its aggregate superblock sits 32 KiB into the volume and
    /// opens with the `JFS1` magic, then a `u64` aggregate size (in physical
    /// blocks) at offset 8 and a `u32` physical block size at offset 0x18. The
    /// image length is `s_size × s_pbsize`. The magic plus a power-of-two block
    /// size reject a coincidental match.
    Jfs,
    /// UFS1 filesystem image (`.ufs`) — the Berkeley Fast File System, the
    /// traditional filesystem of the BSDs and Solaris. The UFS1 superblock sits
    /// 8 KiB into the volume with the `0x00011954` magic at offset 0x55C
    /// (little- or big-endian). The early geometry records the fragment size at
    /// offset 0x34 and the total size in fragments at offset 0x24, so the image
    /// length is `fs_old_size × fs_fsize`. Only UFS1 is sized; UFS2 (whose size
    /// lives in a 64-bit field this layout leaves zero) is not carved, so it is
    /// skipped rather than mis-sized.
    Ufs,
    /// BeFS filesystem image (`.befs`) — the Be File System from BeOS, still
    /// used by Haiku. Its superblock sits 512 bytes into the volume and carries
    /// two magics — `BFS1` (0x42465331) at offset 0x20 and 0xDD121031 at offset
    /// 0x44 (little- or big-endian, resolved from the first) — plus a `u32`
    /// block size at offset 0x28 and a `u64` block count at offset 0x30. The
    /// image length is `num_blocks × block_size`. The two magics plus a
    /// power-of-two block size reject a coincidental match.
    Befs,
    /// HFS+ filesystem image (`.hfsplus`) — the Mac OS Extended filesystem, the
    /// macOS default before APFS and still used on many external and
    /// Time Machine drives. Its volume header sits 1024 bytes into the volume
    /// with a big-endian `H+` (HFS+, version 4) or `HX` (HFSX, version 5)
    /// signature, then a `u32` allocation block size at offset 0x28 and a `u32`
    /// total block count at offset 0x2C. The image length is
    /// `totalBlocks × blockSize`. The signature/version pair plus a power-of-two
    /// block size reject a coincidental match. (Only direct volumes are matched;
    /// the rare HFS-wrapped layout is left to `info`.)
    HfsPlus,
    /// ReiserFS filesystem image (`.reiserfs`) — Hans Reiser's journaling
    /// filesystem, the SUSE default and a common choice on Linux through the
    /// 2000s (removed from the mainline kernel in 6.13). The **3.6** superblock
    /// sits 64 KiB into the volume and the older **3.5** superblock 8 KiB in,
    /// each carrying a long ASCII magic at offset 0x34 — `ReIsEr2Fs` or
    /// `ReIsEr3Fs` (3.6) / `ReIsErFs` (3.5) — plus a `u32` block count at
    /// offset 0x00 and a `u16` block size at offset 0x2C, all little-endian. The
    /// image length is `block_count × block_size`. The 8–9-byte magic plus a
    /// power-of-two block size reject a coincidental match.
    Reiserfs,
    /// MPEG transport stream (`.ts`) — the container used by DVB/ATSC broadcast
    /// captures, HDHomeRun/DVR recordings, and many camcorders. The stream is a
    /// run of fixed **188-byte packets**, each beginning with the sync byte
    /// `0x47`; the packets are walked to the end of the stream, giving an exact
    /// end at the last whole packet. The signature requires the sync byte at two
    /// packet boundaries and the walk requires a longer run, so the single-byte
    /// sync cannot trigger a false carve. The 192-byte (M2TS, timestamp-prefixed)
    /// and 204-byte (Reed-Solomon FEC) variants are not carved — their packets do
    /// not begin with the sync byte at offset 0.
    Mpegts,
    /// MPEG program stream (`.mpg`/`.mpeg`/`.vob`) — the container used by DVDs,
    /// VCDs, and older camcorders/recorders. It opens with a pack header
    /// (`00 00 01 BA`) and is a chain of packs, system headers, and PES packets,
    /// each introduced by a `00 00 01` start code. Packs are sized from the
    /// MPEG-1/MPEG-2 header layout (with pack stuffing); system headers and PES
    /// packets carry a 16-bit length. The chain is walked to the program-end code
    /// (`00 00 01 B9`), giving an exact end, or to the last whole packet when the
    /// stream is truncated. Several consecutive valid packets are required so the
    /// start code cannot trigger a false carve.
    Mpegps,
    /// Microsoft Program Database (`.pdb`) — the debug-symbol file every MSVC
    /// build produces. The MSF 7.0 superblock records the block size (a
    /// little-endian u32 at offset 0x20) and the total block count (offset 0x28),
    /// so the file ends at `block_size × num_blocks`. The long 32-byte magic makes
    /// a false match implausible; the block size is checked to be a sane power of
    /// two.
    Pdb,
    /// Binary (DOS) Encapsulated PostScript (`.eps`). The 30-byte header
    /// (`C5 D0 D3 C6`) holds the byte offset and length of the PostScript section
    /// and the optional WMF and TIFF previews (little-endian u32 pairs at offsets
    /// 4, 12, and 20). The file ends at the furthest `offset + length` of the
    /// sections present. The plain-text EPS form (no binary header) carries no
    /// length and is not carved.
    Eps,
    /// Fixed-length record: the file is always exactly `size` bytes. Used by
    /// runtime-injected custom carvers (see [`crate::custom`]) for formats with
    /// a constant size; bounds-checked against the scan limit like every extent.
    Fixed { size: u64 },
    /// Custom size field: the total length is an unsigned integer stored at
    /// `offset`, `width` bits wide (8/16/32/64), in the given byte order, scaled
    /// and biased as `value * mul + add`. This generalises the built-in
    /// [`Extent::HeaderSizeLe32`]/[`Extent::HeaderSizeBe32`] for runtime-injected
    /// custom carvers. Overflow in the arithmetic yields no match, never a wrong
    /// length.
    SizeField {
        offset: usize,
        width: u8,
        big_endian: bool,
        mul: u64,
        add: u64,
    },
}

/// A recoverable file type.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    /// Human-readable name, e.g. `"JPEG image"`.
    pub name: &'static str,
    /// Output file extension (without the dot), e.g. `"jpg"`.
    pub ext: &'static str,
    /// Magic bytes that identify the type.
    pub magic: &'static [u8],
    /// Where the magic appears relative to the start of the file. This is `0`
    /// for most formats but `4` for MP4/HEIC where the `ftyp` marker follows a
    /// 4-byte box-size field.
    pub magic_offset: u64,
    /// Optional secondary tag to disambiguate formats that share a magic, given
    /// as `(offset_from_magic, bytes)`. Used to tell RIFF (WAV/AVI/WEBP) and
    /// ISO-BMFF brands (HEIC vs MP4) apart.
    pub secondary: Option<(usize, &'static [u8])>,
    /// Strategy used to compute the file length.
    pub extent: Extent,
    /// Hard cap on carved size; protects against runaway files when an end
    /// marker is missing or corrupt.
    pub max_size: u64,
}

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;

/// The 48-byte Nintendo logo every Game Boy cartridge carries at offset 0x104.
/// The boot ROM bitmap-compares these bytes before running the cartridge, so a
/// bootable ROM reproduces them exactly — making this an unusually strong magic.
const GAMEBOY_LOGO: [u8; 48] = [
    0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B, 0x03, 0x73, 0x00, 0x83, 0x00, 0x0C, 0x00, 0x0D,
    0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E, 0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99,
    0xBB, 0xBB, 0x67, 0x63, 0x6E, 0x0E, 0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E,
];

/// The 48-byte Game Boy logo, for the carver's length check to re-verify a match.
pub(crate) fn gameboy_logo() -> [u8; 48] {
    GAMEBOY_LOGO
}

/// The built-in signature table.
///
/// Order matters where magics overlap: more specific entries (with a
/// `secondary` tag) must precede the generic fallback for the same magic, so
/// HEIC is matched before the generic MP4 `ftyp` entry.
pub static SIGNATURES: &[Signature] = &[
    Signature {
        name: "JPEG image",
        ext: "jpg",
        magic: &[0xFF, 0xD8, 0xFF],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Jpeg,
        max_size: 50 * MB,
    },
    Signature {
        name: "PNG image",
        ext: "png",
        magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Footer {
            // IEND chunk: length(0) + "IEND" + CRC
            marker: &[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82],
            trailing: 0,
        },
        max_size: 100 * MB,
    },
    Signature {
        // MNG (Multiple-image Network Graphics): a PNG-family animation with the
        // same chunk structure, terminated by an empty MEND chunk.
        name: "MNG animation",
        ext: "mng",
        magic: &[0x8A, 0x4D, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Footer {
            // MEND chunk: length(0) + "MEND" + CRC (of the bytes "MEND")
            marker: &[0x4D, 0x45, 0x4E, 0x44, 0x21, 0x20, 0xF7, 0xD5],
            trailing: 0,
        },
        max_size: 200 * MB,
    },
    Signature {
        // JNG (JPEG Network Graphics): a PNG-family wrapper around JPEG data;
        // like PNG, a standalone datastream ends with an empty IEND chunk.
        name: "JNG image",
        ext: "jng",
        magic: &[0x8B, 0x4A, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Footer {
            // IEND chunk: length(0) + "IEND" + CRC
            marker: &[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82],
            trailing: 0,
        },
        max_size: 100 * MB,
    },
    Signature {
        name: "GIF image (89a)",
        ext: "gif",
        magic: b"GIF89a",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Gif,
        max_size: 30 * MB,
    },
    Signature {
        name: "GIF image (87a)",
        ext: "gif",
        magic: b"GIF87a",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Gif,
        max_size: 30 * MB,
    },
    Signature {
        name: "BMP image",
        ext: "bmp",
        magic: b"BM",
        magic_offset: 0,
        secondary: None,
        // Total file size is a LE u32 at offset 2.
        extent: Extent::HeaderSizeLe32 { offset: 2 },
        max_size: 100 * MB,
    },
    Signature {
        name: "PDF document",
        ext: "pdf",
        magic: b"%PDF",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Footer {
            marker: b"%%EOF",
            trailing: 2, // allow a trailing CR/LF
        },
        max_size: 500 * MB,
    },
    Signature {
        name: "ZIP archive (also DOCX/XLSX/PPTX/ODT/JAR/APK)",
        ext: "zip",
        magic: &[0x50, 0x4B, 0x03, 0x04],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Zip,
        max_size: 2 * GB,
    },
    Signature {
        name: "WAV audio",
        ext: "wav",
        magic: b"RIFF",
        magic_offset: 0,
        secondary: Some((8, b"WAVE")),
        extent: Extent::RiffSize,
        max_size: 2 * GB,
    },
    Signature {
        name: "AVI video",
        ext: "avi",
        magic: b"RIFF",
        magic_offset: 0,
        secondary: Some((8, b"AVI ")),
        extent: Extent::RiffSize,
        max_size: 4 * GB,
    },
    Signature {
        name: "WebP image",
        ext: "webp",
        magic: b"RIFF",
        magic_offset: 0,
        secondary: Some((8, b"WEBP")),
        extent: Extent::RiffSize,
        max_size: 100 * MB,
    },
    Signature {
        // SoundFont 2 (`.sf2`): a RIFF container with the "sfbk" form type,
        // widely used for sampled instruments in music software.
        name: "SoundFont 2",
        ext: "sf2",
        magic: b"RIFF",
        magic_offset: 0,
        secondary: Some((8, b"sfbk")),
        extent: Extent::RiffSize,
        max_size: 2 * GB,
    },
    Signature {
        name: "AIFF audio",
        ext: "aiff",
        magic: b"FORM",
        magic_offset: 0,
        secondary: Some((8, b"AIFF")),
        extent: Extent::FormSize,
        max_size: 2 * GB,
    },
    Signature {
        name: "AIFF-C audio",
        ext: "aifc",
        magic: b"FORM",
        magic_offset: 0,
        secondary: Some((8, b"AIFC")),
        extent: Extent::FormSize,
        max_size: 2 * GB,
    },
    Signature {
        name: "Apple icon image",
        ext: "icns",
        magic: b"icns",
        magic_offset: 0,
        secondary: None,
        // Total file size is a big-endian u32 at offset 4 (includes the header).
        extent: Extent::HeaderSizeBe32 { offset: 4 },
        max_size: 50 * MB,
    },
    Signature {
        name: "SQLite database",
        ext: "sqlite",
        magic: b"SQLite format 3\0",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Sqlite,
        max_size: 2 * GB,
    },
    Signature {
        name: "7-Zip archive",
        ext: "7z",
        magic: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        magic_offset: 0,
        secondary: None,
        extent: Extent::SevenZip,
        max_size: 4 * GB,
    },
    Signature {
        name: "Microsoft Cabinet archive",
        ext: "cab",
        magic: b"MSCF",
        magic_offset: 0,
        secondary: None,
        // Cabinet size is a LE u32 at offset 8.
        extent: Extent::HeaderSizeLe32 { offset: 8 },
        max_size: 2 * GB,
    },
    Signature {
        name: "RAR archive",
        ext: "rar",
        // The 6-byte prefix shared by RAR v4 (`Rar!\x1A\x07\x00`) and v5
        // (`Rar!\x1A\x07\x01\x00`); the version byte that follows is read by the
        // block walk.
        magic: b"Rar!\x1a\x07",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Rar,
        max_size: 8 * GB,
    },
    Signature {
        name: "Zstandard compressed",
        ext: "zst",
        magic: &[0x28, 0xB5, 0x2F, 0xFD],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Zstd,
        max_size: 8 * GB,
    },
    Signature {
        name: "LZ4 compressed",
        ext: "lz4",
        magic: &[0x04, 0x22, 0x4D, 0x18],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Lz4,
        max_size: 8 * GB,
    },
    Signature {
        name: "Photoshop document",
        ext: "psd",
        magic: b"8BPS",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Psd,
        max_size: 4 * GB,
    },
    Signature {
        name: "Windows Metafile (placeable)",
        ext: "wmf",
        magic: &[0xD7, 0xCD, 0xC6, 0x9A],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wmf,
        max_size: 256 * MB,
    },
    Signature {
        name: "Windows Metafile",
        ext: "wmf",
        // METAHEADER: mtType=1 (memory), mtHeaderSize=9 words. The metafile
        // version and size are validated by the extent walk.
        magic: &[0x01, 0x00, 0x09, 0x00],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wmf,
        max_size: 256 * MB,
    },
    Signature {
        name: "Windows Metafile",
        ext: "wmf",
        // METAHEADER with mtType=2 (disk).
        magic: &[0x02, 0x00, 0x09, 0x00],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wmf,
        max_size: 256 * MB,
    },
    Signature {
        name: "glTF binary (3D model)",
        ext: "glb",
        magic: b"glTF",
        magic_offset: 0,
        secondary: None,
        // The 12-byte header stores total length as a LE u32 at offset 8.
        extent: Extent::HeaderSizeLe32 { offset: 8 },
        max_size: 2 * GB,
    },
    Signature {
        name: "DjVu document",
        ext: "djvu",
        magic: b"AT&TFORM",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Djvu,
        max_size: 512 * MB,
    },
    Signature {
        name: "Windows Event Log",
        ext: "evtx",
        magic: b"ElfFile\x00",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Evtx,
        max_size: 2 * GB,
    },
    Signature {
        name: "Rich Text Format",
        ext: "rtf",
        magic: b"{\\rtf1",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Rtf,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio",
        ext: "mp3",
        magic: b"ID3",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3,
        max_size: 100 * MB,
    },
    // MP3 with no ID3v2 tag: anchor on a Layer III frame sync. One entry per
    // common second byte — MPEG 1/2/2.5, CRC present or absent. `mp3_raw_length`
    // requires a long run of valid frames, so these short magics do not
    // false-carve.
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xFB], // MPEG-1 Layer III, no CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xFA], // MPEG-1 Layer III, CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xF3], // MPEG-2 Layer III, no CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xF2], // MPEG-2 Layer III, CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xE3], // MPEG-2.5 Layer III, no CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    Signature {
        name: "MP3 audio (frame sync)",
        ext: "mp3",
        magic: &[0xFF, 0xE2], // MPEG-2.5 Layer III, CRC
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp3Raw,
        max_size: 100 * MB,
    },
    // HEIC/HEIF brands share the `ftyp` magic with MP4, so they must come first
    // and use a secondary brand tag (at offset 8 in the file => 4 past `ftyp`).
    Signature {
        name: "HEIC image",
        ext: "heic",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"heic")),
        extent: Extent::Mp4Atoms,
        max_size: 100 * MB,
    },
    Signature {
        name: "HEIC image",
        ext: "heic",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"heix")),
        extent: Extent::Mp4Atoms,
        max_size: 100 * MB,
    },
    Signature {
        name: "HEIF image",
        ext: "heic",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"mif1")),
        extent: Extent::Mp4Atoms,
        max_size: 100 * MB,
    },
    Signature {
        name: "AVIF image",
        ext: "avif",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"avif")),
        extent: Extent::Mp4Atoms,
        max_size: 100 * MB,
    },
    Signature {
        name: "Canon CR3 raw image",
        ext: "cr3",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"crx ")),
        extent: Extent::Mp4Atoms,
        max_size: 200 * MB,
    },
    Signature {
        name: "JPEG XL image",
        ext: "jxl",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"jxl ")),
        extent: Extent::Mp4Atoms,
        max_size: 200 * MB,
    },
    Signature {
        name: "3GP video",
        ext: "3gp",
        magic: b"ftyp",
        magic_offset: 4,
        // A 3-byte tag matches the "3gp4"/"3gp5"/"3gp6" major brands.
        secondary: Some((4, b"3gp")),
        extent: Extent::Mp4Atoms,
        max_size: 4 * GB,
    },
    Signature {
        name: "QuickTime movie",
        ext: "mov",
        magic: b"ftyp",
        magic_offset: 4,
        // `qt  ` major brand (note the two trailing spaces) — iPhone/Mac video.
        secondary: Some((4, b"qt  ")),
        extent: Extent::Mp4Atoms,
        max_size: 16 * GB,
    },
    Signature {
        name: "M4A audio",
        ext: "m4a",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"M4A ")),
        extent: Extent::Mp4Atoms,
        max_size: 4 * GB,
    },
    Signature {
        name: "M4V video",
        ext: "m4v",
        magic: b"ftyp",
        magic_offset: 4,
        secondary: Some((4, b"M4V ")),
        extent: Extent::Mp4Atoms,
        max_size: 16 * GB,
    },
    Signature {
        name: "MP4/MOV/M4A media",
        ext: "mp4",
        magic: b"ftyp",
        magic_offset: 4, // preceded by a 4-byte box size
        secondary: None,
        extent: Extent::Mp4Atoms,
        max_size: 4 * GB,
    },
    Signature {
        name: "ELF executable / shared object",
        ext: "elf",
        magic: &[0x7F, b'E', b'L', b'F'],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Elf,
        max_size: 2 * GB,
    },
    Signature {
        name: "PE executable (EXE/DLL)",
        ext: "exe",
        magic: b"MZ",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pe,
        max_size: 2 * GB,
    },
    // Mach-O thin binaries: one entry per magic (32/64-bit × byte order). Fat
    // (universal) binaries share Java's 0xCAFEBABE magic and are not carved.
    Signature {
        name: "Mach-O binary (64-bit LE)",
        ext: "macho",
        magic: &[0xCF, 0xFA, 0xED, 0xFE],
        magic_offset: 0,
        secondary: None,
        extent: Extent::MachO,
        max_size: 2 * GB,
    },
    Signature {
        name: "Mach-O binary (32-bit LE)",
        ext: "macho",
        magic: &[0xCE, 0xFA, 0xED, 0xFE],
        magic_offset: 0,
        secondary: None,
        extent: Extent::MachO,
        max_size: 2 * GB,
    },
    Signature {
        name: "Mach-O binary (64-bit BE)",
        ext: "macho",
        magic: &[0xFE, 0xED, 0xFA, 0xCF],
        magic_offset: 0,
        secondary: None,
        extent: Extent::MachO,
        max_size: 2 * GB,
    },
    Signature {
        name: "Mach-O binary (32-bit BE)",
        ext: "macho",
        magic: &[0xFE, 0xED, 0xFA, 0xCE],
        magic_offset: 0,
        secondary: None,
        extent: Extent::MachO,
        max_size: 2 * GB,
    },
    Signature {
        name: "Windows registry hive",
        ext: "regf",
        magic: b"regf",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Regf,
        max_size: 2 * GB,
    },
    // ADTS AAC: one entry per common first-two-byte sync (the sync word is
    // 0xFFF; the low nibble of byte 1 varies by MPEG version and CRC presence).
    // The frame-walk in `aac_length` rejects coincidental matches.
    Signature {
        name: "AAC audio (ADTS, MPEG-4)",
        ext: "aac",
        magic: &[0xFF, 0xF1],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Aac,
        max_size: 200 * MB,
    },
    Signature {
        name: "AAC audio (ADTS, MPEG-2)",
        ext: "aac",
        magic: &[0xFF, 0xF9],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Aac,
        max_size: 200 * MB,
    },
    Signature {
        name: "AAC audio (ADTS, MPEG-4, CRC)",
        ext: "aac",
        magic: &[0xFF, 0xF0],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Aac,
        max_size: 200 * MB,
    },
    Signature {
        name: "AAC audio (ADTS, MPEG-2, CRC)",
        ext: "aac",
        magic: &[0xFF, 0xF8],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Aac,
        max_size: 200 * MB,
    },
    Signature {
        name: "MPEG transport stream",
        ext: "ts",
        magic: &[0x47],
        magic_offset: 0,
        // Require the sync byte again one 188-byte packet later, so the
        // single-byte sync is not a candidate on its own.
        secondary: Some((188, &[0x47])),
        extent: Extent::Mpegts,
        max_size: 16 * GB,
    },
    Signature {
        name: "MPEG program stream",
        ext: "mpg",
        magic: &[0x00, 0x00, 0x01, 0xBA],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mpegps,
        max_size: 16 * GB,
    },
    Signature {
        name: "Microsoft Program Database (PDB)",
        ext: "pdb",
        magic: b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pdb,
        max_size: 4 * GB,
    },
    Signature {
        name: "Encapsulated PostScript (binary)",
        ext: "eps",
        magic: &[0xC5, 0xD0, 0xD3, 0xC6],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Eps,
        max_size: 512 * MB,
    },
    Signature {
        name: "Android Dalvik executable (DEX)",
        ext: "dex",
        magic: b"dex\n",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Dex,
        max_size: GB,
    },
    Signature {
        name: "Windows Imaging (WIM)",
        ext: "wim",
        magic: b"MSWIM\x00\x00\x00",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wim,
        max_size: 8 * GB,
    },
    Signature {
        name: "Flash movie (uncompressed)",
        ext: "swf",
        magic: b"FWS",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Swf,
        max_size: 500 * MB,
    },
    Signature {
        name: "ICC colour profile",
        ext: "icc",
        magic: b"acsp",
        magic_offset: 36,
        secondary: None,
        extent: Extent::Icc,
        max_size: 64 * MB,
    },
    Signature {
        name: "Unix ar archive (deb/static lib)",
        ext: "ar",
        magic: b"!<arch>\n",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ar,
        max_size: 2 * GB,
    },
    Signature {
        name: "ESRI Shapefile",
        ext: "shp",
        magic: &[0x00, 0x00, 0x27, 0x0A], // file code 9994 (big-endian)
        magic_offset: 0,
        secondary: None,
        extent: Extent::Shp,
        max_size: 2 * GB,
    },
    Signature {
        name: "Blender file",
        ext: "blend",
        magic: b"BLENDER",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Blend,
        max_size: 2 * GB,
    },
    Signature {
        name: "NES ROM (iNES)",
        ext: "nes",
        magic: b"NES\x1a",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Nes,
        max_size: 64 * MB,
    },
    Signature {
        name: "Game Boy ROM",
        ext: "gb",
        magic: &GAMEBOY_LOGO,
        // The logo sits at 0x104; the ROM (and carved file) begins 0x104 earlier.
        magic_offset: 0x104,
        secondary: None,
        extent: Extent::Gameboy,
        max_size: 8 * MB,
    },
    Signature {
        name: "Doom WAD (IWAD)",
        ext: "wad",
        magic: b"IWAD",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wad,
        max_size: 2 * GB,
    },
    Signature {
        name: "Doom WAD (PWAD)",
        ext: "wad",
        magic: b"PWAD",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wad,
        max_size: 2 * GB,
    },
    Signature {
        name: "Sun/NeXT audio",
        ext: "au",
        magic: b".snd",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Au,
        max_size: 2 * GB,
    },
    Signature {
        name: "Sega Mega Drive ROM",
        ext: "md",
        magic: b"SEGA",
        // The console name sits at 0x100; the ROM (and carved file) begins there.
        magic_offset: 0x100,
        secondary: None,
        extent: Extent::Genesis,
        max_size: 16 * MB,
    },
    Signature {
        name: "Creative Voice",
        ext: "voc",
        magic: b"Creative Voice File\x1a",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Voc,
        max_size: 2 * GB,
    },
    Signature {
        name: "AMR audio",
        ext: "amr",
        magic: b"#!AMR\n",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Amr,
        max_size: 256 * MB,
    },
    Signature {
        name: "PlayStation executable",
        ext: "psexe",
        magic: b"PS-X EXE",
        magic_offset: 0,
        secondary: None,
        extent: Extent::PsxExe,
        max_size: 8 * MB,
    },
    Signature {
        name: "Android sparse image",
        ext: "simg",
        magic: b"\x3a\xff\x26\xed",
        magic_offset: 0,
        secondary: None,
        extent: Extent::AndroidSparse,
        max_size: 16 * GB,
    },
    // Canon CR2 raw shares the little-endian TIFF magic, but carries a "CR" tag
    // at offset 8, so it must precede the generic TIFF entry.
    Signature {
        name: "Canon CR2 raw image",
        ext: "cr2",
        magic: &[0x49, 0x49, 0x2A, 0x00],
        magic_offset: 0,
        secondary: Some((8, b"CR")),
        extent: Extent::Tiff,
        max_size: 200 * MB,
    },
    Signature {
        name: "TIFF image / raw (DNG/NEF/ARW)",
        ext: "tif",
        magic: &[0x49, 0x49, 0x2A, 0x00], // little-endian ("II*\0")
        magic_offset: 0,
        secondary: None,
        extent: Extent::Tiff,
        max_size: 500 * MB,
    },
    Signature {
        name: "TIFF image / raw (DNG/NEF/ARW)",
        ext: "tif",
        magic: &[0x4D, 0x4D, 0x00, 0x2A], // big-endian ("MM\0*")
        magic_offset: 0,
        secondary: None,
        extent: Extent::Tiff,
        max_size: 500 * MB,
    },
    Signature {
        name: "BigTIFF image",
        ext: "tif",
        magic: &[0x49, 0x49, 0x2B, 0x00], // little-endian BigTIFF ("II+\0")
        magic_offset: 0,
        secondary: None,
        extent: Extent::Tiff,
        max_size: 2 * GB,
    },
    Signature {
        name: "BigTIFF image",
        ext: "tif",
        magic: &[0x4D, 0x4D, 0x00, 0x2B], // big-endian BigTIFF ("MM\0+")
        magic_offset: 0,
        secondary: None,
        extent: Extent::Tiff,
        max_size: 2 * GB,
    },
    Signature {
        name: "Matroska / WebM video",
        ext: "mkv",
        magic: &[0x1A, 0x45, 0xDF, 0xA3], // EBML header element ID
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ebml,
        max_size: 16 * GB,
    },
    Signature {
        name: "Ogg (Vorbis/Opus/Theora)",
        ext: "ogg",
        magic: b"OggS",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ogg,
        max_size: 2 * GB,
    },
    Signature {
        name: "ASF / WMV / WMA media",
        ext: "asf",
        // ASF Header Object GUID (75B22630-668E-11CF-A6D9-00AA0062CE6C).
        magic: &[
            0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62,
            0xCE, 0x6C,
        ],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Asf,
        max_size: 8 * GB,
    },
    Signature {
        name: "WebAssembly module",
        ext: "wasm",
        magic: &[0x00, 0x61, 0x73, 0x6D], // "\0asm"
        magic_offset: 0,
        secondary: None,
        extent: Extent::Wasm,
        max_size: GB,
    },
    Signature {
        name: "Windows icon",
        ext: "ico",
        magic: &[0x00, 0x00, 0x01, 0x00], // reserved=0, type=1 (icon)
        magic_offset: 0,
        secondary: None,
        extent: Extent::IcoCur,
        max_size: 16 * MB,
    },
    Signature {
        name: "Windows cursor",
        ext: "cur",
        magic: &[0x00, 0x00, 0x02, 0x00], // reserved=0, type=2 (cursor)
        magic_offset: 0,
        secondary: None,
        extent: Extent::IcoCur,
        max_size: 16 * MB,
    },
    Signature {
        name: "TrueType font",
        ext: "ttf",
        magic: &[0x00, 0x01, 0x00, 0x00], // sfnt version 1.0
        magic_offset: 0,
        secondary: None,
        extent: Extent::Sfnt,
        max_size: 64 * MB,
    },
    Signature {
        name: "OpenType font",
        ext: "otf",
        magic: b"OTTO", // sfnt with CFF outlines
        magic_offset: 0,
        secondary: None,
        extent: Extent::Sfnt,
        max_size: 64 * MB,
    },
    Signature {
        name: "WOFF web font",
        ext: "woff",
        magic: b"wOFF",
        magic_offset: 0,
        secondary: None,
        extent: Extent::HeaderSizeBe32 { offset: 8 },
        max_size: 64 * MB,
    },
    Signature {
        name: "WOFF2 web font",
        ext: "woff2",
        magic: b"wOF2",
        magic_offset: 0,
        secondary: None,
        extent: Extent::HeaderSizeBe32 { offset: 8 },
        max_size: 64 * MB,
    },
    Signature {
        name: "Enhanced Metafile",
        ext: "emf",
        // The EMR_HEADER's dSignature " EMF" sits 40 bytes into the file.
        magic: b" EMF",
        magic_offset: 40,
        secondary: None,
        extent: Extent::HeaderSizeLe32 { offset: 48 },
        max_size: 64 * MB,
    },
    Signature {
        name: "Standard MIDI",
        ext: "mid",
        magic: b"MThd",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Midi,
        max_size: 16 * MB,
    },
    Signature {
        name: "Flash Video",
        ext: "flv",
        magic: &[0x46, 0x4C, 0x56, 0x01], // "FLV" + version 1
        magic_offset: 0,
        secondary: None,
        extent: Extent::Flv,
        max_size: 2 * GB,
    },
    // libpcap: the magic is written in the host byte order, so it appears on
    // disk in either orientation; the microsecond and nanosecond variants
    // differ in the low bytes. The walker reads the byte order back from it.
    Signature {
        name: "pcap capture",
        ext: "pcap",
        magic: &[0xD4, 0xC3, 0xB2, 0xA1], // microsecond, little-endian host
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pcap,
        max_size: 4 * GB,
    },
    Signature {
        name: "pcap capture",
        ext: "pcap",
        magic: &[0xA1, 0xB2, 0xC3, 0xD4], // microsecond, big-endian host
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pcap,
        max_size: 4 * GB,
    },
    Signature {
        name: "pcap capture",
        ext: "pcap",
        magic: &[0x4D, 0x3C, 0xB2, 0xA1], // nanosecond, little-endian host
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pcap,
        max_size: 4 * GB,
    },
    Signature {
        name: "pcap capture",
        ext: "pcap",
        magic: &[0xA1, 0xB2, 0x3C, 0x4D], // nanosecond, big-endian host
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pcap,
        max_size: 4 * GB,
    },
    Signature {
        name: "pcapng capture",
        ext: "pcapng",
        // Section Header Block type, then the byte-order magic follows at +8.
        magic: &[0x0A, 0x0D, 0x0D, 0x0A],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pcapng,
        max_size: 4 * GB,
    },
    Signature {
        name: "TrueType Collection",
        ext: "ttc",
        magic: b"ttcf",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ttc,
        max_size: 256 * MB,
    },
    Signature {
        name: "JPEG 2000 image",
        ext: "jp2",
        // The 12-byte JP2 signature box: length 12, "jP  ", then 0D 0A 87 0A.
        magic: &[
            0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
        ],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mp4Atoms,
        max_size: 512 * MB,
    },
    Signature {
        name: "JPEG 2000 codestream",
        ext: "j2k",
        // SOC marker (FF4F) immediately followed by the SIZ marker (FF51).
        magic: &[0xFF, 0x4F, 0xFF, 0x51],
        magic_offset: 0,
        secondary: None,
        // The codestream ends at the EOC marker (FF D9). JPEG 2000 packet data is
        // bit-stuffed so an FF is never followed by a marker byte, making FF D9
        // unambiguous.
        extent: Extent::Footer {
            marker: &[0xFF, 0xD9],
            trailing: 0,
        },
        max_size: 512 * MB,
    },
    Signature {
        name: "Windows animated cursor",
        ext: "ani",
        magic: b"RIFF",
        magic_offset: 0,
        secondary: Some((8, b"ACON")),
        extent: Extent::RiffSize,
        max_size: 16 * MB,
    },
    Signature {
        // Legacy Office and other OLE2 containers; refined to doc/xls/ppt by
        // inspecting the directory stream names (see `classify_cfbf`).
        name: "Compound File Binary (OLE2)",
        ext: "ole",
        magic: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        magic_offset: 0,
        // The little-endian byte-order mark at offset 28 rejects a coincidental
        // magic; CFBF is always little-endian in practice.
        secondary: Some((28, &[0xFE, 0xFF])),
        extent: Extent::Cfbf,
        max_size: 2 * GB,
    },
    Signature {
        // Outlook data file (PST/OST). "!BDN" magic, then the "SM" client tag at
        // offset 8; the size is read from the header's ibFileEof field.
        name: "Outlook data file (PST/OST)",
        ext: "pst",
        magic: &[0x21, 0x42, 0x44, 0x4E],
        magic_offset: 0,
        secondary: Some((8, b"SM")),
        extent: Extent::Pst,
        max_size: 50 * GB,
    },
    Signature {
        // POSIX/GNU tar: the "ustar" magic sits at offset 257 of the first
        // 512-byte header; the member chain is walked to the zero terminator.
        name: "tar archive",
        ext: "tar",
        magic: b"ustar",
        magic_offset: 257,
        secondary: None,
        extent: Extent::Tar,
        max_size: 8 * GB,
    },
    Signature {
        // cpio "new ASCII" format (initramfs, RPM payloads).
        name: "cpio archive (newc)",
        ext: "cpio",
        magic: b"070701",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Cpio,
        max_size: 8 * GB,
    },
    Signature {
        // cpio "new ASCII" with CRC; same layout as 070701.
        name: "cpio archive (newc, CRC)",
        ext: "cpio",
        magic: b"070702",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Cpio,
        max_size: 8 * GB,
    },
    Signature {
        // SquashFS (Snap/AppImage/live media/firmware): "hsqs" magic, size from
        // the superblock's bytes_used field.
        name: "SquashFS image",
        ext: "squashfs",
        magic: b"hsqs",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Squashfs,
        max_size: 16 * GB,
    },
    Signature {
        // ISO 9660 disc image: the "CD001" standard identifier appears at
        // offset 1 of the primary volume descriptor, which lives at byte
        // offset 0x8000 (logical sector 16). magic_offset 0x8001 rewinds to the
        // true file start (including the 32 KiB system area).
        name: "ISO 9660 disc image",
        ext: "iso",
        magic: b"CD001",
        magic_offset: 0x8001,
        secondary: None,
        extent: Extent::Iso9660,
        max_size: 16 * GB,
    },
    Signature {
        // Autodesk FLIC animation (FLI variant, 0xAF11): the format magic is a
        // little-endian u16 at offset 4, so magic_offset rewinds to the file
        // start where the total-size u32 lives.
        name: "Autodesk FLIC animation (FLI)",
        ext: "fli",
        magic: b"\x11\xaf",
        magic_offset: 4,
        secondary: None,
        extent: Extent::Flic,
        max_size: 256 * MB,
    },
    Signature {
        // Autodesk FLIC animation (FLC variant, 0xAF12).
        name: "Autodesk FLIC animation (FLC)",
        ext: "flc",
        magic: b"\x12\xaf",
        magic_offset: 4,
        secondary: None,
        extent: Extent::Flic,
        max_size: 256 * MB,
    },
    Signature {
        // WavPack lossless audio: "wvpk" block magic, size walked over the
        // block chain.
        name: "WavPack audio",
        ext: "wv",
        magic: b"wvpk",
        magic_offset: 0,
        secondary: None,
        extent: Extent::WavPack,
        max_size: 2 * GB,
    },
    Signature {
        // Monkey's Audio: "MAC " descriptor magic, size summed from the
        // descriptor's segment byte counts.
        name: "Monkey's Audio",
        ext: "ape",
        magic: b"MAC ",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ape,
        max_size: 2 * GB,
    },
    Signature {
        // AppleSingle container: 0x00051600 magic, size from the entry table.
        name: "AppleSingle container",
        ext: "applesingle",
        magic: &[0x00, 0x05, 0x16, 0x00],
        magic_offset: 0,
        secondary: None,
        extent: Extent::AppleSingle,
        max_size: 2 * GB,
    },
    Signature {
        // AppleDouble container (the "._name" resource-fork sidecar files):
        // 0x00051607 magic, same entry-table layout as AppleSingle.
        name: "AppleDouble container",
        ext: "appledouble",
        magic: &[0x00, 0x05, 0x16, 0x07],
        magic_offset: 0,
        secondary: None,
        extent: Extent::AppleSingle,
        max_size: 2 * GB,
    },
    Signature {
        // Sun raster image: 0x59A66A95 magic, size = header + colormap + data.
        name: "Sun raster image",
        ext: "ras",
        magic: &[0x59, 0xA6, 0x6A, 0x95],
        magic_offset: 0,
        secondary: None,
        extent: Extent::SunRaster,
        max_size: 512 * MB,
    },
    Signature {
        // DSF (DSD Stream File): "DSD " chunk magic, total size from the header.
        name: "DSF audio (DSD)",
        ext: "dsf",
        magic: b"DSD ",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Dsf,
        max_size: 4 * GB,
    },
    Signature {
        // DSDIFF: "FRM8" outer chunk with a "DSD " form type at offset 0x0C.
        name: "DSDIFF audio (DSD)",
        ext: "dff",
        magic: b"FRM8",
        magic_offset: 0,
        secondary: Some((12, b"DSD ")),
        extent: Extent::Dsdiff,
        max_size: 4 * GB,
    },
    Signature {
        // PCF bitmap font (X11): "\x01fcp" magic, size from the table of contents.
        name: "PCF bitmap font",
        ext: "pcf",
        magic: b"\x01fcp",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pcf,
        max_size: 64 * MB,
    },
    Signature {
        // U-Boot legacy image: 0x27051956 magic, size = 64-byte header + data.
        name: "U-Boot uImage",
        ext: "uimage",
        magic: &[0x27, 0x05, 0x19, 0x56],
        magic_offset: 0,
        secondary: None,
        extent: Extent::UImage,
        max_size: 512 * MB,
    },
    Signature {
        // Quake PAK archive: "PACK" magic, size from the directory location.
        name: "Quake PAK archive",
        ext: "pak",
        magic: b"PACK",
        magic_offset: 0,
        secondary: None,
        extent: Extent::QuakePak,
        max_size: 2 * GB,
    },
    Signature {
        // Quake II model: "IDP2" magic, size from the header's ofs_end field.
        name: "Quake II model",
        ext: "md2",
        magic: b"IDP2",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Md2,
        max_size: 64 * MB,
    },
    Signature {
        // IVF (AV1/VP9/VP8 raw-bitstream container): "DKIF" magic, size walked
        // over the frame count in the header.
        name: "IVF video (AV1/VP9)",
        ext: "ivf",
        magic: b"DKIF",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ivf,
        max_size: 4 * GB,
    },
    Signature {
        // ZIM archive (openZIM/Kiwix offline content): "ZIM\x04" magic, size from
        // the checksum position field plus the trailing 16-byte MD5.
        name: "ZIM archive",
        ext: "zim",
        magic: b"ZIM\x04",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Zim,
        max_size: 64 * GB,
    },
    Signature {
        // GGUF (llama.cpp/ggml model weights): "GGUF" magic, size from the
        // metadata + tensor-info tables and the aligned tensor data.
        name: "GGUF model",
        ext: "gguf",
        magic: b"GGUF",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Gguf,
        max_size: 512 * GB,
    },
    Signature {
        // Android boot image: "ANDROID!" magic, size from the page-rounded
        // section sizes in the header.
        name: "Android boot image",
        ext: "img",
        magic: b"ANDROID!",
        magic_offset: 0,
        secondary: None,
        extent: Extent::BootImg,
        max_size: 2 * GB,
    },
    Signature {
        // KTX2 GPU texture: the 12-byte «KTX 20» identifier, size from the level
        // index and data descriptors.
        name: "KTX2 texture",
        ext: "ktx2",
        magic: &[
            0xAB, 0x4B, 0x54, 0x58, 0x20, 0x32, 0x30, 0xBB, 0x0D, 0x0A, 0x1A, 0x0A,
        ],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ktx2,
        max_size: 2 * GB,
    },
    Signature {
        // QOA audio ("Quite OK Audio"): "qoaf" magic, size walked over the frame
        // chain for the header's sample count.
        name: "QOA audio",
        ext: "qoa",
        magic: b"qoaf",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Qoa,
        max_size: 512 * MB,
    },
    Signature {
        // Android vendor_boot image: "VNDRBOOT" magic, size from the
        // page-rounded section sizes in the header.
        name: "Android vendor_boot image",
        ext: "img",
        magic: b"VNDRBOOT",
        magic_offset: 0,
        secondary: None,
        extent: Extent::VendorBoot,
        max_size: 2 * GB,
    },
    Signature {
        // NumPy array: "\x93NUMPY" magic, size from the header's dtype and shape.
        name: "NumPy array",
        ext: "npy",
        magic: b"\x93NUMPY",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Npy,
        max_size: 8 * GB,
    },
    Signature {
        // systemd journal: "LPKSHHRH" magic, size = header size + arena size.
        name: "systemd journal",
        ext: "journal",
        magic: b"LPKSHHRH",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Journal,
        max_size: 4 * GB,
    },
    Signature {
        // Unity asset bundle: "UnityFS" signature, total size from the header
        // after the version strings.
        name: "Unity asset bundle",
        ext: "unity3d",
        magic: b"UnityFS\0",
        magic_offset: 0,
        secondary: None,
        extent: Extent::UnityFs,
        max_size: 4 * GB,
    },
    Signature {
        // Fuji RAF raw image: 16-byte "FUJIFILMCCD-RAW " magic, size from the
        // section offset/length pairs in the header.
        name: "Fuji RAF raw image",
        ext: "raf",
        magic: b"FUJIFILMCCD-RAW ",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Raf,
        max_size: 512 * MB,
    },
    Signature {
        // Valve VPK archive (Source/Source 2 games): 0x55AA1234 magic, size
        // summed from the v2 header's section sizes.
        name: "Valve VPK archive",
        ext: "vpk",
        magic: &[0x34, 0x12, 0xAA, 0x55],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Vpk,
        max_size: 4 * GB,
    },
    Signature {
        // LAS LiDAR point cloud: "LASF" magic, size = point-data offset +
        // point count x record length.
        name: "LAS point cloud",
        ext: "las",
        magic: b"LASF",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Las,
        max_size: 8 * GB,
    },
    Signature {
        // Godot asset pack (Godot Engine games): "GDPC" magic, size from the
        // directory of packed files.
        name: "Godot asset pack",
        ext: "pck",
        magic: b"GDPC",
        magic_offset: 0,
        secondary: None,
        extent: Extent::GodotPck,
        max_size: 8 * GB,
    },
    Signature {
        // E57 3D point cloud (ASTM E2807): "ASTM-E57" magic, physical file
        // length as a u64 in the header.
        name: "E57 point cloud",
        ext: "e57",
        magic: b"ASTM-E57",
        magic_offset: 0,
        secondary: None,
        extent: Extent::E57,
        max_size: 16 * GB,
    },
    Signature {
        // RF64/BW64 large WAV: "RF64" magic with a "WAVE" form type, size from
        // the ds64 chunk's 64-bit RIFF size.
        name: "RF64/BW64 audio",
        ext: "rf64",
        magic: b"RF64",
        magic_offset: 0,
        secondary: Some((8, b"WAVE")),
        extent: Extent::Rf64,
        max_size: 64 * GB,
    },
    Signature {
        // NIfTI-1 neuroimaging volume: "n+1\0" magic at offset 344, size from
        // the dimensions and bit depth in the header.
        name: "NIfTI neuroimaging volume",
        ext: "nii",
        magic: b"n+1\0",
        magic_offset: 344,
        secondary: None,
        extent: Extent::Nifti,
        max_size: 4 * GB,
    },
    Signature {
        // USD crate scene (Pixar Universal Scene Description, binary): "PXR-USDC"
        // magic, size from the table of contents.
        name: "USD crate scene",
        ext: "usdc",
        magic: b"PXR-USDC",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Usdc,
        max_size: 8 * GB,
    },
    Signature {
        // Apache Avro object container: "Obj\x01" magic, size walked over the
        // data blocks by the file's sync marker.
        name: "Apache Avro container",
        ext: "avro",
        magic: b"Obj\x01",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Avro,
        max_size: 8 * GB,
    },
    Signature {
        // HDF5 scientific/ML data file: "\x89HDF\r\n\x1a\n" magic, size from the
        // superblock's end-of-file address.
        name: "HDF5 data file",
        ext: "h5",
        magic: &[0x89, 0x48, 0x44, 0x46, 0x0D, 0x0A, 0x1A, 0x0A],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Hdf5,
        max_size: 64 * GB,
    },
    Signature {
        // DDS GPU texture (DirectDraw Surface): "DDS " magic, size = header +
        // computed mip chain.
        name: "DDS texture",
        ext: "dds",
        magic: b"DDS ",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Dds,
        max_size: 512 * MB,
    },
    Signature {
        // ASTC GPU texture: 0x5CA1AB13 magic, size = header + 16 bytes/block.
        name: "ASTC texture",
        ext: "astc",
        magic: &[0x13, 0xAB, 0xA1, 0x5C],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Astc,
        max_size: 512 * MB,
    },
    Signature {
        // glTF binary 3D model: "glTF" magic, u32 total length at offset 8.
        name: "glTF binary 3D model",
        ext: "glb",
        magic: b"glTF",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Glb,
        max_size: 2 * GB,
    },
    Signature {
        // EROFS filesystem image: 0xE0F5E1E2 superblock magic at offset 1024,
        // size = block count << block-size shift.
        name: "EROFS filesystem image",
        ext: "erofs",
        magic: &[0xE2, 0xE1, 0xF5, 0xE0],
        magic_offset: 1024,
        secondary: None,
        extent: Extent::Erofs,
        max_size: 16 * GB,
    },
    Signature {
        // KTX v1 GPU texture: the 12-byte «KTX 11» identifier, size from the
        // per-level imageSize fields.
        name: "KTX texture",
        ext: "ktx",
        magic: &[
            0xAB, 0x4B, 0x54, 0x58, 0x20, 0x31, 0x31, 0xBB, 0x0D, 0x0A, 0x1A, 0x0A,
        ],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Ktx1,
        max_size: 2 * GB,
    },
    Signature {
        // OpenEXR image: 0x76 0x2f 0x31 0x01 magic, size from the chunk offset
        // table walked to the last chunk.
        name: "OpenEXR image",
        ext: "exr",
        magic: &[0x76, 0x2F, 0x31, 0x01],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Exr,
        max_size: 2 * GB,
    },
    Signature {
        // MCAP log: "\x89MCAP0\r\n" magic, size from the record stream walked to
        // the footer record plus the trailing magic.
        name: "MCAP log",
        ext: "mcap",
        magic: &[0x89, 0x4D, 0x43, 0x41, 0x50, 0x30, 0x0D, 0x0A],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Mcap,
        max_size: 16 * GB,
    },
    Signature {
        // Source-engine BSP map: "VBSP" magic, size from the furthest lump end
        // in the 64-entry lump directory.
        name: "Source BSP map",
        ext: "bsp",
        magic: b"VBSP",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Bsp,
        max_size: 2 * GB,
    },
    Signature {
        // QOI image: "qoif" magic, size from decoding the chunk stream to the
        // pixel count plus the 8-byte end marker.
        name: "QOI image",
        ext: "qoi",
        magic: b"qoif",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Qoi,
        max_size: 512 * MB,
    },
    Signature {
        // RPM package: 0xEDABEEDB lead magic, size from the lead plus the padded
        // signature header plus the RPMSIGTAG_SIZE header/payload size.
        name: "RPM package",
        ext: "rpm",
        magic: &[0xED, 0xAB, 0xEE, 0xDB],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Rpm,
        max_size: 8 * GB,
    },
    Signature {
        // farbfeld image: "farbfeld" magic, size = 16 + width*height*8.
        name: "farbfeld image",
        ext: "ff",
        magic: b"farbfeld",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Farbfeld,
        max_size: 512 * MB,
    },
    Signature {
        // YUV4MPEG2 raw-video stream: "YUV4MPEG2" magic, size from walking the
        // fixed-size frames.
        name: "YUV4MPEG2 video",
        ext: "y4m",
        magic: b"YUV4MPEG2",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Y4m,
        max_size: 16 * GB,
    },
    Signature {
        // PVR v3 texture: 0x03525650 ("PVR\3") magic, size = header + metadata +
        // block-compressed mip chain.
        name: "PVR texture",
        ext: "pvr",
        magic: &[0x50, 0x56, 0x52, 0x03],
        magic_offset: 0,
        secondary: None,
        extent: Extent::Pvr,
        max_size: 512 * MB,
    },
    Signature {
        // BLP2 texture (World of Warcraft): "BLP2" magic, size from the furthest
        // mipmap end in the 16-entry offset/length directory.
        name: "BLP2 texture",
        ext: "blp",
        magic: b"BLP2",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Blp,
        max_size: 256 * MB,
    },
    Signature {
        // GRIB2 weather data: "GRIB" magic, size from walking the per-message
        // 64-bit total lengths (each validated by a trailing "7777").
        name: "GRIB2 weather data",
        ext: "grib2",
        magic: b"GRIB",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Grib2,
        max_size: 16 * GB,
    },
    Signature {
        // F2FS filesystem image: 0xF2F52010 superblock magic at offset 1024,
        // size = block count << block-size shift.
        name: "F2FS filesystem image",
        ext: "f2fs",
        magic: &[0x10, 0x20, 0xF5, 0xF2],
        magic_offset: 1024,
        secondary: None,
        extent: Extent::F2fs,
        max_size: 64 * GB,
    },
    Signature {
        // btrfs filesystem image: "_BHRfS_M" superblock magic 64 KiB in (at
        // +64), size = total_bytes for a single-device image.
        name: "btrfs filesystem image",
        ext: "btrfs",
        magic: b"_BHRfS_M",
        magic_offset: 0x1_0040,
        secondary: None,
        extent: Extent::Btrfs,
        max_size: 64 * GB,
    },
    Signature {
        // XFS filesystem image: big-endian "XFSB" magic at offset 0, size =
        // sb_dblocks × sb_blocksize.
        name: "XFS filesystem image",
        ext: "xfs",
        magic: b"XFSB",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Xfs,
        max_size: 64 * GB,
    },
    Signature {
        // exFAT filesystem image: "EXFAT   " boot-sector magic at offset 3,
        // size = VolumeLength << BytesPerSectorShift.
        name: "exFAT filesystem image",
        ext: "exfat",
        magic: b"EXFAT   ",
        magic_offset: 3,
        secondary: None,
        extent: Extent::Exfat,
        max_size: 512 * GB,
    },
    Signature {
        // APFS container image: "NXSB" superblock magic at offset 32, size =
        // block count × block size.
        name: "APFS container image",
        ext: "apfs",
        magic: b"NXSB",
        magic_offset: 32,
        secondary: None,
        extent: Extent::Apfs,
        max_size: 512 * GB,
    },
    Signature {
        // ReFS filesystem image: "ReFS" boot-record signature at offset 3 and
        // "FSRS" at 0x10, size = NumberOfSectors × BytesPerSector.
        name: "ReFS filesystem image",
        ext: "refs",
        magic: b"ReFS",
        magic_offset: 3,
        secondary: Some((0x10, b"FSRS")),
        extent: Extent::Refs,
        max_size: 512 * GB,
    },
    Signature {
        // NTFS filesystem image: "NTFS    " OEM signature at offset 3, size =
        // TotalSectors × BytesPerSector.
        name: "NTFS filesystem image",
        ext: "ntfs",
        magic: b"NTFS    ",
        magic_offset: 3,
        secondary: None,
        extent: Extent::Ntfs,
        max_size: 512 * GB,
    },
    Signature {
        // Linux swap area (4 KiB pages): "SWAPSPACE2" magic at page_size - 10
        // (4086), size = (last_page + 1) × 4096.
        name: "Linux swap area",
        ext: "swap",
        magic: b"SWAPSPACE2",
        magic_offset: 4086,
        secondary: None,
        extent: Extent::Swap,
        max_size: 128 * GB,
    },
    Signature {
        // romfs image: "-rom1fs-" magic at offset 0, full image size as a
        // big-endian u32 at offset 8.
        name: "romfs image",
        ext: "romfs",
        magic: b"-rom1fs-",
        magic_offset: 0,
        secondary: None,
        extent: Extent::Romfs,
        max_size: 4 * GB,
    },
    Signature {
        // cramfs image: the 16-byte "Compressed ROMFS" signature at offset 0x10
        // (endianness-independent); size = u32 at offset 4 (magic endianness).
        name: "cramfs image",
        ext: "cramfs",
        magic: b"Compressed ROMFS",
        magic_offset: 0x10,
        secondary: None,
        extent: Extent::Cramfs,
        max_size: 4 * GB,
    },
    Signature {
        // JFS filesystem image: "JFS1" aggregate-superblock magic 32 KiB in,
        // size = aggregate block count × physical block size.
        name: "JFS filesystem image",
        ext: "jfs",
        magic: b"JFS1",
        magic_offset: 0x8000,
        secondary: None,
        extent: Extent::Jfs,
        max_size: 64 * GB,
    },
    Signature {
        // UFS1 filesystem image (little-endian): 0x00011954 magic at 0x255C
        // (superblock at 8 KiB + 0x55C), size = fragment count × fragment size.
        name: "UFS filesystem image",
        ext: "ufs",
        magic: &[0x54, 0x19, 0x01, 0x00],
        magic_offset: 0x255C,
        secondary: None,
        extent: Extent::Ufs,
        max_size: 64 * GB,
    },
    Signature {
        // UFS1 filesystem image (big-endian): 0x00011954 magic at 0x255C.
        name: "UFS filesystem image",
        ext: "ufs",
        magic: &[0x00, 0x01, 0x19, 0x54],
        magic_offset: 0x255C,
        secondary: None,
        extent: Extent::Ufs,
        max_size: 64 * GB,
    },
    Signature {
        // BeFS filesystem image (little-endian): "BFS1" magic at 0x220
        // (superblock 512 + 0x20), size = block count × block size.
        name: "BeFS filesystem image",
        ext: "befs",
        magic: &[0x31, 0x53, 0x46, 0x42],
        magic_offset: 0x220,
        secondary: None,
        extent: Extent::Befs,
        max_size: 64 * GB,
    },
    Signature {
        // BeFS filesystem image (big-endian): "BFS1" magic at 0x220.
        name: "BeFS filesystem image",
        ext: "befs",
        magic: &[0x42, 0x46, 0x53, 0x31],
        magic_offset: 0x220,
        secondary: None,
        extent: Extent::Befs,
        max_size: 64 * GB,
    },
    Signature {
        // HFS+ volume header ("H+" signature + version 4) at offset 1024,
        // size = total blocks × allocation block size.
        name: "HFS+ filesystem image",
        ext: "hfsplus",
        magic: &[0x48, 0x2B, 0x00, 0x04],
        magic_offset: 1024,
        secondary: None,
        extent: Extent::HfsPlus,
        max_size: 512 * GB,
    },
    Signature {
        // HFSX volume header ("HX" signature + version 5) at offset 1024.
        name: "HFS+ filesystem image",
        ext: "hfsplus",
        magic: &[0x48, 0x58, 0x00, 0x05],
        magic_offset: 1024,
        secondary: None,
        extent: Extent::HfsPlus,
        max_size: 512 * GB,
    },
    Signature {
        // ReiserFS 3.6 filesystem image: "ReIsEr2Fs" magic at 0x10034
        // (superblock 64 KiB + 0x34), size = block count × block size.
        name: "ReiserFS filesystem image",
        ext: "reiserfs",
        magic: b"ReIsEr2Fs",
        magic_offset: 0x10034,
        secondary: None,
        extent: Extent::Reiserfs,
        max_size: 512 * GB,
    },
    Signature {
        // ReiserFS 3.6 with a relocated journal: "ReIsEr3Fs" magic at 0x10034.
        name: "ReiserFS filesystem image",
        ext: "reiserfs",
        magic: b"ReIsEr3Fs",
        magic_offset: 0x10034,
        secondary: None,
        extent: Extent::Reiserfs,
        max_size: 512 * GB,
    },
    Signature {
        // ReiserFS 3.5 filesystem image: "ReIsErFs" magic at 0x2034
        // (superblock 8 KiB + 0x34).
        name: "ReiserFS filesystem image",
        ext: "reiserfs",
        magic: b"ReIsErFs",
        magic_offset: 0x2034,
        secondary: None,
        extent: Extent::Reiserfs,
        max_size: 512 * GB,
    },
    Signature {
        // Android DTBO / DTB image (dt_table_header): 0xD7B7AB1E magic with the
        // total image size as a big-endian u32 at offset 4.
        name: "Android DTBO image",
        ext: "dtbo",
        magic: &[0xD7, 0xB7, 0xAB, 0x1E],
        magic_offset: 0,
        secondary: None,
        extent: Extent::HeaderSizeBe32 { offset: 4 },
        max_size: 64 * MB,
    },
    Signature {
        // Flattened device tree (`.dtb`/FDT): 0xD00DFEED magic, with the total
        // block size as a big-endian u32 at offset 4 (the exact file length).
        name: "Device Tree Blob",
        ext: "dtb",
        magic: &[0xD0, 0x0D, 0xFE, 0xED],
        magic_offset: 0,
        secondary: None,
        extent: Extent::HeaderSizeBe32 { offset: 4 },
        max_size: 256 * MB,
    },
    Signature {
        // TRX firmware container (Broadcom/OpenWrt router images): "HDR0" magic
        // with the total file length (header included) as a little-endian u32 at
        // offset 4.
        name: "TRX firmware image",
        ext: "trx",
        magic: b"HDR0",
        magic_offset: 0,
        secondary: None,
        extent: Extent::HeaderSizeLe32 { offset: 4 },
        max_size: 256 * MB,
    },
    Signature {
        // DPX film frame (SMPTE ST 268), big-endian ("SDPX"): the generic file
        // header stores the total file size as a big-endian u32 at offset 0x10.
        name: "DPX image (big-endian)",
        ext: "dpx",
        magic: b"SDPX",
        magic_offset: 0,
        secondary: None,
        extent: Extent::HeaderSizeBe32 { offset: 0x10 },
        max_size: 2 * GB,
    },
    Signature {
        // DPX film frame, little-endian ("XPDS"): same layout, total file size
        // is a little-endian u32 at offset 0x10.
        name: "DPX image (little-endian)",
        ext: "dpx",
        magic: b"XPDS",
        magic_offset: 0,
        secondary: None,
        extent: Extent::HeaderSizeLe32 { offset: 0x10 },
        max_size: 2 * GB,
    },
    Signature {
        // Cineon film frame (the Kodak format DPX descends from), big-endian
        // only: magic 0x802A5FD7 at offset 0, total file size as a big-endian
        // u32 at offset 0x14 of the file-information header.
        name: "Cineon image",
        ext: "cin",
        magic: b"\x80\x2a\x5f\xd7",
        magic_offset: 0,
        secondary: None,
        extent: Extent::HeaderSizeBe32 { offset: 0x14 },
        max_size: 2 * GB,
    },
];

/// Look up signatures relevant to a single source byte, keyed by the first
/// byte of their magic *as it appears on disk*. The on-disk first byte is the
/// first byte of `magic` (because `magic_offset` shifts the file start
/// backward, not the magic position).
pub struct SignatureIndex {
    /// For each possible leading byte, the signatures whose magic starts with
    /// it. Most slots are empty, keeping per-byte work tiny.
    by_first_byte: [Vec<&'static Signature>; 256],
    /// A 65536-bit set (one bit per two-byte magic prefix) that gates the hot
    /// scan loop: for a byte position whose first two bytes are not the prefix
    /// of any magic, one bitset lookup rejects it without walking a `by_first_byte`
    /// bucket. Buckets for common leading bytes (`f`, `0xFF`, `R`, `0x00`, `M`)
    /// hold a dozen signatures each, so this skips almost all of that comparison
    /// work on real data. A one-byte magic marks all 256 prefixes for its byte,
    /// so the gate never hides a valid match.
    prefix_bits: Box<[u64]>,
    /// Largest number of bytes we must inspect from the magic position to
    /// confirm any magic *and* its secondary tag.
    pub max_lookahead: usize,
}

impl SignatureIndex {
    pub fn build(active: &[&'static Signature]) -> Self {
        // `Vec` is not `Copy`, so build the array element by element.
        let by_first_byte: [Vec<&'static Signature>; 256] = std::array::from_fn(|_| Vec::new());
        // 65536 bits = 1024 u64 words = 8 KiB, small enough to stay L1-resident.
        let mut prefix_bits = vec![0u64; 1024];
        let mut mark = |p: usize| prefix_bits[p >> 6] |= 1u64 << (p & 63);
        let mut idx = SignatureIndex {
            by_first_byte,
            prefix_bits: Box::new([]),
            max_lookahead: 0,
        };
        for sig in active {
            let first = sig.magic[0] as usize;
            idx.by_first_byte[first].push(sig);
            if sig.magic.len() >= 2 {
                mark((first << 8) | sig.magic[1] as usize);
            } else {
                // A one-byte magic can be followed by any byte; mark them all.
                for b1 in 0..256 {
                    mark((first << 8) | b1);
                }
            }
            let reach = match sig.secondary {
                Some((off, tag)) => sig.magic.len().max(off + tag.len()),
                None => sig.magic.len(),
            };
            idx.max_lookahead = idx.max_lookahead.max(reach);
        }
        idx.prefix_bits = prefix_bits.into_boxed_slice();
        idx
    }

    /// Return the signature whose magic (and secondary tag, if any) matches the
    /// bytes starting at `window`. `window` must begin at the on-disk position
    /// of a candidate magic.
    pub fn match_at(&self, window: &[u8]) -> Option<&'static Signature> {
        let &first = window.first()?;
        // Fast reject: if the two-byte prefix at this position isn't the start of
        // any magic, there is nothing to compare. (Windows shorter than two bytes
        // only occur at the very end of the scan; fall through to the bucket,
        // which is where the lone one-byte magic is confirmed.)
        if window.len() >= 2 {
            let p = ((first as usize) << 8) | window[1] as usize;
            if self.prefix_bits[p >> 6] & (1u64 << (p & 63)) == 0 {
                return None;
            }
        }
        for sig in &self.by_first_byte[first as usize] {
            if window.len() < sig.magic.len() || &window[..sig.magic.len()] != sig.magic {
                continue;
            }
            if let Some((off, tag)) = sig.secondary {
                if window.len() < off + tag.len() || &window[off..off + tag.len()] != tag {
                    continue;
                }
            }
            return Some(sig);
        }
        None
    }
}

/// Resolve user-requested type names (extensions or `"all"`) to signatures.
///
/// Returns an error listing the offending name if one is unknown.
pub fn select(types: &[String]) -> anyhow::Result<Vec<&'static Signature>> {
    if types.is_empty() || types.iter().any(|t| t.eq_ignore_ascii_case("all")) {
        // "all" means every *file* type. Filesystem images are opt-in (see
        // `Category::Volume`); the real-image corpus showed a default scan of an
        // exFAT or HFS+ volume carving the whole volume as one file and
        // nothing inside it.
        return Ok(SIGNATURES
            .iter()
            .filter(|s| category_of(s.ext) != Category::Volume)
            .collect());
    }
    let mut selected = Vec::new();
    for t in types {
        // A token may name a whole category (e.g. "image", "audio") or a single
        // extension. Categories are tried first so they take precedence.
        if let Some(cat) = Category::from_name(t) {
            selected.extend(SIGNATURES.iter().filter(|s| category_of(s.ext) == cat));
            continue;
        }
        let matches: Vec<&'static Signature> = SIGNATURES
            .iter()
            .filter(|s| s.ext.eq_ignore_ascii_case(t))
            .collect();
        if matches.is_empty() {
            // De-duplicate known extensions for the error message.
            let mut known: Vec<&str> = SIGNATURES.iter().map(|s| s.ext).collect();
            known.dedup();
            anyhow::bail!(
                "unknown file type or category '{t}'. Categories: {}. Known types: {}",
                Category::NAMES.join(", "),
                known.join(", ")
            );
        }
        selected.extend(matches);
    }
    Ok(selected)
}

impl Signature {
    /// Whether this signature describes a whole filesystem or partition image
    /// rather than a file. Such a match never hides the files inside it from
    /// the carver, and is only carved when asked for by name or category.
    pub fn is_volume(&self) -> bool {
        category_of(self.ext) == Category::Volume
    }
}

/// A broad grouping of file types, so a whole class (e.g. all images) can be
/// selected with one name instead of listing every extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Image,
    Audio,
    Video,
    Document,
    Archive,
    Executable,
    Font,
    System,
    /// A whole filesystem or partition image (NTFS, exFAT, HFS+, btrfs, ...).
    /// Not part of the implicit "all" selection: a default scan of a disk would
    /// otherwise copy every partition on it wholesale, and the files inside are
    /// what people want. Ask for it by name (`--type volume` or `--type ntfs`)
    /// to carve a lost partition out of a larger image.
    Volume,
    Other,
}

impl Category {
    /// The selectable category names, in display order.
    pub const NAMES: &'static [&'static str] = &[
        "image",
        "audio",
        "video",
        "document",
        "archive",
        "executable",
        "font",
        "system",
        "volume",
    ];

    /// Resolve a user-supplied category name (case-insensitive; a trailing "s"
    /// is allowed, e.g. "images"). `Other` is not selectable by name.
    pub fn from_name(name: &str) -> Option<Category> {
        let n = name.trim().to_ascii_lowercase();
        let n = n.strip_suffix('s').unwrap_or(&n);
        match n {
            "image" => Some(Category::Image),
            "audio" => Some(Category::Audio),
            "video" => Some(Category::Video),
            "document" | "doc" => Some(Category::Document),
            "archive" => Some(Category::Archive),
            "executable" => Some(Category::Executable), // "exe" stays a file type
            "font" => Some(Category::Font),
            "system" => Some(Category::System),
            "volume" | "filesystem" | "partition" => Some(Category::Volume),
            _ => None,
        }
    }

    /// The category's lowercase name (the inverse of [`Category::from_name`]).
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Image => "image",
            Category::Audio => "audio",
            Category::Video => "video",
            Category::Document => "document",
            Category::Archive => "archive",
            Category::Executable => "executable",
            Category::Font => "font",
            Category::System => "system",
            Category::Volume => "volume",
            Category::Other => "other",
        }
    }
}

/// Refine a ZIP into the specific ZIP-based format it carries, by looking for a
/// marker member name in its bytes. Returns `(extension, name)` for a known
/// format, or `None` for a plain ZIP. APK is checked before JAR because both
/// carry `META-INF/MANIFEST.MF`.
pub fn classify_zip(head: &[u8]) -> Option<(&'static str, &'static str)> {
    let has = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
    if has(b"application/epub+zip") {
        Some(("epub", "EPUB e-book"))
    } else if has(b"application/vnd.oasis.opendocument.text") {
        Some(("odt", "OpenDocument text"))
    } else if has(b"application/vnd.oasis.opendocument.spreadsheet") {
        Some(("ods", "OpenDocument spreadsheet"))
    } else if has(b"application/vnd.oasis.opendocument.presentation") {
        Some(("odp", "OpenDocument presentation"))
    } else if has(b"AndroidManifest.xml") {
        Some(("apk", "Android package"))
    } else if has(b"word/document.xml") {
        Some(("docx", "Word (OOXML) document"))
    } else if has(b"xl/workbook.xml") {
        Some(("xlsx", "Excel (OOXML) workbook"))
    } else if has(b"ppt/presentation.xml") {
        Some(("pptx", "PowerPoint (OOXML) presentation"))
    } else if has(b"META-INF/MANIFEST.MF") {
        Some(("jar", "Java archive"))
    } else {
        None
    }
}

/// Root storage CLSID of a Windows Installer database (`{000C1084-0000-0000-
/// C000-000000000046}`), stored as a GUID: the first three fields little-endian,
/// the last eight bytes in order.
const MSI_CLSID: [u8; 16] = [
    0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// Read the root directory entry's CLSID (16 bytes at directory-entry offset 80)
/// and compare it to `clsid`. Returns false if the directory sector isn't within
/// `head` (so the caller falls back to other checks).
fn root_clsid_is(head: &[u8], clsid: &[u8; 16]) -> bool {
    if head.len() < 512 {
        return false;
    }
    let sector_size = match u16::from_le_bytes([head[30], head[31]]) {
        9 => 512usize,
        12 => 4096usize,
        _ => return false,
    };
    let first_dir = u32::from_le_bytes([head[48], head[49], head[50], head[51]]) as usize;
    // The root entry is the first 128-byte record of the directory sector, which
    // starts at byte `(sector + 1) * sector_size`.
    let clsid_off = match first_dir
        .checked_add(1)
        .and_then(|s| s.checked_mul(sector_size))
        .and_then(|o| o.checked_add(80))
    {
        Some(o) => o,
        None => return false,
    };
    head.len() >= clsid_off + 16 && &head[clsid_off..clsid_off + 16] == clsid
}

/// Refine a Compound File Binary (OLE2) container into the specific format it
/// carries. Most legacy formats are recognised by a marker stream name (stored
/// as UTF-16LE, so each ASCII letter is matched interleaved with a NUL byte);
/// installer databases, whose stream names are mangled, are recognised by the
/// root storage CLSID instead. Returns `(extension, name)`, or `None` for an
/// unrecognised compound file (which stays a generic `.ole`).
pub fn classify_cfbf(head: &[u8]) -> Option<(&'static str, &'static str)> {
    let has = |name: &str| {
        let needle: Vec<u8> = name.bytes().flat_map(|b| [b, 0]).collect();
        head.windows(needle.len()).any(|w| w == needle)
    };
    if root_clsid_is(head, &MSI_CLSID) {
        Some(("msi", "Windows Installer package"))
    } else if has("__substg1.0_") {
        // Property-stream prefix unique to Outlook .msg messages.
        Some(("msg", "Outlook message"))
    } else if has("PowerPoint Document") {
        Some(("ppt", "PowerPoint 97-2003 presentation"))
    } else if has("WordDocument") {
        Some(("doc", "Word 97-2003 document"))
    } else if has("Workbook") || has("Book") {
        Some(("xls", "Excel 97-2003 workbook"))
    } else {
        None
    }
}

/// Classify a file-type extension into a [`Category`].
pub fn category_of(ext: &str) -> Category {
    match ext {
        "jpg" | "png" | "gif" | "bmp" | "tif" | "webp" | "heic" | "avif" | "jp2" | "j2k"
        | "jxl" | "ico" | "cur" | "icns" | "cr2" | "cr3" | "psd" | "wmf" | "emf" | "djvu"
        | "ani" | "eps" | "fli" | "flc" | "dpx" | "cin" | "mng" | "jng" | "ras" | "ktx2"
        | "raf" | "nii" | "dds" | "astc" | "ktx" | "exr" | "qoi" | "ff" | "pvr" | "blp" => {
            Category::Image
        }
        "mp3" | "aac" | "wav" | "aiff" | "aifc" | "ogg" | "mid" | "m4a" | "au" | "voc" | "amr"
        | "wv" | "ape" | "dsf" | "dff" | "sf2" | "qoa" | "rf64" => Category::Audio,
        "mp4" | "mov" | "m4v" | "3gp" | "mkv" | "avi" | "flv" | "asf" | "ts" | "mpg" | "ivf"
        | "y4m" => Category::Video,
        // The OOXML/OpenDocument/e-book types come from ZIP-content
        // classification; doc/xls/ppt/msg (and a generic OLE2 container) from
        // CFBF.
        "pdf" | "rtf" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub" | "doc"
        | "xls" | "ppt" | "msg" | "pst" | "ole" => Category::Document,
        "zip" | "7z" | "rar" | "cab" | "ar" | "tar" | "cpio" | "zst" | "lz4" | "jar" | "pak"
        | "zim" | "unity3d" | "vpk" | "pck" => Category::Archive,
        "elf" | "exe" | "macho" | "dex" | "wasm" | "apk" | "msi" | "pdb" | "rpm" => {
            Category::Executable
        }
        "ttf" | "otf" | "woff" | "woff2" | "ttc" | "pcf" => Category::Font,
        "regf" | "evtx" | "wim" | "sqlite" | "pcap" | "pcapng" | "squashfs" | "iso" | "uimage"
        | "dtb" | "trx" | "img" | "dtbo" | "journal" | "h5" | "mcap" => Category::System,
        "erofs" | "f2fs" | "btrfs" | "xfs" | "exfat" | "apfs" | "refs" | "ntfs" | "swap"
        | "romfs" | "cramfs" | "jfs" | "ufs" | "befs" | "hfsplus" | "reiserfs" => Category::Volume,
        _ => Category::Other,
    }
}

/// Whether the signature table carves this extension directly — i.e. the type
/// has a magic number we recognise at the start of a file. This deliberately
/// excludes container subtypes that are only resolved from content: `docx` /
/// `xlsx` / `epub` (a ZIP) and `doc` / `xls` / `msg` (an OLE2 container) are
/// listed in the table as `zip` / `ole`, so they return `false` here.
pub fn has_signature(ext: &str) -> bool {
    SIGNATURES.iter().any(|s| s.ext == ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> SignatureIndex {
        let all = select(&[]).unwrap();
        SignatureIndex::build(&all)
    }

    fn ext_of(window: &[u8]) -> Option<&'static str> {
        index().match_at(window).map(|s| s.ext)
    }

    #[test]
    fn riff_secondary_tag_disambiguates() {
        assert_eq!(ext_of(b"RIFF\0\0\0\0WAVE"), Some("wav"));
        assert_eq!(ext_of(b"RIFF\0\0\0\0AVI "), Some("avi"));
        assert_eq!(ext_of(b"RIFF\0\0\0\0WEBP"), Some("webp"));
        assert_eq!(ext_of(b"RIFF\0\0\0\0sfbk"), Some("sf2"));
        // An unknown RIFF form type matches nothing (no generic fallback).
        assert_eq!(ext_of(b"RIFF\0\0\0\0JUNK"), None);
    }

    #[test]
    fn ftyp_brand_picks_heic_over_mp4() {
        // The window starts at the `ftyp` magic; the brand is 4 bytes later.
        assert_eq!(ext_of(b"ftypheic"), Some("heic"));
        assert_eq!(ext_of(b"ftypmif1"), Some("heic"));
        // Brand-specific media types get their own extension.
        assert_eq!(ext_of(b"ftypqt  "), Some("mov"));
        assert_eq!(ext_of(b"ftypM4A "), Some("m4a"));
        assert_eq!(ext_of(b"ftypM4V "), Some("m4v"));
        // An unrecognised brand falls through to the generic MP4 entry.
        assert_eq!(ext_of(b"ftypisom"), Some("mp4"));
    }

    #[test]
    fn plain_magics_match() {
        assert_eq!(ext_of(&[0xFF, 0xD8, 0xFF, 0x00]), Some("jpg"));
        assert_eq!(ext_of(b"SQLite format 3\0"), Some("sqlite"));
        assert_eq!(ext_of(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]), Some("7z"));
        assert_eq!(ext_of(b"not a magic"), None);
    }

    #[test]
    fn dpx_both_byte_orders_match() {
        // Both the big-endian ("SDPX") and little-endian ("XPDS") DPX magics
        // resolve to the dpx type.
        assert_eq!(ext_of(b"SDPX\0\0\0\0"), Some("dpx"));
        assert_eq!(ext_of(b"XPDS\0\0\0\0"), Some("dpx"));
    }

    #[test]
    fn cineon_magic_matches() {
        assert_eq!(ext_of(&[0x80, 0x2A, 0x5F, 0xD7, 0, 0, 0, 0]), Some("cin"));
    }

    #[test]
    fn dtb_magic_matches() {
        assert_eq!(ext_of(&[0xD0, 0x0D, 0xFE, 0xED, 0, 0, 0, 0]), Some("dtb"));
    }

    #[test]
    fn dtbo_magic_matches() {
        assert_eq!(ext_of(&[0xD7, 0xB7, 0xAB, 0x1E, 0, 0, 0, 0]), Some("dtbo"));
    }

    #[test]
    fn trx_magic_matches() {
        assert_eq!(ext_of(b"HDR0\0\0\0\0"), Some("trx"));
    }

    #[test]
    fn mng_magic_matches() {
        assert_eq!(
            ext_of(&[0x8A, 0x4D, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            Some("mng")
        );
    }

    #[test]
    fn jng_magic_matches() {
        assert_eq!(
            ext_of(&[0x8B, 0x4A, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            Some("jng")
        );
    }

    #[test]
    fn select_filters_and_rejects() {
        assert_eq!(select(&["jpg".to_string()]).unwrap().len(), 1);
        // "gif" maps to two entries (87a and 89a).
        assert_eq!(select(&["gif".to_string()]).unwrap().len(), 2);
        assert!(select(&["all".to_string()]).unwrap().len() >= 13);
        let err = select(&["nope".to_string()]).unwrap_err().to_string();
        assert!(err.contains("unknown file type or category"));
    }

    #[test]
    fn select_by_category() {
        // A category expands to every signature classified into it.
        let images = select(&["image".to_string()]).unwrap();
        assert!(images.iter().all(|s| category_of(s.ext) == Category::Image));
        assert!(images.iter().any(|s| s.ext == "jpg"));
        assert!(images.iter().any(|s| s.ext == "png"));
        assert!(!images.iter().any(|s| s.ext == "mp3"));

        // Plural form is accepted.
        assert_eq!(select(&["images".to_string()]).unwrap().len(), images.len());

        // "executable" is a category; "exe" remains a single file type.
        assert!(select(&["executable".to_string()])
            .unwrap()
            .iter()
            .any(|s| s.ext == "elf"));
        assert_eq!(select(&["exe".to_string()]).unwrap().len(), 1);

        // Categories and extensions can be mixed in one selection.
        let mixed = select(&["audio".to_string(), "pdf".to_string()]).unwrap();
        assert!(mixed.iter().any(|s| s.ext == "mp3"));
        assert!(mixed.iter().any(|s| s.ext == "pdf"));
    }
}
