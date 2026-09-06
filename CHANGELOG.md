# Changelog

All notable changes to `unearth` are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.5.0](https://github.com/trondegil/file-recover-lib/compare/unearth-v0.4.0...unearth-v0.5.0) (2026-09-06)


### Features

* check JPEG structure while reassembling, and settle XFS with real images (roadmap step 5) ([8a1a214](https://github.com/trondegil/file-recover-lib/commit/8a1a214155eb11d2d862d1053591d5c49029c963))
* confine every recovered write, and find volumes in extended partitions ([3d72f5c](https://github.com/trondegil/file-recover-lib/commit/3d72f5c5ea2599590c6e5f26b0ab59594ed4bf4f))
* reassemble fragmented FAT and exFAT files from the allocation map (roadmap step 5.1) ([bccd114](https://github.com/trondegil/file-recover-lib/commit/bccd114e03ad0589e491c5c1d0d922e7931a5886))
* say exactly what the tool can do (roadmap step 4) ([5fa9351](https://github.com/trondegil/file-recover-lib/commit/5fa9351d0ce34879aaff959ead2ec388350d6c23))


### Bug Fixes

* correct the bytes recovered from NTFS, HFS+, and the carver ([66e1c34](https://github.com/trondegil/file-recover-lib/commit/66e1c34df662948f3ecea692bd700faec0c62ed6))
* harden the engine against hostile input and long sessions (roadmap step 3) ([43237f7](https://github.com/trondegil/file-recover-lib/commit/43237f7253185b0e6e8186e6d65fcec01526a119))
* read raw devices the platform way and keep recovered names writable everywhere ([f8fda28](https://github.com/trondegil/file-recover-lib/commit/f8fda280f14035bca619111cf6ecee50d68bec54))
* recover from real macOS and Linux disks, not just synthetic ones ([107295f](https://github.com/trondegil/file-recover-lib/commit/107295f7ea39836faa6c80e340b36313cf42fb83))
* recover what Windows leaves behind on FAT32 and exFAT ([982d71f](https://github.com/trondegil/file-recover-lib/commit/982d71f0693e97f4bd0f8066020761d1e7fcb297))
* reject stale image maps, malformed MCP requests, and bad checkpoints ([7b22194](https://github.com/trondegil/file-recover-lib/commit/7b221949ac4048db1adfd21ba17f87b7c40d9912))
* two crashes the fuzzers found in their first minute ([692ad18](https://github.com/trondegil/file-recover-lib/commit/692ad18bfc6bc79006b2de52bbf34fc953db87ab))


### Performance Improvements

* skip runs of zero bytes in the carver's scan loop ([b61e8d4](https://github.com/trondegil/file-recover-lib/commit/b61e8d4883c8830d304a936f3ad93703026d8879))

## [Unreleased]

### Performance

- The `exr`, `qoi`, and `rpm` length finders now reuse the carver's shared
  scratch buffer instead of allocating a fresh 64–128 KiB scan buffer on every
  match, extending the 0.4.0 buffer-reuse work to the remaining finders that
  still allocated per call.

## [0.4.0] - 2026-07-11

The tool becomes extensible and easier to reach for: an AI agent can inject its
own carvers over MCP, everything installs in one command (and ships as a Claude
Code plugin), the signature scanner is roughly twice as fast, and the project is
renamed to **unearth** to reflect that it is now a full recovery & disk-forensics
toolkit rather than a file carver alone.

### Performance

- **~2× faster signature scanning.** The carver now gates every scan position
  through a 65536-bit two-byte-prefix set before walking a candidate bucket, so
  a position whose first two bytes don't begin any magic is rejected with a
  single bitset lookup instead of comparing against the dozen-plus signatures
  that can share a common leading byte (`f`, `0xFF`, `R`, `0x00`, `M`). On the
  micro-benchmarks this **doubled pure matching throughput (≈82 → ≈175 MiB/s)**
  and sped the end-to-end carve (I/O + hashing included) by **~22%** — recovering
  the slowdown that accrued as the signature table grew past 180 entries. Results
  are identical; a one-byte magic marks all 256 prefixes for its byte so the gate
  never hides a match. A `scan/noise` benchmark now guards this hot loop.
- **Less allocation churn while carving.** The walk-style length finders
  (`jpeg`, `zip`, `rtf`, `mpegts`) reuse the carver's shared scratch buffer
  instead of allocating a fresh scan buffer on every match. Heap profiling
  showed `jpeg_length` alone allocating a 1 MiB buffer per JPEG; the profiled
  workload's total allocation dropped **~29% (114 MB → 81 MB)** and per-JPEG
  allocations fell 32×, with identical output and no throughput change.

### Changed

- **Renamed the project from `filerecovery` to `unearth`.** The generic name
  undersold a tool that is now a full recovery & disk-forensics toolkit, so the
  crate, binary, MCP server, Claude Code plugin, and repository were renamed
  ahead of the first crates.io publish. The command is now `unearth …` (e.g.
  `unearth scan …`); the crates.io description and README were reworked to
  cover the whole toolkit (undelete, carving, filesystem/partition recovery,
  imaging, and the MCP/agent interface) rather than carving alone. Earlier
  changelog entries below use the new name for consistency; none of these
  versions were published under the old one.

### Added

- **Easier installation.** `cargo binstall unearth` now fetches the
  prebuilt binary the release workflow attaches to each GitHub Release (via
  `[package.metadata.binstall]`) instead of compiling, and a POSIX `install.sh`
  (`curl … | sh`) downloads and installs the right binary on Linux/macOS with no
  Rust toolchain. The crates.io description was refreshed to reflect the full
  toolkit (filesystem-aware undelete plus carving, not carving alone), and the
  published crate now excludes the plugin/skill/CI files.
- **Custom carvers can be injected at run time via the MCP `scan` tool.** A new
  `custom_carvers` argument takes an array of carver specs — a magic number
  (hex, at an optional offset, with an optional secondary tag) plus a
  *declarative* length rule — so an AI agent can recover a file type the tool
  doesn't know natively, for that scan only, without a rebuild. Three length
  strategies are supported: `fixed` (a constant size), `size_field` (an
  unsigned 8/16/32/64-bit integer at an offset, little- or big-endian, taken as
  `value * mul + add`), and `footer` (ends a fixed number of bytes after a
  marker sequence). To preserve the crate's core guarantee, a custom carver
  carries no arbitrary code: every strategy computes an **exact** length that is
  bounds-checked exactly like a built-in, so a malformed or over-eager spec can
  only fail to match — it can never over-read the source or emit a wrong length.
  Specs are validated up front (required size cap ≤ 1 TiB, filesystem-safe
  extension, well-formed hex), and a bad spec is reported before the scan job
  starts. Two new length primitives (`Extent::Fixed`, `Extent::SizeField`) back
  the feature and generalise the existing header-size extents.
- **Claude Code plugin & marketplace.** The repository now doubles as a Claude
  Code plugin marketplace (`.claude-plugin/marketplace.json` +
  `.claude-plugin/plugin.json` + `.mcp.json`), so the MCP server and the
  `custom-carver` skill install in two commands
  (`/plugin marketplace add marcelroozekrans/unearth` then
  `/plugin install unearth@unearth-tools`) instead of hand-editing an
  MCP config. The plugin launches the `unearth` binary from `PATH`; it does
  not bundle it.
- **Skill: authoring custom carvers.** A bundled Agent skill
  (`skills/custom-carver/SKILL.md`) walks an agent through building a
  `custom_carvers` spec safely — identify the magic, derive an *exact* size rule,
  validate it reproduces a known sample's byte length, and abandon the carver if
  the format can't be sized reliably — closing the authoring-layer gap the tool
  itself can't police.

## [0.3.0] - 2026-07-09

Recovery reach grows in several directions: every supported filesystem can now
carve only its free space, Mac/Linux copy-on-write and encrypted volumes are
recognised and described, lost partitions can be found and recovered without a
partition table, the carver gains modern archive/compression and image formats,
and `scan` can now reconstruct whole **filesystem images** — JFS, UFS1, BeFS,
HFS+/HFSX, and ReiserFS — sizing each exactly from its superblock rather than
guessing.

### Added

- **ReiserFS filesystem images are carved** — `scan` now recovers whole
  `.reiserfs` images, Hans Reiser's journaling filesystem — the SUSE default and
  a common choice on Linux through the 2000s (removed from the mainline kernel in
  6.13). The **3.6** superblock sits 64 KiB into the volume and the older **3.5**
  superblock 8 KiB in, each carrying a long ASCII magic at offset 0x34
  (`ReIsEr2Fs`/`ReIsEr3Fs` for 3.6, `ReIsErFs` for 3.5), a block count at offset
  0x00, and a block size at offset 0x2C, so the exact image length is
  `block_count × block_size`. A missing magic, non-power-of-two block size, or
  zero block count rejects a coincidental match. Complements the existing
  ReiserFS *detection* used by `info`/`list_volumes`.
- **HFS+ filesystem images are carved** — `scan` now recovers whole `.hfsplus`
  images, the Mac OS Extended filesystem — the macOS default before APFS and
  still used on many external and Time Machine drives. The volume header sits
  1024 bytes into the volume with a big-endian `H+` (HFS+, v4) or `HX`
  (HFSX, v5) signature, then a block size at offset 0x28 and a total block count
  at offset 0x2C, so the exact image length is `totalBlocks × blockSize`. A
  bad signature/version, non-power-of-two block size, or zero block count
  rejects a coincidental match. Complements the existing HFS+ *detection* used
  by `undelete`/`info`.
- **BeFS filesystem images are carved** — `scan` now recovers whole `.befs`
  images, the Be File System from BeOS, still used by Haiku. The superblock sits
  512 bytes into the volume and carries two magics — `BFS1` at offset 0x20 and
  0xDD121031 at offset 0x44 (little- or big-endian) — plus a block size at
  offset 0x28 and a block count at offset 0x30, so the exact image length is
  `num_blocks × block_size`. The two magics plus a power-of-two block size
  reject a coincidental match. Complements the existing BeFS *detection* used by
  `info`.
- **UFS1 filesystem images are carved** — `scan` now recovers whole `.ufs`
  images, the Berkeley Fast File System traditional to the BSDs and Solaris. The
  UFS1 superblock sits 8 KiB into the volume with the `0x00011954` magic at
  offset 0x55C (little- or big-endian), and its early geometry records the total
  size in fragments at offset 0x24 and the fragment size at offset 0x34, so the
  exact image length is `fs_old_size × fs_fsize`. Only UFS1 is sized; UFS2
  (whose size moved to a 64-bit field this layout leaves zero) has a different
  magic and is not matched, so it is never mis-sized.
- **JFS filesystem images are carved** — `scan` now recovers whole `.jfs`
  images, IBM's Journaled File System (from AIX/OS2, ported to Linux). The
  aggregate superblock sits 32 KiB into the volume and opens with the `JFS1`
  magic, then a `u64` aggregate size (in physical blocks) at offset 8 and a
  `u32` physical block size at offset 0x18, so the exact image length is
  `s_size × s_pbsize`. A non-power-of-two block size or zero block count rejects
  a coincidental magic. Complements the existing JFS *detection* used by `info`.
- **cramfs images are carved** — `scan` now recovers `.cramfs` images, the small
  compressed read-only Linux filesystem long used in firmware and embedded/boot
  images. The superblock carries the `0x28CD3D45` magic (little- or big-endian)
  and the 16-byte `Compressed ROMFS` signature at offset 0x10, with the total
  image size as a `u32` at offset 4 in the magic's endianness, which is the
  image length directly. The 16-byte signature rejects a coincidental match.
- **romfs images are carved** — `scan` now recovers `.romfs` images, the tiny
  read-only filesystem long used for Linux initramfs and embedded/boot images.
  The header opens with the 8-byte `-rom1fs-` magic and a big-endian `u32`
  full-image-size field at offset 8, which is the image length directly; a size
  smaller than the header rejects a coincidental match.
- **Linux swap areas are carved** — `scan` now recovers `.swap` areas, a
  formatted swap partition or file, which is a key forensics artifact because it
  holds paged-out process memory. The header records a version at offset 1024
  and a `last_page` index at offset 1028, with the `SWAPSPACE2` magic at
  `page_size − 10`; matching it at offset 4086 fixes the page size at 4 KiB, so
  the area length is `(last_page + 1) × 4096`. The 10-byte magic and a version
  of 1 reject a coincidental match.
- **NTFS filesystem images are carved** — `scan` now recovers whole `.ntfs`
  images, the dominant Windows filesystem. The boot sector opens with an
  `NTFS    ` OEM signature at offset 3 and records `BytesPerSector` at offset 11
  and `TotalSectors` at offset 0x28, so the exact image length is
  `TotalSectors × BytesPerSector` — the same computation the NTFS undelete
  module uses. A non-power-of-two sector size or zero sector count rejects a
  coincidental magic. (`scan` carves the whole volume as one image; `undelete`
  continues to recover individual named files, folder paths, and fragmented
  runs from an NTFS volume.)
- **ReFS filesystem images are carved** — `scan` now recovers whole `.refs`
  images, Microsoft's copy-on-write Resilient File System (Windows Server,
  Storage Spaces, and the Dev Drive feature on Windows 11). The boot record
  carries the `ReFS` signature at offset 3 and the `FSRS` structure identifier
  at offset 0x10, then a sector count at 0x18 and a bytes-per-sector at 0x20, so
  the exact image length is `NumberOfSectors × BytesPerSector`. The two
  signatures plus a power-of-two sector size reject a coincidental match.
  Complements the existing ReFS *detection* used by `info`.
- **APFS container images are carved** — `scan` now recovers whole `.apfs`
  images, the Apple File System that is the default on every Mac, iPhone, and
  iPad since 2017. The container superblock opens the volume with the `NXSB`
  magic at offset 32, a block size at offset 36, and a block count at offset 40,
  so the exact image length is `block_count × block_size`; a non-power-of-two
  block size or zero block count rejects a coincidental magic. Complements the
  existing APFS *detection* used by `info`, which cannot undelete a
  copy-on-write filesystem and points the user at `scan`.
- **exFAT filesystem images are carved** — `scan` now recovers whole `.exfat`
  images, the Microsoft filesystem that is the default on SD/SDXC cards over
  32 GB, most cameras, and many phones and USB drives. The boot sector opens
  with `EXFAT   ` at offset 3 and records `VolumeLength` (in sectors) and
  `BytesPerSectorShift`, so the exact image length is
  `VolumeLength << BytesPerSectorShift`; sane sector/cluster shifts reject a
  coincidental magic. (`scan` carves the whole volume as one image; `undelete`
  continues to recover individual named files from an exFAT volume.)
- **XFS filesystem images are carved** — `scan` now recovers whole `.xfs`
  images, the high-performance journaling filesystem that is the default on
  RHEL, CentOS, and Rocky Linux. The superblock opens the volume with the
  big-endian `XFSB` magic, a block size at offset 4, and a total data-block
  count at offset 8, so the exact image length is `sb_dblocks × sb_blocksize`.
  A non-power-of-two block size or zero block count rejects a coincidental
  magic. Complements the existing XFS *detection* used by `info`.
- **btrfs filesystem images are carved** — `scan` now recovers whole `.btrfs`
  images, the copy-on-write Linux filesystem that is the default on Fedora
  Workstation and openSUSE and is used by Synology NAS units. The superblock
  64 KiB into the volume (magic `_BHRfS_M`) records `total_bytes`, which is the
  image length for a single-device filesystem; power-of-two sector/node sizes
  reject a coincidental magic and multi-device filesystems are skipped rather
  than over-sized. Complements the existing btrfs *detection* used by `info`,
  which cannot undelete a copy-on-write filesystem and points the user at `scan`.
- **F2FS filesystem images are carved** — `scan` now recovers whole `.f2fs`
  images, the Flash-Friendly File System that is the default internal-storage
  filesystem on most modern Android phones. The superblock at the fixed
  1024-byte offset (magic `0xF2F52010`) records the block-size shift and total
  block count, so the exact image length is `block_count << log_blocksize`.
  Complements the existing F2FS *detection* used by `info`, which cannot undelete
  a log-structured filesystem and points the user at `scan`.
- **GRIB2 weather data is carved** — `scan` now recovers `.grib2` files, the WMO
  gridded-binary format that is the backbone of modern meteorology and climate
  data (NOAA, ECMWF, NASA). A file is one or more self-delimiting messages, each
  opening with `GRIB`, an edition byte, and a 64-bit total length, and closing
  with a `7777` end marker. Messages are walked by their length — each validated
  by confirming its trailing `7777` — for an exact size across any number of
  concatenated messages.
- **BLP2 textures are carved** — `scan` now recovers `.blp` files, the Blizzard
  texture format used by World of Warcraft. After the `BLP2` magic and a header
  of encoding flags and dimensions comes a directory of 16 mipmap offsets and
  16 mipmap lengths; the exact file end is the furthest `offset + length` across
  that directory (never less than the 148-byte header). The `BLP2` magic and
  sane dimensions reject a coincidental match.
- **PVR textures are carved** — `scan` now recovers `.pvr` files, the PowerVR
  texture container from Imagination's PVRTexTool, widely used in iOS and
  Android game development. The 52-byte header records the pixel format,
  dimensions, mip count, and metadata size, so the file is the header plus the
  metadata plus the block-compressed mip chain. Only plain 2D textures in the
  4×4-block codecs whose block size is unambiguous (BC1–BC7, ETC1/ETC2, EAC) are
  sized; PVRTC (with its minimum-size rule), ASTC, uncompressed formats, and
  array/cube/volume textures are skipped rather than mis-sized.
- **YUV4MPEG2 video is carved** — `scan` now recovers `.y4m` files, the
  uncompressed raw-video interchange format piped between modern encoders and
  tools (FFmpeg, the AV1/VP9/x264/x265 reference encoders). A one-line header
  fixes the per-frame byte size from the width, height, and colourspace; each
  `FRAME…\n` line plus that many bytes is walked to the end for an exact length.
  Only the 8-bit `mono`/`420`/`422`/`444` colourspaces are sized — higher bit
  depths and alpha variants are skipped rather than mis-sized.
- **farbfeld images are carved** — `scan` now recovers `.ff` files, the
  deliberately minimal lossless image format from the suckless project. The
  16-byte header is the `farbfeld` magic plus big-endian `u32` width and height,
  and every pixel is four 16-bit channels (8 bytes), so the exact file length is
  `16 + width × height × 8`.
- **RPM packages are carved** — `scan` now recovers `.rpm` files, the package
  format of Fedora, RHEL, openSUSE, and related distributions. After a 96-byte
  lead comes the signature header (an 8-byte-padded `header` structure) whose
  `RPMSIGTAG_SIZE`/`LONGSIZE` tag records the combined size of the main header
  and payload, so the exact file length is `96 + padded signature header +
  that size`. The `0xEDABEEDB` lead magic and `0x8EADE8` header magic reject a
  coincidental match; packages whose signature omits the size tag are skipped
  rather than mis-sized.
- **QOI images are carved** — `scan` now recovers `.qoi` files, the "Quite OK
  Image" format (2021), a fast lossless codec adopted across game engines and
  image tooling. Each chunk's byte size is fixed by its tag alone (independent
  of pixel values), so the chunk stream is decoded — counting the pixels each
  chunk covers — until exactly `width × height` pixels are produced, locating
  the end without searching for the 8-byte marker (which can appear in pixel
  data); the trailing marker is then verified. A sliding window keeps large
  images from needing a full-file buffer.
- **Source-engine BSP maps are carved** — `scan` now recovers `.bsp` files, the
  compiled level format for Valve's Source games (CS:GO, Team Fortress 2,
  Portal 2, Garry's Mod) and their large modding communities. After the `VBSP`
  magic and a `u32` version comes a directory of 64 lumps, each with a file
  offset and length; the exact file end is the furthest `offset + length` across
  the directory (never less than the 1036-byte header). The `VBSP` magic and a
  sane version reject a coincidental match.
- **MCAP logs are carved** — `scan` now recovers `.mcap` files, the modern
  container for robotics and autonomous-vehicle recordings (ROS 2, Foxglove).
  After the 8-byte magic the file is a stream of records, each a 1-byte opcode,
  a `u64` length, and its payload; walking the records by their length to the
  footer record (opcode `0x02`) and adding the trailing magic gives the exact
  length. Detection never depends on the trailing magic, which is byte-for-byte
  identical to the leading one.
- **OpenEXR images are carved** — `scan` now recovers `.exr` files, the
  ILM/Academy high-dynamic-range format that is the standard for film and VFX
  compositing. After the header's attribute list comes a chunk offset table
  whose first entry equals `header_end + count × 8` — revealing the table's
  length without decoding the compression — and whose last entry locates the
  final chunk, whose own `dataSize` field gives the exact file end. Only
  single-part scanline images are sized; tiled, deep, and multi-part files
  (flagged in the version word) are skipped rather than mis-sized.
- **KTX (v1) textures are carved** — `scan` now recovers `.ktx` files, the
  original Khronos GPU-texture container (WebGL/three.js, Android GPU textures,
  older glTF). After the 12-byte «KTX 11» identifier and a fixed 64-byte header
  comes the key/value data and then one block per mip level, each introduced by
  its own explicit `imageSize` field and padded to a 4-byte boundary — so the
  exact length is found by walking the levels, with no pixel-format table
  required. Only ordinary non-array, single-face textures are sized; array and
  cubemap layouts, whose per-face padding is ambiguous, are skipped rather than
  mis-sized. Multi-byte fields honour the header's endianness flag.
- **EROFS filesystem images are carved** — `scan` now recovers EROFS images, the
  Enhanced Read-Only File System used for Android 10+ `system`/`vendor`
  partitions and increasingly for container images. The superblock at the fixed
  1024-byte offset (magic `0xE0F5E1E2`) records the block-size shift and the
  total block count, so the exact image length is `blocks << blkszbits` (a zero
  shift means the historical 4 KiB default). The magic at the fixed superblock
  offset plus a sane block-size shift make a false match negligible.
- **glTF binary 3D models are carved** — `scan` now recovers `.glb` files, the
  binary container for glTF 2.0, the standard runtime format for 3D assets in
  games, AR/VR, and `<model-viewer>`. The 12-byte header carries a `u32` total
  length spanning the whole file; that length is confirmed exact by walking the
  chunk table (each an 8-byte `length`/`type` preamble plus padded data) and
  checking the chunks begin with a `JSON` chunk and sum to precisely the
  declared length — so a coincidental `glTF` magic is rejected rather than
  mis-sized.
- **ASTC textures are carved** — `scan` now recovers `.astc` files, the
  Adaptive Scalable Texture Compression format used by modern mobile GPUs and
  Vulkan pipelines. The 16-byte header records the block footprint and the
  texel dimensions, and every compressed block is exactly 16 bytes, so the
  length is `16 + ceil(x/bx) * ceil(y/by) * ceil(z/bz) * 16` — an exact,
  content-independent size.
- **DDS textures are carved** — `scan` now recovers `.dds` files, the DirectDraw
  Surface GPU-texture format used throughout games and 3D tools. The exact
  length is the 128-byte header plus the mip-chain size, computed from the block
  size of the compressed format (DXT1/3/5, BC4/5) or the bit depth of an
  uncompressed one. DX10-extended, cubemap, and volume textures are skipped
  rather than mis-sized.
- **HDF5 data files are carved** — `scan` now recovers `.h5`/HDF5 files, the
  dominant scientific and machine-learning data container (Keras models,
  scientific datasets, NetCDF-4). The exact length is the end-of-file address in
  the superblock, read for superblock versions 0–3 with 8-byte offsets; other
  offset sizes or versions are skipped rather than mis-sized.
- **Apache Avro containers are carved** — `scan` now recovers `.avro` files, the
  row-oriented object-container format used throughout modern data engineering
  (Kafka, Hadoop, data lakes). The exact length comes from walking the data
  blocks and verifying the file's 16-byte sync marker after each, so recovery
  ends precisely at the last valid block.
- **USD crate scenes are carved** — `scan` now recovers `.usdc` files, Pixar's
  binary Universal Scene Description format, the standard for 3D scene
  interchange in film/VFX and NVIDIA Omniverse. The exact length is the largest
  section start-plus-size in the file's table of contents, behind the `PXR-USDC`
  magic.
- **NIfTI neuroimaging volumes are carved** — `scan` now recovers `.nii` files,
  the standard MRI/fMRI volumetric medical-imaging format used throughout
  research and clinical pipelines. The exact length is the data offset plus
  `product(dimensions) × bytes-per-voxel` from the header. Big-endian volumes
  and unusual headers are skipped rather than mis-sized.
- **RF64/BW64 audio is carved** — `scan` now recovers `.rf64` files, the EBU
  extension of WAV for recordings larger than 4 GiB (broadcast and field
  recording), where the classic 32-bit RIFF size overflows. The exact length is
  the 64-bit RIFF size in the `ds64` chunk plus 8, behind the `RF64`/`WAVE`/
  `ds64` anchors.
- **E57 point clouds are carved** — `scan` now recovers `.e57` files, the ASTM
  E2807 format for 3D laser-scan and imaging data used in surveying, BIM, and
  robotics. The exact length is the physical-file-length field in the header,
  behind the 8-byte `ASTM-E57` magic.
- **Godot asset packs are carved** — `scan` now recovers `.pck` files, the
  resource bundle for Godot Engine games, covering pack format v1 (Godot 3) and
  v2 (Godot 4). The exact length comes from walking the directory to the largest
  `file_base + offset + size`, behind the `GDPC` magic.
- **LAS point clouds are carved** — `scan` now recovers `.las` files, the LiDAR
  point-cloud format used in surveying, GIS, and autonomous-vehicle datasets.
  The exact length is the point-data offset plus `point_count × record_length`
  from the public header block. Compressed (LAZ) files, waveform point formats,
  and LAS 1.4 files with extended VLRs are skipped rather than mis-sized.
- **Valve VPK archives are carved** — `scan` now recovers `.vpk` files, the pak
  format used by Source and Source 2 games (CS2, Dota 2, Half-Life: Alyx). The
  exact length is the 28-byte version-2 header plus the sum of its section sizes
  (tree, file data, archive MD5, other MD5, signature). Version-1 VPKs, which
  lack the section-size fields, are skipped rather than mis-sized.
- **Fuji RAF raw images are carved** — `scan` now recovers `.raf` files, the raw
  photo format from Fujifilm's mirrorless cameras. The exact length is the
  largest section offset-plus-length across the embedded JPEG, CFA header, and
  CFA raw data recorded in the 16-byte-magic header.
- **Unity asset bundles are carved** — `scan` now recovers `.unity3d` files, the
  `UnityFS` container that ships the assets of virtually every Unity game. The
  exact length is the total-size field in the header, read after the two
  null-terminated Unity version strings.
- **systemd journals are carved** — `scan` now recovers `.journal` files, the
  binary log format under `/var/log/journal` on every modern Linux system and a
  common forensics artifact. The exact length is the header size plus the arena
  size recorded in the header, behind the 8-byte `LPKSHHRH` magic.
- **NumPy arrays are carved** — `scan` now recovers `.npy` files, the standard
  `numpy.save` array format ubiquitous in machine-learning and scientific
  Python. The exact length is the header plus `product(shape) × itemsize`,
  parsed from the header's `descr` (dtype) and `shape`. Object, structured,
  unicode, and datetime dtypes — whose element size can't be derived exactly —
  are skipped rather than recovered at the wrong length.
- **Android vendor_boot images are carved** — `scan` now recovers
  `vendor_boot.img` files (the GKI-era partition on Android 11+ devices holding
  the vendor ramdisk and DTB), completing the Android boot-partition set
  alongside `boot.img` and DTBO. The exact length is the sum of the page-rounded
  header, vendor ramdisk, DTB, and (v4) vendor-ramdisk-table and bootconfig
  sections. Header versions other than 3–4 are skipped rather than mis-sized,
  and the `VNDRBOOT` magic makes false positives negligible.
- **QOA audio is carved** — `scan` now recovers `.qoa` files, the modern
  "Quite OK Audio" lossy codec. The exact length is walked over the frame chain
  for the header's sample count, using each frame's own size field, behind the
  `qoaf` magic.
- **KTX2 textures are carved** — `scan` now recovers `.ktx2` files, the current
  Khronos GPU-texture container (glTF `KHR_texture_basisu`, WebGPU, game
  engines). The exact length is the largest section offset-plus-length across
  the level index and the data-format / key-value / supercompression
  descriptors, behind the 12-byte «KTX 20» magic.
- **Android DTBO images are carved** — `scan` now recovers `.dtbo`/`dtb.img`
  device-tree-overlay partition images (present on every modern Android device).
  The exact length is the `total_size` field at offset 4 of the `dt_table_header`
  (magic `0xD7B7AB1E`).
- **Android boot images are carved** — `scan` now recovers `boot.img` files
  (the kernel/ramdisk container flashed to Android devices), a common
  phone-forensics target. The exact length is the sum of the page-rounded
  sections: header versions 0–2 use the header's page size with (v1) a
  recovery-DTBO and (v2) a DTB section, while versions 3–4 use a fixed 4096-byte
  page with (v4) a boot signature. The `ANDROID!` magic makes false positives
  negligible, and any header version beyond those is skipped rather than
  mis-sized.
- **GGUF models are carved** — `scan` now recovers `.gguf` files, the dominant
  on-disk format for local large-language-model weights (llama.cpp / ggml). The
  exact length is computed by walking the metadata and tensor-info tables and
  taking the largest tensor offset plus its byte size (from the fixed ggml block
  constants), aligned to the tensor-data boundary. A file that uses a tensor
  type whose layout is not known is skipped rather than recovered at the wrong
  length.
- **ZIM archives are carved** — `scan` now recovers `.zim` files, the
  openZIM/Kiwix container for offline web content (offline Wikipedia and other
  educational corpora). The exact length is the checksum position in the header
  plus the trailing 16-byte MD5, with the `ZIM\x04` magic and a checksum
  position past the header rejecting a coincidental match.
- **IVF video is carved** — `scan` now recovers `.ivf` files, the container
  that wraps raw AV1, VP9, and VP8 bitstreams from modern web-video encoders and
  codec test suites. The exact length is walked frame by frame for the frame
  count recorded in the header, with the `DKIF` magic, version, and header
  length rejecting a coincidental match.
- **Quake II models are carved** — `scan` now recovers `.md2` animated meshes
  from Quake II and the many games and mods built on it. The exact length is the
  `ofs_end` field in the header, with the `IDP2` magic and version 8 rejecting a
  coincidental match.
- **Quake PAK archives are carved** — `scan` now recovers `.pak` asset bundles
  from id Software's Quake engine and games built on it. The exact length is the
  directory offset plus the directory length from the header, with the 64-byte
  entry alignment and a header-relative offset rejecting a coincidental magic.
- **SoundFont 2 files are carved** — `scan` now recovers `.sf2` sampled-
  instrument banks, a RIFF container with the `sfbk` form type, using the RIFF
  size field for the exact length.
- **TRX firmware images are carved** — `scan` now recovers `.trx` router
  firmware containers (Broadcom/OpenWrt and many consumer routers). The exact
  length is the `len` field at offset 4 of the header (which counts the header),
  behind the `HDR0` magic.
- **Device tree blobs are carved** — `scan` now recovers `.dtb` flattened
  device trees (FDT), the hardware-description blobs used throughout embedded
  Linux and Android boot. The exact length is the `totalsize` field at offset 4
  of the header, behind the distinctive `0xD00DFEED` magic.
- **U-Boot uImages are carved** — `scan` now recovers `.uimage` boot images
  (the `mkimage` wrapper ubiquitous in router/IoT firmware). The exact length
  is the 64-byte header plus the image-data size field at offset 0x0C, with the
  distinctive `0x27051956` magic and a non-zero size rejecting a coincidental
  match.
- **PCF bitmap fonts are carved** — `scan` now recovers `.pcf` fonts (the X11
  Portable Compiled Font behind classic Linux/Unix console and terminal
  bitmap fonts). The exact length is the largest data offset-plus-size across
  the font's table of contents, with a bounded table count and offset checks to
  reject a coincidental magic.
- **DSDIFF (DSD) audio is carved** — `scan` now recovers `.dff` files, the
  Philips DSD Interchange File Format for 1-bit audio. The exact length is the
  `FRM8` form's big-endian 64-bit data size plus its 12-byte header, with the
  `DSD ` form type checked to reject a coincidental magic.
- **DSF (DSD) audio is carved** — `scan` now recovers `.dsf` files, the Sony
  DSD Stream File format used for high-resolution 1-bit audio. The exact length
  is the total-file-size field in the opening DSD chunk, with the chunk size
  (28) and the following `fmt ` chunk checked to reject a coincidental magic.
- **Sun raster images are carved** — `scan` now recovers `.ras`/`.sun` images,
  the classic SunOS raster format. The exact length is the 32-byte header plus
  the colormap length and image-data length recorded in the header, with the
  depth, image type, colormap type, and geometry checked to reject a
  coincidental magic.
- **AppleSingle/AppleDouble containers are carved** — `scan` now recovers the
  RFC 1740 containers macOS uses for resource forks and metadata on non-Apple
  filesystems (the `._name` sidecar files inside ZIP/tar archives and on
  FAT/SMB volumes). The exact length is the largest offset-plus-length across
  the entries in the header's entry table, with the magic, version, and a
  bounded entry count checked to reject a coincidental match.
- **JNG images are carved** — `scan` now recovers `.jng` images (JPEG Network
  Graphics), a PNG-family wrapper around JPEG data. Like PNG, a standalone
  datastream ends with an empty `IEND` chunk, so the same footer marker locates
  the file end.
- **MNG animations are carved** — `scan` now recovers `.mng` images (Multiple-
  image Network Graphics), a PNG-family animation that shares PNG's chunk
  structure. The file ends at the empty `MEND` chunk, found by its constant
  type-and-CRC marker.
- **Monkey's Audio is carved** — `scan` now recovers `.ape` lossless-audio
  files (version 3.98 and later). The exact length is the sum of the segment
  byte counts in the file's descriptor (descriptor, header, seek table, WAV
  header, APE frame data, and terminating data). The version and descriptor
  size are checked to reject a coincidental magic.
- **WavPack audio is carved** — `scan` now recovers `.wv` lossless-audio files.
  The exact length is found by walking the `wvpk` block chain to the last whole
  block, with the first block's format version checked to reject a coincidental
  magic.
- **Cineon film frames are carved** — `scan` now recovers `.cin` images, the
  Kodak film-scan format DPX descends from. The exact length comes from the
  total-file-size field at offset 0x14 of the big-endian file-information
  header.
- **DPX film frames are carved** — `scan` now recovers `.dpx` images (SMPTE
  ST 268, the standard frame format in film scanning and VFX). Both byte
  orders (`SDPX`/`XPDS`) are recognised, and the exact length comes from the
  total-file-size field at offset 0x10 of the generic file header.
- **Autodesk FLIC animations are carved** — `scan` now recovers `.fli`/`.flc`
  palette animations (Autodesk Animator / Animator Pro, old games and demos).
  The exact length is the total-size field at the start of the 128-byte header.
  The format magic (`0xAF11`/`0xAF12`), colour depth, frame count, and frame
  dimensions are range-checked to reject a coincidental two-byte magic.
- **ISO 9660 disc images are carved** — `scan` now recovers `.iso` images
  (CD/DVD filesystems, distro installers, optical-media backups). The exact
  length comes from the primary volume descriptor at sector 16: the volume
  space size multiplied by the logical block size. The descriptor type/version
  and the both-endian halves of each field must agree, rejecting a coincidental
  `CD001` match. This complements the existing ISO 9660 filesystem reader.
- **Android sparse images are carved** — `scan` now recovers `.simg` sparse
  images (the format `fastboot` and Android factory images use), with the exact
  length summed from each chunk header's on-disk size. The header sizes and chunk
  count are range-checked to reject a coincidental magic.
- **romfs volumes are recognised** — the minimal ROM File System (small initrds
  and embedded systems) is now detected from its `-rom1fs-` magic, so `info` /
  `list_volumes` report its size and volume name instead of leaving it
  unrecognised. Read-only, so use `scan` (carving) for its contents.
- **cramfs volumes are recognised** — the Compressed ROM File System (initrds,
  embedded systems, and router/appliance firmware) is now detected from its
  `0x28CD3D45` magic and `Compressed ROMFS` signature, so `info` / `list_volumes`
  report its size and label instead of leaving it unrecognised. Read-only, so use
  `scan` (carving) for its contents.
- **EROFS volumes are recognised** — the Enhanced Read-Only File System (used for
  Android system/vendor images and ChromeOS) is now detected from its
  `0xE0F5E1E2` superblock, so `info` / `list_volumes` report its size, label,
  UUID, and build time instead of leaving it unrecognised. Being read-only it has
  no deleted files to undelete — use `scan` (carving) for its contents.
- **UFS / UFS2 volumes are recognised** — the BSD Fast File System (also Solaris
  and historical Unix) is now detected from its superblock magic (8 KiB in for
  UFS1, 64 KiB for UFS2), in either byte order, so `info` / `list_volumes` report
  its version, size, and block size instead of leaving it unrecognised. Its
  cylinder-group layout is unlike the filesystems recovered from metadata, so use
  `scan` (carving).
- **BSD disklabels are read** — `info` / `list_volumes` now recognise a BSD
  disklabel (FreeBSD/OpenBSD/NetBSD on a whole-disk "dangerously dedicated"
  layout) as a fourth partition scheme alongside GPT, MBR, and APM, listing each
  partition's filesystem type, letter, and byte range. Both byte orders are
  handled, and the dual `d_magic` is required to avoid false matches.
- **Volume timestamps reported for NILFS2 and JFS** — `info` now shows NILFS2's
  creation (`s_ctime`) and last-write (`s_wtime`) times and JFS's last-updated
  time (`s_time`), the same way the ext / NTFS / HFS+ / ISO 9660 backends already
  report volume timestamps.
- **Clean/dirty state reported for ReiserFS and NILFS2** — `info` now flags
  whether these volumes were cleanly unmounted (a dirty volume is a sign the
  filesystem may need a check and that recovery may be less reliable), the same
  as for ext / exFAT / NTFS.
- **Free space reported for ReiserFS, NILFS2, and BeFS** — `info` /
  `list_volumes` now show how much of these volumes is unallocated, read from the
  superblock's free/used-block counts (the same as XFS and Btrfs already do).
- **Allocation unit reported for more filesystems** — `info` / `list_volumes`
  now show the allocation-unit (block/cluster) size for ReiserFS, JFS, NILFS2,
  GFS2, OCFS2, Minix, bcachefs, and BeFS, the same as for the filesystems that
  already exposed it. It documents the volume's geometry and bounds per-file
  slack when carving within one of these volumes.
- **PlayStation executables are carved** — `scan` now recovers PS1 `PS-X EXE`
  programs, with the exact length taken from the 2 KiB header plus the
  text-section size at offset 0x1C. A non-zero, 2 KiB-aligned text size guards
  the match alongside the 8-byte magic.
- **AMR audio is carved** — `scan` now recovers `.amr` (AMR narrowband) audio —
  the codec mobile phones use for voice recordings and voicemail — by walking the
  fixed-size speech frames from the `#!AMR\n` header to the end of the stream.
- **Creative Voice (`.voc`) audio is carved** — `scan` now recovers Sound
  Blaster / DOS-era `.voc` audio files, walking the data-block chain from the
  header to the terminator block to find the exact end. The 20-byte ASCII magic
  makes a false match effectively impossible.
- **Sega Mega Drive / Genesis ROMs are carved** — `scan` now recovers `.md` ROM
  images, anchored on the `SEGA` cartridge-header signature at 0x100 with the
  exact length taken from the ROM end address in the header. The start address
  and a plausible end address are checked to reject a coincidental match. (This
  is the plain, non-interleaved ROM layout.)
- **Sun/NeXT `.au` audio is carved** — `scan` now recovers `.au` / `.snd` audio
  files (the default sound format in Java and classic Unix), with the exact length
  taken from the header's data offset and data size. Streamed files with an
  unknown size are skipped, and the data offset and encoding code are
  range-checked to reject a coincidental `.snd` match.
- **Doom WAD archives are carved** — `scan` now recovers `.wad` files (`IWAD` /
  `PWAD`), with the exact length computed from the header's lump count and
  directory offset (the Doom engine writes the lump directory last). The two
  fields are range-checked to reject a coincidental magic.
- **Game Boy / Game Boy Color ROMs are carved** — `scan` now recovers `.gb` ROM
  images, anchored on the 48-byte Nintendo logo (an exact, boot-ROM-verified
  magic) with the exact length read from the cartridge header's size code and the
  header checksum verified to reject false matches.
- **BeFS volumes are recognised** — the Be File System (the native filesystem of
  BeOS and of Haiku, its modern successor) is now detected from its superblock's
  dual magics, in either byte order, so `info` / `list_volumes` report its volume
  name and size instead of leaving it unrecognised. Its B+tree metadata is
  specialised, so it is not recovered from metadata — use `scan` (carving).
- **bcachefs volumes are recognised** — the modern copy-on-write Linux filesystem
  (merged into the mainline kernel in 6.7) is now detected from its superblock's
  16-byte magic, so `info` / `list_volumes` report its label and UUID instead of
  leaving it unrecognised. Like the other copy-on-write filesystems it leaves no
  stale metadata to scavenge, so it is not recovered from metadata — use `scan`
  (carving).
- **Minix volumes are recognised** — the filesystem the earliest Linux ran on
  (still found on boot floppies and small/embedded media) is now detected from
  its superblock, so `info` / `list_volumes` report its on-disk version (v1/v2/v3)
  and size instead of leaving it unrecognised. All three versions are handled.
  Minix has no on-disk label or UUID, and the format is long superseded, so it is
  not recovered from metadata — use `scan` (carving).
- **OCFS2 volumes are recognised** — the Oracle Cluster File System 2, a
  shared-disk Linux cluster filesystem, is now detected from its `OCFSV2`
  superblock inode (probed across the supported block sizes), so `info` /
  `list_volumes` report its size, label, and UUID instead of leaving it
  unrecognised. Its metadata is cluster-managed, so it is not recovered from
  metadata — use `scan` (carving).
- **GFS2 / GFS volumes are recognised** — Red Hat's Global File System 2 (and the
  original GFS), a shared-disk cluster filesystem, is now detected from its
  superblock's big-endian `0x01161970` magic, so `info` / `list_volumes` report
  its lock table and UUID instead of leaving it unrecognised. Its metadata is
  cluster-coordinated, so it is not recovered from metadata — use `scan`
  (carving).
- **NILFS2 volumes are recognised** — the log-structured Linux filesystem with
  continuous snapshotting is now detected from its `0x3434` superblock, so
  `info` / `list_volumes` report its size, label, and UUID instead of leaving it
  unrecognised. Like the other log-structured/copy-on-write filesystems, it leaves
  no stale metadata to scavenge, so it is not recovered from metadata — use `scan`
  (carving).
- **JFS volumes are recognised** — IBM's Journaled File System (ported to Linux
  from AIX/OS2) is now detected from its `JFS1` aggregate superblock, so
  `info` / `list_volumes` report its size, label, and UUID instead of leaving it
  unrecognised. Its B+tree layout is unlike the ext family, so it is not recovered
  from metadata — use `scan` (carving).
- **ReiserFS volumes are recognised** — the once-popular Linux journaling
  filesystem (the SUSE default through the 2000s, now removed from the mainline
  kernel) is now detected from its `ReIsEr2Fs` / `ReIsErFs` superblock, so
  `info` / `list_volumes` report its size, label, and UUID instead of leaving it
  unrecognised. Both on-disk layouts are handled — 3.6 (64 KiB in, with UUID and
  label) and the older 3.5 (8 KiB in). Its tree layout is long obsolete, so it is
  not recovered from metadata — use `scan` (carving).
- **Old HFS (Mac OS Standard) volumes are recognised** — the original HFS
  filesystem (1985–1998, found on old Mac floppies, disks, and CDs) is now
  detected from its `BD` Master Directory Block, so `info` / `list_volumes`
  report its size and volume name instead of leaving it unrecognised. Its catalog
  is a long-obsolete on-disk format, so it is not recovered from metadata — use
  `scan` (carving). A `BD` block that wraps an embedded HFS+ volume is still
  followed to the HFS+ volume, so only a pure old-HFS volume is reported as `HFS`.
  This completes the Mac filesystem family (HFS / HFS+ / HFSX, plus the HFS
  wrapper and Apple Partition Map).
- **QuickTime / M4A / M4V get their own extensions when carved** — ISO base-media
  files are now carved to a brand-specific extension instead of always `.mp4`:
  the `qt  ` major brand (iPhone/Mac video) → `.mov`, `M4A ` → `.m4a`, and
  `M4V ` → `.m4v`. `identify` and `triage` recognise them by content too. (Other
  brands still carve as `.mp4`.)
- **HFS-wrapped HFS+ volumes are detected** — an HFS+ volume embedded inside an
  old HFS `BD` wrapper (the layout on old Mac media and hybrid CDs) is now
  followed to the embedded volume, so `info` / `undelete` / `scan` work on it
  instead of seeing only the wrapper. Both 512-byte and larger allocation blocks
  are handled.
- **More GPT partition types are named** — `info` / `list_volumes` now give
  friendly names to many more GPT type GUIDs (Linux root for x86-64/ARM64,
  `/srv`, extended boot, LUKS/dm-crypt, reserved; Windows LDM data/metadata;
  ChromeOS kernel/root; Apple UFS/RAID; FreeBSD data/swap/UFS/boot) instead of
  showing the raw GUID.
- **Apple Partition Map (APM) is supported** — disks partitioned with the Apple
  Partition Map (PowerPC-era Macs, older Mac disks, hybrid CDs) are now
  recognised: `info` / `list_volumes` report the `apm` scheme and each entry's
  type (e.g. `Apple_HFS`), name, and byte range, and `undelete` / `scan` /
  `recover` detect and recover the volumes inside APM partitions. Both 512-byte
  and 2048-byte block maps are handled. This is the third partition scheme
  alongside GPT and MBR.
- **Extracted ISO 9660 files keep their recording date** — a file extracted from
  an ISO 9660 disc now has its directory-record recording date/time applied as
  the output file's modification time, matching how the undelete backends already
  preserve a deleted file's timestamps. The 7-byte binary date in each directory
  record is parsed (new `times::from_iso9660_dir`) and applied via the shared
  `times::apply`.
- **LUKS UUID and LUKS2 label are reported** — `info` / `list_volumes` now report
  a LUKS container's UUID (the value `cryptsetup luksUUID` / `blkid` show), read
  from offset 0xA8 of the LUKS1/LUKS2 header, plus the LUKS2 label when set — so
  an encrypted volume can be correlated with a system's configuration even though
  its contents can't be read without the key. Surfaced on the existing `uuid:` /
  `label:` lines and `uuid` / `label` fields.
- **Binary EPS (`.eps`) carving** — Encapsulated PostScript with a DOS preview
  header (`C5 D0 D3 C6`) is carved from the section table in its 30-byte header:
  the file ends at the furthest `offset + length` of the PostScript section and
  the optional WMF/TIFF previews. The plain-text EPS form (no binary header)
  carries no length and is not carved. `identify` and `triage` recognise binary
  `.eps` by content too.
- **Microsoft Program Database (`.pdb`) carving** — the debug-symbol file every
  MSVC build produces is carved from its MSF 7.0 superblock, whose block size
  (offset 0x20) and block count (offset 0x28) give the exact size
  (`block_size × num_blocks`). The 32-byte magic and a power-of-two block-size
  check reject a coincidental match. `identify` and `triage` recognise `.pdb` by
  content too.
- **Partition attribute flags are reported** — `info` / `list_volumes` now report
  each partition's notable flags: for GPT the attribute bits (`required`,
  `legacy-bios-bootable`, `read-only`, `hidden`, `no-automount`, `no-block-io`)
  and for MBR `active` when the boot flag is set — helping spot, for instance, a
  hidden read-only recovery partition. The text view adds a `flags:` line under
  the entry and `--json` / the MCP `list_volumes` tool a per-partition
  `attributes` array (empty when none apply).
- **MPEG program stream (`.mpg`) carving** — the container used by DVDs, VCDs,
  and older camcorders/recorders is carved by walking its pack / system-header /
  PES-packet chain (each introduced by a `00 00 01` start code) to the
  program-end code (`00 00 01 B9`), giving an exact end — or to the last whole
  packet when the stream is truncated. Pack headers are sized from the
  MPEG-1/MPEG-2 layout (with pack stuffing); a run of consecutive valid packets
  is required so the start code cannot trigger a false carve. `identify` and
  `triage` recognise `.mpg` by content too.
- **Free space is reported for XFS and Btrfs** — `info` / `list_volumes` now show
  free space for XFS (from `sb_fdblocks`) and Btrfs (`total_bytes` −
  `bytes_used`), read straight from the superblock, in addition to the
  allocation-map-based free space already reported for FAT/exFAT/ext/NTFS/HFS+.
  This is a reported `free_bytes` count only — free-space-only carving
  (`--unallocated`) still needs an allocation map, which those backends don't
  expose.
- **Linux MD/RAID members are recognised** — a software-RAID member device is
  detected from its version-1 `mdadm` superblock (1.1 at the device start, 1.2 at
  4 KiB in) and reported by `info` / `list_volumes` with the array's RAID level
  (e.g. `Linux RAID5`), UUID, name, and the member's data size, instead of
  showing as an unrecognised volume. The array is not assembled — assemble it
  with `mdadm` first, then recover from the assembled device. The 1.0 layout
  (superblock near the end of the device) is not detected.
- **Inode (file) usage is reported** — `info` / `list_volumes` now show roughly
  how many files and directories a volume holds, for **ext**
  (`s_inodes_count` / `s_free_inodes_count`) and **XFS** (`sb_icount` /
  `sb_ifree`), so you can gauge the scale of data on a recovered volume. The text
  view adds an `inodes: <used> used / <total>` line and `--json` / the MCP
  `list_volumes` tool add `inodes_used` / `inodes_total` fields (`null` for
  filesystems without fixed inode accounting).
- **The ext last-mounted path is reported** — `info` / `list_volumes` now show
  the directory an ext volume was last mounted on (`s_last_mounted`, e.g. `/` or
  `/home` — the `Last mounted on` value `dumpe2fs` reports), which helps identify
  which volume a recovered image came from. The text view adds a `last mounted:`
  line and `--json` / the MCP `list_volumes` tool a `last_mounted` field (`null`
  when unset).
- **MPEG transport stream (`.ts`) carving** — the container used by DVB/ATSC
  broadcast captures, HDHomeRun/DVR recordings, and many camcorders is carved by
  walking its fixed 188-byte packets (each starting with the `0x47` sync byte) to
  the end of the stream, giving an exact end at the last whole packet. The sync
  byte is required at two packet boundaries plus a longer consecutive run, so the
  single-byte sync cannot trigger a false carve. The 192-byte (M2TS) and 204-byte
  (FEC) variants are not carved. `identify` and `triage` recognise `.ts` by
  content too.
- **Filesystem creation / last-write times are reported** — `info` /
  `list_volumes` now show a volume's creation and last-write times when the
  filesystem records them: **ext** from `s_mkfs_time` / `s_wtime` (the values
  `dumpe2fs` reports), **NTFS** from the `$Volume` file's `$STANDARD_INFORMATION`
  (the timestamps Windows keeps), **HFS+** from the volume header's
  `createDate` / `modifyDate`, and **ISO 9660** from the Primary Volume
  Descriptor's creation / modification date, so a recovered volume can be dated.
  The text view adds `created:` and `last written:` lines (ISO-8601 UTC) and
  `--json` / the MCP `list_volumes` tool add `created_time` / `written_time`
  fields (Unix seconds, `null` when unset).
- **The allocation-unit size is reported** — `info` / `list_volumes` now report
  each volume's cluster size (FAT, exFAT, NTFS, ReFS) or block size (ext, HFS+,
  APFS, XFS, F2FS, Btrfs, ISO 9660) — the granularity the filesystem allocates
  space in, which carving aligns to and which bounds per-file slack. The text
  view adds an `alloc unit:` line and `--json` / the MCP `list_volumes` tool an
  `alloc_unit_bytes` field (`null` for backends with no such unit).
- **The ext variant (ext2 / ext3 / ext4) is reported** — `info` / `list_volumes`
  now refine the `ext2/3/4` family label to the precise variant, read from the
  superblock feature flags the way `blkid` classifies them: ext2 has no journal,
  ext3 adds a journal, and ext4 carries an ext4-only feature such as extents or
  64-bit block addressing. The text view adds a `version:` line and `--json` /
  the MCP `list_volumes` tool a `version` field (`null` for filesystems without a
  sub-version).
- **Linux swap areas are recognised** — a swap partition is detected from its
  version-2 swap header (`SWAPSPACE2`) and reported by `info` / `list_volumes`
  with its size, **UUID**, and **label**, instead of showing as an unrecognised
  volume. A swap area holds no files to recover, but identifying it by its
  `UUID=` (the value `/etc/fstab` uses) helps confirm which disk an image came
  from and rules the area out as a place to look for lost data. The header's page
  size is detected from the magic's position (4–64 KiB), and the area is checked
  before the boot-sector filesystems so a stale disklabel in the reserved
  `bootbits` region is not misread as FAT/NTFS.
- **Volume clean/dirty state is reported** — `info` / `list_volumes` now report
  whether a volume was cleanly unmounted, from ext (`s_state`), exFAT
  (`VolumeFlags`), and NTFS (`$VOLUME_INFORMATION`). A volume that is marked
  dirty (potentially inconsistent, so less reliable to recover from) gets a
  `state: dirty` line in the text view; `--json` / the MCP `list_volumes` tool
  add a `clean` boolean (`null` for filesystems without the flag).
- **Bootable ISOs are flagged with their boot platform (El Torito)** — `info` /
  `list_volumes` report whether an ISO 9660 disc carries an El Torito boot record
  and the platform(s) it boots — e.g. `El Torito (BIOS, UEFI)`, read from the
  boot catalog's validation entry and section headers — distinguishing a
  legacy-BIOS, UEFI, or hybrid image from a pure data disc. The text view adds a
  `boot:` line and `--json` / the MCP `list_volumes` tool a `boot` field.
- **`triage` reports the modification-time span** — the oldest and newest file
  modification time across the directory, so you can see what period the
  recovered data covers. The text view adds a `Modified: <oldest> .. <newest>`
  line (ISO-8601 UTC) and `--json` / the MCP `triage` tool add `oldest_mtime` /
  `newest_mtime` as Unix seconds.
- **Filesystem UUIDs / volume serials are reported** — `info` / `list_volumes`
  now report each volume's identifier (the `UUID=` value `/etc/fstab` and `blkid`
  use) on a `uuid:` line / `uuid` field, so a recovered filesystem can be
  correlated with a system's configuration. For **ext**, **XFS**, **F2FS**, and
  **Btrfs** this is the filesystem UUID; for **FAT**, **exFAT**, and **NTFS** it
  is the volume serial number in the conventional form (`XXXX-XXXX` for
  FAT/exFAT, 16 hex digits for NTFS). (Distinct from a GPT partition's PARTUUID,
  reported in the partition table.)
- **GPT partition GUIDs are reported** — `info` / `list_volumes` now report each
  GPT partition's **unique GUID** (the PARTUUID that `/etc/fstab`, bootloaders,
  and `/dev/disk/by-partuuid` reference) and the **disk GUID**, so a recovered
  partition can be correlated with a system's configuration. The text view adds
  `disk GUID:` and per-entry `uuid:` lines; `--json` adds `disk_guid` and a
  per-partition `uuid` field, as does the MCP `list_volumes` tool.
- **LVM2 physical volumes are recognised** — a Linux LVM physical volume (how a
  partition holds the logical volumes that contain the real filesystems) is
  detected from its `LABELONE` / `LVM2 001` on-disk label and reported by `info`
  / `list_volumes` with the PV's size, instead of showing as unrecognised. The
  logical volumes are not mapped, so recover with a whole-source `scan` /
  `--scan`, which finds the filesystems inside the LVs at their physical offsets.
- **SquashFS image carving** — the read-only compressed filesystem used by Snap
  packages, AppImages, live media, and router/IoT firmware is carved from its
  `hsqs` superblock, whose `bytes_used` field gives the exact image size. The
  major version (4) and block-size/`block_log` consistency are checked, so a
  coincidental `hsqs` does not produce a bogus file. `identify` and `triage`
  recognise `.squashfs` by content too.
- **`cpio` archive carving** — the "new ASCII" (`newc`, and `070702` CRC) format
  used by Linux initramfs images and RPM payloads is carved by walking the entry
  chain (each 110-byte ASCII header's hex `namesize`/`filesize` fields give the
  next entry, names and data padded to 4 bytes) to the `TRAILER!!!` end marker,
  recovering the exact archive length. Header fields are validated as ASCII hex,
  so a coincidental `070701` does not produce a bogus file. `identify` and
  `triage` recognise `.cpio` by content too.
- **`tar` archive carving** — POSIX/GNU `ustar` archives are carved by walking
  the 512-byte member chain (each header's size field gives the next member) to
  the two-zero-block end-of-archive marker, so the exact archive length is
  recovered. Every header's checksum is verified during the walk, so a
  coincidental `ustar` string does not produce a bogus file. `identify` and
  `triage` recognise `.tar` by content too.
- **F2FS volumes are recognised** — the Flash-Friendly File System (internal
  storage on most Android phones, and many SD cards / embedded devices) is
  detected from its `0xF2F52010` superblock and reported by `info` /
  `list_volumes` with its size and volume **label**. Being log-structured and
  copy-on-write, it has no metadata undelete — fall back to `scan` (carving).
  Detected in the normal layout and the whole-source `--scan` partition search.
- **XFS volumes are recognised** — the high-performance journaling filesystem
  common on Linux servers and NAS appliances (the RHEL/CentOS default) is
  detected from its `XFSB` superblock and reported by `info` / `list_volumes`
  with its size and filesystem **label**. Modern XFS zeroes an inode's
  data-extent list on unlink, so there is no metadata undelete — fall back to
  `scan` (carving). Detected in the normal layout and the whole-source `--scan`
  partition search.
- **MBR logical partitions are enumerated** — `info` / `list_volumes` now walk
  the Extended Boot Record chain inside an extended partition and report each
  logical partition (its type and byte range), so an MBR disk with more than
  four partitions shows all of them instead of just the four primary slots. The
  walk is bounded against a malformed or cyclic chain.
- **GPT backup-header fallback** — when a disk's primary GPT header (LBA 1) is
  missing or corrupt (e.g. its first sectors were overwritten), `info` /
  `list_volumes` now recover the partition layout from the **backup** GPT header
  and entry array kept at the end of the disk, instead of showing no table. The
  text view flags this (`recovered from backup header; …`) and `--json` / the
  MCP `list_volumes` tool add a `gpt_from_backup` boolean.
- **`triage` flags corrupt/truncated files** — a recovered file whose extension
  names a type with a known magic signature, but whose content matches no
  signature at all (a destroyed or truncated header, or a mislabelled blob).
  This is reserved for types with a direct magic number, so unidentifiable-but-
  plausible container subtypes (`docx`, `msg`, …) and empty files never produce
  noise — it complements the existing mismatch check (which flags content that
  *is* a different known type). Reported in the text output, as a `corrupt`
  array in `--json`, and by the MCP `triage` tool (which now also reports
  `mismatches`).
- **ReFS volumes are recognised** — Microsoft's Resilient File System (Windows
  Server, Storage Spaces, Dev Drive) is detected from the `ReFS`/`FSRS`
  signatures in its volume boot record and reported by `info`/`list_volumes`
  with its size (from the boot record's sector geometry). Like APFS and Btrfs it
  is copy-on-write (and undocumented), so there is no metadata undelete — fall
  back to `scan` (carving) to recover data. Detection runs both in the normal
  layout and in the whole-source `--scan` partition search.
- **`triage` flags content/extension mismatches** — files whose bytes identify
  as a different known type than their extension claims (e.g. a `.jpg` that is
  really an executable — a renamed/disguised file, or a recovery mislabel).
  Common aliases (`jpeg`→`jpg`, `mov`→`mp4`, …) are normalised first and only
  recognised types are compared, so generic blobs and unknown formats don't
  produce noise. Reported in the text output and as a `mismatches` array in
  `--json`.
- **`identify` accepts multiple files** — `identify FILE...` (e.g. `identify *`)
  labels each file's type from its contents, one line per file; with `--json` it
  emits an array (a single file still prints one object, unchanged).
- **`info` shows the partition table** — the scheme (GPT or MBR) and each entry's
  type (friendly names for known GPT type GUIDs and MBR type bytes, otherwise the
  raw GUID / `0xNN`), GPT name, and byte range. This reveals the on-disk layout
  even for partitions whose filesystem isn't recovered (EFI System, swap, empty
  slots). `--json` adds `partition_scheme` and a `partitions` array, and the MCP
  `list_volumes` tool reports the same.
- **`info` reports each volume's free (unallocated) space** — read from the
  allocation map for FAT, exFAT, ext2/3/4, NTFS, and HFS+/HFSX — so you can gauge
  how much deleted data might be recoverable before running a carve. The text
  view adds a `free:` line (bytes and unallocated percentage) under each volume;
  `--json` adds a `free_bytes` field (`null` when the filesystem's map is not
  parsed). The MCP `list_volumes` tool reports the same `free_bytes` per volume.
- **Free-space-aware carving** — `recover --unallocated` and `scan --unallocated`
  carve only a volume's unallocated space (less noise, faster), reading the
  allocation map for FAT, exFAT, ext2/3/4, NTFS, and HFS+/HFSX. Falls back to a
  full-source carve, with a notice, when no map is available.
- **HFS+/HFSX** recovery now reassembles **fragmented files** via the
  extents-overflow B-tree and restores each file's original **folder path** from
  the catalog hierarchy.
- **APFS** volume enumeration and **Btrfs** detection plus **subvolume
  enumeration** in `info`/`list_volumes` — the names of the volumes/subvolumes
  inside the container (and the Btrfs filesystem label). Neither is recovered
  from metadata (copy-on-write); carving remains the fallback.
- **Encrypted-volume recognition** — LUKS (LUKS1/LUKS2) and BitLocker are named
  by `info`/`list_volumes` so the user knows to unlock them first; they hold only
  ciphertext and are not recovered.
- **UDF recognition** — UDF volumes (optical media, and many large USB drives and
  camcorder cards) are detected via their Volume Recognition Sequence and named by
  `info`/`list_volumes`. Their descriptor metadata is not parsed, so UDF is not
  recovered from metadata — carving (`scan`) is the fallback, as for APFS/Btrfs.
- **ISO 9660 detection and file extraction** — data CD/DVD discs and `.iso`
  images are detected via the Primary Volume Descriptor at sector 16 and named by
  `info`/`list_volumes` (with their size and volume label), and `undelete`/
  `recover` **extract their files with original names and folder paths** by
  walking the directory tree — far better than carving, which loses names and
  structure. Long names are decoded from both **Joliet** (Windows discs —
  UCS-2/Unicode) and **Rock Ridge** (`NM` entries on Linux/macOS discs) —
  including names that overflow the directory record into Rock Ridge
  continuation (`CE`) areas — so files come back with their full filenames
  either way. Files stored across several **multi-extent** records (how ISO 9660
  holds files larger than ~4 GiB) are reassembled into one output file rather
  than emitted as separate fragments. A hybrid UDF disc is reported as UDF.
- **Lost/corrupt partition recovery** — `info --scan` finds volumes that have no
  partition-table entry via a whole-source signature scan, and `undelete --scan`
  / `recover --scan` recover from every volume found, in one command.
- More **carvable types**: AIFF/AIFF-C audio, Apple ICNS icons, RAR archives
  (v4 and v5), Zstandard (`.zst`), LZ4 (`.lz4`), Photoshop documents (PSD/PSB),
  Windows Metafiles (WMF), DjVu documents, binary glTF (`.glb`), Windows Event
  Logs (EVTX), Rich Text Format (RTF), MP3 audio (ID3v2-anchored MPEG-frame
  walk), Mach-O binaries (macOS/iOS, sized from segment and link-edit
  extents), Windows registry hives (`regf`, base block + hive-bins data
  size), AAC audio (ADTS frame-length walk), Android Dalvik executables
  (DEX, file-size header field), ICC colour profiles (size in the profile
  header), Unix `ar` archives (`.deb`/`.a`, member-chain walk), and ESRI
  Shapefiles (`.shp`, length field in the header), and Blender files
  (`.blend`, block chain walked to the terminating `ENDB` block), and NES ROMs
  (iNES / NES 2.0, sized from the PRG/CHR bank counts), raw JPEG 2000
  codestreams (`.j2k`, ended at the EOC marker), Windows Imaging images
  (WIM/ESD, sized from the resource-table extents), uncompressed Flash
  movies (`.swf`/`FWS`, length field in the header), and Compound File Binary
  (OLE2) containers — the legacy Microsoft Office formats (`.doc`/`.xls`/`.ppt`)
  and other OLE2 files (e.g. `.msi`) — sized by reading the FAT (located via the
  DIFAT) and taking the highest sector still marked in use, and Outlook data
  files (`.pst`/`.ost`, Unicode format — sized from the `ibFileEof` field in the
  NDB header) — each with a deterministic length strategy.
- **MP3 without an ID3v2 tag** is now carved by anchoring directly on a Layer III
  frame sync (requiring a long run of valid frames), so ID3v1-only and tagless
  MP3s are recovered, not just ID3v2-tagged ones.
- **`scan --dry-run`** previews a recovery: it reports the counts, sizes, per-type
  breakdown, and (with `--report`) the manifest of what *would* be recovered,
  without writing any files — useful for sizing up a device first. Also exposed
  as a `dry_run` argument on the MCP `scan` tool.
- **`recover --dry-run`** previews both passes (filesystem undelete and carving)
  without writing any files, so dry-run is now available on `scan`, `undelete`,
  and `recover` alike.
- **`--volume <N>`** — `undelete` and `recover` can target a single detected
  volume by its `info` index (0-based), a friendlier alternative to copying the
  raw `--offset`. Out-of-range indexes are reported clearly.
- **Name/glob filtering** — `--name <GLOB>` and `--exclude-name <GLOB>` (on
  `undelete` and `recover`, and the MCP `undelete` tool) recover only — or skip —
  files whose name matches a case-insensitive glob (`*` and `?`); repeatable or
  comma-separated (`--name '*.jpg,*.png'`, `--exclude-name '*.tmp,Thumbs.db'`).
  Includes match any pattern; excludes are applied after and win on overlap.
  Applies to every undelete backend (FAT, exFAT, NTFS, ext, HFS+) and to ISO 9660
  file extraction. Completes the recovery filter family alongside
  `--min-size`/`--max-size` and the time bounds.
- **Time-range filtering** — `--modified-after` and `--modified-before` (on
  `undelete` and `recover`, and the MCP `undelete` tool) restrict the undelete
  pass to files whose modification time falls in a window, e.g. `--modified-after
  2021-01-01`. Accepts `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS` (UTC). Applies to
  every filesystem backend (FAT, exFAT, NTFS, ext, HFS+); a file whose timestamp
  can't be read is kept rather than silently dropped. (As with timestamp
  restoration, FAT/exFAT times are treated as UTC for lack of a recorded zone.)
- **`--align`** — restrict carving (on `scan` and `recover`, and the MCP `scan`
  tool) to candidates whose start offset is a multiple of the given size (e.g.
  `--align 512` or `--align 4K`). Files inside a filesystem begin on cluster
  (sector-multiple) boundaries, so aligning discards the coincidental mid-sector
  magic matches that produce most false positives. Default 1 (every offset).
- **`--max-size`** — a size cap symmetric with `--min-size`, on `scan`, `undelete`,
  and `recover` (and the MCP `scan`/`undelete` tools). Recognised files larger than
  the cap are skipped — carving counts them under `skipped_large` (reported in the
  text output, the `--summary`, and the MCP scan result) rather than writing them.
  Both bounds apply to the undelete *and* carving passes of `recover`. Useful for
  fast triage: recover the small stuff first, or skip multi-gigabyte files.
- **Human-readable size suffixes** — every byte-valued option (`--start`, `--end`,
  `--min-size`, `--offset`, `--scan-step`, `--sector-size`) now accepts binary
  unit suffixes like `5M`, `2G`, or `1.5G` (powers of 1024), not just raw byte
  counts.
- **Type categories** — `--type` (on `scan` and `recover`) now accepts a category
  name (`image`, `audio`, `video`, `document`, `archive`, `executable`, `font`,
  `system`) to select a whole class of types at once, instead of listing every
  extension. Categories and extensions can be mixed. `list-types` groups its
  output by category so the names are discoverable. The MCP server exposes this
  too: `list_types` now reports each type's `category` (de-duplicated by
  extension), and the `scan` tool's `types` argument accepts category names.
  `identify` (CLI and MCP) reports the detected file's category, and `triage`
  adds a per-category rollup (image/audio/video/…) alongside its per-type
  breakdown. `--type` also accepts a comma-separated list (`--type image,pdf`),
  not just repetition. A new `--exclude` option drops types or categories from
  the selection (applied after `--type`), e.g. `--type image --exclude png` or
  `--exclude video`.

- **OLE2 compound files are recovered with their real extension.** A carved
  compound file (`.ole`) is inspected for the marker stream name of the format it
  carries, so it is written as `.doc` (Word), `.xls` (Excel), `.ppt`
  (PowerPoint), or `.msg` (Outlook message) instead of a generic `.ole`; a
  Windows Installer is recognised by its root storage CLSID and written as
  `.msi`. An unrecognised compound file stays `.ole`. `identify` reports the same
  refined type; doc/xls/ppt/msg map to the document category and msi to the
  executable category for `--type`, `triage`, and `identify`.

- **ZIP-based formats are recovered with their real extension.** A carved ZIP is
  inspected for the marker member of the common ZIP container formats, so a
  recovered Office (`.docx`/`.xlsx`/`.pptx`), OpenDocument (`.odt`/`.ods`/`.odp`),
  e-book (`.epub`), Java (`.jar`), or Android (`.apk`) file is written with that
  extension (and counted under it) instead of a generic `.zip`. A plain ZIP stays
  `.zip`. `identify` reports the same refined type, and these types are mapped to
  their categories (documents, archives) for `--type`, `triage`, and `identify`.

### Fixed

- **Fewer carving false positives** — structural validators were added for eight
  more types: PDF (version string), TIFF/BigTIFF (byte order, version, and a
  plausible first-IFD offset), Microsoft Cabinet (zeroed reserved fields),
  WebAssembly and Android DEX (version checks), Photoshop (version + reserved
  fields), and Ogg and FLV (header constants). A coincidental magic match in
  unrelated data now fails these checks and is dropped, on top of the existing
  JPEG/PNG/GIF/BMP/SQLite/ELF/EMF/MIDI validators.
- **JPEG carving no longer truncates at an embedded thumbnail.** Camera and phone
  JPEGs embed a full thumbnail (its own `FF D8 … FF D9`) in the EXIF metadata; the
  carver previously stopped at the thumbnail's End-of-Image marker, producing a
  truncated file. It now tracks nested Start/End-of-Image markers and carves to
  the outer image's `FF D9`.
- **ZIP carving no longer truncates at a nested archive, and keeps the EOCD
  comment.** A ZIP stored inside a ZIP (a JAR/asset bundle, etc.) has its own
  End-of-Central-Directory record; the carver previously stopped at the first one,
  truncating the outer archive, and also dropped any EOCD comment. It now selects
  the EOCD whose recorded central-directory geometry matches the archive and
  includes the declared comment. This also covers the ZIP-based formats (DOCX,
  XLSX, PPTX, ODT, JAR, APK, EPUB).
- **GIF carving now walks the block structure** instead of stopping at the first
  `00 3B` byte pair, which can occur by chance inside the LZW-compressed image
  data and truncate the file. The carver follows the image and extension blocks
  (and their sub-block chains) to the real trailer.

## [0.2.0] - 2026-06-23

A large release that grows `unearth` from a signature carver into a
full recovery toolkit: filesystem-aware undelete, robust imaging, a one-pass
combined mode, and an AI-agent interface — all dependency-light and read-only on
the source.

### Added

- **Filesystem-aware undelete** (`undelete`) for FAT12/16/32, exFAT, NTFS, and
  ext2/3/4, restoring original names, paths, sizes, and timestamps. NTFS and ext
  reassemble fragmented files; ext4 falls back to the jbd2 journal when a live
  inode's extents were zeroed.
- **HFS+/HFSX undelete** by scanning catalog B-tree leaf-node free space for
  stale file records.
- **APFS detection** in `info`/`list_volumes` (recognised but not recovered from
  metadata — carving is the fallback).
- **Disk imaging** (`image`): read-only, bad-sector tolerant (sector-granular
  retry, unreadable regions recorded), sparse output, a checkpoint/map file for
  `--resume`, and `--retry-bad` to re-read unreadable regions.
- **One-pass recovery** (`recover`): undelete then content-deduplicated carving,
  written to `named/` and `carved/`, with a verifiable combined `--report`.
- **Resumable carving** (`scan --resume`) via a checkpoint file, plus
  `--organize` to group carved output into per-type subdirectories.
- **MCP server** (`mcp`): a Model Context Protocol server over stdio exposing
  recovery as tools for an AI agent, with `scan`/`image` running as cancellable
  background jobs (poll `scan_status`, stop with `scan_cancel`).
- **Auditing**: SHA-256 manifests (`--report`), run summaries (`--summary`), and
  a `verify` command that re-hashes recovered files against a manifest.
- **Inspection**: `info` (partition/filesystem layout), `triage` (summarize a
  recovery directory), and `identify` (detect a file's type from its contents).
- Many more carvable types — 40 in total, including fonts (TTF/OTF/WOFF/WOFF2/
  TTC), EMF, MIDI, FLV, pcap/pcapng, JPEG 2000, and animated cursors — each with
  a deterministic length strategy and, where useful, a structural validator.
- Shell completions (`completions`), Criterion benchmarks, a dhat heap-profiling
  example, and a release workflow that builds binaries on `v*` tags.

## [0.1.0]

- Initial release: signature-based file carving (`scan`) with structural
  validation, content dedup, and recovery manifests.

[Unreleased]: https://github.com/MarcelRoozekrans/unearth/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/MarcelRoozekrans/unearth/releases/tag/v0.4.0
[0.3.0]: https://github.com/MarcelRoozekrans/unearth/releases/tag/v0.3.0
[0.2.0]: https://github.com/MarcelRoozekrans/unearth/releases/tag/v0.2.0
[0.1.0]: https://github.com/MarcelRoozekrans/unearth/releases/tag/v0.1.0
