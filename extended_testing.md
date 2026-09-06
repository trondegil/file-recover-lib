# Extended testing: work order for an Opus 5 session

This is a self-contained brief for a Claude Opus 5 session running in Claude
Code on this repository. It closes the test gaps found in the September 2026
review of the suite. Everything you need to start is here: ground rules, a map
of the code and fixtures, the facts that were checked against the source, and
twenty-three tasks with fixtures, assertions, and done criteria. Read it once
top to bottom, then start at section 4.

The review combined a structural pass over the suite with an independent
written review of the same material by OpenAI's gpt-6-astra. Where they
disagreed, the code was re-read and the corrected fact is what appears here.
The guiding conclusion, from that review: the suite proves that expected files
come back; it does not yet prove that everything the tool wrote is correct,
that nothing extra or mislabelled was written, or that no write could escape
the output directory or land on the source. The tasks are ordered by that.

## 1. Ground rules

- **The source is read-only.** No test, fixture, or helper may open a source
  image or device for writing. Fixtures are byte vectors written to a
  `tempfile::tempdir()` and opened with `Source::open`.
- **Commits carry no AI attribution.** No `Co-Authored-By`, `Generated with`,
  or similar lines in commit messages or PR bodies. The owner has asked for
  this explicitly.
- **Branch and PR.** Branch `testing/extended` off `main`. Push to `origin`
  (the fork `trondegil/file-recover-lib`), never `upstream`. One PR per group
  as marked in section 4. release-please handles releases; do not touch
  `CHANGELOG.md` or the version.
- **Before every commit:**

  ```sh
  cargo fmt --all -- --check
  cargo clippy --all-targets -- -D warnings
  cargo test --all --no-fail-fast
  ```

  CI runs these on Ubuntu, macOS, and Windows. Gate Unix-only APIs with
  `#[cfg(unix)]`. Build paths with `Path::join`. Creating a symlink on Windows
  needs a privilege the runner may lack: gate symlink tests to Unix.
- **Conventions from CONTRIBUTING.md and ARCHITECTURE.md hold:** saturating
  arithmetic on on-disk offsets and sizes, every read bounds-checked, parsers
  return `Ok`/`Err` and never panic, allocations bounded by real limits. No
  test shells out to `mkfs`, `mtools`, or `hdiutil`. No new dependencies; the
  dev-dependencies are `tempfile` and `criterion`.
- **Tests assert output, not survival.** Four layers of "does not panic"
  already exist. Every new test asserts bytes, lengths, paths, grades, error
  values, or manifest rows. For a malformed input, assert refusal or weaker
  confidence; "returned something" is not a pass.
- **No `#[ignore]`, no `sleep`.** A test that needs timing uses the
  `ProgressSink::cancelled` hook, a channel, or polling of job status with a
  bounded loop.
- **Do not weaken an existing test** or lower a corpus baseline. If a new
  test exposes a bug, fix it in `src/` in the same PR and say so.
- **Mutation check every wrong-bytes test.** After a test passes, break the
  code path it guards (swap a run order, drop a bounds check) and confirm the
  test fails, then restore. Mention in the PR that this was done.
- **Where this document says "expect this to fail"**, the code was read and
  the behaviour is missing. Write the test first, watch it fail, fix, and
  keep the test.

## 2. Orientation

### Modules these tasks touch

| Module | What it is | Entry points |
|---|---|---|
| `src/source.rs` | Read-only positioned access; device check | `Source::open(&Path)`, `read_at(off, buf)`, `source::same_device(src, out)` |
| `src/recover.rs` | Detection (bare, GPT, MBR), `Volume` dispatcher, output-path safety | `recover::detect(&src)`, `parse_at(&src, off)`, `scan_lost_volumes(&src, step, progress)`, `Volume::recover_deleted(&src, out, &RecoverOptions)`, `confine`, `unique_path`, `sanitize_component` |
| `src/partition.rs` | MBR, GPT, APM parsing | `partition::read(&src) -> Table` |
| `src/fat.rs`, `exfat.rs`, `ntfs.rs`, `ext4.rs`, `hfsplus.rs` | Undelete backends | `Volume::parse(src, offset)`, `recover_deleted(...)` |
| `src/carver.rs` | `scan` engine; `SCAN_CHUNK` is 8 MiB with an overlap; grading `Confidence::{Verified, Plausible, Truncated}` | `carver::carve(&src, &sigs, &CarveOptions, &impl ProgressSink)` |
| `src/signatures.rs` | 188-entry table and matcher | `signatures::select(&[])`, `select(&["jpg"])` |
| `src/image.rs` | Bad-sector-tolerant imaging over `trait BlockSource { size, read_at }` | `image::image(...)`; test mocks `TransientSource`, `FaultySource` in its test module |
| `src/mcp.rs` | JSON-RPC over stdio | `mcp::serve(reader, writer)`, `mcp::handle_request(&Json) -> Option<Json>` |
| `src/job.rs` | Background jobs | `job::start(kind, work) -> u64`, `job::status(id) -> Option<Json>`, `job::cancel(id) -> bool` |
| `src/main.rs` | CLI wiring; `refuse_output_on_source` at four call sites; manifest writers | reached only by spawning the binary |

`RecoverOptions`: `min_size`, `max_size: Option<u64>`, `modified_after`,
`modified_before`, `names: Vec<String>`, `exclude_names: Vec<String>`,
`dry_run`. `CarveOptions`: `output_dir`, `start`, `end`, `min_size`,
`max_size`, `max_files`, `allow_nested`, `validate`, `dedup`, `progress`,
`checkpoint`, `resume`, `organize`, `dry_run`, `align`. Both are filled in
inside `tests/robustness_test.rs`.

Probe order in `recover::try_parse_volume`: encrypted containers, exFAT,
NTFS, ReFS, ext, HFS+, HFS, APFS, Btrfs, XFS, F2FS, then the remaining
detect-only parsers. Each `is_*` reads a magic; each `parse` validates
geometry; a failed `parse` falls through.

### Facts checked against the code that shape the tasks

- Every backend writes recovered files with `fs::create_dir_all(parent)`
  then `fs::File::create(&target)`, after `recover::unique_path` has confined
  the relative path. `File::create` follows a symlink at the final component
  and `create_dir_all` follows symlinked parents. There is no `create_new`
  and no `O_NOFOLLOW`. Task 2 will find this.
- `recover::confine` drops every non-`Normal` path component, and
  `unique_path` appends `_N` on collision. All five undelete backends and
  ISO 9660 route through `unique_path`. Both have unit tests in `recover.rs`
  (`output_paths_stay_inside_the_output_directory`,
  `sanitize_component_is_portable`, including Windows reserved names).
- `source::same_device` returns `true` only for a block or char device
  whose `rdev` matches, or shares a major number with, the device the output
  directory sits on. Regular files always give `false`.
- Undelete manifests carry a `confidence` column whose value for undeleted
  files is the single word `named`. Only carved files use `verified`,
  `plausible`, `truncated`. There is no partial or heuristic grade for a
  reassembled FAT file.
- `ext4::build_journal_index` records only descriptor-tagged data blocks. It
  skips commit and revoke blocks. `journaled_inode` picks, among copies with
  a block map, the one with the newest `ctime`, ties to the later position.
  Commit status is not consulted.
- `image.rs` unit tests already cover bad sectors, merged bad regions, map
  round-trip, corrupt map fallback, resume, and transient retry, using
  `TransientSource` and `FaultySource`.
- `mcp` runs `scan` and `image` through `job::start`; cancellation is
  observed once per 8 MiB chunk. `scan_status` returns the job's progress
  JSON including a `cancelled` flag.
- `scan_lost_volumes` probes at `step`-aligned offsets (minimum 512), skips
  past each found volume's body, and caps probes at 16 million.
- FAT type is chosen by cluster count: under 4085 is FAT12, under 65525 is
  FAT16. `fs_version()` on the volume reports it.
- Several files besides `cli_test.rs` spawn the binary: `apfs_test`,
  `btrfs_test`, `capabilities_test`, `partition_info_test`,
  `volume_select_test`, `free_space_test`, `lost_partition_test`,
  `encrypted_test`, `iso9660_test`, `udf_test`, `swap_test`. `main.rs` still
  has no unit tests.
- The corpus covers FAT32, exFAT, NTFS, ext4, HFS+ (undelete) and XFS
  (detect and scan). It does not cover FAT12, FAT16, ext2, ext3, or HFSX.

### Fixture builders in `tests/common/mod.rs`

Every integration file starts with `mod common;`. Extend this file rather
than duplicating a builder.

| Builder | Produces |
|---|---|
| `jpeg(payload)` | Minimal JPEG: SOI/APP0, payload, EOI |
| `ext_volume(name, payload)` | 32 KiB ext4, 1 KiB blocks, 128-byte inodes, one deleted file (inode 11, links 0, dtime set, extents flag, one extent at block 11) as a stale root dirent. Any `name` up to 255 bytes, so it is the hostile-name fixture. |
| `fat32_volume(name8, ext3, payload)` | FAT32 with a cluster-chained root and one deleted 8.3 entry |
| `fat32_deleted_dir_volume`, `fat32_windows_deleted_dir_volume`, `fat32_highword_volume`, `fat32_fragmented_volume(data_clusters, wrap)`, `fat32_jpeg_decoy_volume(jpeg)` | FAT32 edge cases; read the doc comments |
| `hfsplus_volume`, `hfsplus_fragmented_volume`, `hfsplus_nested_volume(folder, name, payload)`, `hfsplus_journaled_volume` | HFS+ shapes |
| `gpt_disk(volume, sector_size, part_lba)` | Wraps a volume in a GPT disk, 512 or 4096-byte sectors |

Local helpers worth copying: `tests/ntfs_test.rs` (`write_boot`,
`filename_attr`, `std_info_attr`, `data_resident`,
`data_nonresident(real_size, runs)`, `build_record(flags, attrs)`);
`tests/ext4_test.rs` (`write_superblock`, `write_gdt`, `write_inode`,
`write_dirent`); `tests/ext4_journal_test.rs` (journal builder);
`tests/fat_test.rs` (`deleted_lfn_entry`); `tests/partition_info_test.rs`
(`mbr_disk`); `tests/cli_test.rs` (`bin()`, `run(args)`);
`tests/scan_resume_test.rs` (`image_with_jpegs`, a `ProgressSink` with a
`cancelled` hook); `tests/mcp_test.rs` (`session(requests)` drives `serve`
over a `Cursor`, `call(req)` drives `handle_request` in-process and returns
the tool result JSON).

## 3. Baseline (2026-09-06, main at 13f4572)

| Measure | Value |
|---|---|
| Tests passing / failing / ignored | 593 / 0 / 1 (corpus, opt-in) |
| Library unit tests | 390 |
| Integration tests | 200 in 88 files |
| Corpus images | 77 |
| Coverage tooling | none |

## 4. Start here

1. Run `cargo test --all` once and confirm 593 pass.
2. Read, in this order: `ARCHITECTURE.md`, `tests/common/mod.rs`,
   `src/recover.rs` lines 90 to 260 (sanitising and confinement), the
   `recover_deleted` function of one backend (`src/fat.rs` around line 490),
   and `tests/cli_test.rs` to line 60.
3. Create the branch and begin PR 1.

Groups:

| PR | Tasks | Theme | Read first |
|---|---|---|---|
| 1 | 1 to 6 | Safety and detection | `src/recover.rs`, `src/source.rs` from line 185, `src/partition.rs`, `src/main.rs` `refuse_output_on_source` |
| 2 | 7 to 13 | Wrong bytes | `src/ntfs.rs` data runs, `src/ext4.rs` lines 500 to 640 and 880 to 950, `src/hfsplus.rs` overflow walk, `src/carver.rs` lines 160 to 260 |
| 3 | 14 to 20 | Infrastructure and orchestration | `src/image.rs`, `src/job.rs`, `src/mcp.rs` lines 680 to 830, `.github/workflows/ci.yml` |
| 4 | 21 to 23 | Corpus oracle | `corpus/README.md`, `tests/corpus_test.rs`, `examples/corpus_tool.rs` |

Corpus runs, needed for PR 1, 2, and 4 verification and for tasks 21 to 23:

```sh
cargo test --release --test corpus_test -- --ignored --nocapture
UNEARTH_CORPUS_ONLY=macos-hfsplus cargo test --release --test corpus_test -- --ignored --nocapture
```

The first run downloads the tarball pinned in `corpus/corpus.lock`.

## 5. Tasks

### PR 1. Safety and detection

#### Task 1. Hostile names end to end

File: new `tests/output_safety_test.rs`.

Fixture: `common::ext_volume(name, payload)` per name, each in its own
tempdir; one FAT32 case using a copied `deleted_lfn_entry` so a long-name
entry carries the name; one HFS+ case via `hfsplus_nested_volume` with a
hostile folder name.

Names: `../../escape.txt`, `/abs.txt`, `C:\\win.txt`,
`\\\\server\\share\\x.txt`, `..`, `.`, `CON`, `nul.txt`, `a\u{0}b.txt`
(write the dirent bytes directly), `trailing.`, `spaced  `, a 255-byte name,
and `sub/dir/file.txt`.

Assertions per case:

1. `detect` finds one volume; `recover_deleted` returns `Ok`.
2. A sentinel file placed outside the output directory before the run is
   unchanged afterwards, and every file under the tempdir is either the
   sentinel or `starts_with(out_dir)`.
3. Exactly one file recovered; bytes equal `payload`.
4. Its file name equals `recover::sanitize_component(name)`.
5. On Windows, `CON` and `nul.txt` come out prefixed with `_`.
6. The `../../escape.txt` case repeated through the CLI (`undelete`) and
   through MCP (`undelete` tool via `call`).

#### Task 2. Symlinked parents and source aliases as destinations

Files: `tests/output_safety_test.rs` (Unix-gated), `tests/cli_test.rs`,
`src/source.rs`, and the backends' file creation.

1. **Symlinked parent. Expect this to fail.** Before the run, create
   `out_dir/sub` as a symlink to a directory outside the tempdir. Recover
   `sub/file.txt` from `hfsplus_nested_volume("sub", "file.txt", payload)`.
   Assert the outside directory is unchanged and the payload is either under
   a real directory inside `out_dir` or refused with an error. Fix: in one
   shared helper in `recover.rs` (call it `create_output_file(out_dir,
   rel)`), walk `rel`'s parent components under `out_dir`, refuse or replace
   any component whose `symlink_metadata` is a symlink, then open with
   `OpenOptions::new().write(true).create_new(true)`, which also refuses an
   existing symlink at the final component. Route all six `File::create`
   sites (five backends and `carver.rs` line 7162) through it. Note in the
   PR that check-then-open still has a replacement window and that
   `create_new` is what closes it at the final component.
2. **Source alias as destination.** Make a hard link and a symlink to the
   source image. Run `image`, `scan --report`, `scan --checkpoint`, and
   `image` with a map path, each with an alias as the destination. Assert
   the source's bytes and length are unchanged and the run failed before any
   write. If any case truncates the source, fix it in `main.rs`: on Unix
   compare `(dev, ino)` from `metadata()` of source and destination (a hard
   link shares both); on all platforms compare `canonicalize()` results. Say
   in the PR that hard links on Windows remain undetected.
3. **Device refusal, unit level.** Extract the pure comparison from
   `same_device_impl` into `fn same_device_numbers(src_rdev: u64,
   out_dev: u64) -> bool` and unit-test it with hand-built Linux and macOS
   device numbers (Linux major `((d >> 32) & 0xffff_f000) | ((d >> 8) &
   0xfff)`, macOS major `(d >> 24) & 0xff`): one pair sharing a major, one
   not. Assert `same_device(regular_file, dir)` and
   `same_device("/dev/null", dir)` are both `false` on Unix.

#### Task 3. Name collisions never overwrite a recovery

File: `tests/output_safety_test.rs`; builder `ext_volume_multi(entries:
&[(&str, &[u8])])` in `tests/common/mod.rs` (several deleted files as stale
dirents with distinct inodes and data blocks).

Cases: two names that sanitise to one string (`a:b.txt` and `a?b.txt` on
Windows; `a/b` and `a\\b` everywhere); two names differing only by Unicode
normalisation (`é` precomposed and decomposed); a name equal to a file that
already exists in `out_dir`; a name equal to a symlink that already exists in
`out_dir` (Unix).

Assertions: both payloads present under distinct names; the pre-existing
file unchanged; nothing written through the pre-existing symlink (this is the
same fix as task 2 item 1).

#### Task 4. Partition table edge cases

File: new `tests/partition_edges_test.rs`. Read `src/partition.rs` first
and note what it supports.

1. **MBR extended chain.** Primary entry type `0x05` or `0x0F` pointing at
   an EBR whose entry 1 is a logical partition holding `ext_volume` and whose
   entry 2 links to a second EBR with another logical partition. Assert both
   are detected at the right absolute offsets. Entry 1 LBA is relative to its
   EBR; entry 2 LBA is relative to the extended partition's start. Comment
   this in the fixture. If unsupported, implement it with saturating
   arithmetic and add a `partition.rs` unit test.
2. **Corrupt primary GPT.** `gpt_disk`, then zero LBA 1. If `gpt_disk` does
   not write the backup header at the last LBA, extend it. Assert the
   volume is still detected.
3. **Entry past end of source.** Two MBR entries, the second beyond the
   image. Assert the first is detected and recovered byte-for-byte; the
   second is skipped without error.
4. **Overlapping entries** pointing at one volume. Assert `undelete` over all
   volumes recovers the file exactly once.

#### Task 5. Decoy magics during detection

File: new `tests/decoy_magic_test.rs`.

Fixture: a few-MiB image with `fat32_volume` at a partition offset, preceded
and followed by sector-aligned decoy blocks, each carrying one detect-only
magic at its parser's expected offset (section 8) and random bytes
elsewhere. One variant wrapped with the `mbr_disk` pattern; one with no
table.

Assertions:

1. `detect` on the MBR variant returns exactly one volume, `Volume::Fat`, at
   the right offset.
2. `scan_lost_volumes(&src, 512, |_| {})` on the bare variant reports the
   FAT volume; for each non-FAT volume it also reports, `parse_at` at that
   offset returns `Ok(Some(_))` with a non-zero `size()` within the source.
   If a bare magic with garbage geometry is reported, tighten that parser's
   `parse` and add a unit test there.
3. A FAT32 volume whose data area holds the Minix magic at the right
   relative offset within a cluster still undeletes the file byte-for-byte.

#### Task 6. Detect-only refusal is asserted

`tests/apfs_test.rs` has `undelete_cli_refuses_a_detect_only_volume_with_a_hint`.
Generalise it for Btrfs, XFS, ISO 9660, UDF, and an encrypted container:
non-zero exit, a message naming the filesystem and pointing at `scan`, and an
empty output directory. Reuse fixtures from `btrfs_test`, `iso9660_test`,
`udf_test`, `encrypted_test`; XFS needs a minimal superblock (`XFSB`, block
size, block count, label).

### PR 2. Wrong bytes

#### Task 7. NTFS signed and sparse data runs

File: `tests/ntfs_test.rs`, using its helpers.

Fixture: a deleted record whose `$DATA` is non-resident with runs 20..22,
then 10..11 (negative offset, signed encoding), then a sparse run of two
clusters (offset width 0), then 30..30, with `real_size` ending
mid-cluster. Stamp each cluster with its index.

Assertions:

1. Recovered bytes are the clusters in that order, the sparse span as
   zeros, exactly `real_size` bytes.
2. A run overrunning the volume: error or short file, never padded to
   `real_size`, and the manifest row reflects it.
3. A record whose update-sequence fixups do not match is rejected, not
   parsed with stale bytes.

#### Task 8. ext2-style indirect blocks end to end

Files: `tests/common/mod.rs` (`ext_indirect_volume(name, payload)`),
`tests/ext4_test.rs`.

Builder: like `ext_volume` but 64 blocks, no extents flag, `i_block[0..12]`
direct, `i_block[12]` a single-indirect block. Payload over 12 KiB, data
blocks interleaved with unused blocks.

Assertions: byte-for-byte; `dry_run` reports one file of the right size;
the image truncated just before the indirect block gives an error or a short
file, never a full-size zero-padded one.

#### Task 9. ext4 journal copy selection

File: `tests/ext4_journal_test.rs`, extending its builder.

Current rule (checked): among journaled copies of the inode block that have
a block map, the newest `ctime` wins; commit and revoke blocks are not read.

1. Two copies, older with extent A and newer with extent B, both committed.
   Assert bytes come from B.
2. Sequence numbers that wrap. Assert no panic and B still wins.
3. Newer copy in a transaction with no commit block. Assert what the code
   does today (B is used) in a test named for it, and put the question to
   the owner in the PR: for undelete, an uncommitted copy is often the
   pre-deletion state and using it is arguably right, so do not change the
   policy without a decision.
4. A revoke record for the block in a later transaction: same treatment as
   item 3, pinned and flagged.

#### Task 10. HFS+ malformed overflow extents

File: `tests/hfsplus_test.rs`, extending `hfsplus_fragmented_volume` with a
parameter for the overflow records. Stamp every 512-byte block with its
index.

Cases: records out of logical order; a missing middle record; two records
covering the same logical range; a record beyond the volume.

Assertions: the valid case is byte-for-byte with the right EOF; each
malformed case yields an error or a short file, never a full-size file with
wrong blocks.

#### Task 11. FAT12 and FAT16, and ambiguous reassembly

Files: `tests/common/mod.rs`, `tests/fat_test.rs`, `tests/exfat_test.rs`.

1. `fat12_volume` and `fat16_volume` builders (cluster counts under 4085 and
   under 65525; FAT12 entries are 12-bit packed). Assert byte-for-byte
   recovery and the right `fs_version()`.
2. Ambiguity: a deleted non-JPEG file with two equally free continuations.
   Assert the current behaviour (first free cluster is used) in a test named
   for it, and assert the manifest row says `named`. Propose in the PR a
   `reassembled` confidence value for files whose chain was reconstructed
   rather than read, so the manifest stops calling a guess `named`. Do not
   add it without the owner's decision.

#### Task 12. Carving invariance across chunk boundaries

File: `tests/carve_test.rs`. `SCAN_CHUNK` is 8 MiB.

Build a 20 MiB image where a JPEG's SOI, a PNG's `IHDR` length field, a
ZIP's EOCD, and an ISO-BMFF `ftyp` brand each straddle the 8 MiB and 16 MiB
boundaries, then shift the whole layout by 1, 511, 512, and 4095 bytes.
Assert the carved set (SHA-256 and length) is identical at every shift: no
misses, no duplicates, no neighbouring bytes. Place one file with its footer
exactly at end of source and one cut off by it; assert `verified` and
`truncated` respectively. Keep the image mostly zeros so the test stays fast.

#### Task 13. Real sample files and grading negatives

Files: new `tests/samples/`, `tests/samples/make.sh`, new
`tests/real_samples_test.rs`, `tests/carve_test.rs`.

Samples under 24 KiB each, generated by the script from self-made content,
committed with the script. Skip a format whose tool is absent and say so:

| Format | Generator |
|---|---|
| JPEG with JFIF and EXIF thumbnail | Pillow, `sips`, or `magick` |
| PNG | Pillow or `magick` |
| GIF, two frames | Pillow |
| PDF | `magick` or Pillow |
| ZIP, two members, a comment | `zip` |
| WAV | Python `wave` |
| MP4, one black frame | `ffmpeg` |
| SQLite | `sqlite3` |
| CFBF | Python `olefile` |

Test: plant each in `% 251` filler, carve with all signatures, assert one
file with that extension, equal length, equal SHA-256, grade `verified`.
Expected hashes live in a table in the test.

Grading negatives in `carve_test.rs`: JPEG with no EOI cut at `max_size` is
`truncated`; PNG with valid `IEND` is `verified`; a size-field-only format
with no validator is `plausible`; end-of-run counts match the grades.

### PR 3. Infrastructure and orchestration

#### Task 14. Imaging: faults during resume, sparse path, map validation

File: `src/image.rs` tests. If `TransientSource` and `FaultySource` are
private, move them to `#[cfg(test)] pub(crate) mod testing`.

1. Interrupt, then resume with a `FaultySource` whose bad range is in the
   uncopied part: map records exactly that range, the copied prefix is
   untouched, the rest is byte-for-byte.
2. A fault inside a long zero run: the sparse path does not skip it; the map
   records it.
3. Map validation: a map whose recorded source size differs, entries that
   overlap or exceed the source, a truncated destination, a map for a
   different range. Each rejected before any write; a valid resume equals an
   uninterrupted copy in bytes and map.
4. Short reads: a `BlockSource` returning fewer bytes than asked without
   error. Offsets stay aligned; no stale buffer bytes are written.

#### Task 15. MCP protocol edges and cancellation

File: `tests/mcp_test.rs`.

1. Through `session`: a non-JSON line; an object without `jsonrpc: "2.0"`; a
   request without `id`; a string where an integer is required;
   `tools/call` with an unknown tool. Assert the standard error codes
   (`-32700`, `-32600`, `-32602`, `-32601`) and that later requests in the
   same session are still answered.
2. Cancel an active scan through `call`: an image over 32 MiB (so at least
   four chunks) with planted JPEGs; start `scan`, poll `scan_status` in a
   bounded loop until `scanned` is non-zero, call `scan_cancel`, poll until
   the job reports finished. Assert `cancelled` is true, repeated status
   calls agree, the set of output files is stable after the finished report,
   and any checkpoint written is accepted by a resume.
3. Two scans back to back: distinct job ids, both complete with the right
   counts.

#### Task 16. Resumed scan equals an uninterrupted scan

File: `tests/scan_resume_test.rs`, extending `image_with_jpegs` with
duplicate payloads and one file spanning the checkpoint position;
`dedup: true` and a manifest. Cancel at three positions via the
`ProgressSink::cancelled` hook, resume each, and assert output set (by
hash), dedup outcome, and manifest rows equal a single uninterrupted run.

#### Task 17. Reachable cycles and extreme geometry

File: `tests/robustness_test.rs`.

Cases, each a valid fixture with one corruption: a FAT chain that loops; an
exFAT bitmap claiming more clusters than the volume; an HFS+ catalog leaf
whose `fLink` points at itself; an NTFS `$MFT` run that includes the record
being parsed; an ext4 extent tree with depth pointing at its own block; a GPT
entry count of `u32::MAX`; a directory that lists its own parent as a child.

Run each on a thread and wait on a channel with a five-second timeout.
Assert completion inside the timeout, `Ok` or `Err`, nothing written outside
the output directory. Measure peak allocation locally with the `dhat-heap`
feature and record the numbers in the PR; do not assert on them in CI.

#### Task 18. Option interactions

File: `tests/cli_test.rs`. One test each, asserting files and manifest rows:
`--resume` with `--dedup` and `--report`; `--dry-run` with `--name` and
`--modified-after` (reported counts equal a real run's writes);
`--organize` with two files that sanitise to one name; `--unallocated` with
`--volume N` on a two-volume disk.

#### Task 19. Merge the dry-run files

Move `tests/dry_run_test.rs` (carver) into `tests/carve_test.rs` and
`tests/dryrun_test.rs` (ext4) into `tests/ext4_test.rs`; delete both files.
Both behaviours stay covered.

#### Task 20. Coverage and MSRV in CI

File: `.github/workflows/ci.yml`. Pin action SHAs like the rest of the file.

1. Job `coverage`, `ubuntu-latest`, `continue-on-error: true`, using
   `cargo-llvm-cov`. Two reports: the default suite, and the default suite
   plus the corpus test (copy the corpus cache step). `--all-targets`,
   `--lcov`, plus HTML; upload both. Confirm spawned-binary tests contribute
   profiles; if not, say so and note the `cargo llvm-cov run` alternative.
2. No threshold. Paste per-file line coverage for `recover.rs`,
   `source.rs`, `image.rs`, the five backends, `carver.rs`, `mcp.rs`, and
   `job.rs` in the PR. Intended policy: per-module ratchet against the
   observed baseline, no global target, a changed-code target near 90
   percent once the baseline is known.
3. A job building and testing on the declared MSRV, `1.75`, with
   `dtolnay/rust-toolchain` pinned by SHA.

### PR 4. Corpus oracle

#### Task 21. Precision and per-file identity

Files: `tests/corpus_test.rs`, `examples/corpus_tool.rs`.

1. `expected/<image>.json` gains, under a new key, the list of expected
   paths recovered on the last recording. The test fails if a previously
   recovered path is missing now, even when aggregate recall is unchanged.
   Record with `UNEARTH_CORPUS_RECORD=1` and commit.
2. Precision: count output files matching no expected file by hash, per
   image. Fail if any is graded `verified` by scan; warn on the rest.
3. Oracle self-test: a unit test in `corpus_test.rs` feeding mock expected
   and recovered trees (one swap, one duplicate hash, one extra `verified`)
   to the measurement functions, asserting each is caught. No images
   needed.

#### Task 22. Zero floors and a control file in fragmented images

Files: `examples/corpus_tool.rs`, `corpus/recipes/*`, `corpus/expected/*`.

A scan floor of 0 (ext4, FAT32 on Linux and macOS, NTFS on Linux, all
`fragmented`) protects nothing. Add to the `fragmented` plan one small
contiguous file deleted last and expected to carve, so those floors become
non-zero. Record each counted file's pre-deletion extent layout in the plan
output where the platform can report it (`filefrag -v` on Linux) so
"fragmented" is a fact, and check the XFS `fragmented` image in particular,
where scan recall of 1 suggests nothing was fragmented. Rebuilding changes
image hashes; follow `corpus/README.md` and publish a new tarball only with
the owner's agreement.

#### Task 23 (needs a Mac). Explain the HFS+ baselines

Undelete recall is 0.86, 0.8, 0.8, 0.8 on `baseline`, `deeptree`,
`longnames`, `nonascii`, and scan recall is 0.8 on `longnames`: one file
missing each time. Run the HFS+ subset, find the missed file per image, and
classify: record absent from live leaf and journal, missed traversal, wrong
bytes, wrong path, name normalisation, or timestamp mismatch. The likely
cause is the last-deleted file whose record was scrubbed from the live leaf
and had not reached the journal; check AppleDouble files too. The
`longnames` scan miss is not a naming issue, since carving ignores names;
compare that file's layout with the others. Fix in `src/hfsplus.rs` and
re-record, or document the cause in `corpus/README.md`. Do not lower a
baseline.

## 6. Verification and PR contents

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all --no-fail-fast
cargo test --release --test corpus_test -- --ignored --nocapture   # PR 1, 2, 4
```

No corpus baseline may drop. If one improves, re-record with
`UNEARTH_CORPUS_RECORD=1` and commit the changed JSON.

Each PR body states: tasks closed; bugs found and fixed in `src/` with the
test that caught each; tasks skipped and why; questions for the owner (tasks
9, 11, 22); the mutation checks performed; the new test count.

## 7. Corrections made during the review, so they are not repeated

- `main.rs` is reached by many spawned-binary tests, not only `cli_test.rs`.
- The write barrier has unit tests; the gaps are end-to-end, symlinks,
  aliases, and collisions.
- Imaging already has fault-injecting mocks; the gaps are resume, the sparse
  path, and map validation.
- `dry_run_test.rs` and `dryrun_test.rs` test different subjects; merge into
  their subject files, do not delete one.
- 27 integration files import `recover`, not 28.
- The corpus does not cover FAT12, FAT16, ext2, ext3, or HFSX.
- A zero recall floor protects nothing; aggregate recall can hide a per-file
  regression.

## 8. On-disk cheat sheet

**ext2/3/4 inode (128 bytes):** `i_mode` 0x00, `i_size` 0x04, `i_dtime`
0x14, `i_links_count` 0x1A, `i_flags` 0x20 (extents `0x80000`), `i_block`
0x28 (60 bytes: with extents, header `0xF30A`, entry count, 12-byte entries;
without, 15 u32 pointers: 12 direct, single, double, triple). Dirent:
`inode` u32, `rec_len` u16, `name_len` u8, `file_type` u8, name.

**jbd2:** every journal block starts with magic `0xC03B3998` and a type:
1 descriptor, 2 commit, 3 and 4 superblock, 5 revoke. Descriptor tags carry
the filesystem block number and flags (`ESCAPE 1`, `SAME_UUID 2`,
`DELETED 4`, `LAST_TAG 8`); the data blocks follow in tag order. Sequence
numbers are u32 and wrap.

**NTFS data run:** header byte, low nibble = length field width, high
nibble = offset field width (0 means sparse). Length unsigned LE; offset
signed LE, relative to the previous run's start. List ends with `0x00`.
Records carry an update-sequence array: the last two bytes of each sector
must equal the sequence number and are replaced by the array's values.

**HFS+ overflow key:** keyLength u16, forkType u8, pad u8, fileID u32,
startBlock u32, big-endian; record is eight (startBlock, blockCount) pairs.
Leaf nodes link forward with `fLink` at offset 0.

**MBR:** entries at 0x1BE, 16 bytes: status, CHS start (3), type, CHS end
(3), LBA start u32, sector count u32. Extended types `0x05`, `0x0F`. In an
EBR, entry 1 is the logical partition (LBA relative to this EBR) and entry 2
links to the next EBR (LBA relative to the extended partition's start);
entry 2 zero ends the chain.

**GPT:** protective MBR at LBA 0; primary header at LBA 1 (`EFI PART`, CRC
0x10, current LBA 0x18, backup LBA 0x20, entries LBA 0x48, count 0x50, size
0x54, entries CRC 0x58). Backup header at the last LBA, entry array just
before it.

**Detect-only magics for task 5:** Minix `0x137F`/`0x138F`/`0x2468`/`0x2478`
u16 at 1024+16; romfs `-rom1fs-` at 0; BeFS `BFS1` at 0x20 within the
superblock at 512; cramfs `0x28CD3D45` u32 at 0; Reiser `ReIsErFs` or
`ReIsEr2Fs` at 64 KiB + 52; XFS `XFSB` at 0; UFS `0x00011954` at 8 KiB +
0x55C; JFS `JFS1` at 32 KiB. Check each module's `is_*` function for the
offset it actually reads before planting.

## 9. Progress (session of 2026-09-06)

Four branches off `main` on the fork, each stacked on the one before, each
verified with `cargo fmt --check`, `cargo clippy --all-targets -D warnings`,
`cargo test --all --no-fail-fast`, and the corpus run. No commit or PR body
carries AI attribution.

| PR | Branch | Tasks | State | Tests |
|---|---|---|---|---|
| [#7](https://github.com/trondegil/file-recover-lib/pull/7) | `testing/extended` | 1 to 6 | open, base `main` | 590 to 622 |
| [#8](https://github.com/trondegil/file-recover-lib/pull/8) | `testing/extended-2` | 7 to 13 | open, base `testing/extended` | 622 to 651 |
| [#9](https://github.com/trondegil/file-recover-lib/pull/9) | `testing/extended-3` | 14 to 20 | open, base `testing/extended-2` | 651 to 673 |
| 4 | `testing/extended-4` | 21, 22 (part), 23 | committed, PR to open | 673 to 675 |

All 23 tasks are closed except the parts of 22 and 23 that need the owner's
decision (below). Corpus: 77 images, no baseline dropped at any step.

### Bugs found and fixed in `src/`, with the test that caught each

1. A symlink planted in the output directory redirected recovered files
   outside it, and a dangling symlink at the target was followed
   (`a_symlinked_parent_inside_the_output_directory_is_not_followed`,
   `a_symlink_at_the_target_path_is_not_written_through`). Fixed by
   `recover::create_output_file`, now the single write site for all six
   backends and the carver.
2. `image src src`, and any hard link, symlink, or relative spelling of the
   source given as image, map, report, checkpoint, or summary path,
   truncated the source (`the_source_path_itself_is_refused_as_a_destination`,
   `an_alias_of_the_source_is_refused_as_a_destination`). Fixed by
   `refuse_writing_onto_source` in `main.rs`.
3. `recover::detect` ignored logical partitions in an MBR extended chain,
   ignored a GPT whose primary header was wiped, and listed a volume twice
   when two entries named one start (`tests/partition_edges_test.rs`).
4. Six detect-only parsers (Minix, romfs, cramfs, BeFS, ReiserFS, JFS)
   accepted a bare magic over random bytes and then claimed the rest of the
   source, hiding a real volume from a lost-volume scan
   (`a_lost_volume_scan_finds_the_real_volume_and_reports_no_garbage`).
5. NTFS counted a data run that ran past the source in full, so the manifest
   claimed a size the file did not have; FAT, exFAT, and ext recorded the
   declared size the same way
   (`a_run_past_the_volume_end_is_not_padded_to_real_size`).
6. NTFS parsed records whose sector tails did not match the update sequence
   number (`a_record_with_mismatched_fixups_is_rejected`).
7. HFS+ assembled a full-size file from the wrong blocks when the overflow
   tree held two records for one logical range
   (`two_overflow_records_for_one_range_do_not_both_get_used`).
8. A carved file whose footer sat exactly at the source end was graded
   `truncated` (`the_carved_set_does_not_depend_on_where_chunk_boundaries_fall`).
9. The ISO-BMFF box walk accepted any four printable bytes as a box type, so
   a real MP4 followed by text was carved to the source end
   (`each_real_sample_is_carved_whole_with_its_grade`).
10. The scan checkpoint reader split `file` lines into six fields where the
    writer emits seven, so every manifest row carried across a resume lost
    its grade and gained it as part of its name
    (`checkpoint_file_lines_round_trip_name_and_grade`,
    `a_resumed_scan_matches_an_uninterrupted_one`).
11. `image --resume` accepted any map with a position, so a map for another
    range or source could keep a wrong prefix or skip bytes
    (`a_map_that_does_not_match_the_run_is_rejected_before_any_write`).
12. The MCP server answered objects with no `jsonrpc` version as requests and
    reported unknown tools in band
    (`protocol_errors_are_coded_and_the_session_continues`).
13. The exFAT bitmap read was bounded by a 256 MiB constant rather than the
    cluster count: a corrupt entry cost 256 MiB of heap on a 24 KiB image
    (`bitmap_read_is_bounded_by_the_cluster_count`).

### Task 23, answered: the HFS+ misses are `.fseventsd`

The missed file is the last one the plan deleted, in every affected image.
Its catalog record is found and it is written under the right name and size,
but its blocks now hold a gzip stream beginning `3SLD`: the `.fseventsd` log
macOS writes at unmount, listing the very deletions the plan made. The log is
allocated into the blocks the last deletion freed, so the data is gone and
the tool's answer is right. `corpus/recipes/macos.sh` now writes
`.fseventsd/no_log` before applying the plan; a rebuilt `macos-hfsplus-baseline`
recovers 7 of 7 and carves 5 of 5. Recorded in `corpus/README.md` under
"Known misses". `src/hfsplus.rs` needed no change.

### Task 22, measured: what a rebuild would give

The `fragmented` plan now overfills the volume and adds `last-small.jpg`,
written after the big files and deleted last, so it lands past their
fragments and can be carved whole. Plans are versioned (`plan_version` in
each expected file) so an old image still regenerates its own file set.
Rebuilt into scratch trees and measured, not published:

| image | scan recall now | with the control file |
|---|---|---|
| linux-ext4-fragmented | 0 | 1 of 5 |
| linux-fat32-fragmented | 0 | 0 of 5 (its own copy fragmented in two) |
| linux-ntfs-fragmented | 0 | 1 of 5 |
| linux-exfat-fragmented | 0.25 | 2 of 5 |
| macos-*-fragmented | 0 to 0.25 | 1 to 2 of 5 |
| linux-xfs-fragmented | 1 | 5 of 5, now genuinely fragmented |

`filefrag` extent counts are recorded per deleted file on Linux, and confirm
the diagnosis for XFS: under the old plan every file had **1 extent**, so
"fragmented" was not fragmented at all. Under the new plan the big files span
2 to 6 extents on every Linux filesystem.

**Blocked on the owner:** rebuilding changes every image hash, so a new
tarball (`corpus/publish.sh corpus-v3`) and a lockfile bump are needed. The
recipe, plan, and tooling changes are in PR 4; the rebuilt images are not.

### Questions for the owner, gathered

1. **ext4 journal policy** (task 9): an uncommitted newer copy of an inode
   block is used, and a later revoke does not withdraw it. Both are pinned as
   tests, not changed. For undelete, using the uncommitted copy is arguably
   right.
2. **A `reassembled` confidence** (task 11): a FAT file whose chain was
   guessed is reported as `named`, the same word an intact chain gets.
   Proposed, not added.
3. **MSRV** (task 20): the committed `Cargo.lock` resolves `clap_lex 1.1.0`,
   which needs edition 2024 (Rust 1.85), so `cargo +1.75 build` fails before
   compiling anything of ours. The CI job is `continue-on-error` with a
   comment. Raise `rust-version`, or pin the dependency?
4. **MCP unknown tools** (task 15) are now a -32602 protocol error per the
   spec rather than an in-band tool error.
5. **Corpus rebuild** (task 22): publish `corpus-v3`?

### Not done

- A footerless JPEG cut by `--max-size` is still not carved at all rather
  than carved and graded `truncated`; the existing regression test pins that
  and was not weakened. Noted in PR 2 as a policy question.
- Per-file coverage numbers: `cargo-llvm-cov` is not installed on this
  machine; the CI job uploads LCOV and HTML and prints the table.
