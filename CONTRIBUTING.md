# Contributing

Thanks for helping improve `unearth`. This guide covers the development
workflow and the most common contribution: teaching the carver a new file type.

## Development workflow

```sh
cargo fmt                                   # format
cargo clippy --all-targets -- -D warnings   # lint (warnings are errors in CI)
cargo test                                  # unit + integration tests
```

CI (`.github/workflows/ci.yml`) runs all three; please make sure they pass
locally before opening a PR. A change to a filesystem parser or the carver
should also be run against the real-image corpus (`corpus/README.md`):

```sh
cargo test --release --test corpus_test -- --ignored --nocapture
``` See [ARCHITECTURE.md](ARCHITECTURE.md) for the
module map and [PERFORMANCE.md](PERFORMANCE.md) for the heap-profiling harness.

A few conventions the codebase holds to (see *Robustness conventions* in
ARCHITECTURE.md):

- The source is **read-only** — never write back to the device/image.
- Any offset or size derived from on-disk data uses `saturating_add` /
  `saturating_mul`, and every read is bounds-checked. Parsers must return
  `Ok`/`Err`, never panic, on malformed input (`tests/robustness_test.rs`
  fuzzes this).
- Bound allocations by real limits; never trust an on-disk length as a `Vec`
  capacity.

## Commit messages

Releases are automated, and the automation reads the commits. release-please
parses the subject of every commit **inside** a pull request (merge-commit
subjects are ignored) and builds the next version and its changelog section
from them, so a subject that does not parse is a change no user will ever read
about. CI checks this on every pull request.

Write each subject as `type(scope)?: description`, with the type from this
list:

| Type | Effect on the next release |
|---|---|
| `fix`, `perf` | patch bump, entry in the changelog |
| `feat` | minor bump, entry in the changelog |
| any of the above with `!`, or a `BREAKING CHANGE:` footer | major bump |
| `docs`, `test`, `ci`, `build`, `chore`, `refactor`, `style`, `revert`, `corpus` | no release on their own |

The scope is optional and names the area, not the type: `fix(carver): …`,
not `carver: …`. A bug a user could have hit needs `fix:`, however small the
diff; that is what puts it in the release notes. See
[RELEASING.md](RELEASING.md) for the rest of the release flow.

## Adding a file-type signature (carving)

Carving recognises a file by a **magic** at its start, then computes its length
with an **extent strategy**. Adding a type is usually three small steps plus a
test.

### 1. Add a `Signature` to the table

Append an entry to `SIGNATURES` in [`src/signatures.rs`](src/signatures.rs):

```rust
Signature {
    name: "My format",
    ext: "myf",
    magic: b"MYF\0",          // bytes at the start of the file
    magic_offset: 0,          // where the magic sits relative to the file start
    secondary: None,          // Some((offset, tag)) to disambiguate shared magics
    extent: Extent::Footer { marker: b"MYEND", trailing: 0 },
    max_size: 100 * MB,       // hard cap if the end marker is missing/corrupt
},
```

- Use `secondary` when several formats share a magic (e.g. RIFF → WAV/AVI/WEBP,
  or ISO-BMFF `ftyp` brands). More specific entries must come **before** the
  generic fallback for the same magic.
- `magic_offset` is non-zero only when the magic isn't at byte 0 (e.g. MP4's
  `ftyp` is 4 bytes in).

### 2. Pick (or add) an extent strategy

Reuse an existing `Extent` if one fits:

| Strategy | Use when the length is… |
|----------|--------------------------|
| `Footer { marker, trailing }` | terminated by a trailing marker (JPEG, PNG, PDF, ZIP) |
| `HeaderSizeLe32 { offset }`   | a little-endian `u32` size field in the header (BMP, CAB) |
| `RiffSize`                    | a RIFF container size at offset 4 |
| `Sqlite` / `SevenZip`         | computed from header fields |
| `Mp4Atoms`                    | an ISO base-media box/atom structure (MP4, HEIC, AVIF, 3GP) |
| `Tiff` / `Ebml` / `Ogg` / `Asf` / `Elf` / `Pe` | a structured container/header walk |

If none fit, add a new `Extent` variant and handle it in `file_length` in
[`src/carver.rs`](src/carver.rs) with a `*_length(source, file_start, limit)`
helper. Keep it bounds-checked and saturating, and return `None` when the
structure isn't valid so a coincidental magic carves nothing.

### 3. (Optional) Add a validator

If the magic is short or common, add a structural check in
[`src/validate.rs`](src/validate.rs) keyed on `sig.ext`. Validators are
**conservative**: return `Validity::Invalid` only on a definite violation, and
`Validity::Unknown` (accepted) when unsure, so a real file is never dropped.

### 4. Add a test

Hand-build a minimal file and assert byte-for-byte recovery. Put image/raw and
container formats alongside the others in
[`tests/more_signatures_test.rs`](tests/more_signatures_test.rs); the
`carve_one(&bytes, "ext")` helper carves a single planted file and returns it.
Use a filler that can't contain stray magics (the `% 251` ascending pattern the
tests use avoids `0xFF` and accidental footers). New types are also worth adding
to the end-to-end `tests/kitchen_sink_test.rs` when they exercise a new extent
strategy.

`unearth list-types` prints the table, so no extra wiring is needed for the
CLI.

## Adding filesystem support (undelete)

Each backend (`fat`, `exfat`, `ntfs`, `ext4`) exposes the same shape —
`Volume::parse(src, offset)` and `Volume::recover_deleted(src, out, opts)` — and
is wired into `recover::Volume` and `recover::try_parse_volume`. Recovered files
are written through `hash::HashingWriter` so the manifest gets a SHA-256. Build
fixtures by hand in `tests/common/` (no `mkfs` needed) and assert byte-for-byte
recovery.
