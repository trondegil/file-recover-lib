# Real-image test corpus

Every other test in this repository runs against disk images that were built
by hand in Rust. Those tests prove the parsers agree with their author. The
corpus proves they agree with the filesystems: each image here was formatted
by a real operating system's own tool, filled with files through that OS's
filesystem driver, and then had a documented subset of those files deleted.
The test measures how many of the deleted files unearth brings back
byte-for-byte.

This is step 1 of [ROADMAP.md](../ROADMAP.md).

## Layout

| Path | In git | What |
|---|---|---|
| `corpus.lock` | yes | Every image: name, source, size, SHA-256, and where its expected results are. Also the release tarball's URL and hash. |
| `expected/<image>.json` | yes | For one image: the deleted files (path, size, SHA-256, whether the data is expected to survive), the image's own size and hash, and the recall baseline. |
| `images/` | no | The images themselves, 64 MiB each. Built locally or downloaded from the release tarball. |
| `work/` | no | Scratch space for the recipes. |
| `recipes/` | yes | The scripts that build the images on each platform. |
| `build.sh`, `publish.sh` | yes | Build for this platform; package and publish a release. |
| `../examples/corpus_tool.rs` | yes | Generates file sets, writes expected results, assembles the lock. |
| `../tests/corpus_test.rs` | yes | The test. |

## How an image is made

1. `corpus_tool plan <scenario> <stage> <plan>` writes a deterministic set of
   files into a staging directory and a plan: an ordered list of `copy`,
   `fill` (a copy that may fail because the volume is full, used to pack it),
   `delete`, `rmdir`, and `sync` operations. The files are real enough for the
   carver: JPEG, PNG, BMP, PDF, and WAV with correct headers, footers, and
   size fields, plus text and raw binary that only undelete can name. Every
   512-byte sector of every file carries a unique stamp, so a recovery that is
   mis-ordered or mis-sized changes the hash, while the images still compress
   well for distribution. Each staged file also gets a distinct modification
   time in March 2024, which the recipes preserve when copying (`cp -p`,
   `Copy-Item`) and the test checks on the recovered file.
2. The platform recipe creates a raw 64 MiB file, formats it with the
   platform's own tool, mounts it, and applies the plan through the ordinary
   filesystem driver: `cp` and `rm` on Unix, `Copy-Item` and `Remove-Item` on
   Windows. `sync` steps make sure data reaches the disk before it is deleted.
3. The recipe unmounts and runs `corpus_tool expect`, which replays the plan to
   find the files whose last operation was a delete, hashes them from the
   staging copy, and writes `expected/<image>.json`.
4. `corpus_tool lock` assembles `corpus.lock` from the expected files.

Deleted files are marked `intact` or `maybe`. `intact` means the data should
still be on disk and the test counts it. `maybe` means the scenario went on to
overwrite it on purpose, so it is recorded but not counted; a recovery is a
bonus and is reported as one.

## Scenarios

Each filesystem gets one image per scenario.

| Scenario | What it exercises |
|---|---|
| `baseline` | Photos and documents in a few folders, a third deleted. |
| `deeptree` | Files at every level of a three-deep tree; one subtree removed recursively. |
| `longnames` | Names from 60 to 200 characters. |
| `nonascii` | Norwegian, German, Japanese, Russian, Greek, Korean, and emoji names. |
| `fragmented` | The volume packed full, every other file deleted, then files bigger than any gap written into the gaps and deleted. |
| `nearlyfull` | Three quarters of the volume filled, every third file deleted. |
| `overwritten` | Two files written, the volume packed full around them, the two deleted, then new data written into the only free space: theirs. A third file deleted after that must still come back whole. |

## Filesystems and where they come from

| Image prefix | Formatted by | Recipe |
|---|---|---|
| `macos-fat32-*`, `macos-exfat-*`, `macos-hfsplus-*` | `diskutil eraseVolume` on a raw image attached with `hdiutil` | `recipes/macos.sh` |
| `linux-ext4-*`, `linux-fat32-*`, `linux-exfat-*` | `mke2fs`, `mkfs.fat`, `mkfs.exfat`, mounted with the kernel driver | `recipes/linux.sh` |
| `linux-ntfs-*` | `mkfs.ntfs` from ntfs-3g, mounted with the kernel `ntfs3` driver. A stopgap until the Windows recipe has been run. | `recipes/linux.sh` |
| `windows-fat32-*`, `windows-exfat-*`, `windows-ntfs-*` | `diskpart` `format` on a fixed VHD | `recipes/windows.ps1` |

Notes on what the platforms do that a synthetic image never would:

- macOS writes an AppleDouble `._name` file next to every file copied to FAT
  and exFAT, and a `.fseventsd` folder at the root. They are left in place
  because real cards have them.
- Linux mounts FAT with `utf8=1`, as desktop automounters do, so non-ASCII
  names land as long-name entries.
- The Windows images are VHDs: a raw disk with an MBR and one partition, plus
  a 512-byte footer that unearth ignores. They are built by the
  `Corpus (Windows)` GitHub Actions workflow on a `windows-latest` runner
  (which runs elevated); download its two artifacts into `corpus/images/`
  and `corpus/expected/`, then regenerate the lock.
- 64 MiB is the smallest FAT32 volume macOS will create.

## Building the images

```sh
corpus/build.sh                                   # this platform's recipe, then the lock
CORPUS_LINUX_TOO=1 corpus/build.sh                # on macOS: also the Linux images via Docker
CORPUS_SCENARIOS=baseline,nonascii corpus/recipes/macos.sh
CORPUS_ONLY=exfat corpus/recipes/linux.sh
```

macOS needs no root. Linux needs root for loop mounts; on any other host, or
with `CORPUS_DOCKER=1`, the Linux recipe re-runs itself in a privileged
`rust:1-bookworm` container. Windows needs an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File corpus\recipes\windows.ps1
```

Rebuilding an image keeps its recorded baseline, so a rebuild that changes
the on-disk layout is caught by the test rather than silently re-baselined.

## Running the test

```sh
cargo test --release --test corpus_test -- --ignored --nocapture
```

The test is marked `#[ignore]` so a plain `cargo test` stays fast; it takes a
minute or two in release mode and far longer in debug. It prints one line per
image:

```
image                              deleted  undelete baseline | carvable      scan baseline   notes
macos-fat32-baseline                     7    7/7    100.0%   |        5    5/5    100.0%
```

`undelete` is how many of the intact-expected deleted files came back with the
right hash by metadata; `scan` is the same for the carvable subset by
signature. Each file recovered by name is also checked for its modification
time: exact to 2 seconds on NTFS, ext4, and HFS+; on FAT and exFAT, which
store local time with no zone, a whole number of quarter hours off (up to 14
hours) is accepted, since the building machine's zone is not recorded. A
time that is wrong beyond that fails the test outright. The test fails if either drops below the image's baseline, if an
image's hash does not match the lock, or if a listed image is missing while
`UNEARTH_CORPUS_REQUIRED=1`. Images that are missing without that flag are
skipped with a notice, so the rest of the suite still runs on a machine with
no corpus.

Record baselines for new images, or ratchet them after an improvement:

```sh
UNEARTH_CORPUS_RECORD=1 cargo test --release --test corpus_test -- --ignored --nocapture
```

Baselines are floors, not targets. A baseline below 100% documents a known
gap (fragmented files on FAT, say); raising it is a feature, and the test
tells you when a run beats the recorded value.

Other switches: `UNEARTH_CORPUS_DIR` points at the images, `UNEARTH_CORPUS_ONLY`
filters by name substring, `UNEARTH_CORPUS_OFFLINE` disables the download.

The CI job runs the corpus on Ubuntu, macOS, and Windows runners, so a
parser that behaves differently on one platform is caught there. The
release workflow also runs `corpus/smoke.sh` with each freshly built
native binary against one image before uploading it.

## Publishing

Images are not in git. They are published as one tarball on a GitHub Release
tagged `corpus-vN`, and `corpus.lock` pins its URL and SHA-256. The test
downloads and unpacks it when `images/` is missing something. CI caches the
directory keyed on the lock file, so a pull request pays the download once.

```sh
corpus/publish.sh corpus-v1
git add corpus/corpus.lock corpus/expected
git commit -m "corpus: publish corpus-v1"
```

Bump the tag whenever an image changes. Old releases stay so that old commits
remain testable.

## Adding a device-made image

Cards formatted by cameras, phones, dashcams, and drones have quirks no
`mkfs` reproduces, and the corpus should have a few. To contribute one:

1. Format the card in the device. Let the device create whatever folders it
   wants.
2. Copy a set of files onto it. Keep a copy of every file in a staging
   directory that mirrors the card's tree.
3. Delete some of them, using the device where possible (the camera's delete
   button, the phone's gallery), and note which.
4. Image the card, read-only: `unearth image /dev/rdiskN corpus/images/<name>.img`.
5. Write a plan file by hand: one `copy\t<path>` line per file you copied, in
   order, then `delete\t<path>\tintact` for each one you deleted.
6. Run `corpus_tool expect` with `--platform device` and a `--source` that
   names the device and its firmware version, then `corpus_tool lock`.
7. Record a baseline and open a pull request with the expected file and the
   lock. The image goes into the next corpus release.

A small card (up to a few hundred MB) keeps the tarball manageable. Trim the
image with `--end` on `unearth image` if the card is large and the data sits
at the front.

## What the corpus has found so far

The first build (September 2026, 49 images from macOS and Linux, then 21
from Windows via the `Corpus (Windows)` workflow) found the following. Every
one had passed the synthetic test suite.

| Finding | Effect on a user | Fix |
|---|---|---|
| Carved PDFs were two bytes too long. The footer allowance for a line ending after `%%EOF` was applied blindly. | Every carved PDF's hash differed from the original, so `verify`-style checks and dedup against undelete results failed. | Only CR/LF bytes are absorbed after the marker. |
| `scan` on an exFAT, NTFS, or HFS+ volume produced one file: the whole volume. The filesystem-image signatures carved it and hid everything inside. | A default scan of any such disk recovered nothing useful. | Filesystem images are a separate `volume` category, left out of the default set and transparent to nested carving. |
| An exFAT up-case table (`00 00 01 00 02 00 ...`) matched the four-byte ICO magic and carved as a 2 MiB icon that swallowed the files behind it. | Scan recall on exFAT dropped to 0 to 20%. | ICO directory entries must have legal plane and bit-depth values and point at DIB or PNG data. |
| An HFS+ journal header matched the TrueType magic and carved as a 42 MiB font. | Scan recall on HFS+ was 0. | The SFNT binary-search fields must match the table count; tags must be printable. |
| HFS+ undelete found nothing on a Mac-formatted disk. macOS rewrites the catalog leaf cleanly, so no stale record survives in free space. | Zero recovery on every Mac disk. | Stale leaf nodes are read from the journal, where the pre-deletion copies live. |
| ext4 undelete found nothing on a Linux-formatted disk. Linux 6.x/7.x zeroes the deleted directory entry, and a deleted inode's empty extent header was being taken as a usable block map. | Zero recovery on every modern Linux disk. | Names are read from journaled directory blocks; an extent header with no entries no longer counts as a map; the newest journaled inode copy is preferred. |
| FAT and exFAT undelete skipped the contents of a folder that had been deleted as a whole. | Every "I deleted the wrong folder" case lost all files. | Deleted directories are descended (FAT: only when the cluster still starts with `.`). |
| NTFS files deleted by the Linux `ntfs3` driver lose their `$FILE_NAME` attribute but keep `$DATA`. | Zero recovery on Linux-written NTFS. | Nameless records are recovered under `_unnamed/` with a content-identified extension. |
| Windows zeroes the high 16 bits of a deleted FAT32 entry's start cluster. On a volume with more than 65,536 clusters (any card over about 32 MB at 512-byte clusters, or 256 GB at 4 KiB) every deleted file past cluster 65,535 was read from the wrong place. | Wrong bytes for a third of the deleted files on a Windows-formatted card. | The cluster is found again among the free candidates: a `.` entry naming itself for a folder, the content's identified type for a file, then the longest free run. |
| Windows frees a deleted folder's cluster without writing back the deletion markers of the files it just removed, so they still look live. | Nothing under a folder deleted on Windows came back, on FAT32 and exFAT. | Everything under a deleted folder counts as deleted. |
| Windows stores an all-lowercase 8.3 name without a long-name entry, flagging the case in a reserved byte. | `jpg-000.jpg` came back as `_PG-000.JPG`. | The case flags are honoured. |

Known gaps the baselines document rather than hide:

- FAT and exFAT undelete assume contiguous files, so the `fragmented`
  scenario recovers one of four (the contiguous control). This is item 1 of
  roadmap step 5.
- ext4 scan recall on `fragmented` is 0 and undelete is now 4 of 4: carving
  cannot reassemble fragments, metadata can.
- HFS+ names come back in the decomposed Unicode form the catalog stores
  (`Å` as `A` plus a combining ring), so the `nonascii` name match is 1 of 5
  even though the contents are 4 of 5.
- The `overwritten` scenario's two victims are recovered on most images
  because the allocator did not actually reuse their clusters; they are
  reported as bonuses, not counted.
- No device-made images have been collected yet.
