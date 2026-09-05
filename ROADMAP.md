# Roadmap: from promising engine to production recovery tool

This is the plan for turning unearth into a recovery tool you can hand to
someone whose only copy of their photos just vanished. It is written for a
skilled user as well as for the people who will implement it. Each step says
what to do, why it matters, and how you know it is finished.

The order matters. Steps 1 and 2 come before any new features. There is no
point adding filesystems to a tool nobody has yet run against a real disk.

## Where the project stands today

An audit in September 2026 found the code clean, careful, and well shaped.
There is no unsafe code, no network access, the source disk is only ever
opened read-only, and 547 tests pass. Signature carving of about 150 formats
works, and metadata undelete works for FAT, exFAT, NTFS, ext2/3/4, and HFS+.

Three gaps stand between that and something you would trust with a client's
data.

First, every test image was built by hand in Rust. No test has ever seen a
disk formatted by Windows, macOS, Linux, a camera, or a phone. The parsers
agree with the author's understanding of each format, which is not the same
as agreeing with the format.

Second, the tool is only tested on Linux. Windows and macOS binaries are
cross-compiled and shipped, but nobody runs the test suite there, and opening
a raw disk on Windows has never been exercised.

Third, the feature list is wider than the implementation. Around 30
filesystems are recognised, but 23 of them return nothing from undelete. The
README says so in its Limitations section, which is honest, but a user
reading the headline will expect more.

The plan below closes those gaps in that order, then extends the tool.

## Step 1. Build a real-image test corpus

Goal. Prove the parsers work on disks made by real operating systems, and
catch regressions automatically from then on.

Why first. This is the single largest source of risk. A synthetic test can
only fail in ways its author imagined. A disk formatted by Windows 11, filled
with files, and then partly deleted, fails in the ways that actually happen.

What to do.

1. Write a corpus recipe for each supported filesystem. A recipe is a
   script that, on the native OS, creates a small image (16 to 256 MB),
   formats it with the platform's own tool, copies in a known set of files,
   deletes a documented subset, and records the SHA-256 of every file that
   was deleted. Native tools mean `format` and `diskpart` on Windows,
   `diskutil` and `hdiutil` on macOS, and `mkfs.*` and `mtools` on Linux.
2. Cover the scenarios users actually hit, beyond the happy path. For each
   filesystem, include images with fragmented files, long filenames, non-ASCII
   filenames, a nearly full volume, a file deleted then partly overwritten,
   and a folder tree three levels deep.
3. Add a few images made by devices rather than computers. A camera-formatted
   SD card, a phone-formatted USB stick, and a card from a dashcam or drone
   have quirks that no `mkfs` reproduces. These can be collected by hand once
   and kept.
4. Store the images outside git. They are large and binary. Publish them as a
   versioned tarball on a GitHub Release or an object store, with a
   `corpus.lock` file in the repo listing each image's name, source, size, and
   SHA-256, plus the expected recovery results as JSON.
5. Write one integration test that downloads the corpus if missing, runs
   `undelete` and `scan` on every image, and compares recovered file hashes
   against the expected results. Report per-image recall (how many of the
   deleted files came back intact) rather than pass or fail alone, so a
   regression from 96 percent to 90 percent is visible.
6. Run this in CI on every pull request, cached so it adds under two minutes.

Done when. The corpus has at least three images per supported filesystem
from native tools, at least three device-made images, and CI fails if recall
on any image drops. Also done when the first real bug the corpus finds is
fixed. There will be one.

Status (September 2026). Items 1, 2, 4, 5, and 6 are in place: see
`corpus/README.md`. Seventy images exist, seven scenarios each for FAT32,
exFAT, and HFS+ from macOS, for ext4, FAT32, exFAT, and NTFS from Linux, and
for FAT32, exFAT, and NTFS from Windows (built by the `Corpus (Windows)`
workflow). The corpus found eleven real bugs on its first runs, all fixed;
the table in that README lists them. Still open: no device-made images have
been collected (item 3), and the tarball has not yet been published
(`corpus/publish.sh`), so the CI job skips until it is.

## Step 2. Make cross-platform true on real machines

Goal. The tool behaves the same on Windows, macOS, and Linux, including when
pointed at a physical drive.

What to do.

1. Add Windows and macOS runners to CI and run the full test suite on all
   three. Today the suite runs only on Ubuntu. Cross-compiling a binary
   proves it links, not that it works.
2. Fix positioned reads on Windows. The Unix path uses `read_at`; the
   fallback for other platforms clones the file handle and seeks on every
   call, which is correct but slow on a large disk. Use `seek_read` from
   `std::os::windows::fs::FileExt` instead.
3. Open raw devices on each platform and document how. On Windows that is
   `\\.\PhysicalDrive0` or `\\.\D:`, which needs administrator rights and,
   for a mounted volume, may need the volume locked or dismounted first. On
   macOS the raw device is `/dev/rdisk2` (the `r` matters for speed) and
   needs Full Disk Access or `sudo`. On Linux it is `/dev/sdb` and needs
   root or membership in the `disk` group. The tool should detect a
   permission failure and print the fix for that platform rather than a bare
   "permission denied".
4. Handle device size on each platform. Block devices report zero length from
   `metadata()`, and the current fallback seeks to the end. Verify that
   works on Windows physical drives and macOS raw disks; use the platform
   ioctl if it does not.
5. Verify timestamp restoration on each platform. Recovered files should keep
   their original modification time. Right now failures are ignored
   silently, which is fine, but the test corpus should assert the times
   actually landed.
6. Check filename handling for each target. Windows forbids characters like
   `:` and `?` and names like `CON`; the current sanitizer only strips
   slashes and control characters. A file recovered from an ext4 disk named
   `report:final?.txt` must still be writable on Windows.
7. Add a release smoke test. After the release workflow builds each binary,
   run it against one small corpus image on that same runner and check the
   output hashes. A binary that builds but crashes on start should never
   reach a Release page.

Done when. CI is green on three operating systems, the corpus test passes on
all three, and a physical USB stick has been recovered end to end on each
platform by a human following only the README.

Status (September 2026). Items 1, 2, 3, 4, 6, and 7 are in place: the suite
and the corpus test run on Ubuntu, macOS, and Windows in CI; positioned
reads use `seek_read` on Windows; a device that refuses `SEEK_END` has its
size probed by reading; a permission failure prints the fix for the
platform; recovered names are made Windows-safe on Windows; and the release
workflow recovers a corpus image with each native binary before uploading
it (`corpus/smoke.sh`). Item 5 is in place too: every corpus file is staged
with a distinct modification time, and the corpus test checks each file
recovered by name for it on all three platforms (exact on NTFS, ext4, and
HFS+; to a whole number of quarter hours on FAT and exFAT, which store local
time with no zone).

OUTSTANDING (deferred, September 2026): the human end-to-end run with a
physical USB stick on each of the three platforms, following only the
README. No CI can stand in for it. Until it is done, Step 2 is not closed
and the raw-device paths (`/dev/rdiskN`, `\\.\PhysicalDriveN`) have been
exercised only by their unit tests, not by a real disk.

## Step 3. Harden the engine

Goal. The tool never crashes, never runs away, and never writes where it
should not, even on hostile or badly damaged input.

What to do.

1. Add continuous fuzzing with `cargo-fuzz`. The existing robustness test
   feeds random bytes through the parsers once; a fuzzer does the same for
   hours and keeps the inputs that crash. Target each filesystem parser, the
   carver's per-format length logic, and the JSON parser used by the MCP
   server. Run it nightly in CI and keep the corpus of found crashers as
   regression tests.
2. Fix the JSON parser's unbounded recursion. A request nested a few thousand
   levels deep will overflow the stack and kill the MCP server. Add a depth
   limit of 128 and return a parse error past it.
3. Stop leaking custom carver specs. Each custom carver passed to the MCP
   `scan` tool is leaked to get a `'static` lifetime. A long-running agent
   session that starts many scans will grow without bound. Store custom
   signatures in an `Arc` and let them drop with the scan.
4. Set a dependency policy. Run `cargo audit` in CI and fail on
   vulnerabilities. Pin GitHub Actions to commit hashes rather than tags.
   Keep the dependency count small; the current 115 crates are nearly all
   from the dev-only benchmark tooling, and the release binary should stay
   close to the five direct dependencies it has now.
5. Add a write barrier. Every output path the tool creates should be checked
   to resolve inside the chosen output directory after joining, as a second
   line of defence behind the per-component sanitizers. This is cheap and
   turns a future sanitizer bug into a refused write rather than a file
   outside the folder.
6. Test on large sources. Run `scan` and `image` against a 2 TB disk image
   (sparse, mostly zeros, with files scattered through it) and confirm memory
   stays flat, progress is accurate, resume works after a kill, and the run
   finishes in a time proportional to disk read speed.
7. Test on bad media. The imaging module retries bad sectors and records
   holes. Validate it against a device that actually returns read errors. A
   USB stick with a damaged flash chip, or a Linux `dm-error` or `dm-flakey`
   target, gives reproducible failures.

Done when. A week of fuzzing finds nothing new, the 2 TB run is measured and
recorded in PERFORMANCE.md, and imaging a flaky device produces a map file
that matches the errors injected.

## Step 4. Say exactly what the tool can do

Goal. A user can tell, before running anything, whether their situation is
one the tool handles.

What to do.

1. Publish a feature matrix in the README and in `unearth info` output. One
   row per filesystem, with columns for detect, list volumes, undelete, and
   handles fragmentation, each marked yes, partial, or no. Today APFS, Btrfs,
   XFS, ReFS, and 19 others are detect-only, and a user should see that in
   one glance rather than in paragraph twelve of the Limitations section.
2. Make `undelete` on a detect-only filesystem say so and suggest `scan`,
   with a non-zero exit code. Returning zero files recovered and exit code
   zero looks like "there was nothing to recover", which is the wrong
   message.
3. Report confidence with results. A carved file with a validated header and
   a matching footer is a strong recovery; a file cut at `max_size` because
   no footer was found is a guess. Mark each recovered file in the manifest
   as `verified`, `plausible`, or `truncated`, and show the counts at the
   end of a run.
4. Write a short recovery guide for end users. Stop using the drive. Image
   it first with `unearth image`. Run undelete on the image, then scan for
   what undelete could not find. Never write recovered files to the drive
   you are recovering from. The tool should refuse the last one outright when
   it can detect it.

Done when. The matrix exists, is generated from code rather than maintained
by hand, and the corpus test in Step 1 checks that every "yes" cell has at
least one passing real image behind it.

## Step 5. Extend recovery where it pays off

Goal. Raise the recovery rate on the disks people actually bring in. Ordered
by how often the case shows up in practice.

What to do.

1. Fragmented files on FAT and exFAT. These are the filesystems on every
   camera card and USB stick, and video files on them fragment constantly.
   Today the tool assumes each file is contiguous. Two approaches, both
   worth doing. First, use the FAT itself: on a deleted file the chain is
   cleared, but the surviving cluster allocations of other files tell you
   which clusters are not the file's, so a gap-skipping reconstruction beats
   a straight run. Second, for the big formats (JPEG, MP4, MOV) use the
   format's own structure to validate each candidate next cluster.
2. exFAT and FAT test depth. exFAT has zero unit tests and one integration
   file. Bring both up to the level of NTFS and ext4 before extending them.
3. XFS, UFS, and JFS undelete. Unlike APFS and Btrfs, these keep inodes in
   place after deletion, so metadata recovery is possible and the detection
   code already parses the superblocks. XFS is the one that matters; it is
   the default on Red Hat and several NAS products.
4. APFS and Btrfs through snapshots and old checkpoints. Copy-on-write means
   deleted metadata is not scavengeable from the live tree, but older
   checkpoints (APFS) and older tree roots (Btrfs) often survive on disk for
   a while. Walking back through them recovers whole files with names. This
   is harder than the rest of the list but is what modern Macs and many
   Linux desktops use.
5. More carvers, driven by samples. Adopt the rule from the custom-carver
   skill for built-in carvers too: no format ships without a real sample file
   whose exact length the carver reproduces. Add RAW camera formats (CR3,
   ARW, NEF, DNG), HEIC, and the Office formats as full validators, since
   those are what people lose.
6. Encrypted volumes with a known key. BitLocker and LUKS are detected but
   not opened. A user who has their recovery key should be able to hand it
   to the tool and recover from the decrypted view. This is well specified
   for both and keeps the read-only guarantee.

Done when. Each item has corpus images demonstrating the new capability and
the feature matrix updates from "no" or "partial" to "yes".

## Step 6. Build the end-user application

Goal. A person who has never opened a terminal can recover their files.

The library core is already separate from the CLI, which makes this
tractable. Build the app on the library, not by shelling out to the binary.

What to do.

1. Choose the shell. Tauri is the natural fit: Rust backend, native webview,
   installers for all three platforms, small download. The recovery engine
   runs in-process and streams progress to the UI. An Electron shell would
   work but would triple the download for no gain.
2. Design a guided flow, not a dashboard. Pick a drive. Image it first (the
   app should push hard for this and explain why in one sentence). Choose a
   destination on a different drive. Scan. Review results grouped by type
   with thumbnails for images and previews for documents. Restore selected
   files. Five screens, in that order.
3. Require elevation only when needed, and explain it. On macOS request Full
   Disk Access and show the exact System Settings path. On Windows request
   administrator at the moment the user picks a physical drive, not at
   launch. On Linux use polkit rather than telling people to run the whole
   app as root.
4. Refuse dangerous choices. Writing recovered files onto the source drive,
   scanning the drive the app itself is running from, and closing the app
   mid-image should all get a clear warning, and the first should be blocked.
5. Make results reviewable. Show the confidence marker from Step 4 on every
   file, let the user preview before restoring, and write the same manifest
   the CLI writes so `verify` works on the output later.
6. Package and sign. Notarised `.dmg` for macOS, signed MSI for Windows,
   AppImage and `.deb` for Linux. An unsigned recovery tool gets blocked or
   distrusted by exactly the users who need it most. Budget for the Apple
   Developer and Windows code-signing certificates from the start.
7. Keep the CLI and the MCP server as first-class entry points. Power users
   and agents will keep using them, and they exercise the same library, so
   every app feature should exist in the CLI first.

Done when. Three people who have never used the CLI recover files from a
test USB stick on their own laptops, one per platform, without help.

## Step 7. Run it like a product

Goal. Users can rely on releases, report problems, and know what changed.

What to do.

1. Keep the release-please flow that is already in place, and extend it so a
   release is blocked unless the corpus test, the three-platform suite, and
   the release smoke test all pass.
2. Publish a security policy (`SECURITY.md`) with a contact address and a
   promise on response time. A recovery tool reads the most private data a
   person owns.
3. Produce a software bill of materials with each release and sign the
   binaries and checksums. Users can then verify what they downloaded.
4. Keep a support matrix of tested OS versions per release, and drop
   versions deliberately rather than by accident.
5. Write the "what to do when it fails" document. Which log to attach, how to
   share an image safely (a metadata-only dump the tool can produce, without
   file contents), and what the maintainers can and cannot do with it.
6. Decide the sustainability model early. Half the current commit history is
   AI-assisted and the whole thing was written in about three weeks by one
   person. That is a strength for speed and a risk for continuity. Whether
   that means a second maintainer, a company behind it, or a paid app tier
   funding the open engine, decide it before Step 6 ships, not after.

Done when. Two consecutive releases go out on the automated path with no
manual steps, and the first external bug report is handled through the
documented process.

## Rough sequencing

Steps 1 and 2 can run in parallel and should come first. Together they are a
few weeks of work and change what you know about the tool more than anything
else on this list.

Step 3 overlaps with the second half of Step 2. Step 4 is small and can be
done any time after Step 1 produces numbers.

Step 5 is where most of the calendar time goes, and its items are independent
enough to pick by demand.

Step 6 should not start until Steps 1 through 4 are done. A polished
interface on an engine with unknown real-world recall is how recovery tools
earn bad reviews.

Step 7 starts the day Step 6 has a first build.
