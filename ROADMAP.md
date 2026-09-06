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
`corpus/README.md`. Seventy-seven images exist, seven scenarios each for
FAT32, exFAT, and HFS+ from macOS, for ext4, FAT32, exFAT, NTFS, and XFS
from Linux, and for FAT32, exFAT, and NTFS from Windows (built by the
`Corpus (Windows)` workflow). They are published as release `corpus-v3`,
pinned in `corpus/corpus.lock`, and run in CI on Ubuntu, macOS, and Windows
on every push. The corpus found eleven real bugs on its first runs, all
fixed; the table in that README lists them. Still open: no device-made
images have been collected (item 3), which needs a camera, a phone, and a
dashcam or drone card in hand.

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

Status (September 2026). Items 2 through 7 are in place: the JSON parser
refuses nesting past 128 levels; custom carver specs are borrowed for one
scan instead of leaked; every recovered path passes a write barrier;
`cargo audit` runs in CI (two advisories cleared by dependency updates)
and every action is pinned to a commit; the 2 TB run is measured in
PERFORMANCE.md (and made 5.5 times faster on empty space by skipping zero
runs); and `corpus/badmedia.sh` images a device-mapper `error` device and
checks the map against the injected ranges. Item 1 is set up (six
cargo-fuzz targets, a nightly workflow, and a regression harness that
replays kept crashers) and found two crashes in its first minute, both
fixed. Its "a week of fuzzing finds nothing new" criterion is a matter of
letting the nightly job run; `dm-flakey` is not available in Docker, so
intermittent (as opposed to hard) read failures are not yet exercised.

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

Status (September 2026). Done. The matrix is a table in `recover.rs` that
every `Volume` variant must map to (a new filesystem does not compile
without a row); `unearth info --features` prints it as text, Markdown, or
JSON; the README carries the Markdown copy between markers and a test
fails if it drifts; the corpus test fails if any "yes" under undelete has no
image with a recorded undelete baseline. `undelete` on a detect-only source
names the filesystem, points at `scan`, and exits non-zero. Every carved
file is graded `verified`, `plausible`, or `truncated` in the manifests, the
MCP result, and the end-of-run summary. The README opens with the
four-step guide, and the four writing commands refuse an output directory
on the device being read when they can tell (a device source whose
filesystem holds the output).

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

Status (September 2026). Item 1, first approach, is in: a deleted FAT or
exFAT file is read from its start cluster skipping clusters the FAT or
bitmap still shows allocated to live files, and follows the allocator's
wrap to the first free gap once. On the corpus's `fragmented` images that
took FAT32 from 1 of 4 to 3 of 4 (Linux) and 2 of 4 (macOS, Windows);
exFAT on Linux and Windows was already 4 of 4 because their drivers leave
the chain intact, and macOS exFAT stays at 1 of 4. What remains is the
second approach: the misses are files whose next free cluster belonged to
a neighbour deleted *after* them (or to their own deleted AppleDouble
companion on macOS), which no allocation map can attribute, so only
format-aware validation of each candidate cluster (JPEG first) can settle
them. The JPEG half of that second approach is in: while reassembling a
`.jpg`, each candidate cluster is checked against JPEG structure (marker
segments, then the entropy-coded rule that `FF` may only precede `00`, a
restart marker, `D9`, or a legal segment marker), and a cluster that fails
is stepped over. It rejects foreign data that carries `FF` bytes; it cannot
reject zero-filled remnants, which is what the corpus's remaining misses
are, so the corpus numbers did not move. PDF and PNG have no cheap
per-cluster test. Item 2: fragmented-file, decoy, and Windows-behaviour
integration tests, plus unit tests for FAT and exFAT directory parsing.
Item 3: XFS images were added to the corpus and settle the question the
wrong way: a current kernel zeroes a freed inode entirely, so there is no
inode-table undelete to build; names survive in directory blocks and the
data map would have to come from the XFS log, a parser of its own. UFS and
JFS were not examined. Items 4 to 6 are untouched.

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

Status (September 2026). The app lives in its own repository,
`trondegil/file-recovery-app`, and every line of app code stays there; this
engine is a git dependency of it. Item 1 was decided against Tauri: the
shell is Slint, Rust-native with no web view, one binary per platform, in
the Cupertino widget style on macOS (Fluent on Windows, Cosmic on Linux) on
the system palette so it follows dark mode. Items 2 to 5 and 7 are in
place: the five screens in order; imaging pushed first and resumable;
elevation only when a raw drive is opened, with the platform's own action
(the Full Disk Access pane on macOS, a UAC relaunch on Windows, `pkexec` on
Linux); a destination on the source drive refused, the system drive warned
about, and a close mid-image turned into a cancel; the review screen shows
the confidence grade and image previews and the restored files carry the
CLI's manifest; and the app adds no recovery logic, only the flow. Item 6
is half done: `cargo-packager` metadata and an `Installers` workflow build
unsigned `.dmg`, NSIS, `.deb`, and AppImage artifacts, while signing and
notarising wait for the Apple Developer ID and Windows code-signing
certificates. Not done: the "three people" test.

## Step 7. Run it like a product

Goal. Users can rely on releases, report problems, and know what changed.

What to do.

1. Keep the release-please flow that is already in place, and extend it so a
   release is blocked unless the corpus test, the three-platform suite, and
   the release smoke test all pass.
2. Make the commit convention enforceable rather than assumed. release-please
   parses the Conventional Commit subjects of the commits *inside* a pull
   request and ignores merge-commit subjects (`RELEASING.md`), so a branch
   whose commits carry no `fix:`, `feat:`, or `perf:` prefix produces no
   changelog entry and no version bump however much it changes. Nothing
   currently caught that: `CONTRIBUTING.md` did not mention the convention
   and no check rejected a commit that does not parse. Both now exist: a
   *Commit messages* section in `CONTRIBUTING.md`, and a `commit-messages`
   CI job running `.github/check-commit-messages.sh` over a pull request's
   own commits. What remains is the outstanding case that prompted it. The
   extended-testing series (PRs 7 to 10) fixes thirteen bugs under four
   non-conforming subjects, among them recovered files escaping the output
   directory through a planted symlink and `unearth image <src> <src>`
   truncating the source. Reword those four subjects, or fold the fixes into
   the changelog's Unreleased section by hand; either way a user reading the
   release notes should learn that those two bugs existed and are gone. The
   CI job is `continue-on-error` until then, since those very branches fail
   it; drop that line once they are dealt with and the check becomes a gate.
3. Publish a security policy (`SECURITY.md`) with a contact address and a
   promise on response time. A recovery tool reads the most private data a
   person owns.
4. Produce a software bill of materials with each release and sign the
   binaries and checksums. Users can then verify what they downloaded.
5. Keep a support matrix of tested OS versions per release, and drop
   versions deliberately rather than by accident.
6. Write the "what to do when it fails" document. Which log to attach, how to
   share an image safely (a metadata-only dump the tool can produce, without
   file contents), and what the maintainers can and cannot do with it.
7. Decide the sustainability model early. Half the current commit history is
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
