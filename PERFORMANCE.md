# Performance & memory profiling

The recovery engines are I/O-bound, but careless per-file allocation can dominate
runtime and memory. This project ships two complementary harnesses, mirroring the
.NET tooling pair:

- **Benchmarks** ([`criterion`](https://docs.rs/criterion), the BenchmarkDotNet
  analogue) — statistical timing of the hot paths.
- **Heap profiling** ([`dhat`](https://docs.rs/dhat), the dotMemory analogue) —
  allocation totals/peaks and call sites.

## Benchmarks (`cargo bench`)

```sh
cargo bench
```

The `benches/recovery.rs` suite measures SHA-256 hashing, signature carving,
content identification, and filesystem undelete. Criterion warms up, collects
many samples, and reports mean/median/std-dev with outlier detection; the
throughput-annotated benchmarks also print MiB/s. It is console-only (no
plotting dependencies). To iterate quickly, shorten the run:

```sh
cargo bench --bench recovery -- --sample-size 10 --measurement-time 1
```

Indicative results (debug-host, relative numbers — use your own machine as the
baseline):

| Benchmark              | What it measures                          |
|------------------------|-------------------------------------------|
| `hash/sha256_1MiB`     | hashing throughput (dedup / manifests)    |
| `carve/all_signatures` | end-to-end carving throughput (MiB/s)     |
| `identify/jpeg`        | content type-detection latency            |
| `undelete/ext_one_file`| filesystem undelete latency               |

Criterion saves each run under `target/criterion/` and compares against the
previous run, so a regression shows up as a "change" line on the next `cargo
bench`.

### What benchmarking found (and fixed)

The first run flagged SHA-256 as the main CPU cost — and because the carver
hashes every recovered file for the manifest, it also caps carving throughput.
Two changes to `hash.rs`: the block compression now runs as **64 fully unrolled
rounds** (the eight working words stay in registers instead of being shuffled
every iteration), and whole blocks are compressed **straight from the input**
(no per-block copy). Result: SHA-256 ~219 → ~230 MiB/s, and end-to-end carving
~12% faster on the small-file workload.

Beyond this, scalar SHA-256 is limited by its inherent per-round dependency
chain; materially higher throughput would need SHA-NI hardware intrinsics, which
the portable, `unsafe`-free design intentionally avoids.

## Running the profiler

The [`dhat`](https://docs.rs/dhat) heap profiler is wired in behind the optional
`dhat-heap` feature and driven by the `heap_profile` example:

```sh
cargo run --profile profiling --features dhat-heap --example heap_profile
```

It runs a representative workload (carving a ~12 MiB image of many small JPEGs,
then an ext4 undelete pass) and on exit prints allocation totals/peaks to stderr
and writes `dhat-heap.json`. Open that file in the
[dhat viewer](https://nnethercote.github.io/dh_view/dh_view.html) to drill into
the allocation call sites — peak/total bytes, block counts, and where each came
from, just like a memory-profiler snapshot.

Without the feature the example simply runs the workload (and prints carving
throughput), which is handy as a quick timing check:

```sh
cargo run --release --example heap_profile
```

## What profiling found (and fixed)

The first run flagged enormous transient allocation: the carver allocated a fixed
**4 MiB** copy buffer for every recovered file and a **1 MiB** buffer for every
footer search. On the small-file workload that meant ~1 GB of churn to process
~12 MiB.

The fix was to size those buffers to the actual file and **reuse** them across
the whole carving run instead of allocating per file.

| Metric (same workload)     | Before    | After    | Change       |
|----------------------------|-----------|----------|--------------|
| Total bytes allocated      | 1.12 GB   | 72 MB    | **~15× less** |
| Allocation blocks          | 2,937     | 2,537    | fewer        |
| Carving throughput         | 69 MiB/s  | 103 MiB/s| ~1.5× faster |
| Peak heap                  | 25.7 MB   | 22.6 MB  | lower        |

Peak memory is now dominated by the single 8 MiB sequential scan buffer, which is
intentional and independent of how many files are recovered.

### Recovery backends

A second pass profiled the `undelete` path. The NTFS backend read **every MFT
record** through a helper that allocated a fresh 1 MiB temp buffer per call, so
scanning the MFT churned ~1 MiB per record. The fix reads each record straight
into its output buffer, and the FAT/exFAT/NTFS per-file copy buffers are now
sized to the file (capped at 1 MiB).

Workload: carve (as above) **plus** an NTFS volume with 90 deleted files.

| Metric                | Before  | After  | Change        |
|-----------------------|---------|--------|---------------|
| Total bytes allocated | 200 MB  | 72 MB  | **~2.8× less** |
| NTFS undelete time    | 15.7 ms | 6.5 ms | ~2.4× faster  |

The ~128 MB difference is exactly the per-record temp buffers that no longer
exist.

### ext4 read path

A third pass profiled the ext4 backend. Reconstructing a recovered file walked
its block map and allocated a **fresh `Vec` per block** (`read_block`), copying
each block into the output — so a 2 MiB file churned ~2,000 short-lived
allocations. The fix reads each block straight into the output buffer (sparse
holes stay zero-filled), and the jbd2 journal scan now reuses a single block
buffer instead of allocating one per journal block.

Workload: carve (as above) plus an ext4 volume with a 2 MiB deleted file.

| Metric                | Before  | After  | Change        |
|-----------------------|---------|--------|---------------|
| Total bytes allocated | 78.7 MB | 76.6 MB| ~2 MB less    |
| Allocation blocks     | 6,883   | 4,834  | ~2,000 fewer  |
| ext undelete time     | 11.2 ms | 3.2 ms | ~3.5× faster  |

The byte saving is one avoided copy of the file; the bigger win is eliminating
the per-block allocation traffic, which is what drives the ~3.5× speedup.

## Large and damaged sources (roadmap step 3)

Measured in September 2026 on an M-series MacBook with a release build.

### A 2 TB source

A sparse 2 TiB image (APFS holes, so reads of empty space run at memory
speed) with 48 real files scattered from the first gigabyte to the last,
scanned with `scan --type jpg,png,pdf,bmp,wav --checkpoint`:

| | Before | After zero-run skipping |
|---|---|---|
| Throughput over empty space | 775 MB/s (252 GB in 326 s, CPU-bound) | 4.3 GB/s (2 TiB in 515 s) |
| Peak resident memory | 9.8 MB | 14 MB |
| Files recovered | | 48 of 48, all hashes exact |

The per-byte magic scan, not the disk, was the limit before: every zero byte
still went through the index. A 64-byte block of zeros cannot start any
magic except in its last few bytes (the most leading zeros any active
magic has, two for `.ico`), so the scan now jumps over such blocks. Memory
stays flat for the whole run: the scanner holds one chunk plus the
dedup set, nothing proportional to the source.

Progress is accurate (the checkpoint's `pos` advances linearly through the
source). Killed with SIGTERM after 120 s (at 510 GB, 12 files written), the
same command with `--resume` picked up from the checkpoint, took 397 s for
the remaining 1.5 TiB, and ended with the identical 48 files and hashes an
uninterrupted run produces.

### Bad media

`corpus/badmedia.sh` builds a 64 MiB FAT32 volume in a privileged Linux
container, maps it through device-mapper with three ranges replaced by the
`error` target (sectors 2048–2063, 40000–40031, and the last eight), and
images it with `unearth image --map --retry-bad 2`. The result:

- every readable sector is copied byte-for-byte and every unreadable one
  is zero-filled;
- the map records exactly the three injected ranges, byte-accurate;
- the command exits non-zero, on purpose, so an incomplete image is never
  mistaken for a clean one.

`dm-flakey` is not available in Docker's kernel, so intermittent failures
(a sector that reads on the second try) are not yet exercised; `dm-error`
covers the hard-failure case the imager's retry logic is written for.

## Tips

- Profile in the `profiling` profile (release optimizations + line info) so the
  call sites in `dhat-heap.json` are meaningful.
- The harness is deterministic, so before/after comparisons are stable.
