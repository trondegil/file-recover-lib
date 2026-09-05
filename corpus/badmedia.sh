#!/usr/bin/env bash
# Bad-media test (roadmap step 3.7): image a block device that really returns
# read errors, and check that the map records exactly the injected holes and
# that every readable byte came across. Runs inside a privileged Linux
# container (device-mapper's `error` target), re-executing itself in Docker
# from any other host.
#
# Usage: corpus/badmedia.sh
set -euo pipefail

if [ "$(uname -s)" != Linux ] || [ -n "${BADMEDIA_DOCKER:-}" ]; then
    REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    exec docker run --rm --privileged -v "$REPO:/work" -w /work \
        -e CARGO_TARGET_DIR=/work/target/linux-corpus \
        rust:1-bookworm bash -c '
            set -e
            apt-get update -qq >/dev/null
            apt-get install -y -qq dmsetup dosfstools python3 >/dev/null
            exec bash corpus/badmedia.sh'
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W=/tmp/badmedia
rm -rf "$W"; mkdir -p "$W/mnt"
cargo build --release --quiet
BIN="${CARGO_TARGET_DIR:-$REPO/target}/release/unearth"

# A 64 MiB FAT32 volume with real files on it.
dd if=/dev/zero of="$W/good.img" bs=1M count=64 status=none
mkfs.fat -F 32 "$W/good.img" >/dev/null
mount -o loop "$W/good.img" "$W/mnt"
cp -r "$REPO"/corpus/work/linux-fat32-baseline/stage/* "$W/mnt/" 2>/dev/null \
    || python3 -c "
import os
for i in range(24):
    open('$W/mnt/f%02d.bin' % i, 'wb').write(os.urandom(300_000))"
sync; umount "$W/mnt"

# Inject read errors: sectors 2048-2063, 40000-40031, and the last 8 sectors.
LOOP=$(losetup -f --show "$W/good.img")
SECTORS=$((64 * 1024 * 1024 / 512))
cat > "$W/table" <<TABLE
0 2048 linear $LOOP 0
2048 16 error
2064 $((40000 - 2064)) linear $LOOP 2064
40000 32 error
40032 $((SECTORS - 8 - 40032)) linear $LOOP 40032
$((SECTORS - 8)) 8 error
TABLE
dmsetup create badmedia "$W/table"
# No udev in a container: make the node by hand, or use the raw dm-N node.
dmsetup mknodes badmedia 2>/dev/null || true
DEV=/dev/mapper/badmedia
if [ ! -e "$DEV" ]; then
    minor=$(dmsetup info -c --noheadings -o minor badmedia)
    DEV=/dev/dm-$minor
    [ -e "$DEV" ] || mknod "$DEV" b 253 "$minor"
fi
trap 'dmsetup remove badmedia 2>/dev/null; losetup -d "$LOOP" 2>/dev/null' EXIT

echo "== imaging a device with three unreadable ranges"
# The tool exits non-zero when it had to zero-fill anything, on purpose: an
# incomplete image must not look like a clean one. That is the expected
# outcome here.
status=0
"$BIN" image "$DEV" "$W/copy.img" --map "$W/copy.map" --summary "$W/summary.json" \
    --retry-bad 2 --no-sparse --quiet || status=$?
echo "image exited with $status (non-zero expected: regions were zero-filled)"
[ "$status" -ne 0 ] || { echo "expected a non-zero exit for an incomplete image"; exit 1; }
cat "$W/summary.json"

python3 - "$W" <<'PY'
import json, sys, hashlib
W = sys.argv[1]
good = open(f"{W}/good.img", "rb").read()
copy = open(f"{W}/copy.img", "rb").read()
assert len(copy) == len(good), (len(copy), len(good))
bad = [(2048 * 512, 16 * 512), (40000 * 512, 32 * 512), (len(good) - 8 * 512, 8 * 512)]
# Every readable byte must match; every unreadable byte must be zero.
for off in range(0, len(good), 512):
    in_bad = any(b <= off < b + n for b, n in bad)
    src = good[off:off + 512]; dst = copy[off:off + 512]
    if in_bad:
        assert dst == b"\0" * 512, f"bad sector {off // 512} not zero-filled"
    else:
        assert dst == src, f"sector {off // 512} differs"
s = json.load(open(f"{W}/summary.json"))
print("summary: bad_regions =", s.get("bad_regions"), "bytes_zeroed =", s.get("bytes_zeroed"))
# The map file lists every unreadable region as "bad <offset> <len>".
got = sorted(
    (int(f[1]), int(f[2]))
    for f in (line.split() for line in open(f"{W}/copy.map"))
    if f and f[0] == "bad"
)
assert got == sorted(bad), (got, sorted(bad))
print("map records exactly the injected errors:", got)
print("every readable sector copied byte-for-byte; every unreadable one zero-filled")
PY
