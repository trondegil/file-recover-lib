#!/usr/bin/env bash
# Release smoke test: run a freshly built unearth binary against one corpus
# image and check that every deleted file the image documents comes back
# with the right hash. A binary that builds but cannot recover should never
# reach a Release page.
#
# Usage: corpus/smoke.sh <path-to-unearth-binary> [image-name]
# Needs curl, tar, and python3 (all present on GitHub's runners).
set -euo pipefail
BIN="${1:?usage: corpus/smoke.sh <unearth-binary> [image-name]}"
NAME="${2:-linux-fat32-baseline}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$REPO/corpus/corpus.lock"
WORK="${SMOKE_WORK:-$REPO/target/smoke}"
mkdir -p "$WORK"

read -r URL SHA FILE < <(python3 - "$LOCK" "$NAME" <<'PY'
import json, sys
lock = json.load(open(sys.argv[1]))
img = next(i for i in lock["images"] if i["name"] == sys.argv[2])
print(lock["tarball"]["url"], lock["tarball"]["sha256"], img["file"])
PY
)
IMG="$WORK/$FILE"
if [ ! -f "$IMG" ]; then
    echo "smoke: downloading $URL"
    curl -fsSL --retry 3 -o "$WORK/corpus.tar.gz" "$URL"
    python3 - "$WORK/corpus.tar.gz" "$SHA" <<'PY'
import hashlib, sys
h = hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()
if h != sys.argv[2]:
    sys.exit(f"tarball sha256 {h} != locked {sys.argv[2]}")
PY
    tar -xzf "$WORK/corpus.tar.gz" -C "$WORK" "$FILE"
fi

rm -rf "$WORK/out"
"$BIN" --version
"$BIN" undelete "$IMG" -o "$WORK/out" --report "$WORK/report.json"

python3 - "$REPO/corpus/expected/$NAME.json" "$WORK/report.json" <<'PY'
import json, sys
expected = json.load(open(sys.argv[1]))
got = {r["sha256"] for r in json.load(open(sys.argv[2])) if r.get("recovered")}
want = {f["sha256"] for f in expected["files"] if f["expect"] == "intact"}
missing = want - got
print(f"smoke: {len(want - missing)}/{len(want)} deleted files recovered intact from {expected['name']}")
if missing:
    sys.exit(f"smoke: {len(missing)} expected file(s) did not come back intact")
PY
