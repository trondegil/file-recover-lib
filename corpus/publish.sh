#!/usr/bin/env bash
# Package corpus/images into one tarball, attach it to a GitHub Release, and
# pin its URL and SHA-256 in corpus/corpus.lock.
#
# Usage: corpus/publish.sh corpus-v1
#
# Every image listed in the lock must be present locally (build them, or
# download the previous release first) so the tarball is complete.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
TAG="${1:?usage: corpus/publish.sh <release-tag>}"
REPO_SLUG="${CORPUS_REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
TARBALL="unearth-$TAG.tar.gz"

cargo build --quiet --example corpus_tool
TOOL=target/debug/examples/corpus_tool

# Refuse to publish a tarball that is missing images the lock promises.
missing=0
for f in $(grep -o '"file": "[^"]*"' corpus/corpus.lock | cut -d'"' -f4); do
    [ -f "corpus/images/$f" ] || { echo "missing corpus/images/$f" >&2; missing=1; }
done
[ "$missing" = 0 ] || exit 1

tar -C corpus/images -czf "corpus/$TARBALL" $(ls corpus/images)
SHA="$($TOOL sha256 "corpus/$TARBALL" | cut -d' ' -f1)"
URL="https://github.com/$REPO_SLUG/releases/download/$TAG/$TARBALL"

gh release create "$TAG" "corpus/$TARBALL" \
    --repo "$REPO_SLUG" \
    --title "Test corpus $TAG" \
    --notes "Real-filesystem test images for tests/corpus_test.rs. See corpus/README.md. SHA-256: $SHA"

$TOOL lock --expected corpus/expected --out corpus/corpus.lock \
    --release "$TAG" --tarball-name "$TARBALL" --tarball-url "$URL" --tarball-sha256 "$SHA"
rm -f "corpus/$TARBALL"
echo "Published $URL"
echo "Now commit corpus/corpus.lock and corpus/expected/."
