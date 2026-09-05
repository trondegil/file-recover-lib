#!/usr/bin/env bash
# Shared helpers for the corpus recipes. Sourced by macos.sh and linux.sh.
#
# A recipe formats a small raw image with the platform's own tool, applies a
# plan (copy files in, sync, delete some, sync), unmounts, and records what was
# deleted. See corpus/README.md for the whole picture.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CORPUS="$REPO/corpus"
IMAGES="${CORPUS_IMAGES:-$CORPUS/images}"
WORK="${CORPUS_WORK:-$CORPUS/work}"
VOLUME_SIZE="${CORPUS_VOLUME_SIZE:-67108864}"   # 64 MiB: the smallest FAT32 macOS will make
SEED="${CORPUS_SEED:-1}"
SCENARIOS="${CORPUS_SCENARIOS:-}"
ONLY="${CORPUS_ONLY:-}"                          # substring filter on image names

mkdir -p "$IMAGES" "$WORK" "$CORPUS/expected"

# Build (once) and locate the corpus_tool helper.
tool() {
    if [ -z "${CORPUS_TOOL:-}" ]; then
        ( cd "$REPO" && cargo build --quiet --example corpus_tool )
        CORPUS_TOOL="${CARGO_TARGET_DIR:-$REPO/target}/debug/examples/corpus_tool"
        export CORPUS_TOOL
    fi
    "$CORPUS_TOOL" "$@"
}

all_scenarios() {
    if [ -n "$SCENARIOS" ]; then
        echo "$SCENARIOS" | tr ',' ' '
    else
        tool scenarios | tr '\n' ' '
    fi
}

# Apply a plan file to a mounted volume. $1 = mount point, $2 = stage dir,
# $3 = plan file. Copies go through the OS's own copy so the filesystem driver
# lays the data out exactly as it would for a user.
apply_plan() {
    local mnt="$1" stage="$2" plan="$3"
    local op path expect
    while IFS=$'\t' read -r op path expect; do
        case "$op" in
            copy)
                mkdir -p "$mnt/$(dirname "$path")"
                cp "$stage/$path" "$mnt/$path"
                ;;
            fill)
                # Packing the volume: a copy that fails for lack of space is
                # expected. Drop the partial file so the volume stays consistent.
                mkdir -p "$mnt/$(dirname "$path")"
                if ! cp "$stage/$path" "$mnt/$path" 2>/dev/null; then
                    rm -f "$mnt/$path"
                    fs_sync "$mnt"
                fi
                ;;
            delete)
                if [ "$expect" = maybe ]; then
                    rm -f "$mnt/$path"   # a fill that did not fit is not there
                else
                    rm "$mnt/$path"
                fi
                ;;
            rmdir)
                rmdir "$mnt/$path"
                ;;
            sync)
                fs_sync "$mnt"
                ;;
            ''|'#'*) ;;
            *) echo "bad plan line: $op $path" >&2; return 1 ;;
        esac
    done < "$plan"
}

# Build one image. $1 = image name, $2 = filesystem label for the manifest,
# $3 = scenario, $4 = human description of the tool that formatted it.
# Relies on the platform recipe defining fs_format (image, fs -> mounts it and
# sets MNT), fs_sync (mount point), and fs_release (unmount + detach).
build_one() {
    local name="$1" fs="$2" scenario="$3" source="$4"
    if [ -n "$ONLY" ] && [[ "$name" != *"$ONLY"* ]]; then
        return 0
    fi
    local img="$IMAGES/$name.img"
    local stage="$WORK/$name/stage" plan="$WORK/$name/plan.txt"
    echo "== $name"
    rm -rf "$WORK/$name"
    mkdir -p "$WORK/$name"
    tool plan "$scenario" "$stage" "$plan" --volume-size "$VOLUME_SIZE" --seed "$SEED"

    rm -f "$img"
    dd if=/dev/zero of="$img" bs=1048576 count=$((VOLUME_SIZE / 1048576)) status=none 2>/dev/null \
        || dd if=/dev/zero of="$img" bs=1048576 count=$((VOLUME_SIZE / 1048576))
    MNT=""
    fs_format "$img" "$fs"
    trap 'fs_release || true' EXIT
    apply_plan "$MNT" "$stage" "$plan"
    fs_release
    trap - EXIT

    tool expect --stage "$stage" --plan "$plan" --image "$img" --name "$name" \
        --filesystem "$fs" --platform "$PLATFORM" --source "$source" \
        --scenario "$scenario" --out "$CORPUS/expected/$name.json"
}

write_lock() {
    tool lock --expected "$CORPUS/expected" --out "$CORPUS/corpus.lock"
}
