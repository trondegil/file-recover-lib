#!/usr/bin/env bash
# Build the macOS-formatted corpus images: FAT32, exFAT, and HFS+ (journaled),
# each formatted by diskutil, the same code path Disk Utility uses.
#
# Needs no root: a raw file is attached as a disk device with hdiutil and
# formatted in place. Note that `hdiutil create` is not used, because a fixed
# raw file gives an image with no DMG wrapper.
#
# Usage: corpus/recipes/macos.sh            (all filesystems, all scenarios)
#        CORPUS_SCENARIOS=baseline,deeptree corpus/recipes/macos.sh
#        CORPUS_ONLY=exfat corpus/recipes/macos.sh

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PLATFORM=macos
OSVER="$(sw_vers -productVersion)"
DEV=""

fs_format() {
    local img="$1" fs="$2" kind
    case "$fs" in
        fat32)   kind="FAT32" ;;
        exfat)   kind="ExFAT" ;;
        hfsplus) kind="JHFS+" ;;
        *) echo "unknown fs $fs" >&2; return 1 ;;
    esac
    DEV="$(hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount "$img" | awk 'NR==1{print $1}')"
    diskutil eraseVolume "$kind" CORPUS "$DEV" >/dev/null
    # eraseVolume mounts under /Volumes; remount at a private mount point so
    # Spotlight and Finder do not touch the volume while the plan runs.
    diskutil unmount "$DEV" >/dev/null
    MNT="$WORK/mnt-$$"
    mkdir -p "$MNT"
    diskutil mount -mountPoint "$MNT" "$DEV" >/dev/null
    # Keep fseventsd from writing its log at unmount: the log is written into
    # the blocks the last deletion freed, and took the last deleted file's
    # data with it in every HFS+ image of the first corpus build (see
    # corpus/README.md, "Known misses"). A `no_log` marker disables logging
    # for the volume; the folder is what a real card carries anyway.
    mkdir -p "$MNT/.fseventsd"
    touch "$MNT/.fseventsd/no_log"
}

fs_sync() {
    sync
}

fs_release() {
    if [ -n "$DEV" ]; then
        diskutil unmount "$DEV" >/dev/null || diskutil unmountDisk force "$DEV" >/dev/null || true
        hdiutil detach "$DEV" >/dev/null || true
        DEV=""
        rmdir "$MNT" 2>/dev/null || true
    fi
}

for fs in fat32 exfat hfsplus; do
    for scenario in $(all_scenarios); do
        build_one "macos-$fs-$scenario" "$fs" "$scenario" \
            "macOS $OSVER diskutil eraseVolume (hdiutil-attached raw image)"
    done
done
write_lock
