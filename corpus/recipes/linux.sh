#!/usr/bin/env bash
# Build the Linux-formatted corpus images: ext4 (mke2fs), FAT32 (mkfs.fat),
# exFAT (mkfs.exfat), and NTFS (mkfs.ntfs from ntfs-3g, mounted with the
# kernel's ntfs3 driver). NTFS made by Windows `format` is the real target;
# the Linux-made image is labelled as such and is a stopgap until the Windows
# recipe has been run.
#
# Needs root for loop mounts. On a non-Linux host (or with CORPUS_DOCKER=1) it
# re-runs itself inside a privileged Docker container with the repo mounted.
#
# Usage: corpus/recipes/linux.sh
#        CORPUS_SCENARIOS=baseline corpus/recipes/linux.sh

if [ "$(uname -s)" != "Linux" ] || [ -n "${CORPUS_DOCKER:-}" ]; then
    REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    exec docker run --rm --privileged \
        -v "$REPO:/work" -w /work \
        -e CORPUS_SCENARIOS -e CORPUS_ONLY -e CORPUS_SEED -e CORPUS_VOLUME_SIZE \
        -e CARGO_TARGET_DIR=/work/target/linux-corpus \
        rust:1-bookworm bash -c '
            set -e
            apt-get update -qq >/dev/null
            apt-get install -y -qq e2fsprogs dosfstools exfatprogs ntfs-3g >/dev/null
            exec bash corpus/recipes/linux.sh'
fi

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PLATFORM=linux
KERNEL="$(uname -r)"

fs_format() {
    local img="$1" fs="$2" opts=""
    case "$fs" in
        ext4)  mkfs.ext4 -q -L CORPUS "$img" ;;
        fat32) mkfs.fat -F 32 -n CORPUS "$img" >/dev/null; opts="utf8=1" ;;
        exfat) mkfs.exfat -L CORPUS "$img" >/dev/null ;;
        ntfs)  mkfs.ntfs -F -Q -L CORPUS "$img" >/dev/null 2>&1 ;;
        *) echo "unknown fs $fs" >&2; return 1 ;;
    esac
    MNT="$WORK/mnt-$$"
    mkdir -p "$MNT"
    if [ "$fs" = ntfs ]; then
        mount -t ntfs3 -o loop "$img" "$MNT"
    else
        mount -o "loop${opts:+,$opts}" "$img" "$MNT"
    fi
}

fs_sync() {
    sync -f "$1" 2>/dev/null || sync
}

fs_release() {
    if [ -n "$MNT" ] && mountpoint -q "$MNT"; then
        umount "$MNT"
    fi
    rmdir "$MNT" 2>/dev/null || true
    MNT=""
}

for fs in ext4 fat32 exfat ntfs; do
    case "$fs" in
        ext4)  desc="Linux $KERNEL $(mkfs.ext4 -V 2>&1 | sed -n 1p || true)" ;;
        fat32) desc="Linux $KERNEL $(mkfs.fat 2>&1 | sed -n 1p || true)" ;;
        exfat) desc="Linux $KERNEL $(mkfs.exfat -V 2>&1 | sed -n 1p || true)" ;;
        ntfs)  desc="Linux $KERNEL mkfs.ntfs (ntfs-3g; stopgap for Windows format)" ;;
    esac
    for scenario in $(all_scenarios); do
        build_one "linux-$fs-$scenario" "$fs" "$scenario" "$desc"
    done
done
write_lock
