#!/usr/bin/env bash
# Build the corpus images for the platform this runs on, then regenerate the
# lock file. Run the Windows recipe separately (corpus/recipes/windows.ps1).
#
# Afterwards, record a recall baseline for any new image:
#   UNEARTH_CORPUS_RECORD=1 cargo test --release --test corpus_test -- --ignored --nocapture
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "$(uname -s)" in
    Darwin) bash corpus/recipes/macos.sh ;;
    Linux)  bash corpus/recipes/linux.sh ;;
    *) echo "use corpus/recipes/windows.ps1 on Windows" >&2; exit 1 ;;
esac
if [ "${CORPUS_LINUX_TOO:-}" = 1 ] && [ "$(uname -s)" = Darwin ]; then
    bash corpus/recipes/linux.sh
fi
echo
echo "Images are in corpus/images. Next:"
echo "  UNEARTH_CORPUS_RECORD=1 cargo test --release --test corpus_test -- --ignored --nocapture   # record baselines"
echo "  corpus/publish.sh corpus-vN                                             # publish a release"
