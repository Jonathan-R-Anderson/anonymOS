#!/usr/bin/env bash
# Repair the vendored dependency source trees under deps/.
#
# Several of them were committed INCOMPLETE: git has openrc-0.54/src/**/*.h but
# none of the .c files, elogind-255.4 is missing 353 of its 955 files, and so on.
# Every dep makefile keys extraction on a file that IS present (openrc waits on
# $(SRC)/meson.build), so `make` never re-extracts and the build dies a long way
# downstream — e.g. "openrc-0.54/src/shared/meson.build:1:9: ERROR: File misc.c
# does not exist."  A machine that extracted these tarballs before the partial
# commit never sees it; a fresh clone (or a container build) always does.
#
# This fills the gaps from the tarball that is vendored right next to each tree,
# and NEVER overwrites a file the repo does ship — so anything patched in place
# stays patched.  Trees that are not extracted at all are left alone: their
# makefile still owns the download-and-extract step.
#
# Idempotent.  Run it after a fresh clone, or with --dry-run to just see the gaps.
set -euo pipefail
cd "$(dirname "$0")/.."

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

repaired=0
while IFS= read -r tarball; do
    dir="$(dirname "$tarball")"
    top="$(tar tf "$tarball" 2>/dev/null | sed -n '1p' | cut -d/ -f1)"
    [ -n "$top" ] || continue
    # Not extracted yet — the dep makefile will fetch/extract it itself.
    [ -d "$dir/$top" ] || continue

    missing=0
    while IFS= read -r f; do
        case "$f" in */) continue ;; esac
        [ -e "$dir/$f" ] || missing=$((missing + 1))
    done < <(tar tf "$tarball" 2>/dev/null)

    [ "$missing" -gt 0 ] || continue
    repaired=$((repaired + 1))
    if [ "$DRY_RUN" = 1 ]; then
        echo "  $dir/$top — $missing file(s) missing (would restore from $(basename "$tarball"))"
    else
        echo "  $dir/$top — restoring $missing file(s) from $(basename "$tarball")"
        # --skip-old-files: fill in what is absent, keep every file already there.
        tar xf "$tarball" -C "$dir" --skip-old-files
    fi
done < <(find deps -maxdepth 2 -type f \
             \( -name '*.tar.gz' -o -name '*.tgz' -o -name '*.tar.xz' -o -name '*.tar.bz2' \) \
         | sort)

if [ "$repaired" = 0 ]; then
    echo "vendored sources: all extracted trees are complete"
else
    echo "vendored sources: $repaired incomplete tree(s)$([ "$DRY_RUN" = 1 ] && echo ' (dry run — nothing written)')"
fi
