#!/usr/bin/env bash
# Strip the BUILD HOST's absolute path out of every staged artifact (roadmap 4.7).
#
# The vendored stack bakes compile-time absolute paths into its binaries — musl's
# ld-musl-x86_64.path, Mesa's DRI/GBM driver search, glib's gio modules, libinput's data dir,
# fontconfig's config dir, zsh's terminfo. Built in this tree, every one of them starts with the
# builder's home directory, so the shipped ISO carried "/home/<user>/Documents/anonymOS" 396 times
# across 28 files.
#
# Two reasons that matters, and neither is "it crashes" — the guest probes these paths, they all
# fail ENOENT, and nothing breaks:
#
#   1. DENIABILITY. An image whose entire premise is that it cannot be tied to a person embeds its
#      builder's username and source-tree layout. That is a fingerprint of exactly the kind this OS
#      exists to avoid, and it survives into every copy anyone ever distributes.
#   2. REPRODUCIBILITY. Two people building the same commit produce different bytes purely because
#      their checkouts live in different directories.
#
# HOW: an in-place, SAME-LENGTH byte replacement of the build root with a neutral placeholder.
# Equal length is what makes this safe on ELF files — nothing shifts, so every offset, section
# size and relocation stays valid. The padding is repeated slashes, which POSIX collapses, so
#     /home/bruns/Documents/anonymOS/deps/musl/install/lib/ld-musl-x86_64.so.1
# becomes
#     /build////////////////////////deps/musl/install/lib/ld-musl-x86_64.so.1
# which resolves exactly as /build/deps/musl/... — a legal path, just not anyone's.
#
# WHAT THIS IS NOT: the principled fix is rebuilding the dependencies with guest-relative
# prefixes so the strings are never baked in. This is a build-output sanitiser, and it is honest
# about that. It does make the ISO reproducible across machines and removes the fingerprint, which
# are the two things 4.7 actually asks for.
#
# ORDERING: must run BEFORE scripts/build-boot-integrity-manifest.py, which hashes cd/. Sanitising
# afterwards would invalidate every hash in the attestation manifest.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TREE="${1:-$ROOT/cd}"

[ -d "$TREE" ] || { echo "sanitize-build-paths: no staged tree at $TREE" >&2; exit 2; }

BUILD_ROOT="$ROOT"
LEN=${#BUILD_ROOT}

# The placeholder must be exactly as long as the build root. "/build" plus slash padding gets
# there for any sane checkout path; a path shorter than "/build" cannot be padded down to size, so
# say so rather than silently corrupting binaries with a wrong-length write.
BASE="/build"
if [ "$LEN" -lt "${#BASE}" ]; then
    echo "sanitize-build-paths: build root '$BUILD_ROOT' is shorter than '$BASE'; cannot pad" >&2
    exit 2
fi
PAD=$(( LEN - ${#BASE} ))
PLACEHOLDER="$BASE$(printf '/%.0s' $(seq 1 $PAD 2>/dev/null) 2>/dev/null || true)"
# printf with an empty seq yields nothing, which is correct when PAD is 0.
[ "$PAD" -eq 0 ] && PLACEHOLDER="$BASE"

if [ "${#PLACEHOLDER}" -ne "$LEN" ]; then
    echo "sanitize-build-paths: placeholder length ${#PLACEHOLDER} != build root length $LEN" >&2
    exit 2
fi

changed=0
files=0
while IFS= read -r f; do
    # -a: treat every file as text. Many of these are ELF binaries and GNU grep would otherwise
    # report "binary file matches" and skip them.
    if grep -aqF "$BUILD_ROOT" "$f" 2>/dev/null; then
        # LC_ALL=C so sed works on bytes, not multibyte characters: a UTF-8 locale can mangle
        # arbitrary binary content.
        LC_ALL=C sed -i "s|$BUILD_ROOT|$PLACEHOLDER|g" "$f"
        files=$((files + 1))
        changed=1
    fi
done < <(find "$TREE" -type f)

remaining=$(grep -rac "$BUILD_ROOT" "$TREE" 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')

echo "sanitize-build-paths: rewrote build root in $files file(s)"
echo "  from  $BUILD_ROOT"
echo "  to    $PLACEHOLDER   (${#PLACEHOLDER} bytes, same length — ELF offsets unchanged)"
echo "  remaining occurrences in $TREE: $remaining"

if [ "$remaining" -ne 0 ]; then
    echo "sanitize-build-paths: FAILED — the build root still appears in the staged tree" >&2
    exit 1
fi
exit 0
