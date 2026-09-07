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

# TWO prefixes, longest first.
#
#   1. the current build root -- musl/Mesa/glib/fontconfig search paths compiled in this tree
#   2. the builder's HOME -- which catches what pass 1 cannot: binaries VENDORED AS PREBUILT
#      ARTIFACTS that were compiled in a DIFFERENT checkout.  gnupg and libarchive still carry
#      __FILE__ strings naming "/home/<user>/Documents/EpinAnonymOS/deps/...", an older directory
#      that no longer exists.  Sanitising only the current build root left 114 of those behind,
#      which is why this second pass exists: the username is the identifying part, and it leaks
#      just as badly from a stale path as from a live one.
#
# Longest first matters: replacing HOME first would shorten nothing but would leave the build-root
# pattern unmatchable, since its prefix would already have been rewritten.
# Each entry is "<host prefix>|<guest path it should become>".  Order matters: LONGEST first, so a
# dependency's sysroot is rewritten before the generic build root that contains it.
#
# The dependency sysroots map to /usr rather than to a placeholder, because these strings are not
# dead weight -- the guest PROBES them at runtime (Mesa's DRI/GBM search, musl's ld path, glib's
# gio modules, libinput's data dir, fontconfig).  Rewriting
#     <root>/deps/gtk-stack/sysroot/share/drirc.d  ->  /usr/////...////share/drirc.d
# leaves a path POSIX collapses to /usr/share/drirc.d, which is where this OS actually stages that
# kind of file.  A probe landing there can resolve; one landing in /build never could.
#
# The principled fix remains building the dependencies with --prefix=/usr and DESTDIR so nothing is
# baked in at all.  That is a refactor of a 722 MB dependency tree -- changing the prefix relocates
# every installed file and every staging path that reads it -- and this reaches the same two
# outcomes, no host identity and probes that point somewhere real, without rebuilding it.
# REVERTED to a single neutral placeholder.  Mapping the dependency sysroots to /usr looked like an
# improvement -- probes would land where files are actually staged -- but these strings are not all
# diagnostic.  One of them is the ELF PT_INTERP, the dynamic loader path, and rewriting it to
# /usr/////...////lib/ld-musl-x86_64.so.1 produced a boot that loaded the interpreter and then took
# a kernel fault (null read, tid=0).  /build had been through dozens of clean boots, a full install
# and an installed-system boot, so it is the known-good target.
#
# The lesson is about the technique, not the target: a blind same-length byte rewrite cannot tell a
# log string from a path the loader will act on, so the only safe placeholder is one that changes
# nothing about how a path RESOLVES.  Landing probes on real files needs the deps rebuilt with
# guest prefixes, which is 4.11's actual remaining work.
PREFIX_MAP=(
    "$ROOT|/build"
)
[ -n "${HOME:-}" ] && [ "$HOME" != "/" ] && PREFIX_MAP+=("$HOME|/build")

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

files=0
for ENTRY in "${PREFIX_MAP[@]}"; do
    PFX="${ENTRY%%|*}"
    TGT="${ENTRY##*|}"
    PLEN=${#PFX}
    [ "$PLEN" -lt "${#TGT}" ] && continue
    PPAD=$(( PLEN - ${#TGT} ))
    if [ "$PPAD" -eq 0 ]; then REPL="$TGT"
    else REPL="$TGT$(printf '/%.0s' $(seq 1 $PPAD))"; fi
    [ "${#REPL}" -eq "$PLEN" ] || { echo "sanitize-build-paths: pad error for $PFX" >&2; exit 2; }

    while IFS= read -r f; do
        # -a: treat every file as text.  Most of these are ELF binaries and GNU grep would
        # otherwise report "binary file matches" and skip them entirely.
        if grep -aqF "$PFX" "$f" 2>/dev/null; then
            # LC_ALL=C so sed works on BYTES: a UTF-8 locale can mangle arbitrary binary content.
            LC_ALL=C sed -i "s|$PFX|$REPL|g" "$f"
            files=$((files + 1))
        fi
    done < <(find "$TREE" -type f)
    echo "sanitize-build-paths: $PFX -> $TGT"
done

# `grep -c` exits 1 when it finds NOTHING, which here is the success case -- with `pipefail`
# that killed the script precisely when the sanitisation had worked.  `|| true` keeps the
# count without letting "no matches" read as a failure.
remaining=0
for ENTRY in "${PREFIX_MAP[@]}"; do
    PFX="${ENTRY%%|*}"
    n=$( { grep -rac "$PFX" "$TREE" 2>/dev/null || true; } | awk -F: '{s+=$2} END {print s+0}' )
    remaining=$(( remaining + n ))
done

echo "sanitize-build-paths: rewrote build root in $files file(s)"
echo "  from  $BUILD_ROOT"
echo "  to    $PLACEHOLDER   (${#PLACEHOLDER} bytes, same length — ELF offsets unchanged)"
echo "  remaining occurrences in $TREE: $remaining"

if [ "$remaining" -ne 0 ]; then
    echo "sanitize-build-paths: FAILED — the build root still appears in the staged tree" >&2
    exit 1
fi
exit 0
