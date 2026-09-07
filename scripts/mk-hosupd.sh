#!/usr/bin/env bash
# Package a built esp-image into a signed whole-image update bundle (.hosupd).
#
# SYSTEM_UPDATE D1 (roadmap 4.4): "an update = a complete signed esp-image (kernel + modules +
# limine) written to the inactive slot".  This produces that artifact.  The kernel verifies it with
# core/imgupdate.d — the format below MUST stay byte-identical to the header documented there.
#
#   offset  size  field
#        0     8  magic "HOSUPD01"
#        8     4  formatVersion (1)
#       12     4  imageVersion    -- monotonic; the kernel refuses <= its own SYSTEM_VERSION
#       16     4  prevVersion     -- version this replaces (0 = any)
#       20     4  keyId           -- 0 = built-in HMAC dev key
#       24     8  imageLen
#       32    32  imageHash       -- SHA-256 over the whole image
#       64    32  sig             -- HMAC-SHA-256 over bytes [0,64) under the trusted key
#       96   ...  image
#
# SIGNING IS SYMMETRIC AND THAT IS A REAL LIMITATION, not an oversight to discover later: the key
# below is the kernel's built-in HMAC key (core/crypto.d g_trustedKey), so anyone holding this
# script can forge a bundle this kernel accepts.  That is adequate for a locally-built image and is
# NOT a release-signing story.  D3 replaces it with Ed25519 (asymmetric, pinned root, offline
# verifiable); the bundle's keyId field exists so that swap does not break the format.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-$ROOT/cd/esp-image}"
OUT="${OUT:-$ROOT/build/system.hosupd}"
VERSION="${VERSION:-}"
# Left EMPTY by default so the block below can derive it from SYSTEM_VERSION.  Setting it to 0 here
# would silently win over that derivation and every bundle would say "replaces any version".
PREV="${PREV-}"
KEYID="${KEYID:-0}"

# Must equal core/crypto.d g_trustedKey.
TRUSTED_KEY_HEX="a17eb00f5161cafedeadbeef0123456789abcdeffedcba98765432100f1e2d3c"

command -v openssl >/dev/null 2>&1 || { echo "mk-hosupd: openssl not found" >&2; exit 2; }
[ -f "$IMAGE" ] || { echo "mk-hosupd: no image at $IMAGE (run 'make iso' first)" >&2; exit 2; }

# Default the version to SYSTEM_VERSION+1: the kernel refuses anything <= its running version, so a
# bundle stamped with the CURRENT version would be correctly rejected as a replay and look like a
# packaging bug.  Read it from the source of truth rather than hardcoding a second copy.
if [ -z "$VERSION" ]; then
    cur="$(sed -n 's/^public enum uint SYSTEM_VERSION = \([0-9]\+\);.*/\1/p' \
           "$ROOT/src/kernel/d/core/sysversion.d" | head -1)"
    [ -n "$cur" ] || { echo "mk-hosupd: cannot read SYSTEM_VERSION" >&2; exit 2; }
    VERSION=$((cur + 1))
    [ -n "$PREV" ] || PREV="$cur"
fi

IMAGE_LEN=$(stat -c %s "$IMAGE")
IMAGE_HASH=$(openssl dgst -sha256 -binary "$IMAGE" | xxd -p -c 256)

# Little-endian field writers.  printf with \x escapes is used rather than a here-doc so the bytes
# are exact; anything that could reinterpret them (echo -e, text mode) would corrupt the header.
le32() { printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
        $(( $1        & 0xff)) $((($1 >>  8) & 0xff)) \
        $((($1 >> 16) & 0xff)) $((($1 >> 24) & 0xff)))"; }
le64() { printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x' \
        $(( $1        & 0xff)) $((($1 >>  8) & 0xff)) $((($1 >> 16) & 0xff)) $((($1 >> 24) & 0xff)) \
        $((($1 >> 32) & 0xff)) $((($1 >> 40) & 0xff)) $((($1 >> 48) & 0xff)) $((($1 >> 56) & 0xff)))"; }

mkdir -p "$(dirname "$OUT")"
HDR="$(mktemp)"; trap 'rm -f "$HDR" "$HDR.sig"' EXIT

{
    printf 'HOSUPD01'
    le32 1                 # formatVersion
    le32 "$VERSION"
    le32 "${PREV:-0}"
    le32 "$KEYID"
    le64 "$IMAGE_LEN"
    printf '%s' "$IMAGE_HASH" | xxd -r -p
} > "$HDR"

[ "$(stat -c %s "$HDR")" -eq 64 ] || { echo "mk-hosupd: header is not 64 bytes" >&2; exit 2; }

openssl dgst -sha256 -mac HMAC -macopt "hexkey:$TRUSTED_KEY_HEX" -binary -out "$HDR.sig" "$HDR"

cat "$HDR" "$HDR.sig" "$IMAGE" > "$OUT"

echo "mk-hosupd: wrote $OUT"
echo "  image      $IMAGE ($IMAGE_LEN bytes)"
echo "  imageHash  $IMAGE_HASH"
echo "  version    $VERSION (replaces $PREV)"
echo "  bundle     $(stat -c %s "$OUT") bytes"
