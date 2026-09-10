#!/usr/bin/env bash
# T2.6 / T13.1 / E13.1 — are two independent builds of this source identical?
#
#   bash scripts/reproducible-build.sh            # this platform
#   bash scripts/reproducible-build.sh --all      # all seven release targets
#
# WHY THIS EXISTS
# ---------------
# T2.6 has been outstanding since P2 and T13.1/E13.1 since P13, and they are the
# same missing apparatus counted twice: both ask that two INDEPENDENTLY built
# binaries be byte-identical (T13.1 phrases it as identical QUIC Initials, which
# is a consequence). Nothing could answer that, so both stayed unclaimed.
#
# "Independently" is the whole difficulty. Building twice in one directory tells
# you almost nothing -- Go's build cache makes that trivially true. What has to
# match is a build on ANOTHER MACHINE, from another directory, without this
# repository's .git. So the second build here is done from a COPY at a different
# path with .git removed, which is the closest a single machine can get to it.
#
# WHAT THIS FOUND, AND IT WAS NOT REPRODUCIBLE
# --------------------------------------------
# `-trimpath -ldflags=-s -w`, the flags scripts/build-release.sh has always
# used, are NOT enough. Go stamps VCS metadata into the binary by default:
#
#     build  vcs=git
#     build  vcs.revision=fa36dbd4a6cc...
#     build  vcs.time=2026-08-17T00:25:02Z
#     build  vcs.modified=false
#     mod    github.com/...  v0.0.0-20260817002502-fa36dbd4a6cc
#
# so the same source built inside the repo and from a tarball produced different
# binaries. `-buildvcs=false` removes all five lines and the two agree.
#
# Note vcs.time is the COMMIT time, not the build time, so two builds of one
# commit at different moments already matched -- which is exactly why this was
# easy to miss. The divergence only appears when the .git directory does, and a
# release built in CI from a checkout and verified by a user from a tarball is
# precisely that case.
#
# WHAT IT STILL DOES NOT PROVE
# ----------------------------
# One machine, one Go toolchain, one libc, one GOAMD64 level. A genuinely
# independent build on another machine can still differ on any of those, and
# this script cannot see it. What it does is remove the causes that are within
# the build's control, so that a real cross-machine difference is a signal
# rather than noise. E13.1 asks for all three release platforms and that needs
# CI; this is the local half.

set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

# The canonical flags. Anything that builds a release binary must use exactly
# these or the comparison is meaningless.
FLAGS=(-trimpath -buildvcs=false -ldflags=-s\ -w)

TARGETS=("linux/amd64")
if [ "${1:-}" = "--all" ]; then
  TARGETS=(linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The second tree: a copy at a different path with no VCS metadata. Standing in
# for "another machine" as closely as one machine can.
COPY="$WORK/independent"
mkdir -p "$COPY"
tar -c --exclude=.git --exclude=dist -C "$ROOT" . | tar -x -C "$COPY"

fail=0
printf '%-22s %-8s %s\n' TARGET RESULT DIGEST
for target in "${TARGETS[@]}"; do
  os=${target%/*}; arch=${target#*/}
  suffix=""; [ "$os" = windows ] && suffix=.exe
  goarm=""; [ "$arch" = arm ] && goarm=6

  a="$WORK/a-$os-$arch$suffix"
  b="$WORK/b-$os-$arch$suffix"

  ( cd "$ROOT" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOARM=$goarm \
      go build "${FLAGS[@]}" -o "$a" ./cmd/syndichan-node ) || { echo "build A failed for $target"; fail=1; continue; }
  ( cd "$COPY" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOARM=$goarm \
      go build "${FLAGS[@]}" -o "$b" ./cmd/syndichan-node ) || { echo "build B failed for $target"; fail=1; continue; }

  if cmp -s "$a" "$b"; then
    printf '%-22s %-8s %s\n' "$target" "OK" "$(sha256sum "$a" | cut -c1-16)"
  else
    fail=1
    printf '%-22s %-8s %s\n' "$target" "DIFFERS" "$(sha256sum "$a" | cut -c1-16) vs $(sha256sum "$b" | cut -c1-16)"
    # Name the cause rather than leaving an operator to bisect a stripped
    # binary: the embedded build settings are where the answer usually is.
    echo "  embedded build settings that differ:"
    diff <(go version -m "$a" 2>/dev/null) <(go version -m "$b" 2>/dev/null) \
      | sed 's/^/    /' | head -20
  fi
done

echo
if [ "$fail" -eq 0 ]; then
  echo "REPRODUCIBLE: every target built identically from two independent trees."
  echo "  Flags: ${FLAGS[*]}"
  echo "  Still unproven: another machine, another toolchain, another GOAMD64"
  echo "  level. That is E13.1's cross-platform half and needs CI."
else
  echo "NOT REPRODUCIBLE. T2.6 and T13.1/E13.1 cannot be claimed."
fi
exit "$fail"
