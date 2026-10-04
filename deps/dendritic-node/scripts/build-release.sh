#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p dist

# GOARM only matters for linux/arm. 6 rather than 7 so ONE 32-bit ARM build runs
# on every Pi anybody actually volunteers -- a Zero or a 1 is armv6l, a 2/3 on a
# 32-bit OS is armv7l, and armv7 code faults on the former. The installer maps
# both of those `uname -m` values to this file.
for target in \
  linux/amd64 linux/arm64 linux/arm \
  darwin/amd64 darwin/arm64 \
  windows/amd64 windows/arm64
do
  os=${target%/*}
  arch=${target#*/}
  suffix=""
  if [ "$os" = "windows" ]; then
    suffix=".exe"
  fi
  goarm=""
  if [ "$arch" = "arm" ]; then
    goarm="6"
  fi
  output="dist/rabbiit-node-${os}-${arch}${suffix}"
  echo "building ${output}"
  # -buildvcs=false is NOT cosmetic and must not be dropped.
  #
  # Without it Go stamps vcs.revision, vcs.time, vcs.modified and a
  # commit-derived module version into every binary, so the same source built in
  # CI from a checkout and rebuilt by a user from a tarball produces DIFFERENT
  # bytes -- and T2.6/T13.1's "two independent builds are identical" is
  # unprovable by construction. scripts/reproducible-build.sh verifies these
  # exact flags; changing them here without changing them there makes that check
  # a check of something else.
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOARM="$goarm" \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$output" ./cmd/rabbiit-node
done

# Checksums: scripts/check-release.sh builds, verifies and writes a .sha256
# beside every artifact -- the form the installer checks before running one.
