#!/usr/bin/env bash
# Build third-party shell binary with automatic fallback to stub shell.
# Usage: build_sh_bin.sh <output-path>
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <output-binary>" >&2
  exit 1
fi

OUT=$(realpath "$1")
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$(dirname "$OUT")"

pushd "$ROOT_DIR/third_party/sh" >/dev/null
BUILD_SUCCESS=true

# Attempt to compile the real shell.
if bash build_betterc.sh; then
  if [[ -f interpreter ]]; then
    cp interpreter "$OUT"
  else
    BUILD_SUCCESS=false
  fi
else
  BUILD_SUCCESS=false
fi
popd >/dev/null

if [[ "$BUILD_SUCCESS" == false ]]; then
  echo "[WARN] third_party/sh build failed – falling back to stub shell" >&2
  pushd "$ROOT_DIR" >/dev/null
  # Compile minimal stub shell (no libc / druntime).
  ldc2 -betterC --nogc --boundscheck=off -O1 -c third_party/stub_shell.d -of=/tmp/stub_shell.o
  ld.lld -nostdlib -e main /tmp/stub_shell.o -o "$OUT"
  popd >/dev/null
fi

chmod +x "$OUT"
echo "Shell binary ready at $OUT" 