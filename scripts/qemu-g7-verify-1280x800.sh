#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec "$ROOT/scripts/qemu-g7-verify.sh" 1280 800
