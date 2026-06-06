#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
G7_REBUILD="${G7_REBUILD:-1}" exec "$ROOT/scripts/qemu-g7-verify.sh" 1920 1080
