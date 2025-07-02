#!/usr/bin/env bash
# ****************************************************
# run_anonymos.sh – launch anonymOS in QEMU so that
# the built-in shell appears on *this* terminal and
# accepts interactive input.
# ****************************************************
# Usage:  ./scripts/run_anonymos.sh [extra-qemu-args]
# The script must be executed from the repository root
# (it automatically resolves paths).
set -e

echo "Launching anonymOS in QEMU..."
echo "The shell will appear in this terminal once booted."
echo "Use Ctrl-C to exit."
echo

cd "$(dirname "$0")/.."

# Add a slight delay before starting to ensure clean output
sleep 1

exec qemu-system-x86_64 \
  -cdrom build/anonymOS.iso \
  -m 512 \
  -serial stdio \
  -display none \
  -monitor none \
  -no-reboot \
  -M smm=off
