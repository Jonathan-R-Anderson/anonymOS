#!/usr/bin/env bash
# ****************************************************
# run_anonymos.sh – launch anonymOS in QEMU so that
# the built-in shell appears on *this* terminal and
# accepts interactive input.
# ****************************************************
# Usage:  ./scripts/run_anonymos.sh [extra-qemu-args]
# The script must be executed from the repository root
# (it automatically resolves paths).
set -euo pipefail

ISO_PATH="$(dirname "$0")/../build/anonymOS.iso"

if [[ ! -f "$ISO_PATH" ]]; then
  echo "[run_anonymos] ISO not found at $ISO_PATH" >&2
  echo "Build the project first (make iso) or adjust the path." >&2
  exit 1
fi

# Recommended QEMU arguments
ARGS=(
  -cdrom "$ISO_PATH"      # boot our ISO image
  -m 512                  # 512 MB RAM is plenty
  -nographic              # redirect VGA and serial to this terminal
  -monitor none           # prevent the QEMU monitor from stealing stdio
  -serial stdio           # connect COM1 to stdin/stdout
  -no-reboot              # stop instead of rebooting when the guest exits
)

# Forward any extra parameters the user provided
ARGS+=("$@")

echo "Launching anonymOS…  (Ctrl-a c for QEMU console, Ctrl-a x to quit)" >&2
exec qemu-system-x86_64 "${ARGS[@]}" 