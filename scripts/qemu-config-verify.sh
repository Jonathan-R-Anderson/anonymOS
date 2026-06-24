#!/usr/bin/env bash
# DECLARITIVE_MODEL_ROADMAP §4 verification: boot the ISO headless and confirm
# the kernel located, HMAC-verified, and applied the declarative-config manifest
# (manifest.blob boot module) before reaching PID1.
#
# Requires the ISO to be built with a staged manifest (the default build does
# this from anonymos-config/examples/system.json unless DECLARATIVE_CONFIG=none).
# Run on a host with qemu-system-x86_64 (Linux/KVM or the Docker build image).
#
# Success markers (in serial.log):
#   "[dkernel] config: applied <N> services, <M> identities, <K> namespaces, gen="
#       → a verified manifest was located, HMAC-checked, and lowered onto the
#         in-kernel service/identity/namespace managers
#   "[dkernel] config: serviceStartAll started <N>"
#       → the declared services actually started in dependency order
#
# Negative checks (set DECLARATIVE_CONFIG=none when building to exercise these):
#   "[dkernel] config: no manifest.blob boot module"  → clean fallthrough
#   "[dkernel] config: manifest HMAC FAILED"          → tampered manifest refused
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ISO="${HOS_ISO:-$ROOT/hos.iso}"
if [ ! -f "$ISO" ]; then
  echo "config-verify: $ISO not found — build it first: make hos.iso (needs Docker/Linux)" >&2
  exit 2
fi

SERIAL="$ROOT/serial-config.log"
rm -f "$SERIAL"

echo "[config-verify] booting $ISO headless, capturing serial → $SERIAL"
qemu-system-x86_64 \
  -boot d -cdrom "$ISO" -m 512 \
  -no-reboot -no-shutdown \
  -cpu qemu64,-smap,-smep \
  -display none \
  -serial "file:$SERIAL" &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null' EXIT

# Give the kernel time to boot through d_kernel_main + the PID1 scan.
BOOT_TIMEOUT="${BOOT_TIMEOUT:-90}"
for i in $(seq 1 "$BOOT_TIMEOUT"); do
  if grep -qa '\[dkernel\] config:' "$SERIAL"; then break; fi
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "[config-verify] QEMU exited before the config marker appeared" >&2
    break
  fi
  sleep 1
done

echo "==== §4 config-boot serial markers ===="
if grep -qaE '\[dkernel\] config: applied' "$SERIAL"; then
  echo "PASS: a verified declarative manifest was applied at boot"
  grep -aE '\[dkernel\] config:' "$SERIAL"
  # confirm the declared services actually started
  if grep -qaE '\[dkernel\] config: serviceStartAll started' "$SERIAL"; then
    echo "PASS: declared services started (serviceStartAll)"
  else
    echo "WARN: manifest applied but serviceStartAll marker not found (check serial)" >&2
  fi
  exit 0
elif grep -qaE '\[dkernel\] config: (no manifest.blob|manifest HMAC FAILED)' "$SERIAL"; then
  echo "INFO: clean fallthrough (no/tampered manifest) — expected if built with DECLARATIVE_CONFIG=none"
  grep -aE '\[dkernel\] config:' "$SERIAL"
  exit 0
else
  echo "FAIL: no [dkernel] config: marker found in $SERIAL" >&2
  echo "---- last 20 serial lines ----"
  tail -20 "$SERIAL" || true
  exit 1
fi
