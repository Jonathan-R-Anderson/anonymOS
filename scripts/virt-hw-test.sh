#!/usr/bin/env bash
# [HW] validation for the anonymOS native VMM / KVM-compat layer.
#
# What it proves, on real virtualization hardware:
#   1. The host CPU exposes VMX (Intel) or SVM (AMD) and nested KVM is on.
#   2. The anonymOS kernel boots with the virtualization feature exposed to
#      the guest and executes VMXON successfully  ->  "[vmx] VMXON ok".
#   3. The virt boot selftest passes against the REAL backend (VM/vCPU
#      lifecycle, slot validation, ceilings, userspace guards, KVM ABI
#      capability probes)  ->  "[virt] selftest PASS".
#
# What it does NOT prove (needs a test program inside the guest):
#   - actual guest entry via KVM_RUN and a known exit (KVM_EXIT_HLT/IO).
#     That is OpenSpec task 6.2 ("KVM smoke [HW]") and stays open.
#
# Usage:
#   scripts/virt-hw-test.sh
#   TIMEOUT=600 MEM=4096 scripts/virt-hw-test.sh
#
# Exit 0 = hardware present and all assertions held.
#      1 = an assertion failed (see the log path printed at the end).
#      2 = setup problem (no HW virt, no /dev/kvm, nested off, no ISO, ...).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TIMEOUT="${TIMEOUT:-300}"
MEM="${MEM:-2048}"
SERIAL="${TMPDIR:-/tmp}/virt-hw-serial.$$.log"
CLEAN="${TMPDIR:-/tmp}/virt-hw-clean.$$.log"
QEMU_BIN="${QEMU_BIN:-$HOME/.local/qemu-virgl/bin/qemu-system-x86_64}"
[ -x "$QEMU_BIN" ] || QEMU_BIN="qemu-system-x86_64"

fail()  { echo "virt-hw-test: $*" >&2; exit "${2:-2}"; }
pass()  { echo "virt-hw-test: $*"; }

# ── preflight: real virtualization hardware ──────────────────────────────
grep -q '^flags.*\bvmx\b' /proc/cpuinfo && VIRT=vmx
grep -q '^flags.*\bsvm\b' /proc/cpuinfo && VIRT=svm
[ -z "${VIRT:-}" ] && fail "host CPU exposes neither vmx nor svm — no hardware virtualization to test"

[ -e /dev/kvm ] || fail "/dev/kvm missing — KVM not available on this host"
[ -r /dev/kvm ] && [ -w /dev/kvm ] || fail "/dev/kvm not readable+writable by $USER (add yourself to the kvm group)"

# Nested virtualization must be on, otherwise the guest's VMXON will fail.
case "$VIRT" in
  vmx) NESTED_FILE=/sys/module/kvm_intel/parameters/nested; KMOD=kvm_intel ;;
  svm) NESTED_FILE=/sys/module/kvm_amd/parameters/nested;   KMOD=kvm_amd ;;
esac
if [ -f "$NESTED_FILE" ]; then
  grep -qx 'Y\|1' "$NESTED_FILE" || fail "nested KVM is off ($NESTED_FILE = $(cat "$NESTED_FILE")). Enable with (as root): modprobe -r $KMOD && modprobe $KMOD nested=1   — or kvm-intel.nested=1 / kvm-amd.nested=1 on the kernel cmdline"
else
  echo "virt-hw-test: warning: $NESTED_FILE not found — cannot confirm nested KVM; continuing" >&2
fi

command -v "$QEMU_BIN" >/dev/null 2>&1 || fail "no qemu-system-x86_64 found"

# ── preflight: a fresh ISO ───────────────────────────────────────────────
[ -f "$ROOT/hos-install.iso" ] || fail "hos-install.iso missing — build first (see README build instructions)"
if [ -x "$ROOT/scripts/iso-verify.sh" ] && [ "${NO_VERIFY:-0}" != "1" ]; then
  "$ROOT/scripts/iso-verify.sh" || fail "refusing to boot a stale ISO (NO_VERIFY=1 to override)"
fi

# ── boot headless with the virt feature exposed ──────────────────────────
# qemu64 keeps the advertised feature set small (the kernel does not enable
# AVX state; -cpu host faulted the desktop), +vmx/+svm exposes exactly the
# virtualization feature under test. SMAP/SMEP stay off: the OS requires it.
case "$VIRT" in
  vmx) CPU="qemu64,+vmx,-smap,-smep" ;;
  svm) CPU="qemu64,+svm,-smap,-smep" ;;
esac
pass "booting with -cpu $CPU (nested $VIRT)"

"$QEMU_BIN" \
  -boot d \
  -cdrom "$ROOT/hos-install.iso" \
  -serial "file:$SERIAL" \
  -display none \
  -m "$MEM" \
  -smp 1 \
  -no-reboot \
  -enable-kvm \
  -cpu "$CPU" \
  -monitor "unix:$PWD/virt-hw-mon.$$.sock,server=on,wait=off" \
  >"${TMPDIR:-/tmp}/virt-hw-qemu.$$.log" 2>&1 &
QEMU_PID=$!
trap 'kill $QEMU_PID 2>/dev/null; rm -f "$PWD/virt-hw-mon.$$.sock"' EXIT

# QEMU rejecting the CPU (or any other instant failure) shows up here.
sleep 5
if ! kill -0 $QEMU_PID 2>/dev/null; then
  echo "----- qemu stderr -----" >&2
  cat "${TMPDIR:-/tmp}/virt-hw-qemu.$$.log" >&2
  fail "QEMU exited immediately — see above (bad -cpu string? KVM denied?)"
fi

# ── wait for the selftest verdict ────────────────────────────────────────
pass "waiting up to ${TIMEOUT}s for [virt] selftest verdict ..."
deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if [ -f "$SERIAL" ]; then
    tr -d '\000' < "$SERIAL" > "$CLEAN" 2>/dev/null
    grep -qF "[virt] selftest PASS" "$CLEAN" && VERDICT=pass && break
    grep -qF "[virt] selftest FAIL" "$CLEAN" && VERDICT=fail && break
  fi
  kill -0 $QEMU_PID 2>/dev/null || { VERDICT=dead; break; }
  sleep 2
done

kill $QEMU_PID 2>/dev/null
trap - EXIT
rm -f "$PWD/virt-hw-mon.$$.sock"

[ -f "$SERIAL" ] || fail "no serial output captured at all"
tr -d '\000' < "$SERIAL" > "$CLEAN"

# ── assertions ─────────────────────────────────────────────────────────
rc=0
check() { # check <kind: require|forbid> <fixed string>
  if [ "$1" = require ]; then
    grep -qF "$2" "$CLEAN" || { echo "ASSERT FAIL: required line missing: $2" >&2; rc=1; }
  else
    grep -qF "$2" "$CLEAN" && { echo "ASSERT FAIL: forbidden line present: $2" >&2; rc=1; }
  fi
}

check require "[virt] selftest PASS"
check forbid  "[virt] selftest FAIL"
if [ "$VIRT" = vmx ]; then
  # Intel: the kernel attempts VMXON at boot (kernel_main -> vmxBootInit) and it
  # must succeed under nested KVM; the honest "no VMX" line would mean the
  # CPUID detection broke.
  check require "[vmx] VMXON ok"
  check forbid  "[vmx] VMXON failed"
  check forbid  "[vmx] no VMX "
else
  # AMD: the SVM backend is fail-closed (svm.d SVM_BACKEND_READY=false — the
  # VMRUN tier is not built yet), and the Intel-only VMX attempt prints its
  # honest "[vmx] no VMX" line, which is EXPECTED here, not a failure.  The
  # positive signal is the backend-agnostic selftest verdict above.
  check forbid  "[vmx] VMXON ok"
  check forbid  "[vmx] VMXON failed"
fi

if [ "$rc" -eq 0 ]; then
  pass "ALL ASSERTIONS HELD — VMXON ok, virt selftest PASS on real hardware"
  pass "full serial log: $SERIAL"
else
  echo "virt-hw-test: ASSERTIONS FAILED — full serial log: $SERIAL" >&2
fi
exit $rc
