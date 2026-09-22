#!/bin/sh
# tests/virt/host/build.sh — build + run the host VMM/KVM test harness.
#
# Compiles the REAL core.virt.* modules against the fake kernel surface in
# stubs/ (host triple, -betterC) and runs all four test binaries.  Fails
# loudly (nonzero exit) on any compile error, any binary failure, or any
# missing PASS line.
#
# Prerequisites: ldc2 (D compiler) on PATH, x86_64 host.  No VMX/SVM hardware
# needed — every test runs without virtualization extensions.
set -eu

cd "$(dirname "$0")"
ROOT="../../.."
SRC="$ROOT/src/kernel/d"
OUT="build"
mkdir -p "$OUT"

# NOTE: LDC spells DMD's -version= as -d-version=.
COMMON="-betterC -O1 -d-version=HostTest -I$SRC"
STUBS="stubs/stub_*.d"
VIRT="$SRC/core/virt/vm.d $SRC/core/virt/vmx.d $SRC/core/virt/svm.d \
      $SRC/core/virt/ept.d $SRC/core/virt/kvmabi.d $SRC/core/virt/vmexit.d \
      $SRC/core/virt/kvm.d $SRC/core/virt/selftest.d"
# NOTE: the real core/virt/vmm_policy.d is deliberately NOT in the list above:
# it imports core.domain/identity/namespace (no host meaning).  The harness
# compiles stubs/stub_vmm_policy.d instead (see stubs/ and README.md).

build_one() {
    name="$1"; main="$2"; expect="$3"
    echo "=== building $name ==="
    # shellcheck disable=SC2086
    ldc2 $COMMON $STUBS $VIRT "$main" -of="$OUT/$name"
}

build_one run_selftest  run_selftest.d  "[virt] selftest PASS"
build_one run_fuzz       run_fuzz.d       "[virt] fuzz PASS"
build_one run_dispatch   run_dispatch.d   "[virt] dispatch PASS"
build_one run_adversarial run_adversarial.d "[virt] adversarial PASS"

run_one() {
    name="$1"; expect="$2"
    echo "=== running $name ==="
    if out="$("$OUT/$name")"; then
        :
    else
        echo "*** $name: EXITED NONZERO" >&2
        echo "$out" | tail -20 >&2
        exit 1
    fi
    echo "$out" | tail -5
    case "$out" in
        *"$expect"*) echo "--- $name: PASS line present" ;;
        *) echo "*** $name: MISSING PASS LINE ($expect)" >&2; exit 1 ;;
    esac
}

run_one run_selftest  "[virt] selftest PASS"
run_one run_fuzz       "[virt] fuzz PASS"
run_one run_dispatch   "[virt] dispatch PASS"
run_one run_adversarial "[virt] adversarial PASS"

echo "ALL HOST VIRT TESTS PASS"
