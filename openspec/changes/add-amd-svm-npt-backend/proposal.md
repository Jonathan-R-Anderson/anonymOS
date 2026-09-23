# Proposal: add-amd-svm-npt-backend

## Status (2026-09-23)

IMPLEMENTED (software): the AMD SVM / NPT backend is fully implemented in
`core.virt.svm` / `core.virt.vmcb` / `core.virt.npt`, wired behind the
vendor-neutral `core.virt.backend` API, with the SLAT abstraction and the
vendor-neutral exit dispatcher. All host-harness tests pass
(`tests/virt/host/build.sh`: selftest, fuzz, dispatch, adversarial).
`scripts/virt-hw-test.sh` asserts the real AMD boot path.

NOT hardware-validated: no `VMRUN` has executed on AMD silicon. Tasks 9.x
(`[HW]`) stay open until the user's machine runs them.

## Why

The native VMM/KVM-compat substrate on `feat/anonymos-vmm-kvm-compat` was
Intel-only in practice. `core.virt.svm` detected AMD SVM
(`CPUID.8000_0001:ECX[2]`) but was deliberately fail-closed:
`SVM_BACKEND_READY = false`, `svmEnter()` returned `-ENODEV`, and there was
no VMCB, no NPT, no VMRUN path. On AMD hardware every `KVM_RUN` failed with
`ENODEV` even though the silicon could virtualize.

Worse, the common code had Intel leakage that would have made an AMD backend
an awkward bolt-on: `core.virt.vmexit` dispatched on raw VMX basic
exit-reason numbers, the `Vm` object embedded an Intel-specific `Ept`,
validation helpers were named `vmxValidate*` even where they checked generic
x86 rules, and `kvm.d`'s `KVM_RUN` path hand-rolled
`if (vmxIsReady()) … else if (svmAvailable()) …` dispatch. Building AMD
support without fixing that layering would have forked the subsystem into
two dialects.

This change adds a real AMD SVM / AMD-V + NPT backend — VMCB programming,
nested paging, VMRUN guest entry, #VMEXIT decoding — and uses the
opportunity to make the hardware layer cleanly dual-vendor: a
vendor-neutral backend API, a second-level address translation (SLAT)
abstraction over EPT/NPT, and a vendor-neutral exit representation feeding
the one existing common dispatcher and the one existing KVM ABI.
`kvm.d`'s `KVM_RUN` path hand-rolls `if (vmxIsReady()) … else if
(svmAvailable()) …` dispatch. Building AMD support without fixing that
layering would fork the subsystem into two dialects.

This change adds a real AMD SVM / AMD-V + NPT backend — VMCB programming,
nested paging, VMRUN guest entry, #VMEXIT decoding — and uses the
opportunity to make the hardware layer cleanly dual-vendor: a
vendor-neutral backend API, a second-level address translation (SLAT)
abstraction over EPT/NPT, and a vendor-neutral exit representation feeding
the one existing common dispatcher and the one existing KVM ABI.

## What Changes

- **Vendor-neutral backend API** (`core.virt.backend`, new): `VirtBackendKind`
  (`None`/`Vmx`/`Svm`), `virtBackendKind()`, `virtBootInit()` /
  `virtCpuInit(cpuId)` per-CPU init dispatch, and `virtEnter()` — the single
  guest-entry point `kvm.d`'s `KVM_RUN` calls. No more Intel/AMD conditionals
  in the KVM layer.
- **SLAT abstraction** (`core.virt.slat`, new): `SlatKind` (`None`/`Ept`/`Npt`)
  plus `slatMap`/`slatUnmap`/`slatLookup`/`slatFree`/`slatRootPhys` over a
  common `Slat` value. `Vm.ept` becomes `Vm.slat`; guest-memory registration,
  pinning, unpin, and teardown go through the abstraction. EPT and NPT keep
  their own encodings underneath.
- **NPT implementation** (`core.virt.npt`, new): 4-level, 4 KiB nested page
  tables mirroring `core.virt.ept`'s structure and fail-closed validation,
  with ordinary x86 paging encodings (P/RW/US/NX) instead of EPT encodings.
- **VMCB implementation** (`core.virt.vmcb`, new): the exact AMD64 APM
  hardware layout with `static assert`s on size, alignment, and key offsets;
  intercept policy (conservative: intercept-all IOPM/MSRPM), ASID field,
  NPT enable + `N_CR3`.
- **Real SVM backend** (`core.virt.svm`, major): vendor-gated detection
  (`AuthenticAMD` + `CPUID.8000_0001:ECX[2]`), `MSR_VM_CR` LOCK/SVMDIS
  handling (firmware-disabled SVM fails cleanly, never bypassed),
  `EFER.SVME` enable, per-CPU host-save area + `MSR_VM_HSAVE_PA`, NPT
  feature gate (`CPUID.8000_000A`), per-CPU ASID allocator, VMCB
  programming from validated guest state, the `VMRUN` entry wrapper, and
  the SVM exit decoder producing vendor-neutral exits.
- **Exit normalization** (`core.virt.vmexit`, refactor): `VmExitInfo`
  (VMX reason numbers) becomes `VirtExitInfo` (`VirtExitKind`:
  `Unknown`/`Hlt`/`Shutdown`/`Io`/`Hypercall`/`SlatFault`, decoded fields,
  original `hardwareReason` for `KVM_EXIT_UNKNOWN`); `vmxDispatchExit`
  becomes `virtDispatchExit`; `vmxValidate*` become `virtValidate*`
  (they were generic x86 checks all along); `VirtDiag.EptViolation`
  becomes `VirtDiag.SlatViolation` (same numeric value — wire-compatible).
- **KVM ABI integration**: `kvmVcpuRun` builds a `VirtGuestState` snapshot
  (regs + sregs) and calls `virtEnter()`; the returned `VirtExitInfo`
  flows into the unchanged common dispatcher and the existing
  `struct kvm_run` output behavior (`KVM_EXIT_HLT/IO/MMIO/HYPERCALL/
  SHUTDOWN/UNKNOWN`). No AMD-specific KVM semantics.
- **Diagnostics & scripts**: boot logs name the selected backend
  (`[virt] backend: AMD SVM`, `[svm] …` lines); `scripts/virt-hw-test.sh`
  gains a real AMD validation path (no longer "fail-closed" expectations).
- **Tests**: host-harness unit tests for NPT map/lookup/unmap/free,
  readonly/duplicate/unaligned rejection, leak detection, SVM exit-code
  translation, SLAT dispatch, backend selection, ASID allocation; the
  kernel `virtSelfTest` covers the new names; `virt-hw-test.sh` documents
  the real-hardware smoke guest (`HLT` → `KVM_EXIT_HLT`, COM1 `OUT` →
  guest serial tap, NPF → MMIO, VMMCALL → hypercall).

What this change does **not** do: no VMX `VMLAUNCH` implementation (the VMX
`[HW]` entry tier stays exactly where the base proposal left it — this
change rewires `vmxEnter` through the new API but keeps it fail-closed);
no nested-SVM for guests (intercepted); no shadow paging (NPT required,
fail closed without it); no interrupt virtualization beyond the
conservative intercept policy; no FPU/SSE guest-host isolation yet
(documented limitation).

## Capabilities

### New Capabilities

- `amd-svm-backend`: AMD SVM/NPT hardware backend — detection, enablement,
  VMCB, NPT, VMRUN entry, #VMEXIT decode, per-CPU state, ASID management,
  conservative intercepts, fail-closed behavior, dual-vendor backend and
  SLAT abstractions, exit normalization.

### Modified Capabilities

- `native-hardware-virtualization`: the backend is now dual-vendor; EPT is
  one SLAT kind; exit reasons are vendor-neutral before dispatch.
- `kvm-compatibility`: `KVM_RUN` dispatches through `virtEnter()`; exit
  output behavior unchanged.
- `appvm-execution-integration`: `EptViolation` diagnostic renamed
  `SlatViolation` (value unchanged); guest serial tap works on AMD.

## Non-goals

- Completing Intel VMX `VMLAUNCH`/`VMRESUME` (separate `[HW]` tier).
- Nested virtualization, device passthrough, interrupt injection backends.
- Performance optimization (4 KiB pages, ASID=1-class simple allocation,
  flush-heavy TLB policy are acceptable for bring-up).
