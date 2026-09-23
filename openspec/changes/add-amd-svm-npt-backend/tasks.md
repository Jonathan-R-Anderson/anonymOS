# Tasks: add-amd-svm-npt-backend

Conventions: each task states its verification. A task is done only when
its verification passes — code existing is not enough. Host-testable tasks
verify with `tests/virt/host/build.sh` (all four binaries PASS). Tasks that
need real AMD silicon are marked `[HW]`; they verify on the user's machine
via `scripts/virt-hw-test.sh`, not in this sandbox.

Status key: `[x]` = implemented AND host-harness tested. `[x]` does NOT
mean hardware-verified — every `[HW]` task stays open until real silicon
runs it.

## 1. Vendor-neutral backend abstraction

- [x] 1.1 Add `src/kernel/d/core/virt/backend.d`: `VirtBackendKind`
  (`None`/`Vmx`/`Svm`), `virtBackendKind()`, `virtBackendAvailable()`,
  `virtBootInit()` (vendor detect → `virtCpuInit(0)`), `virtCpuInit(cpuId)`
  dispatching to `vmxCpuInit`/`svmCpuInit`, and
  `int virtEnter(Vm* vm, Vcpu* vc, KvmRegs* regs, const KvmSRegs* sregs,
  const KvmMsrEntry* msrs, uint nmsrs, VirtExitInfo* xi)` returning `0`
  with `*xi` filled on guest exit, `-ENODEV` when no backend is runnable,
  `-EINVAL` on bad guest state. (Implemented with direct regs/sregs
  pointers rather than the planned `VirtGuestState` wrapper — same
  contract, less indirection. `KvmRegs*` is mutable: the backend writes
  back guest GPR state on exit.)
  Verify: host test — with no hardware, `virtEnter` returns `-ENODEV`.
- [x] 1.2 Rewire `kvmVcpuRun` (`kvm.d`): build the `VirtGuestState`
  snapshot (regs from `vc.regs`, sregs from the vCPU cache or zeroed),
  call `virtEnter()`, feed the returned `VirtExitInfo` to
  `virtDispatchExit`. Remove the `vmxIsReady()/svmAvailable()` conditional
  from `kvm.d`. Verify: host tests pass; `KVM_RUN` without hardware still
  returns `-ENODEV` with the `NoHardware` diagnostic.
- [x] 1.3 Rewire `vmxEnter` to the new signature
  `(uint,uint,uint,const VirtGuestState*,VirtExitInfo*)`; keep it
  fail-closed (`-ENODEV`) — the VMX `[HW]` entry tier is untouched.
  Verify: host tests pass; Intel behavior identical to before.

## 2. SLAT abstraction + `Vm` refactor

- [x] 2.1 Add `src/kernel/d/core/virt/slat.d`: `SlatKind`
  (`None`/`Ept`/`Npt`), `struct Slat` (kind + backing builder state),
  `slatInit`, `slatWireKernel`, `slatMap`/`slatUnmap`/`slatLookup`/
  `slatFree`/`slatRootPhys`, generic `SLAT_R/W/X` prot bits. Fail-closed
  on unknown kind. Verify: host test — SLAT over EPT behaves exactly like
  raw EPT (round-trip, readonly, unaligned rejection, leak-free).
- [x] 2.2 Refactor `Vm`: replace `Ept ept` with `Slat slat`; `vmAlloc`
  selects the kind from `virtBackendKind()` (`Svm`→`Npt`, else `Ept` —
  `Ept` is the inert software-only default when no backend exists so
  memslot tests keep working without hardware). Route
  `vmSetMemoryRegion`/`vmUnpinRange`/`vmTeardown` through `slat*`.
  Verify: host tests pass; teardown leaks nothing (`tables==0`).
- [x] 2.3 Add `Vcpu.hwCtrlPhys` (per-vCPU backend control page: VMCS on
  Intel, VMCB on AMD; `0` = not allocated). Free it in `vcpuRelease` and
  `vmTeardown`. Verify: host test — alloc/teardown leaves no page behind.

## 3. NPT implementation

- [x] 3.1 Add `src/kernel/d/core/virt/npt.d`: 4-level walk, 4 KiB pages,
  injected allocator (same pattern as `ept.d`), x86 paging encodings
  (`P`/`RW`/`US`/`NX`), 48-bit GPA/HPA bound, fail-closed validation
  (misaligned, zero page, overflow, unknown prot, duplicate map refused),
  `tables` leak counter, depth-first free. Verify: host test —
  map/lookup/unmap round-trip, readonly (`SLAT_W` clear → `RW`=0,
  `NX` handling), duplicate-map refusal, unaligned rejection,
  allocation-failure unwind, `nptFree` → `tables==0`.
- [x] 3.2 Wire NPT into `slat.d` (`SlatKind.Npt`). Verify: SLAT-over-NPT
  passes the same behavioral tests as SLAT-over-EPT.

## 4. Exit normalization

- [x] 4.1 In `vmexit.d`: add `VirtExitKind`
  (`Unknown`/`Hlt`/`Shutdown`/`Io`/`Hypercall`/`SlatFault`) and
  `VirtExitInfo { kind; qual; gpa; data; count; hardwareReason }`;
  rename `vmxDispatchExit` → `virtDispatchExit`,
  `VmExitInfo` → removed (replaced), `vmxValidateRegs/SRegs/Msrs/
  GuestState` → `virtValidateRegs/SRegs/Msrs/GuestState`; move the
  `EXIT_REASON_*` VMX constants to `vmx.d`. `SlatFault` → `KVM_EXIT_MMIO`
  (was `EPT_VIOLATION` → MMIO). Verify: host dispatch tests updated and
  passing with identical `kvm_run` output bytes.
- [x] 4.2 Rename `VirtDiag.EptViolation` → `VirtDiag.SlatViolation`
  (keep value `4`); update `APPVM_CONTRACT.md` and the conformance doc.
  Verify: `ANONVM_GET_VM_STATE` still reports `4` for a SLAT fault.
- [x] 4.3 Update `selftest.d`, `tests/virt/host/*.d` imports to the new
  names. Verify: `build.sh` green.

## 5. VMCB layout

- [x] 5.1 Add `src/kernel/d/core/virt/vmcb.d`: exact AMD64 APM VMCB
  layout — control area (intercept vectors, `IOPM_BASE_PA`,
  `MSRPM_BASE_PA`, `TSC_OFFSET`, `GUEST_ASID`, `TLB_CONTROL`,
  `EXITCODE`, `EXITINFO1/2`, `EXITINTINFO`, `NP_ENABLE`, `N_CR3`,
  clean bits) and state-save area (segments, GDTR/IDTR/LDTR/TR, `EFER`,
  `CR0/2/3/4`, `RIP/RSP/RAX/RFLAGS`, `CPL`, `DR6/7`) — with
  `static assert`s on total size (1024), 4 KiB alignment requirement,
  and the offsets the backend touches. Verify: compiles; a host test
  asserts every documented offset against the struct layout.
- [x] 5.2 `vmcbInitIntercepts(Vmcb*)`: conservative policy — intercept
  CPUID, HLT, IOIO (via all-intercept IOPM), MSR (via all-intercept
  MSRPM), VMMCALL, all SVM instructions (no nested virt), shutdown.
  IMPLEMENTED AS: intercepts programmed per-VMCB in `svmProgramVmcb`
  (`vmcbSetIntercept`); `IOPM` (12 KiB) / `MSRPM` (8 KiB) allocated per-VM
  (not globally) as single contiguous allocations in `vmAlloc`, all-ones
  init, shared read-only across the VM's vCPUs, freed in `vmTeardown`.
  Per-VM (not global) was chosen for isolation: a compromised guest's
  bitmaps die with its VM. Verify: host test — intercept bits set,
  nested-SVM bits set, IOPM/MSRPM all-ones; `build.sh` green.

## 6. SVM backend

- [x] 6.1 Detection: `svmDetect()` — vendor string `AuthenticAMD` AND
  `CPUID.8000_0001:ECX[2]`; `svmCheckFirmware()` — `MSR_VM_CR`: `SVMDIS`
  set (with or without `LOCK`) → firmware-disabled, fail clean with a
  klog line, never bypass (fixed 2026-09-23: SVMDIS alone #UDs every SVM
  instruction; the old LOCK+SVMDIS conjunction would have run VMRUN into
  #UD). NPT gate: `CPUID.8000_000A` NPT bit; absent →
  backend unavailable (`-ENODEV`, klog explains). Verify: host test —
  pure decode helpers (CPUID/MSR bit parsing) with synthetic values.
- [x] 6.2 `svmCpuInit(cpuId)`: allocate per-CPU host-save page, program
  `MSR_VM_HSAVE_PA`, set `EFER.SVME`, record `maxAsid = EBX-1` from
  `CPUID.8000_000A:EBX` (EBX is the ASID *count* incl. host ASID 0),
  gate `CPUID.8000_000A` on the max extended leaf (CPUID never faults on
  a high leaf — it aliases the max leaf's data), mark CPU ready.
  `svmBootInit()` runs it for the BSP and allocates the shared
  IOPM/MSRPM. Fail-soft: any failure latches not-ready, boot continues.
  Verify: host test — init is a no-op without hardware
  (`svmAvailable()` false); code review of the MSR sequence.
- [x] 6.3 ASID: per-CPU monotonic allocator (`svmAllocAsid(cpuId)`),
  `ASID 0` never handed out, exhaustion falls back to `1`;
  `TLB_CONTROL = FLUSH_ALL` on every `VMRUN` (correctness over speed).
  `maxAsids = EBX-1`: CPUID.8000_000A:EBX is the COUNT of ASIDs (incl.
  host ASID 0); guests get 1..EBX-1 — handing out ASID EBX would be a
  #VMEXIT(INVALID) on VMRUN (fixed 2026-09-23 against the APM/KVM
  reference). Verify: host test — allocator sequence, no `0`,
  exhaustion fallback.
- [x] 6.4 VMCB programming (`svmProgramVmcb`): from `VirtGuestState` —
  segments (selector/base/limit/attrib from `KvmSegment`), `GDTR/IDTR/
  LDTR/TR`, `CR0/CR3/CR4` (validated), `EFER`, `RIP/RSP/RFLAGS/RAX`,
  `CPL=0`; control area — intercepts, `ASID`, `TLB_CONTROL=flush`,
  `NP_ENABLE=1`, `N_CR3 = slatRootPhys`, `TSC_OFFSET=0`, clean bits `0`
  (reload everything). Fail closed (`-EINVAL`) on guest state the
  validator rejects; never program a half-valid VMCB. Verify: host test
  — a synthetic guest state programs the expected VMCB fields; invalid
  state refused before any hardware touch.
- [x] 6.5 `VMRUN` wrapper: minimal auditable transition — save
  callee-saved regs (`RBX/RBP/R12–R15`), `CLGI`, `VMRUN` (raw encoding
  `0F 01 D8`, `RAX` = VMCB phys), `STGI`, restore. Full sequence:
  save host GPRs → `VMSAVE` host → `VMLOAD` guest → `VMRUN` →
  `VMSAVE` guest → `VMLOAD` host → `STGI` → write back guest GPRs →
  restore host GPRs. `STGI` is deliberately AFTER `VMLOAD` host
  (fixed 2026-09-23): no interrupt may observe guest FS/GS/TR/LDTR/
  syscall state. Document exactly which state hardware saves (HSAVE)
  vs the wrapper saves. Known limitation documented: guest FPU/SSE
  not isolated in this tier.
  Verify: code review + `[HW]` smoke (task 9.1).
- [x] 6.6 Exit decoder (`svmDecodeExit`): `EXITCODE` → `VirtExitKind`
  (`HLT`→`Hlt`, `IOIO`→`Io` with port/dir/size/REP+count from
  `EXITINFO1`, `VMMCALL`→`Hypercall` (`CPL` check), `NPF`→`SlatFault`
  with GPA from `EXITINFO2` and write bit from `EXITINFO1`,
  shutdown/triple-fault→`Shutdown`, else `Unknown` with
  `hardwareReason=EXITCODE`). `NRIPS`: advance guest `RIP` past the
  instruction for `Io`/`Hypercall` (update `vc.regs`). Verify: host
  test — synthetic VMCBs decode to the exact `VirtExitInfo` the common
  dispatcher expects.
- [x] 6.7 `svmEnter()`: full path — `vcpuCheck` + lifecycle gate,
  `virtValidateGuestState`, lazy per-vCPU VMCB alloc, `svmProgramVmcb`,
  `svmRunGuest`, `svmDecodeExit`, return `0`/`-ENODEV`/`-EINVAL`/`-EIO`.
  `SVM_BACKEND_READY` replaced by the real readiness latch. Verify:
  host test — no hardware → `-ENODEV`; `[HW]` for the real path.

## 7. Boot + diagnostics + scripts

- [x] 7.1 `core/kmain.d` `initializeKernelCore()`: call `virtBootInit()`
  after `smpBringup()`; `apKernelLoopBody()`: call `virtCpuInit(idx)` on
  each AP. Boot logs: `[virt] backend=svm available=yes` /
  `[svm] SVM enabled (EFER.SVME, HSAVE, host-save area, ...)` on success;
  `[svm] MSR_VM_CR locked with SVMDIS` / `[svm] no SVM ...` /
  `[virt] backend=none available=no` on failure — never `available=yes`
  unless entry is truly enabled. Verify: code review; `[HW]` boot log.
- [x] 7.2 `scripts/virt-hw-test.sh`: replace the AMD fail-closed
  expectations with the real validation path — vendor auto-detect,
  `kvm_amd nested=1` module check, require `[virt] backend: AMD SVM`,
  forbid Intel-only claims (`[vmx] VMXON ok`) on AMD hosts. Verify:
  shellcheck-clean; `[HW]` run on AMD.
- [x] 7.3 `selftest.d`: backend log lines updated (`[virt] backend:
  AMD SVM ready` when `svmAvailable()`); SLAT smoke (map/lookup/unmap
  through `slat*`); dispatch tests use `VirtExitInfo`. Verify: host
  selftest PASS.

## 8. Docs

- [ ] 8.1 `docs/virtualization/ARCHITECTURE.md`: dual-vendor backend
  diagram, SLAT section, Intel↔AMD equivalence table
  (VMX↔SVM, VMCS↔VMCB, VMLAUNCH↔VMRUN, EPT↔NPT, EPT violation↔NPF,
  VPID↔ASID, VM-exit reason↔EXITCODE, EPTP↔N_CR3).
- [ ] 8.2 `docs/virtualization/APPVM_CONTRACT.md` +
  `KVM_CONFORMANCE.md`: `SlatViolation` rename (value `4` unchanged),
  AMD backend notes, FPU/SSE limitation.

## 9. Real-hardware validation [HW]

- [ ] 9.1 `[HW]` AMD smoke guest 1 — `HLT`: `VMRUN` → guest `HLT` →
  `#VMEXIT` → `VirtExitKind.Hlt` → `KVM_EXIT_HLT`, `KVM_RUN` returns
  `0`. Verify: `virt-hw-test.sh` AMD path PASS on the user's machine.
- [ ] 9.2 `[HW]` AMD smoke guest 2 — COM1 `OUT`: guest `OUT 0x3F8, AL`
  → `KVM_EXIT_IO` + `[guestN]` klog tap. Verify: serial log shows the
  tap line.
- [ ] 9.3 `[HW]` AMD smoke guest 3 — NPF + VMMCALL: unmapped GPA access
  → `SlatFault` → `KVM_EXIT_MMIO`; `VMMCALL` → `KVM_EXIT_HYPERCALL`.
  Verify: exit reasons observed on hardware.
- [ ] 9.4 `[HW]` AMD negative matrix: firmware-disabled SVM →
  `[svm] SVM disabled by firmware`, `KVM_RUN` → `ENODEV`, no `#GP`;
  SVM-without-NPT → backend unavailable, `ENODEV`; Intel host →
  AMD path never selected, existing Intel behavior unchanged.
- [ ] 9.5 `[HW]` Intel regression: existing Intel host tests still pass;
  `vmxEnter` still fail-closed `-ENODEV` through the new API.

## 10. Final review

- [ ] 10.1 Security review pass: host-state safety across `VMRUN`,
  guest isolation (no stale ASID/TLB, no dangling SLAT mappings),
  teardown completeness (VMCB/IOPM/MSRPM/NPT/HSAVE/ASID lifetimes),
  Intel/AMD separation (no Intel MSR reads on AMD, no AMD MSRs on
  Intel), fail-closed audit (no fake success paths).
- [ ] 10.2 `openspec` reconciliation: all non-`[HW]` tasks `[x]`;
  `[HW]` tasks listed as remaining with exact validation commands.
