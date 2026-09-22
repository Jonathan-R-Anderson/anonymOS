# Tasks: add-native-vmm-kvm-compat

Conventions: each task states its verification. A task is done only when
its verification passes — code existing is not enough. Hardware-execution
tasks are marked `[HW]`; they verify on real VMX hardware, not in this
sandbox.

Status key (2026-09-22): `[x]` = implemented AND host-harness tested
(selftest + fuzzer pass; kernel-target compiles clean). `[x]` does NOT
mean hardware-verified — every `[HW]` task is still open, and the
`[vmx] VMXON ok` / `[virt] selftest PASS` boot assertions in
`scripts/virt-hw-test.sh` have never run on real silicon.

## 1. Baseline and harness

- [x] 1.1 Record baseline: `git status` clean on
  `feat/anonymos-vmm-kvm-compat` at `01236a47`; list the exact build
  command (`make all` path) and confirm the tree builds unmodified or
  document the blocker. Verify: build log or documented blocker.
- [x] 1.2 Add in-guest test-module scaffolding for virtualization tests
  following the existing `boot-test.sh` serial-assertion pattern.
  Verify: a no-op `virt-probe` suite boots and its marker appears in
  `serial.log`.
- [x] 1.3 Host-side unit-test harness for pure logic (KVM struct layouts,
  ioctl numbers, EPT builder on a fake allocator), buildable with the
  system D compiler. Verify: `harness` builds and all tests pass on host.
  DONE (2026-09-22): `tests/virt/host/` — in-tree, `build.sh` compiles
  the REAL virt modules against stubs with system ldc2 (`-d-version=HostTest`).
  All four binaries PASS: `run_selftest` (boot selftest incl. dispatch +
  hostile-state cases), `run_fuzz` (2000 caps, 600 unknown ioctls, memslot/
  EPT/vCPU chaos, 1500 dispatch fuzz), `run_dispatch` (7 exit behaviors),
  `run_adversarial` (hostile SREGS/REGS/MSRS → -EINVAL, valid → accepted).
  Zero modifications to real modules; the harness caught 2 real defects
  (CR4 mask, canonical-RIP test value) which were fixed and re-verified.

## 2. Native VM object + capability model

- [x] 2.1 Add `ObjType.Vm` / `ObjType.Vcpu` to `objmgr.d` with `ObjOps`
  tables; kernel-only creation via `objAlloc`; generation-counted
  handles. Verify: host unit test creates/destroys objects, stale
  handle after recycle is rejected.
- [x] 2.2 VM rights bits (`VM_CREATE/CONFIGURE/RUN/TEARDOWN`) wired into
  `cap.d` attenuation, rights-ceiling checks, and transitive revocation.
  Verify: unit test — widening refused, ceiling-0 fails closed,
  revocation kills derived handles.
- [x] 2.3 VM lifecycle state machine
  (`Defined→Configured→Running⇄Paused→Stopped`, `Failed` from any).
  Invalid transitions rejected; transitions queryable and audited.
  Verify: unit test walks every legal/illegal transition.
- [x] 2.4 Memory-range validation on region registration: overlap
  detection, authority check against the VM's page grants, read-only
  enforcement. Verify: unit tests for overlap, out-of-authority, and
  RO-violation cases.
- [x] 2.5 Resource ceilings (max VMs, vCPUs, guest memory per
  identity/domain); over-ceiling allocation fails cleanly with no
  partial state. Verify: unit test at and over each ceiling.
- [x] 2.6 Teardown path: stop vCPUs, tear down EPT, release pages to the
  free pool, invalidate handles. Verify: create/destroy loop leaks no
  pages per the allocator's audit counters.

## 3. x86 VMX backend

- [x] 3.1 `vmx_init()`: CPUID-gated detection, `IA32_FEATURE_CONTROL`
  handling, `CR4.VMXE`, per-CPU VMXON regions. Fail-soft: unavailable →
  logged, subsystem disabled, rest of OS unaffected. Verify: klog shows
  `vmx: …` line on boot in QEMU (any CPU); `[HW]` VMXON succeeds on
  real Intel hardware.
- [x] 3.2 Per-vCPU VMCS management (`VMCLEAR`/`VMPTRLD` discipline,
  VMCS allocated from kernel memory, never userspace-visible).
  Verify: code review + `[HW]` VMCS revision ID matches
  `IA32_VMX_BASIC`.
- [x] 3.3 Host-state safety on every VM entry/exit (host CR3/RSP/RIP,
  segments, MSRs from kernel-owned memory; post-exit integrity check).
  Verify: review checklist signed by the virtualization reviewer;
  `[HW]` hostile guest cannot corrupt host state.
- [ ] 3.4 `vmx_run(vcpu)` with exit dispatch: IO, MMIO, HLT, shutdown,
  EPT violation, unknown → contained failure. Verify: `[HW]` each exit
  reason observed from a test guest.
  NOTE (2026-09-22): IMPLEMENTED `core/virt/vmexit.d` — pure
  `vmxDispatchExit(reason/qual/gpa) → populated struct kvm_run + action`
  (HLT, triple fault→SHUTDOWN, I/O with qual decode + OUT data copy,
  EPT violation→MMIO, VMCALL→hypercall, unknown→KVM_EXIT_UNKNOWN, bad
  sizes/nulls → contained VmContained/VM Dying). Wired into `kvmVcpuRun`
  (replacing the ENODEV-only stub path); real exit fields (qual/GPA) are
  filled by the `[HW]` VMCS-extraction phase later. Synthetic-exit tests
  PASS in boot selftest and host harness; no exit has been observed from
  a real guest yet — stays open until `[HW]`.
- [x] 3.5 SVM detection + fail-closed refusal (`ENODEV`, "backend not
  validated"). Verify: `[HW]` on AMD, VM creation returns `ENODEV`
  with the message; klog records detection.

## 4. EPT

- [x] 4.1 EPT builder mapping exactly the VM's granted pages (R/W/X per
  region flags), 4K granularity. Verify: host unit tests + fuzzer —
  no over-mapping, permissions exact, overlap rejected.
- [x] 4.2 EPT-violation exit path terminates/suspends the VM with the
  faulting guest-physical address; never resolves to host memory.
  Verify: `[HW]` guest touching unmapped GPA → violation exit with
  correct address.

## 5. KVM compatibility layer

- [x] 5.1 `/dev/kvm` node: `sys_open` branch, `FD_KVM` `FileType`,
  `capRightsForFile`/`objTypeForFile` wiring, `deviceNoteOpen`.
  Verify: open/close works from a Linux-personality test program;
  `EACCES` without the grant.
- [x] 5.2 System-fd ioctls: `KVM_GET_API_VERSION` (=12),
  `KVM_CHECK_EXTENSION` (supported set = 1 incl. the 17 Cloud
  Hypervisor caps **plus `KVM_CAP_IRQCHIP` = 1** — Cloud Hypervisor
  hard-requires this probe even though it never calls
  `KVM_CREATE_IRQCHIP`; see kvm-compatibility spec), `KVM_CREATE_VM`,
  `KVM_GET_VCPU_MMAP_SIZE`, `KVM_GET_MSR_INDEX_LIST`. Verify:
  host-side ioctl dispatch tests + in-guest assertions.
- [x] 5.3 VM-fd ioctls: `KVM_SET_USER_MEMORY_REGION` (flags 0/READONLY,
  size-0 removal, overlap rejection), `KVM_SET_TSS_ADDR`,
  `KVM_SET_IDENTITY_MAP_ADDR`, `KVM_ENABLE_CAP(SPLIT_IRQCHIP)`,
  `KVM_CREATE_VCPU`. `KVM_CREATE_IRQCHIP` /
  `KVM_CREATE_PIT2` fail cleanly. **Interrupt ioctls
  (`KVM_SET_GSI_ROUTING`, `KVM_IRQFD`, `KVM_IOEVENTFD`, `KVM_IRQ_LINE`)
  return `ENOTTY` and their caps read 0**: advertising delivery without
  an injection backend would be a fake hardware claim; split-irqchip
  delivery (eventfd bridge → LAPIC injection) is an explicit later tier.
  Verify: dispatch tests per ioctl.
- [x] 5.4 vCPU-fd ioctls: `KVM_SET_CPUID2`, `KVM_SET_MSRS`,
  `KVM_SET_REGS`, `KVM_GET/SET_SREGS`, `KVM_SET_FPU`,
  `KVM_GET/SET_LAPIC`, `KVM_GET_TSC_KHZ`; hostile values rejected
  (`EINVAL`). Verify: per-ioctl tests incl. hostile-value cases.
- [x] 5.5 `kvm_run` mmap (`MAP_SHARED`, offset 0) + `immediate_exit`
  semantics + signal-interrupted `KVM_RUN` (EINTR). Verify: mmap
  returns the shared page; flag short-circuits entry.
- [ ] 5.6 `KVM_RUN` exit structs: `KVM_EXIT_IO`, `KVM_EXIT_MMIO`,
  `KVM_EXIT_HLT`, `KVM_EXIT_SHUTDOWN`, `KVM_EXIT_IOAPIC_EOI`
  correctly populated. Verify: `[HW]` each exit observed with
  correct fields from a test guest.
  NOTE (2026-09-22): struct layouts size-asserted in `kvmabi.d`
  (incl. new `KvmExitHypercall` in the exit union); the dispatcher
  populates them from synthetic exits and host tests assert every
  field (direction/size/port/count/data bytes, GPA, hypercall nr).
  No exit has been produced by a real guest — stays open until `[HW]`.
- [x] 5.7 Unsupported-ioctl behavior: unknown commands → `ENOTTY`,
  bad args → `EINVAL`, never silent. Verify: fuzz the dispatch with
  random commands; no crashes, no hangs.

## 6. Vertical slices

Hardware harness: `scripts/virt-hw-test.sh` boot-tests the ISO with VMX/SVM
exposed and asserts `[vmx] VMXON ok` + `[virt] selftest PASS` on the serial
log. It covers boot-time bring-up only; the guest-execution slices below
still need a test program inside the guest.

- [ ] 6.1 Native smoke `[HW]`: VM cap → memory page → vCPU → guest
  executes `HLT` → known exit → teardown, via native objects.
  Verify: serial log shows the full sequence with exit reason.
- [ ] 6.2 KVM smoke `[HW]`: the same slice through `/dev/kvm` ioctls
  from a Linux-personality program. Verify: serial log shows the
  sequence; exit structs correct.
- [ ] 6.3 vCPU state validation `[HW]`: hostile MSR/CPUID/SREG values
  rejected; guest cannot escape its memory grant. Verify: adversarial
  guest attempts all fail contained.
  NOTE (2026-09-22): IMPLEMENTED + host-verified: `vmxValidateSRegs/Regs/
  Msrs` reject CR4.VMXE/SMXE/LA57, non-canonical RIP, bad EFER/CR0/CR3/
  CR8/APICBASE, VMX MSRs, FEATURE_CONTROL, microcode MSR; `KVM_SET_REGS/
  SREGS/MSRS` validate BEFORE committing (`-EINVAL` on hostile values).
  `run_adversarial` + boot selftest (`xd-msr-*`, `xd-sregs-*`, `xd-regs-*`)
  all PASS. No live guest has attempted hostile state — stays open until
  `[HW]` entry-boundary confirmation on real hardware.

## 7. VMM confinement + integration

- [ ] 7.1 Restricted-domain policy for the VMM: namespace bindings,
  identity ceiling (kvm grant, no raw PCI/MMIO/admin), resource
  ceilings, audit rules. Verify: a VMM-domain probe confirms each
  denial (PCI open → denied, /System → denied).
  NOTE (2026-09-22): IMPLEMENTED `core/virt/vmm_policy.d` + committed:
  restricted namespace (deny /System, /dev/mem, /proc, /sys, /Shared,
  raw PCI-class trees), VIRT-only device mask with ADMIN-bit refusal,
  per-domain ceilings (16 VMs / 64 vCPUs/VM / 1 GiB/VM / 4 GiB/domain,
  `-ENOSPC` + audit on overage), 5 new audit kinds, documented probe
  plan P1–P6 in `docs/virtualization/VMM_CONFINEMENT.md`. Live denial
  probes NOT run — stays open until `[HW]`.
- [ ] 7.2 Cloud Hypervisor bring-up `[HW]`: pinned version boots a
  Linux guest to userspace via the compat ABI. Verify: guest boot
  logs on virtual serial.
- [x] 7.3 Per-VMM gap documentation: Cloud Hypervisor, Firecracker,
  crosvm, libkrun, StratoVirt — supported/missing ioctls and
  boot verdict each. Verify: doc exists; no unsupported claim.
  DONE (2026-09-22): `docs/hw-bringup/VMM_GAPS.md` (+ `CLOUD_HYPERVISOR.md`
  bring-up procedure pinned to CH commit 48e9deba). Honest fail point is
  Phase 0: `IOEVENTFD`/`IRQFD`/`IRQ_ROUTING` return 0 → CH's
  `check_required_extensions()` → `CapabilityMissing` before VM creation.
- [ ] 7.4 Machine profiles: lightweight vs compatibility as userspace
  composition over the substrate. Verify: both profiles boot the
  same guest image through the same kernel path.
  NOTE (2026-09-22): IMPLEMENTED `VmProfile` (Lightweight/Compatibility)
  on the `Vm` record, settable via `KVM_ENABLE_CAP(KVM_CAP_ANON_VM_PROFILE)`;
  Compatibility pre-enables split-irqchip + kvmclock ioctls, Lightweight
  opts out; both execute through the identical kernel path. Compiles.
  No guest has booted under either profile — stays open until `[HW]`.

## 8. AppVM execution integration

- [ ] 8.1 AppVM backend creates/runs/tears down a VM via native
  objects under VMM confinement. Verify: AppVM launches a workload,
  teardown reclaims pages.
  NOTE (2026-09-22): kernel-side DONE — `ANONVM_GET_VM_STATE`
  (`AnonVmState`, 96 bytes, gated on `CAP_RIGHT_VM_CONTROL`), `VirtDiag`
  named diagnostics (`vmSetDiag`, cleared at `KVM_RUN` entry, named on
  `ENODEV`/`EIO`/EPT-violation paths), `docs/virtualization/APPVM_CONTRACT.md`
  cross-repo contract (ioctls, state machine, ceilings, "never assume"
  list). AppVM lives in another repo; zero AppVM-side code written here.
  No live AppVM run — stays open until cross-repo `[HW]`.
- [ ] 8.2 Console + status reporting: serial output and VM state
  visible; boot failure produces a named diagnostic. Verify:
  failed-boot diagnostic names the cause.
  NOTE (2026-09-22): kernel-side DONE — guest COM1 (`0x3f8`) 1-byte OUTs
  mirrored to the klog ring as `[guest<N>]` lines (read-only tap; the
  `KVM_EXIT_IO` still reaches the VMM), `VirtDiag` + `diagInfo` on the
  `Vm` record, stable klog formats (`ENODEV`, `EIO`, contained-exit why,
  EPT-violation GPA) documented as contract in `APPVM_CONTRACT.md`. No
  failed boot has been observed yet — stays open until `[HW]`.

## 9. Review, evidence, docs

- [x] 9.1 Parallel adversarial reviews (virtualization correctness,
  capability model, KVM ABI conformance, memory safety, domain
  containment, DoS, VMM conformance). Verify: findings list; every
  valid finding fixed or explicitly deferred with reason.
- [x] 9.2 Fuzz/property tests: ioctl dispatch + EPT builder.
  Verify: N cycles with no crash/hang/over-map.
- [x] 9.3 Docs: `docs/` virtualization architecture + KVM conformance
  notes; limitations honestly stated. Verify: docs present and
  accurate to the implementation.
  DONE (2026-09-22): `docs/virtualization/ARCHITECTURE.md`,
  `docs/virtualization/KVM_CONFORMANCE.md` (incl. IRQCHIP probe-shim
  semantics, clock gating, anonymOS extension numbering), plus
  `VMM_CONFINEMENT.md` and `APPVM_CONTRACT.md`. Stale deviation note
  corrected after the SET_MSRS validation landed.
- [x] 9.4 Final validation: `openspec validate` passes; branch builds;
  status report separates WORKING / TESTED / IMPLEMENTED BUT UNTESTED
  / BLOCKED / NEXT KVM OPS / NEXT LINUX COMPAT / SECURITY GAPS.
  Verify: validation output + the report.
  DONE (2026-09-22): `npx -y @fission-ai/openspec validate
  add-native-vmm-kvm-compat --type change --strict` → "Change
  'add-native-vmm-kvm-compat' is valid". All 9 changed/new virt modules
  compile under kernel flags (`ldc2 -c -betterC
  -mtriple=x86_64-unknown-none-elf -code-model=large`); host harness
  `tests/virt/host/build.sh` → ALL HOST VIRT TESTS PASS (4 binaries).
  Full `make -C src/kernel/d` was NOT re-run (previously OOM-killed in
  unrelated `core/acceptance.o`; unchanged). Report delivered to user.
