# Tasks: add-native-vmm-kvm-compat

Conventions: each task states its verification. A task is done only when
its verification passes — code existing is not enough. Hardware-execution
tasks are marked `[HW]`; they verify on real VMX hardware, not in this
sandbox.

## 1. Baseline and harness

- [ ] 1.1 Record baseline: `git status` clean on
  `feat/anonymos-vmm-kvm-compat` at `01236a47`; list the exact build
  command (`make all` path) and confirm the tree builds unmodified or
  document the blocker. Verify: build log or documented blocker.
- [ ] 1.2 Add in-guest test-module scaffolding for virtualization tests
  following the existing `boot-test.sh` serial-assertion pattern.
  Verify: a no-op `virt-probe` suite boots and its marker appears in
  `serial.log`.
- [ ] 1.3 Host-side unit-test harness for pure logic (KVM struct layouts,
  ioctl numbers, EPT builder on a fake allocator), buildable with the
  system D compiler. Verify: `harness` builds and all tests pass on host.

## 2. Native VM object + capability model

- [ ] 2.1 Add `ObjType.Vm` / `ObjType.Vcpu` to `objmgr.d` with `ObjOps`
  tables; kernel-only creation via `objAlloc`; generation-counted
  handles. Verify: host unit test creates/destroys objects, stale
  handle after recycle is rejected.
- [ ] 2.2 VM rights bits (`VM_CREATE/CONFIGURE/RUN/TEARDOWN`) wired into
  `cap.d` attenuation, rights-ceiling checks, and transitive revocation.
  Verify: unit test — widening refused, ceiling-0 fails closed,
  revocation kills derived handles.
- [ ] 2.3 VM lifecycle state machine
  (`Defined→Configured→Running⇄Paused→Stopped`, `Failed` from any).
  Invalid transitions rejected; transitions queryable and audited.
  Verify: unit test walks every legal/illegal transition.
- [ ] 2.4 Memory-range validation on region registration: overlap
  detection, authority check against the VM's page grants, read-only
  enforcement. Verify: unit tests for overlap, out-of-authority, and
  RO-violation cases.
- [ ] 2.5 Resource ceilings (max VMs, vCPUs, guest memory per
  identity/domain); over-ceiling allocation fails cleanly with no
  partial state. Verify: unit test at and over each ceiling.
- [ ] 2.6 Teardown path: stop vCPUs, tear down EPT, release pages to the
  free pool, invalidate handles. Verify: create/destroy loop leaks no
  pages per the allocator's audit counters.

## 3. x86 VMX backend

- [ ] 3.1 `vmx_init()`: CPUID-gated detection, `IA32_FEATURE_CONTROL`
  handling, `CR4.VMXE`, per-CPU VMXON regions. Fail-soft: unavailable →
  logged, subsystem disabled, rest of OS unaffected. Verify: klog shows
  `vmx: …` line on boot in QEMU (any CPU); `[HW]` VMXON succeeds on
  real Intel hardware.
- [ ] 3.2 Per-vCPU VMCS management (`VMCLEAR`/`VMPTRLD` discipline,
  VMCS allocated from kernel memory, never userspace-visible).
  Verify: code review + `[HW]` VMCS revision ID matches
  `IA32_VMX_BASIC`.
- [ ] 3.3 Host-state safety on every VM entry/exit (host CR3/RSP/RIP,
  segments, MSRs from kernel-owned memory; post-exit integrity check).
  Verify: review checklist signed by the virtualization reviewer;
  `[HW]` hostile guest cannot corrupt host state.
- [ ] 3.4 `vmx_run(vcpu)` with exit dispatch: IO, MMIO, HLT, shutdown,
  EPT violation, unknown → contained failure. Verify: `[HW]` each exit
  reason observed from a test guest.
- [ ] 3.5 SVM detection + fail-closed refusal (`ENODEV`, "backend not
  validated"). Verify: `[HW]` on AMD, VM creation returns `ENODEV`
  with the message; klog records detection.

## 4. EPT

- [ ] 4.1 EPT builder mapping exactly the VM's granted pages (R/W/X per
  region flags), 4K granularity. Verify: host unit tests + fuzzer —
  no over-mapping, permissions exact, overlap rejected.
- [ ] 4.2 EPT-violation exit path terminates/suspends the VM with the
  faulting guest-physical address; never resolves to host memory.
  Verify: `[HW]` guest touching unmapped GPA → violation exit with
  correct address.

## 5. KVM compatibility layer

- [ ] 5.1 `/dev/kvm` node: `sys_open` branch, `FD_KVM` `FileType`,
  `capRightsForFile`/`objTypeForFile` wiring, `deviceNoteOpen`.
  Verify: open/close works from a Linux-personality test program;
  `EACCES` without the grant.
- [ ] 5.2 System-fd ioctls: `KVM_GET_API_VERSION` (=12),
  `KVM_CHECK_EXTENSION` (supported set = 1 incl. the 17 Cloud
  Hypervisor caps **plus `KVM_CAP_IRQCHIP` = 1** — Cloud Hypervisor
  hard-requires this probe even though it never calls
  `KVM_CREATE_IRQCHIP`; see kvm-compatibility spec), `KVM_CREATE_VM`,
  `KVM_GET_VCPU_MMAP_SIZE`, `KVM_GET_MSR_INDEX_LIST`. Verify:
  host-side ioctl dispatch tests + in-guest assertions.
- [ ] 5.3 VM-fd ioctls: `KVM_SET_USER_MEMORY_REGION` (flags 0/READONLY,
  size-0 removal, overlap rejection), `KVM_SET_TSS_ADDR`,
  `KVM_SET_IDENTITY_MAP_ADDR`, `KVM_ENABLE_CAP(SPLIT_IRQCHIP)`,
  `KVM_CREATE_VCPU`. `KVM_CREATE_IRQCHIP` /
  `KVM_CREATE_PIT2` fail cleanly. **Interrupt ioctls
  (`KVM_SET_GSI_ROUTING`, `KVM_IRQFD`, `KVM_IOEVENTFD`, `KVM_IRQ_LINE`)
  return `ENOTTY` and their caps read 0**: advertising delivery without
  an injection backend would be a fake hardware claim; split-irqchip
  delivery (eventfd bridge → LAPIC injection) is an explicit later tier.
  Verify: dispatch tests per ioctl.
- [ ] 5.4 vCPU-fd ioctls: `KVM_SET_CPUID2`, `KVM_SET_MSRS`,
  `KVM_SET_REGS`, `KVM_GET/SET_SREGS`, `KVM_SET_FPU`,
  `KVM_GET/SET_LAPIC`, `KVM_GET_TSC_KHZ`; hostile values rejected
  (`EINVAL`). Verify: per-ioctl tests incl. hostile-value cases.
- [ ] 5.5 `kvm_run` mmap (`MAP_SHARED`, offset 0) + `immediate_exit`
  semantics + signal-interrupted `KVM_RUN` (EINTR). Verify: mmap
  returns the shared page; flag short-circuits entry.
- [ ] 5.6 `KVM_RUN` exit structs: `KVM_EXIT_IO`, `KVM_EXIT_MMIO`,
  `KVM_EXIT_HLT`, `KVM_EXIT_SHUTDOWN`, `KVM_EXIT_IOAPIC_EOI`
  correctly populated. Verify: `[HW]` each exit observed with
  correct fields from a test guest.
- [ ] 5.7 Unsupported-ioctl behavior: unknown commands → `ENOTTY`,
  bad args → `EINVAL`, never silent. Verify: fuzz the dispatch with
  random commands; no crashes, no hangs.

## 6. Vertical slices

- [ ] 6.1 Native smoke `[HW]`: VM cap → memory page → vCPU → guest
  executes `HLT` → known exit → teardown, via native objects.
  Verify: serial log shows the full sequence with exit reason.
- [ ] 6.2 KVM smoke `[HW]`: the same slice through `/dev/kvm` ioctls
  from a Linux-personality program. Verify: serial log shows the
  sequence; exit structs correct.
- [ ] 6.3 vCPU state validation `[HW]`: hostile MSR/CPUID/SREG values
  rejected; guest cannot escape its memory grant. Verify: adversarial
  guest attempts all fail contained.

## 7. VMM confinement + integration

- [ ] 7.1 Restricted-domain policy for the VMM: namespace bindings,
  identity ceiling (kvm grant, no raw PCI/MMIO/admin), resource
  ceilings, audit rules. Verify: a VMM-domain probe confirms each
  denial (PCI open → denied, /System → denied).
- [ ] 7.2 Cloud Hypervisor bring-up `[HW]`: pinned version boots a
  Linux guest to userspace via the compat ABI. Verify: guest boot
  logs on virtual serial.
- [ ] 7.3 Per-VMM gap documentation: Cloud Hypervisor, Firecracker,
  crosvm, libkrun, StratoVirt — supported/missing ioctls and
  boot verdict each. Verify: doc exists; no unsupported claim.
- [ ] 7.4 Machine profiles: lightweight vs compatibility as userspace
  composition over the substrate. Verify: both profiles boot the
  same guest image through the same kernel path.

## 8. AppVM execution integration

- [ ] 8.1 AppVM backend creates/runs/tears down a VM via native
  objects under VMM confinement. Verify: AppVM launches a workload,
  teardown reclaims pages.
- [ ] 8.2 Console + status reporting: serial output and VM state
  visible; boot failure produces a named diagnostic. Verify:
  failed-boot diagnostic names the cause.

## 9. Review, evidence, docs

- [ ] 9.1 Parallel adversarial reviews (virtualization correctness,
  capability model, KVM ABI conformance, memory safety, domain
  containment, DoS, VMM conformance). Verify: findings list; every
  valid finding fixed or explicitly deferred with reason.
- [ ] 9.2 Fuzz/property tests: ioctl dispatch + EPT builder.
  Verify: N cycles with no crash/hang/over-map.
- [ ] 9.3 Docs: `docs/` virtualization architecture + KVM conformance
  notes; limitations honestly stated. Verify: docs present and
  accurate to the implementation.
- [ ] 9.4 Final validation: `openspec validate` passes; branch builds;
  status report separates WORKING / TESTED / IMPLEMENTED BUT UNTESTED
  / BLOCKED / NEXT KVM OPS / NEXT LINUX COMPAT / SECURITY GAPS.
  Verify: validation output + the report.
