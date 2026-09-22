# Capability: kvm-compatibility

Behavior contract for the KVM-compatible ABI presented to Linux-personality
VMM programs. KVM is a *compatibility* interface: the native VM objects
(`vm-capability-model`) remain the authority model, and every KVM operation
maps onto a native object operation. The covered subset is derived from the
traced behavior of Cloud Hypervisor; it is intentionally not all of Linux
KVM.

## ADDED Requirements

### Requirement: /dev/kvm device node

`/dev/kvm` SHALL exist as an openable device node following the system's
existing device-node pattern (open branch, `FileType`, ioctl/mmap arms).
Opening `/dev/kvm` SHALL require no privilege beyond holding the domain
grant for virtualization; the returned fd represents the KVM *system*
object. Opening SHALL fail with `ENOENT` only if the kernel was built
without virtualization; it SHALL fail with `EACCES` if the caller's
identity/domain lacks the virtualization grant.

#### Scenario: open with and without grant

A Linux-personality program in a domain with the virtualization grant
opens `/dev/kvm` → success. The same program in a domain without the
grant → `EACCES`.

### Requirement: KVM_GET_API_VERSION

`KVM_GET_API_VERSION` on the system fd SHALL return `12`.

#### Scenario: version check

A VMM issues `KVM_GET_API_VERSION` → returns `12`; the VMM proceeds
instead of aborting with "incompatible API version".

### Requirement: KVM_CHECK_EXTENSION semantics

`KVM_CHECK_EXTENSION` SHALL return `1` for exactly the extensions the
implementation supports and `0` otherwise. The supported set SHALL include
at minimum the extensions Cloud Hypervisor probes as mandatory:
`KVM_CAP_USER_MEMORY`, `KVM_CAP_SET_TSS_ADDR`,
`KVM_CAP_SET_IDENTITY_MAP_ADDR`, `KVM_CAP_SPLIT_IRQCHIP`,
`KVM_CAP_MP_STATE`, `KVM_CAP_ADJUST_CLOCK`, `KVM_CAP_XSAVE`,
`KVM_CAP_VCPU_EVENTS`, `KVM_CAP_TSC_DEADLINE_TIMER`, `KVM_CAP_USER_NMI`,
`KVM_CAP_EXT_CPUID`, `KVM_CAP_GET_TSC_KHZ`, `KVM_CAP_IMMEDIATE_EXIT`,
`KVM_CAP_IRQCHIP`.
`KVM_CAP_IRQCHIP` SHALL return `1`: Cloud Hypervisor hard-requires this
probe (`check_required_kvm_extensions` aborts the process when it is
missing), even though it never issues `KVM_CREATE_IRQCHIP` — it enables
the split-irqchip model via `KVM_CAP_SPLIT_IRQCHIP` instead. Claiming the
probe while rejecting `KVM_CREATE_IRQCHIP`/`KVM_CREATE_PIT2` with
`-ENOTTY` is a deliberate, documented split: the probe is a
feature-gate the pinned VMM requires; the creation ioctls are the
in-kernel device-model surface this OS refuses to provide (device
models stay in userspace). Any VMM that actually calls
`KVM_CREATE_IRQCHIP` fails fast with `-ENOTTY` and a documented reason.

#### Scenario: capability probe

Cloud Hypervisor probes its 17 mandatory extensions → all return `1`, so
it proceeds. It probes `KVM_CAP_IRQCHIP` → returns `1` (probe gate
passes); it then enables split irqchip and never calls
`KVM_CREATE_IRQCHIP`. A VMM that does call `KVM_CREATE_IRQCHIP` →
`-ENOTTY` with the split-irqchip-only reason documented.

### Requirement: VM and vCPU file descriptors

`KVM_CREATE_VM` SHALL return a VM fd bound to a native VM object;
`KVM_CREATE_VCPU` on a VM fd SHALL return a vCPU fd bound to a native
vCPU object of that VM. Closing a VM fd SHALL tear down the VM
(equivalent to native teardown); closing the last reference to a vCPU fd
SHALL stop that vCPU. Fds SHALL NOT be usable across VMs (a vCPU fd from
VM A rejected by VM B's ioctls).

#### Scenario: fd lifecycle and isolation

A VMM creates VM A and VM B, then a vCPU on A. Issuing a vCPU ioctl for
A's vCPU fd against B's VM fd → rejected. Closing A's VM fd → A's VM is
torn down; B is unaffected.

### Requirement: Guest memory ioctls

`KVM_SET_USER_MEMORY_REGION` SHALL register guest-physical → userspace
mappings with `flags` `0` or `KVM_MEM_READONLY`; re-registering with
`memory_size = 0` SHALL remove the region. Overlapping registrations
SHALL be rejected. Regions SHALL be backed by the VM's entitled pages;
registration of memory the caller does not own SHALL fail.

#### Scenario: region register and remove

A VMM registers a 1 GiB region at guest-physical 0 → success. It
registers an overlapping region → rejected. It re-registers with size 0
→ the region is removed and the pages are reclaimable.

### Requirement: vCPU state ioctls

The implementation SHALL support `KVM_SET_CPUID2`, `KVM_SET_MSRS`
(boot MSR set), `KVM_SET_REGS`, `KVM_GET_SREGS`/`KVM_SET_SREGS`,
`KVM_SET_FPU`, `KVM_GET_LAPIC`/`KVM_SET_LAPIC`, and `KVM_GET_TSC_KHZ`
with the semantics Cloud Hypervisor relies on. Values that would
compromise the host SHALL be rejected per `vm-capability-model`
CPU-state validation.

#### Scenario: boot-state programming

Cloud Hypervisor's vCPU init sequence (CPUID2 → MSRs → REGS →
SREGS → FPU → LAPIC) → all accepted. An attempt to set a host-reserved
MSR → `EINVAL`.

### Requirement: kvm_run shared memory

`KVM_GET_VCPU_MMAP_SIZE` SHALL return the kernel's `kvm_run` size, and
`mmap` (`MAP_SHARED`, offset 0) on a vCPU fd SHALL map the shared
`kvm_run` page. The `immediate_exit` flag SHALL be honored: a `KVM_RUN`
with the flag set returns promptly without entering the guest.

#### Scenario: immediate exit

A VMM mmaps the `kvm_run` page, sets `immediate_exit = 1`, and calls
`KVM_RUN` → returns immediately with exit reason `KVM_EXIT_INTR`
(or the documented equivalent) without executing guest code.

### Requirement: KVM_RUN and exit structs

`KVM_RUN` SHALL enter the guest and return with a populated `kvm_run`
exit reason. The kernel SHALL produce at least `KVM_EXIT_IO`,
`KVM_EXIT_MMIO`, `KVM_EXIT_HLT`, `KVM_EXIT_SHUTDOWN`, and
`KVM_EXIT_IOAPIC_EOI` (split irqchip) with correctly filled structs.
Signals pending on the vCPU thread SHALL interrupt `KVM_RUN` (EINTR
semantics) so userspace kick mechanisms work.

#### Scenario: HLT exit

A test guest executes `HLT` → `KVM_RUN` returns `KVM_EXIT_HLT`. A
`pthread_kill(SIGRTMIN)`-style kick during `KVM_RUN` → the call returns
with EINTR semantics and the vCPU thread observes the signal.

### Requirement: Interrupt and event ioctls

The implementation SHALL support `KVM_SET_TSS_ADDR`,
`KVM_SET_IDENTITY_MAP_ADDR`, `KVM_ENABLE_CAP` with
`KVM_CAP_SPLIT_IRQCHIP` (24 IOAPIC pins; only the local APIC is
kernel-modeled, PICs/IOAPIC stay in userspace). `KVM_SET_GSI_ROUTING`,
`KVM_IRQFD`, `KVM_IOEVENTFD`, and `KVM_IRQ_LINE` SHALL fail with `ENOTTY`
and their capabilities (`KVM_CAP_IRQ_ROUTING`, `KVM_CAP_IRQFD`,
`KVM_CAP_IOEVENTFD`) SHALL return `0`: advertising interrupt delivery
without an injection backend would be a fake hardware claim.
Split-irqchip delivery (eventfd bridge → LAPIC injection) is an explicit
later tier. `KVM_CREATE_IRQCHIP` and
`KVM_CREATE_PIT2` SHALL fail with `ENOTTY`/`EINVAL` and be documented as
the later full-irqchip tier.

#### Scenario: split irqchip setup fails fast without delivery

A VMM enables split irqchip, then calls `KVM_SET_GSI_ROUTING` or
`KVM_IRQFD`. The calls fail with `ENOTTY` (not silent success, not a
guest hang later). When the delivery tier lands, the scenario becomes:
writing to the eventfd → the guest's local APIC receives the interrupt.
`KVM_CREATE_IRQCHIP` → fails cleanly with documentation pointing at the
later tier.

### Requirement: Clean failure for unsupported ioctls

Any KVM ioctl outside the supported subset SHALL fail with a standard
error (`ENOTTY` for unknown commands, `EINVAL` for bad arguments) —
never silently ignored, never crashing the caller. The unsupported list
SHALL be documented in `docs/` so VMM porters know exactly what to
expect.

#### Scenario: unknown ioctl

A program issues ioctl number `0xAEFF` (undefined) on the system fd →
`ENOTTY`. A fuzzer hammers the dispatch with random commands → no
crashes, no hangs, every call returns an error.
