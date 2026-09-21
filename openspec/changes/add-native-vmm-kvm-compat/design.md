# Design: add-native-vmm-kvm-compat

## Context

See `proposal.md` (Why) and `specs/*/spec.md` (behavior contracts). Current
state, from reconnaissance (`~/workspace/anonymOS-recon/ARCHITECTURE.md`):

- Kernel is `-betterC` D (LDC2), x86_64, x2APIC-only. `CR4.VMXE` is never set;
  no VMX/SVM/EPT/NPT/VMCS/VMCB code exists anywhere in `src/`.
- Objects live in one fixed 8192-slot table (`objmgr.d`); only the kernel
  creates them via `objAlloc`. Capabilities are 20-byte `{objId, rights, …}`
  in per-task tables, strictly attenuating, with transitive revocation.
- Domains are a 32-slot registry with deny-by-default namespaces; the VMM
  runs as an ordinary confined task.
- Linux-personality programs reach the kernel through the syscall translation
  layer (`ioctl` = syscall 16, `mmap`, `eventfd2`, `epoll`, `memfd_create`
  all implemented). `/dev/*` nodes are hardcoded branches in `sys_open`;
  `mknod` returns `-EROFS`.
- Tests are QEMU-boot suites asserting on serial-log strings (`boot-test.sh`);
  there are no D `unittest` blocks in `src/`.

Evidence inputs: `KVM_API_TRACE.md` (Cloud Hypervisor's exact ioctl surface,
traced to source) and `VMM_COMPARISON.md` (StratoVirt/crosvm/libkrun/
Firecracker all require in-kernel `KVM_CREATE_IRQCHIP`+`KVM_CREATE_PIT2`).

## Goals / Non-Goals

Goals: a minimal, secure, working VMX substrate; VM/vCPU as capability
objects; a KVM ABI sufficient to boot Cloud Hypervisor; the VMM confined
in a standard domain; everything testable in QEMU.

Non-goals (this change): in-kernel 8259 PIC / IOAPIC / PIT
(`KVM_CREATE_IRQCHIP`, `KVM_CREATE_PIT2`); physical device passthrough;
AMD SVM execution; Windows guests; snapshot/migration ioctls; virtio
device emulation in the kernel; forking any VMM.

## Decisions

### 1. VM and vCPU become new `ObjType`s in the existing object manager

New `ObjType.Vm` / `ObjType.Vcpu` entries in `objmgr.d`'s enum, with
`ObjOps` method tables, created only via `objAlloc`. Rationale: reuses
the audited capability machinery (attenuation, rights ceilings,
transitive revocation, `requireCap` checks) instead of inventing a
parallel handle system that would need its own security review.
Alternative (fd-only pseudo-objects like Linux KVM) rejected: it would
bypass the capability model the whole OS is built on.

New rights bits (within the existing 19-bit space or extended per
`cap.d` conventions): `VM_CREATE`, `VM_CONFIGURE` (memory/vCPU setup),
`VM_RUN`, `VM_TEARDOWN`. A `/dev/kvm` open grants a system-level cap
from which VM caps derive, strictly attenuated.

### 2. VMX backend lives in `arch/x86_64`, kernel-only, per-CPU VMXON

New module (e.g. `arch/x86_64/vmx.d`): CPUID-gated `vmx_init()` runs at
boot (fail-soft: logs and disables), per-CPU VMXON regions, per-vCPU
VMCS allocated from kernel memory, `VMCLEAR`/`VMPTRLD` discipline, and a
single `vmx_run(vcpu)` entry point that does `VMLAUNCH`/`VMRESUME` and
returns a decoded exit. Host-state fields (host CR3/RSP/RIP, segment
selectors, key MSRs) are filled from kernel-owned constants on every
entry — never from userspace. Rationale: keeps all privileged
virtualization state behind the existing kernel/userspace boundary;
matches "kernel owns VMX/SVM privileged operations".

### 3. EPT reuses the 4-level page-table code

EPT is structurally a 4-level table walk like the existing `arch.d`
pagers. The design adds an EPT builder that maps exactly the VM's
granted pages (from `alloc_phys_pages` / the VM's Untyped budget) with
R/W/X per the region flags, plus an EPT-violation exit path. No
second-level translation exists today, so this is new code — but it
follows the reviewed `map_page` patterns rather than a fresh MMU design.

### 4. KVM compat is a `FileType`, not a syscall family

`/dev/kvm` gets a `cstrEq` branch in `sys_open` (allocating `FD_KVM`),
an arm in `fileObjIoctl` dispatching the supported `KVM_*` commands, and
an arm in `fileObjMmap` for the `kvm_run` shared page — exactly the
extension pattern recon documented. Linux-personality VMMs reach it via
the already-implemented `ioctl`/`mmap` translation; no new syscalls are
added. Each KVM fd (system/VM/vCPU) wraps the corresponding native
capability: the ioctl layer translates KVM semantics into native object
operations, so the capability checks in (1) always apply.

### 5. Split irqchip only; local APIC in kernel, IOAPIC in userspace

`KVM_ENABLE_CAP(KVM_CAP_SPLIT_IRQCHIP)` is supported; `KVM_CREATE_IRQCHIP`
/ `KVM_CREATE_PIT2` return errors. The kernel models the local APIC
(reusing x2APIC MSR code) and delivers interrupts via the GSI routing
table + irqfd eventfds; the IOAPIC/PICs are userspace (Cloud Hypervisor
already ships one). Rationale: evidence-driven — the primary target VMM
never calls the full-irqchip ioctls, and a kernel 8259/PIT is exactly
the "giant PC chipset emulator in the kernel" the mission forbids.

### 6. All device emulation in userspace via exits

`KVM_EXIT_IO` / `KVM_EXIT_MMIO` return to the VMM with decoded operands;
the kernel never emulates virtio or legacy devices. `KVM_IOEVENTFD`
(MMIO, no datamatch) turns guest writes at registered addresses into
eventfd signals for fast doorbells.

### 7. VMM confinement uses existing domain machinery

No new sandbox primitives. The VMM's domain gets the deny-by-default
namespace, an identity whose ceiling includes the virtualization grant
but excludes raw PCI/MMIO/admin, and resource ceilings. This is
configuration + a small amount of policy code, not a new isolation
mechanism.

### 8. Machine profiles follow StratoVirt's shape

One substrate; `Lightweight` vs `Compatibility` profiles differ in
userspace machine composition (transport, firmware, ACPI tables), not
in kernel primitives. The kernel does not know about profiles.

### 9. Testing strategy

- **In-guest modules** via the existing `boot-test.sh` mechanism: a VMX
  probe module (reports VMX/SVM presence), a native-smoke module (VM
  cap → page → vCPU → guest `HLT` → exit → teardown), and a KVM-smoke
  module (the same through `/dev/kvm` ioctls). Assertions are
  serial-log strings, the established pattern.
- **Host-side unit tests** for pure logic that doesn't need the kernel
  (KVM struct layouts, capability-derivation math, EPT builder on a
  fake phys allocator) — compiled with the system D compiler where
  available, kept out of the kernel tree's `-betterC` constraints.
- **Fuzz/property tests** for the ioctl dispatch argument validation
  and the EPT builder (bounds, overlap, permission mapping).

## Risks / Trade-offs

- [Risk] No VMX-capable CPU in this build environment (sandbox CPU
  exposes no `vmx`/`svm`; `/dev/kvm` absent) → **Mitigation**: all
  hardware-execution claims gated on real hardware; ship exact probe/boot
  scripts; architecture-independent code (capability model, ioctl
  dispatch validation, EPT builder logic) fully tested on host; VMX
  backend marked `IMPLEMENTED BUT UNTESTED` until hardware run.
- [Risk] EPT + page-allocator integration bugs could expose host memory
  → **Mitigation**: EPT builder only maps pages from the VM's explicit
  grant list; violation exits terminate the VM; adversarial review
  focused on the grant→EPT path; fuzzer on the builder.
- [Risk] KVM ioctl semantics drift vs Cloud Hypervisor versions →
  **Mitigation**: subset pinned to the traced commit; `KVM_API_TRACE.md`
  kept with the change as the conformance reference; unsupported ioctls
  fail loudly (`ENOTTY`) instead of half-working.
- [Risk] Full-irqchip VMMs (Firecracker/crosvm/libkrun/StratoVirt) won't
  boot → **Mitigation**: documented as the later tier in specs and docs;
  `KVM_CHECK_EXTENSION(KVM_CAP_IRQCHIP)` returns 0 so VMMs fail fast with
  a clear message instead of mysterious hangs.
- [Risk] Multi-hour kernel build slows iteration → **Mitigation**:
  develop pure logic host-side first; batch kernel changes; keep new
  modules self-contained to limit rebuild scope.

## Migration Plan

N/A (new subsystem, no existing users). Rollback = don't open `/dev/kvm`;
the kernel without any VM creation behaves exactly as before. The VMX
init is fail-soft at boot.

## Open Questions

1. Exact LDC version in the blessed Docker image (unpinned) — needed
   for reproducing `-betterC` builds; does not change specs or tasks.
2. Whether the Untyped physical-allocation gate is enabled in production
   boot (affects which budget VM pages charge against) — recon open
   question; the implementation will probe at runtime and handle both.
3. `FD_DRM` mmap mapping a userspace offset verbatim as a physical
   address (`posix.d:12522-12529`) — flagged to the kernel owners as a
   separate security issue; this change does not touch that path but
   the VM memory path is designed to never share it.
