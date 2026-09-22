# Native Virtualization Architecture

> **STATUS.** This document describes the architecture as implemented in
> `src/kernel/d/core/virt/` (`vm.d`, `vmx.d`, `svm.d`, `ept.d`, `kvm.d`,
> `kvmabi.d`, `selftest.d`; ~2700 lines, `-betterC`, `@nogc nothrow`) on branch
> `feat/anonymos-vmm-kvm-compat`. No guest has ever run: guest entry
> (`vmxEnter`/`svmEnter`) is declared but not implemented — the `[HW]` phase —
> and this document does not claim otherwise.

## 1. The authoritative objects: native VM/vCPU

The virtualization substrate is a set of **native kernel objects**, not the KVM
ABI. They live in the central object table as `ObjType.Vm` / `ObjType.Vcpu`
(`src/kernel/d/core/virt/vm.d`), with `impl` pointing at records in static
pools — address-stable, so the object mirror never orphans.

- `Vm`: lifecycle state, the EPT root, memslot table, pinned-page accounting,
  TSS/identity-map addresses, split-irqchip flag, the GSI routing table
  structs (for the future delivery tier).
- `Vcpu`: index, register file (`regs[18]`), state machine, lazily-allocated
  state caches (fixed-regs+MSRs page, CPUID2 page, XSAVE page), the `kvm_run`
  shared page (`runPhys`).

A VMM that wants virtualization **without** the Linux ABI would use these
objects directly — that is the native path. Everything KVM-shaped is a
translation layer on top (see §2).

## 2. KVM is a compatibility ABI, not the substrate

`core.virt.kvm` translates Linux KVM ioctls into operations on the native
objects; **it never bypasses them**. The fd trinity maps cleanly onto
capability-checked objects:

- `/dev/kvm` (system fd) → `kvmSystemIoctl`: `KVM_GET_API_VERSION`,
  `KVM_CHECK_EXTENSION`, `KVM_CREATE_VM` (type 0 only), `KVM_GET_VCPU_MMAP_SIZE`,
  `KVM_GET_SUPPORTED_CPUID`, `KVM_GET_MSR_INDEX_LIST`.
- VM fd → `kvmVmIoctl`: `KVM_CREATE_VCPU`, `KVM_SET_USER_MEMORY_REGION`,
  `KVM_SET_TSS_ADDR`, `KVM_SET_IDENTITY_MAP_ADDR`, `KVM_ENABLE_CAP`
  (split-irqchip only), plus the honestly-rejected delivery ioctls
  (`KVM_CREATE_IRQCHIP`, `KVM_CREATE_PIT2`, `KVM_SET_GSI_ROUTING`, `KVM_IRQFD`,
  `KVM_IOEVENTFD`, `KVM_IRQ_LINE` → `ENOTTY`).
- vCPU fd → `kvmVcpuIoctl`: the `GET/SET_*` state family, `KVM_RUN`
  (`kvmVcpuRun`), and the vCPU-fd `mmap` of the 4096-byte `kvm_run` page
  (`kvmVcpuMmap`).

`core.virt.kvmabi` is **pure data**: ioctl numbers, `KVM_CAP_*` numbers, exit
reasons, and struct layouts with `static assert`s against the sizes measured
from the authoritative UAPI headers (`kvm_run`=2352, `kvm_regs`=144,
`kvm_sregs`=312, `kvm_fpu`=416, ...). It has no dependency on hardware, the
object model, or the syscall layer. (During verification it caught two errors
in the earlier trace: `KVM_GET_MSR_INDEX_LIST` is `0xc004ae02`, not
`0xc008ae05`; `KVM_CREATE_PIT2` is `0x4040ae77`, not `0xa0`.)

## 3. The kernel owns the privileged operations

Privileged virtualization state is kernel-owned, end of story:

- **`core.virt.vmx`** — Intel VMX: `vmxDetect()` reads the real
  `CPUID.1:ECX[5]`; `vmxBootInit()` is fail-soft (checks
  `IA32_FEATURE_CONTROL`, enables VMXON outside SMX if the BIOS left it
  unlocked, sets `CR4.VMXE`, allocates the VMXON region with the correct
  revision ID, executes `VMXON`; any failure latches `g_vmxReady=false` and
  boot continues — virtualization is simply unavailable). `vmxEnter()` is
  declared but returns `VMX_NOHW` until the `[HW]` phase implements VMCS
  programming + `VMLAUNCH` against real hardware.
- **`core.virt.svm`** — AMD SVM: detection-only (`CPUID.8000_0001:ECX[2]`);
  `svmEnter()` fails closed with `ENODEV`. VMCB layout, ASID management, NPT,
  and `VMRUN` are an explicitly later tier — "claiming SVM support without a
  verified execution path would be a fake-hardware claim".
- **`core.virt.ept`** — EPT builder (4-level walk, 4 KiB pages, on-demand
  table allocation, fail-closed validation). The allocator is injected, so the
  module is fully testable on the host; the kernel wires in
  `alloc_phys_page`/`free_phys_page` and `phys_to_virt`.

**The VMM (userspace) never touches these.** Device models stay in userspace;
the kernel is asked only for vCPU execution, memory, and (later) LAPIC/irqfd
delivery. This mirrors Cloud Hypervisor's own shape: all virtio emulation
happens in userspace via MMIO/PIO exits; the kernel is not a device model.

## 4. Capability model

Every mutating ioctl is gated by a capability right, resolved per fd kind and
ioctl (`kvmRequiredRight` in `kvm.d`):

| right | covers |
|---|---|
| `CAP_RIGHT_VM_CREATE` | `KVM_CREATE_VM` on the system fd |
| `CAP_RIGHT_VM_CONTROL` | VM/vCPU configuration ioctls (memslots, TSS/identity-map, caps, vCPU state) |
| `CAP_RIGHT_VM_MEM` | `KVM_SET_USER_MEMORY_REGION` |
| `CAP_RIGHT_VM_RUN` | `KVM_RUN` only |

Creating a VM/vCPU fd does not implicitly grant the rights to use it — the
fd's capability rights are checked at ioctl time.

## 5. Guest memory: pinning, EPT as source of truth

`KVM_SET_USER_MEMORY_REGION` validates the slot (range, flags, alignment,
overflow, overlap), then for each userspace page:

1. pre-faults it through the **real** page-fault path
   (`core.addrspace.handlePageFault`),
2. translates VA→phys (`userVirtToPhys`),
3. **pins** it (`physPageRefInc`) so the VMM cannot free/reuse the backing
   while the EPT points at it.

The creating task's untyped budget is charged per page and released on
teardown — guest RAM is never ambient. The EPT is built **eagerly** at region
registration (fail fast) and updated on removal. Crucially: **the EPT is the
source of truth for pinned pages** — unpin walks the EPT (GPA→HPA) and never
re-translates the userspace VA, which the VMM could have remapped concurrently.

## 6. Lifecycle and ceilings

- **Lifecycle:** `Empty → Active → Dying → Empty`. Teardown (`vmTeardown`) is
  idempotent and reclaims: EPT tables, pinned guest pages, the untyped-memory
  charge, vCPU records, and finally the object-table slot. vCPU lifecycle
  states: `Created → Runnable → Running → Exited`, with re-entry guarded.
- **Stale-handle protection:** every VM/vCPU carries a generation, mirrored in
  `ObjHeader.version_`. Handles are `(objId, generation)` pairs; a lookup fails
  if the slot was freed and reused (generation mismatch) or reused for another
  type. Generations never reuse 0. A stale VM handle on `kvmVmIoctl` returns
  `-EBADF`; a stale vCPU handle on `KVM_RUN` returns `-EBADF`.
- **Ceilings (hard, fail-closed):** 16 VMs system-wide, 64 vCPUs per VM, 32
  memslots (also reported via `KVM_CAP_NR_MEMSLOTS`), 262144 guest pages per VM
  (1 GiB), 1048576 guest pages system-wide (4 GiB).
- **fd refcounting:** `kvmVmFdDuped`/`kvmVmFdClosed` (and vCPU equivalents) tie
  object lifetime to fd lifetime — teardown is fd close on drop, matching the
  KVM contract that shutdown needs no destroy ioctl.

## 7. Interrupt model: split irqchip only

The only first-tier interrupt model is **split irqchip**: the local APIC is
(in the future) in-kernel; PICs/IOAPIC stay in userspace. `KVM_ENABLE_CAP`
with `KVM_CAP_SPLIT_IRQCHIP` (args[0] ≤ 24 GSIs) is accepted. In-kernel
PIC/IOAPIC/PIT (`KVM_CREATE_IRQCHIP`, `KVM_CREATE_PIT2`) is an explicit
**non-goal** — rejected with `ENOTTY`, not emulated badly. The eventfd-based
delivery tier (`KVM_IRQFD`, `KVM_IOEVENTFD`, `KVM_SET_GSI_ROUTING`,
`KVM_IRQ_LINE` + LAPIC injection) is the next tier; the routing-table structs
already exist in the ABI for it to consume.

## 8. Self-test

`core.virt.selftest` runs once at boot as task 0 through the **real dispatch
path** (`kvmSystemIoctl`/`kvmVmIoctl`/`kvmVcpuIoctl`), not just internals:
the extension-probe table (including the `IRQCHIP=1` / `PIT2=0` split-irqchip
contract), the userspace-pointer guard (null, wrap, high-half, oversize),
VM/vCPU lifecycle (create, stale-handle rejection, generation advance,
fd-refcount release, slot reuse, ceilings), memslot validation, EPT
validation failures plus a real map/lookup/unmap round-trip, and `KVM_RUN`
fail-soft (`-ENODEV` without hardware; skipped when a backend reports ready).
Every allocation is released; failures log and continue. Leaves no state.

## 9. Teardown summary

Closing the last fd reference to a VM (`kvmVmFdClosed`) drives
`vmTeardown`: vCPU records released, EPT walked to unpin every guest page
(GPA→HPA — never re-translating the VMM's VA), the untyped-memory charge
released, EPT tables freed, object-table slot returned to `Empty` with the
generation advanced so stale handles fail. Idempotent: safe to run twice.
