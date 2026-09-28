# Capability: amd-svm-backend

Behavior contract for the anonymOS kernel's AMD SVM (AMD-V) + NPT backend.
This is the AMD half of the native hardware-virtualization substrate; it
sits behind the vendor-neutral `core.virt.backend` API alongside the Intel
VMX half, and feeds the same vendor-neutral exit dispatcher and KVM ABI.

## ADDED Requirements

### Requirement: SVM availability detection and enablement

The kernel SHALL detect AMD SVM support via the `AuthenticAMD` vendor
string AND `CPUID.8000_0001:ECX[2]`, and enable SVM operation
(`EFER.SVME`, per-CPU HSAVE page, `MSR_VM_HSAVE_PA`, per-CPU host
VMLOAD/VMSAVE area) only when every required check passes:
- `MSR_VM_CR` `LOCK`+`SVMDIS` set → firmware-disabled SVM: fail closed,
  never bypass the lock.
- `CPUID.8000_000A` must report `NPT`, `NRIP_SAVE`, `VMCB_CLEAN`,
  `DECODE_ASSISTS`; absent → backend unavailable (no shadow-paging
  fallback exists).
- The maximum extended CPUID leaf must cover `0x8000000A`.

If SVM is unavailable for any reason, virtualization SHALL be an optional
subsystem: the kernel continues normally, `virtBackendAvailable()` returns
false, and `KVM_RUN` returns `-ENODEV` exactly like Linux without
`/dev/kvm`.

#### Scenario: boot on AMD without SVM

On a CPU without the SVM bit, klog records `[svm] no SVM ...`; the rest
of the OS is unaffected.

#### Scenario: boot on AMD with SVM locked by firmware

`MSR_VM_CR` reads `LOCK`+`SVMDIS`: klog records
`[svm] MSR_VM_CR locked with SVMDIS (firmware disabled SVM)`;
`EFER.SVME` is restored to its previous value; no `#GP` is ever raised by
probing.

#### Scenario: boot on AMD with SVM

klog records `[virt] backend=svm available=yes` and
`[svm] SVM enabled (EFER.SVME, HSAVE, host-save area, multi-ASID)` (or
`single-ASID` when the CPU reports one ASID).

### Requirement: VMCB programming

Each vCPU SHALL have a kernel-owned VMCB: one 4 KiB, 4 KiB-aligned,
write-back page, never readable or writable by userspace. On every entry
the kernel SHALL program the control area (intercepts, ASID,
`TLB_CONTROL`, `NP_ENABLE=1`, `N_CR3` = the VM's SLAT root, clean bits 0)
and re-sync the save area from the vCPU's cached `KvmRegs`/`KvmSRegs`
(segments, `CPL`, `EFER`, `CR0/2/3/4`, `RIP/RSP/RFLAGS/RAX`, `DR6/7`,
`GPAT`). Guest state the validator rejects SHALL fail entry with
`-EINVAL` before any hardware touch; a half-programmed VMCB SHALL never
be entered.

#### Scenario: invalid guest state

A vCPU with a non-canonical RIP or `CR4` containing `VMXE`/`SMXE`:
`virtEnter` returns `-EINVAL`; no `VMRUN` executes.

### Requirement: ASID isolation

Guest ASIDs SHALL start at 1; ASID 0 (the host's) SHALL never be handed
to a guest. ASID exhaustion SHALL wrap with a full TLB flush. Every fresh
ASID binding SHALL use `TLB_CONTROL=FLUSH_ALL`.

#### Scenario: ASID wrap

After `maxAsids` entries the allocator wraps to 1 with a flush; no stale
TLB entries from a previous guest lifetime are ever reachable.

### Requirement: NPT-based guest memory isolation

Guest-physical addresses SHALL translate through kernel-managed Nested
Page Tables to host-physical pages. The NPT SHALL map exactly the pages
the VM object was granted — no more. NPT faults (guest access outside
granted memory, or violating granted permissions) SHALL cause a `#VMEXIT`
(`NPF`, `0x400`) decoded to `VirtExitKind.SlatFault` with the faulting GPA
from `EXITINFO2` and the write bit from `EXITINFO1[1]`; they SHALL NOT
resolve to host memory.

#### Scenario: guest escapes its grant

A test guest reads a guest-physical page outside its grant. An NPF
`#VMEXIT` fires; `svmDecodeExit` yields `SlatFault` with the faulting GPA;
the VM is paused/terminated. Host memory outside the grant is never
exposed.

### Requirement: default-deny I/O and MSR interception

The per-VM IOPM (12 KiB) and MSRPM (8 KiB) SHALL be single contiguous
allocations, initialized to all-ones (intercept every port, intercept
every MSR). Every guest `IN`/`OUT` and every guest `RDMSR`/`WRMSR` SHALL
cause a `#VMEXIT` until a deliberate policy change opens specific
ports/MSRs. The bitmaps are per-VM and die with the VM.

#### Scenario: guest touches a port

Guest `OUT 0x3F8, AL` → `#VMEXIT` `IOIO` → decoded port `0x3F8`,
direction OUT, size 1, payload = guest `AL` → `KVM_EXIT_IO` to the VMM.

### Requirement: #VMEXIT decoding

`svmDecodeExit` SHALL be a pure function of the VMCB exit fields:
- `0x078` → `Hlt`; `0x07F` → `Shutdown`.
- `0x07B` → `Io` with port/direction/size from `EXITINFO1` (size bits
  must be exactly one of SZ8/SZ16/SZ32; ambiguous → `ioSize=0` and the
  dispatcher contains the VM).
- `0x081` → `Hypercall` with `data` = guest RAX (CPL is recorded).
- `0x400` → `SlatFault` with GPA/write bit.
- Anything else → `Unknown` with `hardwareReason` = `EXITCODE`.
- `0xFFFFFFFFFFFFFFFF` (invalid VMCB state) → `svmEnter` returns `-EINVAL`.

#### Scenario: decode matrix

A synthetic VMCB with `EXITCODE=0x07B`, `EXITINFO1` encoding port `0x3F8`
OUT size 1: `svmDecodeExit` yields `kind=Io, port=0x3F8, dir=OUT,
ioSize=1`. A synthetic `EXITCODE=0x400` with `EXITINFO2=0xDEAD000` and
write bit set: `kind=SlatFault, gpa=0xDEAD000, write=true`. The host test
asserts both without hardware.

### Requirement: host-state safety across VMRUN

The `VMRUN` transition SHALL preserve all host GPRs, restore GIF to its
pre-entry state (`STGI` immediately after `#VMEXIT`), and park host
FS/GS/TR/LDTR/syscall state via `VMSAVE` before loading the guest's via
`VMLOAD`, reversing the dance on exit. No interrupt or exception path
SHALL observe guest segment/syscall state. Known limitation (documented):
guest FPU/SSE state is not isolated in this tier.

#### Scenario: guest returns cleanly

After `VMRUN` → `#VMEXIT` → `STGI`, the host's GPRs, FS/GS bases, TR,
LDTR and syscall MSRs are bit-identical to their pre-entry values; an
interrupt arriving immediately after `STGI` runs the host handler with
host state. (Verified `[HW]`; the wrapper's push/pop balance is reviewed
in code.)

### Requirement: vendor separation

On AMD hardware the kernel SHALL never read an Intel VMX MSR or execute
a VMX instruction; on Intel hardware it SHALL never read an AMD SVM MSR
or execute an SVM instruction. `kvm.d` SHALL contain no vendor
conditionals — all dispatch goes through `core.virt.backend`.

#### Scenario: wrong-vendor hardware

On an Intel host, `virtBackendKind()` returns `Vmx`; no `MSR_VM_CR`,
`MSR_VM_HSAVE_PA` or `EFER.SVME` access ever occurs. On an AMD host the
reverse holds. (Verified by code audit; `[HW]` on both vendors.)

## ADDED Requirements

### Requirement: KVM_RUN entry on AMD

`KVM_RUN` SHALL enter the guest through `virtEnter()` — the single
backend entry point — with a mutable `KvmRegs*` so the backend writes
guest GPR state back on exit. Without a ready backend it SHALL return
`-ENODEV` with the `NoHardware` diagnostic, exactly like Linux without
`/dev/kvm`.

#### Scenario: KVM_RUN without hardware

On a host with no VMX/SVM, `KVM_RUN` returns `-ENODEV`, the VM's
diagnostic is `NoHardware`, and the vCPU returns to `Runnable`. (Host
test: `build.sh` green.)

### Requirement: SLAT root on AMD

`Vm.slat` replaces the Intel-only `Vm.ept`. On AMD the SLAT kind is `Npt`
and `N_CR3` is programmed from `slatRootPhys()`; on Intel it is `Ept`.
Teardown SHALL free all SLAT tables (`tables==0`), the VMCB page, and the
per-VM IOPM/MSRPM.

#### Scenario: teardown is leak-free

A VM with mapped memslots and an allocated VMCB is torn down: SLAT
`tables==0`, VMCB page freed, IOPM/MSRPM pages freed. (Host fuzz test:
`build.sh` green.)
