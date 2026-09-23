# Design: add-amd-svm-npt-backend

## Goal

Give anonymOS a real AMD SVM (AMD-V) + NPT backend for the native VMM/KVM-compat
substrate, and in the process make the hardware layer cleanly dual-vendor: one
backend API, one second-level address translation (SLAT) abstraction, one
vendor-neutral exit representation feeding the single common dispatcher and the
single KVM ABI.

## Non-goals

- Intel VMX guest entry (`VMLAUNCH`) — still fail-closed, untouched tier.
- In-kernel MSR emulation, IRQFD/IOEVENTFD, dirty-log ring, TSC calibration —
  separate changes.
- Nested virtualization (guest hypervisors): `VMRUN`/`VMLOAD`/`VMSAVE`/`CLGI`/
  `STGI`/`SKINIT` are intercepted and refused.

## Architecture

```
kvm.d (KVM ABI: /dev/kvm, ioctls, kvm_run)
  │  KvmRegs (mutable) / KvmSRegs / KvmMsrEntry
  ▼
backend.d ── virtEnter() ──► svmEnter()   (svm.d)      AMD
             ── virtEnter() ──► vmxEnter()   (vmx.d)      Intel (fail-closed)
  │  VirtBackendKind: None / Vmx / Svm  (CPUID vendor, no preference order)
  ▼
vm.d ── Vm.slat ──► slat.d ──► npt.d (AMD) / ept.d (Intel)
  │      Vcpu.hwCtrlPhys ──► VMCB page (AMD) / VMCS page (Intel)
  │      Vm.svmIopmPhys / svmMsrpmPhys (AMD only, per-VM, contiguous)
  ▼
vmexit.d ── VirtExitInfo { kind, qual, gpa, data, count, hardwareReason }
         ── virtDispatchExit() ──► kvm_run / containment
```

### Backend selection (`core.virt.backend`)

`virtBackendKind()` reads the CPUID vendor string: `AuthenticAMD` → `Svm`,
`GenuineIntel` → `Vmx`, anything else → `None`. There is no preference order —
exactly one vendor matches. `virtBackendAvailable()` is the fail-closed
readiness latch (per-CPU init completed). `virtEnter()` is the single entry
point `kvmVcpuRun` calls; it validates guest state once, then dispatches to
the vendor backend. `kvm.d` contains no vendor conditionals.

`KvmRegs*` is mutable across the entry boundary: the backend writes guest GPR
state back on exit (the VMRUN wrapper round-trips RBX–R15/RBP/RSI/RDI/RCX/RDX
through `*regs`; RAX/RSP/RIP/RFLAGS are picked up from the VMCB save area).

### SLAT (`core.virt.slat`, `core.virt.npt`)

`SlatKind`: `None`/`Ept`/`Npt`. `Vm.slat` replaces the old Intel-only `Vm.ept`.
`slatMap/Unmap/Lookup/Free/RootPhys` dispatch on kind; unknown kind
fail-closes. `vmAlloc` selects `Npt` when the backend is `Svm`, else `Ept`
(`Ept` is the inert software default when no backend exists so memslot tests
work without hardware).

NPT is a 4-level, 4 KiB nested page-table builder mirroring `ept.d`'s
structure: injected alloc/map/free callbacks, 48-bit GPA/HPA bound,
fail-closed validation (misaligned, zero page, overflow, unknown prot,
duplicate map), a `tables` leak counter, depth-first free. Leaf encodings:
`P[0] + RW[1] + US[2] + NX[63](=!exec)`. NPT faults surface as
`VirtExitKind.SlatFault` (→ `KVM_EXIT_MMIO`), the AMD analogue of EPT
violation.

### VMCB (`core.virt.vmcb`)

Exact AMD64 APM Vol. 2 layout, pinned by `static assert`s on every offset the
backend touches: control area `0x000`–`0x3FF` (intercepts, `IOPM_BASE_PA`
`0x040`, `MSRPM_BASE_PA` `0x048`, `TSC_OFFSET` `0x050`, `GUEST_ASID` `0x058`,
`TLB_CONTROL` `0x05C`, `EXITCODE` `0x070`, `EXITINFO1` `0x078`, `EXITINFO2`
`0x080`, `NP_ENABLE` `0x090`, `N_CR3` `0x0B0`, clean bits `0x0C0`, `nRIP`
`0x0C8`), save area `0x400`–`0xFFF` (segments incl. `CPL` `0x4CB`, `EFER`
`0x4D0`, `CR4`/`CR3`/`CR0`, `RIP` `0x578`, `RSP` `0x5D8`, `RAX` `0x5F8`).
The whole VMCB is one 4 KiB, 4 KiB-aligned, write-back page.

### SVM per-CPU init (`svmCpuInit`)

Fail-soft, must run on the target CPU:
1. `CPUID.8000_0001:ECX[2]` (SVM) — else log and leave `ready=false`.
2. `MSR_VM_CR`: `LOCK+SVMDIS` → firmware disabled SVM; fail closed, never
   bypass the lock.
3. `CPUID.8000_000A:EDX` must have `NPT | NRIP_SAVE | VMCB_CLEAN |
   DECODE_ASSISTS` — else fail closed (no shadow-paging fallback exists).
4. Set `EFER.SVME`.
5. Allocate the per-CPU HSAVE page (4 KiB) and the per-CPU host
   VMLOAD/VMSAVE area (4 KiB); program `MSR_VM_HSAVE_PA`.
6. Record `maxAsids` from `CPUID.8000_000A:EBX` (a *count*; ASID 0 is the
   host and is never handed out).

Any failure restores `EFER` and leaves `ready=false`; boot continues without
virtualization.

### ASIDs

Per-CPU monotonic allocator. Guests get `1..maxAsids`, then wrap with a full
TLB flush. Every fresh ASID binding uses `TLB_CONTROL=FLUSH_ALL`
(conservative; per-ASID flush is a later optimization). `FLUSH_NONE` on
steady-state entries.

### VMCB programming (`svmProgramVmcb`)

Per-vCPU page, allocated lazily on first entry. Control area programmed once:
intercepts for CPUID/HLT/IOIO/MSR/SHUTDOWN/VMRUN/VMMCALL/VMLOAD/VMSAVE,
`IOPM_BASE_PA`/`MSRPM_BASE_PA` (per-VM bitmaps, see below), `TSC_OFFSET=0`,
fresh ASID, `TLB_CONTROL`, `NP_ENABLE=1`, `N_CR3 = slatRootPhys()`, clean
bits `0` (reload everything). Save area re-synced from `KvmRegs`/`KvmSRegs`
on every entry (segments, GDTR/IDTR/LDTR/TR, `CPL`, `EFER`, `CR0/2/3/4`,
`RFLAGS`/`RIP`/`RSP`/`RAX`, `DR6/7`, `GPAT`); the VMLOAD/VMSAVE-only fields
(`STAR`/`LSTAR`/`CSTAR`/`SFMASK`/`KernelGsBase`/`SYSENTER_*`) are programmed
once and thereafter preserved by the VMSAVE/VMLOAD dance.

### Permission bitmaps (IOPM/MSRPM)

Allocated per-VM in `vmAlloc` as *single contiguous* allocations (3 pages /
12 KiB IOPM, 2 pages / 8 KiB MSRPM — the VMCB holds one base PA per bitmap,
so independent 4 KiB pages would be wrong), all-ones init =
intercept-everything (default-deny), shared read-only across the VM's vCPUs,
freed in `vmTeardown`. Per-VM (not global) so a VM's bitmaps die with it.
Opening ports/MSRs to guests is a deliberate future policy step, not a
default.

### VMRUN transition (`svmRunVmcb`) — [HW]

A thin `asm` wrapper, the only code that executes `VMRUN`:
1. Save all 15 host GPRs (+1 dummy push keeps RSP 16-byte aligned).
2. `VMSAVE` host → parks host FS/GS/TR/LDTR/SYSENTER/etc in the per-CPU
   host-save area.
3. `VMLOAD` guest → loads the guest's from the VMCB.
4. Swap GPRs to guest values (guest RSP/RAX come from the VMCB save area;
   `RAX` holds the VMCB phys for `VMRUN`).
5. `VMRUN`. On `#VMEXIT`: `STGI` first (GIF was cleared by `#VMEXIT`; the
   kernel runs with GIF=1 from boot), `VMSAVE` guest, `VMLOAD` host,
   write guest GPRs back to `*regs`, restore host GPRs.

Pushes/pops are exactly balanced; the D epilogue runs normally (no `ret`
inside the asm). Known limitation: guest FPU/SSE state is not isolated in
this tier (documented, future work).

### Exit decoding (`svmDecodeExit`)

Pure function, fully host-testable. `EXITCODE` → `VirtExitKind`:
- `0x078 HLT` → `Hlt`; `0x07F SHUTDOWN` → `Shutdown`.
- `0x07B IOIO` → `Io`: port from `EXITINFO1[31:16]`, size from SZ8/SZ16/SZ32
  bits (exactly one must be set; 0/ambiguous → `ioSize=0` → the dispatcher
  contains the VM), direction from bit 0 (`0=OUT,1=IN`), string from bit 2.
  OUT payload = low `ioSize` bytes of guest RAX; string count from `REP`+RCX.
- `0x07C MSR` → `Unknown` (→ `KVM_EXIT_UNKNOWN`; the VMM emulates.
  In-kernel MSR emulation is a later tier).
- `0x081 VMMCALL` → `Hypercall`, `data` = guest RAX.
- `0x400 NPF` → `SlatFault`: GPA from `EXITINFO2`, write bit from
  `EXITINFO1[1]`.
- Anything else → `Unknown` with `hardwareReason = EXITCODE`.
- `0xFFFFFFFFFFFFFFFF` (invalid guest state) → `svmEnter` returns `-EINVAL`
  before decoding.

### Lifecycle hardening found during implementation

Decoding IOIO/NPF for real (instead of `Unknown`) exposed a latent resource
leak: a contained VM (`Dying`) / vCPU (`Dead`) could never be freed —
`vmCheck`/`vcpuCheckObj` reject non-live objects, so `kvmVmFdClosed`/
`kvmVcpuFdClosed` skipped refcounting and `vmTeardown` refused non-`Active`
VMs. Fixed: close paths use `vmCheckQuery`/`vcpuCheckObjClose` (accept
`Dying`/`Dead`), and `vmTeardown` tears down `Dying` VMs. The fuzz harness
(`run_fuzz`, 1500 dispatch iterations) now passes.

## Verification

- Host: `tests/virt/host/build.sh` — all four binaries PASS (selftest incl.
  VMCB layout helpers, fuzz, dispatch incl. SVM IOIO/NPF decode, adversarial).
- The virt modules also compile against the real kernel sources
  (`-mtriple=x86_64-unknown-none-elf`).
- `[HW]` (open): `scripts/virt-hw-test.sh` on AMD — asserts
  `[virt] backend=svm available=yes` + `[svm] SVM enabled (EFER.SVME` +
  selftest PASS; guest entry (HLT/IO/NPF/VMMCALL smoke) is task 9.x.
