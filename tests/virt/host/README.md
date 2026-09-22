# tests/virt/host — host test harness for the native VMM / KVM layer

Compiles the **real** `core.virt.*` modules (`src/kernel/d/core/virt/`) against
a fake kernel surface in `stubs/` and runs four test binaries — all on the
host triple with the system D compiler, no VMX/SVM hardware required.

## Prerequisites

- `ldc2` on `PATH` (tested with LDC 1.36.0; anything recent works)
- x86_64 host (the virt modules use x86 inline asm)
- No virtualization hardware needed — `KVM_RUN` paths fail soft with
  `-ENODEV` here, exactly as they do on a VMX-less boot

## Build & run

```sh
tests/virt/host/build.sh
```

This compiles all four binaries into `tests/virt/host/build/` (git-ignored)
and runs them, failing loudly (nonzero exit) on any compile error, any
binary failure, or any missing `PASS` line.

## Test binaries

| binary | what it runs |
|---|---|
| `run_selftest` | `core.virt.selftest.virtSelfTest()` built with `-d-version=HostTest`, so the host-only compat block runs too (userspace guards incl. read-only, XSAVE/XCRS/debugregs/TSC round-trips, honest `-ENOTTY` interrupt ioctls). Expects `[virt] selftest PASS`. |
| `run_fuzz` | Deterministic xorshift64 fuzzer (fixed seed): random `KVM_CHECK_EXTENSION` caps, unknown ioctls on all three fd kinds, memslot overlap/overflow/alignment chaos, EPT map/unmap chaos, vCPU-id chaos, synthetic `vmxDispatchExit` fuzz. Expects `[virt] fuzz PASS`. |
| `run_dispatch` | Targeted `core.virt.vmexit` dispatch tests: HLT→`KVM_EXIT_HLT`, IO OUT/IN fields + data bytes, EPT violation→MMIO, VMCALL→hypercall, triple fault→SHUTDOWN, unknown→`KVM_EXIT_UNKNOWN`, bad IO size→contained + VM Dying. Expects `[virt] dispatch PASS`. |
| `run_adversarial` | Task 6.3 hostile-state tests through the real `kvmVcpuIoctl`: `SET_SREGS` with CR4.VMXE / EFER.LMA-without-LME / CR8=16, `SET_REGS` with non-canonical RIP, `SET_MSRS` with VMX MSR 0x480 / FEATURE_CONTROL / bad EFER — all → `-EINVAL`; valid values accepted. Expects `[virt] adversarial PASS`. |

## Stubs

`stubs/stub_*.d` provide exactly the symbols the virt modules import from the
rest of the kernel, with the real module names (`module core.objmgr;`, …) so
no real module is touched. They are deliberately minimal and obviously fake:

- `stub_objmgr.d` — array-backed object table (512 slots), refcount model
  mirroring the real one; generation (`version_`) survives release so
  stale-handle checks behave like the real table.
- `stub_io.d` — `klog`/`klog_hex`/`klog_dec` → `printf`.
- `stub_exports.d` — `g_current_task_id = 0`; `phys_to_virt` is the identity
  (the stub page allocator hands out real host pointers as "phys").
- `stub_task.d` — 64-entry task table; `untypedObjId`/`domainObjId` are 0.
- `stub_untyped.d` — trivially succeeds.
- `stub_cap.d` — `CAP_RIGHT_VM_*` bits, same values as the real `core/cap.d`.
- `stub_mm.d` — `aligned_alloc`-backed 4 KiB pages; advisory pin counts.
- `stub_addrspace.d` — fake userspace mapping table with **per-page RW bits**:
  `stubMapUser` / `stubMapUserReadOnly` (HostTest helpers), demand-zero
  faulting, write fault on a read-only page fails, VA < 0x1000 never faults,
  `userVirtToPhys` returns one shared scratch page.
- `stub_audit.d` — audit ring sink (drops `VirtVmTeardown` events).
- `stub_vmm_policy.d` — stands in for the real `core/virt/vmm_policy.d`,
  which is **not** compiled here (it needs `core.domain`/`identity`/
  `namespace`). Matches the real policy's behavior for the only case the
  harness produces (`domainObjId == 0` → allow, and the real
  `vmmMayCreateVm(0)` returns true unconditionally).

## Known stub compromises

- **Per-domain VM ceilings are not under test.** The real `vmm_policy.d`
  enforces per-domain VM budgets; the harness has no domains, so the stub
  always allows. That policy is exercised on hardware where domains exist.
- **`userVirtToPhys` aliases.** Every userspace page translates to one shared
  scratch page. The memslot path only needs a stable page-aligned phys to pin
  and EPT-map; nothing under test requires distinct backing pages.
- **Audit events are dropped**, not recorded.
- **The stub page table evicts** under extreme pressure (64k slots); entries
  are re-faulted on demand, so this degrades gracefully.
- `vmxEnter`/`svmEnter`/VMXON are the real modules' fail-closed stubs —
  `KVM_RUN` returns `-ENODEV` here, as on hardware-less boot.
