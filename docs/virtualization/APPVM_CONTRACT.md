# AppVM ↔ anonymOS Kernel Contract

> **STATUS.** Kernel-side interface as implemented on branch
> `feat/anonymos-vmm-kvm-compat` (`src/kernel/d/core/virt/`).  This is the
> cross-repo contract an out-of-tree AppVM backend (the `melpomenex/appvm`
> repo) programs against.  **No guest has ever run** (guest entry is the
> `[HW]` phase); everything marked `[HW]` below is explicitly unverified.

AppVM is a **userspace VMM**: an ordinary confined task that drives virtualization
entirely through the KVM compatibility ABI on `/dev/kvm`.  The native VM/vCPU
objects (`core.virt.vm`) are authoritative; the KVM ioctl numbers are just names
for operations on them.  AppVM never touches the native objects directly —
there is no in-kernel API for userspace besides the ioctls below.

---

## 1. How AppVM gets /dev/kvm

- AppVM runs inside a **VMM domain** (`core.virt.vmm_policy`): its namespace
  contains its own `/Domains/<name>/Home` (guest images under `Home/images/`),
  `/tmp`, `/dev/kvm`, and a pty pair.  Everything else is deny-by-default,
  with explicit denies on `/System`, `/dev/mem`, `/proc`, `/sys`, `/Shared`,
  and the raw PCI-class device subtrees.
- Its identity's device mask is **exactly `DEVCLASS_VIRT`** — the kvm grant.
  `VIRT` is never in a default device mask, not even System's.
- The launch model: System (or a configboot manifest, pre-freeze) creates the
  domain linked to a non-admin identity, calls `vmmInitDomain(domId)`, then
  `domain spawn Vmm <appvm-binary>`.
- **AppVM must never assume** it can open `/dev/kvm` outside this domain, or
  that the fd is obtainable by any other task.  Opening it without the grant
  is refused at the device-class gate (and audit-logged).

The system fd carries `VM_CREATE` only; each VM fd and vCPU fd carries exactly
the capability rights its kind needs (`kvmRequiredRight` in `core.virt.kvm`).
Duplicating an fd derives narrowed rights; closing the last view tears the
object down.

---

## 2. Exact ioctl surface AppVM may use

### System fd (`/dev/kvm`)

| ioctl | nr | notes |
|---|---|---|
| `KVM_GET_API_VERSION` | `0xae00` | returns 12 |
| `KVM_CHECK_EXTENSION` | `0xae03` | see §3; anonymOS extensions 250/251 |
| `KVM_CREATE_VM` | `0xae01` | arg must be 0 (`KVM_X86_DEFAULT_VM`); anything else (SEV/TDX types) → `-EINVAL` |
| `KVM_GET_VCPU_MMAP_SIZE` | `0xae04` | returns 4096 (one `kvm_run` page) |
| `KVM_GET_SUPPORTED_CPUID` | `0xc008ae05` | 4 honest leaves; feature words filled from the **real** host CPUID — VMX/SVM are never faked |
| `KVM_GET_MSR_INDEX_LIST` | `0xc004ae02` | 8 MSRs (TSC, SYSENTER×3, EFER, STAR, LSTAR, FMASK) |

### VM fd

| ioctl | nr | notes |
|---|---|---|
| `KVM_CREATE_VCPU` | `0xae41` | arg **is** the vCPU id (ulong, must fit 32 bits); id taken/out of range → `-ENOSPC` |
| `KVM_SET_USER_MEMORY_REGION` | `0x4020ae46` | flags 0 / `KVM_MEM_READONLY`; slot, alignment, overlap validated; pages pre-faulted through the real fault path, VA→phys translated, **pinned**; creator's untyped budget charged; EPT built eagerly; size-0 = slot removal |
| `KVM_SET_TSS_ADDR` | `0xae47` | arg is the address (u64); stored |
| `KVM_SET_IDENTITY_MAP_ADDR` | `0x4008ae48` | arg is a u64 pointer; stored |
| `KVM_ENABLE_CAP` | `0x4068aea3` | `SPLIT_IRQCHIP` (`args[0]` ≤ 24); `ANON_VM_PROFILE` (§6); everything else → `-EINVAL` |
| `KVM_SET_CLOCK` / `KVM_GET_CLOCK` | `0x4030ae7b` / `0x8030ae7c` | Compatibility only: accepted / returns **zeroed** `kvm_clock_data` (honest "no kvmclock"); Lightweight → `-ENOTTY` |
| `KVM_CREATE_IRQCHIP`, `KVM_CREATE_PIT2` | `0xae60`, `0x4040ae77` | **always `-ENOTTY`** — split irqchip is the only first-tier model; no in-kernel PIC/IOAPIC/PIT, ever |
| `KVM_SET_GSI_ROUTING`, `KVM_IRQ_LINE`, `KVM_IRQFD`, `KVM_IOEVENTFD` | `0x4008ae6a`, `0x4008ae61`, `0x4020ae76`, `0x4040ae79` | **always `-ENOTTY`** — no interrupt/eventfd delivery backend yet; fail fast rather than claim and hang |
| `KVM_GET_DIRTY_LOG` | `0x4010ae42` | `-EINVAL` — no dirty tracking yet |
| `ANONVM_GET_VM_STATE` | `0x8060aef0` | anonymOS-specific; §4 |

### vCPU fd

| ioctl / op | nr | notes |
|---|---|---|
| `mmap` (offset 0) | — | maps the 4096-byte `kvm_run` page; nonzero offset → `-ENODEV` |
| `KVM_RUN` | `0xae80` | §5; without VMX/SVM hardware → `-ENODEV` **by design** |
| `KVM_GET/SET_REGS` | `0x8090ae81` / `0x4090ae82` | `SET` validates (non-canonical RIP → `-EINVAL`) and transitions `Created → Runnable` |
| `KVM_GET/SET_SREGS` | `0x8138ae83` / `0x4138ae84` | `SET` validates (VMX/SMX/LA57 in guest CR4, bad EFER/CR0/CR3 → `-EINVAL`) |
| `KVM_GET/SET_MSRS` | `0xc008ae88` / `0x4008ae89` | fixed allow-list; VMX MSRs, FEATURE_CONTROL, microcode → `-EINVAL`; `SET` returns count applied |
| `KVM_SET_CPUID2` | `0x4008ae90` | ≤ 64 entries; cached |
| `KVM_GET/SET_FPU`, `KVM_GET/SET_XSAVE` | `0x81a0ae8c`/`0x41a0ae8d`, `0x9000aea4`/`0x5000aea5` | XSAVE reset defaults match fresh FPU (FCW=0x37f, MXCSR=0x1f80) |
| `KVM_GET/SET_VCPU_EVENTS` | `0x8040aea0`/`0x8040ae9f` | cached; `KVM_NMI` accepted (queued when the APIC model lands) |
| `KVM_GET/SET_MP_STATE` | `0x8004ae98` / `0x4004ae99` | > 6 → `-EINVAL` |
| `KVM_GET/SET_LAPIC` | `0x8400ae8e` / `0x4400ae8f` | GET returns zeros ("not modeled"); SET accepted, applied when the APIC model lands |
| `KVM_SET_TSC_KHZ` / `KVM_GET_TSC_KHZ` | `0xaea2` / `0xaea3` | GET returns `-EIO` when unset, like Linux |
| `KVM_GET/SET_DEBUGREGS`, `KVM_GET/SET_XCRS` | `0x8080aea1`/`0x4080aea2`, `0x8188aea6`/`0x4188aea7` | cached |

### Negative errno names (Linux numbers, returned as `-errno`)

`EPERM 1`, `ENOENT 2`, `EIO 5`, `E2BIG 7`, `EBADF 9`, `ENOMEM 12`,
`EACCES 13`, `EFAULT 14`, `EBUSY 16`, `EEXIST 17`, `ENODEV 19`,
`EINVAL 22`, `ENOTTY 25`, `ENOSPC 28`.

---

## 3. Capability values (`KVM_CHECK_EXTENSION`)

The table in `docs/virtualization/KVM_CONFORMANCE.md` is authoritative.  The
values AppVM is most likely to probe:

- `KVM_CAP_IRQCHIP` (0) → **1 (probe shim)**: Cloud Hypervisor hard-requires
  it, but `KVM_CREATE_IRQCHIP` returns `-ENOTTY`.  The shim exists so the VMM's
  setup sequence proceeds; only split irqchip is real.
- `KVM_CAP_SPLIT_IRQCHIP` (121) → 24 (#GSIs, nonzero = supported).
- `KVM_CAP_NR_VCPUS` (9) / `KVM_CAP_MAX_VCPUS` (66) → 64.
- `KVM_CAP_NR_MEMSLOTS` (10) → 32.
- `KVM_CAP_IRQ_ROUTING` (25), `KVM_CAP_IRQFD` (32), `KVM_CAP_IOEVENTFD` (36),
  `KVM_CAP_PIT`/`KVM_CAP_PIT2` (11/33) → **0** (fail fast).
- `KVM_CAP_GET_TSC_KHZ` (61) → 1 (`KVM_GET_TSC_KHZ` → `-EIO` when unset).
- **anonymOS-specific** (never in Linux UAPI numbering):
  - `KVM_CAP_ANON_VM_PROFILE` (250) → 1: `KVM_ENABLE_CAP` accepts a profile.
  - `KVM_CAP_ANON_VM_STATE` (251) → 1: `ANONVM_GET_VM_STATE` is supported.

---

## 4. VM state query + named diagnostics (task 8.1)

`ANONVM_GET_VM_STATE` (`0x8060aef0`, `_IOR('A', 0xf0, 96)`, VM fd,
requires `CAP_RIGHT_VM_CONTROL`) fills `struct AnonVmState` (96 bytes):

```
magic        u32   0x41565356 ('AVMS') — always check this first
vmState      u8    VmState: 0=Empty, 1=Active, 2=Dying
profile      u8    VmProfile: 0=Lightweight, 1=Compatibility
vcpuCount    u16   live vCPUs
diag         u32   VirtDiag — the named diagnostic (below)
diagInfo     u64   EptViolation → faulting GPA; 0 otherwise
pagesCharged u64   pinned guest pages currently charged to this VM
vcpuState    u8[64] VcpuState per vCPU index:
                   0=Empty, 1=Created, 2=Runnable, 3=Running,
                   4=Exited (HLT/SHUTDOWN), 5=Dead
```

The query works on **Active and Dying** VMs, so AppVM can read the post-mortem
of a contained VM.  A fully torn-down VM (stale handle) is `-EBADF`, like any
other fd use.

**Diagnostic semantics.** The synchronous `-errno` is always the primary
signal; the diagnostic is the pollable post-mortem.  Last event wins:
`KVM_RUN` clears the diagnostic at entry (fresh attempt, fresh story) and
re-records if the run fails; setup calls record directly.

| `diag` | name | meaning | synchronous signal |
|---|---|---|---|
| 0 | `None` | no fault recorded for the current attempt | — |
| 1 | `NoHardware` | `KVM_RUN` attempted with no VMX/SVM hardware | `-ENODEV` |
| 2 | `Contained` | VM entered `Dying` via `vmContained`; the *why* is in klog (§5) | `-EIO` |
| 3 | `BudgetExhausted` | untyped pin-budget exhausted during memory registration | `-ENOMEM` |
| 4 | `EptViolation` | last EPT violation (informational, **not** terminal); `diagInfo` = faulting GPA | `KVM_EXIT_MMIO` exit (the GPA is also in the exit itself) |

Note: an EPT violation that the VMM emulates is normal operation — it arrives
as `KVM_EXIT_MMIO` with `physAddr`/`isWrite`, exactly like Linux.

---

## 5. Console: guest serial output + boot-failure diagnostics (task 8.2)

**Guest serial.** There is no kernel device model.  Guest `OUT` to COM1
(`0x3f8`, the serial port every x86 firmware/OS knows) exits to userspace as
`KVM_EXIT_IO` — AppVM's device model handles it.  *In addition*, the kernel
keeps a **read-only tap**: every 1-byte guest `OUT` to `0x3f8` is mirrored
into the klog ring as

```
[guest<N>] <bytes…>
```

where `N` is the vCPU index, one line per guest newline (or per vCPU switch /
256-byte cap).  The kernel never interprets the bytes, and the `KVM_EXIT_IO`
exit still reaches the VMM unchanged.

**Where AppVM reads it.** The klog ring is the existing serial mechanism:
every byte that reaches the host serial port passes through it, and it is
exposed as the synthetic file `/run/klog` (→ the Logs app).  AppVM reads guest
serial output from `/run/klog` exactly like any other kernel log line.  No new
file, no new device, no new ioctl.

**Boot-failure diagnostic contract.** When a VM fails, the kernel names the
cause on klog with a stable format (these lines are the contract — a VMM may
grep them):

| klog line | meaning | errno |
|---|---|---|
| `[virt] vmAlloc: VM ceiling reached` | > 16 VMs (per VMM domain) | `-ENOSPC` |
| `[virt] memRegion: untyped budget exhausted` | pin budget exhausted | `-ENOMEM` |
| `[virt] kvmVcpuRun: no virtualization hardware (ENODEV)` | no VMX/SVM | `-ENODEV` |
| `[vmexit] contained failure: <why>` | contained; `<why>` names the cause, e.g. `I/O with bad access size`, `string I/O with zero count`, `null run/vcpu/vm` | `-EIO` |
| `[guest<N>] …` | guest serial tap (§5 top) | — |

A contained VM is `Dying` and never re-enterable; its post-mortem
(`vmState=2`, `diag=2`) stays queryable via `ANONVM_GET_VM_STATE` until the
last fd closes.

---

## 6. Machine profiles (task 7.4)

`VmProfile` is a **userspace policy bundle over one substrate** (StratoVirt
precedent), not a security class.  Both profiles allocate the same native
objects, run the same EPT builder, the same guest-state validators, and the
same VM-exit dispatcher — one kernel execution path.  The profile changes
*defaults and advertised policy only*.

- Set with `KVM_ENABLE_CAP(KVM_CAP_ANON_VM_PROFILE, args[0])` on the VM fd
  (`args[0]`: 0 = Lightweight, 1 = Compatibility; anything else → `-EINVAL`).
  Requires `CAP_RIGHT_VM_CONTROL`, like the rest of `KVM_ENABLE_CAP`.
- **Default is `Compatibility`** (1): the Linux-VMM bundle.  Split-irqchip is
  pre-enabled at VM creation (no enable call needed), and `KVM_SET_CLOCK` /
  `KVM_GET_CLOCK` behave as documented in §2.  Cloud Hypervisor-style VMMs
  need no changes.
- **`Lightweight`** (0) opts out of the compat bundle:
  `KVM_ENABLE_CAP(SPLIT_IRQCHIP)` → `-EINVAL`, and `KVM_SET_CLOCK` /
  `KVM_GET_CLOCK` → `-ENOTTY`.  A VMM that wants neither pays for neither.
- Switching profiles after creation is allowed (it only flips the policy
  bundle), but AppVM should set it before first `KVM_RUN` — profiling is a
  creation-time decision in spirit.
- **`KVM_CHECK_EXTENSION` answers are global** (system fd): profiles do not
  change them.  What changes is per-VM *behavior* (the ioctls above), not the
  advertised capability set.

**[HW] open:** "both profiles boot the same guest" is unverified — no guest
has ever run.  The profile mechanism compiles and the dispatch paths are
identical by construction (a single `if (vm.profile …)` gate at the ioctl
boundary), but live-boot parity across profiles awaits real hardware.

---

## 7. State machine

```
Vm:    Empty -> Active -> Dying -> Empty
Vcpu:  Empty -> Created -> Runnable -> Running -> {Runnable, Exited, Dead}
```

- Teardown is idempotent and reclaims everything: EPT tables, pinned guest
  pages (walked from the EPT — the source of truth — never re-translated
  from the userspace VA), the untyped-memory charge, vCPU records, and the
  object-table slot.
- Stale-handle protection: every VM/vCPU carries a generation mirrored in the
  object header; handles are `(objId, generation)` pairs.  A lookup fails if
  the slot was freed and reused (generation mismatch) or reused for another
  type.  Generations never reuse 0.
- Ceilings are hard and fail-closed: ≤ 16 VMs per VMM domain, ≤ 64 vCPUs/VM,
  ≤ 32 memslots, ≤ 1 GiB guest pages per VM, ≤ 4 GiB system-wide (the per-VMM-
  domain 4 GiB accounting exists but the memslot path enforces the per-VM and
  system-wide ceilings today — see `vmm_policy.d`).
- Closing the last VM-fd view tears the VM down; a vCPU pins its parent VM
  (the VM outlives vCPU fds, like Linux).
- `KVM_RUN` gating: only `Created`/`Runnable` may enter; `Running` re-entry
  and `Exited`/`Dead` re-entry → `-EINVAL`.  `immediate_exit` → `KVM_EXIT_INTR`.
- A contained VM (`Dying`) rejects all ioctls except `ANONVM_GET_VM_STATE`.

---

## 8. What AppVM must never assume

- **No `/dev/kvm` outside the VMM domain.**  The grant is `DEVCLASS_VIRT`,
  never in a default mask; opens elsewhere are refused and audit-logged.
- **No interrupt delivery.**  `KVM_IRQ_LINE`, `KVM_IRQFD`, `KVM_IOEVENTFD`,
  `KVM_SET_GSI_ROUTING` are `-ENOTTY`.  There is no IRQFD yet, no IOAPIC/PIC,
  no PIT — never.  `KVM_CAP_IRQCHIP` answering 1 is a probe shim, not hardware.
- **No kvmclock.**  `KVM_GET_CLOCK` returns zeros; `KVM_SET_CLOCK` is accepted
  and ignored.  Do not treat the zeroed struct as a real clock.
- **No dirty-page tracking.**  `KVM_GET_DIRTY_LOG` is `-EINVAL`.  Live
  migration needs another mechanism (future tier).
- **No MMIO length in EPT violations.**  `KVM_EXIT_MMIO.len` is 0 ("unknown");
  the access length is not in the exit qualification and is never guessed.
- **CPUID/MSRs are allow-lists, not the host's.**  `KVM_GET_SUPPORTED_CPUID`
  returns 4 leaves with real feature words (VMX/SVM never faked);
  `KVM_SET_MSRS` rejects anything outside the fixed list, including all VMX
  MSRs, `IA32_FEATURE_CONTROL`, and microcode.  Guest CR4 may not set
  VMX/SMX/LA57.
- **anonymOS-specific numbers are not Linux.**  `KVM_CAP_ANON_VM_PROFILE`
  (250), `KVM_CAP_ANON_VM_STATE` (251), and `ANONVM_GET_VM_STATE`
  (`0x8060aef0`) exist only here; probing them on Linux returns "unsupported",
  and Linux VMM code must not treat them as portable.
- **The klog contract is lines, not a stream protocol.**  `…: <why>` text
  after the prefixes in §5 is stable; do not parse beyond the documented
  formats.
- **Guest memory is pinned and charged.**  Every registered page is pinned
  (refcounted) and charged against the creator's untyped budget; the VMM
  cannot free or reuse backing while the EPT points at it, and the EPT —
  not the userspace VA — is the source of truth on teardown.
- **`[HW]` gaps AppVM will hit first:** guest entry (`vmxEnter`/`svmEnter`)
  is declared but unimplemented — `KVM_RUN` returns `-ENODEV` on machines
  without VMX/SVM *and* on machines with it, until the `[HW]` phase lands.
  The LAPIC is not modeled (`KVM_GET_LAPIC` zeros).  Live AppVM runs are
  unverified by construction.

---

## 9. Source map (this repo)

| item | file |
|---|---|
| native objects, ceilings, `VmProfile`, `VirtDiag`, `vmCheckQuery` | `src/kernel/d/core/virt/vm.d` |
| ioctl dispatch, `kvmRequiredRight`, `ANONVM_GET_VM_STATE` | `src/kernel/d/core/virt/kvm.d` |
| pure ABI data, `AnonVmState`, anonymOS extensions | `src/kernel/d/core/virt/kvmabi.d` |
| exit dispatch, containment, guest serial tap | `src/kernel/d/core/virt/vmexit.d` |
| VMM domain confinement | `src/kernel/d/core/virt/vmm_policy.d` |
| conformance tables | `docs/virtualization/KVM_CONFORMANCE.md` |
| architecture | `docs/virtualization/ARCHITECTURE.md` |
