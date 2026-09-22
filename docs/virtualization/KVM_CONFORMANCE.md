# KVM Conformance

> **STATUS.** This table describes the implementation in
> `src/kernel/d/core/virt/kvm.d` + `kvmabi.d` on branch
> `feat/anonymos-vmm-kvm-compat`, read 2026-09-22. Nothing here has been
> exercised against a real VMM — no guest has ever run, and `KVM_RUN` returns
> `-ENODEV` without VMX/SVM hardware. The "rationale" column is the reason
> recorded in the code comments.

Conventions: **supported** = implemented and dispatched; **ENOTTY** = recognized
ioctl, explicitly rejected ("not implemented here" — the clean probe signal);
**EINVAL** = unrecognized or invalid use; **ENODEV** = valid call, no hardware
backend. Error constants are Linux negatives (`E_NOTTY` = -25, etc.).

## System fd (`/dev/kvm`)

| ioctl | nr | status | notes |
|---|---|---|---|
| `KVM_GET_API_VERSION` | 0xae00 | supported | returns 12 |
| `KVM_CHECK_EXTENSION` | 0xae03 | supported | per-cap table below |
| `KVM_CREATE_VM` | 0xae01 | supported | type must be `KVM_X86_DEFAULT_VM` (0); SEV/TDX types → `EINVAL` |
| `KVM_GET_VCPU_MMAP_SIZE` | 0xae04 | supported | returns 4096 (one page: `struct kvm_run`) |
| `KVM_GET_SUPPORTED_CPUID` | 0xc008ae05 | supported | honest minimal 4-leaf list; feature words filled from the **real** host CPUID at call time; VMX bit reflects real hardware, never faked; `-E2BIG` retry protocol honored |
| `KVM_GET_MSR_INDEX_LIST` | 0xc004ae02 | supported | 8 indices (IA32_TSC, SYSENTER_CS/ESP/EIP, EFER, STAR, LSTAR, FMASK); `-E2BIG` retry protocol honored |
| anything else | — | `EINVAL` | |

## Capability values (`KVM_CHECK_EXTENSION`)

| cap | nr | returns | rationale |
|---|---|---|---|
| `KVM_CAP_IRQCHIP` | 0 | **1 (probe shim)** | Cloud Hypervisor hard-requires it but never calls `KVM_CREATE_IRQCHIP` (split irqchip only); the ioctl that would realize it returns `ENOTTY`. See note below. |
| `KVM_CAP_HLT` | 1 | 1 | |
| `KVM_CAP_USER_MEMORY` | 3 | 1 | |
| `KVM_CAP_SET_TSS_ADDR` | 4 | 1 | |
| `KVM_CAP_EXT_CPUID` | 7 | 1 | |
| `KVM_CAP_NR_VCPUS` / `KVM_CAP_MAX_VCPUS` | 9 / 66 | 64 | `VIRT_MAX_VCPUS_PER_VM` |
| `KVM_CAP_NR_MEMSLOTS` | 10 | 32 | `VIRT_MAX_MEMSLOTS` |
| `KVM_CAP_NOP_IO_DELAY` | 12 | 1 | |
| `KVM_CAP_MP_STATE` | 14 | 1 | |
| `KVM_CAP_USER_NMI` | 22 | 1 | `KVM_NMI` accepted (queued when APIC lands) |
| `KVM_CAP_SET_GUEST_DEBUG` | 23 | 0 | GDB stub not implemented |
| `KVM_CAP_IRQ_ROUTING` | 25 | 0 | routing stored in structs, but **no delivery backend yet** — fail fast rather than claim and hang |
| `KVM_CAP_IRQFD` | 32 | 0 | no eventfd→IRQ delivery yet — fail fast |
| `KVM_CAP_PIT` / `KVM_CAP_PIT2` | 11 / 33 | 0 | no in-kernel PIT, ever (non-goal) |
| `KVM_CAP_IOEVENTFD` | 36 | 0 | no MMIO-bus doorbell matching yet — fail fast |
| `KVM_CAP_SET_IDENTITY_MAP_ADDR` | 37 | 1 | |
| `KVM_CAP_ADJUST_CLOCK` | 39 | 1 | |
| `KVM_CAP_VCPU_EVENTS` | 41 | 1 | |
| `KVM_CAP_DEBUGREGS` | 50 | 1 | |
| `KVM_CAP_ENABLE_CAP` | 54 | 1 | split-irqchip only (see VM fd table) |
| `KVM_CAP_XSAVE` / `KVM_CAP_XCRS` | 55 / 56 | 1 | state cached per vCPU |
| `KVM_CAP_TSC_CONTROL` | 60 | 1 | |
| `KVM_CAP_GET_TSC_KHZ` | 61 | 1 | `KVM_GET_TSC_KHZ` returns `-EIO` when unset, like Linux (Cloud Hypervisor treats EIO as non-fatal) |
| `KVM_CAP_TSC_DEADLINE_TIMER` | 72 | 1 | |
| `KVM_CAP_SIGNAL_MSI` | 77 | 0 | not used by any targeted VMM |
| `KVM_CAP_READONLY_MEM` | 81 | 1 | |
| `KVM_CAP_DISABLE_QUIRKS` | 116 | 0 | `KVM_ENABLE_CAP(DISABLE_QUIRKS)` → `EINVAL` |
| `KVM_CAP_MULTI_ADDRESS_SPACE` | 118 | 0 | |
| `KVM_CAP_SPLIT_IRQCHIP` | 121 | 24 | nonzero = supported; value is the #GSIs |
| `KVM_CAP_IMMEDIATE_EXIT` | 136 | 1 | `immediate_exit` honored → `KVM_EXIT_INTR` |
| anything else | — | 0 | |

**The `KVM_CAP_IRQCHIP=1` shim, precisely:** Linux semantics of this cap mean
"full in-kernel irqchip available", which anonymOS does not implement and does
not plan to. The compat layer answers 1 anyway because Cloud Hypervisor's
`check_required_extensions()` treats it as hard-required while its actual boot
path never creates an in-kernel irqchip — it enables split irqchip instead
(`KVM_CAP_SPLIT_IRQCHIP` = 24 is the cap it really acts on). This is a
documented, deliberate probe shim: the ioctl that would realize the capability
(`KVM_CREATE_IRQCHIP`) is honestly rejected with `ENOTTY`. No VMM can
accidentally depend on an in-kernel PIC through this shim, because any attempt
to create one fails.

## VM fd

| ioctl | nr | status | notes |
|---|---|---|---|
| `KVM_CREATE_VCPU` | 0xae41 | supported | arg is the vCPU id; rejected if it doesn't fit 32 bits |
| `KVM_SET_USER_MEMORY_REGION` | 0x4020ae46 | supported | flags 0 / `KVM_MEM_READONLY`; slot/alignment/overlap validation; pages pre-faulted, VA→phys translated, **pinned**; untyped budget charged; EPT built eagerly; size-0 re-register = removal |
| `KVM_SET_TSS_ADDR` | 0xae47 | supported | arg is the address (u64); stored |
| `KVM_SET_IDENTITY_MAP_ADDR` | 0x4008ae48 | supported | arg is a u64 pointer; stored |
| `KVM_CREATE_IRQCHIP` | 0xae60 | **ENOTTY** | split irqchip is the only first-tier model |
| `KVM_CREATE_PIT2` | 0x4040ae77 | **ENOTTY** | no in-kernel PIT (non-goal) |
| `KVM_ENABLE_CAP` | 0x4068aea3 | partial | `KVM_CAP_SPLIT_IRQCHIP` accepted (`args[0]` ≤ 24); `DISABLE_QUIRKS` and all others → `EINVAL` |
| `KVM_SET_GSI_ROUTING` | 0x4008ae6a | **ENOTTY** | routing structs exist for the delivery tier; ioctl fails fast until injection exists |
| `KVM_IRQ_LINE` | 0x4008ae61 | **ENOTTY** | acking without LAPIC injection would hang guests |
| `KVM_IRQFD` | 0x4020ae76 | **ENOTTY** | no eventfd bridge / injection yet |
| `KVM_IOEVENTFD` | 0x4040ae79 | **ENOTTY** | no MMIO-bus doorbell matching yet |
| `KVM_SET_CLOCK` | 0x4030ae7b | supported (no-op) | accepted; kvmclock is a later tier |
| `KVM_GET_CLOCK` | 0x8030ae7c | supported | returns a **zeroed** `kvm_clock_data` — honest "no kvmclock", not fake timestamps |
| `KVM_GET_DIRTY_LOG` | 0x4010ae42 | `EINVAL` | no dirty tracking yet (later tier) |
| anything else | — | `EINVAL` | |

## vCPU fd

| ioctl / op | nr | status | notes |
|---|---|---|---|
| `mmap` (offset 0) | — | supported | returns phys of the per-vCPU `kvm_run` page; nonzero offset → `ENODEV` |
| `KVM_RUN` | 0xae80 | dispatched | full state dance (stale checks, `immediate_exit` → `KVM_EXIT_INTR`, `Created/Runnable` gating); then `vmxEnter()`/`svmEnter()` — **returns `-ENODEV` without VMX/SVM hardware** by design; `[HW]` phase implements entry |
| `KVM_GET/SET_REGS` | 0x8090ae81 / 0x4090ae82 | supported | `SET` transitions vCPU `Created → Runnable` |
| `KVM_GET/SET_SREGS` | 0x8138ae83 / 0x4138ae84 | supported | cached in the per-vCPU fixed page |
| `KVM_GET/SET_FPU` | 0x81a0ae8c / 0x41a0ae8d | supported | cached |
| `KVM_GET/SET_MSRS` | 0xc008ae88 / 0x4008ae89 | supported | `SET` returns the number applied (Linux behavior); `GET` fills known indices, reads 0 for indices never programmed ("honest: the MSR was never programmed through us"). Boot-MSR allow-list defined in `kvmabi.d` (SYSENTER_*, TSC, EFER, STAR, LSTAR, CSTAR, FMASK, KERNEL_GS_BASE). |
| `KVM_SET_CPUID2` | 0x4008ae90 | supported | cached; capped at `KVM_CACHE_MAX_CPUID`, overflow → `-E2BIG` |
| `KVM_GET/SET_LAPIC` | 0x8400ae8e / 0x4400ae8f | supported | `GET` returns **zeros** ("honest: not modeled"); `SET` accepted and deferred until the kernel APIC model lands |
| `KVM_GET/SET_MP_STATE` | 0x8004ae98 / 0x4004ae99 | supported | validated ≤ 6 (`KVM_MP_STATE_SIPI_RECEIVED`) |
| `KVM_NMI` | 0xae9a | supported (no-op) | queued when the APIC model lands |
| `KVM_GET/SET_VCPU_EVENTS` | 0x8040ae9f / 0x4040aea0 | supported | cached |
| `KVM_SET_TSC_KHZ` / `KVM_GET_TSC_KHZ` | 0xaea2 / 0xaea3 | supported | arg is the kHz value itself; `GET` returns `-EIO` when unset (Linux behavior; Cloud Hypervisor treats as non-fatal) |
| `KVM_GET/SET_DEBUGREGS` | 0x8080aea1 / 0x4080aea2 | supported | DR6 reset value `0xFFFF0FF0` when unset |
| `KVM_GET/SET_XSAVE` | 0x9000aea4 / 0x5000aea5 | supported | reset defaults `fcw=0x37f`, `mxcsr=0x1f80` when unset |
| `KVM_GET/SET_XCRS` | 0x8188aea6 / 0x4188aea7 | supported | XCR0 reset value: x87 only |
| anything else | — | `EINVAL` | includes `KVM_SET_GUEST_DEBUG`, `KVM_INTERRUPT`, `KVM_GET_NESTED_STATE`, `KVM_SET_USER_MEMORY_REGION2`, `KVM_CREATE_DEVICE`, `KVM_SIGNAL_MSI`, `KVM_KVMCLOCK_CTRL`, `KVM_ARM_*` |

## Capability rights (checked per ioctl)

`kvmRequiredRight()`: `KVM_CREATE_VM` → `CAP_RIGHT_VM_CREATE`; VM/vCPU
configuration ioctls → `CAP_RIGHT_VM_CONTROL`; `KVM_SET_USER_MEMORY_REGION` →
`CAP_RIGHT_VM_MEM`; `KVM_RUN` → `CAP_RIGHT_VM_RUN`. Rights are checked at
ioctl time, not implied by fd possession.

## Explicit non-goals

- **In-kernel PIC/IOAPIC/PIT** (`KVM_CREATE_IRQCHIP`, `KVM_CREATE_PIT2`) —
  rejected by design; split irqchip is the only model.
- **Eventfd interrupt delivery** (`KVM_IRQFD`, `KVM_IOEVENTFD`,
  `KVM_SET_GSI_ROUTING`, `KVM_IRQ_LINE`) — structs exist; the delivery tier
  (LAPIC injection) is next, not here.
- **Guest entry** (`KVM_RUN` beyond dispatch) — the `[HW]` phase; returns
  `-ENODEV` until then.
- **aarch64** (`KVM_CREATE_DEVICE`/VGIC, `KVM_ARM_*`, one-reg) — not implemented.
- **Snapshot/migration** (`GET/SET_PIT2`, `GET/SET_IRQCHIP`, `GET/SET_CLOCK`
  beyond the zeroed stub, the full `GET/SET_*` state family,
  `KVM_GET_DIRTY_LOG`) — deferred.
- **Confidential computing** (SEV/SNP/TDX: non-zero `KVM_CREATE_VM` types →
  `EINVAL`), **MSHV**, **kvmclock**, **GDB stub**, **VFIO**.
- **Windows guests via Hyper-V enlightenments** (`KVM_CAP_HYPERV_SYNIC`,
  Hyper-V MSRs) — out of scope for tier 1.

## Deviation notes vs. the trace docs

- `kvmabi.d` records two corrections to `KVM_API_TRACE.md` found during
  UAPI verification: `KVM_GET_MSR_INDEX_LIST` is `0xc004ae02` (not
  `0xc008ae05`, which is `KVM_GET_SUPPORTED_CPUID`); `KVM_CREATE_PIT2` is
  `0x4040ae77` (nr `0x77`, not `0xa0`).
- `KVM_SET_MSRS` allow-list: `kvmabi.d` defines a fixed boot-MSR allow-list and
  comments that anything outside it is rejected with `EINVAL`. The dispatch
  code read on 2026-09-22 caches the submitted entries and returns the count
  applied; per-index enforcement was not verified in the read path — confirm
  before relying on it.
