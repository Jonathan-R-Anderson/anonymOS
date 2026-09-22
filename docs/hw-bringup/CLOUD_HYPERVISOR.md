# Cloud Hypervisor Bring-Up Procedure (anonymOS KVM-compat target)

> **VERIFICATION STATUS: NOT RUN.** This procedure has never been executed.
> The sandbox where it was written has no VMX/SVM hardware (`vmxDetect()` fails
> there), so Cloud Hypervisor cannot run against anonymOS here. Everything below
> is derived from the traced source of a pinned Cloud Hypervisor checkout
> (`~/workspace/cloud-hypervisor-reference/`) and from reading anonymOS's own
> KVM-compat implementation (`src/kernel/d/core/virt/{kvm,kvmabi,vm,vmx,svm,ept}.d`).
> Treat every step as a prediction to confirm on real hardware, not a record of
> what happened.

## 1. Pinned version

Pin Cloud Hypervisor to the exact commit that was traced:

- **Commit:** `48e9deba50e7a61250ef7b855b34c45b5eaa9a88` (2026-09-21, depth-1 clone)
- **Latest tag in its release-notes.md at that commit:** v53.0
- **Key dependency versions (from its `Cargo.lock`):** `kvm-ioctls 0.25.0`, `kvm-bindings 0.14.1`
- **Reference material:** `~/workspace/cloud-hypervisor-reference/KVM_API_TRACE.md`
  (the full traced KVM ioctl inventory; this document summarizes the parts
  relevant to anonymOS).

License note: Cloud Hypervisor is Apache-2.0 OR BSD-3-Clause; depending on it
(or on kvm-ioctls/kvm-bindings as crates) is license-clean. Copying its source
files requires preserving the license notices. No Cloud Hypervisor code was
copied into anonymOS.

Cloud Hypervisor never issues raw KVM ioctls itself; everything goes through
the `kvm-ioctls` crate (`Kvm`, `VmFd`, `VcpuFd`, `DeviceFd` wrappers). The method
name -> ioctl mapping below was verified against kvm-ioctls 0.25.0 source and
Cloud Hypervisor's `vmm/src/seccomp_filters.rs` (the authoritative machine-
readable list of every KVM ioctl the process may ever issue).

Why Cloud Hypervisor is the first VMM target: it is the only one of the five
researched VMMs that boots x86_64 with **split irqchip** — it never calls
`KVM_CREATE_IRQCHIP` on the boot path (it uses `KVM_ENABLE_CAP(KVM_CAP_SPLIT_IRQCHIP)`;
its `create_irq_chip()` is only exercised by a unit test). The other four
(Firecracker, crosvm default, libkrun default, StratoVirt both machine types)
require in-kernel `KVM_CREATE_IRQCHIP` + `KVM_CREATE_PIT2`, which anonymOS
explicitly rejects with `ENOTTY` — they are a later tier (see `VMM_GAPS.md`).

## 2. Building Cloud Hypervisor (on a real machine)

All of the following must run on a Linux x86_64 host with a recent Rust
toolchain — **not** in this sandbox (no VMX, and the build was not attempted
here; verify locally).

```bash
git clone https://github.com/cloud-hypervisor/cloud-hypervisor.git
cd cloud-hypervisor
git checkout 48e9deba50e7a61250ef7b855b34c45b5eaa9a88
cargo build --release
```

- On Linux x86_64 the `kvm` backend is selected by default features (per the
  checkout's own `AGENTS.md`: some workspace members need `--features kvm` when a
  default build failure looks feature-related — retry narrow before widening).
- Formatting uses nightly-only rustfmt (`cargo +nightly fmt --all`); not needed
  to build.
- Beyond KVM, Cloud Hypervisor's process needs on the host: `eventfd`
  (+`EFD_NONBLOCK`), `epoll`, `timerfd`, signal handling (`pthread_kill`,
  `SIGRTMIN`), `memfd_create` + `ftruncate` + `fcntl(F_ADD_SEALS)` (guest RAM),
  and (for networking) TUN/TAP ioctls. The hypervisor crate itself needs only
  `open`/`ioctl`/`mmap`/`munmap`.

## 3. The exact KVM sequence Cloud Hypervisor will issue (x86_64)

What follows is the baseline-boot path (no SEV-SNP/TDX/VFIO/snapshot) against
anonymOS's `/dev/kvm`. Call sites are in the pinned checkout.

### Phase 0 — Startup / capability probe

| order | fd | ioctl | anonymOS answer today |
|---|---|---|---|
| 1 | `/dev/kvm` | `KVM_GET_API_VERSION` (0xae00) | 12 (`KVM_API_VERSION`) ✓ |
| 2–18 | `/dev/kvm` | `KVM_CHECK_EXTENSION` (0xae03) × 17 | see cap table below |

The 17 hard-required caps (`hypervisor/src/kvm/x86_64/mod.rs:54-66`);
missing **any one** -> `CapabilityMissing` -> VM creation refused:

| cap (name) | KVM_CAP nr | anonymOS returns today | verdict |
|---|---|---|---|
| AdjustClock | 39 | 1 | ✓ |
| ExtCpuid | 7 | 1 | ✓ |
| GetTscKhz | 61 | 1 | ✓ |
| ImmediateExit | 136 | 1 | ✓ |
| Ioeventfd | 36 | **0** | ✗ FAIL |
| Irqchip | 0 | **1 (probe shim)** | ✓ (see §5) |
| Irqfd | 32 | **0** | ✗ FAIL |
| IrqRouting | 25 | **0** | ✗ FAIL |
| MpState | 14 | 1 | ✓ |
| SetIdentityMapAddr | 37 | 1 | ✓ |
| SetTssAddr | 4 | 1 | ✓ |
| SplitIrqchip | 121 | 24 (#GSIs) | ✓ |
| TscDeadlineTimer | 72 | 1 | ✓ |
| UserMemory | 3 | 1 | ✓ |
| UserNmi | 22 | 1 | ✓ |
| VcpuEvents | 41 | 1 | ✓ |
| Xsave | 55 | 1 | ✓ |

**Expected failure today: `check_required_extensions()` fails on
`Ioeventfd`, `Irqfd`, `IrqRouting` (all 0). Cloud Hypervisor exits with
`CapabilityMissing` before any VM is created.** This is the fail-fast design of
the anonymOS compat layer (`kvmCheckExtension` in `src/kernel/d/core/virt/kvm.d`
deliberately returns 0 for delivery caps it does not implement — "fail fast
rather than claim and hang").

### Phase 1 — VM creation (never reached today)

| fd | ioctl | # | call site |
|---|---|---|---|
| `/dev/kvm` | `KVM_CREATE_VM` | 0xae01 | type `KVM_X86_DEFAULT_VM = 0`; anonymOS accepts type 0 only, `EINVAL` otherwise |
| `/dev/kvm` | `KVM_GET_MSR_INDEX_LIST` | 0xc004ae02 | returns 8 indices (IA32_TSC, SYSENTER_*, EFER, STAR, LSTAR, FMASK); retry-with-bigger-buffer protocol (`-E2BIG`) honored |
| VM fd | `KVM_SET_IDENTITY_MAP_ADDR` | 0x4008ae48 | stored; u64 arg |
| VM fd | `KVM_SET_TSS_ADDR` | 0xae47 | stored; u64 arg |
| VM fd | `KVM_ENABLE_CAP` | 0x4068aea3 | `KVM_CAP_SPLIT_IRQCHIP`, `args[0] = 24`; anonymOS requires `args[0] ≤ 24` |

### Phase 2 — Guest memory

| fd | ioctl | anonymOS behavior |
|---|---|---|
| VM fd | `KVM_SET_USER_MEMORY_REGION` (0x4020ae46) | supported; flags `0`/`KVM_MEM_READONLY`; slot validated; pages pre-faulted through the real page-fault path, translated VA→phys, and **pinned** (`physPageRefInc`) so the VMM can't free backing the EPT points at; untyped budget charged per page, released on teardown; EPT built eagerly |
| VM fd | size-0 re-register | supported (region removal via `vmRemoveMemoryRegion`) |
| VM fd | `KVM_SET_USER_MEMORY_REGION2` / `KVM_GET_DIRTY_LOG` | **not supported** (`EINVAL`; v2 used only on SEV-SNP path) |

### Phase 3 — vCPU creation

| fd | ioctl | anonymOS behavior |
|---|---|---|
| VM fd | `KVM_CREATE_VCPU` (0xae41) | supported; arg is the vCPU id (rejected if it doesn't fit 32 bits) |
| `/dev/kvm` | `KVM_GET_VCPU_MMAP_SIZE` (0xae04) | returns 4096 (one page: `struct kvm_run`); issued by kvm-ioctls itself |
| vCPU fd | `mmap` (MAP_SHARED, offset 0) | supported via `kvmVcpuMmap` (returns the phys of the per-vCPU `kvm_run` page) |

### Phase 4 — vCPU initialization

Cloud Hypervisor's `configure_vcpu` order, and anonymOS's answer:

1. `KVM_SET_CPUID2` — supported (cached; capped at `KVM_CACHE_MAX_CPUID`)
2. `KVM_ENABLE_CAP(KVM_CAP_HYPERV_SYNIC)` — **only** when the `kvm_hyperv` (Windows) config flag is set; anonymOS has no HyperV cap in its check table → returns 0 / `EINVAL`. Windows-guest path is out of scope for the first tier.
3. `KVM_SET_MSRS` — supported; returns the number applied (as Linux does). Cloud Hypervisor programs the boot MSR set (SYSENTER_*, STAR/CSTAR/LSTAR, KERNEL_GS_BASE, SYSCALL_MASK, IA32_TSC, MISC_ENABLE, MTRRdefType, plus Hyper-V MSRs when enabled). Note: anonymOS's `KVM_GET_MSR_INDEX_LIST` advertises only 8 indices, and a fixed boot-MSR allow-list is defined in `kvmabi.d` — verify on hardware that Cloud Hypervisor's full MSR set is accepted, not just cached.
4. `KVM_SET_REGS` — supported (transitions vCPU `Created → Runnable`)
5. `KVM_GET_SREGS` then `KVM_SET_SREGS` — supported (cached)
6. `KVM_SET_FPU` — supported
7. `KVM_GET_LAPIC` then `KVM_SET_LAPIC` — `GET` returns zeros ("honest: not modeled"); `SET` is accepted and deferred until the kernel APIC model lands
8. `KVM_GET_TSC_KHZ` (0xaea3) — returns `-EIO` when unset, exactly like Linux; Cloud Hypervisor treats EIO as "no TSC frequency", **not fatal**

### Phase 5 — Interrupts (never reached today)

| fd | ioctl | anonymOS answer today |
|---|---|---|
| VM fd | `KVM_SET_GSI_ROUTING` (0x4008ae6a) | **ENOTTY** (structs exist; delivery tier consumes them later) |
| VM fd | `KVM_IRQFD` (0x4020ae76) | **ENOTTY** |
| VM fd | `KVM_IOEVENTFD` (0x4040ae79) | **ENOTTY** |
| vCPU fd | `KVM_NMI` (0xae9a) | accepted; no-op until the APIC model lands |

**Not used by Cloud Hypervisor:** `KVM_CREATE_IRQCHIP` (anonymOS rejects with
ENOTTY — split irqchip only), `KVM_CREATE_PIT2` (ENOTTY — no in-kernel PIT),
`KVM_SIGNAL_MSI` (delivered via irqfd + GSI routing instead).

### Phase 6 — vCPU run loop (never reached without hardware)

- `KVM_RUN` (0xae80) on the vCPU fd. anonymOS does the full state dance (stale-
  handle checks, `immediate_exit` handling → `KVM_EXIT_INTR`, state transitions)
  and then calls the backend. **Without VMX/SVM hardware it fails cleanly with
  `-ENODEV`** (`vmxEnter()` returns `VMX_NOHW`; `svmEnter()` fails closed too) —
  exactly like Linux without `/dev/kvm`. The `[HW]` phase is what turns this
  into real guest entry.
- The `kvm_run` exits a real backend must produce: `KVM_EXIT_IO`, `KVM_EXIT_MMIO`,
  `KVM_EXIT_IOAPIC_EOI` (split irqchip), `KVM_EXIT_HLT`, `KVM_EXIT_SHUTDOWN`
  (plus `DEBUG`/`HYPERV` only if those paths are used).
- vCPU kick needs `KVM_RUN` to return `-EINTR` on a pending signal plus
  `immediate_exit` semantics — both are load-bearing for `pthread_kill` +
  `set_immediate_exit` at `vmm/src/cpu.rs:806`.

### Phase 7–9 (not needed for plain boot)

Snapshot/migration ioctls (`KVM_GET/SET_CLOCK`, the `GET/SET_*` vCPU state
family, `KVM_GET_DIRTY_LOG`), GDB stub (`KVM_SET_GUEST_DEBUG`), VFIO
(`KVM_CREATE_DEVICE` + device attrs) — all explicitly out of scope; none are
on the boot path. Shutdown is fd close on drop.

## 4. Where it is expected to FAIL today (ordered)

1. **Phase 0 capability probe** — `check_required_extensions()` sees 0 for
   `KVM_CAP_IOEVENTFD`, `KVM_CAP_IRQFD`, `KVM_CAP_IRQ_ROUTING` → `CapabilityMissing`
   → Cloud Hypervisor refuses to create a VM. **This is the current boot verdict:
   fails at startup, before `KVM_CREATE_VM`.**
2. **Phase 5 (if the probe were shimmed)** — `KVM_IRQFD`, `KVM_IOEVENTFD`,
   `KVM_SET_GSI_ROUTING` return `ENOTTY`: there is no eventfd→virtual-IRQ delivery
   backend yet (no LAPIC injection). The routing-table structs stay in the ABI
   for the delivery tier to consume; the ioctls fail fast until it lands.
3. **Phase 6 (if phases 0–5 were reached)** — `KVM_RUN` returns `-ENODEV`:
   the VMX backend detects hardware (`CPUID.1:ECX[5]`, fail-soft `vmxBootInit()`)
   but `vmxEnter()` is a declared-not-implemented stub until the `[HW]` phase;
   the SVM backend is detection-only by design. No guest entry without real
   hardware and the `[HW]` implementation.

## 5. Why the `KVM_CAP_IRQCHIP=1` shim exists

Linux semantics of `KVM_CAP_IRQCHIP` mean "full in-kernel irqchip available"
— which anonymOS deliberately does **not** implement (split irqchip is the only
first-tier model; `KVM_CREATE_IRQCHIP` → `ENOTTY`). The compat layer answers
`1` to the `KVM_CAP_IRQCHIP` probe anyway, because Cloud Hypervisor lists it as
hard-required while its actual boot path never creates an in-kernel irqchip
(`KVM_CAP_SPLIT_IRQCHIP` = 24 is the cap it really acts on). This is a
documented probe shim in `kvm.d` (`kvmCheckExtension`), not a claim of
functionality: the ioctl that would realize the capability is honestly rejected.
`KVM_CAP_PIT2` returns 0 because there is no PIT at all, and Cloud Hypervisor
doesn't require it.

## 6. Human bring-up checklist (real hardware)

Prerequisites: a Linux x86_64 machine **with VMX or SVM** (verify:
`grep -E 'vmx|svm' /proc/cpuinfo`), the anonymOS kernel built with the VMM
tier, and the pinned Cloud Hypervisor checkout built with `cargo build --release`.

- [ ] anonymOS boots; kernel log shows the virt self-test passing
      (`[virt] selftest`, covering the extension-probe table incl. the
      IRQCHIP=1/PIT2=0 split-irqchip contract)
- [ ] `vmxBootInit()` succeeded (`g_vmxReady=true` in log) **or** SVM detected;
      otherwise `KVM_RUN` will return `-ENODEV` by design — stop here and fix
      the hardware path first
- [ ] Launch Cloud Hypervisor with a minimal Linux guest and observe the
      **expected current failure**: `CapabilityMissing` at `check_required_extensions`
      naming `Ioeventfd`/`Irqfd`/`IrqRouting` (confirms the probe sequence and the
      shim behavior match this document)
- [ ] After the interrupt-delivery tier lands (irqfd/ioeventfd/GSI routing +
      LAPIC injection): re-run and confirm `KVM_CREATE_VM` → `KVM_SET_TSS_ADDR` →
      `KVM_ENABLE_CAP(SPLIT_IRQCHIP)` → memory regions → `KVM_CREATE_VCPU` →
      vCPU state ioctls → `KVM_RUN` proceed past Phase 0/5
- [ ] After the `[HW]` guest-entry phase: confirm `KVM_EXIT_IO`/`KVM_EXIT_MMIO`
      exits arrive in userspace and the guest reaches its bootloader
- [ ] Verify `KVM_GET_TSC_KHZ` returning `-EIO` does not abort boot (expected:
      treated as "no TSC frequency")
- [ ] Verify the guest's `KVM_SET_MSRS` boot set (incl. MTRRdefType) is accepted
      end-to-end, not just cached
- [ ] Verify `KVM_SET_USER_MEMORY_REGION` size-0 removal works (hot-unplug path)

Unverified here: every step above, the build procedure, the seccomp filter's
allowance of the ioctls, and any Cloud Hypervisor behavior change since the
2026-09-21 pinned commit.
