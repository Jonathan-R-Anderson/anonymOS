# Per-VMM KVM Gap Analysis (anonymOS KVM-compat layer)

> **VERIFICATION STATUS: NOT RUN.** None of these VMMs have been executed
> against anonymOS. The verdicts below are derived from traced source
> (`~/workspace/cloud-hypervisor-reference/KVM_API_TRACE.md` and
> `~/workspace/vmm-reference/VMM_COMPARISON.md`, both traced 2026-09-21 from
> actual checkouts) cross-referenced against anonymOS's own implementation
> (`src/kernel/d/core/virt/kvm.d`, `kvmabi.d`). Predictions, not measurements.

The five VMMs split cleanly into two groups on the one question that decides
everything: **who owns the irqchip.**

| group | VMMs | irqchip model |
|---|---|---|
| A — split irqchip, no in-kernel PIC/PIT | Cloud Hypervisor | `KVM_ENABLE_CAP(KVM_CAP_SPLIT_IRQCHIP)`; LAPIC in-kernel, PIC/IOAPIC in userspace |
| B — full in-kernel irqchip required on x86_64 default path | Firecracker, crosvm, libkrun, StratoVirt | `KVM_CREATE_IRQCHIP` + `KVM_CREATE_PIT2` before `KVM_CREATE_VCPU` |

anonymOS's first tier implements **group A only**: `KVM_CREATE_IRQCHIP` and
`KVM_CREATE_PIT2` are explicitly rejected with `ENOTTY` ("split irqchip is the
only first-tier model: no in-kernel PIC/IOAPIC/PIT"). Group B is a later tier.

## Common ground (all five)

The following ioctls are supported by anonymOS today and are exercised by all
five VMMs on their boot paths: `KVM_GET_API_VERSION` (=12), `KVM_CHECK_EXTENSION`
(per-cap values differ — see below), `KVM_CREATE_VM` (type 0 only),
`KVM_GET_VCPU_MMAP_SIZE` (4096), `KVM_GET_SUPPORTED_CPUID` (minimal honest 4-leaf
list), `KVM_GET_MSR_INDEX_LIST` (8 indices), `KVM_SET_USER_MEMORY_REGION`
(flags 0 / `KVM_MEM_READONLY`; slot validation, page pinning, eager EPT),
`KVM_SET_TSS_ADDR`, `KVM_SET_IDENTITY_MAP_ADDR`, `KVM_CREATE_VCPU`,
`KVM_SET_CPUID2`, `KVM_SET_REGS`, `KVM_GET/SET_SREGS`, `KVM_SET_FPU`,
`KVM_GET/SET_MSRS`, `KVM_GET_LAPIC` (returns zeros — "honest: not modeled"),
`KVM_SET_LAPIC` (accepted, deferred until the APIC model lands),
`KVM_GET/SET_MP_STATE`, `KVM_GET/SET_VCPU_EVENTS`, `KVM_GET/SET_XSAVE`,
`KVM_GET/SET_XCRS`, `KVM_GET/SET_DEBUGREGS`, `KVM_NMI` (accepted; queued when
APIC lands), `KVM_SET/GET_TSC_KHZ` (`-EIO` when unset, like Linux), and the
vCPU-fd `mmap` of the 4096-byte `kvm_run` page. `KVM_RUN` is fully dispatched
but fails with `-ENODEV` until the `[HW]` guest-entry phase lands (VMX backend
is detect-only; `vmxEnter()` is a stub returning `VMX_NOHW`; SVM is
detection-only by design).

Ceilings that bind all VMMs: 16 VMs, 64 vCPUs/VM, 32 memslots
(`KVM_CAP_NR_MEMSLOTS`), 1 GiB guest pages per VM, 4 GiB system-wide.

---

## 1. Cloud Hypervisor (group A — first target)

**Pinned for bring-up:** commit `48e9deba50e7a61250ef7b855b34c45b5eaa9a88`
(2026-09-21); kvm-ioctls 0.25.0 / kvm-bindings 0.14.1. Full procedure in
`CLOUD_HYPERVISOR.md`.

| area | anonymOS support | gap |
|---|---|---|
| Startup probe (17 hard-required caps) | 14/17 pass; `KVM_CAP_IRQCHIP` answered 1 by probe shim; `KVM_CAP_SPLIT_IRQCHIP` = 24 | **`KVM_CAP_IOEVENTFD`, `KVM_CAP_IRQFD`, `KVM_CAP_IRQ_ROUTING` return 0** — probe fails |
| VM/memory/vCPU creation + state | supported (see common ground) | none known on the ioctl surface |
| `KVM_ENABLE_CAP(KVM_CAP_SPLIT_IRQCHIP)` | supported (`args[0] ≤ 24`) | none |
| `KVM_SET_GSI_ROUTING` / `KVM_IRQFD` / `KVM_IOEVENTFD` | **ENOTTY** | eventfd→virtual-IRQ delivery backend not implemented (no LAPIC injection yet) |
| `KVM_NMI` (API-driven, optional) | accepted, no-op | delivery comes with the APIC model |
| `KVM_RUN` | dispatched; `-ENODEV` without `[HW]` phase | guest entry is the `[HW]` phase |
| Windows guests (`KVM_ENABLE_CAP(HYPERV_SYNIC)` + Hyper-V MSRs) | no HyperV cap; Hyper-V MSRs not in the allow-list | Windows path out of scope for tier 1 |

**Boot verdict:** fails at the startup capability probe with `CapabilityMissing`
(on `Ioeventfd`/`Irqfd`/`IrqRouting`), before any VM is created. After the
interrupt-delivery tier lands, the next expected failure is `KVM_RUN` →
`-ENODEV` until the `[HW]` guest-entry phase.

## 2. Firecracker (group B — later tier)

**Irqchip model:** full in-kernel irqchip + PIT2 required on x86_64; no split
mode. `KVM_CREATE_IRQCHIP` + `KVM_CREATE_PIT2` (`KVM_PIT_SPEAKER_DUMMY`) happen
**before** `KVM_CREATE_VCPU` (`arch_pre_create_vcpus`). All interrupt delivery
is `KVM_IRQFD` + `KVM_SET_GSI_ROUTING`; `KVM_IRQ_LINE` appears zero times in
non-test code.

**Required probe caps** (`src/vmm/src/arch/x86_64/kvm.rs:31-45`): `IRQCHIP`,
`IOEVENTFD`, `IRQFD`, `USER_MEMORY`, `SET_TSS_ADDR`, `PIT2`, `PIT_STATE2`,
`ADJUST_CLOCK`, `DEBUGREGS`, `MP_STATE`, `VCPU_EVENTS`, `XCRS`, `XSAVE`,
`EXT_CPUID`.

| area | anonymOS support | gap |
|---|---|---|
| Probe caps | IRQCHIP=1 (shim), USER_MEMORY/SET_TSS_ADDR/ADJUST_CLOCK/DEBUGREGS/MP_STATE/VCPU_EVENTS/XCRS/XSAVE/EXT_CPUID = 1 | **`IOEVENTFD=0`, `IRQFD=0`, `PIT2=0`, `PIT_STATE2=0`** (not in table → default 0) — probe fails |
| `KVM_CREATE_IRQCHIP` / `KVM_CREATE_PIT2` | **ENOTTY** | fundamental: anonymOS will not implement in-kernel PIC/IOAPIC/PIT (explicit non-goal) |
| `KVM_IRQFD` / `KVM_SET_GSI_ROUTING` | **ENOTTY** | same delivery-backend gap as Cloud Hypervisor |
| `KVM_SET_TSS_ADDR` (0xfffbd000) | supported | none |
| `KVM_KVMCLOCK_CTRL` | not implemented (`EINVAL`) | best-effort in Firecracker — non-fatal |

**Boot verdict:** fails at the 14-cap startup probe (`PIT2`, `PIT_STATE2`,
`IOEVENTFD`, `IRQFD` = 0). Even past the probe, `KVM_CREATE_IRQCHIP` →
`ENOTTY` is a hard stop — Firecracker has no split-irqchip path, so it cannot
boot on anonymOS until and unless a group-B irqchip tier is built (currently an
explicit non-goal).

## 3. crosvm (group B, with an opt-in group-A mode — later tier)

**Irqchip model:** default is full in-kernel irqchip (`KvmKernelIrqChip`:
`KVM_CREATE_IRQCHIP` + `KVM_CREATE_PIT2`); opt-in `--irqchip=split` uses
`KVM_ENABLE_CAP` + `KVM_CAP_SPLIT_IRQCHIP` with userspace PIC/IOAPIC/PIT.
Userspace-irqchip (fully emulated) is explicitly rejected for KVM.

| area | anonymOS support | gap |
|---|---|---|
| Default path `KVM_CREATE_IRQCHIP` / `KVM_CREATE_PIT2` | **ENOTTY** | hard stop on the default path |
| `--irqchip=split` path | `KVM_CAP_SPLIT_IRQCHIP` = 24 supported; `KVM_ENABLE_CAP` accepted | still needs `KVM_IRQFD` / `KVM_IOEVENTFD` / `KVM_SET_GSI_ROUTING` → **ENOTTY** (delivery backend) |
| Capability surface | ~100-entry `KvmCap` list; many extras (`KVM_INTERRUPT`, `KVM_SET_GUEST_DEBUG`, `KVM_GET/SET_NESTED_STATE`, pvclock `KVM_GET/SET_CLOCK` beyond the zeroed stub, `KVM_KVMCLOCK_CTRL`, `KVM_SET_USER_MEMORY_REGION2`, `KVM_SIGNAL_MSI`) | not implemented (`EINVAL`/`ENOTTY`/default 0); crosvm's largest surface makes it the worst fit for tier 1 |
| `KVM_IRQFD_FLAG_RESAMPLE` | no resamplefd support planned in tier 1 | crosvm uses the flag; would need the delivery tier to handle it |

**Boot verdict:** fails on the default path at `KVM_CREATE_IRQCHIP` →
`ENOTTY` (after whatever subset of its broad capability probe the check table
answers). The `--irqchip=split` variant is the only crosvm configuration that
could ever boot on anonymOS, and only after the interrupt-delivery tier lands.

## 4. libkrun (group B, with an opt-in split mode — later tier)

**Irqchip model:** default requires `KVM_CAP_IRQCHIP` probe + `KVM_CREATE_IRQCHIP`
+ `KVM_CREATE_PIT2` (`KVM_PIT_SPEAKER_DUMMY`) + `KVM_REINJECT_CONTROL` (disable
PIT reinjection), set up **before** `KVM_CREATE_VCPU`. Opt-in split irqchip
via `krun_vmm_builder_split_irqchip()` (`KVM_ENABLE_CAP(KVM_CAP_SPLIT_IRQCHIP)`
+ userspace IOAPIC driving `KVM_SET_GSI_ROUTING`/`KVM_IRQ_LINE`).

**Fatal probe set** (`vstate.rs:434-454`): `KVM_CAP_IRQCHIP`, `KVM_CAP_IOEVENTFD`,
`KVM_CAP_IRQFD`, `KVM_CAP_USER_MEMORY`, `KVM_CAP_SET_TSS_ADDR`.

| area | anonymOS support | gap |
|---|---|---|
| Probe caps | IRQCHIP=1 (shim) ✓, USER_MEMORY=1, SET_TSS_ADDR=1 | **`IOEVENTFD=0`, `IRQFD=0`** — probe fails on the fatal set |
| Default `KVM_CREATE_IRQCHIP` / `KVM_CREATE_PIT2` / `KVM_REINJECT_CONTROL` | **ENOTTY** (`REINJECT_CONTROL` not implemented at all) | hard stop on the default path |
| Split opt-in | `KVM_ENABLE_CAP(SPLIT_IRQCHIP)` supported | needs `KVM_SET_GSI_ROUTING` / `KVM_IRQ_LINE` → **ENOTTY** (delivery backend) |
| `KVM_SET_IDENTITY_MAP_ADDR` | supported | none (libkrun never calls it) |
| `KVM_SET_TSS_ADDR` (0xfffbd000) | supported | none |

**Boot verdict:** fails at the fatal capability probe (`IOEVENTFD`, `IRQFD`
= 0). Past the probe, the default path dies at `KVM_CREATE_IRQCHIP` →
`ENOTTY`; the split opt-in dies at the delivery ioctls. The split-irqchip
builder variant is the only libkrun configuration with a path forward.

## 5. StratoVirt (group B — later tier)

**Irqchip model:** `KVM_CREATE_IRQCHIP` + `KVM_CREATE_PIT2` for **both** machine
types (`microvm` and `q35` — usage is arch-gated, not machine-gated); no split
mode; no `KVM_ENABLE_CAP` anywhere in the tree.

| area | anonymOS support | gap |
|---|---|---|
| Probe caps (`KVM_CHECK_EXTENSION` for Irqfd, IrqRouting, Xsave/Xcrs, NrMemslots) | Xsave/Xcrs = 1, NR_MEMSLOTS = 32 | **`IRQFD=0`, `IRQ_ROUTING=0`** — probe fails |
| `KVM_CREATE_IRQCHIP` / `KVM_CREATE_PIT2` (both machine types) | **ENOTTY** | fundamental: no split mode exists in StratoVirt |
| `KVM_IRQFD` / `KVM_SET_GSI_ROUTING` / `KVM_IOEVENTFD` | **ENOTTY** | delivery backend |
| `KVM_IRQ_LINE` / `KVM_SIGNAL_MSI` | **ENOTTY** / not implemented | runtime delivery |
| `KVM_SET_IDENTITY_MAP_ADDR`, `KVM_SET_TSS_ADDR` | supported | none |
| aarch64 VGIC (`KVM_CREATE_DEVICE` + device attrs) | not implemented | aarch64 is out of scope for the KVM-compat tier entirely |

**Boot verdict:** fails at the capability probe (`Irqfd`, `IrqRouting` = 0).
Past the probe, `KVM_CREATE_IRQCHIP` → `ENOTTY` is a hard stop with no
alternative configuration — StratoVirt has no split-irqchip mode.

---

## Summary: expected fail points today

| VMM | expected fail point | root cause |
|---|---|---|
| Cloud Hypervisor | startup capability probe (`CapabilityMissing`) | `IOEVENTFD`/`IRQFD`/`IRQ_ROUTING` = 0 |
| Firecracker | startup capability probe | `PIT2`/`PIT_STATE2`/`IOEVENTFD`/`IRQFD` = 0; then `KVM_CREATE_IRQCHIP` → ENOTTY |
| crosvm | `KVM_CREATE_IRQCHIP` → ENOTTY (default); probe/delivery gaps (`--irqchip=split`) | in-kernel irqchip required by default |
| libkrun | startup capability probe (fatal set) | `IOEVENTFD`/`IRQFD` = 0; then `KVM_CREATE_IRQCHIP` → ENOTTY |
| StratoVirt | startup capability probe; `KVM_CREATE_IRQCHIP` → ENOTTY | no split mode exists |

**What unblocks what:** the interrupt-delivery tier (eventfd→virtual-IRQ
delivery with LAPIC injection: `KVM_IRQFD`, `KVM_IOEVENTFD`, `KVM_SET_GSI_ROUTING`,
`KVM_IRQ_LINE` + the corresponding caps) moves Cloud Hypervisor, crosvm-split,
and libkrun-split to the next failure (`KVM_RUN` → `-ENODEV` until the `[HW]`
guest-entry phase). Firecracker and StratoVirt stay blocked at
`KVM_CREATE_IRQCHIP` regardless — in-kernel irqchip is an explicit non-goal of
the compat design.
