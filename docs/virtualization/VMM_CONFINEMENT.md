# VMM Domain Confinement Policy

OpenSpec task 7.1 — the restricted-domain policy for the anonymOS native
VMM/KVM mission.  Declared in `src/kernel/d/core/virt/vmm_policy.d`
(`core.virt.vmm_policy`); this document states the policy, the launch model,
what is enforced vs documented, and the [HW] live probe plan.

## 1. The restricted VMM domain

The VMM (e.g. a Cloud Hypervisor build running as an anonymOS task) executes
**inside a confined domain**, not as System and not in a default user domain.
The domain is an ordinary `core.domain` domain, narrowed by
`vmmInitDomain(domId)`:

- **Namespace** — built by `vmmBuildNamespace()`, a fresh restricted view
  (not the default domain view: no `/Shared`, no compositor socket):

  | Path | Verdict | Why |
  |---|---|---|
  | `/Domains/<name>/Home` | allow rw | guest images (`Home/images/`), configs, state |
  | `/tmp` | allow rw | transient staging |
  | `/dev/kvm` | allow rw | the KVM device (ioctl-only; ioctl rights ride on the fd type) |
  | `/dev/ptmx`, `/dev/pts` | allow rw | VMM console |
  | `/System` | **deny** | admin interfaces |
  | `/dev/mem` | **deny** | raw physical memory |
  | `/proc`, `/sys` | **deny** | raw host / PCI-MMIO introspection |
  | `/Shared` | **deny** | not granted to the VMM |
  | `/dev/dri`, `/dev/bus/usb`, `/dev/video`, `/dev/snd`, `/dev/input` | **deny** | raw PCI-class device nodes |
  | everything else | deny-by-default | no `/` binding |

  The denies are explicit `nsBindDeny` entries (longest-prefix deny-override),
  so they survive a future allow of a parent path; unbound paths already fail
  closed via deny-by-default.

- **Identity ceiling** — the domain's device mask is set to **exactly
  `DEVCLASS_VIRT`** (the kvm grant; VIRT is never in a default mask, not even
  System's — it arrives only by explicit grant, which is what `vmmInitDomain`
  performs).  No raw PCI (no GPU/USB/video/snd/input class bits), no physical
  memory (namespace-deny on `/dev/mem`), no admin rights: `vmmInitDomain`
  **refuses** a domain whose linked identity carries any `CAP_RIGHT_ADMIN_*`
  bit (`vmmIdentityCeilingOk`, fail-closed), and refuses a template chain
  whose least-privilege merge would overrule the VIRT grant.  The declared
  ceiling for a future dedicated VMM identity is
  `VMM_CAP_CEIL = CAP_RIGHT_UNIVERSE & ~CAP_RIGHT_ADMIN_ALL`
  (user rights + the four VM rights, minus every admin right).

- **Resource ceilings** — the `core.virt.vm` ceilings, scoped per VMM domain
  identity (accounted via `Vm.creatorDom`, stamped at `vmAlloc`):

  | Ceiling | Value | Scope | Enforcement |
  |---|---|---|---|
  | VMs | 16 | per VMM domain | `vmmMayCreateVm()` at `KVM_CREATE_VM` (kvm.d) |
  | vCPUs | 64 | per VM | `vmCreateVcpu()` (vm.d, pre-existing) |
  | guest pages | 1 GiB | per VM | `vmSetMemoryRegion()` (vm.d, pre-existing) |
  | guest pages | 4 GiB | per VMM domain | **documented** — counter (`virtPagesForDomain`) and predicate (`vmmMayChargePages`) exist; the memslot path does not consult them yet (see §3) |

  The global pool ceilings (16 VMs / 4 GiB system-wide) still apply on top:
  a VMM domain can never exceed what the machine allows.

- **Audit** — every VMM lifecycle/security event lands in the `core.audit`
  ring (new kinds appended to `AuditKind`, never inserted):

  | Kind | Subject | Detail | Emitted from |
  |---|---|---|---|
  | `VirtVmCreate` | Vm objId | creator domainObjId | `kvmCreateVm` (kvm.d) |
  | `VirtVmTeardown` | Vm objId | creator domainObjId | `kvmVmFdClosed` (vm.d) |
  | `VirtCapDerive` | fd number | `FileType` kind | `kvmAllocChildFd` (posix.d) — a VM/vCPU fd deriving narrowed rights from the `/dev/kvm` system fd |
  | `VirtVmDeny` | domainObjId | `VMM_DENY_*` reason | per-domain ceiling / pool exhaustion (kvm.d); refused `/dev/kvm` open (posix.d `deviceClassGate`) |
  | `VirtNsDeny` | — | — | **reserved** for namespace-deny-hit logging (future) |

## 2. Launch model

1. System (or a configboot manifest, pre-freeze) creates the VMM domain
   linked to a **non-admin** identity: `domainCreate("Vmm", <idObj>, 0)`.
2. System calls `vmmInitDomain(domId)` — narrows the device mask, builds the
   restricted namespace, registers the per-domain ceiling marker.
3. The VMM binary is spawned into the domain (`domain spawn Vmm <vmm>`);
   its tasks carry `domainObjId`, so `namespaceCheckOpen`, `deviceClassGate`,
   and the KVM create path all evaluate against this policy.

A `vmmconfine <domain>` control verb is future work; until then the launcher
calls `vmmInitDomain` directly.  The VMM domain must **not** inherit from a
template that lacks the VIRT grant (`vmmInitDomain` fails closed if it does).

## 3. Enforced vs documented — honest split

- **Enforced**: VIRT-only device mask; the namespace allow/deny set;
  no-admin identity ceiling (refusal at confine time); per-domain VM-count
  ceiling at `KVM_CREATE_VM`; audit of create / teardown / fd derivation /
  `/dev/kvm` denials / ceiling denials.
- **Documented** (declared, probed, not yet wired): the per-VMM-domain 4 GiB
  guest-page total — `virtPagesForDomain()` and `vmmMayChargePages()` exist
  and the probe asserts the predicate, but `KVM_SET_USER_MEMORY_REGION` does
  not consult it; the hard enforcement remains vm.d's per-VM 1 GiB and
  system-wide 4 GiB ceilings.  Likewise, namespace-deny *hits* (e.g. an
  open of `/System`) are refused with `EACCES`/`ENOENT` but only the
  `/dev/kvm` class-denial is audit-logged today (`VirtNsDeny` reserved).

## 4. [HW] live probe plan (task 7.1 verification — stays open)

Prerequisites: a `Vmm` domain confined via `vmmInitDomain`, a test task
spawned into it (`domain spawn Vmm <probe>`), and virtualization hardware
(or the fail-soft paths where noted).  `vmmPolicySelfCheck(vmmDomId)` is the
static half — callable any time, freeze-safe, asserts mask/namespace/ceiling
shape without mutating.  The dynamic half, with exact expected denials:

**P1 — PCI open → denied.**
From the VMM-domain task: `open("/dev/dri/card0", O_RDWR)` → `-EACCES`
(device mask is VIRT-only; `deviceClassGate` refuses).
`open("/dev/mem", O_RDONLY)` → `-EACCES` (explicit namespace deny).
`open("/dev/bus/usb/001/002", O_RDWR)` → `-EACCES`.
Assert `auditCount(VirtVmDeny)` increased with detail `VMM_DENY_DEVICE_CLASS`
for the `/dev/kvm`-class case on a *non*-granted domain (negative control:
temporarily `devoff Vmm virt`, open `/dev/kvm` → `-EACCES` + `VirtVmDeny`,
then `devon Vmm virt` to restore).

**P2 — /System → denied.**
`open("/System/Kernel", O_RDONLY)` → `-EACCES` (explicit deny binding;
`nsResolveCheck` reports `denied=true`).  `stat("/proc/cpuinfo")` →
`-EACCES`; `open("/sys/bus/pci/devices/0000:00:02.0/config", O_RDONLY)` →
`-EACCES`.  Positive controls: `open("/dev/kvm", O_RDWR)` → fd ≥ 0;
`open("/Domains/Vmm/Home/images/disk.qcow2", O_RDWR|O_CREAT)` → fd ≥ 0.

**P3 — second VMM over ceiling → denied.**
VMM domain A: loop `KVM_CREATE_VM` 16 times → 16 fds, 16 `VirtVmCreate`
records, `virtVmLiveForDomain(A) == 16`.
17th `KVM_CREATE_VM` from A → `-ENOSPC` + `VirtVmDeny`/`VMM_DENY_VM_CEILING`
(per-domain ceiling, even though… here the pool is also full).
Then close one VM fd (→ `VirtVmTeardown`), and from VMM domain B
`KVM_CREATE_VM` → succeeds (pool has room; B is under its own budget) —
then fill B to 16 as well and assert a further create from *either* domain →
`-ENOSPC` + `VirtVmDeny`/`VMM_DENY_POOL_EXHAUSTED` (global pool exhausted:
the "second VMM over the ceiling" denial).  Tear everything down; assert
`virtVmLiveForDomain(A) == 0` and matching `VirtVmTeardown` count.

**P4 — vCPU / memslot ceilings (regression).**
On one VM: `KVM_CREATE_VCPU` for ids 0..63 → ok; id 64 → `-EINVAL`
(pre-existing per-VM ceiling).  `KVM_SET_USER_MEMORY_REGION` totalling
> 1 GiB on one VM → `-ENOSPC` (pre-existing per-VM page ceiling).

**P5 — capability derivation audit.**
After P3's creates: `auditCount(VirtCapDerive)` equals the number of VM +
vCPU fds minted, each record's detail naming `FD_KVM_VM`/`FD_KVM_VCPU`;
`VirtVmCreate` subjects match the VM objIds; create/teardown counts balance
at the end of the run.

**P6 — page-budget predicate (documented tier).**
Assert `vmmMayChargePages(vmmDom, 0)` true and
`vmmMayChargePages(vmmDom, VMM_MAX_PAGES_PER_DOMAIN + 1)` false, and that
`virtPagesForDomain(vmmDom)` tracks the pages charged by P4's memslots.
(Wiring the predicate into the memslot path is the follow-up; the probe
records the gap if the predicate and the path ever disagree.)
