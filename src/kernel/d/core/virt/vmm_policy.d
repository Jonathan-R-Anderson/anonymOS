// VMM domain confinement policy — OpenSpec task 7.1 (anonymOS native VMM/KVM mission).
//
// This module DECLARES the restricted-domain policy for the VMM and enforces the
// parts that hook into existing mechanisms.  It is deliberately additive: the
// domain/namespace/device-class/audit machinery already exists (core.domain,
// core.namespace, core.identity, core.audit); this file only binds it into the
// one policy a VMM task runs under.  Nothing here restructures the domain system.
//
// The VMM runs as an ordinary confined task (see core.virt.kvm's header): it
// opens /dev/kvm, gets a system fd with VM_CREATE only, and each VM/vCPU fd
// carries exactly the rights its kind needs.  This policy answers "what may
// that task see, hold, and consume":
//
//   NAMESPACE   — its own /Domains/<name>/Home (guest images live under
//                 Home/images/), /tmp, /dev/kvm, and a pty pair.  Everything
//                 else is deny-by-default, with EXPLICIT denies on /System
//                 (admin interfaces), /dev/mem (raw physical memory),
//                 /proc and /sys (raw host/PCI introspection), /Shared, and the
//                 raw PCI-class device subtrees (/dev/dri, /dev/bus/usb,
//                 /dev/video, /dev/snd, /dev/input).
//   IDENTITY    — device mask EXACTLY DEVCLASS_VIRT (the kvm grant, via an
//                 explicit `devon`-style grant; VIRT is never in a default
//                 mask, not even System's).  No raw PCI, no physical memory,
//                 no admin rights: the linked identity's ceiling must carry no
//                 CAP_RIGHT_ADMIN_* bit (fail-closed in vmmInitDomain), and the
//                 declared ceiling for a dedicated VMM identity is VMM_CAP_CEIL.
//   RESOURCES   — the core.virt.vm ceilings, scoped per VMM domain identity:
//                 <= 16 VMs per VMM domain, <= 64 vCPUs per VM, <= 1 GiB per
//                 VM, <= 4 GiB per VMM domain.
//   AUDIT       — VM create/teardown, VM/vCPU fd capability derivations, and
//                 denied accesses are logged to the audit ring (core.audit).
//
// ENFORCED vs DOCUMENTED (honest split):
//   ENFORCED    device mask == VIRT-only (vmmInitDomain, via domainSetDevice);
//               the VMM namespace allow/deny set (vmmBuildNamespace, via
//               nsBind/nsBindDeny — the open path consults it through
//               namespaceCheckOpen); the no-admin-identity-ceiling check
//               (vmmInitDomain refuses otherwise); the per-domain VM-count
//               ceiling at KVM_CREATE_VM (kvm.d calls vmmMayCreateVm, backed
//               by Vm.creatorDom accounting in vm.d); audit records for VM
//               create (kvm.d), VM teardown (vm.d), fd capability derivation
//               (posix.d kvmAllocChildFd), and denied /dev/kvm opens
//               (posix.d deviceClassGate).
//   DOCUMENTED  the per-VMM-domain 4 GiB page total: the counter
//               (virtPagesForDomain) and the predicate (vmmMayChargePages)
//               exist and the HW probe asserts them, but the memslot path
//               (KVM_SET_USER_MEMORY_REGION) does not consult them yet — the
//               per-VM 1 GiB and system-wide 4 GiB ceilings in vm.d are the
//               hard enforcement today.  Likewise, generic namespace-deny
//               hits (e.g. /System) are refused with EACCES/ENOENT but only
//               the /dev/kvm class-denial is audit-logged; a VirtNsDeny kind
//               is reserved for the follow-up.
//
// Launch model: System (or a configboot manifest, pre-freeze) creates the VMM
// domain linked to a non-admin identity, then calls vmmInitDomain(domId).  The
// domain is then spawned into (`domain spawn Vmm <vmm-binary>`) like any other
// domain task.  A `vmmconfine <domain>` control verb is future work; until then
// the launcher calls vmmInitDomain directly.
//
// Constraints: -betterC, @nogc nothrow, no GC/druntime/exceptions.
module core.virt.vmm_policy;

import core.virt.vm : VIRT_MAX_VMS, VIRT_MAX_VCPUS_PER_VM,
                      VIRT_MAX_PAGES_PER_VM, VIRT_MAX_PAGES_TOTAL,
                      virtVmLiveForDomain, virtPagesForDomain;
import core.domain : DomainId, domainById, domainSetDevice, domainDeviceAllowed,
                     domainDeviceMask, domainEffectiveDevices, domainNamePrint;
import core.identity : identityById,
                       DEVCLASS_INPUT, DEVCLASS_GPU, DEVCLASS_CAMERA,
                       DEVCLASS_MIC, DEVCLASS_AUDIO, DEVCLASS_USB,
                       DEVCLASS_NET, DEVCLASS_VIRT;
import core.namespace : nsAllocRestricted, nsBind, nsBindDeny, nsRootDir,
                        nsResolveCheck, nsRelease;
import core.cap : CAP_RIGHT_READ, CAP_RIGHT_WRITE, CAP_RIGHT_STAT,
                  CAP_RIGHT_ADMIN_ALL, CAP_RIGHT_VM_ALL, CAP_RIGHT_UNIVERSE;
import core.audit : auditLog, AuditKind;
import core.io : klog, klog_hex;

extern (C) @nogc nothrow:

// ---------------------------------------------------------------------------
// Identity ceiling
// ---------------------------------------------------------------------------
// The VMM domain's device grant: kvm ONLY.  No raw PCI (no GPU/USB/video/snd/
// input class bits), no physical memory (no /dev/mem — namespace-denied), no
// admin interfaces (no /System — namespace-denied).
enum uint VMM_DEV_CEIL = DEVCLASS_VIRT;

// Declared capability ceiling for a dedicated VMM identity: everything a user
// identity may hold, PLUS the four VM rights (the kvm grant), MINUS every
// admin right.  Compare identity.d: CEIL_USER excludes both ADMIN_ALL and
// VM_ALL; the VMM adds back exactly the VM rights and nothing else.
enum uint VMM_CAP_CEIL = CAP_RIGHT_UNIVERSE & ~CAP_RIGHT_ADMIN_ALL;

// Fail-closed check on the domain's LINKED identity: it must exist and must
// carry no admin right.  (The kvm grant itself arrives via the DEVCLASS_VIRT
// device grant + the /dev/kvm fd rights, not via the identity ceiling — see
// identity.d's "never in a default mask" note.)
public bool vmmIdentityCeilingOk(uint identityObjId) {
    auto r = identityById(identityObjId);
    if (r is null) return false;
    if ((r.rightsCeiling & CAP_RIGHT_ADMIN_ALL) != 0) return false;  // no admin rights, ever
    return true;
}

// ---------------------------------------------------------------------------
// Resource ceilings — the core.virt.vm ceilings, scoped per VMM domain
// ---------------------------------------------------------------------------
enum uint  VMM_MAX_VMS_PER_DOMAIN  = VIRT_MAX_VMS;            // 16 VMs per VMM domain
enum uint  VMM_MAX_VCPUS_PER_VM    = VIRT_MAX_VCPUS_PER_VM;   // 64 vCPUs per VM
enum ulong VMM_MAX_PAGES_PER_VM    = VIRT_MAX_PAGES_PER_VM;   // 1 GiB per VM
enum ulong VMM_MAX_PAGES_PER_DOMAIN = VIRT_MAX_PAGES_TOTAL;   // 4 GiB per VMM domain

// ---------------------------------------------------------------------------
// Deny reasons (VirtVmDeny detail payload)
// ---------------------------------------------------------------------------
enum uint VMM_DENY_VM_CEILING     = 1;  // per-domain VM count ceiling at KVM_CREATE_VM
enum uint VMM_DENY_POOL_EXHAUSTED = 2;  // global VM pool exhausted (second VMM over the ceiling)
enum uint VMM_DENY_DEVICE_CLASS   = 3;  // deviceClassGate refused a brokered node
enum uint VMM_DENY_PAGES          = 4;  // reserved: per-domain page ceiling

// ---------------------------------------------------------------------------
// Audit emitters — the (subject, detail) contract for the VMM audit kinds
// ---------------------------------------------------------------------------
public void vmmAuditCreate(uint vmObjId, uint domObjId) {
    auditLog(AuditKind.VirtVmCreate, vmObjId, domObjId);
}
public void vmmAuditTeardown(uint vmObjId, uint domObjId) {
    auditLog(AuditKind.VirtVmTeardown, vmObjId, domObjId);
}
public void vmmAuditDeny(uint domObjId, uint reason) {
    auditLog(AuditKind.VirtVmDeny, domObjId, reason);
}

// ---------------------------------------------------------------------------
// VMM-domain marker — which domains the per-domain ceilings apply to
// ---------------------------------------------------------------------------
enum int VMM_MAX_DOMAINS = 8;
private __gshared uint[VMM_MAX_DOMAINS] g_vmmDomains;

public bool vmmMarkDomain(uint domObjId) {
    if (domObjId == 0) return false;
    foreach (id; g_vmmDomains) if (id == domObjId) return true;
    foreach (ref id; g_vmmDomains) if (id == 0) { id = domObjId; return true; }
    return false;
}
public bool vmmUnmarkDomain(uint domObjId) {
    foreach (ref id; g_vmmDomains) if (id == domObjId) { id = 0; return true; }
    return false;
}
public bool vmmIsVmmDomain(uint domObjId) {
    if (domObjId == 0) return false;
    foreach (id; g_vmmDomains) if (id == domObjId) return true;
    return false;
}

// ---------------------------------------------------------------------------
// Per-domain resource predicates
// ---------------------------------------------------------------------------
// May this domain create another VM?  Tasks with no domain, or in a domain
// that was never VMM-confined, are decided by the existing gates (device
// class, fd rights, the global pool ceiling) — this predicate only narrows
// VMM-confined domains.  Called from kvmCreateVm before vmAlloc.
public bool vmmMayCreateVm(uint domObjId) {
    if (domObjId == 0) return true;
    if (!vmmIsVmmDomain(domObjId)) return true;
    return virtVmLiveForDomain(domObjId) < VMM_MAX_VMS_PER_DOMAIN;
}

// Per-VMM-domain guest-page budget (DOCUMENTED, not yet wired into the
// memslot path — see the header).  The HW probe asserts the predicate; the
// hard per-VM / system-wide ceilings in vm.d enforce today.
public bool vmmMayChargePages(uint domObjId, ulong extraPages) {
    if (domObjId == 0) return true;
    if (!vmmIsVmmDomain(domObjId)) return true;
    return virtPagesForDomain(domObjId) + extraPages <= VMM_MAX_PAGES_PER_DOMAIN;
}

// ---------------------------------------------------------------------------
// Namespace policy — what the VMM domain may see, and what it may not
// ---------------------------------------------------------------------------
// Build "/Domains/<name>/Home" into buf (NUL-terminated); returns the length
// without the NUL, or 0 on overflow.
private size_t vmmHomePath(uint domObjId, char* buf, size_t bufLen) {
    auto d = domainById(domObjId);
    if (d is null || bufLen < 32) return 0;
    size_t p = 0;
    foreach (c; "/Domains/") buf[p++] = c;
    foreach (i; 0 .. d.nameLen) {
        if (p + 8 >= bufLen) return 0;
        buf[p++] = d.name[i];
    }
    foreach (c; "/Home") buf[p++] = c;
    buf[p] = 0;
    return p;
}

// The VMM's restricted view.  Fresh restricted namespace (not the default
// domain view — the VMM gets no /Shared and no compositor socket):
//
//   ALLOW  /Domains/<name>/Home  rw    — guest images (Home/images/), configs, state
//   ALLOW  /tmp                  rw    — transient staging
//   ALLOW  /dev/kvm              rw    — the KVM device (ioctl-only; ioctl rights
//                                        ride on the fd type, not the namespace)
//   ALLOW  /dev/ptmx, /dev/pts   rw    — VMM console
//   DENY   /System                     — admin interfaces
//   DENY   /dev/mem                    — raw physical memory
//   DENY   /proc, /sys                 — raw host/PCI introspection
//   DENY   /Shared                     — not granted to the VMM
//   DENY   /dev/dri /dev/bus/usb /dev/video /dev/snd /dev/input — raw PCI-class nodes
//   (everything else: deny-by-default — no "/" binding)
public uint vmmBuildNamespace(uint domObjId) {
    auto d = domainById(domObjId);
    if (d is null) return 0;
    const uint ns = nsAllocRestricted();
    if (ns == 0) return 0;
    const uint root = nsRootDir();
    const uint RW = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_STAT;

    char[64] home = void;
    if (vmmHomePath(domObjId, home.ptr, home.length) == 0) { nsRelease(ns); return 0; }
    nsBind(ns, home.ptr,            root, RW);
    nsBind(ns, "/tmp\0".ptr,        root, RW);
    nsBind(ns, "/dev/kvm\0".ptr,    root, RW);
    nsBind(ns, "/dev/ptmx\0".ptr,   root, RW);
    nsBind(ns, "/dev/pts\0".ptr,    root, RW);

    // Explicit denies — also covered by deny-by-default, listed so the policy
    // reads as policy and survives a future allow of a parent path.
    nsBindDeny(ns, "/System\0".ptr);
    nsBindDeny(ns, "/dev/mem\0".ptr);
    nsBindDeny(ns, "/proc\0".ptr);
    nsBindDeny(ns, "/sys\0".ptr);
    nsBindDeny(ns, "/Shared\0".ptr);
    nsBindDeny(ns, "/dev/dri\0".ptr);
    nsBindDeny(ns, "/dev/bus/usb\0".ptr);
    nsBindDeny(ns, "/dev/video\0".ptr);
    nsBindDeny(ns, "/dev/snd\0".ptr);
    nsBindDeny(ns, "/dev/input\0".ptr);

    d.nsObjId = ns;
    return ns;
}

// Confine an existing domain to the VMM policy.  Fail-closed: refuses a
// template (immutable), a domain whose linked identity carries admin rights,
// and a domain whose template chain would overrule the VIRT grant (the DM9
// least-privilege merge intersects the chain, so a VIRT-less template would
// silently deny /dev/kvm — detect it here instead).
public bool vmmInitDomain(uint domObjId) {
    auto d = domainById(domObjId);
    if (d is null || d.isTemplate) return false;
    if (!vmmIdentityCeilingOk(d.identityObjId)) return false;

    // 1. device ceiling: kvm grant only — clear every other class bit.
    domainSetDevice(domObjId, DEVCLASS_INPUT,  false);
    domainSetDevice(domObjId, DEVCLASS_GPU,    false);
    domainSetDevice(domObjId, DEVCLASS_CAMERA, false);
    domainSetDevice(domObjId, DEVCLASS_MIC,    false);
    domainSetDevice(domObjId, DEVCLASS_AUDIO,  false);
    domainSetDevice(domObjId, DEVCLASS_USB,    false);
    domainSetDevice(domObjId, DEVCLASS_NET,    false);
    domainSetDevice(domObjId, DEVCLASS_VIRT,   true);
    // The effective mask (after the template-chain merge) must be exactly the
    // grant — otherwise the chain, not this policy, decides.
    if (domainEffectiveDevices(domObjId) != VMM_DEV_CEIL) return false;

    // 2. namespace: drop any existing view, build the VMM-restricted one.
    if (d.nsObjId != 0) { nsRelease(d.nsObjId); d.nsObjId = 0; }
    if (vmmBuildNamespace(domObjId) == 0) return false;

    // 3. register the marker so the create-path ceiling applies.
    if (!vmmMarkDomain(domObjId)) return false;

    ++d.policyEpoch;
    klog("[vmm] domain confined: ");
    domainNamePrint(domObjId);
    klog(" (dev=virt-only, ns=vmm-restricted)\n");
    return true;
}

// ---------------------------------------------------------------------------
// Static self-check — callable by the [HW] live probe on the real VMM domain.
// Asserts the declared policy without mutating anything (freeze-safe): device
// mask, namespace allow/deny shape, marker registration, ceiling sanity.
// Dynamic denials (PCI open, /System open, over-ceiling create) are exercised
// by the live probe driving ioctls from a task spawned into the domain.
// ---------------------------------------------------------------------------
__gshared bool g_vmmPolicyCheckDone = false;

private bool vmmCheckResolve(uint ns, const(char)* path, bool expectTarget,
                             uint expectRights, bool expectDenied) {
    const(char)* rest; uint rights; bool denied;
    const uint t = nsResolveCheck(ns, path, rest, rights, denied);
    if ((t != 0) != expectTarget) return false;
    if (denied != expectDenied) return false;
    if (expectTarget && ((rights & expectRights) != expectRights)) return false;
    return true;
}

public bool vmmPolicySelfCheck(uint domObjId) {
    auto d = domainById(domObjId);
    if (d is null) { klog("[vmm] policy check FAIL: no domain\n"); return false; }
    bool ok = true;

    // identity ceiling: kvm grant only, no admin
    ok = ok && vmmIsVmmDomain(domObjId);
    ok = ok && vmmIdentityCeilingOk(d.identityObjId);
    ok = ok && (domainDeviceMask(domObjId) == VMM_DEV_CEIL);
    ok = ok && (domainEffectiveDevices(domObjId) == VMM_DEV_CEIL);
    ok = ok &&  domainDeviceAllowed(domObjId, DEVCLASS_VIRT);
    ok = ok && !domainDeviceAllowed(domObjId, DEVCLASS_GPU);
    ok = ok && !domainDeviceAllowed(domObjId, DEVCLASS_USB);
    ok = ok && !domainDeviceAllowed(domObjId, DEVCLASS_NET);
    ok = ok && !domainDeviceAllowed(domObjId, DEVCLASS_INPUT);

    // ceiling sanity: the per-domain numbers ARE the vm.d ceilings, scoped
    ok = ok && (VMM_MAX_VMS_PER_DOMAIN   == VIRT_MAX_VMS);
    ok = ok && (VMM_MAX_VCPUS_PER_VM     == VIRT_MAX_VCPUS_PER_VM);
    ok = ok && (VMM_MAX_PAGES_PER_VM     == VIRT_MAX_PAGES_PER_VM);
    ok = ok && (VMM_MAX_PAGES_PER_DOMAIN == VIRT_MAX_PAGES_TOTAL);
    ok = ok && (VMM_CAP_CEIL & CAP_RIGHT_ADMIN_ALL) == 0;
    ok = ok && (VMM_CAP_CEIL & CAP_RIGHT_VM_ALL) == CAP_RIGHT_VM_ALL;

    // namespace shape
    const uint RW = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    const uint ns = d.nsObjId;
    ok = ok && (ns != 0);
    if (ns != 0) {
        char[96] img = void;
        size_t hp = vmmHomePath(domObjId, img.ptr, 64);
        bool imgOk = false;
        if (hp != 0 && hp + 20 < img.length) {
            size_t p = hp;
            foreach (c; "/images/disk.qcow2") img[p++] = c;
            img[p] = 0;
            imgOk = vmmCheckResolve(ns, img.ptr, true, RW, false);   // guest image: rw
        }
        ok = ok && imgOk;
        ok = ok && vmmCheckResolve(ns, "/dev/kvm\0".ptr, true, RW, false); // the kvm grant
        ok = ok && vmmCheckResolve(ns, "/tmp/x\0".ptr, true, RW, false);
        ok = ok && vmmCheckResolve(ns, "/System/Kernel\0".ptr, false, 0, true);      // admin IF: denied
        ok = ok && vmmCheckResolve(ns, "/dev/mem\0".ptr, false, 0, true);            // raw physmem: denied
        ok = ok && vmmCheckResolve(ns, "/proc/cpuinfo\0".ptr, false, 0, true);       // host introspection: denied
        ok = ok && vmmCheckResolve(ns, "/sys/bus/pci/devices/x\0".ptr, false, 0, true);
        ok = ok && vmmCheckResolve(ns, "/dev/dri/card0\0".ptr, false, 0, true);      // raw PCI: denied
        ok = ok && vmmCheckResolve(ns, "/dev/bus/usb/001/002\0".ptr, false, 0, true);
        ok = ok && vmmCheckResolve(ns, "/Shared/readme\0".ptr, false, 0, true);
        ok = ok && vmmCheckResolve(ns, "/etc/passwd\0".ptr, false, 0, false);        // unbound: ENOENT, not EACCES
    }

    // per-domain predicates on the live pool (no mutation)
    ok = ok && vmmMayCreateVm(domObjId)
              == (virtVmLiveForDomain(domObjId) < VMM_MAX_VMS_PER_DOMAIN);
    ok = ok && vmmMayChargePages(domObjId, 0);
    ok = ok && !vmmMayChargePages(domObjId, VMM_MAX_PAGES_PER_DOMAIN + 1);

    if (ok) klog("[vmm] policy check PASS: virt-only device grant, no-admin identity, vmm namespace shape, ceilings sane\n");
    else    klog("[vmm] policy check FAIL\n");
    return ok;
}
