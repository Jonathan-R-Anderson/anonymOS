// Memory-protection hardening + capability audit — IMMUTABLE_ROOTLESS §8.3/§8.4.
//
// §8.3 W^X / NX: a page must never be simultaneously writable and executable, and
// pages are non-executable (NX) by default; making memory executable is a gated
// decision (CAP_RIGHT_EXEC).  `wxPteFlags`/`wxProtectMasks` compute page-table
// flags enforcing this, and `sys_mprotect` routes through them so a process can
// never mprotect a page to W+X (the §G #7 "mint exec pages / patch running code"
// attack).  §8.4: every `requireCap` decision is recorded in the audit ring
// (`core/audit.d`), so capability use is attributable.
//
// Live-path caveat: the dynamic linker's load path deliberately maps file segments
// W+X, writes relocations, then mprotects down to R+X.  W^X is therefore enforced
// at the *mprotect* tighten step (legitimate loaders only ever drop privileges
// there); flipping the inline mmap path to NX-by-default needs the loader reworked
// to map RW→relocate→mprotect RX first.  The exec-cap gate ships in audit mode on
// the live path (`g_wxEnforceExecCap=false`) so ld.so's R+X mprotect is never
// denied; the self-test exercises the enforcing path.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared,
// @nogc nothrow.
module core.hardening;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objRelease;
import core.cap : CAP_RIGHT_EXEC, CAP_INVALID, CAPTAB_COUNT, requireCapIn,
                  capInstallIn, capTableClear, capLiveCount;
import core.audit : auditLog, auditCount, AuditKind;

extern (C) @nogc nothrow:

// Linux PROT_* bits.
enum uint PROT_READ  = 0x1;
enum uint PROT_WRITE = 0x2;
enum uint PROT_EXEC  = 0x4;

// x86-64 PTE flags (must match arch.d / mmap.d).
enum ulong PTE_PRESENT = 1UL << 0;
enum ulong PTE_RW      = 1UL << 1;
enum ulong PTE_USER    = 1UL << 2;
enum ulong PTE_NX      = 1UL << 63;

// Fixed handle for a task's execute capability (outside the fd range, like the
// admin caps at 1032+ and untyped at 1024).
enum uint EXEC_CAP_HANDLE = 1040;

// Live-path exec-cap gate.  Default OFF (audit only) so the dynamic linker's R+X
// mprotect is never denied; the self-test flips it on to prove enforcement.
__gshared bool  g_wxEnforceExecCap = false;

__gshared ulong g_wxMapped     = 0;   // mappings whose flags were W^X-sanitized
__gshared ulong g_wxViol       = 0;   // W+X requests downgraded (exec dropped)
__gshared ulong g_wxExecMap    = 0;   // executable pages permitted
__gshared ulong g_wxExecDenied = 0;   // exec refused (gate on, no cap)
__gshared bool  g_hardenSelfTested = false;

// True iff `prot` requests both write and execute (the forbidden W^X combination).
public bool wxViolation(uint prot) {
    return (prot & PROT_WRITE) != 0 && (prot & PROT_EXEC) != 0;
}

// Does the active/given table hold an execute capability?
public bool execCapHeld(int tableId) {
    return requireCapIn(tableId, EXEC_CAP_HANDLE, CAP_RIGHT_EXEC);
}

// Core policy: may a mapping with `prot` be executable?  Never if also writable
// (W^X — the exec request is dropped and counted); when exec-alone is requested it
// is permitted unless the gate is enforcing and the task lacks CAP_RIGHT_EXEC.
private bool wxMayExec(uint prot, int tableId) {
    if ((prot & PROT_EXEC) == 0) return false;
    if (prot & PROT_WRITE) {                 // W^X conflict ⇒ never executable
        ++g_wxViol;
        auditLog(AuditKind.CapDeny, EXEC_CAP_HANDLE, cast(ulong)prot);
        return false;
    }
    if (g_wxEnforceExecCap && !execCapHeld(tableId)) {
        ++g_wxExecDenied;
        auditLog(AuditKind.CapDeny, EXEC_CAP_HANDLE, cast(ulong)prot);
        return false;
    }
    ++g_wxExecMap;
    return true;
}

// PTE flag mask for a fresh user mapping with linux `prot`: USER|PRESENT always;
// RW iff writable; NX unless the page is permitted to be executable (W^X enforced).
public ulong wxPteFlags(uint prot, int tableId) {
    ++g_wxMapped;
    ulong f = PTE_PRESENT | PTE_USER;
    if (prot & PROT_WRITE) f |= PTE_RW;
    if (!wxMayExec(prot, tableId)) f |= PTE_NX;   // NX by default / on W^X conflict
    return f;
}

// set/clear masks for mprotect honoring the same policy.  A request to make a page
// W+X comes back as writable + NX (exec dropped) — never W and X together.
public void wxProtectMasks(uint prot, int tableId, ulong* setMask, ulong* clearMask) {
    ++g_wxMapped;
    ulong s = PTE_PRESENT | PTE_USER;
    ulong c = 0;
    if (prot & PROT_WRITE) s |= PTE_RW; else c |= PTE_RW;
    if (wxMayExec(prot, tableId)) c |= PTE_NX; else s |= PTE_NX;
    if (prot == 0) { c |= PTE_USER; s &= ~PTE_USER; } // PROT_NONE ⇒ no user access
    *setMask = s;
    *clearMask = c;
}

// --- proof --------------------------------------------------------------------
private bool selfTestWx(int st) {            // §8.3
    g_wxEnforceExecCap = false;
    // W+X request ⇒ writable but NX (exec dropped): no page is ever W and X.
    ulong fwx = wxPteFlags(PROT_READ | PROT_WRITE | PROT_EXEC, st);
    bool wxEnforced = ((fwx & PTE_RW) != 0) && ((fwx & PTE_NX) != 0);
    bool viol = wxViolation(PROT_WRITE | PROT_EXEC) && !wxViolation(PROT_READ | PROT_EXEC);
    // Plain data mapping ⇒ NX.
    ulong fdata = wxPteFlags(PROT_READ | PROT_WRITE, st);
    bool dataNx = (fdata & PTE_NX) != 0;
    // Exec-only mapping in audit mode ⇒ executable (NX clear).
    ulong fexec = wxPteFlags(PROT_READ | PROT_EXEC, st);
    bool execOk = (fexec & PTE_NX) == 0;
    // mprotect to W+X comes back writable + NX (never W and X).
    ulong sm, cm;
    wxProtectMasks(PROT_READ | PROT_WRITE | PROT_EXEC, st, &sm, &cm);
    // W+X mprotect ⇒ set writable + NX, and NX is not in the clear mask: never W&X.
    bool mprotWx = ((sm & PTE_RW) != 0) && ((sm & PTE_NX) != 0) && ((cm & PTE_NX) == 0);

    // With the gate ENFORCING: exec-only without the cap ⇒ NX (denied); with the
    // cap installed ⇒ executable.
    g_wxEnforceExecCap = true;
    capTableClear(st);
    ulong fNoCap = wxPteFlags(PROT_READ | PROT_EXEC, st);
    bool deniedNoCap = (fNoCap & PTE_NX) != 0;
    uint o = objAlloc(ObjType.MemRegion, null);
    capInstallIn(st, EXEC_CAP_HANDLE, o, CAP_RIGHT_EXEC, CAP_INVALID);
    ulong fCap = wxPteFlags(PROT_READ | PROT_EXEC, st);
    bool allowedCap = (fCap & PTE_NX) == 0;
    g_wxEnforceExecCap = false;
    capTableClear(st);
    if (o) objRelease(o);

    return wxEnforced && viol && dataNx && execOk && mprotWx && deniedNoCap && allowedCap;
}

private bool selfTestAudit(int st) {         // §8.4 every requireCap decision recorded
    capTableClear(st);
    ulong denyBefore = auditCount(AuditKind.CapDeny);
    ulong okBefore   = auditCount(AuditKind.CapAllow);
    // A denied requireCap (no such cap) must record a CapDeny event.
    bool denied = !requireCapIn(st, EXEC_CAP_HANDLE, CAP_RIGHT_EXEC);
    bool denyLogged = (auditCount(AuditKind.CapDeny) > denyBefore);
    // An admitted requireCap (cap held) must record a CapAllow event.
    uint o = objAlloc(ObjType.MemRegion, null);
    capInstallIn(st, EXEC_CAP_HANDLE, o, CAP_RIGHT_EXEC, CAP_INVALID);
    bool allowed = requireCapIn(st, EXEC_CAP_HANDLE, CAP_RIGHT_EXEC);
    bool allowLogged = (auditCount(AuditKind.CapAllow) > okBefore);
    capTableClear(st);
    if (o) objRelease(o);
    return denied && denyLogged && allowed && allowLogged;
}

public void hardeningSelfTest() {
    if (g_hardenSelfTested) return;
    int st = CAPTAB_COUNT - 2;
    if (capLiveCount(st) != 0) return;  // scratch table busy; retry next tick
    g_hardenSelfTested = true;

    bool wx = selfTestWx(st);
    bool au = selfTestAudit(st);

    if (wx && au) {
        klog("[harden] selftest PASS\n");
    } else {
        klog("[harden] selftest FAIL:");
        if (!wx) klog(" wx");
        if (!au) klog(" audit");
        klog("\n");
    }
}

public void hardeningStats() {
    klog("[harden] wxmapped="); klog_hex(g_wxMapped);
    klog(" wxviol=");           klog_hex(g_wxViol);
    klog(" execmap=");          klog_hex(g_wxExecMap);
    klog(" execdeny=");         klog_hex(g_wxExecDenied);
    klog(" capaudit=");         klog_hex(auditCount(AuditKind.CapAllow) +
                                          auditCount(AuditKind.CapDeny));
    klog("\n");
}
