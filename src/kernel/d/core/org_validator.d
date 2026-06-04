// Runtime validator daemon — ORG Phase 8 of OBJECT_REFERENCE_GRAPH_ROADMAP.md.
//
// Drives the ORG validate/GC machinery as a continuous, **budgeted**,
// **epoch-driven** state machine instead of a stop-the-world pass.  Each tick
// advances one bounded phase of the cycle
//   Idle → Reach → Scc → Invariant → Gc → Audit → Idle
// so a full validation is spread across many ticks and never stalls the scheduler.
// The cycle only restarts when the graph epoch changed since the last cycle
// (8.1 "epoch-driven; only re-validate when something changed").  Findings are
// written to the audit log (8.2).  The control surface (query / trigger /
// quarantine) requires a validator capability token (8.3).
//
// It is driven from the cooperative amortized dispatch hook (one tick per ~256
// syscalls) — the kernel's equivalent of a low-priority background thread.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared,
// @nogc nothrow.
module core.org_validator;

import core.io; // klog / klog_hex
import core.audit : auditLog, auditTotal, auditCount, AuditKind;
import core.org : orgEpoch, orgReachBegin, orgReachStep, orgTarjanRun,
                  orgValidateInvariants, orgGcScan, orgNullDeadWeak, orgLabelAudit,
                  orgAddAnchorRoots, orgQuarantine, orgReachableCount, orgSccCount,
                  edgeAdd, edgeRemove, orgSetLabel, EdgeKind; // P8 self-test
import core.objmgr : objAlloc, objRelease, ObjType;          // P8 self-test
import core.task : orgReconcileRoots;

extern (C) @nogc nothrow:

enum ValPhase : uint { Idle = 0, Reach, Scc, Invariant, Gc, Audit }
enum ValOp    : uint { Query = 1, TriggerCycle, Quarantine }

__gshared ValPhase g_valPhase    = ValPhase.Idle;
__gshared uint     g_valEpochSeen = 0;     // graph epoch at the last cycle start
__gshared int      g_valBudget   = 256;    // work budget per reach/weak-sweep tick
__gshared ulong    g_valTicks    = 0;
__gshared ulong    g_valCycles   = 0;
__gshared ulong    g_valFindings = 0;      // invariant/label/cycle findings (cumulative)
__gshared bool     g_valInited   = false;

// The validator capability: a token only privileged (kernel) code holds.  There is
// no syscall that hands it to userspace, so unprivileged callers cannot drive the
// validator (8.3).
__gshared ulong g_valCapToken = 0;

public void orgValidatorInit() {
    if (g_valInited) return;
    g_valInited = true;
    g_valCapToken = 0x5641_4C49_4441_544FUL; // "VALIDATO" — kernel-held secret
    g_valPhase = ValPhase.Idle;
}

// Hand the validator capability to privileged in-kernel callers only.
public ulong orgValidatorCap() { orgValidatorInit(); return g_valCapToken; }

// One bounded step of the daemon.  Advances a single phase; each phase is bounded
// so a tick is cheap and the scheduler is never stalled.
public void orgValidatorTick() {
    orgValidatorInit();
    ++g_valTicks;
    final switch (g_valPhase) {
        case ValPhase.Idle:
            // Epoch-driven: skip a whole cycle if nothing changed.
            if (orgEpoch() == g_valEpochSeen) return;
            g_valEpochSeen = orgEpoch();
            orgReconcileRoots();   // scheduler-anchored process roots
            orgAddAnchorRoots();   // + registry-anchored roots (complete set)
            orgReachBegin();
            g_valPhase = ValPhase.Reach;
            auditLog(AuditKind.ValidatorRun, 0, g_valCycles);
            break;

        case ValPhase.Reach:
            if (!orgReachStep(g_valBudget)) g_valPhase = ValPhase.Scc; // resumable
            break;

        case ValPhase.Scc:
            orgTarjanRun();
            if (orgSccCount() > 0) auditLog(AuditKind.CycleFound, 0, orgSccCount());
            g_valPhase = ValPhase.Invariant;
            break;

        case ValPhase.Invariant:
            if (!orgValidateInvariants(false)) { // report mode; never auto-quarantine live
                ++g_valFindings;
                auditLog(AuditKind.InvariantBreach, 0, 1);
            }
            g_valPhase = ValPhase.Gc;
            break;

        case ValPhase.Gc: {
            uint cand   = orgGcScan();              // unreachable strong objects
            uint nulled = orgNullDeadWeak(g_valBudget); // safe: dead-weak nulling
            if (cand > 0)   { ++g_valFindings; auditLog(AuditKind.CycleFound, 0, cand); }
            if (nulled > 0) auditLog(AuditKind.WeakNulled, 0, nulled);
            g_valPhase = ValPhase.Audit;
            break;
        }

        case ValPhase.Audit:
            uint lv = orgLabelAudit();
            if (lv > 0) { ++g_valFindings; auditLog(AuditKind.InvariantBreach, 0, lv); }
            ++g_valCycles;
            g_valPhase = ValPhase.Idle;
            break;
    }
}

// 8.3 — control surface, gated by the validator capability.  Returns ≥0 on success,
// -1 (EPERM-like) when the caller does not present the validator capability.
public long orgValidatorControl(ValOp op, ulong capToken, uint arg) {
    orgValidatorInit();
    if (capToken != g_valCapToken) {
        auditLog(AuditKind.ControlDenied, arg, cast(ulong)op);
        return -1; // unprivileged: refused
    }
    auditLog(AuditKind.ControlOk, arg, cast(ulong)op);
    final switch (op) {
        case ValOp.Query:        return cast(long)g_valFindings;
        case ValOp.TriggerCycle: g_valEpochSeen = 0; g_valPhase = ValPhase.Idle; return 0;
        case ValOp.Quarantine:   orgQuarantine(arg); return 0;
    }
}

// --- Phase 8 validator self-test (runtime proof) ------------------------------
// 8.3 the control surface refuses a caller without the validator capability and
// admits one with it; 8.1 an injected ownership label-inversion is detected by the
// daemon within a bounded number of ticks; 8.2 the control calls and the breach
// are recorded in the audit log (attributable).
__gshared bool g_valTested = false;
public void orgValidatorSelfTest() {
    if (g_valTested) return;
    g_valTested = true;
    orgValidatorInit();

    // 8.3 — capability-gated control.
    bool denied  = (orgValidatorControl(ValOp.Query, 0xBAD, 0) < 0);
    bool allowed = (orgValidatorControl(ValOp.Query, orgValidatorCap(), 0) >= 0);
    bool p83 = denied && allowed;

    ulong adBefore = auditTotal();

    // 8.1 — inject a label inversion along an ownership edge.
    uint a1 = objAlloc(ObjType.File, null);
    uint a2 = objAlloc(ObjType.File, null);
    bool inj = (a1 != 0 && a2 != 0 && edgeAdd(a1, a2, EdgeKind.StrongOwn, 0));
    orgSetLabel(a2, 9); orgSetLabel(a1, 1);     // child more sensitive than parent
    ulong breachBefore = auditCount(AuditKind.InvariantBreach);
    orgValidatorControl(ValOp.TriggerCycle, orgValidatorCap(), 0); // force a fresh cycle
    int n = 0; bool detected = false;
    for (; n < 24 && !detected; ++n) {
        orgValidatorTick();
        if (auditCount(AuditKind.InvariantBreach) > breachBefore) detected = true;
    }
    bool p81 = inj && detected && n <= 24;

    orgSetLabel(a1, 0); orgSetLabel(a2, 0);
    edgeRemove(a1, a2, EdgeKind.StrongOwn);
    objRelease(a1); objRelease(a2);

    // 8.2 — the control calls + the breach are recorded and attributable.
    bool p82 = (auditTotal() > adBefore &&
                auditCount(AuditKind.ControlDenied) >= 1 &&
                auditCount(AuditKind.ControlOk) >= 1);

    if (p81 && p82 && p83) klog("[val] selftest PASS\n");
    else                   klog("[val] selftest FAIL\n");
}

public void orgValidatorStats() {
    klog("[val] phase=");   klog_hex(cast(ulong)g_valPhase);
    klog(" ticks=");        klog_hex(g_valTicks);
    klog(" cycles=");       klog_hex(g_valCycles);
    klog(" findings=");     klog_hex(g_valFindings);
    klog(" reach=");        klog_hex(cast(ulong)orgReachableCount());
    klog(" epoch=");        klog_hex(cast(ulong)orgEpoch());
    klog("\n");
}
