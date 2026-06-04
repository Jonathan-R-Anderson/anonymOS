// Audit log — ORG Phase 8.2 (shared seam with SECURITY_ROADMAP.md's core/audit.d).
//
// A bounded ring buffer of security-relevant graph events so every action the ORG
// validator takes — a cycle found, an SCC collected, an invariant breach, a
// revocation, a quarantine, a denied/permitted control call — is attributable
// (sequence number + kind + object + detail). Kept dependency-free (only klog) so
// any subsystem can log without an import cycle.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module core.audit;

import core.io; // klog / klog_hex

extern (C) @nogc nothrow:

enum AuditKind : uint {
    None = 0,
    ValidatorRun,     // a validator cycle started
    CycleFound,       // unreachable strong-SCC / GC candidates detected
    SccCollected,     // an SCC was reclaimed
    InvariantBreach,  // I1/I4/label violation observed
    Revocation,       // a capability was revoked
    Quarantine,       // an object was quarantined
    WeakNulled,       // dead weak edges nulled
    ControlOk,        // validator control call admitted (held the cap)
    ControlDenied,    // validator control call refused (no cap)
    CapAllow,         // §8.4: a requireCap decision admitted (held the rights)
    CapDeny,          // §8.4: a requireCap decision refused (missing rights)
    Count
}

enum int AUDIT_LOG_MAX = 256;

struct AuditEvent {
    ulong     seq;     // monotonic sequence number (0 = empty slot)
    AuditKind kind;
    uint      objId;   // subject object, or 0
    ulong     detail;  // kind-specific payload
}

__gshared AuditEvent[AUDIT_LOG_MAX] g_auditLog;
__gshared uint                      g_auditHead = 0;   // next write slot (ring)
__gshared ulong                     g_auditSeq  = 0;   // total events ever logged
__gshared ulong[AuditKind.Count]    g_auditCounts;

// Record an event.  O(1); never blocks.  The ring overwrites oldest entries; the
// per-kind counters and the running sequence are never lost.
public void auditLog(AuditKind kind, uint objId, ulong detail) {
    auto e = &g_auditLog[g_auditHead];
    e.seq    = ++g_auditSeq;
    e.kind   = kind;
    e.objId  = objId;
    e.detail = detail;
    g_auditHead = (g_auditHead + 1) % AUDIT_LOG_MAX;
    if (kind < AuditKind.Count) ++g_auditCounts[kind];
}

public ulong auditCount(AuditKind kind) {
    return (kind < AuditKind.Count) ? g_auditCounts[kind] : 0;
}
public ulong auditTotal() { return g_auditSeq; }

// Copy the most-recent event of a given kind into `out_`; returns false if none.
public bool auditLastOf(AuditKind kind, AuditEvent* out_) {
    if (out_ is null) return false;
    for (int i = 0; i < AUDIT_LOG_MAX; ++i) {
        int idx = (cast(int)g_auditHead - 1 - i + AUDIT_LOG_MAX * 2) % AUDIT_LOG_MAX;
        auto e = &g_auditLog[idx];
        if (e.seq != 0 && e.kind == kind) { *out_ = *e; return true; }
    }
    return false;
}

public void auditStats() {
    klog("[audit] total=");  klog_hex(g_auditSeq);
    klog(" breach=");        klog_hex(auditCount(AuditKind.InvariantBreach));
    klog(" cycle=");         klog_hex(auditCount(AuditKind.CycleFound));
    klog(" quar=");          klog_hex(auditCount(AuditKind.Quarantine));
    klog(" revoke=");        klog_hex(auditCount(AuditKind.Revocation));
    klog(" ctlok=");         klog_hex(auditCount(AuditKind.ControlOk));
    klog(" ctldeny=");       klog_hex(auditCount(AuditKind.ControlDenied));
    klog(" capok=");         klog_hex(auditCount(AuditKind.CapAllow));
    klog(" capdeny=");       klog_hex(auditCount(AuditKind.CapDeny));
    klog("\n");
}
