// Cross-identity IPC policy — Phase 5 of roadmap/IDENTITY_DOMAIN_ROADMAP.md.
//
// Deny-by-default cross-identity communication.  Two processes may open a secure
// IPC session only if they share a security domain (same Identity) OR an explicit
// `IpcPairRule` authorizes the directed pair (optionally routing through a broker
// service, e.g. a Dev→Disposable sanitizer).  The policy is enforced where the
// broker mints a session descriptor: `core/secipc.d` calls a gate this module
// installs, which resolves each process object to its security domain, decides via
// `idipcMayConnect`, stamps both domains into the (signed) descriptor, and audits
// `IdIpcDeny` on refusal.  secipc itself stays identity-agnostic — the channel-cap
// routing gate (K1) remains key-free; the identity check happens only at issuance.
//
// Kernel build constraints (hard): -betterC (ldc2, no GC/druntime/exceptions),
// plain structs, __gshared fixed-size tables, @nogc nothrow, -O0.
module core.idipc;

import core.objmgr : ObjType, objAlloc, objRelease, objGet;
import core.identity : IdentityId, IpcPairRule, g_idIpcRules, ID_IPC_RULES_MAX,
                       identityByName;
import core.secipc : SessionDescriptor, secipcSetIdGate, brokerRequestSession,
                     brokerAuthorizePair, identityRegister,
                     SUITE_CHACHA20POLY1305, SUITE_AES256GCM;
import core.cap : CAPTAB_COUNT, CAP_RIGHT_CALL, CAP_INVALID,
                  capInstallIn, capClearIn, capLiveCount;
import core.task : g_tasks, MAX_TASKS;
import core.audit : auditLog, AuditKind;
import core.io : klog, klog_hex;

extern (C) @nogc nothrow:

__gshared ulong g_idipcChecks = 0;
__gshared ulong g_idipcAllow  = 0;
__gshared ulong g_idipcDeny   = 0;
__gshared bool  g_idipcInited     = false;
__gshared bool  g_idipcSelfTested = false;

// Resolve a process object to the security-domain identity it is labelled with.
// The authoritative source is the owning Task's `identityObjId`; a process object
// not backed by a live task (or the kernel/null domain) resolves to 0.  Pluggable
// so a launcher or a self-test can supply process→identity labels directly.
alias IdipcResolverFn = extern (C) uint function(uint procObj) @nogc nothrow;

extern (C) uint idipcResolveViaTask(uint procObj) @nogc nothrow {
    if (procObj == 0) return 0;
    foreach (ref t; g_tasks) {
        if (!t.active || t.exited) continue;
        if (t.processObjId == procObj || t.objId == procObj)
            return t.identityObjId;
    }
    return 0;
}

__gshared IdipcResolverFn g_idipcResolver = &idipcResolveViaTask;
public void idipcSetResolver(IdipcResolverFn fn) {
    g_idipcResolver = (fn is null) ? &idipcResolveViaTask : fn;
}

// === policy ===================================================================
// Deny-by-default: a session is allowed iff the two domains are identical (same
// Identity — including two unlabelled/0 processes) or a directed `IpcPairRule`
// exists.  A 0 broker means a direct allow; a non-zero broker means the pair is
// expected to route through that sanitizer/broker service, but the connection is
// still authorized here (the broker object is advisory metadata for §7).
public bool idipcMayConnect(IdentityId fromId, IdentityId toId) {
    if (fromId == toId) return true;
    foreach (ref r; g_idIpcRules)
        if (r.inUse && r.from == fromId && r.to == toId) return true;
    return false;
}

// The broker service object a directed pair routes through (0 = direct / none).
public uint idipcBrokerSvc(IdentityId fromId, IdentityId toId) {
    foreach (ref r; g_idIpcRules)
        if (r.inUse && r.from == fromId && r.to == toId) return r.brokerSvcObjId;
    return 0;
}

// Install / update a directed cross-identity allow rule (policy authority does
// this; also used by tests and §7 brokers).  Idempotent on (from,to).
public bool idipcPairRuleAdd(IdentityId fromId, IdentityId toId, uint brokerSvcObjId) {
    return idipcPairRuleAddEx(fromId, toId, brokerSvcObjId, false, false);
}

// DECLARATIVE_CONFIG Phase 7: the manifest carries `dh` and `audit` per allow-rule and the kernel
// dropped both, so "dh": true in system.json granted nothing.  They are policy the config author
// wrote down; storing them is what lets anything act on them.
public bool idipcPairRuleAddEx(IdentityId fromId, IdentityId toId, uint brokerSvcObjId,
                               bool dh, bool audit) {
    if (fromId == 0 || toId == 0 || fromId == toId) return false;
    foreach (ref r; g_idIpcRules)
        if (r.inUse && r.from == fromId && r.to == toId) {
            r.brokerSvcObjId = brokerSvcObjId; r.dh = dh; r.audit = audit; return true;
        }
    foreach (ref r; g_idIpcRules)
        if (!r.inUse) {
            r.inUse = true; r.from = fromId; r.to = toId;
            r.brokerSvcObjId = brokerSvcObjId; r.dh = dh; r.audit = audit; return true;
        }
    return false;
}

public bool idipcRemovePairRule(IdentityId fromId, IdentityId toId) {
    foreach (ref r; g_idIpcRules)
        if (r.inUse && r.from == fromId && r.to == toId) { r = IpcPairRule.init; return true; }
    return false;
}

// === the secipc gate ==========================================================
// Installed into core.secipc; called when the broker is about to mint a session
// descriptor for (aProc → bProc).  Resolves both domains, applies the policy,
// stamps the identity ids into *aIdOut/*bIdOut (the broker signs them into the
// descriptor), and audits a refusal.
extern (C) bool idipcGate(uint aProc, uint bProc, uint* aIdOut, uint* bIdOut) @nogc nothrow {
    uint a = g_idipcResolver(aProc);
    uint b = g_idipcResolver(bProc);
    if (aIdOut !is null) *aIdOut = a;
    if (bIdOut !is null) *bIdOut = b;
    ++g_idipcChecks;
    if (idipcMayConnect(a, b)) { ++g_idipcAllow; return true; }
    ++g_idipcDeny;
    auditLog(AuditKind.IdIpcDeny, aProc, (cast(ulong)a << 32) | b);
    return false;
}

// Boot: install the gate and seed default brokered pairs.  Per §5/§7 a Development
// process may hand work to a Disposable one only through a sanitizer service.
public void idipcInit() {
    if (g_idipcInited) return;
    g_idipcInited = true;
    secipcSetIdGate(&idipcGate);

    IdentityId dev  = identityByName("Development\0".ptr);
    IdentityId disp = identityByName("Disposable\0".ptr);
    if (dev != 0 && disp != 0) {
        uint sanitizer = objAlloc(ObjType.Service, null); // Dev→Disposable broker
        idipcPairRuleAdd(dev, disp, sanitizer);
    }

    // ROADMAP 4.1 §7: the COMPOSITOR HUB, written down as broker rules.
    //
    // sys_connect already lets any identity reach a system-trust peer, because measurement showed
    // every real cross-identity connect is app -> compositor on the Wayland socket; refusing it
    // would cut every application off from its display.  But that lived only as a trust comparison
    // inside the connect path, so the broker -- which is where IDENTITY_DOMAIN §1.2 says the
    // decision belongs -- did not know about it, and brokerRequestSession refused to mint a
    // descriptor for the one crossing that actually happens.  Stating it as rules keeps the two
    // agreeing and makes the policy greppable instead of implicit.
    // Spelled out one call at a time rather than looped over a string-pointer array: a
    // `static immutable(char)*[6]` of literal .ptrs needs load-time relocations this kernel does
    // not apply, so every entry read back as null and identityByName faulted on CR2=0 inside
    // idipcInit, before the desktop existed.  Six calls cost nothing and need no relocation.
    IdentityId sys = identityByName("System\0".ptr);
    if (sys != 0) {
        idipcAddHubRule(sys, "Personal\0".ptr);
        idipcAddHubRule(sys, "Work\0".ptr);
        idipcAddHubRule(sys, "Banking\0".ptr);
        idipcAddHubRule(sys, "Development\0".ptr);
        idipcAddHubRule(sys, "Untrusted\0".ptr);
        idipcAddHubRule(sys, "Disposable\0".ptr);
    }
}

private void idipcAddHubRule(IdentityId sys, const(char)* nm) {
    IdentityId u = identityByName(nm);
    if (u != 0 && u != sys) idipcPairRuleAdd(u, sys, 0);   // 0: no sanitizer, direct hub
}

// ROADMAP 4.1 §7: mint a REAL brokered session for a real crossing.
//
// brokerRequestSession has been reachable only from idipcSelfTest, on three synthetic process
// objects and a throwaway resolver.  Everything it needs from a real crossing already exists:
// tasks carry processObjId (ObjType.Process), and the default resolver idipcResolveViaTask maps
// those to the identity the task actually runs as.  So the only thing standing between the
// self-test and the live path was a caller.
//
// Called once per distinct identity pair from sys_connect, after the connect is allowed: the
// point is not to gate the connection a second time -- sys_connect already decided -- but to
// produce the signed, expiring descriptor the design says a crossing should be attributable to.
//
// Returns true if a descriptor was minted; the sessionId and both stamped identities are logged
// so the record shows a real pair, not the self-test's 0x100/0x200 fixtures.
public bool idipcMintLiveSession(uint aProc, uint bProc) {
    if (aProc == 0 || bProc == 0 || aProc == bProc) return false;

    // A scratch table distinct from the self-test's (CAPTAB_COUNT-5), so a mint cannot disturb
    // a self-test in flight or vice versa.
    enum int  ST       = CAPTAB_COUNT - 6;
    enum uint LAUNCH_H = 60, CHAN_H = 61;

    uint launchObj = objAlloc(ObjType.Process, null);
    if (launchObj == 0) return false;
    if (capInstallIn(ST, LAUNCH_H, launchObj, CAP_RIGHT_CALL, CAP_INVALID) == CAP_INVALID) {
        objRelease(launchObj); return false;
    }

    // The kernel is its own CA here (caSign), so a self-registered cert verifies.  The public key
    // is a placeholder until identities carry real launch keys -- what is being proven now is that
    // the broker path runs on live processes, not that the key material is meaningful.
    ubyte[32] pub; foreach (i; 0 .. 32) pub[i] = cast(ubyte)(0x40 + i);
    bool ok = identityRegister(ST, aProc, pub.ptr, LAUNCH_H, 1_000_000)
           && identityRegister(ST, bProc, pub.ptr, LAUNCH_H, 1_000_000);
    if (ok) brokerAuthorizePair(aProc, bProc);

    SessionDescriptor d;
    bool minted = ok && brokerRequestSession(ST, aProc, bProc,
                                             SUITE_CHACHA20POLY1305 | SUITE_AES256GCM,
                                             CHAN_H, 10, 100_000, &d);
    if (minted) {
        klog("[4.1] brokered session minted: id="); klog_hex(d.sessionId);
        klog(" aIdentity="); klog_hex(d.aIdentity);
        klog(" bIdentity="); klog_hex(d.bIdentity);
        klog(" suite=");     klog_hex(d.suite);
        klog(" channelCap="); klog_hex(d.channelCap);
        klog("\n");
    } else {
        klog("[4.1] brokered session REFUSED for a connect sys_connect had already allowed\n");
    }

    capClearIn(ST, LAUNCH_H);
    capClearIn(ST, CHAN_H);
    objRelease(launchObj);
    return minted;
}

// === proof (roadmap §5 outcome) ==============================================
// A self-contained throwaway resolver maps three test process objects to two
// security domains; we drive the real broker path and verify: same-domain IPC is
// minted, cross-domain is denied without a rule, a brokered pair is allowed once
// a rule exists, and the issued descriptor carries both (signed) domains.
__gshared uint g_idipcTPA, g_idipcTPB, g_idipcTPC; // test process objects
__gshared uint g_idipcTIA, g_idipcTIB;             // test domains: PA,PC=TIA; PB=TIB

extern (C) uint idipcTestResolver(uint procObj) @nogc nothrow {
    if (procObj == g_idipcTPA) return g_idipcTIA;   // domain A
    if (procObj == g_idipcTPB) return g_idipcTIB;   // domain B
    if (procObj == g_idipcTPC) return g_idipcTIA;   // domain A (same as PA)
    return 0;
}

public void idipcSelfTest() {
    if (g_idipcSelfTested) return;
    int st = CAPTAB_COUNT - 5;                 // scratch table (≠ secipc/admin/idproc)
    if (capLiveCount(st) != 0) return;         // busy; retry next tick
    g_idipcSelfTested = true;

    // Pure-policy checks first (identity-id level).
    enum IdentityId A = 0xA1, B = 0xB2;
    bool pol = idipcMayConnect(A, A)            // same domain → allow
            && !idipcMayConnect(A, B)           // cross, no rule → deny
            && idipcPairRuleAdd(A, B, 0)
            && idipcMayConnect(A, B)            // cross, rule → allow
            && !idipcMayConnect(B, A)           // directed: reverse still denied
            && idipcRemovePairRule(A, B)
            && !idipcMayConnect(A, B);          // rule removed → deny again

    // End-to-end through the broker, exercising the gate + descriptor stamping.
    uint pa = objAlloc(ObjType.Process, null);
    uint pb = objAlloc(ObjType.Process, null);
    uint pc = objAlloc(ObjType.Process, null);
    uint launchObj = objAlloc(ObjType.Process, null);
    enum uint LAUNCH_H = 50, CHAN_H = 51;
    g_idipcTPA = pa; g_idipcTPB = pb; g_idipcTPC = pc;
    g_idipcTIA = 0x100; g_idipcTIB = 0x200;    // PA,PC in domain 0x100; PB in 0x200

    auto savedResolver = g_idipcResolver;
    g_idipcResolver = &idipcTestResolver;

    bool e2e = false;
    if (pa && pb && pc && launchObj) {
        ubyte[32] pub; foreach (i; 0 .. 32) pub[i] = cast(ubyte)(0x40 + i);
        capInstallIn(st, LAUNCH_H, launchObj, CAP_RIGHT_CALL, CAP_INVALID);
        bool ra = identityRegister(st, pa, pub.ptr, LAUNCH_H, 1000);
        bool rb = identityRegister(st, pb, pub.ptr, LAUNCH_H, 1000);
        bool rc = identityRegister(st, pc, pub.ptr, LAUNCH_H, 1000);
        brokerAuthorizePair(pa, pb);           // secipc-level pair (crypto layer)
        brokerAuthorizePair(pa, pc);

        // Same domain (PA→PC, both 0x100): allowed; descriptor stamps both domains.
        SessionDescriptor dSame;
        bool sameOk = brokerRequestSession(st, pa, pc, SUITE_CHACHA20POLY1305,
                                           CHAN_H, 10, 100, &dSame);
        bool sameStamp = sameOk && dSame.aIdentity == 0x100 && dSame.bIdentity == 0x100;

        // Cross domain (PA→PB) with NO idipc rule: denied at descriptor issuance.
        SessionDescriptor dX;
        bool crossDenied = !brokerRequestSession(st, pa, pb, SUITE_CHACHA20POLY1305,
                                                 CHAN_H + 1, 10, 100, &dX);

        // Add a brokered rule 0x100→0x200, retry: now allowed, both domains stamped.
        uint sanit = objAlloc(ObjType.Service, null);
        bool ruled = idipcPairRuleAdd(0x100, 0x200, sanit);
        SessionDescriptor dB;
        bool crossOk = brokerRequestSession(st, pa, pb, SUITE_CHACHA20POLY1305,
                                            CHAN_H + 2, 10, 100, &dB);
        bool crossStamp = crossOk && dB.aIdentity == 0x100 && dB.bIdentity == 0x200;
        bool brokerSvc = idipcBrokerSvc(0x100, 0x200) == sanit;

        e2e = ra && rb && rc && sameOk && sameStamp && crossDenied
           && ruled && crossOk && crossStamp && brokerSvc;

        idipcRemovePairRule(0x100, 0x200);
        if (sanit) objRelease(sanit);
    }

    // teardown
    g_idipcResolver = savedResolver;
    capClearIn(st, LAUNCH_H);
    capClearIn(st, CHAN_H);
    capClearIn(st, CHAN_H + 1);
    capClearIn(st, CHAN_H + 2);
    if (pa) objRelease(pa);
    if (pb) objRelease(pb);
    if (pc) objRelease(pc);
    if (launchObj) objRelease(launchObj);
    g_idipcTPA = g_idipcTPB = g_idipcTPC = 0;

    if (pol && e2e) klog("[idipc] selftest PASS\n");
    else {
        klog("[idipc] selftest FAIL:");
        if (!pol) klog(" policy");
        if (!e2e) klog(" e2e");
        klog("\n");
    }
}

public void idipcStats() {
    klog("[idipc] checks="); klog_hex(g_idipcChecks);
    klog(" allow=");         klog_hex(g_idipcAllow);
    klog(" deny=");          klog_hex(g_idipcDeny);
    klog("\n");
}
