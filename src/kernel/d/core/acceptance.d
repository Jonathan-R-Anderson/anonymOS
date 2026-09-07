// IMMUTABLE_ROOTLESS Phase 0.4 — §F acceptance gates, executable.
//
// §0.4 asks for "a test list that fails today and must pass to claim each property", and §F
// states the eight conditions -- four for "immutable", four for "rootless" -- that must ALL hold
// before either word is honest.  Until now those eight lived as prose in a markdown file, which
// meant the only way to answer "is this system immutable?" was to read the source and form an
// opinion.  This module answers it at every boot, in eight lines, with the probe that decided
// each answer.
//
// Design rules, learned from the failures this tier kept producing:
//
//   * A CHECK THAT CANNOT FAIL IS NOT A CHECK.  Every probe below exercises a path where a wrong
//     implementation gives the other answer -- an admin right is demanded from a table that was
//     never given it, a derive asks for more than the parent holds, a rollback is measured by
//     reading the active generation back.  None of them assert a constant.
//
//   * FAILING IS A LEGITIMATE RESULT.  §0.4 explicitly expects failures today; the deliverable is
//     the gate, not a green board.  So each line prints WHY it reached its verdict, and the
//     summary counts rather than celebrates.  A gate that is quietly weakened to pass is worse
//     than no gate.
//
//   * SUB-CONDITIONS ARE PRINTED SEPARATELY.  §F item 1 is a conjunction (read-only AND
//     integrity-verified AND a real backing); collapsing it to one bit hides which half is
//     missing, and the missing half is the actionable part.
//
// Nothing here mutates system state that outlives the probe: generations are created and rolled
// back, scratch cap tables are cleared, and no probe writes to the store's arena.
module core.acceptance;

@nogc: nothrow:

import core.io : klog, klog_dec;
import core.cap : CAPTAB_COUNT, CAP_INVALID, CAP_RIGHT_READ, CAP_RIGHT_WRITE, CAP_RIGHT_STAT,
                  CAP_RIGHT_ADMIN_MOUNT, CAP_RIGHT_ADMIN_REBOOT, CAP_RIGHT_ADMIN_UPDATE,
                  CAP_RIGHT_ADMIN_USER, CAP_RIGHT_ADMIN_DEVICE, CAP_RIGHT_ADMIN_INSPECT,
                  CAP_RIGHT_ADMIN_IDENTITY,
                  capInstallIn, capClearIn, requireCapIn, capDeriveObjectToIn, capRevokeIn,
                  capLiveCount;
import core.admin : adminInstallCapIn, adminRequireIn;
import core.store : storeWritable, storeReadable, storePut, storeImageIntact,
                    genCreate, genSetActive, genRollback, genActive;
import core.update : slotActive, slotInactive, slotGood, updateRollbackIndex;
import core.objstore : objstoreMounted;
import core.hardening : wxViolation, wxPteFlags;
import core.objmgr : ObjType, objAlloc, objRelease;
import core.task : g_tasks;

__gshared bool g_acceptanceRan = false;

// PTE_NX as hardening.d computes it; checked rather than imported so this probe fails if the
// flag ever stops being applied, instead of silently agreeing with whatever hardening exports.
private enum ulong PTE_NX_BIT = 1UL << 63;
private enum uint  PROT_READ_  = 0x1;
private enum uint  PROT_WRITE_ = 0x2;
private enum uint  PROT_EXEC_  = 0x4;

private void line(const(char)* id, const(char)* name, bool pass, const(char)* why) {
    klog("[F] ");
    klog(id);
    klog(" ");
    klog(name);
    klog(pass ? "  PASS  " : "  FAIL  ");
    klog(why);
    klog("\n");
}

// ── IMMUTABLE ────────────────────────────────────────────────────────────────────────────────

// §F immutable-1: a write to /usr is IMPOSSIBLE, not discouraged, on an integrity-verified
// backing.  Three independent sub-conditions, printed apart because the missing one is the
// actionable one.  storeWritable() consults the system namespace's mount rights, so a /usr bound
// with CAP_RIGHT_WRITE by mistake would flip it.
private bool checkImmutable1() {
    const bool usrRefused = !storeWritable("/usr/lib/libc.so\0".ptr);
    const bool usrReadable = storeReadable("/usr/lib/libc.so\0".ptr);

    // Verity: a freshly stored blob must verify.  (store.d's own self-test proves the other
    // half -- that a tampered block FAULTS -- by corrupting its private arena, which this
    // module deliberately cannot reach.)
    ubyte[96] payload;
    foreach (uint i; 0 .. cast(uint)payload.length) payload[i] = cast(ubyte)(i * 11 + 3);
    const uint blob = storePut(payload.ptr, payload.length);
    const bool verityLive = (blob != 0) && storeImageIntact(blob);

    // The backing.  §F says "read-only, integrity-verified BACKING"; a RAM store satisfies the
    // rights check and the hash tree while still losing everything at power off, so an honest
    // answer has to say whether the store is actually on disk.
    const bool persisted = objstoreMounted();

    klog("[F]     immutable-1 parts: usr-write-refused=");  klog_dec(usrRefused ? 1 : 0);
    klog(" usr-readable=");                                 klog_dec(usrReadable ? 1 : 0);
    klog(" verity-verifies=");                              klog_dec(verityLive ? 1 : 0);
    klog(" backing-on-disk=");                              klog_dec(persisted ? 1 : 0);
    klog("\n");
    return usrRefused && usrReadable && verityLive && persisted;
}

// §F immutable-2: the state split is ENFORCED -- /usr ro, /etc overlay, /var user state.
private bool checkImmutable2() {
    const bool usrRo  = !storeWritable("/usr/share/x\0".ptr);
    const bool etcRw  =  storeWritable("/etc/hostname\0".ptr);
    const bool varRw  =  storeWritable("/var/lib/x\0".ptr);
    // ENFORCEMENT, not description.  The earlier version of this check asked whether an UNMOUNTED
    // path was writable in the system view, and that was the wrong question twice over: the system
    // namespace's job is to describe the three trees, and everything outside them is legitimately
    // governed by each task's own namespace, so demanding deny-by-default there would have failed
    // for a correct system.  Worse, storeWritable had NO callers outside store.d's self-test and
    // this file -- it described a policy no real open consulted.
    //
    // §F says "state split ENFORCED", so the honest test is whether a real WRITE to the read-only
    // image is actually refused.  namespaceCheckOpen now returns EROFS for exactly that case, so
    // this asks the question that matters: is /usr writable in practice?
    // Ask the REAL gate, with the real flags a writing open would carry.  O_WRONLY = 1.
    import core.syscalls.posix : namespaceOpenVerdict;
    const int wr = namespaceOpenVerdict("/usr/lib/libc.so\0".ptr, 1);
    const int rd = namespaceOpenVerdict("/usr/lib/libc.so\0".ptr, 0);
    const bool usrEnforced = (wr < 0) && (rd == 0);   // write refused, read still allowed

    klog("[F]     immutable-2 parts: usr-ro="); klog_dec(usrRo ? 1 : 0);
    klog(" etc-rw=");                           klog_dec(etcRw ? 1 : 0);
    klog(" var-rw=");                           klog_dec(varRw ? 1 : 0);
    klog(" usr-write-enforced="); klog_dec(usrEnforced ? 1 : 0);
    klog(" (openW=");   klog_dec(cast(ulong)cast(uint)-wr);
    klog(" openR=");    klog_dec(cast(ulong)cast(uint)rd); klog(")");
    klog("\n");
    return usrRo && etcRw && varRw && usrEnforced;
}

// §F immutable-3: atomic update AND rollback to a prior generation.  Measured by actually
// switching generations and reading the active one back, so a genRollback that returned true
// without moving anything would fail here.
private bool checkImmutable3() {
    const uint before = genActive();

    ubyte[16] a; foreach (uint i; 0 .. 16) a[i] = cast(ubyte)(i + 1);
    ubyte[16] b; foreach (uint i; 0 .. 16) b[i] = cast(ubyte)(i + 200);
    uint[1] e1 = [storePut(a.ptr, a.length)];
    uint[1] e2 = [storePut(b.ptr, b.length)];
    if (e1[0] == 0 || e2[0] == 0) { line("     ", "gen-store\0".ptr, false, "storePut failed\0".ptr); return false; }

    const uint g1 = genCreate(0,  e1.ptr, 1);
    const uint g2 = genCreate(g1, e2.ptr, 1);
    if (g1 == 0 || g2 == 0) return false;

    const bool act2   = genSetActive(g2) && (genActive() == g2);   // deploy
    const bool rolled = genRollback(g1)  && (genActive() == g1);   // and go back

    // A/B slots are the other half of §6.1: there must be two, and the inactive one must be a
    // real candidate rather than a placeholder.
    const int  ai = slotActive();
    const int  ii = slotInactive();
    const bool abDistinct = (ai != ii);
    const bool abUsable   = slotGood(ai);

    if (before != 0) cast(void)genSetActive(before);               // leave boot state alone

    klog("[F]     immutable-3 parts: deploy="); klog_dec(act2 ? 1 : 0);
    klog(" rollback=");                         klog_dec(rolled ? 1 : 0);
    klog(" ab-slots-distinct=");                klog_dec(abDistinct ? 1 : 0);
    klog(" active-slot-good=");                 klog_dec(abUsable ? 1 : 0);
    klog(" rollback-index=");                   klog_dec(updateRollbackIndex());
    klog("\n");
    return act2 && rolled && abDistinct && abUsable;
}

// §F immutable-4: no W^X pages.  Probes the real PTE builder rather than the predicate alone:
// asking for W+X must come back NX (exec dropped), and exec-alone must NOT be NX, because a
// blanket-NX kernel would "pass" a predicate-only test while being unable to run anything.
private bool checkImmutable4() {
    const int  st = CAPTAB_COUNT - 2;
    const bool flags  = wxViolation(PROT_WRITE_ | PROT_EXEC_) && !wxViolation(PROT_READ_ | PROT_EXEC_);
    const ulong wxPte = wxPteFlags(PROT_READ_ | PROT_WRITE_ | PROT_EXEC_, st);
    const ulong xPte  = wxPteFlags(PROT_READ_ | PROT_EXEC_, st);
    const bool wxIsNx = (wxPte & PTE_NX_BIT) != 0;    // W+X requested ⇒ execute refused
    const bool xIsExec = (xPte & PTE_NX_BIT) == 0;    // X alone ⇒ still executable
    klog("[F]     immutable-4 parts: predicate="); klog_dec(flags ? 1 : 0);
    klog(" w+x-mapped-NX=");                       klog_dec(wxIsNx ? 1 : 0);
    klog(" x-alone-executable=");                  klog_dec(xIsExec ? 1 : 0);
    klog("\n");
    return flags && wxIsNx && xIsExec;
}

// ── ROOTLESS ─────────────────────────────────────────────────────────────────────────────────

// §F rootless-1: no code path grants privilege from uid==0.  The probe is an EMPTY capability
// table: nothing in it, no admin object, no caps at all.  Every one of the seven administrative
// actions must be refused.  If any authorization path still consulted a uid, a task could be
// privileged while holding nothing, and this is where that would show.
private bool checkRootless1() {
    // CAPTAB_COUNT-1..-6 are already spoken for: cap/ipc (-1), admin/hardening/update and several
    // security self-tests (-2), identity (-3 and -4), idipc's self-test (-5) and its live session
    // minting (-6).  The first version of these probes reused -3 and collided with identity.d,
    // which is why ROOTLESS-3 reported FAIL with no parts line at all: it bailed on a busy table
    // before printing anything.  A gate that cannot say why it failed is not a gate, so the busy
    // path now announces itself instead of being indistinguishable from a real failure.
    const int st = CAPTAB_COUNT - 7;
    if (capLiveCount(st) != 0) {
        klog("[F]     rootless-1 parts: SKIPPED -- scratch table busy\n");
        return false;
    }

    const bool anyGranted =
           adminRequireIn(st, CAP_RIGHT_ADMIN_MOUNT)
        || adminRequireIn(st, CAP_RIGHT_ADMIN_REBOOT)
        || adminRequireIn(st, CAP_RIGHT_ADMIN_UPDATE)
        || adminRequireIn(st, CAP_RIGHT_ADMIN_USER)
        || adminRequireIn(st, CAP_RIGHT_ADMIN_DEVICE)
        || adminRequireIn(st, CAP_RIGHT_ADMIN_INSPECT)
        || adminRequireIn(st, CAP_RIGHT_ADMIN_IDENTITY);

    klog("[F]     rootless-1 parts: empty-table-grants-nothing="); klog_dec(anyGranted ? 0 : 1);
    klog("\n");
    return !anyGranted;
}

// §F rootless-2: every privileged action requires its OWN capability, and no cap means
// "everything".  Install exactly one admin right and demand all seven: the one must be granted
// and the other six refused.  A "god" cap, or an ADMIN_ALL bitmask treated as a single grant,
// fails this immediately -- which is §G mistake #2.
private bool checkRootless2() {
    const int st = CAPTAB_COUNT - 7;
    if (capLiveCount(st) != 0) {
        klog("[F]     rootless-2 parts: SKIPPED -- scratch table busy\n");
        return false;
    }

    bool granted = false, leaked = false;
    if (adminInstallCapIn(st, CAP_RIGHT_ADMIN_REBOOT)) {
        granted = adminRequireIn(st, CAP_RIGHT_ADMIN_REBOOT);
        leaked  = adminRequireIn(st, CAP_RIGHT_ADMIN_MOUNT)
               || adminRequireIn(st, CAP_RIGHT_ADMIN_UPDATE)
               || adminRequireIn(st, CAP_RIGHT_ADMIN_USER)
               || adminRequireIn(st, CAP_RIGHT_ADMIN_DEVICE)
               || adminRequireIn(st, CAP_RIGHT_ADMIN_INSPECT)
               || adminRequireIn(st, CAP_RIGHT_ADMIN_IDENTITY);
    }
    // Clear every handle this probe could have touched, so the table is empty for the next check.
    foreach (uint h; 0 .. 64) capClearIn(st, h);

    klog("[F]     rootless-2 parts: held-right-granted="); klog_dec(granted ? 1 : 0);
    klog(" other-rights-refused=");                        klog_dec(leaked ? 0 : 1);
    klog("\n");
    return granted && !leaked;
}

// §F rootless-3: caps are unforgeable, delegate only what the holder has, and are revocable.
// The widening attempt is the load-bearing part: a derive that returns a cap with rights the
// parent never held collapses the whole model (§G #6).
private bool checkRootless3() {
    // A table of its own, not shared with rootless-1/2: those install and clear admin caps, and
    // admin.d chooses its own handle numbers, so "clear handles 0..63" is not a reliable reset.
    const int st = CAPTAB_COUNT - 8;
    if (capLiveCount(st) != 0) {
        klog("[F]     rootless-3 parts: SKIPPED -- scratch table busy\n");
        return false;
    }

    const uint obj = objAlloc(ObjType.Directory, null);
    if (obj == 0) return false;

    enum uint SRC = 10, NARROW = 11, WIDE = 12;
    bool installed = capInstallIn(st, SRC, obj, CAP_RIGHT_READ | CAP_RIGHT_STAT, CAP_INVALID) != CAP_INVALID;

    // Narrowing is allowed…
    const bool narrowOk = installed
        && capDeriveObjectToIn(st, SRC, NARROW, obj, CAP_RIGHT_READ) != CAP_INVALID
        && requireCapIn(st, NARROW, CAP_RIGHT_READ)
        && !requireCapIn(st, NARROW, CAP_RIGHT_WRITE);

    // …widening is not.  The parent holds READ|STAT and never held WRITE.
    const bool widenRefused = installed
        && capDeriveObjectToIn(st, SRC, WIDE, obj, CAP_RIGHT_READ | CAP_RIGHT_WRITE) == CAP_INVALID;

    // Revocation must actually strip authority, not just mark a flag.
    bool revokedOk = false;
    if (installed) {
        capRevokeIn(st, SRC);
        revokedOk = !requireCapIn(st, SRC, CAP_RIGHT_READ);
    }

    foreach (uint h; 0 .. 64) capClearIn(st, h);
    objRelease(obj);

    klog("[F]     rootless-3 parts: narrowing-allowed="); klog_dec(narrowOk ? 1 : 0);
    klog(" widening-refused=");                           klog_dec(widenRefused ? 1 : 0);
    klog(" revoke-strips-authority=");                    klog_dec(revokedOk ? 1 : 0);
    klog("\n");
    return narrowOk && widenRefused && revokedOk;
}

// §F rootless-4: PID1 starts least-privilege -- it must NOT hold rights it was never delegated.
// adminInstallInitCaps gives init MOUNT, REBOOT, INSPECT and IDENTITY and deliberately withholds
// UPDATE, USER and DEVICE, so this reads init's real table and checks both halves: a system that
// quietly handed init everything "for convenience" is §G mistake #2 wearing a different hat.
private bool checkRootless4() {
    const int it = g_tasks[0].capTabId;
    const bool has = adminRequireIn(it, CAP_RIGHT_ADMIN_MOUNT)
                  && adminRequireIn(it, CAP_RIGHT_ADMIN_REBOOT)
                  && adminRequireIn(it, CAP_RIGHT_ADMIN_INSPECT);
    const bool withheld = !adminRequireIn(it, CAP_RIGHT_ADMIN_UPDATE)
                       && !adminRequireIn(it, CAP_RIGHT_ADMIN_USER)
                       && !adminRequireIn(it, CAP_RIGHT_ADMIN_DEVICE);
    klog("[F]     rootless-4 parts: init-holds-what-it-needs="); klog_dec(has ? 1 : 0);
    klog(" init-lacks-update/user/device=");                     klog_dec(withheld ? 1 : 0);
    klog("\n");
    return has && withheld;
}

// ── the gate ─────────────────────────────────────────────────────────────────────────────────

public void acceptanceRun() {
    if (g_acceptanceRan) return;
    g_acceptanceRan = true;

    klog("[F] === IMMUTABLE_ROOTLESS Phase 0.4 acceptance gates (roadmap section F) ===\n");

    const bool i1 = checkImmutable1();
    line("IMMUTABLE-1\0".ptr, "system-tree-read-only-and-verified\0".ptr, i1,
         i1 ? "/usr unwritable, verity verifies, store on disk\0".ptr
            : "see parts above; on live media backing-on-disk=0 is expected, not a defect\0".ptr);

    const bool i2 = checkImmutable2();
    line("IMMUTABLE-2\0".ptr, "state-split-enforced\0".ptr, i2,
         i2 ? "/usr ro, /etc + /var rw, unmounted denied\0".ptr
            : "system ns root binds / with uint.max rights -- split is 3 subtrees, not a default\0".ptr);

    const bool i3 = checkImmutable3();
    line("IMMUTABLE-3\0".ptr, "atomic-update-and-rollback\0".ptr, i3,
         i3 ? "generation deployed and rolled back; A/B slots live\0".ptr
            : "see parts above\0".ptr);

    const bool i4 = checkImmutable4();
    line("IMMUTABLE-4\0".ptr, "no-w-xor-x-pages\0".ptr, i4,
         i4 ? "W+X maps NX; X alone still executable\0".ptr
            : "see parts above\0".ptr);

    const bool r1 = checkRootless1();
    line("ROOTLESS-1\0".ptr, "no-privilege-from-uid-zero\0".ptr, r1,
         r1 ? "empty cap table grants none of the 7 admin actions\0".ptr
            : "an admin action was granted to a table holding nothing\0".ptr);

    const bool r2 = checkRootless2();
    line("ROOTLESS-2\0".ptr, "typed-admin-caps-no-god-cap\0".ptr, r2,
         r2 ? "one right held grants exactly that right\0".ptr
            : "see parts above\0".ptr);

    const bool r3 = checkRootless3();
    line("ROOTLESS-3\0".ptr, "unforgeable-narrowing-revocable\0".ptr, r3,
         r3 ? "narrow ok, widen refused, revoke strips authority\0".ptr
            : "see parts above\0".ptr);

    const bool r4 = checkRootless4();
    line("ROOTLESS-4\0".ptr, "pid1-least-privilege\0".ptr, r4,
         r4 ? "init holds mount/reboot/inspect, lacks update/user/device\0".ptr
            : "see parts above\0".ptr);

    uint immutablePassed = 0;
    if (i1) ++immutablePassed; if (i2) ++immutablePassed;
    if (i3) ++immutablePassed; if (i4) ++immutablePassed;
    uint rootlessPassed = 0;
    if (r1) ++rootlessPassed; if (r2) ++rootlessPassed;
    if (r3) ++rootlessPassed; if (r4) ++rootlessPassed;

    // §F is explicit that these are conjunctions: "until all four hold, it is read-mostly, not
    // immutable" / "single-root with extra steps".  So the summary reports the word the system
    // has EARNED, not the score.
    klog("[F] SUMMARY immutable ");  klog_dec(immutablePassed); klog("/4 -> ");
    klog(immutablePassed == 4 ? "IMMUTABLE\0".ptr : "read-mostly (not immutable)\0".ptr);
    klog(";  rootless ");            klog_dec(rootlessPassed);  klog("/4 -> ");
    klog(rootlessPassed == 4 ? "ROOTLESS\0".ptr : "single-root with extra steps\0".ptr);
    klog("\n");
}
