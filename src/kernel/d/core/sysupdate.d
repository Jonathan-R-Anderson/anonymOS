// sysupdate.d — the A/B update engine control surface (U1, roadmap/SYSTEM_UPDATE_ROADMAP.md).
//
// Drives the boot-state machine from userspace via the deny-by-default control file
// /config/update.action (mirrors the installer's /config/install.action), and renders
// /config/update.status as JSON for the Settings "System Update" page.
//
// U1 verbs (boot-state only; no image staging yet — that arrives with the GPT v2 slot
// layout in U1-B):
//   switch     — boot the OTHER slot next (after an update was staged to it); full retry
//                budget.  If that boot never commits boot-ok, the arbiter rolls back.
//   rollback   — boot the last known-good slot next (undo a switch).
//   boot-ok    — commit the CURRENTLY-BOOTED slot as healthy (the health gate calls this;
//                also manually testable).  Resets the retry budget.
//   status     — no-op poke; the state is observed by reading /config/update.status.
//
// Every verb persists the boot-state sector (atomic single-sector write) and logs an
// [update] line so the Logs app (filter `update`) shows the whole state machine.
module core.sysupdate;

import core.io : klog, klog_hex;
import core.bootstate : BootState, bootStateRead, bootStateWrite, bootStateInit,
                        SLOT_A, SLOT_B, SLOT_NONE, DEFAULT_TRIES;
import core.sysversion : g_bootSlot, SYSTEM_VERSION, SYSTEM_VERSION_STRING, SYSTEM_CHANNEL;

@nogc nothrow:

private char slotCh(ubyte s) { return (s == SLOT_A) ? 'A' : (s == SLOT_B) ? 'B' : '?'; }
private ubyte otherSlot(ubyte s) { return (s == SLOT_A) ? SLOT_B : SLOT_A; }

// Last verb outcome, surfaced in update.status (so a GUI sees accept/reject without
// scraping the log).  Empty until the first verb.
__gshared char[64] g_updLastMsg = ['i','d','l','e','\0'];

private void setMsg(string m) {
    size_t i = 0;
    for (; i < m.length && i < g_updLastMsg.length - 1; ++i) g_updLastMsg[i] = m[i];
    g_updLastMsg[i] = '\0';
}

// At boot, adopt the arbiter's decision: the slot recorded as `trySlot` is the slot we
// actually came up from, so the running kernel reports it (sysversion.g_bootSlot) and
// the health gate commits the right slot.  Legacy/fresh disks with no boot-state stay
// on the compiled default ('A').
public void updateAdoptBootSlot() {
    BootState s;
    if (!bootStateRead(s)) {
        klog("[update] no boot-state on disk; slot defaults to A (legacy/pre-U1 install)\n");
        return;
    }
    g_bootSlot = slotCh(s.trySlot);
    klog("[update] adopted boot slot from disk: try="); { char[2] c=[slotCh(s.trySlot),'\0']; klog(c.ptr); }
    klog(" ok="); { char[2] c=[slotCh(s.bootOkSlot),'\0']; klog(c.ptr); }
    klog(" triesLeft=0x"); klog_hex(s.triesLeft); klog("\n");
}

// Health gate: commit the currently-booted slot as good.  Called once the boot proofs
// pass + the desktop is up (see kernel_main).  Idempotent.  No-op on legacy disks.
public bool updateCommitBootOk() {
    BootState s;
    if (!bootStateRead(s)) return false;                 // no A/B state (legacy) — nothing to commit
    const ubyte booted = (g_bootSlot == 'B') ? SLOT_B : SLOT_A;
    if (s.bootOkSlot == booted && s.triesLeft == DEFAULT_TRIES &&
        s.activeSlot == booted && s.trySlot == booted)
        return true;                                     // already committed (incl. no pending switch)
    s.bootOkSlot = booted;
    s.activeSlot = booted;
    s.triesLeft  = DEFAULT_TRIES;
    s.trySlot    = booted;
    if (!bootStateWrite(s)) { klog("[update] boot-ok commit FAILED (write)\n"); return false; }
    klog("[update] boot-ok: slot "); { char[2] c=[slotCh(booted),'\0']; klog(c.ptr); }
    klog(" committed healthy (triesLeft reset)\n");
    return true;
}

// Parse + execute one control verb.  Deny-by-default: unknown verbs are rejected.
// Returns true iff the verb was recognized AND applied (persisted) — false surfaces in
// the status so the GUI can show a failure.
public bool updateControlWrite(const(char)* cmd, size_t len) {
    if (cmd is null || len == 0) return false;
    // Trim trailing whitespace/newline/NUL the GUI may include.
    while (len > 0 && (cmd[len-1] == '\n' || cmd[len-1] == '\r' || cmd[len-1] == ' ' || cmd[len-1] == 0))
        --len;

    bool eq(string v) {
        if (len != v.length) return false;
        foreach (i; 0 .. v.length) if (cmd[i] != v[i]) return false;
        return true;
    }

    BootState s;
    const bool haveState = bootStateRead(s);

    if (eq("status")) { setMsg("status"); return true; }

    if (eq("switch")) {
        if (!haveState) { klog("[update] switch REJECT: no A/B boot-state (not an A/B install)\n"); setMsg("switch: no boot-state"); return false; }
        const ubyte tgt = otherSlot(s.activeSlot);
        s.trySlot   = tgt;
        s.triesLeft = DEFAULT_TRIES;
        // bootOkSlot stays at the current good slot → a failed switch auto-rolls back.
        if (!bootStateWrite(s)) { setMsg("switch: write failed"); return false; }
        klog("[update] switch: next boot -> slot "); { char[2] c=[slotCh(tgt),'\0']; klog(c.ptr); }
        klog(" (fallback slot "); { char[2] c=[slotCh(s.bootOkSlot),'\0']; klog(c.ptr); } klog(")\n");
        setMsg("switch armed"); return true;
    }

    if (eq("rollback")) {
        if (!haveState) { klog("[update] rollback REJECT: no A/B boot-state\n"); setMsg("rollback: no boot-state"); return false; }
        const ubyte good = (s.bootOkSlot == SLOT_NONE) ? s.activeSlot : s.bootOkSlot;
        s.trySlot   = good;
        s.activeSlot= good;
        s.triesLeft = DEFAULT_TRIES;
        if (!bootStateWrite(s)) { setMsg("rollback: write failed"); return false; }
        klog("[update] rollback: next boot -> known-good slot "); { char[2] c=[slotCh(good),'\0']; klog(c.ptr); } klog("\n");
        setMsg("rolled back"); return true;
    }

    if (eq("boot-ok")) {
        if (!updateCommitBootOk()) { setMsg("boot-ok: no boot-state"); return false; }
        setMsg("boot-ok committed"); return true;
    }

    // Dev/test verb: (re)initialize A/B boot-state for the running slot, so a scratch
    // install without the U1-B dual-slot installer can still exercise the machine.
    if (eq("init-state")) {
        const ubyte cur = (g_bootSlot == 'B') ? SLOT_B : SLOT_A;
        if (!bootStateInit(cur)) { setMsg("init-state: write failed"); return false; }
        klog("[update] init-state: boot-state initialized for slot "); { char[2] c=[slotCh(cur),'\0']; klog(c.ptr); } klog("\n");
        setMsg("state initialized"); return true;
    }

    klog("[update] control: unknown verb (deny-by-default)\n");
    setMsg("unknown verb");
    return false;
}

// One-shot headless proof of the WHOLE U1 verb state machine, driven through the same
// updateControlWrite() the GUI uses, with disk-backed assertions after each verb.  Gated
// (by the caller) to scratch/install-payload boots so it never mutates a real live
// boot-state; it also saves+restores LBA 34 to be doubly safe.  This is U1-A's "verify"
// short of the actual reboot (which needs the U1-C arbiter).
public void updateEngineSelfTest() {
    import drivers.block.disk : diskReady, diskReadSectorsOn, diskWriteSectorsOn, diskIsNvme, diskStoreIndex;
    import core.diskpart : SECTOR;
    import core.bootstate : BOOTSTATE_LBA;

    if (!diskReady()) { klog("[update] engine selftest SKIP (no disk)\n"); return; }
    int idx = diskIsNvme() ? 0 : (){ ulong s; return diskStoreIndex(s); }();
    if (idx < 0) { klog("[update] engine selftest SKIP (no store idx)\n"); return; }

    __gshared ubyte[SECTOR] saved;
    const bool hadSaved = diskReadSectorsOn(idx, BOOTSTATE_LBA, 1, saved.ptr);

    bool fail(string why) { klog("[update] engine selftest FAIL: "); klog(why.ptr); klog("\n"); return false; }
    bool ok = true;

    // 1) init-state for the running slot (A) → try=A ok=A active=A tries=DEFAULT
    updateControlWrite("init-state".ptr, 10);
    BootState s;
    if (!bootStateRead(s) || s.trySlot != SLOT_A || s.bootOkSlot != SLOT_A ||
        s.activeSlot != SLOT_A || s.triesLeft != DEFAULT_TRIES) ok = fail("init-state");

    // 2) switch → try=B, bootOk stays A (fallback), tries reset
    if (ok) { updateControlWrite("switch".ptr, 6);
        if (!bootStateRead(s) || s.trySlot != SLOT_B || s.bootOkSlot != SLOT_A ||
            s.triesLeft != DEFAULT_TRIES) ok = fail("switch"); }

    // 3) rollback → try=A, active=A (undo the switch)
    if (ok) { updateControlWrite("rollback".ptr, 8);
        if (!bootStateRead(s) || s.trySlot != SLOT_A || s.activeSlot != SLOT_A) ok = fail("rollback"); }

    // 4) switch again then boot-ok (simulating a healthy boot INTO the running slot A):
    //    boot-ok commits the CURRENTLY-BOOTED slot (g_bootSlot='A' in this test) → try=A ok=A.
    if (ok) { updateControlWrite("switch".ptr, 6);
        updateControlWrite("boot-ok".ptr, 7);
        if (!bootStateRead(s) || s.bootOkSlot != SLOT_A || s.activeSlot != SLOT_A ||
            s.trySlot != SLOT_A || s.triesLeft != DEFAULT_TRIES) ok = fail("boot-ok commit"); }

    // 5) deny-by-default: an unknown verb must be rejected and NOT change state.
    if (ok) { const uint seqBefore = s.seq;
        if (updateControlWrite("frobnicate".ptr, 10)) ok = fail("unknown verb accepted");
        else if (!bootStateRead(s) || s.seq != seqBefore) ok = fail("unknown verb mutated state"); }

    if (hadSaved) diskWriteSectorsOn(idx, BOOTSTATE_LBA, 1, saved.ptr);   // restore
    setMsg("idle");                                                       // reset status line

    if (ok) klog("[update] engine selftest PASS (init/switch/rollback/boot-ok/deny-by-default)\n");
}

// Render /config/update.status as JSON into buf; returns bytes written.
public long updateStatusRender(char* buf, size_t buflen) {
    if (buf is null || buflen == 0) return 0;
    size_t n = 0;
    void s(string t) { foreach (i; 0 .. t.length) { if (n < buflen-1) buf[n++] = t[i]; } }
    void ch(char c) { if (n < buflen-1) buf[n++] = c; }
    void dec(uint v) { char[10] r; int rn=0; if (v==0){ch('0');return;} while(v>0){r[rn++]=cast(char)('0'+v%10);v/=10;} while(rn>0) ch(r[--rn]); }

    BootState st;
    const bool have = bootStateRead(st);

    s("{\n  \"version\": "); dec(SYSTEM_VERSION);
    s(",\n  \"versionString\": \""); s(SYSTEM_VERSION_STRING); ch('"');
    s(",\n  \"channel\": \""); s(SYSTEM_CHANNEL); ch('"');
    s(",\n  \"bootSlot\": \""); ch(g_bootSlot); ch('"');
    s(",\n  \"abState\": ");
    if (!have) {
        s("null");
    } else {
        s("{ \"trySlot\": \""); ch(slotCh(st.trySlot));
        s("\", \"bootOkSlot\": \""); ch(slotCh(st.bootOkSlot));
        s("\", \"activeSlot\": \""); ch(slotCh(st.activeSlot));
        s("\", \"triesLeft\": "); dec(st.triesLeft);
        s(", \"seq\": "); dec(st.seq); s(" }");
    }
    s(",\n  \"lastMessage\": \""); { size_t i=0; while (g_updLastMsg[i] != '\0' && i < g_updLastMsg.length) { ch(g_updLastMsg[i]); ++i; } } ch('"');
    s("\n}\n");
    return cast(long)n;
}
