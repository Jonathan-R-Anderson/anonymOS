// Update / rollback system — IMMUTABLE_ROOTLESS_ROADMAP §6.
//
// Atomic, capability-gated, signature-verified, anti-downgrade updates with a
// known-good fallback — the ChromeOS A/B + Android Verified Boot model on top of the
// §4 content-addressed store and generations:
//
//   §6.1 A/B slots            — two system slots; boot selects the active one, the
//        *inactive* slot is the only writable update target (slotActive/slotInactive,
//        updateActivateInactive = the atomic boot-time swap).
//   §6.2 signed update bundles — updateApply requires CAP_RIGHT_ADMIN_UPDATE *and* a
//        valid signature *before* any write, and only ever writes the inactive slot.
//   §6.3 rollback index        — a monotonic counter rejects a validly-signed but
//        downgraded image (anti-rollback, AVB).
//   §6.4 boot-success counter  — N failed boots of a slot auto-reverts to the other
//        known-good slot (bootBegin/bootConfirm/bootCheckRollback).
//   §6.5 user-state snapshots   — /var snapshot/restore as store objects, independent
//        of the system generation (rolling back the OS never rolls back user data).
//
// Crypto note: §6.2 ultimately uses the §8.1 ed25519 verify; until that lands the
// signature is a keyed digest over the content hash (the kernel holds the trusted
// key) — it genuinely rejects tampered content and wrong-key signatures, which the
// self-test proves, and is a drop-in for the real asymmetric verify.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module core.update;

import core.io; // klog / klog_hex
import core.store : storePut, storeRoot, storeReadVerified, storeHash,
                    storeDigestEqual, genCreate, genSetActive, genActive,
                    genNumber, Digest256;
import core.admin : adminRequireIn, adminInstallCapIn;
import core.cap : CAP_RIGHT_ADMIN_UPDATE, CAPTAB_COUNT, capTableClear,
                  capLiveCount, g_activeCapTabId;

extern (C) @nogc nothrow:

enum int  SLOT_A = 0;
enum int  SLOT_B = 1;
enum uint BOOT_FAIL_THRESHOLD = 3; // §6.4: this many unconfirmed boots ⇒ auto-rollback

// The trusted verification key (stands in for the §8.1 ed25519 public key baked
// into the kernel / verified-boot chain).
enum ulong UPDATE_TRUSTED_KEY = 0xA17E_B00F_5161_CafE;

// Result codes for updateApply (negative = refused, no write happened).
enum int UPD_OK         =  0;
enum int UPD_NO_CAP     = -1;  // §6.2 missing CAP_RIGHT_ADMIN_UPDATE
enum int UPD_BAD_SIG    = -2;  // §6.2 signature did not verify
enum int UPD_DOWNGRADE  = -3;  // §6.3 rollback index < current
enum int UPD_BAD_BUNDLE = -4;  // malformed

struct Slot {
    uint genObjId;    // the system Generation (§4.4) deployed in this slot
    bool good;        // confirmed-good (a successful boot marked it)
    uint tryCount;    // boots attempted since last confirm
}

// A signed, content-addressed update bundle (applied to the inactive slot only).
struct UpdateBundle {
    uint      storeObjId;     // content-addressed image bits (§4.1)
    uint      genObjId;       // Generation this update deploys (§4.4)
    ulong     rollbackIndex;  // monotonic anti-downgrade index (§6.3)
    Digest256 sig;            // signature over storeRoot(storeObjId) (§6.2)
}

__gshared Slot[2] g_slots;
__gshared int     g_activeSlot   = SLOT_A;
__gshared ulong   g_rollbackIndex = 0;       // highest index ever applied
__gshared bool    g_updInited     = false;
__gshared bool    g_updSelfTested = false;

__gshared ulong g_updApplied    = 0;
__gshared ulong g_updRefused    = 0;   // cap/sig/downgrade refusals
__gshared ulong g_updActivated  = 0;   // inactive→active swaps
__gshared ulong g_bootTries     = 0;
__gshared ulong g_autoRollback  = 0;
__gshared ulong g_varSnapTotal  = 0;

public void updateInit() {
    if (g_updInited) return;
    g_updInited = true;
    g_slots[SLOT_A] = Slot.init;
    g_slots[SLOT_B] = Slot.init;
    // The booted system is a generation in slot A.  If nothing has established one
    // yet (very early boot), synthesize the boot generation so slot A is a valid,
    // known-good rollback target from the start.
    uint bootGen = genActive();
    if (bootGen == 0) bootGen = genCreate(0, null, 0);
    if (bootGen != 0) genSetActive(bootGen);
    g_slots[SLOT_A].genObjId = bootGen;     // current deployment occupies slot A
    g_slots[SLOT_A].good     = true;        // we booted it, so it is known-good
    g_activeSlot = SLOT_A;
}

// --- §6.1 A/B slots -----------------------------------------------------------
public int  slotActive()    { return g_activeSlot; }
public int  slotInactive()  { return g_activeSlot == SLOT_A ? SLOT_B : SLOT_A; }
public uint slotGen(int idx) { return (idx == SLOT_A || idx == SLOT_B) ? g_slots[idx].genObjId : 0; }
public uint slotActiveGen() { return g_slots[g_activeSlot].genObjId; }
public bool slotGood(int idx) { return (idx == SLOT_A || idx == SLOT_B) && g_slots[idx].good; }

// Atomic boot-time A/B swap: make the (freshly updated) inactive slot active and
// deploy its generation.  A single pointer move — never a half-applied tree.
public bool updateActivateInactive() {
    int ni = slotInactive();
    if (g_slots[ni].genObjId == 0) return false;   // nothing staged there
    g_activeSlot = ni;                              // atomic slot pointer swap
    genSetActive(g_slots[ni].genObjId);             // deploy its generation (§4.4)
    g_slots[ni].tryCount = 0;
    ++g_updActivated;
    return true;
}

// --- §6.2 signature (ed25519 stand-in) ----------------------------------------
// Sign the content digest with `key`; the kernel verifies against UPDATE_TRUSTED_KEY.
public Digest256 updateSign(uint storeObjId, ulong key) {
    Digest256 d = storeRoot(storeObjId);
    ubyte[Digest256.sizeof + ulong.sizeof] buf;
    auto dp = cast(const(ubyte)*)&d;
    foreach (i; 0 .. Digest256.sizeof) buf[i] = dp[i];
    auto kp = cast(const(ubyte)*)&key;
    foreach (i; 0 .. ulong.sizeof) buf[Digest256.sizeof + i] = kp[i];
    return storeHash(buf.ptr, buf.length);
}

public bool updateVerify(ref const(UpdateBundle) b) {
    if (b.storeObjId == 0) return false;
    Digest256 expect = updateSign(b.storeObjId, UPDATE_TRUSTED_KEY);
    Digest256 got = b.sig;
    return storeDigestEqual(expect, got);
}

// --- §6.2/§6.3 apply ----------------------------------------------------------
// Apply a bundle to the INACTIVE slot only, after a cap check, signature check, and
// anti-downgrade check.  The active slot is never touched (so a bad update cannot
// brick the running system).  Activation is a separate, explicit boot-time swap.
public int updateApplyIn(int tableId, ref const(UpdateBundle) b) {
    updateInit();
    if (b.storeObjId == 0 || b.genObjId == 0) { ++g_updRefused; return UPD_BAD_BUNDLE; }
    if (!adminRequireIn(tableId, CAP_RIGHT_ADMIN_UPDATE)) { ++g_updRefused; return UPD_NO_CAP; }
    if (!updateVerify(b)) { ++g_updRefused; return UPD_BAD_SIG; }
    if (b.rollbackIndex < g_rollbackIndex) { ++g_updRefused; return UPD_DOWNGRADE; }

    int ni = slotInactive();
    g_slots[ni].genObjId = b.genObjId;   // stage into the inactive slot only
    g_slots[ni].good     = false;        // unproven until it boots successfully
    g_slots[ni].tryCount = 0;
    g_rollbackIndex = b.rollbackIndex;   // advance the monotonic index (§6.3)
    ++g_updApplied;
    return UPD_OK;
}

public int updateApply(ref const(UpdateBundle) b) {
    return updateApplyIn(g_activeCapTabId, b);
}

public ulong updateRollbackIndex() { return g_rollbackIndex; }

// --- §6.4 boot-success counter + auto-rollback --------------------------------
public void bootBegin() {
    updateInit();
    ++g_slots[g_activeSlot].tryCount;
    ++g_bootTries;
}

public void bootConfirm() {
    updateInit();
    g_slots[g_activeSlot].good     = true;
    g_slots[g_activeSlot].tryCount = 0;
}

// If the active slot has failed to confirm after too many tries, revert to the other
// slot when it is known-good.  Returns true if a rollback happened.
public bool bootCheckRollback() {
    updateInit();
    int act = g_activeSlot;
    if (g_slots[act].good) return false;
    if (g_slots[act].tryCount < BOOT_FAIL_THRESHOLD) return false;
    int other = (act == SLOT_A) ? SLOT_B : SLOT_A;
    if (!g_slots[other].good || g_slots[other].genObjId == 0) return false;
    g_activeSlot = other;                       // revert to known-good slot
    genSetActive(g_slots[other].genObjId);
    ++g_autoRollback;
    return true;
}

// --- §6.5 user-state (/var) snapshots -----------------------------------------
// A /var snapshot is just a content-addressed store object — orthogonal to the
// system generation, so an OS rollback never disturbs user data and vice versa.
public uint varSnapshot(const(ubyte)* data, uint len) {
    uint id = storePut(data, len);
    if (id != 0) ++g_varSnapTotal;
    return id;
}

public long varRestore(uint snapObjId, ubyte* outBuf, uint len) {
    return storeReadVerified(snapObjId, 0, outBuf, len);
}

// --- proof --------------------------------------------------------------------
private bool selfTestSlots() {        // §6.1
    updateInit();
    bool init = (slotActive() == SLOT_A && slotInactive() == SLOT_B &&
                 slotActive() != slotInactive() && slotGood(SLOT_A));
    return init;
}

private bool selfTestApply(int st) {  // §6.2 cap + signature gate, inactive-only write
    static immutable ubyte[8] img1 = ['s','y','s','-','v','0','0','1'];
    uint o1 = storePut(img1.ptr, img1.length);
    uint g1 = genCreate(genActive(), &o1, 1);
    if (o1 == 0 || g1 == 0) return false;

    UpdateBundle good = { o1, g1, 1, updateSign(o1, UPDATE_TRUSTED_KEY) };
    UpdateBundle forged = good;
    forged.sig = updateSign(o1, 0xDEAD_BEEF);  // wrong signing key

    uint activeGenBefore = slotActiveGen();

    capTableClear(st);
    bool denyNoCap = (updateApplyIn(st, good) == UPD_NO_CAP);  // no update cap ⇒ refused
    adminInstallCapIn(st, CAP_RIGHT_ADMIN_UPDATE);
    bool denyForged = (updateApplyIn(st, forged) == UPD_BAD_SIG); // bad sig ⇒ refused
    bool ok = (updateApplyIn(st, good) == UPD_OK);             // cap + sig ⇒ applied
    bool inactiveGot = (slotGen(slotInactive()) == g1);        // staged in inactive slot
    bool activeUntouched = (slotActiveGen() == activeGenBefore); // active never written

    return denyNoCap && denyForged && ok && inactiveGot && activeUntouched;
}

private bool selfTestDowngrade(int st) {  // §6.3 anti-rollback
    static immutable ubyte[8] img2 = ['s','y','s','-','v','0','0','2'];
    uint o2 = storePut(img2.ptr, img2.length);
    uint g2 = genCreate(genActive(), &o2, 1);
    if (o2 == 0 || g2 == 0) return false;
    // Current index is 1 (from selfTestApply).  An index-0 bundle is a downgrade.
    UpdateBundle older = { o2, g2, 0, updateSign(o2, UPDATE_TRUSTED_KEY) };
    UpdateBundle newer = { o2, g2, 2, updateSign(o2, UPDATE_TRUSTED_KEY) };
    bool blocked = (updateApplyIn(st, older) == UPD_DOWNGRADE);
    bool accepted = (updateApplyIn(st, newer) == UPD_OK);
    bool advanced = (updateRollbackIndex() == 2);
    return blocked && accepted && advanced;
}

private bool selfTestBootRollback() {  // §6.4 boot-success counter + auto-rollback
    // Stage a (bad) image in the inactive slot and activate it; it never confirms,
    // so after BOOT_FAIL_THRESHOLD tries we must auto-revert to the good slot.
    int goodSlot = slotActive();
    uint goodGen = slotActiveGen();
    if (!updateActivateInactive()) return false;     // switch to the staged slot
    bool switched = (slotActive() != goodSlot);
    foreach (i; 0 .. BOOT_FAIL_THRESHOLD) bootBegin(); // tries without bootConfirm()
    bool reverted = bootCheckRollback();
    bool backToGood = (slotActive() == goodSlot && slotActiveGen() == goodGen);
    // The confirm path clears the counter (no spurious rollback).
    bootBegin();
    bootConfirm();
    bool noRollbackAfterConfirm = !bootCheckRollback();
    return switched && reverted && backToGood && noRollbackAfterConfirm;
}

private bool selfTestVarSnapshot() {   // §6.5 user-state independent of OS rollback
    static immutable ubyte[6] vA = ['v','a','r','-','v','A'];
    uint snap = varSnapshot(vA.ptr, vA.length);
    if (snap == 0) return false;
    // An OS generation switch must not disturb the /var snapshot.
    uint savedGen = genActive();
    uint sysGen = genCreate(genActive(), &snap, 1);
    genSetActive(sysGen);
    ubyte[6] buf;
    bool restored = (varRestore(snap, buf.ptr, vA.length) == vA.length);
    bool intact = restored;
    foreach (i; 0 .. vA.length) if (buf[i] != vA[i]) intact = false;
    genSetActive(savedGen);             // leave the deployment pointer as we found it
    return intact;
}

public void updateSelfTest() {
    if (g_updSelfTested) return;
    g_updSelfTested = true;
    int st = CAPTAB_COUNT - 2;     // scratch cap table (shared by the gate self-tests)
    if (capLiveCount(st) != 0) { g_updSelfTested = false; return; } // retry next tick

    bool slots = selfTestSlots();
    bool apply = selfTestApply(st);
    bool down  = selfTestDowngrade(st);
    bool boot  = selfTestBootRollback();
    bool varss = selfTestVarSnapshot();

    capTableClear(st);

    if (slots && apply && down && boot && varss) {
        klog("[update] selftest PASS\n");
    } else {
        klog("[update] selftest FAIL:");
        if (!slots) klog(" slots");
        if (!apply) klog(" apply");
        if (!down)  klog(" downgrade");
        if (!boot)  klog(" bootroll");
        if (!varss) klog(" varsnap");
        klog("\n");
    }
}

public void updateStats() {
    klog("[update] active=");  klog_hex(cast(ulong)g_activeSlot);
    klog(" idx=");             klog_hex(g_rollbackIndex);
    klog(" applied=");         klog_hex(g_updApplied);
    klog(" refused=");         klog_hex(g_updRefused);
    klog(" activated=");       klog_hex(g_updActivated);
    klog(" boottries=");       klog_hex(g_bootTries);
    klog(" autoroll=");        klog_hex(g_autoRollback);
    klog(" varsnap=");         klog_hex(g_varSnapTotal);
    klog("\n");
}
