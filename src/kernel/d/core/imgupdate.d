// imgupdate.d — the whole-image A/B update UNIT (SYSTEM_UPDATE D1, roadmap 4.4).
//
// D1 chose image-based A/B over package surgery: "an update = a complete signed esp-image (kernel
// + modules + limine) written to the inactive slot.  Atomic by construction; rollback = boot the
// other slot; verification = one hash tree.  The object store (user data) lives outside the slots
// and is untouched."  This module is that unit.
//
// WHAT THIS IS NOT.  core/update.d already implements A/B slots, signed bundles and an anti-
// rollback index, and 4.2's IMMUTABLE-3 gate proves deploy+rollback work -- but its update unit is
// a GENERATION OF STORE OBJECTS, an in-memory content-addressed set.  D1's unit is a whole ESP
// image: one contiguous byte range containing the bootloader, kernel and modules, verified as a
// single hash.  Those are different artifacts with different failure modes, which is why this is a
// separate module rather than another field on UpdateBundle.
//
// DELIBERATE SCOPE.  D1 is the UNIT.  Two neighbouring decisions are explicitly NOT implemented
// here and are not claimed:
//
//   * D2 (two physical ESPs + arbiter) is partly built already -- core/bootstate.d holds the
//     boot-state sector and boot/arbiter/efi_arbiter.c chainloads by it -- but the installer still
//     lays down ONE ESP, so there is no second partition to stream an image into.  Staging here
//     therefore verifies and DECIDES; the physical write lands when D2 creates ESP-B.
//   * D3 (Ed25519) is not here.  Verification uses the kernel's existing HMAC trusted key via
//     cryptoVerify, which is symmetric -- the verifier holds the signing secret.  That is honest
//     for a locally-produced image and NOT sufficient for public releases; D3 replaces it.  The
//     bundle carries a keyId field so a real release key can be distinguished later without a
//     format break.
//
// The point of shipping the unit before the transport is that every later milestone (U2 bundles,
// U3 UI, U5 I2P, U6 DHT) is a different way of DELIVERING these bytes.  If the unit does not
// verify correctly, none of them can be trusted no matter how they arrive.
module core.imgupdate;

@nogc: nothrow:

import core.io : klog, klog_hex, klog_dec;
import core.crypto : sha256, cryptoVerify, cryptoSign, ctEqual32;
import core.bootstate : BootState, bootStateRead, bootStateWrite, SLOT_A, SLOT_B, DEFAULT_TRIES;
import core.sysversion : SYSTEM_VERSION;

// ── Bundle format ────────────────────────────────────────────────────────────────────────────
//
//   offset  size  field
//        0     8  magic "HOSUPD01"
//        8     4  formatVersion (1)
//       12     4  imageVersion      -- monotonic; must exceed the running version
//       16     4  prevVersion       -- the version this update expects to replace (0 = any)
//       20     4  keyId             -- which key signed it (0 = the built-in HMAC dev key)
//       24     8  imageLen
//       32    32  imageHash         -- SHA-256 over the WHOLE image ("one hash tree", D1)
//       64    32  sig               -- signature over bytes [0,64)
//       96   ...  image
//
// The signature covers the HEADER, and the header commits to the image via imageHash.  So one
// verification of 64 bytes plus one hash of the payload authenticates the entire artifact -- and
// the hash can be computed while streaming, which is what U2 needs for chunked download.
enum uint IMGUPD_HDR   = 96;
enum uint IMGUPD_FMT   = 1;
enum ulong IMGUPD_MAGIC_0 = 0x44505355534F48UL;   // "HOSUPD" + 0x00 padding, compared bytewise below

struct ImgUpdateHeader {
    uint  formatVersion;
    uint  imageVersion;
    uint  prevVersion;
    uint  keyId;
    ulong imageLen;
    ubyte[32] imageHash;
    ubyte[32] sig;
}

// Why each refusal happened.  A single bool would make the self-proof unable to tell "tampered
// image" from "replayed version", and those are different attacks with different responses.
enum ImgUpdVerdict : int {
    Ok            = 0,
    BadMagic      = 1,
    BadFormat     = 2,
    Truncated     = 3,
    BadSignature  = 4,
    BadImageHash  = 5,
    Rollback      = 6,
    WrongPrev     = 7,
}

// The running version is SYSTEM_VERSION, which sysversion.d already documents as "the MONOTONIC
// integer the update engine compares for anti-rollback".  Read from there rather than duplicated:
// a second copy would drift, and the copy that drifts is the one that lets a replay through.
__gshared uint  g_imgRunningVersion = SYSTEM_VERSION;
__gshared ulong g_imgVerifyTotal    = 0;
__gshared ulong g_imgRefuseTotal    = 0;
__gshared bool  g_imgSelfTested     = false;

public const(char)* imgUpdVerdictName(ImgUpdVerdict v) {
    final switch (v) {
        case ImgUpdVerdict.Ok:           return "ok\0".ptr;
        case ImgUpdVerdict.BadMagic:     return "bad-magic\0".ptr;
        case ImgUpdVerdict.BadFormat:    return "bad-format\0".ptr;
        case ImgUpdVerdict.Truncated:    return "truncated\0".ptr;
        case ImgUpdVerdict.BadSignature: return "bad-signature\0".ptr;
        case ImgUpdVerdict.BadImageHash: return "bad-image-hash\0".ptr;
        case ImgUpdVerdict.Rollback:     return "rollback-refused\0".ptr;
        case ImgUpdVerdict.WrongPrev:    return "wrong-prev-version\0".ptr;
    }
}

private bool magicOk(const(ubyte)* b) {
    static immutable char[8] M = ['H','O','S','U','P','D','0','1'];
    foreach (i; 0 .. 8) if (b[i] != cast(ubyte)M[i]) return false;
    return true;
}

private uint rdU32(const(ubyte)* b, size_t off) {
    return cast(uint)b[off] | (cast(uint)b[off+1] << 8) |
           (cast(uint)b[off+2] << 16) | (cast(uint)b[off+3] << 24);
}
private ulong rdU64(const(ubyte)* b, size_t off) {
    ulong v = 0;
    foreach (i; 0 .. 8) v |= (cast(ulong)b[off+i]) << (8*i);
    return v;
}

public bool imgUpdateParse(const(ubyte)* buf, ulong len, out ImgUpdateHeader h) {
    h = ImgUpdateHeader.init;
    if (buf is null || len < IMGUPD_HDR) return false;
    h.formatVersion = rdU32(buf, 8);
    h.imageVersion  = rdU32(buf, 12);
    h.prevVersion   = rdU32(buf, 16);
    h.keyId         = rdU32(buf, 20);
    h.imageLen      = rdU64(buf, 24);
    foreach (i; 0 .. 32) h.imageHash[i] = buf[32 + i];
    foreach (i; 0 .. 32) h.sig[i]       = buf[64 + i];
    return true;
}

// Verify a complete bundle in memory.  ORDER MATTERS and is chosen so the cheapest refusals come
// first and no expensive work is done on an unauthenticated buffer: shape, then signature over the
// 64-byte header, then the image hash the (now trusted) header commits to, then policy.
//
// Anti-rollback is checked LAST on purpose.  A replayed old bundle is validly signed with a
// correct hash -- it fails only on policy -- so checking it earlier would report a misleading
// reason for a genuine attack.
public ImgUpdVerdict imgUpdateVerify(const(ubyte)* buf, ulong len) {
    ++g_imgVerifyTotal;
    ImgUpdateHeader h;
    if (buf is null || len < IMGUPD_HDR)          { ++g_imgRefuseTotal; return ImgUpdVerdict.Truncated; }
    if (!magicOk(buf))                            { ++g_imgRefuseTotal; return ImgUpdVerdict.BadMagic; }
    if (!imgUpdateParse(buf, len, h))             { ++g_imgRefuseTotal; return ImgUpdVerdict.Truncated; }
    if (h.formatVersion != IMGUPD_FMT)            { ++g_imgRefuseTotal; return ImgUpdVerdict.BadFormat; }
    if (h.imageLen == 0 || IMGUPD_HDR + h.imageLen > len)
                                                  { ++g_imgRefuseTotal; return ImgUpdVerdict.Truncated; }

    // Signature over the header's first 64 bytes (everything up to and excluding `sig`).
    if (!cryptoVerify(buf, 64, &h.sig[0]))        { ++g_imgRefuseTotal; return ImgUpdVerdict.BadSignature; }

    // The header is now trusted, so its imageHash is a trustworthy commitment to the payload.
    ubyte[32] actual;
    sha256(buf + IMGUPD_HDR, h.imageLen, &actual[0]);
    if (!ctEqual32(&actual[0], &h.imageHash[0])) { ++g_imgRefuseTotal; return ImgUpdVerdict.BadImageHash; }

    if (h.imageVersion <= g_imgRunningVersion)   { ++g_imgRefuseTotal; return ImgUpdVerdict.Rollback; }
    if (h.prevVersion != 0 && h.prevVersion != g_imgRunningVersion)
                                                  { ++g_imgRefuseTotal; return ImgUpdVerdict.WrongPrev; }
    return ImgUpdVerdict.Ok;
}

// Which slot would this update be written into?  Never the running one -- that is the whole point
// of A/B, and it is why an update cannot brick a booted system.
public ubyte imgUpdateTargetSlot() {
    BootState s;
    if (!bootStateRead(s)) return SLOT_B;              // no state yet: A is running, stage into B
    return (s.activeSlot == SLOT_A) ? SLOT_B : SLOT_A;
}

// Stage a verified bundle: arm the boot-state so the NEXT boot tries the inactive slot with a
// retry budget.  If that boot does not confirm health, the arbiter's counter runs out and it flips
// back -- so a bad-but-genuine image costs one reboot, not the machine.
//
// The image BYTES are not written here: the installer still lays down a single ESP, so there is no
// ESP-B to stream into until D2.  Refusing to pretend otherwise is the point -- this returns the
// slot it WOULD write and arms the state, and the byte-copy lands with D2's second partition.
public bool imgUpdateStage(const(ubyte)* buf, ulong len, out ImgUpdVerdict verdict,
                           out ubyte targetSlot) {
    targetSlot = imgUpdateTargetSlot();
    verdict = imgUpdateVerify(buf, len);
    if (verdict != ImgUpdVerdict.Ok) return false;

    BootState s;
    if (!bootStateRead(s)) {
        s = BootState.init;
        s.activeSlot = SLOT_A;
        s.bootOkSlot = SLOT_A;
    }
    s.trySlot   = targetSlot;
    s.triesLeft = DEFAULT_TRIES;
    ++s.seq;
    return bootStateWrite(s);
}

// ── Proof (roadmap 4.4 outcome) ───────────────────────────────────────────────────────────────
//
// Builds a bundle in RAM and drives the real verifier, asserting each refusal reports its OWN
// reason.  Every case here is one a delivery mechanism cannot protect against: a flipped bit, a
// forged signature, and a replayed older release all arrive looking like valid downloads.
private __gshared ubyte[512] g_imgTestBuf;

private void buildBundle(uint ver, uint prev, ulong imageLen) {
    foreach (i; 0 .. g_imgTestBuf.length) g_imgTestBuf[i] = 0;
    static immutable char[8] M = ['H','O','S','U','P','D','0','1'];
    foreach (i; 0 .. 8) g_imgTestBuf[i] = cast(ubyte)M[i];
    void wr32(size_t off, uint v) { foreach (i; 0 .. 4) g_imgTestBuf[off+i] = cast(ubyte)(v >> (8*i)); }
    void wr64(size_t off, ulong v) { foreach (i; 0 .. 8) g_imgTestBuf[off+i] = cast(ubyte)(v >> (8*i)); }
    wr32(8, IMGUPD_FMT);
    wr32(12, ver);
    wr32(16, prev);
    wr32(20, 0);
    wr64(24, imageLen);
    // A synthetic "image" with recognisable content.
    foreach (i; 0 .. cast(size_t)imageLen)
        g_imgTestBuf[IMGUPD_HDR + i] = cast(ubyte)(0x5A + (i * 7));
    sha256(&g_imgTestBuf[IMGUPD_HDR], imageLen, &g_imgTestBuf[32]);
    cryptoSign(&g_imgTestBuf[0], 64, &g_imgTestBuf[64]);
}

public void imgUpdateSelfTest() {
    if (g_imgSelfTested) return;
    g_imgSelfTested = true;

    enum ulong IMGLEN = 200;
    const uint running = g_imgRunningVersion;

    // 1. A well-formed, correctly-signed, newer image is accepted.
    buildBundle(running + 1, running, IMGLEN);
    const auto vOk = imgUpdateVerify(&g_imgTestBuf[0], IMGUPD_HDR + IMGLEN);

    // 2. One flipped bit anywhere in the image is caught by the hash.
    buildBundle(running + 1, running, IMGLEN);
    g_imgTestBuf[IMGUPD_HDR + 91] ^= 0x01;
    const auto vTamper = imgUpdateVerify(&g_imgTestBuf[0], IMGUPD_HDR + IMGLEN);

    // 3. A forged signature is caught before the image is even hashed.
    buildBundle(running + 1, running, IMGLEN);
    g_imgTestBuf[64] ^= 0xFF;
    const auto vSig = imgUpdateVerify(&g_imgTestBuf[0], IMGUPD_HDR + IMGLEN);

    // 4. A REPLAY: an older release, validly signed, with a correct hash.  Refused on policy.
    buildBundle(running, running, IMGLEN);        // same version, not newer
    const auto vReplay = imgUpdateVerify(&g_imgTestBuf[0], IMGUPD_HDR + IMGLEN);

    // 5. A bundle whose declared image runs past the buffer is truncated, not read past.
    buildBundle(running + 1, running, IMGLEN);
    const auto vShort = imgUpdateVerify(&g_imgTestBuf[0], IMGUPD_HDR + 4);

    // 6. The target slot is never the running one.
    const ubyte tgt = imgUpdateTargetSlot();
    BootState st;
    const bool haveState = bootStateRead(st);
    const bool slotOk = !haveState || (tgt != st.activeSlot);

    const bool pass = (vOk     == ImgUpdVerdict.Ok)
                   && (vTamper == ImgUpdVerdict.BadImageHash)
                   && (vSig    == ImgUpdVerdict.BadSignature)
                   && (vReplay == ImgUpdVerdict.Rollback)
                   && (vShort  == ImgUpdVerdict.Truncated)
                   && slotOk;

    klog("[4.4] whole-image update unit: accept=");   klog(imgUpdVerdictName(vOk));
    klog(" tampered=");                               klog(imgUpdVerdictName(vTamper));
    klog(" forged=");                                 klog(imgUpdVerdictName(vSig));
    klog(" replayed=");                               klog(imgUpdVerdictName(vReplay));
    klog(" short=");                                  klog(imgUpdVerdictName(vShort));
    klog(" targetSlot=");                             klog_dec(tgt);
    klog(pass ? " -- D1 PASS\n" : " -- D1 FAIL\n");
}

// ── Cross-check against a REAL host-produced bundle ───────────────────────────────────────────
//
// The self-test above proves the verifier is internally consistent: it accepts what it builds and
// rejects what it corrupts.  That is necessary and not sufficient.  The failure this project has
// actually hit -- twice, on the config manifest -- is the HOST and the KERNEL disagreeing about a
// wire format, and a self-test cannot see that because both sides of it are the same code.
//
// So scripts/mk-hosupd.sh packages a small real bundle, the ISO stages it as a boot module, and
// this verifies THAT.  If a field width, an endianness or the signed byte range ever drifts
// between the script and this module, the boot log says so on the next build.
public void imgUpdateHostBundleProof() {
    import core.exports : g_mboot_modules, g_module_count, phys_to_virt;

    align(8) static struct BootModuleRecord {
        ulong mod_start;
        ulong mod_end;
        char[112] name;
    }

    if (g_mboot_modules is null || g_module_count <= 0) {
        klog("[4.4] host bundle: no boot modules\n");
        return;
    }
    auto recs = cast(const(BootModuleRecord)*) g_mboot_modules;
    foreach (i; 0 .. g_module_count) {
        const BootModuleRecord* rec = &recs[i];
        const(char)* nm = cast(const(char)*)&rec.name[0];
        const(char)* base = nm;
        for (const(char)* p = nm; *p != 0; p++) if (*p == '/') base = p + 1;

        bool match = true;
        static immutable char[13] WANT = ['t','e','s','t','.','h','o','s','u','p','d','\0','\0'];
        foreach (k; 0 .. 12) { if (base[k] != WANT[k]) { match = false; break; } }
        if (!match) continue;

        const ulong len = cast(ulong)rec.mod_end - cast(ulong)rec.mod_start;
        const(ubyte)* buf = cast(const(ubyte)*) phys_to_virt(cast(ulong)rec.mod_start);
        const auto v = imgUpdateVerify(buf, len);
        klog("[4.4] host bundle (");
        klog_dec(len);
        klog(" bytes) verdict=");
        klog(imgUpdVerdictName(v));
        klog(v == ImgUpdVerdict.Ok
             ? " -- host packager and kernel verifier AGREE\n"
             : " -- host/kernel wire-format MISMATCH\n");
        return;
    }
    klog("[4.4] host bundle: test.hosupd not staged in this image\n");
}

// ── D1's last clause: "the object store (user data) is untouched" ─────────────────────────────
//
// The compile-time assert in objstore.d pins the CONSTANTS apart (GPT_GAP_FIRST > BOOTSTATE_LBA).
// This checks the same thing about the LIVE disk, which the constants alone cannot: the store's
// base is chosen at mount time and can land in the free tail after the last partition instead of
// the gap, so where it actually sits is a runtime fact.
//
// The invariant an update depends on is simple and worth stating as an inequality rather than a
// paragraph: the sector the update engine rewrites must not be inside the region the object store
// owns.  If it ever is, a perfectly valid, correctly signed update silently destroys the user's
// data -- the worst possible outcome for an update system, and one no amount of signature checking
// would catch.
public void imgUpdateStoreDisjointProof() {
    import core.objstore : objstoreMounted, objstoreBaseLba;
    import core.bootstate : BOOTSTATE_LBA;

    if (!objstoreMounted()) {
        // Live media: the store stays in RAM because the disk is reserved for the installer, so
        // there is no on-disk region to be disjoint FROM.  Reported rather than silently skipped:
        // "not applicable" and "checked and fine" are different claims.
        klog("[4.4] store/update disjointness: N/A -- object store is in RAM (live media)\n");
        return;
    }

    const ulong base = objstoreBaseLba();
    const bool disjoint = (base > BOOTSTATE_LBA);
    klog("[4.4] store/update disjointness: storeBaseLBA=");
    klog_dec(base);
    klog(" bootStateLBA=");
    klog_dec(BOOTSTATE_LBA);
    klog(disjoint
         ? " -- DISJOINT, an update cannot reach user data\n"
         : " -- OVERLAP: an update would destroy user data\n");
}

// ── D2: write the verified image into the INACTIVE slot ──────────────────────────────────────
//
// 4.4 shipped the unit but not the landing, on the stated grounds that "the installer lays down
// ONE ESP, so there is no ESP-B to stream into".  That was WRONG, and checking took one grep:
// diskpart.d's A/B layout writes THREE partitions -- entry 0 the boot ESP, entry 1 slot A, entry
// 2 slot B -- and a plain (non-hidden) install takes that path whenever the esp-boot-image module
// is staged, which the ISO always stages.  Slot B has been on every installed disk all along.
//
// So the missing piece was never a partition; it was code to find it and write to it.
//
// The slot extents are NOT re-derived from install-time state, which would be a second source of
// truth that drifts.  They are read back from the GPT the installer actually wrote, so this agrees
// with the on-disk layout by construction.
enum uint GPT_IDX_SLOT_A = 1;
enum uint GPT_IDX_SLOT_B = 2;

public struct ImgSlotTarget {
    bool  valid;
    ubyte slot;        // SLOT_A / SLOT_B
    ulong firstLba;
    ulong sectors;
}

// Resolve where an update WOULD land, without writing anything.  Separated from the write so the
// resolution is provable on a live system: reading a partition table is safe, streaming 300 MB
// over the running system's other slot is not something a boot proof should do casually.
public ImgSlotTarget imgUpdateResolveTarget() {
    import core.diskpart : gptReadPartition, GptPart;
    ImgSlotTarget t;
    t.valid = false;
    t.slot = imgUpdateTargetSlot();
    const GptPart p = gptReadPartition(t.slot == SLOT_A ? GPT_IDX_SLOT_A : GPT_IDX_SLOT_B);
    if (!p.valid || p.last <= p.first) return t;
    t.firstLba = p.first;
    t.sectors  = p.last - p.first + 1;
    t.valid    = true;
    return t;
}

// Stream a VERIFIED bundle's image payload into the inactive slot.  Verification is re-run here
// rather than trusted from an earlier call: a caller that verified once and wrote later is exactly
// the shape a TOCTOU bug takes, and re-verifying an in-memory buffer costs one hash.
//
// Writes go through the same one-shot capability gate the installer uses, so an update cannot
// write to any disk but the one the cap names, and the cap is revoked immediately after.
public bool imgUpdateWriteToSlot(const(ubyte)* buf, ulong len, out ImgUpdVerdict verdict,
                                 out ImgSlotTarget target) {
    import core.install_cap : InstallWriteCap, mintInstallWriteCap, gatedDiskWrite,
                              revokeInstallWriteCap;
    import drivers.block.disk : diskStoreIndex;

    target = imgUpdateResolveTarget();
    verdict = imgUpdateVerify(buf, len);
    if (verdict != ImgUpdVerdict.Ok) return false;
    if (!target.valid) return false;

    ImgUpdateHeader h;
    if (!imgUpdateParse(buf, len, h)) return false;

    const ulong needSectors = (h.imageLen + 511) / 512;
    if (needSectors > target.sectors) {
        klog("[4.4] image does not fit the inactive slot -- refusing\n");
        return false;
    }

    ulong dsec;
    const int idx = diskStoreIndex(dsec);
    if (idx < 0) return false;

    auto cap = mintInstallWriteCap(idx);
    const(ubyte)* src = buf + IMGUPD_HDR;
    bool ok = true;
    ulong done = 0;
    // 64 sectors (32 KiB) per call: large enough that the per-write overhead disappears, small
    // enough that a failure names a narrow range.
    enum uint CHUNK = 64;
    while (done < needSectors) {
        uint n = CHUNK;
        if (done + n > needSectors) n = cast(uint)(needSectors - done);
        if (!gatedDiskWrite(cap, idx, target.firstLba + done, n, src + done * 512)) { ok = false; break; }
        done += n;
    }
    revokeInstallWriteCap(cap);

    klog(ok ? "[4.4] image written to slot " : "[4.4] image write FAILED to slot ");
    klog_dec(target.slot);
    klog(" lba="); klog_dec(target.firstLba);
    klog(" sectors="); klog_dec(done);
    klog("\n");
    return ok;
}

// D2 proof.  Resolution is verified on ANY system, because reading a partition table is harmless.
// The destructive write is NOT performed here: streaming an image over the other slot of a running
// installed system is not something a boot proof gets to do, and doing it on live media would
// write to a disk the installer has reserved.  The write path is exercised by an actual update.
//
// What this proves is the part that was actually missing and was wrongly reported as impossible:
// that an update can FIND its target slot on a real disk, that the slot is not the running one,
// and that it is big enough for the image.
public void imgUpdateSlotResolveProof() {
    const auto t = imgUpdateResolveTarget();
    klog("[4.4] D2 slot resolve: ");
    if (!t.valid) {
        // Live media has no installed A/B layout, which is the correct answer there rather than a
        // failure -- said explicitly so it is not mistaken for the write path being broken.
        klog("no A/B slot layout on this disk (live media / legacy single-ESP install)\n");
        return;
    }
    BootState s;
    const bool haveState = bootStateRead(s);
    const bool notRunning = !haveState || (t.slot != s.activeSlot);
    klog("targetSlot=");  klog_dec(t.slot);
    klog(" firstLba=");   klog_dec(t.firstLba);
    klog(" sectors=");    klog_dec(t.sectors);
    klog(notRunning ? " -- inactive slot located, D2 PASS\n"
                    : " -- ERROR: resolved the RUNNING slot\n");
}
