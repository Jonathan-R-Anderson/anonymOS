// Secure IPC — Phase 2 (authenticated DH + AEAD) of SECURE_IPC_ROADMAP.md.
//
// The per-endpoint session layer that turns a Phase-1 broker descriptor + channel
// into an authenticated, encrypted, replay-resistant stream.  Keys never leave the
// endpoint (the kernel/broker never see them — invariants K1/K2):
//
//   §2.1 signed-DH (SIGMA-style) — each endpoint sends its ephemeral X25519 public
//        key signed by its identity key; the peer verifies the identity cert (chains
//        to the CA), the signature, and that the peer matches the descriptor's
//        {aId,bId}.  (Identity signatures are the HMAC-SHA-256 stand-in for Ed25519,
//        via `core/secipc.d`'s Identity Service.)
//   §2.2 HKDF key schedule — ss = X25519(ePriv, peerEPub); transcript =
//        SHA-256(descHash‖ePubA‖ePubB‖suiteList); PRK = HKDF-Extract(transcript, ss);
//        distinct A→B / B→A keys via HKDF-Expand.  Both endpoints derive identical
//        keys; the all-zero (low-order) shared secret is rejected; ss + ePriv are
//        zeroized (forward secrecy).
//   §2.3 AEAD record layer — ChaCha20-Poly1305 per message; nonce = direction‖counter,
//        AAD = sessionId‖epoch‖direction‖counter; strict per-direction monotonic
//        counter + 64-entry sliding replay window; MAC failure ⇒ drop (fail-closed).
//   §2.4 downgrade resistance — the offered suiteList is inside the signed handshake,
//        so stripping a suite breaks the identity signature.
//
// Built on the real §8.1 SHA-256/HMAC and the §0 libsecipc (X25519/HKDF/AEAD), all
// RFC-vector-proven.  Constraints mirror the rest of the kernel: -betterC, plain
// structs, __gshared, @nogc nothrow.
module core.secsession;

import core.io; // klog
import core.crypto : sha256;
import core.libsecipc : x25519, x25519Base, hkdfExtract, hkdfExpand,
                        aeadSeal, aeadOpen, ctEqual, zeroize;
import core.secipc : SessionDescriptor, identitySign, identityVerifySig,
                    identityVerifyCert, identityLookup, brokerVerifyDescriptor,
                    secipcDescriptorHash, SUITE_CHACHA20POLY1305, SUITE_AES256GCM,
                    identityRegister, brokerAuthorizePair, brokerRequestSession;
import core.cap : CAPTAB_COUNT, capInstallIn, capClearIn, capLiveCount,
                  CAP_RIGHT_CALL, CAP_INVALID;
import core.objmgr : ObjType, objAlloc, objRelease;

extern (C) @nogc nothrow:

enum int SEC_MSG_MAX = 256;     // max plaintext per record (proof scale)
enum ubyte ST_HANDSHAKE = 0, ST_OPEN = 1, ST_CLOSED = 2;

// Per-endpoint session state — NEVER leaves the process; not in the kernel/broker.
struct Session {
    ulong     sessionId;
    ushort    suite;
    ulong     epoch;
    ubyte[32] sendKey, recvKey;
    ulong     sendCtr;
    ulong     recvCtr;          // highest accepted counter (window anchor)
    ulong     recvWindow;       // 64-entry sliding replay window (bit i = recvCtr-i)
    uint      selfId, peerId;
    ubyte     dir;              // this endpoint's send direction: 0 = A→B, 1 = B→A
    ubyte     state;
    ulong     notAfter;
    ubyte[32] ePriv, ePub;      // ephemeral X25519 (ePriv zeroized after derive)
}

struct HandshakeMsg {
    ulong     sessionId;
    ubyte[32] ephemeralPub;
    ushort    suiteList;        // offered suites (signed ⇒ downgrade-resistant)
    ubyte[32] idSig;            // identity signature (HMAC stand-in for Ed25519)
}

struct SecRecord {
    ulong     sessionId;
    ulong     epoch;
    ubyte     dir;
    ulong     counter;
    uint      ctLen;
    ubyte[SEC_MSG_MAX] ct;
    ubyte[16] tag;
}

__gshared ulong g_secSessions   = 0;
__gshared ulong g_secHandshakeNo = 0;
__gshared ulong g_secSent       = 0;
__gshared ulong g_secRecv       = 0;
__gshared ulong g_secDropReplay = 0;
__gshared ulong g_secDropAuth   = 0;
__gshared bool  g_secSessionSelfTested = false;

private uint put64le(ubyte* b, uint off, ulong v) {
    foreach (i; 0 .. 8) b[off+i] = cast(ubyte)(v >> (i*8)); return off+8;
}
private uint put32le(ubyte* b, uint off, uint v) {
    foreach (i; 0 .. 4) b[off+i] = cast(ubyte)(v >> (i*8)); return off+4;
}
private uint put16le(ubyte* b, uint off, ushort v) {
    b[off]=cast(ubyte)v; b[off+1]=cast(ubyte)(v>>8); return off+2;
}

private bool allZero32(const(ubyte)* p) {
    ubyte d = 0; foreach (i; 0 .. 32) d |= p[i]; return d == 0;
}

// The message an endpoint's identity key signs (and the peer verifies):
// sessionId ‖ ephemeralPub ‖ suiteList ‖ descHash.
private uint handshakeSigned(ulong sessionId, const(ubyte)* ePub, ushort suiteList,
                             const(ubyte)* descHash, ubyte* out_) {
    uint o = put64le(out_, 0, sessionId);
    foreach (i; 0 .. 32) out_[o+i] = ePub[i];
    o += 32;
    o = put16le(out_, o, suiteList);
    foreach (i; 0 .. 32) out_[o+i] = descHash[i];
    return o + 32;
}

// Initialize a session from a descriptor; generate the ephemeral key from `seed32`
// (getrandom in production).  Sets the endpoint's direction from its identity.
public bool sessionInit(Session* s, ref const(SessionDescriptor) d, uint selfId,
                        const(ubyte)* seed32) {
    *s = Session.init;
    if (selfId == d.aId)      { s.dir = 0; s.peerId = d.bId; }
    else if (selfId == d.bId) { s.dir = 1; s.peerId = d.aId; }
    else return false;
    s.sessionId = d.sessionId; s.suite = d.suite; s.epoch = d.epoch;
    s.notAfter = d.notAfter; s.selfId = selfId;
    foreach (i; 0 .. 32) s.ePriv[i] = seed32[i];
    x25519Base(s.ePub.ptr, s.ePriv.ptr);
    s.state = ST_HANDSHAKE;
    ++g_secSessions;
    return true;
}

// Build this endpoint's handshake message (offers `suiteList`).
public void sessionBuildHandshake(Session* s, ref const(SessionDescriptor) d,
                                  ushort suiteList, HandshakeMsg* msg) {
    ubyte[32] dh; secipcDescriptorHash(d, dh.ptr);
    msg.sessionId = s.sessionId;
    foreach (i; 0 .. 32) msg.ephemeralPub[i] = s.ePub[i];
    msg.suiteList = suiteList;
    ubyte[8+32+2+32] signed;
    uint n = handshakeSigned(s.sessionId, s.ePub.ptr, suiteList, dh.ptr, signed.ptr);
    identitySign(s.selfId, signed.ptr, n, msg.idSig.ptr);
}

// Process the peer's handshake: verify descriptor, peer cert, the peer's signature
// (binds its ephemeral + offered suites), reject downgrade, run X25519 + HKDF, set
// the per-direction keys, and zeroize the ephemeral secret.  Returns false (no
// session) on any verification failure — fail-closed.
public bool sessionProcessHandshake(Session* s, ref const(SessionDescriptor) d,
                                    ref const(HandshakeMsg) peer, ulong now) {
    if (s.state != ST_HANDSHAKE) return false;
    if (!brokerVerifyDescriptor(d, now)) { ++g_secHandshakeNo; return false; }
    auto pid = identityLookup(s.peerId);
    if (pid is null || !identityVerifyCert(*pid)) { ++g_secHandshakeNo; return false; }
    if (peer.sessionId != s.sessionId) { ++g_secHandshakeNo; return false; }
    // §2.4 downgrade resistance: the negotiated suite must be in the *signed* offer.
    if ((peer.suiteList & s.suite) == 0) { ++g_secHandshakeNo; return false; }
    // §2.1 verify the peer's identity signature over its ephemeral + suites.
    ubyte[32] dh; secipcDescriptorHash(d, dh.ptr);
    ubyte[8+32+2+32] signed;
    uint n = handshakeSigned(peer.sessionId, peer.ephemeralPub.ptr, peer.suiteList,
                             dh.ptr, signed.ptr);
    if (!identityVerifySig(s.peerId, signed.ptr, n, peer.idSig.ptr)) {
        ++g_secHandshakeNo; return false;
    }
    // §2.2 X25519 shared secret; reject the all-zero (low-order) result.
    ubyte[32] ss;
    x25519(ss.ptr, s.ePriv.ptr, peer.ephemeralPub.ptr);
    if (allZero32(ss.ptr)) { zeroize(ss.ptr, 32); ++g_secHandshakeNo; return false; }
    // transcript hash with canonical A→B ephemeral order (both sides agree).
    ubyte[32] ePubA, ePubB;
    if (s.dir == 0) { ePubA = s.ePub; ePubB = peer.ephemeralPub; }
    else            { ePubA = peer.ephemeralPub; ePubB = s.ePub; }
    ubyte[32+32+32+2] tin;
    uint to = 0;
    foreach (i; 0 .. 32) tin[to++] = dh[i];
    foreach (i; 0 .. 32) tin[to++] = ePubA[i];
    foreach (i; 0 .. 32) tin[to++] = ePubB[i];
    to = put16le(tin.ptr, to, s.suite);
    ubyte[32] transcript; sha256(tin.ptr, to, transcript.ptr);
    // HKDF: PRK from (salt=transcript, ikm=ss); per-direction keys.
    ubyte[32] prk; hkdfExtract(transcript.ptr, 32, ss.ptr, 32, prk.ptr);
    ubyte[32] keyAB, keyBA;
    deriveDirKey(prk.ptr, "secipc A->B".ptr, s.sessionId, keyAB.ptr);
    deriveDirKey(prk.ptr, "secipc B->A".ptr, s.sessionId, keyBA.ptr);
    if (s.dir == 0) { s.sendKey = keyAB; s.recvKey = keyBA; }
    else            { s.sendKey = keyBA; s.recvKey = keyAB; }
    // forward secrecy: wipe the shared secret, ephemeral private key, and PRK.
    zeroize(ss.ptr, 32); zeroize(s.ePriv.ptr, 32); zeroize(prk.ptr, 32);
    s.recvCtr = 0; s.recvWindow = 0; s.sendCtr = 0;
    s.state = ST_OPEN;
    return true;
}

private void deriveDirKey(const(ubyte)* prk, const(char)* label, ulong sessionId,
                          ubyte* out32) {
    ubyte[11+8] info;          // label(11) ‖ sessionId(8)
    foreach (i; 0 .. 11) info[i] = cast(ubyte)label[i];
    put64le(info.ptr, 11, sessionId);
    hkdfExpand(prk, info.ptr, 19, out32, 32);
}

// nonce(12) = direction(1) ‖ 00 00 00 ‖ counter(LE64);  aad(25) = sessionId ‖ epoch ‖
// direction ‖ counter.
private void recordNonceAad(ubyte dir, ulong counter, ulong sessionId, ulong epoch,
                            ubyte* nonce12, ubyte* aad25) {
    foreach (i; 0 .. 12) nonce12[i] = 0;
    nonce12[0] = dir;
    put64le(nonce12, 4, counter);
    uint o = put64le(aad25, 0, sessionId);
    o = put64le(aad25, o, epoch);
    aad25[o++] = dir;
    put64le(aad25, o, counter);
}

// Encrypt a message into a record (AEAD).  Refuses past counter exhaustion (rekey is
// Phase 3).  Returns false if not OPEN / too large / exhausted.
public bool sessionSend(Session* s, const(ubyte)* pt, uint len, SecRecord* rec) {
    if (s.state != ST_OPEN || len > SEC_MSG_MAX) return false;
    if (s.sendCtr == ulong.max) return false;     // exhausted ⇒ must rekey
    ubyte[12] nonce; ubyte[25] aad;
    recordNonceAad(s.dir, s.sendCtr, s.sessionId, s.epoch, nonce.ptr, aad.ptr);
    if (!aeadSeal(s.sendKey.ptr, nonce.ptr, aad.ptr, 25, pt, len, rec.ct.ptr, rec.tag.ptr))
        return false;
    rec.sessionId = s.sessionId; rec.epoch = s.epoch; rec.dir = s.dir;
    rec.counter = s.sendCtr; rec.ctLen = len;
    ++s.sendCtr; ++g_secSent;
    return true;
}

private bool windowCheck(Session* s, ulong ctr) {
    if (ctr > s.recvCtr) return true;              // ahead of the window
    if (s.recvCtr - ctr >= 64) return false;       // too old
    return (s.recvWindow & (1UL << (s.recvCtr - ctr))) == 0; // unseen
}
private void windowAdvance(Session* s, ulong ctr) {
    if (ctr > s.recvCtr) {
        ulong shift = ctr - s.recvCtr;
        s.recvWindow = (shift >= 64) ? 0 : (s.recvWindow << shift);
        s.recvWindow |= 1;                         // bit0 = the new highest
        s.recvCtr = ctr;
    } else {
        s.recvWindow |= (1UL << (s.recvCtr - ctr));
    }
}

// Decrypt + authenticate a record; enforces epoch, peer direction, replay window,
// and AEAD tag.  Delivers plaintext into `out` (sets `*outLen`) only on success; a
// replay or MAC failure is dropped (fail-closed, no state change on auth failure).
public bool sessionRecv(Session* s, ref const(SecRecord) rec, ubyte* outBuf, uint* outLen) {
    if (s.state != ST_OPEN) return false;
    if (rec.sessionId != s.sessionId) return false;
    if (rec.epoch != s.epoch) return false;                 // revoked / wrong epoch
    if (rec.dir != cast(ubyte)(1 - s.dir)) return false;    // must be peer's direction
    if (rec.ctLen > SEC_MSG_MAX) return false;
    if (!windowCheck(s, rec.counter)) { ++g_secDropReplay; return false; } // replay/old
    ubyte[12] nonce; ubyte[25] aad;
    recordNonceAad(rec.dir, rec.counter, s.sessionId, s.epoch, nonce.ptr, aad.ptr);
    if (!aeadOpen(s.recvKey.ptr, nonce.ptr, aad.ptr, 25, rec.ct.ptr, rec.ctLen,
                  rec.tag.ptr, outBuf)) {
        ++g_secDropAuth; return false;                      // MAC fail ⇒ drop
    }
    windowAdvance(s, rec.counter);                          // only after auth
    if (outLen !is null) *outLen = rec.ctLen;
    ++g_secRecv;
    return true;
}

public void sessionClose(Session* s) {
    zeroize(s.sendKey.ptr, 32); zeroize(s.recvKey.ptr, 32);
    zeroize(s.ePriv.ptr, 32);
    s.state = ST_CLOSED;
}

// === proof: a full A↔B authenticated, encrypted exchange =====================
private bool bytesEq(const(ubyte)* a, const(ubyte)* b, uint n) { return ctEqual(a, b, n); }

public void secsessionSelfTest() {
    if (g_secSessionSelfTested) return;
    int st = CAPTAB_COUNT - 2;
    if (capLiveCount(st) != 0) return;     // scratch table busy; retry next tick
    g_secSessionSelfTested = true;

    // --- Phase-1 setup: two identities, an authorized pair, a signed descriptor ---
    uint oa = objAlloc(ObjType.Process, null);
    uint ob = objAlloc(ObjType.Process, null);
    uint launchObj = objAlloc(ObjType.Process, null);
    enum uint LAUNCH_H = 60, CHAN_H = 61;
    bool ok = (oa && ob && launchObj);
    SessionDescriptor desc;
    if (ok) {
        capInstallIn(st, LAUNCH_H, launchObj, CAP_RIGHT_CALL, CAP_INVALID);
        ubyte[32] pubA; foreach (i; 0 .. 32) pubA[i] = cast(ubyte)(0x10 + i);
        ubyte[32] pubB; foreach (i; 0 .. 32) pubB[i] = cast(ubyte)(0xA0 + i);
        ok = identityRegister(st, oa, pubA.ptr, LAUNCH_H, 1000) &&
             identityRegister(st, ob, pubB.ptr, LAUNCH_H, 1000);
        brokerAuthorizePair(oa, ob);
        ok = ok && brokerRequestSession(st, oa, ob,
                     cast(ushort)(SUITE_CHACHA20POLY1305 | SUITE_AES256GCM),
                     CHAN_H, 10, 100, &desc);
    }

    bool handshake=false, agree=false, msg=false, replay=false, tamper=false,
         downgrade=false, dirSep=false;
    if (ok) {
        ushort offer = cast(ushort)(SUITE_CHACHA20POLY1305 | SUITE_AES256GCM);
        ubyte[32] seedA; foreach (i; 0 .. 32) seedA[i] = cast(ubyte)(0x31 + i);
        ubyte[32] seedB; foreach (i; 0 .. 32) seedB[i] = cast(ubyte)(0x73 + i);
        Session sA, sB;
        sessionInit(&sA, desc, oa, seedA.ptr);
        sessionInit(&sB, desc, ob, seedB.ptr);
        HandshakeMsg hsA, hsB;
        sessionBuildHandshake(&sA, desc, offer, &hsA);
        sessionBuildHandshake(&sB, desc, offer, &hsB);

        // §2.4 downgrade: a tampered suiteList in A's handshake fails B's verify.
        {
            Session sBd; sessionInit(&sBd, desc, ob, seedB.ptr);
            HandshakeMsg forged = hsA; forged.suiteList = SUITE_AES256GCM; // strip ChaCha
            downgrade = !sessionProcessHandshake(&sBd, desc, forged, 10);
        }

        // §2.1/§2.2 happy-path handshake both ways.
        bool pa = sessionProcessHandshake(&sA, desc, hsB, 10);
        bool pb = sessionProcessHandshake(&sB, desc, hsA, 10);
        handshake = pa && pb && sA.state == ST_OPEN && sB.state == ST_OPEN;
        // Both endpoints derived matching directional keys (and ePriv was wiped).
        agree = bytesEq(sA.sendKey.ptr, sB.recvKey.ptr, 32) &&
                bytesEq(sA.recvKey.ptr, sB.sendKey.ptr, 32) &&
                !bytesEq(sA.sendKey.ptr, sA.recvKey.ptr, 32) &&
                allZero32(sA.ePriv.ptr);

        // §2.3 encrypted A→B and B→A messages round-trip.
        static immutable ubyte[5] m1 = ['h','e','l','l','o'];
        static immutable ubyte[5] m2 = ['w','o','r','l','d'];
        SecRecord rAB, rBA;
        ubyte[SEC_MSG_MAX] buf; uint blen;
        bool s1 = sessionSend(&sA, m1.ptr, 5, &rAB);
        bool r1 = sessionRecv(&sB, rAB, buf.ptr, &blen) && blen == 5 && bytesEq(buf.ptr, m1.ptr, 5);
        bool s2 = sessionSend(&sB, m2.ptr, 5, &rBA);
        bool r2 = sessionRecv(&sA, rBA, buf.ptr, &blen) && blen == 5 && bytesEq(buf.ptr, m2.ptr, 5);
        msg = s1 && r1 && s2 && r2;

        // §2.3 replay: re-delivering A→B's record is dropped.
        replay = !sessionRecv(&sB, rAB, buf.ptr, &blen);

        // §2.3 tamper: a flipped ciphertext byte fails the AEAD tag (fail-closed).
        SecRecord rT;
        sessionSend(&sA, m1.ptr, 5, &rT);
        rT.ct[0] ^= 0x20;
        tamper = !sessionRecv(&sB, rT, buf.ptr, &blen);

        // per-direction key separation: an A→B record fed to A's recv (B→A key) fails.
        SecRecord rDir;
        sessionSend(&sA, m1.ptr, 5, &rDir);
        dirSep = !sessionRecv(&sA, rDir, buf.ptr, &blen);  // wrong direction ⇒ rejected
    }

    capClearIn(st, LAUNCH_H);
    if (oa) objRelease(oa);
    if (ob) objRelease(ob);
    if (launchObj) objRelease(launchObj);

    if (ok && handshake && agree && msg && replay && tamper && downgrade && dirSep) {
        klog("[secsession] selftest PASS\n");
    } else {
        klog("[secsession] selftest FAIL:");
        if (!ok)        klog(" setup");
        if (!handshake) klog(" handshake");
        if (!agree)     klog(" keyagree");
        if (!msg)       klog(" aead");
        if (!replay)    klog(" replay");
        if (!tamper)    klog(" tamper");
        if (!downgrade) klog(" downgrade");
        if (!dirSep)    klog(" dirsep");
        klog("\n");
    }
}

public void secsessionStats() {
    klog("[secsession] sessions="); klog_hex(g_secSessions);
    klog(" hsfail=");               klog_hex(g_secHandshakeNo);
    klog(" sent=");                 klog_hex(g_secSent);
    klog(" recv=");                 klog_hex(g_secRecv);
    klog(" dropreplay=");           klog_hex(g_secDropReplay);
    klog(" dropauth=");             klog_hex(g_secDropAuth);
    klog("\n");
}
