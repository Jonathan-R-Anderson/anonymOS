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
                    brokerRevokeSession, secipcDescriptorHash,
                    SUITE_CHACHA20POLY1305, SUITE_AES256GCM,
                    identityRegister, brokerAuthorizePair, brokerRequestSession;
import core.cap : CAPTAB_COUNT, capInstallIn, capClearIn, capLiveCount,
                  CAP_RIGHT_CALL, CAP_INVALID;
import core.objmgr : ObjType, objAlloc, objRelease;

extern (C) @nogc nothrow:

enum int SEC_MSG_MAX = 256;     // max plaintext per record (proof scale)
enum ubyte ST_HANDSHAKE = 0, ST_OPEN = 1, ST_CLOSED = 2, ST_REKEY = 3;

// §3.1 rekey when the send counter approaches exhaustion (no (key,nonce) reuse).
enum ulong REKEY_THRESHOLD = 0xFFFF_FFFF_FFFF_FF00;
// §3.3 tear a session after this many consecutive AEAD authentication failures.
enum uint AUTH_FAIL_MAX = 4;

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
    // --- §3 lifecycle ---------------------------------------------------------
    ulong     keyGen;           // key generation; bumped on each rekey (§3.1)
    uint      authFailCount;    // consecutive AEAD failures (§3.3 tear threshold)
    ubyte[32] descHash;         // bound transcript anchor (for rekey continuity)
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
    ulong     keyGen;          // §3.1 key generation; a stale-generation record is dropped
    ubyte     dir;
    ulong     counter;
    uint      ctLen;
    ubyte[SEC_MSG_MAX] ct;
    ubyte[16] tag;
}

// §3.1 on-wire rekey message: a fresh signed ephemeral within a live session.
struct RekeyMsg {
    ulong     sessionId;
    ulong     keyGen;          // the NEW generation being established
    ubyte[32] ephemeralPub;
    ubyte[32] idSig;
}

__gshared ulong g_secSessions   = 0;
__gshared ulong g_secHandshakeNo = 0;
__gshared ulong g_secSent       = 0;
__gshared ulong g_secRecv       = 0;
__gshared ulong g_secDropReplay = 0;
__gshared ulong g_secDropAuth   = 0;
__gshared ulong g_secRekey      = 0;   // §3.1 completed rekeys
__gshared ulong g_secRevoked    = 0;   // §3.2 sessions closed by revocation
__gshared ulong g_secTimeout    = 0;   // §3.3 handshakes timed out
__gshared ulong g_secTorn       = 0;   // §3.3 sessions torn (auth flood / peer death)
__gshared bool  g_secSessionSelfTested = false;
__gshared bool  g_secLifeSelfTested    = false;

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
    // Bind the descriptor transcript anchor + derive generation-0 keys.
    foreach (i; 0 .. 32) s.descHash[i] = dh[i];
    s.keyGen = 0;
    deriveKeys(s, s.ePub.ptr, peer.ephemeralPub.ptr, ss.ptr, 0);
    // forward secrecy: wipe the shared secret + ephemeral private key.
    zeroize(ss.ptr, 32); zeroize(s.ePriv.ptr, 32);
    s.recvCtr = 0; s.recvWindow = 0; s.sendCtr = 0; s.authFailCount = 0;
    s.state = ST_OPEN;
    return true;
}

private void deriveDirKey(const(ubyte)* prk, const(char)* label, ulong sessionId,
                          ulong keyGen, ubyte* out32) {
    ubyte[11+8+8] info;        // label(11) ‖ sessionId(8) ‖ keyGen(8)
    foreach (i; 0 .. 11) info[i] = cast(ubyte)label[i];
    uint o = put64le(info.ptr, 11, sessionId);
    put64le(info.ptr, o, keyGen);
    hkdfExpand(prk, info.ptr, 27, out32, 32);
}

// Derive the per-direction keys from a shared secret, binding the transcript anchor
// (descHash), both ephemerals (canonical A→B order), the suite, and the key
// generation.  Used by both the initial handshake (§2.2) and rekey (§3.1).
private void deriveKeys(Session* s, const(ubyte)* ePubSelf, const(ubyte)* ePubPeer,
                        const(ubyte)* ss, ulong keyGen) {
    ubyte[32] ePubA, ePubB;
    if (s.dir == 0) { foreach (i; 0..32) { ePubA[i]=ePubSelf[i]; ePubB[i]=ePubPeer[i]; } }
    else            { foreach (i; 0..32) { ePubA[i]=ePubPeer[i]; ePubB[i]=ePubSelf[i]; } }
    ubyte[32+32+32+2+8] tin;
    uint to = 0;
    foreach (i; 0 .. 32) tin[to++] = s.descHash[i];
    foreach (i; 0 .. 32) tin[to++] = ePubA[i];
    foreach (i; 0 .. 32) tin[to++] = ePubB[i];
    to = put16le(tin.ptr, to, s.suite);
    to = put64le(tin.ptr, to, keyGen);
    ubyte[32] transcript; sha256(tin.ptr, to, transcript.ptr);
    ubyte[32] prk; hkdfExtract(transcript.ptr, 32, ss, 32, prk.ptr);
    ubyte[32] keyAB, keyBA;
    deriveDirKey(prk.ptr, "secipc A->B".ptr, s.sessionId, keyGen, keyAB.ptr);
    deriveDirKey(prk.ptr, "secipc B->A".ptr, s.sessionId, keyGen, keyBA.ptr);
    if (s.dir == 0) { s.sendKey = keyAB; s.recvKey = keyBA; }
    else            { s.sendKey = keyBA; s.recvKey = keyAB; }
    zeroize(prk.ptr, 32);
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
    rec.sessionId = s.sessionId; rec.epoch = s.epoch; rec.keyGen = s.keyGen;
    rec.dir = s.dir; rec.counter = s.sendCtr; rec.ctLen = len;
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
    if (rec.keyGen != s.keyGen) return false;               // §3.1 stale generation
    if (rec.dir != cast(ubyte)(1 - s.dir)) return false;    // must be peer's direction
    if (rec.ctLen > SEC_MSG_MAX) return false;
    if (!windowCheck(s, rec.counter)) { ++g_secDropReplay; return false; } // replay/old
    ubyte[12] nonce; ubyte[25] aad;
    recordNonceAad(rec.dir, rec.counter, s.sessionId, s.epoch, nonce.ptr, aad.ptr);
    if (!aeadOpen(s.recvKey.ptr, nonce.ptr, aad.ptr, 25, rec.ct.ptr, rec.ctLen,
                  rec.tag.ptr, outBuf)) {
        ++g_secDropAuth;                                    // MAC fail ⇒ drop
        if (++s.authFailCount >= AUTH_FAIL_MAX) {           // §3.3 auth flood ⇒ tear
            sessionClose(s); ++g_secTorn;
        }
        return false;
    }
    s.authFailCount = 0;                                    // a good record clears it
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

// === §3.1 key rotation / rekey ================================================
// True when the send counter is close enough to exhaustion that a rekey is due
// (no (key,nonce) pair is ever reused — invariant K5).
public bool sessionNeedsRekey(Session* s) {
    return s.state == ST_OPEN && s.sendCtr >= REKEY_THRESHOLD;
}

private uint rekeySigned(ulong sessionId, ulong keyGen, const(ubyte)* ePub, ubyte* out_) {
    uint o = put64le(out_, 0, sessionId);
    o = put64le(out_, o, keyGen);
    foreach (i; 0 .. 32) out_[o+i] = ePub[i];
    return o + 32;
}

// Begin a rekey: generate a fresh ephemeral from `seed32`, enter ST_REKEY, and emit a
// signed rekey message advancing to the next key generation.
public bool sessionRekeyBuild(Session* s, const(ubyte)* seed32, RekeyMsg* msg) {
    if (s.state != ST_OPEN) return false;
    foreach (i; 0 .. 32) s.ePriv[i] = seed32[i];
    x25519Base(s.ePub.ptr, s.ePriv.ptr);
    s.state = ST_REKEY;
    ulong ng = s.keyGen + 1;
    msg.sessionId = s.sessionId;
    msg.keyGen = ng;
    foreach (i; 0 .. 32) msg.ephemeralPub[i] = s.ePub[i];
    ubyte[8+8+32] signed;
    uint n = rekeySigned(s.sessionId, ng, s.ePub.ptr, signed.ptr);
    identitySign(s.selfId, signed.ptr, n, msg.idSig.ptr);
    return true;
}

// Complete a rekey from the peer's signed rekey message: verify, run a fresh X25519,
// derive next-generation keys (old keys overwritten), reset counters.  Fail-closed.
public bool sessionRekeyProcess(Session* s, ref const(RekeyMsg) peer) {
    if (s.state != ST_REKEY) return false;
    if (peer.sessionId != s.sessionId) return false;
    ulong ng = s.keyGen + 1;
    if (peer.keyGen != ng) return false;
    ubyte[8+8+32] signed;
    uint n = rekeySigned(peer.sessionId, peer.keyGen, peer.ephemeralPub.ptr, signed.ptr);
    if (!identityVerifySig(s.peerId, signed.ptr, n, peer.idSig.ptr)) return false;
    ubyte[32] ss;
    x25519(ss.ptr, s.ePriv.ptr, peer.ephemeralPub.ptr);
    if (allZero32(ss.ptr)) { zeroize(ss.ptr, 32); return false; }
    deriveKeys(s, s.ePub.ptr, peer.ephemeralPub.ptr, ss.ptr, ng);  // overwrites old keys
    zeroize(ss.ptr, 32); zeroize(s.ePriv.ptr, 32);
    s.keyGen = ng;
    s.sendCtr = 0; s.recvCtr = 0; s.recvWindow = 0; s.authFailCount = 0;
    s.state = ST_OPEN;
    ++g_secRekey;
    return true;
}

// === §3.2 revocation ==========================================================
// Re-check the descriptor (broker signature + expiry + revocation set).  If it no
// longer verifies (epoch bumped / session revoked / expired), close the session and
// zeroize its keys — fail-closed.  Returns true if the session is now closed.
public bool sessionRevocationTick(Session* s, ref const(SessionDescriptor) d, ulong now) {
    if (s.state == ST_CLOSED) return true;
    if (!brokerVerifyDescriptor(d, now)) {
        sessionClose(s); ++g_secRevoked; return true;
    }
    return false;
}

// === §3.3 failure handling ====================================================
// A handshake that has not reached OPEN by `deadline` fails closed.
public bool sessionHandshakeTimeout(Session* s, ulong now, ulong deadline) {
    if (s.state == ST_HANDSHAKE && now >= deadline) {
        sessionClose(s); ++g_secTimeout; return true;
    }
    return false;
}

// Peer death (EPOLLHUP / eventfd): mark closed + zeroize.
public void sessionPeerDied(Session* s) {
    if (s.state != ST_CLOSED) { sessionClose(s); ++g_secTorn; }
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
    capClearIn(st, CHAN_H);          // channel cap installed by brokerRequestSession
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

// === §3 lifecycle proof: rekey, revocation, failure handling =================
// Build an OPEN A↔B session pair through the full Phase-1+2 flow (handles 60/61 in
// the scratch table).  Outputs the descriptor + the three allocated objects.
public bool secsessionOpenPair(int st, Session* sa, Session* sb, SessionDescriptor* desc,
                               uint* oa, uint* ob, uint* lo) {
    *oa = objAlloc(ObjType.Process, null);
    *ob = objAlloc(ObjType.Process, null);
    *lo = objAlloc(ObjType.Process, null);
    if (!*oa || !*ob || !*lo) return false;
    enum uint LAUNCH_H = 60, CHAN_H = 61;
    capInstallIn(st, LAUNCH_H, *lo, CAP_RIGHT_CALL, CAP_INVALID);
    ubyte[32] pubA; foreach (i; 0 .. 32) pubA[i] = cast(ubyte)(0x10 + i);
    ubyte[32] pubB; foreach (i; 0 .. 32) pubB[i] = cast(ubyte)(0xA0 + i);
    if (!identityRegister(st, *oa, pubA.ptr, LAUNCH_H, 1000)) return false;
    if (!identityRegister(st, *ob, pubB.ptr, LAUNCH_H, 1000)) return false;
    brokerAuthorizePair(*oa, *ob);
    if (!brokerRequestSession(st, *oa, *ob,
            cast(ushort)(SUITE_CHACHA20POLY1305 | SUITE_AES256GCM), CHAN_H, 10, 100, desc))
        return false;
    ushort offer = cast(ushort)(SUITE_CHACHA20POLY1305 | SUITE_AES256GCM);
    ubyte[32] seedA; foreach (i; 0 .. 32) seedA[i] = cast(ubyte)(0x31 + i);
    ubyte[32] seedB; foreach (i; 0 .. 32) seedB[i] = cast(ubyte)(0x73 + i);
    sessionInit(sa, *desc, *oa, seedA.ptr);
    sessionInit(sb, *desc, *ob, seedB.ptr);
    HandshakeMsg hsA, hsB;
    sessionBuildHandshake(sa, *desc, offer, &hsA);
    sessionBuildHandshake(sb, *desc, offer, &hsB);
    if (!sessionProcessHandshake(sa, *desc, hsB, 10)) return false;
    if (!sessionProcessHandshake(sb, *desc, hsA, 10)) return false;
    return sa.state == ST_OPEN && sb.state == ST_OPEN;
}

public void seclifeSelfTest() {
    if (g_secLifeSelfTested) return;
    int st = CAPTAB_COUNT - 2;
    if (capLiveCount(st) != 0) return;     // scratch table busy; retry next tick
    g_secLifeSelfTested = true;

    Session sA, sB, sC, sD;
    SessionDescriptor d1, d2;
    uint o1a,o1b,l1, o2a,o2b,l2;
    bool ok = secsessionOpenPair(st, &sA, &sB, &d1, &o1a, &o1b, &l1) &&
              secsessionOpenPair(st, &sC, &sD, &d2, &o2a, &o2b, &l2);

    bool rekey=false, stale=false, torn=false, peerdeath=false, revoke=false, timeout=false;
    ubyte[SEC_MSG_MAX] buf; uint bl;
    static immutable ubyte[3] m = ['n','e','w'];

    if (ok) {
        // --- §3.1 rekey: force the counter near exhaustion, rekey both sides ------
        bool needBefore = !sessionNeedsRekey(&sA);
        sA.sendCtr = REKEY_THRESHOLD;
        bool needNow = sessionNeedsRekey(&sA);
        ubyte[32] oldSend; foreach (i; 0 .. 32) oldSend[i] = sA.sendKey[i];
        ubyte[32] seedA2; foreach (i; 0 .. 32) seedA2[i] = cast(ubyte)(0x90 + i);
        ubyte[32] seedB2; foreach (i; 0 .. 32) seedB2[i] = cast(ubyte)(0xC0 + i);
        RekeyMsg rkA, rkB;
        sessionRekeyBuild(&sA, seedA2.ptr, &rkA);
        sessionRekeyBuild(&sB, seedB2.ptr, &rkB);
        bool pa = sessionRekeyProcess(&sA, rkB);
        bool pb = sessionRekeyProcess(&sB, rkA);
        bool agree2 = bytesEq(sA.sendKey.ptr, sB.recvKey.ptr, 32) &&
                      bytesEq(sA.recvKey.ptr, sB.sendKey.ptr, 32) &&
                      !bytesEq(sA.sendKey.ptr, oldSend.ptr, 32) &&  // keys rotated
                      sA.keyGen == 1 && sB.keyGen == 1 && sA.sendCtr == 0;
        SecRecord r;
        bool s1 = sessionSend(&sA, m.ptr, 3, &r);
        bool r1 = sessionRecv(&sB, r, buf.ptr, &bl) && bl == 3 && bytesEq(buf.ptr, m.ptr, 3);
        rekey = needBefore && needNow && pa && pb && agree2 && s1 && r1;

        // --- §3.1 stale generation: a record stamped with the old keyGen is dropped -
        SecRecord rs = r; rs.keyGen = 0;
        stale = !sessionRecv(&sB, rs, buf.ptr, &bl);

        // --- §3.3 auth flood tears the session (pair2: sD) -----------------------
        SecRecord rbad;
        sessionSend(&sC, m.ptr, 3, &rbad);
        rbad.tag[0] ^= 0xFF;                          // corrupt the AEAD tag
        foreach (_; 0 .. AUTH_FAIL_MAX) sessionRecv(&sD, rbad, buf.ptr, &bl);
        torn = (sD.state == ST_CLOSED) && allZero32(sD.recvKey.ptr);

        // --- §3.3 peer death closes + zeroizes (pair2: sC) -----------------------
        sessionPeerDied(&sC);
        peerdeath = (sC.state == ST_CLOSED) && allZero32(sC.sendKey.ptr);

        // --- §3.2 revocation: broker revokes pair1 ⇒ tick closes both ------------
        brokerRevokeSession(d1.sessionId);
        bool cA = sessionRevocationTick(&sA, d1, 10);
        bool cB = sessionRevocationTick(&sB, d1, 10);
        bool noIo = !sessionSend(&sA, m.ptr, 3, &r) && allZero32(sA.sendKey.ptr);
        revoke = cA && cB && noIo && sA.state == ST_CLOSED;

        // --- §3.3 handshake timeout: stuck in HANDSHAKE past the deadline ---------
        Session sH;
        ubyte[32] seedH; foreach (i; 0 .. 32) seedH[i] = cast(ubyte)(0x20 + i);
        sessionInit(&sH, d2, o2a, seedH.ptr);         // ST_HANDSHAKE, never completes
        timeout = sessionHandshakeTimeout(&sH, 1000, 500) && sH.state == ST_CLOSED;
    }

    capClearIn(st, 60); capClearIn(st, 61);
    if (o1a) objRelease(o1a); if (o1b) objRelease(o1b); if (l1) objRelease(l1);
    if (o2a) objRelease(o2a); if (o2b) objRelease(o2b); if (l2) objRelease(l2);

    if (ok && rekey && stale && torn && peerdeath && revoke && timeout) {
        klog("[seclife] selftest PASS\n");
    } else {
        klog("[seclife] selftest FAIL:");
        if (!ok)        klog(" setup");
        if (!rekey)     klog(" rekey");
        if (!stale)     klog(" stalegen");
        if (!torn)      klog(" authflood");
        if (!peerdeath) klog(" peerdeath");
        if (!revoke)    klog(" revoke");
        if (!timeout)   klog(" timeout");
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
    klog(" rekey=");                klog_hex(g_secRekey);
    klog(" revoked=");              klog_hex(g_secRevoked);
    klog(" timeout=");              klog_hex(g_secTimeout);
    klog(" torn=");                 klog_hex(g_secTorn);
    klog("\n");
}
