// Secure IPC — Phase 1 (identity + descriptors) of roadmap/SECURE_IPC_ROADMAP.md.
//
// Authenticated, capability-gated IPC setup *without* wire crypto yet (that is
// Phase 2's signed-DH/AEAD).  Three roles, per the roadmap's trust split:
//
//   §1.1 Identity Service (CA) — `identityRegister` binds a process object to an
//        identity public key and issues a cert signed by the CA over
//        (objId‖identityPub‖notAfter); registration requires the process to *prove
//        it holds its launch capability* (it cannot register as an object it did not
//        launch).  `identityVerifyCert` is the anchor peers use to authenticate.
//   §1.2 Broker / Key Service — `brokerRequestSession(A→B)` consults the capability
//        manager (an authorized-pair policy), mints a sessionId+epoch, allocates a
//        channel endpoint, installs the **channel capability** into A's cap table,
//        and returns a **broker-signed Session Descriptor** binding {A,B,channelCap,
//        suite,policy,epoch,notAfter}.  It holds the broker signing key, never a
//        session key.
//   §1.3 Kernel capability-gated routing — `secipcKernelRoute` delivers **iff** the
//        sender holds the channel capability (CAP_RIGHT_CALL); it performs **no
//        crypto** and parses no descriptor (invariant K1).  `secipcChannelRevoke`
//        tears the transport by revoking the cap (kernel op `channel_revoke`).
//
// Trust split honored: the kernel routing gate is key-free; the broker/CA signatures
// are HMAC-SHA-256 (§8.1) under service-held keys — a genuine authenticator and the
// seam where Ed25519 slots in (the roadmap's §6 names Ed25519).  In this build the
// broker/identity/cap-manager run *in-kernel* as object services; relocating them to
// userspace and wiring the live `LocalSocket`/`sendmsg` path through
// `secipcKernelRoute` is the remaining integration (roadmap §7, M2).
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared,
// @nogc nothrow.
module core.secipc;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objRelease, objGet;
import core.crypto : hmacSha256, ctEqual32, sha256;
import core.cap : CAP_RIGHT_CALL, CAP_INVALID, CAPTAB_COUNT, capInstallIn,
                  requireCapIn, capRevokeIn, capClearIn, capLiveCount;
import core.ipc : ipcEndpointAlloc;

extern (C) @nogc nothrow:

enum int SECIPC_ID_MAX   = 32;   // registered process identities
enum int SECIPC_PAIR_MAX = 64;   // authorized A↔B pairs
enum int SECIPC_REVOKE_MAX = 64; // revoked session ids

// Cipher suites (offered as a preference bitmask; §6 default ChaCha20-Poly1305).
enum ushort SUITE_CHACHA20POLY1305 = 1;
enum ushort SUITE_AES256GCM        = 2;

// --- service signing keys (held by the userspace services in the real design) ----
__gshared ubyte[32] g_caKey = [        // Identity CA key
    0x1C,0xA0,0x55,0x16,0x4E,0x71,0x37,0x44,0x91,0xB5,0xC0,0xFB,0xCF,0xE9,0xB5,0xDB,
    0xA5,0x39,0x56,0xC2,0x5B,0x59,0xF1,0x11,0xF1,0x92,0x3F,0x82,0xA4,0xAB,0x1C,0x5E,
];
__gshared ubyte[32] g_brokerKey = [    // Broker descriptor signing key
    0xB0,0x06,0xE7,0x10,0x12,0x83,0x5B,0x01,0x24,0x31,0x85,0xBE,0x55,0x0C,0x7D,0xC3,
    0x72,0xBE,0x5D,0x74,0x80,0xDE,0xB1,0xFE,0x9B,0xDC,0x06,0xA7,0xC1,0x9B,0xF1,0x74,
];

// === data structures (roadmap §4) =============================================
struct ProcIdentity {
    bool      inUse;
    uint      objId;            // the process object this identity is bound to
    ubyte[32] identityPub;      // the process's identity public key (Ed25519 in §6)
    ubyte[32] certSig;          // CA signature over (objId‖identityPub‖notAfter)
    uint      launchCap;        // the launch capability handle that proved ownership
    ulong     notAfter;         // cert expiry
}

struct SessionDescriptor {
    ulong     sessionId;
    uint      aId, bId;
    uint      channelCap;       // channel endpoint object the cap points at
    ushort    suite;
    uint      policy;
    ulong     epoch;            // revocation epoch at mint
    ulong     notAfter;
    uint      aIdentity, bIdentity; // IDENTITY_DOMAIN §5: security domains of A and B
    ubyte[32] brokerSig;        // broker signature over all prior fields
}

struct PairPolicy {
    bool inUse;
    uint aId, bId;              // A is authorized to open a channel to B
}

__gshared ProcIdentity[SECIPC_ID_MAX]   g_ids;
__gshared PairPolicy[SECIPC_PAIR_MAX]    g_pairs;
__gshared ulong[SECIPC_REVOKE_MAX]       g_revoked;
__gshared uint  g_revokedHead = 0;

__gshared ulong g_sessionCtr     = 0;
__gshared ulong g_revocationEpoch = 1;
__gshared ulong g_regTotal       = 0;
__gshared ulong g_sessionTotal   = 0;
__gshared ulong g_sessionDenied  = 0;   // RequestSession refused (unauth / bad identity)
__gshared ulong g_routeOk        = 0;
__gshared ulong g_routeDeny      = 0;
__gshared ulong g_descReject     = 0;
__gshared bool  g_secipcSelfTested = false;

// IDENTITY_DOMAIN §5: optional cross-identity gate installed by core.idipc at boot.
// Given the two process objects, it returns true to allow the session and fills the
// security-domain identity ids to stamp into the descriptor; false denies.  The
// deny-by-default policy lives in idipc, so secipc stays identity-agnostic when the
// gate is unset (e.g. before the Identity Manager is up, or in lower-level tests).
alias SecipcIdGate = extern(C) bool function(uint aProc, uint bProc,
                                             uint* aIdOut, uint* bIdOut) @nogc nothrow;
__gshared SecipcIdGate g_secipcIdGate = null;
public void secipcSetIdGate(SecipcIdGate fn) { g_secipcIdGate = fn; }

// --- little-endian field serializers ------------------------------------------
private uint put32(ubyte* b, uint off, uint v) {
    b[off]=cast(ubyte)v; b[off+1]=cast(ubyte)(v>>8);
    b[off+2]=cast(ubyte)(v>>16); b[off+3]=cast(ubyte)(v>>24); return off+4;
}
private uint put16(ubyte* b, uint off, ushort v) {
    b[off]=cast(ubyte)v; b[off+1]=cast(ubyte)(v>>8); return off+2;
}
private uint put64(ubyte* b, uint off, ulong v) {
    foreach (i; 0 .. 8) b[off+i]=cast(ubyte)(v>>(i*8)); return off+8;
}

// === §1.1 Identity Service (CA) ===============================================
private void certBody(uint objId, const(ubyte)* pub32, ulong notAfter, ubyte* out44) {
    uint o = put32(out44, 0, objId);
    foreach (i; 0 .. 32) out44[o+i] = pub32[i];
    o += 32;
    put64(out44, o, notAfter);
}

private void caSign(uint objId, const(ubyte)* pub32, ulong notAfter, ubyte* sig32) {
    ubyte[44] body_;
    certBody(objId, pub32, notAfter, body_.ptr);
    hmacSha256(g_caKey.ptr, 32, body_.ptr, 44, sig32);
}

private ProcIdentity* idByObj(uint objId) {
    if (objId == 0) return null;
    foreach (ref p; g_ids) if (p.inUse && p.objId == objId) return &p;
    return null;
}

// Register a process identity.  The caller must prove it holds `launchCapHandle`
// (its launch capability) — registration is refused otherwise, so a process cannot
// claim an object it did not launch.  Returns true and stores a signed cert.
public bool identityRegister(int tableId, uint objId, const(ubyte)* pub32,
                             uint launchCapHandle, ulong notAfter) {
    if (objId == 0 || pub32 is null || objGet(objId) is null) return false;
    // Proof-of-launch-cap: the registrant must hold a usable cap at launchCapHandle.
    if (!requireCapIn(tableId, launchCapHandle, 0)) return false;
    auto p = idByObj(objId);
    if (p is null) {
        foreach (ref e; g_ids) if (!e.inUse) { p = &e; break; }
        if (p is null) return false;
    }
    p.inUse = true;
    p.objId = objId;
    foreach (i; 0 .. 32) p.identityPub[i] = pub32[i];
    p.launchCap = launchCapHandle;
    p.notAfter = notAfter;
    caSign(objId, pub32, notAfter, p.certSig.ptr);
    ++g_regTotal;
    return true;
}

public ProcIdentity* identityLookup(uint objId) { return idByObj(objId); }

// Verify a cert: recompute the CA signature over its bound fields.
public bool identityVerifyCert(ref const(ProcIdentity) p) {
    ubyte[32] expect;
    caSign(p.objId, p.identityPub.ptr, p.notAfter, expect.ptr);
    return ctEqual32(expect.ptr, p.certSig.ptr);
}

// Identity signing for the Phase-2 signed-DH handshake.  In the real design each
// process holds an Ed25519 *private* key and peers verify with the public key in the
// cert; as the HMAC-SHA-256 stand-in, the identity key is derived deterministically
// from (CA key, objId), so the Identity Service offers a `sign`/`verify` pair that
// models a local asymmetric verify (the seam where Ed25519 slots in).
private void identityKey(uint objId, ubyte* key32) {
    ubyte[4] o; put32(o.ptr, 0, objId);
    hmacSha256(g_caKey.ptr, 32, o.ptr, 4, key32);
}

public void identitySign(uint objId, const(ubyte)* msg, ulong len, ubyte* sig32) {
    ubyte[32] k; identityKey(objId, k.ptr);
    hmacSha256(k.ptr, 32, msg, len, sig32);
}

public bool identityVerifySig(uint objId, const(ubyte)* msg, ulong len,
                              const(ubyte)* sig32) {
    ubyte[32] expect; identitySign(objId, msg, len, expect.ptr);
    return ctEqual32(expect.ptr, sig32);
}

// SHA-256 of the descriptor's bound fields — the transcript anchor both endpoints
// fold into the signed-DH handshake (§2.2 channel binding).
public void secipcDescriptorHash(ref const(SessionDescriptor) d, ubyte* out32) {
    ubyte[50] body_;
    descBody(d, body_.ptr);
    sha256(body_.ptr, 50, out32);
}

// === §1.2 Broker / Key Service ================================================
// Capability Manager policy: authorize A to open a channel to B.
public bool brokerAuthorizePair(uint aId, uint bId) {
    if (aId == 0 || bId == 0) return false;
    foreach (ref pr; g_pairs)
        if (pr.inUse && pr.aId == aId && pr.bId == bId) return true;
    foreach (ref pr; g_pairs) if (!pr.inUse) {
        pr.inUse = true; pr.aId = aId; pr.bId = bId; return true;
    }
    return false;
}

public bool brokerPairAuthorized(uint aId, uint bId) {
    foreach (ref pr; g_pairs)
        if (pr.inUse && pr.aId == aId && pr.bId == bId) return true;
    return false;
}

private ushort pickSuite(ushort prefs) {
    if (prefs & SUITE_CHACHA20POLY1305) return SUITE_CHACHA20POLY1305; // §6 default
    if (prefs & SUITE_AES256GCM)        return SUITE_AES256GCM;
    return 0;
}

private void descBody(ref const(SessionDescriptor) d, ubyte* out50) {
    uint o = put64(out50, 0, d.sessionId);
    o = put32(out50, o, d.aId);
    o = put32(out50, o, d.bId);
    o = put32(out50, o, d.channelCap);
    o = put16(out50, o, d.suite);
    o = put32(out50, o, d.policy);
    o = put64(out50, o, d.epoch);
    o = put64(out50, o, d.notAfter);
    o = put32(out50, o, d.aIdentity);   // §5: identities are signed into the descriptor
    put32(out50, o, d.bIdentity);
}

private void brokerSign(ref SessionDescriptor d) {
    ubyte[50] body_;
    descBody(d, body_.ptr);
    hmacSha256(g_brokerKey.ptr, 32, body_.ptr, 50, d.brokerSig.ptr);
}

// RequestSession(A→B): both identities must be registered with valid, unexpired
// certs; the pair must be authorized; then mint a signed descriptor, allocate the
// channel endpoint, and install the channel capability into A's cap table.  Returns
// true with `out_` filled, or false (denied) leaving sessionId 0.
public bool brokerRequestSession(int tableId, uint aId, uint bId, ushort suitePrefs,
                                 uint channelCapHandle, ulong now, ulong ttl,
                                 SessionDescriptor* out_) {
    if (out_ is null) return false;
    *out_ = SessionDescriptor.init;
    auto ia = idByObj(aId);
    auto ib = idByObj(bId);
    if (ia is null || ib is null) { ++g_sessionDenied; return false; }
    if (!identityVerifyCert(*ia) || !identityVerifyCert(*ib)) { ++g_sessionDenied; return false; }
    if (ia.notAfter <= now || ib.notAfter <= now) { ++g_sessionDenied; return false; }
    if (!brokerPairAuthorized(aId, bId)) { ++g_sessionDenied; return false; }   // cap manager
    ushort suite = pickSuite(suitePrefs);
    if (suite == 0) { ++g_sessionDenied; return false; }

    // IDENTITY_DOMAIN §5: cross-identity policy gate (deny-by-default lives in idipc).
    // Resolves & stamps both security domains; refuses to mint across identities
    // without a rule.  No-op when no gate is installed (identity-agnostic build).
    uint aIdent = 0, bIdent = 0;
    if (g_secipcIdGate !is null && !g_secipcIdGate(aId, bId, &aIdent, &bIdent)) {
        ++g_sessionDenied; return false;
    }

    uint chObj = ipcEndpointAlloc();
    if (chObj == 0) { ++g_sessionDenied; return false; }
    if (capInstallIn(tableId, channelCapHandle, chObj, CAP_RIGHT_CALL, CAP_INVALID)
            == CAP_INVALID) {
        ++g_sessionDenied; return false;
    }

    SessionDescriptor d;
    d.sessionId = ++g_sessionCtr;
    d.aId = aId; d.bId = bId;
    d.aIdentity = aIdent; d.bIdentity = bIdent;   // §5: descriptor carries both domains
    d.channelCap = chObj;
    d.suite = suite;
    d.policy = 0;
    d.epoch = g_revocationEpoch;
    d.notAfter = now + ttl;
    brokerSign(d);
    *out_ = d;
    ++g_sessionTotal;
    return true;
}

private bool sessionRevoked(ulong sessionId) {
    foreach (v; g_revoked) if (v == sessionId) return true;
    return false;
}

// Verify a descriptor (endpoint-side, K3): broker signature checks, not expired, and
// not revoked.  Endpoints call this before trusting a descriptor.
public bool brokerVerifyDescriptor(ref const(SessionDescriptor) d, ulong now) {
    ubyte[50] body_;
    descBody(d, body_.ptr);
    ubyte[32] expect;
    hmacSha256(g_brokerKey.ptr, 32, body_.ptr, 50, expect.ptr);
    if (!ctEqual32(expect.ptr, d.brokerSig.ptr)) { ++g_descReject; return false; }
    if (d.notAfter <= now) { ++g_descReject; return false; }
    if (sessionRevoked(d.sessionId)) { ++g_descReject; return false; }
    return true;
}

public ulong brokerRevocationEpoch() { return g_revocationEpoch; }

// Revoke a session: record it and bump the revocation epoch so endpoints re-checking
// the epoch notice (the kernel cap revoke is `secipcChannelRevoke`, §3.2 full).
public void brokerRevokeSession(ulong sessionId) {
    g_revoked[g_revokedHead] = sessionId;
    g_revokedHead = (g_revokedHead + 1) % SECIPC_REVOKE_MAX;
    ++g_revocationEpoch;
}

// Endpoint admission (K3 partial for Phase 1): the descriptor must verify and name
// this endpoint as one of its two parties.  (Signed-DH peer-auth is Phase 2.)
public bool secipcEndpointAccept(ref const(SessionDescriptor) d, uint selfId, ulong now) {
    if (!brokerVerifyDescriptor(d, now)) return false;
    return d.aId == selfId || d.bId == selfId;
}

// === §1.3 Kernel capability-gated routing (key-free) ==========================
// THE kernel gate: deliver iff the sender holds the channel capability with CALL.
// No crypto, no descriptor parsing — invariant K1.
public bool secipcKernelRoute(int senderTableId, uint channelCapHandle) {
    if (requireCapIn(senderTableId, channelCapHandle, CAP_RIGHT_CALL)) {
        ++g_routeOk; return true;
    }
    ++g_routeDeny; return false;
}

// `channel_revoke`: tear a session's transport by revoking the channel cap
// (transitively); after this `secipcKernelRoute` denies.
public void secipcChannelRevoke(int tableId, uint channelCapHandle) {
    capRevokeIn(tableId, channelCapHandle);
    capClearIn(tableId, channelCapHandle);
}

// === proof ====================================================================
private bool selfTestIdentity(int st, uint oa, uint ob, uint launchH) {  // §1.1
    ubyte[32] pubA; foreach (i; 0 .. 32) pubA[i] = cast(ubyte)(0x10 + i);
    ubyte[32] pubB; foreach (i; 0 .. 32) pubB[i] = cast(ubyte)(0xA0 + i);
    // Registration proving ownership via an EMPTY handle (no cap held) is refused.
    enum uint EMPTY_H = 62;
    bool noCap = !identityRegister(st, oa, pubA.ptr, EMPTY_H, 1000);
    // With the launch cap held at launchH (installed by the caller), registration
    // succeeds and the issued cert verifies.
    bool regA = identityRegister(st, oa, pubA.ptr, launchH, 1000);
    bool regB = identityRegister(st, ob, pubB.ptr, launchH, 1000);
    auto ia = identityLookup(oa);
    bool certOk = (ia !is null && identityVerifyCert(*ia));
    // A tampered cert fails verification.
    ProcIdentity forged = *ia;
    forged.certSig[0] ^= 0x55;
    bool tamper = !identityVerifyCert(forged);
    return noCap && regA && regB && certOk && tamper;
}

private bool selfTestBroker(int st, uint oa, uint ob, uint oc, uint chH,
                            SessionDescriptor* desc) {                    // §1.2
    brokerAuthorizePair(oa, ob);                  // A may talk to B (not to C)
    // Unauthorized pair A→C is refused.
    SessionDescriptor tmp;
    bool unauth = !brokerRequestSession(st, oa, oc, SUITE_CHACHA20POLY1305, chH, 10, 100, &tmp);
    // Authorized A→B yields a signed descriptor + a channel cap in A's table.
    bool ok = brokerRequestSession(st, oa, ob, SUITE_CHACHA20POLY1305 | SUITE_AES256GCM,
                                   chH, 10, 100, desc);
    bool fields = (ok && desc.aId == oa && desc.bId == ob &&
                   desc.suite == SUITE_CHACHA20POLY1305 &&  // strongest of the offer
                   desc.channelCap != 0);
    bool verify = brokerVerifyDescriptor(*desc, 10);        // valid now
    bool accept = secipcEndpointAccept(*desc, ob, 10);      // names B as a party
    // Tampered descriptor (swap parties) fails the broker signature.
    SessionDescriptor t = *desc; t.aId = oc;
    bool tamper = !brokerVerifyDescriptor(t, 10);
    // Expired descriptor (now past notAfter) is refused.
    bool expired = !brokerVerifyDescriptor(*desc, 1000);
    return unauth && fields && verify && accept && tamper && expired;
}

private bool selfTestRouteRevoke(int st, uint chH, SessionDescriptor* desc) { // §1.3
    // The kernel routes while A holds the channel cap (installed by RequestSession).
    bool routeOk = secipcKernelRoute(st, chH);
    // Revoke the session at the broker ⇒ endpoint descriptor check fails.
    brokerRevokeSession(desc.sessionId);
    bool descGone = !brokerVerifyDescriptor(*desc, 10);
    // channel_revoke tears the transport ⇒ the kernel no longer routes.
    secipcChannelRevoke(st, chH);
    bool routeGone = !secipcKernelRoute(st, chH);
    return routeOk && descGone && routeGone;
}

public void secipcSelfTest() {
    if (g_secipcSelfTested) return;
    int st = CAPTAB_COUNT - 2;
    if (capLiveCount(st) != 0) return;   // scratch table busy; retry next tick
    g_secipcSelfTested = true;

    // Three distinct process objects + a launch cap held in the scratch table.
    uint oa = objAlloc(ObjType.Process, null);
    uint ob = objAlloc(ObjType.Process, null);
    uint oc = objAlloc(ObjType.Process, null);
    uint launchObj = objAlloc(ObjType.Process, null);
    enum uint LAUNCH_H = 60;
    enum uint CHAN_H   = 61;

    bool id = false, br = false, rt = false;
    if (oa && ob && oc && launchObj) {
        capInstallIn(st, LAUNCH_H, launchObj, CAP_RIGHT_CALL, CAP_INVALID);
        id = selfTestIdentity(st, oa, ob, LAUNCH_H);
        SessionDescriptor desc;
        br = selfTestBroker(st, oa, ob, oc, CHAN_H, &desc);
        rt = selfTestRouteRevoke(st, CHAN_H, &desc);
    }

    capClearIn(st, LAUNCH_H);
    if (oa) objRelease(oa);
    if (ob) objRelease(ob);
    if (oc) objRelease(oc);
    if (launchObj) objRelease(launchObj);

    if (id && br && rt) {
        klog("[secipc] selftest PASS\n");
    } else {
        klog("[secipc] selftest FAIL:");
        if (!id) klog(" identity");
        if (!br) klog(" broker");
        if (!rt) klog(" route");
        klog("\n");
    }
}

public void secipcStats() {
    klog("[secipc] ids=");   klog_hex(g_regTotal);
    klog(" sessions=");      klog_hex(g_sessionTotal);
    klog(" denied=");        klog_hex(g_sessionDenied);
    klog(" routeok=");       klog_hex(g_routeOk);
    klog(" routedeny=");     klog_hex(g_routeDeny);
    klog(" descreject=");    klog_hex(g_descReject);
    klog(" epoch=");         klog_hex(g_revocationEpoch);
    klog("\n");
}
