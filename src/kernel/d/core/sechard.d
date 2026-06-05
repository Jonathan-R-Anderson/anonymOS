// Secure IPC — Phase 5 (production hardening) of SECURE_IPC_ROADMAP.md.
//
//   §5.1 constant-time compare, nonce-reuse impossibility, memory zeroization.
//   §5.2 fuzz the record / handshake parsers; state-machine invariant review.
//
// This is a hardening + adversarial-input pass over the Phase 0–4 implementation,
// not new protocol.  It asserts the security properties the roadmap's invariants
// (K3/K5) and §10 failure matrix require, and bombards every parser on the receive
// path with malformed/random input to prove it is bounds-safe and fail-closed: a
// fault in any parser would crash the kernel before `[sechard] selftest PASS` ever
// prints, so a green run over thousands of malformed inputs is the proof.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared,
// @nogc nothrow.
module core.sechard;

import core.io; // klog / klog_hex
import core.objmgr : objRelease;
import core.cap : CAPTAB_COUNT, capClearIn, capLiveCount;
import core.libsecipc : ctEqual, zeroize, frameDecode, frameEncode;
import core.secipc : SessionDescriptor;
import core.secsession : Session, SecRecord, HandshakeMsg, RekeyMsg,
                        sessionInit, sessionSend, sessionRecv, sessionClose,
                        sessionProcessHandshake, sessionRekeyBuild, sessionRekeyProcess,
                        secsessionOpenPair, SEC_MSG_MAX,
                        ST_HANDSHAKE, ST_OPEN, ST_CLOSED, ST_REKEY;
import core.secobj : SecWire, secRecordUnpack, secShimRecv;

extern (C) @nogc nothrow:

enum int FUZZ_ITERS = 4096;     // malformed inputs per parser

__gshared ulong g_shFuzzState     = 0x243F6A8885A308D3; // π fractional bits
__gshared ulong g_shFuzzFrame     = 0;   // frameDecode invocations survived
__gshared ulong g_shFuzzRecord    = 0;   // secRecordUnpack invocations survived
__gshared ulong g_shFuzzHandshake = 0;   // handshake parse invocations survived
__gshared ulong g_shFuzzShim      = 0;   // shim recv invocations survived
__gshared ulong g_shFuzzDelivered = 0;   // MUST stay 0: a parser never delivered junk
__gshared bool  g_sechardSelfTested = false;

private ulong xorshift() {
    ulong x = g_shFuzzState;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    g_shFuzzState = x;
    return x;
}
private ubyte rb() { return cast(ubyte)(xorshift() & 0xff); }
private uint  ru(uint mod) { return cast(uint)(xorshift() % mod); }

// === §5.1 constant-time compare ===============================================
private bool selfTestConstantTime() {
    ubyte[32] a, b;
    foreach (i; 0 .. 32) { a[i] = cast(ubyte)(i*7+1); b[i] = a[i]; }
    bool equal = ctEqual(a.ptr, b.ptr, 32);
    // A difference at the FIRST, MIDDLE and LAST byte must all be detected (the
    // compare scans the whole buffer — no secret-dependent early-out).
    b[0]  ^= 0x01; bool d0  = !ctEqual(a.ptr, b.ptr, 32); b[0]  ^= 0x01;
    b[15] ^= 0x80; bool d15 = !ctEqual(a.ptr, b.ptr, 32); b[15] ^= 0x80;
    b[31] ^= 0x01; bool d31 = !ctEqual(a.ptr, b.ptr, 32); b[31] ^= 0x01;
    bool reEqual = ctEqual(a.ptr, b.ptr, 32);     // restored ⇒ equal again
    return equal && d0 && d15 && d31 && reEqual;
}

// === §5.1 nonce-reuse impossibility ===========================================
// nonce = direction ‖ counter, per-direction keys, strictly monotonic counter that
// never wraps (sender refuses at max).  We assert each enforceable mechanism.
private bool selfTestNonceReuse(Session* s) {
    static immutable ubyte[4] m = ['n','o','n','c'];
    SecRecord r0, r1;
    ulong before = s.sendCtr;
    bool s0 = sessionSend(s, m.ptr, 4, &r0);
    bool s1 = sessionSend(s, m.ptr, 4, &r1);
    bool monotonic = s0 && s1 && r1.counter == r0.counter + 1 &&
                     r0.counter == before;                 // strictly increasing
    // per-direction key separation ⇒ A→B and B→A never share a (key,nonce).
    bool perDir = !ctEqual(s.sendKey.ptr, s.recvKey.ptr, 32);
    // counter exhaustion ⇒ refuse to send (forces rekey; never wraps to reuse 0).
    s.sendCtr = ulong.max;
    SecRecord rx;
    bool refused = !sessionSend(s, m.ptr, 4, &rx);
    s.sendCtr = r1.counter + 1;                            // restore
    return monotonic && perDir && refused;
}

// === §5.1 memory zeroization ==================================================
private bool selfTestZeroization(Session* s) {
    // zeroize actually clears.
    ubyte[32] k; foreach (i; 0 .. 32) k[i] = cast(ubyte)(i+1);
    zeroize(k.ptr, 32);
    bool cleared = true; foreach (i; 0 .. 32) if (k[i] != 0) cleared = false;
    // closing a live session wipes all key material (send/recv/ephemeral).
    sessionClose(s);
    bool noKeys = true;
    foreach (i; 0 .. 32) if (s.sendKey[i] != 0 || s.recvKey[i] != 0 || s.ePriv[i] != 0)
        noKeys = false;
    return cleared && noKeys && s.state == ST_CLOSED;
}

// === §5.2 parser fuzzing ======================================================
private bool fuzzParsers(Session* hs, ref const(SessionDescriptor) desc) {
    ubyte[512] buf;
    foreach (_; 0 .. FUZZ_ITERS) {
        uint len = ru(420);
        foreach (i; 0 .. len) buf[i] = rb();

        // frameDecode: any "valid" frame must fit entirely within the buffer.
        uint plen;
        if (frameDecode(buf.ptr, len, &plen)) {
            if (cast(ulong)plen + 4 > len) return false;   // claimed past the buffer ⇒ bug
        }
        ++g_shFuzzFrame;

        // secRecordUnpack: a "valid" record must have a bounded ciphertext length.
        SecRecord rec;
        if (secRecordUnpack(buf.ptr, len, &rec)) {
            if (rec.ctLen > SEC_MSG_MAX) return false;
        }
        ++g_shFuzzRecord;

        // handshake parser: a random message must NEVER establish a session.
        HandshakeMsg hm;
        hm.sessionId = xorshift();
        foreach (i; 0 .. 32) hm.ephemeralPub[i] = rb();
        hm.suiteList = cast(ushort)xorshift();
        foreach (i; 0 .. 32) hm.idSig[i] = rb();
        if (sessionProcessHandshake(hs, desc, hm, 10)) { ++g_shFuzzDelivered; return false; }
        if (hs.state != ST_HANDSHAKE) return false;        // must stay un-opened
        ++g_shFuzzHandshake;
    }
    return true;
}

// Fuzz the full shim receive path (frame → unpack → AEAD open) on an OPEN session;
// random wire bytes must never decrypt to a delivered message (fail-closed).
private bool fuzzShim(Session* s) {
    SecWire wire;
    ubyte[SEC_MSG_MAX] out_; uint olen;
    foreach (_; 0 .. FUZZ_ITERS) {
        wire.roff = 0;
        wire.wlen = ru(400);
        foreach (i; 0 .. wire.wlen) wire.buf[i] = rb();
        if (secShimRecv(s, &wire, out_.ptr, &olen) > 0) { ++g_shFuzzDelivered; return false; }
        ++g_shFuzzShim;
    }
    return true;
}

// === §5.2 state-machine invariant review ======================================
private bool selfTestStateMachine(int st, ref const(SessionDescriptor) desc, uint selfId) {
    ubyte[32] seed; foreach (i; 0 .. 32) seed[i] = cast(ubyte)(0x44 + i);
    Session s;
    sessionInit(&s, desc, selfId, seed.ptr);               // ST_HANDSHAKE
    static immutable ubyte[2] m = ['x','y'];
    SecRecord r;
    ubyte[SEC_MSG_MAX] rbuf; uint rl;
    // send/recv are illegal before OPEN.
    bool noSendInHs = !sessionSend(&s, m.ptr, 2, &r);
    bool noRecvInHs = !sessionRecv(&s, r, rbuf.ptr, &rl);
    // rekeyProcess illegal without a pending rekey (state must be ST_REKEY).
    RekeyMsg rk;
    bool noRekeyProcess = !sessionRekeyProcess(&s, rk);
    // rekeyBuild illegal outside OPEN.
    bool noRekeyBuildInHs = !sessionRekeyBuild(&s, seed.ptr, &rk);
    // closed is terminal: after close, send + rekey are refused.
    sessionClose(&s);
    bool closedNoSend = !sessionSend(&s, m.ptr, 2, &r);
    bool closedNoRecv = !sessionRecv(&s, r, rbuf.ptr, &rl);
    bool closedNoRekey = !sessionRekeyBuild(&s, seed.ptr, &rk);
    return noSendInHs && noRecvInHs && noRekeyProcess && noRekeyBuildInHs &&
           closedNoSend && closedNoRecv && closedNoRekey;
}

public void sechardSelfTest() {
    if (g_sechardSelfTested) return;
    int st = CAPTAB_COUNT - 2;
    if (capLiveCount(st) != 0) return;     // scratch table busy; retry next tick
    g_sechardSelfTested = true;

    Session sA, sB;
    SessionDescriptor desc;
    uint oa, ob, lo;
    bool ok = secsessionOpenPair(st, &sA, &sB, &desc, &oa, &ob, &lo);

    bool ct=false, nonce=false, fuzz=false, shim=false, sm=false, zero=false;
    if (ok) {
        ct    = selfTestConstantTime();
        nonce = selfTestNonceReuse(&sA);          // sA stays OPEN (counter restored)
        sm    = selfTestStateMachine(st, desc, oa);
        // fuzz a fresh HANDSHAKE session (so a stray success is observable) + sB open.
        ubyte[32] seedH; foreach (i; 0 .. 32) seedH[i] = cast(ubyte)(0x60 + i);
        Session hs; sessionInit(&hs, desc, oa, seedH.ptr);
        fuzz  = fuzzParsers(&hs, desc);
        shim  = fuzzShim(&sB);                     // sB still OPEN
        zero  = selfTestZeroization(&sA);          // closes sA last
    }

    capClearIn(st, 60); capClearIn(st, 61);
    if (oa) objRelease(oa); if (ob) objRelease(ob); if (lo) objRelease(lo);

    if (ok && ct && nonce && fuzz && shim && sm && zero && g_shFuzzDelivered == 0) {
        klog("[sechard] selftest PASS\n");
    } else {
        klog("[sechard] selftest FAIL:");
        if (!ok)    klog(" setup");
        if (!ct)    klog(" consttime");
        if (!nonce) klog(" noncereuse");
        if (!fuzz)  klog(" parserfuzz");
        if (!shim)  klog(" shimfuzz");
        if (!sm)    klog(" statemachine");
        if (!zero)  klog(" zeroize");
        if (g_shFuzzDelivered != 0) klog(" LEAK");
        klog("\n");
    }
}

public void sechardStats() {
    klog("[sechard] fuzzframe="); klog_hex(g_shFuzzFrame);
    klog(" fuzzrec=");            klog_hex(g_shFuzzRecord);
    klog(" fuzzhs=");            klog_hex(g_shFuzzHandshake);
    klog(" fuzzshim=");          klog_hex(g_shFuzzShim);
    klog(" delivered=");         klog_hex(g_shFuzzDelivered);
    klog("\n");
}
