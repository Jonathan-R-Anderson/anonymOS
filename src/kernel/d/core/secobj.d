// Secure IPC — Phase 4 (object-tree + Linux-compat integration) of SECURE_IPC_ROADMAP.md.
//
//   §4.1 channel / session / identity cert / descriptor are first-class **objects**
//        in the tree (`ObjType.SecChannel/SecSession/SecCert/SecDescriptor`), and the
//        authority to open a channel to a peer is a **capability to the SecChannel
//        object**, delegated downward and **narrowed** parent→child via
//        `capDeriveObjectToIn` (a child can only ever hold ⊆ the parent's IPC reach;
//        widening is refused).
//   §4.2 Linux-compat shim — a Linux app uses ordinary `send`/`recv` over a normal
//        socket fd and the library does the AEAD **transparently**: `secShimSend`
//        seals + frames the message onto the wire (ciphertext only), `secShimRecv`
//        deframes + opens it.  No new Linux syscalls; the broker is a service object
//        reachable by name (Phase 1).
//
// Built on the object manager, the capability tables, the Phase-2/3 `Session`, and the
// §0 libsecipc framing — all already in the tree.  Constraints mirror the rest of the
// kernel: -betterC, plain structs, __gshared, @nogc nothrow.
module core.secobj;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objRelease, objCountType;
import core.cap : CAPTAB_COUNT, capInstallIn, capDeriveObjectToIn, capGetIn,
                  capUsable, capClearIn, capLiveCount, Capability,
                  CAP_RIGHT_CALL, CAP_RIGHT_READ, CAP_INVALID;
import core.secipc : SessionDescriptor;
import core.secsession : Session, SecRecord, sessionSend, sessionRecv,
                        secsessionOpenPair, SEC_MSG_MAX;
import core.libsecipc : frameEncode, frameDecode;

extern (C) @nogc nothrow:

enum int SECOBJ_CHAN_MAX = 32;

// === §4.1 secure-IPC objects ==================================================
struct SecChannelRec {
    bool  inUse;
    uint  objId;          // ObjType.SecChannel
    uint  aId, bId;       // the two process objects this channel connects
    uint  endpointObjId;  // the underlying IPC Endpoint (transport)
}
__gshared SecChannelRec[SECOBJ_CHAN_MAX] g_secChannels;

__gshared ulong g_secObjCreated = 0;
__gshared ulong g_pairNarrowed  = 0;   // §4.1 parent→child IPC-cap narrowings
__gshared ulong g_pairWidenDeny = 0;   // attempts to widen IPC authority, refused
__gshared ulong g_shimSent      = 0;
__gshared ulong g_shimRecv      = 0;
__gshared ulong g_shimCipher    = 0;   // sends verified to put ciphertext (not plaintext) on the wire
__gshared bool  g_secObjSelfTested = false;

// A secure channel as a tree object (carries its endpoint + the connected parties).
public uint secChannelObject(uint aId, uint bId, uint endpointObjId) {
    foreach (ref e; g_secChannels) {
        if (e.inUse) continue;
        uint id = objAlloc(ObjType.SecChannel, cast(void*)&e);
        if (id == 0) return 0;
        e = SecChannelRec.init;
        e.inUse = true; e.objId = id; e.aId = aId; e.bId = bId; e.endpointObjId = endpointObjId;
        ++g_secObjCreated;
        return id;
    }
    return 0;
}

// Session / cert / descriptor as tree objects (metadata only — a SecSession holds NO
// keys; those never leave the endpoint).
public uint secSessionObject(ulong sessionId, uint aId, uint bId, uint channelObjId) {
    uint id = objAlloc(ObjType.SecSession, null);
    if (id != 0) ++g_secObjCreated;
    return id;
}
public uint secCertObject(uint procObjId) {
    uint id = objAlloc(ObjType.SecCert, null);
    if (id != 0) ++g_secObjCreated;
    return id;
}
public uint secDescriptorObject(ref const(SessionDescriptor) d) {
    uint id = objAlloc(ObjType.SecDescriptor, null);
    if (id != 0) ++g_secObjCreated;
    return id;
}

// IPC-pair authority = a capability to the SecChannel object with CAP_RIGHT_CALL.
public uint ipcPairInstall(int tableId, uint handle, uint channelObjId) {
    return capInstallIn(tableId, handle, channelObjId, CAP_RIGHT_CALL, CAP_INVALID);
}

// Delegate the authority downward, narrowing to `subsetRights` (a child can never
// hold more than the parent — `capDeriveObjectToIn` refuses to widen).
public uint ipcPairDerive(int tableId, uint parentHandle, uint childHandle,
                          uint channelObjId, uint subsetRights) {
    uint h = capDeriveObjectToIn(tableId, parentHandle, childHandle, channelObjId, subsetRights);
    if (h == CAP_INVALID) ++g_pairWidenDeny; else ++g_pairNarrowed;
    return h;
}

// True iff the table's `handle` is authority to use exactly `channelObjId` (CALL).
public bool ipcPairMayUse(int tableId, uint handle, uint channelObjId) {
    auto cap = capGetIn(tableId, handle);
    return capUsable(cap) && cap.objId == channelObjId &&
           (cap.rights & CAP_RIGHT_CALL) == CAP_RIGHT_CALL;
}

// === §4.2 Linux-compat shim: transparent AEAD over a socket fd ================
// The "wire" stands in for the socketpair / memfd ciphertext ring; a Linux app's
// send()/recv() map onto secShimSend/secShimRecv with no new syscalls.
enum int SHIM_RING = 2048;
struct SecWire { ubyte[SHIM_RING] buf; uint wlen; uint roff; }

private enum int SEC_REC_HDR = 8+8+8+1+8+4;   // sessionId,epoch,keyGen,dir,counter,ctLen

private uint p64(ubyte* b, uint o, ulong v){ foreach(i;0..8) b[o+i]=cast(ubyte)(v>>(i*8)); return o+8; }
private uint p32(ubyte* b, uint o, uint v){ foreach(i;0..4) b[o+i]=cast(ubyte)(v>>(i*8)); return o+4; }
private ulong g64(const(ubyte)* b, uint o){ ulong v=0; foreach(i;0..8) v|=cast(ulong)b[o+i]<<(i*8); return v; }
private uint  g32(const(ubyte)* b, uint o){ uint v=0; foreach(i;0..4) v|=cast(uint)b[o+i]<<(i*8); return v; }

// Serialize a record for the wire.
public uint secRecordPack(ref const(SecRecord) r, ubyte* out_) {
    uint o = p64(out_, 0, r.sessionId);
    o = p64(out_, o, r.epoch);
    o = p64(out_, o, r.keyGen);
    out_[o++] = r.dir;
    o = p64(out_, o, r.counter);
    o = p32(out_, o, r.ctLen);
    foreach (i; 0 .. r.ctLen) out_[o+i] = r.ct[i];
    o += r.ctLen;
    foreach (i; 0 .. 16) out_[o+i] = r.tag[i];
    return o + 16;
}

public bool secRecordUnpack(const(ubyte)* b, uint len, SecRecord* r) {
    if (len < SEC_REC_HDR + 16) return false;
    *r = SecRecord.init;
    uint o = 0;
    r.sessionId = g64(b,o); o+=8;
    r.epoch     = g64(b,o); o+=8;
    r.keyGen    = g64(b,o); o+=8;
    r.dir       = b[o++];
    r.counter   = g64(b,o); o+=8;
    r.ctLen     = g32(b,o); o+=4;
    if (r.ctLen > SEC_MSG_MAX) return false;
    if (len != SEC_REC_HDR + r.ctLen + 16) return false;
    foreach (i; 0 .. r.ctLen) r.ct[i] = b[o+i];
    o += r.ctLen;
    foreach (i; 0 .. 16) r.tag[i] = b[o+i];
    return true;
}

// Linux app send(): seal the plaintext into a record and frame it onto the wire.
public long secShimSend(Session* s, SecWire* w, const(ubyte)* pt, uint len) {
    SecRecord rec;
    if (!sessionSend(s, pt, len, &rec)) return -1;
    ubyte[SEC_REC_HDR + SEC_MSG_MAX + 16] wirebuf;
    uint rl = secRecordPack(rec, wirebuf.ptr);
    ulong fl = frameEncode(wirebuf.ptr, rl, w.buf.ptr + w.wlen,
                           cast(ulong)(SHIM_RING - w.wlen));
    if (fl == 0) return -1;
    w.wlen += cast(uint)fl;
    ++g_shimSent;
    return len;
}

// Linux app recv(): deframe the next record off the wire and open it (AEAD).
public long secShimRecv(Session* s, SecWire* w, ubyte* outBuf, uint* outLen) {
    if (w.roff + 4 > w.wlen) return -1;             // no complete frame
    uint plen;
    if (!frameDecode(w.buf.ptr + w.roff, w.wlen - w.roff, &plen)) return -1;
    SecRecord rec;
    bool unpacked = secRecordUnpack(w.buf.ptr + w.roff + 4, plen, &rec);
    w.roff += 4 + plen;                              // consume the frame
    if (!unpacked) return -1;
    if (!sessionRecv(s, rec, outBuf, outLen)) return -1;
    ++g_shimRecv;
    return cast(long)(*outLen);
}

private bool wireContains(SecWire* w, const(ubyte)* pat, uint plen) {
    if (plen == 0 || w.wlen < plen) return false;
    for (uint i = 0; i + plen <= w.wlen; ++i) {
        bool m = true;
        foreach (j; 0 .. plen) if (w.buf[i+j] != pat[j]) { m = false; break; }
        if (m) return true;
    }
    return false;
}

// === proof ====================================================================
private bool selfTestObjects(uint oa, uint ob, ref const(SessionDescriptor) d) { // §4.1
    uint ch   = secChannelObject(oa, ob, d.channelCap);
    uint sess = secSessionObject(d.sessionId, oa, ob, ch);
    uint cert = secCertObject(oa);
    uint dsc  = secDescriptorObject(d);
    if (ch==0 || sess==0 || cert==0 || dsc==0) return false;
    // each is a live, correctly-typed tree object.
    auto hc = objGet(ch); auto hs = objGet(sess); auto hk = objGet(cert); auto hd = objGet(dsc);
    bool typed = (hc !is null && hc.type == ObjType.SecChannel &&
                  hs !is null && hs.type == ObjType.SecSession &&
                  hk !is null && hk.type == ObjType.SecCert &&
                  hd !is null && hd.type == ObjType.SecDescriptor);
    objRelease(ch); objRelease(sess); objRelease(cert); objRelease(dsc);
    return typed;
}

private bool selfTestPairCap(int st, uint channelObjId) {   // §4.1 parent ⊇ child
    enum uint P=50, CHILD_OK=51, CHILD_WIDE=52, CHILD_NONE=53;
    // parent holds the IPC-pair cap (CALL) to the channel.
    if (ipcPairInstall(st, P, channelObjId) == CAP_INVALID) return false;
    bool parentUses = ipcPairMayUse(st, P, channelObjId);
    // narrow to a child keeping CALL: allowed, child can use it.
    bool childOk = (ipcPairDerive(st, P, CHILD_OK, channelObjId, CAP_RIGHT_CALL) != CAP_INVALID)
                   && ipcPairMayUse(st, CHILD_OK, channelObjId);
    // attempt to WIDEN (parent has only CALL, ask for CALL|READ): refused.
    bool widenDenied = (ipcPairDerive(st, P, CHILD_WIDE, channelObjId,
                                      CAP_RIGHT_CALL | CAP_RIGHT_READ) == CAP_INVALID);
    // narrow to NO call: child holds the cap but cannot use the channel.
    bool childNone = (ipcPairDerive(st, P, CHILD_NONE, channelObjId, 0) != CAP_INVALID)
                     && !ipcPairMayUse(st, CHILD_NONE, channelObjId);
    capClearIn(st, P); capClearIn(st, CHILD_OK);
    capClearIn(st, CHILD_WIDE); capClearIn(st, CHILD_NONE);
    return parentUses && childOk && widenDenied && childNone;
}

private bool selfTestShim(Session* sA, Session* sB) {       // §4.2
    static immutable ubyte[10] secret = ['t','o','p','s','e','c','r','e','t','!'];
    SecWire wire;            // shared "socket" between A and B
    wire.wlen = 0; wire.roff = 0;
    // A sends via the shim; the wire must carry ciphertext, never the plaintext.
    bool sent = (secShimSend(sA, &wire, secret.ptr, 10) == 10);
    bool ciphertext = !wireContains(&wire, secret.ptr, 10);
    if (ciphertext) ++g_shimCipher;
    // B recvs via the shim and recovers the plaintext transparently.
    ubyte[SEC_MSG_MAX] buf; uint bl;
    bool got = (secShimRecv(sB, &wire, buf.ptr, &bl) == 10) && bl == 10;
    bool match = true; foreach (i; 0 .. 10) if (buf[i] != secret[i]) match = false;
    // reverse direction round-trips too.
    static immutable ubyte[3] back = ['a','c','k'];
    bool s2 = (secShimSend(sB, &wire, back.ptr, 3) == 3);
    bool r2 = (secShimRecv(sA, &wire, buf.ptr, &bl) == 3) && bl == 3 &&
              buf[0]=='a' && buf[1]=='c' && buf[2]=='k';
    return sent && ciphertext && got && match && s2 && r2;
}

public void secobjSelfTest() {
    if (g_secObjSelfTested) return;
    int st = CAPTAB_COUNT - 2;
    if (capLiveCount(st) != 0) return;     // scratch table busy; retry next tick
    g_secObjSelfTested = true;

    Session sA, sB;
    SessionDescriptor desc;
    uint oa, ob, lo;
    bool ok = secsessionOpenPair(st, &sA, &sB, &desc, &oa, &ob, &lo);

    bool objs=false, pair=false, shim=false;
    if (ok) {
        objs = selfTestObjects(oa, ob, desc);
        uint ch = secChannelObject(oa, ob, desc.channelCap);  // channel for the cap test
        pair = (ch != 0) && selfTestPairCap(st, ch);
        if (ch) objRelease(ch);
        shim = selfTestShim(&sA, &sB);
    }

    capClearIn(st, 60); capClearIn(st, 61);   // handles used by secsessionOpenPair
    if (oa) objRelease(oa); if (ob) objRelease(ob); if (lo) objRelease(lo);

    if (ok && objs && pair && shim) {
        klog("[secobj] selftest PASS\n");
    } else {
        klog("[secobj] selftest FAIL:");
        if (!ok)   klog(" setup");
        if (!objs) klog(" objects");
        if (!pair) klog(" paircap");
        if (!shim) klog(" shim");
        klog("\n");
    }
}

public void secobjStats() {
    klog("[secobj] chanobj="); klog_hex(cast(ulong)objCountType(ObjType.SecChannel));
    klog(" created=");         klog_hex(g_secObjCreated);
    klog(" narrow=");          klog_hex(g_pairNarrowed);
    klog(" widendeny=");       klog_hex(g_pairWidenDeny);
    klog(" shimsent=");        klog_hex(g_shimSent);
    klog(" shimrecv=");        klog_hex(g_shimRecv);
    klog(" cipherwire=");      klog_hex(g_shimCipher);
    klog("\n");
}
