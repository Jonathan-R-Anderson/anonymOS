// Distributed OS integration — IMMUTABLE_ROOTLESS_ROADMAP §9.
//
// Extends the object tree, capabilities and content store across nodes, built on
// the ORG federation seams (`core/org_dist.d`'s OrgRef + leased edges), the §8.1
// crypto, and the §4 content store:
//
//   §9.1 network-transparent object references — a global handle (node:obj:epoch)
//        is addressed identically whether local or remote; `dosResolve` returns a
//        live local object or *routes* a remote ref to its node (Plan 9 9P-style),
//        with a node registry so an unknown node never routes.
//   §9.2 capability delegation across nodes — unforgeable, attenuable **macaroon**
//        tokens: HMAC-SHA-256 chained over an identifier + narrowing caveats (the
//        §8.1 primitive).  A holder can only *narrow* rights; tampering, a wrong
//        key, or a replayed nonce all fail verification.
//   §9.3 distributed content-addressed store — `dosFetch(digest)` returns the local
//        object if present (natural dedup, no transfer) else fetches a peer's bytes
//        and accepts them only if they hash to the requested digest (content
//        addressing self-verifies integrity; a lying peer is rejected).
//
// No real NIC traffic is issued here — there is one kernel — but every locality,
// routing, signature, attenuation, replay and integrity *decision* is real and
// self-tested; the transport is the remaining integration.  Constraints mirror the
// rest of the kernel: -betterC, plain structs, __gshared, @nogc nothrow.
module core.distos;

import core.io; // klog / klog_hex
import core.org_dist : OrgRef, orgRefLocal, orgRefMake, orgRefIsLocal,
                       orgRefResolves, ORG_SELF_NODE;
import core.crypto : hmacSha256, ctEqual32, sha256, g_trustedKey;
import core.store : storePut, storeLookup, storeRoot, Digest256, storeDigestEqual;
import core.objmgr : ObjType, objAlloc, objRelease;

extern (C) @nogc nothrow:

enum int DOS_NODE_MAX   = 16;   // known peer nodes
enum int DOS_PEER_MAX   = 32;   // peer-published content advertisements
enum int DOS_PEER_BYTES = 64;   // bytes cached per advertisement (proof scale)
enum int MAC_CAVEAT_MAX = 4;    // attenuation caveats per macaroon
enum int DOS_NONCE_MAX  = 64;   // remembered nonces (replay window)

// --- §9.1 node registry + network-transparent references ----------------------
struct NodeRec {
    bool inUse;
    uint nodeId;
    bool reachable;
}
__gshared NodeRec[DOS_NODE_MAX] g_nodes;

__gshared ulong g_dosLocalResolve  = 0;
__gshared ulong g_dosRemoteRoute   = 0;
__gshared ulong g_dosRouteFail     = 0;
__gshared bool  g_dosSelfTested    = false;

public uint dosLocalNode() { return ORG_SELF_NODE; }

public bool dosRegisterNode(uint nodeId, bool reachable) {
    if (nodeId == ORG_SELF_NODE) return false;     // self is implicit
    foreach (ref n; g_nodes)
        if (n.inUse && n.nodeId == nodeId) { n.reachable = reachable; return true; }
    foreach (ref n; g_nodes) {
        if (n.inUse) continue;
        n.inUse = true; n.nodeId = nodeId; n.reachable = reachable;
        return true;
    }
    return false;
}

private NodeRec* nodeBy(uint nodeId) {
    foreach (ref n; g_nodes) if (n.inUse && n.nodeId == nodeId) return &n;
    return null;
}

// Resolve a network-transparent reference.  A local ref yields its live object id
// (or 0 if dead); a remote ref yields 0 and sets `*routeNode` to the node it must be
// sent to (only if that node is registered and reachable) — same handle type either
// way (the network-transparency property).  Returns the local object id, or 0.
public uint dosResolve(OrgRef r, uint* routeNode) {
    if (routeNode !is null) *routeNode = ORG_SELF_NODE;
    if (orgRefIsLocal(r)) {
        if (orgRefResolves(r)) { ++g_dosLocalResolve; return r.objId; }
        return 0;                                   // local but dead
    }
    auto n = nodeBy(r.nodeId);
    if (n is null || !n.reachable) { ++g_dosRouteFail; return 0; }
    if (routeNode !is null) *routeNode = r.nodeId;
    ++g_dosRemoteRoute;                             // routed to the owning node
    return 0;
}

// Make a network-transparent handle for an object on a peer node.
public OrgRef dosImportRemote(uint nodeId, uint remoteObjId, uint epoch) {
    return orgRefMake(nodeId, remoteObjId, epoch);
}

// --- §9.2 cross-node capability delegation (macaroons) ------------------------
struct Macaroon {
    uint      capObjId;                 // target object (identifier)
    uint      nodeId;                   // issuing node
    ulong     nonce;                    // replay protection
    uint      rootRights;              // rights at mint
    uint      caveatCount;
    uint[MAC_CAVEAT_MAX] caveatRights;  // each caveat narrows the rights
    ubyte[32] sig;                      // HMAC chain tag
}

__gshared ulong[DOS_NONCE_MAX] g_nonceSeen;
__gshared uint  g_nonceHead = 0;
__gshared ulong g_macMinted   = 0;
__gshared ulong g_macAtten    = 0;
__gshared ulong g_macVerifyOk = 0;
__gshared ulong g_macVerifyNo = 0;
__gshared ulong g_macReplay   = 0;

// Serialize the macaroon identifier (the part bound at mint).
private void macIdentifier(ref const(Macaroon) m, ubyte* buf20) {
    buf20[0]=cast(ubyte)(m.capObjId); buf20[1]=cast(ubyte)(m.capObjId>>8);
    buf20[2]=cast(ubyte)(m.capObjId>>16); buf20[3]=cast(ubyte)(m.capObjId>>24);
    buf20[4]=cast(ubyte)(m.nodeId); buf20[5]=cast(ubyte)(m.nodeId>>8);
    buf20[6]=cast(ubyte)(m.nodeId>>16); buf20[7]=cast(ubyte)(m.nodeId>>24);
    foreach (i; 0 .. 8) buf20[8+i] = cast(ubyte)(m.nonce >> (i*8));
    buf20[16]=cast(ubyte)(m.rootRights); buf20[17]=cast(ubyte)(m.rootRights>>8);
    buf20[18]=cast(ubyte)(m.rootRights>>16); buf20[19]=cast(ubyte)(m.rootRights>>24);
}

// Recompute the HMAC chain tag from the trusted root key + identifier + caveats.
private void macComputeSig(ref const(Macaroon) m, ubyte* out32) {
    ubyte[20] id;
    macIdentifier(m, id.ptr);
    ubyte[32] sig;
    hmacSha256(g_trustedKey.ptr, 32, id.ptr, 20, sig.ptr);   // sig0 = HMAC(rootKey, id)
    foreach (k; 0 .. m.caveatCount) {
        ubyte[4] c;
        c[0]=cast(ubyte)(m.caveatRights[k]); c[1]=cast(ubyte)(m.caveatRights[k]>>8);
        c[2]=cast(ubyte)(m.caveatRights[k]>>16); c[3]=cast(ubyte)(m.caveatRights[k]>>24);
        ubyte[32] next;
        hmacSha256(sig.ptr, 32, c.ptr, 4, next.ptr);         // sig_{i+1} = HMAC(sig_i, caveat)
        foreach (i; 0 .. 32) sig[i] = next[i];
    }
    foreach (i; 0 .. 32) out32[i] = sig[i];
}

// Mint a root macaroon for `capObjId` on `nodeId` granting `rights`.
public Macaroon macaroonMint(uint capObjId, uint nodeId, uint rights, ulong nonce) {
    Macaroon m;
    m.capObjId = capObjId; m.nodeId = nodeId; m.nonce = nonce;
    m.rootRights = rights; m.caveatCount = 0;
    macComputeSig(m, m.sig.ptr);
    ++g_macMinted;
    return m;
}

// Attenuate (delegate): append a narrowing caveat and re-chain the tag.  A caveat
// can only *remove* rights; widening is impossible because the verifier ANDs them.
public Macaroon macaroonAttenuate(ref const(Macaroon) m, uint narrowRights) {
    Macaroon d = m;
    if (d.caveatCount < MAC_CAVEAT_MAX) {
        d.caveatRights[d.caveatCount] = narrowRights;
        ++d.caveatCount;
        macComputeSig(d, d.sig.ptr);
        ++g_macAtten;
    }
    return d;
}

// Effective rights = root rights with every caveat ANDed in (monotonically narrows).
public uint macaroonRights(ref const(Macaroon) m) {
    uint r = m.rootRights;
    foreach (k; 0 .. m.caveatCount) r &= m.caveatRights[k];
    return r;
}

// Verify the tag chains correctly from the trusted key (unforgeable + tamper-evident).
public bool macaroonVerify(ref const(Macaroon) m) {
    ubyte[32] expect;
    macComputeSig(m, expect.ptr);
    bool ok = ctEqual32(expect.ptr, m.sig.ptr);
    if (ok) ++g_macVerifyOk; else ++g_macVerifyNo;
    return ok;
}

private bool nonceSeen(ulong nonce) {
    foreach (v; g_nonceSeen) if (v == nonce) return true;
    return false;
}

// Verify AND consume the nonce: a valid macaroon presented a second time with the
// same nonce is rejected (replay protection).
public bool macaroonVerifyConsume(ref const(Macaroon) m) {
    if (!macaroonVerify(m)) return false;
    if (nonceSeen(m.nonce)) { ++g_macReplay; return false; }
    g_nonceSeen[g_nonceHead] = m.nonce;
    g_nonceHead = (g_nonceHead + 1) % DOS_NONCE_MAX;
    return true;
}

// --- §9.3 distributed content-addressed store ---------------------------------
struct PeerContent {
    bool      inUse;
    uint      nodeId;
    Digest256 advertised;            // the digest the peer claims to serve
    uint      len;
    ubyte[DOS_PEER_BYTES] bytes;     // the bytes it would actually return
}
__gshared PeerContent[DOS_PEER_MAX] g_peerContent;

__gshared ulong g_dosFetchLocal   = 0;  // satisfied locally (dedup, no transfer)
__gshared ulong g_dosFetchRemote  = 0;  // bytes fetched from a peer + verified
__gshared ulong g_dosFetchReject  = 0;  // peer bytes failed the content-hash check
__gshared ulong g_dosFetchMiss    = 0;  // no peer advertises the digest

// A peer advertises content it will serve.  `advertised` is what it claims; `bytes`
// is what it actually returns (a lying peer sets them inconsistent — caught on fetch).
public bool dosPeerPublish(uint nodeId, ref const(Digest256) advertised,
                           const(ubyte)* bytes, uint len) {
    if (len > DOS_PEER_BYTES) return false;
    foreach (ref p; g_peerContent) {
        if (p.inUse) continue;
        p.inUse = true; p.nodeId = nodeId; p.advertised = advertised; p.len = len;
        foreach (i; 0 .. len) p.bytes[i] = bytes[i];
        return true;
    }
    return false;
}

// Fetch content by digest: local hit ⇒ dedup (no transfer); else pull a peer's
// bytes and accept only if sha256(bytes) == requested digest (content-addressing
// self-verifies — a tampered/lying peer is rejected).  Returns the local store
// object id, or 0 on miss/reject.
public uint dosFetch(ref const(Digest256) digest, uint len) {
    uint local = storeLookup(digest, len);
    if (local != 0) { ++g_dosFetchLocal; return local; }   // already have it (dedup)
    foreach (ref p; g_peerContent) {
        if (!p.inUse || p.len != len) continue;
        if (!storeDigestEqual(p.advertised, digest)) continue;
        Digest256 actual;
        sha256(p.bytes.ptr, len, cast(ubyte*)&actual);
        if (!storeDigestEqual(actual, digest)) { ++g_dosFetchReject; return 0; } // lying peer
        uint id = storePut(p.bytes.ptr, len);
        if (id != 0) ++g_dosFetchRemote;
        return id;
    }
    ++g_dosFetchMiss;
    return 0;
}

// --- proof --------------------------------------------------------------------
private bool selfTestRefs() {                 // §9.1
    dosRegisterNode(7, true);                 // a reachable peer
    dosRegisterNode(9, false);                // a known-but-unreachable peer
    // A local ref to a live object resolves to that object id; once the object is
    // released the same ref no longer resolves.
    uint someLive = objAlloc(ObjType.MemRegion, null);
    OrgRef loc = orgRefLocal(someLive);
    uint rn;
    uint got = dosResolve(loc, &rn);
    bool localOk = (someLive != 0 && got == someLive && orgRefIsLocal(loc) &&
                    rn == ORG_SELF_NODE);
    objRelease(someLive);
    uint rn2;
    bool deadFails = (dosResolve(orgRefLocal(someLive), &rn2) == 0);
    localOk = localOk && deadFails;
    // A remote ref does not resolve locally but routes to its (reachable) node.
    OrgRef rem = dosImportRemote(7, 42, 1);
    uint rrn;
    bool remoteRoutes = (dosResolve(rem, &rrn) == 0 && rrn == 7 && !orgRefIsLocal(rem));
    // An unreachable / unknown node never routes.
    OrgRef bad = dosImportRemote(9, 42, 1);
    uint brn;
    bool unreachable = (dosResolve(bad, &brn) == 0 && brn == ORG_SELF_NODE);
    OrgRef unknown = dosImportRemote(13, 42, 1);
    uint urn;
    bool unknownFails = (dosResolve(unknown, &urn) == 0 && urn == ORG_SELF_NODE);
    return localOk && remoteRoutes && unreachable && unknownFails;
}

private bool selfTestMacaroons() {            // §9.2
    enum uint R_RW = 0x3, R_R = 0x1;
    Macaroon root = macaroonMint(100, 7, R_RW, 0xA1B2C3D4);
    bool rootOk = macaroonVerify(root) && macaroonRights(root) == R_RW;
    // Attenuate read-write → read-only: verifies, and effective rights narrowed.
    Macaroon ro = macaroonAttenuate(root, R_R);
    bool attenOk = macaroonVerify(ro) && macaroonRights(ro) == R_R;
    // Tampering the rights/caveat without re-chaining the tag fails verification.
    Macaroon forgedRights = ro;
    forgedRights.caveatRights[0] = R_RW;      // try to widen back
    bool widenFails = !macaroonVerify(forgedRights);
    // Tampering the signature fails.
    Macaroon forgedSig = root;
    forgedSig.sig[0] ^= 0x40;
    bool sigFails = !macaroonVerify(forgedSig);
    // Replay: first consume succeeds, second with the same nonce is rejected.
    Macaroon once = macaroonMint(101, 7, R_RW, 0x5151AA55);
    bool firstUse = macaroonVerifyConsume(once);
    bool replayBlocked = !macaroonVerifyConsume(once);
    return rootOk && attenOk && widenFails && sigFails && firstUse && replayBlocked;
}

private bool selfTestDistStore() {            // §9.3
    static immutable ubyte[10] content = ['p','e','e','r','-','b','l','o','b','1'];
    Digest256 dg;
    sha256(content.ptr, content.length, cast(ubyte*)&dg);
    // Before anyone publishes it, a fetch misses.
    bool missFirst = (dosFetch(dg, content.length) == 0);
    // A peer advertises the content honestly; fetch pulls + verifies + inserts.
    dosPeerPublish(7, dg, content.ptr, content.length);
    uint got = dosFetch(dg, content.length);
    Digest256 gotRoot = storeRoot(got);
    bool fetched = (got != 0 && storeDigestEqual(gotRoot, dg));
    // A second fetch is a local dedup hit (no transfer).
    ulong remoteBefore = g_dosFetchRemote;
    uint again = dosFetch(dg, content.length);
    bool dedup = (again == got && g_dosFetchRemote == remoteBefore);
    // A lying peer (advertises dg but serves different bytes) is rejected on the
    // content-hash check.
    static immutable ubyte[10] other = ['p','e','e','r','-','b','l','o','b','2'];
    Digest256 dg2;
    sha256(other.ptr, other.length, cast(ubyte*)&dg2);
    dosPeerPublish(9, dg2, content.ptr, content.length); // advertises dg2, serves blob1
    bool liarRejected = (dosFetch(dg2, other.length) == 0);
    return missFirst && fetched && dedup && liarRejected;
}

public void distosSelfTest() {
    if (g_dosSelfTested) return;
    g_dosSelfTested = true;
    bool refs = selfTestRefs();
    bool mac  = selfTestMacaroons();
    bool ds   = selfTestDistStore();
    if (refs && mac && ds) {
        klog("[distos] selftest PASS\n");
    } else {
        klog("[distos] selftest FAIL:");
        if (!refs) klog(" refs");
        if (!mac)  klog(" macaroon");
        if (!ds)   klog(" diststore");
        klog("\n");
    }
}

public void distosStats() {
    klog("[distos] locres="); klog_hex(g_dosLocalResolve);
    klog(" route=");          klog_hex(g_dosRemoteRoute);
    klog(" routefail=");      klog_hex(g_dosRouteFail);
    klog(" macok=");          klog_hex(g_macVerifyOk);
    klog(" macno=");          klog_hex(g_macVerifyNo);
    klog(" replay=");         klog_hex(g_macReplay);
    klog(" fetchloc=");       klog_hex(g_dosFetchLocal);
    klog(" fetchrem=");       klog_hex(g_dosFetchRemote);
    klog(" fetchrej=");       klog_hex(g_dosFetchReject);
    klog("\n");
}
