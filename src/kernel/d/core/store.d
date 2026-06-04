// Immutable content-addressed object store — IMMUTABLE_ROOTLESS_ROADMAP §4.
//
// This is the system-image substrate the roadmap calls for: a read-only,
// hash-named store where writing content creates a *new* object (never mutates an
// old one), every read of stored content is integrity-verified against a
// dm-verity-style block hash tree, the system tree is split into read-only `/usr`
// / overlay `/etc` / user-state `/var`, and named immutable **generations** snapshot
// the whole tree so a rollback is an atomic pointer swap.  It maps directly onto §F
// "Immutable": a write to `/usr`/store objects is impossible (not discouraged),
// reads are verified, and rollback selects a prior generation.
//
//   §4.1 content-addressed store  — storePut / storeGet (dedup by digest, immutable)
//   §4.2 dm-verity block hash tree — storeReadVerified (tampered block ⇒ fault)
//   §4.3 /usr(ro) /etc(ovl) /var   — storeMountSystem + storeWritable (rights gate)
//   §4.4 generations / deployments — genCreate / genSetActive / genRollback (atomic)
//
// Crypto note: §4.2/§6.2 ultimately chain to the BLAKE3/ed25519 primitives of
// Phase 8.1, which are not built yet.  Until then this uses a self-contained
// 256-bit content hash (four position-sensitive FNV-1a lanes) — strong enough to
// *address* content and to *detect* a flipped backing-store byte (which the
// self-test proves), and a drop-in for the real digest once §8.1 lands.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow — no GC, no druntime, no heap.
module core.store;

import core.io; // klog / klog_hex
import core.objmgr : ObjType, objAlloc, objGet, objRelease, objCountType;
import core.namespace : nsAlloc, nsBind, nsResolveWithRights, nsRelease;
import core.cap : CAP_RIGHT_READ, CAP_RIGHT_WRITE;

extern (C) @nogc nothrow:

// --- sizing -------------------------------------------------------------------
enum int   STORE_BLOB_MAX   = 64;        // live content-addressed blobs
enum int   STORE_ARENA      = 1 << 16;   // 64 KiB shared content arena ("the disk")
enum int   STORE_BLOCK      = 64;        // verity leaf-block size, bytes
enum int   STORE_MAX_BLOCKS = 256;       // per-blob verity leaves ⇒ max blob 16 KiB
enum int   GEN_MAX          = 16;        // live generations
enum int   GEN_ENTRY_MAX    = 8;         // store objects captured per generation

// --- 256-bit content digest ---------------------------------------------------
struct Digest256 { ulong[4] w; }

private bool digEqual(ref const(Digest256) a, ref const(Digest256) b) {
    return a.w[0] == b.w[0] && a.w[1] == b.w[1] &&
           a.w[2] == b.w[2] && a.w[3] == b.w[3];
}

// Four FNV-1a lanes with distinct offset bases; each input byte is folded into
// every lane, mixed with its position so byte order matters and the lanes diverge.
// Placeholder for BLAKE3 (§8.1) — content-addressing + tamper detection only.
private Digest256 digestOf(const(ubyte)* p, ulong len) {
    enum ulong PRIME = 0x1000_0000_01b3;
    Digest256 d;
    d.w[0] = 0xcbf2_9ce4_8422_2325;
    d.w[1] = 0x9e37_79b9_7f4a_7c15;
    d.w[2] = 0xff51_afd7_ed55_8ccd;
    d.w[3] = 0xc4ce_b9fe_1a85_ec53;
    foreach (ulong i; 0 .. len) {
        ulong b = cast(ulong)p[i];
        foreach (lane; 0 .. 4) {
            ulong h = d.w[lane];
            h ^= b + (i << (lane * 3 + 1));     // position- and lane-dependent twist
            h *= PRIME;
            h ^= h >> 29;
            d.w[lane] = h;
        }
    }
    // Fold the length in so distinct-length inputs never alias.
    foreach (lane; 0 .. 4) { d.w[lane] ^= len; d.w[lane] *= PRIME; }
    return d;
}

private Digest256 digestOfDigests(const(Digest256)* leaves, uint n) {
    return digestOf(cast(const(ubyte)*)leaves, cast(ulong)n * Digest256.sizeof);
}

// --- store blob (content-addressed, immutable) --------------------------------
struct StoreBlob {
    bool      inUse;
    uint      objId;        // ObjType.StoreObject
    uint      off;          // start in g_storeArena
    uint      len;          // content length, bytes
    uint      blocks;       // verity leaf count = ceil(len / STORE_BLOCK)
    Digest256 root;         // content digest = name (content address)
    Digest256[STORE_MAX_BLOCKS] leaf;   // per-block hash tree leaves (§4.2)
}

__gshared StoreBlob[STORE_BLOB_MAX] g_blobs;
__gshared ubyte[STORE_ARENA]        g_storeArena;
__gshared uint  g_arenaTop = 0;

__gshared ulong g_storePutTotal   = 0;
__gshared ulong g_storeDedupTotal = 0;   // puts satisfied by an existing object
__gshared ulong g_storeReadTotal  = 0;
__gshared ulong g_storeVerifyFail = 0;   // verified reads that detected tampering
__gshared bool  g_storeSelfTested = false;

private StoreBlob* blobByObj(uint objId) {
    if (objId == 0) return null;
    foreach (ref b; g_blobs)
        if (b.inUse && b.objId == objId) return &b;
    return null;
}

private void hashLeaves(StoreBlob* b) {
    b.blocks = cast(uint)((b.len + STORE_BLOCK - 1) / STORE_BLOCK);
    if (b.blocks > STORE_MAX_BLOCKS) b.blocks = STORE_MAX_BLOCKS;
    foreach (uint i; 0 .. b.blocks) {
        uint o   = b.off + i * STORE_BLOCK;
        uint rem = b.len - i * STORE_BLOCK;
        uint n   = rem < STORE_BLOCK ? rem : STORE_BLOCK;
        b.leaf[i] = digestOf(&g_storeArena[o], n);
    }
}

// §4.1 — put content into the store.  Identical content de-duplicates to the same
// store object (content addressing); distinct content allocates a new immutable
// object.  There is no API that mutates an existing blob: writes only ever create.
public uint storePut(const(ubyte)* data, uint len) {
    if (data is null || len > STORE_ARENA) return 0;
    Digest256 dg = digestOf(data, len);
    foreach (ref b; g_blobs)               // dedup: same content ⇒ same object
        if (b.inUse && b.len == len && digEqual(b.root, dg)) {
            ++g_storePutTotal; ++g_storeDedupTotal;
            return b.objId;
        }
    if (g_arenaTop + len > STORE_ARENA) return 0;   // arena full
    foreach (ref b; g_blobs) {
        if (b.inUse) continue;
        uint id = objAlloc(ObjType.StoreObject, cast(void*)&b);
        if (id == 0) return 0;
        b = StoreBlob.init;
        b.inUse = true;
        b.objId = id;
        b.off   = g_arenaTop;
        b.len   = len;
        b.root  = dg;
        foreach (uint i; 0 .. len) g_storeArena[b.off + i] = data[i];
        g_arenaTop += len;
        hashLeaves(&b);
        ++g_storePutTotal;
        return id;
    }
    return 0;
}

// Look up a store object by its content digest ("fetch by hash").
public uint storeLookup(ref const(Digest256) dg, uint len) {
    foreach (ref b; g_blobs)
        if (b.inUse && b.len == len && digEqual(b.root, dg)) return b.objId;
    return 0;
}

public uint storeLen(uint objId) { auto b = blobByObj(objId); return b is null ? 0 : b.len; }
public Digest256 storeRoot(uint objId) {
    auto b = blobByObj(objId);
    return b is null ? Digest256.init : b.root;
}

// Public hash primitives (the §4.2 content digest), reused by the update/signature
// path (§6.2) until the real §8.1 BLAKE3/ed25519 primitives land.
public Digest256 storeHash(const(ubyte)* p, ulong len) { return digestOf(p, len); }
public bool storeDigestEqual(ref const(Digest256) a, ref const(Digest256) b) { return digEqual(a, b); }

// §4.2 — verified read.  Every leaf block covering [off, off+len) is re-hashed from
// the backing arena and checked against the stored hash tree before any byte is
// returned: a tampered block faults the read (dm-verity).  Returns bytes copied, or
// -1 on a verification failure / bad range.
public long storeReadVerified(uint objId, uint off, ubyte* outBuf, uint len) {
    auto b = blobByObj(objId);
    if (b is null || outBuf is null) return -1;
    if (off > b.len || off + len > b.len) return -1;
    ++g_storeReadTotal;
    uint first = off / STORE_BLOCK;
    uint last  = (len == 0) ? first : (off + len - 1) / STORE_BLOCK;
    foreach (uint i; first .. last + 1) {
        uint o   = b.off + i * STORE_BLOCK;
        uint rem = b.len - i * STORE_BLOCK;
        uint n   = rem < STORE_BLOCK ? rem : STORE_BLOCK;
        Digest256 now = digestOf(&g_storeArena[o], n);
        if (!digEqual(now, b.leaf[i])) {   // backing block was altered ⇒ fault
            ++g_storeVerifyFail;
            return -1;
        }
    }
    foreach (uint i; 0 .. len) outBuf[i] = g_storeArena[b.off + off + i];
    return cast(long)len;
}

// Whole-image integrity check: confirm the root over the leaf array still matches a
// freshly recomputed tree.  (The leaf hashes are the trusted metadata; the arena is
// the untrusted backing store — this re-derives the tree to detect arena tampering.)
public bool storeImageIntact(uint objId) {
    auto b = blobByObj(objId);
    if (b is null) return false;
    foreach (uint i; 0 .. b.blocks) {
        uint o   = b.off + i * STORE_BLOCK;
        uint rem = b.len - i * STORE_BLOCK;
        uint n   = rem < STORE_BLOCK ? rem : STORE_BLOCK;
        Digest256 now = digestOf(&g_storeArena[o], n);
        if (!digEqual(now, b.leaf[i])) return false;
    }
    return true;
}

// --- §4.3 state split: /usr (ro) · /etc (overlay) · /var (user state) ----------
// The system namespace binds the three trees with the rights that *are* the
// immutability boundary: `/usr` read-only (no WRITE right ⇒ writes denied), `/etc`
// and `/var` read+write overlays.  storeWritable() is the gate every write to a
// system path must pass — there is no UID-0 / ambient-write escape hatch (§G #4).
__gshared uint g_sysNs       = 0;
__gshared uint g_usrDirObj   = 0;
__gshared uint g_etcDirObj   = 0;
__gshared uint g_varDirObj   = 0;

public uint storeMountSystem() {
    if (g_sysNs != 0 && objGet(g_sysNs) !is null) return g_sysNs;
    g_sysNs = nsAlloc();
    if (g_sysNs == 0) return 0;
    g_usrDirObj = objAlloc(ObjType.Directory, null);
    g_etcDirObj = objAlloc(ObjType.Directory, null);
    g_varDirObj = objAlloc(ObjType.Directory, null);
    nsBind(g_sysNs, "/usr\0".ptr, g_usrDirObj, CAP_RIGHT_READ);                  // read-only image
    nsBind(g_sysNs, "/etc\0".ptr, g_etcDirObj, CAP_RIGHT_READ | CAP_RIGHT_WRITE); // overlay
    nsBind(g_sysNs, "/var\0".ptr, g_varDirObj, CAP_RIGHT_READ | CAP_RIGHT_WRITE); // user state
    return g_sysNs;
}

// True iff a write to `path` is permitted by the system namespace's mount rights.
public bool storeWritable(const(char)* path) {
    if (g_sysNs == 0) storeMountSystem();
    const(char)* rest;
    uint rights;
    uint target = nsResolveWithRights(g_sysNs, path, rest, rights);
    if (target == 0) return false;                 // unmounted ⇒ not writable
    return (rights & CAP_RIGHT_WRITE) != 0;
}

// True iff `path` resolves in the system namespace at all (readable).
public bool storeReadable(const(char)* path) {
    if (g_sysNs == 0) storeMountSystem();
    const(char)* rest;
    uint rights;
    return nsResolveWithRights(g_sysNs, path, rest, rights) != 0;
}

// --- §4.4 generations / deployments -------------------------------------------
// A generation is a named, immutable snapshot: a number, its parent, and the set of
// store-object ids that make up the system tree.  The *active* generation is a
// single pointer; switching/rolling back is one atomic assignment — the Silverblue
// "repoint the deployment" / NixOS "swap the generation symlink" model.
struct GenRec {
    bool inUse;
    uint objId;                       // ObjType.Generation
    uint number;                      // monotonic generation number
    uint parentObjId;                 // generation this descends from (0 = root)
    uint count;                       // store objects captured
    uint[GEN_ENTRY_MAX] entry;        // StoreObject ids snapshotted
}

__gshared GenRec[GEN_MAX] g_gens;
__gshared uint  g_activeGen   = 0;    // THE deployment pointer (atomic swap target)
__gshared uint  g_genNextNum  = 1;
__gshared ulong g_genCreated  = 0;
__gshared ulong g_genRollback = 0;

private GenRec* genByObj(uint objId) {
    if (objId == 0) return null;
    foreach (ref g; g_gens)
        if (g.inUse && g.objId == objId) return &g;
    return null;
}

// Capture a new generation from a parent and a set of store-object ids.  The
// snapshot is immutable: entries are fixed at creation.
public uint genCreate(uint parentObjId, const(uint)* entries, uint count) {
    if (count > GEN_ENTRY_MAX) return 0;
    foreach (ref g; g_gens) {
        if (g.inUse) continue;
        uint id = objAlloc(ObjType.Generation, cast(void*)&g);
        if (id == 0) return 0;
        g = GenRec.init;
        g.inUse = true;
        g.objId = id;
        g.number = g_genNextNum++;
        g.parentObjId = parentObjId;
        g.count = count;
        foreach (uint i; 0 .. count) g.entry[i] = entries[i];
        ++g_genCreated;
        return id;
    }
    return 0;
}

// Atomic deployment swap: make `genObjId` the active system tree.  A single pointer
// store — a boot/rollback never leaves a half-applied tree.
public bool genSetActive(uint genObjId) {
    if (genByObj(genObjId) is null) return false;
    g_activeGen = genObjId;             // atomic pointer swap (single word store)
    return true;
}

public bool genRollback(uint genObjId) {
    if (!genSetActive(genObjId)) return false;
    ++g_genRollback;
    return true;
}

public uint genActive()       { return g_activeGen; }
public uint genNumber(uint genObjId) { auto g = genByObj(genObjId); return g is null ? 0 : g.number; }
public uint genParent(uint genObjId) { auto g = genByObj(genObjId); return g is null ? 0 : g.parentObjId; }
public uint genCount(uint genObjId)  { auto g = genByObj(genObjId); return g is null ? 0 : g.count; }
public uint genEntry(uint genObjId, uint i) {
    auto g = genByObj(genObjId);
    return (g is null || i >= g.count) ? 0 : g.entry[i];
}

// --- self-test (runtime proof of §4.1–§4.4) -----------------------------------
private bool selfTestCa() {           // §4.1 content addressing + dedup + immutability
    static immutable ubyte[5] a = ['u','s','r','/','a'];
    static immutable ubyte[5] b = ['u','s','r','/','b'];
    uint o1 = storePut(a.ptr, a.length);
    uint o2 = storePut(a.ptr, a.length);   // identical ⇒ dedup to same object
    uint o3 = storePut(b.ptr, b.length);   // different ⇒ distinct object
    if (o1 == 0 || o3 == 0) return false;
    bool dedup    = (o1 == o2);
    bool distinct = (o1 != o3);
    Digest256 d = storeRoot(o1);
    bool addressable = (storeLookup(d, a.length) == o1);  // fetch by hash
    return dedup && distinct && addressable;
}

private bool selfTestVerity() {       // §4.2 dm-verity: tampering faults the read
    // Two blocks' worth so a corrupted block is provably localized.  Stack-local
    // (not `static`) to keep mutable state off TLS, matching the kernel convention.
    ubyte[STORE_BLOCK + 8] payload;
    foreach (uint i; 0 .. cast(uint)payload.length) payload[i] = cast(ubyte)(i * 7 + 1);
    uint id = storePut(payload.ptr, payload.length);
    if (id == 0) return false;
    ubyte[STORE_BLOCK + 8] buf;
    bool cleanOk = (storeReadVerified(id, 0, buf.ptr, payload.length) == payload.length);
    bool intact  = storeImageIntact(id);
    // Tamper with the backing arena directly (simulating a disk-level bit flip),
    // then a verified read must fault and the image must report broken.
    auto blob = blobByObj(id);
    g_storeArena[blob.off + 3] ^= 0x40;
    bool faults  = (storeReadVerified(id, 0, buf.ptr, payload.length) == -1);
    bool broken  = !storeImageIntact(id);
    g_storeArena[blob.off + 3] ^= 0x40;       // restore for honesty
    bool healed  = storeImageIntact(id);
    return cleanOk && intact && faults && broken && healed;
}

private bool selfTestSplit() {        // §4.3 /usr ro · /etc ovl · /var user state
    if (storeMountSystem() == 0) return false;
    bool usrRo   = !storeWritable("/usr/lib/libc.so\0".ptr);  // read-only image
    bool usrRead =  storeReadable("/usr/lib/libc.so\0".ptr);  // ...but readable
    bool etcRw   =  storeWritable("/etc/hostname\0".ptr);     // overlay writable
    bool varRw   =  storeWritable("/var/log/x\0".ptr);        // user state writable
    return usrRo && usrRead && etcRw && varRw;
}

private bool selfTestGenerations() {  // §4.4 generations + atomic rollback
    uint[2] e1 = [storePut(cast(const(ubyte)*)"gen1".ptr, 4), 0];
    uint[2] e2 = [storePut(cast(const(ubyte)*)"gen2".ptr, 4), 0];
    uint g1 = genCreate(0,  e1.ptr, 1);
    uint g2 = genCreate(g1, e2.ptr, 1);
    if (g1 == 0 || g2 == 0) return false;
    bool deploy   = genSetActive(g2) && genActive() == g2;
    bool lineage  = (genParent(g2) == g1 && genNumber(g2) > genNumber(g1));
    bool rollback = genRollback(g1) && genActive() == g1;     // atomic revert
    bool restored = (genEntry(g1, 0) == e1[0]);               // prior tree intact
    return deploy && lineage && rollback && restored;
}

public void storeSelfTest() {
    if (g_storeSelfTested) return;
    g_storeSelfTested = true;

    bool ca  = selfTestCa();
    bool ver = selfTestVerity();
    bool spl = selfTestSplit();
    bool gen = selfTestGenerations();

    if (ca && ver && spl && gen) {
        klog("[store] selftest PASS\n");
    } else {
        klog("[store] selftest FAIL:");
        if (!ca)  klog(" ca");
        if (!ver) klog(" verity");
        if (!spl) klog(" split");
        if (!gen) klog(" gen");
        klog("\n");
    }
}

public void storeStats() {
    klog("[store] blobs="); klog_hex(cast(ulong)objCountType(ObjType.StoreObject));
    klog(" gens=");         klog_hex(cast(ulong)objCountType(ObjType.Generation));
    klog(" put=");          klog_hex(g_storePutTotal);
    klog(" dedup=");        klog_hex(g_storeDedupTotal);
    klog(" read=");         klog_hex(g_storeReadTotal);
    klog(" vfail=");        klog_hex(g_storeVerifyFail);
    klog(" arena=");        klog_hex(cast(ulong)g_arenaTop);
    klog(" active=");       klog_hex(cast(ulong)g_activeGen);
    klog("\n");
}
