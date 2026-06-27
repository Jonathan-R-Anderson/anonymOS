// Signed template bundles + local template registry — DM12 (the offline, feasible-now core) of
// roadmap/domain_manager.md.
//
// A *template bundle* (`.hosdt`) is a self-describing, **HMAC-signed** snapshot of a Template
// Domain's policy (name / identity / device mask / distro+pkgMgr / persist / version / publisher).
// It can be exported from a domain, verified, and installed into the local template registry as a
// first-class object — without rebuilding the OS.  Import is deny-by-default:
//   * a tampered or unsigned bundle      → rejected (bad HMAC, via crypto.d)
//   * an untrusted/blocked publisher     → rejected (unless quarantine)
//   * each accepted import               → a new content-addressed Generation (store.d) → rollback
//
// The brief's I2P/Kademlia P2P marketplace (discover/download templates from peers) is OUT OF
// SCOPE here: it needs a TCP/IP stack + an I2P router this from-scratch microkernel does not have
// (sockets are AF_UNIX only).  The OFFLINE half — export/import/sign/verify/trust/Generations/
// rollback — is real and boot-proven; the P2P transport is the documented honest limit.  Signing
// uses the single system trusted key (crypto.d), not per-publisher PKI (also an honest limit).
//
// Kernel constraints: -betterC, plain structs, __gshared fixed tables, @nogc nothrow.
module core.template_bundle;

import core.domain   : domainById, domainByName, DomainRec, DomainId;
import core.objmgr   : ObjType, objAlloc;
import core.crypto   : cryptoSign, cryptoVerify;
import core.store    : storePut, genCreate, genNumber, genParent;
import core.io       : klog, klog_hex;

extern (C) @nogc nothrow:

enum int  TPL_NAME_MAX = 24;
enum int  TPL_PUB_MAX  = 24;
enum uint TPL_MAGIC    = 0x54534F48;   // "HOST" (HOsDt)
enum ubyte TPL_SCHEMA  = 1;
enum uint TPL_SIG_LEN  = 32;           // HMAC-SHA256

// publisher trust levels (higher = more trusted; BLOCKED is a hard deny).
enum ubyte PUBTRUST_UNTRUSTED = 0, PUBTRUST_KNOWN = 1, PUBTRUST_TRUSTED = 2, PUBTRUST_BLOCKED = 3;

// import() result codes.
enum int TPL_OK = 0, TPL_ERR_SHORT = -1, TPL_ERR_MAGIC = -2, TPL_ERR_SCHEMA = -3,
         TPL_ERR_HMAC = -4, TPL_ERR_BLOCKED = -5, TPL_ERR_UNTRUSTED = -6,
         TPL_ERR_DOWNGRADE = -7, TPL_ERR_FULL = -8, TPL_ERR_NODOMAIN = -9;

// The signed body of a bundle (the "manifest").  Followed by a TPL_SIG_LEN HMAC over these bytes.
struct TplBundle {
    uint   magic;
    ubyte  schema;
    ubyte  distro;
    ubyte  pkgMgr;
    ubyte  persist;
    uint   ver;          // semver packed: major<<16 | minor<<8 | patch
    uint   policyEpoch;  // anti-downgrade guard
    uint   devices;      // §7 device mask
    uint   bodyHash;     // FNV-1a of the policy fields (the templateHash)
    char[TPL_NAME_MAX] name;
    char[TPL_NAME_MAX] identity;
    char[TPL_PUB_MAX]  publisher;
}

// An installed template in the local registry (/config/templates.json, /objects/templates/<id>).
struct TemplateRec {
    bool  inUse;
    uint  objId;         // ObjType.Template
    char[TPL_NAME_MAX] name;
    char[TPL_PUB_MAX]  publisher;
    uint  ver;
    uint  policyEpoch;
    uint  genObjId;      // current Generation (rollback re-points this)
    uint  bundleHash;
}
__gshared TemplateRec[16] g_templates;

struct PublisherRec { bool inUse; char[TPL_PUB_MAX] name; ubyte trust; }
__gshared PublisherRec[16] g_publishers;
__gshared bool g_tplSeeded = false;

// ── small helpers ────────────────────────────────────────────────────────────
private int tplLen(const(char)* s) { int n = 0; while (s !is null && s[n] != 0) ++n; return n; }
private void tplCopy(char* dst, int cap, const(char)* src) {
    int i = 0; for (; i < cap - 1 && src[i] != 0; ++i) dst[i] = src[i];
    for (int j = i; j < cap; ++j) dst[j] = 0;
}
private bool tplEq(const(char)* a, const(char)* b) {
    int i = 0; for (;; ++i) { if (a[i] != b[i]) return false; if (a[i] == 0) return true; }
}
private uint fnv(const(ubyte)* p, uint n) {
    uint h = 2166136261u; foreach (i; 0 .. n) { h ^= p[i]; h *= 16777619u; } return h;
}

// ── publisher trust table ────────────────────────────────────────────────────
public void tplSeed() {
    if (g_tplSeeded) return;
    g_tplSeeded = true;
    publisherSetTrust("local\0".ptr, PUBTRUST_TRUSTED);   // the local node is trusted to itself
}
public ubyte publisherTrust(const(char)* name) {
    foreach (ref p; g_publishers) if (p.inUse && tplEq(p.name.ptr, name)) return p.trust;
    return PUBTRUST_UNTRUSTED;   // unknown ⟹ untrusted (deny-by-default)
}
public bool publisherSetTrust(const(char)* name, ubyte trust) {
    foreach (ref p; g_publishers) if (p.inUse && tplEq(p.name.ptr, name)) { p.trust = trust; return true; }
    foreach (ref p; g_publishers) if (!p.inUse) { p.inUse = true; tplCopy(p.name.ptr, TPL_PUB_MAX, name); p.trust = trust; return true; }
    return false;
}

// ── export: serialize a domain's policy into a signed bundle ─────────────────
// Writes [TplBundle | HMAC] into buf; returns the byte length or a negative error.
public long bundleExportAs(uint domObjId, const(char)* publisher, uint ver, ubyte* buf, ulong cap) {
    auto d = domainById(domObjId);
    if (d is null) return TPL_ERR_NODOMAIN;
    const ulong need = TplBundle.sizeof + TPL_SIG_LEN;
    if (cap < need) return TPL_ERR_SHORT;
    TplBundle* b = cast(TplBundle*)buf;
    *b = TplBundle.init;
    b.magic = TPL_MAGIC; b.schema = TPL_SCHEMA;
    b.distro = d.distro; b.pkgMgr = d.pkgMgr; b.persist = d.persistMode;
    b.ver = ver; b.policyEpoch = cast(uint)d.policyEpoch; b.devices = d.allowedDevices;
    tplCopy(b.name.ptr, TPL_NAME_MAX, d.name.ptr);
    tplCopy(b.publisher.ptr, TPL_PUB_MAX, publisher);
    // identity name (best-effort; the registry mainly keys on the template name)
    b.identity[0] = 0;
    b.bodyHash = fnv(cast(const(ubyte)*)b, TplBundle.sizeof - 4);  // hash excludes bodyHash slot tail-safe
    cryptoSign(cast(const(ubyte)*)b, TplBundle.sizeof, buf + TplBundle.sizeof);   // HMAC over the body
    return cast(long)need;
}
public long bundleExport(uint domObjId, ubyte* buf, ulong cap) {
    return bundleExportAs(domObjId, "local\0".ptr, 0x00010000u, buf, cap);   // v1.0.0, local publisher
}

// ── import: verify + install into the registry ───────────────────────────────
private TemplateRec* tplByName(const(char)* name) {
    foreach (ref t; g_templates) if (t.inUse && tplEq(t.name.ptr, name)) return &t;
    return null;
}
public int bundleImport(const(ubyte)* buf, ulong len, bool quarantine) {
    if (len < TplBundle.sizeof + TPL_SIG_LEN) return TPL_ERR_SHORT;
    const TplBundle* b = cast(const TplBundle*)buf;
    if (b.magic != TPL_MAGIC)   return TPL_ERR_MAGIC;
    if (b.schema != TPL_SCHEMA) return TPL_ERR_SCHEMA;
    if (!cryptoVerify(cast(const(ubyte)*)b, TplBundle.sizeof, buf + TplBundle.sizeof))
        return TPL_ERR_HMAC;                               // tampered / unsigned → reject
    const ubyte tr = publisherTrust(b.publisher.ptr);
    if (tr == PUBTRUST_BLOCKED) return TPL_ERR_BLOCKED;
    if (tr < PUBTRUST_TRUSTED && !quarantine) return TPL_ERR_UNTRUSTED;

    const uint bh = fnv(buf, cast(uint)(TplBundle.sizeof + TPL_SIG_LEN));
    const uint storeId = storePut(buf, cast(uint)(TplBundle.sizeof + TPL_SIG_LEN));

    auto t = tplByName(b.name.ptr);
    if (t is null) {
        foreach (ref e; g_templates) if (!e.inUse) { t = &e; break; }
        if (t is null) return TPL_ERR_FULL;
        *t = TemplateRec.init;
        t.inUse = true;
        t.objId = objAlloc(ObjType.Template, cast(void*)t);
        tplCopy(t.name.ptr, TPL_NAME_MAX, b.name.ptr);
        t.genObjId = 0;
    } else if (b.policyEpoch < t.policyEpoch && !quarantine) {
        return TPL_ERR_DOWNGRADE;                          // anti-downgrade (rollback is explicit)
    }
    tplCopy(t.publisher.ptr, TPL_PUB_MAX, b.publisher.ptr);
    t.ver = b.ver; t.policyEpoch = b.policyEpoch; t.bundleHash = bh;
    t.genObjId = genCreate(t.genObjId, &storeId, 1);       // a new Generation parented on the previous
    return TPL_OK;
}

// Rollback the template to an earlier Generation number (must already be in its lineage).
public bool templateRollback(const(char)* name, uint genNum) {
    auto t = tplByName(name);
    if (t is null) return false;
    uint g = t.genObjId;
    while (g != 0) { if (genNumber(g) == genNum) { t.genObjId = g; return true; } g = genParent(g); }
    return false;
}

// Publish a domain as a local template: export → sign → verify → install (the GUI Export button /
// the "export <domain>" control verb).  Returns TPL_OK or an import error.
__gshared ubyte[256] g_tplStage;
public int templatePublish(uint domObjId) {
    const long n = bundleExport(domObjId, g_tplStage.ptr, g_tplStage.length);
    if (n <= 0) return cast(int)n;
    return bundleImport(g_tplStage.ptr, cast(ulong)n, false);
}

public uint templateCount() { uint n = 0; foreach (ref t; g_templates) if (t.inUse) ++n; return n; }
public TemplateRec* templateAt(uint i) {
    uint k = 0; foreach (ref t; g_templates) if (t.inUse) { if (k == i) return &t; ++k; }
    return null;
}

// ── DM12 boot proof: export → verify → install; tamper → reject; untrusted → block; rollback ──
__gshared bool g_tplProofDone = false;
__gshared ubyte[256] g_tplBuf;
public void templateBundleProof() {
    if (g_tplProofDone) return;
    g_tplProofDone = true;
    tplSeed();
    const uint dev = domainByName("Development\0".ptr);
    if (dev == 0) { klog("[tpl] bundle proof SKIP (no Development)\n"); return; }

    // export → a signed bundle (publisher "local", trusted)
    const long n = bundleExport(dev, g_tplBuf.ptr, g_tplBuf.length);
    bool ok = (n > 0);
    // valid import installs the template + a Generation
    ok = ok && (bundleImport(g_tplBuf.ptr, cast(ulong)n, false) == TPL_OK);
    auto t = tplByName("Development\0".ptr);
    ok = ok && (t !is null) && (t.genObjId != 0);
    const uint gen1 = (t !is null) ? t.genObjId : 0;

    // tamper a body byte → HMAC verify fails → rejected
    g_tplBuf[8] ^= 0xFF;
    ok = ok && (bundleImport(g_tplBuf.ptr, cast(ulong)n, false) == TPL_ERR_HMAC);
    g_tplBuf[8] ^= 0xFF;   // restore

    // an untrusted publisher is blocked (valid HMAC, but the publisher isn't trusted)
    const long n2 = bundleExportAs(dev, "Stranger\0".ptr, 0x00020000u, g_tplBuf.ptr, g_tplBuf.length);
    ok = ok && (n2 > 0) && (bundleImport(g_tplBuf.ptr, cast(ulong)n2, false) == TPL_ERR_UNTRUSTED);
    // …until the user trusts that publisher
    publisherSetTrust("Stranger\0".ptr, PUBTRUST_TRUSTED);
    ok = ok && (bundleImport(g_tplBuf.ptr, cast(ulong)n2, false) == TPL_OK);
    // the second import created a 2nd Generation; rollback to gen1 restores it
    t = tplByName("Development\0".ptr);
    ok = ok && (t !is null) && (t.genObjId != gen1) && templateRollback("Development\0".ptr, genNumber(gen1)) && (t.genObjId == gen1);

    klog(ok ? "[tpl] bundle proof PASS (export/sign → verify+install; tamper→HMAC reject; untrusted→block→trust→install; rollback)\n"
            : "[tpl] bundle proof FAIL\n");
}
