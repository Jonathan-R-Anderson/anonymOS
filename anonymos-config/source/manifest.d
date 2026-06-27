// manifest.d — the binary boot-manifest wire format shared between the host
// `anonymos-config` emitter and the in-kernel applier (src/kernel/d/core/configboot.d).
//
// This is the parser-free lowering channel for DECLARATIVE_CONFIG_SPEC §4: the
// host compiler lowers its CompiledGraph into a flat sequence of fixed records
// that the -betterC @nogc nothrow kernel walks with plain pointer arithmetic —
// NO JSON parser in the kernel, NO allocation.  A 32-byte HMAC-SHA-256 trailer
// (over header+records) lets the kernel reject a tampered manifest before
// applying a single record (cryptoVerify, core/crypto.d).
//
// Why not JSON in the kernel?  There is no JSON parser in src/kernel/d/ and
// adding one to a -betterC freestanding kernel is a maintainability hazard.  The
// spec's §4 "PID1 parses JSON" assumes a config-driven PID1 that does not exist
// yet; until it does, the manifest is the parser-free bridge that lets the
// existing in-kernel service/identity/namespace managers be driven by a declared
// (not hardcoded) config.  The POLICY still lives outside the kernel (authored
// in the host compiler from system.json); the kernel only APPLIES a verified,
// pre-compiled plan.
module anonymos.config.manifest;

import std.digest.sha;
import std.digest.hmac;
import std.conv;
import std.json;
import anonymos.config.compiler : CompiledGraph;

// ── Wire format ──────────────────────────────────────────────────────────────
//   Header (16 bytes):  magic "ACFG" | u32 version | u32 recordCount | u32 reserved
//   Records:            a sequence of TLV records:
//                         tag:u8  len:u8  payload[len]
//   Trailer (32 bytes): HMAC-SHA-256 over (header ++ all records), key = g_trustedKey.
//
// Every payload field that is a name is stored NUL-terminated, so the kernel
// hands the pointer straight to the C-string kernel APIs (serviceRegister etc.).

enum MANIFEST_MAGIC = "ACFG";
enum MANIFEST_VERSION = 1u;
enum MANIFEST_HEADER_SIZE = 16;
enum MANIFEST_HMAC_SIZE = 32;

// Record tags.  Mirrored verbatim in configboot.d.
enum Tag : ubyte
{
    end            = 0,   // terminator (len 0) — also implied by recordCount
    svcReg         = 1,   // payload: name\0 u32 rights        → serviceRegister
    svcDep         = 2,   // payload: name\0 depname\0          → serviceAddDep
    identityCreate = 3,   // payload: name\0 u32 color u8 trust u32 ceiling u32 nsNameLen nsName  → identityCreate
    nsAlloc        = 4,   // payload: name\0                    → nsAlloc (records a namespace by name)
    genSet         = 5,   // payload: u32 genNumber             → genSetActive (selects boot generation)
    identityFreeze = 6,   // payload: (none)                    → identityFreeze
    svcStartAll    = 7,   // payload: (none)                    → serviceStartAll (applied after all svcDep)
    domainCreate   = 8,   // payload: name\0 identity\0 template\0 u8 persist  → domainCreate (DOMAIN_MANAGER DM1)
    fsPolicy       = 9,   // payload: domainName\0 u8 flags(bit0=allowTraversal)  → start a domain fs policy (DM2.3)
    fsBind         = 10,  // payload: domainName\0 u8 mode(1=ro,2=rw,3=deny) path\0  → add a binding (DM2.3)
}

// The trusted key MUST match src/kernel/d/core/crypto.d g_trustedKey exactly.
// (It is the kernel-held HMAC verification key; the host signs with it so the
// kernel's cryptoVerify accepts.  This is the spec §4 "kernel-held trusted-key
// seam" — same constant the crypto module's self-tests use.)
immutable ubyte[32] TRUSTED_KEY = [
    0xA1, 0x7E, 0xB0, 0x0F, 0x51, 0x61, 0xCA, 0xFE,
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
    0x76, 0x54, 0x32, 0x10, 0x0F, 0x1E, 0x2D, 0x3C,
];

// ── Builder ──────────────────────────────────────────────────────────────────
struct ManifestBuilder
{
    ubyte[] buf;

    void putHeader(uint recordCount)
    {
        buf ~= cast(ubyte[])"ACFG";
        putU32(MANIFEST_VERSION);
        putU32(recordCount);
        putU32(0); // reserved
    }

    void putU32(uint v)
    {
        buf ~= [cast(ubyte)(v & 0xff), cast(ubyte)((v >> 8) & 0xff),
                cast(ubyte)((v >> 16) & 0xff), cast(ubyte)((v >> 24) & 0xff)];
    }

    void putU8(ubyte v) { buf ~= v; }

    // Append one TLV record.
    void putRecord(ubyte tag, in ubyte[] payload)
    {
        assert(payload.length <= 255, "manifest record payload > 255 bytes");
        buf ~= tag;
        buf ~= cast(ubyte) payload.length;
        buf ~= payload;
    }

    // Append a NUL-terminated name.
    void putName(string s)
    {
        foreach (c; s) buf ~= cast(ubyte) c;
        buf ~= cast(ubyte) 0;
    }

    // Sign in place: append the HMAC-SHA-256 trailer over (header ++ records).
    void sign()
    {
        ubyte[32] tag = manifestHmac(buf[]);
        buf ~= tag[];
    }
}

// Compute the manifest body's HMAC-SHA-256 tag (RFC 2104) under TRUSTED_KEY.
// Matches the kernel's cryptoVerify(msg,len,sig) (core/crypto.d:144), which
// recomputes hmacSha256(g_trustedKey, msg) — same key, same algorithm.
ubyte[32] manifestHmac(in ubyte[] headerAndRecords)
{
    auto hmac = HMAC!SHA256(TRUSTED_KEY[]);
    hmac.start();
    hmac.put(headerAndRecords);
    return hmac.finish();
}

// ── CompiledGraph → manifest serialization ───────────────────────────────────
// (Moved here from main.d so both the CLI and the host test suite share one
// implementation of the lowering.)  Emits records in kernel-apply order:
// namespaces → identities → freeze → service-register → service-deps →
// serviceStartAll → genSet, then signs the whole blob.
public ubyte[] buildManifest(in CompiledGraph g, in JSONValue doc)
{
    auto nsRecs = manifestNamespaces(g);
    auto idRecs = manifestIdentities(g);
    auto domRecs = manifestDomains(g);      // DOMAIN_MANAGER DM1
    auto svcRegRecs = manifestServiceRegs(g, doc);
    auto svcDepRecs = manifestServiceDeps(g, doc);
    uint count = 0;
    count += countRecords(nsRecs);
    count += countRecords(idRecs);
    if (idRecs.length) count += 1;          // identityFreeze
    count += countRecords(domRecs);         // DOMAIN_MANAGER DM1
    count += countRecords(svcRegRecs);
    count += countRecords(svcDepRecs);
    count += 1;                              // svcStartAll
    if (auto sys = "system" in doc.object)
        if (sys.type == JSONType.object)
            if (auto gn = "generation" in sys.object) count += 1;

    ManifestBuilder b;
    b.putHeader(count);
    b.buf ~= nsRecs;
    b.buf ~= idRecs;
    if (idRecs.length) b.putRecord(Tag.identityFreeze, null);
    b.buf ~= domRecs;                       // DOMAIN_MANAGER DM1 (after identities exist + freeze)
    b.buf ~= svcRegRecs;
    b.buf ~= svcDepRecs;
    b.putRecord(Tag.svcStartAll, null);
    if (auto sys = "system" in doc.object)
        if (sys.type == JSONType.object)
            if (auto gn = "generation" in sys.object)
            {
                ubyte[4] p; uint v = cast(uint) gn.integer;
                p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
                b.putRecord(Tag.genSet, p[]);
            }
    b.sign();
    return b.buf;
}

private uint countRecords(in ubyte[] recs)
{
    uint n = 0; size_t i = 0;
    while (i + 1 < recs.length) { i += 2 + recs[i + 1]; ++n; }
    return n;
}

private ubyte[] manifestNamespaces(in CompiledGraph g)
{
    ManifestBuilder b;
    foreach (ns, rec; g.namespaceTable)
    {
        ubyte[] p;
        foreach (c; ns) p ~= cast(ubyte) c;
        p ~= cast(ubyte) 0;
        b.putRecord(Tag.nsAlloc, p);
    }
    return b.buf;
}

private ubyte[] manifestIdentities(in CompiledGraph g)
{
    ManifestBuilder b;
    foreach (name, rec; g.identityTable)
    {
        // payload: name\0 u32 color u8 trust u32 ceiling u32 nsNameLen nsName
        ubyte[] p;
        foreach (c; name) p ~= cast(ubyte) c;
        p ~= cast(ubyte) 0;
        putU32Raw(p, rec.color);
        p ~= trustLevel(rec.trust);
        uint ceiling = 0;
        if (auto ce = rec.rightsCeiling in g.capabilityManifest) ceiling = ce.mask;
        putU32Raw(p, ceiling);
        if (rec.namespace_.length)
        {
            putU32Raw(p, cast(uint) rec.namespace_.length);
            foreach (c; rec.namespace_) p ~= cast(ubyte) c;
        }
        else putU32Raw(p, 0);
        b.putRecord(Tag.identityCreate, p);
    }
    return b.buf;
}

private ubyte persistMode(string s)
{
    if (s == "full") return 2;
    if (s == "home-only") return 1;
    return 0; // ephemeral (default)
}

// DOMAIN_MANAGER DM1: emit one domainCreate record per declared domain.
private ubyte[] manifestDomains(in CompiledGraph g)
{
    ManifestBuilder b;
    foreach (name, rec; g.domainTable)
    {
        // payload: name\0 identity\0 template\0 u8 persist
        ubyte[] p;
        foreach (c; name) p ~= cast(ubyte) c;
        p ~= cast(ubyte) 0;
        // identity name ("" → same-named identity, resolved kernel-side)
        string idn = rec.identity.length ? rec.identity : name;
        foreach (c; idn) p ~= cast(ubyte) c;
        p ~= cast(ubyte) 0;
        foreach (c; rec.template_) p ~= cast(ubyte) c;
        p ~= cast(ubyte) 0;
        p ~= persistMode(rec.persist);
        b.putRecord(Tag.domainCreate, p);

        // DM2.3: the restricted-filesystem policy (fsPolicy starts the domain's ns, fsBind per path)
        if (rec.fsHasPolicy)
        {
            ubyte[] fp;
            foreach (c; name) fp ~= cast(ubyte) c;
            fp ~= cast(ubyte) 0;
            ubyte flags = 0;
            if (rec.fsAllowTraversal) flags |= 1;
            fp ~= flags;
            b.putRecord(Tag.fsPolicy, fp);

            void emitBinds(in string[] paths, ubyte mode)
            {
                foreach (path; paths)
                {
                    ubyte[] bp;
                    foreach (c; name) bp ~= cast(ubyte) c;
                    bp ~= cast(ubyte) 0;
                    bp ~= mode;
                    foreach (c; path) bp ~= cast(ubyte) c;
                    bp ~= cast(ubyte) 0;
                    b.putRecord(Tag.fsBind, bp);
                }
            }
            emitBinds(rec.fsReadOnly,  1);
            emitBinds(rec.fsReadWrite, 2);
            emitBinds(rec.fsDeny,      3);
        }
    }
    return b.buf;
}

private ubyte[] manifestServiceRegs(in CompiledGraph g, in JSONValue doc)
{
    ManifestBuilder b;
    if (auto svcs = "services" in doc.object)
        if (svcs.type == JSONType.array)
            foreach (s; svcs.array)
            {
                if (s.type != JSONType.object) continue;
                string nm; if (auto n = "name" in s.object) nm = n.str;
                if (!nm.length) continue;
                ubyte[] p;
                foreach (c; nm) p ~= cast(ubyte) c;
                p ~= cast(ubyte) 0;
                uint rights = 0;
                if (auto caps = "capabilities" in s.object)
                    if (caps.type == JSONType.array)
                        foreach (c; caps.array)
                            if (c.type == JSONType.STRING)
                                if (auto m = c.str in g.capabilityManifest) rights |= m.mask;
                putU32Raw(p, rights);
                b.putRecord(Tag.svcReg, p);
            }
    return b.buf;
}

private ubyte[] manifestServiceDeps(in CompiledGraph g, in JSONValue doc)
{
    ManifestBuilder b;
    if (auto svcs = "services" in doc.object)
        if (svcs.type == JSONType.array)
            foreach (s; svcs.array)
            {
                if (s.type != JSONType.object) continue;
                string nm; if (auto n = "name" in s.object) nm = n.str;
                if (!nm.length) continue;
                if (auto deps = "depends" in s.object)
                    if (deps.type == JSONType.array)
                        foreach (d; deps.array)
                            if (d.type == JSONType.STRING)
                            {
                                ubyte[] p;
                                foreach (c; nm) p ~= cast(ubyte) c;
                                p ~= cast(ubyte) 0;
                                foreach (c; d.str) p ~= cast(ubyte) c;
                                p ~= cast(ubyte) 0;
                                b.putRecord(Tag.svcDep, p);
                            }
            }
    return b.buf;
}

private void putU32Raw(ref ubyte[] p, uint v)
{
    p ~= cast(ubyte)(v & 0xff);
    p ~= cast(ubyte)((v >> 8) & 0xff);
    p ~= cast(ubyte)((v >> 16) & 0xff);
    p ~= cast(ubyte)((v >> 24) & 0xff);
}

private ubyte trustLevel(string t)
{
    switch (t)
    {
    case "system":    return 100;
    case "banking":   return 80;
    case "work":      return 60;
    case "personal":  return 50;
    case "dev":       return 40;
    case "untrusted": return 10;
    case "disposable": return 5;
    default:          return 50;
    }
}
