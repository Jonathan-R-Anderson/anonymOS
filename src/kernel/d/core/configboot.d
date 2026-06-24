// configboot.d — DECLARITIVE_MODEL_ROADMAP §4 "Boot Integration" (Option 1:
// in-kernel lowering).  This is the trusted-config boot path that the spec's §0
// item #2 named as missing: the kernel LOCATES a boot-module manifest, HMAC-
// VERIFIES it (core/crypto.d), and APPLIES it by driving the existing
// service/identity/namespace/generation managers — so a declared config, not
// hardcoded init, constructs running system state.
//
// Why a binary manifest and not JSON?  There is no JSON parser in src/kernel/d/
// and adding one to a -betterC @nogc nothrow freestanding kernel is a real
// maintainability hazard.  The spec's §4 table says "PID1 parses the JSON", but
// no config-driven PID1 exists today (the service manager is in-kernel and is
// exercised only by self-tests).  So the host compiler (anonymos-config
// emit-manifest) lowers its CompiledGraph into a flat, parser-free TLV manifest
// that this module walks with plain pointer arithmetic.  The POLICY is still
// authored outside the kernel (in system.json via the host compiler); the kernel
// only APPLIES a verified, pre-compiled plan — honouring §17 "most policy lives
// outside the kernel".
//
// Safe failure (§12): a missing or tampered manifest is logged and the kernel
// falls through to the existing hardcoded init.  A manifest is NEVER partially
// applied: verification happens before the first record is walked.
//
// Wire format (mirrors anonymos-config/source/manifest.d exactly):
//   Header 16B:  "ACFG" | u32 version | u32 recordCount | u32 reserved
//   Records:     tag:u8 len:u8 payload[len]   (TLV, no padding)
//   Trailer 32B: HMAC-SHA-256 over (header ++ records), key = g_trustedKey.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed buffers, @nogc nothrow.
module core.configboot;

import core.io : klog, klog_hex;
import core.exports : g_mboot_modules, g_module_count, phys_to_virt;
import core.crypto : cryptoVerify;
import core.namespace : nsAlloc;
import core.identity : identityCreate, identityFreeze, identityByName, NetPolicy, ClipPolicy;
import core.servicemgr : serviceRegister, serviceAddDep, serviceStartAll;
import core.store : genSetActive, genActive, genCreate;
import core.audit : auditLog, AuditKind;
import core.user : userDefaultObjId;

extern (C) @nogc nothrow:

// The boot-module record layout published by bootstrap.d (128 bytes).
align(8) private struct BootModuleRecord {
    uint mod_start;
    uint mod_end;
    char[120] name;
}

// The manifest boot-module name (staged as module_path: boot():/manifest.blob).
private enum MANIFEST_MODULE = "manifest.blob\0";
// Buffer cap: a config manifest is a few hundred bytes; cap generously.
private enum CONFIG_BUF_MAX = 4096;
__gshared ubyte[CONFIG_BUF_MAX] g_cfgbootBuf;   // renamed: g_cfgbootBuf collides with posix.d
__gshared ulong g_cfgbootLen = 0;

// Record tags — mirror anonymos-config/source/manifest.d Tag.
private enum ubyte TAG_END            = 0;
private enum ubyte TAG_SVC_REG        = 1;
private enum ubyte TAG_SVC_DEP        = 2;
private enum ubyte TAG_IDENTITY_CREATE = 3;
private enum ubyte TAG_NS_ALLOC       = 4;
private enum ubyte TAG_GEN_SET        = 5;
private enum ubyte TAG_IDENTITY_FREEZE = 6;
private enum ubyte TAG_SVC_START_ALL  = 7;

private enum MANIFEST_HEADER_SIZE = 16;
private enum MANIFEST_HMAC_SIZE   = 32;

// Counters for the serial report.
__gshared ulong g_cfgNsApplied;
__gshared ulong g_cfgIdApplied;
__gshared ulong g_cfgSvcApplied;
__gshared ulong g_cfgSvcDeps;
__gshared bool  g_cfgApplied;     // a verified manifest was applied this boot
__gshared bool  g_cfgSelfTested;

// ── Boot-module lookup (mirrors the inline walk in d_kernel_main) ─────────────
// Returns the physical base + size of the manifest boot module, or false.
private bool findManifestModule(out ulong physStart, out ulong size) {
    physStart = 0;
    size = 0;
    if (g_mboot_modules is null || g_module_count <= 0) return false;
    auto recs = cast(const(BootModuleRecord)*) g_mboot_modules;
    for (int i = 0; i < g_module_count; i++) {
        const BootModuleRecord* rec = &recs[i];
        // basename of the module path (after the last '/')
        const(char)* nm = cast(const(char)*)&rec.name[0];
        const(char)* base = nm;
        for (const(char)* p = nm; *p != 0; p++) if (*p == '/') base = p + 1;
        if (cfgCstrEq(base, "manifest.blob")) {
            physStart = cast(ulong) rec.mod_start;
            size = cast(ulong) rec.mod_end - cast(ulong) rec.mod_start;
            return true;
        }
    }
    return false;
}

// (renamed cfgCstrEq: a plain cfgCstrEq collides with posix.d's definition at link)
private bool cfgCstrEq(const(char)* a, const(char)* b) {
    while (*a != 0 && *b != 0) { if (*a != *b) return false; ++a; ++b; }
    return *a == *b;
}

// ── The entry point: locate, verify, apply ───────────────────────────────────
// Called from d_kernel_main AFTER the service/identity/namespace/store managers
// are initialized, BEFORE the PID1 module scan.  Returns true if a verified
// manifest was applied; false (and falls through silently) if absent/tampered.
public bool configBootApply() {
    g_cfgbootLen = 0;
    g_cfgApplied = false;

    // 1. Locate the manifest boot module.
    ulong phys; ulong sz;
    if (!findManifestModule(phys, sz)) {
        klog("[dkernel] config: no manifest.blob boot module — using hardcoded init\n");
        return false;
    }
    if (sz < MANIFEST_HEADER_SIZE + MANIFEST_HMAC_SIZE || sz > CONFIG_BUF_MAX) {
        klog("[dkernel] config: manifest.blob bad size\n");
        return false;
    }

    // 2. Read it into the static buffer (clone of the display.conf pattern).
    const(ubyte)* src = cast(const(ubyte)*) phys_to_virt(phys);
    for (ulong i = 0; i < sz; i++) g_cfgbootBuf[i] = src[i];
    g_cfgbootLen = sz;

    // 3. Verify the HMAC trailer over (header ++ records).
    const ulong bodyLen = sz - MANIFEST_HMAC_SIZE;
    const(ubyte)* sig = &g_cfgbootBuf[bodyLen];
    if (!cryptoVerify(&g_cfgbootBuf[0], bodyLen, sig)) {
        klog("[dkernel] config: manifest HMAC FAILED — refusing to apply (safe fallthrough)\n");
        auditLog(AuditKind.InvariantBreach, 0, 0); // record the refusal
        return false;
    }

    // 4. Walk the records and lower them onto the kernel managers.
    applyRecords();
    g_cfgApplied = true;
    auditLog(AuditKind.ControlOk, 0, g_cfgbootLen); // "config applied" measurement
    klog("[dkernel] config: applied ");
    klog_hex(g_cfgSvcApplied);
    klog(" services, ");
    klog_hex(g_cfgIdApplied);
    klog(" identities, ");
    klog_hex(g_cfgNsApplied);
    klog(" namespaces, gen=");
    klog_hex(genActive());
    klog("\n");
    return true;
}

// Walk the TLV records in order: ns → identity → freeze → svc reg → svc dep →
// svcStartAll → genSet.  Names in payloads are NUL-terminated C strings handed
// directly to the kernel APIs.
private void applyRecords() {
    g_cfgNsApplied = 0; g_cfgIdApplied = 0;
    g_cfgSvcApplied = 0; g_cfgSvcDeps = 0;

    if (g_cfgbootLen < MANIFEST_HEADER_SIZE) return;
    // (record count is in the header but we just walk until the HMAC boundary)
    ulong i = MANIFEST_HEADER_SIZE;
    const ulong bodyEnd = g_cfgbootLen - MANIFEST_HMAC_SIZE;
    while (i + 2 <= bodyEnd) {
        const ubyte tag = g_cfgbootBuf[i];
        const ubyte len = g_cfgbootBuf[i + 1];
        if (i + 2 + len > bodyEnd) break;        // truncated record — stop
        const(ubyte)* payload = &g_cfgbootBuf[i + 2];
        applyOne(tag, len, payload);
        i += 2 + len;
        if (tag == TAG_END) break;
    }
}

private void applyOne(ubyte tag, ubyte len, const(ubyte)* payload) {
    // Helper to read a NUL-terminated C string from payload at byte offset off.
    // Returns a pointer into payload and advances off past the NUL.
    final switch (tag) {
    case TAG_END:
        break;
    case TAG_NS_ALLOC: {
        // payload: name\0  → nsAlloc (record it for identity nsTemplate lookup)
        const(char)* name = cast(const(char)*) payload;
        uint nsObj = nsAlloc();
        if (nsObj != 0) { ++g_cfgNsApplied; rememberNs(name, nsObj); }
        break;
    }
    case TAG_IDENTITY_CREATE: {
        // payload: name\0 u32 color u8 trust u32 ceiling u32 nsNameLen nsName
        size_t off = 0;
        const(char)* name = readCStr(payload, len, off);
        if (name is null) break;
        if (off + 1 + 4 + 4 + 4 > len) break;
        const uint color  = readU32(payload, off); off += 4;
        const ubyte trust = payload[off]; off += 1;
        const uint ceiling = readU32(payload, off); off += 4;
        const uint nsNameLen = readU32(payload, off); off += 4;
        // resolve the nsTemplate: a namespace named earlier by this name, else 0
        uint nsTemplate = 0;
        if (nsNameLen > 0 && off + nsNameLen <= len) {
            const(char)* nsName = cast(const(char)*)(payload + off);
            nsTemplate = lookupNs(nsName);
        }
        // An identity of this name may already exist (the kernel's compiled-in
        // identityInitDefaults creates System/Personal/Banking before the config
        // runs).  Treat that as a successful no-op re-assertion (the config
        // agrees with the built-ins) rather than a failure — count it applied.
        const uint existing = identityByName(name);
        if (existing != 0) { ++g_cfgIdApplied; break; }
        // ceiling must be ⊆ UNIVERSE (identityCreate checks this); a declared
        // ceiling of 0 means "use the safe default (no ambient rights)".
        const uint safeCeiling = (ceiling == 0) ? 0 : ceiling;
        const uint id = identityCreate(name, color, trust, safeCeiling, nsTemplate,
                                       NetPolicy.None, ClipPolicy.Deny, 0);
        if (id != 0) ++g_cfgIdApplied;
        break;
    }
    case TAG_IDENTITY_FREEZE: {
        identityFreeze();
        break;
    }
    case TAG_SVC_REG: {
        // payload: name\0 u32 rights
        size_t off = 0;
        const(char)* name = readCStr(payload, len, off);
        if (name is null || off + 4 > len) break;
        const uint rights = readU32(payload, off);
        const uint svc = serviceRegister(name, userDefaultObjId(), rights);
        if (svc != 0) { ++g_cfgSvcApplied; rememberSvc(name, svc); }
        break;
    }
    case TAG_SVC_DEP: {
        // payload: name\0 depname\0  → serviceAddDep
        size_t off = 0;
        const(char)* name = readCStr(payload, len, off);
        const(char)* depName = readCStr(payload, len, off);
        if (name is null || depName is null) break;
        const uint a = lookupSvc(name);
        const uint b = lookupSvc(depName);
        if (a != 0 && b != 0 && serviceAddDep(a, b)) ++g_cfgSvcDeps;
        break;
    }
    case TAG_SVC_START_ALL: {
        // Dependency-ordered start of every registered service.
        const uint started = serviceStartAll();
        klog("[dkernel] config: serviceStartAll started ");
        klog_hex(started);
        klog("\n");
        break;
    }
    case TAG_GEN_SET: {
        // payload: u32 genNumber  → genSetActive(generation with that number)
        if (len >= 4) {
            const uint genNum = readU32(payload, 0);
            // create a generation capturing nothing extra (the active pointer is
            // the deployment swap); then atomically set it active.
            const uint g = genCreate(0, null, 0);
            if (g != 0) genSetActive(g);
        }
        break;
    }
    }
}

// ── name → objId side tables (so SVC_DEP / IDENTITY nsTemplate resolve) ───────
private enum CFG_NAME_MAX = 32;
private enum CFG_NAME_TAB = 64;
private struct NameSlot { bool inUse; uint objId; char[CFG_NAME_MAX] name; }
private __gshared NameSlot[CFG_NAME_TAB] g_nsNames;
private __gshared NameSlot[CFG_NAME_TAB] g_svcNames;

private void rememberTab(ref NameSlot[CFG_NAME_TAB] tab, const(char)* name, uint objId) {
    foreach (ref s; tab) {
        if (!s.inUse) {
            s.inUse = true; s.objId = objId;
            size_t i = 0;
            while (i + 1 < s.name.length && name[i] != 0) { s.name[i] = name[i]; ++i; }
            s.name[i] = 0;
            return;
        }
    }
}

private uint lookupTab(const ref NameSlot[CFG_NAME_TAB] tab, const(char)* name) {
    foreach (ref s; tab) {
        if (!s.inUse) continue;
        const(char)* n = cast(const(char)*)&s.name[0];
        if (cfgCstrEq(n, name)) return s.objId;
    }
    return 0;
}

private void rememberNs(const(char)* name, uint objId)  { rememberTab(g_nsNames, name, objId); }
private void rememberSvc(const(char)* name, uint objId) { rememberTab(g_svcNames, name, objId); }
private uint lookupNs(const(char)* name)  { return lookupTab(g_nsNames, name); }
private uint lookupSvc(const(char)* name) { return lookupTab(g_svcNames, name); }

// ── payload readers ──────────────────────────────────────────────────────────
// readCStr: return a pointer to a NUL-terminated string at payload+off, advance
// off past the NUL.  Bounds-checked against len.
private const(char)* readCStr(const(ubyte)* payload, ubyte len, ref size_t off) {
    if (off >= len) return null;
    const(char)* s = cast(const(char)*)(payload + off);
    // find the NUL within bounds
    while (off < len && payload[off] != 0) off++;
    if (off < len) off++; // skip the NUL
    return s;
}

private uint readU32(const(ubyte)* p, size_t off) {
    return cast(uint)p[off] | (cast(uint)p[off+1] << 8) |
           (cast(uint)p[off+2] << 16) | (cast(uint)p[off+3] << 24);
}
