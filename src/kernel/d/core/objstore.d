// ─────────────────────────────────────────────────────────────────────────────
// Persisted object store  (OBJECT_FILESYSTEM_ROADMAP F4 — the north star)
//
// Backs /objects/apps with REAL storage on the SATA disk so objects + their data
// survive reboot.  Apps are first-class objects: each carries a manifest, declared
// permissions, an identity binding, and a private writable `storage` blob — the
// only area an app may mutate, separate from the immutable system base (F3).
//
// On-disk layout (sector = 512B):
//   LBA 0        superblock (magic, version, appCount, bootCount, nextFreeLba)
//   LBA 1..32    app directory  (ObjAppEntry, 256B each → 2/sector, 64 entries)
//   LBA 64..     blob region (manifest / permissions / executable / storage),
//                allocated sequentially, sector-granular.
//
// A bootCount in the superblock, bumped every mount, is the persistence proof:
// it keeps climbing across reboots because it is read from and written to disk.
// ─────────────────────────────────────────────────────────────────────────────
module core.objstore;

import drivers.block.disk : diskReady, diskReadSectors, diskWriteSectors;
import memory.dma : dma_alloc;
import core.io : klog, klog_hex;
import core.stdc.string : memset, memcpy;

@nogc nothrow:

enum uint  SECTOR        = 512;
enum ulong DIR_LBA       = 1;          // app directory start
enum uint  MAX_APPS      = 64;
enum ulong BLOB_LBA_BASE = 64;         // blob region start
enum uint  STAGE_BYTES   = 65536;      // 64 KiB blob staging window

immutable char[8] OBJ_MAGIC = ['H','O','S','O','B','J','F','S'];

struct ObjSuper {
    char[8] magic;
    uint    version_;
    uint    appCount;
    ulong   bootCount;
    ulong   nextFreeLba;
    uint    domainCount;        // DOMAIN_MANAGER DM5: persisted domains in the domain directory
    ubyte[SECTOR - 36] _pad;
}
static assert(ObjSuper.sizeof == SECTOR);

// DOMAIN_MANAGER DM5: persisted domain directory (LBA 33..48 — 16 sectors, between the app
// directory at 1..32 and the blob region at 64).  Each DomainEntry persists a domain's
// DEFINITION (name / identity / template / persist mode); the writable overlay+home blobs are DM6.
enum ulong DOM_DIR_LBA      = 33;
enum uint  DOM_MAX_PERSIST  = 32;
struct DomainEntry {
    uint    inUse;
    uint    nameLen;     char[64] name;
    uint    identityLen; char[32] identity;     // the identity name the domain binds to
    uint    templateLen; char[32] template_;    // the template name (DM6; "" = none)
    uint    persistMode;                        // 0=ephemeral 1=home-only 2=full
    ubyte[256 - 148] _pad;
}
static assert(DomainEntry.sizeof == 256);

struct ObjAppEntry {
    uint    inUse;
    uint    nameLen;
    char[64] name;
    uint    identityLen;
    char[32] identity;          // identity-domain binding
    uint    rights;             // declared capability bits
    ulong   manifestLba; uint manifestLen;
    ulong   permsLba;    uint permsLen;
    ulong   execLba;     uint execLen;
    ulong   storageLba;  uint storageLen;  // private writable blob
    ulong   storageCap;                    // sectors reserved for storage growth
    ubyte[256 - 184] _pad;
}
static assert(ObjAppEntry.sizeof == 256);

__gshared bool        g_mounted = false;
__gshared ObjSuper    g_super;
__gshared ObjAppEntry[MAX_APPS] g_apps;
__gshared DomainEntry[DOM_MAX_PERSIST] g_domEntries;   // DOMAIN_MANAGER DM5
__gshared ubyte[STAGE_BYTES] g_stage;     // scratch for blob read/write

public bool objstoreMounted() { return g_mounted; }
public ulong objstoreBootCount() { return g_super.bootCount; }
public uint  objstoreAppCount() { return g_super.appCount; }

private uint sectorsFor(uint bytes) { return (bytes + SECTOR - 1) / SECTOR; }

private bool magicOk() {
    foreach (i; 0 .. 8) if (g_super.magic[i] != OBJ_MAGIC[i]) return false;
    return true;
}

// Persist the superblock (LBA 0) and the directory (LBA 1..32).
private bool flushMeta() {
    if (!diskWriteSectors(0, 1, &g_super)) return false;
    // app directory: MAX_APPS*256 bytes = 16 KiB = 32 sectors
    if (!diskWriteSectors(DIR_LBA, sectorsFor(MAX_APPS * ObjAppEntry.sizeof), g_apps.ptr)) return false;
    // DM5 domain directory: DOM_MAX_PERSIST*256 = 8 KiB = 16 sectors
    return diskWriteSectors(DOM_DIR_LBA, sectorsFor(DOM_MAX_PERSIST * DomainEntry.sizeof), g_domEntries.ptr);
}

// Allocate a blob region of `len` bytes; returns its LBA (0 on failure).
private ulong allocBlob(uint len, uint reserveSectors = 0) {
    uint sec = sectorsFor(len);
    if (reserveSectors > sec) sec = reserveSectors;
    const ulong lba = g_super.nextFreeLba;
    g_super.nextFreeLba += sec;
    return lba;
}

// Write `len` bytes to a blob at `lba` (zero-pads the trailing sector).
private bool writeBlob(ulong lba, const(void)* data, uint len) {
    if (len > STAGE_BYTES) return false;
    const uint sec = sectorsFor(len);
    memset(g_stage.ptr, 0, sec * SECTOR);
    if (len) memcpy(g_stage.ptr, data, len);
    return diskWriteSectors(lba, sec, g_stage.ptr);
}

// Read up to `cap` bytes of a blob (`len` bytes) at `lba` into `dst`; returns count.
public int objstoreReadBlob(ulong lba, uint len, ubyte* dst, uint cap) {
    if (!g_mounted || lba == 0 || len == 0) return 0;
    uint want = len < cap ? len : cap;
    const uint sec = sectorsFor(want);
    if (sec * SECTOR > STAGE_BYTES) return 0;
    if (!diskReadSectors(lba, sec, g_stage.ptr)) return 0;
    memcpy(dst, g_stage.ptr, want);
    return cast(int)want;
}

private void setStr(char* dst, ref uint dstLen, const(char)[] s, uint cap) {
    uint n = cast(uint)(s.length < cap ? s.length : cap);
    foreach (i; 0 .. n) dst[i] = s[i];
    dstLen = n;
}

// Install an app object (manifest + permissions + identity + executable + storage).
public bool objstoreInstallApp(const(char)[] name, const(char)[] identity, uint rights,
                               const(char)[] manifest, const(char)[] perms,
                               const(void)[] exec, const(char)[] storage0) {
    if (!g_mounted || g_super.appCount >= MAX_APPS) return false;
    int slot = -1;
    foreach (i; 0 .. MAX_APPS) if (!g_apps[i].inUse) { slot = cast(int)i; break; }
    if (slot < 0) return false;

    ObjAppEntry e;
    memset(&e, 0, ObjAppEntry.sizeof);
    e.inUse = 1;
    setStr(e.name.ptr, e.nameLen, name, 64);
    setStr(e.identity.ptr, e.identityLen, identity, 32);
    e.rights = rights;

    e.manifestLen = cast(uint)manifest.length;
    e.manifestLba = allocBlob(e.manifestLen);
    e.permsLen = cast(uint)perms.length;
    e.permsLba = allocBlob(e.permsLen);
    e.execLen = cast(uint)exec.length;
    e.execLba = e.execLen ? allocBlob(e.execLen) : 0;
    e.storageLen = cast(uint)storage0.length;
    e.storageCap = 8;                          // reserve 8 sectors (4 KiB) for storage
    e.storageLba = allocBlob(e.storageLen, 8);

    if (!writeBlob(e.manifestLba, manifest.ptr, e.manifestLen)) return false;
    if (!writeBlob(e.permsLba, perms.ptr, e.permsLen)) return false;
    if (e.execLen && !writeBlob(e.execLba, exec.ptr, e.execLen)) return false;
    if (!writeBlob(e.storageLba, storage0.ptr, e.storageLen)) return false;

    g_apps[slot] = e;
    g_super.appCount++;
    return flushMeta();
}

// Overwrite an app's private storage blob (the round-trip-across-reboot area).
public bool objstoreStorageWrite(int appIdx, const(void)* data, uint len) {
    if (!g_mounted || appIdx < 0 || appIdx >= MAX_APPS || !g_apps[appIdx].inUse) return false;
    if (sectorsFor(len) > g_apps[appIdx].storageCap) return false;   // would overrun reservation
    if (!writeBlob(g_apps[appIdx].storageLba, data, len)) return false;
    g_apps[appIdx].storageLen = len;
    return flushMeta();
}

// ── DOMAIN_MANAGER DM5: persist + rehydrate domain definitions ────────────────
// Persist a domain's definition (name / identity / template / persist mode).  Idempotent
// on name: replaces an existing entry of the same name.  Returns false if the table is full.
public bool objstoreInstallDomain(const(char)[] name, const(char)[] identity,
                                  const(char)[] template_, ubyte persist) {
    if (!g_mounted) return false;
    int slot = -1;
    // replace a same-named entry, else take a free slot
    foreach (i; 0 .. cast(int)DOM_MAX_PERSIST) {
        if (g_domEntries[i].inUse && g_domEntries[i].nameLen == name.length) {
            bool eq = true;
            foreach (j; 0 .. cast(int)name.length) if (g_domEntries[i].name[j] != name[j]) { eq = false; break; }
            if (eq) { slot = i; break; }
        }
    }
    if (slot < 0) foreach (i; 0 .. cast(int)DOM_MAX_PERSIST) if (!g_domEntries[i].inUse) { slot = i; break; }
    if (slot < 0) return false;
    const bool isNew = !g_domEntries[slot].inUse;

    DomainEntry e;
    memset(&e, 0, DomainEntry.sizeof);
    e.inUse = 1;
    setStr(e.name.ptr, e.nameLen, name, 64);
    setStr(e.identity.ptr, e.identityLen, identity, 32);
    setStr(e.template_.ptr, e.templateLen, template_, 32);
    e.persistMode = persist;
    g_domEntries[slot] = e;
    if (isNew) g_super.domainCount++;
    return flushMeta();
}

public uint objstoreDomainCount() { return g_mounted ? g_super.domainCount : 0; }

// The i-th persisted domain (for rehydration). `name`/`identity` are NUL-terminated (the
// fixed buffers are zero-padded).  Returns false past the last in-use entry.
public bool objstoreDomainAt(int i, out const(char)* name, out const(char)* identity, out uint persist) {
    if (!g_mounted || i < 0 || i >= cast(int)DOM_MAX_PERSIST || !g_domEntries[i].inUse) return false;
    name     = g_domEntries[i].name.ptr;
    identity = g_domEntries[i].identity.ptr;
    persist  = g_domEntries[i].persistMode;
    return true;
}

// Directory accessors for the /objects/apps FS views.
public int objstoreAppByName(const(char)* name, uint nameLen) {
    if (!g_mounted) return -1;
    foreach (i; 0 .. MAX_APPS) {
        if (!g_apps[i].inUse || g_apps[i].nameLen != nameLen) continue;
        bool eq = true;
        foreach (j; 0 .. nameLen) if (g_apps[i].name[j] != name[j]) { eq = false; break; }
        if (eq) return cast(int)i;
    }
    return -1;
}
// Nth installed app's name → buf; returns len, or -1 past the end.
public int objstoreAppEnum(int logical, char* buf, uint cap) {
    if (!g_mounted) return -1;
    int n = 0;
    foreach (i; 0 .. MAX_APPS) if (g_apps[i].inUse) {
        if (n == logical) {
            uint l = g_apps[i].nameLen < cap ? g_apps[i].nameLen : cap;
            foreach (j; 0 .. l) buf[j] = g_apps[i].name[j];
            return cast(int)l;
        }
        ++n;
    }
    return -1;
}
public ObjAppEntry* objstoreApp(int idx) {
    if (!g_mounted || idx < 0 || idx >= MAX_APPS || !g_apps[idx].inUse) return null;
    return &g_apps[idx];
}
public uint objstoreAppRights(int idx) {
    auto e = objstoreApp(idx); return e is null ? 0 : e.rights;
}

// F4.2: parse "/objects/apps/<app>/executable" -> the app index (-1 otherwise).
public int objstoreResolveExecPath(const(char)* path) {
    if (!g_mounted || path is null) return -1;
    static immutable string pre = "/objects/apps/";
    foreach (i; 0 .. pre.length) if (path[i] != pre[i]) return -1;
    const(char)* p = path + pre.length;
    uint nlen = 0; while (p[nlen] != 0 && p[nlen] != '/') ++nlen;
    if (p[nlen] != '/') return -1;
    const(char)* rest = p + nlen + 1;
    static immutable string ex = "executable";
    foreach (i; 0 .. ex.length) if (rest[i] != ex[i]) return -1;
    if (rest[ex.length] != 0) return -1;
    return objstoreAppByName(p, nlen);
}

// F4.2: load an app's executable blob into a DMA buffer for execve; returns its
// physical address + length (so the ELF loader can map it like a boot module).
__gshared void*  g_execVirt = null;
__gshared size_t g_execPhys = 0;
enum uint EXEC_BUF_BYTES = 262144;            // 256 KiB cap for an app image
public bool objstoreLoadExec(int idx, ulong* physOut, ulong* sizeOut) {
    auto e = objstoreApp(idx);
    if (e is null || e.execLen == 0 || e.execLen > EXEC_BUF_BYTES) return false;
    if (g_execVirt is null) {
        g_execVirt = dma_alloc(EXEC_BUF_BYTES, 4096, &g_execPhys);
        if (g_execVirt is null) return false;
    }
    const uint sec = sectorsFor(e.execLen);
    if (!diskReadSectors(e.execLba, sec, g_execVirt)) return false;
    *physOut = cast(ulong)g_execPhys;
    *sizeOut = cast(ulong)e.execLen;
    return true;
}

// Mount the on-disk store (format on first use), bump + persist the boot counter,
// and seed sample apps so /objects/apps has something to show on first boot.
// `sampleExec`/`sampleExecLen` = the app image (store-app boot module) the kernel
// installs into the seeded apps' executable blobs.
public void objstoreMount(const(void)* sampleExec = null, uint sampleExecLen = 0) {
    if (!diskReady()) { klog("[objstore] no disk — /objects/apps stays empty\n"); return; }

    // INSTALLER §D: never claim a GPT-partitioned disk.  On an INSTALLED EpinAnonymOS system
    // the first disk's LBA0 is the boot GPT; formatting a raw object store over it would wipe
    // the bootloader.  Such a disk → store stays unmounted (in-memory), so the OS boots again.
    {
        import drivers.block.disk : diskFirstSectorIsGpt;
        if (diskFirstSectorIsGpt()) {
            klog("[objstore] disk is GPT-partitioned (installed system) — store stays in-memory\n");
            g_mounted = false;
            return;
        }
    }

    if (!diskReadSectors(0, 1, &g_super)) { klog("[objstore] superblock read failed\n"); return; }
    g_mounted = true;

    if (!magicOk()) {
        klog("[objstore] formatting new object store\n");
        memset(&g_super, 0, ObjSuper.sizeof);
        foreach (i; 0 .. 8) g_super.magic[i] = OBJ_MAGIC[i];
        g_super.version_ = 2;                  // DM5: v2 adds the domain directory
        g_super.appCount = 0;
        g_super.bootCount = 0;
        g_super.domainCount = 0;
        g_super.nextFreeLba = BLOB_LBA_BASE;
        memset(g_apps.ptr, 0, MAX_APPS * ObjAppEntry.sizeof);
        memset(g_domEntries.ptr, 0, DOM_MAX_PERSIST * DomainEntry.sizeof);   // DM5
        flushMeta();
        seedSampleApp(sampleExec, sampleExecLen);
    } else {
        // load the app directory
        diskReadSectors(DIR_LBA, sectorsFor(MAX_APPS * ObjAppEntry.sizeof), g_apps.ptr);
        // DM5: load the domain directory (v2+); an old v1 disk has none → start empty
        if (g_super.version_ >= 2 && g_super.domainCount <= DOM_MAX_PERSIST) {
            diskReadSectors(DOM_DIR_LBA, sectorsFor(DOM_MAX_PERSIST * DomainEntry.sizeof), g_domEntries.ptr);
        } else {
            memset(g_domEntries.ptr, 0, DOM_MAX_PERSIST * DomainEntry.sizeof);
            g_super.domainCount = 0;
            g_super.version_ = 2;
        }
    }

    g_super.bootCount++;
    flushMeta();

    // Demonstrate the private storage area persisting AND updating across reboots:
    // stamp the sample app's storage with the live boot count (read from disk).
    int hi = objstoreAppByName("hello".ptr, 5);
    if (hi >= 0) {
        char[32] sbuf = void; uint p = 0;
        foreach (c; "boots=") sbuf[p++] = c;
        ulong v = g_super.bootCount; char[20] t = void; int ti = 0;
        if (!v) t[ti++] = '0'; while (v) { t[ti++] = cast(char)('0' + v % 10); v /= 10; }
        while (ti > 0) sbuf[p++] = t[--ti];
        sbuf[p++] = '\n';
        objstoreStorageWrite(hi, sbuf.ptr, p);
    }

    klog("[objstore] mounted: apps=0x"); klog_hex(g_super.appCount);
    klog(" boots=0x"); klog_hex(g_super.bootCount); klog("\n");
}

private void seedSampleApp(const(void)* exec, uint execLen) {
    const(void)[] image = exec is null ? null : exec[0 .. execLen];

    // "hello": declares rights 0x3 (ipc|storage) — a subset of any domain ceiling, so
    // it launches.  Its executable is the store-app image (prints a line + exits).
    static immutable string helloManifest =
        "{\n  \"name\": \"hello\",\n  \"version\": \"1.0\",\n  \"identity\": \"Personal\",\n"
        ~ "  \"exec\": \"/objects/apps/hello/executable\",\n"
        ~ "  \"capabilities\": [\"ipc\", \"storage\"]\n}\n";
    static immutable string helloPerms =
        "{\n  \"net\": false,\n  \"storage\": true,\n  \"ipc\": true,\n  \"rights\": \"0x3\"\n}\n";
    objstoreInstallApp("hello", "Personal", 0x3, helloManifest, helloPerms, image,
                       "installed on first boot\n");

    // "rogue": declares rights 0x100000 — a bit OUTSIDE the System ceiling (0x7ffff),
    // so launching it is denied by the cap-gate (declared ⊄ caller's identity ceiling).
    static immutable string rogueManifest =
        "{\n  \"name\": \"rogue\",\n  \"version\": \"1.0\",\n  \"identity\": \"Untrusted\",\n"
        ~ "  \"exec\": \"/objects/apps/rogue/executable\",\n"
        ~ "  \"capabilities\": [\"admin-everything\"]\n}\n";
    static immutable string roguePerms =
        "{\n  \"net\": true,\n  \"storage\": true,\n  \"ipc\": true,\n  \"rights\": \"0x100000\"\n}\n";
    objstoreInstallApp("rogue", "Untrusted", 0x100000, rogueManifest, roguePerms, image,
                       "over-privileged demo app\n");
}
