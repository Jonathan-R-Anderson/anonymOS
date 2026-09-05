// ─────────────────────────────────────────────────────────────────────────────
// Persisted object store  (OBJECT_FILESYSTEM_ROADMAP F4 — the north star)
//
// Backs /objects/apps with REAL storage on the SATA disk so objects + their data
// survive reboot.  Apps are first-class objects: each carries a manifest, declared
// permissions, an identity binding, and a private writable `storage` blob — the
// only area an app may mutate, separate from the immutable system base (F3).
//
// On-disk layout (sector = 512B).  These are all RELATIVE to g_baseLba — see the
// "where the store lives on the disk" note below; on a raw disk the base is 0, on an
// installed (GPT) system the whole layout is offset into the pre-partition gap.
//   LBA 0        superblock (magic, version, appCount, bootCount, nextFreeLba)
//   LBA 1..32    app directory  (ObjAppEntry, 256B each → 2/sector, 64 entries)
//   LBA 33..48   domain directory (DomainEntry, 256B each, 32 entries)  [DM5]
//   LBA 64..     blob region (manifest / permissions / executable / storage),
//                allocated sequentially, sector-granular.
//
// A bootCount in the superblock, bumped every mount, is the persistence proof:
// it keeps climbing across reboots because it is read from and written to disk.
// ─────────────────────────────────────────────────────────────────────────────
module core.objstore;

import drivers.block.disk : diskReady, diskReadSectors, diskWriteSectors;
import memory.dma : dma_alloc;
import core.io : klog, klog_hex, klog_dec;
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
    // ROADMAP 1.2: one large blob holding the serialised /home subtree.  Kept in the superblock
    // rather than the app directory because it is not an app -- it is the filesystem snapshot,
    // written once per reboot and read once per boot.  v3 adds these; a v2 disk is upgraded in
    // place on mount (the fields read back as zero, which means "no snapshot yet").
    // domainCount ends at offset 36, and a ulong wants 8-byte alignment, so the compiler would
    // insert 4 invisible bytes here and the struct would be 520 -- caught by the static assert
    // below.  Spell the gap out instead: an on-disk layout must never depend on what the
    // compiler chooses to pad.
    uint    _rsv0;              // explicit alignment filler (offset 36..39)
    ulong   fsBlobLba;          // relative LBA of the snapshot (0 = none)   offset 40
    uint    fsBlobLen;          // bytes actually stored                     offset 48
    uint    fsBlobCap;          // sectors reserved, so a growing /home does not have to move
    ubyte[SECTOR - 56] _pad;
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

// ── ROADMAP 1.2: where the store lives on the disk ────────────────────────────────────────
//
// Every LBA in this module (DIR_LBA, DOM_DIR_LBA, BLOB_LBA_BASE, and every ObjAppEntry.*Lba
// written to disk) is RELATIVE to g_baseLba.  On a raw, unpartitioned disk g_baseLba is 0 and
// nothing changes.  On a GPT-partitioned disk -- i.e. an INSTALLED EpinAnonymOS -- the store
// moves into the pre-partition gap instead of refusing to mount at all.
//
// Why the gap is safe.  A GPT disk's opening sectors are fixed by the spec and by what this
// project's own installer lays down (diskpart.d):
//     LBA 0        protective MBR
//     LBA 1        GPT header
//     LBA 2..33    the 128-entry partition array (ENTRY_SECTORS = 32)
//     LBA 34       boot-state sector (core.bootstate.BOOTSTATE_LBA)
//     LBA 35..2047 UNUSED -- diskpart.d's align2048() starts the first partition at 2048
//     LBA 2048+    partitions (ESP, slots, decoy/outer volumes)
// So writing inside [GPT_GAP_FIRST, GPT_GAP_END) touches neither the bootloader, nor the
// partition table, nor any partition's contents.  That is the whole reason the previous code
// refused: it wrote the superblock at absolute LBA 0 and would have destroyed the GPT.
//
// The cost is size: the gap is ~1 MiB, so this persists the app + domain DIRECTORIES and their
// small blobs, not a general filesystem.  g_endLba makes that a hard wall rather than silent
// corruption of partition 1 -- allocBlob() now fails instead of walking past the end.
enum ulong GPT_GAP_FIRST = 40;      // 34 is bootstate; 35..39 left as slack
enum ulong GPT_GAP_END   = 2048;    // exclusive -- diskpart.d align2048() puts partition 0 here

__gshared ulong g_baseLba = 0;      // absolute LBA of this store's relative sector 0
__gshared ulong g_endLba  = 0;      // first absolute LBA the store may NOT touch (0 = unbounded)

public bool objstoreMounted() { return g_mounted; }
public ulong objstoreBootCount() { return g_super.bootCount; }
public uint  objstoreAppCount() { return g_super.appCount; }
public ulong objstoreBaseLba() { return g_baseLba; }

// All store I/O goes through these two.  They translate relative -> absolute and enforce the
// upper wall, so no code path in this module can write outside its region even if a length or a
// persisted LBA is wrong.
private bool stRead(ulong rel, uint count, void* dst) {
    const ulong a = g_baseLba + rel;
    if (g_endLba != 0 && (a + count) > g_endLba) return false;
    return diskReadSectors(a, count, dst);
}
private bool stWrite(ulong rel, uint count, const(void)* src) {
    const ulong a = g_baseLba + rel;
    if (g_endLba != 0 && (a + count) > g_endLba) return false;
    return diskWriteSectors(a, count, src);
}

private uint sectorsFor(uint bytes) { return (bytes + SECTOR - 1) / SECTOR; }

private bool magicOk() {
    foreach (i; 0 .. 8) if (g_super.magic[i] != OBJ_MAGIC[i]) return false;
    return true;
}

// Persist the superblock (LBA 0) and the directory (LBA 1..32).
private bool flushMeta() {
    if (!stWrite(0, 1, &g_super)) return false;
    // app directory: MAX_APPS*256 bytes = 16 KiB = 32 sectors
    if (!stWrite(DIR_LBA, sectorsFor(MAX_APPS * ObjAppEntry.sizeof), g_apps.ptr)) return false;
    // DM5 domain directory: DOM_MAX_PERSIST*256 = 8 KiB = 16 sectors
    return stWrite(DOM_DIR_LBA, sectorsFor(DOM_MAX_PERSIST * DomainEntry.sizeof), g_domEntries.ptr);
}

// Allocate a blob region of `len` bytes; returns its relative LBA, or 0 = OUT OF ROOM.
//
// This used to bump nextFreeLba unconditionally, which was survivable only because the store
// owned an entire raw disk.  Inside the ~1 MiB GPT gap an unbounded allocator would hand out
// LBAs past GPT_GAP_END and the first write would land in partition 0 (the ESP).  Refusing is
// the only safe answer, so callers MUST check for 0 -- and writeBlob() refuses lba 0 as a second
// line of defence, since relative 0 is the superblock.
private ulong allocBlob(uint len, uint reserveSectors = 0) {
    uint sec = sectorsFor(len);
    if (reserveSectors > sec) sec = reserveSectors;
    const ulong lba = g_super.nextFreeLba;
    if (g_endLba != 0 && (g_baseLba + lba + sec) > g_endLba) return 0;   // store region full
    g_super.nextFreeLba += sec;
    return lba;
}

// Write `len` bytes to a blob at `lba` (zero-pads the trailing sector).
private bool writeBlob(ulong lba, const(void)* data, uint len) {
    if (lba < BLOB_LBA_BASE) return false;   // 0 = allocation failed; never scribble on metadata
    if (len > STAGE_BYTES) return false;
    const uint sec = sectorsFor(len);
    memset(g_stage.ptr, 0, sec * SECTOR);
    if (len) memcpy(g_stage.ptr, data, len);
    return stWrite(lba, sec, g_stage.ptr);
}

// ── ROADMAP 1.2: the filesystem snapshot blob ────────────────────────────────
//
// writeBlob()/objstoreReadBlob() both stage through g_stage, which is 64 KiB, so neither can
// carry a /home image.  These two stream straight to and from the disk in STAGE_BYTES chunks
// instead, with no single allocation proportional to the payload.
//
// The region is reserved ONCE and reused: a snapshot is rewritten on every reboot, and
// reallocating each time would walk nextFreeLba up the disk until the store filled with dead
// copies of previous boots.  fsBlobCap is that reservation in sectors.
public bool objstoreSaveBlob(const(void)* data, uint len) {
    if (!g_mounted || data is null) return false;
    const uint need = sectorsFor(len);

    if (g_super.fsBlobLba == 0 || need > g_super.fsBlobCap) {
        // First save, or the snapshot outgrew its reservation.  Reserve with headroom so
        // ordinary growth does not trigger a second allocation every boot.
        const uint want = need + (need / 2) + 16;
        const ulong lba = allocBlob(0, want);
        if (lba == 0) { klog("[objstore] no room for the /home snapshot\n"); return false; }
        g_super.fsBlobLba = lba;
        g_super.fsBlobCap = want;
    }

    auto src = cast(const(ubyte)*)data;
    uint done = 0;
    ulong lba = g_super.fsBlobLba;
    while (done < len) {
        uint chunk = len - done;
        if (chunk > STAGE_BYTES) chunk = STAGE_BYTES;
        const uint sec = sectorsFor(chunk);
        memset(g_stage.ptr, 0, sec * SECTOR);        // zero-pad the trailing sector
        memcpy(g_stage.ptr, src + done, chunk);
        if (!stWrite(lba, sec, g_stage.ptr)) return false;
        lba  += sec;
        done += chunk;
    }
    g_super.fsBlobLen = len;
    return flushMeta();
}

// Read the snapshot back into `dst`; returns the byte count (0 = none stored).
public uint objstoreLoadBlob(ubyte* dst, uint cap) {
    if (!g_mounted || dst is null) return 0;
    if (g_super.fsBlobLba == 0 || g_super.fsBlobLen == 0) return 0;
    uint want = g_super.fsBlobLen;
    if (want > cap) want = cap;

    uint done = 0;
    ulong lba = g_super.fsBlobLba;
    while (done < want) {
        uint chunk = want - done;
        if (chunk > STAGE_BYTES) chunk = STAGE_BYTES;
        const uint sec = sectorsFor(chunk);
        if (!stRead(lba, sec, g_stage.ptr)) return done;
        memcpy(dst + done, g_stage.ptr, chunk);
        lba  += sec;
        done += chunk;
    }
    return done;
}

// Read up to `cap` bytes of a blob (`len` bytes) at `lba` into `dst`; returns count.
public int objstoreReadBlob(ulong lba, uint len, ubyte* dst, uint cap) {
    if (!g_mounted || lba == 0 || len == 0) return 0;
    uint want = len < cap ? len : cap;
    const uint sec = sectorsFor(want);
    if (sec * SECTOR > STAGE_BYTES) return 0;
    if (!stRead(lba, sec, g_stage.ptr)) return 0;
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

    // allocBlob returns 0 when the store region is full (see its note).  Bail BEFORE any write:
    // the entry is not yet published, and nextFreeLba only moved for the allocations that did
    // succeed, so a full store simply refuses new apps instead of corrupting the ones it has.
    // execLba is legitimately 0 when there is no executable, hence the execLen guard.
    if (e.manifestLba == 0 || e.permsLba == 0 || e.storageLba == 0 ||
        (e.execLen != 0 && e.execLba == 0)) {
        klog("[objstore] store region full — app not installed\n");
        return false;
    }

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
    if (!stRead(e.execLba, sec, g_execVirt)) return false;
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

    // INSTALLER §D: on an INSTALL image (the esp-image payload is present), don't claim any
    // disk — leave it free as the install target, so a single-disk machine can install onto its
    // only disk without the live store racing/clobbering the write.  Store stays in-memory.
    {
        import drivers.veracrypt_impl : bootHasInstallPayload;
        if (bootHasInstallPayload()) {
            klog("[objstore] INSTALL image — store stays in-memory (disk is a free install target)\n");
            g_mounted = false;
            return;
        }
    }

    // ROADMAP 1.2 — persistence on an INSTALLED system.
    //
    // This used to refuse a GPT-partitioned disk outright and fall back to an in-memory store,
    // with the note "formatting a raw object store over it would wipe the bootloader".  That was
    // the right call for the code as written (the superblock went to absolute LBA 0, straight
    // over the protective MBR) but it meant persistence could NEVER work on an installed system,
    // which is precisely what roadmap 1.2 asks for: an installed OS whose state survives reboot.
    //
    // A GPT disk is not out of bounds, only its first 34 sectors and its partitions are.  The
    // gap between the partition array and the first partition is unused by the spec and by this
    // project's own installer, so the store relocates there instead of refusing.  Everything in
    // this module addresses sectors relative to g_baseLba, and g_endLba is a hard wall.
    {
        import drivers.block.disk : diskFirstSectorIsGpt, diskFindTarget;
        import core.diskpart : gptTailFreeSpace;
        if (diskFirstSectorIsGpt()) {
            // PREFERRED: the unallocated tail after the last partition.  The A/B layout uses
            // ESP-boot + slot-A + slot-B ~= 650 MiB, so a 4 GiB target leaves ~3.3 GiB free
            // past slot-B -- room for an actual filesystem, where the pre-partition gap below
            // is ~1 MiB and only ever held the directories.
            ulong total = 0;
            const int di = diskFindTarget(total);
            bool placed = false;
            if (di >= 0 && total > 0) {
                // Require 64 MiB before bothering; a sliver is not worth the extra code path.
                auto tail = gptTailFreeSpace(di, total, 131072);
                if (tail.valid) {
                    g_baseLba = tail.first;
                    g_endLba  = tail.last + 1;         // exclusive
                    placed = true;
                    klog("[objstore] installed system (GPT) — store in the free tail, LBA 0x");
                    klog_hex(tail.first); klog("..0x"); klog_hex(tail.last);
                    klog(" ("); klog_dec((tail.last - tail.first + 1) / 2048); klog(" MiB)\n");
                }
            }
            if (!placed) {
                // FALLBACK: the pre-partition gap (see the note above).  Small, but safe on a
                // disk whose tail is already occupied.
                g_baseLba = GPT_GAP_FIRST;
                g_endLba  = GPT_GAP_END;
                klog("[objstore] installed system (GPT) — no usable tail; store in the pre-partition gap, LBA 0x");
                klog_hex(GPT_GAP_FIRST); klog("..0x"); klog_hex(GPT_GAP_END - 1); klog("\n");
            }
        } else {
            g_baseLba = 0;      // raw disk: the store owns the whole device, as before
            g_endLba  = 0;
        }
    }

    if (!stRead(0, 1, &g_super)) { klog("[objstore] superblock read failed\n"); return; }
    g_mounted = true;

    if (!magicOk()) {
        klog("[objstore] formatting new object store\n");
        memset(&g_super, 0, ObjSuper.sizeof);
        foreach (i; 0 .. 8) g_super.magic[i] = OBJ_MAGIC[i];
        g_super.version_ = 3;                  // v2 = domain directory (DM5); v3 = /home snapshot (1.2)
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
        stRead(DIR_LBA, sectorsFor(MAX_APPS * ObjAppEntry.sizeof), g_apps.ptr);
        // DM5: load the domain directory (v2+); an old v1 disk has none → start empty
        if (g_super.version_ >= 2 && g_super.domainCount <= DOM_MAX_PERSIST) {
            stRead(DOM_DIR_LBA, sectorsFor(DOM_MAX_PERSIST * DomainEntry.sizeof), g_domEntries.ptr);
        } else {
            memset(g_domEntries.ptr, 0, DOM_MAX_PERSIST * DomainEntry.sizeof);
            g_super.domainCount = 0;
            g_super.version_ = 2;
        }
        // ROADMAP 1.2: v3 adds the /home snapshot fields.  A v2 disk predates them, and the
        // bytes they now occupy were _pad -- which format() zeroed -- so they read back as 0,
        // meaning "no snapshot yet".  Upgrading is therefore just relabelling the version; the
        // first fsPersistSave() allocates the region.  Do NOT reformat: that would discard the
        // app and domain directories a v2 disk legitimately holds.
        if (g_super.version_ < 3) {
            g_super.fsBlobLba = 0;
            g_super.fsBlobLen = 0;
            g_super.fsBlobCap = 0;
            g_super.version_  = 3;
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
