// ─────────────────────────────────────────────────────────────────────────────
// Native object-FS partition engine (roadmap/INSTALLER.md §D2(b)).
//
// The udev-free, libparted-free, rootless partitioning backend for the in-OS
// Calamares installer.  The kernel owns block I/O (drivers.block.disk) and the
// capabilities, so the installer never touches raw devices — it asks the kernel to
// "lay down GPT + ESP + rootfs" on a target disk.  This module is the GPT layout
// primitive: it BUILDS a spec-valid GPT (protective MBR + GPT header + a 128-entry
// array with an EFI System Partition + a Linux root partition, all CRC32-checked)
// and VALIDATES one back.  Writing it to a disk via diskWriteSectors() is a thin,
// cap-gated step layered on top (subsequent §D2(b) work); building/validating is
// pure in-memory, so the boot proof never risks the live object store.
//
// Built byte-at-offset (little-endian) rather than via packed structs, so the
// on-disk layout is exact and independent of D struct packing.
// ─────────────────────────────────────────────────────────────────────────────
module core.diskpart;

import core.io : klog, klog_hex;

@nogc nothrow:

enum uint SECTOR        = 512;
enum uint GPT_ENTRIES   = 128;            // standard GPT array size
enum uint GPT_ENTSZ     = 128;            // bytes per entry
enum uint ENTRY_SECTORS = (GPT_ENTRIES * GPT_ENTSZ) / SECTOR;   // 32
enum uint PRIMARY_SECTORS = 2 + ENTRY_SECTORS;                  // MBR + header + entries = 34
enum ulong FIRST_USABLE = 2 + ENTRY_SECTORS;                    // LBA 34

// EFI System Partition type GUID  C12A7328-F81F-11D2-BA4B-00A0C93EC93B
static immutable ubyte[16] GUID_ESP = [
    0x28,0x73,0x2A,0xC1, 0x1F,0xF8, 0xD2,0x11, 0xBA,0x4B, 0x00,0xA0,0xC9,0x3E,0xC9,0x3B];
// Linux root (x86-64) type GUID    4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709
static immutable ubyte[16] GUID_LINUX_ROOT = [
    0xE3,0xBC,0x68,0x4F, 0xCD,0xE8, 0xB1,0x4D, 0x96,0xE7, 0xFB,0xCA,0xF9,0x84,0xB7,0x09];
static immutable ubyte[8] GPT_SIG = ['E','F','I',' ','P','A','R','T'];

// ── little-endian writers/readers ────────────────────────────────────────────
private void put16(ubyte* b, size_t off, ushort v) {
    b[off] = cast(ubyte)(v); b[off+1] = cast(ubyte)(v >> 8);
}
private void put32(ubyte* b, size_t off, uint v) {
    foreach (i; 0 .. 4) b[off+i] = cast(ubyte)(v >> (8*i));
}
private void put64(ubyte* b, size_t off, ulong v) {
    foreach (i; 0 .. 8) b[off+i] = cast(ubyte)(v >> (8*i));
}
private uint get32(const(ubyte)* b, size_t off) {
    return cast(uint)b[off] | (cast(uint)b[off+1]<<8) | (cast(uint)b[off+2]<<16) | (cast(uint)b[off+3]<<24);
}
private ulong get64(const(ubyte)* b, size_t off) {
    ulong v = 0; foreach (i; 0 .. 8) v |= (cast(ulong)b[off+i]) << (8*i); return v;
}

// ── CRC32 (IEEE 802.3, reflected, init/final 0xFFFFFFFF) — what GPT uses ──────
uint crc32(const(ubyte)* data, size_t len) {
    uint crc = 0xFFFFFFFFu;
    foreach (i; 0 .. len) {
        crc ^= data[i];
        foreach (_; 0 .. 8)
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320u : (crc >> 1);
    }
    return crc ^ 0xFFFFFFFFu;
}

// A pseudo-unique 16-byte GUID derived from a seed (rdtsc at call time + a salt).
// Not cryptographically random, but distinct per partition for the proof and a real
// install alike; a future hardening can swap in a CSPRNG.
private void fillGuid(ubyte* dst, ulong seed) {
    ulong x = seed * 0x9E3779B97F4A7C15UL + 0x1234567890ABCDEFUL;
    foreach (i; 0 .. 16) {
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27; x *= 0x2545F4914F6CDD1DUL;
        dst[i] = cast(ubyte)(x >> ((i & 7) * 8));
    }
    dst[6] = cast(ubyte)((dst[6] & 0x0F) | 0x40);   // version 4
    dst[8] = cast(ubyte)((dst[8] & 0x3F) | 0x80);   // variant
}

private ulong rdtscSeed() {
    uint lo, hi;
    asm @nogc nothrow { rdtsc; mov lo, EAX; mov hi, EDX; }
    return (cast(ulong)hi << 32) | lo;
}

// Layout describing what gptBuildPrimary laid down (for the caller / validation).
struct GptLayout {
    ulong diskSectors;
    ulong espFirst, espLast;       // EFI System Partition (FAT32) LBA range
    ulong rootFirst, rootLast;     // Linux root partition LBA range
}

// Build the PRIMARY GPT region — protective MBR (LBA0) + GPT header (LBA1) +
// 128-entry array (LBA2..33) — into `buf` (>= PRIMARY_SECTORS*SECTOR bytes), for a
// disk of `diskSectors` 512-byte sectors with an ESP of `espSectors`.  Returns the
// resulting layout.  Caller writes buf to LBA0 (and a backup header/array to the
// disk tail) to commit; the boot proof only builds + validates in memory.
GptLayout gptBuildPrimary(ubyte* buf, ulong diskSectors, ulong espSectors) {
    GptLayout L;
    L.diskSectors = diskSectors;
    foreach (i; 0 .. PRIMARY_SECTORS * SECTOR) buf[i] = 0;

    const ulong lastLba   = diskSectors - 1;
    const ulong firstUse  = FIRST_USABLE;
    const ulong lastUse   = lastLba - 1 - ENTRY_SECTORS;   // leave room for backup hdr+array
    L.espFirst  = firstUse;
    L.espLast   = firstUse + espSectors - 1;
    L.rootFirst = L.espLast + 1;
    L.rootLast  = lastUse;

    // ── Protective MBR (LBA0): one 0xEE partition spanning the disk ──────────
    ubyte* mbr = buf;
    mbr[446 + 0] = 0x00;                 // status
    mbr[446 + 4] = 0xEE;                 // type = GPT protective
    put32(mbr, 446 + 8, 1);              // first LBA = 1
    const ulong span = (diskSectors - 1 > 0xFFFFFFFFUL) ? 0xFFFFFFFFUL : (diskSectors - 1);
    put32(mbr, 446 + 12, cast(uint)span);
    mbr[510] = 0x55; mbr[511] = 0xAA;

    // ── Partition entry array (LBA2..33) ─────────────────────────────────────
    ubyte* ents = buf + 2 * SECTOR;
    void writeEntry(uint idx, const ubyte[16] typeGuid, ulong first, ulong last, ulong seed) {
        ubyte* e = ents + idx * GPT_ENTSZ;
        foreach (i; 0 .. 16) e[i] = typeGuid[i];      // partition type GUID
        fillGuid(e + 16, seed);                        // unique partition GUID
        put64(e, 32, first);
        put64(e, 40, last);
        put64(e, 48, 0);                               // attributes
        // name (offset 56, 36 UTF-16LE chars) left zero
    }
    const ulong baseSeed = rdtscSeed();
    writeEntry(0, GUID_ESP,        L.espFirst,  L.espLast,  baseSeed);
    writeEntry(1, GUID_LINUX_ROOT, L.rootFirst, L.rootLast, baseSeed + 0x100);
    const uint entriesCrc = crc32(ents, GPT_ENTRIES * GPT_ENTSZ);

    // ── GPT header (LBA1) ────────────────────────────────────────────────────
    ubyte* h = buf + SECTOR;
    foreach (i; 0 .. 8) h[i] = GPT_SIG[i];
    put32(h, 8,  0x00010000);            // revision 1.0
    put32(h, 12, 92);                    // header size
    put32(h, 16, 0);                     // header CRC (zero while computing)
    put32(h, 20, 0);                     // reserved
    put64(h, 24, 1);                     // current LBA
    put64(h, 32, lastLba);               // backup LBA
    put64(h, 40, firstUse);              // first usable
    put64(h, 48, lastUse);               // last usable
    fillGuid(h + 56, baseSeed + 0x200);  // disk GUID
    put64(h, 72, 2);                     // partition entries start LBA
    put32(h, 80, GPT_ENTRIES);           // num entries
    put32(h, 84, GPT_ENTSZ);             // entry size
    put32(h, 88, entriesCrc);            // partition array CRC32
    const uint hdrCrc = crc32(h, 92);
    put32(h, 16, hdrCrc);                // header CRC32 (over the 92 bytes, CRC field 0)
    return L;
}

// Validate a PRIMARY GPT region built/read into `buf` (>= PRIMARY_SECTORS*SECTOR).
// Checks: protective MBR signature + 0xEE; GPT signature; header CRC; entry-array
// CRC; and that the first two entries are non-empty (ESP + root).  Returns true iff
// the table is spec-valid and self-consistent.
bool gptValidate(const(ubyte)* buf) {
    // protective MBR
    if (buf[510] != 0x55 || buf[511] != 0xAA) return false;
    if (buf[446 + 4] != 0xEE) return false;

    const(ubyte)* h = buf + SECTOR;
    foreach (i; 0 .. 8) if (h[i] != GPT_SIG[i]) return false;
    if (get32(h, 12) != 92) return false;

    // header CRC: recompute with the CRC field zeroed
    ubyte[92] tmp = void;
    foreach (i; 0 .. 92) tmp[i] = h[i];
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
    if (crc32(tmp.ptr, 92) != get32(h, 16)) return false;

    const uint numEnt = get32(h, 80);
    const uint entSz  = get32(h, 84);
    if (numEnt != GPT_ENTRIES || entSz != GPT_ENTSZ) return false;

    const(ubyte)* ents = buf + 2 * SECTOR;
    if (crc32(ents, GPT_ENTRIES * GPT_ENTSZ) != get32(h, 88)) return false;

    // entry 0 (ESP) + entry 1 (root): type GUID present + sane LBA range
    bool entryOk(uint idx, const ubyte[16] want) {
        const(ubyte)* e = ents + idx * GPT_ENTSZ;
        foreach (i; 0 .. 16) if (e[i] != want[i]) return false;
        const ulong first = get64(e, 32), last = get64(e, 40);
        return first >= FIRST_USABLE && last >= first;
    }
    if (!entryOk(0, GUID_ESP)) return false;
    if (!entryOk(1, GUID_LINUX_ROOT)) return false;
    return true;
}

// Boot proof (mirrors the kernel's other one-shot proofs): build a GPT for a
// synthetic 8 GiB disk with a 512 MiB ESP, entirely in memory, then validate it
// back and corrupt-check.  Never writes a disk, so the live object store is safe.
public void gptPartProof() {
    enum ulong DISK = (8UL * 1024 * 1024 * 1024) / SECTOR;   // 8 GiB in sectors
    enum ulong ESP  = (512UL * 1024 * 1024) / SECTOR;        // 512 MiB ESP
    __gshared ubyte[PRIMARY_SECTORS * SECTOR] buf;
    GptLayout L = gptBuildPrimary(buf.ptr, DISK, ESP);
    if (!gptValidate(buf.ptr)) { klog("[diskpart] GPT proof FAIL (validate)\n"); return; }
    // negative check: flip a byte in the entry array → CRC must reject it
    buf[2 * SECTOR + 40] ^= 0xFF;
    if (gptValidate(buf.ptr)) { klog("[diskpart] GPT proof FAIL (corruption not caught)\n"); return; }
    klog("[diskpart] GPT proof PASS (built+validated ESP esp_lba=0x"); klog_hex(L.espFirst);
    klog(" root_lba=0x"); klog_hex(L.rootFirst);
    klog(" last_usable=0x"); klog_hex(L.rootLast); klog("; corruption rejected)\n");
}
