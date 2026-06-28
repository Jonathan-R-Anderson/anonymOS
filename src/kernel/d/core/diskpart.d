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
import drivers.block.disk : diskFindTarget, diskReadSectorsOn, diskWriteSectorsOn;

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

// ── Commit a full GPT (primary + backup) to a TARGET disk ────────────────────
// Lays down: protective MBR + primary GPT header + entry array at the front, and
// the backup entry array + backup GPT header at the disk tail.  Caller must pick a
// disk that is NOT the live object-store disk (diskFindTarget).  Cap-gating (the
// one-shot block-write capability, Phase 11) belongs at the call site; this is the
// raw write.  Returns false on any I/O failure or a too-small disk.
bool gptWriteToDisk(int diskIdx, ulong diskSectors, ulong espSectors) {
    if (diskSectors < FIRST_USABLE + ENTRY_SECTORS + 64) return false;
    __gshared ubyte[PRIMARY_SECTORS * SECTOR] pbuf;     // MBR + header + entries (34 sectors)
    gptBuildPrimary(pbuf.ptr, diskSectors, espSectors);
    const ulong lastLba = diskSectors - 1;

    // primary region → LBA 0..33
    if (!diskWriteSectorsOn(diskIdx, 0, PRIMARY_SECTORS, pbuf.ptr)) return false;
    // backup entry array (same 128 entries) → (last-32) .. (last-1)
    if (!diskWriteSectorsOn(diskIdx, lastLba - ENTRY_SECTORS, ENTRY_SECTORS, pbuf.ptr + 2 * SECTOR))
        return false;
    // backup GPT header → last LBA: the primary header with current/backup/entry-start
    // fields fixed for the tail copy and the header CRC recomputed.
    __gshared ubyte[SECTOR] bhdr;
    foreach (i; 0 .. SECTOR) bhdr[i] = (pbuf.ptr + SECTOR)[i];
    put64(bhdr.ptr, 24, lastLba);                       // current LBA = last
    put64(bhdr.ptr, 32, 1);                             // backup LBA  = 1
    put64(bhdr.ptr, 72, lastLba - ENTRY_SECTORS);       // partition entries start = last-32
    put32(bhdr.ptr, 16, 0);
    put32(bhdr.ptr, 16, crc32(bhdr.ptr, 92));
    if (!diskWriteSectorsOn(diskIdx, lastLba, 1, bhdr.ptr)) return false;
    return true;
}

// ── Minimal FAT32 formatter for the ESP (UEFI/limine-readable) ───────────────
// Writes a valid, EMPTY FAT32 onto the ESP partition (espFirstLba .. +espSectors) of
// the target disk: boot sector/BPB + FSInfo + backup boot + the head of each FAT
// (cluster 2 = root dir, EOC).  The disk is assumed zeroed, so the rest of the FATs
// and the empty root cluster read as free/zero — a valid empty filesystem; a real
// install should zero the reserved+FAT region first for non-blank targets.
bool fatFormatEsp(int diskIdx, ulong espFirstLba, ulong espSectors) {
    enum uint RESERVED = 32;
    enum uint NUM_FATS = 2;
    const uint secPerClus = 1;                       // 512 B clusters — valid FAT32 at ESP sizes
    // Microsoft fatgen FAT-size formula (FAT32 variant).
    const ulong tmp1 = espSectors - RESERVED;
    const ulong tmp2 = (256UL * secPerClus + NUM_FATS) / 2;
    const uint fatSize = cast(uint)((tmp1 + (tmp2 - 1)) / tmp2);
    const ulong dataStart = RESERVED + cast(ulong)NUM_FATS * fatSize;
    if (dataStart + secPerClus > espSectors) return false;
    const uint totalClusters = cast(uint)((espSectors - dataStart) / secPerClus);
    if (totalClusters < 65525) return false;         // below this it isn't FAT32

    __gshared ubyte[SECTOR] s;
    void clr() { foreach (i; 0 .. SECTOR) s[i] = 0; }

    // boot sector / BPB
    clr();
    s[0] = 0xEB; s[1] = 0x58; s[2] = 0x90;
    immutable char[8] oem = ['M','S','W','I','N','4','.','1'];
    foreach (i; 0 .. 8) s[3 + i] = oem[i];
    put16(s.ptr, 11, 512);                           // bytes/sector
    s[13] = cast(ubyte)secPerClus;                   // sectors/cluster
    put16(s.ptr, 14, cast(ushort)RESERVED);          // reserved sectors
    s[16] = NUM_FATS;                                // FAT count
    put16(s.ptr, 17, 0);                             // root entries (0 on FAT32)
    put16(s.ptr, 19, 0);                             // total16 (use 32)
    s[21] = 0xF8;                                    // media
    put16(s.ptr, 22, 0);                             // FATsz16 (use 32)
    put16(s.ptr, 24, 32);                            // sectors/track
    put16(s.ptr, 26, 8);                             // heads
    put32(s.ptr, 28, cast(uint)espFirstLba);         // hidden sectors (partition LBA)
    put32(s.ptr, 32, cast(uint)espSectors);          // total32
    put32(s.ptr, 36, fatSize);                       // FATsz32
    put16(s.ptr, 40, 0);                             // ext flags
    put16(s.ptr, 42, 0);                             // fs version
    put32(s.ptr, 44, 2);                             // root cluster
    put16(s.ptr, 48, 1);                             // FSInfo sector
    put16(s.ptr, 50, 6);                             // backup boot sector
    s[64] = 0x80;                                    // drive number
    s[66] = 0x29;                                    // ext boot sig
    put32(s.ptr, 67, cast(uint)(rdtscSeed() | 1));   // volume serial
    immutable char[11] lbl = ['E','P','I','N',' ','E','S','P',' ',' ',' '];
    foreach (i; 0 .. 11) s[71 + i] = lbl[i];
    immutable char[8] fst = ['F','A','T','3','2',' ',' ',' '];
    foreach (i; 0 .. 8) s[82 + i] = fst[i];
    s[510] = 0x55; s[511] = 0xAA;
    if (!diskWriteSectorsOn(diskIdx, espFirstLba + 0, 1, s.ptr)) return false;     // boot
    if (!diskWriteSectorsOn(diskIdx, espFirstLba + 6, 1, s.ptr)) return false;     // backup boot

    // FSInfo (sector 1)
    clr();
    put32(s.ptr, 0,   0x41615252);                   // "RRaA"
    put32(s.ptr, 484, 0x61417272);                   // "rrAa"
    put32(s.ptr, 488, totalClusters - 1);            // free count (root uses 1)
    put32(s.ptr, 492, 3);                            // next free hint
    put32(s.ptr, 508, 0xAA550000);                   // trail sig
    if (!diskWriteSectorsOn(diskIdx, espFirstLba + 1, 1, s.ptr)) return false;

    // head of each FAT: cluster 0 (media|EOC), 1 (EOC), 2 (root dir, EOC)
    clr();
    put32(s.ptr, 0, 0x0FFFFFF8);
    put32(s.ptr, 4, 0x0FFFFFFF);
    put32(s.ptr, 8, 0x0FFFFFFF);
    if (!diskWriteSectorsOn(diskIdx, espFirstLba + RESERVED, 1, s.ptr)) return false;
    if (!diskWriteSectorsOn(diskIdx, espFirstLba + RESERVED + fatSize, 1, s.ptr)) return false;
    return true;
}

// Boot proof: if a spare (non-object-store) target disk is attached, write a real
// GPT to it (primary + backup) and read it back to validate.  SKIPs (never clobbers)
// when the only disk is the live object store.  Lays a 256 MiB ESP + root remainder.
public void gptWriteProof() {
    ulong tsec;
    const int idx = diskFindTarget(tsec);
    if (idx < 0 || tsec < 8192) { klog("[diskpart] GPT-write proof SKIP (no spare target disk)\n"); return; }
    enum ulong ESP = (256UL * 1024 * 1024) / SECTOR;    // 256 MiB
    if (!gptWriteToDisk(idx, tsec, ESP)) { klog("[diskpart] GPT-write proof FAIL (write)\n"); return; }

    __gshared ubyte[PRIMARY_SECTORS * SECTOR] rbuf;
    if (!diskReadSectorsOn(idx, 0, PRIMARY_SECTORS, rbuf.ptr)) { klog("[diskpart] GPT-write proof FAIL (read)\n"); return; }
    if (!gptValidate(rbuf.ptr)) { klog("[diskpart] GPT-write proof FAIL (primary invalid)\n"); return; }

    __gshared ubyte[SECTOR] bk;
    bool backupSig = false;
    if (diskReadSectorsOn(idx, tsec - 1, 1, bk.ptr)) {
        backupSig = true;
        foreach (i; 0 .. 8) if (bk[i] != GPT_SIG[i]) backupSig = false;
    }
    // Format the just-laid ESP (at the standard first-usable LBA) as FAT32.
    const bool fatOk = fatFormatEsp(idx, FIRST_USABLE, ESP);
    klog("[diskpart] GPT-write proof PASS (wrote+reread GPT on target idx=0x"); klog_hex(idx);
    klog(" sectors=0x"); klog_hex(tsec); klog("; primary validated, backup-hdr-sig=0x");
    klog_hex(backupSig ? 1 : 0); klog(", esp-fat32=0x"); klog_hex(fatOk ? 1 : 0); klog(")\n");
}
