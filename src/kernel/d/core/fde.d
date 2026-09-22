// ─────────────────────────────────────────────────────────────────────────────
// Full-disk-encryption runtime key hand-off  (roadmap/INSTALLER.md §D)
//
// The pre-boot loader (deps/veracrypt/efi/efi_main.c), after it has authenticated
// the disk/hidden password and decrypted the EpinAnonymOS boot volume into RAM,
// patches the /anos.key placeholder inside that in-RAM FAT image with an ANOSKEY1
// record (the master key + the absolute LBA bounds of the encrypted object store).
// Limine then loads /anos.key as an ordinary boot module and the kernel receives it
// here.  This module:
//   - accepts + parses the ANOSKEY1 record,
//   - derives a SEPARATE object-store key from the master key (design-review
//     BLOCKER 3: never reuse one XTS key across two tweak domains),
//   - SCRUBS the key material out of reclaimable RAM (design-review BLOCKER 4:
//     both Limine's module copy AND, when the loader records it, the /anos.key
//     sector still sitting in the loader's decrypted RAM-FAT buffer),
//   - and exposes fdeActive()/fdeStoreBounds()/fdeStoreKey* to objstore.d.
//
// On a plain (unencrypted) install there is no ANOSKEY1 record — /anos.key is the
// 512-byte placeholder — so nothing here activates and objstore behaves as before.
//
// ─────────────────────────────────────────────────────────────────────────────
//   /anos.key ANOSKEY1 record — the LOADER↔KERNEL contract (all u64 little-endian):
//     [0  .. 8 )  magic "ANOSKEY1"
//     [8  .. 72)  master key (64 bytes: XTS key1[0..32] || key2[32..64])
//     [72 .. 80)  store_first_lba   (absolute, inclusive)
//     [80 .. 88)  store_last_lba    (absolute, inclusive)
//     [88 .. 96)  boot_region_lba   (absolute LBA the payload was decrypted from)
//     [96 ..104)  flags  (bit0 = hidden-OS boot, bit1 = full-disk boot)
//     [104..112)  ram_fat_base  (OPTIONAL, 0 = absent) — see BLOCKER 4 below
//     [112..120)  ram_fat_len   (OPTIONAL, 0 = absent)
//     [120..512)  zero pad
//
//   BLOCKER 4 note: [104..120) is a kernel-side, backward-compatible extension.  If
//   the loader fills ram_fat_base/len with the base+length of its decrypted RAM-FAT
//   block-device buffer, the kernel scans that range for the ANOSKEY1 marker and
//   zeroes the stray 512-byte record there too, before that memory is released to
//   the general allocator.  A loader that writes zeros gets the old behaviour (only
//   Limine's module copy is scrubbed).
// ─────────────────────────────────────────────────────────────────────────────
module core.fde;

import core.io : klog, klog_hex;
import core.stdc.string : memset, memcpy;

extern(C) void sha512_hash(const(ubyte)* data, size_t len, ubyte* output) @nogc nothrow;

@nogc nothrow:

enum size_t ANOSKEY_RECORD = 512;
enum ulong  FDE_FLAG_HIDDEN   = 0x1;
enum ulong  FDE_FLAG_FULLDISK = 0x2;

private immutable char[8] ANOSKEY1_MAGIC = ['A','N','O','S','K','E','Y','1'];

__gshared bool   g_fdeActive   = false;
__gshared ubyte[64] g_masterKey;    // XTS master key straight from the loader
__gshared ubyte[64] g_storeKey;     // DERIVED object-store key (never == master key)
__gshared ulong  g_storeFirst  = 0; // absolute LBA, inclusive
__gshared ulong  g_storeLast   = 0; // absolute LBA, inclusive
__gshared ulong  g_bootRegion  = 0;
__gshared ulong  g_flags       = 0;

private ulong rdLE64(const(ubyte)* p) {
    ulong v = 0;
    foreach (i; 0 .. 8) v |= (cast(ulong)p[i]) << (8 * i);
    return v;
}

private bool markerAt(const(ubyte)* p) {
    foreach (i; 0 .. 8) if (p[i] != cast(ubyte)ANOSKEY1_MAGIC[i]) return false;
    return true;
}

// Derive the object-store XTS key: store_key = SHA-512(master_key || "anos-objstore").
// SHA-512 output is exactly 64 bytes = XTS key1(32) || key2(32).  This guarantees the
// object store and the boot payload never share an XTS key even if their tweak spaces
// (payload-relative index vs absolute LBA) ever collide (design-review BLOCKER 3).
private void deriveStoreKey() {
    enum string TAG = "anos-objstore";
    ubyte[64 + TAG.length] buf = void;
    foreach (i; 0 .. 64) buf[i] = g_masterKey[i];
    foreach (i; 0 .. TAG.length) buf[64 + i] = cast(ubyte)TAG[i];
    sha512_hash(buf.ptr, buf.length, g_storeKey.ptr);
    memset(buf.ptr, 0, buf.length);   // the derivation buffer held the master key
}

// Scan [base, base+len) for a stray ANOSKEY1 record and zero its 512 bytes.  The
// /anos.key file is <= 1 cluster, so its record is contiguous and a linear marker
// scan is safe (design-review NOTE).  Used to scrub the loader's RAM-FAT buffer.
private void scrubRange(ubyte* base, size_t len) {
    if (base is null || len < ANOSKEY_RECORD) return;
    size_t last = len - ANOSKEY_RECORD;
    // The record is a whole FAT sector, so it is 512-aligned within the volume image: step by
    // sector (a byte-wise scan of a 512 MiB buffer is ~30x more work for nothing).
    for (size_t off = 0; off <= last; off += ANOSKEY_RECORD) {
        if (markerAt(base + off)) {
            memset(base + off, 0, ANOSKEY_RECORD);
            // keep scanning: a buffer could in principle carry more than one copy
        }
    }
}

// Accept the "anos.key" boot module.  Returns true when it carried a live ANOSKEY1
// record (i.e. this is an encrypted install); false for a plain-install placeholder.
// After a successful accept the caller's module memory is ZEROED.
public bool fdeAcceptKeyModule(void* mod, size_t len) {
    if (mod is null || len < ANOSKEY_RECORD) return false;
    ubyte* p = cast(ubyte*)mod;
    if (!markerAt(p)) return false;   // placeholder / plain install — leave it, do nothing

    memcpy(g_masterKey.ptr, p + 8, 64);
    g_storeFirst = rdLE64(p + 72);
    g_storeLast  = rdLE64(p + 80);
    g_bootRegion = rdLE64(p + 88);
    g_flags      = rdLE64(p + 96);
    const ulong ramFatBase = rdLE64(p + 104);
    const ulong ramFatLen  = rdLE64(p + 112);

    deriveStoreKey();
    g_fdeActive = true;

    klog("[fde] key module accepted: store LBA 0x");
    klog_hex(g_storeFirst); klog("-0x"); klog_hex(g_storeLast);
    klog(" flags=0x"); klog_hex(g_flags); klog("\n");

    // BLOCKER 4: scrub the loader's RAM-FAT buffer copy first (if the loader recorded
    // it), THEN Limine's module copy we were just handed.  Both are reclaimable RAM.
    // ram_fat_base is the PHYSICAL address the loader allocated (firmware identity map); the
    // kernel reaches physical memory through the HHDM.  Bound the length to something sane so
    // a corrupt record cannot walk the kernel off into MMIO.
    if (ramFatBase != 0 && ramFatLen != 0 && ramFatLen <= (2UL << 30)) {
        import core.exports : phys_to_virt;
        scrubRange(cast(ubyte*)phys_to_virt(ramFatBase), cast(size_t)ramFatLen);
    }
    memset(mod, 0, len);
    klog("[fde] key material scrubbed from reclaimable RAM\n");
    return true;
}

public bool fdeActive() { return g_fdeActive; }

// Absolute LBA bounds of the encrypted object store (inclusive).  Valid only when
// fdeActive().  objstore.d uses [first, last] -> g_baseLba/g_endLba.
public void fdeStoreBounds(out ulong first, out ulong last) {
    first = g_storeFirst;
    last  = g_storeLast;
}

public ulong fdeFlags() { return g_flags; }

// The two 32-byte halves of the DERIVED object-store XTS key.
public ubyte* fdeStoreKey1() { return g_storeKey.ptr; }
public ubyte* fdeStoreKey2() { return g_storeKey.ptr + 32; }
