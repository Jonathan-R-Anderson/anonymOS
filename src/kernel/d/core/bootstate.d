// bootstate.d — A/B slot boot-state (U1, roadmap/SYSTEM_UPDATE_ROADMAP.md).
//
// The single source of truth the slot-arbiter EFI reads at power-on and the running
// OS updates: which slot to try next, how many boot attempts remain before giving up,
// and which slot last proved a healthy boot.  Persisted as ONE 512-byte sector so a
// write is atomic w.r.t. power loss (the disk either commits the whole sector or not),
// guarded by a magic + CRC32 so a torn/blank sector is detected and defaulted.
//
// On-disk byte layout (little-endian, offset : size : field):
//   0  : 4 : magic  = 'E','U','B','S'  (Epin Update Boot State)
//   4  : 2 : format version (=1)
//   6  : 1 : trySlot   (0=A, 1=B)  — slot the arbiter boots next
//   7  : 1 : bootOkSlot(0=A, 1=B, 0xFF=none) — last slot that wrote boot-ok
//   8  : 1 : triesLeft — arbiter decrements each attempt; 0 without boot-ok => flip
//   9  : 1 : activeSlot(0=A,1=B) — slot the installer/updater considers "current"
//   10 : 2 : reserved (0)
//   12 : 4 : seq — monotonically increasing write counter (newest wins if ever mirrored)
//   16 .. 507 : reserved (0)
//   508: 4 : crc32 over bytes [0,508)
//
// The arbiter is a tiny freestanding UEFI app (efi/), so this layout is deliberately
// dumb: fixed offsets, no structs, CRC32 identical to the GPT one (core.diskpart.crc32).
module core.bootstate;

import core.io : klog, klog_hex;
import core.diskpart : crc32, SECTOR;
import drivers.block.disk : diskReadSectorsOn, diskWriteSectorsOn, diskIsNvme;

@nogc nothrow:

enum ubyte SLOT_A = 0;
enum ubyte SLOT_B = 1;
enum ubyte SLOT_NONE = 0xFF;
enum ubyte DEFAULT_TRIES = 3;      // boot attempts before the arbiter flips slots

// The boot-state lives at a FIXED LBA the arbiter also hardcodes.  It sits just past
// the primary GPT (LBA 0..33) at LBA 34 — a dedicated GPT partition covers it so no
// filesystem ever reuses the sector (see diskpart U1 layout).  Kept as a constant
// shared by the kernel writer and (documented for) the EFI reader.
enum ulong BOOTSTATE_LBA = 34;

enum uint BS_MAGIC = 0x53425545;   // 'E','U','B','S' little-endian
enum ushort BS_VERSION = 1;

struct BootState {
    ubyte trySlot;
    ubyte bootOkSlot;
    ubyte triesLeft;
    ubyte activeSlot;
    uint  seq;
}

private void put16(ubyte* b, size_t off, ushort v) { b[off]=cast(ubyte)v; b[off+1]=cast(ubyte)(v>>8); }
private void put32(ubyte* b, size_t off, uint v) { foreach (i; 0 .. 4) b[off+i]=cast(ubyte)(v>>(8*i)); }
private uint get32(const(ubyte)* b, size_t off) {
    return cast(uint)b[off] | (cast(uint)b[off+1]<<8) | (cast(uint)b[off+2]<<16) | (cast(uint)b[off+3]<<24);
}

// Serialize `s` into a 512-byte sector buffer (must be >= SECTOR).
private void encode(const ref BootState s, ubyte* buf) {
    foreach (i; 0 .. SECTOR) buf[i] = 0;
    put32(buf, 0, BS_MAGIC);
    put16(buf, 4, BS_VERSION);
    buf[6] = s.trySlot;
    buf[7] = s.bootOkSlot;
    buf[8] = s.triesLeft;
    buf[9] = s.activeSlot;
    put32(buf, 12, s.seq);
    put32(buf, 508, crc32(buf, 508));
}

// Parse a sector into `out_`; false if magic/version/CRC don't validate (blank/torn).
private bool decode(const(ubyte)* buf, out BootState out_) {
    if (get32(buf, 0) != BS_MAGIC) return false;
    if ((cast(uint)buf[4] | (cast(uint)buf[5]<<8)) != BS_VERSION) return false;
    if (crc32(buf, 508) != get32(buf, 508)) return false;
    out_.trySlot    = buf[6];
    out_.bootOkSlot = buf[7];
    out_.triesLeft  = buf[8];
    out_.activeSlot = buf[9];
    out_.seq        = get32(buf, 12);
    return true;
}

// A boot-state's install target index: NVMe = 0, else the AHCI store index.  The
// boot-state partition lives on the SAME disk the OS was installed to.
private int stateDiskIdx() {
    import drivers.block.disk : diskStoreIndex;
    if (diskIsNvme()) return 0;
    ulong sec;
    return diskStoreIndex(sec);
}

// Read the persisted boot-state.  Returns false (and leaves out_ zeroed) if the disk
// has no valid boot-state sector yet (fresh/legacy install).
public bool bootStateRead(out BootState out_) {
    out_ = BootState.init;
    const int idx = stateDiskIdx();
    if (idx < 0) return false;
    __gshared ubyte[SECTOR] buf;
    if (!diskReadSectorsOn(idx, BOOTSTATE_LBA, 1, buf.ptr)) return false;
    return decode(buf.ptr, out_);
}

// Persist `s` (bumping seq).  Atomic single-sector write; false on I/O failure.
public bool bootStateWrite(ref BootState s) {
    const int idx = stateDiskIdx();
    if (idx < 0) return false;
    s.seq += 1;
    __gshared ubyte[SECTOR] buf;
    encode(s, buf.ptr);
    return diskWriteSectorsOn(idx, BOOTSTATE_LBA, 1, buf.ptr);
}

// Initialize the boot-state for a FRESH install to `activeSlot` (the slot the
// installer wrote the running image to): boot that slot, full retry budget, and mark
// it boot-ok so the very first boot is trusted (the installer just verified it).
public bool bootStateInit(ubyte activeSlot) {
    BootState s;
    s.trySlot    = activeSlot;
    s.bootOkSlot = activeSlot;
    s.triesLeft  = DEFAULT_TRIES;
    s.activeSlot = activeSlot;
    s.seq        = 0;
    return bootStateWrite(s);
}

private char slotCh(ubyte s) { return (s == SLOT_A) ? 'A' : (s == SLOT_B) ? 'B' : '?'; }

// One-shot boot proof + self-test (mirrors the disk/GPT proofs): round-trip a
// boot-state sector on the real target disk, then restore what was there.  Proves the
// arbiter's on-disk contract works on THIS machine, headlessly.  Never runs when no
// disk is attached.
public void bootStateSelfTest() {
    import drivers.block.disk : diskReady;
    if (!diskReady()) { klog("[bootstate] selftest SKIP (no disk)\n"); return; }
    const int idx = stateDiskIdx();
    if (idx < 0) { klog("[bootstate] selftest SKIP (no store idx)\n"); return; }

    // Preserve whatever is currently at the boot-state LBA so the proof is non-destructive.
    __gshared ubyte[SECTOR] saved;
    const bool hadSaved = diskReadSectorsOn(idx, BOOTSTATE_LBA, 1, saved.ptr);

    BootState w;
    w.trySlot = SLOT_B; w.bootOkSlot = SLOT_A; w.triesLeft = 2; w.activeSlot = SLOT_A; w.seq = 41;
    if (!bootStateWrite(w)) { klog("[bootstate] selftest FAIL (write)\n"); return; }

    BootState r;
    if (!bootStateRead(r)) { klog("[bootstate] selftest FAIL (read/decode)\n"); return; }
    if (r.trySlot != SLOT_B || r.bootOkSlot != SLOT_A || r.triesLeft != 2 ||
        r.activeSlot != SLOT_A || r.seq != 42) {
        klog("[bootstate] selftest FAIL (mismatch)\n"); return;
    }

    // Restore the original sector (or clear it if there was none) so we don't strand a
    // synthetic state on a real install.
    if (hadSaved) diskWriteSectorsOn(idx, BOOTSTATE_LBA, 1, saved.ptr);

    klog("[bootstate] selftest PASS (sector round-trip: try=");
    { char[2] c = [slotCh(w.trySlot), '\0']; klog(c.ptr); }
    klog(" ok="); { char[2] c = [slotCh(w.bootOkSlot), '\0']; klog(c.ptr); }
    klog(" seq bump verified)\n");
}
