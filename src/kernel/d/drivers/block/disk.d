// ─────────────────────────────────────────────────────────────────────────────
// Block disk layer (SHELL_AND_COMMANDS_ROADMAP A5 / OBJECT_FILESYSTEM F4 enabler)
//
// A thin, kernel-friendly wrapper over the AHCI SATA driver: it owns a physically
// contiguous DMA "bounce" buffer and exposes byte/sector read+write against the
// first SATA data disk in terms of ordinary kernel (HHDM) pointers, so higher
// layers (the persisted object store) never touch DMA phys details.
//
// Polled, no interrupts — matches the rest of the kernel (no kernel-mode IRQs).
// ─────────────────────────────────────────────────────────────────────────────
module drivers.block.disk;

import drivers.block.ahci : initAHCI, ahciDataPort, readSector, writeSector,
                            HBA_PORT, g_ahciDevices, getPort;
import memory.dma : dma_alloc;
import core.stdc.string : memcpy, memset;
import core.io : klog, klog_hex;

@nogc nothrow:

enum uint SECTOR = 512;
enum uint BOUNCE_SECTORS = 128;             // 64 KiB DMA window
enum uint BOUNCE_BYTES = BOUNCE_SECTORS * SECTOR;

private __gshared bool   g_diskReady = false;
private __gshared void*  g_bounceVirt = null;
private __gshared size_t g_bouncePhys = 0;
private __gshared ulong  g_diskSectors = 0;  // capacity in 512-byte sectors

public bool diskReady() { return g_diskReady; }
public ulong diskSectors() { return g_diskSectors; }

// Bring up AHCI, find the SATA data disk, and allocate the DMA bounce buffer.
public void diskInit() {
    initAHCI();
    auto port = ahciDataPort();
    if (port is null) {
        klog("[disk] no SATA data disk found (object store stays in-memory)\n");
        return;
    }
    g_bounceVirt = dma_alloc(BOUNCE_BYTES, 4096, &g_bouncePhys);
    if (g_bounceVirt is null) {
        klog("[disk] bounce buffer alloc failed\n");
        return;
    }
    // Record capacity (in sectors) from the IDENTIFY done during probe.
    foreach (ref d; g_ahciDevices)
        if (d.present && d.type == 1 && d.capacity != 0) { g_diskSectors = d.capacity / SECTOR; break; }
    g_diskReady = true;
    klog("[disk] SATA data disk ready, sectors=0x"); klog_hex(g_diskSectors); klog("\n");
}

// Read `count` sectors starting at `lba` into `dst` (a kernel/HHDM pointer).
public bool diskReadSectors(ulong lba, uint count, void* dst) {
    if (!g_diskReady || count == 0) return false;
    auto port = ahciDataPort();
    ubyte* out_ = cast(ubyte*)dst;
    while (count > 0) {
        const ushort chunk = cast(ushort)(count > BOUNCE_SECTORS ? BOUNCE_SECTORS : count);
        if (!readSector(port, lba, chunk, g_bouncePhys)) return false;
        memcpy(out_, g_bounceVirt, chunk * SECTOR);
        out_  += chunk * SECTOR;
        lba   += chunk;
        count -= chunk;
    }
    return true;
}

// Write `count` sectors starting at `lba` from `src` (a kernel/HHDM pointer).
public bool diskWriteSectors(ulong lba, uint count, const(void)* src) {
    if (!g_diskReady || count == 0) return false;
    auto port = ahciDataPort();
    const(ubyte)* in_ = cast(const(ubyte)*)src;
    while (count > 0) {
        const ushort chunk = cast(ushort)(count > BOUNCE_SECTORS ? BOUNCE_SECTORS : count);
        memcpy(g_bounceVirt, in_, chunk * SECTOR);
        if (!writeSector(port, lba, chunk, g_bouncePhys)) return false;
        in_   += chunk * SECTOR;
        lba   += chunk;
        count -= chunk;
    }
    return true;
}

// ─── Per-disk I/O (INSTALLER §D2(b): write a TARGET disk, not the object store) ──
// The object store lives on the first SATA disk (ahciDataPort / g_dataPort).  The
// installer lays a GPT down on a DIFFERENT disk, so these address a chosen disk by
// its g_ahciDevices[] index, reusing the same DMA bounce buffer.

// Find an installable target: a present SATA data disk that is NOT the object-store
// disk.  Returns its g_ahciDevices index (or -1) and its capacity in sectors.
public int diskFindTarget(out ulong targetSectors) {
    targetSectors = 0;
    if (!g_diskReady) return -1;
    foreach (i; 0 .. cast(int)g_ahciDevices.length) {
        auto d = &g_ahciDevices[i];
        if (!d.present || d.type != 1 || d.capacity == 0) continue;
        if (getPort(d.port) is ahciDataPort()) continue;   // skip the live/object-store disk
        targetSectors = d.capacity / SECTOR;
        return i;
    }
    return -1;
}

// Like diskFindTarget, but only a spare disk whose capacity is <= maxSectors (so the
// in-kernel full-disk install proof can pick a small dedicated disk it can fill quickly,
// distinct from a large generic-install target).
public int diskFindTargetBySize(ulong maxSectors, out ulong targetSectors) {
    targetSectors = 0;
    if (!g_diskReady) return -1;
    foreach (i; 0 .. cast(int)g_ahciDevices.length) {
        auto d = &g_ahciDevices[i];
        if (!d.present || d.type != 1 || d.capacity == 0) continue;
        if (getPort(d.port) is ahciDataPort()) continue;
        ulong sec = d.capacity / SECTOR;
        if (sec <= maxSectors) { targetSectors = sec; return i; }
    }
    return -1;
}

public bool diskWriteSectorsOn(int idx, ulong lba, uint count, const(void)* src) {
    if (!g_diskReady || count == 0 || idx < 0 || idx >= cast(int)g_ahciDevices.length) return false;
    if (!g_ahciDevices[idx].present) return false;
    HBA_PORT* port = getPort(g_ahciDevices[idx].port);
    if (port is null) return false;
    const(ubyte)* in_ = cast(const(ubyte)*)src;
    while (count > 0) {
        const ushort chunk = cast(ushort)(count > BOUNCE_SECTORS ? BOUNCE_SECTORS : count);
        memcpy(g_bounceVirt, in_, chunk * SECTOR);
        if (!writeSector(port, lba, chunk, g_bouncePhys)) return false;
        in_ += chunk * SECTOR; lba += chunk; count -= chunk;
    }
    return true;
}

public bool diskReadSectorsOn(int idx, ulong lba, uint count, void* dst) {
    if (!g_diskReady || count == 0 || idx < 0 || idx >= cast(int)g_ahciDevices.length) return false;
    if (!g_ahciDevices[idx].present) return false;
    HBA_PORT* port = getPort(g_ahciDevices[idx].port);
    if (port is null) return false;
    ubyte* out_ = cast(ubyte*)dst;
    while (count > 0) {
        const ushort chunk = cast(ushort)(count > BOUNCE_SECTORS ? BOUNCE_SECTORS : count);
        if (!readSector(port, lba, chunk, g_bouncePhys)) return false;
        memcpy(out_, g_bounceVirt, chunk * SECTOR);
        out_ += chunk * SECTOR; lba += chunk; count -= chunk;
    }
    return true;
}

// One-shot proof the disk round-trips: write a marked pattern to a scratch sector,
// read it back, verify.  Idempotent; uses a high LBA clear of the store region.
public void diskSelfTest() {
    if (!g_diskReady) { klog("[disk] selftest SKIP (no disk)\n"); return; }
    enum ulong SCRATCH_LBA = 2048;          // 1 MiB in — clear of the store superblock
    ubyte[SECTOR] wbuf = void;
    ubyte[SECTOR] rbuf = void;
    foreach (i; 0 .. SECTOR) wbuf[i] = cast(ubyte)(i * 31 + 7);
    // a recognizable marker at the front
    immutable ubyte[8] mark = ['H','O','S','D','I','S','K','1'];
    foreach (i; 0 .. 8) wbuf[i] = mark[i];

    if (!diskWriteSectors(SCRATCH_LBA, 1, wbuf.ptr)) { klog("[disk] selftest FAIL (write)\n"); return; }
    memset(rbuf.ptr, 0, SECTOR);
    if (!diskReadSectors(SCRATCH_LBA, 1, rbuf.ptr))  { klog("[disk] selftest FAIL (read)\n"); return; }
    foreach (i; 0 .. SECTOR)
        if (rbuf[i] != wbuf[i]) {
            klog("[disk] selftest FAIL (mismatch at 0x"); klog_hex(i); klog(")\n");
            return;
        }
    klog("[disk] selftest PASS (sector round-trip verified)\n");
}
