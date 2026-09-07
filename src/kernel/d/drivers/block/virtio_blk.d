// virtio-blk (modern / virtio-1.0) block driver.
//
// WHY THIS EXISTS
// ---------------
// The disk layer knew AHCI and NVMe only.  Proxmox VE's DEFAULT disk bus is VirtIO SCSI, and
// QEMU's `-drive if=virtio` is the most common way anyone attaches a disk, so on a stock VM the
// installer reported "no disk to install to" and the object store silently stayed in RAM --
// nothing was broken, there was simply no block device the kernel could see.  Confirmed on
// Proxmox 2026-09-05 (roadmap 5.0).
//
// TRANSPORT
// ---------
// Deliberately a mirror of drivers/network/virtio_net.d, which is itself a mirror of the proven
// virtio_gpu.d: the same PCI capability walk (vendor cap 0x09, cfg_type COMMON=1 / NOTIFY=2 /
// DEVICE=4), the same common-config offsets, the same "rings come from alloc_phys_page() because
// the device DMAs PHYSICAL addresses and there is no low identity map" rule, and the same
// poll-the-used-ring completion model.  Copying a transport that already works beats writing a
// third one: every bug in this file is then a block-layer bug, not a virtio bug.
//
// DEVICE IDS
// ----------
// QEMU/Proxmox present virtio-blk as a TRANSITIONAL device, PCI 1AF4:1001, which still exposes
// the virtio-1.0 capability structures; a modern-only device is 1AF4:1042.  Both are accepted and
// driven through the modern path, so no legacy I/O-BAR code is needed.
//
// SYNCHRONOUS BY DESIGN
// ---------------------
// Every request is submitted and then polled to completion before returning.  The disk layer above
// is synchronous (diskReadSectors returns the data), the object store calls it during early boot
// before any scheduler exists, and the installer streams through it a batch at a time.  An
// interrupt-driven queue would have to be reconciled with all three; polling is what the AHCI and
// NVMe backends already do.
module drivers.block.virtio_blk;

import drivers.pci : PCIDevice, pciConfigRead32, pciConfigWrite32;
import drivers.virtio : VirtqDesc, VirtqAvail, VirtqUsed, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE;
import core.io : klog, klog_hex;

@nogc nothrow:

enum VIRTIO_VENDOR        = 0x1AF4;
enum VBLK_DEV_TRANSITIONAL = 0x1001;   // QEMU/Proxmox default
enum VBLK_DEV_MODERN       = 0x1042;

private enum { VS_ACK = 1, VS_DRIVER = 2, VS_DRIVER_OK = 4, VS_FEATURES_OK = 8, VS_FAILED = 128 }

// virtio-1.0 common-configuration field offsets (identical to virtio_net.d's).
private enum { CC_DEV_FEAT_SEL = 0x00, CC_DEV_FEAT = 0x04, CC_DRV_FEAT_SEL = 0x08, CC_DRV_FEAT = 0x0C,
               CC_NUM_QUEUES = 0x12, CC_STATUS = 0x14, CC_Q_SELECT = 0x16, CC_Q_SIZE = 0x18,
               CC_Q_ENABLE = 0x1C, CC_Q_NOTIFY_OFF = 0x1E, CC_Q_DESC = 0x20, CC_Q_DRIVER = 0x28,
               CC_Q_DEVICE = 0x30 }

private enum VIRTIO_F_VERSION_1 = 32;

// virtio-blk request types and status codes (spec §5.2).
private enum { VBLK_T_IN = 0, VBLK_T_OUT = 1 };
private enum { VBLK_S_OK = 0, VBLK_S_IOERR = 1, VBLK_S_UNSUPP = 2 };

// The device's own config space: capacity is the first field, in 512-byte sectors, and is the
// only field this driver needs.
private enum DEVCFG_CAPACITY = 0x00;

enum VBLK_SECTOR = 512;
// One page of payload per request.  The disk layer already loops over larger transfers, and a
// page keeps the descriptor chain to a fixed three entries with no scatter-gather.
enum VBLK_MAX_SECTORS = 8;

// The 16-byte request header the device reads before the payload.
private struct VBlkReqHdr {
    uint  type;
    uint  reserved;
    ulong sector;
}

private struct VBlkQueue {
    VirtqDesc*  desc;
    VirtqAvail* avail;
    VirtqUsed*  used;
    ulong  descPhys, availPhys, usedPhys;
    ushort qsz;
    ushort lastUsed;
    ulong  notifyAddr;
}

__gshared bool  g_vblkReady = false;
__gshared ulong g_vblkCapacity = 0;      // in 512-byte sectors
private __gshared VBlkQueue g_q;
private __gshared ulong  g_hdrPhys,  g_payPhys,  g_stsPhys;
private __gshared ubyte* g_hdrVirt, g_payVirt, g_stsVirt;
private __gshared ulong g_reads = 0, g_writes = 0;

public bool virtioBlkReady()        { return g_vblkReady; }
public ulong virtioBlkCapacity()    { return g_vblkCapacity; }

// ── volatile MMIO accessors ──────────────────────────────────────────────────────────────────
private uint   volLoadU (uint* p)             { return *cast(shared const uint*)p; }
private void   volStoreU(uint* p, uint v)     { *cast(shared uint*)p = v; }
private ubyte  volLoadB (ubyte* p)            { return *cast(shared const ubyte*)p; }
private void   volStoreB(ubyte* p, ubyte v)   { *cast(shared ubyte*)p = v; }
private ushort volLoadW (ushort* p)           { return *cast(shared const ushort*)p; }
private void   volStoreW(ushort* p, ushort v) { *cast(shared ushort*)p = v; }
private ulong  volLoadQ (ulong* p)            { return *cast(shared const ulong*)p; }
private void   memBarrier() { asm @nogc nothrow { mfence; } }

private void enableBusMastering(PCIDevice* pci) {
    uint cmd = pciConfigRead32(pci.bus, pci.slot, pci.func, 0x04);
    cmd |= 0x06;                       // memory space + bus master; without it the device cannot DMA
    pciConfigWrite32(pci.bus, pci.slot, pci.func, 0x04, cmd);
}

private ulong barBase(PCIDevice* pci, uint barIndex) {
    uint lo = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(0x10 + barIndex * 4));
    ulong base = lo & 0xFFFFFFF0u;
    if ((lo & 0x6) == 0x4) {           // 64-bit BAR: high half in the next dword
        uint hi = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(0x10 + barIndex * 4 + 4));
        base |= (cast(ulong)hi << 32);
    }
    return base;
}

private void allocPage(out ulong phys, out ubyte* virt) {
    import memory.mm : alloc_phys_page;
    import core.globals : hhdm_offset;
    phys = alloc_phys_page();
    virt = (phys == 0) ? null : cast(ubyte*)(phys + hhdm_offset);
    if (virt !is null) foreach (i; 0 .. 4096) virt[i] = 0;
}

private bool setupQueue(ulong cc, ulong notifyBase, uint notifyOff, uint notifyMult, ushort qidx) {
    import core.globals : hhdm_offset;

    volStoreW(cast(ushort*)(cc + CC_Q_SELECT), qidx);
    ushort qsz = volLoadW(cast(ushort*)(cc + CC_Q_SIZE));
    if (qsz == 0) { klog("[virtio-blk] queue absent\n"); return false; }
    if (qsz > 256) qsz = 256;          // VirtqAvail/VirtqUsed carry fixed 256-entry rings
    g_q.qsz = qsz;
    g_q.lastUsed = 0;

    ubyte* dv, av, uv;
    allocPage(g_q.descPhys,  dv);
    allocPage(g_q.availPhys, av);
    allocPage(g_q.usedPhys,  uv);
    if (dv is null || av is null || uv is null) { klog("[virtio-blk] ring alloc failed\n"); return false; }
    g_q.desc  = cast(VirtqDesc*)dv;
    g_q.avail = cast(VirtqAvail*)av;
    g_q.used  = cast(VirtqUsed*)uv;

    volStoreW(cast(ushort*)(cc + CC_Q_SELECT), qidx);
    volStoreU(cast(uint*)(cc + CC_Q_DESC),       cast(uint)g_q.descPhys);
    volStoreU(cast(uint*)(cc + CC_Q_DESC + 4),   cast(uint)(g_q.descPhys >> 32));
    volStoreU(cast(uint*)(cc + CC_Q_DRIVER),     cast(uint)g_q.availPhys);
    volStoreU(cast(uint*)(cc + CC_Q_DRIVER + 4), cast(uint)(g_q.availPhys >> 32));
    volStoreU(cast(uint*)(cc + CC_Q_DEVICE),     cast(uint)g_q.usedPhys);
    volStoreU(cast(uint*)(cc + CC_Q_DEVICE + 4), cast(uint)(g_q.usedPhys >> 32));
    volStoreW(cast(ushort*)(cc + CC_Q_ENABLE), 1);

    ushort qNotifyOff = volLoadW(cast(ushort*)(cc + CC_Q_NOTIFY_OFF));
    g_q.notifyAddr = notifyBase + notifyOff + cast(ulong)qNotifyOff * notifyMult + hhdm_offset;
    return true;
}

// Bring up a virtio-blk device.  Returns true and fills g_vblkCapacity on success.
export extern(C) bool virtioBlkInit(PCIDevice* pci) {
    import core.globals : hhdm_offset;

    g_vblkReady = false;
    if (pci is null) return false;

    uint cmdStatus = pciConfigRead32(pci.bus, pci.slot, pci.func, 0x04);
    if (!((cmdStatus >> 16) & 0x10)) {
        klog("[virtio-blk] no PCI capability list (legacy-only device) -- cannot use modern transport\n");
        return false;
    }

    uint commonBar = 0xFFFFFFFFu, commonOff = 0;
    uint notifyBar = 0xFFFFFFFFu, notifyOff = 0, notifyMult = 0;
    uint deviceBar = 0xFFFFFFFFu, deviceOff = 0;
    ubyte cap = cast(ubyte)(pciConfigRead32(pci.bus, pci.slot, pci.func, 0x34) & 0xFC);
    int guard = 0;
    while (cap != 0 && guard++ < 48) {
        uint dw0 = pciConfigRead32(pci.bus, pci.slot, pci.func, cap);
        ubyte capId   = cast(ubyte)(dw0 & 0xFF);
        ubyte capNext = cast(ubyte)((dw0 >> 8) & 0xFF);
        ubyte cfgType = cast(ubyte)((dw0 >> 24) & 0xFF);
        if (capId == 0x09) {
            uint barNo = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 4)) & 0xFF;
            uint off   = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 8));
            if      (cfgType == 1) { commonBar = barNo; commonOff = off; }
            else if (cfgType == 2) { notifyBar = barNo; notifyOff = off;
                                     notifyMult = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 16)); }
            else if (cfgType == 4) { deviceBar = barNo; deviceOff = off; }
        }
        cap = capNext;
    }
    if (commonBar == 0xFFFFFFFFu || notifyBar == 0xFFFFFFFFu) {
        klog("[virtio-blk] missing COMMON or NOTIFY capability -- abort\n");
        return false;
    }

    enableBusMastering(pci);

    ulong cc = barBase(pci, commonBar) + commonOff + hhdm_offset;
    ubyte* pStatus = cast(ubyte*)(cc + CC_STATUS);

    volStoreB(pStatus, 0);
    volStoreB(pStatus, VS_ACK);
    volStoreB(pStatus, cast(ubyte)(VS_ACK | VS_DRIVER));

    volStoreU(cast(uint*)(cc + CC_DEV_FEAT_SEL), 1);
    uint featHi = volLoadU(cast(uint*)(cc + CC_DEV_FEAT));
    if (!((featHi >> (VIRTIO_F_VERSION_1 - 32)) & 1)) {
        klog("[virtio-blk] device does not offer VIRTIO_F_VERSION_1 -- abort\n");
        volStoreB(pStatus, VS_FAILED);
        return false;
    }
    // Negotiate NOTHING but VERSION_1.  Declining the optional features (SEG_MAX, BLK_SIZE,
    // TOPOLOGY, MQ, DISCARD…) keeps every request a fixed three-descriptor chain against a
    // 512-byte-sector device, which is exactly what the disk layer above assumes.
    volStoreU(cast(uint*)(cc + CC_DRV_FEAT_SEL), 0);
    volStoreU(cast(uint*)(cc + CC_DRV_FEAT), 0);
    volStoreU(cast(uint*)(cc + CC_DRV_FEAT_SEL), 1);
    volStoreU(cast(uint*)(cc + CC_DRV_FEAT), 1u << (VIRTIO_F_VERSION_1 - 32));

    volStoreB(pStatus, cast(ubyte)(VS_ACK | VS_DRIVER | VS_FEATURES_OK));
    if (!(volLoadB(pStatus) & VS_FEATURES_OK)) {
        klog("[virtio-blk] device rejected our feature set -- abort\n");
        volStoreB(pStatus, VS_FAILED);
        return false;
    }

    ulong notifyBase = barBase(pci, notifyBar);
    if (!setupQueue(cc, notifyBase, notifyOff, notifyMult, 0)) {
        volStoreB(pStatus, VS_FAILED);
        return false;
    }

    // Request header, payload and status byte each get their own page: the device DMAs all three
    // and they must be physically addressable independently.
    allocPage(g_hdrPhys, g_hdrVirt);
    allocPage(g_payPhys, g_payVirt);
    allocPage(g_stsPhys, g_stsVirt);
    if (g_hdrVirt is null || g_payVirt is null || g_stsVirt is null) {
        klog("[virtio-blk] request buffer alloc failed\n");
        volStoreB(pStatus, VS_FAILED);
        return false;
    }

    // Capacity comes from the device config area, in 512-byte sectors.
    if (deviceBar != 0xFFFFFFFFu) {
        ulong dc = barBase(pci, deviceBar) + deviceOff + hhdm_offset;
        g_vblkCapacity = volLoadQ(cast(ulong*)(dc + DEVCFG_CAPACITY));
    }

    volStoreB(pStatus, cast(ubyte)(VS_ACK | VS_DRIVER | VS_FEATURES_OK | VS_DRIVER_OK));
    g_vblkReady = true;

    klog("[virtio-blk] ready: sectors=0x");
    klog_hex(g_vblkCapacity);
    klog(" (");
    klog_hex(g_vblkCapacity / 2048);
    klog(" MiB), queue size=0x");
    klog_hex(g_q.qsz);
    klog("\n");
    return true;
}

// Submit one request and poll it to completion.  `write` selects OUT vs IN; the caller's data is
// staged through the DMA-safe payload page either way.
private bool vblkRequest(bool write, ulong lba, uint sectors, ubyte* buf) {
    if (!g_vblkReady || sectors == 0 || sectors > VBLK_MAX_SECTORS) return false;

    const uint bytes = sectors * VBLK_SECTOR;

    auto hdr = cast(VBlkReqHdr*)g_hdrVirt;
    hdr.type     = write ? VBLK_T_OUT : VBLK_T_IN;
    hdr.reserved = 0;
    hdr.sector   = lba;
    g_stsVirt[0] = 0xFF;                              // poison, so "unchanged" is distinguishable

    if (write) foreach (i; 0 .. bytes) g_payVirt[i] = buf[i];

    // Three descriptors: header (device reads), payload (direction depends), status (device writes).
    g_q.desc[0].addr  = g_hdrPhys;
    g_q.desc[0].len   = VBlkReqHdr.sizeof;
    g_q.desc[0].flags = VIRTQ_DESC_F_NEXT;
    g_q.desc[0].next  = 1;

    g_q.desc[1].addr  = g_payPhys;
    g_q.desc[1].len   = bytes;
    g_q.desc[1].flags = cast(ushort)(VIRTQ_DESC_F_NEXT | (write ? 0 : VIRTQ_DESC_F_WRITE));
    g_q.desc[1].next  = 2;

    g_q.desc[2].addr  = g_stsPhys;
    g_q.desc[2].len   = 1;
    g_q.desc[2].flags = VIRTQ_DESC_F_WRITE;
    g_q.desc[2].next  = 0;

    const ushort slot = cast(ushort)(g_q.avail.idx % g_q.qsz);
    g_q.avail.ring[slot] = 0;                         // head of our chain
    memBarrier();
    g_q.avail.idx = cast(ushort)(g_q.avail.idx + 1);
    memBarrier();
    volStoreW(cast(ushort*)g_q.notifyAddr, 0);

    // Poll the used ring.  Bounded: a device that never completes must not hang the boot, and on
    // a software-emulated device (TCG) a request can take a while, so the ceiling is generous.
    ulong spins = 0;
    while (g_q.used.idx == g_q.lastUsed) {
        if (++spins > 200_000_000UL) {
            klog("[virtio-blk] request timed out (lba=0x");
            klog_hex(lba);
            klog(")\n");
            return false;
        }
        asm @nogc nothrow { rep; nop; }   // spin hint; same idiom as ahci.d
    }
    g_q.lastUsed = g_q.used.idx;
    memBarrier();

    const ubyte st = g_stsVirt[0];
    if (st != VBLK_S_OK) {
        klog("[virtio-blk] request failed status=0x");
        klog_hex(st);
        klog("\n");
        return false;
    }

    if (!write) foreach (i; 0 .. bytes) buf[i] = g_payVirt[i];
    if (write) ++g_writes; else ++g_reads;
    return true;
}

// Read/write, looping so callers are not bound by VBLK_MAX_SECTORS.
public bool virtioBlkRead(ulong lba, uint count, void* dst) {
    ubyte* out_ = cast(ubyte*)dst;
    while (count > 0) {
        uint chunk = count > VBLK_MAX_SECTORS ? VBLK_MAX_SECTORS : count;
        if (!vblkRequest(false, lba, chunk, out_)) return false;
        lba   += chunk;
        out_  += chunk * VBLK_SECTOR;
        count -= chunk;
    }
    return true;
}

public bool virtioBlkWrite(ulong lba, uint count, const(void)* src) {
    ubyte* in_ = cast(ubyte*)src;
    while (count > 0) {
        uint chunk = count > VBLK_MAX_SECTORS ? VBLK_MAX_SECTORS : count;
        if (!vblkRequest(true, lba, chunk, in_)) return false;
        lba   += chunk;
        in_   += chunk * VBLK_SECTOR;
        count -= chunk;
    }
    return true;
}

// Scan PCI for a virtio-blk device and bring the first one up.
public bool virtioBlkProbe() {
    import drivers.pci : scanPCIDevices;
    // scanPCIDevices() is the public enumeration every other driver uses; the device table itself
    // is private to pci.d.
    auto devs = scanPCIDevices();
    foreach (ref dev; devs) {
        auto d = &dev;
        if (d.vendorId != VIRTIO_VENDOR) continue;
        if (d.deviceId != VBLK_DEV_TRANSITIONAL && d.deviceId != VBLK_DEV_MODERN) continue;
        klog("[virtio-blk] found device 0x");
        klog_hex(d.deviceId);
        klog(" at bus/slot/func 0x");
        klog_hex(d.bus); klog("/0x"); klog_hex(d.slot); klog("/0x"); klog_hex(d.func);
        klog("\n");
        if (virtioBlkInit(d)) return true;
    }
    return false;
}
