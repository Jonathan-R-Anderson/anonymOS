// virtio-net (modern / virtio-1.0) NIC driver.
//
// WHY THIS EXISTS
// ---------------
// Proxmox VE's DEFAULT NIC model is virtio, and anonymOS had only three empty stubs for it
// (initVirtIO/virtioSend/virtioReceive in drivers/network/network.d printed "not yet
// implemented" and returned false/0).  So on a stock Proxmox VM there was no usable network
// device at all -- which is exactly the "no sign of a LAN connection" symptom.
//
// The transport here is deliberately a mirror of the PROVEN modern-virtio code in
// drivers/graphics/virtio_gpu.d: the same PCI capability walk (vendor cap 0x09, cfg_type
// COMMON=1 / NOTIFY=2 / DEVICE=4), the same common-config field offsets, the same
// "rings come from alloc_phys_page() because the device DMAs PHYSICAL addresses and there is
// no low identity map" rule, and the same poll-the-used-ring completion model.  Nothing here
// needs interrupts: the e1000 path already runs fully polled (network.d: "we are polling")
// and networkStackPoll() is pumped from kernelLoop's 1 kHz tick.
//
// DEVICE IDS
// ----------
// QEMU/Proxmox present virtio-net as a TRANSITIONAL device, PCI 1AF4:1000, which still
// exposes the virtio-1.0 capability structures; a modern-only device is 1AF4:1041.  We accept
// both and drive both through the modern path, so no legacy I/O-BAR code is needed.
//
// THE HEADER SIZE TRAP
// --------------------
// Every buffer on both queues is prefixed by a virtio_net_hdr.  Under virtio 1.0 the struct is
// virtio_net_hdr_v1, which ALWAYS carries num_buffers -- 12 bytes -- regardless of whether
// VIRTIO_NET_F_MRG_RXBUF was negotiated (the pre-1.0 header was 10).  Using 10 here is the
// classic "link is up but nothing works" bug: every frame is offset by two bytes.
module drivers.network.virtio_net;

import drivers.pci : PCIDevice, pciConfigRead32, pciConfigWrite32;
import drivers.virtio : VirtqDesc, VirtqAvail, VirtqUsed, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE;
import userland.shell.console : printLine, print, printHex;

enum VIRTIO_VENDOR = 0x1AF4;
enum VNET_DEV_TRANSITIONAL = 0x1000;   // QEMU/Proxmox default
enum VNET_DEV_MODERN       = 0x1041;

// virtio-1.0 device-status bits (same set virtio_gpu.d uses).
private enum { VS_ACK = 1, VS_DRIVER = 2, VS_DRIVER_OK = 4, VS_FEATURES_OK = 8, VS_FAILED = 128 }

// virtio-1.0 common-configuration field offsets.
private enum { CC_DEV_FEAT_SEL = 0x00, CC_DEV_FEAT = 0x04, CC_DRV_FEAT_SEL = 0x08, CC_DRV_FEAT = 0x0C,
               CC_NUM_QUEUES = 0x12, CC_STATUS = 0x14, CC_Q_SELECT = 0x16, CC_Q_SIZE = 0x18,
               CC_Q_ENABLE = 0x1C, CC_Q_NOTIFY_OFF = 0x1E, CC_Q_DESC = 0x20, CC_Q_DRIVER = 0x28,
               CC_Q_DEVICE = 0x30 }

// Feature bits we care about.
private enum VIRTIO_NET_F_MAC        = 5;    // device config carries a MAC we should use
private enum VIRTIO_NET_F_MRG_RXBUF  = 15;   // deliberately NOT negotiated (keeps RX one-buf-per-frame)
private enum VIRTIO_F_VERSION_1      = 32;   // mandatory for the modern transport

enum NET_HDR_LEN = 12;      // virtio_net_hdr_v1 — see "THE HEADER SIZE TRAP" above
enum RX_BUFS     = 16;      // receive buffers kept posted on the avail ring
enum BUF_SZ      = 2048;    // per-buffer payload budget (hdr + a 1518-byte Ethernet frame fits)

// Queue indices are fixed by the virtio-net spec.
private enum QUEUE_RX = 0;
private enum QUEUE_TX = 1;

private struct VNetQueue {
    VirtqDesc*  desc;
    VirtqAvail* avail;
    VirtqUsed*  used;
    ulong  descPhys;
    ulong  availPhys;
    ulong  usedPhys;
    ushort qsz;
    ushort lastUsed;
    ulong  notifyAddr;
}

__gshared bool      g_vnetReady = false;
__gshared VNetQueue g_rx;
__gshared VNetQueue g_tx;
__gshared ulong[RX_BUFS] g_rxBufPhys;
__gshared ubyte*[RX_BUFS] g_rxBufVirt;
__gshared ulong  g_txBufPhys;
__gshared ubyte* g_txBufVirt;
__gshared bool   g_txBusy = false;   // reentrancy guard, mirroring g_gpuCtrlBusy

// ── volatile MMIO accessors (identical in intent to virtio_gpu.d's) ──────────────
private uint   volLoadU (uint* p)              @nogc nothrow { return *cast(shared const uint*)p; }
private void   volStoreU(uint* p, uint v)      @nogc nothrow { *cast(shared uint*)p = v; }
private ubyte  volLoadB (ubyte* p)             @nogc nothrow { return *cast(shared const ubyte*)p; }
private void   volStoreB(ubyte* p, ubyte v)    @nogc nothrow { *cast(shared ubyte*)p = v; }
private ushort volLoadW (ushort* p)            @nogc nothrow { return *cast(shared const ushort*)p; }
private void   volStoreW(ushort* p, ushort v)  @nogc nothrow { *cast(shared ushort*)p = v; }
private void   memBarrier() @nogc nothrow { asm @nogc nothrow { mfence; } }

// Bus mastering is REQUIRED: without it the device cannot DMA the rings or the buffers.
private void enableBusMastering(PCIDevice* pci) @nogc nothrow {
    uint cmd = pciConfigRead32(pci.bus, pci.slot, pci.func, 0x04);
    cmd |= 0x06;                       // bit1 memory space + bit2 bus master
    pciConfigWrite32(pci.bus, pci.slot, pci.func, 0x04, cmd);
}

// Resolve a BAR index to its MMIO base (handling the 64-bit BAR form).
private ulong barBase(PCIDevice* pci, uint barIndex) @nogc nothrow {
    uint lo = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(0x10 + barIndex * 4));
    ulong base = lo & 0xFFFFFFF0u;
    if ((lo & 0x6) == 0x4) {           // type 10b => 64-bit BAR, high half in the next dword
        uint hi = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(0x10 + barIndex * 4 + 4));
        base |= (cast(ulong)hi << 32);
    }
    return base;
}

// Allocate and zero one physical page, returning both halves of the mapping.
private void allocPage(out ulong phys, out ubyte* virt) @nogc nothrow {
    import memory.mm : alloc_phys_page;
    import core.globals : hhdm_offset;
    phys = alloc_phys_page();
    virt = (phys == 0) ? null : cast(ubyte*)(phys + hhdm_offset);
    if (virt !is null) foreach (i; 0 .. 4096) virt[i] = 0;
}

// Program one split virtqueue: allocate its three rings, hand the device their PHYSICAL
// addresses, enable it, and work out where to poke to kick it.
private bool setupQueue(ulong cc, ulong notifyBase, uint notifyOff, uint notifyMult,
                        ushort qidx, ref VNetQueue q) @nogc nothrow {
    import core.globals : hhdm_offset;

    volStoreW(cast(ushort*)(cc + CC_Q_SELECT), qidx);
    ushort qsz = volLoadW(cast(ushort*)(cc + CC_Q_SIZE));
    if (qsz == 0) { printLine("[virtio-net] queue absent"); return false; }
    if (qsz > 256) qsz = 256;          // VirtqAvail/VirtqUsed carry fixed 256-entry rings
    q.qsz = qsz;
    q.lastUsed = 0;

    ubyte* dv, av, uv;
    allocPage(q.descPhys,  dv);
    allocPage(q.availPhys, av);
    allocPage(q.usedPhys,  uv);
    if (dv is null || av is null || uv is null) { printLine("[virtio-net] ring alloc failed"); return false; }
    q.desc  = cast(VirtqDesc*)dv;
    q.avail = cast(VirtqAvail*)av;
    q.used  = cast(VirtqUsed*)uv;

    volStoreW(cast(ushort*)(cc + CC_Q_SELECT), qidx);
    volStoreU(cast(uint*)(cc + CC_Q_DESC),       cast(uint)q.descPhys);
    volStoreU(cast(uint*)(cc + CC_Q_DESC + 4),   cast(uint)(q.descPhys >> 32));
    volStoreU(cast(uint*)(cc + CC_Q_DRIVER),     cast(uint)q.availPhys);
    volStoreU(cast(uint*)(cc + CC_Q_DRIVER + 4), cast(uint)(q.availPhys >> 32));
    volStoreU(cast(uint*)(cc + CC_Q_DEVICE),     cast(uint)q.usedPhys);
    volStoreU(cast(uint*)(cc + CC_Q_DEVICE + 4), cast(uint)(q.usedPhys >> 32));
    volStoreW(cast(ushort*)(cc + CC_Q_ENABLE), 1);

    ushort qNotifyOff = volLoadW(cast(ushort*)(cc + CC_Q_NOTIFY_OFF));
    q.notifyAddr = notifyBase + notifyOff + cast(ulong)qNotifyOff * notifyMult + hhdm_offset;
    return true;
}

private void kick(ref VNetQueue q, ushort qidx) @nogc nothrow {
    memBarrier();
    volStoreW(cast(ushort*)q.notifyAddr, qidx);
}

// ── Public entry points, called from drivers/network/network.d ────────────────────

// Bring up a virtio-net device.  On success fills mac[0..6] and returns true.
export extern(C) bool virtioNetInit(PCIDevice* pci, ubyte* mac) @nogc nothrow {
    import core.globals : hhdm_offset;

    g_vnetReady = false;
    if (pci is null) return false;

    // Capability list present?  (PCI status word bit 4, status is the high half of dword 0x04.)
    uint cmdStatus = pciConfigRead32(pci.bus, pci.slot, pci.func, 0x04);
    if (!((cmdStatus >> 16) & 0x10)) {
        printLine("[virtio-net] device has no PCI capability list (legacy-only) -- cannot use modern transport");
        return false;
    }

    // Walk for COMMON (cfg_type 1), NOTIFY (2) and DEVICE (4) configuration structures.
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
        if (capId == 0x09) {           // PCI_CAP_ID_VNDR — a virtio structure
            uint barNo = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 4)) & 0xFF;
            uint off   = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 8));
            if (cfgType == 1) { commonBar = barNo; commonOff = off; }
            else if (cfgType == 2) {
                notifyBar = barNo; notifyOff = off;
                notifyMult = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 16));
            }
            else if (cfgType == 4) { deviceBar = barNo; deviceOff = off; }
        }
        cap = capNext;
    }
    if (commonBar == 0xFFFFFFFFu || notifyBar == 0xFFFFFFFFu) {
        printLine("[virtio-net] missing COMMON or NOTIFY capability -- abort");
        return false;
    }

    enableBusMastering(pci);

    ulong cc = barBase(pci, commonBar) + commonOff + hhdm_offset;
    ubyte* pStatus = cast(ubyte*)(cc + CC_STATUS);

    // Reset, then ACK + DRIVER.
    volStoreB(pStatus, 0);
    volStoreB(pStatus, VS_ACK);
    volStoreB(pStatus, cast(ubyte)(VS_ACK | VS_DRIVER));

    // Read both 32-bit feature windows.
    volStoreU(cast(uint*)(cc + CC_DEV_FEAT_SEL), 0);
    uint featLo = volLoadU(cast(uint*)(cc + CC_DEV_FEAT));
    volStoreU(cast(uint*)(cc + CC_DEV_FEAT_SEL), 1);
    uint featHi = volLoadU(cast(uint*)(cc + CC_DEV_FEAT));

    // Negotiate the bare minimum: VERSION_1 (window 1, bit 32-32=0) plus MAC if offered.
    // Everything else -- MRG_RXBUF, checksum offload, GSO -- is deliberately declined so each
    // received frame lands in exactly one buffer with a fixed 12-byte header.
    if (!((featHi >> (VIRTIO_F_VERSION_1 - 32)) & 1)) {
        printLine("[virtio-net] device does not offer VIRTIO_F_VERSION_1 -- abort");
        volStoreB(pStatus, VS_FAILED);
        return false;
    }
    const bool hasMac = ((featLo >> VIRTIO_NET_F_MAC) & 1) != 0;
    volStoreU(cast(uint*)(cc + CC_DRV_FEAT_SEL), 0);
    volStoreU(cast(uint*)(cc + CC_DRV_FEAT), hasMac ? (1u << VIRTIO_NET_F_MAC) : 0u);
    volStoreU(cast(uint*)(cc + CC_DRV_FEAT_SEL), 1);
    volStoreU(cast(uint*)(cc + CC_DRV_FEAT), 1u << (VIRTIO_F_VERSION_1 - 32));

    volStoreB(pStatus, cast(ubyte)(VS_ACK | VS_DRIVER | VS_FEATURES_OK));
    if (!(volLoadB(pStatus) & VS_FEATURES_OK)) {
        printLine("[virtio-net] device rejected our feature set (FEATURES_OK cleared) -- abort");
        volStoreB(pStatus, VS_FAILED);
        return false;
    }

    ulong notifyBase = barBase(pci, notifyBar);
    if (!setupQueue(cc, notifyBase, notifyOff, notifyMult, QUEUE_RX, g_rx)) return false;
    if (!setupQueue(cc, notifyBase, notifyOff, notifyMult, QUEUE_TX, g_tx)) return false;

    // RX buffers: one page each, described as DEVICE-WRITABLE, and posted on the avail ring
    // BEFORE DRIVER_OK.  A device with nothing posted simply drops every inbound frame.
    foreach (i; 0 .. RX_BUFS) {
        allocPage(g_rxBufPhys[i], g_rxBufVirt[i]);
        if (g_rxBufVirt[i] is null) { printLine("[virtio-net] rx buffer alloc failed"); return false; }
        g_rx.desc[i].addr  = g_rxBufPhys[i];
        g_rx.desc[i].len   = BUF_SZ;
        g_rx.desc[i].flags = VIRTQ_DESC_F_WRITE;
        g_rx.desc[i].next  = 0;
        g_rx.avail.ring[i % g_rx.qsz] = cast(ushort)i;
    }
    volStoreW(&g_rx.avail.idx, cast(ushort)RX_BUFS);

    allocPage(g_txBufPhys, g_txBufVirt);
    if (g_txBufVirt is null) { printLine("[virtio-net] tx buffer alloc failed"); return false; }

    // MAC: read the device-configuration structure if the device offered one.
    if (hasMac && deviceBar != 0xFFFFFFFFu) {
        ubyte* dcfg = cast(ubyte*)(barBase(pci, deviceBar) + deviceOff + hhdm_offset);
        foreach (i; 0 .. 6) mac[i] = volLoadB(dcfg + i);
    } else {
        // No MAC offered: synthesise a locally-administered one so the stack still works.
        mac[0] = 0x02; mac[1] = 0x00; mac[2] = 0x00;
        mac[3] = 0x00; mac[4] = 0x00; mac[5] = 0x01;
    }

    volStoreB(pStatus, cast(ubyte)(VS_ACK | VS_DRIVER | VS_FEATURES_OK | VS_DRIVER_OK));
    memBarrier();
    kick(g_rx, QUEUE_RX);              // tell the device the rx buffers are ready

    g_vnetReady = true;
    // printHex takes a ulong, so a per-byte call printed 16 hex digits each and the
    // MAC came out as an unreadable 96-character smear.  Pack it into one value.
    ulong macv = 0; foreach (i; 0 .. 6) macv = (macv << 8) | mac[i];
    print("[virtio-net] up: rx/tx queues live, MAC=");
    printHex(macv);
    printLine("");
    return true;
}

// Transmit one Ethernet frame.  Prepends the 12-byte virtio_net_hdr, which we zero: no
// checksum offload and no GSO were negotiated, so every field must read as "plain frame".
export extern(C) bool virtioNetSend(const(ubyte)* data, size_t len) @nogc nothrow {
    if (!g_vnetReady || data is null || len == 0) return false;
    if (len > BUF_SZ - NET_HDR_LEN) return false;
    if (g_txBusy) return false;
    g_txBusy = true; scope(exit) g_txBusy = false;

    foreach (i; 0 .. NET_HDR_LEN) g_txBufVirt[i] = 0;
    foreach (i; 0 .. len) g_txBufVirt[NET_HDR_LEN + i] = data[i];

    g_tx.desc[0].addr  = g_txBufPhys;
    g_tx.desc[0].len   = cast(uint)(NET_HDR_LEN + len);
    g_tx.desc[0].flags = 0;            // device-readable
    g_tx.desc[0].next  = 0;

    ushort ai = volLoadW(&g_tx.avail.idx);
    g_tx.avail.ring[ai % g_tx.qsz] = 0;
    volStoreW(&g_tx.avail.idx, cast(ushort)(ai + 1));
    kick(g_tx, QUEUE_TX);

    // Wait for the device to consume it.  Bounded: a wedged device must not hang the kernel
    // loop (which holds the BKL while networkStackPoll runs).
    int spin = 0;
    while (volLoadW(&g_tx.used.idx) == g_tx.lastUsed && spin < 20_000_000) spin++;
    if (volLoadW(&g_tx.used.idx) == g_tx.lastUsed) return false;
    g_tx.lastUsed = volLoadW(&g_tx.used.idx);
    memBarrier();
    return true;
}

// Receive one Ethernet frame if the device has delivered any.  Returns the frame length
// (header stripped), 0 when the ring is empty, or -1 when the driver is not up.
export extern(C) int virtioNetReceive(ubyte* buffer, size_t maxLen) @nogc nothrow {
    if (!g_vnetReady || buffer is null || maxLen == 0) return -1;

    ushort uidx = volLoadW(&g_rx.used.idx);
    if (uidx == g_rx.lastUsed) return 0;          // nothing arrived

    memBarrier();
    auto elem = &g_rx.used.ring[g_rx.lastUsed % g_rx.qsz];
    uint id  = elem.id;
    uint tot = elem.len;                          // header + frame, as written by the device
    g_rx.lastUsed = cast(ushort)(g_rx.lastUsed + 1);

    int copied = 0;
    if (id < RX_BUFS && tot > NET_HDR_LEN) {
        uint flen = tot - NET_HDR_LEN;
        if (flen > maxLen) flen = cast(uint)maxLen;
        ubyte* src = g_rxBufVirt[id] + NET_HDR_LEN;
        foreach (i; 0 .. flen) buffer[i] = src[i];
        copied = cast(int)flen;
    }

    // Re-post the buffer, or the ring drains to nothing and RX stops after RX_BUFS frames.
    if (id < RX_BUFS) {
        g_rx.desc[id].addr  = g_rxBufPhys[id];
        g_rx.desc[id].len   = BUF_SZ;
        g_rx.desc[id].flags = VIRTQ_DESC_F_WRITE;
        g_rx.desc[id].next  = 0;
        ushort ai = volLoadW(&g_rx.avail.idx);
        g_rx.avail.ring[ai % g_rx.qsz] = cast(ushort)id;
        volStoreW(&g_rx.avail.idx, cast(ushort)(ai + 1));
        kick(g_rx, QUEUE_RX);
    }
    return copied;
}

export extern(C) bool virtioNetReady() @nogc nothrow { return g_vnetReady; }
