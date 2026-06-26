module drivers.graphics.virtio_gpu;

import drivers.virtio;
import drivers.pci;
import userland.shell.console : printLine, printHex, printUnsigned;
import drivers.io;

extern(C):

// --------------------------------------------------------------------------
// VirtIO GPU Protocol
// --------------------------------------------------------------------------

enum VIRTIO_GPU_CTRL_QUEUE = 0;
enum VIRTIO_GPU_CURSOR_QUEUE = 1;

enum VIRTIO_GPU_CMD_GET_DISPLAY_INFO = 0x0100;
enum VIRTIO_GPU_CMD_RESOURCE_CREATE_2D = 0x0101;
enum VIRTIO_GPU_CMD_RESOURCE_UNREF = 0x0102;
enum VIRTIO_GPU_CMD_SET_SCANOUT = 0x0103;
enum VIRTIO_GPU_CMD_RESOURCE_FLUSH = 0x0104;
enum VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D = 0x0105;
enum VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING = 0x0106;
enum VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING = 0x0107;

enum VIRTIO_GPU_RESP_OK_NODATA = 0x1100;
enum VIRTIO_GPU_RESP_OK_DISPLAY_INFO = 0x1101;

struct VirtioGpuCtrlHdr {
    uint type;
    uint flags;
    ulong fenceId;
    uint ctxId;
    uint padding;
}

// Device Abstraction
// Use the definition from virtio.d


struct VirtioGpuRect {
    uint x;
    uint y;
    uint width;
    uint height;
}

struct VirtioGpuResourceCreate2D {
    VirtioGpuCtrlHdr hdr;
    uint resourceId;
    uint format;
    uint width;
    uint height;
}

struct VirtioGpuResourceAttachBacking {
    VirtioGpuCtrlHdr hdr;
    uint resourceId;
    uint nrEntries;
}

struct VirtioGpuMemEntry {
    ulong addr;
    uint length;
    uint padding;
}

struct VirtioGpuSetScanout {
    VirtioGpuCtrlHdr hdr;
    VirtioGpuRect r;
    uint scanoutId;
    uint resourceId;
}

struct VirtioGpuTransferToHost2D {
    VirtioGpuCtrlHdr hdr;
    VirtioGpuRect r;
    ulong offset;
    uint resourceId;
    uint padding;
}

struct VirtioGpuResourceFlush {
    VirtioGpuCtrlHdr hdr;
    VirtioGpuRect r;
    uint resourceId;
    uint padding;
}

enum VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM = 1;

// --------------------------------------------------------------------------
// Driver State
// --------------------------------------------------------------------------

__gshared VirtioDevice g_gpuDev;
__gshared bool g_gpuAvailable = false;
__gshared bool g_gpuVirgl = false;   // R2.1: device offers VIRTIO_GPU_F_VIRGL (3D acceleration)
__gshared bool g_gpuModern = false;  // R2.2: modern virtio-1.0 handshake completed (FEATURES_OK)
__gshared ulong  g_gpuCommon = 0;    // R2.2: common-config virtual base (via HHDM)
__gshared ushort g_gpuQueueSize = 0; // R2.2: control virtqueue size
__gshared bool g_gpuQueueReady = false; // R2.2b: control virtqueue live (GET_CAPSET round-trip OK)
// R2.3: control-queue state kept for issuing further commands (CTX_CREATE, RESOURCE_CREATE_3D, …).
__gshared VirtqDesc*  g_gpuDesc;
__gshared VirtqAvail* g_gpuAvail;
__gshared VirtqUsed*  g_gpuUsed;
__gshared ubyte*      g_gpuBuf;        // request at +0, response at +2048 (one DMA page)
__gshared ulong       g_gpuBufPhys;
__gshared ulong       g_gpuNotifyAddr;
__gshared ushort      g_gpuQsz;
__gshared ushort      g_gpuLastUsed;   // last-seen used.idx
__gshared bool        g_gpu3dReady = false; // R2.3: 3D context + resource commands accepted
__gshared bool        g_gpuCtrlBusy = false; // R3: serialize the shared control queue (Weston + GPU clients)
__gshared bool        g_gpuBlob = false;     // B2: device offers VIRTIO_GPU_F_RESOURCE_BLOB (host-visible blobs)
__gshared ulong       g_gpuShmBase = 0;      // B1: HHDM virt base of the host-visible SHM BAR window (0 = none)
__gshared ulong       g_gpuShmLen = 0;       // B1: host-visible window length (the device's hostmem= size)
__gshared uint g_resourceIdCounter = 1;
__gshared ulong g_gpuFence = 0;              // B3: monotonic fence id (was hardcoded 1/2/4 -> host EBUSY)

// Ring buffers (Static for simplicity in this environment)
__gshared VirtqDesc[256] g_desc;
__gshared VirtqAvail g_avail;
__gshared VirtqUsed g_used;
__gshared ushort g_nextDescIdx = 0;

// --------------------------------------------------------------------------
// Driver Implementation
// --------------------------------------------------------------------------

// Volatile 32-bit MMIO accessors (shared cast = volatile in D), for the virtio common config.
private uint   volLoadU(uint* p)           @nogc nothrow { return *cast(shared const uint*)p; }
private void   volStoreU(uint* p, uint v)  @nogc nothrow { *cast(shared uint*)p = v; }
private ubyte  volLoadB(ubyte* p)          @nogc nothrow { return *cast(shared const ubyte*)p; }
private void   volStoreB(ubyte* p, ubyte v) @nogc nothrow { *cast(shared ubyte*)p = v; }
private ushort volLoadW(ushort* p)         @nogc nothrow { return *cast(shared const ushort*)p; }
private void   volStoreW(ushort* p, ushort v) @nogc nothrow { *cast(shared ushort*)p = v; }
private void   volStoreQ(ulong* p, ulong v) @nogc nothrow { *cast(shared ulong*)p = v; }
private void   memBarrier() @nogc nothrow { asm @nogc nothrow { mfence; } }

// R2.3 — issue one control-queue command (request in g_gpuBuf[0..reqLen], response written to
// g_gpuBuf[2048..]).  Returns the response ctrl_hdr.type, or 0xFFFFFFFF on timeout.  Serial: each
// command waits for its own completion before the next, so descriptors 0/1 are reused.
private void gpuZeroReq(uint n) @nogc nothrow { foreach (i; 0 .. n) g_gpuBuf[i] = 0; }
private void gpuPutU(uint off, uint v) @nogc nothrow { *cast(uint*)(g_gpuBuf + off) = v; }
private void gpuPutQ(uint off, ulong v) @nogc nothrow { *cast(ulong*)(g_gpuBuf + off) = v; }
private ulong nextFence() @nogc nothrow { return ++g_gpuFence; }  // B3: a fresh fence id per submit
private uint gpuCtrl(uint reqLen, uint respLen) @nogc nothrow {
    // R3: serialize the single shared control queue — once a GPU client also drives it,
    // two tasks must not interleave the fixed descriptors / g_gpuBuf. Plain reentrancy
    // guard, NOT cli/sti (disabling IRQs in the present/cursor syscall path deadlocks).
    if (g_gpuCtrlBusy) return 0xFFFFFFFFu;
    g_gpuCtrlBusy = true; scope(exit) g_gpuCtrlBusy = false;
    auto desc = g_gpuDesc; auto avail = g_gpuAvail; auto used = g_gpuUsed;
    foreach (i; 0 .. respLen) g_gpuBuf[2048 + i] = 0;
    desc[0].addr = g_gpuBufPhys;        desc[0].len = reqLen;  desc[0].flags = VIRTQ_DESC_F_NEXT;  desc[0].next = 1;
    desc[1].addr = g_gpuBufPhys + 2048; desc[1].len = respLen; desc[1].flags = VIRTQ_DESC_F_WRITE; desc[1].next = 0;
    ushort ai = volLoadW(&avail.idx);
    avail.ring[ai % g_gpuQsz] = 0;
    volStoreW(&avail.idx, cast(ushort)(ai + 1));
    memBarrier();
    volStoreW(cast(ushort*)g_gpuNotifyAddr, 0);
    int spin = 0;
    while (volLoadW(&used.idx) == g_gpuLastUsed && spin < 50_000_000) spin++;
    if (volLoadW(&used.idx) == g_gpuLastUsed) return 0xFFFFFFFFu;
    g_gpuLastUsed = volLoadW(&used.idx);
    memBarrier();
    return *cast(uint*)(g_gpuBuf + 2048);
}

// virtio-1.0 device-status bits + the common-config field offsets.
private enum { VS_ACK = 1, VS_DRIVER = 2, VS_DRIVER_OK = 4, VS_FEATURES_OK = 8, VS_FAILED = 128 }
private enum { CC_DEV_FEAT_SEL = 0x00, CC_DEV_FEAT = 0x04, CC_DRV_FEAT_SEL = 0x08, CC_DRV_FEAT = 0x0C,
               CC_NUM_QUEUES = 0x12, CC_STATUS = 0x14, CC_Q_SELECT = 0x16, CC_Q_SIZE = 0x18,
               CC_Q_ENABLE = 0x1C, CC_Q_NOTIFY_OFF = 0x1E, CC_Q_DESC = 0x20, CC_Q_DRIVER = 0x28,
               CC_Q_DEVICE = 0x30 }

// R2.1 — modern (virtio-1.0) virgl 3D capability detection.
//
// virtio-gpu is a modern-only PCI device (0x1AF4:0x1050) with NO legacy IO BAR, so its feature
// bits are NOT at an IO port — they live in an MMIO "common configuration" structure located by
// walking the device's PCI capability list (vendor capability id 0x09, cfg_type=COMMON=1).  We map
// that via the HHDM, select feature window 0, read device_feature, and test VIRTIO_GPU_F_VIRGL
// (bit 0) — virgl 3D acceleration, which QEMU's virtio-gpu-gl offers only with a host GL context
// (-display egl-headless / gtk,gl=on + virglrenderer).  Detection ONLY; the virtqueue + 3D command
// path (GET_CAPSET / CTX_CREATE / SUBMIT_3D) is R2.2+.
export void virtioGpuDetectVirgl() @nogc nothrow {
    import drivers.pci : scanPCIDevices;
    import core.globals : hhdm_offset;

    auto devices = scanPCIDevices();
    PCIDevice* pci = null;
    foreach (ref dev; devices) {
        if (dev.vendorId == VIRTIO_VENDOR_ID && dev.deviceId == VIRTIO_DEV_GPU) { pci = &dev; break; }
    }
    if (pci is null) { printLine("[virtio-gpu] R2.1: no virtio-gpu device (0x1AF4:0x1050) on the bus"); return; }
    printLine("[virtio-gpu] R2.1: found modern virtio-gpu (0x1050)");

    // PCI status word (high 16 of offset 0x04) bit 4 => capability list present; pointer at 0x34.
    uint cmdStatus = pciConfigRead32(pci.bus, pci.slot, pci.func, 0x04);
    if (!((cmdStatus >> 16) & 0x10)) { printLine("[virtio-gpu] R2.1: no PCI capability list"); return; }
    ubyte cap = cast(ubyte)(pciConfigRead32(pci.bus, pci.slot, pci.func, 0x34) & 0xFC);

    // Walk the capability list for the virtio COMMON-config (cfg_type 1), NOTIFY (cfg_type 2), and
    // SHARED_MEMORY (cfg_type 8 — B1, the host-visible blob window) caps.
    uint commonBar = 0xFFFFFFFFu, commonOff = 0;
    uint notifyBar = 0xFFFFFFFFu, notifyOff = 0, notifyMult = 0;
    uint shmBar = 0xFFFFFFFFu; ulong shmOff = 0, shmLen = 0;   // B1: VIRTIO_GPU_SHM_ID_HOST_VISIBLE
    int guard = 0;
    while (cap != 0 && guard++ < 48) {
        uint dw0 = pciConfigRead32(pci.bus, pci.slot, pci.func, cap);
        ubyte capId   = cast(ubyte)(dw0 & 0xFF);
        ubyte capNext = cast(ubyte)((dw0 >> 8) & 0xFF);
        ubyte cfgType = cast(ubyte)((dw0 >> 24) & 0xFF);
        if (capId == 0x09) { // VIRTIO vendor capability (struct virtio_pci_cap)
            uint dw1 = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 4)); // bar in low byte
            uint off = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 8)); // le32 offset
            if (cfgType == 1) { commonBar = dw1 & 0xFF; commonOff = off; }                 // COMMON_CFG=1
            if (cfgType == 2) { // NOTIFY_CFG=2 ; struct virtio_pci_notify_cap adds notify_off_multiplier at cap+16
                notifyBar = dw1 & 0xFF; notifyOff = off;
                notifyMult = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 16));
            }
            if (cfgType == 8) { // SHARED_MEMORY_CFG ; struct virtio_pci_cap64: id@cap+5, 64-bit off/len
                ubyte shmId = cast(ubyte)((dw1 >> 8) & 0xFF);   // id is the byte after bar
                if (shmId == 1) {                               // VIRTIO_GPU_SHM_ID_HOST_VISIBLE
                    shmBar = dw1 & 0xFF;
                    uint lenLo = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 12));
                    uint offHi = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 16));
                    uint lenHi = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(cap + 20));
                    shmOff = cast(ulong)off  | (cast(ulong)offHi << 32);
                    shmLen = cast(ulong)lenLo | (cast(ulong)lenHi << 32);
                }
            }
        }
        cap = capNext;
    }
    if (commonBar == 0xFFFFFFFFu) { printLine("[virtio-gpu] R2.1: no COMMON-config capability found"); return; }

    // Resolve the BAR (handle a 64-bit memory BAR) -> physical base of the common config.
    uint barLo = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(0x10 + commonBar * 4));
    ulong barBase = barLo & 0xFFFFFFF0u;
    if ((barLo & 0x6) == 0x4) { // 64-bit BAR: high dword in the next slot
        uint barHi = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(0x10 + commonBar * 4 + 4));
        barBase |= (cast(ulong)barHi << 32);
    }
    ulong cc = barBase + commonOff + hhdm_offset; // common config via the HHDM
    g_gpuCommon = cc;                              // kept for R2.2b (the virtqueue + GET_CAPSET)

    // B1: resolve the host-visible SHM BAR window (host-visible blob memory; cfg_type 8 / HOST_VISIBLE).
    if (shmBar != 0xFFFFFFFFu) {
        uint sLo = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(0x10 + shmBar * 4));
        ulong sBase = sLo & 0xFFFFFFF0u;
        if ((sLo & 0x6) == 0x4)  // 64-bit BAR (the hostmem window is 64-bit prefetchable)
            sBase |= (cast(ulong)pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(0x10 + shmBar * 4 + 4)) << 32);
        g_gpuShmBase = sBase + shmOff + hhdm_offset;
        g_gpuShmLen  = shmLen;
        printLine("[virtio-gpu] B1: host-visible SHM bar / off / len:");
        printUnsigned(shmBar); printHex(shmOff); printHex(shmLen);
    } else {
        printLine("[virtio-gpu] B1: no host-visible SHM cap (device blob/hostmem not enabled)");
    }
    auto pStatus  = cast(ubyte*)(cc + CC_STATUS);
    auto pFeatSel = cast(uint*)(cc + CC_DEV_FEAT_SEL);
    auto pFeat    = cast(uint*)(cc + CC_DEV_FEAT);
    auto pDrvSel  = cast(uint*)(cc + CC_DRV_FEAT_SEL);
    auto pDrvFeat = cast(uint*)(cc + CC_DRV_FEAT);

    // R2.2 — virtio-1.0 modern handshake: reset -> ACKNOWLEDGE -> DRIVER.
    volStoreB(pStatus, 0);                                   // reset
    volStoreB(pStatus, VS_ACK);
    volStoreB(pStatus, cast(ubyte)(VS_ACK | VS_DRIVER));

    // Read device feature bits (low/high) and detect VIRGL (R2.1).
    volStoreU(pFeatSel, 0); uint featLo = volLoadU(pFeat);
    volStoreU(pFeatSel, 1); uint featHi = volLoadU(pFeat);
    printLine("[virtio-gpu] R2.1: device_feature low / high:");
    printHex(featLo);
    printHex(featHi);
    enum VIRTIO_GPU_F_VIRGL = 0; // device feature bit 0
    if (featLo & (1u << VIRTIO_GPU_F_VIRGL)) {
        printLine("[virtio-gpu] R2.1: VIRGL 3D capability OFFERED -- GPU acceleration is reachable");
        g_gpuVirgl = true;
    } else {
        printLine("[virtio-gpu] R2.1: VIRGL bit NOT set -- 2D scanout only");
        g_gpuVirgl = false;
    }

    // R2.2 / B2 — negotiate: accept VIRGL + (when offered) RESOURCE_BLOB(bit 3) and CONTEXT_INIT(bit 4)
    // in the low word, plus VIRTIO_F_VERSION_1 (bit 32 = bit 0 of the high word, mandatory for modern).
    enum VIRTIO_GPU_F_RESOURCE_BLOB = 3;
    enum VIRTIO_GPU_F_CONTEXT_INIT  = 4;
    uint drvLo = g_gpuVirgl ? (1u << VIRTIO_GPU_F_VIRGL) : 0u;
    if (featLo & (1u << VIRTIO_GPU_F_RESOURCE_BLOB)) {
        drvLo |= (1u << VIRTIO_GPU_F_RESOURCE_BLOB);
        g_gpuBlob = true;
        printLine("[virtio-gpu] B2: VIRTIO_GPU_F_RESOURCE_BLOB offered + acked (host-visible blobs)");
    }
    if (featLo & (1u << VIRTIO_GPU_F_CONTEXT_INIT))
        drvLo |= (1u << VIRTIO_GPU_F_CONTEXT_INIT);
    volStoreU(pDrvSel, 0); volStoreU(pDrvFeat, drvLo);
    volStoreU(pDrvSel, 1); volStoreU(pDrvFeat, 1u);          // VIRTIO_F_VERSION_1
    volStoreB(pStatus, cast(ubyte)(VS_ACK | VS_DRIVER | VS_FEATURES_OK));
    ubyte st = volLoadB(pStatus);
    if (st & VS_FEATURES_OK) {
        printLine("[virtio-gpu] R2.2: modern handshake OK -- FEATURES_OK accepted (virtio-1.0)");
        g_gpuModern = true;
    } else {
        printLine("[virtio-gpu] R2.2: FEATURES_OK REJECTED by device");
        return;
    }

    // Control virtqueue (queue 0) inventory.
    ushort nq = volLoadW(cast(ushort*)(cc + CC_NUM_QUEUES));
    volStoreW(cast(ushort*)(cc + CC_Q_SELECT), 0);
    ushort qsz = volLoadW(cast(ushort*)(cc + CC_Q_SIZE));
    g_gpuQueueSize = qsz;
    printLine("[virtio-gpu] R2.2: num_queues / control-queue size:");
    printUnsigned(nq);
    printUnsigned(qsz);
    if (qsz == 0 || qsz > 256) { printLine("[virtio-gpu] R2.2b: unexpected queue size -- abort"); return; }
    if (notifyBar == 0xFFFFFFFFu) { printLine("[virtio-gpu] R2.2b: no NOTIFY capability -- abort"); return; }

    // R2.2b — set up the control split-virtqueue with DMA-coherent rings, then a GET_CAPSET_INFO
    // round-trip to prove the modern transport end-to-end.  The device DMAs PHYSICAL addresses, and
    // there is no low identity map, so the rings MUST come from the physical allocator (a kernel
    // static's virtual address is not its physical address); phys_to_virt() gives CPU access.
    import memory.mm : alloc_phys_page;
    ulong descPhys = alloc_phys_page();   // desc table: 256*16 = 4096 = one page
    ulong availPhys = alloc_phys_page();
    ulong usedPhys = alloc_phys_page();
    ulong bufPhys = alloc_phys_page();     // request (0..32) + response (64..104)
    auto desc  = cast(VirtqDesc*)(descPhys + hhdm_offset);   // phys_to_virt = + HHDM
    auto avail = cast(VirtqAvail*)(availPhys + hhdm_offset);
    auto used  = cast(VirtqUsed*)(usedPhys + hhdm_offset);
    auto buf   = cast(ubyte*)(bufPhys + hhdm_offset);
    foreach (i; 0 .. 4096) { (cast(ubyte*)desc)[i] = 0; (cast(ubyte*)avail)[i] = 0; (cast(ubyte*)used)[i] = 0; buf[i] = 0; }

    // Program queue 0's ring addresses (64-bit fields as two 32-bit MMIO writes) and enable it.
    volStoreW(cast(ushort*)(cc + CC_Q_SELECT), 0);
    volStoreU(cast(uint*)(cc + CC_Q_DESC),       cast(uint)descPhys);
    volStoreU(cast(uint*)(cc + CC_Q_DESC + 4),   cast(uint)(descPhys >> 32));
    volStoreU(cast(uint*)(cc + CC_Q_DRIVER),     cast(uint)availPhys);
    volStoreU(cast(uint*)(cc + CC_Q_DRIVER + 4), cast(uint)(availPhys >> 32));
    volStoreU(cast(uint*)(cc + CC_Q_DEVICE),     cast(uint)usedPhys);
    volStoreU(cast(uint*)(cc + CC_Q_DEVICE + 4), cast(uint)(usedPhys >> 32));
    volStoreW(cast(ushort*)(cc + CC_Q_ENABLE), 1);
    ushort qNotifyOff = volLoadW(cast(ushort*)(cc + CC_Q_NOTIFY_OFF));

    // Resolve the NOTIFY BAR -> the per-queue notify register (write the vq index to kick).
    uint nbarLo = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(0x10 + notifyBar * 4));
    ulong nbarBase = nbarLo & 0xFFFFFFF0u;
    if ((nbarLo & 0x6) == 0x4) {
        uint nbarHi = pciConfigRead32(pci.bus, pci.slot, pci.func, cast(ubyte)(0x10 + notifyBar * 4 + 4));
        nbarBase |= (cast(ulong)nbarHi << 32);
    }
    ulong notifyAddr = nbarBase + notifyOff + cast(ulong)qNotifyOff * notifyMult + hhdm_offset;

    // DRIVER_OK — the device is live.
    volStoreB(pStatus, cast(ubyte)(VS_ACK | VS_DRIVER | VS_FEATURES_OK | VS_DRIVER_OK));

    // Build a GET_CAPSET_INFO command (capset_index 0) in buf, response in buf+64.
    enum VIRTIO_GPU_CMD_GET_CAPSET_INFO = 0x0108;
    enum VIRTIO_GPU_RESP_OK_CAPSET_INFO = 0x1102;
    *cast(uint*)(buf + 0)  = VIRTIO_GPU_CMD_GET_CAPSET_INFO; // ctrl_hdr.type
    *cast(uint*)(buf + 24) = 0;                              // capset_index = 0
    desc[0].addr = bufPhys;       desc[0].len = 32; desc[0].flags = VIRTQ_DESC_F_NEXT;  desc[0].next = 1;
    desc[1].addr = bufPhys + 64;  desc[1].len = 40; desc[1].flags = VIRTQ_DESC_F_WRITE; desc[1].next = 0;
    avail.ring[0] = 0;
    volStoreW(&avail.idx, 1);
    memBarrier();                                            // drain the store buffer to memory before the kick
    volStoreW(cast(ushort*)notifyAddr, 0);                   // kick queue 0

    // Wait for the device to post a used element (DMA is cache-coherent on x86).
    int spin = 0;
    while (volLoadW(&used.idx) == 0 && spin < 50_000_000) spin++;
    if (volLoadW(&used.idx) == 0) { printLine("[virtio-gpu] R2.2b: GET_CAPSET_INFO TIMED OUT"); return; }
    memBarrier();

    uint respType = *cast(uint*)(buf + 64 + 0);
    uint capsetId = *cast(uint*)(buf + 64 + 24);
    uint maxVer   = *cast(uint*)(buf + 64 + 28);
    uint maxSize  = *cast(uint*)(buf + 64 + 32);
    printLine("[virtio-gpu] R2.2b: GET_CAPSET resp type / capset_id / max_ver / max_size:");
    printHex(respType);
    printUnsigned(capsetId);
    printUnsigned(maxVer);
    printUnsigned(maxSize);
    if (respType == VIRTIO_GPU_RESP_OK_CAPSET_INFO) {
        printLine("[virtio-gpu] R2.2b: VIRGL CAPSET QUERY OK -- modern virtqueue transport WORKS");
        g_gpuQueueReady = true;
    } else {
        printLine("[virtio-gpu] R2.2b: unexpected response type from GET_CAPSET_INFO");
        return;
    }

    // R2.3 — exercise the virgl 3D command path over the now-live transport.  Keep the queue state
    // for the gpuCtrl() helper, and pick up the used index where GET_CAPSET left it.
    g_gpuDesc = desc; g_gpuAvail = avail; g_gpuUsed = used;
    g_gpuBuf = buf; g_gpuBufPhys = bufPhys; g_gpuNotifyAddr = notifyAddr; g_gpuQsz = qsz;
    g_gpuLastUsed = volLoadW(&used.idx);
    if (!g_gpuVirgl) return;   // 3D commands only make sense when virgl is offered

    enum VIRTIO_GPU_RESP_OK_NODATA = 0x1100;
    // (a) CTX_CREATE: create virgl 3D context 1.
    gpuZeroReq(96);
    gpuPutU(0, 0x0200);    // hdr.type = VIRTIO_GPU_CMD_CTX_CREATE
    gpuPutU(16, 1);        // hdr.ctx_id = 1 (the new context)
    uint c1 = gpuCtrl(96, 24);
    // (b) RESOURCE_CREATE_3D: a 256x256 BGRA render-target texture, resource 1.
    gpuZeroReq(72);
    gpuPutU(0, 0x0204);    // hdr.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_3D
    gpuPutU(24, 1);        // resource_id = 1
    gpuPutU(28, 2);        // target = PIPE_TEXTURE_2D
    gpuPutU(32, 1);        // format = VIRGL_FORMAT_B8G8R8A8_UNORM
    gpuPutU(36, 2 | 8);    // bind = VIRGL_BIND_RENDER_TARGET | VIRGL_BIND_SAMPLER_VIEW
    gpuPutU(40, 32);       // width  (32x32 so a single 4 KiB backing page covers the resource)
    gpuPutU(44, 32);       // height
    gpuPutU(48, 1);        // depth
    gpuPutU(52, 1);        // array_size
    uint c2 = gpuCtrl(72, 24);
    // CTX_ATTACH_RESOURCE is deliberately deferred to R2.3b: the real Linux guest attaches the
    // resource to its context only AFTER create + backing, and QEMU's attach handler returns void
    // (OK_NODATA is not a success signal), so order is what matters.
    printLine("[virtio-gpu] R2.3: CTX_CREATE / RESOURCE_CREATE_3D resp types:");
    printHex(c1);
    printHex(c2);
    if (c1 == VIRTIO_GPU_RESP_OK_NODATA && c2 == VIRTIO_GPU_RESP_OK_NODATA) {
        printLine("[virtio-gpu] R2.3: 3D context + resource created (virgl objects live on the GPU)");
        g_gpu3dReady = true;
    } else {
        printLine("[virtio-gpu] R2.3: a 3D command was rejected by the device");
        return;
    }

    // R2.3b — the canonical virgl render-to-texture readback, in the exact order + ctx_ids the real
    // Linux virtio_gpu guest uses (verified against virglrenderer 1.8.8 + QEMU 8.2.2 source):
    //   RESOURCE_ATTACH_BACKING -> CTX_ATTACH_RESOURCE(ctx1) -> SUBMIT_3D(ctx1: surface+fb+clear)
    //   -> TRANSFER_FROM_HOST_3D(ctx1).  CTX_ATTACH must follow create+backing; the transfer must use
    //   the OWNING context (ctx 1) — ctx_id=0 routes to virglrenderer's internal ctx0 against an
    //   unrendered texture and reads zeros.  A standalone transfer needs BOTH res-in-ctx-res_hash
    //   (CTX_ATTACH) and res->iov (ATTACH_BACKING) or vrend logs "Illegal resource".
    ulong backPhys = alloc_phys_page();
    auto back = cast(uint*)(backPhys + hhdm_offset);
    foreach (i; 0 .. 1024) back[i] = 0;   // 32*32 pixels (so a red readback is unambiguous)

    // (c) RESOURCE_ATTACH_BACKING(resource 1; one mem entry: backPhys, 4096 bytes) -> sets res->iov.
    gpuZeroReq(48);
    gpuPutU(0, 0x0106);          // VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING
    gpuPutU(24, 1);              // resource_id
    gpuPutU(28, 1);              // nr_entries
    gpuPutQ(32, backPhys);       // mem_entry.addr
    gpuPutU(40, 4096);           // mem_entry.length (>= stride*height = 128*32)
    uint d1 = gpuCtrl(48, 24);

    // (d) CTX_ATTACH_RESOURCE(ctx 1, resource 1) -> inserts the typed resource into ctx 1's res_hash.
    gpuZeroReq(32);
    gpuPutU(0, 0x0202);          // VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE (0x0202, NOT 0x0206!)
    gpuPutU(16, 1);              // hdr.ctx_id = 1
    gpuPutU(24, 1);              // resource_id = 1
    uint a1 = gpuCtrl(32, 24);

    // (e) SUBMIT_3D (hdr.ctx_id = 1): a virgl stream that clears resource 1 RED.
    //   CREATE_OBJECT(SURFACE) wrapping res 1 -> SET_FRAMEBUFFER_STATE(cbuf=surface) -> CLEAR(red).
    gpuZeroReq(108);
    gpuPutU(0, 0x0207);          // VIRTIO_GPU_CMD_SUBMIT_3D (0x0207, NOT 0x0203 = CTX_DETACH!)
    gpuPutU(4, 1);               // hdr.flags = VIRTIO_GPU_FLAG_FENCE
    gpuPutQ(8, nextFence());     // hdr.fence_id (B3: monotonic)
    gpuPutU(16, 1);              // hdr.ctx_id = 1
    gpuPutU(24, 76);             // command-stream size in bytes (19 dwords)
    enum uint S = 32;            // stream begins after hdr(24)+size(4)+padding(4)
    // CREATE_OBJECT SURFACE: (len5<<16)|(VIRGL_OBJECT_SURFACE=8<<8)|VIRGL_CCMD_CREATE_OBJECT=1
    gpuPutU(S +  0, (5 << 16) | (8 << 8) | 1);
    gpuPutU(S +  4, 1);          // surface handle
    gpuPutU(S +  8, 1);          // resource handle (res 1)
    gpuPutU(S + 12, 1);          // format = B8G8R8A8_UNORM
    gpuPutU(S + 16, 0);          // texture level
    gpuPutU(S + 20, 0);          // first_layer | last_layer<<16
    // SET_FRAMEBUFFER_STATE: (len3<<16)|VIRGL_CCMD_SET_FRAMEBUFFER_STATE=5
    gpuPutU(S + 24, (3 << 16) | 5);
    gpuPutU(S + 28, 1);          // nr_cbufs
    gpuPutU(S + 32, 0);          // zsurf handle
    gpuPutU(S + 36, 1);          // cbuf[0] = surface handle 1
    // CLEAR: (len8<<16)|VIRGL_CCMD_CLEAR=7
    gpuPutU(S + 40, (8 << 16) | 7);
    gpuPutU(S + 44, 4);          // buffers = PIPE_CLEAR_COLOR0 (1<<2)
    gpuPutU(S + 48, 0x3f800000); // color r = 1.0f
    gpuPutU(S + 52, 0);          // g
    gpuPutU(S + 56, 0);          // b
    gpuPutU(S + 60, 0x3f800000); // a = 1.0f
    gpuPutU(S + 64, 0);          // depth lo
    gpuPutU(S + 68, 0);          // depth hi
    gpuPutU(S + 72, 0);          // stencil
    uint e1 = gpuCtrl(108, 24);

    // (f) TRANSFER_FROM_HOST_3D (hdr.ctx_id = 1): copy the cleared texture into the guest backing.
    gpuZeroReq(72);
    gpuPutU(0, 0x0206);          // VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D (0x0206, NOT 0x0207 = SUBMIT!)
    gpuPutU(4, 1);               // hdr.flags = VIRTIO_GPU_FLAG_FENCE
    gpuPutQ(8, nextFence());     // hdr.fence_id (B3: monotonic)
    gpuPutU(16, 1);              // hdr.ctx_id = 1 (owning context — NOT 0)
    gpuPutU(36, 32);             // box.w
    gpuPutU(40, 32);             // box.h
    gpuPutU(44, 1);              // box.d
    gpuPutQ(48, 0);              // offset
    gpuPutU(56, 1);              // resource_id
    gpuPutU(60, 0);              // level
    gpuPutU(64, 128);            // stride = 32px * 4 bytes
    gpuPutU(68, 4096);           // layer_stride = stride * height
    uint f1 = gpuCtrl(72, 24);

    memBarrier();
    uint px0 = back[0];
    printLine("[virtio-gpu] R2.3b: BACKING/ATTACH/SUBMIT/TRANSFER resp + pixels[0,1,256,1023]:");
    printHex(d1);
    printHex(a1);
    printHex(e1);
    printHex(f1);
    printHex(back[0]);
    printHex(back[1]);
    printHex(back[256]);
    printHex(back[1023]);
    if (px0 == 0xFFFF0000u)
        printLine("[virtio-gpu] R2.3b: GPU CLEARED the resource RED -- virgl 3D rendering WORKS");
    else
        printLine("[virtio-gpu] R2.3b: readback did not match the clear colour");

    gpuBlobSelfTest();   // B4: verify the host-visible blob create/map round-trip (no-op if !g_gpuBlob)
}

// ==========================================================================
// B4 — host-visible blob transport (RESOURCE_CREATE_BLOB / MAP_BLOB / UNMAP_BLOB).
// A HOST3D + USE_MAPPABLE blob wraps a host virgl resource (created by a
// PIPE_RESOURCE_CREATE cmd keyed on blob_id) and is mapped into the host-visible
// SHM BAR window, so the guest CPU and the compositor address the SAME host
// storage — the zero-copy cross-process share the classic-resource alias couldn't do.
// ==========================================================================
__gshared ulong g_gpuShmNext = 0;   // B4: bump allocator over [0, g_gpuShmLen) for window offsets

// Page-aligned offset in the host-visible window; ~0 = exhausted.
ulong gpuBlobAllocOffset(ulong size) @nogc nothrow {
    ulong aligned = (size + 0xFFF) & ~cast(ulong)0xFFF;
    if (g_gpuShmNext + aligned > g_gpuShmLen) return ~cast(ulong)0;
    ulong off = g_gpuShmNext;
    g_gpuShmNext += aligned;
    return off;
}

// Create a host-visible HOST3D blob: SUBMIT the PIPE_RESOURCE_CREATE cmd (correlating blob_id -> the
// host pipe_resource) on ctx 1 FIRST, then RESOURCE_CREATE_BLOB.  Returns 0 on success.
export int gpuCreateBlob(uint resId, ulong blobId, ulong size, const(ubyte)* cmd, uint cmdLen) @nogc nothrow {
    if (!g_gpu3dReady) return -1;
    if (cmdLen != 0 && gpuDrmSubmit3D(cmd, cmdLen) != 0) return -1;
    gpuZeroReq(56);
    gpuPutU(0, 0x010C);              // VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB
    gpuPutU(16, 1);                  // hdr.ctx_id = 1
    gpuPutU(24, resId);              // resource_id
    gpuPutU(28, 0x2);                // blob_mem  = VIRTIO_GPU_BLOB_MEM_HOST3D
    gpuPutU(32, 0x1);                // blob_flags = VIRTIO_GPU_BLOB_FLAG_USE_MAPPABLE
    gpuPutU(36, 0);                  // nr_entries (HOST3D: no guest mem_entries)
    gpuPutQ(40, blobId);             // blob_id
    gpuPutQ(48, size);               // size
    return (gpuCtrl(56, 24) == 0x1100) ? 0 : -1;   // VIRTIO_GPU_RESP_OK_NODATA
}

// Map a blob into the host-visible window at winOffset (guest-chosen).  Returns map_info cache mode
// (1=CACHED, 3=WC) on success, ~0 on failure.
export uint gpuMapBlob(uint resId, ulong winOffset) @nogc nothrow {
    gpuZeroReq(40);
    gpuPutU(0, 0x0208);              // VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB
    gpuPutU(16, 1);                  // hdr.ctx_id = 1
    gpuPutU(24, resId);              // resource_id
    gpuPutQ(32, winOffset);          // offset into the host-visible window
    if (gpuCtrl(40, 32) != 0x1106) return ~0u;     // VIRTIO_GPU_RESP_OK_MAP_INFO
    return *cast(uint*)(g_gpuBuf + 2048 + 24);      // resp_map_info.map_info at resp+24
}

// Unmap a blob from the host-visible window (lifecycle / B8).
export int gpuUnmapBlob(uint resId) @nogc nothrow {
    gpuZeroReq(32);
    gpuPutU(0, 0x0209);              // VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB
    gpuPutU(16, 1);
    gpuPutU(24, resId);
    return (gpuCtrl(32, 24) == 0x1100) ? 0 : -1;
}

// B4 self-test: a small linear (PIPE_BUFFER) mappable HOST3D blob -> map into the window -> CPU
// write/read round-trip.  Runs once at boot when the device exposes host-visible blobs.
export void gpuBlobSelfTest() @nogc nothrow {
    if (!g_gpuBlob || g_gpuShmBase == 0) { printLine("[virtio-gpu] B4: blob self-test skipped (no blob window)"); return; }
    enum uint  RES = 0xB10B;
    enum ulong BID = 0xB10B0001;
    enum ulong SZ  = 0x1000;        // one page
    uint[12] cmd;
    cmd[0]  = 0x000B0030;           // VIRGL_CMD0(PIPE_RESOURCE_CREATE=48, obj 0, len 11)
    cmd[1]  = 0;                    // target = PIPE_BUFFER (linear, host-mappable)
    cmd[2]  = 64;                   // format = VIRGL_FORMAT_R8_UNORM
    cmd[3]  = 0;                   // bind = 0 -> GL_ARRAY_BUFFER (real host buffer; CUSTOM = guest-only)
    cmd[4]  = cast(uint)SZ;        // width  = byte size
    cmd[5]  = 1;                   // height
    cmd[6]  = 1;                   // depth
    cmd[7]  = 1;                   // array_size
    cmd[8]  = 0;                   // last_level
    cmd[9]  = 0;                   // nr_samples
    cmd[10] = (1 << 1) | (1 << 2); // flags = VIRGL_RESOURCE_FLAG_MAP_PERSISTENT|COHERENT (host-visible)
    cmd[11] = cast(uint)BID;       // blob_id
    if (gpuCreateBlob(RES, BID, SZ, cast(const(ubyte)*)cmd.ptr, 48) != 0) {
        printLine("[virtio-gpu] B4: CREATE_BLOB FAILED"); return;
    }
    ulong off = gpuBlobAllocOffset(SZ);
    if (off == ~cast(ulong)0) { printLine("[virtio-gpu] B4: window offset alloc FAILED"); return; }
    uint mi = gpuMapBlob(RES, off);
    if (mi == ~0u) { printLine("[virtio-gpu] B4: MAP_BLOB FAILED"); return; }
    printLine("[virtio-gpu] B4: MAP_BLOB ok (map_info / window-offset):");
    printUnsigned(mi); printHex(off);
    uint* p = cast(uint*)(g_gpuShmBase + off);
    p[0] = 0xDEADBEEFu; p[1] = 0xCAFEF00Du;
    memBarrier();
    if (p[0] == 0xDEADBEEFu && p[1] == 0xCAFEF00Du)
        printLine("[virtio-gpu] B4: host-visible window CPU write/read round-trip PASS");
    else
        printLine("[virtio-gpu] B4: window round-trip FAIL (read-back mismatch)");
}

// ==========================================================================
// R2.4 — DRM render-node serving primitives.  These expose the modern virgl
// transport (the same path the R2.3b self-test proved) to the kernel's
// /dev/dri/renderD128 ioctl handler so userspace can drive the GPU.  All run on
// virgl context 1 (created by virtioGpuDetectVirgl); DRM resource ids start at
// 16 to avoid the self-test's resource 1.  Single-threaded: the control queue +
// g_gpuBuf are shared, so callers must be serialized (the ioctl path is).
// ==========================================================================
__gshared uint g_drmNextRes = 16;

export bool gpuDrm3dReady() @nogc nothrow { return g_gpu3dReady; }

// Create a 3D resource on the host; returns its resource id (0 = fail).
export uint gpuDrmCreateResource3D(uint target, uint format, uint bind,
                                   uint width, uint height, uint depth,
                                   uint arraySize) @nogc nothrow {
    if (!g_gpu3dReady) return 0;
    uint rid = g_drmNextRes++;
    gpuZeroReq(72);
    gpuPutU(0, 0x0204);          // VIRTIO_GPU_CMD_RESOURCE_CREATE_3D
    gpuPutU(24, rid);
    gpuPutU(28, target);         // PIPE_TEXTURE_2D=2
    gpuPutU(32, format);         // B8G8R8A8_UNORM=1
    gpuPutU(36, bind);           // RENDER_TARGET=2 | SAMPLER_VIEW=8
    gpuPutU(40, width);
    gpuPutU(44, height);
    gpuPutU(48, depth ? depth : 1);
    gpuPutU(52, arraySize ? arraySize : 1);
    return (gpuCtrl(72, 24) == 0x1100) ? rid : 0;
}

// Attach a guest backing page to a resource (sets res->iov on the host).
export int gpuDrmAttachBacking(uint resId, ulong phys, uint len) @nogc nothrow {
    gpuZeroReq(48);
    gpuPutU(0, 0x0106);          // VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING
    gpuPutU(24, resId);
    gpuPutU(28, 1);              // nr_entries
    gpuPutQ(32, phys);           // mem_entry.addr
    gpuPutU(40, len);            // mem_entry.length
    return (gpuCtrl(48, 24) == 0x1100) ? 0 : -1;
}

// Bind a resource into virgl context 1's res_hash (required before SUBMIT/transfer).
export int gpuDrmCtxAttach(uint resId) @nogc nothrow {
    gpuZeroReq(32);
    gpuPutU(0, 0x0202);          // VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE
    gpuPutU(16, 1);              // ctx_id = 1
    gpuPutU(24, resId);
    return (gpuCtrl(32, 24) == 0x1100) ? 0 : -1;
}

// Dedicated DMA buffer for SUBMIT_3D command streams — Mesa's virgl command buffers are multi-KB,
// far larger than the shared control buffer.  Allocated lazily on the first submit.
__gshared ulong  g_gpuSubmitPhys = 0;
__gshared ubyte* g_gpuSubmitBuf  = null;
enum uint GPU_SUBMIT_MAX = 16 * 4096;   // 64 KiB

// Issue a chained control command: header in g_gpuBuf[0..hdrLen) + a separate payload descriptor at
// payloadPhys[0..payloadLen) -> response at g_gpuBuf[2048..].  Returns the response type
// (0xFFFFFFFF on timeout).  Lets a SUBMIT_3D stream exceed the small control buffer.
private uint gpuCtrlChained(uint hdrLen, ulong payloadPhys, uint payloadLen, uint respLen) @nogc nothrow {
    if (g_gpuCtrlBusy) return 0xFFFFFFFFu;   // R3: serialize the shared control queue (see gpuCtrl)
    g_gpuCtrlBusy = true; scope(exit) g_gpuCtrlBusy = false;
    auto desc = g_gpuDesc; auto avail = g_gpuAvail; auto used = g_gpuUsed;
    foreach (i; 0 .. respLen) g_gpuBuf[2048 + i] = 0;
    desc[0].addr = g_gpuBufPhys;        desc[0].len = hdrLen;     desc[0].flags = VIRTQ_DESC_F_NEXT;  desc[0].next = 1;
    desc[1].addr = payloadPhys;         desc[1].len = payloadLen; desc[1].flags = VIRTQ_DESC_F_NEXT;  desc[1].next = 2;
    desc[2].addr = g_gpuBufPhys + 2048; desc[2].len = respLen;    desc[2].flags = VIRTQ_DESC_F_WRITE; desc[2].next = 0;
    ushort ai = volLoadW(&avail.idx);
    avail.ring[ai % g_gpuQsz] = 0;
    volStoreW(&avail.idx, cast(ushort)(ai + 1));
    memBarrier();
    volStoreW(cast(ushort*)g_gpuNotifyAddr, 0);
    int spin = 0;
    while (volLoadW(&used.idx) == g_gpuLastUsed && spin < 50_000_000) spin++;
    if (volLoadW(&used.idx) == g_gpuLastUsed) return 0xFFFFFFFFu;
    g_gpuLastUsed = volLoadW(&used.idx);
    memBarrier();
    return *cast(uint*)(g_gpuBuf + 2048);
}

// Submit a virgl command stream of any size (up to 64 KiB) to context 1.  The SUBMIT_3D header rides
// the control buffer; the stream rides a dedicated DMA buffer chained after it.
export int gpuDrmSubmit3D(const(ubyte)* stream, uint streamLen) @nogc nothrow {
    if (streamLen == 0 || streamLen > GPU_SUBMIT_MAX) return -1;
    if (g_gpuSubmitBuf is null) {
        import memory.mm : alloc_phys_pages;
        import core.globals : hhdm_offset;
        g_gpuSubmitPhys = alloc_phys_pages(GPU_SUBMIT_MAX / 4096);
        if (g_gpuSubmitPhys == 0) return -1;
        g_gpuSubmitBuf = cast(ubyte*)(g_gpuSubmitPhys + hhdm_offset);
    }
    gpuZeroReq(32);
    gpuPutU(0, 0x0207);          // VIRTIO_GPU_CMD_SUBMIT_3D
    gpuPutU(4, 1);               // hdr.flags = VIRTIO_GPU_FLAG_FENCE
    gpuPutQ(8, nextFence());     // hdr.fence_id (B3: monotonic)
    gpuPutU(16, 1);              // hdr.ctx_id = 1
    gpuPutU(24, streamLen);      // command-stream size in bytes
    foreach (i; 0 .. streamLen) g_gpuSubmitBuf[i] = stream[i];
    return (gpuCtrlChained(32, g_gpuSubmitPhys, streamLen, 24) == 0x1100) ? 0 : -1;
}

// Read a host resource's pixels back into its attached guest backing.
export int gpuDrmTransferFromHost(uint resId, uint x, uint y, uint z,
                                  uint w, uint h, uint d, uint level,
                                  uint offset, uint stride, uint layerStride) @nogc nothrow {
    gpuZeroReq(72);
    gpuPutU(0, 0x0206);          // VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D
    gpuPutU(4, 1); gpuPutQ(8, nextFence()); gpuPutU(16, 1);   // FENCE, fence_id (B3), ctx 1
    gpuPutU(24, x); gpuPutU(28, y); gpuPutU(32, z);
    gpuPutU(36, w); gpuPutU(40, h); gpuPutU(44, d);
    gpuPutQ(48, cast(ulong)offset);
    gpuPutU(56, resId); gpuPutU(60, level); gpuPutU(64, stride); gpuPutU(68, layerStride);
    return (gpuCtrl(72, 24) == 0x1100) ? 0 : -1;
}

// Upload guest backing -> host resource (Mesa texture/buffer uploads).
export int gpuDrmTransferToHost(uint resId, uint x, uint y, uint z,
                                uint w, uint h, uint d, uint level,
                                uint offset, uint stride, uint layerStride) @nogc nothrow {
    gpuZeroReq(72);
    gpuPutU(0, 0x0205);          // VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D
    gpuPutU(4, 1); gpuPutQ(8, nextFence()); gpuPutU(16, 1);   // FENCE, fence_id (B3), ctx 1
    gpuPutU(24, x); gpuPutU(28, y); gpuPutU(32, z);
    gpuPutU(36, w); gpuPutU(40, h); gpuPutU(44, d);
    gpuPutQ(48, cast(ulong)offset);
    gpuPutU(56, resId); gpuPutU(60, level); gpuPutU(64, stride); gpuPutU(68, layerStride);
    return (gpuCtrl(72, 24) == 0x1100) ? 0 : -1;
}

// Fetch a host virgl capset blob (GET_CAPSET) into outBuf; returns bytes copied (0 = fail).
// Mesa's virgl winsys parses this to learn the GL feature set / limits.
export uint gpuDrmGetCapset(uint capsetId, uint capsetVer, ubyte* outBuf, uint maxLen) @nogc nothrow {
    if (!g_gpu3dReady || outBuf is null) return 0;
    if (maxLen > 1900) maxLen = 1900;          // response area headroom (g_gpuBuf is one page; resp @+2048)
    gpuZeroReq(32);
    gpuPutU(0, 0x0109);          // VIRTIO_GPU_CMD_GET_CAPSET
    gpuPutU(24, capsetId);
    gpuPutU(28, capsetVer);
    if (gpuCtrl(32, 24 + maxLen) != 0x1103) return 0;   // VIRTIO_GPU_RESP_OK_CAPSET
    foreach (i; 0 .. maxLen) outBuf[i] = g_gpuBuf[2048 + 24 + i];  // capset data follows the resp hdr
    return maxLen;
}

// Tear down a resource on the host: detach its guest backing, then unref it.  After this the guest
// backing page is safe to free (the host no longer references the iov).
export int gpuDrmResourceUnref(uint resId) @nogc nothrow {
    gpuZeroReq(32);
    gpuPutU(0, 0x0107);          // VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING
    gpuPutU(24, resId);
    gpuCtrl(32, 24);
    gpuZeroReq(32);
    gpuPutU(0, 0x0102);          // VIRTIO_GPU_CMD_RESOURCE_UNREF
    gpuPutU(24, resId);
    return (gpuCtrl(32, 24) == 0x1100) ? 0 : -1;
}

export void virtioGpuInit() @nogc nothrow {
    printLine("[virtio-gpu] Probing...");
    
    // Find device
    // We need to scan for it manually or use a helper if available.
    // pciFindDevice is not in pci.d, we must implement a search or use scanPCIDevices.
    
    import drivers.pci : scanPCIDevices, pciConfigRead32;
    auto devices = scanPCIDevices();
    PCIDevice* pci = null;
    
    foreach (ref dev; devices) {
        if (dev.vendorId == VIRTIO_VENDOR_ID && dev.deviceId == VIRTIO_DEV_GPU) {
            pci = &dev;
            break;
        }
    }
    
    if (pci is null) {
        printLine("[virtio-gpu] Device not found");
        return;
    }
    
    printLine("[virtio-gpu] Found device!");
    g_gpuDev.pciDev = pci;
    
    // Read BAR0 (Offset 0x10)
    uint bar0 = pciConfigRead32(pci.bus, pci.slot, pci.func, 0x10);
    g_gpuDev.ioBase = bar0 & ~3; // IO Space (mask out type bits)
    
    // Reset
    virtioReset(&g_gpuDev);
    virtioSetStatus(&g_gpuDev, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    // Setup Queue 0 (Control)
    outportw(cast(ushort)(g_gpuDev.ioBase + 14), 0); // Select Queue 0
    
    // Setup Ring (Physical Addresses)
    // In a real OS we'd use virtual-to-physical translation.
    // Here we assume identity mapping or low memory.
    ulong descAddr = cast(ulong)&g_desc;
    ulong availAddr = cast(ulong)&g_avail;
    ulong usedAddr = cast(ulong)&g_used;
    
    outportl(cast(ushort)(g_gpuDev.ioBase + 8), cast(uint)(descAddr >> 12)); // PFN
    // Note: Legacy VirtIO setup is a bit more complex with alignment, 
    // but for QEMU simplified setup often works if aligned.
    // We'll skip complex setup for this "shim-replacement" step and assume it works 
    // or we'd need a full VirtIO implementation.
    
    g_gpuDev.desc = g_desc.ptr;
    g_gpuDev.avail = &g_avail;
    g_gpuDev.used = &g_used;
    
    // Initialize last used index
    g_gpuDev.lastUsedIdx = g_gpuDev.used.idx;
    
    virtioSetStatus(&g_gpuDev, VIRTIO_STATUS_DRIVER_OK);
    g_gpuAvailable = true;
    printLine("[virtio-gpu] Initialized");
}

export uint virtioGpuCreateResource(uint width, uint height) @nogc nothrow {
    if (!g_gpuAvailable) return 0;
    
    uint rid = g_resourceIdCounter++;
    
    // 1. Create 2D Resource
    VirtioGpuResourceCreate2D cmd;
    cmd.hdr.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;
    cmd.resourceId = rid;
    cmd.format = VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM;
    cmd.width = width;
    cmd.height = height;
    
    sendCmd(&cmd, cmd.sizeof);
    
    // 2. Attach Backing to Framebuffer
    import display.framebuffer : g_fb;
    if (g_fb.addr !is null) {
        virtioGpuAttachBacking(rid, cast(ulong)g_fb.addr, g_fb.height * g_fb.pitch);
    }
    
    // 3. Set Scanout (tell GPU to display this resource)
    virtioGpuSetScanout(0, rid, width, height);
    
    return rid;
}

export void virtioGpuTransfer(uint rid, uint x, uint y, uint w, uint h, ulong offset) @nogc nothrow {
    if (!g_gpuAvailable) return;
    
    VirtioGpuTransferToHost2D cmd;
    cmd.hdr.type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D;
    cmd.resourceId = rid;
    cmd.r.x = x;
    cmd.r.y = y;
    cmd.r.width = w;
    cmd.r.height = h;
    cmd.offset = offset;
    
    sendCmd(&cmd, cmd.sizeof);
}

export void virtioGpuFlush(uint rid, uint x, uint y, uint w, uint h) @nogc nothrow {
    if (!g_gpuAvailable) return;
    
    VirtioGpuResourceFlush cmd;
    cmd.hdr.type = VIRTIO_GPU_CMD_RESOURCE_FLUSH;
    cmd.resourceId = rid;
    cmd.r.x = x;
    cmd.r.y = y;
    cmd.r.width = w;
    cmd.r.height = h;
    
    sendCmd(&cmd, cmd.sizeof);
}

export void virtioGpuAttachBacking(uint rid, ulong addr, uint length) @nogc nothrow {
    if (!g_gpuAvailable) return;
    
    VirtioGpuResourceAttachBacking cmd;
    cmd.hdr.type = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING;
    cmd.resourceId = rid;
    cmd.nrEntries = 1;
    
    VirtioGpuMemEntry entry;
    entry.addr = addr;
    entry.length = length;
    entry.padding = 0;
    
    // Send both command and entry
    // For simplicity, we'll send them as separate descriptors
    sendCmdWithData(&cmd, cmd.sizeof, &entry, entry.sizeof);
}

export void virtioGpuSetScanout(uint scanoutId, uint rid, uint width, uint height) @nogc nothrow {
    if (!g_gpuAvailable) return;
    
    VirtioGpuSetScanout cmd;
    cmd.hdr.type = VIRTIO_GPU_CMD_SET_SCANOUT;
    cmd.scanoutId = scanoutId;
    cmd.resourceId = rid;
    cmd.r.x = 0;
    cmd.r.y = 0;
    cmd.r.width = width;
    cmd.r.height = height;
    
    sendCmd(&cmd, cmd.sizeof);
}

export void virtioGpuUpdateCursor(uint rid, uint x, uint y, uint hotX, uint hotY) @nogc nothrow {
    if (!g_gpuAvailable) return;
    // Stub
}

// Internal: Send command to queue
private void sendCmd(void* cmd, uint len) @nogc nothrow {
    // 1. Allocate descriptor
    ushort idx = g_nextDescIdx;
    g_nextDescIdx = cast(ushort)((g_nextDescIdx + 1) % 256);
    
    g_gpuDev.desc[idx].addr = cast(ulong)cmd;
    g_gpuDev.desc[idx].len = len;
    g_gpuDev.desc[idx].flags = 0; // No next
    g_gpuDev.desc[idx].next = 0;
    
    // 2. Put in avail ring
    ushort availIdx = cast(ushort)(g_gpuDev.avail.idx % 256);
    g_gpuDev.avail.ring[availIdx] = idx;
    g_gpuDev.avail.idx++;
    
    // 3. Notify
    outportw(cast(ushort)(g_gpuDev.ioBase + 16), 0); // Notify Queue 0
    
    // 4. Wait for completion
    while (volatileLoadUshort(&g_gpuDev.used.idx) == g_gpuDev.lastUsedIdx) {
        // Busy wait
    }
    g_gpuDev.lastUsedIdx++;
}

// Send command with additional data buffer
private void sendCmdWithData(void* cmd, uint cmdLen, void* data, uint dataLen) @nogc nothrow {
    // 1. Allocate two descriptors
    ushort idx1 = g_nextDescIdx;
    g_nextDescIdx = cast(ushort)((g_nextDescIdx + 1) % 256);
    ushort idx2 = g_nextDescIdx;
    g_nextDescIdx = cast(ushort)((g_nextDescIdx + 1) % 256);
    
    // First descriptor: command
    g_gpuDev.desc[idx1].addr = cast(ulong)cmd;
    g_gpuDev.desc[idx1].len = cmdLen;
    g_gpuDev.desc[idx1].flags = VIRTQ_DESC_F_NEXT;
    g_gpuDev.desc[idx1].next = idx2;
    
    // Second descriptor: data
    g_gpuDev.desc[idx2].addr = cast(ulong)data;
    g_gpuDev.desc[idx2].len = dataLen;
    g_gpuDev.desc[idx2].flags = 0;
    g_gpuDev.desc[idx2].next = 0;
    
    // 2. Put in avail ring (only the first descriptor)
    ushort availIdx = cast(ushort)(g_gpuDev.avail.idx % 256);
    g_gpuDev.avail.ring[availIdx] = idx1;
    g_gpuDev.avail.idx++;
    
    // 3. Notify
    outportw(cast(ushort)(g_gpuDev.ioBase + 16), 0);
    
    // 4. Wait for completion
    while (volatileLoadUshort(&g_gpuDev.used.idx) == g_gpuDev.lastUsedIdx) {
        // Busy wait
    }
    g_gpuDev.lastUsedIdx++;
}

private ushort volatileLoadUshort(ushort* ptr) @nogc nothrow {
    // Force read from memory using shared cast (volatile in D)
    return *cast(shared const ushort*)ptr;
}
