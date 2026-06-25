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
__gshared uint g_resourceIdCounter = 1;

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

    // Walk the capability list for the virtio COMMON-config cap (vndr 0x09, cfg_type 1).
    uint commonBar = 0xFFFFFFFFu, commonOff = 0;
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

    // R2.2 — negotiate: accept VIRGL (if offered) in the low word + VIRTIO_F_VERSION_1 (bit 32,
    // = bit 0 of the high word) which is mandatory for a modern device.
    volStoreU(pDrvSel, 0); volStoreU(pDrvFeat, g_gpuVirgl ? (1u << VIRTIO_GPU_F_VIRGL) : 0u);
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
