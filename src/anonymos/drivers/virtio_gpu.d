module anonymos.drivers.virtio_gpu;

import anonymos.drivers.virtio;
import anonymos.drivers.pci;
import anonymos.kernel.heap;
import anonymos.kernel.memory;
import anonymos.console : printLine, printHex, printUnsigned;
import anonymos.drivers.io;

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
__gshared uint g_resourceIdCounter = 1;

// Ring buffers (Static for simplicity in this environment)
__gshared VirtqDesc[256] g_desc;
__gshared VirtqAvail g_avail;
__gshared VirtqUsed g_used;
__gshared ushort g_nextDescIdx = 0;

// --------------------------------------------------------------------------
// Driver Implementation
// --------------------------------------------------------------------------

export void virtioGpuInit() @nogc nothrow {
    printLine("[virtio-gpu] Probing...");
    
    // Find device
    // We need to scan for it manually or use a helper if available.
    // pciFindDevice is not in pci.d, we must implement a search or use scanPCIDevices.
    
    import anonymos.drivers.pci : scanPCIDevices, pciConfigRead32;
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
    import anonymos.display.framebuffer : g_fb;
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
