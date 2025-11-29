module anonymos.drivers.virtio;

import anonymos.drivers.pci;
import anonymos.kernel.memory;
import anonymos.console : printLine, printHex;

// --------------------------------------------------------------------------
// VirtIO Constants & Types
// --------------------------------------------------------------------------

extern(C):

enum VIRTIO_VENDOR_ID = 0x1AF4;

// Device IDs (Legacy / Modern)
enum VIRTIO_DEV_NET = 0x1000;
enum VIRTIO_DEV_BLOCK = 0x1001;
enum VIRTIO_DEV_GPU = 0x1050; // Modern GPU

// Status Bits
enum VIRTIO_STATUS_ACKNOWLEDGE = 1;
enum VIRTIO_STATUS_DRIVER      = 2;
enum VIRTIO_STATUS_DRIVER_OK   = 4;
enum VIRTIO_STATUS_FEATURES_OK = 8;
enum VIRTIO_STATUS_FAILED      = 128;

// Queue Descriptors
struct VirtqDesc {
    ulong addr;
    uint len;
    ushort flags;
    ushort next;
}

enum VIRTQ_DESC_F_NEXT = 1;
enum VIRTQ_DESC_F_WRITE = 2;

struct VirtqAvail {
    ushort flags;
    ushort idx;
    ushort[256] ring; // Fixed size for simplicity
}

struct VirtqUsedElem {
    uint id;
    uint len;
}

struct VirtqUsed {
    ushort flags;
    ushort idx;
    VirtqUsedElem[256] ring;
}

// Device Abstraction
struct VirtioDevice {
    PCIDevice* pciDev;
    uint ioBase;
    ubyte* mmioBase;
    
    // Queue State
    uint queueNum;
    VirtqDesc* desc;
    VirtqAvail* avail;
    VirtqUsed* used;
    ushort lastUsedIdx;
}

// --------------------------------------------------------------------------
// VirtIO Core Functions
// --------------------------------------------------------------------------

void virtioReset(VirtioDevice* dev) @nogc nothrow {
    // Legacy PIO reset
    import anonymos.drivers.io;
    outportb(cast(ushort)(dev.ioBase + 18), 0);
}

void virtioSetStatus(VirtioDevice* dev, ubyte status) @nogc nothrow {
    import anonymos.drivers.io;
    ubyte cur = inportb(cast(ushort)(dev.ioBase + 18));
    outportb(cast(ushort)(dev.ioBase + 18), cur | status);
}

void virtioSetupQueue(VirtioDevice* dev, uint queueIndex) @nogc nothrow {
    import anonymos.drivers.io;
    
    // Select queue
    outportw(cast(ushort)(dev.ioBase + 14), cast(ushort)queueIndex);
    
    // Get size
    // uint size = inportw(dev.ioBase + 16);
    
    // Allocate memory (Simplified: static allocation or simple heap)
    // For this environment, we assume we have a simple allocator or use static buffers for now.
    // In a real driver, we'd allocate pages.
    
    // TODO: Implement proper allocation. For now, we rely on the specific driver to set pointers.
}
