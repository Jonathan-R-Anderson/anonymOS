module anonymos.drivers.network;

import anonymos.console : printLine, print;
import anonymos.drivers.pci : PCIDevice, scanPCIDevices;

/// Network device types
enum NetworkDeviceType {
    Unknown,
    E1000,      // Intel E1000 (QEMU default)
    RTL8139,    // Realtek RTL8139
    VirtIO,     // VirtIO network
}

/// Network device state
struct NetworkDevice {
    NetworkDeviceType type;
    PCIDevice* pciDev;
    ubyte[6] macAddress;
    bool initialized;
    ulong ioBase;
    ulong memBase;
    uint irq;
}

export __gshared NetworkDevice g_netDevice;
private __gshared bool g_networkAvailable = false;

/// Initialize network driver
export extern(C) void initNetwork() @nogc nothrow {
    printLine("[network] Scanning for network devices...");
    
    // Scan PCI for network devices
    auto devices = scanPCIDevices();
    
    foreach (ref dev; devices) {
        // Intel E1000 (0x8086 = Intel, 0x100E = E1000)
        if (dev.vendorId == 0x8086 && dev.deviceId == 0x100E) {
            printLine("[network] Found Intel E1000 network adapter");
            g_netDevice.type = NetworkDeviceType.E1000;
            g_netDevice.pciDev = &dev;
            initE1000(&g_netDevice);
            g_networkAvailable = true;
            return;
        }
        
        // Realtek RTL8139 (0x10EC = Realtek, 0x8139 = RTL8139)
        if (dev.vendorId == 0x10EC && dev.deviceId == 0x8139) {
            printLine("[network] Found Realtek RTL8139 network adapter");
            g_netDevice.type = NetworkDeviceType.RTL8139;
            g_netDevice.pciDev = &dev;
            initRTL8139(&g_netDevice);
            g_networkAvailable = true;
            return;
        }
        
        // VirtIO Network (0x1AF4 = Red Hat, 0x1000 = VirtIO net)
        if (dev.vendorId == 0x1AF4 && dev.deviceId == 0x1000) {
            printLine("[network] Found VirtIO network adapter");
            g_netDevice.type = NetworkDeviceType.VirtIO;
            g_netDevice.pciDev = &dev;
            initVirtIO(&g_netDevice);
            g_networkAvailable = true;
            return;
        }
    }
    
    printLine("[network] No supported network device found");
}

/// Check if network is available
export extern(C) bool isNetworkAvailable() @nogc nothrow {
    return g_networkAvailable;
}

/// Get MAC address
export extern(C) void getMacAddress(ubyte* outMac) @nogc nothrow {
    if (outMac is null) return;
    for (int i = 0; i < 6; i++) {
        outMac[i] = g_netDevice.macAddress[i];
    }
}

/// Send raw Ethernet frame
export extern(C) bool sendEthFrame(const(ubyte)* data, size_t len) @nogc nothrow {
    if (!g_networkAvailable || data is null || len == 0) return false;
    
    switch (g_netDevice.type) {
        case NetworkDeviceType.E1000:
            return e1000Send(data, len);
        case NetworkDeviceType.RTL8139:
            return rtl8139Send(data, len);
        case NetworkDeviceType.VirtIO:
            return virtioSend(data, len);
        default:
            return false;
    }
}

/// Receive raw Ethernet frame
export extern(C) int receiveEthFrame(ubyte* buffer, size_t maxLen) @nogc nothrow {
    if (!g_networkAvailable || buffer is null || maxLen == 0) return -1;
    
    switch (g_netDevice.type) {
        case NetworkDeviceType.E1000:
            return e1000Receive(buffer, maxLen);
        case NetworkDeviceType.RTL8139:
            return rtl8139Receive(buffer, maxLen);
        case NetworkDeviceType.VirtIO:
            return virtioReceive(buffer, maxLen);
        default:
            return -1;
    }
}

// ============================================================================
// Intel E1000 Driver
// ============================================================================

// E1000 Register Offsets
private enum E1000Reg : uint {
    CTRL    = 0x0000,  // Device Control
    STATUS  = 0x0008,  // Device Status
    EECD    = 0x0010,  // EEPROM Control
    EERD    = 0x0014,  // EEPROM Read
    CTRL_EXT = 0x0018, // Extended Control
    MDIC    = 0x0020,  // MDI Control
    ICR     = 0x00C0,  // Interrupt Cause Read
    IMS     = 0x00D0,  // Interrupt Mask Set
    RCTL    = 0x0100,  // Receive Control
    TCTL    = 0x0400,  // Transmit Control
    RDBAL   = 0x2800,  // RX Descriptor Base Low
    RDBAH   = 0x2804,  // RX Descriptor Base High
    RDLEN   = 0x2808,  // RX Descriptor Length
    RDH     = 0x2810,  // RX Descriptor Head
    RDT     = 0x2818,  // RX Descriptor Tail
    TDBAL   = 0x3800,  // TX Descriptor Base Low
    TDBAH   = 0x3804,  // TX Descriptor Base High
    TDLEN   = 0x3808,  // TX Descriptor Length
    TDH     = 0x3810,  // TX Descriptor Head
    TDT     = 0x3818,  // TX Descriptor Tail
    RAL     = 0x5400,  // Receive Address Low
    RAH     = 0x5404,  // Receive Address High
}

// E1000 Descriptor
struct E1000RxDesc {
    ulong addr;
    ushort length;
    ushort checksum;
    ubyte status;
    ubyte errors;
    ushort special;
}

struct E1000TxDesc {
    ulong addr;
    ushort length;
    ubyte cso;
    ubyte cmd;
    ubyte status;
    ubyte css;
    ushort special;
}

// Descriptor counts
private enum NUM_RX_DESC = 32;
private enum NUM_TX_DESC = 8;
private enum RX_BUFFER_SIZE = 2048;

// Descriptor rings (static allocation for simplicity)
private __gshared E1000RxDesc[NUM_RX_DESC] g_rxDescriptors;
private __gshared E1000TxDesc[NUM_TX_DESC] g_txDescriptors;
private __gshared ubyte[NUM_RX_DESC * RX_BUFFER_SIZE] g_rxBuffers;
private __gshared ubyte[NUM_TX_DESC * RX_BUFFER_SIZE] g_txBuffers;
private __gshared uint g_rxCurrent = 0;
private __gshared uint g_txCurrent = 0;

private void initE1000(NetworkDevice* dev) @nogc nothrow {
    printLine("[e1000] Initializing Intel E1000...");
    
    // Read BAR0 for memory-mapped I/O
    dev.memBase = readPCIBar(dev.pciDev, 0);
    
    // Enable bus mastering
    enablePCIBusMastering(dev.pciDev);
    
    // Reset device
    writeE1000Reg(dev, E1000Reg.CTRL, 0x04000000 | readE1000Reg(dev, E1000Reg.CTRL));
    
    // Wait for reset
    for (uint i = 0; i < 1000000; i++) {
        asm @nogc nothrow { nop; }
    }
    
    // Read MAC address from EEPROM
    readE1000Mac(dev);
    
    // Initialize receive/transmit rings
    initE1000Rings(dev);
    
    // Enable interrupts (optional, we'll poll)
    writeE1000Reg(dev, E1000Reg.IMS, 0x1F6DC);
    writeE1000Reg(dev, E1000Reg.ICR, 0xFFFFFFFF);
    
    dev.initialized = true;
    printLine("[e1000] Initialization complete");
}

private void readE1000Mac(NetworkDevice* dev) @nogc nothrow {
    // Read MAC from EEPROM (simplified)
    uint macLow = readE1000Reg(dev, E1000Reg.RAL);
    uint macHigh = readE1000Reg(dev, E1000Reg.RAH);
    
    dev.macAddress[0] = cast(ubyte)(macLow & 0xFF);
    dev.macAddress[1] = cast(ubyte)((macLow >> 8) & 0xFF);
    dev.macAddress[2] = cast(ubyte)((macLow >> 16) & 0xFF);
    dev.macAddress[3] = cast(ubyte)((macLow >> 24) & 0xFF);
    dev.macAddress[4] = cast(ubyte)(macHigh & 0xFF);
    dev.macAddress[5] = cast(ubyte)((macHigh >> 8) & 0xFF);
    
    print("[e1000] MAC: ");
    for (int i = 0; i < 6; i++) {
        if (i > 0) print(":");
        // Print hex byte
        ubyte b = dev.macAddress[i];
        ubyte hi = (b >> 4) & 0xF;
        ubyte lo = b & 0xF;
        char[2] hex;
        hex[0] = cast(char)(hi < 10 ? '0' + hi : 'A' + hi - 10);
        hex[1] = cast(char)(lo < 10 ? '0' + lo : 'A' + lo - 10);
        print(hex[0..2]);
    }
    printLine("");
}

private void initE1000Rings(NetworkDevice* dev) @nogc nothrow {
    // Initialize RX descriptors
    for (uint i = 0; i < NUM_RX_DESC; i++) {
        g_rxDescriptors[i].addr = cast(ulong)&g_rxBuffers[i * RX_BUFFER_SIZE];
        g_rxDescriptors[i].status = 0;
    }
    
    // Set RX descriptor base
    ulong rxBase = cast(ulong)g_rxDescriptors.ptr;
    writeE1000Reg(dev, E1000Reg.RDBAL, cast(uint)(rxBase & 0xFFFFFFFF));
    writeE1000Reg(dev, E1000Reg.RDBAH, cast(uint)(rxBase >> 32));
    writeE1000Reg(dev, E1000Reg.RDLEN, NUM_RX_DESC * E1000RxDesc.sizeof);
    writeE1000Reg(dev, E1000Reg.RDH, 0);
    writeE1000Reg(dev, E1000Reg.RDT, NUM_RX_DESC - 1);
    
    // Initialize TX descriptors
    for (uint i = 0; i < NUM_TX_DESC; i++) {
        g_txDescriptors[i].addr = cast(ulong)&g_txBuffers[i * RX_BUFFER_SIZE];
        g_txDescriptors[i].status = 1; // DD bit set (descriptor done)
        g_txDescriptors[i].cmd = 0;
    }
    
    // Set TX descriptor base
    ulong txBase = cast(ulong)g_txDescriptors.ptr;
    writeE1000Reg(dev, E1000Reg.TDBAL, cast(uint)(txBase & 0xFFFFFFFF));
    writeE1000Reg(dev, E1000Reg.TDBAH, cast(uint)(txBase >> 32));
    writeE1000Reg(dev, E1000Reg.TDLEN, NUM_TX_DESC * E1000TxDesc.sizeof);
    writeE1000Reg(dev, E1000Reg.TDH, 0);
    writeE1000Reg(dev, E1000Reg.TDT, 0);
    
    // Enable receiver
    writeE1000Reg(dev, E1000Reg.RCTL, 
        (1 << 1) |  // EN - Enable
        (1 << 4) |  // MPE - Multicast Promiscuous
        (1 << 15) | // BAM - Broadcast Accept Mode
        (0 << 16) | // BSIZE - 2048 bytes
        (1 << 25) | // BSEX - Buffer Size Extension (for 2048)
        (1 << 26)   // SECRC - Strip Ethernet CRC
    );
    
    // Enable transmitter
    writeE1000Reg(dev, E1000Reg.TCTL,
        (1 << 1) |  // EN - Enable
        (1 << 3) |  // PSP - Pad Short Packets
        (15 << 4) | // CT - Collision Threshold
        (64 << 12)  // COLD - Collision Distance
    );
    
    g_rxCurrent = 0;
    g_txCurrent = 0;
}

private uint readE1000Reg(NetworkDevice* dev, uint offset) @nogc nothrow {
    uint* reg = cast(uint*)(dev.memBase + offset);
    uint val;
    // Volatile read using inline assembly
    asm @nogc nothrow {
        mov RDX, reg;
        mov EAX, [RDX];
        mov val, EAX;
    }
    return val;
}

private void writeE1000Reg(NetworkDevice* dev, uint offset, uint value) @nogc nothrow {
    uint* reg = cast(uint*)(dev.memBase + offset);
    // Volatile write using inline assembly
    asm @nogc nothrow {
        mov RDX, reg;
        mov EAX, value;
        mov [RDX], EAX;
    }
}

private bool e1000Send(const(ubyte)* data, size_t len) @nogc nothrow {
    if (data is null || len == 0 || len > RX_BUFFER_SIZE) return false;
    
    // Get current TX descriptor
    E1000TxDesc* desc = &g_txDescriptors[g_txCurrent];
    
    // Check if descriptor is available (DD bit set)
    if ((desc.status & 1) == 0) {
        return false; // Descriptor not ready
    }
    
    // Copy data to TX buffer
    ubyte* txBuf = &g_txBuffers[g_txCurrent * RX_BUFFER_SIZE];
    for (size_t i = 0; i < len; i++) {
        txBuf[i] = data[i];
    }
    
    // Setup descriptor
    desc.length = cast(ushort)len;
    desc.cmd = (1 << 0) | // EOP - End of Packet
               (1 << 1) | // IFCS - Insert FCS
               (1 << 3);  // RS - Report Status
    desc.status = 0; // Clear DD bit
    
    // Update tail pointer
    g_txCurrent = (g_txCurrent + 1) % NUM_TX_DESC;
    writeE1000Reg(&g_netDevice, E1000Reg.TDT, g_txCurrent);
    
    return true;
}

private int e1000Receive(ubyte* buffer, size_t maxLen) @nogc nothrow {
    if (buffer is null || maxLen == 0) return -1;
    
    // Get current RX descriptor
    E1000RxDesc* desc = &g_rxDescriptors[g_rxCurrent];
    
    // Check if descriptor has data (DD bit set)
    if ((desc.status & 1) == 0) {
        return 0; // No packet available
    }
    
    // Get packet length
    uint pktLen = desc.length;
    if (pktLen > maxLen) pktLen = cast(uint)maxLen;
    
    // Copy data from RX buffer
    ubyte* rxBuf = &g_rxBuffers[g_rxCurrent * RX_BUFFER_SIZE];
    for (uint i = 0; i < pktLen; i++) {
        buffer[i] = rxBuf[i];
    }
    
    // Reset descriptor
    desc.status = 0;
    
    // Update tail pointer
    uint oldCurrent = g_rxCurrent;
    g_rxCurrent = (g_rxCurrent + 1) % NUM_RX_DESC;
    writeE1000Reg(&g_netDevice, E1000Reg.RDT, oldCurrent);
    
    return cast(int)pktLen;
}

// ============================================================================
// RTL8139 Driver (stub)
// ============================================================================

private void initRTL8139(NetworkDevice* dev) @nogc nothrow {
    printLine("[rtl8139] RTL8139 driver not yet implemented");
}

private bool rtl8139Send(const(ubyte)* data, size_t len) @nogc nothrow {
    return false;
}

private int rtl8139Receive(ubyte* buffer, size_t maxLen) @nogc nothrow {
    return 0;
}

// ============================================================================
// VirtIO Driver (stub)
// ============================================================================

private void initVirtIO(NetworkDevice* dev) @nogc nothrow {
    printLine("[virtio] VirtIO network driver not yet implemented");
}

private bool virtioSend(const(ubyte)* data, size_t len) @nogc nothrow {
    return false;
}

private int virtioReceive(ubyte* buffer, size_t maxLen) @nogc nothrow {
    return 0;
}

// ============================================================================
// PCI Helper Functions
// ============================================================================

private ulong readPCIBar(PCIDevice* dev, uint barIndex) @nogc nothrow {
    import anonymos.drivers.pci : pciConfigRead32;
    uint bar = pciConfigRead32(dev.bus, dev.slot, dev.func, cast(ubyte)(0x10 + (barIndex * 4)));
    
    // Check if memory-mapped or I/O
    if ((bar & 1) == 0) {
        // Memory-mapped
        return bar & 0xFFFFFFF0;
    } else {
        // I/O space
        return bar & 0xFFFFFFFC;
    }
}

private void enablePCIBusMastering(PCIDevice* dev) @nogc nothrow {
    import anonymos.drivers.pci : pciConfigRead32, pciConfigWrite32;
    
    // Read command register (offset 0x04)
    uint cmd = pciConfigRead32(dev.bus, dev.slot, dev.func, 0x04);
    
    // Set bus mastering bit (bit 2)
    cmd |= (1 << 2);
    
    // Write back
    pciConfigWrite32(dev.bus, dev.slot, dev.func, 0x04, cmd);
}
