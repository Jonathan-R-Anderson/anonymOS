module drivers.network.network;

import userland.shell.console : printLine, print, printHex;
import drivers.pci : PCIDevice, scanPCIDevices;

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
        // Debug: Print all network class devices
        if (dev.classCode == 0x02) {
            print("[network] Found Network Controller: ");
            printHex(dev.vendorId); print(":"); printHex(dev.deviceId);
            printLine("");
        }

        // Intel E1000 Family
        // 0x100E: 82540EM (QEMU, VirtualBox)
        // 0x100F: 82545EM (VirtualBox)
        // 0x1004: 82543GC (VirtualBox)
        // 0x1015: 82540EP
        // 0x1017: 82540EP Mobile
        // 0x10D3: 82574L (Intel Pro/1000 MT Desktop)
        if (dev.vendorId == 0x8086 && 
           (dev.deviceId == 0x100E || dev.deviceId == 0x100F || 
            dev.deviceId == 0x1004 || dev.deviceId == 0x1015 || 
            dev.deviceId == 0x1017 || dev.deviceId == 0x10D3)) 
        {
            printLine("[network] Found Intel E1000 network adapter");
            g_netDevice.type = NetworkDeviceType.E1000;
            g_netDevice.pciDev = &dev;
            if (!initE1000(&g_netDevice)) {
                printLine("[network] e1000 init failed -- not claiming this device");
                continue;   // keep scanning; do not report a LAN we could not bring up
            }
            g_networkAvailable = true;
            return;
        }
        
        // Generic Intel Network Controller Fallback
        // If it's Intel (0x8086) and Network Class (0x02), try E1000 driver
        // subClass 0x00 == Ethernet controller.  WITHOUT this check an Intel Wi-Fi card (class
        // 0x02, subClass 0x80 -- e.g. the AX210 in this laptop) was claimed as an e1000: it got
        // e1000 register writes at its BAR and the scan RETURNED, so a real Ethernet NIC further
        // down the bus was never seen and Wi-Fi was poked with the wrong driver.
        if (dev.vendorId == 0x8086 && dev.classCode == 0x02 && dev.subClass == 0x00 && !g_networkAvailable) {
             printLine("[network] Found Generic Intel Network Controller - Attempting E1000 driver...");
             g_netDevice.type = NetworkDeviceType.E1000;
             g_netDevice.pciDev = &dev;
             if (!initE1000(&g_netDevice)) {
                 printLine("[network] e1000 init failed -- not claiming this device");
                 continue;   // keep scanning; do not report a LAN we could not bring up
             }
             g_networkAvailable = true;
             return;
        }
        
        // Realtek RTL8139 (0x10EC:0x8139) -- initRTL8139() is a STUB that only prints.
        // This branch used to set g_networkAvailable = true and RETURN, which (a) reported a
        // working LAN that can never send or receive a frame, and (b) abandoned the scan, so a
        // real e1000 further down the bus was never found.  Log it and keep looking instead.
        if (dev.vendorId == 0x10EC && dev.deviceId == 0x8139) {
            printLine("[network] Found Realtek RTL8139 -- driver is a stub, not claiming it");
            initRTL8139(&g_netDevice);
            continue;
        }

        // VirtIO network.  0x1000 is the TRANSITIONAL id that QEMU/Proxmox present by default
        // (it still exposes the virtio-1.0 capability structures); 0x1041 is modern-only.  Both
        // are driven through the modern transport in drivers/network/virtio_net.d.  This is the
        // Proxmox default NIC, so it is the difference between having a LAN and not.
        if (dev.vendorId == 0x1AF4 && (dev.deviceId == 0x1000 || dev.deviceId == 0x1041)) {
            printLine("[network] Found VirtIO network adapter");
            g_netDevice.type = NetworkDeviceType.VirtIO;
            g_netDevice.pciDev = &dev;
            if (!initVirtIO(&g_netDevice)) {
                printLine("[network] virtio-net init failed -- not claiming this device");
                continue;   // keep scanning; never report a LAN we could not bring up
            }
            g_netDevice.initialized = true;
            g_networkAvailable = true;
            return;
        }
    }
    
    printLine("[network] No supported network device found");
}

/// Stop network driver
export extern(C) void stopNetwork() @nogc nothrow {
    if (!g_networkAvailable) return;
    
    printLine("[network] Stopping network driver...");
    
    switch (g_netDevice.type) {
        case NetworkDeviceType.E1000:
            stopE1000(&g_netDevice);
            break;
        default:
            break;
    }
    
    g_networkAvailable = false;
    g_netDevice.initialized = false;
    printLine("[network] Network driver stopped");
}

private void stopE1000(NetworkDevice* dev) @nogc nothrow {
    // Disable interrupts
    writeE1000Reg(dev, E1000Reg.IMS, 0);
    
    // Disable Receiver and Transmitter
    writeE1000Reg(dev, E1000Reg.RCTL, 0);
    writeE1000Reg(dev, E1000Reg.TCTL, 0);
    
    // Reset Device (optional, but good for clean state)
    // writeE1000Reg(dev, E1000Reg.CTRL, 0x04000000 | readE1000Reg(dev, E1000Reg.CTRL));
}

/// Check if network is available (Driver init + Link Up)
export extern(C) bool isNetworkAvailable() @nogc nothrow {
    return g_networkAvailable && g_netDevice.initialized;
}

private bool e1000LinkStatus() @nogc nothrow {
    // Read Status Register (Bit 1 = Link Up)
    uint status = readE1000Reg(&g_netDevice, E1000Reg.STATUS);
    return (status & 2) != 0;
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

    bool ok;
    switch (g_netDevice.type) {
        case NetworkDeviceType.E1000:
            ok = e1000Send(data, len); break;
        case NetworkDeviceType.RTL8139:
            ok = rtl8139Send(data, len); break;
        case NetworkDeviceType.VirtIO:
            ok = virtioSend(data, len); break;
        default:
            return false;
    }
    // ROADMAP 2.1: real counters for /proc/net/dev.  Counted at the one dispatcher every
    // transmit passes through, rather than in each device path, so a new NIC driver gets
    // accounting for free instead of being silently missing from it.
    if (ok) { ++g_netTxFrames; g_netTxBytes += len; } else { ++g_netTxErrs; }
    return ok;
}

/// Receive raw Ethernet frame
export extern(C) int receiveEthFrame(ubyte* buffer, size_t maxLen) @nogc nothrow {
    if (!g_networkAvailable || buffer is null || maxLen == 0) return -1;
    
    int r;
    switch (g_netDevice.type) {
        case NetworkDeviceType.E1000:   r = e1000Receive(buffer, maxLen); break;
        case NetworkDeviceType.RTL8139: r = rtl8139Receive(buffer, maxLen); break;
        case NetworkDeviceType.VirtIO:  r = virtioReceive(buffer, maxLen); break;
        default: r = -1;
    }
    if (r >= 14) { ++g_netRxFrames; g_netRxBytes += cast(ulong)r; g_netRxLastEtherType = (cast(ulong)buffer[12] << 8) | buffer[13]; }
    return r;
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

import memory.physmem : allocFrame, freeFrame;
import core.globals : hhdm_offset;   // N0 fix: phys↔virt via the runtime HHDM (not a hardcoded base)

// phys → virt through the kernel's higher-half direct map (matches phys_to_virt / the AHCI MMIO path).
private T* physToVirt(T)(size_t phys) { return cast(T*)(phys + hhdm_offset); }

// Descriptor rings (Dynamic allocation)
private __gshared E1000RxDesc* g_rxDescriptors;
private __gshared E1000TxDesc* g_txDescriptors;
private __gshared uint g_rxCurrent = 0;
private __gshared uint g_txCurrent = 0;
// ROADMAP 2.1: byte and TX counters so /proc/net/dev reports what actually happened.  It
// used to be a static table of invented numbers (lo: 4096/32, eth0: 65536/512), which any
// monitor reading it would present to the user as fact.
private __gshared ulong g_netRxBytes  = 0;
private __gshared ulong g_netTxFrames = 0;
private __gshared ulong g_netTxBytes  = 0;
private __gshared ulong g_netTxErrs   = 0;
public ulong netRxFrames() @nogc nothrow { return g_netRxFrames; }
public ulong netRxBytes()  @nogc nothrow { return g_netRxBytes; }
public ulong netTxFrames() @nogc nothrow { return g_netTxFrames; }
public ulong netTxBytes()  @nogc nothrow { return g_netTxBytes; }
public ulong netTxErrs()   @nogc nothrow { return g_netTxErrs; }
private __gshared ulong g_netRxFrames = 0;   // N0: count inbound frames the driver has delivered
private __gshared ulong g_netRxLastEtherType = 0;  // N0: ethertype of the most recent frame (verify)
export extern(C) ulong getNetRxFrames() @nogc nothrow { return g_netRxFrames; }
export extern(C) ulong getNetRxLastEtherType() @nogc nothrow { return g_netRxLastEtherType; }

private bool initE1000(NetworkDevice* dev) @nogc nothrow {
    printLine("[e1000] Initializing Intel E1000...");
    
    // Read BAR0 for memory-mapped I/O — map it through the HHDM so memBase is a usable virtual
    // address (the registers are accessed as memBase+offset; the raw phys is not mapped low).
    // BAR0 must be a MEMORY BAR holding a real address.  readPCIBar() masks the low bits for
    // BOTH memory and I/O BARs, so it cannot tell them apart, and an unassigned BAR reads back
    // 0 -- either way memBase would collapse to a bare hhdm_offset and every register access
    // would land on unrelated memory while init still reported success.  Check before binding.
    {
        import drivers.pci : pciConfigRead32;
        const uint bar0 = pciConfigRead32(dev.pciDev.bus, dev.pciDev.slot, dev.pciDev.func, 0x10);
        if ((bar0 & 1) != 0) {
            printLine("[e1000] BAR0 is an I/O BAR, not MMIO -- refusing to bind");
            return false;
        }
        if ((bar0 & 0xFFFFFFF0) == 0) {
            printLine("[e1000] BAR0 is unassigned (0) -- refusing to bind");
            return false;
        }
    }
    dev.memBase = readPCIBar(dev.pciDev, 0) + hhdm_offset;

    // Reset device (RST bit clears itself and all other bits)
    uint ctrl = readE1000Reg(dev, E1000Reg.CTRL);
    writeE1000Reg(dev, E1000Reg.CTRL, ctrl | 0x04000000); // Set RST (bit 26)
    
    // Wait for reset to complete
    for (uint i = 0; i < 1000000; i++) {
        asm @nogc nothrow { nop; }
    }
    
    // After reset, configure CTRL for link establishment
    // Bit 5 (ASDE) = Auto-Speed Detection Enable
    // Bit 6 (SLU) = Set Link Up
    ctrl = readE1000Reg(dev, E1000Reg.CTRL);
    ctrl |= (1 << 6) | (1 << 5);
    writeE1000Reg(dev, E1000Reg.CTRL, ctrl);

    // Enable bus mastering AFTER the reset, not before.  Without PCI bus-master the device
    // cannot DMA at all -- QEMU refuses the frame with
    //   e1000x_rx_can_recv_disabled link_up: 1, rx_enabled 0, pci_master 0
    // which is exactly what the device trace showed on a failing boot.  Setting it before the
    // MAC reset leaves a window where it can be lost; the canonical order is
    // reset -> bus master -> program the rings.  (REQUIRED for DMA: rings + buffers.)
    enablePCIBusMastering(dev.pciDev);
    
    // Read MAC address from EEPROM
    readE1000Mac(dev);
    
    // Initialize receive/transmit rings
    initE1000Rings(dev);
    
    // Disable interrupts (we are polling)
    writeE1000Reg(dev, E1000Reg.IMS, 0);
    writeE1000Reg(dev, E1000Reg.ICR, 0xFFFFFFFF); // Clear any pending
    
    dev.initialized = true;
    printLine("[e1000] Initialization complete");
    return true;
}

private void readE1000Mac(NetworkDevice* dev) @nogc nothrow {
    // The device loads the MAC from EEPROM into Receive-Address registers RAL/RAH after reset.
    uint macLow  = readE1000Reg(dev, E1000Reg.RAL);
    uint macHigh = readE1000Reg(dev, E1000Reg.RAH);
    dev.macAddress[0] = cast(ubyte)(macLow & 0xFF);
    dev.macAddress[1] = cast(ubyte)((macLow >> 8) & 0xFF);
    dev.macAddress[2] = cast(ubyte)((macLow >> 16) & 0xFF);
    dev.macAddress[3] = cast(ubyte)((macLow >> 24) & 0xFF);
    dev.macAddress[4] = cast(ubyte)(macHigh & 0xFF);
    dev.macAddress[5] = cast(ubyte)((macHigh >> 8) & 0xFF);
}

private void initE1000Rings(NetworkDevice* dev) @nogc nothrow {
    // Allocate RX Descriptors (1 page is enough for 32 descriptors)
    size_t rxDescPhys = allocFrame();
    g_rxDescriptors = physToVirt!E1000RxDesc(rxDescPhys);
    
    // Allocate TX Descriptors
    size_t txDescPhys = allocFrame();
    g_txDescriptors = physToVirt!E1000TxDesc(txDescPhys);
    
    // Allocate Buffers (Need multiple pages)
    // 32 * 2048 = 64KB = 16 pages
    // For simplicity, we'll allocate one page per buffer for now to avoid contiguous requirement issues, 
    // OR just allocate a chunk. 
    // Let's allocate 16 pages for RX and 4 pages for TX (8 * 2048 = 16KB).
    
    // RX Buffers
    // Allocating contiguous physical memory is hard with single allocFrame.
    // We will allocate separate frames for each buffer if needed, but descriptors need a pointer.
    // E1000 descriptors take a 64-bit address. So we can scatter-gather.
    
    // Initialize RX descriptors
    for (uint i = 0; i < NUM_RX_DESC; i++) {
        size_t bufPhys = allocFrame();
        g_rxDescriptors[i].addr = cast(ulong)bufPhys;
        g_rxDescriptors[i].status = 0;
        
        // Map virtual address for CPU access (for e1000Receive)
        // We need to store these virtual pointers somewhere?
        // Or just re-calculate physToVirt(addr) when receiving.
    }
    
    // Set RX descriptor base (Physical Address)
    writeE1000Reg(dev, E1000Reg.RDBAL, cast(uint)(rxDescPhys & 0xFFFFFFFF));
    writeE1000Reg(dev, E1000Reg.RDBAH, cast(uint)(rxDescPhys >> 32));
    writeE1000Reg(dev, E1000Reg.RDLEN, NUM_RX_DESC * E1000RxDesc.sizeof);
    writeE1000Reg(dev, E1000Reg.RDH, 0);
    writeE1000Reg(dev, E1000Reg.RDT, NUM_RX_DESC - 1);
    
    // Initialize TX descriptors
    for (uint i = 0; i < NUM_TX_DESC; i++) {
        size_t bufPhys = allocFrame();
        g_txDescriptors[i].addr = cast(ulong)bufPhys;
        g_txDescriptors[i].status = 1; // DD bit set
        g_txDescriptors[i].cmd = 0;
    }
    
    // Set TX descriptor base (Physical Address)
    writeE1000Reg(dev, E1000Reg.TDBAL, cast(uint)(txDescPhys & 0xFFFFFFFF));
    writeE1000Reg(dev, E1000Reg.TDBAH, cast(uint)(txDescPhys >> 32));
    writeE1000Reg(dev, E1000Reg.TDLEN, NUM_TX_DESC * E1000TxDesc.sizeof);
    writeE1000Reg(dev, E1000Reg.TDH, 0);
    writeE1000Reg(dev, E1000Reg.TDT, 0);
    
    // Enable receiver
    writeE1000Reg(dev, E1000Reg.RCTL, 
        (1 << 1) |  // EN - Enable
        (1 << 4) |  // MPE - Multicast Promiscuous
        (1 << 15) | // BAM - Broadcast Accept Mode
        (0 << 16) | // BSIZE - 2048 bytes (BSEX=0)
        (0 << 25) | // BSEX - Buffer Size Extension (0 for 2048)
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
    // We need to get the virtual address of the buffer
    ubyte* txBuf = physToVirt!ubyte(cast(size_t)desc.addr);
    
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
    // Poll the current RX descriptor for the DD (descriptor-done) bit.
    E1000RxDesc* desc = &g_rxDescriptors[g_rxCurrent];
    if ((desc.status & 1) == 0) return 0;        // no packet available yet
    uint pktLen = desc.length;
    if (pktLen > maxLen) pktLen = cast(uint)maxLen;
    // Copy out of the DMA buffer (mapped via the HHDM).
    ubyte* rxBuf = physToVirt!ubyte(cast(size_t)desc.addr);
    for (uint i = 0; i < pktLen; i++) buffer[i] = rxBuf[i];
    // Hand the descriptor back to the NIC and advance RDT to it.
    desc.status = 0;
    const uint oldCurrent = g_rxCurrent;
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
// VirtIO Driver (real -- see drivers/network/virtio_net.d)
// ============================================================================

// VirtIO-net is implemented in drivers/network/virtio_net.d: a real modern (virtio-1.0)
// driver mirroring the proven virtio-gpu transport.  It matters because virtio is the
// DEFAULT NIC model on Proxmox, where these three functions previously being stubs meant
// the guest simply had no network device at all.
private bool initVirtIO(NetworkDevice* dev) @nogc nothrow {
    import drivers.network.virtio_net : virtioNetInit;
    return virtioNetInit(dev.pciDev, dev.macAddress.ptr);
}

private bool virtioSend(const(ubyte)* data, size_t len) @nogc nothrow {
    import drivers.network.virtio_net : virtioNetSend;
    return virtioNetSend(data, len);
}

private int virtioReceive(ubyte* buffer, size_t maxLen) @nogc nothrow {
    import drivers.network.virtio_net : virtioNetReceive;
    return virtioNetReceive(buffer, maxLen);
}

// ============================================================================
// PCI Helper Functions
// ============================================================================

private ulong readPCIBar(PCIDevice* dev, uint barIndex) @nogc nothrow {
    import drivers.pci : pciConfigRead32;
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
    import drivers.pci : pciConfigRead32, pciConfigWrite32;
    // Command register (0x04): set bus-master (bit 2) + memory-space (bit 1) so MMIO + DMA work.
    uint cmd = pciConfigRead32(dev.bus, dev.slot, dev.func, 0x04);
    cmd |= (1 << 2) | (1 << 1);
    pciConfigWrite32(dev.bus, dev.slot, dev.func, 0x04, cmd);
}

// ════════════════════════════════════════════════════════════════════════════════
// On-screen network HUD (the green text overlay, top-left)
// ════════════════════════════════════════════════════════════════════════════════
//
// The panel indicator can only ever say "wired / wifi / nothing".  When the question is
// "am I actually ON the LAN?" that is not enough, and on a machine whose pointer does not
// work you cannot go clicking through menus to find out.  So mirror the network state onto
// the same always-visible framebuffer HUD the Wi-Fi survey already uses: it is re-stamped
// after every compositor present, so it survives the desktop owning the screen, and it
// needs no input, no working mouse and no userspace at all.
//
// Rows are drawn BELOW the Wi-Fi survey block (which occupies rows 16..16+4*16).
enum int NET_HUD_MAX = 6;
__gshared char[80][NET_HUD_MAX] g_netHud;
__gshared int  g_netHudN = 0;
// OFF BY DEFAULT since 2026-09-05.  This painted a black band with green text over the
// top-left of the live desktop on EVERY present ("NET: NO NIC FOUND - check the VM network
// device"), which is a debugging aid sitting permanently on top of the user's screen.  The
// information is still in serial.log, where a diagnostic belongs.  Set true when actually
// bringing up a NIC and you need it visible on the panel.
__gshared bool g_netHudEnabled = false;

private void nhStr(ref char[80] b, ref int n, const(char)* s) @nogc nothrow {
    while (*s != 0 && n < 79) b[n++] = *s++;
}
private void nhHex(ref char[80] b, ref int n, ulong v, int nib) @nogc nothrow {
    static immutable char[16] hx = "0123456789abcdef";
    for (int i = nib - 1; i >= 0 && n < 79; --i) b[n++] = hx[(v >> (i * 4)) & 0xF];
}
private void nhDec(ref char[80] b, ref int n, ulong v) @nogc nothrow {
    char[24] tmp; int t = 0;
    if (v == 0) { if (n < 79) b[n++] = '0'; return; }
    while (v > 0 && t < 24) { tmp[t++] = cast(char)('0' + (v % 10)); v /= 10; }
    while (t > 0 && n < 79) b[n++] = tmp[--t];
}

public void netHudClear() @nogc nothrow { g_netHudN = 0; }

// Append one line.  Silently drops past NET_HUD_MAX so a chatty caller cannot scribble
// over the rest of the screen.
public void netHudLine(const(char)* s) @nogc nothrow {
    if (g_netHudN >= NET_HUD_MAX) return;
    int n = 0;
    nhStr(g_netHud[g_netHudN], n, s);
    g_netHud[g_netHudN][n] = 0;
    g_netHudN++;
}

// "NET nic=<kind> mac=<aabbccddeeff> link=<up|down>"
public void netHudNic() @nogc nothrow {
    if (g_netHudN >= NET_HUD_MAX) return;
    int n = 0; auto b = &g_netHud[g_netHudN];
    nhStr(*b, n, "NET nic=".ptr);
    switch (g_netDevice.type) {
        case NetworkDeviceType.E1000:   nhStr(*b, n, "e1000".ptr);  break;
        case NetworkDeviceType.VirtIO:  nhStr(*b, n, "virtio".ptr); break;
        case NetworkDeviceType.RTL8139: nhStr(*b, n, "rtl8139".ptr); break;
        default:                        nhStr(*b, n, "none".ptr);   break;
    }
    nhStr(*b, n, " mac=".ptr);
    foreach (i; 0 .. 6) nhHex(*b, n, g_netDevice.macAddress[i], 2);
    nhStr(*b, n, g_networkAvailable ? " link=UP".ptr : " link=DOWN".ptr);
    (*b)[n] = 0;
    g_netHudN++;
}

// "NET ip=a.b.c.d gw=a.b.c.d"
public void netHudAddr(ubyte a, ubyte b_, ubyte c, ubyte d,
                       ubyte ga, ubyte gb, ubyte gc, ubyte gd) @nogc nothrow {
    if (g_netHudN >= NET_HUD_MAX) return;
    int n = 0; auto b = &g_netHud[g_netHudN];
    nhStr(*b, n, "NET ip=".ptr);
    nhDec(*b, n, a); nhStr(*b, n, ".".ptr); nhDec(*b, n, b_); nhStr(*b, n, ".".ptr);
    nhDec(*b, n, c); nhStr(*b, n, ".".ptr); nhDec(*b, n, d);
    nhStr(*b, n, " gw=".ptr);
    nhDec(*b, n, ga); nhStr(*b, n, ".".ptr); nhDec(*b, n, gb); nhStr(*b, n, ".".ptr);
    nhDec(*b, n, gc); nhStr(*b, n, ".".ptr); nhDec(*b, n, gd);
    (*b)[n] = 0;
    g_netHudN++;
}

// "NET <label>=<OK|FAIL> ..." — one line per probe result, plus live rx counters.
public void netHudProbe(const(char)* label, bool ok) @nogc nothrow {
    if (g_netHudN >= NET_HUD_MAX) return;
    int n = 0; auto b = &g_netHud[g_netHudN];
    nhStr(*b, n, "NET ".ptr); nhStr(*b, n, label);
    nhStr(*b, n, ok ? "=OK".ptr : "=FAIL".ptr);
    nhStr(*b, n, "  rx=".ptr); nhDec(*b, n, g_netRxFrames);
    nhStr(*b, n, " lastEth=0x".ptr); nhHex(*b, n, g_netRxLastEtherType, 4);
    (*b)[n] = 0;
    g_netHudN++;
}

// Re-stamp onto the desktop after each present, below the Wi-Fi survey block.
public void netHudRepaint(uint y0) @nogc nothrow {
    import arch.x86_64.bootstrap : fb_draw_hud_row;
    if (!g_netHudEnabled) return;
    for (int i = 0; i < g_netHudN; i++)
        fb_draw_hud_row(y0 + cast(uint)(i * 16), g_netHud[i].ptr);
}

// One-shot e1000 RX diagnostic.  Read the registers BACK from the device and compare them
// with what we programmed, then show descriptor 0.  This distinguishes the three remaining
// explanations for "frames arrive at the device but rx stays 0":
//
//   RDBAL/RDLEN readback != what we wrote  -> our MMIO register writes are not landing
//   RDH still 0                            -> the device never wrote a descriptor at all
//   RDH advanced but desc[0].status == 0   -> it DMA'd the descriptor somewhere else,
//                                             i.e. RDBAL does not match g_rxDescriptors
public void e1000Diag() @nogc nothrow {
    import core.io : klog, klog_hex;
    if (g_netDevice.type != NetworkDeviceType.E1000 || !g_networkAvailable) return;
    auto d = &g_netDevice;
    klog("[e1000diag] RCTL=");  klog_hex(readE1000Reg(d, E1000Reg.RCTL));
    klog(" RDBAL=");            klog_hex(readE1000Reg(d, E1000Reg.RDBAL));
    klog(" RDBAH=");            klog_hex(readE1000Reg(d, E1000Reg.RDBAH));
    klog(" RDLEN=");            klog_hex(readE1000Reg(d, E1000Reg.RDLEN));
    klog("\n[e1000diag] RDH=");  klog_hex(readE1000Reg(d, E1000Reg.RDH));
    klog(" RDT=");              klog_hex(readE1000Reg(d, E1000Reg.RDT));
    klog(" STATUS=");           klog_hex(readE1000Reg(d, E1000Reg.STATUS));
    klog("\n[e1000diag] ringVirt="); klog_hex(cast(ulong)g_rxDescriptors);
    if (g_rxDescriptors !is null) {
        klog(" d0.addr=");   klog_hex(g_rxDescriptors[0].addr);
        klog(" d0.status="); klog_hex(g_rxDescriptors[0].status);
        klog(" d0.len=");    klog_hex(g_rxDescriptors[0].length);
        klog(" d1.status="); klog_hex(g_rxDescriptors[1].status);
    }
    klog("\n");
}
