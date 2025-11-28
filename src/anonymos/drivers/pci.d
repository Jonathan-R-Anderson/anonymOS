module anonymos.drivers.pci;

import anonymos.console : print, printHex, printLine, printUnsigned;

@nogc nothrow:

private enum ushort pciConfigAddress = 0xCF8;
private enum ushort pciConfigData    = 0xCFC;

uint pciConfigRead32(ubyte bus, ubyte slot, ubyte func, ubyte offset)
{
    const uint address = (1u << 31) |
                         ((cast(uint)bus) << 16) |
                         ((cast(uint)slot) << 11) |
                         ((cast(uint)func) << 8) |
                         (offset & 0xFC);

    uint value;
    asm @nogc nothrow
    {
        mov DX, pciConfigAddress;
        mov EAX, address;
        out DX, EAX;
        mov DX, pciConfigData;
        in  EAX, DX;
        mov value, EAX;
    }

    return value;
}

void pciConfigWrite32(ubyte bus, ubyte slot, ubyte func, ubyte offset, uint value)
{
    const uint address = (1u << 31) |
                         ((cast(uint)bus) << 16) |
                         ((cast(uint)slot) << 11) |
                         ((cast(uint)func) << 8) |
                         (offset & 0xFC);

    asm @nogc nothrow
    {
        mov DX, pciConfigAddress;
        mov EAX, address;
        out DX, EAX;
        mov DX, pciConfigData;
        mov EAX, value;
        out DX, EAX;
    }
}

/// PCI Device structure
struct PCIDevice {
    ubyte bus;
    ubyte slot;
    ubyte func;
    ushort vendorId;
    ushort deviceId;
    ubyte classCode;
    ubyte subClass;
    ubyte progIf;
}

private __gshared PCIDevice[32] g_pciDevices;
private __gshared size_t g_pciDeviceCount = 0;

/// Scan PCI bus and return list of devices
PCIDevice[] scanPCIDevices() {
    g_pciDeviceCount = 0;
    
    foreach (bus; 0 .. 256) {
        foreach (slot; 0 .. 32) {
            foreach (func; 0 .. 8) {
                const uint vendorDevice = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 0);
                if ((vendorDevice & 0xFFFF) == 0xFFFF) {
                    if (func == 0) break;
                    continue;
                }

                const ushort vendorId = cast(ushort)(vendorDevice & 0xFFFF);
                const ushort deviceId = cast(ushort)((vendorDevice >> 16) & 0xFFFF);
                const uint classRev = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 8);
                const ubyte baseClass = cast(ubyte)((classRev >> 24) & 0xFF);
                const ubyte subClass  = cast(ubyte)((classRev >> 16) & 0xFF);
                const ubyte progIf    = cast(ubyte)((classRev >> 8) & 0xFF);

                if (g_pciDeviceCount < g_pciDevices.length) {
                    g_pciDevices[g_pciDeviceCount] = PCIDevice(
                        cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func,
                        vendorId, deviceId, baseClass, subClass, progIf
                    );
                    g_pciDeviceCount++;
                }
            }
        }
    }
    
    return g_pciDevices[0 .. g_pciDeviceCount];
}

/// Basic bus walk that logs every present device/function with IDs and class.
void initializePCI()
{
    printLine("[pci] Enumerating devices");
    
    auto devices = scanPCIDevices();
    
    foreach (dev; devices) {
        print("[pci] ");
        printHex(dev.bus); print(":"); printHex(dev.slot); print("."); printHex(dev.func);
        print(" vid:"); printHex(dev.vendorId);
        print(" did:"); printHex(dev.deviceId);
        print(" class:"); printHex(dev.classCode);
        print("."); printHex(dev.subClass);
        print("."); printHex(dev.progIf);
        printLine("");
    }

    printLine("[pci] enumeration complete");
}
