module minimal_os.drivers.pci;

import minimal_os.console : print, printHex, printLine, printUnsigned;

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

/// Basic bus walk that logs every present device/function with IDs and class.
void initializePCI()
{
    printLine("[pci] Enumerating devices");

    foreach (bus; 0 .. 256)
    {
        foreach (slot; 0 .. 32)
        {
            foreach (func; 0 .. 8)
            {
                const uint vendorDevice = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 0);
                if ((vendorDevice & 0xFFFF) == 0xFFFF)
                {
                    if (func == 0)
                    {
                        break;
                    }
                    continue;
                }

                const ushort vendorId = cast(ushort)(vendorDevice & 0xFFFF);
                const ushort deviceId = cast(ushort)((vendorDevice >> 16) & 0xFFFF);
                const uint classCode = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 8);
                const ubyte baseClass = cast(ubyte)((classCode >> 24) & 0xFF);
                const ubyte subClass  = cast(ubyte)((classCode >> 16) & 0xFF);
                const ubyte progIf    = cast(ubyte)((classCode >> 8) & 0xFF);

                print("[pci] ");
                printHex(bus); print(":"); printHex(slot); print("."); printHex(func);
                print(" vid:"); printHex(vendorId);
                print(" did:"); printHex(deviceId);
                print(" class:"); printHex(baseClass);
                print("."); printHex(subClass);
                print("."); printHex(progIf);
                printLine("");
            }
        }
    }

    printLine("[pci] enumeration complete");
}
