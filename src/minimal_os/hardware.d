module minimal_os.hardware;

import minimal_os.console : print, printLine, printUnsigned, printHex;

enum uint multibootLoaderMagic = 0x2BADB002;

enum MultibootInfoFlag : uint
{
    memoryInfo      = 1u << 0,
    moduleInfo      = 1u << 3,
    memoryMap       = 1u << 6,
    framebufferInfo = 1u << 12,
}

align(1) struct MultibootInfo
{
    uint flags;
    uint memLower;
    uint memUpper;
    uint bootDevice;
    uint cmdline;
    uint modsCount;
    uint modsAddr;
    uint syms0;
    uint syms1;
    uint syms2;
    uint syms3;
    uint mmapLength;
    uint mmapAddr;
    uint drivesLength;
    uint drivesAddr;
    uint configTable;
    uint bootLoaderName;
    uint apmTable;
    uint vbeControlInfo;
    uint vbeModeInfo;
    ushort vbeMode;
    ushort vbeInterfaceSeg;
    ushort vbeInterfaceOff;
    ushort vbeInterfaceLen;
    ulong framebufferAddr;
    uint framebufferPitch;
    uint framebufferWidth;
    uint framebufferHeight;
    ubyte framebufferBpp;
    ubyte framebufferType;
    ubyte[6] colorInfo;
}

align(1) struct MultibootModule
{
    uint modStart;
    uint modEnd;
    uint stringPtr;
    uint reserved;
}

align(1) struct MultibootMmapEntry
{
    uint entrySize;
    ulong address;
    ulong length;
    uint entryType;
}

enum MmapRegionType : uint
{
    available       = 1,
    reserved        = 2,
    acpiReclaimable = 3,
    acpiNvs         = 4,
    badMemory       = 5,
}

@nogc nothrow
void probeHardware(ulong magic, ulong infoAddress)
{
    printLine("");
    printLine("[probe] Inspecting firmware-provided hardware tables...");

    if (magic != multibootLoaderMagic)
    {
        printLine("[probe] Multiboot signature missing, skipping hardware scan.");
        return;
    }

    if (infoAddress == 0)
    {
        printLine("[probe] Multiboot info pointer invalid.");
        return;
    }

    const MultibootInfo* info = cast(const MultibootInfo*)infoAddress;
    if (info is null)
    {
        printLine("[probe] Unable to decode Multiboot info block.");
        return;
    }

    logBasicMemory(*info);
    logModules(*info);
    logMemoryMap(*info);
    logFramebuffer(*info);
}

private @nogc nothrow void logBasicMemory(const MultibootInfo info)
{
    if ((info.flags & MultibootInfoFlag.memoryInfo) == 0)
    {
        printLine("[probe] Firmware omitted basic memory totals.");
        return;
    }

    print("[probe] Lower memory : ");
    printUnsigned(info.memLower);
    printLine(" KiB");

    print("[probe] Upper memory : ");
    printUnsigned(info.memUpper);
    printLine(" KiB");
}

private @nogc nothrow void logModules(const MultibootInfo info)
{
    if ((info.flags & MultibootInfoFlag.moduleInfo) == 0 || info.modsCount == 0)
    {
        printLine("[probe] No Multiboot modules supplied.");
        return;
    }

    print("[probe] Modules      : ");
    printUnsigned(info.modsCount);
    printLine("");

    foreach (index; 0 .. info.modsCount)
    {
        const size_t base = info.modsAddr + index * MultibootModule.sizeof;
        const MultibootModule* module = cast(const MultibootModule*)base;
        if (module is null)
        {
            continue;
        }

        print("           [");
        printUnsigned(index);
        print("] 0x");
        printHex(module.modStart, 8);
        print(" - 0x");
        printHex(module.modEnd, 8);
        printLine("");
    }
}

private @nogc nothrow void logMemoryMap(const MultibootInfo info)
{
    if ((info.flags & MultibootInfoFlag.memoryMap) == 0 || info.mmapLength == 0)
    {
        printLine("[probe] Memory map not available.");
        return;
    }

    printLine("[probe] Physical memory map:");

    size_t offset = 0;
    const size_t base = info.mmapAddr;
    while (offset < info.mmapLength)
    {
        const MultibootMmapEntry* entry = cast(const MultibootMmapEntry*)(base + offset);
        if (entry is null)
        {
            break;
        }

        logRegion(*entry);

        // Each record stores the payload size excluding the entrySize field.
        const size_t advance = entry.entrySize + uint.sizeof;
        if (advance == 0)
        {
            break;
        }
        offset += advance;
    }
}

private @nogc nothrow void logRegion(const MultibootMmapEntry entry)
{
    print("           0x");
    printHex(cast(size_t)entry.address, 16);
    print(" - 0x");
    printHex(cast(size_t)(entry.address + entry.length), 16);
    print("  ");
    print(regionTypeName(entry.entryType));
    print(" (" );
    printUnsigned(cast(size_t)(entry.length / 1024));
    printLine(" KiB)");
}

private @nogc nothrow immutable(char)[] regionTypeName(uint entryType)
{
    switch (entryType)
    {
        case MmapRegionType.available:       return "available";
        case MmapRegionType.reserved:        return "reserved";
        case MmapRegionType.acpiReclaimable: return "ACPI reclaimable";
        case MmapRegionType.acpiNvs:         return "ACPI NVS";
        case MmapRegionType.badMemory:       return "bad memory";
        default:                             return "unknown";
    }
}

private @nogc nothrow void logFramebuffer(const MultibootInfo info)
{
    if ((info.flags & MultibootInfoFlag.framebufferInfo) == 0)
    {
        printLine("[probe] No framebuffer description provided.");
        return;
    }

    print("[probe] Framebuffer  : 0x");
    printHex(cast(size_t)info.framebufferAddr, 16);
    print("  ");
    printUnsigned(info.framebufferWidth);
    print("x");
    printUnsigned(info.framebufferHeight);
    print("x");
    printUnsigned(info.framebufferBpp);
    print(" @ ");
    printUnsigned(info.framebufferPitch);
    printLine(" bytes/scanline");
}
