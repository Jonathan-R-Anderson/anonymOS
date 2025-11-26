module anonymos.hardware;

import anonymos.console : print, printLine, printUnsigned, printHex;
import anonymos.multiboot;

@nogc nothrow
MultibootContext probeHardware(ulong magic, ulong infoAddress)
{
    printLine("");
    printLine("[probe] Inspecting firmware-provided hardware tables...");

    const context = MultibootContext.fromBootValues(magic, infoAddress);
    if (!context.valid)
    {
        printLine("[probe] Multiboot signature missing, skipping hardware scan.");
        return context;
    }

    logBasicMemory(context);
    logModules(context);
    logMemoryMap(context);
    logFramebuffer(context);

    return context;
}

private @nogc nothrow void logBasicMemory(const MultibootContext context)
{
    if (!context.hasFlag(MultibootInfoFlag.memoryInfo))
    {
        printLine("[probe] Firmware omitted basic memory totals.");
        return;
    }

    print("[probe] Lower memory : ");
    printUnsigned(context.info.memLower);
    printLine(" KiB");

    print("[probe] Upper memory : ");
    printUnsigned(context.info.memUpper);
    printLine(" KiB");
}

private @nogc nothrow void logModules(const MultibootContext context)
{
    if (!context.hasFlag(MultibootInfoFlag.moduleInfo) || context.moduleCount() == 0)
    {
        printLine("[probe] No Multiboot modules supplied.");
        return;
    }

    print("[probe] Modules      : ");
    printUnsigned(context.moduleCount());
    printLine("");

    foreach (index; 0 .. context.moduleCount())
    {
        // renamed from `module` (keyword!) to `mod`
        const MultibootModule* mod = context.moduleAt(index);
        if (mod is null)
        {
            continue;
        }

        print("           [");
        printUnsigned(index);
        print("] 0x");
        printHex(mod.modStart, 8);
        print(" - 0x");
        printHex(mod.modEnd, 8);
        printLine("");
    }
}

private @nogc nothrow void logMemoryMap(const MultibootContext context)
{
    if (!context.hasFlag(MultibootInfoFlag.memoryMap) || context.info.mmapLength == 0)
    {
        printLine("[probe] Memory map not available.");
        return;
    }

    printLine("[probe] Physical memory map:");

    auto entries = context.mmapEntries();
    while (!entries.empty())
    {
        const entry = entries.front();
        logRegion(entry);
        entries.popFront();
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

private @nogc nothrow void logFramebuffer(const MultibootContext context)
{
    if (!context.hasFlag(MultibootInfoFlag.framebufferInfo))
    {
        printLine("[probe] No framebuffer description provided.");
        return;
    }

    const fbInfo = selectFramebufferMode(context.info, FramebufferModeRequest.init);
    if (!fbInfo.valid())
    {
        printLine("[probe] Framebuffer description was present but invalid.");
        return;
    }

    print("[probe] Framebuffer  : 0x");
    printHex(cast(size_t)fbInfo.base, 16);
    print("  ");
    printUnsigned(fbInfo.width);
    print("x");
    printUnsigned(fbInfo.height);
    print("x");
    printUnsigned(fbInfo.bpp);
    print(" @ ");
    printUnsigned(fbInfo.pitch);
    print(" bytes/scanline (mode ");
    printUnsigned(fbInfo.modeNumber);
    print(", backend: ");
    print(videoBackendLabel(fbInfo.backend));
    printLine(")");
}

private @nogc nothrow immutable(char)[] videoBackendLabel(MultibootVideoBackend backend)
{
    final switch (backend)
    {
        case MultibootVideoBackend.vbe:     return "VBE";
        case MultibootVideoBackend.efiGop:  return "EFI GOP";
        case MultibootVideoBackend.drm:     return "DRM";
        case MultibootVideoBackend.unknown: return "unknown";
    }
}
