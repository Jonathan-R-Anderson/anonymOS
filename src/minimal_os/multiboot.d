module minimal_os.multiboot;

import minimal_os.display.framebuffer;

/// Helpers and data layouts for interacting with Multiboot loaders.
///
/// The structures mirror the Multiboot 1 specification so that the kernel can
/// safely read memory supplied by GRUB or another compliant bootloader without
/// relying on external libraries.

/// Magic value placed in %eax by a Multiboot-compliant loader when jumping into
/// the kernel entry point.
enum uint multibootLoaderMagic = 0x2BADB002;

/// Flags for the MultibootInfo.flags field.
enum MultibootInfoFlag : uint
{
    memoryInfo      = 1u << 0,
    moduleInfo      = 1u << 3,
    memoryMap       = 1u << 6,
    framebufferInfo = 1u << 12,
}

/// Wire format of the Multiboot information block.
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

/// Description of a boot module.
align(1) struct MultibootModule
{
    uint modStart;
    uint modEnd;
    uint stringPtr;
    uint reserved;
}

/// A single memory map record.
align(1) struct MultibootMmapEntry
{
    uint entrySize;
    ulong address;
    ulong length;
    uint entryType;
}

/// Enumerated region types found in the memory map.
enum MmapRegionType : uint
{
    available       = 1,
    reserved        = 2,
    acpiReclaimable = 3,
    acpiNvs         = 4,
    badMemory       = 5,
}

/// Lightweight view over the bootloader-provided structures.
///
/// This avoids copying the raw data while providing convenience helpers for
/// sanity checking and iteration in other modules.
struct MultibootContext
{
    const MultibootInfo* info;

    private static @trusted const(T)* ptrFromAddress(T)(size_t address)
    {
        return cast(const(T)*)address;
    }

    /// Attempt to construct a context from the raw Multiboot register values.
    @nogc nothrow
    static MultibootContext fromBootValues(ulong magic, ulong infoAddress)
    {
        if (magic != multibootLoaderMagic || infoAddress == 0)
        {
            return MultibootContext.init;
        }

        const MultibootInfo* info = cast(const MultibootInfo*)infoAddress;
        return MultibootContext(info);
    }

    /// Return true when the context is usable.
    @nogc @safe pure nothrow
    bool valid() const
    {
        return info !is null;
    }

    /// Check whether a specific flag is set.
    @nogc @safe pure nothrow
    bool hasFlag(MultibootInfoFlag flag) const
    {
        return valid && (info.flags & flag) != 0;
    }

    /// Number of modules supplied by the bootloader.
    @nogc @safe pure nothrow
    size_t moduleCount() const
    {
        return valid ? info.modsCount : 0;
    }

    /// Retrieve the Nth module, or null on error.
    @nogc @safe pure nothrow
    const(MultibootModule)* moduleAt(size_t index) const
    {
        if (!valid || index >= moduleCount())
        {
            return null;
        }

        const size_t base = info.modsAddr + index * MultibootModule.sizeof;
        return ptrFromAddress!MultibootModule(base);
    }

    /// Iterate over memory map entries in-order.
    @nogc @safe pure nothrow
    MultibootMmapRange mmapEntries() const
    {
        if (!valid || info.mmapLength == 0)
        {
            return MultibootMmapRange.init;
        }

        return MultibootMmapRange(info.mmapAddr, info.mmapLength);
    }
}

/// Description of a framebuffer parsed from Multiboot data.
struct MultibootFramebufferInfo
{
    void* base;
    uint  width;
    uint  height;
    uint  pitch;
    uint  bpp;
    bool  isBGR;

    @nogc @safe pure nothrow
    bool valid() const
    {
        return base !is null && width > 0 && height > 0 && bpp > 0;
    }
}

/// Range helper for memory map iteration.
struct MultibootMmapRange
{
    size_t base;
    size_t remaining;

    @nogc @safe pure nothrow
    this(size_t base, size_t length)
    {
        this.base = base;
        this.remaining = length;
    }

    @nogc @safe pure nothrow
    bool empty() const
    {
        return remaining == 0;
    }

    @nogc @safe nothrow
    MultibootMmapEntry front() const
    {
        // Caller must ensure !empty().
        const MultibootMmapEntry* entry = MultibootContext.ptrFromAddress!MultibootMmapEntry(base);
        return *entry;
    }

    @nogc @safe nothrow
    void popFront()
    {
        const MultibootMmapEntry* entry = MultibootContext.ptrFromAddress!MultibootMmapEntry(base);
        const size_t advance = entry.entrySize + uint.sizeof;
        base += advance;

        if (advance >= remaining)
        {
            remaining = 0;
        }
        else
        {
            remaining -= advance;
        }
    }
}


/// Extract framebuffer configuration from a Multiboot info block.
MultibootFramebufferInfo framebufferInfoFromMultiboot(const MultibootInfo* mbi) @nogc nothrow @system
{
    MultibootFramebufferInfo fbInfo;
    if (mbi is null)
    {
        return fbInfo;
    }

    fbInfo.base   = cast(void*) mbi.framebufferAddr;
    fbInfo.width  = mbi.framebufferWidth;
    fbInfo.height = mbi.framebufferHeight;
    fbInfo.pitch  = mbi.framebufferPitch;
    fbInfo.bpp    = mbi.framebufferBpp;

    // Color layout is only meaningful for RGB framebuffers (type 1 in Multiboot
    // spec). The colorInfo array is laid out as
    // [red_position, red_size, green_position, green_size, blue_position, blue_size].
    enum ubyte framebufferTypeRgb = 1;
    if (mbi.framebufferType == framebufferTypeRgb)
    {
        const ubyte redPosition  = mbi.colorInfo[0];
        const ubyte bluePosition = mbi.colorInfo[4];
        fbInfo.isBGR = (redPosition == 16 && bluePosition == 0);
    }

    return fbInfo;
}

/// Initialize the framebuffer using Multiboot info and display a banner.
bool initVideoFromMultiboot(const MultibootInfo* mbi, const(char)[] bannerMessage = "minimal_os framebuffer online") @nogc nothrow @system
{
    const fbInfo = framebufferInfoFromMultiboot(mbi);
    if (!fbInfo.valid())
    {
        return false;
    }

    initFramebuffer(fbInfo.base, fbInfo.width, fbInfo.height, fbInfo.pitch, fbInfo.bpp, fbInfo.isBGR);

    if (!framebufferAvailable())
    {
        return false;
    }

    framebufferBootBanner(bannerMessage);
    return true;
}
