module anonymos.multiboot;

import anonymos.display.framebuffer;

/// Helpers and data layouts for interacting with Multiboot loaders.
///
/// The structures mirror the Multiboot 1 specification so that the kernel can
/// safely read memory supplied by GRUB or another compliant bootloader without
/// relying on external libraries.

/// Magic value placed in %eax by a Multiboot-compliant loader when jumping into
/// the kernel entry point.
enum uint multibootLoaderMagic = 0x1BADB002;

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
        cast(void) magic; // magic is informative only; some loaders fail to set it
        if (infoAddress == 0)
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

    /// Retrieve the command line string.
    @nogc pure nothrow
    const(char)[] cmdline() const
    {
        if (!valid || !(info.flags & (1u << 2)))
        {
            return null;
        }

        const char* ptr = ptrFromAddress!char(info.cmdline);
        if (ptr is null) return null;

        // Find length (bounded to avoid infinite loop on bad data)
        size_t len = 0;
        while (len < 1024 && ptr[len] != '\0') len++;

        return ptr[0 .. len];
    }
}

/// Identify which firmware path delivered the framebuffer description.
enum MultibootVideoBackend : ubyte
{
    unknown,
    vbe,
    efiGop,
    drm,
}

/// Optional mode selection parameters passed from higher layers so we can
/// validate or override the bootloader-provided framebuffer info.
struct FramebufferModeRequest
{
    uint   desiredWidth;
    uint   desiredHeight;
    uint   desiredBpp;
    ushort desiredModeNumber;
    bool   allowFallback = true; // accept bootloader defaults when the request cannot be met
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
    ushort modeNumber;
    MultibootVideoBackend backend;

    @nogc @safe pure nothrow
    bool valid() const
    {
        return base !is null && width > 0 && height > 0 && bpp > 0;
    }
}

align(1) struct VbeModeInfo
{
    ushort attributes;
    ubyte  winA, winB;
    ushort granularity;
    ushort winsize;
    ushort segmentA, segmentB;
    uint   realFctPtr;
    ushort pitch; // bytes per scanline
    ushort width, height;
    ubyte  wChar, yChar, planes, bpp, banks;
    ubyte  memoryModel, bankSize, imagePages;
    ubyte  reserved0;

    ubyte  redMaskSize, redFieldPosition;
    ubyte  greenMaskSize, greenFieldPosition;
    ubyte  blueMaskSize, blueFieldPosition;
    ubyte  rsvdMaskSize, rsvdFieldPosition;
    ubyte  directColorModeInfo;

    uint   physBasePtr;
    uint   reserved1;
    ushort reserved2;
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
    fbInfo.modeNumber = mbi.vbeMode;
    fbInfo.backend = (mbi.vbeControlInfo != 0 || mbi.vbeModeInfo != 0) ? MultibootVideoBackend.vbe : MultibootVideoBackend.efiGop;

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

    // Validate that the loader didn't hand us a bogus pitch/bpp combination.
    if (!framebufferModeSupported(fbInfo.base, fbInfo.width, fbInfo.height, fbInfo.pitch, fbInfo.bpp))
    {
        fbInfo.base = null;
    }

    return fbInfo;
}

/// Try to reinterpret the VBE mode info block when Multiboot provided one. This
/// helps us reconstruct the mode when the loader didn't populate the generic
/// framebuffer fields (common with older BIOS VBE paths).
MultibootFramebufferInfo framebufferInfoFromVbe(const MultibootInfo* mbi) @nogc nothrow @system
{
    MultibootFramebufferInfo fbInfo;
    if (mbi is null || mbi.vbeModeInfo == 0)
    {
        return fbInfo;
    }

    const VbeModeInfo* modeInfo = cast(const VbeModeInfo*) mbi.vbeModeInfo;
    fbInfo.base       = cast(void*) modeInfo.physBasePtr;
    fbInfo.width      = modeInfo.width;
    fbInfo.height     = modeInfo.height;
    fbInfo.pitch      = modeInfo.pitch;
    fbInfo.bpp        = modeInfo.bpp;
    fbInfo.modeNumber = mbi.vbeMode;
    fbInfo.backend    = MultibootVideoBackend.vbe;

    const ubyte redPosition  = modeInfo.redFieldPosition;
    const ubyte bluePosition = modeInfo.blueFieldPosition;
    fbInfo.isBGR = (redPosition == 16 && bluePosition == 0);

    if (!framebufferModeSupported(fbInfo.base, fbInfo.width, fbInfo.height, fbInfo.pitch, fbInfo.bpp))
    {
        fbInfo.base = null;
    }

    return fbInfo;
}

/// Choose which framebuffer mode to expose based on the bootloader tables and a
/// requested mode from higher layers.
MultibootFramebufferInfo selectFramebufferMode(const MultibootInfo* mbi, FramebufferModeRequest request) @nogc nothrow @system
{
    // Prefer the generic Multiboot framebuffer description first.
    auto fbInfo = framebufferInfoFromMultiboot(mbi);

    // If a specific mode is requested, attempt to validate it before falling
    // back to whatever the bootloader set.
    bool requestHasDims = request.desiredWidth != 0 && request.desiredHeight != 0 && request.desiredBpp != 0;
    if (requestHasDims && fbInfo.valid())
    {
        if (fbInfo.width != request.desiredWidth ||
            fbInfo.height != request.desiredHeight ||
            fbInfo.bpp != request.desiredBpp)
        {
            fbInfo.base = null; // force fallback path
        }
    }

    if (fbInfo.valid())
    {
        // Honor an explicit mode number mismatch if requested.
        if (request.desiredModeNumber != 0 && fbInfo.modeNumber != 0 && fbInfo.modeNumber != request.desiredModeNumber)
        {
            fbInfo.base = null;
        }
    }

    if (!fbInfo.valid())
    {
        // See if the firmware left VBE mode info around that satisfies the request.
        auto vbeInfo = framebufferInfoFromVbe(mbi);
        if (vbeInfo.valid())
        {
            bool matches = true;
            if (request.desiredModeNumber != 0 && vbeInfo.modeNumber != 0)
            {
                matches = (vbeInfo.modeNumber == request.desiredModeNumber);
            }

            if (matches && requestHasDims)
            {
                matches = vbeInfo.width == request.desiredWidth &&
                          vbeInfo.height == request.desiredHeight &&
                          vbeInfo.bpp == request.desiredBpp;
            }

            if (matches || request.allowFallback)
            {
                return vbeInfo;
            }
        }
    }

    // Either the Multiboot framebuffer was already good, or we could not do
    // better than whatever the loader provided.
    return fbInfo;
}

/// Initialize the framebuffer using Multiboot info and display a banner.
bool initVideoFromMultiboot(const MultibootInfo* mbi, const(char)[] bannerMessage = "minimal_os framebuffer online") @nogc nothrow @system
{
    const fbInfo = selectFramebufferMode(mbi, FramebufferModeRequest.init);
    if (!fbInfo.valid())
    {
        return false;
    }

    initFramebuffer(fbInfo.base, fbInfo.width, fbInfo.height, fbInfo.pitch, fbInfo.bpp, fbInfo.isBGR, fbInfo.modeNumber, true);

    if (!framebufferAvailable())
    {
        return false;
    }

    framebufferBootBanner(bannerMessage);
    return true;
}
