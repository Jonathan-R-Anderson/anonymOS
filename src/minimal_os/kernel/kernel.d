module minimal_os.kernel.kernel;

public import minimal_os.kernel.memory;

import minimal_os.display.framebuffer;
import minimal_os.console : clearScreen, print, printLine, printStageHeader, printUnsigned;
import minimal_os.serial : initSerial;
import minimal_os.hardware : probeHardware;
import minimal_os.multiboot : MultibootInfoFlag, selectFramebufferMode, FramebufferModeRequest, MultibootFramebufferInfo, MultibootVideoBackend, MultibootContext;
import minimal_os.display.desktop : desktopProcessEntry, runSimpleDesktopOnce;
import minimal_os.posix : posixInit, registerProcessExecutable, spawnRegisteredProcess,
    schedYield, initializeInterrupts, ProcessEntry;
import minimal_os.kernel.shell_integration : compilerBuilderProcessEntry;

/// Entry point invoked from boot.s once the CPU is ready to run D code.
/// Initialises the VGA output and runs the compiler build program.
extern(C) void kmain(ulong magic, ulong info)
{
    cast(void) magic;
    cast(void) info;

    clearScreen();
    initSerial();
    auto context = probeHardware(magic, info);

    bool framebufferReady = false;

    framebufferReady = tryEnableFirmwareFramebuffer(context);
    if (!framebufferReady)
    {
        framebufferReady = tryEnableFallbackFramebuffer();
    }

    // If no framebuffer, inform user that shell will be available via serial
    if (!framebufferReady)
    {
        printLine("");
        printLine("========================================");
        printLine("  No Framebuffer Detected");
        printLine("========================================");
        printLine("Graphics desktop is unavailable.");
        printLine("The lfe-sh shell will be accessible");
        printLine("via serial console after toolchain build.");
        printLine("");
        printLine("Connect via: -serial stdio (QEMU)");
        printLine("========================================");
        printLine("");
    }

    initializeInterrupts();

    posixInit();

    // Register processes that should run alongside the kernel core.
    version (MinimalOsUserlandLinked)
    {
        ProcessEntry builderEntry = &compilerBuilderProcessEntry;
        const int builderRegistration = registerProcessExecutable(
            "/sbin/compiler-builder",
            builderEntry
        );
        if (builderRegistration == 0)
        {
            cast(void) spawnRegisteredProcess("/sbin/compiler-builder", null, null);
        }
    }
    else
    {
        printLine("[kernel] Compiler builder disabled (MinimalOsUserlandLinked not set)");
    }

    // Only spawn desktop if framebuffer is available
    if (framebufferReady)
    {
        const int desktopRegistration = registerProcessExecutable("/sbin/desktop",
            &desktopProcessEntry);
        if (desktopRegistration == 0)
        {
            cast(void) spawnRegisteredProcess("/sbin/desktop", null, null);
        }
    }
    else
    {
        printLine("[kernel] Graphics desktop disabled - framebuffer unavailable");
        printLine("[kernel] Serial shell will be available after build completes");
        printLine("");
    }

    // Idle the kernel while co-operative tasks (desktop, compiler, shell) run.
    while (true)
    {
        schedYield();
        asm { hlt; }
    }
}

private @nogc nothrow bool tryEnableFirmwareFramebuffer(const MultibootContext context)
{
    if (!context.valid || !context.hasFlag(MultibootInfoFlag.framebufferInfo))
    {
        return false;
    }

    FramebufferModeRequest fbRequest;
    fbRequest.desiredWidth  = 1024;
    fbRequest.desiredHeight = 768;
    fbRequest.desiredBpp    = 32;
    fbRequest.desiredModeNumber = context.info.vbeMode;
    fbRequest.allowFallback = true;

    const fbInfo = selectFramebufferMode(context.info, fbRequest);
    if (!fbInfo.valid())
    {
        return false;
    }

    initFramebuffer(fbInfo.base, fbInfo.width, fbInfo.height, fbInfo.pitch, fbInfo.bpp, fbInfo.isBGR, fbInfo.modeNumber, true);

    if (!framebufferAvailable())
    {
        return false;
    }

    logActiveFramebuffer(fbInfo, true);
    framebufferBootBanner("minimal_os is booting...");
    runSimpleDesktopOnce();
    return true;
}

private @nogc nothrow bool tryEnableFallbackFramebuffer()
{
    // Attempt to bring up a Bochs/QEMU-compatible VBE framebuffer if the
    // boot firmware did not hand one to us.
    printLine("[kernel] No firmware framebuffer - attempting Bochs/QEMU fallback...");

    enum fallbackWidth  = 1024u;
    enum fallbackHeight = 768u;
    enum fallbackBpp    = 32u;

    const bool modeEnabled = enableBochsVbeMode(fallbackWidth, fallbackHeight, fallbackBpp);
    if (!modeEnabled)
    {
        printLine("[kernel] Fallback framebuffer setup failed.");
        return false;
    }

    const MultibootFramebufferInfo fbInfo = MultibootFramebufferInfo(
        cast(void*)0xE0000000,
        fallbackWidth,
        fallbackHeight,
        fallbackWidth * (fallbackBpp / 8),
        fallbackBpp,
        false,
        0,
        MultibootVideoBackend.vbe
    );

    logActiveFramebuffer(fbInfo, false);
    framebufferBootBanner("minimal_os is booting...");
    runSimpleDesktopOnce();
    return true;
}

private @nogc nothrow void logActiveFramebuffer(const MultibootFramebufferInfo fbInfo, bool fromFirmware)
{
    print("[kernel] Framebuffer detected: ");
    printUnsigned(fbInfo.width);
    print("x");
    printUnsigned(fbInfo.height);
    print("x");
    printUnsigned(fbInfo.bpp);
    print(" @ ");
    printUnsigned(fbInfo.pitch);
    print(fromFirmware ? " (firmware)" : " (fallback)");
    printLine("");
}

private @nogc nothrow bool enableBochsVbeMode(uint width, uint height, uint bpp)
{
    // Sanity check that dimensions fit the 16-bit register interface.
    if (width == 0 || width > ushort.max || height == 0 || height > ushort.max || bpp > ushort.max)
    {
        return false;
    }

    enum ushort VBE_DISPI_IOPORT_INDEX = 0x1CE;
    enum ushort VBE_DISPI_IOPORT_DATA  = 0x1CF;
    enum ushort VBE_DISPI_INDEX_ID     = 0;
    enum ushort VBE_DISPI_INDEX_XRES   = 1;
    enum ushort VBE_DISPI_INDEX_YRES   = 2;
    enum ushort VBE_DISPI_INDEX_BPP    = 3;
    enum ushort VBE_DISPI_INDEX_ENABLE = 4;
    enum ushort VBE_DISPI_INDEX_BANK   = 5;
    enum ushort VBE_DISPI_INDEX_VIRT_WIDTH  = 6;
    enum ushort VBE_DISPI_INDEX_VIRT_HEIGHT = 7;
    enum ushort VBE_DISPI_INDEX_X_OFFSET    = 8;
    enum ushort VBE_DISPI_INDEX_Y_OFFSET    = 9;

    enum ushort VBE_DISPI_ID4 = 0xB0C4;
    enum ushort VBE_DISPI_ID5 = 0xB0C5;
    enum ushort VBE_DISPI_ENABLED    = 0x01;
    enum ushort VBE_DISPI_LFB_ENABLE = 0x40;

    const ushort id = dispiRead(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_IOPORT_DATA, VBE_DISPI_INDEX_ID);
    if (id != VBE_DISPI_ID5 && id != VBE_DISPI_ID4)
    {
        return false;
    }

    dispiWrite(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_IOPORT_DATA, VBE_DISPI_INDEX_ENABLE, 0);
    dispiWrite(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_IOPORT_DATA, VBE_DISPI_INDEX_XRES, cast(ushort)width);
    dispiWrite(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_IOPORT_DATA, VBE_DISPI_INDEX_YRES, cast(ushort)height);
    dispiWrite(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_IOPORT_DATA, VBE_DISPI_INDEX_BPP, cast(ushort)bpp);
    dispiWrite(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_IOPORT_DATA, VBE_DISPI_INDEX_VIRT_WIDTH, cast(ushort)width);
    dispiWrite(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_IOPORT_DATA, VBE_DISPI_INDEX_VIRT_HEIGHT, cast(ushort)height);
    dispiWrite(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_IOPORT_DATA, VBE_DISPI_INDEX_X_OFFSET, 0);
    dispiWrite(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_IOPORT_DATA, VBE_DISPI_INDEX_Y_OFFSET, 0);
    dispiWrite(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_IOPORT_DATA, VBE_DISPI_INDEX_BANK, 0);
    dispiWrite(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_IOPORT_DATA, VBE_DISPI_INDEX_ENABLE, VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLE);

    const uint pitch = width * (bpp / 8);
    initFramebuffer(cast(void*)0xE0000000, width, height, pitch, bpp, false, 0, false);
    return framebufferAvailable();
}

private @nogc nothrow void dispiWrite(ushort portIndex, ushort portData, ushort index, ushort value)
{
    outw(portIndex, index);
    outw(portData, value);
}

private @nogc nothrow ushort dispiRead(ushort portIndex, ushort portData, ushort index)
{
    outw(portIndex, index);
    return inw(portData);
}

private @nogc nothrow void outw(ushort port, ushort value)
{
    asm @nogc nothrow
    {
        mov DX, port;
        mov AX, value;
        out DX, AX;
    }
}

private @nogc nothrow ushort inw(ushort port)
{
    ushort value;
    asm @nogc nothrow
    {
        mov DX, port;
        in  AX, DX;
        mov value, AX;
    }
    return value;
}
