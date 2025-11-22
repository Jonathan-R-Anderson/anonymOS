module minimal_os.display.modesetting;

import minimal_os.console : printLine, print, printUnsigned;
import minimal_os.display.framebuffer;
import minimal_os.multiboot;

@nogc nothrow:

/// Describe the active scanout backend so higher layers can adapt (e.g. prefer
/// GPU-accelerated blits when a DRM device is in control).
struct ModesetResult
{
    bool framebufferReady;
    MultibootFramebufferInfo fbInfo;
    MultibootVideoBackend backendUsed = MultibootVideoBackend.unknown;
    bool accelerationPreferred; /// true when a DRM-like path was chosen
}

/// Attempt to enable a DRM/KMS framebuffer first, falling back to the loader's
/// firmware mode and finally to a Bochs/QEMU-compatible VBE mode.
ModesetResult enableDisplayPipeline(const MultibootContext context,
                                    FramebufferModeRequest request) @system
{
    ModesetResult result;
    if (!context.valid)
    {
        return result;
    }

    // 1) Prefer explicit DRM/KMS handoff if the bootloader provided one.
    if (context.hasFlag(MultibootInfoFlag.framebufferInfo))
    {
        auto drmFirst = selectFramebufferMode(context.info, request);
        if (drmFirst.valid())
        {
            result.framebufferReady = initFramebufferWithInfo(drmFirst, true);
            result.fbInfo = drmFirst;
            result.backendUsed = drmFirst.backend;
            result.accelerationPreferred = drmFirst.backend == MultibootVideoBackend.drm;
            if (result.framebufferReady)
            {
                return result;
            }
        }
    }

    // 2) Retry with firmware/VBE tables even if DRM failed validation.
    if (context.hasFlag(MultibootInfoFlag.framebufferInfo))
    {
        FramebufferModeRequest relaxed = request;
        relaxed.allowFallback = true;
        auto fbInfo = selectFramebufferMode(context.info, relaxed);
        if (fbInfo.valid())
        {
            result.framebufferReady = initFramebufferWithInfo(fbInfo, true);
            result.fbInfo = fbInfo;
            result.backendUsed = fbInfo.backend;
            result.accelerationPreferred = fbInfo.backend == MultibootVideoBackend.drm ||
                                           fbInfo.backend == MultibootVideoBackend.efiGop;
            if (result.framebufferReady)
            {
                return result;
            }
        }
    }

    // 3) Hard fallback: program a Bochs VBE-compatible mode directly.
    enum fallbackWidth  = 1024u;
    enum fallbackHeight = 768u;
    enum fallbackBpp    = 32u;

    printLine("[modeset] Falling back to Bochs/QEMU VBE 1024x768x32...");
    const bool bochsEnabled = enableBochsVbeMode(fallbackWidth, fallbackHeight, fallbackBpp);
    if (bochsEnabled)
    {
        auto fbInfo = MultibootFramebufferInfo(
            cast(void*)0xE0000000,
            fallbackWidth,
            fallbackHeight,
            fallbackWidth * (fallbackBpp / 8),
            fallbackBpp,
            false,
            0,
            MultibootVideoBackend.vbe
        );

        result.framebufferReady = initFramebufferWithInfo(fbInfo, false);
        result.fbInfo = fbInfo;
        result.backendUsed = fbInfo.backend;
    }

    return result;
}

/// Small helper to feed a validated framebuffer description into the low level
/// framebuffer module and log the active mode.
private bool initFramebufferWithInfo(const MultibootFramebufferInfo fbInfo, bool fromFirmware)
{
    initFramebuffer(fbInfo.base, fbInfo.width, fbInfo.height, fbInfo.pitch, fbInfo.bpp, fbInfo.isBGR, fbInfo.modeNumber, fromFirmware);

    if (!framebufferAvailable())
    {
        return false;
    }

    logActiveFramebuffer(fbInfo, fromFirmware);
    framebufferBootBanner("minimal_os is booting...");
    return true;
}

private void logActiveFramebuffer(const MultibootFramebufferInfo fbInfo, bool fromFirmware)
{
    print("[modeset] Framebuffer configured: ");
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

/// Minimal Bochs/QEMU VBE programming path used when no framebuffer was
/// handed off by firmware. This mirrors the previous kernel-side helper but is
/// colocated with modesetting now.
private bool enableBochsVbeMode(uint width, uint height, uint bpp)
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

    // Disable while reprogramming the registers.
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

    return framebufferAvailable();
}

private void dispiWrite(ushort indexPort, ushort dataPort, ushort reg, ushort value)
{
    asm @nogc nothrow
    {
        mov DX, indexPort;
        mov AX, reg;
        out DX, AX;
        mov DX, dataPort;
        mov AX, value;
        out DX, AX;
    }
}

private ushort dispiRead(ushort indexPort, ushort dataPort, ushort reg)
{
    asm @nogc nothrow
    {
        mov DX, indexPort;
        mov AX, reg;
        out DX, AX;
        mov DX, dataPort;
        in  AX, DX;
    }
}
