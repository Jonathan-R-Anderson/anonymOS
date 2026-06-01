module boot.multiboot;

@nogc nothrow:

enum MultibootInfoFlag : uint
{
    framebufferInfo = 1u << 12,
}

enum MultibootVideoBackend : ubyte
{
    unknown,
    vbe,
    efiGop,
    drm,
}

struct MultibootFramebufferInfo
{
    void* base;
    uint width;
    uint height;
    uint pitch;
    uint bpp;
    bool isBGR;
    uint modeNumber;
    MultibootVideoBackend backend = MultibootVideoBackend.unknown;

    bool valid() const @nogc nothrow
    {
        return base !is null && width > 0 && height > 0 && pitch > 0 && bpp > 0;
    }
}

struct FramebufferModeRequest
{
    uint preferredWidth;
    uint preferredHeight;
    uint preferredBpp = 32;
    bool allowFallback;
    bool preferDrm = true;
}

struct MultibootInfo
{
    uint flags;
    MultibootFramebufferInfo framebuffer;
}

struct MultibootContext
{
    bool valid;
    MultibootInfo info;

    bool hasFlag(MultibootInfoFlag flag) const @nogc nothrow
    {
        return (info.flags & cast(uint) flag) != 0;
    }
}

MultibootFramebufferInfo selectFramebufferMode(const MultibootInfo info,
                                               FramebufferModeRequest request)
{
    if (!((info.flags & cast(uint) MultibootInfoFlag.framebufferInfo) != 0))
    {
        return MultibootFramebufferInfo.init;
    }

    auto candidate = info.framebuffer;

    if (!candidate.valid())
    {
        return MultibootFramebufferInfo.init;
    }

    if (request.preferredWidth && candidate.width != request.preferredWidth)
    {
        if (!request.allowFallback)
        {
            return MultibootFramebufferInfo.init;
        }
    }

    if (request.preferredHeight && candidate.height != request.preferredHeight)
    {
        if (!request.allowFallback)
        {
            return MultibootFramebufferInfo.init;
        }
    }

    if (request.preferredBpp && candidate.bpp != request.preferredBpp)
    {
        if (!request.allowFallback)
        {
            return MultibootFramebufferInfo.init;
        }
    }

    return cast(MultibootFramebufferInfo)candidate;
}
