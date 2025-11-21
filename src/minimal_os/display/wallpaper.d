module minimal_os.display.wallpaper;

import minimal_os.display.framebuffer : framebufferPutPixel, framebufferAvailable,
    g_fb;
import minimal_os.display.wallpaper_types;

nothrow:
@nogc:

private enum uint fallbackColor = 0xFF202020;

private WallpaperData loadWallpaper()
{
    static if (__traits(compiles, { import minimal_os.display.generated_wallpaper; }))
    {
        import minimal_os.display.generated_wallpaper;
        enum WallpaperData data = WallpaperData(
            wallpaperWidth,
            wallpaperHeight,
            wallpaperFrameDurations,
            wallpaperFrames,
        );
        return data;
    }
    else
    {
        import minimal_os.display.wallpaper_builtin;
        enum WallpaperData data = WallpaperData(
            wallpaperWidth,
            wallpaperHeight,
            wallpaperFrameDurations,
            wallpaperFrames,
        );
        return data;
    }
}

private immutable WallpaperData g_wallpaper = loadWallpaper();

private __gshared size_t g_wallpaperFrameIndex;
private __gshared uint g_wallpaperFrameTick;

WallpaperData wallpaperImage()
{
    return g_wallpaper;
}

private uint frameCount()
{
    return cast(uint) g_wallpaper.frames.length;
}

private uint currentFrameDurationTicks()
{
    if (frameCount() <= 1)
    {
        return 0;
    }

    if (g_wallpaper.frameDurationsMs.length == 0)
    {
        return 1;
    }

    const size_t idx = g_wallpaperFrameIndex % g_wallpaper.frameDurationsMs.length;
    uint durationMs = g_wallpaper.frameDurationsMs[idx];
    if (durationMs == 0)
    {
        durationMs = 100; // Sensible default when GIF delay is missing.
    }

    // Assume a ~60Hz render cadence to approximate the intended animation rate.
    const uint ticks = cast(uint)((durationMs + 15) / 16);
    return ticks == 0 ? 1 : ticks;
}

private const(uint)[] currentFramePixels()
{
    if (frameCount() == 0)
    {
        return null;
    }
    const size_t idx = g_wallpaperFrameIndex % g_wallpaper.frames.length;
    return g_wallpaper.frames[idx];
}

void advanceWallpaperAnimation()
{
    if (frameCount() <= 1)
    {
        return;
    }

    const uint ticksPerFrame = currentFrameDurationTicks();
    ++g_wallpaperFrameTick;
    if (g_wallpaperFrameTick >= ticksPerFrame)
    {
        g_wallpaperFrameTick = 0;
        g_wallpaperFrameIndex = (g_wallpaperFrameIndex + 1) % g_wallpaper.frames.length;
    }
}

/// Sample the wallpaper, scaling to the target surface using nearest neighbour.
uint sampleWallpaper(uint x, uint y, uint targetWidth, uint targetHeight)
{
    auto pixels = currentFramePixels();
    if (pixels is null || pixels.length == 0 || g_wallpaper.width == 0 || g_wallpaper.height == 0)
    {
        return fallbackColor;
    }

    // Clamp to the last pixel in case target dimensions are zero (avoid div by zero).
    if (targetWidth == 0 || targetHeight == 0)
    {
        return fallbackColor;
    }

    const uint srcX = cast(uint)((cast(ulong) x * g_wallpaper.width) / targetWidth);
    const uint srcY = cast(uint)((cast(ulong) y * g_wallpaper.height) / targetHeight);

    const size_t idx = cast(size_t) srcY * g_wallpaper.width + srcX;
    if (idx >= pixels.length)
    {
        return fallbackColor;
    }
    return pixels[idx];
}

void drawWallpaperToFramebuffer()
{
    if (!framebufferAvailable())
    {
        return;
    }

    advanceWallpaperAnimation();

    foreach (y; 0 .. g_fb.height)
    {
        foreach (x; 0 .. g_fb.width)
        {
            auto color = sampleWallpaper(cast(uint) x, cast(uint) y, g_fb.width, g_fb.height);
            framebufferPutPixel(cast(uint) x, cast(uint) y, color);
        }
    }
}

void drawWallpaperToBuffer(uint* buffer, uint surfaceWidth, uint surfaceHeight, uint surfacePitch)
{
    if (buffer is null || surfaceWidth == 0 || surfaceHeight == 0)
    {
        return;
    }

    advanceWallpaperAnimation();

    foreach (y; 0 .. surfaceHeight)
    {
        const size_t rowStart = cast(size_t) y * surfacePitch;
        foreach (x; 0 .. surfaceWidth)
        {
            const size_t index = rowStart + x;
            buffer[index] = sampleWallpaper(cast(uint) x, cast(uint) y, surfaceWidth, surfaceHeight);
        }
    }
}
