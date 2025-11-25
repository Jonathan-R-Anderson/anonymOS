module minimal_os.display.gpu_accel;

import core.stdc.string : memcpy;
import minimal_os.display.framebuffer;
import minimal_os.display.modesetting : ModesetResult;

@nogc nothrow:

/// Simple set of acceleration hooks that mirror what a DRM/KMS driver would
/// expose for fast 2D paths. The helpers operate directly on the mapped linear
/// framebuffer, so they remain safe for firmware-provided GOP/VBE scanout too.
struct GpuAcceleration
{
    bool available;
    bool fastFill;
    bool fastBlit;
}

private __gshared GpuAcceleration g_accel;

/// Configure the acceleration flags based on the modeset result. DRM/GOP paths
/// are preferred because they imply a linear framebuffer with sane pitch.
void configureAccelerationFromModeset(const ModesetResult result)
{
    g_accel.available = framebufferAvailable();
    g_accel.fastFill = result.accelerationPreferred && g_fb.bpp == 32 && g_fb.pitch % 4 == 0;
    g_accel.fastBlit = g_accel.fastFill;
}

GpuAcceleration accelerationState()
{
    return g_accel;
}

/// Accelerated clear of the entire framebuffer. Returns true when the fast path
/// was used so callers can fall back otherwise.
bool acceleratedFill(uint argbColor)
{
    if (!g_accel.available || !g_accel.fastFill)
    {
        return false;
    }

    const size_t totalPixels = cast(size_t) g_fb.pitch * g_fb.height / 4;
    uint* dst = cast(uint*) g_fb.addr;
    if (dst is null)
    {
        return false;
    }

    foreach (i; 0 .. totalPixels)
    {
        dst[i] = argbColor;
    }
    return true;
}

/// Accelerated rectangle fill for framebuffer-backed canvases.
bool acceleratedFillRect(uint x, uint y, uint w, uint h, uint argbColor)
{
    if (!g_accel.available || !g_accel.fastFill || w == 0 || h == 0)
    {
        return false;
    }

    if (x >= g_fb.width || y >= g_fb.height)
    {
        return false;
    }

    const uint xEnd = (x + w > g_fb.width) ? g_fb.width : x + w;
    const uint yEnd = (y + h > g_fb.height) ? g_fb.height : y + h;

    uint* base = cast(uint*) g_fb.addr;
    const uint wordsPerRow = g_fb.pitch / 4;

    foreach (row; y .. yEnd)
    {
        uint* dst = base + row * wordsPerRow + x;
        foreach (col; x .. xEnd)
        {
            dst[col - x] = argbColor;
        }
    }
    return true;
}

/// Accelerated copy of an ARGB buffer to the linear framebuffer.
bool acceleratedPresentBuffer(const(uint)* src, uint width, uint height, uint pitch)
{
    return false; // DEBUG: Disable acceleration to test fallback
    if (!g_accel.available || !g_accel.fastBlit || src is null)
    {
        return false;
    }

    if (width != g_fb.width || height != g_fb.height)
    {
        return false;
    }

    const uint dstPitchBytes = g_fb.pitch;
    const uint srcPitchBytes = pitch * 4;
    foreach (row; 0 .. height)
    {
        const(uint)* srcRow = src + row * pitch;
        uint* dstRow = cast(uint*)(g_fb.addr + row * dstPitchBytes);
        memcpy(dstRow, srcRow, srcPitchBytes);
    }
    return true;
}
