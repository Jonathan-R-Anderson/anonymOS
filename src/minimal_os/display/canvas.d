module minimal_os.display.canvas;

import minimal_os.display.framebuffer;

/// Basic 2D canvas abstraction layered on top of the existing framebuffer
/// helpers. This is intentionally light-weight so that callers can express
/// higher-level drawing intent without being tied to pixel routines.
struct Canvas
{
    uint width;
    uint height;
    uint pitch;
    uint* pixels;
    bool targetsFramebuffer;
    bool available;
}

/// Build a canvas that maps directly to the linear framebuffer.
Canvas createFramebufferCanvas() @nogc nothrow
{
    Canvas canvas;
    canvas.available = framebufferAvailable();
    if (canvas.available)
    {
        canvas.width = g_fb.width;
        canvas.height = g_fb.height;
        canvas.pitch = (g_fb.bpp > 0) ? g_fb.pitch / (g_fb.bpp / 8) : 0;
        canvas.pixels = cast(uint*) g_fb.addr;
        canvas.targetsFramebuffer = true;
    }
    return canvas;
}

/// Build a canvas around an existing ARGB pixel buffer.
Canvas createBufferCanvas(uint* pixels, uint width, uint height, uint pitch) @nogc nothrow
{
    Canvas canvas;
    if (pixels is null || width == 0 || height == 0)
    {
        return canvas;
    }

    canvas.width = width;
    canvas.height = height;
    canvas.pitch = pitch;
    canvas.pixels = pixels;
    canvas.targetsFramebuffer = false;
    canvas.available = true;
    return canvas;
}

/// Fill the entire canvas with a solid color.
void canvasFill(ref Canvas canvas, uint argbColor) @nogc nothrow
{
    if (!canvas.available)
    {
        return;
    }

    if (canvas.targetsFramebuffer)
    {
        framebufferFill(argbColor);
        return;
    }

    if (canvas.pixels is null || canvas.pitch == 0)
    {
        return;
    }

    foreach (y; 0 .. canvas.height)
    {
        const rowOffset = y * canvas.pitch;
        foreach (x; 0 .. canvas.width)
        {
            canvas.pixels[rowOffset + x] = argbColor;
        }
    }
}

/// Draw a rectangle with optional fill using framebuffer helpers.
void canvasRect(ref Canvas canvas, uint x, uint y, uint w, uint h, uint argbColor, bool filled = true) @nogc nothrow
{
    if (!canvas.available)
    {
        return;
    }

    if (canvas.targetsFramebuffer)
    {
        framebufferDrawRect(x, y, w, h, argbColor, filled);
        return;
    }

    if (canvas.pixels is null || canvas.pitch == 0 || w == 0 || h == 0)
    {
        return;
    }

    const uint xEnd = x + w;
    const uint yEnd = y + h;

    foreach (yy; y .. yEnd)
    {
        if (yy >= canvas.height)
        {
            break;
        }

        foreach (xx; x .. xEnd)
        {
            if (xx >= canvas.width)
            {
                break;
            }

            if (!filled && xx > x && xx < xEnd - 1 && yy > y && yy < yEnd - 1)
            {
                continue;
            }

            canvas.pixels[yy * canvas.pitch + xx] = argbColor;
        }
    }
}

/// Render text using the framebuffer's glyph path. The text is written at the
/// current framebuffer cursor; a more advanced text API can later hook into a
/// font stack and positioning system.
void canvasText(ref Canvas canvas, const(char)[] text, uint fg, uint bg) @nogc nothrow
{
    if (!canvas.available)
    {
        return;
    }

    if (!canvas.targetsFramebuffer)
    {
        // Text rendering against off-screen canvas is not yet implemented.
        return;
    }

    framebufferSetTextColors(fg, bg);
    framebufferWriteString(text);
}
