module minimal_os.display.canvas;

import minimal_os.display.framebuffer;

/// Basic 2D canvas abstraction layered on top of the existing framebuffer
/// helpers. This is intentionally light-weight so that callers can express
/// higher-level drawing intent without being tied to pixel routines.
struct Canvas
{
    uint width;
    uint height;
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
    }
    return canvas;
}

/// Fill the entire canvas with a solid color.
void canvasFill(ref Canvas canvas, uint argbColor) @nogc nothrow
{
    if (!canvas.available)
    {
        return;
    }
    framebufferFill(argbColor);
}

/// Draw a rectangle with optional fill using framebuffer helpers.
void canvasRect(ref Canvas canvas, uint x, uint y, uint w, uint h, uint argbColor, bool filled = true) @nogc nothrow
{
    if (!canvas.available)
    {
        return;
    }
    framebufferDrawRect(x, y, w, h, argbColor, filled);
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
    framebufferSetTextColors(fg, bg);
    framebufferWriteString(text);
}
