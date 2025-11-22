module minimal_os.display.canvas;

import minimal_os.display.font_stack;
import minimal_os.display.framebuffer;
import core.stdc.string : memcmp;

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

private enum size_t maxCachedRuns = 8;
private enum size_t maxGlyphsPerRun = 128;
private enum size_t maxCachedTextLength = 256;

private struct ShapedGlyph
{
    ubyte[glyphWidth * glyphHeight] mask;
    uint advance;
}

private struct ShapedRun
{
    ShapedGlyph[maxGlyphsPerRun] glyphs;
    size_t count;
    uint width;
}

private struct CachedRun
{
    char[maxCachedTextLength] text;
    size_t length;
    ShapedRun run;
}

private __gshared CachedRun[maxCachedRuns] g_cachedRuns;
private __gshared size_t g_cacheCursor;

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

private size_t decodeUTF8(const(char)[] text, size_t index, out dchar codepoint) @nogc nothrow
{
    if (index >= text.length)
    {
        return 0;
    }

    const ubyte first = cast(ubyte) text[index];
    if (first < 0x80)
    {
        codepoint = first;
        return 1;
    }
    if ((first & 0xE0) == 0xC0 && index + 1 < text.length)
    {
        codepoint = ((first & 0x1F) << 6) | (cast(ubyte) text[index + 1] & 0x3F);
        return 2;
    }
    if ((first & 0xF0) == 0xE0 && index + 2 < text.length)
    {
        codepoint = ((first & 0x0F) << 12) |
                    ((cast(ubyte) text[index + 1] & 0x3F) << 6) |
                    (cast(ubyte) text[index + 2] & 0x3F);
        return 3;
    }
    if ((first & 0xF8) == 0xF0 && index + 3 < text.length)
    {
        codepoint = ((first & 0x07) << 18) |
                    ((cast(ubyte) text[index + 1] & 0x3F) << 12) |
                    ((cast(ubyte) text[index + 2] & 0x3F) << 6) |
                    (cast(ubyte) text[index + 3] & 0x3F);
        return 4;
    }

    // Invalid byte sequence.
    codepoint = 0xFFFD;
    return 1;
}

private const(ShapedRun)* lookupCachedRun(const(char)[] text) @nogc nothrow
{
    foreach (ref entry; g_cachedRuns)
    {
        if (entry.length == 0 || entry.length != text.length)
        {
            continue;
        }

        if (memcmp(entry.text.ptr, text.ptr, entry.length) == 0)
        {
            return &entry.run;
        }
    }

    return null;
}

private const(ShapedRun)* storeCachedRun(const(char)[] text, const ShapedRun* run) @nogc nothrow
{
    if (run is null)
    {
        return null;
    }

    CachedRun* slot = &g_cachedRuns[g_cacheCursor % maxCachedRuns];
    ++g_cacheCursor;

    const size_t len = (text.length < maxCachedTextLength) ? text.length : maxCachedTextLength - 1;
    slot.length = len;
    foreach (i; 0 .. len)
    {
        slot.text[i] = text[i];
    }
    if (len < slot.text.length)
    {
        slot.text[len] = '\0';
    }

    slot.run = *run;
    return &slot.run;
}

private const(ShapedRun)* shapeRun(const(FontStack)* stack, const(char)[] text) @nogc nothrow
{
    if (text.length == 0)
    {
        return null;
    }

    if (auto cached = lookupCachedRun(text))
    {
        return cached;
    }

    ShapedRun run;
    size_t cursor;
    while (cursor < text.length && run.count < maxGlyphsPerRun)
    {
        dchar cp;
        const consumed = decodeUTF8(text, cursor, cp);
        if (consumed == 0)
        {
            break;
        }

        cursor += consumed;
        auto glyph = &run.glyphs[run.count];
        if (!glyphMaskFromStack(stack, cp, glyph.mask))
        {
            continue;
        }
        glyph.advance = glyphWidth;
        ++run.count;
        run.width += glyph.advance;
    }

    if (run.count == 0)
    {
        return null;
    }

    return storeCachedRun(text, &run);
}

private void canvasBlitMask(ref Canvas canvas, uint dstX, uint dstY,
                            const(ubyte)* mask,
                            uint maskWidth, uint maskHeight,
                            uint maskStride,
                            uint fgARGB, uint bgARGB,
                            bool useBg) @nogc nothrow
{
    if (!canvas.available || mask is null || maskWidth == 0 || maskHeight == 0)
    {
        return;
    }

    if (canvas.targetsFramebuffer)
    {
        framebufferBlitMask(dstX, dstY, mask, maskWidth, maskHeight, maskStride, fgARGB, bgARGB, useBg);
        return;
    }

    if (canvas.pixels is null || canvas.pitch == 0)
    {
        return;
    }

    if (dstX >= canvas.width || dstY >= canvas.height)
    {
        return;
    }

    uint maxW = canvas.width - dstX;
    uint maxH = canvas.height - dstY;
    uint blitW = (maskWidth < maxW) ? maskWidth : maxW;
    uint blitH = (maskHeight < maxH) ? maskHeight : maxH;

    foreach (row; 0 .. blitH)
    {
        const(ubyte)* srcRow = mask + row * maskStride;
        const uint dstOffset = (dstY + row) * canvas.pitch + dstX;
        foreach (col; 0 .. blitW)
        {
            const ubyte m = srcRow[col];
            if (m == 0 && !useBg)
            {
                continue;
            }
            const uint color = (m == 0) ? bgARGB : fgARGB;
            canvas.pixels[dstOffset + col] = color;
        }
    }
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

/// Render UTF-8 text to the canvas using the shared font stack. Returns the
/// horizontal advance of the rendered run so callers can chain draws when
/// building UI layouts.
uint canvasText(ref Canvas canvas, const(FontStack)* stack, uint x, uint y, const(char)[] text, uint fg, uint bg, bool opaqueBg = true) @nogc nothrow
{
    if (stack is null)
    {
        stack = activeFontStack();
    }

    if (!canvas.available || !fontStackReady(stack))
    {
        return 0;
    }

    const run = shapeRun(stack, text);
    if (run is null)
    {
        return 0;
    }

    uint cursorX = x;
    foreach (i; 0 .. run.count)
    {
        const auto glyph = &run.glyphs[i];
        canvasBlitMask(canvas, cursorX, y, glyph.mask.ptr, glyphWidth, glyphHeight, glyphWidth, fg, bg, opaqueBg);
        cursorX += glyph.advance;
    }

    return run.width;
}
