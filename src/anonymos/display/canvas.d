module anonymos.display.canvas;

import anonymos.display.font_stack;
import anonymos.display.framebuffer;
import anonymos.display.gpu_accel : acceleratedFill, acceleratedFillRect;
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
    int clipX, clipY, clipW, clipH;
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
        canvas.clipX = 0;
        canvas.clipY = 0;
        canvas.clipW = g_fb.width;
        canvas.clipH = g_fb.height;
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
    canvas.clipX = 0;
    canvas.clipY = 0;
    canvas.clipW = width;
    canvas.clipH = height;
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
        uint advance;
        if (!glyphMaskFromStack(stack, cp, glyph.mask, advance))
        {
            continue;
        }
        glyph.advance = advance;
        ++run.count;
        run.width += glyph.advance;
    }

    if (run.count == 0)
    {
        return null;
    }

    return storeCachedRun(text, &run);
}

/// Set the clipping rectangle for subsequent draw operations.
void canvasSetClip(ref Canvas canvas, int x, int y, int w, int h) @nogc nothrow
{
    // Intersect with canvas bounds
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    
    if (x >= cast(int)canvas.width) { x = canvas.width; w = 0; }
    if (y >= cast(int)canvas.height) { y = canvas.height; h = 0; }
    
    if (x + w > cast(int)canvas.width) w = canvas.width - x;
    if (y + h > cast(int)canvas.height) h = canvas.height - y;
    
    canvas.clipX = x;
    canvas.clipY = y;
    canvas.clipW = w;
    canvas.clipH = h;
}

/// Reset clipping to the full canvas size.
void canvasResetClip(ref Canvas canvas) @nogc nothrow
{
    canvas.clipX = 0;
    canvas.clipY = 0;
    canvas.clipW = canvas.width;
    canvas.clipH = canvas.height;
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

    // Clip against canvas.clip*
    int cx = canvas.clipX;
    int cy = canvas.clipY;
    int cw = canvas.clipW;
    int ch = canvas.clipH;
    
    // Intersection of (dstX, dstY, maskWidth, maskHeight) and (cx, cy, cw, ch)
    int x1 = cast(int)dstX;
    int y1 = cast(int)dstY;
    int x2 = x1 + cast(int)maskWidth;
    int y2 = y1 + cast(int)maskHeight;
    
    int ix1 = (x1 > cx) ? x1 : cx;
    int iy1 = (y1 > cy) ? y1 : cy;
    int ix2 = (x2 < cx + cw) ? x2 : cx + cw;
    int iy2 = (y2 < cy + ch) ? y2 : cy + ch;
    
    if (ix1 >= ix2 || iy1 >= iy2) return; // Fully clipped
    
    // Adjust mask pointer
    int skipX = ix1 - x1;
    int skipY = iy1 - y1;
    
    const(ubyte)* clippedMask = mask + (skipY * maskStride) + skipX;
    
    // New dimensions
    uint drawW = ix2 - ix1;
    uint drawH = iy2 - iy1;

    if (canvas.targetsFramebuffer)
    {
        framebufferBlitMask(ix1, iy1, clippedMask, drawW, drawH, maskStride, fgARGB, bgARGB, useBg);
        return;
    }

    if (canvas.pixels is null || canvas.pitch == 0)
    {
        return;
    }

    // Software blit using clipped coordinates
    foreach (row; 0 .. drawH)
    {
        const(ubyte)* srcRow = clippedMask + row * maskStride;
        const uint dstOffset = (iy1 + row) * canvas.pitch + ix1;
        foreach (col; 0 .. drawW)
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
        if (!acceleratedFill(argbColor))
        {
            framebufferFill(argbColor);
        }
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
/// Draw a rectangle with optional fill using framebuffer helpers.
void canvasRect(ref Canvas canvas, uint x, uint y, uint w, uint h, uint argbColor, bool filled = true) @nogc nothrow
{
    if (!canvas.available)
    {
        return;
    }

    // Clip rect
    int x1 = cast(int)x;
    int y1 = cast(int)y;
    int x2 = x1 + cast(int)w;
    int y2 = y1 + cast(int)h;
    
    int cx = canvas.clipX;
    int cy = canvas.clipY;
    int cw = canvas.clipW;
    int ch = canvas.clipH;
    
    int ix1 = (x1 > cx) ? x1 : cx;
    int iy1 = (y1 > cy) ? y1 : cy;
    int ix2 = (x2 < cx + cw) ? x2 : cx + cw;
    int iy2 = (y2 < cy + ch) ? y2 : cy + ch;
    
    if (ix1 >= ix2 || iy1 >= iy2) return;
    
    uint drawX = ix1;
    uint drawY = iy1;
    uint drawW = ix2 - ix1;
    uint drawH = iy2 - iy1;

    if (canvas.targetsFramebuffer)
    {
        if (!(filled && acceleratedFillRect(drawX, drawY, drawW, drawH, argbColor)))
        {
            framebufferDrawRect(drawX, drawY, drawW, drawH, argbColor, filled);
        }
        return;
    }

    if (canvas.pixels is null || canvas.pitch == 0 || w == 0 || h == 0)
    {
        return;
    }

    const uint xEnd = drawX + drawW;
    const uint yEnd = drawY + drawH;
    
    // Original bounds for outline check
    const uint origXEnd = x + w;
    const uint origYEnd = y + h;

    foreach (yy; drawY .. yEnd)
    {
        foreach (xx; drawX .. xEnd)
        {
            if (!filled)
            {
                bool onLeft   = (xx == x);
                bool onRight  = (xx == origXEnd - 1);
                bool onTop    = (yy == y);
                bool onBottom = (yy == origYEnd - 1);
                
                if (!onLeft && !onRight && !onTop && !onBottom) continue;
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
