module minimal_os.display.framebuffer;

@safe: // default, we drop to @system in the few places we need pointer math

import core.stdc.string : memmove; // for scrolling

// --------------------------------------------------------------------------
// Types and globals
// --------------------------------------------------------------------------

enum fbDefaultFgColor = 0xFFFFFFFF; // ARGB: white
enum fbDefaultBgColor = 0x00000000; // ARGB: black

enum glyphWidth  = 8;
enum glyphHeight = 16;

enum MaxSupportedBpp = 32;

struct Framebuffer {
    ubyte* addr;     // linear framebuffer base
    uint   width;    // pixels
    uint   height;   // pixels
    uint   pitch;    // bytes per scanline
    uint   bpp;      // bits per pixel (16/24/32 supported)
    bool   isBGR;    // true if hardware expects BGR ordering instead of RGB
}

// Global state
__gshared Framebuffer g_fb;
__gshared bool        g_fbInitialized   = false;
__gshared uint        g_fbFgColor       = fbDefaultFgColor;
__gshared uint        g_fbBgColor       = fbDefaultBgColor;
__gshared uint        g_fbCursorX       = 0; // in character cells
__gshared uint        g_fbCursorY       = 0; // in character cells

// --------------------------------------------------------------------------
// Fallback 8x16 glyph
// All characters use the same simple box glyph so we don't need a full font.
// You can later replace drawChar() with a real font module.
// --------------------------------------------------------------------------

private immutable ubyte[glyphHeight] fallbackGlyph = [
    // 8x16 box: 1 = foreground, 0 = background
    // 11111111
    // 10000001
    // ...
    // 11111111
    cast(ubyte)0b1111_1111,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1000_0001,
    cast(ubyte)0b1111_1111,
];

// --------------------------------------------------------------------------
// Helpers: color conversion
// --------------------------------------------------------------------------

// Convert ARGB (0xAARRGGBB) to native 16-bit RGB565
@nogc nothrow @system
private uint argbToRgb565(uint argb) {
    auto r = (argb >> 16) & 0xFF;
    auto g = (argb >> 8)  & 0xFF;
    auto b =  argb        & 0xFF;

    uint r5 = (r * 31) / 255;
    uint g6 = (g * 63) / 255;
    uint b5 = (b * 31) / 255;

    return (r5 << 11) | (g6 << 5) | b5;
}

// Convert ARGB to native 24/32-bit pixel for RGB/BGR (alpha ignored)
@nogc nothrow @system
private uint argbToNative(uint argb) {
    auto r = (argb >> 16) & 0xFF;
    auto g = (argb >> 8)  & 0xFF;
    auto b =  argb        & 0xFF;

    if (!g_fb.isBGR) {
        // 0x00RRGGBB
        return (r << 16) | (g << 8) | b;
    } else {
        // 0x00BBGGRR
        return (b << 16) | (g << 8) | r;
    }
}

// --------------------------------------------------------------------------
// Initialization
// Call this once from your multiboot / hardware probe code.
// --------------------------------------------------------------------------

// C-ABI init hook so you can call it from C/ASM if desired
extern(C) @nogc nothrow @system
void framebufferInit(const(void)* base,
                     uint        width,
                     uint        height,
                     uint        pitchBytes,
                     uint        bpp,
                     bool        isBGR)
{
    if (base is null) {
        g_fbInitialized = false;
        return;
    }

    if (bpp == 0 || bpp > MaxSupportedBpp) {
        g_fbInitialized = false;
        return;
    }

    g_fb.addr   = cast(ubyte*) base;
    g_fb.width  = width;
    g_fb.height = height;
    g_fb.pitch  = pitchBytes;
    g_fb.bpp    = bpp;
    g_fb.isBGR  = isBGR;

    g_fbInitialized = true;
    g_fbFgColor     = fbDefaultFgColor;
    g_fbBgColor     = fbDefaultBgColor;
    g_fbCursorX     = 0;
    g_fbCursorY     = 0;

    framebufferClear();
}

// D-friendly wrapper (same as above, just nicer to call)
@nogc nothrow @system
void initFramebuffer(const(void)* base,
                     uint        width,
                     uint        height,
                     uint        pitchBytes,
                     uint        bpp,
                     bool        isBGR)
{
    framebufferInit(base, width, height, pitchBytes, bpp, isBGR);
}

// Query
@nogc nothrow @system
bool framebufferAvailable() {
    return g_fbInitialized;
}

// --------------------------------------------------------------------------
// Low-level pixel operations (Set pixel / fill)
// --------------------------------------------------------------------------

// Put a single pixel in ARGB space; handles 16/24/32bpp if initialized.
@nogc nothrow @system
void framebufferPutPixel(uint x, uint y, uint argbColor) {
    if (!g_fbInitialized) return;
    if (x >= g_fb.width || y >= g_fb.height) return;

    const bpp   = g_fb.bpp;
    ubyte* addr = g_fb.addr;

    const byteOffset = y * g_fb.pitch + x * (bpp / 8);

    switch (bpp) {
        case 16: {
            auto px = cast(ushort*) (addr + byteOffset);
            *px = cast(ushort) argbToRgb565(argbColor);
            break;
        }
        case 24: {
            const native = argbToNative(argbColor);
            auto p = addr + byteOffset;
            // 24bpp: lowest 3 bytes are the pixel.
            p[0] = cast(ubyte)( native        & 0xFF);
            p[1] = cast(ubyte)((native >> 8)  & 0xFF);
            p[2] = cast(ubyte)((native >> 16) & 0xFF);
            break;
        }
        case 32: {
            auto px = cast(uint*) (addr + byteOffset);
            *px = argbToNative(argbColor); // ignore alpha
            break;
        }
        default:
            // Unsupported format
            break;
    }
}

// Fill entire screen with a given color
@nogc nothrow @system
void framebufferFill(uint argbColor) {
    if (!g_fbInitialized) return;

    foreach (y; 0 .. g_fb.height) {
        foreach (x; 0 .. g_fb.width) {
            framebufferPutPixel(x, y, argbColor);
        }
    }
}

// Clear to background color
@nogc nothrow @system
void framebufferClear() {
    framebufferFill(g_fbBgColor);
}

// Draw a rectangle (filled or outline)
@nogc nothrow @system
void framebufferDrawRect(uint x, uint y, uint w, uint h, uint argbColor, bool filled = true) {
    if (!g_fbInitialized) return;
    if (w == 0 || h == 0) return;

    const xEnd = x + w;
    const yEnd = y + h;

    if (filled) {
        foreach (yy; y .. yEnd) {
            foreach (xx; x .. xEnd) {
                framebufferPutPixel(xx, yy, argbColor);
            }
        }
    } else {
        // Top and bottom
        foreach (xx; x .. xEnd) {
            framebufferPutPixel(xx, y,        argbColor);
            framebufferPutPixel(xx, yEnd - 1, argbColor);
        }
        // Left and right
        foreach (yy; y .. yEnd) {
            framebufferPutPixel(x,        yy, argbColor);
            framebufferPutPixel(xEnd - 1, yy, argbColor);
        }
    }
}

// Convenience: fill rectangle wrapper (explicit "fill rect" op)
@nogc nothrow @system
void framebufferFillRect(uint x, uint y, uint w, uint h, uint argbColor) {
    framebufferDrawRect(x, y, w, h, argbColor, true);
}

// --------------------------------------------------------------------------
// Bitmap blit: 8-bit mask (for fonts/icons)
// --------------------------------------------------------------------------
//
// We treat the source as an 8-bit per pixel mask:
//   - mask == 0   -> transparent (or background if useBg == true)
//   - mask != 0   -> draw foreground color
//
// This is generic and independent of your fallback font; you can use it
// for icons or higher-res fonts later.

@nogc nothrow @system
void framebufferBlitMask(uint dstX, uint dstY,
                         const(ubyte)* mask,
                         uint maskWidth, uint maskHeight,
                         uint maskStride,
                         uint fgARGB,
                         uint bgARGB = 0,
                         bool useBg = false)
{
    if (!g_fbInitialized) return;
    if (mask is null) return;
    if (maskWidth == 0 || maskHeight == 0) return;

    // Clip against framebuffer bounds.
    if (dstX >= g_fb.width || dstY >= g_fb.height) return;

    uint maxW = g_fb.width  - dstX;
    uint maxH = g_fb.height - dstY;

    uint blitW = maskWidth;
    uint blitH = maskHeight;
    if (blitW > maxW) blitW = maxW;
    if (blitH > maxH) blitH = maxH;

    foreach (row; 0 .. blitH) {
        const(ubyte)* srcRow = mask + row * maskStride;

        foreach (col; 0 .. blitW) {
            const ubyte m = srcRow[col];

            // Fully transparent and no background requested
            if (m == 0 && !useBg) {
                continue;
            }

            const uint color = (m == 0) ? bgARGB : fgARGB;
            framebufferPutPixel(dstX + col, dstY + row, color);
        }
    }
}

// --------------------------------------------------------------------------
// Text rendering (simple 8x16 cell-based "console")
// --------------------------------------------------------------------------

@nogc nothrow @system
void framebufferSetTextColors(uint fg, uint bg) {
    g_fbFgColor = fg;
    g_fbBgColor = bg;
}

// Number of character cells horizontally/vertically
@nogc nothrow @system
uint framebufferCols() {
    if (!g_fbInitialized) return 0;
    return g_fb.width / glyphWidth;
}

@nogc nothrow @system
uint framebufferRows() {
    if (!g_fbInitialized) return 0;
    return g_fb.height / glyphHeight;
}

// Draw the fallback 8x16 glyph at pixel position (px, py)
@nogc nothrow @system
private void drawGlyph(uint px, uint py, uint fg, uint bg) {
    if (!g_fbInitialized) return;

    foreach (row; 0 .. glyphHeight) {
        const bits = fallbackGlyph[row];
        foreach (col; 0 .. glyphWidth) {
            const mask = cast(ubyte)(0x80 >> col);
            const isOn = (bits & mask) != 0;
            const color = isOn ? fg : bg;
            framebufferPutPixel(px + col, py + row, color);
        }
    }
}

// Scroll text console up by one glyph row (16 pixels)
@nogc nothrow @system
private void scrollUpOneRow() {
    if (!g_fbInitialized) return;

    const glyphPixels = glyphHeight;
    const visibleRows = framebufferRows();
    if (visibleRows == 0) return;

    // total pixel height occupied by the text grid
    const textHeightPixels = visibleRows * glyphPixels;

    // If the framebuffer is taller than text grid, we'll just scroll the grid area.
    const bytesPerRow = g_fb.pitch;
    auto src = g_fb.addr + glyphPixels * bytesPerRow;
    auto dst = g_fb.addr;
    const bytesToMove = (textHeightPixels - glyphPixels) * bytesPerRow;

    memmove(dst, src, bytesToMove);

    // Clear the last glyph row area
    const startClearY = (visibleRows - 1) * glyphPixels;
    foreach (y; startClearY .. startClearY + glyphPixels) {
        foreach (x; 0 .. g_fb.width) {
            framebufferPutPixel(x, y, g_fbBgColor);
        }
    }
}

// Place glyph for character at current cell (cx, cy)
@nogc nothrow @system
private void putCharAtCell(uint cx, uint cy, uint fg, uint bg) {
    const px = cx * glyphWidth;
    const py = cy * glyphHeight;
    drawGlyph(px, py, fg, bg);
}

// Advance cursor, scroll if needed
@nogc nothrow @system
private void advanceCursor() {
    ++g_fbCursorX;
    const cols = framebufferCols();
    const rows = framebufferRows();

    if (cols == 0 || rows == 0) return;

    if (g_fbCursorX >= cols) {
        g_fbCursorX = 0;
        ++g_fbCursorY;
    }

    if (g_fbCursorY >= rows) {
        scrollUpOneRow();
        g_fbCursorY = rows - 1;
    }
}

@nogc nothrow @system
private void newLine() {
    g_fbCursorX = 0;
    ++g_fbCursorY;

    const rows = framebufferRows();
    if (rows == 0) return;

    if (g_fbCursorY >= rows) {
        scrollUpOneRow();
        g_fbCursorY = rows - 1;
    }
}

// Public: write a single character (uses same glyph for every printable)
// Recognizes '\n', '\r', '\t', '\b'.
@nogc nothrow @system
void framebufferWriteChar(char c) {
    if (!g_fbInitialized) return;

    switch (c) {
        case '\n':
            newLine();
            break;
        case '\r':
            g_fbCursorX = 0;
            break;
        case '\t':
            // simple 4-space tabs
            foreach (_; 0 .. 4) {
                framebufferWriteChar(' ');
            }
            break;
        case '\b':
            if (g_fbCursorX > 0) {
                --g_fbCursorX;
                putCharAtCell(g_fbCursorX, g_fbCursorY, g_fbBgColor, g_fbBgColor);
            }
            break;
        default:
            putCharAtCell(g_fbCursorX, g_fbCursorY, g_fbFgColor, g_fbBgColor);
            advanceCursor();
            break;
    }
}

// Public: write a D string
@nogc nothrow @system
void framebufferWriteString(const(char)[] s) {
    if (!g_fbInitialized) return;
    foreach (c; s) {
        framebufferWriteChar(c);
    }
}

// C-ABI helper: write a null-terminated C string
extern(C) @nogc nothrow @system
void framebufferWriteCString(const(char)* s) {
    if (!g_fbInitialized || s is null) return;
    for (; *s != 0; ++s) {
        framebufferWriteChar(*s);
    }
}

// Convenience: draw a simple "boot banner"
@nogc nothrow @system
void framebufferBootBanner(const(char)[] msg) {
    if (!g_fbInitialized) return;

    g_fbCursorX = 0;
    g_fbCursorY = 0;
    framebufferClear();

    framebufferSetTextColors(0xFFFFFFFF, 0x00000000); // white on black
    framebufferWriteString(msg);
    framebufferWriteChar('\n');
}
