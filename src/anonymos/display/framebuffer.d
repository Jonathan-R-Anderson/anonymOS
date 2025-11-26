module anonymos.display.framebuffer;

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
    ushort modeNumber; // firmware-reported mode number (VBE or GOP-like), 0 when unknown
    bool   fromFirmware; // true when imported from Multiboot/VBE/EFI tables
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
                     bool        isBGR,
                     ushort      modeNumber = 0,
                     bool        fromFirmware = true)
{
    if (!framebufferModeSupported(base, width, height, pitchBytes, bpp)) {
        g_fbInitialized = false;
        return;
    }

    g_fb.addr   = cast(ubyte*) base;
    g_fb.width  = width;
    g_fb.height = height;
    g_fb.pitch  = pitchBytes;
    g_fb.bpp    = bpp;
    g_fb.isBGR  = isBGR;
    g_fb.modeNumber = modeNumber;
    g_fb.fromFirmware = fromFirmware;

    g_fbInitialized = true;
    g_fbFgColor     = fbDefaultFgColor;
    g_fbBgColor     = fbDefaultBgColor;
    g_fbCursorX     = 0;
    g_fbCursorY     = 0;
    
    framebufferResetClip();

    framebufferClear();
    framebufferInitCursor();
}

// D-friendly wrapper (same as above, just nicer to call)
@nogc nothrow @system
void initFramebuffer(const(void)* base,
                     uint        width,
                     uint        height,
                     uint        pitchBytes,
                     uint        bpp,
                     bool        isBGR,
                     ushort      modeNumber = 0,
                     bool        fromFirmware = true)
{
    framebufferInit(base, width, height, pitchBytes, bpp, isBGR, modeNumber, fromFirmware);
}

// Query
@nogc nothrow @system
bool framebufferAvailable() {
    return g_fbInitialized;
}

/// Validate a framebuffer mode before enabling it. This keeps callers honest
/// about stride alignment and supported pixel formats.
@nogc nothrow @system
bool framebufferModeSupported(const(void)* base,
                              uint width,
                              uint height,
                              uint pitchBytes,
                              uint bpp)
{
    if (base is null || width == 0 || height == 0) {
        return false;
    }

    // Only the canonical RGB565/RGB888/RGBA8888 layouts are supported.
    if (bpp != 16 && bpp != 24 && bpp != 32) {
        return false;
    }

    const uint bytesPerPixel = bpp / 8;
    if (bytesPerPixel == 0) {
        return false;
    }

    // Pitch must be large enough to hold an entire scanline and aligned to the
    // pixel size so putPixel math remains correct.
    if (pitchBytes < width * bytesPerPixel) {
        return false;
    }

    if ((pitchBytes % bytesPerPixel) != 0) {
        return false;
    }

    return true;
}

/// Expose the active framebuffer descriptor so higher layers (display server,
/// compositor experiments) can understand the chosen mode.
@nogc nothrow @system
Framebuffer framebufferDescriptor()
{
    return g_fb;
}

// --------------------------------------------------------------------------
// Low-level pixel operations (Set pixel / fill)
// --------------------------------------------------------------------------

// Clipping state
struct ClipRect { int x, y; uint w, h; }
__gshared ClipRect g_fbClip;

@nogc nothrow @system
void framebufferSetClip(int x, int y, uint w, uint h) {
    g_fbClip = ClipRect(x, y, w, h);
}

@nogc nothrow @system
void framebufferResetClip() {
    if (g_fbInitialized) {
        g_fbClip = ClipRect(0, 0, g_fb.width, g_fb.height);
    } else {
        g_fbClip = ClipRect(0, 0, 0, 0);
    }
}

// Put a single pixel in ARGB space; handles 16/24/32bpp if initialized.
@nogc nothrow @system
void framebufferPutPixel(uint x, uint y, uint argbColor) {
    if (!g_fbInitialized) return;
    if (g_fb.addr is null) return;
    
    // Bounds check against framebuffer
    if (x >= g_fb.width || y >= g_fb.height) return;

    // Clip check
    if (cast(int)x < g_fbClip.x || cast(int)x >= g_fbClip.x + cast(int)g_fbClip.w ||
        cast(int)y < g_fbClip.y || cast(int)y >= g_fbClip.y + cast(int)g_fbClip.h) return;

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

// --------------------------------------------------------------------------
// Software Cursor
// --------------------------------------------------------------------------

struct CursorIcon {
    uint width;
    uint height;
    const(uint)* pixels; // ARGB
}

private __gshared CursorIcon g_currentCursorIcon;
private __gshared int        g_cursorX = 0;
private __gshared int        g_cursorY = 0;
private __gshared bool       g_cursorVisible = false;
private __gshared uint[64 * 64] g_cursorSaveBuffer; // Max 64x64 cursor
private __gshared bool       g_cursorSaveBufferValid = false;

// Default 12x19 arrow cursor (ARGB)
// Simple pixel art arrow
private __gshared uint[12 * 19] g_defaultCursorPixels = [
    0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0xFF000000, 0xFF000000, 0xFF000000, 0xFF000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0xFF000000, 0x00000000, 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFF000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFF000000, 0xFF000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
];

@nogc nothrow @system
void framebufferInitCursor()
{
    g_currentCursorIcon.width  = 12;
    g_currentCursorIcon.height = 19;
    g_currentCursorIcon.pixels = g_defaultCursorPixels.ptr;
    g_cursorVisible = false;
    g_cursorSaveBufferValid = false;
}

@nogc nothrow @system
void framebufferSetCursorIcon(uint width, uint height, const(uint)* pixels)
{
    // Hide old cursor first to restore background
    bool wasVisible = g_cursorVisible;
    if (wasVisible) framebufferHideCursor();

    g_currentCursorIcon.width  = width;
    g_currentCursorIcon.height = height;
    g_currentCursorIcon.pixels = pixels;

    if (wasVisible) framebufferShowCursor();
}

@nogc nothrow @system
void framebufferMoveCursor(int x, int y)
{
    if (!g_fbInitialized) return;

    // If visible, we must:
    // 1. Restore background at old position
    // 2. Save background at new position
    // 3. Draw cursor at new position
    if (g_cursorVisible)
    {
        framebufferRestoreBackground();
        g_cursorX = x;
        g_cursorY = y;
        framebufferSaveBackground();
        framebufferDrawCursorIcon();
    }
    else
    {
        g_cursorX = x;
        g_cursorY = y;
    }
}

@nogc nothrow @system
void framebufferShowCursor()
{
    if (!g_fbInitialized) return;
    if (g_cursorVisible)
    {
        // Redraw without resaving background to avoid losing cursor when the
        // framebuffer is overdrawn every frame.
        framebufferDrawCursorIcon();
        return;
    }

    g_cursorVisible = true;
    framebufferSaveBackground();
    framebufferDrawCursorIcon();
}

@nogc nothrow @system
void framebufferHideCursor()
{
    if (!g_fbInitialized) return;
    if (!g_cursorVisible) return;

    framebufferRestoreBackground();
    g_cursorVisible = false;
}

// Internal helpers

@nogc nothrow @system
private void framebufferSaveBackground()
{
    if (!g_fbInitialized) return;
    
    const w = g_currentCursorIcon.width;
    const h = g_currentCursorIcon.height;
    if (w > 64 || h > 64) return; // Safety cap

    // Read pixels from framebuffer into g_cursorSaveBuffer
    // We need a 'getPixel' equivalent, but for speed we'll just calc offsets
    // Note: This is slow if done pixel-by-pixel. 
    // Ideally we'd have a blitRead, but we'll implement a simple loop here.
    
    // We must clip against screen bounds
    const fbW = g_fb.width;
    const fbH = g_fb.height;

    foreach (row; 0 .. h)
    {
        const cy = g_cursorY + row;
        if (cy < 0 || cy >= fbH) continue;

        foreach (col; 0 .. w)
        {
            const cx = g_cursorX + col;
            if (cx < 0 || cx >= fbW) continue;

            // Read pixel
            // This requires reading from video memory, which can be slow, but necessary for software cursor.
            // We'll implement a fast read helper if needed, but for now we assume direct access is okay.
            // WARNING: Reading from LFB is very slow on some hardware.
            
            // Calculate offset
            const byteOffset = cy * g_fb.pitch + cx * (g_fb.bpp / 8);
            uint pixelVal = 0;
            
            // We only support 32bpp read-back easily here for simplicity, 
            // or we assume we can just cast to uint* if 32bpp.
            // For 16/24bpp it's more complex. Let's support 32bpp primarily for now.
            if (g_fb.bpp == 32)
            {
                pixelVal = *(cast(uint*)(g_fb.addr + byteOffset));
            }
            else if (g_fb.bpp == 16)
            {
                pixelVal = *(cast(ushort*)(g_fb.addr + byteOffset));
            }
            // 24bpp is messy to read back efficiently without a helper
            
            g_cursorSaveBuffer[row * 64 + col] = pixelVal;
        }
    }
    g_cursorSaveBufferValid = true;
}

@nogc nothrow @system
private void framebufferRestoreBackground()
{
    if (!g_fbInitialized || !g_cursorSaveBufferValid) return;

    const w = g_currentCursorIcon.width;
    const h = g_currentCursorIcon.height;
    const fbW = g_fb.width;
    const fbH = g_fb.height;

    foreach (row; 0 .. h)
    {
        const cy = g_cursorY + row;
        if (cy < 0 || cy >= fbH) continue;

        foreach (col; 0 .. w)
        {
            const cx = g_cursorX + col;
            if (cx < 0 || cx >= fbW) continue;

            const saved = g_cursorSaveBuffer[row * 64 + col];
            framebufferPutPixel(cx, cy, saved); // PutPixel handles format conversion if 'saved' was ARGB? 
            // WAIT: We saved the RAW pixel value. framebufferPutPixel expects ARGB.
            // We need a 'putRawPixel' or we need to convert back.
            // Actually, since we read the raw value, we should write the raw value back.
            // But framebufferPutPixel takes ARGB.
            // We should implement a 'putPixelRaw' or just write directly here.
            
            const byteOffset = cy * g_fb.pitch + cx * (g_fb.bpp / 8);
            if (g_fb.bpp == 32)
            {
                *(cast(uint*)(g_fb.addr + byteOffset)) = saved;
            }
            else if (g_fb.bpp == 16)
            {
                *(cast(ushort*)(g_fb.addr + byteOffset)) = cast(ushort)saved;
            }
        }
    }
}

@nogc nothrow @system
private void framebufferDrawCursorIcon()
{
    if (!g_fbInitialized) return;

    const w = g_currentCursorIcon.width;
    const h = g_currentCursorIcon.height;
    const pixels = g_currentCursorIcon.pixels;
    const fbW = g_fb.width;
    const fbH = g_fb.height;

    foreach (row; 0 .. h)
    {
        const cy = g_cursorY + row;
        if (cy < 0 || cy >= fbH) continue;

        foreach (col; 0 .. w)
        {
            const cx = g_cursorX + col;
            if (cx < 0 || cx >= fbW) continue;

            const argb = pixels[row * w + col];
            
            // Simple alpha blending: if alpha > 0, draw.
            // Ideally we'd do proper blending, but for a basic cursor, 
            // 0 alpha = transparent, anything else = opaque is a good start.
            // Or simple threshold.
            if ((argb & 0xFF000000) != 0)
            {
                framebufferPutPixel(cx, cy, argb);
            }
        }
    }
}
