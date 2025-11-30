module anonymos.display.cursor;

import anonymos.display.framebuffer;
import anonymos.display.canvas;
import anonymos.console : printLine, printUnsigned;
import core.stdc.stdlib : malloc, free;

@system:

/// Represents a single frame of a cursor animation
struct CursorFrame {
    uint width;
    uint height;
    uint* pixels; // ARGB data
    uint delayMs;  // Delay in milliseconds (0 for static)
}

/// Represents a complete cursor (static or animated)
struct Cursor {
    CursorFrame* frames;
    size_t frameCount;
    uint hotspotX;
    uint hotspotY;
    
    // Animation state
    size_t currentFrameIndex;
    ulong lastFrameTime; // Timestamp of last frame change
}

/// Helper to create a simple single-color square cursor (fallback)
Cursor createFallbackCursor(uint size, uint color) @nogc nothrow {
    Cursor c;
    c.hotspotX = size / 2;
    c.hotspotY = size / 2;
    c.frameCount = 1;
    c.frames = cast(CursorFrame*) malloc(CursorFrame.sizeof * 1);
    
    c.frames[0].width = size;
    c.frames[0].height = size;
    c.frames[0].delayMs = 0;
    c.frames[0].pixels = cast(uint*) malloc(uint.sizeof * size * size);
    
    foreach(i; 0 .. size * size) {
        c.frames[0].pixels[i] = color;
    }
    
    return c;
}

/// Helper to create a standard arrow cursor
Cursor createArrowCursor() @nogc nothrow {
    Cursor c;
    c.hotspotX = 0;
    c.hotspotY = 0;
    c.frameCount = 1;
    c.frames = cast(CursorFrame*) malloc(CursorFrame.sizeof * 1);
    
    // 12x19 Arrow
    uint w = 12;
    uint h = 19;
    
    c.frames[0].width = w;
    c.frames[0].height = h;
    c.frames[0].delayMs = 0;
    c.frames[0].pixels = cast(uint*) malloc(uint.sizeof * w * h);
    
    uint* p = c.frames[0].pixels;
    
    // Clear to transparent
    foreach(i; 0 .. w*h) p[i] = 0x00000000;
    
    // Draw logic (simplified for @nogc)
    // 1 = Border (Black), 2 = Fill (White)
    ubyte[12*19] bitmap = [
        1,0,0,0,0,0,0,0,0,0,0,0,
        1,1,0,0,0,0,0,0,0,0,0,0,
        1,2,1,0,0,0,0,0,0,0,0,0,
        1,2,2,1,0,0,0,0,0,0,0,0,
        1,2,2,2,1,0,0,0,0,0,0,0,
        1,2,2,2,2,1,0,0,0,0,0,0,
        1,2,2,2,2,2,1,0,0,0,0,0,
        1,2,2,2,2,2,2,1,0,0,0,0,
        1,2,2,2,2,2,2,2,1,0,0,0,
        1,2,2,2,2,2,2,2,2,1,0,0,
        1,2,2,2,2,2,1,1,1,1,1,0,
        1,2,2,1,2,2,1,0,0,0,0,0,
        1,2,1,0,1,2,2,1,0,0,0,0,
        1,1,0,0,1,2,2,1,0,0,0,0,
        1,0,0,0,0,1,2,2,1,0,0,0,
        0,0,0,0,0,1,2,2,1,0,0,0,
        0,0,0,0,0,0,1,1,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0
    ];
    
    foreach(i; 0 .. w*h) {
        if (bitmap[i] == 1) p[i] = 0xFF000000; // Black
        else if (bitmap[i] == 2) p[i] = 0xFFFFFFFF; // White
    }
    
    return c;
}

// Global cursor state
__gshared Cursor g_activeCursor;
__gshared bool g_cursorInitialized = false;

void initCursorSystem() @nogc nothrow {
    import anonymos.console : printLine;
    printLine("[cursor] initCursorSystem called");
    if (g_cursorInitialized) {
        printLine("[cursor] already initialized");
        return;
    }
    g_activeCursor = createArrowCursor();
    g_cursorInitialized = true;
    printLine("[cursor] initCursorSystem done");
}

void setCursor(Cursor c) @nogc nothrow {
    // TODO: Free old cursor if dynamically allocated?
    // For now, we assume cursors are managed elsewhere or leaked (simple OS)
    g_activeCursor = c;
}

// Update animation state
void updateCursorAnimation(ulong currentTimeMs) @nogc nothrow {
    if (!g_cursorInitialized) return;
    if (g_activeCursor.frameCount <= 1) return;
    
    CursorFrame* current = &g_activeCursor.frames[g_activeCursor.currentFrameIndex];
    if (current.delayMs > 0) {
        if (currentTimeMs - g_activeCursor.lastFrameTime >= current.delayMs) {
            g_activeCursor.currentFrameIndex = (g_activeCursor.currentFrameIndex + 1) % g_activeCursor.frameCount;
            g_activeCursor.lastFrameTime = currentTimeMs;
        }
    }
}

// Get current frame pixel data
void getCurrentCursorData(out uint width, out uint height, out const(uint)* pixels, out uint hotX, out uint hotY) @nogc nothrow {
    if (!g_cursorInitialized) {
        // Fallback safety
        width = 0; height = 0; pixels = null; hotX = 0; hotY = 0;
        return;
    }
    
    CursorFrame* f = &g_activeCursor.frames[g_activeCursor.currentFrameIndex];
    width = f.width;
    height = f.height;
    pixels = f.pixels;
    hotX = g_activeCursor.hotspotX;
    hotY = g_activeCursor.hotspotY;
}
