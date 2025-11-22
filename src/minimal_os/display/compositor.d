module minimal_os.display.compositor;

import minimal_os.display.framebuffer;
import minimal_os.display.canvas;
import minimal_os.display.window_manager.manager;
import minimal_os.display.wallpaper : drawWallpaperToBuffer;

nothrow:
@nogc:

private enum uint maxCompositeWidth  = 1920;
private enum uint maxCompositeHeight = 1080;
private enum size_t maxCompositePixels = cast(size_t) maxCompositeWidth * maxCompositeHeight;

private enum uint taskbarColor    = 0xFF303030;
private enum uint windowColor     = 0xFF2C2C2C;
private enum uint titleBarColor   = 0xFF383838;
private enum uint titleFocused    = 0xFF4650C0;
private enum uint borderColor     = 0xFF505050;
private enum uint textColor       = 0xFFFFFFFF;
private enum uint contentFill     = 0xFF1C1C1C;

private immutable ubyte[8][128] font8x8Basic = [
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 0
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 1
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 2
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 3
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 4
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 5
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 6
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 7
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 8
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 9
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 10
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 11
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 12
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 13
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 14
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 15
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 16
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 17
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 18
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 19
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 20
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 21
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 22
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 23
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 24
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 25
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 26
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 27
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 28
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 29
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 30
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 31
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 32
    [0x18, 0x3C, 0x3C, 0x18, 0x18, 0x00, 0x18, 0x00], // 33
    [0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 34
    [0x36, 0x36, 0x7F, 0x36, 0x7F, 0x36, 0x36, 0x00], // 35
    [0x0C, 0x3E, 0x03, 0x1E, 0x30, 0x1F, 0x0C, 0x00], // 36
    [0x00, 0x63, 0x33, 0x18, 0x0C, 0x66, 0x63, 0x00], // 37
    [0x1C, 0x36, 0x1C, 0x6E, 0x3B, 0x33, 0x6E, 0x00], // 38
    [0x06, 0x06, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00], // 39
    [0x18, 0x0C, 0x06, 0x06, 0x06, 0x0C, 0x18, 0x00], // 40
    [0x06, 0x0C, 0x18, 0x18, 0x18, 0x0C, 0x06, 0x00], // 41
    [0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00], // 42
    [0x00, 0x0C, 0x0C, 0x3F, 0x0C, 0x0C, 0x00, 0x00], // 43
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x06], // 44
    [0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00], // 45
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x00], // 46
    [0x60, 0x30, 0x18, 0x0C, 0x06, 0x03, 0x01, 0x00], // 47
    [0x3E, 0x63, 0x73, 0x7B, 0x6F, 0x67, 0x3E, 0x00], // 48
    [0x0C, 0x0E, 0x0C, 0x0C, 0x0C, 0x0C, 0x3F, 0x00], // 49
    [0x1E, 0x33, 0x30, 0x1C, 0x06, 0x33, 0x3F, 0x00], // 50
    [0x1E, 0x33, 0x30, 0x1C, 0x30, 0x33, 0x1E, 0x00], // 51
    [0x38, 0x3C, 0x36, 0x33, 0x7F, 0x30, 0x78, 0x00], // 52
    [0x3F, 0x03, 0x1F, 0x30, 0x30, 0x33, 0x1E, 0x00], // 53
    [0x1C, 0x06, 0x03, 0x1F, 0x33, 0x33, 0x1E, 0x00], // 54
    [0x3F, 0x33, 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x00], // 55
    [0x1E, 0x33, 0x33, 0x1E, 0x33, 0x33, 0x1E, 0x00], // 56
    [0x1E, 0x33, 0x33, 0x3E, 0x30, 0x18, 0x0E, 0x00], // 57
    [0x00, 0x0C, 0x0C, 0x00, 0x00, 0x0C, 0x0C, 0x00], // 58
    [0x00, 0x0C, 0x0C, 0x00, 0x00, 0x0C, 0x0C, 0x06], // 59
    [0x18, 0x0C, 0x06, 0x03, 0x06, 0x0C, 0x18, 0x00], // 60
    [0x00, 0x00, 0x3F, 0x00, 0x00, 0x3F, 0x00, 0x00], // 61
    [0x06, 0x0C, 0x18, 0x30, 0x18, 0x0C, 0x06, 0x00], // 62
    [0x1E, 0x33, 0x30, 0x18, 0x0C, 0x00, 0x0C, 0x00], // 63
    [0x3E, 0x63, 0x7B, 0x7B, 0x7B, 0x03, 0x1E, 0x00], // 64
    [0x0C, 0x1E, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x00], // 65
    [0x3F, 0x66, 0x66, 0x3E, 0x66, 0x66, 0x3F, 0x00], // 66
    [0x3C, 0x66, 0x03, 0x03, 0x03, 0x66, 0x3C, 0x00], // 67
    [0x1F, 0x36, 0x66, 0x66, 0x66, 0x36, 0x1F, 0x00], // 68
    [0x7F, 0x46, 0x16, 0x1E, 0x16, 0x46, 0x7F, 0x00], // 69
    [0x7F, 0x46, 0x16, 0x1E, 0x16, 0x06, 0x0F, 0x00], // 70
    [0x3C, 0x66, 0x03, 0x03, 0x73, 0x66, 0x7C, 0x00], // 71
    [0x33, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x33, 0x00], // 72
    [0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // 73
    [0x78, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1E, 0x00], // 74
    [0x67, 0x66, 0x36, 0x1E, 0x36, 0x66, 0x67, 0x00], // 75
    [0x0F, 0x06, 0x06, 0x06, 0x46, 0x66, 0x7F, 0x00], // 76
    [0x63, 0x77, 0x7F, 0x7F, 0x6B, 0x63, 0x63, 0x00], // 77
    [0x63, 0x67, 0x6F, 0x7B, 0x73, 0x63, 0x63, 0x00], // 78
    [0x1C, 0x36, 0x63, 0x63, 0x63, 0x36, 0x1C, 0x00], // 79
    [0x3F, 0x66, 0x66, 0x3E, 0x06, 0x06, 0x0F, 0x00], // 80
    [0x1E, 0x33, 0x33, 0x33, 0x3B, 0x1E, 0x38, 0x00], // 81
    [0x3F, 0x66, 0x66, 0x3E, 0x36, 0x66, 0x67, 0x00], // 82
    [0x1E, 0x33, 0x07, 0x0E, 0x38, 0x33, 0x1E, 0x00], // 83
    [0x3F, 0x2D, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // 84
    [0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x3F, 0x00], // 85
    [0x33, 0x33, 0x33, 0x33, 0x33, 0x1E, 0x0C, 0x00], // 86
    [0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00], // 87
    [0x63, 0x63, 0x36, 0x1C, 0x1C, 0x36, 0x63, 0x00], // 88
    [0x33, 0x33, 0x33, 0x1E, 0x0C, 0x0C, 0x1E, 0x00], // 89
    [0x7F, 0x63, 0x31, 0x18, 0x4C, 0x66, 0x7F, 0x00], // 90
    [0x1E, 0x06, 0x06, 0x06, 0x06, 0x06, 0x1E, 0x00], // 91
    [0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00], // 92
    [0x1E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1E, 0x00], // 93
    [0x08, 0x1C, 0x36, 0x63, 0x00, 0x00, 0x00, 0x00], // 94
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF], // 95
    [0x0C, 0x0C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00], // 96
    [0x00, 0x00, 0x1E, 0x30, 0x3E, 0x33, 0x6E, 0x00], // 97
    [0x07, 0x06, 0x06, 0x3E, 0x66, 0x66, 0x3B, 0x00], // 98
    [0x00, 0x00, 0x1E, 0x33, 0x03, 0x33, 0x1E, 0x00], // 99
    [0x38, 0x30, 0x30, 0x3e, 0x33, 0x33, 0x6E, 0x00], // 100
    [0x00, 0x00, 0x1E, 0x33, 0x3f, 0x03, 0x1E, 0x00], // 101
    [0x1C, 0x36, 0x06, 0x0f, 0x06, 0x06, 0x0F, 0x00], // 102
    [0x00, 0x00, 0x6E, 0x33, 0x33, 0x3E, 0x30, 0x1F], // 103
    [0x07, 0x06, 0x36, 0x6E, 0x66, 0x66, 0x67, 0x00], // 104
    [0x0C, 0x00, 0x0E, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // 105
    [0x30, 0x00, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1E], // 106
    [0x07, 0x06, 0x66, 0x36, 0x1E, 0x36, 0x67, 0x00], // 107
    [0x0E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // 108
    [0x00, 0x00, 0x33, 0x7F, 0x7F, 0x6B, 0x63, 0x00], // 109
    [0x00, 0x00, 0x1F, 0x33, 0x33, 0x33, 0x33, 0x00], // 110
    [0x00, 0x00, 0x1E, 0x33, 0x33, 0x33, 0x1E, 0x00], // 111
    [0x00, 0x00, 0x3B, 0x66, 0x66, 0x3E, 0x06, 0x0F], // 112
    [0x00, 0x00, 0x6E, 0x33, 0x33, 0x3E, 0x30, 0x78], // 113
    [0x00, 0x00, 0x3B, 0x6E, 0x66, 0x06, 0x0F, 0x00], // 114
    [0x00, 0x00, 0x3E, 0x03, 0x1E, 0x30, 0x1F, 0x00], // 115
    [0x08, 0x0C, 0x3E, 0x0C, 0x0C, 0x2C, 0x18, 0x00], // 116
    [0x00, 0x00, 0x33, 0x33, 0x33, 0x33, 0x6E, 0x00], // 117
    [0x00, 0x00, 0x33, 0x33, 0x33, 0x1E, 0x0C, 0x00], // 118
    [0x00, 0x00, 0x63, 0x6B, 0x7F, 0x7F, 0x36, 0x00], // 119
    [0x00, 0x00, 0x63, 0x36, 0x1C, 0x36, 0x63, 0x00], // 120
    [0x00, 0x00, 0x33, 0x33, 0x33, 0x3E, 0x30, 0x1F], // 121
    [0x00, 0x00, 0x3F, 0x19, 0x0C, 0x26, 0x3F, 0x00], // 122
    [0x38, 0x0C, 0x0C, 0x07, 0x0C, 0x0C, 0x38, 0x00], // 123
    [0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x00], // 124
    [0x07, 0x0C, 0x0C, 0x38, 0x0C, 0x0C, 0x07, 0x00], // 125
    [0x6E, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 126
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // 127
];

private struct WindowEntry
{
    const(Window)* window;
}

private struct Surface
{
    size_t id;
    uint width;
    uint height;
    uint* pixels;
    size_t poolOffset;
    size_t poolLength;
    bool inUse;
}

private struct PoolBlock
{
    size_t offset;
    size_t length;
    bool free;
}

private struct PixelAllocation
{
    uint*  ptr;
    size_t offset;
    size_t length;
}

struct Compositor
{
    @nogc nothrow:

    uint   width;
    uint   height;
    uint   pitch;
    uint*  buffer;
    bool   ready;

    void configureFromFramebuffer()
    {
        if (!framebufferAvailable())
        {
            ready = false;
            return;
        }

        const size_t needed = cast(size_t) g_fb.width * g_fb.height;
        if (needed == 0 || needed > maxCompositePixels)
        {
            ready = false;
            return;
        }

        width = g_fb.width;
        height = g_fb.height;
        pitch = g_fb.width;
        buffer = g_compositorBackBuffer.ptr;
        ready = true;
        clear(0);
    }

    bool available() const
    {
        return ready;
    }

    void clear(uint color)
    {
        if (!ready)
        {
            return;
        }

        const size_t total = cast(size_t) width * height;
        foreach (i; 0 .. total)
        {
            buffer[i] = color;
        }
    }

    void putPixel(uint x, uint y, uint color)
    {
        if (!ready || x >= width || y >= height)
        {
            return;
        }

        buffer[y * pitch + x] = color;
    }

    void fillRect(uint x, uint y, uint w, uint h, uint color)
    {
        if (!ready || w == 0 || h == 0)
        {
            return;
        }

        const uint xEnd = x + w;
        const uint yEnd = y + h;
        foreach (yy; y .. yEnd)
        {
            if (yy >= height)
            {
                break;
            }
            foreach (xx; x .. xEnd)
            {
                if (xx >= width)
                {
                    break;
                }
                putPixel(xx, yy, color);
            }
        }
    }

    void drawRect(uint x, uint y, uint w, uint h, uint color)
    {
        if (w == 0 || h == 0)
        {
            return;
        }

        const uint xEnd = x + w;
        const uint yEnd = y + h;

        foreach (xx; x .. xEnd)
        {
            putPixel(xx, y, color);
            if (h > 1)
            {
                putPixel(xx, yEnd - 1, color);
            }
        }

        foreach (yy; y .. yEnd)
        {
            putPixel(x, yy, color);
            if (w > 1)
            {
                putPixel(xEnd - 1, yy, color);
            }
        }
    }

    void drawGlyph(uint px, uint py, uint fg, uint bg, char glyph)
    {
        foreach (row; 0 .. glyphHeight)
        {
            // The font source is 8px high; expand to 16px by duplicating rows
            const sourceRow = cast(uint)(row / 2);
            const fontIndex = cast(ubyte)glyph & 0x7F; // basic ASCII subset
            const bits = font8x8Basic[fontIndex][sourceRow];
            foreach (col; 0 .. glyphWidth)
            {
                const mask = cast(ubyte)(0x80 >> col);
                const isOn = (bits & mask) != 0;
                const color = isOn ? fg : bg;
                putPixel(px + col, py + row, color);
            }
        }
    }

    void drawString(uint px, uint py, const(char)* text, uint fg, uint bg)
    {
        if (text is null)
        {
            return;
        }

        uint cursorX = px;
        for (auto p = text; *p != '\0'; ++p)
        {
            drawGlyph(cursorX, py, fg, bg, *p);
            cursorX += glyphWidth;
        }
    }

    void present()
    {
        if (!ready || !framebufferAvailable())
        {
            return;
        }

        foreach (y; 0 .. height)
        {
            foreach (x; 0 .. width)
            {
                framebufferPutPixel(x, y, buffer[y * pitch + x]);
            }
        }
    }
}

private __gshared uint[maxCompositePixels] g_compositorBackBuffer;
private __gshared Compositor g_compositor;
private __gshared Surface[WINDOW_MANAGER_CAPACITY] g_surfaces;
private __gshared size_t g_nextSurfaceId;
private __gshared uint[maxCompositePixels] g_surfacePool;
private __gshared PoolBlock[WINDOW_MANAGER_CAPACITY * 2] g_poolBlocks;
private __gshared size_t g_poolBlockCount;

private void ensurePoolInitialized() @nogc nothrow
{
    if (g_poolBlockCount == 0)
    {
        g_poolBlocks[0] = PoolBlock(0, maxCompositePixels, true);
        g_poolBlockCount = 1;
    }
}

private void mergeFreeBlocks() @nogc nothrow
{
    bool merged;
    do
    {
        merged = false;
        foreach (i; 0 .. g_poolBlockCount)
        {
            auto left = &g_poolBlocks[i];
            if (!left.free)
            {
                continue;
            }

            foreach (j; i + 1 .. g_poolBlockCount)
            {
                auto right = &g_poolBlocks[j];
                if (!right.free)
                {
                    continue;
                }

                const bool adjacentForward = left.offset + left.length == right.offset;
                const bool adjacentBackward = right.offset + right.length == left.offset;
                if (!adjacentForward && !adjacentBackward)
                {
                    continue;
                }

                const size_t newOffset = (right.offset < left.offset) ? right.offset : left.offset;
                left.length += right.length;
                left.offset = newOffset;

                foreach (k; j + 1 .. g_poolBlockCount)
                {
                    g_poolBlocks[k - 1] = g_poolBlocks[k];
                }
                --g_poolBlockCount;
                merged = true;
                break;
            }

            if (merged)
            {
                break;
            }
        }
    }
    while (merged);
}

private PixelAllocation allocateSurfacePixels(size_t needed) @nogc nothrow
{
    ensurePoolInitialized();

    if (needed == 0 || needed > maxCompositePixels)
    {
        return PixelAllocation.init;
    }

    foreach (i; 0 .. g_poolBlockCount)
    {
        auto block = &g_poolBlocks[i];
        if (!block.free || block.length < needed)
        {
            continue;
        }

        const offset = block.offset;
        const remaining = block.length - needed;

        block.free = false;
        block.length = needed;

        if (remaining > 0 && g_poolBlockCount < g_poolBlocks.length)
        {
            g_poolBlocks[g_poolBlockCount++] = PoolBlock(offset + needed, remaining, true);
        }

        return PixelAllocation(&g_surfacePool[offset], offset, needed);
    }

    return PixelAllocation.init;
}

private void freeSurfacePixels(size_t offset, size_t length) @nogc nothrow
{
    if (length == 0)
    {
        return;
    }

    ensurePoolInitialized();

    foreach (ref block; g_poolBlocks[0 .. g_poolBlockCount])
    {
        if (!block.free && block.offset == offset && block.length == length)
        {
            block.free = true;
            mergeFreeBlocks();
            break;
        }
    }
}

bool compositorAvailable()
{
    return g_compositor.available();
}

void compositorEnsureReady()
{
    if (!g_compositor.available())
    {
        g_compositor.configureFromFramebuffer();
    }
}

bool compositorAllocateSurface(uint width, uint height, out size_t id, out Canvas canvas)
{
    id = size_t.max;
    canvas = Canvas.init;

    if (width == 0 || height == 0)
    {
        return false;
    }

    const size_t needed = cast(size_t) width * height;
    if (needed > maxCompositePixels)
    {
        return false;
    }

    foreach (ref surface; g_surfaces)
    {
        if (surface.inUse)
        {
            continue;
        }

        const auto allocation = allocateSurfacePixels(needed);
        if (allocation.ptr is null)
        {
            return false;
        }

        surface.inUse = true;
        surface.id = ++g_nextSurfaceId;
        surface.width = width;
        surface.height = height;
        surface.pixels = allocation.ptr;
        surface.poolOffset = allocation.offset;
        surface.poolLength = allocation.length;

        id = surface.id;
        canvas = createBufferCanvas(surface.pixels, width, height, width);
        return canvas.available;
    }

    return false;
}

bool compositorResizeSurface(size_t id, uint width, uint height, out Canvas canvas)
{
    canvas = Canvas.init;
    auto surface = findSurface(id);
    if (surface is null)
    {
        return false;
    }

    const size_t needed = cast(size_t) width * height;
    if (needed == 0 || needed > maxCompositePixels)
    {
        return false;
    }

    const auto allocation = allocateSurfacePixels(needed);
    if (allocation.ptr is null)
    {
        return false;
    }

    freeSurfacePixels(surface.poolOffset, surface.poolLength);

    surface.width = width;
    surface.height = height;
    surface.pixels = allocation.ptr;
    surface.poolOffset = allocation.offset;
    surface.poolLength = allocation.length;

    canvas = createBufferCanvas(surface.pixels, width, height, width);
    return canvas.available;
}

void compositorReleaseSurface(size_t id)
{
    auto surface = findSurface(id);
    if (surface is null)
    {
        return;
    }

    freeSurfacePixels(surface.poolOffset, surface.poolLength);

    *surface = Surface.init;
}

void renderWorkspaceComposited(const WindowManager* manager)
{
    if (manager is null || !framebufferAvailable())
    {
        return;
    }

    compositorEnsureReady();
    if (!g_compositor.available())
    {
        return;
    }

    drawWallpaperToBuffer(g_compositor.buffer, g_compositor.width, g_compositor.height, g_compositor.pitch);

    const uint taskbarHeight = 32;
    drawTaskbar(manager, taskbarHeight);

    WindowEntry[WINDOW_MANAGER_CAPACITY] ordered;
    const size_t visibleCount = collectWindows(manager, ordered);
    drawWindows(ordered[0 .. visibleCount], taskbarHeight);

    g_compositor.present();
}

private size_t collectWindows(const WindowManager* manager, ref WindowEntry[WINDOW_MANAGER_CAPACITY] ordered)
{
    size_t count = 0;
    foreach (ref const window; manager.windows())
    {
        if (window.desktop == manager.activeDesktop() && !window.minimized)
        {
            ordered[count].window = &window;
            ++count;
        }
    }

    if (count == 0)
    {
        return 0;
    }

    foreach (i; 0 .. count)
    {
        size_t maxIndex = i;
        size_t maxZ = ordered[i].window.zOrder;
        foreach (j; i + 1 .. count)
        {
            if (ordered[j].window.zOrder > maxZ)
            {
                maxIndex = j;
                maxZ = ordered[j].window.zOrder;
            }
        }
        if (maxIndex != i)
        {
            auto tmp = ordered[i];
            ordered[i] = ordered[maxIndex];
            ordered[maxIndex] = tmp;
        }
    }

    return count;
}

private Surface* findSurface(size_t id) @nogc nothrow
{
    foreach (ref surface; g_surfaces)
    {
        if (surface.inUse && surface.id == id)
        {
            return &surface;
        }
    }

    return null;
}

private void blitSurface(const Surface* surface, uint destX, uint destY, uint maxWidth, uint maxHeight) @nogc nothrow
{
    if (surface is null || !g_compositor.available() || surface.pixels is null)
    {
        return;
    }

    const uint rows = (surface.height < maxHeight) ? surface.height : maxHeight;
    const uint cols = (surface.width < maxWidth) ? surface.width : maxWidth;

    foreach (y; 0 .. rows)
    {
        const uint targetY = destY + y;
        if (targetY >= g_compositor.height)
        {
            break;
        }

        const uint srcOffset = y * surface.width;
        const uint dstOffset = targetY * g_compositor.pitch + destX;

        foreach (x; 0 .. cols)
        {
            const uint targetX = destX + x;
            if (targetX >= g_compositor.width)
            {
                break;
            }

            g_compositor.buffer[dstOffset + x] = surface.pixels[srcOffset + x];
        }
    }
}

private void drawWindows(scope const(WindowEntry)[] windows, uint taskbarHeight)
{
    foreach (ref const entry; windows)
    {
        if (entry.window is null)
        {
            continue;
        }
        drawWindow(*entry.window, taskbarHeight);
    }
}

private void drawWindow(ref const Window window, uint taskbarHeight)
{
    const uint availableHeight = (g_compositor.height > taskbarHeight) ? g_compositor.height - taskbarHeight : g_compositor.height;
    if (window.y >= availableHeight || window.x >= g_compositor.width)
    {
        return;
    }

    const uint titleHeight = 24;
    g_compositor.fillRect(window.x, window.y, window.width, window.height, windowColor);
    g_compositor.drawRect(window.x, window.y, window.width, window.height, borderColor);

    const uint barColor = window.focused ? titleFocused : titleBarColor;
    g_compositor.fillRect(window.x, window.y, window.width, titleHeight, barColor);

    const uint buttonSize = 12;
    const uint padding = 6;
    const uint buttonY = window.y + (titleHeight > buttonSize ? (titleHeight - buttonSize) / 2 : 0);
    uint buttonX = window.x + window.width - (buttonSize + padding);
    g_compositor.fillRect(buttonX, buttonY, buttonSize, buttonSize, 0xFFCC5555);
    buttonX -= buttonSize + padding;
    g_compositor.fillRect(buttonX, buttonY, buttonSize, buttonSize, 0xFF66AA66);
    buttonX -= buttonSize + padding;
    g_compositor.fillRect(buttonX, buttonY, buttonSize, buttonSize, 0xFFCCCC66);

    g_compositor.drawString(window.x + padding, window.y + (titleHeight > glyphHeight ? (titleHeight - glyphHeight) / 2 : 0), window.title.ptr, textColor, barColor);

    if (window.height > titleHeight)
    {
        const uint contentY = window.y + titleHeight;
        const uint contentHeight = window.height - titleHeight;
        g_compositor.fillRect(window.x, contentY, window.width, contentHeight, contentFill);
        blitSurface(findSurface(window.surfaceId), window.x, contentY, window.width, contentHeight);
    }
}

private void drawTaskbar(const WindowManager* manager, uint taskbarHeight)
{
    const uint taskbarY = (g_compositor.height > taskbarHeight) ? g_compositor.height - taskbarHeight : 0;
    g_compositor.fillRect(0, taskbarY, g_compositor.width, taskbarHeight, taskbarColor);

    uint cursorX = 8;
    const uint cursorY = taskbarY + (taskbarHeight > glyphHeight ? (taskbarHeight - glyphHeight) / 2 : 0);

    cursorX = drawLabel(cursorX, cursorY, "desktops:");
    foreach (i; 0 .. manager.desktopCount())
    {
        const bool active = (i == manager.activeDesktop());
        cursorX = drawLabel(cursorX, cursorY, active ? "[" : " ");
        char[2] label = [cast(char)('1' + i), '\0'];
        cursorX = drawLabel(cursorX, cursorY, label.ptr);
        cursorX = drawLabel(cursorX, cursorY, active ? "]" : " ");
    }

    cursorX = drawLabel(cursorX + glyphWidth, cursorY, "layout:");
    immutable(char)[] layoutName = (manager.layoutForActiveDesktop() == LayoutMode.tiling) ? "tiling" : "floating";
    cursorX = drawLabel(cursorX, cursorY, layoutName.ptr);

    cursorX = drawLabel(cursorX + glyphWidth, cursorY, "focus:");
    char[32] buffer;
    const focused = manager.focusedWindowId();
    if (focused == size_t.max)
    {
        cursorX = drawLabel(cursorX, cursorY, "none");
    }
    else
    {
        formatUnsigned(focused, buffer[]);
        cursorX = drawLabel(cursorX, cursorY, buffer.ptr);
    }

    if (manager.shortcuts().length > 0)
    {
        cursorX = drawLabel(cursorX + glyphWidth, cursorY, "shortcuts:");
        foreach (ref const shortcut; manager.shortcuts())
        {
            cursorX = drawLabel(cursorX, cursorY, shortcut.name.ptr);
            cursorX = drawLabel(cursorX, cursorY, "->");
            cursorX = drawLabel(cursorX, cursorY, shortcut.action.ptr);
            cursorX += glyphWidth;
        }
    }
}

private uint drawLabel(uint cursorX, uint cursorY, const(char)* text)
{
    g_compositor.drawString(cursorX, cursorY, text, textColor, taskbarColor);
    size_t len = 0;
    for (auto p = text; *p != '\0'; ++p)
    {
        ++len;
    }
    return cursorX + cast(uint)(len) * glyphWidth;
}

private size_t formatUnsigned(size_t value, scope char[] buffer)
{
    if (buffer.length == 0)
    {
        return 0;
    }

    size_t index = buffer.length;
    buffer[--index] = '\0';
    do
    {
        if (index == 0)
        {
            break;
        }
        const digit = cast(char)('0' + (value % 10));
        buffer[--index] = digit;
        value /= 10;
    } while (value > 0);

    size_t start = index;
    size_t len = buffer.length - start - 1;
    foreach (i; 0 .. len)
    {
        buffer[i] = buffer[start + i];
    }
    buffer[len] = '\0';
    return len;
}
