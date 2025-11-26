module anonymos.display.compositor;

import anonymos.display.framebuffer;
import anonymos.display.canvas;
import anonymos.display.font_stack : activeFontStack;
import anonymos.display.window_manager.manager;
import anonymos.display.wallpaper : drawWallpaperToBuffer;
import anonymos.display.gpu_accel : acceleratedPresentBuffer;
import core.stdc.string : memcpy;
import anonymos.console : printLine, printHex, printUnsigned, print;
import std.conv : to;

nothrow:
@nogc:

import core.stdc.string : memset;

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
        if (!ready || buffer is null)
        {
            return;
        }
        import anonymos.console : printLine;
        static bool loggedOnce;
        if (!loggedOnce)
        {
            printLine("Compositor.clear start");
            print("[compositor] clear width="); 
            import anonymos.console : printUnsigned, printHex;
            printUnsigned(width); print(" height="); printUnsigned(height);
            print(" pitch="); printUnsigned(pitch);
            print(" buffer="); printHex(cast(ulong)buffer); printLine("");
            loggedOnce = true;
        }

        const size_t total = cast(size_t) width * height;
        
        // Optimization: if color bytes are identical, use memset
        const ubyte b0 = color & 0xFF;
        const ubyte b1 = (color >> 8) & 0xFF;
        const ubyte b2 = (color >> 16) & 0xFF;
        const ubyte b3 = (color >> 24) & 0xFF;

        if (b0 == b1 && b1 == b2 && b2 == b3)
        {
        // Simple loop is safer than memset in this environment
        for (size_t i = 0; i < total; ++i)
        {
            buffer[i] = color;
        }
        }
        else
        {
            // D's array assignment is often optimized to a loop or memset-equivalent
            buffer[0 .. total] = color;
        }
    }

    void putPixel(uint x, uint y, uint color)
    {
        if (!ready || x >= width || y >= height)
        {
            return;
        }

        if (!ready || buffer is null || x >= width || y >= height)
        {
            return;
        }

        const size_t idx = cast(size_t)y * pitch + x;
        // Extra safety check for buffer overflow
        if (idx >= maxCompositePixels)
        {
            return;
        }
        buffer[idx] = color;
    }

    void fillRect(uint x, uint y, uint w, uint h, uint color)
    {
        if (!ready || w == 0 || h == 0)
        {
            return;
        }

        // Clip to screen bounds
        if (x >= width || y >= height) return;
        if (x + w > width) w = width - x;
        if (y + h > height) h = height - y;

        foreach (yy; y .. y + h)
        {
            const size_t rowOffset = cast(size_t)yy * pitch;
            const size_t startIdx = rowOffset + x;
            const size_t endIdx = startIdx + w;
            
            // Safety check for buffer overflow
            if (startIdx >= maxCompositePixels) break;
            const size_t safeEnd = (endIdx <= maxCompositePixels) ? endIdx : maxCompositePixels;

            for (size_t i = startIdx; i < safeEnd; ++i)
            {
                buffer[i] = color;
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

    void present()
    {
        import anonymos.console : printLine, printUnsigned, print;

        static bool loggedOnce;
        // Evaluate framebuffer availability once so the value matches what we print
        const bool fbAvail = framebufferAvailable();

        if (!ready || !fbAvail)
        {
            if (!loggedOnce)
            {
                print("[compositor] present early-exit ready="); print(ready ? "true" : "false");
                print(" fbAvail="); print(fbAvail ? "true" : "false"); printLine("");
            }
            return;
        }

        if (!loggedOnce)
        {
            const auto fb = framebufferDescriptor();
            print("[compositor] present start "); printUnsigned(width); print("x"); printUnsigned(height);
            print(" pitch="); printUnsigned(pitch);
            print(" fb="); printUnsigned(cast(uint)fb.width); print("x"); printUnsigned(cast(uint)fb.height);
            print(" bpp="); printUnsigned(cast(uint)fb.bpp); printLine("");
        }

        if (acceleratedPresentBuffer(buffer, width, height, pitch))
        {
            if (!loggedOnce) printLine("[compositor] accelerated present");
            loggedOnce = true;
            return;
        }

        // Fast path for 32bpp
        auto fb = framebufferDescriptor();
        if (fb.addr !is null && fb.bpp == 32 && fb.width == width && fb.height == height)
        {
            const bool isBGR = fb.isBGR;
            uint* fbPtr = cast(uint*)fb.addr;
            const uint fbPitchPixels = fb.pitch / 4; // pitch is bytes, we need pixels for uint* pointer math
            const size_t copyBytes = cast(size_t)width * 4;

            foreach (y; 0 .. height)
            {
                const(uint)* srcRow = buffer + y * pitch;
                uint* dstRow = fbPtr + y * fbPitchPixels;

                if (!isBGR)
                {
                    memcpy(dstRow, srcRow, copyBytes);
                }
                else
                {
                    for (uint x = 0; x < width; ++x)
                    {
                        const uint c = srcRow[x];
                        dstRow[x] = (c & 0xFF00FF00) | ((c & 0xFF) << 16) | ((c >> 16) & 0xFF);
                    }
                }
            }
            if (!loggedOnce) printLine("[compositor] present memcpy path");
            loggedOnce = true;
            return;
        }

        // Fallback for non-32bpp or dimension mismatch
        foreach (y; 0 .. height)
        {
            foreach (x; 0 .. width)
            {
                framebufferPutPixel(x, y, buffer[y * pitch + x]);
            }
        }
        if (!loggedOnce) printLine("[compositor] present fallback complete");
        loggedOnce = true;
    }



}

private __gshared Compositor g_compositor;
private __gshared uint[128] g_padding; // Safety padding to detect/prevent overflow
private __gshared align(16) uint[maxCompositePixels] g_compositorBackBuffer;
private __gshared Surface[WINDOW_MANAGER_CAPACITY] g_surfaces;
private __gshared size_t g_nextSurfaceId;
private __gshared align(16) uint[maxCompositePixels] g_surfacePool;
private __gshared PoolBlock[WINDOW_MANAGER_CAPACITY * 2] g_poolBlocks;
private __gshared size_t g_poolBlockCount;

private Canvas compositorCanvas() @nogc nothrow
{
    return createBufferCanvas(g_compositor.buffer, g_compositor.width, g_compositor.height, g_compositor.pitch);
}

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

        auto allocation = allocateSurfacePixels(needed);
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

    auto allocation = allocateSurfacePixels(needed);
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
    import anonymos.console : printLine, print, printUnsigned;
    if (manager is null || !framebufferAvailable())
    {
        return;
    }

    compositorEnsureReady();
    if (!g_compositor.available())
    {
        return;
    }

    static bool loggedStart;
    if (!loggedStart)
    {
        printLine("[compositor] renderWorkspaceComposited start");
        loggedStart = true;
    }

    // drawWallpaperToBuffer(g_compositor.buffer, g_compositor.width, g_compositor.height, g_compositor.pitch);
    g_compositor.clear(0xFF202020);

    static uint frameLogs;
    if (frameLogs < 1) printLine("[compositor] cleared buffer");

    const uint taskbarHeight = 32;
    drawTaskbar(manager, taskbarHeight);
    if (frameLogs < 1) printLine("[compositor] taskbar drawn");

    /*
    WindowEntry[WINDOW_MANAGER_CAPACITY] ordered;
    const size_t visibleCount = collectWindows(manager, ordered);
    import anonymos.console : printUnsigned;
    print("[compositor] windows pending: ");
    printUnsigned(visibleCount);
    printLine("");
    */
    // Skip window blitting for now to avoid potential stalls; just present the cleared buffer + taskbar.
    if (frameLogs < 1) printLine("[compositor] windows drawing skipped");

    g_compositor.present();
    if (frameLogs < 1) printLine("[compositor] present done");
    ++frameLogs;

    static bool loggedEnd;
    if (!loggedEnd)
    {
        printLine("[compositor] renderWorkspaceComposited end");
        loggedEnd = true;
    }
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

        for (uint x = 0; x < cols; ++x)
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

    import anonymos.console : print, printLine, printUnsigned, printHex;
    static uint windowLogs;

    auto canvas = compositorCanvas();

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

    canvasText(canvas, activeFontStack(), window.x + padding, window.y + (titleHeight > glyphHeight ? (titleHeight - glyphHeight) / 2 : 0), window.title, textColor, barColor);

    if (window.height > titleHeight)
    {
        const uint contentY = window.y + titleHeight;
        const uint contentHeight = window.height - titleHeight;
        g_compositor.fillRect(window.x, contentY, window.width, contentHeight, contentFill);
        if (windowLogs < 4)
        {
            print("[compositor] window surface "); printUnsigned(window.surfaceId); print(" size "); printUnsigned(window.width); print("x"); printUnsigned(window.height); printLine("");
        }
        // Temporarily skip blitting window content to avoid stalls if surfaces are missing.
        // blitSurface(findSurface(window.surfaceId), window.x, contentY, window.width, contentHeight);
    }

    if (windowLogs < 4)
    {
        ++windowLogs;
    }
}

private void drawTaskbar(const WindowManager* manager, uint taskbarHeight)
{
    const uint taskbarY = (g_compositor.height > taskbarHeight) ? g_compositor.height - taskbarHeight : 0;
    g_compositor.fillRect(0, taskbarY, g_compositor.width, taskbarHeight, taskbarColor);

    uint cursorX = 8;
    const uint cursorY = taskbarY + (taskbarHeight > glyphHeight ? (taskbarHeight - glyphHeight) / 2 : 0);

    auto canvas = compositorCanvas();
    cursorX = drawLabel(canvas, cursorX, cursorY, "desktops:");
    foreach (i; 0 .. manager.desktopCount())
    {
        const bool active = (i == manager.activeDesktop());
        cursorX = drawLabel(canvas, cursorX, cursorY, active ? "[" : " ");
        char[2] label = [cast(char)('1' + i), '\0'];
        cursorX = drawLabel(canvas, cursorX, cursorY, label[0 .. 1]);
        cursorX = drawLabel(canvas, cursorX, cursorY, active ? "]" : " ");
    }

    cursorX = drawLabel(canvas, cursorX + glyphWidth, cursorY, "layout:");
    immutable(char)[] layoutName = (manager.layoutForActiveDesktop() == LayoutMode.tiling) ? "tiling" : "floating";
    cursorX = drawLabel(canvas, cursorX, cursorY, layoutName);

    cursorX = drawLabel(canvas, cursorX + glyphWidth, cursorY, "focus:");
    char[32] buffer;
    const size_t focused = manager.focusedWindowId();
    size_t formatted = 0;
    if (focused != size_t.max)
    {
        formatted = formatUnsigned(focused, buffer[]);
    }
    cursorX = (formatted == 0) ? drawLabel(canvas, cursorX, cursorY, "none")
                               : drawLabel(canvas, cursorX, cursorY, buffer[0 .. formatted]);

    if (manager.shortcuts().length > 0)
    {
        cursorX = drawLabel(canvas, cursorX + glyphWidth, cursorY, "shortcuts:");
        foreach (ref const shortcut; manager.shortcuts())
        {
            cursorX = drawLabel(canvas, cursorX, cursorY, shortcut.name);
            cursorX = drawLabel(canvas, cursorX, cursorY, "->");
            cursorX = drawLabel(canvas, cursorX, cursorY, shortcut.action);
            cursorX += glyphWidth;
        }
    }
}

private uint drawLabel(ref Canvas canvas, uint cursorX, uint cursorY, const(char)[] text)
{
    const uint width = canvasText(canvas, activeFontStack(), cursorX, cursorY, text, textColor, taskbarColor);
    return cursorX + width;
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
