module minimal_os.display.compositor;

import minimal_os.display.framebuffer;
import minimal_os.display.window_manager.manager;

nothrow:
@nogc:

private enum uint maxCompositeWidth  = 1920;
private enum uint maxCompositeHeight = 1080;
private enum size_t maxCompositePixels = cast(size_t) maxCompositeWidth * maxCompositeHeight;

private enum uint backgroundColor = 0xFF202020;
private enum uint taskbarColor    = 0xFF303030;
private enum uint windowColor     = 0xFF2C2C2C;
private enum uint titleBarColor   = 0xFF383838;
private enum uint titleFocused    = 0xFF4650C0;
private enum uint borderColor     = 0xFF505050;
private enum uint textColor       = 0xFFFFFFFF;

private immutable ubyte[glyphHeight] compositorGlyph = [
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

private struct WindowEntry
{
    const(Window)* window;
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

    void drawGlyph(uint px, uint py, uint fg, uint bg)
    {
        foreach (row; 0 .. glyphHeight)
        {
            const bits = compositorGlyph[row];
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
            drawGlyph(cursorX, py, fg, bg);
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

    g_compositor.clear(backgroundColor);

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
