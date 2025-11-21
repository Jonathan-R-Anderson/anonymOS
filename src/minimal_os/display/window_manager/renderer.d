module minimal_os.display.window_manager.renderer;

import minimal_os.display.framebuffer;
import minimal_os.display.window_manager.manager;
import minimal_os.display.wallpaper : drawWallpaperToFramebuffer;

nothrow:
@nogc:

private enum uint taskbarColor    = 0xFF303030;
private enum uint windowColor     = 0xFF2C2C2C;
private enum uint titleBarColor   = 0xFF383838;
private enum uint titleFocused    = 0xFF4650C0;
private enum uint borderColor     = 0xFF505050;
private enum uint textColor       = 0xFFFFFFFF;
private enum uint contentColor    = 0xFF1C1C1C;

private struct WindowEntry
{
    const(Window)* window;
}

void renderWorkspace(const WindowManager* manager)
{
    if (manager is null || !framebufferAvailable())
    {
        return;
    }

    drawWallpaperToFramebuffer();

    const uint taskbarHeight = 32;
    drawTaskbar(manager, taskbarHeight);

    WindowEntry[WINDOW_MANAGER_CAPACITY] ordered;
    const size_t visibleCount = collectWindows(manager, ordered);
    drawWindows(ordered[0 .. visibleCount], taskbarHeight);
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

    // Sort by z-order so the most recently focused window is drawn last.
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
    const uint availableHeight = (g_fb.height > taskbarHeight) ? g_fb.height - taskbarHeight : g_fb.height;
    if (window.y >= availableHeight || window.x >= g_fb.width)
    {
        return;
    }

    const uint titleHeight = 24;
    framebufferFillRect(window.x, window.y, window.width, window.height, windowColor);
    framebufferDrawRect(window.x, window.y, window.width, window.height, borderColor, false);

    const uint barColor = window.focused ? titleFocused : titleBarColor;
    framebufferFillRect(window.x, window.y, window.width, titleHeight, barColor);

    // Decorations: simple close / min / max boxes.
    const uint buttonSize = 12;
    const uint padding = 6;
    const uint buttonY = window.y + (titleHeight > buttonSize ? (titleHeight - buttonSize) / 2 : 0);
    uint buttonX = window.x + window.width - (buttonSize + padding);
    framebufferFillRect(buttonX, buttonY, buttonSize, buttonSize, 0xFFCC5555);
    buttonX -= buttonSize + padding;
    framebufferFillRect(buttonX, buttonY, buttonSize, buttonSize, 0xFF66AA66);
    buttonX -= buttonSize + padding;
    framebufferFillRect(buttonX, buttonY, buttonSize, buttonSize, 0xFFCCCC66);

    framebufferSetTextColors(textColor, barColor);
    g_fbCursorX = (window.x + padding) / glyphWidth;
    g_fbCursorY = (window.y + (titleHeight > glyphHeight ? (titleHeight - glyphHeight) / 2 : 0)) / glyphHeight;
    framebufferWriteString(window.title);

    if (window.height > titleHeight)
    {
        const uint contentY = window.y + titleHeight;
        const uint contentHeight = window.height - titleHeight;
        framebufferFillRect(window.x, contentY, window.width, contentHeight, contentColor);
    }
}

private void drawTaskbar(const WindowManager* manager, uint taskbarHeight)
{
    const uint taskbarY = (g_fb.height > taskbarHeight) ? g_fb.height - taskbarHeight : 0;
    framebufferFillRect(0, taskbarY, g_fb.width, taskbarHeight, taskbarColor);

    framebufferSetTextColors(textColor, taskbarColor);
    g_fbCursorX = 1;
    g_fbCursorY = taskbarY / glyphHeight;

    framebufferWriteString("desktops: ");
    foreach (i; 0 .. manager.desktopCount())
    {
        const bool active = (i == manager.activeDesktop());
        framebufferWriteString(active ? "[" : " ");
        auto ch = cast(char)('1' + i);
        char[2] label = [ch, '\0'];
        framebufferWriteString(label[0 .. 1]);
        framebufferWriteString(active ? "]" : " ");
    }

    framebufferWriteString("  layout: ");
    immutable(char)[] layoutName = (manager.layoutForActiveDesktop() == LayoutMode.tiling) ? "tiling" : "floating";
    framebufferWriteString(layoutName);

    framebufferWriteString("  focus: ");
    const focused = manager.focusedWindowId();
    if (focused == size_t.max)
    {
        framebufferWriteString("none");
    }
    else
    {
        char[32] buffer;
        const len = formatUnsigned(focused, buffer[]);
        framebufferWriteString(buffer[0 .. len]);
    }

    if (manager.shortcuts().length > 0)
    {
        framebufferWriteString("  shortcuts: ");
        foreach (ref const shortcut; manager.shortcuts())
        {
            framebufferWriteString(shortcut.name);
            framebufferWriteString("->");
            framebufferWriteString(shortcut.action);
            framebufferWriteString("  ");
        }
    }
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

    // Shift to the front if we did not fill the buffer.
    size_t start = index;
    size_t len = buffer.length - start - 1;
    foreach (i; 0 .. len)
    {
        buffer[i] = buffer[start + i];
    }
    buffer[len] = '\0';
    return len;
}
