module minimal_os.desktop;

import minimal_os.framebuffer;

/// Render a static placeholder desktop using the framebuffer APIs.
@nogc nothrow
void runSimpleDesktopOnce()
{
    if (!framebufferAvailable())
    {
        return;
    }

    enum uint backgroundColor = 0xFF202020;
    enum uint taskbarColor    = 0xFF303030;
    enum uint windowColor     = 0xFF2C2C2C;
    enum uint titleBarColor   = 0xFF383838;
    enum uint borderColor     = 0xFF505050;
    enum uint textColor       = 0xFFFFFFFF;

    framebufferFill(backgroundColor);

    enum uint taskbarHeight = 32;
    const uint taskbarY = (g_fb.height > taskbarHeight) ? g_fb.height - taskbarHeight : 0;
    framebufferFillRect(0, taskbarY, g_fb.width, taskbarHeight, taskbarColor);

    const uint windowWidth  = g_fb.width / 2;
    const uint windowHeight = g_fb.height / 2;
    const uint availableHeight = (g_fb.height > taskbarHeight) ? g_fb.height - taskbarHeight : g_fb.height;
    const uint windowX = (g_fb.width  > windowWidth)  ? (g_fb.width  - windowWidth)  / 2 : 0;
    const uint windowY = (availableHeight > windowHeight) ? (availableHeight - windowHeight) / 2 : 0;

    framebufferFillRect(windowX, windowY, windowWidth, windowHeight, windowColor);
    framebufferDrawRect(windowX, windowY, windowWidth, windowHeight, borderColor, false);

    enum uint titleHeight = 24;
    framebufferFillRect(windowX, windowY, windowWidth, titleHeight, titleBarColor);

    framebufferSetTextColors(textColor, titleBarColor);
    g_fbCursorX = (windowX + 8) / glyphWidth;
    g_fbCursorY = (windowY + (titleHeight > glyphHeight ? (titleHeight - glyphHeight) / 2 : 0)) / glyphHeight;
    framebufferWriteString("minimal_os desktop (placeholder)");
}

/// Continuously re-render the placeholder desktop.
@nogc nothrow
void runSimpleDesktopLoop()
{
    while (true)
    {
        runSimpleDesktopOnce();
    }
}
