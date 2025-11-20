module minimal_os.display.desktop;

import minimal_os.display.framebuffer;
import minimal_os.display.window_manager.manager;
import minimal_os.display.window_manager.renderer;
import minimal_os.display.compositor : renderWorkspaceComposited, compositorAvailable, compositorEnsureReady;
import minimal_os.kernel.shell_integration : schedYield;

__gshared WindowManager g_windowManager;
__gshared bool g_windowManagerReady = false;

private enum uint desktopTaskbarHeight = 32;
private enum size_t desktopCount = 3;

private @nogc nothrow void ensureWindowManager()
{
    if (g_windowManagerReady || !framebufferAvailable())
    {
        return;
    }

    g_windowManager.reset();
    g_windowManager.configure(g_fb.width, g_fb.height, desktopTaskbarHeight, desktopCount);
    g_windowManager.setLayout(0, LayoutMode.tiling);
    g_windowManager.setLayout(1, LayoutMode.floating);
    g_windowManager.setLayout(2, LayoutMode.tiling);

    const uint halfW = g_fb.width / 2;
    const uint halfH = g_fb.height / 2;
    const uint thirdW = g_fb.width / 3;
    const uint quarterH = g_fb.height / 4;

    auto editor = g_windowManager.createWindow("text editor", halfW, halfH, false, 0);
    auto monitor = g_windowManager.createWindow("system monitor", thirdW, halfH, false, 0);
    auto console = g_windowManager.createWindow("console", thirdW, quarterH, true, 0);
    g_windowManager.moveWindow(console, cast(int) (g_fb.width - thirdW - 24), 24);
    g_windowManager.resizeWindow(monitor, 0, -cast(int) (quarterH / 2));
    g_windowManager.focusWindow(editor);

    auto docs = g_windowManager.createWindow("docs", halfW, halfH, true, 1);
    g_windowManager.moveWindow(docs, 24, 24);
    g_windowManager.toggleFloating(docs, true);

    auto tools = g_windowManager.createWindow("tools", thirdW, halfH, false, 2);
    g_windowManager.maximizeWindow(tools, true);

    g_windowManager.registerShortcut("Alt+Tab", "cycle focus");
    g_windowManager.registerShortcut("Super+Arrow", "snap to tile");
    g_windowManager.registerShortcut("Ctrl+F", "toggle floating");
    g_windowManager.registerShortcut("Ctrl+Win+Left/Right", "switch desktop");

    g_windowManager.switchDesktop(0);
    g_windowManagerReady = true;
}

/// Render a window-managed desktop using the framebuffer APIs.
@nogc nothrow
void runSimpleDesktopOnce()
{
    ensureWindowManager();
    compositorEnsureReady();

    if (compositorAvailable())
    {
        renderWorkspaceComposited(&g_windowManager);
    }
    else
    {
        renderWorkspace(&g_windowManager);
    }
}

/// Continuously re-render the desktop while cooperating with the scheduler.
@nogc nothrow
void runSimpleDesktopLoop()
{
    if (!framebufferAvailable())
    {
        return;
    }

    runSimpleDesktopOnce();

    while (true)
    {
        schedYield();
        asm @nogc nothrow { hlt; }
    }
}

/// Process entrypoint that keeps the desktop running alongside other tasks.
extern(C) @nogc nothrow void desktopProcessEntry(const(char*)* /*argv*/, const(char*)* /*envp*/)
{
    runSimpleDesktopLoop();
}
