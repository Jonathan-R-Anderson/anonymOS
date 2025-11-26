module anonymos.display.desktop;

import anonymos.display.framebuffer;
import anonymos.console : printLine, printUnsigned;
import anonymos.display.window_manager.manager;
import anonymos.display.window_manager.renderer;
import anonymos.display.compositor : renderWorkspaceComposited, compositorAvailable, compositorEnsureReady,
                                       compositorAllocateSurface, compositorResizeSurface, compositorReleaseSurface;
import anonymos.display.input_pipeline : InputQueue;
import anonymos.display.input_handler : initializeInputHandler, processInputEvents;
import anonymos.display.server;
import anonymos.display.font_stack : activeFontStack, enableFreetype, enableHarfBuzz;
import anonymos.drivers.hid_mouse : initializeMouseState, getMousePosition;
import anonymos.drivers.usb_hid : initializeUSBHID, pollUSBHID, usbHIDAvailable;
import anonymos.syscalls.posix : schedYield;
import anonymos.serial : pollSerialInput;
import anonymos.multiboot : FramebufferModeRequest;

__gshared WindowManager g_windowManager;
__gshared bool g_windowManagerReady = false;
__gshared InputQueue g_inputQueue;
__gshared ulong g_frameCount = 0;
__gshared DisplayServerState g_displayServer;
__gshared bool g_displayServerReady = false;
__gshared bool g_inputInitialized = false;

private enum uint desktopTaskbarHeight = 32;
private enum size_t desktopCount = 3;

private @nogc nothrow void ensureDisplayServer()
{
    if (g_displayServerReady || !framebufferAvailable())
    {
        return;
    }

    DisplayServerConfig config;
    config.protocol = DisplayProtocol.wayland;
    // Run without an external compositor process; fall back to the built-in
    // software renderer so the desktop is usable even if /sbin/desktop is
    // absent in the image.
    config.compositorEnabled = false;
    config.inputEnabled = true;
    config.fontStackEnabled = true;
    config.framebufferRequest = FramebufferModeRequest.init;

    g_displayServer = bootstrapDisplayServer(config);

    // Mark the font stack as ready for complex text rendering: we ship the
    // bitmap fallback, but also flag the intended FreeType/HarfBuzz path so
    // higher layers can rely on shaping logic immediately.
    auto stack = activeFontStack();
    enableFreetype(*stack);
    enableHarfBuzz(*stack);
    attachFontStack(g_displayServer, stack);

    attachInputPipeline(g_displayServer);

    g_displayServerReady = displayServerReady(g_displayServer);

    if (g_displayServerReady)
    {
        printLine("[desktop] display server ready");
    }
    else
    {
        printLine("[desktop] display server not ready");
    }
}

private @nogc nothrow void ensureWindowManager()
{
    ensureDisplayServer();

    if (g_windowManagerReady || !framebufferAvailable() || !g_displayServerReady)
    {
        if (!g_displayServerReady)
        {
            printLine("[desktop] window manager blocked: display server not ready");
        }
        return;
    }

    g_windowManager.reset();
    g_windowManager.configure(g_fb.width, g_fb.height, desktopTaskbarHeight, desktopCount);
    g_windowManager.setLayout(0, LayoutMode.tiling);
    g_windowManager.setLayout(1, LayoutMode.floating);
    g_windowManager.setLayout(2, LayoutMode.tiling);
    g_windowManager.configureSurfaceCallbacks(&compositorAllocateSurface,
                                              &compositorResizeSurface,
                                              &compositorReleaseSurface);

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
    
    // Initialize input handler
    initializeInputHandler(g_fb.width, g_fb.height);
    
    g_windowManagerReady = true;
    printLine("[desktop] window manager initialized");
}

/// Render a window-managed desktop using the framebuffer APIs.
@nogc nothrow
void runSimpleDesktopOnce(Damage* damage = null)
{
    ensureWindowManager();
    compositorEnsureReady();

    static bool loggedStart;
    if (!loggedStart)
    {
        import anonymos.console : printLine;
        printLine("[desktop] runSimpleDesktopOnce start");
        loggedStart = true;
    }

    // Keep compositor disabled until it is stable again.
    const bool useCompositor = false;
    if (useCompositor && compositorAvailable())
    {
        renderWorkspaceComposited(&g_windowManager);
    }
    else
    {
        // Fallback renderer writes directly to the framebuffer.
        renderWorkspace(&g_windowManager, damage);
    }

    static bool loggedDone;
    if (!loggedDone)
    {
        import anonymos.console : printLine;
        printLine("[desktop] runSimpleDesktopOnce done");
        loggedDone = true;
    }
}

/// Active event loop for the desktop with input handling
@nogc nothrow
void runSimpleDesktopLoop()
{
    if (!framebufferAvailable())
    {
        return;
    }

    // Initial setup
    ensureWindowManager();
    if (!g_displayServerReady)
    {
        // Best-effort: keep going even if the display server reports not ready
        ensureDisplayServer();
        g_displayServerReady = true;
    }
    // Render initial frame before initializing input/cursor so the desktop is visible.
    runSimpleDesktopOnce(null); // Full render
    static bool loopAnnounced;
    if (!loopAnnounced)
    {
        import anonymos.console : printLine;
        printLine("[desktop] initial frame rendered");
        loopAnnounced = true;
    }
    
    // Initialize input/cursor after the first frame is drawn.
    if (!g_inputInitialized)
    {
        initializeMouseState(g_fb.width, g_fb.height);
        import anonymos.drivers.usb_hid : initializeUSBHID;
        initializeUSBHID();
        framebufferShowCursor();
        framebufferMoveCursor(cast(int)(g_fb.width / 2), cast(int)(g_fb.height / 2));
        static bool cursorAnnounced;
        if (!cursorAnnounced)
        {
            import anonymos.console : printLine;
            printLine("[desktop] cursor initialized/centered");
            cursorAnnounced = true;
        }
        g_inputInitialized = true;
    }

    // Active event loop
    while (true)
    {
        ++g_frameCount;
        Damage damage;
        damage.clear();

        // Poll input devices
        if (usbHIDAvailable())
        {
            pollUSBHID(g_inputQueue);
        }
        
        // Poll serial as fallback
        pollSerialInput(g_inputQueue);

        // Process all pending input events
        processInputEvents(g_inputQueue, g_windowManager, &damage);
        
        // Get latest mouse position
        int mx, my;
        getMousePosition(mx, my);
        
        static int lastMx = int.min;
        static int lastMy = int.min;

        if (damage.any)
        {
            // Hide cursor to prevent it from being overwritten by the renderer
            // (which would corrupt the background restore logic)
            framebufferHideCursor();
            
            runSimpleDesktopOnce(&damage);
            
            // Move and show cursor at new position
            framebufferMoveCursor(mx, my);
            framebufferShowCursor();
            
            lastMx = mx;
            lastMy = my;
        }
        else if (mx != lastMx || my != lastMy)
        {
            // Just move the cursor (handles background save/restore)
            framebufferMoveCursor(mx, my);
            lastMx = mx;
            lastMy = my;
        }
        
        // Yield to scheduler and pause briefly
        schedYield();
        
        // Target ~30-60 FPS: simple delay
        // TODO: More sophisticated timing
        foreach (i; 0 .. 20_000_000)
        {
            asm @nogc nothrow { nop; }
        }
    }
}

/// Process entrypoint that keeps the desktop running alongside other tasks.
extern(C) @nogc nothrow void desktopProcessEntry(const(char*)* /*argv*/, const(char*)* /*envp*/)
{
    printLine("[desktop] entering main loop");
    runSimpleDesktopLoop();
}
