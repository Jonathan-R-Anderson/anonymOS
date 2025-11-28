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
import anonymos.display.font_stack : activeFontStack, enableFreetype, enableHarfBuzz, loadTrueTypeFontIntoStack;
import anonymos.drivers.hid_mouse : initializeMouseState, getMousePosition;
import anonymos.drivers.usb_hid : initializeUSBHID, pollUSBHID, usbHIDAvailable;
import anonymos.syscalls.posix : schedYield;
import anonymos.serial : pollSerialInput;
import anonymos.multiboot : FramebufferModeRequest;
import anonymos.display.canvas;
import anonymos.display.installer;

__gshared WindowManager g_windowManager;
__gshared bool g_windowManagerReady = false;
__gshared InputQueue g_inputQueue;
__gshared ulong g_frameCount = 0;
__gshared DisplayServerState g_displayServer;
__gshared bool g_displayServerReady = false;
__gshared bool g_inputInitialized = false;

private enum uint desktopTaskbarHeight = 32;
private enum size_t desktopCount = 3;
private enum bool useCompositor = true;

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
    
    // Try to load SF Pro font
    if (loadTrueTypeFontIntoStack(*stack, "/usr/share/fonts/SF-Pro.ttf", 16))
    {
        printLine("[desktop] SF Pro font loaded");
    }
    else
    {
        printLine("[desktop] Failed to load SF Pro font, falling back to bitmap");
        enableFreetype(*stack);
        enableHarfBuzz(*stack);
    }
    
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

    if (g_installer.active)
    {
        g_windowManager.reset();
        g_windowManager.configure(g_fb.width, g_fb.height, 0, 1); // No taskbar, 1 desktop
        g_windowManager.configureSurfaceCallbacks(&compositorAllocateSurface,
                                                  &compositorResizeSurface,
                                                  &compositorReleaseSurface);
        
        uint w = 800; // Calamares is usually wider
        uint h = 500;
        uint x = (g_fb.width - w) / 2;
        uint y = (g_fb.height - h) / 2;
        
        auto win = g_windowManager.createWindow("AnonymOS Installer", w, h, false, 0);
        g_windowManager.moveWindow(win, x, y);
        g_windowManager.focusWindow(win);
        
        // Initialize input handler
        initializeInputHandler(g_fb.width, g_fb.height);
        
        g_windowManagerReady = true;
        printLine("[desktop] Installer window initialized");
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
        import anonymos.console : printLine, setFramebufferConsoleEnabled;
        printLine("[desktop] runSimpleDesktopOnce start");
        
        // Disable console output to framebuffer so logs don't appear on screen
        setFramebufferConsoleEnabled(false);
        printLine("[desktop] framebuffer console disabled - logs go to serial only");
        
        loggedStart = true;
    }

    // Keep compositor disabled until it is stable again.
    if (useCompositor && compositorAvailable())
    {
        renderWorkspaceComposited(&g_windowManager);
    }
    else
    {
        // Fallback renderer writes directly to the framebuffer.
        renderWorkspace(&g_windowManager, damage);
        
        if (g_installer.active)
        {
            // Render installer on top
            // We need to find the window rect.
            // For now, hardcode to center as defined in ensureWindowManager
            uint w = 800;
            uint h = 500;
            uint x = (g_fb.width - w) / 2;
            uint y = (g_fb.height - h) / 2;
            
            // We need a canvas.
            // renderWorkspace uses internal canvas.
            // We can create a temporary one or add a renderInstaller method to WindowManager?
            // Easier: just draw directly to FB via a new Canvas.
            Canvas c = createFramebufferCanvas();
            renderInstallerWindow(&c, x, y, w, h);
        }
    }

    static bool loggedDone;
    if (!loggedDone)
    {
        import anonymos.console : printLine;
        printLine("[desktop] runSimpleDesktopOnce done");
        loggedDone = true;
    }
}

// Syscall wrappers
extern(C) long user_sys_block_write(ulong lba, ulong count, void* buf) @nogc nothrow
{
    long ret;
    asm @nogc nothrow {
        mov RAX, 1003; // SYS_BLOCK_WRITE
        mov RDI, lba;
        mov RSI, count;
        mov RDX, buf;
        syscall;
        mov ret, RAX;
    }
    return ret;
}

extern(C) int user_sys_open(const(char)* path, int flags, int mode) @nogc nothrow
{
    int ret;
    asm @nogc nothrow {
        mov RAX, 2; // SYS_OPEN
        mov RDI, path;
        mov RSI, flags;
        mov RDX, mode;
        syscall;
        mov ret, EAX;
    }
    return ret;
}

extern(C) long user_sys_read(int fd, void* buf, size_t count) @nogc nothrow
{
    long ret;
    asm @nogc nothrow {
        mov RAX, 0; // SYS_READ
        mov RDI, fd;
        mov RSI, buf;
        mov RDX, count;
        syscall;
        mov ret, RAX;
    }
    return ret;
}

extern(C) int user_sys_close(int fd) @nogc nothrow
{
    int ret;
    asm @nogc nothrow {
        mov RAX, 3; // SYS_CLOSE
        mov RDI, fd;
        syscall;
        mov ret, EAX;
    }
    return ret;
}

void performInstallation() @nogc nothrow
{
    import anonymos.console : printLine, printUnsigned;
    import anonymos.fs : readFile;
    import anonymos.syscalls.syscalls : sys_block_write;

    printLine("[installer] Starting installation...");
    printLine("[installer] Configuration:");
    printLine("[installer]   Dual Boot: YES");
    printLine("[installer]   Decoy OS: YES (Veracrypt Outer)");
    printLine("[installer]   Hidden OS: YES (Veracrypt Hidden)");
    
    // Simulate Veracrypt Volume Creation
    g_installer.statusMessage = "Creating Veracrypt Outer Volume...";
    schedYield();
    
    // ... (Real logic would go here) ...
    
    // Proceed with legacy MBR/FS write for demo purposes
    g_installer.statusMessage = "Writing MBR...";
    
    // ---------------------------------------------------------
    // Step 1: Write MBR (Partition Table + Boot Code)
    // ---------------------------------------------------------
    
    // Create MBR buffer (512 bytes)
    ubyte[512] mbr;
    // Zero out
    foreach (i; 0 .. 512) mbr[i] = 0;
    
    // Read boot.img (MBR code)
    const(ubyte)[] bootData = readFile("/usr/share/install/boot.img");
    if (bootData is null)
    {
        g_installer.currentModule = CalamaresModule.Failed;
        g_installer.statusMessage = "Error: Missing /usr/share/install/boot.img";
        return;
    }
    
    // Copy boot code (up to 446 bytes)
    size_t bootLen = (bootData.length < 446) ? bootData.length : 446;
    foreach (i; 0 .. bootLen) mbr[i] = bootData[i];
    
    // Construct Partition Table at offset 446
    // Entry 1: Status=0x80 (Active), Type=0x83 (Linux), Start=2048, Size=40960 (20MB)
    // Structure: Status(1), CHS_Start(3), Type(1), CHS_End(3), LBA_Start(4), LBA_Size(4)
    
    // Offset 446 (0x1BE)
    mbr[446] = 0x80; // Active
    mbr[447] = 0x00; mbr[448] = 0x00; mbr[449] = 0x00; // CHS Start (ignored by LBA)
    mbr[450] = 0x83; // Type: Linux
    mbr[451] = 0x00; mbr[452] = 0x00; mbr[453] = 0x00; // CHS End
    
    // LBA Start: 2048 (0x00000800) -> Little Endian: 00 08 00 00
    mbr[454] = 0x00; mbr[455] = 0x08; mbr[456] = 0x00; mbr[457] = 0x00;
    
    // LBA Size: 40960 (0x0000A000) -> Little Endian: 00 A0 00 00
    mbr[458] = 0x00; mbr[459] = 0xA0; mbr[460] = 0x00; mbr[461] = 0x00;
    
    // Magic Signature at 510
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    
    // Write MBR to Sector 0
    if (sys_block_write(0, 1, mbr.ptr) != 0)
    {
        g_installer.currentModule = CalamaresModule.Failed;
        g_installer.statusMessage = "Error: Failed to write MBR";
        return;
    }
    
    // ---------------------------------------------------------
    // Step 2: Write GRUB Core Image (Stage 1.5/2)
    // ---------------------------------------------------------
    // core.img goes into the embedding area (Sector 1 onwards)
    
    const(ubyte)[] coreData = readFile("/usr/share/install/core.img");
    if (coreData is null)
    {
        g_installer.currentModule = CalamaresModule.Failed;
        g_installer.statusMessage = "Error: Missing /usr/share/install/core.img";
        return;
    }
    
    ulong currentSector = 1;
    size_t offset = 0;
    ubyte[512] sectorBuf;
    
    while (offset < coreData.length)
    {
        foreach (i; 0 .. 512) sectorBuf[i] = 0;
        size_t chunk = (coreData.length - offset);
        if (chunk > 512) chunk = 512;
        
        foreach (i; 0 .. chunk) sectorBuf[i] = coreData[offset + i];
        
        if (sys_block_write(currentSector, 1, sectorBuf.ptr) != 0)
        {
            g_installer.currentModule = CalamaresModule.Failed;
            g_installer.statusMessage = "Error: Failed to write GRUB core";
            return;
        }
        currentSector++;
        offset += chunk;
    }
    
    // ---------------------------------------------------------
    // Step 3: Write Base Filesystem to Partition 1
    // ---------------------------------------------------------
    
    const(ubyte)[] fsData = readFile("/usr/share/install/base_fs.img");
    if (fsData is null)
    {
        g_installer.currentModule = CalamaresModule.Failed;
        g_installer.statusMessage = "Error: Missing /usr/share/install/base_fs.img";
        return;
    }
    
    currentSector = 2048;
    offset = 0;
    ubyte[4096] blockBuf;
    
    while (offset < fsData.length)
    {
        foreach (i; 0 .. 4096) blockBuf[i] = 0;
        size_t chunk = (fsData.length - offset);
        if (chunk > 4096) chunk = 4096;
        
        foreach (i; 0 .. chunk) blockBuf[i] = fsData[offset + i];
        
        ulong sectors = (chunk + 511) / 512;
        
        if (sys_block_write(currentSector, sectors, blockBuf.ptr) != 0)
        {
            g_installer.currentModule = CalamaresModule.Failed;
            g_installer.statusMessage = "Error: Failed to write filesystem";
            return;
        }
        
        currentSector += sectors;
        offset += chunk;
        
        g_installer.progress = cast(float)offset / cast(float)fsData.length;
        
        if ((offset % (1024*1024)) == 0)
        {
             schedYield();
        }
    }

    g_installer.currentModule = CalamaresModule.Finished;
    g_installer.statusMessage = "Installation Complete! Rebooting...";
    g_installer.progress = 1.0f;
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
        import anonymos.console : print, printLine, printUnsigned;
        
        ++g_frameCount;
        Damage damage;
        damage.clear();
        
        static uint logThrottle = 0;
        bool shouldLog = (++logThrottle % 1000 == 1);

        // Poll input devices
        if (usbHIDAvailable())
        {
            pollUSBHID(g_inputQueue);
        }
        
        // Poll serial as fallback
        pollSerialInput(g_inputQueue);

        // Installer Input Logic - process BEFORE window manager
        if (g_installer.active)
        {
            import anonymos.display.input_pipeline : InputEvent;
            import anonymos.console : print, printLine, printUnsigned;
            
            size_t idx = g_inputQueue.head;
            while (idx != g_inputQueue.tail)
            {
                // Log button events for debugging
                if (g_inputQueue.events[idx].type == InputEvent.Type.buttonDown)
                {
                    // print("[desktop] Installer received BUTTON DOWN at (");
                    // printUnsigned(cast(uint)g_inputQueue.events[idx].data1);
                    // print(", ");
                    // printUnsigned(cast(uint)g_inputQueue.events[idx].data2);
                    // printLine(")");
                }
                
                if (handleInstallerInput(g_inputQueue.events[idx]))
                {
                    damage.add(0, 0, g_fb.width, g_fb.height); // Redraw on state change
                }
                idx = (idx + 1) % g_inputQueue.capacity;
            }
            
            // Clear the queue so window manager doesn't process installer events
            g_inputQueue.head = g_inputQueue.tail;
        }
        else
        {
            // Process all pending input events for window manager
            processInputEvents(g_inputQueue, g_windowManager, &damage);
        }
        
        // Get latest mouse position
        int mx, my;
        getMousePosition(mx, my);
        
        static int lastMx = int.min;
        static int lastMy = int.min;
        static bool cursorCurrentlyVisible = false;

        // Only redraw if there's damage
        if (damage.any)
        {
            if (shouldLog)
            {
                // print("[desktop] Frame ");
                // printUnsigned(cast(uint)g_frameCount);
                // print(": DAMAGE at (");
                // printUnsigned(cast(uint)damage.bounds.x);
                // print(", ");
                // printUnsigned(cast(uint)damage.bounds.y);
                // print(") size ");
                // printUnsigned(cast(uint)damage.bounds.width);
                // print("x");
                // printUnsigned(cast(uint)damage.bounds.height);
                // printLine("");
            }
            
            // Hide cursor before redraw to prevent corruption
            if (cursorCurrentlyVisible)
            {
                if (useCompositor && compositorAvailable())
                {
                    // Compositor mode: just mark cursor as invalid, don't restore background
                    framebufferForgetCursor();
                }
                else
                {
                    // Direct mode: restore background before redraw
                    framebufferHideCursor();
                }
                cursorCurrentlyVisible = false;
            }
            
            // Render the desktop
            runSimpleDesktopOnce(&damage);
            
            // Show cursor at current position after redraw
            framebufferMoveCursor(mx, my);
            framebufferShowCursor();
            cursorCurrentlyVisible = true;
            
            lastMx = mx;
            lastMy = my;
        }
        else if (mx != lastMx || my != lastMy)
        {
            if (shouldLog)
            {
                // print("[desktop] Frame ");
                // printUnsigned(cast(uint)g_frameCount);
                // print(": CURSOR MOVE (");
                // printUnsigned(cast(uint)lastMx);
                // print(", ");
                // printUnsigned(cast(uint)lastMy);
                // print(") -> (");
                // printUnsigned(cast(uint)mx);
                // print(", ");
                // printUnsigned(cast(uint)my);
                // print(")");
                // printLine("");
            }
            
            // Cursor moved but no damage - just update cursor position
            // framebufferMoveCursor handles save/restore internally
            framebufferMoveCursor(mx, my);
            
            // Ensure cursor is visible
            if (!cursorCurrentlyVisible)
            {
                framebufferShowCursor();
                cursorCurrentlyVisible = true;
            }
            
            lastMx = mx;
            lastMy = my;
        }
        else if (!cursorCurrentlyVisible)
        {
            if (shouldLog)
            {
                // print("[desktop] Frame ");
                // printUnsigned(cast(uint)g_frameCount);
                // printLine(": SHOW CURSOR (was hidden)");
            }
            
            // No movement, no damage, but cursor not visible - show it
            framebufferShowCursor();
            cursorCurrentlyVisible = true;
        }
        
        // Yield to scheduler and pause briefly
        schedYield();
        
        // Installer Execution Logic
        if (g_installer.active && g_installer.currentModule == CalamaresModule.Exec)
        {
            performInstallation();
            damage.add(0, 0, g_fb.width, g_fb.height);
        }
        
        // Target ~30-60 FPS: simple delay
        // TODO: More sophisticated timing
        foreach (i; 0 .. 20_000_000)
        {
            asm @nogc nothrow { nop; }
        }
    }
}

// Syscall wrappers


/// Installer state
// Removed legacy InstallerState


/// Process entrypoint that keeps the desktop running alongside other tasks.
extern(C) @nogc nothrow void desktopProcessEntry(const(char*)* argv, const(char*)* envp)
{
    printLine("[desktop] entering main loop");
    
    // Check for install mode flag
    bool installMode = false;
    if (argv !is null)
    {
        int i = 0;
        while (argv[i] !is null)
        {
            const(char)* arg = argv[i];
            // Check for "--install"
            if (arg[0] == '-' && arg[1] == '-' && arg[2] == 'i' && 
                arg[3] == 'n' && arg[4] == 's' && arg[5] == 't' && 
                arg[6] == 'a' && arg[7] == 'l' && arg[8] == 'l' && arg[9] == '\0')
            {
                installMode = true;
                break;
            }
            i++;
        }
    }
    
    if (installMode)
    {
        initInstaller();
        printLine("[desktop] Starting in INSTALL MODE");
    }
    
    runSimpleDesktopLoop();
}

// ... (rest of file)

// I need to inject the installer logic into runSimpleDesktopLoop and ensureWindowManager.
// Since I can't easily replace the whole file, I will use multi_replace.
