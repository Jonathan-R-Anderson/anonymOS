module core.hs_bridge;

import arch.x86_64.bootstrap : g_fb, g_terminal, fb_putchar;
import display.compositor.compositor : compositorAllocateSurface, compositorEnsureReady,
    compositorReleaseSurface, compositorResizeSurface, renderWorkspaceComposited;
import display.framebuffer : framebufferAvailable, initFramebuffer;
import display.wayland.wserver : initWaylandServer, waylandServerReady, waylandUpdate;
import display.input_handler : initializeInputHandler, processInputEvents;
import display.input_pipeline : InputQueue;
import display.window_manager.manager : Damage, LayoutMode, WindowManager;
import drivers.input.usb_hid : pollUSBHID;
import core.io : klog;

extern(C):

__gshared bool g_displayInitialized = false;
__gshared bool g_driversInitialized = false;
__gshared uint g_heartbeatTick = 0;

private struct DesktopState
{
    bool initialized;
    uint width;
    uint height;
    uint heartbeatCount;
    bool inputInitialized;
    bool waylandInitialized;
    bool waylandOnline;
    WindowManager manager;
    InputQueue inputQueue;
    Damage damage;
}

__gshared DesktopState g_desktop;

void d_puts(const(char)* msg) @nogc nothrow {
    if (msg is null) {
        return;
    }
    for (size_t i = 0; msg[i] != 0; ++i) {
        fb_putchar(msg[i]);
    }
}

private void desktopInitialize() @nogc nothrow
{
    if (g_desktop.initialized || !framebufferAvailable() || g_fb is null) {
        return;
    }

    g_desktop = DesktopState.init;
    g_desktop.width = cast(uint) g_fb.width;
    g_desktop.height = cast(uint) g_fb.height;

    compositorEnsureReady();
    g_desktop.manager.reset();
    g_desktop.manager.configure(g_desktop.width, g_desktop.height, 0, 1);
    g_desktop.manager.configureSurfaceCallbacks(&compositorAllocateSurface,
                                                &compositorResizeSurface,
                                                &compositorReleaseSurface);
    g_desktop.manager.setLayout(0, LayoutMode.floating, null);

    initializeInputHandler(g_desktop.width, g_desktop.height);
    g_desktop.inputInitialized = false;
    klog("[display] desktop input bring-up deferred\n");

    initWaylandServer();
    g_desktop.waylandInitialized = true;
    g_desktop.waylandOnline = waylandServerReady();
    if (g_desktop.waylandOnline) {
        klog("[display] wayland bridge listening on /run/user/1000/wayland-0\n");
    } else {
        klog("[display] wayland bridge failed to start\n");
    }

    g_desktop.initialized = true;
    klog("[display] display bridge ready\n");
    d_puts("[display] display bridge active\n\0".ptr);
}

int d_init_display() @nogc nothrow {
    klog("[display] d_init_display entered\n");
    if (g_displayInitialized) {
        klog("[display] d_init_display: already initialized\n");
        return g_fb !is null ? 1 : 0;
    }

    if (g_fb is null) {
        klog("[display] d_init_display: framebuffer unavailable\n");
        return 0;
    }

    if (!framebufferAvailable()) {
        const bool isBGR = g_fb.blue_mask_shift > g_fb.red_mask_shift;
        initFramebuffer(cast(const(void)*) g_fb.address,
                        cast(uint) g_fb.width,
                        cast(uint) g_fb.height,
                        cast(uint) g_fb.pitch,
                        cast(uint) g_fb.bpp,
                        isBGR,
                        0,
                        true);
        if (!framebufferAvailable()) {
            klog("[display] d_init_display: framebuffer init failed\n");
            return 0;
        }
        klog("[display] d_init_display: imported firmware framebuffer\n");
    }

    g_displayInitialized = true;
    klog("[display] d_init_display: framebuffer ready\n");
    d_puts("[display] D display bridge online\n\0".ptr);
    return 1;
}

int d_init_drivers() @nogc nothrow {
    klog("[drivers] d_init_drivers entered\n");
    if (g_driversInitialized) {
        klog("[drivers] d_init_drivers: already initialized\n");
        return 1;
    }

    // Boot-critical drivers are wired in D bootstrap: serial, Limine terminal, framebuffer.
    if (g_terminal is null && g_fb is null) {
        klog("[drivers] d_init_drivers: no terminal or framebuffer yet\n");
        return 0;
    }

    g_driversInitialized = true;
    klog("[drivers] d_init_drivers: driver bridge ready\n");
    d_puts("[drivers] D driver bridge online\n\0".ptr);
    return 1;
}

int d_display_is_ready() @nogc nothrow {
    return (g_displayInitialized && g_fb !is null) ? 1 : 0;
}

int d_drivers_are_ready() @nogc nothrow {
    return g_driversInitialized ? 1 : 0;
}

void d_display_heartbeat() @nogc nothrow {
    if (g_heartbeatTick == 0) {
        klog("[display] d_display_heartbeat entered\n");
    }

    if (!g_displayInitialized || g_fb is null) {
        if (g_heartbeatTick == 0) {
            klog("[display] heartbeat skipped: display not ready\n");
        }
        return;
    }

    ++g_heartbeatTick;
    if (g_heartbeatTick == 1) {
        klog("[display] heartbeat dispatching desktopInitialize\n");
    }
    desktopInitialize();
    if (!g_desktop.initialized) {
        if (g_heartbeatTick == 1) {
            klog("[display] heartbeat: desktop still not initialized\n");
        }
        return;
    }

    ++g_desktop.heartbeatCount;
    if (g_desktop.heartbeatCount == 1) {
        klog("[display] heartbeat: display bridge compositing\n");
    }

    if (g_desktop.inputInitialized) {
        pollUSBHID(g_desktop.inputQueue);
        processInputEvents(g_desktop.inputQueue, g_desktop.manager, &g_desktop.damage);
    }

    if (g_desktop.waylandInitialized && g_desktop.waylandOnline) {
        waylandUpdate();
    }

    if ((g_desktop.heartbeatCount & 0x0F) == 0) {
        g_desktop.waylandOnline = g_desktop.waylandInitialized && waylandServerReady();
    }

    renderWorkspaceComposited(&g_desktop.manager);
}
