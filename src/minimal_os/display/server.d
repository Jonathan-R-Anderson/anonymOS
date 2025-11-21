module minimal_os.display.server;

import minimal_os.display.framebuffer : framebufferAvailable;
import minimal_os.multiboot : FramebufferModeRequest;
import minimal_os.display.x11_stack;
import minimal_os.display.canvas : Canvas, createFramebufferCanvas;
import minimal_os.posix : spawnRegisteredProcess, pid_t;

/// Enumeration for the type of display server protocol we want to expose.
/// These are intentionally high level: the kernel still lacks the userspace
/// pieces needed to host a real Wayland or X11 runtime, but the enum makes it
/// clear which surface protocols the compositor scaffolding is targeting.
enum DisplayProtocol
{
    wayland,
    x11
}

/// Configuration flags that would be consumed by a compositor/window-manager
/// layer. The current implementation only records intent.
struct DisplayServerConfig
{
    DisplayProtocol protocol = DisplayProtocol.wayland;
    bool compositorEnabled = true;
    bool inputEnabled = true;
    bool fontStackEnabled = true;
    /// Mode selection passed down from the firmware tables. If left as init
    /// values the bootloader's chosen framebuffer is used.
    FramebufferModeRequest framebufferRequest;
    X11StackConfig x11Config;
}

/// Tracks runtime readiness for the display server and attached subsystems.
struct DisplayServerState
{
    DisplayServerConfig config;
    bool framebufferOnline;
    bool compositorReady;
    bool inputPlumbed;
    bool fontStackReady;
    Canvas framebufferCanvas;
    pid_t compositorPid;
    X11StackState x11Stack;
}

/// Provide a human-readable label for the requested protocol. Useful for logs
/// and status lines in the placeholder desktop.
const(char)[] protocolLabel(DisplayProtocol protocol) @nogc pure nothrow
{
    final switch (protocol)
    {
        case DisplayProtocol.wayland:
            return "Wayland";
        case DisplayProtocol.x11:
            return "X11";
    }
}

/// Initialize a display server state object based on the currently available
/// framebuffer. This does not attempt to bring up a real compositor; instead it
/// records which subsystems can be toggled on once the supporting packages are
/// added to the build.
DisplayServerState bootstrapDisplayServer(DisplayServerConfig config) @nogc nothrow
{
    DisplayServerState state;
    state.config = config;
    state.framebufferCanvas = createFramebufferCanvas();
    state.framebufferOnline = state.framebufferCanvas.available;
    if (config.protocol == DisplayProtocol.x11)
    {
        state.x11Stack = bootstrapX11Stack(config.x11Config);
    }
    if (config.compositorEnabled && state.framebufferOnline)
    {
        state.compositorPid = startCompositorProcess();
        state.compositorReady = state.compositorPid > 0;
    }
    else
    {
        state.compositorReady = false;
    }
    return state;
}

/// Attach an input pipeline once devices are enumerated. For now we gate the
/// flag on framebuffer availability so that downstream callers can check a
/// single struct instead of probing disparate drivers.
void attachInputPipeline(ref DisplayServerState state) @nogc nothrow
{
    if (!state.framebufferOnline)
    {
        return;
    }

    if (state.config.inputEnabled)
    {
        state.inputPlumbed = true;
    }
}

/// Attach a font stack. This is intentionally decoupled from framebuffer so
/// future work can plug in FreeType/HarfBuzz without changing call sites.
void attachFontStack(ref DisplayServerState state, bool ready) @nogc nothrow
{
    state.fontStackReady = ready && state.config.fontStackEnabled;
}

/// Aggregate readiness: callers can use this to decide whether to keep the
/// placeholder framebuffer UI or start a real compositor.
bool displayServerReady(ref DisplayServerState state) @nogc nothrow
{
    if (!state.framebufferOnline)
    {
        return false;
    }

    bool protocolReady = state.config.protocol == DisplayProtocol.wayland ?
                         state.compositorReady :
                         x11StackReady(state.x11Stack);

    if (!state.config.compositorEnabled && state.config.protocol == DisplayProtocol.wayland)
    {
        protocolReady = true;
    }

    if (!protocolReady)
    {
        return false;
    }

    return state.inputPlumbed && state.fontStackReady;
}

private pid_t startCompositorProcess() @nogc nothrow
{
    return spawnRegisteredProcess("/sbin/desktop", null, null);
}
