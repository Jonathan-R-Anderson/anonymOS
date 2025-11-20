module minimal_os.display.x11_stack;

import minimal_os.display.framebuffer : framebufferAvailable;

nothrow:
@nogc:

/// Basic display manager options recognised by the mock X11 stack.
enum DisplayManagerKind
{
    none,
    xdm,
    lightdm,
    gdm,
}

/// Configuration flags describing how the X11 server should be brought online.
struct X11StackConfig
{
    bool enableXorgServer = true;
    bool enableXinit = true;
    bool requireDisplayManager = true;
    DisplayManagerKind displayManager = DisplayManagerKind.xdm;
}

/// Runtime status for the X11 stack plumbing. This is bookkeeping only; the
/// actual Xorg server and display manager binaries are not yet bundled.
struct X11StackState
{
    X11StackConfig config;
    bool framebufferOnline;
    bool xorgServerReady;
    bool xinitReady;
    bool displayManagerReady;
    bool sessionReady;
}

/// Human-readable name for the configured display manager.
const(char)[] displayManagerLabel(DisplayManagerKind kind) @nogc pure nothrow
{
    final switch (kind)
    {
        case DisplayManagerKind.none:
            return "none";
        case DisplayManagerKind.xdm:
            return "xdm";
        case DisplayManagerKind.lightdm:
            return "lightdm";
        case DisplayManagerKind.gdm:
            return "gdm";
    }
}

/// Seed X11 stack state based on framebuffer availability and config intent.
X11StackState bootstrapX11Stack(X11StackConfig config) @nogc nothrow
{
    X11StackState state;
    state.config = config;
    state.framebufferOnline = framebufferAvailable();

    if (!state.framebufferOnline)
    {
        return state;
    }

    state.xorgServerReady = config.enableXorgServer;
    state.xinitReady = config.enableXinit;
    state.displayManagerReady = config.requireDisplayManager &&
                                config.displayManager != DisplayManagerKind.none;
    recomputeSessionReady(state);
    return state;
}

/// Toggle Xorg server readiness after dependency probing.
void markXorgServerReady(ref X11StackState state, bool ready) @nogc nothrow
{
    state.xorgServerReady = ready && state.framebufferOnline;
    recomputeSessionReady(state);
}

/// Toggle whether xinit-style session launching is available.
void markXinitReady(ref X11StackState state, bool ready) @nogc nothrow
{
    state.xinitReady = ready && state.framebufferOnline;
    recomputeSessionReady(state);
}

/// Toggle availability of the configured display manager.
void markDisplayManagerReady(ref X11StackState state, bool ready) @nogc nothrow
{
    state.displayManagerReady = ready && state.framebufferOnline &&
                                state.config.displayManager != DisplayManagerKind.none;
    recomputeSessionReady(state);
}

/// Aggregate readiness helper to simplify callers.
bool x11StackReady(ref X11StackState state) @nogc nothrow
{
    if (!state.framebufferOnline)
    {
        return false;
    }

    if (!state.xorgServerReady)
    {
        return false;
    }

    return state.displayManagerReady || state.xinitReady;
}

private void recomputeSessionReady(ref X11StackState state) @nogc nothrow
{
    state.sessionReady = state.xorgServerReady &&
                         (state.displayManagerReady || state.xinitReady);
}
