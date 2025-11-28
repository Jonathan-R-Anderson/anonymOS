# Installer Not Loading - Fix Summary

## Problem

The installer window was being initialized but not displayed on screen.

### Logs Analysis

The logs showed:
```
[desktop] Starting in INSTALL MODE
[desktop] Installer window initialized
[compositor] renderWorkspaceComposited start
[compositor] cleared buffer
[compositor] taskbar drawn
[compositor] windows drawing skipped
[compositor] present done
```

**Notice**: No "[compositor] rendering installer" message!

## Root Cause

The installer rendering code was only in the **non-compositor rendering path**:

```d
// In desktop.d, runSimpleDesktopOnce()
if (useCompositor && compositorAvailable())
{
    renderWorkspaceComposited(&g_windowManager);  // ← Installer NOT rendered here
}
else
{
    renderWorkspace(&g_windowManager, damage);
    
    if (g_installer.active)
    {
        // Render installer on top  // ← Only rendered in fallback path
        Canvas c = createFramebufferCanvas();
        renderInstallerWindow(&c, x, y, w, h);
    }
}
```

Since `useCompositor = true` (line 31 of desktop.d), the compositor path was being used, but it had no installer rendering logic!

## The Fix

Added installer rendering to `renderWorkspaceComposited()` in `compositor.d`:

```d
// Render installer if active
import anonymos.display.installer : g_installer, renderInstallerWindow;
if (g_installer.active)
{
    if (frameLogs < 1) printLine("[compositor] rendering installer");
    
    // Create canvas pointing to compositor buffer
    import anonymos.display.canvas : Canvas;
    import anonymos.display.framebuffer : g_fb;
    
    Canvas c;
    c.buffer = g_compositor.buffer;
    c.width = g_compositor.width;
    c.height = g_compositor.height;
    c.pitch = g_compositor.pitch;
    
    // Calculate installer window position (centered)
    uint w = 800;
    uint h = 500;
    uint x = (g_fb.width - w) / 2;
    uint y = (g_fb.height - h) / 2;
    
    renderInstallerWindow(&c, cast(int)x, cast(int)y, cast(int)w, cast(int)h);
    
    if (frameLogs < 1) printLine("[compositor] installer rendered");
}

g_compositor.present();
```

## Expected Logs After Fix

After rebuilding, you should see:
```
[desktop] Starting in INSTALL MODE
[desktop] Installer window initialized
[compositor] renderWorkspaceComposited start
[compositor] cleared buffer
[compositor] taskbar drawn
[compositor] windows drawing skipped
[compositor] rendering installer    ← NEW!
[compositor] installer rendered     ← NEW!
[compositor] present done
```

And the Calamares-style installer UI should be visible on screen!

## Files Modified

1. `/home/jonny/Documents/internetcomputer/src/anonymos/display/compositor.d`
   - Added installer rendering logic to `renderWorkspaceComposited()` (lines 575-600)

## Next Steps

1. **Rebuild**: `./scripts/buildscript.sh`
2. **Run**: `qemu-system-x86_64 -cdrom build/os.iso -m 512 -serial stdio`
3. **Verify**: The installer should now be visible with:
   - Calamares-style sidebar on the left
   - Welcome screen in the main area
   - Navigation buttons at the bottom

## Additional Notes

The PS/2 mouse fix from earlier is also working well - cursor jumps are much smaller and less frequent now!
