module minimal_os.display.splash;

import minimal_os.display.canvas : Canvas, canvasRect, canvasText, createFramebufferCanvas;
import minimal_os.display.font_stack : activeFontStack;
import minimal_os.display.framebuffer : framebufferAvailable, glyphHeight;
import minimal_os.display.wallpaper : drawWallpaperToFramebuffer;

@nogc:
nothrow:

/// Render a simple splash screen while the rest of the kernel initialises.
/// The splash fills the framebuffer with the configured wallpaper and overlays
/// a status ribbon so boot messages do not scroll the desktop off-screen.
void renderBootSplash()
{
    if (!framebufferAvailable())
    {
        return;
    }

    drawWallpaperToFramebuffer();

    Canvas canvas = createFramebufferCanvas();
    if (!canvas.available)
    {
        return;
    }

    const uint ribbonHeight = (canvas.height > 120) ? (canvas.height / 6) : 48;
    const uint ribbonY = (canvas.height > ribbonHeight) ? (canvas.height - ribbonHeight) : 0;
    const uint ribbonColor = 0xCC11121E; // semi-opaque charcoal ribbon
    const uint accentColor = 0xFF7C5BFF; // accent line matching wallpaper hues
    const uint textColor = 0xFFFFFFFF;
    const uint padding = 32;

    canvasRect(canvas, 0, ribbonY, canvas.width, ribbonHeight, ribbonColor, true);
    canvasRect(canvas, padding, ribbonY + ribbonHeight - 12, canvas.width - (padding * 2), 4, accentColor, true);

    const auto stack = activeFontStack();
    if (stack !is null)
    {
        const uint textY = ribbonY + ((ribbonHeight > glyphHeight) ? ((ribbonHeight - glyphHeight) / 2) : 0);
        canvasText(canvas, stack, padding, textY, "Starting desktop environment…", textColor, ribbonColor, true);
    }
}

