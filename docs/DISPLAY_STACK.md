# Display and Graphics Stack Status

This project currently implements a minimal framebuffer-based path for drawing
pixels and text during boot. Modern desktop stack components such as mode
setting, compositors, GPU acceleration, and display servers are not yet present.

## Implemented pieces
- **Framebuffer init and drawing**: The kernel reads Multiboot framebuffer
  details and initializes a linear framebuffer with support for 16/24/32 bpp
  pixels, basic shapes, and text rendering using a fallback glyph. Related code
  now lives under `src/minimal_os/display/` to keep display components grouped.
- **Placeholder desktop**: A simple task draws a static background, taskbar, and
  window outline directly into the framebuffer and then idles.

## Missing pieces
The following layers are not implemented and would need dedicated subsystems:
- Kernel modesetting beyond the Multiboot-provided mode
- Hardware acceleration (GPU drivers, DRM/KMS), OpenGL/Vulkan, or Cairo/Skia
- Compositor, window manager, or display server (X11/Wayland)
- Font rendering/shaping engines (e.g., FreeType/HarfBuzz)
- Advanced 2D canvas APIs beyond the hand-rolled framebuffer helpers

Overall, the current display path stops at a software framebuffer and placeholder
UI; there is no modern graphics stack in place yet.
