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

## New scaffolding toward a display server
- **Display server bookkeeping**: `src/minimal_os/display/server.d` adds
  protocol and readiness tracking for Wayland/X11 style servers and their
  compositor/input/font dependencies. It does not start a real server yet, but
  provides a structured place to hang future initialization.
- **Font stack description**: `src/minimal_os/display/font_stack.d` models a
  FreeType/HarfBuzz-style pipeline and keeps track of registered fonts so that
  higher-level code can detect whether rich text shaping is available.
- **2D canvas helpers**: `src/minimal_os/display/canvas.d` exposes a thin
  abstraction over the framebuffer with fill/rect/text helpers to decouple
  drawing intent from raw pixel writes. This is a stepping stone toward a
  richer 2D API needed by window managers and toolkits.
- **Input pipeline queue**: `src/minimal_os/display/input_pipeline.d` provides a
  small event queue and event type enumeration to stage keyboard and pointer
  data before dispatching to windows or a compositor.

These additions keep the framebuffer renderer working while sketching the
interfaces needed for a full display server and compositor stack.

## i3 desktop integration scaffolding
- A new userland service entry registers the i3 tiling window manager with the
  boot-time service planner, complete with basic display and IPC capabilities.
  This is a bookkeeping step so i3 shows up alongside core daemons when the
  placeholder desktop renders its process dock.
- The i3 entry is still aspirational: the kernel lacks an X11/Wayland stack,
  modesetting, and the rest of the Linux userspace that i3 expects. Treat the
  service plan as a target interface for when a real display server and package
  loader come online.
- When the display stack grows to include an X11 or Wayland server, the i3
  service plan can be extended with additional capabilities (e.g., GPU access
  or IPC sockets) and wired to a package resolver that fetches the i3 binary
  from userland storage.
