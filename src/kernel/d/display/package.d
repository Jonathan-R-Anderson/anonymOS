module display;

/// AnonymOS Display - Display server and graphics stack
/// 
/// This module provides:
/// - Framebuffer management
/// - Display server (X11, Wayland)
/// - Window manager integration (i3)
/// - Compositor
/// - Font rendering (bitmap and TrueType)
/// - GPU acceleration
/// - Input handling

// Core display components
public import display.framebuffer;
public import display.canvas;
public import display.cursor;
public import display.cursor_diagnostics;
public import display.wallpaper;
public import display.wallpaper_builtin;
public import display.wallpaper_types;
public import display.common;

// Display servers
public import display.server.server;
public import display.server.x11_server;
public import display.server.x11_stack;

// Wayland
public import display.wayland.protocol;
public import display.wayland.wserver;

// Compositor
public import display.compositor.compositor;

// Window manager
public import display.window_manager.manager;
public import display.window_manager.renderer;

// Font rendering
public import display.fonts.bitmap_font;
public import display.fonts.truetype_font;
public import display.fonts.font_stack;
public import display.freetype_bindings;
public import display.harfbuzz_bindings;

// Input
public import display.input_handler;
public import display.input_pipeline;

// Graphics acceleration
public import display.gpu_accel;
public import display.vulkan;
public import display.drm_sim;
public import display.modesetting;
public import display.gnome_session;
