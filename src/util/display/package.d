module anonymos_display;

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
public import anonymos_display.framebuffer;
public import anonymos_display.desktop;
public import anonymos_display.canvas;
public import anonymos_display.cursor;
public import anonymos_display.cursor_diagnostics;
public import anonymos_display.wallpaper;
public import anonymos_display.wallpaper_builtin;
public import anonymos_display.wallpaper_types;
public import anonymos_display.common;

// Display servers
public import anonymos_display.server.server;
public import anonymos_display.server.x11_server;
public import anonymos_display.server.x11_stack;

// Wayland
public import anonymos_display.wayland.protocol;
public import anonymos_display.wayland.wserver;

// Compositor
public import anonymos_display.compositor.compositor;

// Window manager
public import anonymos_display.window_manager.manager;
public import anonymos_display.window_manager.renderer;
public import anonymos_display.i3_integration;

// Font rendering
public import anonymos_display.fonts.bitmap_font;
public import anonymos_display.fonts.truetype_font;
public import anonymos_display.fonts.font_stack;
public import anonymos_display.fonts.freetype_bindings;
public import anonymos_display.fonts.harfbuzz_bindings;

// Input
public import anonymos_display.input_handler;
public import anonymos_display.input_pipeline;

// Graphics acceleration
public import anonymos_display.gpu_accel;
public import anonymos_display.vulkan;
public import anonymos_display.drm_sim;
public import anonymos_display.modesetting;
