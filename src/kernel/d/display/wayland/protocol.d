module display.wayland.protocol;

// --------------------------------------------------------------------------
// Wayland Wire Protocol Definitions
// --------------------------------------------------------------------------

struct wl_message_header {
    uint object_id;
    ushort opcode;
    ushort length;
}

// Fixed Point 24.8
struct wl_fixed_t {
    int val;
}

// Core Interfaces
enum WL_DISPLAY_ID = 1;

// wl_display opcodes (Client -> Server)
enum WL_DISPLAY_SYNC         = 0;
enum WL_DISPLAY_GET_REGISTRY = 1;

// wl_registry opcodes (Client -> Server)
enum WL_REGISTRY_BIND = 0;

// wl_compositor opcodes (Client -> Server)
enum WL_COMPOSITOR_CREATE_SURFACE = 0;
enum WL_COMPOSITOR_CREATE_REGION  = 1;

// wl_surface opcodes (Client -> Server)
enum WL_SURFACE_DESTROY           = 0;
enum WL_SURFACE_ATTACH            = 1;
enum WL_SURFACE_DAMAGE            = 2;
enum WL_SURFACE_FRAME             = 3;
enum WL_SURFACE_SET_OPAQUE_REGION = 4;
enum WL_SURFACE_SET_INPUT_REGION  = 5;
enum WL_SURFACE_COMMIT            = 6;
enum WL_SURFACE_SET_BUFFER_TRANSFORM = 7;
enum WL_SURFACE_SET_BUFFER_SCALE  = 8;
enum WL_SURFACE_DAMAGE_BUFFER     = 9;

// wl_shm opcodes
enum WL_SHM_CREATE_POOL = 0;

// wl_shm_pool opcodes
enum WL_SHM_POOL_CREATE_BUFFER = 0;
enum WL_SHM_POOL_DESTROY       = 1;
enum WL_SHM_POOL_RESIZE        = 2;

// wl_buffer opcodes (Client -> Server)
enum WL_BUFFER_DESTROY = 0;

// wl_seat opcodes (Client -> Server)
enum WL_SEAT_GET_POINTER  = 0;
enum WL_SEAT_GET_KEYBOARD = 1;
enum WL_SEAT_GET_TOUCH    = 2;
enum WL_SEAT_RELEASE      = 3;

// wl_output opcodes (Client -> Server)
enum WL_OUTPUT_RELEASE = 0;

// wl_subcompositor opcodes (Client -> Server)
enum WL_SUBCOMPOSITOR_DESTROY       = 0;
enum WL_SUBCOMPOSITOR_GET_SUBSURFACE = 1;

// wl_subsurface opcodes (Client -> Server)
enum WL_SUBSURFACE_DESTROY         = 0;
enum WL_SUBSURFACE_SET_POSITION    = 1;
enum WL_SUBSURFACE_PLACE_ABOVE     = 2;
enum WL_SUBSURFACE_PLACE_BELOW     = 3;
enum WL_SUBSURFACE_SET_SYNC        = 4;
enum WL_SUBSURFACE_SET_DESYNC      = 5;

// --------------------------------------------------------------------------
// xdg-shell (xdg_wm_base)
// --------------------------------------------------------------------------

// xdg_wm_base opcodes (Client -> Server)
enum XDG_WM_BASE_DESTROY           = 0;
enum XDG_WM_BASE_CREATE_POSITIONER = 1;
enum XDG_WM_BASE_GET_XDG_SURFACE   = 2;
enum XDG_WM_BASE_PONG              = 3;

// xdg_wm_base events (Server -> Client)
enum XDG_WM_BASE_PING = 0;

// xdg_surface opcodes (Client -> Server)
enum XDG_SURFACE_DESTROY        = 0;
enum XDG_SURFACE_GET_TOPLEVEL   = 1;
enum XDG_SURFACE_GET_POPUP      = 2;
enum XDG_SURFACE_SET_WINDOW_GEOMETRY = 3;
enum XDG_SURFACE_ACK_CONFIGURE  = 4;

// xdg_surface events (Server -> Client)
enum XDG_SURFACE_CONFIGURE = 0;

// xdg_toplevel opcodes (Client -> Server)
enum XDG_TOPLEVEL_DESTROY           = 0;
enum XDG_TOPLEVEL_SET_PARENT        = 1;
enum XDG_TOPLEVEL_SET_TITLE         = 2;
enum XDG_TOPLEVEL_SET_APP_ID        = 3;
enum XDG_TOPLEVEL_SHOW_WINDOW_MENU  = 4;
enum XDG_TOPLEVEL_MOVE              = 5;
enum XDG_TOPLEVEL_RESIZE            = 6;
enum XDG_TOPLEVEL_SET_MAX_SIZE      = 7;
enum XDG_TOPLEVEL_SET_MIN_SIZE      = 8;
enum XDG_TOPLEVEL_SET_MAXIMIZED     = 9;
enum XDG_TOPLEVEL_UNSET_MAXIMIZED   = 10;
enum XDG_TOPLEVEL_SET_FULLSCREEN    = 11;
enum XDG_TOPLEVEL_UNSET_FULLSCREEN  = 12;
enum XDG_TOPLEVEL_SET_MINIMIZED     = 13;

// xdg_toplevel events (Server -> Client)
enum XDG_TOPLEVEL_CONFIGURE = 0;
enum XDG_TOPLEVEL_CLOSE     = 1;

// --------------------------------------------------------------------------
// wl_keyboard events
// --------------------------------------------------------------------------

enum WL_KEYBOARD_KEYMAP    = 0;
enum WL_KEYBOARD_ENTER     = 1;
enum WL_KEYBOARD_LEAVE     = 2;
enum WL_KEYBOARD_KEY       = 3;
enum WL_KEYBOARD_MODIFIERS = 4;
enum WL_KEYBOARD_REPEAT_INFO = 5;

enum WL_KEYBOARD_KEYMAP_FORMAT_NO_KEYMAP = 0;
enum WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1   = 1;

enum WL_KEYBOARD_KEY_STATE_RELEASED = 0;
enum WL_KEYBOARD_KEY_STATE_PRESSED  = 1;

// --------------------------------------------------------------------------
// wl_pointer events
// --------------------------------------------------------------------------

enum WL_POINTER_ENTER         = 0;
enum WL_POINTER_LEAVE         = 1;
enum WL_POINTER_MOTION        = 2;
enum WL_POINTER_BUTTON        = 3;
enum WL_POINTER_AXIS          = 4;
enum WL_POINTER_FRAME         = 5;
enum WL_POINTER_AXIS_SOURCE   = 6;
enum WL_POINTER_AXIS_STOP     = 7;
enum WL_POINTER_AXIS_DISCRETE = 8;

enum WL_POINTER_BUTTON_STATE_RELEASED = 0;
enum WL_POINTER_BUTTON_STATE_PRESSED  = 1;

// --------------------------------------------------------------------------
// wl_seat events
// --------------------------------------------------------------------------

enum WL_SEAT_CAPABILITIES = 0;   // event
enum WL_SEAT_NAME         = 1;   // event

enum WL_SEAT_CAPABILITY_POINTER  = 1;
enum WL_SEAT_CAPABILITY_KEYBOARD = 2;
enum WL_SEAT_CAPABILITY_TOUCH    = 4;

// --------------------------------------------------------------------------
// wl_output events
// --------------------------------------------------------------------------

enum WL_OUTPUT_GEOMETRY  = 0;
enum WL_OUTPUT_MODE      = 1;
enum WL_OUTPUT_DONE      = 2;
enum WL_OUTPUT_SCALE     = 3;
enum WL_OUTPUT_NAME      = 4;
enum WL_OUTPUT_DESCRIPTION = 5;

enum WL_OUTPUT_MODE_CURRENT   = 1;
enum WL_OUTPUT_MODE_PREFERRED = 2;

enum WL_OUTPUT_SUBPIXEL_UNKNOWN = 0;
enum WL_OUTPUT_TRANSFORM_NORMAL = 0;

// --------------------------------------------------------------------------
// wl_callback events
// --------------------------------------------------------------------------

enum WL_CALLBACK_DONE = 0;

// --------------------------------------------------------------------------
// wl_buffer events
// --------------------------------------------------------------------------

enum WL_BUFFER_RELEASE = 0;

// --------------------------------------------------------------------------
// wl_shm events
// --------------------------------------------------------------------------

enum WL_SHM_FORMAT = 0;       // server -> client: announce supported format

enum WL_SHM_FORMAT_ARGB8888 = 0;
enum WL_SHM_FORMAT_XRGB8888 = 1;

// --------------------------------------------------------------------------
// wl_display events
// --------------------------------------------------------------------------

enum WL_DISPLAY_ERROR     = 0;
enum WL_DISPLAY_DELETE_ID = 1;

// wl_registry events
enum WL_REGISTRY_GLOBAL        = 0;
enum WL_REGISTRY_GLOBAL_REMOVE = 1;

// --------------------------------------------------------------------------
// Global Interface IDs (registry name slots; arbitrary but stable)
// --------------------------------------------------------------------------

enum GLOBAL_COMPOSITOR_ID  = 2;
enum GLOBAL_SHM_ID         = 3;
enum GLOBAL_SEAT_ID        = 4;
enum GLOBAL_OUTPUT_ID      = 5;
enum GLOBAL_XDG_WM_BASE_ID = 6;
enum GLOBAL_SUBCOMPOSITOR_ID = 7;
enum GLOBAL_PRESENTATION_ID  = 8;
enum GLOBAL_DMABUF_ID        = 9;
enum GLOBAL_ZXDG_OUTPUT_ID   = 10;

// --------------------------------------------------------------------------
// Helper Functions
// --------------------------------------------------------------------------

@nogc nothrow:

uint wl_fixed_to_int(wl_fixed_t f) {
    return f.val / 256;
}

wl_fixed_t wl_fixed_from_int(int i) {
    return wl_fixed_t(i * 256);
}
