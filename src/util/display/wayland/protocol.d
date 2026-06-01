module anonymos_display.wayland.protocol;

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
enum WL_DISPLAY_SYNC = 0;
enum WL_DISPLAY_GET_REGISTRY = 1;

// wl_registry opcodes (Client -> Server)
enum WL_REGISTRY_BIND = 0;

// wl_compositor opcodes (Client -> Server)
enum WL_COMPOSITOR_CREATE_SURFACE = 0;
enum WL_COMPOSITOR_CREATE_REGION = 1;

// wl_surface opcodes (Client -> Server)
enum WL_SURFACE_DESTROY = 0;
enum WL_SURFACE_ATTACH = 1;
enum WL_SURFACE_DAMAGE = 2;
enum WL_SURFACE_FRAME = 3;
enum WL_SURFACE_SET_OPAQUE_REGION = 4;
enum WL_SURFACE_SET_INPUT_REGION = 5;
enum WL_SURFACE_COMMIT = 6;

// wl_shm opcodes
enum WL_SHM_CREATE_POOL = 0;

// wl_shm_pool opcodes
enum WL_SHM_POOL_CREATE_BUFFER = 0;
enum WL_SHM_POOL_DESTROY = 1;
enum WL_SHM_POOL_RESIZE = 2;

// Events (Server -> Client)
// wl_display events
enum WL_DISPLAY_ERROR = 0;
enum WL_DISPLAY_DELETE_ID = 1;

// wl_registry events
enum WL_REGISTRY_GLOBAL = 0;
enum WL_REGISTRY_GLOBAL_REMOVE = 1;

// Global Interface IDs (Arbitrary for our server)
enum GLOBAL_COMPOSITOR_ID = 2;
enum GLOBAL_SHM_ID = 3;
enum GLOBAL_SEAT_ID = 4;
enum GLOBAL_OUTPUT_ID = 5;

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
