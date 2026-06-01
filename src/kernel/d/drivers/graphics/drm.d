module drivers.graphics.drm;

import userland.shell.console : printLine, print, printUnsigned, printHex;
import display.framebuffer;
import core.stdc.string : memcpy, memset, strlen;

@nogc nothrow:

// --------------------------------------------------------------------------
// DRM/KMS Definitions (Subset of drm.h / drm_mode.h)
// --------------------------------------------------------------------------

enum DRM_IOCTL_BASE = 'd';
enum DRM_COMMAND_BASE = 0x40;

// _IOWR(type,nr,size) = ((type) << 8 | (nr) | ((size) << 16) | _IOC_READ|_IOC_WRITE)
// But for now we'll just match the command numbers manually or define a helper.
// Linux ioctl encoding:
// bits 0-7: cmd
// bits 8-15: type
// bits 16-29: size
// bits 30-31: dir (Read/Write)

// We will match mostly on the cmd byte for simplicity if possible, but strict matching is better.

struct drm_version {
    int version_major;
    int version_minor;
    int version_patchlevel;
    size_t name_len;
    char* name;
    size_t date_len;
    char* date;
    size_t desc_len;
    char* desc;
}

struct drm_mode_card_res {
    ulong fb_id_ptr;
    ulong crtc_id_ptr;
    ulong connector_id_ptr;
    ulong encoder_id_ptr;
    uint count_fbs;
    uint count_crtcs;
    uint count_connectors;
    uint count_encoders;
    uint min_width;
    uint max_width;
    uint min_height;
    uint max_height;
}

struct drm_mode_modeinfo {
    uint clock;
    ushort hdisplay, hsync_start, hsync_end, htotal, hskew;
    ushort vdisplay, vsync_start, vsync_end, vtotal, vscan;
    uint vrefresh;
    uint flags;
    uint type;
    char[32] name;
}

struct drm_mode_get_connector {
    ulong encoders_ptr;
    ulong modes_ptr;
    ulong props_ptr;
    ulong prop_values_ptr;
    uint count_modes;
    uint count_props;
    uint count_encoders;
    uint encoder_id;
    uint connector_id;
    uint connector_type;
    uint connector_type_id;
    uint connection;
    uint mm_width;
    uint mm_height;
    uint subpixel;
    uint pad;
}

struct drm_mode_get_encoder {
    uint encoder_id;
    uint encoder_type;
    uint crtc_id;
    uint possible_crtcs;
    uint possible_clones;
}

struct drm_mode_crtc {
    ulong set_connectors_ptr;
    uint count_connectors;
    uint crtc_id;
    uint fb_id;
    uint x, y;
    uint gamma_size;
    uint mode_valid;
    drm_mode_modeinfo mode;
}

struct drm_mode_fb_cmd {
    uint fb_id;
    uint width;
    uint height;
    uint pitch;
    uint bpp;
    uint depth;
    uint handle;
}

struct drm_mode_create_dumb {
    uint height;
    uint width;
    uint bpp;
    uint flags;
    uint handle;
    uint pitch;
    ulong size;
}

struct drm_mode_map_dumb {
    uint handle;
    uint pad;
    ulong offset;
}

struct drm_mode_destroy_dumb {
    uint handle;
}

// IOCTL Commands (approximate, need to verify exact values or use macro logic)
// For x86_64:
// _IOC_NRSHIFT = 0, _IOC_NRBITS = 8
// _IOC_TYPESHIFT = 8, _IOC_TYPEBITS = 8
// _IOC_SIZESHIFT = 16, _IOC_SIZEBITS = 14
// _IOC_DIRSHIFT = 30, _IOC_DIRBITS = 2
// _IOC_NONE = 0, _IOC_WRITE = 1, _IOC_READ = 2

// We will just define the raw values commonly seen on x86_64 Linux for these.
// Calculated using: _IOWR('d', nr, type)

enum DRM_IOCTL_VERSION        = 0xC0406400; // _IOWR(0x64, 0x00, struct drm_version)
enum DRM_IOCTL_GET_CAP        = 0xC010640C; // _IOWR(0x64, 0x0c, struct drm_get_cap)

enum DRM_IOCTL_MODE_GETRESOURCES = 0xC04064A0;
enum DRM_IOCTL_MODE_GETCONNECTOR = 0xC05064A7;
enum DRM_IOCTL_MODE_GETENCODER   = 0xC01464A6;
enum DRM_IOCTL_MODE_GETCRTC      = 0xC06864A1;
enum DRM_IOCTL_MODE_SETCRTC      = 0xC06864A2;
enum DRM_IOCTL_MODE_GETFB        = 0xC01C64AD;
enum DRM_IOCTL_MODE_ADDFB        = 0xC01C64AE;
enum DRM_IOCTL_MODE_RMFB         = 0xC00464AF;
enum DRM_IOCTL_MODE_PAGE_FLIP    = 0xC01864B0;
enum DRM_IOCTL_MODE_CREATE_DUMB  = 0xC02064B2;
enum DRM_IOCTL_MODE_MAP_DUMB     = 0xC01064B3;
enum DRM_IOCTL_MODE_DESTROY_DUMB = 0xC00464B4;

// --------------------------------------------------------------------------
// State
// --------------------------------------------------------------------------

private __gshared bool g_drmInitialized = false;
private __gshared uint g_crtcId = 50;
private __gshared uint g_connectorId = 51;
private __gshared uint g_encoderId = 52;
private __gshared uint g_fbId = 53;
private __gshared uint g_dumbHandle = 1;

// --------------------------------------------------------------------------
// Public Interface (used by kdrv interface)
// --------------------------------------------------------------------------

public void initDRM()
{
    g_drmInitialized = true;
    printLine("[drm] Initialized");
}

public void drmGetDisplayInfo(out uint width, out uint height, out uint bpp)
{
    auto fb = framebufferDescriptor();
    width = fb.width;
    height = fb.height;
    bpp = fb.bpp;
}

public void drmSetMode(uint width, uint height, uint bpp)
{
    // Stub
    print("[drm] SetMode "); printUnsigned(width); print("x"); printUnsigned(height); printLine("");
}

public Framebuffer drmFrameBuffer()
{
    // Return by value or pointer? The error says drmFrameBuffer not found.
    // Assuming it returns the descriptor struct.
    return framebufferDescriptor();
}

// --------------------------------------------------------------------------
// Implementation
// --------------------------------------------------------------------------

int handleDrmIoctl(int fd, ulong cmd, void* arg)
{
    // print("[drm] ioctl cmd="); printHex(cmd); printLine("");

    // Mask out size/dir to match command number if needed, but for now exact match
    
    switch (cmd)
    {
        case DRM_IOCTL_VERSION:
            return drmVersion(cast(drm_version*)arg);
            
        case DRM_IOCTL_MODE_GETRESOURCES:
            return drmGetResources(cast(drm_mode_card_res*)arg);
            
        case DRM_IOCTL_MODE_GETCONNECTOR:
            return drmGetConnector(cast(drm_mode_get_connector*)arg);
            
        case DRM_IOCTL_MODE_GETENCODER:
            return drmGetEncoder(cast(drm_mode_get_encoder*)arg);
            
        case DRM_IOCTL_MODE_GETCRTC:
            return drmGetCrtc(cast(drm_mode_crtc*)arg);
            
        case DRM_IOCTL_MODE_CREATE_DUMB:
            return drmCreateDumb(cast(drm_mode_create_dumb*)arg);
            
        case DRM_IOCTL_MODE_MAP_DUMB:
            return drmMapDumb(cast(drm_mode_map_dumb*)arg);
            
        case DRM_IOCTL_MODE_ADDFB:
             // Just return a fake FB ID
             auto fb = cast(drm_mode_fb_cmd*)arg;
             fb.fb_id = ++g_fbId;
             return 0;
             
        case DRM_IOCTL_MODE_RMFB:
             return 0;
             
        case DRM_IOCTL_MODE_SETCRTC:
             // We ignore mode setting for now and assume current mode
             return 0;
             
        case DRM_IOCTL_MODE_PAGE_FLIP:
             // TODO: Implement page flip (swap buffers)
             return 0;
             
        default:
            // print("[drm] Unknown ioctl: "); printHex(cmd); printLine("");
            return -22; // EINVAL
    }
}

private int drmVersion(drm_version* v)
{
    if (v is null) return -14;
    
    v.version_major = 1;
    v.version_minor = 0;
    v.version_patchlevel = 0;
    
    const(char)[] name = "anonymos_drm";
    const(char)[] date = "20251205";
    const(char)[] desc = "AnonymOS DRM Driver";
    
    if (v.name !is null) {
        size_t len = (v.name_len < name.length) ? v.name_len : name.length;
        memcpy(v.name, name.ptr, len);
        if (len < v.name_len) v.name[len] = 0;
    }
    v.name_len = name.length;
    
    if (v.date !is null) {
        size_t len = (v.date_len < date.length) ? v.date_len : date.length;
        memcpy(v.date, date.ptr, len);
        if (len < v.date_len) v.date[len] = 0;
    }
    v.date_len = date.length;
    
    if (v.desc !is null) {
        size_t len = (v.desc_len < desc.length) ? v.desc_len : desc.length;
        memcpy(v.desc, desc.ptr, len);
        if (len < v.desc_len) v.desc[len] = 0;
    }
    v.desc_len = desc.length;
    
    return 0;
}

private int drmGetResources(drm_mode_card_res* res)
{
    if (res is null) return -14;
    
    res.min_width = 0;
    res.max_width = 4096;
    res.min_height = 0;
    res.max_height = 4096;
    
    // 1 of each
    if (res.count_crtcs >= 1) {
        uint* crtcs = cast(uint*)res.crtc_id_ptr;
        if (crtcs !is null) crtcs[0] = g_crtcId;
    }
    res.count_crtcs = 1;
    
    if (res.count_connectors >= 1) {
        uint* conns = cast(uint*)res.connector_id_ptr;
        if (conns !is null) conns[0] = g_connectorId;
    }
    res.count_connectors = 1;
    
    if (res.count_encoders >= 1) {
        uint* encs = cast(uint*)res.encoder_id_ptr;
        if (encs !is null) encs[0] = g_encoderId;
    }
    res.count_encoders = 1;
    
    if (res.count_fbs >= 1) {
        uint* fbs = cast(uint*)res.fb_id_ptr;
        if (fbs !is null) fbs[0] = g_fbId;
    }
    res.count_fbs = 1;
    
    return 0;
}

private int drmGetConnector(drm_mode_get_connector* conn)
{
    if (conn is null) return -14;
    
    conn.encoder_id = g_encoderId;
    conn.connector_type = 0; // Unknown/Virtual
    conn.connector_type_id = 1;
    conn.connection = 1; // Connected
    conn.mm_width = 0;
    conn.mm_height = 0;
    conn.subpixel = 0;
    
    conn.count_encoders = 1;
    if (conn.encoders_ptr != 0) {
        uint* encs = cast(uint*)conn.encoders_ptr;
        encs[0] = g_encoderId;
    }
    
    // Modes
    conn.count_modes = 1;
    if (conn.modes_ptr != 0) {
        drm_mode_modeinfo* modes = cast(drm_mode_modeinfo*)conn.modes_ptr;
        
        auto fb = framebufferDescriptor();
        
        modes[0].clock = 60000; // 60MHz? Dummy
        modes[0].hdisplay = cast(ushort)fb.width;
        modes[0].hsync_start = cast(ushort)fb.width;
        modes[0].hsync_end = cast(ushort)fb.width;
        modes[0].htotal = cast(ushort)fb.width;
        modes[0].vdisplay = cast(ushort)fb.height;
        modes[0].vsync_start = cast(ushort)fb.height;
        modes[0].vsync_end = cast(ushort)fb.height;
        modes[0].vtotal = cast(ushort)fb.height;
        modes[0].vrefresh = 60;
        modes[0].flags = 0;
        modes[0].type = 0x48; // PREFERRED | DRIVER
        
        // Name "WxH"
        char[32] name;
        // ... construct name ...
        modes[0].name = name;
    }
    
    return 0;
}

private int drmGetEncoder(drm_mode_get_encoder* enc)
{
    if (enc is null) return -14;
    
    enc.encoder_id = g_encoderId;
    enc.encoder_type = 0; // Virtual
    enc.crtc_id = g_crtcId;
    enc.possible_crtcs = 1;
    enc.possible_clones = 0;
    
    return 0;
}

private int drmGetCrtc(drm_mode_crtc* crtc)
{
    if (crtc is null) return -14;
    
    crtc.crtc_id = g_crtcId;
    crtc.fb_id = g_fbId;
    crtc.x = 0;
    crtc.y = 0;
    crtc.mode_valid = 1;
    
    auto fb = framebufferDescriptor();
    crtc.mode.hdisplay = cast(ushort)fb.width;
    crtc.mode.vdisplay = cast(ushort)fb.height;
    // ... fill rest ...
    
    return 0;
}

private int drmCreateDumb(drm_mode_create_dumb* args)
{
    if (args is null) return -14;
    
    // We just pretend to allocate. In reality, we map the framebuffer.
    // Or we should allocate a new buffer?
    // For simplicity in this "make it work" step, we return the main FB handle.
    
    auto fb = framebufferDescriptor();
    
    args.handle = g_dumbHandle;
    args.pitch = (args.width * args.bpp + 7) / 8;
    args.size = args.pitch * args.height;
    
    // Align pitch
    if (args.pitch % 4 != 0) args.pitch += (4 - (args.pitch % 4));
    
    return 0;
}

private int drmMapDumb(drm_mode_map_dumb* args)
{
    if (args is null) return -14;
    
    // Return a fake offset that mmap will recognize
    // We'll use the physical address of the framebuffer if possible, 
    // or a magic offset that sys_mmap handles.
    
    auto fb = framebufferDescriptor();
    
    // We return the physical address of the FB as the offset.
    // sys_mmap needs to allow mapping this physical range.
    args.offset = cast(ulong)fb.addr; 
    
    return 0;
}
