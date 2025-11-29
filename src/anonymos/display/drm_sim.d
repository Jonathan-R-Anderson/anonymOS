module anonymos.display.drm_sim;

import anonymos.display.framebuffer;
import anonymos.console : printLine;
import anonymos.drivers.virtio_gpu;

// --------------------------------------------------------------------------
// DRM/KMS Simulation Types
// --------------------------------------------------------------------------

extern(C):

struct DrmMode {
    uint clock;
    ushort hdisplay, hsync_start, hsync_end, htotal;
    ushort vdisplay, vsync_start, vsync_end, vtotal;
    uint flags;
    char[32] name;
}

struct DrmConnector {
    uint connectorId;
    uint encoderId;
    uint connection; // 1 = connected
    uint mmWidth, mmHeight;
    int countModes;
    DrmMode* modes;
}

struct DrmCrtc {
    uint crtcId;
    uint bufferId;
    uint x, y;
    uint width, height;
    int modeValid;
    DrmMode mode;
}

struct DrmDevice {
    int fd;
    bool available;
    // Sim state
    uint currentFbId;
}

struct DrmClipRect {
    ushort x1, y1;
    ushort x2, y2;
}

// Global simulated device
export __gshared DrmDevice g_drmDevice;
export __gshared uint g_mainResourceId = 0;

// --------------------------------------------------------------------------
// DRM/KMS Simulation Functions
// --------------------------------------------------------------------------

export void initDrm() @nogc nothrow {
    if (!framebufferAvailable()) {
        printLine("[drm] Framebuffer not available, cannot init DRM sim");
        return;
    }
    
    // Initialize Hardware Driver
    virtioGpuInit();
    
    // Create main framebuffer resource
    g_mainResourceId = virtioGpuCreateResource(g_fb.width, g_fb.height);
    
    g_drmDevice.available = true;
    printLine("[drm] DRM/KMS simulation initialized (VirtIO-GPU backed)");
}

export int drmModePageFlip(DrmDevice* dev, uint crtcId, uint fbId, uint flags, void* userData) @nogc nothrow {
    if (!dev.available) return -1;
    
    // Hardware Acceleration: Transfer and Flush
    // Use the main resource created during init
    uint rid = g_mainResourceId; 
    
    // Transfer entire screen (Simplified)
    virtioGpuTransfer(rid, 0, 0, g_fb.width, g_fb.height, 0);
    virtioGpuFlush(rid, 0, 0, g_fb.width, g_fb.height);
    
    return 0;
}

export int drmModeCreateDumbBuffer(DrmDevice* dev, uint width, uint height, uint bpp, uint flags, uint* handle, uint* pitch, ulong* size) @nogc nothrow {
    // Return the main resource that was created during init
    // For now, we just return the main framebuffer info to keep it simple (direct render)
    
    if (!framebufferAvailable()) return -1;
    
    *handle = g_mainResourceId; // Use main resource ID as handle
    *pitch = g_fb.pitch;
    *size = g_fb.height * g_fb.pitch;
    
    return 0;
}

export int drmModeAddFB(DrmDevice* dev, uint width, uint height, uint depth, uint bpp, uint pitch, uint handle, uint* fbId) @nogc nothrow {
    *fbId = 100 + handle;
    return 0;
}

export int drmModeSetCrtc(DrmDevice* dev, uint crtcId, uint fbId, uint x, uint y, uint* connectors, int count, DrmMode* mode) @nogc nothrow {
    printLine("[drm] drmModeSetCrtc called");
    dev.currentFbId = fbId;
    return 0;
}

export int drmModeDirtyFB(DrmDevice* dev, uint fbId, DrmClipRect* clips, uint numClips) @nogc nothrow {
    if (!dev.available) return -1;
    
    uint rid = g_mainResourceId; // Use main resource
    
    if (numClips == 0 || clips is null) {
        // Full update
        virtioGpuTransfer(rid, 0, 0, g_fb.width, g_fb.height, 0);
        virtioGpuFlush(rid, 0, 0, g_fb.width, g_fb.height);
    } else {
        foreach (i; 0 .. numClips) {
            DrmClipRect* clip = &clips[i];
            uint w = clip.x2 - clip.x1;
            uint h = clip.y2 - clip.y1;
            
            // Calculate offset
            ulong offset = (clip.y1 * g_fb.pitch) + (clip.x1 * (g_fb.bpp / 8));
            
            virtioGpuTransfer(rid, clip.x1, clip.y1, w, h, offset);
            virtioGpuFlush(rid, clip.x1, clip.y1, w, h);
        }
    }
    return 0;
}
