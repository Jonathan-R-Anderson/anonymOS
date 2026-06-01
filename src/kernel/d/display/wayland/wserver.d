module display.wayland.wserver;

import userland.shell.console : printLine, print, printUnsigned, printHex;
import core.syscalls.socket;
import core.syscalls.posix : sys_close, ssize_t;
import display.wayland.protocol;
import display.framebuffer : g_fb, framebufferPutPixel, framebufferAvailable;
import display.modesetting : g_lastModesetResult;
import core.stdc.string : memcpy, memset;

@nogc nothrow:

// --------------------------------------------------------------------------
// Wayland object type tag
// --------------------------------------------------------------------------

enum WaylandObjectType
{
    Unknown,
    Display,
    Registry,
    Compositor,
    Shm,
    ShmPool,
    Surface,
    Buffer,
    Seat,
    Output,
    Callback,
    Keyboard,
    Pointer,
    XdgWmBase,
    XdgSurface,
    XdgToplevel,
    Subcompositor,
    Subsurface,
}

// --------------------------------------------------------------------------
// Object table entry
// --------------------------------------------------------------------------

struct WaylandObject
{
    uint id;
    WaylandObjectType type;

    // Surface/buffer geometry
    int width, height, stride, offset, format;

    // Pool size (ShmPool), or generic auxiliary id (Surface -> buffer, Buffer -> pool)
    int size;
    uint parentId;

    // Pool FD received via SCM_RIGHTS
    int poolFd;

    // SHM base pointer (mapped from poolFd or stub pointer)
    void* poolBase;

    // XdgSurface -> backing wl_surface id
    uint surfaceId;

    // Pending frame callback id (0 if none)
    uint pendingCallback;

    // Title (xdg_toplevel)
    char[128] title;
};

// --------------------------------------------------------------------------
// Client state
// --------------------------------------------------------------------------

struct WaylandClient
{
    bool   active;
    int    fd;
    uint   nextId;    // server-side generated ids are high numbers; client uses own ids
    uint   serial;    // incrementing event serial
    uint   keyboardId; // bound wl_keyboard object id (0 if none)
    uint   pointerId;  // bound wl_pointer object id  (0 if none)
}

// --------------------------------------------------------------------------
// Server globals
// --------------------------------------------------------------------------

__gshared int  g_serverFd             = -1;
__gshared bool g_waylandAnnouncedReady = false;
__gshared WaylandClient[8]   g_clients;
__gshared WaylandObject[256] g_objects;
__gshared size_t             g_objectCount = 0;
__gshared uint               g_globalSerial = 1;

// --------------------------------------------------------------------------
// Object lookup / creation helpers
// --------------------------------------------------------------------------

WaylandObject* getObject(uint id) @nogc nothrow
{
    for (size_t i = 0; i < g_objectCount; i++)
    {
        if (g_objects[i].id == id) return &g_objects[i];
    }
    return null;
}

WaylandObject* createObject(uint id, WaylandObjectType type) @nogc nothrow
{
    if (g_objectCount >= 256) return null;
    WaylandObject* obj = &g_objects[g_objectCount++];
    memset(obj, 0, WaylandObject.sizeof);
    obj.id   = id;
    obj.type = type;
    obj.poolFd = -1;
    return obj;
}

void destroyObject(uint id) @nogc nothrow
{
    for (size_t i = 0; i < g_objectCount; i++)
    {
        if (g_objects[i].id == id)
        {
            // Shift down
            for (size_t j = i; j + 1 < g_objectCount; j++)
                g_objects[j] = g_objects[j + 1];
            g_objectCount--;
            return;
        }
    }
}

// --------------------------------------------------------------------------
// Low-level send helpers
// --------------------------------------------------------------------------

// Send a pre-flattened byte buffer as a single iovec
private void sendRaw(WaylandClient* client, const(void)* data, size_t len) @nogc nothrow
{
    iovec iov;
    iov.iov_base = cast(void*)data;
    iov.iov_len  = len;

    msghdr msg;
    memset(&msg, 0, msghdr.sizeof);
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    sys_sendmsg(client.fd, &msg, 0);
}

// Build and send a message with up to 8 uint32 args after the header.
private void sendEvent(WaylandClient* client, uint objId, ushort opcode,
                       uint numArgs, const(uint)[] args) @nogc nothrow
{
    // wire format: [header 8 bytes][args numArgs*4 bytes]
    ubyte[8 + 32] buf;
    wl_message_header* h = cast(wl_message_header*)buf.ptr;
    h.object_id = objId;
    h.opcode    = opcode;
    h.length    = cast(ushort)(8 + numArgs * 4);

    uint* argsPtr = cast(uint*)(buf.ptr + 8);
    for (uint i = 0; i < numArgs && i < 8; i++)
        argsPtr[i] = args[i];

    sendRaw(client, buf.ptr, h.length);
}

// Send a string-bearing event: [name:u32][strlen:u32][bytes...][pad][...]
private void sendGlobal(WaylandClient* client, uint registryId, uint name,
                        const(char)[] ifaceName, uint version_) @nogc nothrow
{
    uint strLen = cast(uint)ifaceName.length + 1; // include NUL
    uint pad    = (4 - (strLen % 4)) % 4;

    enum maxBuf = 256;
    ubyte[maxBuf] flat;
    int ptr = 0;

    auto h  = cast(wl_message_header*)flat.ptr;
    ptr    += wl_message_header.sizeof;

    *cast(uint*)(flat.ptr + ptr) = name;    ptr += 4;
    *cast(uint*)(flat.ptr + ptr) = strLen;  ptr += 4;

    for (int i = 0; i < cast(int)ifaceName.length; i++)
        flat[ptr++] = cast(ubyte)ifaceName[i];
    flat[ptr++] = 0;
    for (int i = 0; i < cast(int)pad; i++)
        flat[ptr++] = 0;

    *cast(uint*)(flat.ptr + ptr) = version_; ptr += 4;

    h.object_id = registryId;
    h.opcode    = WL_REGISTRY_GLOBAL;
    h.length    = cast(ushort)ptr;

    sendRaw(client, flat.ptr, ptr);
}

// Send a string-value event field in a pre-allocated buffer region.
// Returns number of bytes written (header + payload).
private uint buildStringEvent(ubyte[] buf, uint objId, ushort opcode,
                              const(char)[] text) @nogc nothrow
{
    uint strLen = cast(uint)text.length + 1;
    uint pad    = (4 - (strLen % 4)) % 4;
    uint total  = cast(uint)(wl_message_header.sizeof + 4 + strLen + pad);

    if (total > buf.length) return 0;

    auto h = cast(wl_message_header*)buf.ptr;
    h.object_id = objId;
    h.opcode    = opcode;
    h.length    = cast(ushort)total;

    int p = cast(int)wl_message_header.sizeof;
    *cast(uint*)(buf.ptr + p) = strLen; p += 4;
    for (int i = 0; i < cast(int)text.length; i++)
        buf[p++] = cast(ubyte)text[i];
    buf[p++] = 0;
    for (int i = 0; i < cast(int)pad; i++)
        buf[p++] = 0;

    return total;
}

// Emit wl_seat capabilities + name events
private void sendSeatCapabilities(WaylandClient* client, uint seatId) @nogc nothrow
{
    uint caps = WL_SEAT_CAPABILITY_KEYBOARD | WL_SEAT_CAPABILITY_POINTER;
    uint[1] capArgs = [caps];
    sendEvent(client, seatId, WL_SEAT_CAPABILITIES, 1, capArgs[]);

    // wl_seat.name(string) event
    ubyte[64] nameBuf;
    const(char)[] seatName = "seat0";
    uint used = buildStringEvent(nameBuf[], seatId, WL_SEAT_NAME, seatName);
    if (used > 0)
        sendRaw(client, nameBuf.ptr, used);
}

// Emit wl_keyboard.keymap (no-keymap stub: format=0, fd=0, size=0)
private void sendKeymapStub(WaylandClient* client, uint kbdId) @nogc nothrow
{
    // format(u), fd(h), size(u)
    // No keymap memfd is generated yet, so advertise format=0 (none).
    uint[3] args = [WL_KEYBOARD_KEYMAP_FORMAT_NO_KEYMAP, 0, 0];
    sendEvent(client, kbdId, WL_KEYBOARD_KEYMAP, 3, args[]);
}

// Emit wl_keyboard.repeat_info
private void sendRepeatInfo(WaylandClient* client, uint kbdId) @nogc nothrow
{
    uint[2] args = [25, 600]; // rate=25 keys/s, delay=600ms
    sendEvent(client, kbdId, WL_KEYBOARD_REPEAT_INFO, 2, args[]);
}

// Emit wl_output.geometry + mode + scale + done
private void sendOutputInfo(WaylandClient* client, uint outputId) @nogc nothrow
{
    uint w = g_fb.width  != 0 ? g_fb.width  : 1024;
    uint h = g_fb.height != 0 ? g_fb.height : 768;

    // geometry: x,y,phys_w,phys_h,subpixel,make(str),model(str),transform
    // Simplify: use a flat event with known-size string fields
    {
        ubyte[128] gbuf;
        int p = cast(int)wl_message_header.sizeof;
        auto hdr = cast(wl_message_header*)gbuf.ptr;

        *cast(int*)(gbuf.ptr + p) = 0; p += 4; // x
        *cast(int*)(gbuf.ptr + p) = 0; p += 4; // y
        *cast(int*)(gbuf.ptr + p) = cast(int)(w * 10 / 38); p += 4; // phys_w (mm, rough estimate)
        *cast(int*)(gbuf.ptr + p) = cast(int)(h * 10 / 38); p += 4; // phys_h

        *cast(int*)(gbuf.ptr + p) = WL_OUTPUT_SUBPIXEL_UNKNOWN; p += 4; // subpixel

        // make string: "HanonymOS"
        const(char)[] mk = "HanonymOS";
        uint mkLen = cast(uint)mk.length + 1;
        uint mkPad = (4 - (mkLen % 4)) % 4;
        *cast(uint*)(gbuf.ptr + p) = mkLen; p += 4;
        for (int i = 0; i < cast(int)mk.length; i++) gbuf[p++] = cast(ubyte)mk[i];
        gbuf[p++] = 0;
        for (int i = 0; i < cast(int)mkPad; i++) gbuf[p++] = 0;

        // model string: "Framebuffer"
        const(char)[] md = "Framebuffer";
        uint mdLen = cast(uint)md.length + 1;
        uint mdPad = (4 - (mdLen % 4)) % 4;
        *cast(uint*)(gbuf.ptr + p) = mdLen; p += 4;
        for (int i = 0; i < cast(int)md.length; i++) gbuf[p++] = cast(ubyte)md[i];
        gbuf[p++] = 0;
        for (int i = 0; i < cast(int)mdPad; i++) gbuf[p++] = 0;

        *cast(int*)(gbuf.ptr + p) = WL_OUTPUT_TRANSFORM_NORMAL; p += 4; // transform

        hdr.object_id = outputId;
        hdr.opcode    = WL_OUTPUT_GEOMETRY;
        hdr.length    = cast(ushort)p;
        sendRaw(client, gbuf.ptr, p);
    }

    // mode: flags, w, h, refresh (mHz)
    {
        uint flags   = WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED;
        uint refresh = 60000; // 60 Hz in mHz
        uint[4] args = [flags, w, h, refresh];
        sendEvent(client, outputId, WL_OUTPUT_MODE, 4, args[]);
    }

    // scale: factor=1
    {
        uint[1] args = [1];
        sendEvent(client, outputId, WL_OUTPUT_SCALE, 1, args[]);
    }

    // done
    sendEvent(client, outputId, WL_OUTPUT_DONE, 0, null);
}

// Emit wl_shm.format events for supported pixel formats
private void sendShmFormats(WaylandClient* client, uint shmId) @nogc nothrow
{
    uint[1] a = [WL_SHM_FORMAT_ARGB8888];
    sendEvent(client, shmId, WL_SHM_FORMAT, 1, a[]);
    uint[1] b = [WL_SHM_FORMAT_XRGB8888];
    sendEvent(client, shmId, WL_SHM_FORMAT, 1, b[]);
}

// Emit xdg_wm_base.ping
private void sendXdgPing(WaylandClient* client, uint wmBaseId) @nogc nothrow
{
    uint[1] args = [g_globalSerial++];
    sendEvent(client, wmBaseId, XDG_WM_BASE_PING, 1, args[]);
}

// Emit xdg_surface.configure, then xdg_toplevel.configure, then xdg_surface.configure
private void sendXdgConfigure(WaylandClient* client, WaylandObject* xdgSurf,
                               WaylandObject* toplevel) @nogc nothrow
{
    if (toplevel !is null)
    {
        // xdg_toplevel.configure(w=0, h=0, states=[])
        // states is a wl_array: length(u32) + data
        ubyte[24] buf;
        int p = cast(int)wl_message_header.sizeof;
        auto hdr = cast(wl_message_header*)buf.ptr;
        *cast(int*)(buf.ptr + p) = 0; p += 4; // width
        *cast(int*)(buf.ptr + p) = 0; p += 4; // height
        *cast(uint*)(buf.ptr + p) = 0; p += 4; // states array length = 0
        hdr.object_id = toplevel.id;
        hdr.opcode    = XDG_TOPLEVEL_CONFIGURE;
        hdr.length    = cast(ushort)p;
        sendRaw(client, buf.ptr, p);
    }

    // xdg_surface.configure(serial)
    uint[1] args = [g_globalSerial++];
    sendEvent(client, xdgSurf.id, XDG_SURFACE_CONFIGURE, 1, args[]);
}

// Blit surface shm buffer to framebuffer
private void blitSurfaceToFramebuffer(WaylandObject* surface) @nogc nothrow
{
    if (surface is null) return;

    WaylandObject* buf = getObject(surface.parentId);
    if (buf is null || buf.type != WaylandObjectType.Buffer) return;

    WaylandObject* pool = getObject(buf.parentId);
    if (pool is null || pool.type != WaylandObjectType.ShmPool) return;

    // Only proceed if we have a real pool base pointer
    if (pool.poolBase is null) return;

    const ubyte* src      = cast(const ubyte*)pool.poolBase + buf.offset;
    const int    srcW     = buf.width;
    const int    srcH     = buf.height;
    const int    srcStride = buf.stride;

    if (!framebufferAvailable()) return;

    const uint fbW = g_fb.width;
    const uint fbH = g_fb.height;

    const int drawW = (srcW < cast(int)fbW) ? srcW : cast(int)fbW;
    const int drawH = (srcH < cast(int)fbH) ? srcH : cast(int)fbH;

    for (int y = 0; y < drawH; y++)
    {
        const uint* row = cast(const uint*)(src + y * srcStride);
        for (int x = 0; x < drawW; x++)
        {
            framebufferPutPixel(cast(uint)x, cast(uint)y, row[x]);
        }
    }
}

// --------------------------------------------------------------------------
// Dispatch a single client message (header already read, body in bodyBuf)
// --------------------------------------------------------------------------

private void dispatchMessage(WaylandClient* client, ref wl_message_header header,
                              ubyte* bodyPtr, size_t bodyLen) @nogc nothrow
{
    // ---- wl_display ----
    if (header.object_id == WL_DISPLAY_ID)
    {
        if (header.opcode == WL_DISPLAY_GET_REGISTRY)
        {
            if (bodyLen < 4) return;
            uint registryId = *cast(uint*)bodyPtr;
            print("[wayland] get_registry -> "); printUnsigned(registryId); printLine("");
            createObject(registryId, WaylandObjectType.Registry);

            // Advertise all globals
            sendGlobal(client, registryId, GLOBAL_COMPOSITOR_ID,  "wl_compositor",      4);
            sendGlobal(client, registryId, GLOBAL_SHM_ID,         "wl_shm",             1);
            sendGlobal(client, registryId, GLOBAL_SEAT_ID,        "wl_seat",            7);
            sendGlobal(client, registryId, GLOBAL_OUTPUT_ID,      "wl_output",          4);
            sendGlobal(client, registryId, GLOBAL_XDG_WM_BASE_ID, "xdg_wm_base",        5);
            sendGlobal(client, registryId, GLOBAL_SUBCOMPOSITOR_ID,"wl_subcompositor",  1);
            sendGlobal(client, registryId, GLOBAL_PRESENTATION_ID, "wp_presentation",   1);
            sendGlobal(client, registryId, GLOBAL_DMABUF_ID,       "zwp_linux_dmabuf_v1", 3);
            sendGlobal(client, registryId, GLOBAL_ZXDG_OUTPUT_ID,  "zxdg_output_manager_v1", 3);
        }
        else if (header.opcode == WL_DISPLAY_SYNC)
        {
            if (bodyLen < 4) return;
            uint callbackId = *cast(uint*)bodyPtr;
            createObject(callbackId, WaylandObjectType.Callback);
            // Fire callback immediately
            uint[1] args = [g_globalSerial++];
            sendEvent(client, callbackId, WL_CALLBACK_DONE, 1, args[]);
        }
        return;
    }

    WaylandObject* obj = getObject(header.object_id);
    if (obj is null) return;

    // ---- wl_registry ----
    if (obj.type == WaylandObjectType.Registry)
    {
        if (header.opcode == WL_REGISTRY_BIND && bodyLen >= 8)
        {
            uint name    = *cast(uint*)bodyPtr;
            uint strLen  = *cast(uint*)(bodyPtr + 4);
            uint pad     = (4 - (strLen % 4)) % 4;
            uint offset  = 8 + strLen + pad;
            if (bodyLen < offset + 8) return;
            // version at offset, new_id at offset+4
            uint newId = *cast(uint*)(bodyPtr + offset + 4);

            print("[wayland] bind global "); printUnsigned(name);
            print(" -> "); printUnsigned(newId); printLine("");

            if      (name == GLOBAL_COMPOSITOR_ID)   createObject(newId, WaylandObjectType.Compositor);
            else if (name == GLOBAL_SHM_ID)
            {
                auto shmObj = createObject(newId, WaylandObjectType.Shm);
                if (shmObj !is null) sendShmFormats(client, newId);
            }
            else if (name == GLOBAL_SEAT_ID)
            {
                createObject(newId, WaylandObjectType.Seat);
                sendSeatCapabilities(client, newId);
            }
            else if (name == GLOBAL_OUTPUT_ID)
            {
                createObject(newId, WaylandObjectType.Output);
                sendOutputInfo(client, newId);
            }
            else if (name == GLOBAL_XDG_WM_BASE_ID)
            {
                createObject(newId, WaylandObjectType.XdgWmBase);
                sendXdgPing(client, newId);
            }
            else if (name == GLOBAL_SUBCOMPOSITOR_ID)
                createObject(newId, WaylandObjectType.Subcompositor);
            // presentation / dmabuf / zxdg_output: accept bind, do nothing extra
        }
        return;
    }

    // ---- wl_compositor ----
    if (obj.type == WaylandObjectType.Compositor)
    {
        if (header.opcode == WL_COMPOSITOR_CREATE_SURFACE && bodyLen >= 4)
        {
            uint id = *cast(uint*)bodyPtr;
            createObject(id, WaylandObjectType.Surface);
            print("[wayland] create_surface "); printUnsigned(id); printLine("");
        }
        return;
    }

    // ---- wl_shm ----
    if (obj.type == WaylandObjectType.Shm)
    {
        if (header.opcode == WL_SHM_CREATE_POOL && bodyLen >= 8)
        {
            // new_id(u), fd(h) is ancillary, size(i)
            uint id   = *cast(uint*)bodyPtr;
            int  sz   = *cast(int*)(bodyPtr + 4);
            auto pool = createObject(id, WaylandObjectType.ShmPool);
            if (pool !is null)
            {
                pool.size   = sz;
                pool.poolFd = -1;    // fd received separately via SCM_RIGHTS recvmsg
                // poolBase will be set when we actually map the fd
                print("[wayland] create_pool id="); printUnsigned(id);
                print(" size="); printUnsigned(cast(uint)sz); printLine("");
            }
        }
        return;
    }

    // ---- wl_shm_pool ----
    if (obj.type == WaylandObjectType.ShmPool)
    {
        if (header.opcode == WL_SHM_POOL_CREATE_BUFFER && bodyLen >= 24)
        {
            uint id     = *cast(uint*)bodyPtr;
            int  offset = *cast(int*)(bodyPtr + 4);
            int  w      = *cast(int*)(bodyPtr + 8);
            int  h      = *cast(int*)(bodyPtr + 12);
            int  stride = *cast(int*)(bodyPtr + 16);
            uint fmt    = *cast(uint*)(bodyPtr + 20);
            auto buf    = createObject(id, WaylandObjectType.Buffer);
            if (buf !is null)
            {
                buf.parentId = obj.id;
                buf.offset   = offset;
                buf.width    = w;
                buf.height   = h;
                buf.stride   = stride;
                buf.format   = cast(int)fmt;
            }
            print("[wayland] create_buffer id="); printUnsigned(id);
            print(" "); printUnsigned(cast(uint)w); print("x"); printUnsigned(cast(uint)h);
            printLine("");
        }
        else if (header.opcode == WL_SHM_POOL_RESIZE && bodyLen >= 4)
        {
            obj.size = *cast(int*)bodyPtr;
        }
        return;
    }

    // ---- wl_surface ----
    if (obj.type == WaylandObjectType.Surface)
    {
        if (header.opcode == WL_SURFACE_ATTACH && bodyLen >= 4)
        {
            uint bufId = *cast(uint*)bodyPtr;
            obj.parentId = bufId;
        }
        else if (header.opcode == WL_SURFACE_FRAME && bodyLen >= 4)
        {
            uint cbId = *cast(uint*)bodyPtr;
            createObject(cbId, WaylandObjectType.Callback);
            obj.pendingCallback = cbId;
        }
        else if (header.opcode == WL_SURFACE_COMMIT)
        {
            print("[wayland] surface commit "); printUnsigned(obj.id); printLine("");
            blitSurfaceToFramebuffer(obj);

            // Release buffer after use
            WaylandObject* buf = getObject(obj.parentId);
            if (buf !is null)
                sendEvent(client, buf.id, WL_BUFFER_RELEASE, 0, null);

            // Fire pending frame callback
            if (obj.pendingCallback != 0)
            {
                uint[1] args = [g_globalSerial++];
                sendEvent(client, obj.pendingCallback, WL_CALLBACK_DONE, 1, args[]);
                obj.pendingCallback = 0;
            }
        }
        else if (header.opcode == WL_SURFACE_DESTROY)
        {
            destroyObject(obj.id);
        }
        return;
    }

    // ---- wl_buffer ----
    if (obj.type == WaylandObjectType.Buffer)
    {
        if (header.opcode == WL_BUFFER_DESTROY)
            destroyObject(obj.id);
        return;
    }

    // ---- wl_seat ----
    if (obj.type == WaylandObjectType.Seat)
    {
        if (header.opcode == WL_SEAT_GET_KEYBOARD && bodyLen >= 4)
        {
            uint kbdId = *cast(uint*)bodyPtr;
            createObject(kbdId, WaylandObjectType.Keyboard);
            client.keyboardId = kbdId;
            sendKeymapStub(client, kbdId);
            sendRepeatInfo(client, kbdId);
            print("[wayland] get_keyboard -> "); printUnsigned(kbdId); printLine("");
        }
        else if (header.opcode == WL_SEAT_GET_POINTER && bodyLen >= 4)
        {
            uint ptrId = *cast(uint*)bodyPtr;
            createObject(ptrId, WaylandObjectType.Pointer);
            client.pointerId = ptrId;
            print("[wayland] get_pointer -> "); printUnsigned(ptrId); printLine("");
        }
        return;
    }

    // ---- wl_output ----
    if (obj.type == WaylandObjectType.Output)
    {
        if (header.opcode == WL_OUTPUT_RELEASE)
            destroyObject(obj.id);
        return;
    }

    // ---- xdg_wm_base ----
    if (obj.type == WaylandObjectType.XdgWmBase)
    {
        if (header.opcode == XDG_WM_BASE_GET_XDG_SURFACE && bodyLen >= 8)
        {
            uint xdgId  = *cast(uint*)bodyPtr;
            uint wlSurf = *cast(uint*)(bodyPtr + 4);
            auto xdgObj = createObject(xdgId, WaylandObjectType.XdgSurface);
            if (xdgObj !is null)
                xdgObj.surfaceId = wlSurf;
            print("[wayland] get_xdg_surface "); printUnsigned(xdgId); printLine("");
        }
        else if (header.opcode == XDG_WM_BASE_PONG)
        {
            // Consume ping reply
        }
        else if (header.opcode == XDG_WM_BASE_DESTROY)
        {
            destroyObject(obj.id);
        }
        return;
    }

    // ---- xdg_surface ----
    if (obj.type == WaylandObjectType.XdgSurface)
    {
        if (header.opcode == XDG_SURFACE_GET_TOPLEVEL && bodyLen >= 4)
        {
            uint topId = *cast(uint*)bodyPtr;
            auto top   = createObject(topId, WaylandObjectType.XdgToplevel);
            if (top !is null)
                top.surfaceId = obj.surfaceId;
            print("[wayland] get_toplevel "); printUnsigned(topId); printLine("");
            // Send configure immediately
            sendXdgConfigure(client, obj, top);
        }
        else if (header.opcode == XDG_SURFACE_ACK_CONFIGURE)
        {
            // Client acknowledged; no further action needed at this layer
        }
        else if (header.opcode == XDG_SURFACE_DESTROY)
        {
            destroyObject(obj.id);
        }
        return;
    }

    // ---- xdg_toplevel ----
    if (obj.type == WaylandObjectType.XdgToplevel)
    {
        if (header.opcode == XDG_TOPLEVEL_SET_TITLE && bodyLen >= 8)
        {
            uint strLen = *cast(uint*)(bodyPtr + 0);
            uint copyLen = strLen < (obj.title.length - 1) ? strLen : cast(uint)(obj.title.length - 1);
            memcpy(obj.title.ptr, bodyPtr + 4, copyLen);
            obj.title[copyLen] = '\0';
        }
        else if (header.opcode == XDG_TOPLEVEL_DESTROY)
        {
            destroyObject(obj.id);
        }
        return;
    }

    // ---- wl_subcompositor ----
    if (obj.type == WaylandObjectType.Subcompositor)
    {
        if (header.opcode == WL_SUBCOMPOSITOR_GET_SUBSURFACE && bodyLen >= 8)
        {
            uint subId = *cast(uint*)bodyPtr;
            createObject(subId, WaylandObjectType.Subsurface);
        }
        return;
    }

    // ---- wl_subsurface ----
    if (obj.type == WaylandObjectType.Subsurface)
    {
        // Accept and ignore subsurface position/sync opcodes for now
        if (header.opcode == WL_SUBSURFACE_DESTROY)
            destroyObject(obj.id);
        return;
    }

    // ---- keyboard / pointer / callback (client-destroyed objects) ----
    if (obj.type == WaylandObjectType.Keyboard  ||
        obj.type == WaylandObjectType.Pointer   ||
        obj.type == WaylandObjectType.Callback)
    {
        // Destroy on opcode 0 (release/destroy)
        if (header.opcode == 0)
            destroyObject(obj.id);
        return;
    }
}

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

extern(C) void initWaylandServer()
{
    printLine("[wayland] Initializing Mutter-compatible Wayland Compositor...");

    g_serverFd = sys_socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_serverFd < 0)
    {
        printLine("[wayland] Failed to create socket");
        return;
    }

    sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    const(char)[] path = "/run/user/1000/wayland-0";
    for (int i = 0; i < cast(int)path.length; i++) addr.sun_path[i] = path[i];
    addr.sun_path[path.length] = 0;

    if (sys_bind(g_serverFd, cast(sockaddr*)&addr, sockaddr_un.sizeof) != 0)
    {
        printLine("[wayland] Failed to bind socket");
        return;
    }

    if (sys_listen(g_serverFd, 16) != 0)
    {
        printLine("[wayland] Failed to listen");
        return;
    }

    printLine("[wayland] Listening on /run/user/1000/wayland-0");
}

extern(C) export void waylandUpdate()
{
    if (g_serverFd < 0) return;

    if (!g_waylandAnnouncedReady)
    {
        printLine("[wayland] server heartbeat active");
        g_waylandAnnouncedReady = true;
    }

    // Accept new connections (non-blocking: sys_accept with SOCK_NONBLOCK is
    // handled by the socket configured in non-blocking mode at init time;
    // for now we attempt one accept per tick and move on if nothing is there)
    {
        sockaddr_un clientAddr;
        uint len = sockaddr_un.sizeof;
        int cfd  = sys_accept(g_serverFd, cast(sockaddr*)&clientAddr, &len);
        if (cfd >= 0)
        {
            bool added = false;
            foreach (ref cl; g_clients)
            {
                if (!cl.active)
                {
                    cl.active   = true;
                    cl.fd       = cfd;
                    cl.serial   = 1;
                    cl.keyboardId = 0;
                    cl.pointerId  = 0;
                    printLine("[wayland] Client connected");
                    added = true;
                    break;
                }
            }
            if (!added) sys_close(cfd);
        }
    }

    // Service each active client
    foreach (ref client; g_clients)
    {
        if (!client.active) continue;

        // Try to read the fixed-size message header
        wl_message_header header;
        ubyte[8] hdrBuf;

        iovec hiov;
        hiov.iov_base = hdrBuf.ptr;
        hiov.iov_len  = hdrBuf.sizeof;

        // Ancillary cmsg buffer for SCM_RIGHTS fd
        ubyte[cmsghdr.sizeof + 4] cmsgBuf;

        msghdr hmsg;
        memset(&hmsg, 0, msghdr.sizeof);
        hmsg.msg_iov       = &hiov;
        hmsg.msg_iovlen    = 1;
        hmsg.msg_control    = cmsgBuf.ptr;
        hmsg.msg_controllen = cmsgBuf.sizeof;

        ssize_t ret = sys_recvmsg(client.fd, &hmsg, MSG_DONTWAIT);
        if (ret <= 0)
        {
            if (ret == 0)
            {
                printLine("[wayland] Client disconnected");
                sys_close(client.fd);
                client.active = false;
            }
            continue;
        }

        if (ret < cast(ssize_t)wl_message_header.sizeof) continue;

        // Parse header from flat buffer
        header = *cast(wl_message_header*)hdrBuf.ptr;

        // Check for ancillary fd (for wl_shm.create_pool)
        int receivedFd = -1;
        if (hmsg.msg_controllen >= cmsghdr.sizeof)
        {
            auto cm = cast(cmsghdr*)cmsgBuf.ptr;
            if (cm.cmsg_level == SOL_SOCKET && cm.cmsg_type == SCM_RIGHTS &&
                cm.cmsg_len >= cmsghdr.sizeof + 4)
            {
                receivedFd = *cast(int*)(cmsgBuf.ptr + cmsghdr.sizeof);
            }
        }

        // If an fd was received and the current message is wl_shm.create_pool,
        // store the fd in the pool object (looked up after dispatch by create_pool handler)
        // We'll attach it post-dispatch by scanning for the newest pool object.
        bool attachFd = (receivedFd >= 0);

        // Read message body if present
        size_t bodyLen = header.length > 8 ? header.length - 8 : 0;
        ubyte[1024] bodyBuf;
        ubyte* bodyPtr = null;

        if (bodyLen > 0)
        {
            if (bodyLen > 1024) bodyLen = 1024;

            iovec biov;
            biov.iov_base = bodyBuf.ptr;
            biov.iov_len  = bodyLen;

            msghdr bmsg;
            memset(&bmsg, 0, msghdr.sizeof);
            bmsg.msg_iov    = &biov;
            bmsg.msg_iovlen = 1;

            ssize_t bret = sys_recvmsg(client.fd, &bmsg, 0);
            if (bret > 0)
                bodyPtr = bodyBuf.ptr;
            else
                bodyLen = 0;
        }

        // Record pool count before dispatch so we can identify newly created pool
        size_t poolCountBefore = g_objectCount;

        dispatchMessage(&client, header, bodyPtr, bodyLen);

        // Attach received fd to the newest pool if this was a create_pool message
        if (attachFd && g_objectCount > poolCountBefore)
        {
            // The newly created object should be the last one
            for (size_t i = poolCountBefore; i < g_objectCount; i++)
            {
                if (g_objects[i].type == WaylandObjectType.ShmPool)
                {
                    g_objects[i].poolFd = receivedFd;
                    break;
                }
            }
        }
    }
}

extern(C) bool waylandServerReady()
{
    return g_serverFd >= 0;
}

extern(C) bool waylandClientActive()
{
    foreach (ref client; g_clients)
    {
        if (client.active)
        {
            return true;
        }
    }
    return false;
}

// Inject a keyboard key event to all connected clients with a bound keyboard
extern(C) export void waylandInjectKey(uint keyCode, bool pressed) @nogc nothrow
{
    foreach (ref client; g_clients)
    {
        if (!client.active || client.keyboardId == 0) continue;
        uint state = pressed ? WL_KEYBOARD_KEY_STATE_PRESSED : WL_KEYBOARD_KEY_STATE_RELEASED;
        uint[4] args = [g_globalSerial++, 0 /*time ms*/, keyCode, state];
        sendEvent(&client, client.keyboardId, WL_KEYBOARD_KEY, 4, args[]);
    }
}

// Inject a pointer motion event to all connected clients with a bound pointer
extern(C) export void waylandInjectPointerMotion(uint timeMs, int x, int y) @nogc nothrow
{
    foreach (ref client; g_clients)
    {
        if (!client.active || client.pointerId == 0) continue;
        // motion: time(u), x(fixed), y(fixed)
        wl_fixed_t fx = wl_fixed_from_int(x);
        wl_fixed_t fy = wl_fixed_from_int(y);
        uint[3] args = [timeMs, *cast(uint*)&fx, *cast(uint*)&fy];
        sendEvent(&client, client.pointerId, WL_POINTER_MOTION, 3, args[]);
        sendEvent(&client, client.pointerId, WL_POINTER_FRAME, 0, null);
    }
}

// Inject a pointer button event
extern(C) export void waylandInjectPointerButton(uint timeMs, uint btn, bool pressed) @nogc nothrow
{
    foreach (ref client; g_clients)
    {
        if (!client.active || client.pointerId == 0) continue;
        uint state = pressed ? WL_POINTER_BUTTON_STATE_PRESSED : WL_POINTER_BUTTON_STATE_RELEASED;
        uint[4] args = [g_globalSerial++, timeMs, btn, state];
        sendEvent(&client, client.pointerId, WL_POINTER_BUTTON, 4, args[]);
        sendEvent(&client, client.pointerId, WL_POINTER_FRAME, 0, null);
    }
}
