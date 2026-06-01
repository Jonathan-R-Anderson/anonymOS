module anonymos_display.wayland.wserver;

import anonymos_userland.shell.console : printLine, print, printUnsigned, printHex;
import implementation.kernel.syscalls.socket;
import implementation.kernel.syscalls.posix : sys_close, ssize_t;
import anonymos_display.wayland.protocol;
import anonymos_display.framebuffer : g_fb, framebufferPutPixel;
import core.stdc.string : memcpy, memset;

@nogc nothrow:

// --------------------------------------------------------------------------
// Server State
// --------------------------------------------------------------------------

struct WaylandClient {
    bool active;
    int fd;
    uint id;
}

__gshared int g_serverFd = -1;
__gshared WaylandClient[8] g_clients;

enum WaylandObjectType {
    Unknown,
    Display,
    Registry,
    Compositor,
    Shm,
    ShmPool,
    Surface,
    Buffer,
    Seat,
    Output
}

struct WaylandObject {
    uint id;
    WaylandObjectType type;
    uint parentId; // For buffers -> pool
    int width, height, stride, offset, format; // For buffers
    int size; // For pools
}

__gshared WaylandObject[128] g_objects;
__gshared size_t g_objectCount = 0;

WaylandObject* getObject(uint id) {
    for(size_t i=0; i<g_objectCount; i++) {
        if (g_objects[i].id == id) return &g_objects[i];
    }
    return null;
}

WaylandObject* createObject(uint id, WaylandObjectType type) {
    if (g_objectCount >= 128) return null;
    WaylandObject* obj = &g_objects[g_objectCount++];
    obj.id = id;
    obj.type = type;
    return obj;
}

// --------------------------------------------------------------------------
// Sending Events
// --------------------------------------------------------------------------

extern(C) void sendEvent(WaylandClient* client, uint objId, ushort opcode, uint numArgs, uint[] args)
{
    wl_message_header header;
    header.object_id = objId;
    header.opcode = opcode;
    header.length = cast(ushort)(header.sizeof + numArgs * 4);
    
    iovec[2] iovs;
    iovs[0].iov_base = &header;
    iovs[0].iov_len = header.sizeof;
    iovs[1].iov_base = args.ptr;
    iovs[1].iov_len = numArgs * 4;
    
    msghdr msg;
    msg.msg_iov = iovs.ptr;
    msg.msg_iovlen = 2;
    
    sys_sendmsg(client.fd, &msg, 0);
}

extern(C) void sendGlobal(WaylandClient* client, uint registryId, uint name, string interfaceName, uint version_)
{
    uint strLen = cast(uint)interfaceName.length + 1;
    uint pad = (4 - (strLen % 4)) % 4;
    
    ubyte[256] flat;
    int ptr = 0;
    
    wl_message_header* h = cast(wl_message_header*)flat.ptr;
    ptr += wl_message_header.sizeof;
    
    *(cast(uint*)(flat.ptr + ptr)) = name; ptr += 4;
    *(cast(uint*)(flat.ptr + ptr)) = strLen; ptr += 4;
    
    for (int i = 0; i < interfaceName.length; i++) flat[ptr++] = cast(ubyte)interfaceName[i];
    flat[ptr++] = 0;
    for (int i = 0; i < pad; i++) flat[ptr++] = 0;
    
    *(cast(uint*)(flat.ptr + ptr)) = version_; ptr += 4;
    
    h.object_id = registryId;
    h.opcode = WL_REGISTRY_GLOBAL;
    h.length = cast(ushort)ptr;
    
    iovec iov;
    iov.iov_base = flat.ptr;
    iov.iov_len = ptr;
    
    msghdr msg;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    sys_sendmsg(client.fd, &msg, 0);
}

// --------------------------------------------------------------------------
// Main Interface
// --------------------------------------------------------------------------

extern(C) export void waylandUpdate()
{
    if (g_serverFd < 0) return;
    
    // Accept
    sockaddr_un clientAddr;
    uint len = sockaddr_un.sizeof;
    int clientFd = sys_accept(g_serverFd, cast(sockaddr*)&clientAddr, &len);
    
    if (clientFd >= 0) {
        // Add Client Logic Inlined
        bool added = false;
        foreach (ref client; g_clients) {
            if (!client.active) {
                client.active = true;
                client.fd = clientFd;
                client.id = 1;
                printLine("[wayland] Client connected!");
                added = true;
                break;
            }
        }
        if (!added) sys_close(clientFd);
    }
    
    foreach (ref client; g_clients) {
        if (client.active) {
            wl_message_header header;
            iovec iov;
            iov.iov_base = &header;
            iov.iov_len = header.sizeof;
            
            msghdr msg;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            
            ssize_t ret = sys_recvmsg(client.fd, &msg, 0);
            if (ret <= 0) {
                if (ret == 0) {
                    printLine("[wayland] Client disconnected");
                    sys_close(client.fd);
                    client.active = false;
                }
                continue;
            }
            
            if (ret < header.sizeof) continue;
            
            size_t bodyLen = header.length - header.sizeof;
            ubyte[1024] bodyBuf;
            ubyte* bodyPtr = null;

            if (bodyLen > 0) {
                if (bodyLen > 1024) bodyLen = 1024;
                
                iov.iov_base = bodyBuf.ptr;
                iov.iov_len = bodyLen;
                sys_recvmsg(client.fd, &msg, 0);
                bodyPtr = bodyBuf.ptr;
            }

            // Dispatch Logic
            if (header.object_id == WL_DISPLAY_ID) {
                if (header.opcode == WL_DISPLAY_GET_REGISTRY) {
                    uint registryId = *(cast(uint*)bodyPtr);
                    print("[wayland] wl_display.get_registry -> "); printUnsigned(registryId); printLine("");
                    
                    createObject(registryId, WaylandObjectType.Registry);
                    
                    sendGlobal(&client, registryId, GLOBAL_COMPOSITOR_ID, "wl_compositor", 4);
                    sendGlobal(&client, registryId, GLOBAL_SHM_ID, "wl_shm", 1);
                    sendGlobal(&client, registryId, GLOBAL_SEAT_ID, "wl_seat", 5);
                    sendGlobal(&client, registryId, GLOBAL_OUTPUT_ID, "wl_output", 2);
                }
                else if (header.opcode == WL_DISPLAY_SYNC) {
                     uint callbackId = *(cast(uint*)bodyPtr);
                     uint[1] args = [0];
                     sendEvent(&client, callbackId, 0, 1, args[]); 
                }
            }
            else {
                WaylandObject* obj = getObject(header.object_id);
                if (obj !is null) {
                    if (obj.type == WaylandObjectType.Registry) {
                        if (header.opcode == WL_REGISTRY_BIND) {
                            // name(u), interface(s), version(u), new_id(u)
                            uint name = *cast(uint*)bodyPtr;
                            uint strLen = *cast(uint*)(bodyPtr + 4);
                            // Skip string + pad
                            uint pad = (4 - (strLen % 4)) % 4;
                            int offset = 8 + strLen + pad;
                            // version
                            // new_id
                            uint newId = *cast(uint*)(bodyPtr + offset + 4);
                            
                            print("[wayland] bind global "); printUnsigned(name); print(" -> "); printUnsigned(newId); printLine("");
                            
                            if (name == GLOBAL_COMPOSITOR_ID) createObject(newId, WaylandObjectType.Compositor);
                            else if (name == GLOBAL_SHM_ID) createObject(newId, WaylandObjectType.Shm);
                            else if (name == GLOBAL_SEAT_ID) createObject(newId, WaylandObjectType.Seat);
                            else if (name == GLOBAL_OUTPUT_ID) createObject(newId, WaylandObjectType.Output);
                        }
                    }
                    else if (obj.type == WaylandObjectType.Compositor) {
                        if (header.opcode == WL_COMPOSITOR_CREATE_SURFACE) {
                            uint id = *cast(uint*)bodyPtr;
                            createObject(id, WaylandObjectType.Surface);
                            print("[wayland] created surface "); printUnsigned(id); printLine("");
                        }
                    }
                    else if (obj.type == WaylandObjectType.Shm) {
                        if (header.opcode == WL_SHM_CREATE_POOL) {
                            // new_id, fd(h), size(i)
                            // fd is not in body
                            uint id = *cast(uint*)bodyPtr;
                            int size = *cast(int*)(bodyPtr + 4);
                            auto pool = createObject(id, WaylandObjectType.ShmPool);
                            pool.size = size;
                            print("[wayland] created shm pool "); printUnsigned(id); printLine("");
                        }
                    }
                    else if (obj.type == WaylandObjectType.ShmPool) {
                        if (header.opcode == WL_SHM_POOL_CREATE_BUFFER) {
                            // id, offset, w, h, stride, fmt
                            uint id = *cast(uint*)bodyPtr;
                            int offset = *cast(int*)(bodyPtr + 4);
                            int width = *cast(int*)(bodyPtr + 8);
                            int height = *cast(int*)(bodyPtr + 12);
                            int stride = *cast(int*)(bodyPtr + 16);
                            uint fmt = *cast(uint*)(bodyPtr + 20);
                            
                            auto buf = createObject(id, WaylandObjectType.Buffer);
                            buf.parentId = obj.id;
                            buf.offset = offset;
                            buf.width = width;
                            buf.height = height;
                            buf.stride = stride;
                            buf.format = fmt;
                            print("[wayland] created buffer "); printUnsigned(id); printLine("");
                        }
                    }
                    else if (obj.type == WaylandObjectType.Surface) {
                        if (header.opcode == WL_SURFACE_ATTACH) {
                            uint bufId = *cast(uint*)bodyPtr;
                            // x, y
                            print("[wayland] surface attach buffer "); printUnsigned(bufId); printLine("");
                            // Store pending buffer? For now just remember last attached
                            obj.parentId = bufId; // Hack: reuse parentId to store current buffer
                        }
                        else if (header.opcode == WL_SURFACE_COMMIT) {
                            print("[wayland] surface commit"); printLine("");
                            // Draw!
                            uint bufId = obj.parentId;
                            WaylandObject* buf = getObject(bufId);
                            if (buf !is null) {
                                // Draw placeholder rect
                                for(int y=0; y<buf.height; y++) {
                                    for(int x=0; x<buf.width; x++) {
                                        // Draw at 100,100 for now
                                        framebufferPutPixel(100+x, 100+y, 0xFF00FF00); // Green
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

extern(C) void initWaylandServer()
{
    printLine("[wayland] Initializing Minimal Wayland Compositor...");
    
    g_serverFd = sys_socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_serverFd < 0) {
        printLine("[wayland] Failed to create socket");
        return;
    }
    
    sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    const(char)[] path = "/run/user/1000/wayland-0";
    for (int i = 0; i < path.length; i++) addr.sun_path[i] = path[i];
    addr.sun_path[path.length] = 0;
    
    if (sys_bind(g_serverFd, cast(sockaddr*)&addr, sockaddr_un.sizeof) != 0) {
        printLine("[wayland] Failed to bind socket");
        return;
    }
    
    if (sys_listen(g_serverFd, 10) != 0) {
        printLine("[wayland] Failed to listen");
        return;
    }
    
    printLine("[wayland] Listening on wayland-0");
}
