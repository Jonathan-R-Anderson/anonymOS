module anonymos.display.x11_server;

// Minimal X11 server implementation for i3
// Provides enough X11 protocol support for i3 to run

import anonymos.objects;
import anonymos.display.framebuffer;
import anonymos.display.canvas;

// ============================================================================
// X11 Protocol Constants
// ============================================================================

enum X11Opcode : ubyte
{
    CreateWindow = 1,
    ChangeWindowAttributes = 2,
    GetWindowAttributes = 3,
    DestroyWindow = 4,
    DestroySubwindows = 5,
    MapWindow = 8,
    UnmapWindow = 10,
    ConfigureWindow = 12,
    GetGeometry = 14,
    QueryTree = 15,
    InternAtom = 16,
    GetAtomName = 17,
    ChangeProperty = 18,
    DeleteProperty = 19,
    GetProperty = 20,
    GrabKey = 33,
    GrabButton = 28,
    QueryPointer = 38,
    CreateGC = 55,
    ChangeGC = 56,
    CopyArea = 62,
    PolyFillRectangle = 70,
    ImageText8 = 76,
}

// ============================================================================
// X11 Window Management
// ============================================================================

struct X11Window
{
    uint id;
    uint parent;
    short x, y;
    ushort width, height;
    ushort borderWidth;
    bool mapped;
    uint eventMask;
    ObjectID backingStore;  // Blob for window contents
    ubyte* buffer;          // Direct pointer to contents
}

__gshared X11Window[256] g_x11Windows;
__gshared size_t g_x11WindowCount = 0;
__gshared uint g_nextWindowId = 1;

// Create X11 window
@nogc nothrow uint createX11Window(uint parent, short x, short y, ushort width, ushort height)
{
    if (g_x11WindowCount >= g_x11Windows.length) return 0;
    
    X11Window* win = &g_x11Windows[g_x11WindowCount];
    win.id = g_nextWindowId++;
    win.parent = parent;
    win.x = x;
    win.y = y;
    win.width = width;
    win.height = height;
    win.borderWidth = 0;
    win.mapped = false;
    win.eventMask = 0;
    
    // Create backing store
    size_t bufferSize = width * height * 4;  // 32-bit RGBA
    ubyte* buffer = cast(ubyte*)kmalloc(bufferSize);
    if (buffer !is null)
    {
        // Clear to black
        for (size_t i = 0; i < bufferSize; ++i)
            buffer[i] = 0;
        
        win.backingStore = createVMO(cast(const(ubyte)[])buffer[0..bufferSize], false);
        win.buffer = buffer;
    }
    
    g_x11WindowCount++;
    
    return win.id;
}

// Get window by ID
@nogc nothrow X11Window* getX11Window(uint id)
{
    for (size_t i = 0; i < g_x11WindowCount; ++i)
    {
        if (g_x11Windows[i].id == id)
            return &g_x11Windows[i];
    }
    return null;
}

// Composite window to framebuffer
@nogc nothrow void compositeWindow(X11Window* win)
{
    if (!win.mapped || win.buffer is null) return;
    
    // Simple blit
    for (uint dy = 0; dy < win.height; ++dy)
    {
        for (uint dx = 0; dx < win.width; ++dx)
        {
            uint srcIdx = (dy * win.width + dx) * 4;
            // RGBA
            uint r = win.buffer[srcIdx];
            uint g = win.buffer[srcIdx + 1];
            uint b = win.buffer[srcIdx + 2];
            uint a = win.buffer[srcIdx + 3]; // Alpha ignored for now
            
            uint argb = (0xFF << 24) | (r << 16) | (g << 8) | b;
            framebufferPutPixel(win.x + dx, win.y + dy, argb);
        }
    }
}

// Map window (make visible)
@nogc nothrow bool mapX11Window(uint id)
{
    auto win = getX11Window(id);
    if (win is null) return false;
    
    win.mapped = true;
    
    compositeWindow(win);
    
    return true;
}

// Unmap window (make invisible)
@nogc nothrow bool unmapX11Window(uint id)
{
    auto win = getX11Window(id);
    if (win is null) return false;
    
    win.mapped = false;
    
    return true;
}

// Configure window (move/resize)
@nogc nothrow bool configureX11Window(uint id, short x, short y, ushort width, ushort height)
{
    auto win = getX11Window(id);
    if (win is null) return false;
    
    win.x = x;
    win.y = y;
    win.width = width;
    win.height = height;
    
    // TODO: Reallocate backing store if size changed
    
    return true;
}

// ============================================================================
// X11 Server State
// ============================================================================

struct X11ServerState
{
    bool running;
    ObjectID ipcChannel;  // Channel for X11 protocol
    uint rootWindow;
    ushort screenWidth;
    ushort screenHeight;
    ubyte screenDepth;
}

__gshared X11ServerState g_x11Server;

// ============================================================================
// X11 Protocol Handler
// ============================================================================

// Handle X11 request
@nogc nothrow void handleX11Request(const(ubyte)[] request, ubyte* response, size_t* responseLen)
{
    if (request.length < 4)
    {
        *responseLen = 0;
        return;
    }
    
    ubyte opcode = request[0];
    
    switch (opcode)
    {
        case X11Opcode.CreateWindow:
            // Parse create window request
            if (request.length < 32)
            {
                *responseLen = 0;
                return;
            }
            
            ubyte depth = request[1];
            uint wid = *cast(uint*)(request.ptr + 4);
            uint parent = *cast(uint*)(request.ptr + 8);
            short x = *cast(short*)(request.ptr + 12);
            short y = *cast(short*)(request.ptr + 14);
            ushort width = *cast(ushort*)(request.ptr + 16);
            ushort height = *cast(ushort*)(request.ptr + 18);
            
            createX11Window(parent, x, y, width, height);
            
            // Send success response
            *responseLen = 0;  // No response for CreateWindow
            break;
        
        case X11Opcode.MapWindow:
            if (request.length < 8)
            {
                *responseLen = 0;
                return;
            }
            
            uint wid = *cast(uint*)(request.ptr + 4);
            mapX11Window(wid);
            
            *responseLen = 0;
            break;
        
        case X11Opcode.UnmapWindow:
            if (request.length < 8)
            {
                *responseLen = 0;
                return;
            }
            
            uint wid = *cast(uint*)(request.ptr + 4);
            unmapX11Window(wid);
            
            *responseLen = 0;
            break;
        
        case X11Opcode.ConfigureWindow:
            if (request.length < 24)
            {
                *responseLen = 0;
                return;
            }
            
            uint wid = *cast(uint*)(request.ptr + 4);
            short x = *cast(short*)(request.ptr + 8);
            short y = *cast(short*)(request.ptr + 10);
            ushort width = *cast(ushort*)(request.ptr + 12);
            ushort height = *cast(ushort*)(request.ptr + 14);
            
            configureX11Window(wid, x, y, width, height);
            
            *responseLen = 0;
            break;
        
        case X11Opcode.InternAtom:
            // Stub: Return a fake atom ID based on name length for now
            // Real impl would need a string table
            if (request.length < 8) { *responseLen = 0; return; }
            ushort nameLen = *cast(ushort*)(request.ptr + 4);
            uint atomId = 0x100 + nameLen; // Fake ID
            
            // Response: 32 bytes
            // [0] = 1 (Reply)
            // [2..4] = sequence number
            // [4..8] = length
            // [8..12] = atom ID
            
            responseBuffer[0] = 1; // Reply
            *cast(uint*)(responseBuffer.ptr + 8) = atomId;
            *responseLen = 32;
            break;

        case X11Opcode.ChangeProperty:
            // Stub: Just acknowledge
            *responseLen = 0;
            break;

        case X11Opcode.GetProperty:
            // Stub: Return no property
            // Response: 32 bytes
            // [0] = 1 (Reply)
            // [8..12] = type (0 = None)
            responseBuffer[0] = 1; // Reply
            *cast(uint*)(responseBuffer.ptr + 8) = 0; // None
            *cast(uint*)(responseBuffer.ptr + 12) = 0; // bytes after
            *cast(uint*)(responseBuffer.ptr + 16) = 0; // value len
            *responseLen = 32;
            break;

        case X11Opcode.GrabKey:
        case X11Opcode.GrabButton:
            // Stub: Acknowledge
            *responseLen = 0;
            break;

        case X11Opcode.QueryPointer:
            // Stub: Return fake pointer info
            // Response: 32 bytes
            // [0] = 1 (Reply)
            // [8..12] = root
            // [12..16] = child
            // [16..18] = rootX
            // [18..20] = rootY
            // [20..22] = winX
            // [22..24] = winY
            // [24..26] = mask
            responseBuffer[0] = 1; // Reply
            *cast(uint*)(responseBuffer.ptr + 8) = g_x11Server.rootWindow;
            *cast(short*)(responseBuffer.ptr + 16) = 100; // rootX
            *cast(short*)(responseBuffer.ptr + 18) = 100; // rootY
            *responseLen = 32;
            break;

        case X11Opcode.CreateGC:
        case X11Opcode.ChangeGC:
        case X11Opcode.CopyArea:
        case X11Opcode.DestroyWindow:
            if (request.length < 8) { *responseLen = 0; return; }
            uint wid = *cast(uint*)(request.ptr + 4);
            // TODO: Actually remove from list and free memory
            unmapX11Window(wid);
            *responseLen = 0;
            break;

        case X11Opcode.GetGeometry:
            if (request.length < 8) { *responseLen = 0; return; }
            uint wid = *cast(uint*)(request.ptr + 4);
            auto win = getX11Window(wid);
            
            // Response: 32 bytes
            responseBuffer[0] = 1; // Reply
            responseBuffer[1] = g_x11Server.screenDepth; // Depth
            *cast(uint*)(responseBuffer.ptr + 8) = g_x11Server.rootWindow; // Root
            
            if (win !is null)
            {
                *cast(short*)(responseBuffer.ptr + 12) = win.x;
                *cast(short*)(responseBuffer.ptr + 14) = win.y;
                *cast(ushort*)(responseBuffer.ptr + 16) = win.width;
                *cast(ushort*)(responseBuffer.ptr + 18) = win.height;
                *cast(ushort*)(responseBuffer.ptr + 20) = win.borderWidth;
            }
            else if (wid == g_x11Server.rootWindow)
            {
                *cast(short*)(responseBuffer.ptr + 12) = 0;
                *cast(short*)(responseBuffer.ptr + 14) = 0;
                *cast(ushort*)(responseBuffer.ptr + 16) = g_x11Server.screenWidth;
                *cast(ushort*)(responseBuffer.ptr + 18) = g_x11Server.screenHeight;
                *cast(ushort*)(responseBuffer.ptr + 20) = 0;
            }
            
            *responseLen = 32;
            break;

        case X11Opcode.QueryTree:
            if (request.length < 8) { *responseLen = 0; return; }
            uint wid = *cast(uint*)(request.ptr + 4);
            
            // Response: 32 bytes + children
            responseBuffer[0] = 1; // Reply
            *cast(uint*)(responseBuffer.ptr + 8) = g_x11Server.rootWindow; // Root
            *cast(uint*)(responseBuffer.ptr + 12) = 0; // Parent (TODO)
            *cast(ushort*)(responseBuffer.ptr + 16) = 0; // Num children (TODO)
            
            *responseLen = 32;
            break;

        case X11Opcode.PolyFillRectangle:
            if (request.length < 12) { *responseLen = 0; return; }
            uint wid = *cast(uint*)(request.ptr + 4);
            // Skip GC (ptr+8)
            
            auto win = getX11Window(wid);
            if (win !is null && win.buffer !is null)
            {
                // Rectangles start at offset 12
                // x(2), y(2), w(2), h(2)
                size_t offset = 12;
                while (offset + 8 <= request.length)
                {
                    short rx = *cast(short*)(request.ptr + offset);
                    short ry = *cast(short*)(request.ptr + offset + 2);
                    ushort rw = *cast(ushort*)(request.ptr + offset + 4);
                    ushort rh = *cast(ushort*)(request.ptr + offset + 6);
                    offset += 8;
                    
                    // Draw to backing store (simple fill with white for now, TODO: use GC color)
                    // Clipping
                    if (rx < 0) { rw += rx; rx = 0; }
                    if (ry < 0) { rh += ry; ry = 0; }
                    if (rx + rw > win.width) rw = cast(ushort)(win.width - rx);
                    if (ry + rh > win.height) rh = cast(ushort)(win.height - ry);
                    
                    for (int dy = 0; dy < rh; ++dy)
                    {
                        for (int dx = 0; dx < rw; ++dx)
                        {
                            size_t idx = ((ry + dy) * win.width + (rx + dx)) * 4;
                            win.buffer[idx] = 0xFF;     // R
                            win.buffer[idx+1] = 0xFF;   // G
                            win.buffer[idx+2] = 0xFF;   // B
                            win.buffer[idx+3] = 0xFF;   // A
                        }
                    }
                }
                compositeWindow(win);
            }
            *responseLen = 0;
            break;

        default:
            // Unsupported opcode - send empty response
            *responseLen = 0;
            break;
    }
}

// ============================================================================
// X11 Server Initialization
// ============================================================================

// Start X11 server
@nogc nothrow bool startX11Server()
{
    // Create IPC channel for X11 protocol
    ObjectID chan1, chan2;
    createChannelPair(&chan1, &chan2);
    
    g_x11Server.ipcChannel = chan1;
    
    // Create root window
    if (framebufferAvailable())
    {
        g_x11Server.screenWidth = cast(ushort)g_fb.width;
        g_x11Server.screenHeight = cast(ushort)g_fb.height;
    }
    else
    {
        g_x11Server.screenWidth = 1024;
        g_x11Server.screenHeight = 768;
    }
    g_x11Server.screenDepth = 32; // Framebuffer is usually 32bpp
    
    g_x11Server.rootWindow = createX11Window(
        0,  // No parent
        0, 0,
        g_x11Server.screenWidth,
        g_x11Server.screenHeight
    );
    
    // Map root window
    mapX11Window(g_x11Server.rootWindow);
    
    g_x11Server.running = true;
    
    return true;
}

// Stop X11 server
@nogc nothrow void stopX11Server()
{
    g_x11Server.running = false;
}

// Get X11 server channel (for clients to connect)
@nogc nothrow ObjectID getX11ServerChannel()
{
    return g_x11Server.ipcChannel;
}

// ============================================================================
// X11 Server Main Loop (stub)
// ============================================================================

// Process X11 requests
@nogc nothrow void processX11Requests()
{
    if (!g_x11Server.running) return;
    
    // Receive request from channel
    ubyte[4096] requestBuffer;
    ubyte[4096] responseBuffer;
    Capability[1] caps;
    size_t capsReceived;
    
    long bytesRead = channelRecv(
        g_x11Server.ipcChannel,
        requestBuffer.ptr,
        4096,
        caps.ptr,
        1,
        &capsReceived
    );
    
    if (bytesRead > 0)
    {
        // Handle request
        size_t responseLen;
        handleX11Request(
            requestBuffer[0..bytesRead],
            responseBuffer.ptr,
            &responseLen
        );
        
        // Send response
        if (responseLen > 0)
        {
            channelSend(
                g_x11Server.ipcChannel,
                responseBuffer.ptr,
                responseLen,
                null,
                0
            );
        }
    }
}
