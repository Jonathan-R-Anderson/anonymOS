module minimal_os.display.x11_server;

// Minimal X11 server implementation for i3
// Provides enough X11 protocol support for i3 to run

import minimal_os.objects;
import minimal_os.display.framebuffer;
import minimal_os.display.canvas;

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

// Map window (make visible)
@nogc nothrow bool mapX11Window(uint id)
{
    auto win = getX11Window(id);
    if (win is null) return false;
    
    win.mapped = true;
    
    // TODO: Composite to framebuffer
    
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
    g_x11Server.screenWidth = 1920;   // TODO: Get from framebuffer
    g_x11Server.screenHeight = 1080;
    g_x11Server.screenDepth = 24;
    
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
