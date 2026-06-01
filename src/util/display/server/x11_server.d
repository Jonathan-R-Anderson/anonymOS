module anonymos_display.x11_server;

// Minimal X11 server implementation for i3
// Provides enough X11 protocol support for i3 to run

import anonymos_userland.core.objects;
import anonymos_display.framebuffer;
import anonymos_display.canvas;
import implementation.kernel.core.heap : kmalloc, kfree;
import implementation.kernel.core.memory : memcpy, memset;
import anonymos_userland.core.objects : socketBind, socketListen, socketAccept, socketRecv, socketSend, socketClose;
import anonymos_network.stack.types : IPv4Address;
import anonymos_display.input_pipeline : InputEvent;

// ============================================================================
// X11 Atoms & Properties
// ============================================================================

struct X11Atom
{
    uint id;
    char[64] name; // Fixed size for simplicity
    size_t nameLen;
}

struct X11Property
{
    uint property; // Atom
    uint type;     // Atom
    ubyte format;  // 8, 16, 32
    ubyte* data;
    size_t length; // Number of items (not bytes)
}

struct X11GrabKey
{
    uint window;
    ushort modifiers;
    ubyte key;
    bool ownerEvents;
    bool pointerMode;
    bool keyboardMode;
}

struct X11GrabButton
{
    uint window;
    ushort modifiers;
    ubyte button;
    bool ownerEvents;
    bool pointerMode;
    bool keyboardMode;
    uint confineTo;
    uint cursor;
    ushort eventMask;
}

__gshared X11Atom[256] g_atoms;
__gshared size_t g_atomCount = 0;
__gshared uint g_nextAtomId = 1;

uint internAtom(const(char)[] name, bool onlyIfExists) @nogc nothrow
{
    // Check existing
    for (size_t i = 0; i < g_atomCount; ++i)
    {
        if (g_atoms[i].nameLen == name.length)
        {
            bool match = true;
            for (size_t j = 0; j < name.length; ++j)
            {
                if (g_atoms[i].name[j] != name[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return g_atoms[i].id;
        }
    }
    
    if (onlyIfExists) return 0;
    
    if (g_atomCount >= g_atoms.length) return 0;
    
    X11Atom* atom = &g_atoms[g_atomCount++];
    atom.id = g_nextAtomId++;
    size_t len = name.length;
    if (len > 63) len = 63;
    
    for (size_t i = 0; i < len; ++i) atom.name[i] = name[i];
    atom.name[len] = 0;
    atom.nameLen = len;
    
    return atom.id;
}

X11Atom* getAtom(uint id) @nogc nothrow
{
    for (size_t i = 0; i < g_atomCount; ++i)
    {
        if (g_atoms[i].id == id) return &g_atoms[i];
    }
    return null;
}

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
    ListProperties = 21,
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
    
    X11Property[16] properties; // Fixed size for simplicity
    size_t propertyCount;
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
    win.propertyCount = 0;
    
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
// Unmap window (make invisible)
@nogc nothrow bool unmapX11Window(uint id)
{
    auto win = getX11Window(id);
    if (win is null) return false;
    
    win.mapped = false;
    
    // TODO: Generate UnmapNotify event
    
    return true;
}

// Destroy window
@nogc nothrow bool destroyX11Window(uint id)
{
    // Find index
    size_t idx = size_t.max;
    for (size_t i = 0; i < g_x11WindowCount; ++i)
    {
        if (g_x11Windows[i].id == id)
        {
            idx = i;
            break;
        }
    }
    
    if (idx == size_t.max) return false;
    
    X11Window* win = &g_x11Windows[idx];
    
    // Free properties
    for (size_t i = 0; i < win.propertyCount; ++i)
    {
        if (win.properties[i].data !is null)
            kfree(win.properties[i].data);
    }
    
    // Free backing store buffer (VMO handles itself via refcounting usually, but we allocated the buffer manually)
    if (win.buffer !is null)
    {
        kfree(win.buffer);
    }
    
    // Remove from list (shift)
    for (size_t i = idx; i < g_x11WindowCount - 1; ++i)
    {
        g_x11Windows[i] = g_x11Windows[i + 1];
    }
    g_x11WindowCount--;
    
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

struct X11Client
{
    ObjectID socket;
    bool active;
    bool handshakeComplete;  // Track if initial connection setup is done
}

struct X11ServerState
{
    bool running;
    ObjectID serverSocket;
    X11Client[16] clients;
    uint rootWindow;
    ushort screenWidth;
    ushort screenHeight;
    ubyte screenDepth;
    
    X11GrabKey[16] keyGrabs;
    size_t keyGrabCount;
    X11GrabButton[16] buttonGrabs;
    size_t buttonGrabCount;
}

__gshared X11ServerState g_x11Server;


// ============================================================================
// X11 Protocol Handler
// ============================================================================

// Handle X11 connection setup (initial handshake)
@nogc nothrow bool handleX11ConnectionSetup(const(ubyte)[] request, ubyte* responseBuffer, size_t* responseLen)
{
    import anonymos_userland.shell.console : printLine, printUnsigned;
    
    // Connection setup request is 12 bytes minimum
    if (request.length < 12)
    {
        *responseLen = 0;
        return false;
    }
    
    printLine("[x11] Handling connection setup");
    
    // Build connection setup response
    // Format: Success(1) + pad(1) + protocol-major(2) + protocol-minor(2) + length(2)
    //         + release-number(4) + resource-id-base(4) + resource-id-mask(4)
    //         + motion-buffer-size(4) + vendor-length(2) + max-request-length(2)
    //         + num-screens(1) + num-formats(1) + image-byte-order(1) + bitmap-format-bit-order(1)
    //         + bitmap-format-scanline-unit(1) + bitmap-format-scanline-pad(1)
    //         + min-keycode(1) + max-keycode(1) + pad(4) + vendor-string + formats + screens
    
    responseBuffer[0] = 1; // Success
    responseBuffer[1] = 0; // Pad
    *cast(ushort*)(responseBuffer + 2) = 11; // Protocol major version
    *cast(ushort*)(responseBuffer + 4) = 0;  // Protocol minor version
    *cast(ushort*)(responseBuffer + 6) = 0;  // Additional data length (will update)
    
    *cast(uint*)(responseBuffer + 8) = 1;  // Release number
    *cast(uint*)(responseBuffer + 12) = 0x00400000; // Resource ID base
    *cast(uint*)(responseBuffer + 16) = 0x003FFFFF; // Resource ID mask
    *cast(uint*)(responseBuffer + 20) = 256; // Motion buffer size
    *cast(ushort*)(responseBuffer + 24) = 0; // Vendor length
    *cast(ushort*)(responseBuffer + 26) = 65535; // Max request length
    responseBuffer[28] = 1; // Number of screens
    responseBuffer[29] = 1; // Number of formats
    responseBuffer[30] = 0; // Image byte order (LSB first)
    responseBuffer[31] = 0; // Bitmap format bit order (LSB first)
    responseBuffer[32] = 32; // Bitmap scanline unit
    responseBuffer[33] = 32; // Bitmap scanline pad
    responseBuffer[34] = 8;  // Min keycode
    responseBuffer[35] = 255; // Max keycode
    *cast(uint*)(responseBuffer + 36) = 0; // Pad
    
    size_t offset = 40;
    
    // Format (depth=32, bpp=32, scanline-pad=32)
    responseBuffer[offset++] = 32; // Depth
    responseBuffer[offset++] = 32; // Bits per pixel
    responseBuffer[offset++] = 32; // Scanline pad
    offset += 5; // Pad to 8 bytes
    
    // Screen info
    *cast(uint*)(responseBuffer + offset) = g_x11Server.rootWindow; // Root window
    offset += 4;
    *cast(uint*)(responseBuffer + offset) = 0; // Default colormap
    offset += 4;
    *cast(uint*)(responseBuffer + offset) = 0xFFFFFF; // White pixel
    offset += 4;
    *cast(uint*)(responseBuffer + offset) = 0x000000; // Black pixel
    offset += 4;
    *cast(uint*)(responseBuffer + offset) = 0; // Current input masks
    offset += 4;
    *cast(ushort*)(responseBuffer + offset) = g_x11Server.screenWidth;
    offset += 2;
    *cast(ushort*)(responseBuffer + offset) = g_x11Server.screenHeight;
    offset += 2;
    *cast(ushort*)(responseBuffer + offset) = cast(ushort)(g_x11Server.screenWidth * 254 / 96); // Width in mm (assume 96 DPI)
    offset += 2;
    *cast(ushort*)(responseBuffer + offset) = cast(ushort)(g_x11Server.screenHeight * 254 / 96); // Height in mm
    offset += 2;
    *cast(ushort*)(responseBuffer + offset) = 1; // Min installed maps
    offset += 2;
    *cast(ushort*)(responseBuffer + offset) = 1; // Max installed maps
    offset += 2;
    *cast(uint*)(responseBuffer + offset) = 0; // Root visual
    offset += 4;
    responseBuffer[offset++] = 0; // Backing stores (Never)
    responseBuffer[offset++] = 1; // Save unders
    responseBuffer[offset++] = 32; // Root depth
    responseBuffer[offset++] = 1; // Number of depths
    
    // Depth info (depth=32)
    responseBuffer[offset++] = 32; // Depth
    responseBuffer[offset++] = 0;  // Pad
    *cast(ushort*)(responseBuffer + offset) = 1; // Number of visuals
    offset += 2;
    *cast(uint*)(responseBuffer + offset) = 0; // Pad
    offset += 4;
    
    // Visual info (TrueColor)
    *cast(uint*)(responseBuffer + offset) = 0; // Visual ID
    offset += 4;
    responseBuffer[offset++] = 4; // Class (TrueColor)
    responseBuffer[offset++] = 8; // Bits per RGB
    *cast(ushort*)(responseBuffer + offset) = 256; // Colormap entries
    offset += 2;
    *cast(uint*)(responseBuffer + offset) = 0x00FF0000; // Red mask
    offset += 4;
    *cast(uint*)(responseBuffer + offset) = 0x0000FF00; // Green mask
    offset += 4;
    *cast(uint*)(responseBuffer + offset) = 0x000000FF; // Blue mask
    offset += 4;
    *cast(uint*)(responseBuffer + offset) = 0; // Pad
    offset += 4;
    
    // Update length field (in 4-byte units, excluding first 8 bytes)
    *cast(ushort*)(responseBuffer + 6) = cast(ushort)((offset - 8) / 4);
    
    *responseLen = offset;
    
    printLine("[x11] Connection setup complete, response size: ");
    printUnsigned(offset);
    printLine("");
    
    return true;
}

// Handle X11 request
@nogc nothrow void handleX11Request(const(ubyte)[] request, ubyte* responseBuffer, size_t* responseLen)
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
            if (request.length < 8) { *responseLen = 0; return; }
            ushort nameLen = *cast(ushort*)(request.ptr + 4);
            // Pad(2)
            if (request.length < 8 + nameLen) { *responseLen = 0; return; }
            
            const(char)[] name = cast(const(char)[])request[8 .. 8 + nameLen];
            bool onlyIfExists = request[1] != 0;
            
            uint atomId = internAtom(name, onlyIfExists);
            
            // Response: 32 bytes
            responseBuffer[0] = 1; // Reply
            *cast(uint*)(responseBuffer + 8) = atomId;
            *responseLen = 32;
            break;
            
        case X11Opcode.GetAtomName:
            if (request.length < 8) { *responseLen = 0; return; }
            uint atomId = *cast(uint*)(request.ptr + 4);
            
            X11Atom* atom = getAtom(atomId);
            if (atom is null)
            {
                // Error? Or just empty?
                *responseLen = 0; // TODO: Send error
                return;
            }
            
            // Response: 32 bytes + name
            responseBuffer[0] = 1; // Reply
            ushort nameLen = cast(ushort)atom.nameLen;
            *cast(ushort*)(responseBuffer + 8) = nameLen;
            
            // Copy name
            for (size_t i = 0; i < nameLen; ++i)
                responseBuffer[32 + i] = cast(ubyte)atom.name[i];
                
            *responseLen = 32 + nameLen;
            // Pad to 4 bytes
            while ((*responseLen % 4) != 0) (*responseLen)++;
            break;

        case X11Opcode.ChangeProperty:
            if (request.length < 24) { *responseLen = 0; return; }
            
            uint wid = *cast(uint*)(request.ptr + 4);
            uint property = *cast(uint*)(request.ptr + 8);
            uint type = *cast(uint*)(request.ptr + 12);
            ubyte format = request[16];
            uint nUnits = *cast(uint*)(request.ptr + 20);
            
            // Data follows at offset 24
            size_t bytesPerUnit = format / 8;
            size_t dataLen = nUnits * bytesPerUnit;
            
            if (request.length < 24 + dataLen) { *responseLen = 0; return; }
            
            auto win = getX11Window(wid);
            if (win !is null)
            {
                // Find existing property
                X11Property* prop = null;
                for (size_t i = 0; i < win.propertyCount; ++i)
                {
                    if (win.properties[i].property == property)
                    {
                        prop = &win.properties[i];
                        break;
                    }
                }
                
                if (prop is null && win.propertyCount < win.properties.length)
                {
                    prop = &win.properties[win.propertyCount++];
                    prop.property = property;
                    prop.data = null;
                }
                
                if (prop !is null)
                {
                    // Update property
                    if (prop.data !is null) kfree(prop.data);
                    
                    prop.type = type;
                    prop.format = format;
                    prop.length = nUnits;
                    prop.data = cast(ubyte*)kmalloc(dataLen);
                    
                    if (prop.data !is null)
                    {
                        for (size_t i = 0; i < dataLen; ++i)
                            prop.data[i] = request[24 + i];
                    }
                }
            }
            
            *responseLen = 0;
            break;

        case X11Opcode.GetProperty:
            if (request.length < 24) { *responseLen = 0; return; }
            uint wid = *cast(uint*)(request.ptr + 4);
            uint property = *cast(uint*)(request.ptr + 8);
            
            auto win = getX11Window(wid);
            X11Property* prop = null;
            
            if (win !is null)
            {
                for (size_t i = 0; i < win.propertyCount; ++i)
                {
                    if (win.properties[i].property == property)
                    {
                        prop = &win.properties[i];
                        break;
                    }
                }
            }
            
            if (prop !is null)
            {
                // Response: 32 bytes + data
                responseBuffer[0] = 1; // Reply
                responseBuffer[1] = prop.format;
                *cast(uint*)(responseBuffer + 8) = prop.type;
                *cast(uint*)(responseBuffer + 12) = 0; // bytes after (TODO: handle large props)
                *cast(uint*)(responseBuffer + 16) = cast(uint)prop.length;
                
                size_t bytes = prop.length * (prop.format / 8);
                *cast(uint*)(responseBuffer + 4) = cast(uint)(bytes + 3) / 4; // Length in 4-byte units
                
                for (size_t i = 0; i < bytes; ++i)
                    responseBuffer[32 + i] = prop.data[i];
                    
                *responseLen = 32 + bytes;
                while ((*responseLen % 4) != 0) (*responseLen)++;
            }
            else
            {
                // None
                responseBuffer[0] = 1; // Reply
                *cast(uint*)(responseBuffer + 8) = 0; // None
                *responseLen = 32;
            }
            break;

        case X11Opcode.DeleteProperty:
            if (request.length < 12) { *responseLen = 0; return; }
            uint wid = *cast(uint*)(request.ptr + 4);
            uint property = *cast(uint*)(request.ptr + 8);
            
            auto win = getX11Window(wid);
            if (win !is null)
            {
                for (size_t i = 0; i < win.propertyCount; ++i)
                {
                    if (win.properties[i].property == property)
                    {
                        if (win.properties[i].data !is null)
                            kfree(win.properties[i].data);
                            
                        // Shift remove
                        for (size_t j = i; j < win.propertyCount - 1; ++j)
                        {
                            win.properties[j] = win.properties[j + 1];
                        }
                        win.propertyCount--;
                        break;
                    }
                }
            }
            *responseLen = 0;
            break;

        case X11Opcode.GrabKey:
            if (request.length < 16) { *responseLen = 0; return; }
            bool ownerEvents = request[1] != 0;
            uint grabWindow = *cast(uint*)(request.ptr + 4);
            ushort modifiers = *cast(ushort*)(request.ptr + 8);
            ubyte key = request[10];
            ubyte pointerMode = request[11];
            ubyte keyboardMode = request[12];
            
            if (g_x11Server.keyGrabCount < g_x11Server.keyGrabs.length)
            {
                 auto grab = &g_x11Server.keyGrabs[g_x11Server.keyGrabCount++];
                 grab.window = grabWindow;
                 grab.modifiers = modifiers;
                 grab.key = key;
                 grab.ownerEvents = ownerEvents;
                 grab.pointerMode = pointerMode != 0;
                 grab.keyboardMode = keyboardMode != 0;
            }
            *responseLen = 0;
            break;

        case X11Opcode.GrabButton:
             if (request.length < 24) { *responseLen = 0; return; }
             bool ownerEvents = request[1] != 0;
             uint grabWindow = *cast(uint*)(request.ptr + 4);
             ushort eventMask = *cast(ushort*)(request.ptr + 8);
             ubyte pointerMode = request[10];
             ubyte keyboardMode = request[11];
             uint confineTo = *cast(uint*)(request.ptr + 12);
             uint cursor = *cast(uint*)(request.ptr + 16);
             ubyte button = request[20];
             ushort modifiers = *cast(ushort*)(request.ptr + 22);
             
             if (g_x11Server.buttonGrabCount < g_x11Server.buttonGrabs.length)
             {
                 auto grab = &g_x11Server.buttonGrabs[g_x11Server.buttonGrabCount++];
                 grab.window = grabWindow;
                 grab.modifiers = modifiers;
                 grab.button = button;
                 grab.ownerEvents = ownerEvents;
                 grab.pointerMode = pointerMode != 0;
                 grab.keyboardMode = keyboardMode != 0;
                 grab.confineTo = confineTo;
                 grab.cursor = cursor;
                 grab.eventMask = eventMask;
             }
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
            *cast(uint*)(responseBuffer + 8) = g_x11Server.rootWindow;
            *cast(short*)(responseBuffer + 16) = 100; // rootX
            *cast(short*)(responseBuffer + 18) = 100; // rootY
            *responseLen = 32;
            break;

        case X11Opcode.CreateGC:
        case X11Opcode.ChangeGC:
        case X11Opcode.CopyArea:
            *responseLen = 0;
            break;
            
        case X11Opcode.DestroyWindow:
            if (request.length < 8) { *responseLen = 0; return; }
            uint wid = *cast(uint*)(request.ptr + 4);
            destroyX11Window(wid);
            *responseLen = 0;
            break;

        case X11Opcode.GetGeometry:
            if (request.length < 8) { *responseLen = 0; return; }
            uint wid = *cast(uint*)(request.ptr + 4);
            auto win = getX11Window(wid);
            
            // Response: 32 bytes
            responseBuffer[0] = 1; // Reply
            responseBuffer[1] = g_x11Server.screenDepth; // Depth
            *cast(uint*)(responseBuffer + 8) = g_x11Server.rootWindow; // Root
            
            if (win !is null)
            {
                *cast(short*)(responseBuffer + 12) = win.x;
                *cast(short*)(responseBuffer + 14) = win.y;
                *cast(ushort*)(responseBuffer + 16) = win.width;
                *cast(ushort*)(responseBuffer + 18) = win.height;
                *cast(ushort*)(responseBuffer + 20) = win.borderWidth;
            }
            else if (wid == g_x11Server.rootWindow)
            {
                *cast(short*)(responseBuffer + 12) = 0;
                *cast(short*)(responseBuffer + 14) = 0;
                *cast(ushort*)(responseBuffer + 16) = g_x11Server.screenWidth;
                *cast(ushort*)(responseBuffer + 18) = g_x11Server.screenHeight;
                *cast(ushort*)(responseBuffer + 20) = 0;
            }
            
            *responseLen = 32;
            break;

        case X11Opcode.QueryTree:
            if (request.length < 8) { *responseLen = 0; return; }
            uint wid = *cast(uint*)(request.ptr + 4);
            
            auto win = getX11Window(wid);
            if (win is null) { *responseLen = 0; return; }
            
            // Count children
            uint childCount = 0;
            for (size_t i = 0; i < g_x11WindowCount; ++i)
            {
                if (g_x11Windows[i].parent == wid)
                    childCount++;
            }
            
            // Response: 32 bytes + children * 4
            responseBuffer[0] = 1; // Reply
            *cast(uint*)(responseBuffer + 8) = g_x11Server.rootWindow; // Root
            *cast(uint*)(responseBuffer + 12) = win.parent; // Parent
            *cast(ushort*)(responseBuffer + 16) = cast(ushort)childCount; // Num children
            
            *cast(uint*)(responseBuffer + 4) = childCount; // Length in 4-byte units
            
            // Fill children
            size_t offset = 32;
            for (size_t i = 0; i < g_x11WindowCount; ++i)
            {
                if (g_x11Windows[i].parent == wid)
                {
                    *cast(uint*)(responseBuffer + offset) = g_x11Windows[i].id;
                    offset += 4;
                }
            }
            
            *responseLen = offset;
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
    import anonymos_userland.shell.console : printLine;
    
    printLine("[x11] Starting X11 server...");
    
    // Create server socket (Unix domain socket)
    import anonymos_userland.core.objects : createSocket, SocketType;
    g_x11Server.serverSocket = createSocket(SocketType.Stream);
    if (g_x11Server.serverSocket.low == 0)
    {
        printLine("[x11] Failed to create socket");
        return false;
    }
    
    // For Unix domain sockets, we need to bind to a path
    // Standard X11 uses /tmp/.X11-unix/X0 for display :0
    // For now, we'll use TCP on port 6000 as a fallback since Unix sockets
    // require filesystem support
    
    // Bind to 0.0.0.0:6000 (X11 display :0)
    ubyte[16] addr; // Zeros = 0.0.0.0
    if (socketBind(g_x11Server.serverSocket, addr.ptr, 6000) != 0)
    {
        printLine("[x11] Failed to bind socket to port 6000");
        return false;
    }
    
    // Listen for connections
    if (socketListen(g_x11Server.serverSocket, 10) != 0)
    {
        printLine("[x11] Failed to listen on socket");
        return false;
    }
    
    printLine("[x11] Listening on TCP port 6000 (display :0)");
    
    // Clear clients
    for (size_t i = 0; i < g_x11Server.clients.length; ++i)
        g_x11Server.clients[i].active = false;
    
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
    
    printLine("[x11] Screen size: ");
    import anonymos_userland.shell.console : printUnsigned;
    printUnsigned(g_x11Server.screenWidth);
    printLine("x");
    printUnsigned(g_x11Server.screenHeight);
    printLine("");
    
    g_x11Server.rootWindow = createX11Window(
        0,  // No parent
        0, 0,
        g_x11Server.screenWidth,
        g_x11Server.screenHeight
    );
    
    // Map root window
    mapX11Window(g_x11Server.rootWindow);
    
    g_x11Server.running = true;
    
    printLine("[x11] X11 server started successfully");
    
    return true;
}

// Stop X11 server
@nogc nothrow void stopX11Server()
{
    g_x11Server.running = false;
}

// Get X11 server socket (for clients to connect)
@nogc nothrow ObjectID getX11ServerSocket()
{
    return g_x11Server.serverSocket;
}

// ============================================================================
// X11 Server Main Loop (stub)
// ============================================================================

// Process X11 requests
@nogc nothrow void processX11Requests()
{
    if (!g_x11Server.running) return;
    
    // Accept new clients
    ObjectID newClient = socketAccept(g_x11Server.serverSocket);
    if (newClient.low != 0)
    {
        import anonymos_userland.shell.console : printLine, printUnsigned;
        printLine("[x11] New client connected");
        
        // Find free slot
        for (size_t i = 0; i < g_x11Server.clients.length; ++i)
        {
            if (!g_x11Server.clients[i].active)
            {
                g_x11Server.clients[i].socket = newClient;
                g_x11Server.clients[i].active = true;
                printLine("[x11] Client assigned to slot ");
                printUnsigned(i);
                printLine("");
                break;
            }
        }
    }
    
    // Process clients
    ubyte[4096] requestBuffer;
    ubyte[4096] responseBuffer;
    
    for (size_t i = 0; i < g_x11Server.clients.length; ++i)
    {
        if (!g_x11Server.clients[i].active) continue;
        
        long bytesRead = socketRecv(g_x11Server.clients[i].socket, requestBuffer.ptr, 4096);
        
        if (bytesRead > 0)
        {
            size_t responseLen;
            
            // Check if this is a new connection that needs handshake
            if (!g_x11Server.clients[i].handshakeComplete)
            {
                import anonymos_userland.shell.console : printLine;
                printLine("[x11] Processing connection setup for new client");
                
                if (handleX11ConnectionSetup(
                    requestBuffer[0..cast(size_t)bytesRead],
                    responseBuffer.ptr,
                    &responseLen
                ))
                {
                    g_x11Server.clients[i].handshakeComplete = true;
                    
                    // Send connection setup response
                    if (responseLen > 0)
                    {
                        socketSend(g_x11Server.clients[i].socket, responseBuffer.ptr, responseLen);
                    }
                }
            }
            else
            {
                // Handle regular request
                handleX11Request(
                    requestBuffer[0..cast(size_t)bytesRead],
                    responseBuffer.ptr,
                    &responseLen
                );
                
                // Send response
                if (responseLen > 0)
                {
                    socketSend(g_x11Server.clients[i].socket, responseBuffer.ptr, responseLen);
                }
            }
        }
        else if (bytesRead == 0) // EOF? Not necessarily with non-blocking, but let's assume 0 means closed or empty
        {
            // TODO: Check if actually closed
        }
    }
}

// Inject input event from kernel pipeline
@nogc nothrow void injectX11Input(InputEvent event)
{
    if (!g_x11Server.running) return;
    
    ubyte[32] ev;
    // Clear event
    for(int i=0; i<32; i++) ev[i] = 0;
    
    if (event.type == InputEvent.Type.keyDown || event.type == InputEvent.Type.keyUp)
    {
        ev[0] = (event.type == InputEvent.Type.keyDown) ? 2 : 3; // KeyPress/KeyRelease
        ev[1] = cast(ubyte)event.data2; // Keycode
        *cast(uint*)(ev.ptr + 4) = 0; // Time
        *cast(uint*)(ev.ptr + 8) = g_x11Server.rootWindow;
        *cast(uint*)(ev.ptr + 12) = g_x11Server.rootWindow; // Default to root
        *cast(ushort*)(ev.ptr + 28) = cast(ushort)event.data3; // State
        ev[30] = 1; // SameScreen
        
        // Check grabs
        for (size_t i = 0; i < g_x11Server.keyGrabCount; ++i)
        {
            if (g_x11Server.keyGrabs[i].key == ev[1] || g_x11Server.keyGrabs[i].key == 0)
            {
                // TODO: Check modifiers
                *cast(uint*)(ev.ptr + 12) = g_x11Server.keyGrabs[i].window;
                
                // Broadcast to all clients (since we don't track window ownership yet)
                for (size_t c = 0; c < g_x11Server.clients.length; ++c)
                {
                    if (g_x11Server.clients[c].active)
                        socketSend(g_x11Server.clients[c].socket, ev.ptr, 32);
                }
                return;
            }
        }
        
        // If no grab, broadcast anyway for now (focus not implemented)
        for (size_t c = 0; c < g_x11Server.clients.length; ++c)
        {
            if (g_x11Server.clients[c].active)
                socketSend(g_x11Server.clients[c].socket, ev.ptr, 32);
        }
    }
    else if (event.type == InputEvent.Type.buttonDown || event.type == InputEvent.Type.buttonUp)
    {
        ev[0] = (event.type == InputEvent.Type.buttonDown) ? 4 : 5; // ButtonPress/ButtonRelease
        
        // Map button mask to ID
        ubyte button = 1;
        if (event.data3 & 2) button = 3;
        else if (event.data3 & 4) button = 2;
        
        ev[1] = button;
        *cast(uint*)(ev.ptr + 4) = 0; // Time
        *cast(uint*)(ev.ptr + 8) = g_x11Server.rootWindow;
        *cast(uint*)(ev.ptr + 12) = g_x11Server.rootWindow;
        *cast(short*)(ev.ptr + 20) = cast(short)event.data1; // RootX
        *cast(short*)(ev.ptr + 22) = cast(short)event.data2; // RootY
        *cast(short*)(ev.ptr + 24) = cast(short)event.data1; // EventX
        *cast(short*)(ev.ptr + 26) = cast(short)event.data2; // EventY
        ev[30] = 1; // SameScreen
        
        // Check grabs
        for (size_t i = 0; i < g_x11Server.buttonGrabCount; ++i)
        {
             // Simple grab check
             if (g_x11Server.buttonGrabs[i].button == button || g_x11Server.buttonGrabs[i].button == 0)
             {
                 *cast(uint*)(ev.ptr + 12) = g_x11Server.buttonGrabs[i].window;
                 
                  for (size_t c = 0; c < g_x11Server.clients.length; ++c)
                {
                    if (g_x11Server.clients[c].active)
                        socketSend(g_x11Server.clients[c].socket, ev.ptr, 32);
                }
                return;
             }
        }
        
        // Broadcast
        for (size_t c = 0; c < g_x11Server.clients.length; ++c)
        {
            if (g_x11Server.clients[c].active)
                socketSend(g_x11Server.clients[c].socket, ev.ptr, 32);
        }
    }
}

// ============================================================================
// Rendering
// ============================================================================

/// Render all mapped X11 windows to the framebuffer
/// This is called every frame when using i3 as the window manager
@nogc nothrow void renderAllX11Windows()
{
    static bool logged = false;
    static size_t lastWindowCount = 0;
    static size_t lastMappedCount = 0;
    
    size_t mappedCount = 0;
    for (size_t i = 0; i < g_x11WindowCount; ++i)
    {
        if (g_x11Windows[i].mapped)
            mappedCount++;
    }
    
    // Log when window state changes
    if (!logged || g_x11WindowCount != lastWindowCount || mappedCount != lastMappedCount)
    {
        import anonymos_userland.shell.console : printLine, printUnsigned;
        printLine("[x11] renderAllX11Windows: total windows = ");
        printUnsigned(g_x11WindowCount);
        printLine(", mapped = ");
        printUnsigned(mappedCount);
        printLine("");
        
        lastWindowCount = g_x11WindowCount;
        lastMappedCount = mappedCount;
        logged = true;
    }
    
    for (size_t i = 0; i < g_x11WindowCount; ++i)
    {
        // Skip the root window - it's just a container and should be transparent
        // Only render actual application windows
        if (g_x11Windows[i].mapped && g_x11Windows[i].id != g_x11Server.rootWindow)
        {
            compositeWindow(&g_x11Windows[i]);
        }
    }
}

