module anonymos.display.i3_integration;

// i3 window manager integration for the capability-based OS

import anonymos.objects;
import anonymos.namespaces;
import anonymos.syscalls.capabilities;
import anonymos.display.framebuffer;
import anonymos.display.canvas;

// ============================================================================
// i3 IPC Protocol Integration
// ============================================================================

// i3 communicates via IPC socket
// We need to provide a channel object that i3 can use

struct I3Config
{
    char[256] configPath;
    char[256] socketPath;
    bool enableXWayland;
    bool enableCompositing;
    uint workspaceCount;
}

__gshared I3Config g_i3Config;
__gshared ObjectID g_i3Process = ObjectID(0, 0);
__gshared ObjectID g_i3IPCChannel = ObjectID(0, 0);

// ============================================================================
// i3 Namespace Setup
// ============================================================================

// Create namespace for i3 with required capabilities
@nogc nothrow ObjectID createI3Namespace()
{
    ObjectID baseRoot = getRootObject();
    ObjectID i3Ns = createNamespace("i3-wm", baseRoot, false);
    
    auto ns = getNamespace(i3Ns);
    if (ns is null) return ObjectID(0, 0);
    
    // i3 needs access to:
    // 1. Display/framebuffer
    // 2. Input devices
    // 3. Configuration files
    // 4. IPC socket
    
    // Create /dev with display and input devices
    ObjectID devDir = createDirectory();
    
    // Add framebuffer device
    // TODO: Create actual framebuffer device object
    // For now, just create the directory structure
    
    bindMount(i3Ns, "/dev", devDir, Rights.Read | Rights.Write);
    
    // Create /etc with i3 config
    ObjectID etcDir = createDirectory();
    ObjectID i3Dir = createDirectory();
    
    insert(etcDir, "i3", Capability(i3Dir, Rights.Read | Rights.Enumerate));
    bindMount(i3Ns, "/etc", etcDir, Rights.Read | Rights.Enumerate);
    
    // Create /run for IPC socket
    ObjectID runDir = createDirectory();
    ObjectID userDir = createDirectory();
    
    insert(runDir, "user", Capability(userDir, Rights.Read | Rights.Write | Rights.Enumerate));
    bindMount(i3Ns, "/run", runDir, Rights.Read | Rights.Write | Rights.Enumerate);
    
    return i3Ns;
}

// ============================================================================
// i3 Process Management
// ============================================================================

// Start i3 window manager
@nogc nothrow ObjectID startI3()
{
    // 1. Create namespace for i3
    ObjectID i3Ns = createI3Namespace();
    if (i3Ns.low == 0) return ObjectID(0, 0);
    
    auto ns = getNamespace(i3Ns);
    if (ns is null) return ObjectID(0, 0);
    
    // 2. Create IPC channel for i3
    ObjectID chan1, chan2;
    createChannelPair(&chan1, &chan2);
    
    g_i3IPCChannel = chan1;  // Kernel keeps one end
    
    // 3. Create process with i3 namespace
    Capability rootCap = Capability(ns.rootDir, Rights.Read | Rights.Execute | Rights.Enumerate);
    Capability homeCap = Capability(ObjectID(0, 0), Rights.None);  // No home for i3
    
    ObjectID procDir = createDirectory();
    Capability procCap = Capability(procDir, Rights.Read | Rights.Write);
    
    // Export IPC channel to process
    insert(procDir, "ipc", Capability(chan2, Rights.Read | Rights.Write));
    
    ObjectID i3Proc = createProcess(rootCap, homeCap, procCap);
    g_i3Process = i3Proc;
    
    // 4. Initialize process C-List with capabilities
    // Slot 0: root
    // Slot 1: home (none)
    // Slot 2: proc
    // Slot 3: IPC channel
    // Slot 4: framebuffer
    
    // Spawn i3 binary
    const(char)*[2] argv;
    argv[0] = "/bin/i3";
    argv[1] = null;
    
    const(char)*[1] envp;
    envp[0] = null;
    
    // We need to use the kernel's process spawning capability
    // This is a placeholder for the actual syscall/helper
    // spawnProcess(i3Proc, "/bin/i3", argv, envp);
    
    return i3Proc;
}

// Custom configuration support
__gshared char[] g_customI3Config;

@nogc nothrow void setCustomI3Config(const(char)[] config)
{
    // Simple copy (assuming config fits in a reasonable buffer or we just store the slice if static)
    // For safety in this environment, we'll just point to it if it's static, 
    // or we'd need a proper allocator.
    // Given the constraints, let's assume the caller keeps the string alive.
    g_customI3Config = cast(char[])config;
}

// Stop i3 window manager
@nogc nothrow bool stopI3()
{
    if (g_i3Process.low == 0) return false;
    
    // Send shutdown signal
    processSignal(g_i3Process, 15);  // SIGTERM
    
    // Wait for exit
    processWait(g_i3Process);
    
    g_i3Process = ObjectID(0, 0);
    g_i3IPCChannel = ObjectID(0, 0);
    
    return true;
}

// ============================================================================
// i3 IPC Message Handling
// ============================================================================

enum I3MessageType : uint
{
    RunCommand = 0,
    GetWorkspaces = 1,
    Subscribe = 2,
    GetOutputs = 3,
    GetTree = 4,
    GetMarks = 5,
    GetBarConfig = 6,
    GetVersion = 7,
    GetBindingModes = 8,
    GetConfig = 9,
    SendTick = 10,
    Sync = 11,
}

struct I3Message
{
    uint length;
    I3MessageType type;
    ubyte[4096] payload;
}

// Send message to i3
@nogc nothrow long sendI3Message(I3MessageType type, const(ubyte)[] payload)
{
    if (g_i3IPCChannel.low == 0) return -1;
    
    // Format: "i3-ipc" + length (4 bytes) + type (4 bytes) + payload
    ubyte[4096] buffer;
    size_t pos = 0;
    
    // Magic string
    const(char)[] magic = "i3-ipc";
    for (size_t i = 0; i < magic.length; ++i)
        buffer[pos++] = cast(ubyte)magic[i];
    
    // Length
    uint len = cast(uint)payload.length;
    *cast(uint*)(buffer.ptr + pos) = len;
    pos += 4;
    
    // Type
    *cast(uint*)(buffer.ptr + pos) = cast(uint)type;
    pos += 4;
    
    // Payload
    for (size_t i = 0; i < payload.length && pos < 4096; ++i)
        buffer[pos++] = payload[i];
    
    // Send through channel
    return channelSend(g_i3IPCChannel, buffer.ptr, pos, null, 0);
}

// Receive message from i3
@nogc nothrow long recvI3Message(I3Message* msg)
{
    if (g_i3IPCChannel.low == 0) return -1;
    
    ubyte[4096] buffer;
    Capability[1] caps;
    size_t capsReceived;
    
    long result = channelRecv(g_i3IPCChannel, buffer.ptr, 4096, caps.ptr, 1, &capsReceived);
    if (result < 0) return result;
    
    // Parse message
    // Magic: "i3-ipc" (6 bytes)
    // Length: 4 bytes
    // Type: 4 bytes
    // Payload: length bytes
    
    if (result < 14) return -1;  // Too short
    
    // Check magic
    const(char)[] magic = "i3-ipc";
    for (size_t i = 0; i < 6; ++i)
    {
        if (buffer[i] != cast(ubyte)magic[i])
            return -1;  // Invalid magic
    }
    
    // Parse length and type
    msg.length = *cast(uint*)(buffer.ptr + 6);
    msg.type = cast(I3MessageType)(*cast(uint*)(buffer.ptr + 10));
    
    // Copy payload
    size_t payloadLen = msg.length;
    if (payloadLen > 4096) payloadLen = 4096;
    
    for (size_t i = 0; i < payloadLen; ++i)
        msg.payload[i] = buffer[14 + i];
    
    return cast(long)payloadLen;
}

// ============================================================================
// i3 Configuration
// ============================================================================

// Default i3 configuration
const(char)[] getDefaultI3Config() @nogc nothrow
{
    return 
`# i3 config file (v4)

# Mod key (Mod1=Alt, Mod4=Super)
set $mod Mod4

# Font
font pango:monospace 8

# Start a terminal
bindsym $mod+Return exec /bin/sh

# Kill focused window
bindsym $mod+Shift+q kill

# Start dmenu
bindsym $mod+d exec dmenu_run

# Change focus
bindsym $mod+j focus left
bindsym $mod+k focus down
bindsym $mod+l focus up
bindsym $mod+semicolon focus right

# Move focused window
bindsym $mod+Shift+j move left
bindsym $mod+Shift+k move down
bindsym $mod+Shift+l move up
bindsym $mod+Shift+semicolon move right

# Split orientation
bindsym $mod+h split h
bindsym $mod+v split v

# Fullscreen
bindsym $mod+f fullscreen toggle

# Change container layout
bindsym $mod+s layout stacking
bindsym $mod+w layout tabbed
bindsym $mod+e layout toggle split

# Toggle floating
bindsym $mod+Shift+space floating toggle

# Workspaces
bindsym $mod+1 workspace 1
bindsym $mod+2 workspace 2
bindsym $mod+3 workspace 3
bindsym $mod+4 workspace 4

# Move to workspace
bindsym $mod+Shift+1 move container to workspace 1
bindsym $mod+Shift+2 move container to workspace 2
bindsym $mod+Shift+3 move container to workspace 3
bindsym $mod+Shift+4 move container to workspace 4

# Reload config
bindsym $mod+Shift+c reload

# Restart i3
bindsym $mod+Shift+r restart

# Exit i3
bindsym $mod+Shift+e exit

# Resize mode
mode "resize" {
    bindsym j resize shrink width 10 px or 10 ppt
    bindsym k resize grow height 10 px or 10 ppt
    bindsym l resize shrink height 10 px or 10 ppt
    bindsym semicolon resize grow width 10 px or 10 ppt
    
    bindsym Return mode "default"
    bindsym Escape mode "default"
}

bindsym $mod+r mode "resize"

# Status bar
bar {
    status_command i3status
}
`;
}

// Create i3 config file
@nogc nothrow bool createI3ConfigFile()
{
    // Get config partition
    auto configPart = getPartition("config");
    if (configPart is null) return false;
    
    // Create /etc/i3 directory
    auto etcCap = lookup(configPart.rootDir, "etc");
    ObjectID etcDir;
    
    if (etcCap.oid.low == 0)
    {
        // Create etc directory
        etcDir = createDirectory();
        insert(configPart.rootDir, "etc", Capability(etcDir, Rights.Read | Rights.Write | Rights.Enumerate));
    }
    else
    {
        etcDir = etcCap.oid;
    }
    
    // Create i3 subdirectory
    ObjectID i3Dir = createDirectory();
    insert(etcDir, "i3", Capability(i3Dir, Rights.Read | Rights.Write | Rights.Enumerate));
    
    // Create config file
    const(char)[] configContent;
    if (g_customI3Config.length > 0)
    {
        configContent = g_customI3Config;
    }
    else
    {
        configContent = getDefaultI3Config();
    }
    
    ObjectID configBlob = createBlob(cast(const(ubyte)[])configContent);
    
    insert(i3Dir, "config", Capability(configBlob, Rights.Read));
    
    return true;
}

// ============================================================================
// i3 Capability Exports
// ============================================================================

// Export i3 capabilities for other processes
@nogc nothrow bool exportI3Capabilities()
{
    if (g_i3Process.low == 0) return false;
    
    // Export IPC channel so other processes can communicate with i3
    auto procSlot = getObject(g_i3Process);
    if (procSlot is null || procSlot.type != ObjectType.Process)
        return false;
    
    // Create /proc/<pid>/i3 directory
    ObjectID i3ExportDir = createDirectory();
    
    // Export IPC channel
    insert(i3ExportDir, "ipc", Capability(g_i3IPCChannel, Rights.Read | Rights.Write));
    
    // Export to process exports
    processExport(g_i3Process, "i3", Capability(i3ExportDir, Rights.Read | Rights.Enumerate));
    
    return true;
}

// ============================================================================
// i3 Initialization
// ============================================================================

// Initialize i3 window manager
@nogc nothrow bool initializeI3()
{
    // 1. Create config file
    if (!createI3ConfigFile())
        return false;
    
    // 2. Start i3 process
    ObjectID i3Proc = startI3();
    if (i3Proc.low == 0)
        return false;
    
    // 3. Export capabilities
    if (!exportI3Capabilities())
        return false;
    
    return true;
}
