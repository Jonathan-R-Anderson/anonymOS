module anonymos.pseudo_objects;

// Pseudo-file objects that adapt system interfaces to file-like API
// Examples: /sys/cpu, /net/interfaces/eth0, /gui/screen0

import anonymos.objects;
import anonymos.object_methods;

// ============================================================================
// CPU Controller Object - /sys/cpu
// ============================================================================

struct CpuControllerData
{
    uint cpuCount;
    uint currentFrequency;  // MHz
    uint maxFrequency;
    uint minFrequency;
    ubyte temperature;      // Celsius
}

// Adapt to read interface - returns formatted text
@nogc nothrow long cpuControllerRead(CpuControllerData* cpu, ulong offset, ulong length, ubyte* buffer)
{
    // Format: "cpus: 4\nfreq: 2400 MHz\ntemp: 45 C\n"
    char[256] textBuffer;
    size_t pos = 0;
    
    // Helper to add string
    void addStr(const(char)[] str)
    {
        for (size_t i = 0; i < str.length && pos < 256; ++i)
            textBuffer[pos++] = str[i];
    }
    
    // Helper to add number
    void addNum(uint num)
    {
        if (num == 0)
        {
            textBuffer[pos++] = '0';
            return;
        }
        
        char[20] digits;
        size_t digitCount = 0;
        while (num > 0)
        {
            digits[digitCount++] = cast(char)('0' + (num % 10));
            num /= 10;
        }
        
        // Reverse
        for (size_t i = 0; i < digitCount; ++i)
            textBuffer[pos++] = digits[digitCount - 1 - i];
    }
    
    addStr("cpus: ");
    addNum(cpu.cpuCount);
    addStr("\nfreq: ");
    addNum(cpu.currentFrequency);
    addStr(" MHz\ntemp: ");
    addNum(cpu.temperature);
    addStr(" C\n");
    
    // Copy to output buffer
    if (offset >= pos) return 0; // EOF
    
    size_t available = pos - offset;
    if (available > length) available = length;
    
    for (size_t i = 0; i < available; ++i)
        buffer[i] = cast(ubyte)textBuffer[offset + i];
    
    return cast(long)available;
}

// Adapt to write interface - parses commands
@nogc nothrow long cpuControllerWrite(CpuControllerData* cpu, const(ubyte)* data, ulong length)
{
    // Parse commands like "freq 2400" or "governor performance"
    // For now, just accept frequency changes
    
    // Simple parser: "freq NNNN"
    if (length < 5) return -22; // EINVAL
    
    if (data[0] == 'f' && data[1] == 'r' && data[2] == 'e' && data[3] == 'q' && data[4] == ' ')
    {
        // Parse number
        uint freq = 0;
        for (size_t i = 5; i < length; ++i)
        {
            if (data[i] >= '0' && data[i] <= '9')
                freq = freq * 10 + (data[i] - '0');
            else
                break;
        }
        
        // Validate range
        if (freq < cpu.minFrequency || freq > cpu.maxFrequency)
            return -22; // EINVAL
        
        cpu.currentFrequency = freq;
        return cast(long)length;
    }
    
    return -22; // EINVAL
}

// ============================================================================
// Network Interface Object - /net/interfaces/eth0
// ============================================================================

struct NetInterfaceData
{
    char[16] name;          // "eth0"
    ubyte[6] macAddr;       // MAC address
    ubyte[16] ipAddr;       // IPv6 (IPv4-mapped)
    uint mtu;
    bool up;
    ulong rxBytes;
    ulong txBytes;
    ulong rxPackets;
    ulong txPackets;
}

@nogc nothrow long netInterfaceRead(NetInterfaceData* iface, ulong offset, ulong length, ubyte* buffer)
{
    // Format statistics and config
    char[512] textBuffer;
    size_t pos = 0;
    
    void addStr(const(char)[] str)
    {
        for (size_t i = 0; i < str.length && pos < 512; ++i)
            textBuffer[pos++] = str[i];
    }
    
    void addNum(ulong num)
    {
        if (num == 0)
        {
            textBuffer[pos++] = '0';
            return;
        }
        
        char[32] digits;
        size_t digitCount = 0;
        while (num > 0)
        {
            digits[digitCount++] = cast(char)('0' + (num % 10));
            num /= 10;
        }
        
        for (size_t i = 0; i < digitCount; ++i)
            textBuffer[pos++] = digits[digitCount - 1 - i];
    }
    
    void addHex(ubyte val)
    {
        const(char)[] hex = "0123456789abcdef";
        textBuffer[pos++] = hex[val >> 4];
        textBuffer[pos++] = hex[val & 0xF];
    }
    
    addStr("name: ");
    size_t nameLen = 0;
    while (iface.name[nameLen] != 0 && nameLen < 16) nameLen++;
    for (size_t i = 0; i < nameLen; ++i)
        textBuffer[pos++] = iface.name[i];
    
    addStr("\nmac: ");
    for (size_t i = 0; i < 6; ++i)
    {
        if (i > 0) textBuffer[pos++] = ':';
        addHex(iface.macAddr[i]);
    }
    
    addStr("\nmtu: ");
    addNum(iface.mtu);
    
    addStr("\nstate: ");
    addStr(iface.up ? "UP" : "DOWN");
    
    addStr("\nrx_bytes: ");
    addNum(iface.rxBytes);
    
    addStr("\ntx_bytes: ");
    addNum(iface.txBytes);
    
    addStr("\nrx_packets: ");
    addNum(iface.rxPackets);
    
    addStr("\ntx_packets: ");
    addNum(iface.txPackets);
    
    addStr("\n");
    
    // Copy to output
    if (offset >= pos) return 0;
    
    size_t available = pos - offset;
    if (available > length) available = length;
    
    for (size_t i = 0; i < available; ++i)
        buffer[i] = cast(ubyte)textBuffer[offset + i];
    
    return cast(long)available;
}

@nogc nothrow long netInterfaceWrite(NetInterfaceData* iface, const(ubyte)* data, ulong length)
{
    // Parse commands: "up", "down", "mtu 1500"
    
    if (length >= 2 && data[0] == 'u' && data[1] == 'p')
    {
        iface.up = true;
        return cast(long)length;
    }
    
    if (length >= 4 && data[0] == 'd' && data[1] == 'o' && data[2] == 'w' && data[3] == 'n')
    {
        iface.up = false;
        return cast(long)length;
    }
    
    if (length >= 4 && data[0] == 'm' && data[1] == 't' && data[2] == 'u' && data[3] == ' ')
    {
        uint mtu = 0;
        for (size_t i = 4; i < length; ++i)
        {
            if (data[i] >= '0' && data[i] <= '9')
                mtu = mtu * 10 + (data[i] - '0');
            else
                break;
        }
        
        if (mtu < 68 || mtu > 9000) return -22; // EINVAL
        
        iface.mtu = mtu;
        return cast(long)length;
    }
    
    return -22; // EINVAL
}

// ============================================================================
// Display Object - /gui/screen0
// ============================================================================

struct DisplayData
{
    uint width;
    uint height;
    uint bitsPerPixel;
    uint refreshRate;
    void* framebuffer;
    size_t framebufferSize;
}

@nogc nothrow long displayRead(DisplayData* display, ulong offset, ulong length, ubyte* buffer)
{
    // Reading from display returns framebuffer data
    if (display.framebuffer is null) return -5; // EIO
    
    if (offset >= display.framebufferSize) return 0; // EOF
    
    size_t available = display.framebufferSize - offset;
    if (available > length) available = length;
    
    ubyte* fb = cast(ubyte*)display.framebuffer;
    for (size_t i = 0; i < available; ++i)
        buffer[i] = fb[offset + i];
    
    return cast(long)available;
}

@nogc nothrow long displayWrite(DisplayData* display, ulong offset, const(ubyte)* data, ulong length)
{
    // Writing to display updates framebuffer
    if (display.framebuffer is null) return -5; // EIO
    
    if (offset >= display.framebufferSize) return -22; // EINVAL
    
    size_t available = display.framebufferSize - offset;
    if (available > length) available = length;
    
    ubyte* fb = cast(ubyte*)display.framebuffer;
    for (size_t i = 0; i < available; ++i)
        fb[offset + i] = data[i];
    
    return cast(long)available;
}

// ============================================================================
// Example: Creating pseudo-file objects
// ============================================================================

// Create /sys directory with CPU controller
@nogc nothrow ObjectID createSysDirectory()
{
    ObjectID sysDir = createDirectory();
    
    // Create CPU controller object
    CpuControllerData* cpuData = cast(CpuControllerData*)kmalloc(CpuControllerData.sizeof);
    if (cpuData !is null)
    {
        cpuData.cpuCount = 4;
        cpuData.currentFrequency = 2400;
        cpuData.maxFrequency = 3600;
        cpuData.minFrequency = 800;
        cpuData.temperature = 45;
        
        // Create generic object for CPU controller
        ObjectID cpuObj = ObjectID(g_nextFreeSlot + 1, 0);
        if (g_nextFreeSlot < g_objectStore.length)
        {
            ObjectSlot* slot = &g_objectStore[g_nextFreeSlot++];
            slot.id = cpuObj;
            slot.type = ObjectType.Device; // Use Device type
            slot.generic.data = cast(void*)cpuData;
            slot.generic.size = CpuControllerData.sizeof;
            
            // Add to /sys
            insert(sysDir, "cpu", Capability(cpuObj, Rights.Read | Rights.Write));
        }
    }
    
    return sysDir;
}

// Create /net/interfaces directory
@nogc nothrow ObjectID createNetDirectory()
{
    ObjectID netDir = createDirectory();
    ObjectID ifacesDir = createDirectory();
    
    insert(netDir, "interfaces", Capability(ifacesDir, Rights.Read | Rights.Enumerate));
    
    // Create eth0 interface
    NetInterfaceData* eth0Data = cast(NetInterfaceData*)kmalloc(NetInterfaceData.sizeof);
    if (eth0Data !is null)
    {
        eth0Data.name[0] = 'e';
        eth0Data.name[1] = 't';
        eth0Data.name[2] = 'h';
        eth0Data.name[3] = '0';
        eth0Data.name[4] = 0;
        
        eth0Data.macAddr[0] = 0x00;
        eth0Data.macAddr[1] = 0x11;
        eth0Data.macAddr[2] = 0x22;
        eth0Data.macAddr[3] = 0x33;
        eth0Data.macAddr[4] = 0x44;
        eth0Data.macAddr[5] = 0x55;
        
        eth0Data.mtu = 1500;
        eth0Data.up = true;
        eth0Data.rxBytes = 0;
        eth0Data.txBytes = 0;
        
        ObjectID eth0Obj = ObjectID(g_nextFreeSlot + 1, 0);
        if (g_nextFreeSlot < g_objectStore.length)
        {
            ObjectSlot* slot = &g_objectStore[g_nextFreeSlot++];
            slot.id = eth0Obj;
            slot.type = ObjectType.Device;
            slot.generic.data = cast(void*)eth0Data;
            slot.generic.size = NetInterfaceData.sizeof;
            
            insert(ifacesDir, "eth0", Capability(eth0Obj, Rights.Read | Rights.Write));
        }
    }
    
    return netDir;
}
