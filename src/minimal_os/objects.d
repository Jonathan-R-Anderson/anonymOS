module minimal_os.objects;

import minimal_os.kernel.heap : kmalloc, kfree;

// Define g_rootObject
__gshared ObjectID g_rootObject;

static if (!__traits(compiles, { size_t dummy; }))
{
    alias size_t = typeof(int.sizeof);
}

// 128-bit Object ID
struct ObjectID
{
    ulong low;
    ulong high;
    
    bool opEquals(const ObjectID other) const @nogc nothrow
    {
        return low == other.low && high == other.high;
    }
}

enum ObjectType : ubyte
{
    Free = 0,
    VMO,          // Virtual Memory Object (backing store)
    Blob,         // Data container (file) backed by VMO
    Directory,    // Name → Capability mapping
    Process,      // Execution context
    BlockDevice,  // Block storage device
    Channel,      // IPC channel/endpoint
    Socket,       // Network socket
    Window,       // GUI window
    Device        // Generic hardware device
}

enum Rights : uint
{
    None        = 0,
    Read        = 1 << 0,
    Write       = 1 << 1,
    Execute     = 1 << 2,
    Grant       = 1 << 3,
    Enumerate   = 1 << 4,
    Call        = 1 << 5
}

struct Capability
{
    ObjectID oid;
    uint rights;
}

// Simple Directory Entry
struct DirEntry
{
    char[64] name;
    Capability cap;
}

// VMO (Virtual Memory Object) - backing store for Blobs
struct VMOData
{
    const(ubyte)* dataPtr;
    size_t dataLen;
    bool immutable_;  // Immutable VMOs cannot be modified
}

// Blob Object - represents a file
struct BlobData
{
    VMOData* vmo;        // Pointer to backing VMO
    size_t size;         // Logical size
    ulong createdTime;   // Creation timestamp
    ulong modifiedTime;  // Last modification timestamp
}

// Directory Object - already defined via DirEntry
struct DirData
{
    DirEntry* entries;
    size_t count;
    size_t capacity;
}

// Block Device Object
struct BlockDeviceData
{
    ulong blockCount;
    uint blockSize;
    void* deviceContext;  // Driver-specific context
    // Function pointers for operations
    long function(void* ctx, ulong index, ulong count, ubyte* buffer) @nogc nothrow readBlock;
    long function(void* ctx, ulong index, const(ubyte)* data, ulong count) @nogc nothrow writeBlock;
    long function(void* ctx) @nogc nothrow flush;
}

// Process State
enum ProcessState : ubyte
{
    Running,
    Stopped,
    Zombie,
    Terminated
}

// Process Object
struct ProcessData
{
    ObjectID id;
    Capability rootCap;  // Global view (like /)
    Capability homeCap;  // Private namespace root
    Capability procCap;  // Process's own exported objects
    ObjectID cwd;        // Current working directory
    ProcessState state;
    int exitCode;
    ulong pid;
    // Exported capabilities (like /proc/$pid/)
    DirEntry* exports;
    size_t exportCount;
    size_t exportCapacity;
}

// IPC Channel/Socket Object
enum ChannelState : ubyte
{
    Open,
    Shutdown,
    Closed
}

struct Message
{
    ubyte* data;
    size_t dataLen;
    Capability* caps;  // Capabilities being transferred
    size_t capCount;
}

struct ChannelData
{
    ChannelState state;
    ObjectID peerChannel;  // Other end of the channel
    // Message queue (simplified - would be ring buffer in production)
    Message* messageQueue;
    size_t queueHead;
    size_t queueTail;
    size_t queueCapacity;
}

// Network Socket Object
enum SocketType : ubyte
{
    Stream,
    Datagram,
    Raw
}

enum SocketState : ubyte
{
    Unbound,
    Bound,
    Listening,
    Connected,
    Closed
}

struct SocketData
{
    SocketType type;
    SocketState state;
    uint localPort;
    uint remotePort;
    ubyte[16] localAddr;   // IPv6 address (IPv4 mapped)
    ubyte[16] remoteAddr;
    void* protocolContext; // TCP/UDP state
}

// For now, a fixed-size object slot
struct ObjectSlot
{
    ObjectID id;
    ObjectType type;
    
    // Union for different object types
    union
    {
        VMOData vmo;
        BlobData blob;
        DirData directory;
        ProcessData process;
        BlockDeviceData blockDevice;
        ChannelData channel;
        SocketData socket;
        
        // Generic data for Window, etc.
        struct GenericData {
            void* data;
            size_t size;
        }
        GenericData generic;
    }
}

@nogc nothrow ObjectID createProcess(Capability rootCap, Capability homeCap, Capability procCap)
{
    if (g_nextFreeSlot >= g_objectStore.length) return ObjectID(0,0);
    
    ObjectID newId = ObjectID(g_nextFreeSlot + 1, 0);
    
    ObjectSlot* slot = &g_objectStore[g_nextFreeSlot++];
    slot.id = newId;
    slot.type = ObjectType.Process;
    slot.process.id = newId;
    slot.process.rootCap = rootCap;
    slot.process.homeCap = homeCap;
    slot.process.procCap = procCap;
    slot.process.cwd = rootCap.oid; // Default CWD to root
    
    return newId;
}

// Global Object Store
__gshared ObjectSlot[1024] g_objectStore;
__gshared size_t g_nextFreeSlot = 0;

// Create VMO (Virtual Memory Object)
@nogc nothrow ObjectID createVMO(const(ubyte)[] data, bool immutable_)
{
    if (g_nextFreeSlot >= g_objectStore.length) return ObjectID(0,0);
    
    ObjectID newId = ObjectID(g_nextFreeSlot + 1, 0);
    
    ObjectSlot* slot = &g_objectStore[g_nextFreeSlot++];
    slot.id = newId;
    slot.type = ObjectType.VMO;
    slot.vmo.dataPtr = data.ptr;
    slot.vmo.dataLen = data.length;
    slot.vmo.immutable_ = immutable_;
    
    return newId;
}

// Create Blob (file) backed by VMO
@nogc nothrow ObjectID createBlob(const(ubyte)[] data)
{
    if (g_nextFreeSlot >= g_objectStore.length) return ObjectID(0,0);
    
    // Create backing VMO (immutable by default)
    ObjectID vmoId = createVMO(data, true);
    if (vmoId.low == 0) return ObjectID(0,0);

    // Ensure space for the blob entry after the VMO consumed a slot.
    if (g_nextFreeSlot >= g_objectStore.length) return ObjectID(0,0);

    ObjectID newId = ObjectID(g_nextFreeSlot + 1, 0);
    
    ObjectSlot* slot = &g_objectStore[g_nextFreeSlot++];
    slot.id = newId;
    slot.type = ObjectType.Blob;
    
    // Get VMO slot
    auto vmoSlot = getObject(vmoId);
    if (vmoSlot is null) return ObjectID(0,0);

    slot.blob.vmo = &vmoSlot.vmo;
    slot.blob.size = data.length;
    slot.blob.createdTime = 0; // TODO: Get actual time
    slot.blob.modifiedTime = 0;
    
    return newId;
}

@nogc nothrow void resetObjectStore()
{
    g_nextFreeSlot = 0;
    foreach (ref slot; g_objectStore)
    {
        slot = ObjectSlot.init;
    }
}

// Create Block Device
@nogc nothrow ObjectID createBlockDevice(
    ulong blockCount,
    uint blockSize,
    void* deviceContext,
    long function(void*, ulong, ulong, ubyte*) @nogc nothrow readBlock,
    long function(void*, ulong, const(ubyte)*, ulong) @nogc nothrow writeBlock,
    long function(void*) @nogc nothrow flush
)
{
    if (g_nextFreeSlot >= g_objectStore.length) return ObjectID(0,0);
    
    ObjectID newId = ObjectID(g_nextFreeSlot + 1, 0);
    
    ObjectSlot* slot = &g_objectStore[g_nextFreeSlot++];
    slot.id = newId;
    slot.type = ObjectType.BlockDevice;
    slot.blockDevice.blockCount = blockCount;
    slot.blockDevice.blockSize = blockSize;
    slot.blockDevice.deviceContext = deviceContext;
    slot.blockDevice.readBlock = readBlock;
    slot.blockDevice.writeBlock = writeBlock;
    slot.blockDevice.flush = flush;
    
    return newId;
}

// Create IPC Channel (returns pair of connected channels)
@nogc nothrow bool createChannelPair(ObjectID* channel1, ObjectID* channel2)
{
    if (g_nextFreeSlot + 2 > g_objectStore.length) return false;
    
    ObjectID id1 = ObjectID(g_nextFreeSlot + 1, 0);
    ObjectID id2 = ObjectID(g_nextFreeSlot + 2, 0);
    
    // Create first channel
    ObjectSlot* slot1 = &g_objectStore[g_nextFreeSlot++];
    slot1.id = id1;
    slot1.type = ObjectType.Channel;
    slot1.channel.state = ChannelState.Open;
    slot1.channel.peerChannel = id2;
    slot1.channel.messageQueue = cast(Message*)kmalloc(Message.sizeof * 16);
    slot1.channel.queueHead = 0;
    slot1.channel.queueTail = 0;
    slot1.channel.queueCapacity = 16;
    
    // Create second channel
    ObjectSlot* slot2 = &g_objectStore[g_nextFreeSlot++];
    slot2.id = id2;
    slot2.type = ObjectType.Channel;
    slot2.channel.state = ChannelState.Open;
    slot2.channel.peerChannel = id1;
    slot2.channel.messageQueue = cast(Message*)kmalloc(Message.sizeof * 16);
    slot2.channel.queueHead = 0;
    slot2.channel.queueTail = 0;
    slot2.channel.queueCapacity = 16;
    
    *channel1 = id1;
    *channel2 = id2;
    
    return true;
}

// Create Network Socket
@nogc nothrow ObjectID createSocket(SocketType type)
{
    if (g_nextFreeSlot >= g_objectStore.length) return ObjectID(0,0);
    
    ObjectID newId = ObjectID(g_nextFreeSlot + 1, 0);
    
    ObjectSlot* slot = &g_objectStore[g_nextFreeSlot++];
    slot.id = newId;
    slot.type = ObjectType.Socket;
    slot.socket.type = type;
    slot.socket.state = SocketState.Unbound;
    slot.socket.localPort = 0;
    slot.socket.remotePort = 0;
    slot.socket.protocolContext = null;
    
    // Zero out addresses
    for (size_t i = 0; i < 16; ++i)
    {
        slot.socket.localAddr[i] = 0;
        slot.socket.remoteAddr[i] = 0;
    }
    
    return newId;
}

@nogc nothrow ObjectSlot* getObject(ObjectID id)
{
    // Linear search or direct index if ID == index+1
    if (id.high == 0 && id.low > 0 && id.low <= g_nextFreeSlot)
    {
        ObjectSlot* slot = &g_objectStore[id.low - 1];
        if (slot.id == id) return slot;
    }
    return null;
}

@nogc nothrow void setRootObject(ObjectID id)
{
    g_rootObject = id;
}

@nogc nothrow ObjectID getRootObject()
{
    return g_rootObject;
}

@nogc nothrow ObjectID createDirectory()
{
    if (g_nextFreeSlot >= g_objectStore.length) return ObjectID(0,0);
    
    ObjectID newId = ObjectID(g_nextFreeSlot + 1, 0);
    
    ObjectSlot* slot = &g_objectStore[g_nextFreeSlot++];
    slot.id = newId;
    slot.type = ObjectType.Directory;
    slot.directory.count = 0;
    slot.directory.capacity = 16; // Initial capacity
    
    // Use heap allocator
    slot.directory.entries = cast(DirEntry*)kmalloc(DirEntry.sizeof * 16);
    
    return newId;
}

// Helper: Check if adding this entry would create a cycle
@nogc nothrow bool wouldCreateCycle(ObjectID parentDir, ObjectID childId)
{
    // BFS/DFS to check if childId is an ancestor of parentDir
    // For simplicity, we'll do a depth-limited search
    
    if (parentDir.low == childId.low && parentDir.high == childId.high)
        return true; // Self-reference
    
    // Check if childId is a directory
    auto childSlot = getObject(childId);
    if (childSlot is null || childSlot.type != ObjectType.Directory)
        return false; // Not a directory, can't create cycle
    
    // Recursively check if parentDir appears in childId's subtree
    bool searchForParent(ObjectID searchDir, int depth)
    {
        if (depth > 100) return false; // Depth limit to prevent infinite loops
        
        auto slot = getObject(searchDir);
        if (slot is null || slot.type != ObjectType.Directory) return false;
        
        for (size_t i = 0; i < slot.directory.count; ++i)
        {
            auto entry = &slot.directory.entries[i];
            
            // Found the parent in the subtree - would create cycle
            if (entry.cap.oid.low == parentDir.low && entry.cap.oid.high == parentDir.high)
                return true;
            
            // Recursively search subdirectories
            auto entrySlot = getObject(entry.cap.oid);
            if (entrySlot !is null && entrySlot.type == ObjectType.Directory)
            {
                if (searchForParent(entry.cap.oid, depth + 1))
                    return true;
            }
        }
        
        return false;
    }
    
    return searchForParent(childId, 0);
}

// Helper: Get the capability for a directory (used to check parent rights)
@nogc nothrow uint getDirectoryRights(ObjectID dirId)
{
    // In a full implementation, we'd track the capability that was used to reach this directory
    // For now, we'll return full rights for the root, and infer from parent for others
    // This is a simplified version - in production, each directory access would carry its capability
    
    if (dirId.low == g_rootObject.low && dirId.high == g_rootObject.high)
        return Rights.Read | Rights.Write | Rights.Execute | Rights.Grant | Rights.Enumerate | Rights.Call;
    
    // For non-root, we'd need to track the capability chain
    // For now, return a reasonable default
    return Rights.Read | Rights.Write | Rights.Enumerate;
}

@nogc nothrow bool addEntry(ObjectID dirId, const(char)[] name, Capability cap)
{
    ObjectSlot* slot = getObject(dirId);
    if (slot is null || slot.type != ObjectType.Directory) return false;
    
    // Security Check 1: Prevent cycles
    if (wouldCreateCycle(dirId, cap.oid))
    {
        // Cannot add - would create a cycle
        return false;
    }
    
    // Security Check 2: Rights attenuation - child cannot have more rights than parent
    uint parentRights = getDirectoryRights(dirId);
    if ((cap.rights & ~parentRights) != 0)
    {
        // Child has rights that parent doesn't have - attenuate them
        cap.rights = cap.rights & parentRights;
    }
    
    // Resize if needed
    if (slot.directory.count >= slot.directory.capacity)
    {
        size_t newCap = slot.directory.capacity * 2;
        DirEntry* newEntries = cast(DirEntry*)kmalloc(DirEntry.sizeof * newCap);
        
        if (newEntries is null) return false; // Out of memory
        
        // Copy old entries
        for (size_t i = 0; i < slot.directory.count; ++i)
        {
            newEntries[i] = slot.directory.entries[i];
        }
        
        slot.directory.entries = newEntries;
        slot.directory.capacity = newCap;
    }
    
    DirEntry* entry = &slot.directory.entries[slot.directory.count++];
    
    // Copy name
    size_t len = name.length;
    if (len > 63) len = 63;
    
    for (size_t i = 0; i < len; ++i) entry.name[i] = name[i];
    entry.name[len] = 0;
    
    entry.cap = cap;
    
    return true;
}

// Directory Methods

@nogc nothrow Capability lookup(ObjectID dirId, const(char)[] name)
{
    ObjectSlot* slot = getObject(dirId);
    if (slot is null || slot.type != ObjectType.Directory) 
        return Capability(ObjectID(0,0), Rights.None);
    
    for (size_t i = 0; i < slot.directory.count; ++i)
    {
        auto entry = &slot.directory.entries[i];
        
        // Compare name
        bool match = true;
        size_t clen = 0;
        while (entry.name[clen] != 0) clen++;
        
        if (clen != name.length) match = false;
        else
        {
            for (size_t m = 0; m < clen; ++m)
            {
                if (entry.name[m] != name[m]) { match = false; break; }
            }
        }
        
        if (match) return entry.cap;
    }
    
    return Capability(ObjectID(0,0), Rights.None);
}

@nogc nothrow bool insert(ObjectID dirId, const(char)[] name, Capability cap)
{
    // Check if already exists
    auto existing = lookup(dirId, name);
    if (existing.oid.low != 0 || existing.oid.high != 0) return false;
    
    // addEntry now returns bool and performs security checks
    return addEntry(dirId, name, cap);
}

@nogc nothrow bool remove(ObjectID dirId, const(char)[] name)
{
    ObjectSlot* slot = getObject(dirId);
    if (slot is null || slot.type != ObjectType.Directory) return false;
    
    for (size_t i = 0; i < slot.directory.count; ++i)
    {
        auto entry = &slot.directory.entries[i];
        
        // Compare name
        bool match = true;
        size_t clen = 0;
        while (entry.name[clen] != 0) clen++;
        
        if (clen != name.length) match = false;
        else
        {
            for (size_t m = 0; m < clen; ++m)
            {
                if (entry.name[m] != name[m]) { match = false; break; }
            }
        }
        
        if (match)
        {
            // Shift remaining entries
            for (size_t j = i; j < slot.directory.count - 1; ++j)
            {
                slot.directory.entries[j] = slot.directory.entries[j + 1];
            }
            slot.directory.count--;
            return true;
        }
    }
    
    return false;
}

struct DirListEntry
{
    char[64] name;
    ObjectType type;
    uint rights;
}

@nogc nothrow size_t list(ObjectID dirId, DirListEntry* buffer, size_t bufferSize)
{
    ObjectSlot* slot = getObject(dirId);
    if (slot is null || slot.type != ObjectType.Directory) return 0;
    
    size_t count = slot.directory.count;
    if (count > bufferSize) count = bufferSize;
    
    for (size_t i = 0; i < count; ++i)
    {
        auto entry = &slot.directory.entries[i];
        
        // Copy name
        size_t len = 0;
        while (entry.name[len] != 0 && len < 63) len++;
        for (size_t j = 0; j < len; ++j) buffer[i].name[j] = entry.name[j];
        buffer[i].name[len] = 0;
        
        // Get type
        auto childSlot = getObject(entry.cap.oid);
        buffer[i].type = childSlot ? childSlot.type : ObjectType.Free;
        buffer[i].rights = entry.cap.rights;
    }
    
    return count;
}

// Path Resolution
// Implements: /home/alice/docs/report as iterative lookup
@nogc nothrow Capability resolvePath(ObjectID startDir, const(char)[] path)
{
    if (path.length == 0) return Capability(ObjectID(0,0), Rights.None);
    
    ObjectID currentDir = startDir;
    size_t start = 0;
    
    // Skip leading slash
    if (path[0] == '/') start = 1;
    
    for (size_t i = start; i <= path.length; ++i)
    {
        if (i == path.length || path[i] == '/')
        {
            if (i > start)
            {
                const(char)[] component = path[start .. i];
                
                // Lookup component in current directory
                auto cap = lookup(currentDir, component);
                if (cap.oid.low == 0 && cap.oid.high == 0)
                {
                    // Not found
                    return Capability(ObjectID(0,0), Rights.None);
                }
                
                // If not at end, must be a directory
                if (i < path.length)
                {
                    auto slot = getObject(cap.oid);
                    if (slot is null || slot.type != ObjectType.Directory)
                    {
                        return Capability(ObjectID(0,0), Rights.None);
                    }
                    currentDir = cap.oid;
                }
                else
                {
                    // Final component - return the capability
                    return cap;
                }
            }
            
            start = i + 1;
        }
    }
    
    // Path was just "/" or ended with "/"
    return Capability(currentDir, Rights.Read | Rights.Enumerate);
}

// Global Search with Permission Checking
// Searches the entire object tree for objects matching a predicate
// Only returns objects that are reachable with appropriate rights

struct SearchResult
{
    ObjectID oid;
    char[256] path;  // Full path to the object
    uint rights;     // Effective rights at this object
}

@nogc nothrow size_t searchTree(
    ObjectID startDir,
    bool function(ObjectSlot*, uint) @nogc nothrow predicate,
    SearchResult* results,
    size_t maxResults,
    uint currentRights = Rights.Read | Rights.Write | Rights.Execute | Rights.Grant | Rights.Enumerate | Rights.Call
)
{
    size_t resultCount = 0;
    
    void searchRecursive(ObjectID dirId, const(char)[] currentPath, uint effectiveRights, int depth)
    {
        if (depth > 100) return; // Prevent infinite recursion
        if (resultCount >= maxResults) return; // Results buffer full
        
        auto slot = getObject(dirId);
        if (slot is null) return;
        
        // Check if current object matches predicate
        if (predicate(slot, effectiveRights))
        {
            // Add to results
            results[resultCount].oid = dirId;
            results[resultCount].rights = effectiveRights;
            
            // Copy path
            size_t pathLen = currentPath.length;
            if (pathLen > 255) pathLen = 255;
            for (size_t i = 0; i < pathLen; ++i)
                results[resultCount].path[i] = currentPath[i];
            results[resultCount].path[pathLen] = 0;
            
            resultCount++;
        }
        
        // If it's a directory and we have enumerate rights, search children
        if (slot.type == ObjectType.Directory && (effectiveRights & Rights.Enumerate))
        {
            for (size_t i = 0; i < slot.directory.count; ++i)
            {
                auto entry = &slot.directory.entries[i];
                
                // Calculate effective rights for child (attenuation)
                uint childRights = entry.cap.rights & effectiveRights;
                
                // Build child path
                char[256] childPath;
                size_t pos = 0;
                
                // Copy current path
                for (size_t j = 0; j < currentPath.length && pos < 255; ++j)
                    childPath[pos++] = currentPath[j];
                
                // Add separator if needed
                if (pos > 0 && childPath[pos-1] != '/' && pos < 255)
                    childPath[pos++] = '/';
                
                // Add entry name
                size_t nameLen = 0;
                while (entry.name[nameLen] != 0 && nameLen < 63) nameLen++;
                for (size_t j = 0; j < nameLen && pos < 255; ++j)
                    childPath[pos++] = entry.name[j];
                
                searchRecursive(entry.cap.oid, cast(const(char)[])childPath[0..pos], childRights, depth + 1);
            }
        }
    }
    
    // Start search from root
    searchRecursive(startDir, "/", currentRights, 0);
    
    return resultCount;
}

// Example predicates for searchTree

@nogc nothrow bool isBlob(ObjectSlot* slot, uint rights)
{
    return slot.type == ObjectType.Blob && (rights & Rights.Read);
}

@nogc nothrow bool isDirectory(ObjectSlot* slot, uint rights)
{
    return slot.type == ObjectType.Directory && (rights & Rights.Enumerate);
}

@nogc nothrow bool isExecutable(ObjectSlot* slot, uint rights)
{
    return slot.type == ObjectType.Blob && (rights & Rights.Execute);
}



