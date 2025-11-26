module anonymos.snapshots;

// Snapshot and versioning system using immutable VMOs

import anonymos.objects;
import anonymos.object_methods;

// ============================================================================
// Snapshot Metadata
// ============================================================================

struct Snapshot
{
    ObjectID id;
    ObjectID rootDir;      // Root directory at snapshot time
    ulong timestamp;       // When snapshot was taken
    char[64] name;         // User-friendly name
    ObjectID parent;       // Parent snapshot (for incremental)
}

// Global snapshot registry
__gshared Snapshot[256] g_snapshots;
__gshared size_t g_snapshotCount = 0;

// ============================================================================
// Create Snapshot - Captures current filesystem state
// ============================================================================

@nogc nothrow ObjectID createSnapshot(ObjectID rootDir, const(char)[] name)
{
    if (g_snapshotCount >= g_snapshots.length) return ObjectID(0, 0);
    
    // Snapshot is just a capability to the root directory!
    // Since VMOs are immutable, the entire tree is frozen at this point
    
    Snapshot* snap = &g_snapshots[g_snapshotCount];
    snap.id = ObjectID(g_snapshotCount + 1000, 0); // Offset to avoid collision
    snap.rootDir = rootDir;
    snap.timestamp = 0; // TODO: Get actual time
    snap.parent = ObjectID(0, 0);
    
    // Copy name
    size_t len = name.length;
    if (len > 63) len = 63;
    for (size_t i = 0; i < len; ++i)
        snap.name[i] = name[i];
    snap.name[len] = 0;
    
    g_snapshotCount++;
    
    return snap.id;
}

// Get snapshot by ID
@nogc nothrow Snapshot* getSnapshot(ObjectID snapId)
{
    for (size_t i = 0; i < g_snapshotCount; ++i)
    {
        if (g_snapshots[i].id.low == snapId.low && 
            g_snapshots[i].id.high == snapId.high)
        {
            return &g_snapshots[i];
        }
    }
    return null;
}

// Restore from snapshot - returns new root directory
@nogc nothrow ObjectID restoreSnapshot(ObjectID snapId)
{
    auto snap = getSnapshot(snapId);
    if (snap is null) return ObjectID(0, 0);
    
    // Simply return the snapshot's root directory
    // This gives you the entire filesystem as it was at snapshot time!
    return snap.rootDir;
}

// ============================================================================
// Directory Clone - Copy-on-Write
// ============================================================================

@nogc nothrow ObjectID cloneDirectory(ObjectID dirId)
{
    auto srcSlot = getObject(dirId);
    if (srcSlot is null || srcSlot.type != ObjectType.Directory)
        return ObjectID(0, 0);
    
    // Create new directory
    ObjectID newDirId = createDirectory();
    if (newDirId.low == 0) return ObjectID(0, 0);
    
    auto newSlot = getObject(newDirId);
    if (newSlot is null) return ObjectID(0, 0);
    
    // Copy all entries (shallow copy - capabilities point to same objects)
    for (size_t i = 0; i < srcSlot.directory.count; ++i)
    {
        auto entry = &srcSlot.directory.entries[i];
        
        // Extract name
        size_t nameLen = 0;
        while (entry.name[nameLen] != 0 && nameLen < 64) nameLen++;
        
        // Add entry to new directory
        addEntry(newDirId, cast(const(char)[])entry.name[0..nameLen], entry.cap);
    }
    
    return newDirId;
}

// Deep clone - recursively clones directories
@nogc nothrow ObjectID cloneDirectoryDeep(ObjectID dirId)
{
    auto srcSlot = getObject(dirId);
    if (srcSlot is null || srcSlot.type != ObjectType.Directory)
        return ObjectID(0, 0);
    
    // Create new directory
    ObjectID newDirId = createDirectory();
    if (newDirId.low == 0) return ObjectID(0, 0);
    
    // Clone all entries
    for (size_t i = 0; i < srcSlot.directory.count; ++i)
    {
        auto entry = &srcSlot.directory.entries[i];
        
        // Extract name
        size_t nameLen = 0;
        while (entry.name[nameLen] != 0 && nameLen < 64) nameLen++;
        const(char)[] name = cast(const(char)[])entry.name[0..nameLen];
        
        auto childSlot = getObject(entry.cap.oid);
        if (childSlot is null)
        {
            // Just copy the capability
            addEntry(newDirId, name, entry.cap);
            continue;
        }
        
        // Recursively clone directories
        if (childSlot.type == ObjectType.Directory)
        {
            ObjectID clonedChild = cloneDirectoryDeep(entry.cap.oid);
            if (clonedChild.low != 0)
            {
                Capability newCap = Capability(clonedChild, entry.cap.rights);
                addEntry(newDirId, name, newCap);
            }
        }
        else
        {
            // For non-directories, just copy the capability
            // Blobs are immutable VMOs, so this is safe
            addEntry(newDirId, name, entry.cap);
        }
    }
    
    return newDirId;
}

// ============================================================================
// Blob Versioning - Track versions of a file
// ============================================================================

struct BlobVersion
{
    ObjectID blobId;
    ulong timestamp;
    ObjectID previousVersion;
}

// Version chain for a blob
struct BlobVersionChain
{
    ObjectID currentVersion;
    BlobVersion[32] versions;
    size_t versionCount;
}

__gshared BlobVersionChain[256] g_blobVersions;
__gshared size_t g_blobVersionCount = 0;

// Create new version of a blob
@nogc nothrow ObjectID createBlobVersion(ObjectID oldBlobId, const(ubyte)[] newData)
{
    // Create new blob with new data
    ObjectID newBlobId = createBlob(newData);
    if (newBlobId.low == 0) return ObjectID(0, 0);
    
    // Find or create version chain
    BlobVersionChain* chain = null;
    for (size_t i = 0; i < g_blobVersionCount; ++i)
    {
        if (g_blobVersions[i].currentVersion.low == oldBlobId.low &&
            g_blobVersions[i].currentVersion.high == oldBlobId.high)
        {
            chain = &g_blobVersions[i];
            break;
        }
    }
    
    if (chain is null)
    {
        // Create new version chain
        if (g_blobVersionCount >= g_blobVersions.length)
            return newBlobId; // No versioning, but blob created
        
        chain = &g_blobVersions[g_blobVersionCount++];
        chain.currentVersion = oldBlobId;
        chain.versionCount = 0;
    }
    
    // Add version to chain
    if (chain.versionCount < chain.versions.length)
    {
        chain.versions[chain.versionCount].blobId = oldBlobId;
        chain.versions[chain.versionCount].timestamp = 0; // TODO: actual time
        chain.versions[chain.versionCount].previousVersion = 
            chain.versionCount > 0 ? chain.versions[chain.versionCount - 1].blobId : ObjectID(0, 0);
        chain.versionCount++;
    }
    
    // Update current version
    chain.currentVersion = newBlobId;
    
    return newBlobId;
}

// Get previous version of a blob
@nogc nothrow ObjectID getBlobPreviousVersion(ObjectID blobId)
{
    for (size_t i = 0; i < g_blobVersionCount; ++i)
    {
        auto chain = &g_blobVersions[i];
        
        // Check if this is the current version
        if (chain.currentVersion.low == blobId.low &&
            chain.currentVersion.high == blobId.high)
        {
            if (chain.versionCount > 0)
                return chain.versions[chain.versionCount - 1].blobId;
        }
        
        // Check version history
        for (size_t j = 0; j < chain.versionCount; ++j)
        {
            if (chain.versions[j].blobId.low == blobId.low &&
                chain.versions[j].blobId.high == blobId.high)
            {
                return chain.versions[j].previousVersion;
            }
        }
    }
    
    return ObjectID(0, 0);
}

// ============================================================================
// User Home Snapshots
// ============================================================================

struct UserSnapshot
{
    char[32] username;
    ObjectID homeDir;
    Snapshot[16] snapshots;
    size_t snapshotCount;
}

__gshared UserSnapshot[64] g_userSnapshots;
__gshared size_t g_userSnapshotCount = 0;

// Create snapshot of user's home directory
@nogc nothrow ObjectID createUserSnapshot(const(char)[] username, ObjectID homeDir, const(char)[] snapName)
{
    // Find or create user snapshot entry
    UserSnapshot* userSnap = null;
    for (size_t i = 0; i < g_userSnapshotCount; ++i)
    {
        size_t ulen = 0;
        while (g_userSnapshots[i].username[ulen] != 0) ulen++;
        
        if (ulen == username.length)
        {
            bool match = true;
            for (size_t j = 0; j < ulen; ++j)
            {
                if (g_userSnapshots[i].username[j] != username[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                userSnap = &g_userSnapshots[i];
                break;
            }
        }
    }
    
    if (userSnap is null)
    {
        if (g_userSnapshotCount >= g_userSnapshots.length)
            return ObjectID(0, 0);
        
        userSnap = &g_userSnapshots[g_userSnapshotCount++];
        
        // Copy username
        size_t len = username.length;
        if (len > 31) len = 31;
        for (size_t i = 0; i < len; ++i)
            userSnap.username[i] = username[i];
        userSnap.username[len] = 0;
        
        userSnap.homeDir = homeDir;
        userSnap.snapshotCount = 0;
    }
    
    // Create snapshot
    if (userSnap.snapshotCount >= userSnap.snapshots.length)
        return ObjectID(0, 0);
    
    Snapshot* snap = &userSnap.snapshots[userSnap.snapshotCount];
    snap.id = ObjectID(2000 + g_userSnapshotCount * 100 + userSnap.snapshotCount, 0);
    snap.rootDir = homeDir;
    snap.timestamp = 0;
    snap.parent = ObjectID(0, 0);
    
    // Copy snapshot name
    size_t len = snapName.length;
    if (len > 63) len = 63;
    for (size_t i = 0; i < len; ++i)
        snap.name[i] = snapName[i];
    snap.name[len] = 0;
    
    userSnap.snapshotCount++;
    
    return snap.id;
}

// List user snapshots
@nogc nothrow size_t listUserSnapshots(const(char)[] username, Snapshot** snapshots, size_t maxSnapshots)
{
    for (size_t i = 0; i < g_userSnapshotCount; ++i)
    {
        size_t ulen = 0;
        while (g_userSnapshots[i].username[ulen] != 0) ulen++;
        
        if (ulen == username.length)
        {
            bool match = true;
            for (size_t j = 0; j < ulen; ++j)
            {
                if (g_userSnapshots[i].username[j] != username[j])
                {
                    match = false;
                    break;
                }
            }
            
            if (match)
            {
                size_t count = g_userSnapshots[i].snapshotCount;
                if (count > maxSnapshots) count = maxSnapshots;
                
                for (size_t j = 0; j < count; ++j)
                    snapshots[j] = &g_userSnapshots[i].snapshots[j];
                
                return count;
            }
        }
    }
    
    return 0;
}

// ============================================================================
// Container-like Environments
// ============================================================================

struct Container
{
    char[64] name;
    ObjectID rootDir;      // Container's root filesystem
    ObjectID baseSnapshot; // Base snapshot (for layering)
    bool isolated;         // Fully isolated or shared base
}

__gshared Container[32] g_containers;
__gshared size_t g_containerCount = 0;

// Create container from snapshot
@nogc nothrow ObjectID createContainer(const(char)[] name, ObjectID baseSnapshot, bool isolated)
{
    if (g_containerCount >= g_containers.length) return ObjectID(0, 0);
    
    auto snap = getSnapshot(baseSnapshot);
    if (snap is null) return ObjectID(0, 0);
    
    Container* container = &g_containers[g_containerCount++];
    
    // Copy name
    size_t len = name.length;
    if (len > 63) len = 63;
    for (size_t i = 0; i < len; ++i)
        container.name[i] = name[i];
    container.name[len] = 0;
    
    container.baseSnapshot = baseSnapshot;
    container.isolated = isolated;
    
    if (isolated)
    {
        // Deep clone for full isolation
        container.rootDir = cloneDirectoryDeep(snap.rootDir);
    }
    else
    {
        // Shallow clone for shared base (COW)
        container.rootDir = cloneDirectory(snap.rootDir);
    }
    
    return container.rootDir;
}

// ============================================================================
// Persistence Layer (Simplified)
// ============================================================================

// Serialize directory to VMO
@nogc nothrow ObjectID serializeDirectory(ObjectID dirId)
{
    auto slot = getObject(dirId);
    if (slot is null || slot.type != ObjectType.Directory)
        return ObjectID(0, 0);
    
    // Calculate size needed
    // Format: [count: 8 bytes][entries: count * (64 name + 16 oid + 4 rights)]
    size_t entrySize = 64 + 16 + 4; // name + ObjectID + rights
    size_t totalSize = 8 + (slot.directory.count * entrySize);
    
    // Allocate buffer
    ubyte* buffer = cast(ubyte*)kmalloc(totalSize);
    if (buffer is null) return ObjectID(0, 0);
    
    // Write count
    *cast(ulong*)buffer = slot.directory.count;
    size_t pos = 8;
    
    // Write entries
    for (size_t i = 0; i < slot.directory.count; ++i)
    {
        auto entry = &slot.directory.entries[i];
        
        // Write name (64 bytes)
        for (size_t j = 0; j < 64; ++j)
            buffer[pos++] = cast(ubyte)entry.name[j];
        
        // Write ObjectID (16 bytes)
        *cast(ulong*)(buffer + pos) = entry.cap.oid.low;
        pos += 8;
        *cast(ulong*)(buffer + pos) = entry.cap.oid.high;
        pos += 8;
        
        // Write rights (4 bytes)
        *cast(uint*)(buffer + pos) = entry.cap.rights;
        pos += 4;
    }
    
    // Create immutable VMO
    ObjectID vmoId = createVMO(cast(const(ubyte)[])buffer[0..totalSize], true);
    
    return vmoId;
}

// Deserialize directory from VMO
@nogc nothrow ObjectID deserializeDirectory(ObjectID vmoId)
{
    auto vmoSlot = getObject(vmoId);
    if (vmoSlot is null || vmoSlot.type != ObjectType.VMO)
        return ObjectID(0, 0);
    
    const(ubyte)* buffer = vmoSlot.vmo.dataPtr;
    size_t bufferSize = vmoSlot.vmo.dataLen;
    
    if (bufferSize < 8) return ObjectID(0, 0);
    
    // Read count
    ulong count = *cast(ulong*)buffer;
    size_t pos = 8;
    
    // Create directory
    ObjectID dirId = createDirectory();
    if (dirId.low == 0) return ObjectID(0, 0);
    
    // Read entries
    for (size_t i = 0; i < count; ++i)
    {
        if (pos + 84 > bufferSize) break; // 64 + 16 + 4
        
        // Read name
        char[64] name;
        for (size_t j = 0; j < 64; ++j)
            name[j] = cast(char)buffer[pos++];
        
        // Read ObjectID
        ObjectID oid;
        oid.low = *cast(ulong*)(buffer + pos);
        pos += 8;
        oid.high = *cast(ulong*)(buffer + pos);
        pos += 8;
        
        // Read rights
        uint rights = *cast(uint*)(buffer + pos);
        pos += 4;
        
        // Find name length
        size_t nameLen = 0;
        while (nameLen < 64 && name[nameLen] != 0) nameLen++;
        
        // Add entry
        Capability cap = Capability(oid, rights);
        addEntry(dirId, cast(const(char)[])name[0..nameLen], cap);
    }
    
    return dirId;
}
