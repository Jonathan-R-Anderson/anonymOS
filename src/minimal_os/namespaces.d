module minimal_os.namespaces;

// Per-process namespace management and bind mounts

import minimal_os.objects;
import minimal_os.snapshots;

// ============================================================================
// Namespace Structure
// ============================================================================

struct Namespace
{
    ObjectID id;
    ObjectID rootDir;      // Root directory for this namespace
    char[64] name;         // Human-readable name
    ObjectID parent;       // Parent namespace (for hierarchical namespaces)
    bool isolated;         // Fully isolated or inherits from parent
}

__gshared Namespace[128] g_namespaces;
__gshared size_t g_namespaceCount = 0;

// ============================================================================
// Create Namespace
// ============================================================================

@nogc nothrow ObjectID createNamespace(const(char)[] name, ObjectID baseDir, bool isolated)
{
    if (g_namespaceCount >= g_namespaces.length) return ObjectID(0, 0);
    
    Namespace* ns = &g_namespaces[g_namespaceCount];
    ns.id = ObjectID(3000 + g_namespaceCount, 0);
    
    // Copy name
    size_t len = name.length;
    if (len > 63) len = 63;
    for (size_t i = 0; i < len; ++i)
        ns.name[i] = name[i];
    ns.name[len] = 0;
    
    ns.parent = ObjectID(0, 0);
    ns.isolated = isolated;
    
    if (isolated)
    {
        // Deep clone for full isolation
        ns.rootDir = cloneDirectoryDeep(baseDir);
    }
    else
    {
        // Shallow clone - shares most objects
        ns.rootDir = cloneDirectory(baseDir);
    }
    
    g_namespaceCount++;
    
    return ns.id;
}

// Get namespace by ID
@nogc nothrow Namespace* getNamespace(ObjectID nsId)
{
    for (size_t i = 0; i < g_namespaceCount; ++i)
    {
        if (g_namespaces[i].id.low == nsId.low &&
            g_namespaces[i].id.high == nsId.high)
        {
            return &g_namespaces[i];
        }
    }
    return null;
}

// ============================================================================
// Bind Mount - Attach directory at path
// ============================================================================

@nogc nothrow bool bindMount(ObjectID nsId, const(char)[] mountPath, ObjectID targetDir, uint rights)
{
    auto ns = getNamespace(nsId);
    if (ns is null) return false;
    
    // Parse mount path to find parent directory and mount point name
    // E.g., "/dev/disk" -> parent="/dev", name="disk"
    
    size_t lastSlash = 0;
    for (size_t i = 0; i < mountPath.length; ++i)
    {
        if (mountPath[i] == '/')
            lastSlash = i;
    }
    
    const(char)[] parentPath;
    const(char)[] mountName;
    
    if (lastSlash == 0 && mountPath.length > 0 && mountPath[0] == '/')
    {
        // Root-level mount like "/dev"
        parentPath = "/";
        mountName = mountPath[1 .. $];
    }
    else if (lastSlash > 0)
    {
        parentPath = mountPath[0 .. lastSlash];
        mountName = mountPath[lastSlash + 1 .. $];
    }
    else
    {
        // No slash, mount at root
        parentPath = "/";
        mountName = mountPath;
    }
    
    // Resolve parent directory
    auto parentCap = resolvePath(ns.rootDir, parentPath);
    if (parentCap.oid.low == 0 && parentCap.oid.high == 0)
    {
        // Parent doesn't exist - create it
        // For simplicity, just fail for now
        return false;
    }
    
    // Check if parent is a directory
    auto parentSlot = getObject(parentCap.oid);
    if (parentSlot is null || parentSlot.type != ObjectType.Directory)
        return false;
    
    // Insert target directory at mount point
    Capability targetCap = Capability(targetDir, rights);
    return insert(parentCap.oid, mountName, targetCap);
}

// Unmount - Remove bind mount
@nogc nothrow bool unmount(ObjectID nsId, const(char)[] mountPath)
{
    auto ns = getNamespace(nsId);
    if (ns is null) return false;
    
    // Parse path
    size_t lastSlash = 0;
    for (size_t i = 0; i < mountPath.length; ++i)
    {
        if (mountPath[i] == '/')
            lastSlash = i;
    }
    
    const(char)[] parentPath;
    const(char)[] mountName;
    
    if (lastSlash == 0 && mountPath.length > 0 && mountPath[0] == '/')
    {
        parentPath = "/";
        mountName = mountPath[1 .. $];
    }
    else if (lastSlash > 0)
    {
        parentPath = mountPath[0 .. lastSlash];
        mountName = mountPath[lastSlash + 1 .. $];
    }
    else
    {
        parentPath = "/";
        mountName = mountPath;
    }
    
    // Resolve parent
    auto parentCap = resolvePath(ns.rootDir, parentPath);
    if (parentCap.oid.low == 0 && parentCap.oid.high == 0)
        return false;
    
    // Remove entry
    return remove(parentCap.oid, mountName);
}

// ============================================================================
// Per-Process Namespace Views
// ============================================================================

// Update ProcessData to include namespace
// (This would be in objects.d, shown here for clarity)
/*
struct ProcessData {
    ObjectID id;
    ObjectID namespaceId;  // Process's namespace
    Capability rootCap;    // Root within namespace
    Capability homeCap;
    Capability procCap;
    ObjectID cwd;
    ProcessState state;
    int exitCode;
    ulong pid;
    DirEntry* exports;
    size_t exportCount;
    size_t exportCapacity;
}
*/

// Create process with custom namespace
@nogc nothrow ObjectID createProcessWithNamespace(
    ObjectID namespaceId,
    Capability rootCap,
    Capability homeCap,
    Capability procCap
)
{
    auto ns = getNamespace(namespaceId);
    if (ns is null) return ObjectID(0, 0);
    
    // Create process with namespace's root as its root
    return createProcess(rootCap, homeCap, procCap);
}

// ============================================================================
// Predefined Namespace Templates
// ============================================================================

// Create minimal namespace (only essential devices)
@nogc nothrow ObjectID createMinimalNamespace(ObjectID baseRoot)
{
    ObjectID nsId = createNamespace("minimal", baseRoot, false);
    auto ns = getNamespace(nsId);
    if (ns is null) return ObjectID(0, 0);
    
    // Create minimal /dev with only essential devices
    ObjectID devDir = createDirectory();
    
    // Add null device (TODO: create actual device objects)
    // For now, just create the directory structure
    
    // Bind /dev
    bindMount(nsId, "/dev", devDir, Rights.Read | Rights.Enumerate);
    
    return nsId;
}

// Create standard namespace (full system access)
@nogc nothrow ObjectID createStandardNamespace(ObjectID baseRoot)
{
    ObjectID nsId = createNamespace("standard", baseRoot, false);
    auto ns = getNamespace(nsId);
    if (ns is null) return ObjectID(0, 0);
    
    // Standard namespace has access to everything
    // No additional restrictions
    
    return nsId;
}

// Create container namespace (isolated)
@nogc nothrow ObjectID createContainerNamespace(ObjectID baseRoot, const(char)[] containerName)
{
    // Fully isolated namespace
    ObjectID nsId = createNamespace(containerName, baseRoot, true);
    auto ns = getNamespace(nsId);
    if (ns is null) return ObjectID(0, 0);
    
    // Create private /dev
    ObjectID devDir = createDirectory();
    bindMount(nsId, "/dev", devDir, Rights.Read | Rights.Write | Rights.Enumerate);
    
    // Create private /tmp
    ObjectID tmpDir = createDirectory();
    bindMount(nsId, "/tmp", tmpDir, Rights.Read | Rights.Write | Rights.Enumerate);
    
    return nsId;
}

// ============================================================================
// Namespace Hierarchy
// ============================================================================

struct NamespaceMount
{
    char[128] path;
    ObjectID targetDir;
    uint rights;
}

// Create child namespace that inherits from parent
@nogc nothrow ObjectID createChildNamespace(
    ObjectID parentNsId,
    const(char)[] name,
    NamespaceMount* additionalMounts,
    size_t mountCount
)
{
    auto parentNs = getNamespace(parentNsId);
    if (parentNs is null) return ObjectID(0, 0);
    
    // Clone parent's root
    ObjectID nsId = createNamespace(name, parentNs.rootDir, false);
    auto ns = getNamespace(nsId);
    if (ns is null) return ObjectID(0, 0);
    
    ns.parent = parentNsId;
    
    // Apply additional mounts
    for (size_t i = 0; i < mountCount; ++i)
    {
        auto mount = &additionalMounts[i];
        
        // Get path length
        size_t pathLen = 0;
        while (pathLen < 128 && mount.path[pathLen] != 0) pathLen++;
        
        bindMount(nsId, cast(const(char)[])mount.path[0..pathLen], mount.targetDir, mount.rights);
    }
    
    return nsId;
}

// ============================================================================
// Example Namespace Configurations
// ============================================================================

// Create namespace for untrusted process
@nogc nothrow ObjectID createUntrustedNamespace(ObjectID baseRoot)
{
    ObjectID nsId = createNamespace("untrusted", baseRoot, true);
    auto ns = getNamespace(nsId);
    if (ns is null) return ObjectID(0, 0);
    
    // Very restricted /dev - only null, zero, random
    ObjectID devDir = createDirectory();
    
    // TODO: Add only safe devices
    // insert(devDir, "null", nullDeviceCap);
    // insert(devDir, "zero", zeroDeviceCap);
    // insert(devDir, "random", randomDeviceCap);
    
    bindMount(nsId, "/dev", devDir, Rights.Read | Rights.Enumerate);
    
    // No access to /sys, /proc, etc.
    // Remove them if they exist
    unmount(nsId, "/sys");
    unmount(nsId, "/proc");
    
    return nsId;
}

// Create namespace for privileged process
@nogc nothrow ObjectID createPrivilegedNamespace(ObjectID baseRoot)
{
    ObjectID nsId = createNamespace("privileged", baseRoot, false);
    auto ns = getNamespace(nsId);
    if (ns is null) return ObjectID(0, 0);
    
    // Full /dev access
    ObjectID devDir = createDirectory();
    
    // TODO: Add all devices
    // insert(devDir, "sda", sdaDeviceCap);
    // insert(devDir, "sdb", sdbDeviceCap);
    // insert(devDir, "tty", ttyDeviceCap);
    // etc.
    
    bindMount(nsId, "/dev", devDir, Rights.Read | Rights.Write | Rights.Enumerate);
    
    return nsId;
}

// ============================================================================
// Namespace Switching
// ============================================================================

// Switch process to different namespace
@nogc nothrow bool switchNamespace(ObjectID processId, ObjectID newNsId)
{
    auto procSlot = getObject(processId);
    if (procSlot is null || procSlot.type != ObjectType.Process)
        return false;
    
    auto ns = getNamespace(newNsId);
    if (ns is null) return false;
    
    // Update process's root capability to namespace's root
    procSlot.process.rootCap = Capability(
        ns.rootDir,
        Rights.Read | Rights.Write | Rights.Execute | Rights.Enumerate
    );
    
    // Reset CWD to new root
    procSlot.process.cwd = ns.rootDir;
    
    return true;
}

// ============================================================================
// Namespace Introspection
// ============================================================================

// List all mounts in a namespace
@nogc nothrow size_t listMounts(ObjectID nsId, NamespaceMount* buffer, size_t bufferSize)
{
    auto ns = getNamespace(nsId);
    if (ns is null) return 0;
    
    // Walk directory tree and identify mount points
    // For simplicity, just return root for now
    // A full implementation would track mount points explicitly
    
    if (bufferSize > 0)
    {
        buffer[0].path[0] = '/';
        buffer[0].path[1] = 0;
        buffer[0].targetDir = ns.rootDir;
        buffer[0].rights = Rights.Read | Rights.Write | Rights.Enumerate;
        return 1;
    }
    
    return 0;
}

// Get namespace info
@nogc nothrow bool getNamespaceInfo(ObjectID nsId, Namespace* info)
{
    auto ns = getNamespace(nsId);
    if (ns is null) return false;
    
    *info = *ns;
    return true;
}

// ============================================================================
// Overlay Filesystem (Union Mount)
// ============================================================================

struct OverlayLayer
{
    ObjectID dirId;
    bool readOnly;
}

// Create overlay namespace (like Docker layers)
@nogc nothrow ObjectID createOverlayNamespace(
    const(char)[] name,
    OverlayLayer* layers,
    size_t layerCount
)
{
    if (layerCount == 0) return ObjectID(0, 0);
    
    // Start with top layer
    ObjectID topLayer = layers[layerCount - 1].dirId;
    
    ObjectID nsId = createNamespace(name, topLayer, false);
    auto ns = getNamespace(nsId);
    if (ns is null) return ObjectID(0, 0);
    
    // For a full overlay implementation, we'd need to:
    // 1. Create a merged view of all layers
    // 2. On lookup, search layers from top to bottom
    // 3. On write, write to top layer only
    
    // Simplified: just use top layer
    // A full implementation would require a custom Directory type
    
    return nsId;
}

// ============================================================================
// Namespace Capabilities
// ============================================================================

// Grant capability to enter namespace
@nogc nothrow Capability createNamespaceEnterCapability(ObjectID nsId)
{
    // Return a capability that allows entering this namespace
    // The capability itself is just a reference to the namespace
    return Capability(nsId, Rights.Call);
}

// Check if process can enter namespace
@nogc nothrow bool canEnterNamespace(ObjectID processId, Capability nsCap)
{
    // Check if process has the capability
    // In a full implementation, we'd check the process's capability list
    
    if ((nsCap.rights & Rights.Call) == 0)
        return false;
    
    auto ns = getNamespace(nsCap.oid);
    return ns !is null;
}
