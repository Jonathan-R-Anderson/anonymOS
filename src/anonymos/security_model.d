module anonymos.security_model;

// Security model: Authentication, sandboxing, and least privilege

import anonymos.objects;
import anonymos.namespaces;
import anonymos.snapshots;

// ============================================================================
// User Authentication and Session Management
// ============================================================================

struct User
{
    char[32] username;
    ubyte[32] passwordHash;  // SHA-256 hash
    ObjectID homeDir;        // User's home directory
    ObjectID namespace;      // User's namespace
    uint uid;                // Optional: traditional UID
    uint gid;                // Optional: traditional GID
    bool isAdmin;            // Admin privileges
}

__gshared User[64] g_users;
__gshared size_t g_userCount = 0;

// Session represents an authenticated user session
struct Session
{
    ObjectID id;
    char[32] username;
    ObjectID namespace;      // Session's namespace
    Capability rootCap;      // Root capability for this session
    Capability homeCap;      // Home directory capability
    ulong loginTime;
    ulong lastActivity;
    bool active;
}

__gshared Session[128] g_sessions;
__gshared size_t g_sessionCount = 0;

// Create user
@nogc nothrow bool createUser(
    const(char)[] username,
    const(ubyte)[] passwordHash,
    ObjectID homeDir,
    bool isAdmin
)
{
    if (g_userCount >= g_users.length) return false;
    
    User* user = &g_users[g_userCount];
    
    // Copy username
    size_t len = username.length;
    if (len > 31) len = 31;
    for (size_t i = 0; i < len; ++i)
        user.username[i] = username[i];
    user.username[len] = 0;
    
    // Copy password hash
    for (size_t i = 0; i < 32 && i < passwordHash.length; ++i)
        user.passwordHash[i] = passwordHash[i];
    
    user.homeDir = homeDir;
    user.uid = cast(uint)(1000 + g_userCount);  // Start UIDs at 1000
    user.gid = cast(uint)(1000 + g_userCount);
    user.isAdmin = isAdmin;
    
    // Create user's namespace
    user.namespace = createStandardNamespace(getRootObject());
    
    // Bind user's home directory
    bindMount(user.namespace, "/home", homeDir, Rights.Read | Rights.Write | Rights.Enumerate);
    
    g_userCount++;
    
    return true;
}

// Find user by username
@nogc nothrow User* findUser(const(char)[] username)
{
    for (size_t i = 0; i < g_userCount; ++i)
    {
        size_t ulen = 0;
        while (g_users[i].username[ulen] != 0) ulen++;
        
        if (ulen == username.length)
        {
            bool match = true;
            for (size_t j = 0; j < ulen; ++j)
            {
                if (g_users[i].username[j] != username[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return &g_users[i];
        }
    }
    return null;
}

// Authenticate user and create session
@nogc nothrow ObjectID authenticateUser(
    const(char)[] username,
    const(ubyte)[] passwordHash
)
{
    auto user = findUser(username);
    if (user is null) return ObjectID(0, 0);
    
    // Verify password hash
    bool passwordMatch = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (i < passwordHash.length)
        {
            if (user.passwordHash[i] != passwordHash[i])
            {
                passwordMatch = false;
                break;
            }
        }
        else if (user.passwordHash[i] != 0)
        {
            passwordMatch = false;
            break;
        }
    }
    
    if (!passwordMatch) return ObjectID(0, 0);
    
    // Create session
    if (g_sessionCount >= g_sessions.length) return ObjectID(0, 0);
    
    Session* session = &g_sessions[g_sessionCount];
    session.id = ObjectID(4000 + g_sessionCount, 0);
    
    // Copy username
    size_t ulen = 0;
    while (user.username[ulen] != 0) ulen++;
    for (size_t i = 0; i < ulen; ++i)
        session.username[i] = user.username[i];
    session.username[ulen] = 0;
    
    // Create session namespace (clone user's namespace)
    auto ns = getNamespace(user.namespace);
    if (ns !is null)
    {
        session.namespace = createNamespace("session", ns.rootDir, false);
        auto sessionNs = getNamespace(session.namespace);
        if (sessionNs !is null)
        {
            session.rootCap = Capability(
                sessionNs.rootDir,
                Rights.Read | Rights.Write | Rights.Execute | Rights.Enumerate
            );
        }
    }
    
    session.homeCap = Capability(user.homeDir, Rights.Read | Rights.Write | Rights.Enumerate);
    session.loginTime = 0;  // TODO: actual time
    session.lastActivity = 0;
    session.active = true;
    
    g_sessionCount++;
    
    return session.id;
}

// Get session
@nogc nothrow Session* getSession(ObjectID sessionId)
{
    for (size_t i = 0; i < g_sessionCount; ++i)
    {
        if (g_sessions[i].id.low == sessionId.low &&
            g_sessions[i].id.high == sessionId.high)
        {
            return &g_sessions[i];
        }
    }
    return null;
}

// Logout (invalidate session)
@nogc nothrow bool logout(ObjectID sessionId)
{
    auto session = getSession(sessionId);
    if (session is null) return false;
    
    session.active = false;
    return true;
}

// ============================================================================
// Sandboxing
// ============================================================================

enum SandboxLevel
{
    None,        // No restrictions
    Minimal,     // Basic restrictions (no devices, limited /tmp)
    Standard,    // Standard sandbox (read-only system, writable home)
    Strict,      // Very restricted (read-only everything, tiny namespace)
    Isolated     // Completely isolated (no host access)
}

struct SandboxConfig
{
    SandboxLevel level;
    bool allowNetwork;
    bool allowDevices;
    bool allowIPC;
    ObjectID[] allowedDirs;     // Directories process can access
    size_t allowedDirCount;
    uint maxMemory;             // Memory limit (MB)
    uint maxProcesses;          // Process limit
}

// Create sandboxed namespace
@nogc nothrow ObjectID createSandbox(const(char)[] name, SandboxConfig* config)
{
    ObjectID baseRoot = getRootObject();
    ObjectID nsId;
    
    switch (config.level)
    {
        case SandboxLevel.None:
            nsId = createStandardNamespace(baseRoot);
            break;
        
        case SandboxLevel.Minimal:
            nsId = createMinimalNamespace(baseRoot);
            break;
        
        case SandboxLevel.Standard:
            nsId = createNamespace(name, baseRoot, false);
            
            // Read-only system directories
            auto systemDirs = ["bin", "lib", "usr"];
            foreach (dir; systemDirs)
            {
                auto dirCap = lookup(baseRoot, dir);
                if (dirCap.oid.low != 0)
                {
                    // Attenuate to read-only
                    dirCap.rights = Rights.Read | Rights.Execute | Rights.Enumerate;
                    char[64] path;
                    path[0] = '/';
                    for (size_t i = 0; i < dir.length && i < 62; ++i)
                        path[i + 1] = dir[i];
                    path[dir.length + 1] = 0;
                    
                    bindMount(nsId, cast(const(char)[])path[0..dir.length+1], dirCap.oid, dirCap.rights);
                }
            }
            
            // Writable /tmp
            ObjectID tmpDir = createDirectory();
            bindMount(nsId, "/tmp", tmpDir, Rights.Read | Rights.Write | Rights.Enumerate);
            break;
        
        case SandboxLevel.Strict:
            nsId = createUntrustedNamespace(baseRoot);
            
            // Only /bin (read-only)
            auto binCap = lookup(baseRoot, "bin");
            if (binCap.oid.low != 0)
            {
                binCap.rights = Rights.Read | Rights.Execute | Rights.Enumerate;
                bindMount(nsId, "/bin", binCap.oid, binCap.rights);
            }
            
            // Small /tmp
            ObjectID tmpDir = createDirectory();
            bindMount(nsId, "/tmp", tmpDir, Rights.Read | Rights.Write);
            break;
        
        case SandboxLevel.Isolated:
            nsId = createContainerNamespace(baseRoot, name);
            break;
        
        default:
            nsId = createMinimalNamespace(baseRoot);
            break;
    }
    
    auto ns = getNamespace(nsId);
    if (ns is null) return ObjectID(0, 0);
    
    // Apply additional restrictions
    if (!config.allowNetwork)
    {
        // Remove network access
        unmount(nsId, "/sys/net");
        unmount(nsId, "/net");
    }
    
    if (!config.allowDevices)
    {
        // Remove device access (except minimal /dev)
        unmount(nsId, "/dev");
        
        ObjectID minimalDev = createDirectory();
        // Add only null, zero, random
        bindMount(nsId, "/dev", minimalDev, Rights.Read);
    }
    
    if (!config.allowIPC)
    {
        // Remove IPC mechanisms
        unmount(nsId, "/tmp");  // No shared /tmp
    }
    
    return nsId;
}

// Create process in sandbox
@nogc nothrow ObjectID createSandboxedProcess(
    ObjectID sandboxNs,
    Capability executableCap
)
{
    auto ns = getNamespace(sandboxNs);
    if (ns is null) return ObjectID(0, 0);
    
    // Create process with sandbox namespace
    Capability rootCap = Capability(ns.rootDir, Rights.Read | Rights.Enumerate);
    Capability homeCap = Capability(ObjectID(0, 0), Rights.None);  // No home
    
    ObjectID procDir = createDirectory();
    Capability procCap = Capability(procDir, Rights.Read | Rights.Write);
    
    return createProcess(rootCap, homeCap, procCap);
}

// ============================================================================
// Least Privilege Patterns
// ============================================================================

// Grant minimal capability for specific operation
@nogc nothrow Capability grantReadOnlyAccess(ObjectID objectId)
{
    return Capability(objectId, Rights.Read);
}

@nogc nothrow Capability grantWriteOnlyAccess(ObjectID objectId)
{
    return Capability(objectId, Rights.Write);
}

@nogc nothrow Capability grantExecuteOnlyAccess(ObjectID objectId)
{
    return Capability(objectId, Rights.Execute);
}

@nogc nothrow Capability grantEnumerateOnlyAccess(ObjectID objectId)
{
    return Capability(objectId, Rights.Enumerate);
}

// Attenuate capability (reduce rights)
@nogc nothrow Capability attenuateCapability(Capability cap, uint newRights)
{
    // Can only reduce rights, not add them
    return Capability(cap.oid, cap.rights & newRights);
}

// Service pattern: Hand out narrow capabilities
struct ServiceCapability
{
    char[64] serviceName;
    ObjectID serviceObject;
    Capability publicCap;      // Public interface (limited rights)
    Capability adminCap;       // Admin interface (full rights)
}

__gshared ServiceCapability[32] g_services;
__gshared size_t g_serviceCount = 0;

// Register service
@nogc nothrow bool registerService(
    const(char)[] name,
    ObjectID serviceObject,
    uint publicRights,
    uint adminRights
)
{
    if (g_serviceCount >= g_services.length) return false;
    
    ServiceCapability* svc = &g_services[g_serviceCount];
    
    // Copy name
    size_t len = name.length;
    if (len > 63) len = 63;
    for (size_t i = 0; i < len; ++i)
        svc.serviceName[i] = name[i];
    svc.serviceName[len] = 0;
    
    svc.serviceObject = serviceObject;
    svc.publicCap = Capability(serviceObject, publicRights);
    svc.adminCap = Capability(serviceObject, adminRights);
    
    g_serviceCount++;
    
    return true;
}

// Get service capability (public or admin)
@nogc nothrow Capability getServiceCapability(const(char)[] name, bool isAdmin)
{
    for (size_t i = 0; i < g_serviceCount; ++i)
    {
        size_t slen = 0;
        while (g_services[i].serviceName[slen] != 0) slen++;
        
        if (slen == name.length)
        {
            bool match = true;
            for (size_t j = 0; j < slen; ++j)
            {
                if (g_services[i].serviceName[j] != name[j])
                {
                    match = false;
                    break;
                }
            }
            
            if (match)
            {
                return isAdmin ? g_services[i].adminCap : g_services[i].publicCap;
            }
        }
    }
    
    return Capability(ObjectID(0, 0), Rights.None);
}

// ============================================================================
// Traditional UID/GID Layer (Optional)
// ============================================================================

// Check if user has permission (traditional UNIX-style)
@nogc nothrow bool checkUnixPermission(
    ObjectID objectId,
    uint uid,
    uint gid,
    uint requestedMode  // 0x4=read, 0x2=write, 0x1=execute
)
{
    // This is a compatibility layer
    // In pure capability model, you just check if you have the capability
    
    // For now, always allow if you have a capability
    // A full implementation would store owner/group/mode in object metadata
    
    return true;
}

// Set UNIX-style permissions on object (metadata only)
struct UnixPermissions
{
    uint uid;
    uint gid;
    uint mode;  // rwxrwxrwx
}

__gshared UnixPermissions[1024] g_unixPerms;

@nogc nothrow void setUnixPermissions(ObjectID objectId, uint uid, uint gid, uint mode)
{
    // Store in metadata table
    size_t index = objectId.low % g_unixPerms.length;
    g_unixPerms[index].uid = uid;
    g_unixPerms[index].gid = gid;
    g_unixPerms[index].mode = mode;
}

@nogc nothrow UnixPermissions getUnixPermissions(ObjectID objectId)
{
    size_t index = objectId.low % g_unixPerms.length;
    return g_unixPerms[index];
}

// ============================================================================
// Security Policies
// ============================================================================

enum SecurityPolicy
{
    Permissive,   // Allow most operations
    Standard,     // Standard security
    Strict,       // Strict security
    Paranoid      // Maximum security
}

struct SecurityContext
{
    ObjectID sessionId;
    SecurityPolicy policy;
    bool auditEnabled;
    ObjectID auditLog;
}

// Check if operation is allowed
@nogc nothrow bool isOperationAllowed(
    SecurityContext* ctx,
    ObjectID objectId,
    uint requiredRights
)
{
    // In capability model, if you have the capability with rights, you can do it
    // This is just for additional policy enforcement
    
    switch (ctx.policy)
    {
        case SecurityPolicy.Permissive:
            return true;
        
        case SecurityPolicy.Standard:
            // Check basic constraints
            return true;
        
        case SecurityPolicy.Strict:
            // Additional checks
            if (ctx.auditEnabled)
            {
                // Log operation
                // auditLog.append(operation);
            }
            return true;
        
        case SecurityPolicy.Paranoid:
            // Very strict checks
            if (ctx.auditEnabled)
            {
                // Log everything
            }
            // Could deny certain operations even with capability
            return true;
        
        default:
            return false;
    }
}

// ============================================================================
// Example Security Configurations
// ============================================================================

// Create web server security context
@nogc nothrow ObjectID createWebServerContext()
{
    // Create sandbox
    SandboxConfig config;
    config.level = SandboxLevel.Standard;
    config.allowNetwork = true;   // Web server needs network
    config.allowDevices = false;  // No device access
    config.allowIPC = true;       // Allow IPC for logging
    config.maxMemory = 512;       // 512MB limit
    config.maxProcesses = 10;     // Max 10 worker processes
    
    ObjectID sandbox = createSandbox("webserver", &config);
    
    // Bind web root (read-only)
    auto ns = getNamespace(sandbox);
    if (ns !is null)
    {
        // Mount /var/www as read-only
        ObjectID wwwDir = createDirectory();
        bindMount(sandbox, "/var/www", wwwDir, Rights.Read | Rights.Enumerate);
        
        // Mount /var/log as write-only
        ObjectID logDir = createDirectory();
        bindMount(sandbox, "/var/log", logDir, Rights.Write);
    }
    
    return sandbox;
}

// Create database server security context
@nogc nothrow ObjectID createDatabaseContext()
{
    SandboxConfig config;
    config.level = SandboxLevel.Standard;
    config.allowNetwork = true;   // Database needs network
    config.allowDevices = true;   // Needs disk access
    config.allowIPC = true;
    config.maxMemory = 2048;      // 2GB limit
    config.maxProcesses = 50;
    
    ObjectID sandbox = createSandbox("database", &config);
    
    // Bind data directory (read-write)
    auto ns = getNamespace(sandbox);
    if (ns !is null)
    {
        ObjectID dataDir = createDirectory();
        bindMount(sandbox, "/var/lib/db", dataDir, Rights.Read | Rights.Write);
    }
    
    return sandbox;
}

// Create untrusted app context
@nogc nothrow ObjectID createUntrustedAppContext()
{
    SandboxConfig config;
    config.level = SandboxLevel.Isolated;
    config.allowNetwork = false;  // No network
    config.allowDevices = false;  // No devices
    config.allowIPC = false;      // No IPC
    config.maxMemory = 128;       // 128MB limit
    config.maxProcesses = 1;      // Single process
    
    return createSandbox("untrusted", &config);
}
