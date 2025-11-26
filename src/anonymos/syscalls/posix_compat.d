module anonymos.syscalls.posix_compat;

// POSIX compatibility layer - adapts object interfaces to POSIX API

import anonymos.objects;
import anonymos.object_methods;

// File descriptor table entry
struct FileDescriptor
{
    ObjectID oid;
    uint rights;
    ObjectType type;
    ulong offset;      // Current read/write position
    int flags;         // O_RDONLY, O_WRONLY, etc.
    bool inUse;
}

// Per-process file descriptor table
__gshared FileDescriptor[256] g_fdTable;
__gshared size_t g_nextFd = 3; // 0=stdin, 1=stdout, 2=stderr

// POSIX open flags
enum OpenFlags : int
{
    O_RDONLY = 0x0000,
    O_WRONLY = 0x0001,
    O_RDWR   = 0x0002,
    O_CREAT  = 0x0040,
    O_EXCL   = 0x0080,
    O_TRUNC  = 0x0200,
    O_APPEND = 0x0400,
}

// Allocate a file descriptor
@nogc nothrow int allocFd(ObjectID oid, uint rights, ObjectType type, int flags)
{
    for (size_t i = g_nextFd; i < g_fdTable.length; ++i)
    {
        if (!g_fdTable[i].inUse)
        {
            g_fdTable[i].oid = oid;
            g_fdTable[i].rights = rights;
            g_fdTable[i].type = type;
            g_fdTable[i].offset = 0;
            g_fdTable[i].flags = flags;
            g_fdTable[i].inUse = true;
            return cast(int)i;
        }
    }
    return -1; // EMFILE - too many open files
}

// Get file descriptor
@nogc nothrow FileDescriptor* getFd(int fd)
{
    if (fd < 0 || fd >= g_fdTable.length) return null;
    if (!g_fdTable[fd].inUse) return null;
    return &g_fdTable[fd];
}

// ============================================================================
// POSIX open() - Path resolution + object adaptation
// ============================================================================

@nogc nothrow int posix_open(const(char)* pathname, int flags, int mode)
{
    // Convert C string to D slice
    size_t len = 0;
    while (pathname[len] != 0) len++;
    const(char)[] path = pathname[0 .. len];
    
    // Get current process root (TODO: get from actual process object)
    ObjectID rootDir = getRootObject();
    if (rootDir.low == 0) return -2; // ENOENT
    
    // Resolve path to capability
    auto cap = resolvePath(rootDir, path);
    if (cap.oid.low == 0 && cap.oid.high == 0) 
    {
        // File not found
        if (flags & OpenFlags.O_CREAT)
        {
            // TODO: Create new file
            return -1; // Not implemented yet
        }
        return -2; // ENOENT
    }
    
    // Get object to check type
    auto slot = getObject(cap.oid);
    if (slot is null) return -2;
    
    // Validate rights based on flags
    uint requiredRights = 0;
    if ((flags & 0x3) == OpenFlags.O_RDONLY)
        requiredRights = Rights.Read;
    else if ((flags & 0x3) == OpenFlags.O_WRONLY)
        requiredRights = Rights.Write;
    else if ((flags & 0x3) == OpenFlags.O_RDWR)
        requiredRights = Rights.Read | Rights.Write;
    
    if ((cap.rights & requiredRights) != requiredRights)
        return -13; // EACCES
    
    // Allocate file descriptor
    return allocFd(cap.oid, cap.rights, slot.type, flags);
}

// ============================================================================
// POSIX read() - Polymorphic dispatch based on object type
// ============================================================================

@nogc nothrow long posix_read(int fd, void* buf, size_t count)
{
    auto fdEntry = getFd(fd);
    if (fdEntry is null) return -9; // EBADF
    
    if ((fdEntry.rights & Rights.Read) == 0) return -13; // EACCES
    
    ubyte* buffer = cast(ubyte*)buf;
    
    // Dispatch based on object type
    switch (fdEntry.type)
    {
        case ObjectType.Blob:
            // Read from file
            long bytesRead = blobRead(fdEntry.oid, fdEntry.offset, count, buffer);
            if (bytesRead > 0)
                fdEntry.offset += bytesRead;
            return bytesRead;
        
        case ObjectType.BlockDevice:
            // Read blocks (adapt block interface to byte interface)
            auto slot = getObject(fdEntry.oid);
            if (slot is null) return -5; // EIO
            
            ulong blockSize = slot.blockDevice.blockSize;
            ulong startBlock = fdEntry.offset / blockSize;
            ulong blockCount = (count + blockSize - 1) / blockSize;
            
            // Allocate temp buffer for block-aligned read
            ubyte* blockBuffer = cast(ubyte*)kmalloc(blockCount * blockSize);
            if (blockBuffer is null) return -12; // ENOMEM
            
            long result = blockDeviceRead(fdEntry.oid, startBlock, blockCount, blockBuffer);
            if (result < 0)
            {
                kfree(blockBuffer);
                return result;
            }
            
            // Copy relevant bytes
            ulong offsetInBlock = fdEntry.offset % blockSize;
            size_t copyLen = count;
            if (copyLen > blockCount * blockSize - offsetInBlock)
                copyLen = cast(size_t)(blockCount * blockSize - offsetInBlock);
            
            for (size_t i = 0; i < copyLen; ++i)
                buffer[i] = blockBuffer[offsetInBlock + i];
            
            kfree(blockBuffer);
            fdEntry.offset += copyLen;
            return cast(long)copyLen;
        
        case ObjectType.Channel:
            // Read from IPC channel
            Capability[10] caps;
            size_t capsReceived;
            long bytesRead = channelRecv(fdEntry.oid, buffer, count, caps.ptr, 10, &capsReceived);
            // TODO: Handle received capabilities
            return bytesRead;
        
        case ObjectType.Socket:
            // Read from network socket
            return socketRecv(fdEntry.oid, buffer, count);
        
        case ObjectType.Process:
            // Reading from process object - could return state info
            // Adapt getState() to pseudo-file interface
            auto slot = getObject(fdEntry.oid);
            if (slot is null) return -5;
            
            // Format: "state: Running\npid: 123\n"
            char[256] stateBuffer;
            size_t pos = 0;
            
            // Add state
            const(char)[] stateStr = "state: ";
            for (size_t i = 0; i < stateStr.length && pos < 256; ++i)
                stateBuffer[pos++] = stateStr[i];
            
            // Add state value
            switch (slot.process.state)
            {
                case ProcessState.Running:
                    const(char)[] val = "Running\n";
                    for (size_t i = 0; i < val.length && pos < 256; ++i)
                        stateBuffer[pos++] = val[i];
                    break;
                case ProcessState.Stopped:
                    const(char)[] val = "Stopped\n";
                    for (size_t i = 0; i < val.length && pos < 256; ++i)
                        stateBuffer[pos++] = val[i];
                    break;
                default:
                    break;
            }
            
            // Copy to user buffer
            size_t copyLen = pos - fdEntry.offset;
            if (copyLen > count) copyLen = count;
            
            for (size_t i = 0; i < copyLen; ++i)
                buffer[i] = cast(ubyte)stateBuffer[fdEntry.offset + i];
            
            fdEntry.offset += copyLen;
            return cast(long)copyLen;
        
        default:
            // Unsupported object type for reading
            return -22; // EINVAL
    }
}

// ============================================================================
// POSIX write() - Polymorphic dispatch based on object type
// ============================================================================

@nogc nothrow long posix_write(int fd, const(void)* buf, size_t count)
{
    auto fdEntry = getFd(fd);
    if (fdEntry is null) return -9; // EBADF
    
    if ((fdEntry.rights & Rights.Write) == 0) return -13; // EACCES
    
    const(ubyte)* buffer = cast(const(ubyte)*)buf;
    
    // Dispatch based on object type
    switch (fdEntry.type)
    {
        case ObjectType.Blob:
            // Write to file
            long bytesWritten = blobWrite(fdEntry.oid, fdEntry.offset, buffer, count);
            if (bytesWritten > 0)
                fdEntry.offset += bytesWritten;
            return bytesWritten;
        
        case ObjectType.BlockDevice:
            // Write blocks
            auto slot = getObject(fdEntry.oid);
            if (slot is null) return -5; // EIO
            
            ulong blockSize = slot.blockDevice.blockSize;
            ulong startBlock = fdEntry.offset / blockSize;
            ulong blockCount = (count + blockSize - 1) / blockSize;
            
            // For simplicity, require block-aligned writes
            if (fdEntry.offset % blockSize != 0) return -22; // EINVAL
            
            long result = blockDeviceWrite(fdEntry.oid, startBlock, buffer, blockCount);
            if (result >= 0)
                fdEntry.offset += count;
            return result;
        
        case ObjectType.Channel:
            // Write to IPC channel
            return channelSend(fdEntry.oid, buffer, count, null, 0);
        
        case ObjectType.Socket:
            // Write to network socket
            return socketSend(fdEntry.oid, buffer, count);
        
        case ObjectType.Process:
            // Writing to process - could send signal
            // Adapt signal() to pseudo-file interface
            // For now, not supported
            return -22; // EINVAL
        
        default:
            return -22; // EINVAL
    }
}

// ============================================================================
// POSIX close()
// ============================================================================

@nogc nothrow int posix_close(int fd)
{
    auto fdEntry = getFd(fd);
    if (fdEntry is null) return -9; // EBADF
    
    fdEntry.inUse = false;
    return 0;
}

// ============================================================================
// POSIX lseek()
// ============================================================================

@nogc nothrow long posix_lseek(int fd, long offset, int whence)
{
    auto fdEntry = getFd(fd);
    if (fdEntry is null) return -9; // EBADF
    
    // SEEK_SET = 0, SEEK_CUR = 1, SEEK_END = 2
    switch (whence)
    {
        case 0: // SEEK_SET
            fdEntry.offset = offset;
            break;
        
        case 1: // SEEK_CUR
            fdEntry.offset += offset;
            break;
        
        case 2: // SEEK_END
            // Get size based on object type
            if (fdEntry.type == ObjectType.Blob)
            {
                long size = blobSize(fdEntry.oid);
                if (size < 0) return size;
                fdEntry.offset = size + offset;
            }
            else
            {
                return -29; // ESPIPE - illegal seek
            }
            break;
        
        default:
            return -22; // EINVAL
    }
    
    return cast(long)fdEntry.offset;
}

// ============================================================================
// POSIX stat() - Adapt object metadata to stat structure
// ============================================================================

struct posix_stat
{
    ulong st_dev;
    ulong st_ino;
    uint st_mode;
    uint st_nlink;
    uint st_uid;
    uint st_gid;
    ulong st_rdev;
    long st_size;
    long st_blksize;
    long st_blocks;
    long st_atime;
    long st_mtime;
    long st_ctime;
}

@nogc nothrow int posix_stat(const(char)* pathname, posix_stat* statbuf)
{
    // Resolve path
    size_t len = 0;
    while (pathname[len] != 0) len++;
    const(char)[] path = pathname[0 .. len];
    
    ObjectID rootDir = getRootObject();
    auto cap = resolvePath(rootDir, path);
    if (cap.oid.low == 0 && cap.oid.high == 0) return -2; // ENOENT
    
    auto slot = getObject(cap.oid);
    if (slot is null) return -2;
    
    // Fill stat structure based on object type
    statbuf.st_dev = 0;
    statbuf.st_ino = cap.oid.low; // Use ObjectID as inode
    statbuf.st_nlink = 1;
    statbuf.st_uid = 0;
    statbuf.st_gid = 0;
    statbuf.st_rdev = 0;
    statbuf.st_blksize = 4096;
    
    switch (slot.type)
    {
        case ObjectType.Blob:
            statbuf.st_mode = 0x8000; // S_IFREG - regular file
            if (cap.rights & Rights.Read) statbuf.st_mode |= 0x100; // S_IRUSR
            if (cap.rights & Rights.Write) statbuf.st_mode |= 0x80; // S_IWUSR
            if (cap.rights & Rights.Execute) statbuf.st_mode |= 0x40; // S_IXUSR
            
            statbuf.st_size = cast(long)slot.blob.size;
            statbuf.st_blocks = (slot.blob.size + 511) / 512;
            statbuf.st_mtime = cast(long)slot.blob.modifiedTime;
            statbuf.st_ctime = cast(long)slot.blob.createdTime;
            statbuf.st_atime = statbuf.st_mtime;
            break;
        
        case ObjectType.Directory:
            statbuf.st_mode = 0x4000; // S_IFDIR
            if (cap.rights & Rights.Enumerate) statbuf.st_mode |= 0x100; // S_IRUSR
            if (cap.rights & Rights.Write) statbuf.st_mode |= 0x80; // S_IWUSR
            statbuf.st_mode |= 0x40; // S_IXUSR
            
            statbuf.st_size = slot.directory.count * 64; // Approximate
            statbuf.st_blocks = 1;
            break;
        
        case ObjectType.BlockDevice:
            statbuf.st_mode = 0x6000; // S_IFBLK - block device
            statbuf.st_mode |= 0x1C0; // rwx for owner
            statbuf.st_size = cast(long)(slot.blockDevice.blockCount * slot.blockDevice.blockSize);
            statbuf.st_blocks = cast(long)slot.blockDevice.blockCount;
            statbuf.st_blksize = slot.blockDevice.blockSize;
            break;
        
        case ObjectType.Channel:
        case ObjectType.Socket:
            statbuf.st_mode = 0xC000; // S_IFSOCK - socket
            statbuf.st_mode |= 0x1C0;
            statbuf.st_size = 0;
            statbuf.st_blocks = 0;
            break;
        
        default:
            statbuf.st_mode = 0x8000; // Regular file as fallback
            statbuf.st_size = 0;
            statbuf.st_blocks = 0;
            break;
    }
    
    return 0;
}
