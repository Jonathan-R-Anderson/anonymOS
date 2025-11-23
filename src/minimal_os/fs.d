module minimal_os.fs;

static if (!__traits(compiles, { size_t dummy; }))
{
    alias size_t = typeof(int.sizeof);
}

struct FileEntry
{
    immutable(char)[] name;
    const(ubyte)[] data;
}

// Simple linear search for now. In a real OS, this would be a tree/hash map.
__gshared FileEntry[256] g_files;
__gshared size_t g_fileCount = 0;

@nogc nothrow void registerFile(immutable(char)[] name, const(ubyte)[] data)
{
    if (g_fileCount < g_files.length)
    {
        g_files[g_fileCount++] = FileEntry(name, data);
    }
}

@nogc nothrow const(ubyte)[] readFile(const(char)* name)
{
    if (name is null) return null;
    
    // C-string to slice
    size_t len = 0;
    while (name[len] != 0) len++;
    immutable(char)[] nameSlice = cast(immutable(char)[])name[0 .. len];

    // Use Object Store with path resolution
    import minimal_os.objects : getRootObject, getObject, ObjectType, resolvePath, ObjectID;
    
    ObjectID rootDir = getRootObject();
    if (rootDir.low == 0) return null; // No root
    
    auto cap = resolvePath(rootDir, nameSlice);
    if (cap.oid.low == 0 && cap.oid.high == 0) return null; // Not found
    
    auto fileSlot = getObject(cap.oid);
    if (fileSlot !is null && fileSlot.type == ObjectType.Blob)
    {
        if (fileSlot.blob.vmo !is null)
            return fileSlot.blob.vmo.dataPtr[0 .. fileSlot.blob.vmo.dataLen];
    }
    
    return null;
}

// TAR Header
struct TarHeader
{
    char[100] name;
    char[8] mode;
    char[8] uid;
    char[8] gid;
    char[12] size;
    char[12] mtime;
    char[8] chksum;
    char typeflag;
    char[100] linkname;
    char[6] magic;
    char[2] version_;
    char[32] uname;
    char[32] gname;
    char[8] devmajor;
    char[8] devminor;
    char[155] prefix;
}

@nogc nothrow size_t parseOctal(const(char)[] str)
{
    size_t value = 0;
    foreach (c; str)
    {
        if (c < '0' || c > '7') break;
        value = (value << 3) | (c - '0');
    }
    return value;
}

@nogc nothrow void parseTarball(const(ubyte)[] tarData)
{
    size_t offset = 0;
    while (offset + 512 <= tarData.length)
    {
        const(TarHeader)* header = cast(const(TarHeader)*)(tarData.ptr + offset);
        
        // Check for end of archive (empty block)
        if (header.name[0] == 0) break;
        
        size_t size = parseOctal(header.size[]);
        size_t dataOffset = offset + 512;
        
        // Round up to 512 bytes
        size_t nextHeader = dataOffset + ((size + 511) & ~511);
        
        if (header.typeflag == '0' || header.typeflag == 0) // Normal file
        {
            // Extract name
            size_t nameLen = 0;
            while (nameLen < 100 && header.name[nameLen] != 0) nameLen++;
            
            // We need to copy the name because it might not be null-terminated or we want a slice
            // But for now, we can just use the slice from the header if we are careful.
            // Wait, we need to store it.
            // Let's assume we can just cast the slice to immutable for this simple VFS.
            // In a real OS, we'd copy.
            
            // Prepend "/" if missing?
            // The tarball paths are relative usually (e.g. "bin/sh").
            // We want "/bin/sh".
            
            // For this hack, let's just register it as is.
            // But wait, readFile expects absolute paths?
            // Let's check how we call it.
            
            // Actually, let's just store it.
            // We need a buffer for the name if we want to prepend '/'.
            // Or we can just rely on the user requesting "bin/sh" vs "/bin/sh".
            // Let's try to match both in readFile? No, that's messy.
            
            // Let's just register as is.
            immutable(char)[] name = cast(immutable(char)[])header.name[0 .. nameLen];
            const(ubyte)[] data = tarData[dataOffset .. dataOffset + size];
            
            registerFile(name, data);
            
            // Create Blob Object
            import minimal_os.objects : createBlob, createDirectory, addEntry, getRootObject, setRootObject, ObjectID, Capability, Rights, getObject, ObjectType;
            
            // Initialize root if needed
            if (getRootObject().low == 0)
            {
                setRootObject(createDirectory());
            }
            
            ObjectID blobId = createBlob(data);
            
            // Parse path and create directories
            // name is e.g. "bin/sh" or "usr/lib/foo.so"
            // We need to traverse/create directories from root.
            
            ObjectID currentDir = getRootObject();
            
            size_t start = 0;
            // Skip leading slash
            if (name.length > 0 && name[0] == '/') start = 1;
            
            for (size_t i = start; i < name.length; ++i)
            {
                if (name[i] == '/')
                {
                    // Found a component
                    const(char)[] component = name[start .. i];
                    
                    // Check if component exists in currentDir
                    // We need a lookup function. For now, just linear search in addEntry logic?
                    // No, we need to find the ID.
                    
                    ObjectID nextDir = ObjectID(0,0);
                    
                    // Manual lookup in directory
                    auto slot = getObject(currentDir);
                    if (slot !is null && slot.type == ObjectType.Directory)
                    {
                        for (size_t k = 0; k < slot.directory.count; ++k)
                        {
                            auto entry = &slot.directory.entries[k];
                            // Compare name
                            bool match = true;
                            size_t clen = 0;
                            while (entry.name[clen] != 0) clen++;
                            
                            if (clen != component.length) match = false;
                            else
                            {
                                for (size_t m = 0; m < clen; ++m)
                                {
                                    if (entry.name[m] != component[m]) { match = false; break; }
                                }
                            }
                            
                            if (match)
                            {
                                nextDir = entry.cap.oid;
                                break;
                            }
                        }
                    }
                    
                    if (nextDir.low == 0)
                    {
                        // Create new directory
                        nextDir = createDirectory();
                        addEntry(currentDir, component, Capability(nextDir, Rights.Read | Rights.Write | Rights.Enumerate));
                    }
                    
                    currentDir = nextDir;
                    start = i + 1;
                }
            }
            
            // Add file to final directory
            if (start < name.length)
            {
                const(char)[] filename = name[start .. $];
                addEntry(currentDir, filename, Capability(blobId, Rights.Read | Rights.Write | Rights.Execute));
            }

            
            // Also register with leading '/' if it doesn't have one
            if (nameLen > 0 && name[0] != '/')
            {
                 // We can't easily allocate a new string here without a heap.
                 // But we can cheat: if the user asks for "/bin/sh", we can strip the leading slash in readFile.
            }
        }
        
        offset = nextHeader;
    }
}
