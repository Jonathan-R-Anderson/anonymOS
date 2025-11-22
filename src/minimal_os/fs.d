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

    foreach (i; 0 .. g_fileCount)
    {
        if (g_files[i].name == nameSlice)
        {
            return g_files[i].data;
        }
        
        // Handle leading slash mismatch
        // If requested "/bin/sh" but stored "bin/sh"
        if (nameSlice.length > 0 && nameSlice[0] == '/' && g_files[i].name == nameSlice[1 .. $])
        {
            return g_files[i].data;
        }
        
        // If requested "bin/sh" but stored "/bin/sh"
        if (g_files[i].name.length > 0 && g_files[i].name[0] == '/' && g_files[i].name[1 .. $] == nameSlice)
        {
            return g_files[i].data;
        }
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
