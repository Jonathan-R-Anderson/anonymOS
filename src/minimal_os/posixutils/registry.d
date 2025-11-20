module minimal_os.posixutils.registry;

alias ptrdiff_t = object.ptrdiff_t;

import minimal_os.kernel.posixbundle : fallbackPosixUtilityManifestPath,
    hostFallbackPosixUtilityManifestPath, hostPosixUtilityManifestPath,
    posixUtilityManifestEnvVar, posixUtilityManifestPath;

alias ExecEntryFn = extern(C) @nogc nothrow
    void function(const(char*)* argv, const(char*)* envp);

struct PosixUtilityDescriptor
{
    immutable(char)[] objectId;
    immutable(char)[] canonicalPath;
    immutable(char)[] binaryPath;
}

extern(C) @nogc nothrow void posixUtilityExecEntry(const(char*)* argv,
                                                   const(char*)* envp);

@nogc:
nothrow:

enum size_t MAX_POSIX_UTILITIES = 256;
enum size_t MAX_PATH_LENGTH = 256;
enum size_t MAX_OBJECT_ID_LENGTH = 128;

__gshared bool g_manifestLoaded = false;
__gshared bool g_manifestAttempted = false;
__gshared size_t g_manifestCount = 0;

__gshared PosixUtilityDescriptor[MAX_POSIX_UTILITIES] g_descriptorStorage;

__gshared char[MAX_OBJECT_ID_LENGTH][MAX_POSIX_UTILITIES] g_objectIdStorage;
__gshared immutable(char)[][MAX_POSIX_UTILITIES] g_objectIds;

__gshared char[MAX_PATH_LENGTH][MAX_POSIX_UTILITIES] g_canonicalStorage;
__gshared immutable(char)[][MAX_POSIX_UTILITIES] g_canonicalPaths;

__gshared char[MAX_PATH_LENGTH][MAX_POSIX_UTILITIES] g_binaryStorage;
__gshared immutable(char)[][MAX_POSIX_UTILITIES] g_binaryPaths;

__gshared char[MAX_PATH_LENGTH][MAX_POSIX_UTILITIES] g_utilityNameStorage;
__gshared immutable(char)[][MAX_POSIX_UTILITIES] g_utilityNames;

@nogc nothrow ExecEntryFn posixUtilityExecEntry(scope const(char)[] name)
{
    ensureManifestLoaded();

    if (!embeddedPosixUtilitiesAvailable() || name.length == 0)
    {
        return null;
    }

    const ptrdiff_t index = findUtilityIndex(name);
    if (index < 0)
    {
        return null;
    }

    return &registryExecShim;
}

@nogc nothrow bool embeddedPosixUtilitiesAvailable()
{
    ensureManifestLoaded();

    return g_manifestLoaded && g_manifestCount != 0;
}

@nogc nothrow immutable(char)[][] embeddedPosixUtilityPaths()
{
    ensureManifestLoaded();

    return g_canonicalPaths[0 .. g_manifestCount];
}

@nogc nothrow const(PosixUtilityDescriptor)[] posixUtilityDescriptors()
{
    ensureManifestLoaded();

    return g_descriptorStorage[0 .. g_manifestCount];
}

@nogc nothrow immutable(char)[] findPosixUtilityObjectId(scope const(char)[] name)
{
    ensureManifestLoaded();

    const ptrdiff_t index = findUtilityIndex(name);
    if (index < 0)
    {
        return null;
    }
    return g_objectIds[cast(size_t)index];
}

private extern(C) @nogc nothrow void registryExecShim(const(char*)* argv,
                                                      const(char*)* envp)
{
    posixUtilityExecEntry(argv, envp);
}

private ptrdiff_t findUtilityIndex(scope const(char)[] name)
{
    if (name.length == 0)
    {
        return -1;
    }

    foreach (idx, candidate; g_utilityNames[0 .. g_manifestCount])
    {
        if (stringsEqual(candidate, name))
        {
            return cast(ptrdiff_t)idx;
        }
    }

    return -1;
}

private bool stringsEqual(scope const(char)[] lhs, scope const(char)[] rhs)
{
    if (lhs.length != rhs.length)
    {
        return false;
    }

    foreach (i; 0 .. lhs.length)
    {
        if (lhs[i] != rhs[i])
        {
            return false;
        }
    }

    return true;
}

version (Posix)
private alias ManifestHandle = void*;
else
private alias ManifestHandle = const(char)[];

private void ensureManifestLoaded()
{
    if (g_manifestAttempted)
    {
        return;
    }

    g_manifestAttempted = true;

    version (Posix)
    {
        loadManifestFromDisk();
    }
    else
    {
        loadEmbeddedManifest();
    }
}

version (Posix)
private void loadManifestFromDisk()
{
    g_manifestCount = 0;

    auto handle = openManifest();
    if (handle is null)
    {
        g_manifestLoaded = false;
        return;
    }

    scope(exit) closeManifest(handle);

    size_t count = 0;
    char[1024] lineBuffer;
    while (count < MAX_POSIX_UTILITIES)
    {
        auto line = readManifestLine(handle, lineBuffer);
        if (line.ptr is null)
        {
            break;
        }

        PosixUtilityDescriptor desc;
        if (!parseManifestLine(line, desc))
        {
            continue;
        }

        storeDescriptor(count, desc.objectId, desc.canonicalPath, desc.binaryPath);
        ++count;
    }

    finalizeManifest(count);
}

else
private void loadEmbeddedManifest()
{
    g_manifestCount = 0;

    immutable string manifest = importableManifest();
    size_t count = 0;
    size_t cursor = 0;
    while (count < MAX_POSIX_UTILITIES && cursor < manifest.length)
    {
        immutable size_t lineStart = cursor;
        size_t lineEnd = cursor;
        while (lineEnd < manifest.length && manifest[lineEnd] != '\n' && manifest[lineEnd] != '\r')
        {
            ++lineEnd;
        }

        immutable string line = manifest[lineStart .. lineEnd];
        cursor = lineEnd;
        while (cursor < manifest.length && (manifest[cursor] == '\n' || manifest[cursor] == '\r'))
        {
            ++cursor;
        }

        PosixUtilityDescriptor desc;
        if (!parseManifestLine(line, desc))
        {
            continue;
        }

        storeDescriptor(count, desc.objectId, desc.canonicalPath, desc.binaryPath);
        ++count;
    }

    finalizeManifest(count);
}

version (Posix)
@nogc nothrow private ManifestHandle openManifest()
{
    immutable(char)[] mode = "r";

    auto handle = openManifestFromEnvironment(mode);
    if (handle !is null)
    {
        return handle;
    }

    immutable string[4] manifestSearchPaths =
        [ posixUtilityManifestPath,
          hostPosixUtilityManifestPath,
          fallbackPosixUtilityManifestPath,
          hostFallbackPosixUtilityManifestPath ];

    foreach (path; manifestSearchPaths)
    {
        handle = openManifestFromPath(path, mode);
        if (handle !is null)
        {
            return handle;
        }
    }

    return null;
}

version (Posix)
@nogc nothrow private ManifestHandle openManifestFromEnvironment(immutable(char)[] mode)
{
    if (mode.ptr is null)
    {
        return null;
    }

    auto envPath = getenv(posixUtilityManifestEnvVar.ptr);
    if (envPath is null || envPath[0] == '\0')
    {
        return null;
    }

    return fopen(envPath, mode.ptr);
}

version (Posix)
@nogc nothrow private ManifestHandle openManifestFromPath(immutable(char)[] path, immutable(char)[] mode)
{
    if (path.ptr is null || path.length == 0 || mode.ptr is null)
    {
        return null;
    }

    return fopen(path.ptr, mode.ptr);
}

version (Posix)
@nogc nothrow private void closeManifest(ManifestHandle handle)
{
    if (handle !is null)
    {
        fclose(handle);
    }
}

version (Posix)
@nogc nothrow private immutable(char)[] readManifestLine(ManifestHandle handle, char[] buffer)
{
    if (handle is null || buffer.length == 0)
    {
        return null;
    }

    auto result = fgets(buffer.ptr, cast(int)buffer.length, handle);
    if (result is null)
    {
        return null;
    }

    size_t length = 0;
    while (length < buffer.length && buffer[length] != '\0')
    {
        if (buffer[length] == '\n' || buffer[length] == '\r')
        {
            buffer[length] = '\0';
            break;
        }
        ++length;
    }

    return cast(immutable(char)[])buffer[0 .. length];
}

private void finalizeManifest(size_t count)
{
    g_manifestCount = count;
    g_manifestLoaded = count != 0;
}

private void storeDescriptor(size_t index, immutable(char)[] objectId, immutable(char)[] canonicalPath, immutable(char)[] binaryPath)
{
    if (index >= MAX_POSIX_UTILITIES)
    {
        return;
    }

    setStorageSlice!MAX_OBJECT_ID_LENGTH(g_objectIdStorage[index], objectId, g_objectIds[index]);
    setStorageSlice!MAX_PATH_LENGTH(g_canonicalStorage[index], canonicalPath, g_canonicalPaths[index]);
    setStorageSlice!MAX_PATH_LENGTH(g_binaryStorage[index], binaryPath, g_binaryPaths[index]);

    immutable(char)[] name = baseName(g_canonicalPaths[index]);
    setStorageSlice!MAX_PATH_LENGTH(g_utilityNameStorage[index], name, g_utilityNames[index]);

    g_descriptorStorage[index] = PosixUtilityDescriptor(g_objectIds[index], g_canonicalPaths[index], g_binaryPaths[index]);
}

private bool parseManifestLine(string line, ref PosixUtilityDescriptor desc)
{
    if (line.length == 0)
    {
        return false;
    }

    const size_t first = findSeparator(line, 0);
    if (first == line.length)
    {
        return false;
    }

    const size_t second = findSeparator(line, first + 1);
    if (second == line.length)
    {
        return false;
    }

    desc.objectId = line[0 .. first];
    desc.canonicalPath = line[first + 1 .. second];
    desc.binaryPath = line[second + 1 .. line.length];
    return desc.objectId.length != 0 && desc.canonicalPath.length != 0 && desc.binaryPath.length != 0;
}

private size_t findSeparator(string text, size_t start)
{
    size_t index = start;
    while (index < text.length && text[index] != '\t')
    {
        ++index;
    }
    return index;
}

private immutable(char)[] baseName(immutable(char)[] path)
{
    size_t endIndex = path.length;
    size_t startIndex = endIndex;
    while (startIndex > 0)
    {
        immutable char ch = path[startIndex - 1];
        if (ch == '/' || ch == '\\')
        {
            break;
        }
        --startIndex;
    }
    return path[startIndex .. endIndex];
}

auto toStaticArray(T)(const(T)[] values)
{
    immutable(T)[values.length] result;
    foreach (i, value; values)
    {
        result[i] = value;
    }
    return result;
}

version (Posix)
extern(C) @nogc nothrow
{
    void* fopen(const(char)*, const(char)*);
    int fclose(void*);
    char* fgets(char*, int, void*);
    char* getenv(const(char)*);
}

private string importableManifest()
{
    static if (__traits(compiles, { enum c = import(hostPosixUtilityManifestPath); }))
    {
        return import(hostPosixUtilityManifestPath);
    }
    else static if (__traits(compiles, { enum c = import(posixUtilityManifestPath); }))
    {
        return import(posixUtilityManifestPath);
    }
    else static if (__traits(compiles, { enum c = import(hostFallbackPosixUtilityManifestPath); }))
    {
        return import(hostFallbackPosixUtilityManifestPath);
    }
    else static if (__traits(compiles, { enum c = import(fallbackPosixUtilityManifestPath); }))
    {
        return import(fallbackPosixUtilityManifestPath);
    }
    else
    {
        return "";
    }
}

private void setStorageSlice(size_t N)(ref char[N] storage, immutable(char)[] source, out immutable(char)[] slice)
{
    size_t copyLength = source.length;
    if (copyLength >= storage.length)
    {
        copyLength = storage.length - 1;
    }

    foreach (index; 0 .. copyLength)
    {
        storage[index] = source[index];
    }

    storage[copyLength] = '\0';
    slice = cast(immutable(char)[])storage[0 .. copyLength];
}
