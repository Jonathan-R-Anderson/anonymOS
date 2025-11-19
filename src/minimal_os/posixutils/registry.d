module minimal_os.posixutils.registry;

import core.stdc.stddef : ptrdiff_t;
import minimal_os.kernel.posixbundle : fallbackPosixUtilityManifestPath,
    hostFallbackPosixUtilityManifestPath, hostPosixUtilityManifestPath,
    posixUtilityManifestPath;

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

private enum string objectManifest = loadManifest();
private enum PosixUtilityDescriptor[] parsedManifest = parseObjectManifest(objectManifest);
private immutable(PosixUtilityDescriptor)[parsedManifest.length] g_posixUtilityDescriptors =
    toStaticArray(parsedManifest);
private enum immutable(char)[][] canonicalPathList = collectCanonicalPaths(parsedManifest);
private immutable(immutable(char)[])[canonicalPathList.length] g_canonicalPaths =
    toStaticArray(canonicalPathList);
private enum immutable(char)[][] nameList = collectUtilityNames(parsedManifest);
private immutable(immutable(char)[])[nameList.length] g_utilityNames = toStaticArray(nameList);
private enum immutable(char)[][] objectIdList = collectObjectIds(parsedManifest);
private immutable(immutable(char)[])[objectIdList.length] g_objectIds = toStaticArray(objectIdList);

@nogc nothrow ExecEntryFn posixUtilityExecEntry(scope const(char)[] name)
{
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
    return g_posixUtilityDescriptors.length != 0;
}

@nogc nothrow immutable(char)[][] embeddedPosixUtilityPaths()
{
    return g_canonicalPaths[];
}

@nogc nothrow const(PosixUtilityDescriptor)[] posixUtilityDescriptors()
{
    return g_posixUtilityDescriptors[];
}

@nogc nothrow immutable(char)[] findPosixUtilityObjectId(scope const(char)[] name)
{
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

    foreach (idx, candidate; g_utilityNames)
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

private string loadManifest()
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

private PosixUtilityDescriptor[] parseObjectManifest(string manifest)
{
    PosixUtilityDescriptor[] entries;
    size_t cursor = 0;
    while (cursor < manifest.length)
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
        if (parseManifestLine(line, desc))
        {
            entries ~= desc;
        }
    }

    return entries;
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

private immutable(char)[][] collectCanonicalPaths(PosixUtilityDescriptor[] entries)
{
    immutable(char)[][] paths;
    foreach (entry; entries)
    {
        paths ~= entry.canonicalPath;
    }
    return paths;
}

private immutable(char)[][] collectObjectIds(PosixUtilityDescriptor[] entries)
{
    immutable(char)[][] ids;
    foreach (entry; entries)
    {
        ids ~= entry.objectId;
    }
    return ids;
}

private immutable(char)[][] collectUtilityNames(PosixUtilityDescriptor[] entries)
{
    immutable(char)[][] names;
    foreach (entry; entries)
    {
        names ~= baseName(entry.canonicalPath);
    }
    return names;
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
