module anonymos.kernel.posixbundle;

static if (!__traits(compiles, { size_t dummy; }))
{
    alias size_t = typeof(int.sizeof);
}
import anonymos.console : print, printLine, printCString, putChar, printStageHeader, printStatus, printStatusValue;
import anonymos.syscalls.posix : hostPosixInteropEnabled;
static if (hostPosixInteropEnabled) import anonymos.syscalls.posix : environ;

enum string defaultEmbeddedPosixUtilitiesRoot = "/kernel/posixutils/bin";
enum string posixUtilityManifestPath = "/build/posixutils/objects.tsv";
enum string hostPosixUtilityManifestPath = "build/posixutils/objects.tsv";
enum string fallbackPosixUtilityManifestPath = "/build/posixutils/manifest.txt";
enum string hostFallbackPosixUtilityManifestPath = "build/posixutils/manifest.txt";
enum string posixUtilityManifestEnvVar = "POSIXUTILS_MANIFEST";

private enum size_t MAX_EMBEDDED_POSIX_UTILITIES = 128;
private enum size_t MAX_CANONICAL_LENGTH = 96;
private enum size_t MAX_HOST_PATH_LENGTH = 512;

private __gshared size_t g_embeddedPosixUtilityCount = 0;
private __gshared bool   g_manifestLoaded = false;
private __gshared bool   g_manifestAttempted = false;

private __gshared char[MAX_CANONICAL_LENGTH][MAX_EMBEDDED_POSIX_UTILITIES] g_canonicalStorage;
private __gshared char[MAX_CANONICAL_LENGTH][MAX_EMBEDDED_POSIX_UTILITIES] g_baseStorage;
private __gshared char[MAX_HOST_PATH_LENGTH][MAX_EMBEDDED_POSIX_UTILITIES] g_hostStorage;

private __gshared immutable(char)[][MAX_EMBEDDED_POSIX_UTILITIES] g_canonicalSlices;
private __gshared immutable(char)[][MAX_EMBEDDED_POSIX_UTILITIES] g_baseSlices;
private __gshared immutable(char)[][MAX_EMBEDDED_POSIX_UTILITIES] g_hostSlices;

private __gshared char[MAX_HOST_PATH_LENGTH] g_rootStorage;
private __gshared size_t g_rootLength = 0;

@nogc nothrow bool embeddedPosixUtilitiesAvailable()
{
    if (!g_manifestAttempted || (!g_manifestLoaded && g_embeddedPosixUtilityCount == 0))
    {
        loadEmbeddedPosixUtilityManifest();
    }

    return g_manifestLoaded && g_embeddedPosixUtilityCount != 0;
}

@nogc nothrow immutable(char)[] embeddedPosixUtilitiesRoot()
{
    if (!embeddedPosixUtilitiesAvailable())
    {
        return defaultEmbeddedPosixUtilitiesRoot;
    }

    return cast(immutable(char)[])g_rootStorage[0 .. g_rootLength];
}

@nogc nothrow immutable(char)[][] embeddedPosixUtilityPaths()
{
    return g_canonicalSlices[0 .. g_embeddedPosixUtilityCount];
}

@nogc nothrow void compileEmbeddedPosixUtilities()
{
    printStageHeader("Embed POSIX utilities");

    loadEmbeddedPosixUtilityManifest();

    const long bundled = cast(long)g_embeddedPosixUtilityCount;
    printStatusValue("[posix] Utilities bundled : ", bundled);

    immutable(char)[] rootPath = embeddedPosixUtilitiesRoot();
    printStatus("[posix] Bundle root        : ", rootPath, "");

    if (!embeddedPosixUtilitiesAvailable())
    {
        printStatus("[posix] Manifest status   : ", "missing", "");
    }
    else
    {
        printStatus("[posix] Manifest status   : ", "loaded", "");
    }
}

@nogc nothrow bool executeEmbeddedPosixUtility(const(char)* program, const(char*)* argv, const(char*)* envp, out int exitCode)
{
    exitCode = 127;
    if (!embeddedPosixUtilitiesAvailable())
    {
        return false;
    }

    auto hostPath = resolveEmbeddedUtility(program);
    if (hostPath is null)
    {
        return false;
    }

    if (!isExecutable(hostPath))
    {
        print("[posix] Embedded utility not executable: ");
        printCString(hostPath);
        putChar('\n');
        return false;
    }

    auto mutableArgv = cast(char**)argv;
    auto mutableEnvp = cast(char**)envp;

    char*[2] fallbackArgs;
    if (mutableArgv is null || mutableArgv[0] is null)
    {
        fallbackArgs[0] = cast(char*)hostPath;
        fallbackArgs[1] = null;
        mutableArgv = fallbackArgs.ptr;
    }

    if (spawnAndWait(hostPath, mutableArgv, mutableEnvp, exitCode))
    {
        return true;
    }

    print("[posix] Failed to execute embedded utility: ");
    printCString(hostPath);
    putChar('\n');
    return false;
}

@nogc nothrow private void loadEmbeddedPosixUtilityManifest()
{
    g_embeddedPosixUtilityCount = 0;
    g_rootLength = 0;
    g_manifestAttempted = true;

    auto file = openManifest();
    if (file is null)
    {
        g_manifestLoaded = false;
        return;
    }

    scope(exit) closeManifest(file);

    char[1024] lineBuffer;
    size_t count = 0;

    while (count < MAX_EMBEDDED_POSIX_UTILITIES)
    {
        auto line = readManifestLine(file, lineBuffer);
        if (line.ptr is null)
        {
            break;
        }

        immutable(char)[] canonical;
        immutable(char)[] hostPath;
        if (!parseManifestLine(line, canonical, hostPath))
        {
            continue;
        }

        immutable(char)[] base = canonicalBase(canonical);

        char[MAX_HOST_PATH_LENGTH] resolved;
        immutable(char)[] normalizedHost = canonicalizeHostPath(hostPath, resolved);

        setStorageSlice(g_canonicalStorage[count], canonical, g_canonicalSlices[count]);
        setStorageSlice(g_hostStorage[count], normalizedHost, g_hostSlices[count]);
        setStorageSlice(g_baseStorage[count], base, g_baseSlices[count]);

        if (g_rootLength == 0)
        {
            determineRootPath(normalizedHost);
        }

        ++count;
    }

    g_embeddedPosixUtilityCount = count;
    g_manifestLoaded = count != 0;
}

// --- Manifest helpers ----------------------------------------------------

private alias ManifestHandle = void*;

static if (hostPosixInteropEnabled)
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

static if (hostPosixInteropEnabled)
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

static if (hostPosixInteropEnabled)
@nogc nothrow private ManifestHandle openManifestFromPath(immutable(char)[] path, immutable(char)[] mode)
{
    if (path.ptr is null || path.length == 0 || mode.ptr is null)
    {
        return null;
    }

    return fopen(path.ptr, mode.ptr);
}

static if (hostPosixInteropEnabled)
@nogc nothrow private void closeManifest(ManifestHandle handle)
{
    if (handle !is null)
    {
        fclose(handle);
    }
}

static if (hostPosixInteropEnabled)
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

@nogc nothrow private bool parseManifestLine(immutable(char)[] line, out immutable(char)[] canonical, out immutable(char)[] hostPath)
{
    canonical = null;
    hostPath = null;

    if (line.length == 0)
    {
        return false;
    }

    size_t firstTab = findChar(line, '\t');
    if (firstTab == line.length)
    {
        return false;
    }

    size_t secondTab = findChar(line[firstTab + 1 .. $], '\t');
    if (secondTab == line.length - (firstTab + 1))
    {
        return false;
    }

    secondTab += firstTab + 1;

    canonical = line[firstTab + 1 .. secondTab];
    hostPath = line[secondTab + 1 .. $];

    return canonical.length != 0 && hostPath.length != 0;
}

@nogc nothrow private size_t findChar(immutable(char)[] text, char needle)
{
    foreach (index, ch; text)
    {
        if (ch == needle)
        {
            return index;
        }
    }
    return text.length;
}

@nogc nothrow private immutable(char)[] canonicalBase(immutable(char)[] canonical)
{
    size_t start = canonical.length;
    while (start > 0)
    {
        if (canonical[start - 1] == '/')
        {
            break;
        }
        --start;
    }
    return canonical[start .. $];
}

@nogc nothrow private void setStorageSlice(ref char[MAX_CANONICAL_LENGTH] storage, immutable(char)[] source, out immutable(char)[] slice)
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

@nogc nothrow private void setStorageSlice(ref char[MAX_HOST_PATH_LENGTH] storage, immutable(char)[] source, out immutable(char)[] slice)
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

@nogc nothrow private void determineRootPath(immutable(char)[] hostPath)
{
    size_t length = hostPath.length;
    while (length > 0 && hostPath[length - 1] != '/')
    {
        --length;
    }

    if (length > g_rootStorage.length - 1)
    {
        length = g_rootStorage.length - 1;
    }

    foreach (index; 0 .. length)
    {
        g_rootStorage[index] = hostPath[index];
    }

    if (length < g_rootStorage.length)
    {
        g_rootStorage[length] = '\0';
    }

    g_rootLength = length;
}

@nogc nothrow private size_t cStringLength(const(char)* text, size_t limit)
{
    if (text is null || limit == 0)
    {
        return 0;
    }

    size_t length = 0;
    while (length < limit && text[length] != '\0')
    {
        ++length;
    }

    return length;
}

@nogc nothrow private immutable(char)[] canonicalizeHostPath(immutable(char)[] hostPath, ref char[MAX_HOST_PATH_LENGTH] buffer)
{
    if (hostPath.length == 0)
    {
        return hostPath;
    }

    if (hostPath[0] == '/')
    {
        return hostPath;
    }

    auto cwd = getcwd(buffer.ptr, buffer.length);
    if (cwd is null)
    {
        return hostPath;
    }

    size_t limit = (buffer.length == 0) ? 0 : buffer.length - 1;
    size_t cwdLength = cStringLength(buffer.ptr, limit);
    if (cwdLength > limit)
    {
        cwdLength = limit;
    }

    if (cwdLength != 0 && cwdLength < limit && buffer[cwdLength - 1] != '/')
    {
        buffer[cwdLength] = '/';
        ++cwdLength;
    }

    size_t copyLength = hostPath.length;
    if (cwdLength >= limit)
    {
        copyLength = 0;
    }
    else if (cwdLength + copyLength > limit)
    {
        copyLength = limit - cwdLength;
    }

    foreach (index; 0 .. copyLength)
    {
        buffer[cwdLength + index] = hostPath[index];
    }

    size_t total = cwdLength + copyLength;
    if (total > limit)
    {
        total = limit;
    }

    if (total < buffer.length)
    {
        buffer[total] = '\0';
    }

    return cast(immutable(char)[])buffer[0 .. total];
}

// --- Execution helpers ---------------------------------------------------

static if (hostPosixInteropEnabled)
@nogc nothrow private const(char)* resolveEmbeddedUtility(const(char)* program)
{
    if (program is null)
    {
        return null;
    }

    auto index = locateEmbeddedUtility(program);
    if (index < 0)
    {
        return null;
    }

    return g_hostStorage[index].ptr;
}

static if (hostPosixInteropEnabled)
@nogc nothrow private int locateEmbeddedUtility(const(char)* program)
{
    foreach (index; 0 .. g_embeddedPosixUtilityCount)
    {
        if (cStringEquals(program, g_canonicalStorage[index].ptr))
        {
            return cast(int)index;
        }
    }

    foreach (index; 0 .. g_embeddedPosixUtilityCount)
    {
        if (cStringEquals(program, g_baseStorage[index].ptr))
        {
            return cast(int)index;
        }
    }

    return -1;
}

static if (hostPosixInteropEnabled)
@nogc nothrow private bool isExecutable(const(char)* path)
{
    if (path is null)
    {
        return false;
    }

    return access(path, X_OK) == 0;
}

static if (hostPosixInteropEnabled)
package(anonymos) @nogc nothrow bool spawnAndWait(const(char)* program, char** argv, char** envp, out int exitCode)
{
    exitCode = 127;
    if (program is null || program[0] == '\0')
    {
        return false;
    }

    auto child = fork();
    if (child < 0)
    {
        return false;
    }

    if (child == 0)
    {
        auto env = (envp is null) ? environ : envp;
        execve(program, argv, env);
        _exit(127);
    }

    int status = 0;
    for (;;) // wait until child exits
    {
        auto result = waitpid(child, &status, 0);
        if (result < 0)
        {
            return false;
        }
        if (result == child)
        {
            break;
        }
    }

    exitCode = decodeWaitStatus(status);
    return true;
}

static if (hostPosixInteropEnabled)
@nogc nothrow private int decodeWaitStatus(int status)
{
    enum int EXIT_MASK = 0xFF00;
    enum int SIGNAL_MASK = 0x7F;

    if ((status & SIGNAL_MASK) == 0)
    {
        return (status & EXIT_MASK) >> 8;
    }

    const int signal = status & SIGNAL_MASK;
    return 128 + signal;
}

static if (hostPosixInteropEnabled)
@nogc nothrow private bool cStringEquals(const(char)* lhs, const(char)* rhs)
{
    if (lhs is null || rhs is null)
    {
        return false;
    }

    size_t index = 0;
    while (lhs[index] != '\0' && rhs[index] != '\0')
    {
        if (lhs[index] != rhs[index])
        {
            return false;
        }
        ++index;
    }

    return lhs[index] == '\0' && rhs[index] == '\0';
}

static if (hostPosixInteropEnabled)
{
    alias pid_t = int;

    extern(C) @nogc nothrow
    {
        pid_t fork();
        int execve(const(char)*, char**, char**);
        pid_t waitpid(pid_t, int*, int);
        void _exit(int);
        int access(const(char)*, int);
        void* fopen(const(char)*, const(char)*);
        int fclose(void*);
        char* fgets(char*, int, void*);
        char* getcwd(char*, size_t);
        char* getenv(const(char)*);
    }

    enum int X_OK = 1;
}
else
{
    private struct EmbeddedManifestState
    {
        immutable(char)[] data;
        size_t cursor;
    }

    private enum immutable(char)[] embeddedManifestData = (()
    {
        static if (__traits(compiles, { enum content = import(hostPosixUtilityManifestPath); }))
        {
            return import(hostPosixUtilityManifestPath);
        }
        else static if (__traits(compiles, { enum content = import(posixUtilityManifestPath); }))
        {
            return import(posixUtilityManifestPath);
        }
        else static if (__traits(compiles, { enum content = import(hostFallbackPosixUtilityManifestPath); }))
        {
            return import(hostFallbackPosixUtilityManifestPath);
        }
        else static if (__traits(compiles, { enum content = import(fallbackPosixUtilityManifestPath); }))
        {
            return import(fallbackPosixUtilityManifestPath);
        }
        else
        {
            return cast(immutable(char)[])"";
        }
    })();

    private __gshared EmbeddedManifestState g_embeddedManifestState;

    @nogc nothrow private ManifestHandle openManifest()
    {
        if (embeddedManifestData.length == 0)
        {
            return null;
        }

        g_embeddedManifestState.data = embeddedManifestData;
        g_embeddedManifestState.cursor = 0;
        return cast(ManifestHandle)&g_embeddedManifestState;
    }

    @nogc nothrow private void closeManifest(ManifestHandle)
    {
    }

    @nogc nothrow private immutable(char)[] readManifestLine(ManifestHandle handle, char[] buffer)
    {
        if (handle is null || buffer.length == 0)
        {
            return null;
        }

        auto state = cast(EmbeddedManifestState*)handle;
        if (state.data.length == 0 || state.cursor >= state.data.length)
        {
            return null;
        }

        size_t length = 0;
        while (state.cursor < state.data.length && length + 1 < buffer.length)
        {
            immutable char ch = state.data[state.cursor++];
            if (ch == '\n' || ch == '\r')
            {
                if (ch == '\r' && state.cursor < state.data.length && state.data[state.cursor] == '\n')
                {
                    ++state.cursor;
                }
                break;
            }

            buffer[length++] = ch;
        }

        buffer[length] = '\0';
        return cast(immutable(char)[])buffer[0 .. length];
    }

    @nogc nothrow private const(char)* resolveEmbeddedUtility(const(char)*)
    {
        return null;
    }

    @nogc nothrow private int locateEmbeddedUtility(const(char)*)
    {
        return -1;
    }

    @nogc nothrow private bool isExecutable(const(char)*)
    {
        return false;
    }

    package(anonymos) @nogc nothrow bool spawnAndWait(const(char)*, char**, char**, out int)
    {
        return false;
    }

    extern(C) @nogc nothrow char* getcwd(char*, size_t)
    {
        return null;
    }

    enum int X_OK = 0;
}
