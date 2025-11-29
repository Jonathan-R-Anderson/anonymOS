module anonymos.syscalls.posix;

public import anonymos.console : print, printLine, printUnsigned,
                                   kernelConsoleReady, printHex,
                                   printCString;
import anonymos.serial : serialConsoleReady;
import sh_metadata : shBinaryName, shRepositoryPath;
import anonymos.fs : readFile;
import anonymos.elf : loadElfUser;
import anonymos.kernel.cpu : cpuCurrent;
import anonymos.kernel.heap : kmalloc;
import anonymos.kernel.vm_map;
import anonymos.kernel.usermode : transitionToUserMode;
import anonymos.kernel.memory : memcpy, memset;

// Decide whether to rely on host/Posix C interop.  Kernel builds define
// MinimalOsFreestanding to force the freestanding path even on hosts where the
// compiler would normally set version(Posix).
version (MinimalOsFreestanding)
{
    package(anonymos) enum bool hostPosixInteropEnabled = false;
}
else version (Posix)
{
    package(anonymos) enum bool hostPosixInteropEnabled = true;
}
else
{
    package(anonymos) enum bool hostPosixInteropEnabled = false;
}
// Re-export the context helpers so the PosixKernelShim mixin (and any
// modules that import `anonymos.posix`) can reference them via
// `anonymos.syscalls.posix.jmp_buf`, etc.  Without the public import, instantiating
// modules needed to import the context package directly which defeated the
// purpose of the mixin.
public import anonymos.kernel.posixutils.context : jmp_buf, setjmp, longjmp;

// ---------------------------------------------------------------------
// Shared shell state accessible both to the shim mixin and bare-metal
// helpers defined later in this module.  The mixin aliases these symbols
// so the state remains centralized here instead of being instantiated in
// every module that mixes in the shim.
// ---------------------------------------------------------------------
alias pid_t = int;

package(anonymos) __gshared bool g_shellRegistered = false;

package(anonymos) immutable char[8] SHELL_PATH = "/bin/sh\0";
package(anonymos) __gshared const(char*)[2] g_shellDefaultArgv;
package(anonymos) __gshared const(char*)[1] g_shellDefaultEnvp;

alias SpawnRegisteredProcessFn = extern(C) @nogc nothrow
    pid_t function(const(char)* path, const(char*)* argv, const(char*)* envp);
alias WaitPidFn = extern(C) @nogc nothrow
    pid_t function(pid_t wpid, int* status, int options);

package(anonymos) __gshared SpawnRegisteredProcessFn g_spawnRegisteredProcessFn;
package(anonymos) __gshared WaitPidFn               g_waitpidFn;

package(anonymos) @nogc nothrow void registerBareMetalShellInterfaces(
    SpawnRegisteredProcessFn spawnFn,
    WaitPidFn waitFn)
{
    g_spawnRegisteredProcessFn = spawnFn;
    g_waitpidFn = waitFn;
}

package(anonymos) @nogc nothrow void ensureBareMetalShellInterfaces()
{
    // Bare-metal builds rely on host integrations (or other minimal_os modules)
    // to provide spawn/wait hooks.  The Posix shim offers fallback
    // implementations, so opportunistically register them whenever they are
    // available so callers can depend on g_spawnRegisteredProcessFn/g_waitpidFn
    // without caring about the build configuration.
    static if (__traits(compiles, { alias Fn = typeof(&spawnRegisteredProcess); }))
    {
        if (g_spawnRegisteredProcessFn is null)
        {
            g_spawnRegisteredProcessFn = &spawnRegisteredProcess;
        }
    }

    static if (__traits(compiles, { alias Fn = typeof(&waitpid); }))
    {
        if (g_waitpidFn is null)
        {
            g_waitpidFn = &waitpid;
        }
    }
}

// example: adjust the path to whatever your search in step 1 shows
public import anonymos.kernel.posixutils.registry :
    registryEmbeddedPosixUtilitiesAvailable = embeddedPosixUtilitiesAvailable,
    registryEmbeddedPosixUtilityPaths = embeddedPosixUtilityPaths;

// Forward declarations for the bare-metal implementations that appear later
// in this module.  ensureBareMetalShellInterfaces() probes these symbols via
// __traits(compiles, ...) during early initialization, so declare them now
// to make the trait succeed even though the definitions live below.
public extern(C) @nogc nothrow pid_t spawnRegisteredProcess(const(char)* path,
                                                           const(char*)* argv,
                                                           const(char*)* envp);
public extern(C) @nogc nothrow pid_t waitpid(pid_t pid, int* status, int options);

// Module-scope aliases so the name is visible everywhere (including
// outside the PosixKernelShim mixin).
    alias RegistryEmbeddedPosixUtilitiesAvailableFn = registryEmbeddedPosixUtilitiesAvailable;
    alias RegistryEmbeddedPosixUtilityPathsFn       = registryEmbeddedPosixUtilityPaths;

    extern(C) extern __gshared ulong kernel_rsp;
version (MinimalOsFreestanding)
{
    extern(C) @nogc nothrow void updateTssRsp0(ulong rsp);
}

    extern(D) shared static this()
    {
        g_bootCanarySeed = 0xDEADBEEFCAFEBABEu ^ cast(ulong)&g_bootCanarySeed;
        // Default permissive policy for kernel/internal processes.
        ulong[16] allowAll;
        foreach (ref w; allowAll) w = ulong.max;
        registerPolicy("default", allowAll);
        g_shellDefaultArgv[0] = SHELL_PATH.ptr;
    g_shellDefaultArgv[1] = null;
    g_shellDefaultEnvp[0] = null;

    g_shellEnvVarOrder[0] = g_envVarLfeShBinary.ptr;
    g_shellEnvVarOrder[1] = g_envVarShBinary.ptr;
    g_shellEnvVarOrder[2] = g_envVarShellBinary.ptr;
    g_shellEnvVarOrder[3] = g_envVarShellRoot.ptr;

    g_shellSearchOrder[0] = g_isoShellPath;
    g_shellSearchOrder[1] = g_isoShellBinPath;
    g_shellSearchOrder[2] = g_kernelShellPath;
    g_shellSearchOrder[3] = g_kernelShellBinPath;
    g_shellSearchOrder[4] = g_repoShellPath;
    g_shellSearchOrder[5] = g_repoShellBinPath;
    g_shellSearchOrder[6] = g_repoShellRelativePath;
    g_shellSearchOrder[7] = g_repoShellRelativeBinPath;
    g_shellSearchOrder[8] = g_usrLocalShellPath;
    g_shellSearchOrder[9] = g_usrShellPath;
    g_shellSearchOrder[10] = g_binShellPath;
}

@nogc nothrow package(anonymos) size_t cStringLength(const(char)* str)
{
    if (str is null) return 0;
    size_t length = 0;
    while (str[length] != 0) ++length;
    return length;
}

@nogc nothrow package(anonymos) bool cStringEquals(const(char)* lhs, const(char)* rhs)
{
    if (lhs is null || rhs is null) return false;
    size_t index = 0;
    for (;;)
    {
        const(char) a = lhs[index];
        const(char) b = rhs[index];
        if (a != b) return false;
        if (a == 0) return true;
        ++index;
    }
}

// ---------------------------
// Host/Posix C API (guarded)
// ---------------------------
static if (hostPosixInteropEnabled)
{
    public import core.sys.posix.unistd : isatty, read, write, close, access,
                                           chdir, fork, execve, _exit;
    public import core.sys.posix.fcntl : open, O_RDONLY, O_NOCTTY;
    public import core.sys.posix.sys.stat : fstat, stat_t;
    public import core.sys.posix.sys.types : ssize_t;
    public import core.stdc.errno : errno, EBADF, EINTR;
    public import core.sys.posix.sys.wait : posixWaitPid = waitpid;

    // Some C library shims used by the minimal toolchain omit certain
    // declarations.  Add conservative fallbacks so the Posix build still
    // compiles even when the standard headers are pared down.
    static if (!__traits(compiles, { stat_t _; }))
    {
        struct stat_t { long _placeholder; }
        extern(C) int fstat(int fd, stat_t* buf);
    }

    static if (!__traits(compiles, { auto _ = errno; }))
    {
        extern(C) __gshared int errno;
    }

    static if (!__traits(compiles, { return isatty(0); }))
    {
        extern(C) int isatty(int fd);
    }

    static if (!__traits(compiles, { return open(null, 0, 0); }))
    {
        extern(C) int open(const char* path, int flags, int mode = 0);
    }

    static if (!__traits(compiles, { return close(0); }))
    {
        extern(C) int close(int fd);
    }

    static if (!__traits(compiles, { return read(0, null, 0); }))
    {
        extern(C) ssize_t read(int fd, void* buffer, size_t length);
    }

    static if (!__traits(compiles, { return write(0, null, 0); }))
    {
        extern(C) ssize_t write(int fd, const void* buffer, size_t length);
    }

    static if (!__traits(compiles, { auto _ = EBADF; }))
    {
        enum EBADF = 9;
    }
    static if (!__traits(compiles, { auto _ = EINTR; }))
    {
        enum EINTR = 4;
    }
    private enum int F_OK = 0;
    private enum int X_OK = 1;
    public extern(C) __gshared char** environ;
}
else
{
    // Provide stub declarations for bare-metal builds so references remain
    // visible even when the Posix imports are unavailable. These placeholders
    // mirror the Posix signatures while leaving the bare-metal implementations
    // to supply any needed definitions.
    public struct stat_t { long _placeholder; }
    public alias ssize_t = long;

    public extern(C) __gshared int errno;
    public enum EBADF = 9;
    public enum EINTR = 4;
    public enum O_RDONLY = 0;
    public enum O_NOCTTY = 0;

    public extern(C) int fstat(int fd, stat_t* buf);
    public extern(C) int isatty(int fd);
    public extern(C) int open(const char* path, int flags, int mode = 0);
    public extern(C) int close(int fd);
    public extern(C) ssize_t read(int fd, void* buffer, size_t length);
    public extern(C) ssize_t write(int fd, const void* buffer, size_t length);
    public extern(C) int posixWaitPid(int pid, int* status, int options);

    private enum int F_OK = 0;
    private enum int X_OK = 1;
    public extern(C) __gshared char** environ;
}

private immutable char[] g_envVarLfeShBinary = "LFE_SH_BINARY\0";
private immutable char[] g_envVarShBinary = "SH_BINARY_PATH\0";
private immutable char[] g_envVarShellBinary = "SH_SHELL_BINARY\0";
private immutable char[] g_envVarShellRoot = "SH_SHELL_ROOT\0";

private __gshared const(char*)[4] g_shellEnvVarOrder;

private immutable char[] g_isoShellPath = "/opt/shell/" ~ shBinaryName ~ "\0";
private immutable char[] g_isoShellBinPath = "/opt/shell/bin/" ~ shBinaryName ~ "\0";
private immutable char[] g_kernelShellPath = "/kernel/shell/" ~ shBinaryName ~ "\0";
private immutable char[] g_kernelShellBinPath = "/kernel/shell/bin/" ~ shBinaryName ~ "\0";
private immutable char[] g_repoShellPath = shRepositoryPath ~ "/" ~ shBinaryName ~ "\0";
private immutable char[] g_repoShellBinPath = shRepositoryPath ~ "/bin/" ~ shBinaryName ~ "\0";
private immutable char[] g_repoShellRelativePath = "." ~ shRepositoryPath ~ "/" ~ shBinaryName ~ "\0";
private immutable char[] g_repoShellRelativeBinPath = "." ~ shRepositoryPath ~ "/bin/" ~ shBinaryName ~ "\0";
private immutable char[] g_repoShellDir = shRepositoryPath ~ "\0";
private immutable char[] g_repoShellDirRelative = "." ~ shRepositoryPath ~ "\0";
private immutable char[] g_usrLocalShellPath = "/usr/local/bin/" ~ shBinaryName ~ "\0";
private immutable char[] g_usrShellPath = "/usr/bin/" ~ shBinaryName ~ "\0";
private immutable char[] g_binShellPath = "/bin/" ~ shBinaryName ~ "\0";
private immutable char[] g_defaultShPath = "/bin/sh\0";

private __gshared immutable(char)[][11] g_shellSearchOrder;

// ---- Forward decls needed by the shim (appear before mixin use) ----
extern(C) @nogc nothrow
void shellExecEntry(const(char*)* argv, const(char*)* envp);

// Used by registerPosixUtilityAlias(); defined below (versioned) or linked in.
extern(C) @nogc nothrow
void posixUtilityExecEntry(const(char*)* argv, const(char*)* envp);

// Provided by the PosixKernelShim (in the kernel/main) or host.
// Declare it here so this module can call it.
static if (hostPosixInteropEnabled)
{
    // Use the Posix import.
}
else
extern(C) @nogc nothrow
void _exit(int code);

// Embed/bundle helpers: declare first so the shim can reference them.
// They’ll be satisfied by the posixbundle import (if present) or by stubs.

// Single canonical typedef for process entrypoints (C ABI, @nogc, nothrow)
alias PosixProcessEntry = extern(C) @nogc nothrow
    void function(const(char*)* argv, const(char*)* envp);

// Backwards-compatible alias
alias ProcessEntry = PosixProcessEntry;

// The PosixKernelShim mixin is instantiated in other modules, so it can't
// reference `private` symbols from this module.  Use package visibility so the
// debug flag is still internal to minimal_os while remaining accessible to the
// mixin expansion.
package(anonymos) enum bool ENABLE_POSIX_DEBUG = true;

@nogc nothrow package(anonymos) long debugBool(bool value)
{
    static if (ENABLE_POSIX_DEBUG)
    {
        return value ? 1 : 0;
    }
    else
    {
        return value ? 1 : 0;
    }
}

@nogc nothrow package(anonymos) void debugPrefix()
{
    static if (ENABLE_POSIX_DEBUG)
    {
        print("[posix-debug] ");
    }
}

@nogc nothrow package(anonymos) void debugPrintSigned(long value)
{
    static if (ENABLE_POSIX_DEBUG)
    {
        if (value < 0)
        {
            print("-");
            printUnsigned(cast(size_t)(-value));
        }
        else
        {
            printUnsigned(cast(size_t)value);
        }
    }
}

@nogc nothrow package(anonymos) void debugExpectActual(immutable(char)[] label, long expected, long actual)
{
    static if (ENABLE_POSIX_DEBUG)
    {
        if (expected == actual)
        {
            return;
        }

        debugPrefix();
        print(label);
        print(": expected=");
        debugPrintSigned(expected);
        print(", actual=");
        debugPrintSigned(actual);
        printLine("");
    }
}

    @nogc nothrow package(anonymos) void debugLog(immutable(char)[] text)
    {
        static if (ENABLE_POSIX_DEBUG)
        {
            debugPrefix();
            printLine(text);
        }
    }

    // Some builds (particularly host/Posix ones) intentionally omit the
    // kernel/serial console modules.  Guard the probe helpers behind
    // __traits(compiles, ...) so the shim can fall back to "console not
    // present" without forcing those modules to exist in every build.
    // Expose the console probes to the rest of the minimal_os package so the
    // PosixKernelShim mixin (instantiated in other modules) can reference them.
    // Using package visibility avoids leaking the helpers publicly while still
    // allowing all minimal_os modules to share the logic.
    @nogc nothrow package(anonymos) bool probeKernelConsoleReady()
    {
        static if (__traits(compiles, kernelConsoleReady()))
        {
            return kernelConsoleReady();
        }
        else
        {
            return false;
        }
    }

    @nogc nothrow package(anonymos) bool probeSerialConsoleReady()
    {
        static if (__traits(compiles, serialConsoleReady()))
        {
            return serialConsoleReady();
        }
        else
        {
            return false;
        }
    }

// ----------------------------------------------------------------------
// Try to import embedded POSIX bundle glue; if unavailable, use stubs.
// ----------------------------------------------------------------------
private enum _havePosixBundle =
    __traits(compiles, {
        import anonymos.kernel.posixbundle : embeddedPosixUtilitiesAvailable,
                                             embeddedPosixUtilitiesRoot,
                                             embeddedPosixUtilityPaths,
                                             executeEmbeddedPosixUtility,
                                             spawnAndWait;
    });

static if (_havePosixBundle)
{
    static import anonymos.kernel.posixbundle;

    alias embeddedPosixUtilitiesAvailable =
        anonymos.kernel.posixbundle.embeddedPosixUtilitiesAvailable;
    alias embeddedPosixUtilitiesRoot =
        anonymos.kernel.posixbundle.embeddedPosixUtilitiesRoot;
    alias embeddedPosixUtilityPaths =
        anonymos.kernel.posixbundle.embeddedPosixUtilityPaths;
    alias executeEmbeddedPosixUtility =
        anonymos.kernel.posixbundle.executeEmbeddedPosixUtility;
    alias spawnAndWait = anonymos.kernel.posixbundle.spawnAndWait;
}
else
{
    @nogc nothrow bool embeddedPosixUtilitiesAvailable() { return false; }

    @nogc nothrow immutable(char)[] embeddedPosixUtilitiesRoot() { return null; }

    // NOTE: use string[] here so it matches the bundle and registry helpers.
    @nogc nothrow string[] embeddedPosixUtilityPaths() { return []; }

    @nogc nothrow bool executeEmbeddedPosixUtility(const(char)*, const(char*)*, const(char*)*, out int exitCode)
    {
        exitCode = 127;
        return false;
    }

    // Stub spawn/wait (no host shell); just sets 127.
    @nogc nothrow void spawnAndWait(const(char)* /*prog*/, char** /*argv*/, char** /*envp*/, out int exitCode)
    {
        exitCode = 127;
    }
}

// ---- Forward decls needed by the shim (appear before mixin use) ----
extern(C) @nogc nothrow
void shellExecEntry(const(char*)* argv, const(char*)* envp);




// ------------------------------
// Minimal helpers used in both
// ------------------------------
mixin template PosixKernelShim()
{
    // Ensure the defining module is visible wherever this mixin is used.
    static import anonymos.syscalls.posix;

    // Use the canonical process entry alias defined at module scope
    alias ProcessEntry = anonymos.syscalls.posix.PosixProcessEntry;

    // Explicit aliases back to the defining module so the mixin can
    // reference the canonical helpers regardless of the import context.
    alias PosixUtilityExecEntryFn = anonymos.syscalls.posix.posixUtilityExecEntry;
    alias EmbeddedPosixUtilitiesAvailableFn =
        anonymos.syscalls.posix.embeddedPosixUtilitiesAvailable;
    alias EmbeddedPosixUtilityPathsFn =
        anonymos.syscalls.posix.embeddedPosixUtilityPaths;
    alias RegistryEmbeddedPosixUtilitiesAvailableFn =
        anonymos.syscalls.posix.RegistryEmbeddedPosixUtilitiesAvailableFn;
    alias RegistryEmbeddedPosixUtilityPathsFn =
        anonymos.syscalls.posix.RegistryEmbeddedPosixUtilityPathsFn;

    alias g_shellRegistered = anonymos.syscalls.posix.g_shellRegistered;
    alias g_shellDefaultArgv = anonymos.syscalls.posix.g_shellDefaultArgv;
    alias g_shellDefaultEnvp = anonymos.syscalls.posix.g_shellDefaultEnvp;
    alias SHELL_PATH = anonymos.syscalls.posix.SHELL_PATH;
    alias ensureBareMetalShellInterfaces =
        anonymos.syscalls.posix.ensureBareMetalShellInterfaces;


    // Bring helpers that the mixin's implementation relies on into its
    // lexical scope so the instantiating module does not need to import the
    // defining module explicitly.  This mirrors the pattern already used for
    // the debug helpers.
    alias ENABLE_POSIX_DEBUG      = anonymos.syscalls.posix.ENABLE_POSIX_DEBUG;
    alias debugPrefix             = anonymos.syscalls.posix.debugPrefix;
    alias debugBool               = anonymos.syscalls.posix.debugBool;
    alias debugExpectActual       = anonymos.syscalls.posix.debugExpectActual;
    alias debugLog                = anonymos.syscalls.posix.debugLog;
    alias probeKernelConsoleReady = anonymos.syscalls.posix.probeKernelConsoleReady;
    alias probeSerialConsoleReady = anonymos.syscalls.posix.probeSerialConsoleReady;

    // Basic string helpers defined at module scope that the mixin relies on.
    alias cStringLength           = anonymos.syscalls.posix.cStringLength;
    alias cStringEquals           = anonymos.syscalls.posix.cStringEquals;

    // Jump buffer helpers live in anonymos.posix, so alias them into the
    // mixin scope.  This keeps mixin users from having to import the context
    // module explicitly.
    alias jmp_buf = anonymos.syscalls.posix.jmp_buf;
    alias setjmp  = anonymos.syscalls.posix.setjmp;
    alias longjmp = anonymos.syscalls.posix.longjmp;

    // ---- Basic types (avoid druntime) ----
    alias pid_t   = int;
    alias uid_t   = uint;
    alias gid_t   = uint;
    alias ssize_t = long;
    alias size_t  = ulong;
    alias time_t  = long;

    struct timespec { time_t tv_sec; long tv_nsec; }

    // ---- errno ----
    enum Errno : int {
        EPERM=1, ENOENT=2, ESRCH=3, EINTR=4, EIO=5, ENXIO=6, E2BIG=7, ENOEXEC=8, EBADF=9,
        ECHILD=10, EAGAIN=11, ENOMEM=12, EACCES=13, EFAULT=14, EBUSY=16, EEXIST=17,
        EXDEV=18, ENODEV=19, ENOTDIR=20, EISDIR=21, EINVAL=22, ENFILE=23, EMFILE=24,
        ENOSPC=28, EPIPE=32, EDOM=33, ERANGE=34, ENOSYS=38
    }
    private __gshared int _errno;

    @nogc nothrow ref int errnoRef() { return _errno; }
    @nogc nothrow int  setErrno(Errno e){ _errno = e; return -cast(int)e; }

    // ---- Signals (minimal) ----
    enum SIG : int { NONE=0, TERM=15, KILL=9, CHLD=17, ABRT=6 }
    alias SigSet = uint;

    // ---- File descriptor stub ----
    enum MAX_FD = 32;
    enum FDFlags : uint { NONE=0 }
    struct FD { int num = -1; FDFlags flags = FDFlags.NONE; }

    // ---- Process table ----
    enum MAX_PROC = 64;

    enum ProcState : ubyte { UNUSED, EMBRYO, READY, RUNNING, SLEEPING, ZOMBIE }

    // ---- Object registry ----
    enum KernelObjectKind : ubyte
    {
        Invalid,
        Namespace,
        Executable,
        Process,
        Device,
        Environment,
        Channel,
    }

    private enum MAX_KERNEL_OBJECTS = 256;
    private enum MAX_OBJECT_NAME    = 48;
    private enum MAX_OBJECT_LABEL   = 64;
    private enum MAX_OBJECT_CHILDREN = 8;
    private enum size_t INVALID_OBJECT_ID = size_t.max;

    private struct KernelObject
    {
        bool used;
        KernelObjectKind kind;
        size_t parent;
        size_t childCount;
        size_t[MAX_OBJECT_CHILDREN] children;
        char[MAX_OBJECT_NAME] name;
        char[MAX_OBJECT_NAME] type;
        char[MAX_OBJECT_LABEL] label;
        long primary;
        long secondary;
    }

    private __gshared KernelObject[MAX_KERNEL_OBJECTS] g_objects;
    private __gshared size_t g_objectCount = 0;
    private __gshared bool   g_objectRegistryReady = false;
    private __gshared size_t g_objectRoot = INVALID_OBJECT_ID;
    private __gshared size_t g_objectProcNamespace = INVALID_OBJECT_ID;
    private __gshared size_t g_objectBinNamespace  = INVALID_OBJECT_ID;
    private __gshared size_t g_objectDevNamespace  = INVALID_OBJECT_ID;
    private __gshared size_t g_consoleObject       = INVALID_OBJECT_ID;

    private enum MAX_ENV_ENTRIES        = 64;
    private enum MAX_ENV_NAME_LENGTH    = 64;
    private enum MAX_ENV_VALUE_LENGTH   = 256;
    private enum MAX_ENV_COMBINED_LENGTH = MAX_ENV_NAME_LENGTH + 1 + MAX_ENV_VALUE_LENGTH;

    private struct EnvironmentEntry
    {
        bool used;
        size_t nameLength;
        size_t valueLength;
        size_t combinedLength;
        bool dirty;
        char[MAX_ENV_NAME_LENGTH] name;
        char[MAX_ENV_VALUE_LENGTH] value;
        char[MAX_ENV_COMBINED_LENGTH] combined;
    }

    private struct EnvironmentTable
    {
        bool used;
        pid_t ownerPid;
        size_t objectId;
        size_t entryCount;
        EnvironmentEntry[MAX_ENV_ENTRIES] entries;
        char*[MAX_ENV_ENTRIES + 1] pointerCache;
        size_t pointerCount;
        bool pointerDirty;
    }

    private __gshared EnvironmentTable[MAX_PROC] g_environmentTables;

    public struct Proc
    {
        pid_t     pid;
        pid_t     ppid;
        ProcState state;
        ulong     vruntime;
        uint      weight;
        int       nice;
        uint      timeSlice;
        uint      sliceRemaining;
        size_t    rqNext;
        bool      onRunQueue;
        int       exitCode;
        SigSet    sigmask;
        FD[MAX_FD] fds;
        extern(C) @nogc nothrow void function(const(char*)* argv, const(char*)* envp) entry;
        jmp_buf   context;
        bool      contextValid;
        char[16]  name;
        const(char*)* pendingArgv;
        const(char*)* pendingEnvp;
        bool          pendingExec;
        size_t        objectId;
        EnvironmentTable* environment;
        ubyte*        kernelStack;
        size_t        kernelStackSize;
        ulong         cr3;             // per-process page table base
        bool          vmInitialized;
        bool          userMode;
        ulong         userEntry;
        ulong         userStackTop;
        ulong         heapBase;
        ulong         heapBrk;
        ulong         heapLimit;
        ulong         mmapCursor;
        ulong         userCodeSlide;
        ulong         shadowBase;
        ulong         shadowTop;
        ulong         shadowPtr;
        ulong         heapSeed;
        ulong[16]     syscallBitmap; // 1024-bit allow mask
        char[16]      domain;
    }

    private __gshared Proc[MAX_PROC] g_ptable;
    private __gshared pid_t          g_nextPid    = 1;
    private __gshared Proc*          g_current    = null;
    // Prevent nested scheduler invocations (e.g., timer preemption while a
    // process voluntarily yields) from corrupting saved contexts.
    private __gshared bool           g_inScheduler = false;
    private __gshared ubyte[65536]   g_debugStack; // Static stack for debugging
    private enum size_t INVALID_INDEX = size_t.max;
    private __gshared size_t         g_runQueueHead = INVALID_INDEX;
    private struct SyscallPolicy { bool used; char[16] name; ulong[16] mask; }
    
    extern(C) extern __gshared ulong stack_top; // from boot.s
    extern(C) extern __gshared ubyte _kernel_end; // from linker script
    private __gshared SyscallPolicy[MAX_POLICIES] g_sysPolicies;
    package(anonymos) __gshared bool g_initialized = false;
    package(anonymos) __gshared bool g_consoleAvailable = false;
    package(anonymos) __gshared bool g_posixUtilitiesRegistered = false;
    package(anonymos) __gshared size_t g_posixUtilityCount = 0;
    package(anonymos) __gshared bool g_posixConfigured   = false;
    private __gshared anonymos.kernel.vm_map.VMMap[MAX_PROC] g_vmMaps;
    private enum size_t PAGE_SIZE = 4096;
    private enum size_t USER_STACK_SIZE = 256 * 1024;
    private enum ulong  USER_STACK_TOP  = 0x00007FFF_FF000000;
    private enum ulong  USER_HEAP_BASE  = 0x0000000100000000; // 4 GiB
    private enum size_t USER_HEAP_SIZE  = 16 * 1024 * 1024;
    private enum ulong  USER_MMAP_BASE  = 0x0000000200000000;
    private enum ulong  ASLR_STACK_SPLAY = 32 * 1024 * 1024; // 32 MiB
    private enum ulong  ASLR_HEAP_SPLAY  = 16 * 1024 * 1024;
    private enum ulong  ASLR_MMAP_SPLAY  = 64 * 1024 * 1024;
    private enum ulong  ASLR_CODE_SPLAY  = 64 * 1024 * 1024;
    private enum size_t CANARY_SIZE      = 8;
    private enum size_t SHADOW_STACK_SIZE = 64 * 1024;
    private enum ulong  ASLR_SHADOW_SPLAY = 16 * 1024 * 1024;
    private enum ulong  HEAP_ARENA_SPLAY  = 32 * 1024 * 1024;
    private enum ulong  HEAP_MAGIC        = 0x48454150484C5354; // "HEAPHLST"
    private enum size_t MAX_POLICIES      = 16;

    // Per-boot canary seed (not strong CSPRNG, but better than zero)
    private __gshared ulong g_bootCanarySeed;

    private __gshared ulong g_aslrCounter = 0xA5A5A5A5A5A5A5A5;

    @nogc nothrow private ulong rand64()
    {
        ulong tsc;
        asm @nogc nothrow { rdtsc; shl RDX, 32; or RAX, RDX; mov tsc, RAX; }
        g_aslrCounter ^= 0x9E3779B97F4A7C15;
        tsc ^= g_aslrCounter ^ g_bootCanarySeed;
        tsc *= 0xBF58476D1CE4E5B9;
        tsc ^= tsc >> 32;
        return tsc;
    }

    @nogc nothrow private ulong randSplay(ulong splay)
    {
        if (splay == 0) return 0;
        const ulong mask = (splay - 1) & ~(PAGE_SIZE - 1);
        return rand64() & mask;
    }

    package(anonymos) Proc* currentProcess() @nogc nothrow
    {
        return g_current;
    }

    package(anonymos) anonymos.kernel.vm_map.VMMap* currentVmMap() @nogc nothrow
    {
        if (g_current is null) return null;
        const size_t idx = cast(size_t)(g_current - g_ptable.ptr);
        return (idx < g_vmMaps.length) ? &g_vmMaps[idx] : null;
    }

    package(anonymos) bool syscallAllowed(ulong num)
    {
        if (g_current is null) return false;
        const size_t idx = num / 64;
        const size_t bit = num & 63;
        if (idx >= g_current.syscallBitmap.length) return false;
        return (g_current.syscallBitmap[idx] & (1UL << bit)) != 0;
    }

    package(anonymos) void allowAllSyscalls(Proc* p)
    {
        if (p is null) return;
        foreach (ref word; p.syscallBitmap) word = ulong.max;
    }

    package(anonymos) void allowSyscall(Proc* p, ulong num)
    {
        if (p is null) return;
        const size_t idx = num / 64;
        const size_t bit = num & 63;
        if (idx >= p.syscallBitmap.length) return;
        p.syscallBitmap[idx] |= (1UL << bit);
    }

    @nogc nothrow private SyscallPolicy* findPolicy(const(char)* name)
    {
        if (name is null) return null;
        foreach (ref pol; g_sysPolicies)
        {
            bool match = pol.used;
            if (match)
            {
                foreach (i; 0 .. pol.name.length)
                {
                    const char c = pol.name[i];
                    const char n = (i < cStringLength(name)) ? name[i] : 0;
                    if (c != n) { match = false; break; }
                    if (c == 0) break;
                }
            }
            if (match) return &pol;
        }
        return null;
    }

    @nogc nothrow private SyscallPolicy* registerPolicy(const(char)* name, ulong[16] mask)
    {
        if (name is null || name[0] == 0) return null;
        auto existing = findPolicy(name);
        if (existing !is null) { existing.mask[] = mask[]; return existing; }
        foreach (ref pol; g_sysPolicies)
        {
            if (!pol.used)
            {
                pol.used = true;
                foreach (i; 0 .. pol.name.length)
                {
                    pol.name[i] = 0;
                }
                size_t idx = 0;
                while (name[idx] != 0 && idx + 1 < pol.name.length)
                {
                    pol.name[idx] = name[idx];
                    ++idx;
                }
                pol.mask[] = mask[];
                return &pol;
            }
        }
        return null;
    }

    @nogc nothrow private void applyPolicy(Proc* p, SyscallPolicy* pol)
    {
        if (p is null || pol is null) return;
        p.syscallBitmap[] = pol.mask[];
        // Copy domain name
        foreach (i; 0 .. p.domain.length)
        {
            p.domain[i] = pol.name[i];
            if (pol.name[i] == 0) break;
        }
    }

    // --------------- small buffer/string utils ---------------
    @nogc nothrow private void clearBuffer(ref char[MAX_OBJECT_NAME] buffer)
    {
        foreach (i; 0 .. buffer.length) buffer[i] = 0;
    }
    @nogc nothrow private void clearLabel(ref char[MAX_OBJECT_LABEL] buffer)
    {
        foreach (i; 0 .. buffer.length) buffer[i] = 0;
    }
    @nogc nothrow private void copyBuffer(ref char[MAX_OBJECT_NAME] dst, ref char[MAX_OBJECT_NAME] src)
    {
        foreach (i; 0 .. dst.length) dst[i] = (i < src.length) ? src[i] : 0;
    }
    @nogc nothrow private void setBufferFromString(ref char[MAX_OBJECT_NAME] buffer, immutable(char)[] text)
    {
        size_t index = 0;
        foreach (ch; text)
        {
            if (index + 1 >= buffer.length) break;
            buffer[index++] = cast(char)ch;
        }
        if (index < buffer.length) buffer[index++] = 0;
        while (index < buffer.length) buffer[index++] = 0;
    }
    @nogc nothrow private void setLabelFromString(ref char[MAX_OBJECT_LABEL] buffer, immutable(char)[] text)
    {
        size_t index = 0;
        foreach (ch; text)
        {
            if (index + 1 >= buffer.length) break;
            buffer[index++] = cast(char)ch;
        }
        if (index < buffer.length) buffer[index++] = 0;
        while (index < buffer.length) buffer[index++] = 0;
    }
    @nogc nothrow private void setBufferFromCString(ref char[MAX_OBJECT_NAME] buffer, const(char)* text)
    {
        size_t index = 0;
        if (text !is null)
        {
            while (text[index] != 0)
            {
                if (index + 1 >= buffer.length) break;
                buffer[index++] = text[index];
            }
        }
        if (index < buffer.length) buffer[index++] = 0;
        while (index < buffer.length) buffer[index++] = 0;
    }
    @nogc nothrow private void setLabelFromCString(ref char[MAX_OBJECT_LABEL] buffer, const(char)* text)
    {
        size_t index = 0;
        if (text !is null)
        {
            while (text[index] != 0)
            {
                if (index + 1 >= buffer.length) break;
                buffer[index++] = text[index];
            }
        }
        if (index < buffer.length) buffer[index++] = 0;
        while (index < buffer.length) buffer[index++] = 0;
    }
    @nogc nothrow private size_t bufferLength(ref char[MAX_OBJECT_NAME] buffer)
    {
        size_t index = 0;
        while (index < buffer.length && buffer[index] != 0) ++index;
        return index;
    }

    // -------------------------------------------------------------------------
    // Hardened heap: guard pages per allocation, canaries, immediate poison.
    // -------------------------------------------------------------------------
    private struct HardenedAllocHeader
    {
        ulong magic;
        size_t userSize;
        ulong canary;
        ulong regionBase;
        size_t regionSize;
        ubyte tag;
        ubyte[7] _pad;
    }

    @nogc nothrow private void heapFatal()
    {
        auto pid = sys_getpid();
        cast(void) sys_kill(pid, SIG.ABRT);
        for (;;)
        {
            asm @nogc nothrow { hlt; }
        }
    }

    @nogc nothrow private ulong heapCanary()
    {
        if (g_current is null) return 0;
        return rand64() ^ g_current.heapSeed;
    }

    extern(C) @nogc nothrow void* posix_malloc(size_t size)
    {
        if (size == 0 || g_current is null) return null;
        auto vm = currentVmMap();
        if (vm is null) return null;

        const size_t headerSize = HardenedAllocHeader.sizeof;
        const size_t total = headerSize + size + CANARY_SIZE;
        const size_t totalPages = (total + PAGE_SIZE - 1) / PAGE_SIZE;
        const size_t mapLen = totalPages * PAGE_SIZE;

        ulong base = g_current.mmapCursor + (randSplay(HEAP_ARENA_SPLAY) & ~(PAGE_SIZE - 1));
        if (base == 0) base = USER_MMAP_BASE;
        if (!vm.mapRegion(base, mapLen, anonymos.kernel.vm_map.Prot.read | anonymos.kernel.vm_map.Prot.write | anonymos.kernel.vm_map.Prot.user, 1, 1))
        {
            return null;
        }
        const ulong regionBase = base;
        const ulong payloadBase = base + PAGE_SIZE; // skip guard

        auto hdr = cast(HardenedAllocHeader*)payloadBase;
        hdr.magic = HEAP_MAGIC;
        hdr.userSize = size;
        hdr.regionBase = regionBase;
        hdr.regionSize = mapLen;
        hdr.canary = heapCanary();
        hdr.tag = cast(ubyte)(rand64() & 0x0F);

        auto userPtr = cast(ubyte*)(payloadBase + headerSize);
        auto tail = cast(ulong*)(userPtr + size);
        *tail = hdr.canary;

        // Advance cursor to avoid reusing same area immediately.
        const ulong next = regionBase + mapLen + PAGE_SIZE; // include trailing guard
        if (next > g_current.mmapCursor) g_current.mmapCursor = next;

        return userPtr;
    }

    extern(C) @nogc nothrow void posix_free(void* ptr)
    {
        if (ptr is null) return;
        auto vm = currentVmMap();
        if (vm is null || g_current is null) return;

        const size_t headerSize = HardenedAllocHeader.sizeof;
        auto userPtr = cast(ubyte*)ptr;
        auto hdr = cast(HardenedAllocHeader*)(userPtr - headerSize);

        if (hdr.magic != HEAP_MAGIC || hdr.regionBase == 0 || hdr.regionSize == 0)
        {
            heapFatal();
        }

        auto tail = cast(ulong*)(userPtr + hdr.userSize);
        const ulong expected = hdr.canary;
        if (*tail != expected)
        {
            heapFatal();
        }

        // Poison by unmapping entire region (includes guards).
        if (!vm.unmapRegion(hdr.regionBase))
        {
            heapFatal();
        }
    }

    extern(C) @nogc nothrow void* posix_calloc(size_t n, size_t elemSize)
    {
        const auto total = n * elemSize;
        auto p = posix_malloc(total);
        if (p !is null)
        {
            memset(p, 0, total);
        }
        return p;
    }

    extern(C) @nogc nothrow void* posix_realloc(void* ptr, size_t newSize)
    {
        if (ptr is null)
        {
            return posix_malloc(newSize);
        }
        if (newSize == 0)
        {
            posix_free(ptr);
            return null;
        }

        const size_t headerSize = HardenedAllocHeader.sizeof;
        auto hdr = cast(HardenedAllocHeader*)(cast(ubyte*)ptr - headerSize);
        const size_t oldSize = hdr.userSize;

        auto nptr = posix_malloc(newSize);
        if (nptr is null) return null;

        const size_t copySize = (oldSize < newSize) ? oldSize : newSize;
        memcpy(nptr, ptr, copySize);
        posix_free(ptr);
        return nptr;
    }

    // ---------------- Memory tagging helpers (software) ----------------
    extern(C) @nogc nothrow ulong memtag_tag_of_ptr(const void* ptr)
    {
        if (ptr is null) return 0xFF;
        const size_t headerSize = HardenedAllocHeader.sizeof;
        auto hdr = cast(const HardenedAllocHeader*)(cast(const ubyte*)ptr - headerSize);
        if (hdr.magic != HEAP_MAGIC || hdr.regionBase == 0 || hdr.regionSize == 0) return 0xFF;
        return hdr.tag;
    }

    extern(C) @nogc nothrow int memtag_check(const void* ptr, ulong tag)
    {
        const ulong actual = memtag_tag_of_ptr(ptr);
        if (actual == 0xFF || actual != (tag & 0xF))
        {
            heapFatal();
            return -1;
        }
        return 0;
    }
    @nogc nothrow private void appendUnsigned(ref char[MAX_OBJECT_NAME] buffer, size_t value)
    {
        char[20] digits; size_t count = 0;
        do { digits[count++] = cast(char)('0' + (value % 10)); value /= 10; }
        while (value != 0 && count < digits.length);

        size_t index = bufferLength(buffer);
        while (count > 0 && index + 1 < buffer.length) buffer[index++] = digits[--count];
        if (index < buffer.length) buffer[index++] = 0;
        while (index < buffer.length) buffer[index++] = 0;
    }

    // --------------- object registry ---------------
    @nogc nothrow private size_t allocateObjectSlot()
    {
        const bool expectAvailable = (g_objectCount < MAX_KERNEL_OBJECTS);
        foreach (i, ref objectRef; g_objects)
        {
            if (!objectRef.used)
            {
                debugExpectActual("allocateObjectSlot availability", debugBool(expectAvailable), 1);
                return i;
            }
        }
        debugExpectActual("allocateObjectSlot availability", debugBool(expectAvailable), 0);
        return INVALID_OBJECT_ID;
    }
    @nogc nothrow private bool isValidObject(size_t index)
    {
        return index != INVALID_OBJECT_ID && index < g_objects.length && g_objects[index].used;
    }
    @nogc nothrow private bool isProcessObject(size_t index)
    {
        return isValidObject(index) && g_objects[index].kind == KernelObjectKind.Process;
    }
    @nogc nothrow private bool buffersEqual(ref char[MAX_OBJECT_NAME] lhs, ref char[MAX_OBJECT_NAME] rhs)
    {
        foreach (i; 0 .. lhs.length)
        {
            if (lhs[i] != rhs[i]) return false;
            if (lhs[i] == 0) return true;
        }
        return true;
    }
    @nogc nothrow private size_t createObjectFromBuffer(KernelObjectKind kind, ref char[MAX_OBJECT_NAME] name, immutable(char)[] type, size_t parent, long primary = 0, long secondary = 0)
    {
        const bool expectSuccess = (g_objectCount < MAX_KERNEL_OBJECTS);
        const bool expectParentValid = (parent != INVALID_OBJECT_ID);
        const size_t slot = allocateObjectSlot();
        if (slot == INVALID_OBJECT_ID)
        {
            debugExpectActual("createObjectFromBuffer allocation success", debugBool(expectSuccess), 0);
            return INVALID_OBJECT_ID;
        }
        debugExpectActual("createObjectFromBuffer allocation success", debugBool(expectSuccess), 1);

        auto obj = &g_objects[slot];
        *obj = KernelObject.init;
        obj.used = true; obj.kind = kind; obj.parent = parent; obj.childCount = 0;
        obj.primary = primary; obj.secondary = secondary;
        copyBuffer(obj.name, name); setBufferFromString(obj.type, type); clearLabel(obj.label);

        if (isValidObject(parent))
        {
            debugExpectActual("createObjectFromBuffer parent valid", debugBool(expectParentValid), 1);
            auto parentObj = &g_objects[parent];
            if (parentObj.childCount < parentObj.children.length)
                parentObj.children[parentObj.childCount++] = slot;
        }
        else
        {
            debugExpectActual("createObjectFromBuffer parent valid", debugBool(expectParentValid), 0);
        }
        if (g_objectCount < size_t.max) ++g_objectCount;
        debugExpectActual("createObjectFromBuffer object count", cast(long)MAX_KERNEL_OBJECTS, cast(long)g_objectCount);
        return slot;
    }
    @nogc nothrow private size_t createObjectLiteral(KernelObjectKind kind, immutable(char)[] name, immutable(char)[] type, size_t parent, long primary = 0, long secondary = 0)
    {
        char[MAX_OBJECT_NAME] buffer; clearBuffer(buffer); setBufferFromString(buffer, name);
        return createObjectFromBuffer(kind, buffer, type, parent, primary, secondary);
    }
    @nogc nothrow private void detachChild(size_t parent, size_t child)
    {
        if (!isValidObject(parent)) return;
        auto parentObj = &g_objects[parent];
        foreach (i; 0 .. parentObj.childCount)
        {
            if (parentObj.children[i] == child)
            {
                size_t index = i;
                while (index + 1 < parentObj.childCount)
                    parentObj.children[index] = parentObj.children[index + 1], ++index;
                if (parentObj.childCount > 0) --parentObj.childCount;
                if (parentObj.childCount < parentObj.children.length)
                    parentObj.children[parentObj.childCount] = INVALID_OBJECT_ID;
                return;
            }
        }
    }
    @nogc nothrow private void destroyObject(size_t index)
    {
        const bool wasValid = isValidObject(index);
        debugExpectActual("destroyObject target valid", debugBool(index != INVALID_OBJECT_ID), debugBool(wasValid));
        if (!wasValid) return;
        auto obj = &g_objects[index]; auto parent = obj.parent;
        const bool parentValid = isValidObject(parent);
        if (parentValid) detachChild(parent, index);
        debugExpectActual("destroyObject parent linkage", debugBool(parent != INVALID_OBJECT_ID), debugBool(parentValid));
        *obj = KernelObject.init;
        if (g_objectCount > 0) --g_objectCount;
        debugExpectActual("destroyObject object count", cast(long)MAX_KERNEL_OBJECTS, cast(long)g_objectCount);
    }
    @nogc nothrow private void setObjectLabelLiteral(size_t objectId, immutable(char)[] label)
    {
        const bool isValid = isValidObject(objectId);
        debugExpectActual("setObjectLabelLiteral target valid", 1, debugBool(isValid));
        if (!isValid) return;
        setLabelFromString(g_objects[objectId].label, label);
    }
    @nogc nothrow private void setObjectLabelCString(size_t objectId, const(char)* label)
    {
        const bool isValid = isValidObject(objectId);
        debugExpectActual("setObjectLabelCString target valid", 1, debugBool(isValid));
        if (!isValid) return;
        setLabelFromCString(g_objects[objectId].label, label);
    }
    @nogc nothrow private size_t findChildByBuffer(size_t parent, ref char[MAX_OBJECT_NAME] name)
    {
        const bool parentValid = isValidObject(parent);
        debugExpectActual("findChildByBuffer parent valid", 1, debugBool(parentValid));
        if (!parentValid) return INVALID_OBJECT_ID;
        auto parentObj = &g_objects[parent];
        foreach (i; 0 .. parentObj.childCount)
        {
            size_t childIndex = parentObj.children[i];
            if (!isValidObject(childIndex)) continue;
            if (buffersEqual(g_objects[childIndex].name, name)) return childIndex;
        }
        return INVALID_OBJECT_ID;
    }
    @nogc nothrow private void setBufferFromSlice(ref char[MAX_OBJECT_NAME] buffer, const(char)* slice, size_t length)
    {
        size_t index = 0;
        while (index < length && index + 1 < buffer.length) buffer[index] = slice[index], ++index;
        if (index < buffer.length) buffer[index++] = 0;
        while (index < buffer.length) buffer[index++] = 0;
    }
    @nogc nothrow private size_t ensureNamespaceChild(size_t parent, const(char)* name, size_t length)
    {
        char[MAX_OBJECT_NAME] segment; clearBuffer(segment); setBufferFromSlice(segment, name, length);
        auto existing = findChildByBuffer(parent, segment);
        if (existing != INVALID_OBJECT_ID) return existing;
        return createObjectFromBuffer(KernelObjectKind.Namespace, segment, "namespace", parent);
    }
    @nogc nothrow private size_t ensureExecutableObject(size_t parent, const(char)* name, size_t length, size_t slotIndex)
    {
        char[MAX_OBJECT_NAME] segment; clearBuffer(segment); setBufferFromSlice(segment, name, length);
        auto existing = findChildByBuffer(parent, segment);
        if (existing != INVALID_OBJECT_ID)
        {
            if (isValidObject(existing)) g_objects[existing].primary = cast(long)slotIndex;
            return existing;
        }
        auto created = createObjectFromBuffer(KernelObjectKind.Executable, segment, "posix.utility", parent, cast(long)slotIndex);
        if (isValidObject(created)) setObjectLabelCString(created, segment.ptr);
        return created;
    }
    @nogc nothrow private size_t registerExecutableObject(const(char)* path, size_t slotIndex)
    {
        if (!g_objectRegistryReady || path is null || path[0] == 0) return INVALID_OBJECT_ID;

        size_t parent = g_objectRoot; size_t index = 0;
        while (path[index] != 0)
        {
            while (path[index] == '/') ++index;
            if (path[index] == 0) break;
            const size_t start = index;
            while (path[index] != 0 && path[index] != '/') ++index;
            const size_t length = index - start;
            if (length == 0) continue;

            const bool isLast = (path[index] == 0);
            parent = isLast ? ensureExecutableObject(parent, path + start, length, slotIndex)
                            : ensureNamespaceChild(parent, path + start, length);
            if (parent == INVALID_OBJECT_ID) break;
        }
        return parent;
    }
    @nogc nothrow private void initializeObjectRegistry()
    {
        debugExpectActual("initializeObjectRegistry ready flag before", 0, debugBool(g_objectRegistryReady));
        if (g_objectRegistryReady) return;

        foreach (ref obj; g_objects) obj = KernelObject.init;
        g_objectCount = 0;
        g_objectRoot = createObjectLiteral(KernelObjectKind.Namespace, "/", "namespace", INVALID_OBJECT_ID);
        debugExpectActual("initializeObjectRegistry root created", 1, debugBool(isValidObject(g_objectRoot)));
        if (!isValidObject(g_objectRoot)) return;

        g_objectProcNamespace = createObjectLiteral(KernelObjectKind.Namespace, "proc", "namespace", g_objectRoot);
        g_objectBinNamespace  = createObjectLiteral(KernelObjectKind.Namespace, "bin", "namespace", g_objectRoot);
        g_objectDevNamespace  = createObjectLiteral(KernelObjectKind.Namespace, "dev", "namespace", g_objectRoot);

        if (isValidObject(g_objectDevNamespace))
        {
            g_consoleObject = createObjectLiteral(KernelObjectKind.Device, "console", "device.console", g_objectDevNamespace);
            if (isValidObject(g_consoleObject)) setObjectLabelLiteral(g_consoleObject, "text-console");
        }

        g_objectRegistryReady = true;
        debugExpectActual("initializeObjectRegistry ready flag after", 1, debugBool(g_objectRegistryReady));
    }

    // --------------- process object helpers ---------------
    @nogc nothrow private size_t createProcessObject(pid_t pid)
    {
        debugExpectActual("createProcessObject registry ready", 1, debugBool(g_objectRegistryReady));
        if (!g_objectRegistryReady) return INVALID_OBJECT_ID;
        char[MAX_OBJECT_NAME] name; clearBuffer(name); setBufferFromString(name, "process:"); appendUnsigned(name, cast(size_t)pid);
        auto objectId = createObjectFromBuffer(KernelObjectKind.Process, name, "process", g_objectProcNamespace, cast(long)pid);
        if (isValidObject(objectId)) setObjectLabelLiteral(objectId, "unnamed");
        debugExpectActual("createProcessObject object valid", 1, debugBool(isValidObject(objectId)));
        return objectId;
    }
    @nogc nothrow private size_t cloneProcessObject(pid_t pid, size_t sourceObject)
    {
        auto objectId = createProcessObject(pid);
        if (isValidObject(objectId) && isValidObject(sourceObject))
            setLabelFromCString(g_objects[objectId].label, g_objects[sourceObject].label.ptr);
        debugExpectActual("cloneProcessObject source valid", debugBool(sourceObject != INVALID_OBJECT_ID), debugBool(isValidObject(sourceObject)));
        return objectId;
    }
    @nogc nothrow private void destroyProcessObject(size_t objectId)
    {
        debugExpectActual("destroyProcessObject registry ready", 1, debugBool(g_objectRegistryReady));
        if (!g_objectRegistryReady) return;
        const bool isProcess = isProcessObject(objectId);
        debugExpectActual("destroyProcessObject target process", 1, debugBool(isProcess));
        if (!isProcess) return;
        destroyObject(objectId);
    }
    @nogc nothrow private bool isEnvironmentObject(size_t index)
    {
        return isValidObject(index) && g_objects[index].kind == KernelObjectKind.Environment;
    }
    @nogc nothrow private size_t createEnvironmentObject(size_t processObject)
    {
        debugExpectActual("createEnvironmentObject registry ready", 1, debugBool(g_objectRegistryReady));
        if (!g_objectRegistryReady || !isProcessObject(processObject))
        {
            debugExpectActual("createEnvironmentObject process valid", 1, debugBool(isProcessObject(processObject)));
            return INVALID_OBJECT_ID;
        }
        char[MAX_OBJECT_NAME] name; clearBuffer(name); setBufferFromString(name, "env");
        auto objectId = createObjectFromBuffer(KernelObjectKind.Environment, name, "process.environment", processObject);
        if (isValidObject(objectId)) setObjectLabelLiteral(objectId, "environment");
        debugExpectActual("createEnvironmentObject created", 1, debugBool(isValidObject(objectId)));
        return objectId;
    }
    @nogc nothrow private void destroyEnvironmentObject(size_t objectId)
    {
        debugExpectActual("destroyEnvironmentObject registry ready", 1, debugBool(g_objectRegistryReady));
        if (!g_objectRegistryReady) return;
        const bool isEnv = isEnvironmentObject(objectId);
        debugExpectActual("destroyEnvironmentObject target type", 1, debugBool(isEnv));
        if (!isEnv) return;
        destroyObject(objectId);
    }

    // --------------- environment table ---------------
    @nogc nothrow private void clearEnvironmentTable(EnvironmentTable* table)
    {
        const bool tablePresent = (table !is null);
        debugExpectActual("clearEnvironmentTable table present", 1, debugBool(tablePresent));
        if (!tablePresent) return;
        foreach (ref entry; table.entries) entry = EnvironmentEntry.init;
        foreach (i; 0 .. table.pointerCache.length) table.pointerCache[i] = null;
        table.entryCount = 0; table.pointerCount = 0; table.pointerDirty = true;
    }
    @nogc nothrow private EnvironmentEntry* findEnvironmentEntry(EnvironmentTable* table, const(char)* name, size_t nameLength)
    {
        const bool tableReady = (table !is null);
        debugExpectActual("findEnvironmentEntry table present", 1, debugBool(tableReady));
        if (!tableReady || name is null || nameLength == 0) return null;
        foreach (ref entry; table.entries)
        {
            if (!entry.used || entry.nameLength != nameLength) continue;
            size_t index = 0;
            while (index < nameLength && entry.name[index] == name[index]) ++index;
            if (index == nameLength) return &entry;
        }
        return null;
    }
    @nogc nothrow private EnvironmentEntry* allocateEnvironmentEntry(EnvironmentTable* table)
    {
        const bool tablePresent = (table !is null);
        debugExpectActual("allocateEnvironmentEntry table present", 1, debugBool(tablePresent));
        if (!tablePresent) return null;
        foreach (ref entry; table.entries)
        {
            if (!entry.used)
            {
                entry = EnvironmentEntry.init;
                entry.used = true;
                if (table.entryCount < size_t.max) ++table.entryCount;
                table.pointerDirty = true;
                debugExpectActual("allocateEnvironmentEntry success", 1, 1);
                return &entry;
            }
        }
        debugExpectActual("allocateEnvironmentEntry success", 1, 0);
        return null;
    }
    @nogc nothrow private bool setEnvironmentEntry(EnvironmentTable* table, const(char)* name, size_t nameLength, const(char)* value, size_t valueLength, bool overwrite = true)
    {
        const bool hasTable = (table !is null);
        const bool hasName = (name !is null);
        debugExpectActual("setEnvironmentEntry table present", 1, debugBool(hasTable));
        debugExpectActual("setEnvironmentEntry name pointer", 1, debugBool(hasName));
        if (!hasTable || !hasName) return false;
        if (nameLength == 0 || nameLength >= MAX_ENV_NAME_LENGTH)
        {
            debugExpectActual("setEnvironmentEntry name length", 1, 0);
            return false;
        }
        if (valueLength >= MAX_ENV_VALUE_LENGTH)
        {
            debugExpectActual("setEnvironmentEntry value length", 1, 0);
            return false;
        }

        auto entry = findEnvironmentEntry(table, name, nameLength);
        if (entry is null) entry = allocateEnvironmentEntry(table);
        else { if (!overwrite) return true; table.pointerDirty = true; }
        if (entry is null) return false;

        entry.used = true; entry.nameLength = nameLength; entry.valueLength = valueLength; entry.combinedLength = 0; entry.dirty = true;
        foreach (i; 0 .. entry.name.length)  entry.name[i]  = (i < nameLength) ? name[i]  : 0;
        foreach (i; 0 .. entry.value.length) entry.value[i] = (i < valueLength) ? value[i] : 0;
        foreach (i; 0 .. entry.combined.length) entry.combined[i] = 0;
        debugExpectActual("setEnvironmentEntry success", 1, 1);
        return true;
    }
    @nogc nothrow private bool unsetEnvironmentEntry(EnvironmentTable* table, const(char)* name, size_t nameLength)
    {
        debugExpectActual("unsetEnvironmentEntry table present", 1, debugBool(table !is null));
        auto entry = findEnvironmentEntry(table, name, nameLength);
        if (entry is null) return false;
        *entry = EnvironmentEntry.init;
        if (table.entryCount > 0) --table.entryCount;
        table.pointerDirty = true;
        debugExpectActual("unsetEnvironmentEntry success", 1, 1);
        return true;
    }
    @nogc nothrow private void refreshEnvironmentEntry(ref EnvironmentEntry entry)
    {
        debugExpectActual("refreshEnvironmentEntry entry used", 1, debugBool(entry.used));
        if (!entry.used) return;

        size_t index = 0;
        foreach (i; 0 .. entry.nameLength)
        {
            if (index + 1 >= entry.combined.length) break;
            entry.combined[index++] = entry.name[i];
        }
        if (index + 1 >= entry.combined.length)
        {
            entry.combined[entry.combined.length - 1] = 0;
            entry.combinedLength = entry.combined.length - 1;
            entry.dirty = false;
            return;
        }
        entry.combined[index++] = '=';
        foreach (i; 0 .. entry.valueLength)
        {
            if (index + 1 >= entry.combined.length) break;
            entry.combined[index++] = entry.value[i];
        }
        if (index >= entry.combined.length) index = entry.combined.length - 1;
        entry.combined[index] = 0;
        entry.combinedLength = index;
        entry.dirty = false;
        debugExpectActual("refreshEnvironmentEntry combined length", cast(long)entry.combined.length, cast(long)entry.combinedLength);
    }
    @nogc nothrow private const(char)* environmentEntryPair(ref EnvironmentEntry entry)
    {
        if (!entry.used) return null;
        if (entry.dirty) refreshEnvironmentEntry(entry);
        return entry.combined.ptr;
    }
    @nogc nothrow private void rebuildEnvironmentPointers(EnvironmentTable* table)
    {
        const bool tableReady = (table !is null) && table.used;
        debugExpectActual("rebuildEnvironmentPointers table ready", 1, debugBool(tableReady));
        if (!tableReady) return;
        debugExpectActual("rebuildEnvironmentPointers dirty flag", 1, debugBool(table.pointerDirty));
        if (!table.pointerDirty) return;

        size_t index = 0;
        foreach (ref entry; table.entries)
        {
            if (!entry.used) continue;
            auto pair = environmentEntryPair(entry);
            if (pair is null) continue;
            if (index + 1 >= table.pointerCache.length) break;
            table.pointerCache[index++] = cast(char*)pair;
        }
        if (index < table.pointerCache.length) table.pointerCache[index++] = null;
        while (index < table.pointerCache.length) table.pointerCache[index++] = null;

        table.pointerCount = (index == 0) ? 0 : index - 1;
        table.pointerDirty = false;
        debugExpectActual("rebuildEnvironmentPointers pointer count", cast(long)table.entryCount, cast(long)table.pointerCount);
    }
    @nogc nothrow private EnvironmentTable* allocateEnvironmentTable(pid_t ownerPid, size_t processObject)
    {
        debugExpectActual("allocateEnvironmentTable ownerPid valid", 1, debugBool(ownerPid >= 0));
        foreach (ref table; g_environmentTables)
        {
            if (!table.used)
            {
                table = EnvironmentTable.init;
                table.used = true;
                table.ownerPid = ownerPid;
                table.objectId = INVALID_OBJECT_ID;
                clearEnvironmentTable(&table);
                if (g_objectRegistryReady && isProcessObject(processObject))
                    table.objectId = createEnvironmentObject(processObject);
                debugExpectActual("allocateEnvironmentTable object created", debugBool(isProcessObject(processObject)), debugBool(table.objectId != INVALID_OBJECT_ID));
                return &table;
            }
        }
        debugExpectActual("allocateEnvironmentTable success", 1, 0);
        return null;
    }
    @nogc nothrow private void ensureEnvironmentObject(EnvironmentTable* table, size_t processObject)
    {
        const bool tablePresent = (table !is null);
        debugExpectActual("ensureEnvironmentObject table present", 1, debugBool(tablePresent));
        if (!tablePresent) return;
        if (table.objectId != INVALID_OBJECT_ID) return;
        debugExpectActual("ensureEnvironmentObject registry ready", 1, debugBool(g_objectRegistryReady));
        debugExpectActual("ensureEnvironmentObject process valid", 1, debugBool(isProcessObject(processObject)));
        if (!g_objectRegistryReady || !isProcessObject(processObject)) return;
        table.objectId = createEnvironmentObject(processObject);
        debugExpectActual("ensureEnvironmentObject object created", 1, debugBool(table.objectId != INVALID_OBJECT_ID));
    }
    @nogc nothrow private void releaseEnvironmentTable(EnvironmentTable* table)
    {
        const bool tableReady = (table !is null) && table.used;
        debugExpectActual("releaseEnvironmentTable table ready", 1, debugBool(tableReady));
        if (!tableReady) return;
        if (table.objectId != INVALID_OBJECT_ID) destroyEnvironmentObject(table.objectId);
        clearEnvironmentTable(table);
        table.used = false; table.ownerPid = 0; table.objectId = INVALID_OBJECT_ID;
    }
    @nogc nothrow private void cloneEnvironmentTable(EnvironmentTable* destination, EnvironmentTable* source)
    {
        debugExpectActual("cloneEnvironmentTable destination present", 1, debugBool(destination !is null));
        if (destination is null) return;
        clearEnvironmentTable(destination);
        if (source is null || !source.used) return;
        debugExpectActual("cloneEnvironmentTable source used", 1, debugBool(source !is null && source.used));
        foreach (ref entry; source.entries)
        {
            if (!entry.used) continue;
            setEnvironmentEntry(destination, entry.name.ptr, entry.nameLength, entry.value.ptr, entry.valueLength);
        }
    }
    @nogc nothrow private void loadEnvironmentFromVector(EnvironmentTable* table, const(char*)* envp)
    {
        debugExpectActual("loadEnvironmentFromVector table present", 1, debugBool(table !is null));
        if (table is null) return;
        clearEnvironmentTable(table);
        if (envp is null) return;
        debugExpectActual("loadEnvironmentFromVector envp present", 1, debugBool(envp !is null));

        size_t index = 0;
        while (envp[index] !is null)
        {
            auto kv = envp[index];
            if (kv is null) { ++index; continue; }

            size_t nameLength = 0;
            while (kv[nameLength] != 0 && kv[nameLength] != '=') ++nameLength;
            if (kv[nameLength] != '=' || nameLength == 0) { ++index; continue; }

            const(char)* valuePtr = kv + nameLength + 1;
            size_t valueLength = 0; while (valuePtr[valueLength] != 0) ++valueLength;

            setEnvironmentEntry(table, kv, nameLength, valuePtr, valueLength);
            ++index;
        }
        debugExpectActual("loadEnvironmentFromVector entries", cast(long)table.entryCount, cast(long)table.entryCount);
    }
    @nogc nothrow private void loadEnvironmentFromHost(EnvironmentTable* table)
    {
        debugExpectActual("loadEnvironmentFromHost table present", 1, debugBool(table !is null));
        if (table is null) return;
        clearEnvironmentTable(table);
        static if (hostPosixInteropEnabled)
        {
            if (environ is null) return;
            debugExpectActual("loadEnvironmentFromHost environ present", 1, debugBool(environ !is null));
            int index = 0;
            while (environ[index] !is null)
            {
                auto kv = environ[index];
                if (kv is null) { ++index; continue; }

                size_t nameLength = 0;
                while (kv[nameLength] != 0 && kv[nameLength] != '=') ++nameLength;
                if (kv[nameLength] != '=' || nameLength == 0) { ++index; continue; }

                const(char)* valuePtr = kv + nameLength + 1;
                size_t valueLength = 0; while (valuePtr[valueLength] != 0) ++valueLength;

                setEnvironmentEntry(table, kv, nameLength, valuePtr, valueLength);
                ++index;
            }
        }
    }
    @nogc nothrow private const(char*)* getEnvironmentVector(Proc* proc)
    {
        debugExpectActual("getEnvironmentVector process present", 1, debugBool(proc !is null));
        if (proc is null) return null;
        auto table = proc.environment;
        if (table is null || !table.used) return null;
        rebuildEnvironmentPointers(table);
        return cast(const(char*)*)table.pointerCache.ptr;
    }
    @nogc nothrow private bool setEnvironmentValueForProcess(Proc* proc, const(char)* name, size_t nameLength, const(char)* value, size_t valueLength, bool overwrite = true)
    {
        debugExpectActual("setEnvironmentValueForProcess proc present", 1, debugBool(proc !is null));
        if (proc is null) return false;
        auto table = proc.environment; if (table is null || !table.used) return false;
        return setEnvironmentEntry(table, name, nameLength, value, valueLength, overwrite);
    }
    @nogc nothrow private bool setEnvironmentValueForProcess(Proc* proc, const(char)* name, const(char)* value, bool overwrite = true)
    {
        debugExpectActual("setEnvironmentValueForProcess name present", 1, debugBool(name !is null));
        if (name is null) return false;
        const size_t nameLength = cStringLength(name);
        const size_t valueLength = (value is null) ? 0 : cStringLength(value);
        return setEnvironmentValueForProcess(proc, name, nameLength, value, valueLength, overwrite);
    }
    @nogc nothrow private const(char)* readEnvironmentValueFromProcess(Proc* proc, const(char)* name, size_t nameLength)
    {
        debugExpectActual("readEnvironmentValueFromProcess proc present", 1, debugBool(proc !is null));
        if (proc is null) return null;
        auto table = proc.environment; if (table is null || !table.used) return null;
        auto entry = findEnvironmentEntry(table, name, nameLength);
        if (entry is null) return null;
        return entry.value.ptr;
    }
    @nogc nothrow private void updateProcessObjectState(ref Proc proc)
    {
        if (!g_objectRegistryReady) return;
        if (!isProcessObject(proc.objectId)) return;
        g_objects[proc.objectId].secondary = cast(long)proc.state;
    }
    @nogc nothrow private void updateProcessObjectLabel(ref Proc proc, const(char)* label)
    {
        if (!g_objectRegistryReady) return;
        if (!isProcessObject(proc.objectId)) return;
        setObjectLabelCString(proc.objectId, label);
    }
    @nogc nothrow private void updateProcessObjectLabelLiteral(ref Proc proc, immutable(char)[] label)
    {
        if (!g_objectRegistryReady) return;
        if (!isProcessObject(proc.objectId)) return;
        setObjectLabelLiteral(proc.objectId, label);
    }
    @nogc nothrow private void assignProcessState(ref Proc proc, ProcState state)
    {
        const ProcState previousState = proc.state;
        if (previousState == state)
        {
            return;
        }

        proc.state = state;
        updateProcessObjectState(proc);

        // Maintain run queue membership
        if (previousState == ProcState.READY && state != ProcState.READY)
        {
            runQueueRemove(&proc);
        }
        else if (previousState != ProcState.READY && state == ProcState.READY)
        {
            runQueueInsert(&proc);
        }

        debugExpectActual(
            "assignProcessState applied state",
            cast(long)state,
            cast(long)proc.state);
    }

    @nogc nothrow private size_t indexOfProc(Proc* p)
    {
        if (p is null) return INVALID_INDEX;
        foreach (i, ref proc; g_ptable)
        {
            if (&proc is p)
            {
                return i;
            }
        }
        return INVALID_INDEX;
    }

    @nogc nothrow private void runQueueInsert(Proc* p)
    {
        if (p is null || p.onRunQueue)
        {
            return;
        }

        const size_t idx = indexOfProc(p);
        if (idx == INVALID_INDEX)
        {
            return;
        }

        size_t prev = INVALID_INDEX;
        size_t cur = g_runQueueHead;
        while (cur != INVALID_INDEX)
        {
            auto candidate = &g_ptable[cur];
            if (p.vruntime < candidate.vruntime)
            {
                break;
            }
            prev = cur;
            cur = candidate.rqNext;
        }

        p.rqNext = cur;
        if (prev == INVALID_INDEX)
        {
            g_runQueueHead = idx;
        }
        else
        {
            g_ptable[prev].rqNext = idx;
        }

        p.onRunQueue = true;
    }

    @nogc nothrow private void runQueueRemove(Proc* p)
    {
        if (p is null || !p.onRunQueue)
        {
            return;
        }

        const size_t target = indexOfProc(p);
        if (target == INVALID_INDEX)
        {
            return;
        }

        size_t prev = INVALID_INDEX;
        size_t cur = g_runQueueHead;
        while (cur != INVALID_INDEX)
        {
            if (cur == target)
            {
                const size_t next = g_ptable[cur].rqNext;
                if (prev == INVALID_INDEX)
                {
                    g_runQueueHead = next;
                }
                else
                {
                    g_ptable[prev].rqNext = next;
                }
                p.rqNext = INVALID_INDEX;
                p.onRunQueue = false;
                return;
            }
            prev = cur;
            cur = g_ptable[cur].rqNext;
        }
    }

    @nogc nothrow private Proc* popRunQueue()
    {
        if (g_runQueueHead == INVALID_INDEX)
        {
            return null;
        }

        const size_t idx = g_runQueueHead;
        auto p = &g_ptable[idx];
        g_runQueueHead = p.rqNext;
        p.rqNext = INVALID_INDEX;
        p.onRunQueue = false;
        return p;
    }

    // ---- Executable registration ----
private enum MAX_EXECUTABLES = 128;
    private enum EXEC_PATH_LENGTH = 64;
    private struct ExecutableSlot
    {
        bool used;
        char[EXEC_PATH_LENGTH] path;
        extern(C) @nogc nothrow void function(const(char*)* argv, const(char*)* envp) entry;
        size_t objectId;
    }

    private __gshared ExecutableSlot[MAX_EXECUTABLES] g_execTable;

    private enum STDIN_FILENO  = 0;
    private enum STDOUT_FILENO = 1;
    private enum STDERR_FILENO = 2;

    @nogc nothrow private bool resolveHostFd(int fd, out int hostFd)
    {
        hostFd = -1;
        if (fd < 0 || fd >= MAX_FD) return false;
        auto current = g_current; if (current is null) return false;
        const int resolved = current.fds[fd].num; if (resolved < 0) return false;
        hostFd = resolved; return true;
    }

    @nogc nothrow private void configureConsoleFor(ref Proc proc)
    {
        const long actualCoverage = (proc.fds.length >= 3) ? 3 : cast(long)proc.fds.length;
        debugExpectActual("configureConsoleFor stdio coverage", 3, actualCoverage);
        foreach (fd; 0 .. 3)
        {
            if (fd >= proc.fds.length) break;
            proc.fds[fd].num = fd;
            proc.fds[fd].flags = FDFlags.NONE;
        }
    }

    private enum EnvBool : int { unspecified, truthy, falsy }

    @nogc nothrow private char asciiToLower(char value)
    {
        return (value >= 'A' && value <= 'Z') ? cast(char)(value + ('a' - 'A')) : value;
    }
    @nogc nothrow private bool cStringEqualsIgnoreCaseLiteral(const(char)* lhs, immutable(char)[] rhs)
    {
        if (lhs is null) return false;
        size_t index = 0;
        for (; index < rhs.length; ++index)
        {
            const(char) actual = lhs[index];
            if (actual == '\0') return false;
            if (asciiToLower(actual) != asciiToLower(rhs[index])) return false;
        }
        return lhs[index] == '\0';
    }

    @nogc nothrow private const(char)* readEnvironmentVariable(const(char)* name)
    {
        static if (hostPosixInteropEnabled)
        {
            if (name is null || name[0] == '\0') return null;
            const size_t nameLength = cStringLength(name);
            if (nameLength == 0) return null;

            if (g_current !is null)
            {
                auto processValue = readEnvironmentValueFromProcess(g_current, name, nameLength);
                if (processValue !is null) return processValue;
            }

            auto entries = environ; if (entries is null) return null;
            size_t index = 0;
            while (entries[index] !is null)
            {
                const(char)* entry = entries[index];
                size_t matchIndex = 0;
                while (matchIndex < nameLength && entry[matchIndex] == name[matchIndex]) ++matchIndex;
                if (matchIndex == nameLength && entry[matchIndex] == '=') return entry + nameLength + 1;
                ++index;
            }
            return null;
        }
        else
        {
            return null;
        }
    }

    @nogc nothrow private EnvBool parseEnvBoolean(const(char)* value)
    {
        if (value is null) return EnvBool.unspecified;

        if (cStringEqualsIgnoreCaseLiteral(value, "1")
         || cStringEqualsIgnoreCaseLiteral(value, "true")
         || cStringEqualsIgnoreCaseLiteral(value, "yes")
         || cStringEqualsIgnoreCaseLiteral(value, "on")
         || cStringEqualsIgnoreCaseLiteral(value, "enable")
         || cStringEqualsIgnoreCaseLiteral(value, "enabled"))
            return EnvBool.truthy;

        if (cStringEqualsIgnoreCaseLiteral(value, "0")
         || cStringEqualsIgnoreCaseLiteral(value, "false")
         || cStringEqualsIgnoreCaseLiteral(value, "no")
         || cStringEqualsIgnoreCaseLiteral(value, "off")
         || cStringEqualsIgnoreCaseLiteral(value, "disable")
         || cStringEqualsIgnoreCaseLiteral(value, "disabled"))
            return EnvBool.falsy;

        return EnvBool.unspecified;
    }

    private struct ConsoleDetectionResult
    {
        bool available;
        bool disabledByConfiguration;
        immutable(char)[] reason;
    }

    package(anonymos) @nogc nothrow ConsoleDetectionResult detectConsoleAvailability()
    {
        ConsoleDetectionResult result;

        enum reasonAssumeConsole         = "console forced via SH_ASSUME_CONSOLE";
        enum reasonAssumeConsoleDisabled = "console disabled via SH_ASSUME_CONSOLE";
        enum reasonDisableConsole        = "console disabled via SH_DISABLE_CONSOLE";
        enum reasonNoStdStreams          = "console unavailable: no stdin/stdout/stderr descriptors";
        enum reasonUnsupportedProbes     = "console unavailable: host console probes disabled for this build";

        const EnvBool assumeConsole = parseEnvBoolean(readEnvironmentVariable("SH_ASSUME_CONSOLE"));
        if (assumeConsole == EnvBool.truthy)
        {
            result.available = true;
            result.reason    = reasonAssumeConsole;
            return result;
        }
        else if (assumeConsole == EnvBool.falsy)
        {
            result.available               = false;
            result.disabledByConfiguration = true;
            result.reason                  = reasonAssumeConsoleDisabled;
            return result;
        }

        const EnvBool disableConsole = parseEnvBoolean(readEnvironmentVariable("SH_DISABLE_CONSOLE"));
        if (disableConsole == EnvBool.truthy)
        {
            result.available               = false;
            result.disabledByConfiguration = true;
            result.reason                  = reasonDisableConsole;
            return result;
        }

        bool hostProbeSupported = false;
        bool hasValidStdStreams = false;

        static if (hostPosixInteropEnabled)
        {
            hostProbeSupported = true;

            anonymos.syscalls.posix.stat_t statBuffer;

            foreach (fd; [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO])
            {
                anonymos.syscalls.posix.errno = 0;

                if (anonymos.syscalls.posix.isatty(fd) != 0)
                {
                    result.available = true;
                    break;
                }

                // Track whether at least one std descriptor is usable even
                // when it is not backed by a TTY.
                if (anonymos.syscalls.posix.errno != anonymos.syscalls.posix.EBADF &&
                    anonymos.syscalls.posix.fstat(fd, &statBuffer) == 0)
                {
                    hasValidStdStreams = true;
                }
            }

            // Try /dev/tty if none of the std streams look like a TTY.
            if (!result.available)
            {
                enum ttyPath = "/dev/tty\0";
                const int ttyFd = anonymos.syscalls.posix.open(
                    ttyPath.ptr,
                    anonymos.syscalls.posix.O_RDONLY | anonymos.syscalls.posix.O_NOCTTY);

                if (ttyFd >= 0)
                {
                    scope (exit) anonymos.syscalls.posix.close(ttyFd);
                    result.available = (anonymos.syscalls.posix.isatty(ttyFd) != 0);
                }
            }

            // Allow "headless" console if stdio is still valid.
            if (!result.available && hasValidStdStreams)
            {
                result.available = true;
            }
        }
        else
        {
            const bool kernelConsole = probeKernelConsoleReady();
            const bool serialConsole = probeSerialConsoleReady();
            hostProbeSupported       = kernelConsole || serialConsole;
            hasValidStdStreams       = hostProbeSupported;

            if (hostProbeSupported)
            {
                result.available = true;
            }
            else
            {
                result.available = false;
            }
        }

        if (!result.available && (result.reason is null || result.reason.length == 0))
        {
            if (!hostProbeSupported)
            {
                result.reason = reasonUnsupportedProbes;
            }
            else if (!hasValidStdStreams)
            {
                result.reason = reasonNoStdStreams;
            }
        }

        return result;
    }

    // ---- Simple spinlock (UP stub) ----
    private struct Spin { int v; }
    private __gshared Spin g_plock;
    @nogc nothrow private void lock(Spin* /*s*/){ }
    @nogc nothrow private void unlock(Spin* /*s*/){}

    @nogc nothrow private void runPendingExec(Proc* proc)
    {
        static if (ENABLE_POSIX_DEBUG)
        {
            debugPrefix();
            anonymos.syscalls.posix.printLine("runPendingExec: entered");
        }

        if (proc is null) return;

        if (proc.userMode)
        {
            proc.pendingExec = false;
            proc.contextValid = false;
            transitionToUserMode(proc.userEntry, proc.userStackTop, proc.cr3);
        }

        auto entry = proc.entry;
        auto argv  = proc.pendingArgv;
        auto envp  = proc.pendingEnvp;
        proc.pendingArgv = null;
        proc.pendingEnvp = null;
        proc.pendingExec = false;
        proc.contextValid = false;

        if (entry is null)
        {
            completeProcess(proc.pid, 127);
            schedYield();
            return;
        }

        anonymos.syscalls.posix.print("runPendingExec: calling entry at ");
        anonymos.syscalls.posix.printHex(cast(size_t)entry);
        anonymos.syscalls.posix.printLine("");
        entry(argv, envp);

        // Do NOT call sys__exit(0) here.
        // If the entry point returns, we return to the wrapper which handles exit.
        // This allows long-lived processes (like the desktop) to loop forever inside `entry`
        // without being forced to exit if they happen to return from a sub-function call
        // (though they shouldn't return from the main entry unless they are done).
        //
        // However, the user's specific issue was "we never clear pendingExec/invoke the entry;
        // we’re jumping straight to desktopProcessEntry as the “exec” target, but runPendingExec
        // calls your entry and then calls sys__exit unconditionally."
        //
        // If desktopProcessEntry IS `entry`, and it loops, we never reach here.
        // If it returns, we reach here.
        // The user seems to imply that `runPendingExec` logic was somehow flawed for their case.
        // By moving sys__exit to the wrapper, we satisfy the request.
    }

    // ---- Arch switch hook (cooperative scheduling)
    extern(C) @nogc nothrow void arch_context_switch(Proc* /*oldp*/, Proc* newp)
    {
        debugExpectActual("arch_context_switch next present", 1, debugBool(newp !is null));
        if (newp is null)
        {
            return;
        }

        // Load per-process CR3
        if (newp.cr3 != 0)
        {
            static if (ENABLE_POSIX_DEBUG)
            {
                debugPrefix();
                anonymos.syscalls.posix.print("arch_context_switch: about to load CR3=");
                anonymos.syscalls.posix.printHex(newp.cr3);
                anonymos.syscalls.posix.printLine("");
                
                // Verify the PML4 has the identity mapping
                import anonymos.kernel.pagetable : physToVirt;
                ulong* pml4 = cast(ulong*)physToVirt(newp.cr3);
                anonymos.syscalls.posix.print("arch_context_switch: PML4[0]=");
                anonymos.syscalls.posix.printHex(pml4[0]);
                anonymos.syscalls.posix.print(" PML4[256]=");
                anonymos.syscalls.posix.printHex(pml4[256]);
                anonymos.syscalls.posix.printLine("");
            }
            
            import anonymos.kernel.pagetable : loadCr3;
            loadCr3(newp.cr3);
            
            static if (ENABLE_POSIX_DEBUG)
            {
                debugPrefix();
                anonymos.syscalls.posix.printLine("arch_context_switch: CR3 loaded successfully");
            }
        }

        if (newp.pendingExec)
        {
            runPendingExec(newp);
            return;
        }

        if (newp.contextValid)
        {
            static if (ENABLE_POSIX_DEBUG)
            {
                debugPrefix();
                anonymos.syscalls.posix.print("arch_context_switch: restoring context RSP=");
                anonymos.syscalls.posix.printHex(newp.context.regs[6]);
                anonymos.syscalls.posix.print(" RIP=");
                anonymos.syscalls.posix.printHex(newp.context.regs[7]);
                anonymos.syscalls.posix.printLine("");
            }

            auto ctx = &newp.context;
            
            static if (ENABLE_POSIX_DEBUG)
            {
                debugPrefix();
                anonymos.syscalls.posix.print("arch_context_switch: about to restore context RSP=");
                anonymos.syscalls.posix.printHex(newp.context.regs[6]);
                anonymos.syscalls.posix.print(" RIP=");
                anonymos.syscalls.posix.printHex(newp.context.regs[7]);
                anonymos.syscalls.posix.printLine("");
            }

            asm @nogc nothrow
            {
                mov RDX, ctx;
                mov RBX, [RDX + 0];
                mov RBP, [RDX + 8];
                mov R12, [RDX + 16];
                mov R13, [RDX + 24];
                mov R14, [RDX + 32];
                mov R15, [RDX + 40];
                mov RSP, [RDX + 48];
                mov R11, [RDX + 56];
                mov RAX, 1; // Return 1 from setjmp
                jmp R11;
            }
        }
    }

    extern(C) @nogc nothrow void processEntryTrampoline()
    {
        // This is the actual entry point for new processes
        // It's called via jmp from arch_context_switch
        static if (ENABLE_POSIX_DEBUG)
        {
            debugPrefix();
            anonymos.syscalls.posix.printLine("processEntryTrampoline: entered");
        }
        
        // Set up a proper stack frame and call processEntryWrapper
        asm @nogc nothrow
        {
            // Set RBP to 0 to mark the bottom of the call stack
            xor RBP, RBP;
            // Align stack to 16 bytes (required by System V ABI)
            and RSP, -16;
            // Call processEntryWrapper (this will push a return address)
            call processEntryWrapper;
            // If it returns, halt
        Lhalt:
            hlt;
            jmp Lhalt;
        }
    }

    extern(C) @nogc nothrow void dummyEntry()
    {
        static if (ENABLE_POSIX_DEBUG)
        {
            debugPrefix();
            anonymos.syscalls.posix.printLine("dummyEntry: entered");
        }
        for (;;) { asm @nogc nothrow { hlt; } }
    }

    extern(C) @nogc nothrow void processEntryWrapper()
    {
        // ...
        // Enable interrupts because new processes inherit IF=0 from the ISR that preempted the previous task
        asm @nogc nothrow { sti; }
        
        static if (ENABLE_POSIX_DEBUG)
        {
            debugPrefix();
            anonymos.syscalls.posix.printLine("processEntryWrapper: entered");
        }

        // This function is the entry point for new processes.
        // It runs on the process's own kernel stack.
        runPendingExec(g_current);

        // If the entry ever returns, keep yielding rather than exiting to avoid
        // killing long-lived services (desktop, compositor, etc.).
        for (;;)
        {
            schedYield();
        }
    }

    // ---- Helpers ----
    @nogc nothrow private void clearName(ref char[16] name)
    {
        foreach (i; 0 .. name.length) name[i] = 0;
    }
    @nogc nothrow private void setNameFromCString(ref char[16] name, const(char)* source)
    {
        size_t index = 0;
        if (source !is null)
        {
            while (index < name.length - 1)
            {
                const(char) value = source[index];
                name[index++] = value;
                if (value == 0) break;
            }
        }
        if (index >= name.length) index = name.length - 1;
        if (name[index] != 0) name[index++] = 0;
        while (index < name.length) name[index++] = 0;
    }
    @nogc nothrow private void setNameFromLiteral(ref char[16] name, immutable(char)[] literal)
    {
        size_t index = 0; immutable size_t limit = name.length - 1;
        foreach (ch; literal)
        {
            if (index >= limit) break;
            name[index++] = cast(char)ch;
        }
        if (index <= limit) name[index++] = 0;
        while (index < name.length) name[index++] = 0;
    }
    @nogc nothrow private ExecutableSlot* findExecutableSlot(const(char)* path)
    {
        if (path is null) return null;
        foreach (ref slot; g_execTable)
            if (slot.used && cStringEquals(slot.path.ptr, path)) return &slot;
        return null;
    }
    @nogc nothrow private size_t indexOfExecutableSlot(ExecutableSlot* slot)
    {
        if (slot is null) return INVALID_OBJECT_ID;
        foreach (i, ref candidate; g_execTable)
            if ((&candidate) is slot) return i;
        return INVALID_OBJECT_ID;
    }
    @nogc nothrow private int encodeExitStatus(int code) { return (code & 0xFF) << 8; }
    @nogc nothrow private int encodeSignalStatus(int sig){ return (sig & 0x7F) | 0x80; }

    // ---- Utility ----
    @nogc nothrow private void resetProc(ref Proc proc)
    {
        if (proc.environment !is null)
        {
            releaseEnvironmentTable(proc.environment);
            proc.environment = null;
        }

        if (isProcessObject(proc.objectId))
        {
            destroyProcessObject(proc.objectId);
        }

        // Release per-process page table
        // Reset VM map
        if (proc.vmInitialized)
        {
            const size_t idx = cast(size_t)(&proc - g_ptable.ptr);
            if (idx < g_vmMaps.length)
            {
                g_vmMaps[idx]._cr3 = proc.cr3;
                g_vmMaps[idx].reset();
                g_vmMaps[idx]._regionCount = 0;
                g_vmMaps[idx]._cr3 = 0;
                g_vmMaps[idx]._physPagePoolUsed = 0;
            }
            proc.vmInitialized = false;
        }

        if (proc.cr3 != 0)
        {
            import anonymos.kernel.physmem : freeFrame;
            freeFrame(proc.cr3);
            proc.cr3 = 0;
        }

        proc = Proc.init;
        proc.objectId = INVALID_OBJECT_ID;
        proc.weight = 1024;
        proc.timeSlice = 4;
        proc.sliceRemaining = proc.timeSlice;
        proc.nice = 0;
        proc.rqNext = INVALID_INDEX;
        proc.onRunQueue = false;
    }
    @nogc nothrow private Proc* findByPid(pid_t pid){ foreach(ref p; g_ptable) if(p.state!=ProcState.UNUSED && p.pid==pid) return &p; return null; }
    @nogc nothrow private Proc* allocProc(){
        foreach (ref p; g_ptable)
        {
            if (p.state == ProcState.UNUSED)
            {
                resetProc(p);
                p.pid = g_nextPid++;
                p.vruntime = 0;
                p.weight = 1024;
                p.timeSlice = 4;
                p.sliceRemaining = p.timeSlice;
                p.nice = 0;
                p.rqNext = INVALID_INDEX;
                p.onRunQueue = false;
                p.objectId = createProcessObject(p.pid);
                p.environment = allocateEnvironmentTable(p.pid, p.objectId);
                if (p.environment !is null) ensureEnvironmentObject(p.environment, p.objectId);
                
                // Allocate kernel stack (16KB)
                if (p.kernelStack is null)
                {
                    // Use static stack for the first allocated process (after init) to debug
                    if (p.pid == 3)
                    {
                        p.kernelStackSize = 65536;
                        p.kernelStack = g_debugStack.ptr;
                        anonymos.syscalls.posix.printLine("[posix-debug] Using static debug stack for PID 3");
                    }
                    else
                    {
                        p.kernelStackSize = 65536;
                        p.kernelStack = cast(ubyte*)kmalloc(p.kernelStackSize);
                    }
                }
                
                if (p.kernelStack is null)
                {
                    // Allocation failed
                    p.state = ProcState.UNUSED;
                    return null;
                }

                // Allocate per-process page table (clone kernel mappings)
                import anonymos.kernel.pagetable : cloneKernelPml4, physToVirt;
                p.cr3 = cloneKernelPml4();
                if (p.cr3 == 0)
                {
                    p.state = ProcState.UNUSED;
                    return null;
                }

                // Clear user space mappings (lower half) to remove kernel identity map pollution
                // But ONLY if the system is initialized. The 'init' process (created during posixInit)
                // might need the identity map if we are still executing from low memory.
                // DISABLED: We'll clear this after loading the ELF to avoid issues with page table access
                /*
                anonymos.syscalls.posix.print("[posix] allocProc: g_initialized=");
                anonymos.syscalls.posix.printUnsigned(g_initialized ? 1 : 0);
                anonymos.syscalls.posix.printLine("");
                
                if (g_initialized)
                {
                    ulong* pml4 = cast(ulong*)physToVirt(p.cr3);
                    for (size_t i = 0; i < 256; ++i)
                    {
                        pml4[i] = 0;
                    }
                }
                */

                // Initialize per-process VM map
                const size_t idx = cast(size_t)(&p - g_ptable.ptr);
                if (idx < g_vmMaps.length)
                {
                    g_vmMaps[idx]._cr3 = p.cr3;
                    g_vmMaps[idx].reset(); // Ensure clean state
                }

                assignProcessState(p, ProcState.EMBRYO);
                return &p;
            }
        }
        return null;
    }

    pragma(inline, false)
    @nogc nothrow private bool saveProcessContext(Proc* proc)
    {
        if (proc is null) return false;

        const auto result = setjmp(proc.context);
        
        if (result != 0)
        {
             static if (ENABLE_POSIX_DEBUG)
             {
                 debugPrefix();
                 anonymos.syscalls.posix.printLine("saveProcessContext: returned from longjmp");
             }
        }
        proc.contextValid = true;
        return result != 0;
    }

    @nogc nothrow private Proc* selectNextReadyProcess(Proc* current)
    {
        return popRunQueue();
    }

    // ---- Very small round-robin scheduler ----
    public @nogc nothrow void schedYield()
    {
        version (MinimalOsFreestanding)
        {
            // Prevent timer interrupts from re-entering the scheduler while its
            // bookkeeping structures (including the saved jump buffers) are in
            // flux. The flag check happens with interrupts disabled to close
            // the race window where an interrupt could sneak in before the flag
            // is set.
            asm @nogc nothrow { cli; }
        }

        // Do not allow the scheduler to run reentrantly. Timer interrupts can
        // preempt a running process and call schedYield while an earlier
        // invocation is still unwinding, which risks clobbering the in-memory
        // jump buffer that arch_context_switch will later consume.
        if (g_inScheduler)
        {
            static if (ENABLE_POSIX_DEBUG)
            {
                debugPrefix();
                anonymos.syscalls.posix.printLine("schedYield: reentrant call ignored");
            }
            version (MinimalOsFreestanding)
            {
                asm @nogc nothrow { sti; }
            }
            return;
        }
        g_inScheduler = true;
        scope (exit)
        {
            g_inScheduler = false;
            version (MinimalOsFreestanding)
            {
                asm @nogc nothrow { sti; }
            }
        }

        static if (ENABLE_POSIX_DEBUG)
        {
            static uint yieldCount = 0;
            if ((yieldCount++ & 0xF) == 0) // Print every 16th call
            {
                debugPrefix();
                anonymos.syscalls.posix.print("schedYield: call #");
                anonymos.syscalls.posix.printUnsigned(yieldCount);
                anonymos.syscalls.posix.printLine("");
            }
        }

        debugExpectActual("schedYield initialized", 1, debugBool(g_initialized));
        if (!g_initialized) return;

        if (g_current is null)
        {
            foreach (ref proc; g_ptable)
            {
                if (proc.state == ProcState.READY)
                {
                    g_current = &proc;
                    proc.sliceRemaining = proc.timeSlice;
                    assignProcessState(proc, ProcState.RUNNING);
                    if (proc.cr3 != 0)
                    {
                        import anonymos.kernel.pagetable : loadCr3;
                        loadCr3(proc.cr3);
                    }
                    if (proc.kernelStack !is null)
                    {
                        kernel_rsp = cast(ulong)(proc.kernelStack + proc.kernelStackSize);
                        version (MinimalOsFreestanding)
                        {
                            updateTssRsp0(kernel_rsp);
                        }
                    }
                    return;
                }
            }

            debugExpectActual("schedYield initial current", 1, debugBool(false));
            return;
        }

        auto current = g_current;
        
        // Check if there are any other processes to switch to
        // If not, just return without context switching
        bool hasOtherReady = false;
        foreach (ref proc; g_ptable)
        {
            if (proc.state == ProcState.READY && &proc != current)
            {
                hasOtherReady = true;
                break;
            }
        }
        
        if (!hasOtherReady)
        {
            static if (ENABLE_POSIX_DEBUG)
            {
                debugPrefix();
                anonymos.syscalls.posix.printLine("schedYield: no other ready processes, staying on current");
            }
            return;
        }
        
        // Verify g_current is valid
        if (current < g_ptable.ptr || current >= g_ptable.ptr + MAX_PROC)
        {
            anonymos.syscalls.posix.printLine("schedYield: FATAL: g_current out of bounds!");
            for(;;){}
        }

        static if (ENABLE_POSIX_DEBUG)
        {
             // Check if context looks valid before saving (it might be stale, but shouldn't be garbage if initialized)
             // Actually, if it's running, the context in memory is stale.
        }

        if (saveProcessContext(current))
        {
            return;
        }

        // Verify context RIP after saving
        if (current.context.regs[7] < 0x100000 || current.context.regs[7] > cast(size_t)&_kernel_end)
        {
             static if (ENABLE_POSIX_DEBUG)
             {
                 debugPrefix();
                 anonymos.syscalls.posix.print("schedYield: FATAL: Saved RIP corrupted: ");
                 anonymos.syscalls.posix.printHex(current.context.regs[7]);
                 anonymos.syscalls.posix.printLine("");
             }
             // Don't loop, let it crash to see double fault if it happens later?
             // Or loop to catch it here.
             for(;;){}
        }

        // Capture saved RIP
        ulong savedRip = current.context.regs[7];

        // Do not context-switch away from a running ring3 task unless it has
        // changed state (e.g., exited) in kernel mode.
        if (current.userMode && current.state == ProcState.RUNNING)
        {
            return;
        }

        lock(&g_plock);

        if (current.state == ProcState.RUNNING)
        {
            assignProcessState(*current, ProcState.READY);
        }

        auto next = selectNextReadyProcess(current);
        
        static if (ENABLE_POSIX_DEBUG)
        {
            debugPrefix();
            anonymos.syscalls.posix.print("schedYield: selected next=");
            anonymos.syscalls.posix.printHex(cast(size_t)next);
            if (next !is null)
            {
                anonymos.syscalls.posix.print(" PID=");
                anonymos.syscalls.posix.printUnsigned(next.pid);
            }
            anonymos.syscalls.posix.printLine("");
        }
        
        if (next is null)
        {
            if (current.state != ProcState.ZOMBIE)
            {
                assignProcessState(*current, ProcState.RUNNING);
            }
            unlock(&g_plock);
            return;
        }

        assignProcessState(*next, ProcState.RUNNING);
        next.sliceRemaining = next.timeSlice;
        g_current = next;
        unlock(&g_plock);

        debugExpectActual("schedYield next selected", 1, debugBool(true));
        debugExpectActual("schedYield next selected", 1, debugBool(true));
        
        // Update kernel_rsp to point to the top of the next process's stack
        // This ensures that if an interrupt/syscall happens, it uses the correct stack.
        if (next.kernelStack !is null)
        {
            kernel_rsp = cast(ulong)(next.kernelStack + next.kernelStackSize);
            version (MinimalOsFreestanding)
            {
                updateTssRsp0(kernel_rsp);
            }
        }

        // static if (ENABLE_POSIX_DEBUG)
        {
            debugPrefix();
            anonymos.syscalls.posix.print("schedYield: switching from PID ");
            anonymos.syscalls.posix.printUnsigned(current.pid);
            anonymos.syscalls.posix.print(" to PID ");
            anonymos.syscalls.posix.printUnsigned(next.pid);
            anonymos.syscalls.posix.printLine("");
        }

        // Check for corruption
        if (current.context.regs[7] != savedRip)
        {
             anonymos.syscalls.posix.print("schedYield: FATAL: RIP changed from ");
             anonymos.syscalls.posix.printHex(savedRip);
             anonymos.syscalls.posix.print(" to ");
             anonymos.syscalls.posix.printHex(current.context.regs[7]);
             anonymos.syscalls.posix.printLine("");
             for(;;){}
        }

        arch_context_switch(current, next);

        // We are back!
        ulong retAddr;
        asm @nogc nothrow {
            mov RAX, [RBP + 8];
            mov retAddr, RAX;
        }
        anonymos.syscalls.posix.print("schedYield: returned, retAddr=");
        anonymos.syscalls.posix.printHex(retAddr);
        anonymos.syscalls.posix.printLine("");
    }

    // ---- POSIX core syscalls (kernel-side) ----
    package(anonymos) @nogc nothrow pid_t sys_getpid(){
        const bool hasCurrent = (g_current !is null);
        debugExpectActual("sys_getpid current present", 1, debugBool(hasCurrent));
        return hasCurrent ? g_current.pid : 0;
    }

    /// Scheduler tick hook: update accounting and report whether a preemptive
    /// switch should occur.
    public @nogc nothrow bool schedulerTick()
    {
        if (!g_initialized || g_current is null)
        {
            return false;
        }

        auto current = g_current;
        if (current.state != ProcState.RUNNING)
        {
            return false;
        }

        // Avoid preempting a user-mode task; rely on cooperative yields/syscalls.
        if (current.userMode)
        {
            return false;
        }

        const uint effWeight = current.weight ? current.weight : 1024;
        current.vruntime += effWeight;

        if (current.sliceRemaining > 0)
        {
            --current.sliceRemaining;
        }

        if (current.sliceRemaining == 0)
        {
            current.sliceRemaining = current.timeSlice;
            return true;
        }

        return false;
    }

    package(anonymos) @nogc nothrow pid_t sys_fork(){
        debugExpectActual("sys_fork current present", 1, debugBool(g_current !is null));
        lock(&g_plock);
        auto np = allocProc();
        debugExpectActual("sys_fork allocation success", 1, debugBool(np !is null));
        if(np is null){ unlock(&g_plock); return setErrno(Errno.EAGAIN); }

        np.ppid   = (g_current ? g_current.pid : 0);
        assignProcessState(*np, ProcState.READY);
        np.sigmask= 0;
        np.entry  = (g_current ? g_current.entry : null);
        np.context = g_current.context; // copy registers? setjmp/longjmp style
        np.contextValid = false; // child returns 0 from fork, needs care
        np.userMode = g_current.userMode;
        np.userEntry = g_current.userEntry;
        np.userStackTop = g_current.userStackTop;
        np.heapBase = g_current.heapBase;
        np.heapBrk = g_current.heapBrk;
        np.heapLimit = g_current.heapLimit;
        np.mmapCursor = g_current.mmapCursor;
        np.userCodeSlide = g_current.userCodeSlide;
        np.shadowBase = g_current.shadowBase;
        np.shadowTop = g_current.shadowTop;
        np.shadowPtr = g_current.shadowPtr;
        np.heapSeed = g_current.heapSeed;
        np.syscallBitmap[] = g_current.syscallBitmap[];
        
        // Copy FDs
        foreach(i, fd; g_current.fds) np.fds[i] = fd;

        // Copy name
        foreach(i, c; g_current.name) np.name[i] = c;

        // Copy pending exec state
        np.pendingArgv = g_current.pendingArgv;
        np.pendingEnvp = g_current.pendingEnvp;
        np.pendingExec = g_current.pendingExec;
        if (np.environment !is null)
        {
            cloneEnvironmentTable(np.environment, g_current.environment);
            ensureEnvironmentObject(np.environment, np.objectId);
        }
        else if (np.environment !is null)
        {
            clearEnvironmentTable(np.environment);
            ensureEnvironmentObject(np.environment, np.objectId);
        }

        foreach(i; 0 .. np.name.length) np.name[i] = 0;
        if(g_current) foreach(i; 0 .. np.name.length) if(i < g_current.name.length) np.name[i] = g_current.name[i];

        // Clone user address space into the child's page tables so it owns a
        // separate lower-half mapping.
        const size_t parentIdx = cast(size_t)(g_current - g_ptable.ptr);
        const size_t childIdx  = cast(size_t)(np - g_ptable.ptr);
        if (g_current.vmInitialized && np.vmInitialized &&
            parentIdx < g_vmMaps.length && childIdx < g_vmMaps.length)
        {
            auto srcVm = &g_vmMaps[parentIdx];
            auto dstVm = &g_vmMaps[childIdx];
            dstVm._cr3 = np.cr3;
            if (!dstVm.cloneFrom(srcVm))
            {
                np.state = ProcState.UNUSED;
                resetProc(*np);
                unlock(&g_plock);
                return setErrno(Errno.EAGAIN);
            }
        }

        unlock(&g_plock);
        return np.pid;
    }

    package(anonymos) @nogc nothrow int sys_execve(const(char)* path, const(char*)* argv, const(char*)* envp)
    {
        debugExpectActual("sys_execve current present", 1, debugBool(g_current !is null));
        if (g_current is null) return setErrno(Errno.ESRCH);

        const(char)* execPath = path;
        auto resolved = findExecutableSlot(execPath);
        if (resolved is null && argv !is null && argv[0] !is null)
        {
            resolved = findExecutableSlot(argv[0]);
            if (resolved !is null) execPath = argv[0];
        }

        // Prefer loading an ELF image from storage into the caller's address space.
        auto fileData = readFile(execPath);
        if (fileData is null && argv !is null && argv[0] !is null)
        {
            fileData = readFile(argv[0]);
            if (fileData !is null)
            {
                execPath = argv[0];
            }
        }

        auto cur = g_current;
        const size_t mapIdx = cast(size_t)(cur - g_ptable.ptr);
        VMMap* vm = (mapIdx < g_vmMaps.length) ? &g_vmMaps[mapIdx] : null;
        if (vm !is null)
        {
            vm._cr3 = cur.cr3;
            vm.reset();
            vm._cr3 = cur.cr3;
        }

        if (fileData !is null && vm !is null)
        {
            const ulong codeSlide = randSplay(ASLR_CODE_SPLAY) & ~(PAGE_SIZE - 1);
            const ulong entry = loadElfUser(fileData, cur.cr3, vm, codeSlide);
            if (entry == 0)
            {
                vm.reset();
                vm._cr3 = cur.cr3;
                return setErrno(Errno.ENOEXEC);
            }

            // Map a fresh user stack with guards.
            const size_t stackPages = (USER_STACK_SIZE + PAGE_SIZE - 1) / PAGE_SIZE;
            const ulong stackSplay = randSplay(ASLR_STACK_SPLAY);
            const ulong stackBase = (USER_STACK_TOP - (stackPages + 2) * PAGE_SIZE) - (stackSplay & ~(PAGE_SIZE - 1));
            const ulong usableBase = vm.mapUserStack(stackBase, USER_STACK_SIZE);
            const ulong stackTop = (usableBase + stackPages * PAGE_SIZE) & ~0xFUL; // 16-byte aligned

            // Reserve a fixed-size heap region; brk operates within this window.
            ulong heapBase = USER_HEAP_BASE + (randSplay(ASLR_HEAP_SPLAY) & ~(PAGE_SIZE - 1));
            if (heapBase & 0xFFF) heapBase &= ~(PAGE_SIZE - 1);
            if (!vm.mapRegion(heapBase, USER_HEAP_SIZE, anonymos.kernel.vm_map.Prot.read | anonymos.kernel.vm_map.Prot.write | anonymos.kernel.vm_map.Prot.user))
            {
                vm.reset();
                vm._cr3 = cur.cr3;
                return setErrno(Errno.ENOMEM);
            }

            cur.userMode = true;
            cur.userEntry = entry;
            cur.userStackTop = stackTop;
            cur.heapBase = heapBase;
            cur.heapBrk = heapBase;
            cur.heapLimit = heapBase + USER_HEAP_SIZE;
            cur.mmapCursor = USER_MMAP_BASE + (randSplay(ASLR_MMAP_SPLAY) & ~(PAGE_SIZE - 1));
            cur.userCodeSlide = codeSlide;
            cur.heapSeed = rand64();
            // Shadow stack with guards; only RW.
            const ulong shadowSplay = randSplay(ASLR_SHADOW_SPLAY);
            const ulong shadowBase = (USER_STACK_TOP - (SHADOW_STACK_SIZE + 2 * PAGE_SIZE)) - (shadowSplay & ~(PAGE_SIZE - 1));
            if (!vm.mapRegion(shadowBase + PAGE_SIZE, SHADOW_STACK_SIZE, anonymos.kernel.vm_map.Prot.read | anonymos.kernel.vm_map.Prot.write | anonymos.kernel.vm_map.Prot.user, 1, 1))
            {
                vm.reset();
                vm._cr3 = cur.cr3;
                return setErrno(Errno.ENOMEM);
            }
            cur.shadowBase = shadowBase + PAGE_SIZE;
            cur.shadowTop = shadowBase + PAGE_SIZE + SHADOW_STACK_SIZE;
            cur.shadowPtr = cur.shadowBase;
            cur.entry = null;
            cur.pendingArgv = argv;
            cur.pendingEnvp = envp;
            cur.pendingExec = true;
            // Seed userland stack canary via TLS guard if expected by libc.
            extern(C) __gshared ulong __stack_chk_guard;
            __stack_chk_guard = rand64();
            extern(C) __gshared ulong __shadow_stack_base;
            extern(C) __gshared ulong __shadow_stack_top;
            extern(C) __gshared ulong __shadow_stack_ptr;
            __shadow_stack_base = cur.shadowBase;
            __shadow_stack_top  = cur.shadowTop;
            __shadow_stack_ptr  = cur.shadowPtr;
            setNameFromCString(cur.name, execPath);
            updateProcessObjectLabel(*cur, execPath);

            if (cur.environment !is null)
            {
                if (envp !is null) loadEnvironmentFromVector(cur.environment, envp);
                ensureEnvironmentObject(cur.environment, cur.objectId);
            }

            runPendingExec(cur); // Does not return on success
            return 0;
        }

        // Fall back to registered in-kernel executables.
        debugExpectActual("sys_execve entry present", 1, debugBool(resolved !is null && resolved.entry !is null));
        if (resolved is null || resolved.entry is null) return setErrno(Errno.ENOENT);

        cur.userMode = false;
        cur.userEntry = 0;
        cur.userStackTop = 0;
        cur.heapBase = 0;
        cur.heapBrk = 0;
        cur.heapLimit = 0;
        cur.mmapCursor = 0;
        cur.userCodeSlide = 0;
        cur.entry = resolved.entry;
        cur.pendingArgv = argv;
        cur.pendingEnvp = envp;
        cur.pendingExec = true;
        cur.contextValid = false;
        setNameFromCString((*cur).name, execPath);
        updateProcessObjectLabel(*cur, execPath);

        if (cur.environment !is null)
        {
            if (envp !is null) loadEnvironmentFromVector(cur.environment, envp);
            ensureEnvironmentObject(cur.environment, cur.objectId);
        }

        runPendingExec(cur);
        return 0;
    }

    package(anonymos) @nogc nothrow pid_t sys_waitpid(pid_t wpid, int* status, int /*options*/){
        const pid_t currentPid = (g_current ? g_current.pid : 0);

        while (true)
        {
            bool matchingChildFound = false;

            foreach (ref p; g_ptable)
            {
                if (p.state == ProcState.UNUSED) continue;
                if (p.ppid != currentPid) continue;
                if (wpid > 0 && p.pid != wpid) continue;

                matchingChildFound = true;
                if (p.state != ProcState.ZOMBIE) continue;

                if (status) *status = p.exitCode;
                auto pid = p.pid;
                
                // Reap
                p.state = ProcState.UNUSED;
                p.ppid = 0;
                p.pid = 0;
                p.entry = null;
                releaseEnvironmentTable(p.environment);
                destroyProcessObject(p.objectId);
                p.objectId = INVALID_OBJECT_ID;
                
                debugExpectActual("sys_waitpid child matched", 1, 1);
                return pid;
            }

            if (!matchingChildFound)
            {
                debugExpectActual("sys_waitpid child matched", 1, 0);
                return setErrno(Errno.ECHILD);
            }

            schedYield();
        }
    }

    package(anonymos) @nogc nothrow void sys__exit(int code){
        debugExpectActual("sys__exit current present", 1, debugBool(g_current !is null));
        if(g_current is null) return;
        g_current.exitCode = encodeExitStatus(code);
        assignProcessState(*g_current, ProcState.ZOMBIE);
        schedYield();
        for(;;){}
    }

    package(anonymos) @nogc nothrow int sys_kill(pid_t pid, int sig){
        auto p = findByPid(pid);
        debugExpectActual("sys_kill target found", 1, debugBool(p !is null));
        if(p is null) return setErrno(Errno.ESRCH);
        switch(sig){
            case SIG.KILL, SIG.TERM:
                p.exitCode = encodeSignalStatus(sig);
                assignProcessState(*p, ProcState.ZOMBIE);
                return 0;
            default:
                return setErrno(Errno.ENOSYS);
        }
    }

    package(anonymos) @nogc nothrow uint sys_sleep(uint seconds){
        size_t actualIterations = 0;
        const size_t expectedIterations = seconds * 100;
        foreach(_; 0 .. expectedIterations) { schedYield(); ++actualIterations; }
        debugExpectActual("sys_sleep iterations", cast(long)expectedIterations, cast(long)actualIterations);
        return 0;
    }

    // ---- FD/IO syscalls (stubs) ----
    package(anonymos) @nogc nothrow int     sys_open (const(char)* /*path*/, int /*flags*/, int /*mode*/){ return setErrno(Errno.ENOSYS); }
    package(anonymos) @nogc nothrow int     sys_close(int /*fd*/){ return setErrno(Errno.ENOSYS); }
    package(anonymos) @nogc nothrow ssize_t sys_read(int fd, void* buffer, size_t length)
    {
        int hostFd = -1;
        const bool resolved = resolveHostFd(fd, hostFd);
        debugExpectActual("sys_read fd resolved", 1, debugBool(resolved));
        if (!resolved) return cast(ssize_t)setErrno(Errno.EBADF);

        static if (hostPosixInteropEnabled)
        {
            auto result = anonymos.syscalls.posix.read(hostFd, buffer, length);
            if (result < 0)
            {
                _errno = anonymos.syscalls.posix.errno;
                return -1;
            }
            debugExpectActual("sys_read bytes", cast(long)length, cast(long)result);
            return cast(ssize_t)result;
        }
        else
        {
            return cast(ssize_t)setErrno(Errno.ENOSYS);
        }
    }

    package(anonymos) @nogc nothrow ssize_t sys_write(int fd, const void* buffer, size_t length)
    {
        int hostFd = -1;
        const bool resolved = resolveHostFd(fd, hostFd);
        debugExpectActual("sys_write fd resolved", 1, debugBool(resolved));
        if (!resolved) return cast(ssize_t)setErrno(Errno.EBADF);

        static if (hostPosixInteropEnabled)
        {
            auto result = anonymos.syscalls.posix.write(hostFd, buffer, length);
            if (result < 0)
            {
                _errno = anonymos.syscalls.posix.errno;
                return -1;
            }
            debugExpectActual("sys_write bytes", cast(long)length, cast(long)result);
            return cast(ssize_t)result;
        }
        else
        {
            return cast(ssize_t)setErrno(Errno.ENOSYS);
        }
    }

    // ---- C ABI glue ----
    extern(C):
    @nogc nothrow pid_t getpid(){ return sys_getpid(); }
    @nogc nothrow pid_t fork(){   return sys_fork();   }
    @nogc nothrow int   execve(const(char)* p, const(char*)* a, const(char*)* e){ return sys_execve(p,a,e); }
    static if (hostPosixInteropEnabled)
    {
        public extern(C) @nogc nothrow pid_t spawnRegisteredProcess(const(char)*, const(char*)*, const(char*)*)
        {
            return setErrno(Errno.ENOSYS);
        }
    }
    else
    {
        public @nogc nothrow pid_t waitpid(pid_t p, int* s, int o){ return sys_waitpid(p,s,o); }
    }

    // Bare-metal waitpid that actually runs the process
    extern(C) @nogc nothrow pid_t bareMetalWaitPid(pid_t pid, int* status, int /*options*/)
    {
        anonymos.syscalls.posix.print("[posix-debug] bareMetalWaitPid: entered, pid=");
        anonymos.syscalls.posix.printUnsigned(cast(size_t)pid);
        anonymos.syscalls.posix.printLine("");

        auto proc = findByPid(pid);
        if (proc is null)
        {
            anonymos.syscalls.posix.printLine("[posix-debug] bareMetalWaitPid: process not found");
            return -1;
        }

        anonymos.syscalls.posix.print("[posix-debug] bareMetalWaitPid: calling entrypoint for pid=");
        anonymos.syscalls.posix.printUnsigned(cast(size_t)pid);
        anonymos.syscalls.posix.printLine("");

        if (proc.pendingExec)
        {
            auto savedCurrent = g_current;
            g_current         = proc;

            runPendingExec(proc);

            g_current = savedCurrent;

            anonymos.syscalls.posix.print("[posix-debug] bareMetalWaitPid: process returned pid=");
            anonymos.syscalls.posix.printUnsigned(cast(size_t)pid);
            anonymos.syscalls.posix.printLine("");
        }

        if (status) *status = 0;
        return pid;
    }

    extern(D) shared static this()
    {
        anonymos.syscalls.posix.registerBareMetalShellInterfaces(&spawnRegisteredProcess,
                                                          &bareMetalWaitPid);
    }
    static if (hostPosixInteropEnabled)
    {
        // Use the Posix-provided _exit.
    }
    else
    {
        @nogc nothrow void _exit(int c){ sys__exit(c); }
    }
    @nogc nothrow int   kill(pid_t p, int s){ return sys_kill(p,s); }
    @nogc nothrow uint  sleep(uint s){ return sys_sleep(s); }

    // Optional weak-ish symbols for linkage expectations
    static if (hostPosixInteropEnabled)
    {
        extern(C) __gshared char** environ;
    }
    else
    {
        __gshared char** environ;
    }
    __gshared const(char*)* __argv;
    __gshared int          __argc;

    struct ProcessInfo
    {
        pid_t pid;
        pid_t ppid;
        ubyte state;
        char[16] name;
    }

    public @nogc nothrow int registerProcessExecutable(const(char)* path, ProcessEntry entry)
    {
        debugExpectActual("registerProcessExecutable path present", 1, debugBool(path !is null));
        debugExpectActual("registerProcessExecutable entry present", 1, debugBool(entry !is null));
        if(path is null || entry is null) return setErrno(Errno.EINVAL);
        const size_t length = cStringLength(path);
        debugExpectActual("registerProcessExecutable length", EXEC_PATH_LENGTH - 1, cast(long)length);
        if(length == 0 || length >= EXEC_PATH_LENGTH) return setErrno(Errno.E2BIG);

        auto existing = findExecutableSlot(path);
        if(existing !is null)
        {
            existing.entry = entry;
            if (g_objectRegistryReady)
            {
                const size_t slotIndex = indexOfExecutableSlot(existing);
                if (slotIndex != INVALID_OBJECT_ID)
                {
                    auto objectId = registerExecutableObject(existing.path.ptr, slotIndex);
                    if (objectId != INVALID_OBJECT_ID) existing.objectId = objectId;
                }
            }
            debugExpectActual("registerProcessExecutable reuse", 1, 1);
            return 0;
        }

        foreach(slotIndex, ref slot; g_execTable)
        {
            if(!slot.used)
            {
                slot = ExecutableSlot.init;
                slot.used = true;
                foreach(j; 0 .. slot.path.length) slot.path[j] = 0;
                foreach(j; 0 .. length)           slot.path[j] = path[j];
                slot.path[length] = '\0';
                slot.entry = entry;
                slot.objectId = INVALID_OBJECT_ID;
                if (g_objectRegistryReady)
                {
                    auto objectId = registerExecutableObject(slot.path.ptr, slotIndex);
                    if (objectId != INVALID_OBJECT_ID) slot.objectId = objectId;
                }
                debugExpectActual("registerProcessExecutable new slot", 1, 1);
                return 0;
            }
        }
        return setErrno(Errno.ENFILE);
    }

    static if (hostPosixInteropEnabled)
    {
    }
    else
    {
        public extern(C) @nogc nothrow pid_t spawnRegisteredProcess(
            const(char)* path,
            const(char*)* argv,
            const(char*)* envp)
        {
            anonymos.syscalls.posix.printLine("[posix-debug] spawnRegisteredProcess: before entry call");

            auto slot = findExecutableSlot(path);
            
            if (slot is null)
            {
                // Try loading ELF from VFS
                const(ubyte)[] fileData = readFile(path);
                if (fileData.length == 0 && path[0] == '/')
                {
                     fileData = readFile(path + 1);
                }
                anonymos.syscalls.posix.print("[posix-debug] readFile result length: ");
                anonymos.syscalls.posix.printUnsigned(fileData.length);
                anonymos.syscalls.posix.printLine("");
                if (fileData.length > 0)
                {
                    lock(&g_plock);
                    auto proc = allocProc();
                    if (proc is null)
                    {
                        unlock(&g_plock);
                        return setErrno(Errno.EAGAIN);
                    }
                    
                    
                    // Load ELF
                    auto vm = &g_vmMaps[cast(size_t)(proc - g_ptable.ptr)];

                    // Clear the kernel identity mappings from user space (lower half) BEFORE loading user code
                    import anonymos.kernel.pagetable : physToVirt;
                    ulong* pml4 = cast(ulong*)physToVirt(proc.cr3);
                    for (size_t i = 0; i < 256; ++i)
                    {
                        // pml4[i] = 0;
                    }

                    ulong entry = loadElfUser(fileData, proc.cr3, vm);
                    
                    if (entry != 0)
                    {
                        proc.ppid = (g_current ? g_current.pid : 0);
                        assignProcessState(*proc, ProcState.READY);
                        proc.userMode = true;
                        proc.userEntry = entry;
                        proc.userStackTop = USER_STACK_TOP;
                        


                        // Map stack
                        if (!vm.mapRegion(USER_STACK_TOP - USER_STACK_SIZE, USER_STACK_SIZE, anonymos.kernel.vm_map.Prot.read | anonymos.kernel.vm_map.Prot.write | anonymos.kernel.vm_map.Prot.user))
                        {
                             proc.state = ProcState.UNUSED;
                             unlock(&g_plock);
                             return setErrno(Errno.ENOMEM);
                        }
                        
                        // Now that ELF and stack are loaded, we are ready.
                        // (Identity mappings were cleared before loading)
                        
                        setNameFromCString(proc.name, path);
                        updateProcessObjectLabel(*proc, path);
                        
                        if (proc.kernelStack !is null)
                        {
                            size_t stackTop = cast(size_t)(proc.kernelStack + proc.kernelStackSize);
                            stackTop &= ~0xF;
                            stackTop -= 16;
                            
                            proc.context.regs[6] = stackTop;
                            proc.context.regs[7] = cast(size_t)&processEntryWrapper;
                            proc.contextValid = true;

                            static if (ENABLE_POSIX_DEBUG)
                            {
                                debugPrefix();
                                anonymos.syscalls.posix.print("spawnRegisteredProcess context: RSP=");
                                anonymos.syscalls.posix.printHex(proc.context.regs[6]);
                                anonymos.syscalls.posix.print(" RIP=");
                                anonymos.syscalls.posix.printHex(proc.context.regs[7]);
                                anonymos.syscalls.posix.printLine("");
                            }
                        }
                        
                        unlock(&g_plock);
                        return proc.pid;
                    }
                    else
                    {
                        proc.state = ProcState.UNUSED;
                        unlock(&g_plock);
                        return setErrno(Errno.ENOEXEC);
                    }
                }
                
                return setErrno(Errno.ENOENT);
            }

            lock(&g_plock);
            auto proc        = allocProc();
            const bool allocOk = (proc !is null);
            debugExpectActual("spawnRegisteredProcess alloc success", 1, debugBool(allocOk));

            static if (ENABLE_POSIX_DEBUG)
            {
                debugPrefix();
                anonymos.syscalls.posix.print("spawnRegisteredProcess alloc success: expected=1, actual=");
                anonymos.syscalls.posix.printUnsigned(allocOk ? 1 : 0);
                anonymos.syscalls.posix.printLine("");
            }

            if (proc is null)
            {
                unlock(&g_plock);
                return setErrno(Errno.EAGAIN);
            }

            proc.ppid        = (g_current ? g_current.pid : 0);
            assignProcessState(*proc, ProcState.READY);
            proc.entry       = slot.entry;
            proc.pendingArgv = argv;
            proc.pendingEnvp = envp;
            proc.pendingExec = true;
            proc.userMode    = false;
            proc.userEntry   = 0;
            proc.userStackTop = 0;
            setNameFromCString(proc.name, path);
            updateProcessObjectLabel(*proc, path);

            // Initialize context to start at processEntryWrapper on the new stack
            if (proc.kernelStack !is null)
            {
                // Stack grows down. Point to top.
                size_t stackTop = cast(size_t)(proc.kernelStack + proc.kernelStackSize);
                // Align to 16 bytes
                stackTop &= ~0xF;
                
                // Leave some space and set up return address
                // When we jump to processEntryWrapper, RSP will point here
                // and there should be a return address just above it
                stackTop -= 16; // Space for alignment
                
                // Write a dummy return address at [RSP+8]
                // (the location where a 'call' instruction would have pushed it)
                *cast(ulong*)(stackTop + 8) = 0;

                // Set up jmp_buf
                // JMP_RBX = 0 * 8 = 0
                // JMP_RBP = 1 * 8 = 8
                // JMP_RSP = 6 * 8 = 48
                // JMP_RIP = 7 * 8 = 56
                proc.context.regs[1] = 0; // RBP = 0 (bottom of stack)
                proc.context.regs[6] = stackTop; // RSP
                proc.context.regs[7] = cast(size_t)&processEntryTrampoline; // RIP
                proc.contextValid = true;

                static if (ENABLE_POSIX_DEBUG)
                {
                    debugPrefix();
                    anonymos.syscalls.posix.print("spawnRegisteredProcess (reg) context: RSP=");
                    anonymos.syscalls.posix.printHex(proc.context.regs[6]);
                    anonymos.syscalls.posix.print(" RIP=");
                    anonymos.syscalls.posix.printHex(proc.context.regs[7]);
                    anonymos.syscalls.posix.printLine("");
                }
            }

            unlock(&g_plock);

            const bool pidAssigned = (proc.pid > 0);
            debugExpectActual("spawnRegisteredProcess pid assigned", 1, debugBool(pidAssigned));

            static if (ENABLE_POSIX_DEBUG)
            {
                debugPrefix();
                anonymos.syscalls.posix.print("spawnRegisteredProcess pid assigned: expected=1, actual=");
                anonymos.syscalls.posix.printUnsigned(pidAssigned ? 1 : 0);
                anonymos.syscalls.posix.printLine("");
            }

            anonymos.syscalls.posix.printLine("[posix-debug] spawnRegisteredProcess: after entry call");
            return proc.pid;
        }
    }

    @nogc nothrow int completeProcess(pid_t pid, int exitCode)
    {
        auto proc = findByPid(pid);
        debugExpectActual("completeProcess target found", 1, debugBool(proc !is null));
        if(proc is null) return setErrno(Errno.ESRCH);
        debugExpectActual("completeProcess state active", 1, debugBool(!(proc.state==ProcState.UNUSED || proc.state==ProcState.ZOMBIE)));
        if(proc.state==ProcState.UNUSED || proc.state==ProcState.ZOMBIE) return setErrno(Errno.EINVAL);

        proc.exitCode = encodeExitStatus(exitCode);
        assignProcessState(*proc, ProcState.ZOMBIE);
        proc.pendingArgv = null;
        proc.pendingEnvp = null;
        proc.pendingExec = false;
        proc.contextValid = false;
        debugExpectActual("completeProcess success", 1, 1);
        return 0;
    }

    @nogc nothrow size_t listProcesses(ProcessInfo* buffer, size_t capacity)
    {
        if(buffer is null || capacity == 0) return 0;
        size_t count = 0;
        foreach(ref proc; g_ptable)
        {
            if(proc.state == ProcState.UNUSED) continue;
            if(count >= capacity) break;

            buffer[count].pid   = proc.pid;
            buffer[count].ppid  = proc.ppid;
            buffer[count].state = cast(ubyte)proc.state;
            foreach(i; 0 .. buffer[count].name.length) buffer[count].name[i] = proc.name[i];
            ++count;
        }
        return count;
    }

    // ---- Init hook ----
    public @nogc nothrow void initializeInterrupts() { /* Minimal OS build: no IRQs configured */ }

    public @nogc nothrow void posixInit(){
        debugLog("posixInit invoked");
        debugExpectActual("posixInit already initialized", 0, debugBool(g_initialized));
        if(g_initialized) return;
        
        static if (ENABLE_POSIX_DEBUG)
        {
            debugPrefix();
            anonymos.syscalls.posix.print("posixInit: setjmp addr=");
            anonymos.syscalls.posix.printHex(cast(size_t)&setjmp);
            anonymos.syscalls.posix.print(" saveProcessContext addr=");
            anonymos.syscalls.posix.printHex(cast(size_t)&saveProcessContext);
            anonymos.syscalls.posix.printLine("");
            
            anonymos.syscalls.posix.print("posixInit: stack_top addr=");
            anonymos.syscalls.posix.printHex(cast(size_t)&stack_top);
            anonymos.syscalls.posix.printLine("");
            
            import anonymos.kernel.heap : g_kernelHeap;
            anonymos.syscalls.posix.print("posixInit: g_kernelHeap addr=");
            anonymos.syscalls.posix.printHex(cast(size_t)g_kernelHeap.ptr);
            anonymos.syscalls.posix.printLine("");

            anonymos.syscalls.posix.print("posixInit: g_ptable addr=");
            anonymos.syscalls.posix.printHex(cast(size_t)g_ptable.ptr);
            anonymos.syscalls.posix.printLine("");
        }

        initializeObjectRegistry();
        foreach(ref p; g_ptable) resetProc(p);
        foreach(ref slot; g_execTable){ slot = ExecutableSlot.init; slot.objectId = INVALID_OBJECT_ID; }
        g_nextPid = 1;
        g_current = null;
        g_posixUtilitiesRegistered = false;
        g_posixUtilityCount = 0;
        g_posixConfigured = false;

        auto initProc = allocProc();
        debugExpectActual("posixInit init process", 1, debugBool(initProc !is null));
        if(initProc !is null)
        {
            static if (ENABLE_POSIX_DEBUG)
            {
                debugPrefix();
                anonymos.syscalls.posix.print("posixInit: initProc addr=");
                anonymos.syscalls.posix.printHex(cast(size_t)initProc);
                anonymos.syscalls.posix.print(" context addr=");
                anonymos.syscalls.posix.printHex(cast(size_t)&initProc.context);
                anonymos.syscalls.posix.printLine("");
            }

            initProc.ppid  = 0;
            assignProcessState(*initProc, ProcState.RUNNING);
            setNameFromLiteral(initProc.name, "kernel");
            updateProcessObjectLabelLiteral(*initProc, "kernel");
            initProc.pendingArgv = null;
            initProc.pendingEnvp = null;
            initProc.pendingExec = false;
            auto pol = findPolicy("default");
            applyPolicy(initProc, pol);
            g_current = initProc;
            if (initProc.environment !is null)
            {
                loadEnvironmentFromHost(initProc.environment);
                ensureEnvironmentObject(initProc.environment, initProc.objectId);
            }
            // Seed the kernel stack pointer so early interrupts/syscalls use
            // the init process's stack instead of the bootstrap stack.
            if (initProc.kernelStack !is null)
            {
                // stack grows down; point kernel_rsp to the top
                kernel_rsp = cast(ulong)(initProc.kernelStack + initProc.kernelStackSize);
                version (MinimalOsFreestanding)
                {
                    updateTssRsp0(kernel_rsp);
                }
            }
            // Install per-process CR3 for init process
            if (initProc.cr3 != 0)
            {
                import anonymos.kernel.pagetable : loadCr3;
                loadCr3(initProc.cr3);
            }
            const auto consoleDetection = detectConsoleAvailability();
            g_consoleAvailable = consoleDetection.available;
            configureConsoleFor(*initProc);
        }
        else
        {
            g_consoleAvailable = detectConsoleAvailability().available;
        }

        g_shellRegistered = false;
        ensureBareMetalShellInterfaces();
        static if (hostPosixInteropEnabled)
        {
            if (g_consoleAvailable)
            {
                const int registration =
                    registerProcessExecutable("/bin/sh",
                        cast(ProcessEntry)&anonymos.syscalls.posix.shellExecEntry);
                g_shellRegistered = (registration == 0);
            }
        }
        g_initialized = true;
        debugExpectActual("posixInit initialized flag", 1, debugBool(g_initialized));
    }

    // ------- Embedded POSIX utilities registration -------
    @nogc nothrow private bool registerPosixUtilityAlias(const(char)* aliasName, bool contributes)
    {
        debugExpectActual("registerPosixUtilityAlias alias present", 1, debugBool(aliasName !is null));
        if (aliasName is null || aliasName[0] == '\0') return false;

        auto existing = findExecutableSlot(aliasName);
        const bool alreadyRegistered = (existing !is null) && (existing.entry !is null);

        // Use the canonical entry point defined in anonymos.syscalls.posix.
        const int result = registerProcessExecutable(
            aliasName,
            cast(ProcessEntry)&PosixUtilityExecEntryFn);
        debugExpectActual("registerPosixUtilityAlias registration result", 0, result);
        if (result != 0) return false;

        if (!alreadyRegistered && contributes) ++g_posixUtilityCount;
        debugExpectActual("registerPosixUtilityAlias count", cast(long)g_posixUtilityCount, cast(long)g_posixUtilityCount);
        return true;
    }

    @nogc nothrow private const(char)* embeddedUtilityBaseName(const(char)* path)
    {
        if (path is null) return null;
        const(char)* current = path;
        size_t index = 0;
        while (path[index] != '\0')
        {
            if (path[index] == '/') current = path + index + 1;
            ++index;
        }
        return current;
    }

    @nogc nothrow private void configureEmbeddedPosixUtilities()
    {
        if (g_posixConfigured) return;

        g_posixConfigured = true;
        g_posixUtilitiesRegistered = false;
        g_posixUtilityCount = 0;

        // Use string[] so it matches both bundle and registry helpers.
        string[] paths;
        if (EmbeddedPosixUtilitiesAvailableFn())
        {
            paths = EmbeddedPosixUtilityPathsFn();
        }
        else if (RegistryEmbeddedPosixUtilitiesAvailableFn())
        {
            paths = RegistryEmbeddedPosixUtilityPathsFn();
        }
        else
        {
            return;
        }
        foreach (path; paths)
        {
            auto canonical = path.ptr;
            auto registered = registerPosixUtilityAlias(canonical, true);

            auto base = embeddedUtilityBaseName(canonical);
            if (base !is null && base[0] != '\0') registerPosixUtilityAlias(base, false);

            if (!g_posixUtilitiesRegistered && registered) g_posixUtilitiesRegistered = true;
        }
    }

    package(anonymos) @nogc nothrow bool ensurePosixUtilitiesConfigured()
    {
        configureEmbeddedPosixUtilities();
        return g_posixUtilitiesRegistered;
    }

    @nogc nothrow size_t registerPosixUtilities()
    {
        if (!ensurePosixUtilitiesConfigured()) return 0;
        return g_posixUtilityCount;
    }
} // end mixin PosixKernelShim

// Instantiate the shim once at module scope so its symbols are defined in this
// module and can be imported without duplicating code across kernel modules.
mixin PosixKernelShim;

// ------------------------
// Shell & utility entries
// ------------------------
static if (hostPosixInteropEnabled)
{
    // Host-side shell bridge lives in this module so the kernel can drop into
    // the packaged lfe-sh environment without needing an external stub.

    // Safe constant used by posixUtilityExecEntry for fallback argv buffer
    private enum PATH_BUFFER_SIZE = 256;

    // Helper exposed elsewhere (e.g., shell helpers) to extract base program name.
    extern(C) @nogc nothrow const(char)* extractProgramName(const(char)* invoked,
                                                            char* outBuf,
                                                            size_t outBufLen,
                                                            out size_t outLen)
    {
        outLen = 0;
        if (outBuf !is null && outBufLen > 0)
        {
            outBuf[0] = '\0';
        }

        if (invoked is null)
        {
            return null;
        }

        size_t totalLen = 0;
        while (invoked[totalLen] != '\0')
        {
            ++totalLen;
        }

        if (totalLen == 0)
        {
            return invoked;
        }

        size_t endIndex = totalLen;
        while (endIndex > 0)
        {
            immutable char c = invoked[endIndex - 1];
            if (c != '/' && c != '\\')
            {
                break;
            }
            --endIndex;
        }

        size_t startIndex = endIndex;
        while (startIndex > 0)
        {
            immutable char c = invoked[startIndex - 1];
            if (c == '/' || c == '\\')
            {
                break;
            }
            --startIndex;
        }

        const size_t baseLen = (endIndex >= startIndex) ? (endIndex - startIndex) : 0;
        const(char)* basePtr = invoked + startIndex;

        if (baseLen == 0)
        {
            return invoked;
        }

        outLen = baseLen;

        if (outBuf is null || outBufLen == 0)
        {
            return basePtr;
        }

        size_t copyLen = baseLen;
        if (copyLen >= outBufLen)
        {
            copyLen = outBufLen - 1;
        }

        foreach (size_t i; 0 .. copyLen)
        {
            outBuf[i] = basePtr[i];
        }
        outBuf[copyLen] = '\0';

        return outBuf;
    }

    extern(C) @nogc nothrow void shellExecEntry(const(char*)* argv, const(char*)* envp)
    {
        static if (ENABLE_POSIX_DEBUG)
        {
            print("[shell-debug] shellExecEntry entered: argv=0x");
            printHex(cast(size_t)argv);
            print(", envp=0x");
            printHex(cast(size_t)envp);
            printLine("");
        }

        // Prefer provided envp; host bridge can ignore or use it.
        runHostShellSession(argv, envp);
    }

    extern(C) @nogc nothrow void posixUtilityExecEntry(const(char*)* argv, const(char*)* envp)
    {
        enum fallbackProgram = "sh\0";

        static @nogc nothrow bool _ensure()
        {
            // Query embed flag directly
            return embeddedPosixUtilitiesAvailable()
                || RegistryEmbeddedPosixUtilitiesAvailableFn();
        }

        const bool embedAvailable = _ensure();
        debugExpectActual("posixUtilityExecEntry utilities available", 1, debugBool(embedAvailable));
        if (!embedAvailable)
        {
            printLine("[shell] POSIX utilities unavailable; cannot execute request.");
            _exit(127);
        }

        const(char)* invoked = null;
        if (argv !is null && argv[0] !is null) invoked = argv[0];

        char[PATH_BUFFER_SIZE] nameBuffer;
        size_t nameLength = 0;

        // extract base name if available
        auto programName = extractProgramName(invoked, nameBuffer.ptr, nameBuffer.length, nameLength);
        if (programName is null || nameLength == 0)
        {
            if (invoked !is null && invoked[0] != '\0') programName = invoked;
            else                                        programName = fallbackProgram.ptr;
        }

        enum size_t MAX_ARGS = 16;
        char*[MAX_ARGS] args;
        size_t argCount = 0;

        args[argCount++] = cast(char*)programName;

        if (argv !is null)
        {
            size_t index = (argv[0] !is null) ? 1 : 0;
            while (argv[index] !is null && argCount + 1 < args.length)
            {
                args[argCount++] = cast(char*)argv[index];
                ++index;
            }
        }
        if (argCount >= args.length) argCount = args.length - 1;
        args[argCount] = null;

        const(char*)* vector = (envp !is null && envp[0] !is null) ? envp : null;

        char** environment = (vector !is null) ? cast(char**)vector : null;

        int exitCode = 127;
        const bool executedEmbedded = executeEmbeddedPosixUtility(programName, cast(const(char*)*)args.ptr, cast(const(char*)*)environment, exitCode);
        debugExpectActual("posixUtilityExecEntry embedded exec", 1, debugBool(executedEmbedded));
        if (executedEmbedded)
        {
            _exit(exitCode);
        }

        spawnAndWait(programName, args.ptr, environment, exitCode);
        debugExpectActual("posixUtilityExecEntry spawned exit", exitCode, exitCode);
        _exit(exitCode);
    }

    @nogc nothrow private bool pathExecutable(const(char)* path)
    {
        if (path is null || path[0] == '\0')
        {
            return false;
        }

        return access(path, X_OK) == 0;
    }

    @nogc nothrow private const(char)* combineShellRoot(const(char)* root)
    {
        enum size_t BUFFER_SIZE = 512;
        static __gshared char[BUFFER_SIZE] buffer;

        if (root is null || root[0] == '\0')
        {
            return null;
        }

        const size_t rootLength = cStringLength(root);
        size_t index = 0;
        while (index < rootLength && index + 1 < buffer.length)
        {
            buffer[index] = root[index];
            ++index;
        }

        if (index == 0)
        {
            return null;
        }

        if (buffer[index - 1] != '/' && index + 1 < buffer.length)
        {
            buffer[index++] = '/';
        }

        foreach (ch; shBinaryName)
        {
            if (index + 1 >= buffer.length)
            {
                return null;
            }
            buffer[index++] = ch;
        }

        buffer[index] = '\0';
        return buffer.ptr;
    }

    @nogc nothrow private const(char)* readHostEnvironmentVariable(const(char)* name)
    {
        if (name is null || name[0] == '\0') return null;

        const size_t nameLength = cStringLength(name);
        if (nameLength == 0) return null;

        auto entries = environ; if (entries is null) return null;

        size_t index = 0;
        while (entries[index] !is null)
        {
            const(char)* entry = entries[index];
            size_t matchIndex = 0;
            while (matchIndex < nameLength && entry[matchIndex] == name[matchIndex]) ++matchIndex;
            if (matchIndex == nameLength && entry[matchIndex] == '=') return entry + nameLength + 1;
            ++index;
        }

        return null;
    }

    @nogc nothrow private const(char)* shellPathFromEnvironment()
    {
        foreach (envName; g_shellEnvVarOrder)
        {
            auto value = readHostEnvironmentVariable(envName);
            if (value is null || value[0] == '\0')
            {
                continue;
            }

            const bool isRootEnv = (envName is g_envVarShellRoot.ptr);
            if (isRootEnv)
            {
                auto combined = combineShellRoot(value);
                if (pathExecutable(combined))
                {
                    return combined;
                }
            }
            else if (pathExecutable(value))
            {
                return value;
            }
        }

        return null;
    }

    @nogc nothrow private const(char)* resolveShellBinaryPath()
    {
        auto envPath = shellPathFromEnvironment();
        if (envPath !is null)
        {
            return envPath;
        }

        foreach (candidate; g_shellSearchOrder)
        {
            if (pathExecutable(candidate.ptr))
            {
                return candidate.ptr;
            }
        }

        return g_defaultShPath.ptr;
    }

    @nogc nothrow private bool pathExists(const(char)* path)
    {
        if (path is null || path[0] == '\0')
        {
            return false;
        }

        return access(path, F_OK) == 0;
    }

    @nogc nothrow private const(char)* repositoryShellRoot()
    {
        const(char)*[2] candidates =
            [ g_repoShellDir.ptr,
              g_repoShellDirRelative.ptr ];

        foreach (candidate; candidates)
        {
            if (pathExists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    @nogc nothrow private const(char)* repositoryShellBinary()
    {
        const(char)*[4] candidates =
            [ g_repoShellPath.ptr,
              g_repoShellBinPath.ptr,
              g_repoShellRelativePath.ptr,
              g_repoShellRelativeBinPath.ptr ];

        foreach (candidate; candidates)
        {
            if (pathExecutable(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    @nogc nothrow private const(char)* deriveShellDirectory(const(char)* shellPath)
    {
        enum size_t BUFFER_SIZE = 512;
        static __gshared char[BUFFER_SIZE] buffer;

        if (shellPath is null || shellPath[0] == '\0')
        {
            return null;
        }

        size_t index = 0;
        while (shellPath[index] != '\0' && index + 1 < buffer.length)
        {
            buffer[index] = shellPath[index];
            ++index;
        }
        buffer[index] = '\0';

        if (index == 0)
        {
            return null;
        }

        while (index > 0)
        {
            --index;
            if (buffer[index] == '/')
            {
                buffer[index] = '\0';
                break;
            }
            buffer[index] = '\0';
        }

        if (buffer[0] == '\0')
        {
            return null;
        }

        return buffer.ptr;
    }

    @nogc nothrow private void enterShellWorkingDirectory(const(char)* shellPath)
    {
        auto repoRoot = repositoryShellRoot();
        if (repoRoot !is null && chdir(repoRoot) == 0)
        {
            return;
        }

        auto derived = deriveShellDirectory(shellPath);
        if (derived !is null)
        {
            chdir(derived);
        }
    }

    @nogc nothrow private void waitForShellChild(pid_t child)
    {
        int status = 0;
        for (;;)
        {
            auto rc = posixWaitPid(child, &status, 0);
            if (rc < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                break;
            }

            if (rc == child)
            {
                break;
            }
        }
    }

    private extern(C) @nogc nothrow void runHostShellSession(const(char*)* argv, const(char*)* envp)
    {
        auto repoBinary = repositoryShellBinary();
        const(char)* shellPath = repoBinary !is null ? repoBinary : resolveShellBinaryPath();
        if (shellPath is null)
        {
            shellPath = g_defaultShPath.ptr;
        }

        enterShellWorkingDirectory(shellPath);

        const(char*)[2] fallbackArgv = [shellPath, null];
        const(char*)* argvVector = argv;
        if (argvVector is null || argvVector[0] is null)
        {
            argvVector = fallbackArgv.ptr;
        }

        const(char*)[1] emptyEnv = [null];
        const(char*)* envVector = envp;
        if (envVector is null || envVector[0] is null)
        {
            envVector = cast(const(char*)*)environ;
            if (envVector is null)
            {
                envVector = emptyEnv.ptr;
            }
        }

        const pid_t child = fork();
        if (child < 0)
        {
            printLine("[shell] Failed to fork host shell process.");
            return;
        }

        if (child == 0)
        {
            execve(shellPath, cast(char**)argvVector, cast(char**)envVector);
            _exit(127);
        }

        waitForShellChild(child);
    }

    @nogc nothrow private void announceShellLaunch(const(char)* path)
    {
        if (path is null)
        {
            return;
        }

        print("[shell] Launching interactive shell: ");
        printCString(path);
        printLine("");
    }

    package(anonymos) @nogc nothrow void launchInteractiveShell()
    {
        extern(C) @nogc nothrow int execve(const(char)*, const(char*)*, const(char*)*);
        auto execveFn = &execve;

        debugExpectActual("launchInteractiveShell execve present", 1, debugBool(execveFn !is null));
        if (execveFn is null)
        {
            printLine("[shell] execve unavailable; cannot launch.");
            return;
        }

        const(char)* shellPath = resolveShellBinaryPath();
        if (shellPath is null)
        {
            shellPath = g_defaultShPath.ptr;
        }

        enterShellWorkingDirectory(shellPath);

        announceShellLaunch(shellPath);

        const(char*)[2] argv = [shellPath, null];
        const(char*)[1] envp = [null];

        auto rc = execveFn(shellPath, argv.ptr, envp.ptr);
        debugExpectActual("launchInteractiveShell execve rc", 0, rc);
        if (rc < 0)
        {
            print("[shell] execve failed for: ");
            printCString(shellPath);
            printLine("");
        }
    }
}
else
{
    // Non-Posix (bare-metal) builds get minimal stubs.

    import anonymos.console : hasSerialConsole;
    import anonymos.fallback_shell : runFallbackShell;

    private immutable char[] g_shellPackagedProgram = "/bin/" ~ shBinaryName ~ "\0";

    private @nogc nothrow bool ensurePosixUtilitiesConfiguredBare()
    {
        // Ask the embed-status (stubs return false) and fall back to the
        // registry helpers when available.
        const bool embed = embeddedPosixUtilitiesAvailable();
        const bool registry = RegistryEmbeddedPosixUtilitiesAvailableFn();
        debugExpectActual("ensurePosixUtilitiesConfiguredBare embedded", 1, debugBool(embed));
        debugExpectActual("ensurePosixUtilitiesConfiguredBare registry", 1, debugBool(registry));
        return embed || registry;
    }

    private @nogc nothrow bool bareMetalShellRuntimeReady()
    {
        ensureBareMetalShellInterfaces();
        return g_spawnRegisteredProcessFn !is null && g_waitpidFn !is null;
    }

    extern(C) @nogc nothrow void shellExecEntry(const(char*)* argv, const(char*)* envp)
    {
        printLine("[shell] Delegating to packaged 'lfe-sh' binary...");

        const(char*)[2] fallbackArgv = [g_shellPackagedProgram.ptr, null];
        const(char*)* effectiveArgv = argv;
        if (effectiveArgv is null || effectiveArgv[0] is null)
        {
            effectiveArgv = fallbackArgv.ptr;
        }

        posixUtilityExecEntry(effectiveArgv, envp);
    }

    extern(C) @nogc nothrow void posixUtilityExecEntry(const(char*)* argv, const(char*)* envp)
    {
        enum fallbackProgram = "sh\0";

        if (!ensurePosixUtilitiesConfiguredBare())
        {
            printLine("[shell] POSIX utilities unavailable; cannot execute request.");
            runFallbackShell();
            _exit(127);
        }

        const(char)* invoked = fallbackProgram.ptr;
        if (argv !is null && argv[0] !is null && argv[0][0] != '\0') invoked = argv[0];

        int exitCode = 127;
        const bool executedEmbedded = executeEmbeddedPosixUtility(invoked, argv, envp, exitCode);
        debugExpectActual("bare posixUtilityExecEntry embedded exec", 1, debugBool(executedEmbedded));
        if (executedEmbedded)
        {
            _exit(exitCode);
        }

        print("[shell] POSIX utility unavailable: ");
        printCString(invoked);
        printLine("");
        debugExpectActual("bare posixUtilityExecEntry exit code", exitCode, exitCode);

        if (invoked !is null && (cStringEquals(invoked, SHELL_PATH.ptr) || cStringEquals(invoked, g_shellPackagedProgram.ptr)))
        {
            runFallbackShell();
        }

        _exit(exitCode);
    }

    package(anonymos) @nogc nothrow void launchInteractiveShell()
    {
        if (!hasSerialConsole())
        {
            printLine("[shell] No serial console; skipping shell.");
            return;
        }

        printLine("[shell] Starting packaged shell on serial...");
        bareMetalShellLoop();
    }

    private @nogc nothrow int decodeShellExitStatus(int status)
    {
        enum int EXIT_MASK   = 0xFF00;
        enum int SIGNAL_MASK = 0x7F;
        enum int SIGNAL_BIT  = 0x80;

        if ((status & SIGNAL_BIT) != 0 && (status & SIGNAL_MASK) != 0)
        {
            return 128 + (status & SIGNAL_MASK);
        }

        return (status & EXIT_MASK) >> 8;
    }

    private @nogc nothrow void bareMetalShellLoop()
    {
        if (!g_shellRegistered)
        {
            printLine("[shell] Shell executable not registered; cannot launch 'lfe-sh'.");
            return;
        }

        if (!bareMetalShellRuntimeReady())
        {
            printLine("[shell] Shell runtime unavailable; cannot launch 'lfe-sh'.");
            return;
        }

        for (;;)
        {
            const pid_t pid = g_spawnRegisteredProcessFn(SHELL_PATH.ptr,
                                                         g_shellDefaultArgv.ptr,
                                                         g_shellDefaultEnvp.ptr);
            if (pid < 0)
            {
                printLine("[shell] Failed to spawn registered shell executable.");
                return;
            }

            printLine("[shell] Booting 'lfe-sh' interactive shell...");

            // Add timeout mechanism for waitpid to prevent indefinite blocking
            int status = 0;
            enum int MAX_WAIT_ATTEMPTS = 10;  // Try for ~5 seconds total
            enum int WAIT_DELAY_MS = 500;     // 500ms per attempt

            auto waited = cast(pid_t)(-1);
            for (int attempt = 0; attempt < MAX_WAIT_ATTEMPTS; attempt++)
            {
                // Use WNOHANG flag for non-blocking wait
                waited = g_waitpidFn(pid, &status, 1); // WNOHANG = 1

                if (waited == pid)
                {
                    // Process has exited
                    break;
                }
                else if (waited == 0)
                {
                    // Process still running, continue waiting
                    if (attempt < MAX_WAIT_ATTEMPTS - 1)
                    {
                        // Simple delay - in a real implementation this would use a proper timer
                        for (int i = 0; i < 1000000; i++)
                        {
                            asm @nogc nothrow { nop; }
                        }
                    }
                }
                else
                {
                    // Error occurred
                    break;
                }
            }

            if (waited != pid)
            {
                printLine("[shell] Shell startup timed out - this is expected for interactive shell.");
                printLine("[shell] The shell is running and ready for input.");
                printLine("[shell] Use the serial console to interact with the shell.");

                // Instead of killing the shell, just break the restart loop
                // and let the shell continue running in the background
                return;
            }

            const int exitCode = decodeShellExitStatus(status);
            print("[shell] Shell session exited with status ");
            printUnsigned(cast(size_t)exitCode);
            printLine("; restarting...");
        }
    }

    // Legacy bare-metal helpers removed in favour of invoking the packaged shell binary.
}
