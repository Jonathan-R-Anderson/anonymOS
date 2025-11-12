module minimal_os.posix;

import minimal_os.kernel.posixbundle : embeddedPosixUtilitiesAvailable, embeddedPosixUtilitiesRoot,
    embeddedPosixUtilityPaths, executeEmbeddedPosixUtility;
static import minimal_os.posix;

// --- Forward decls so PosixKernelShim can see them ---
extern(C) @nogc nothrow
void shellExecEntry(const(char*)* argv, const(char*)* envp);

extern(C) @nogc nothrow
void posixUtilityExecEntry(const(char*)* argv, const(char*)* envp);

alias ProcessEntry = extern(C) @nogc nothrow
    void function(const(char*)* argv, const(char*)* envp);



mixin template PosixKernelShim()
{
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

    // NOTE: remove @safe; accessing __gshared is not @safe
    @nogc nothrow ref int errnoRef() { return _errno; }
    @nogc nothrow int  setErrno(Errno e){ _errno = e; return -cast(int)e; }

    // ---- Signals (minimal) ----
    enum SIG : int { NONE=0, TERM=15, KILL=9, CHLD=17 }
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

    struct Proc
    {
        pid_t     pid;
        pid_t     ppid;
        ProcState state;
        int       exitCode;
        SigSet    sigmask;
        FD[MAX_FD] fds;
        // Make entry @nogc so sys_execve (also @nogc) can call it
        extern(C) @nogc nothrow void function(const(char*)* argv, const(char*)* envp) entry;
        void*     ctx;    // arch context (opaque to shim)
        void*     kstack; // optional kernel stack
        char[16]  name;
        const(char*)* pendingArgv; // pointer to array of const(char)*
        const(char*)* pendingEnvp;
        bool          pendingExec;
        size_t        objectId;
        EnvironmentTable* environment;
    }

    private __gshared Proc[MAX_PROC] g_ptable;
    private __gshared pid_t          g_nextPid    = 1;
    private __gshared Proc*          g_current    = null;
    private __gshared bool           g_initialized = false;
    private __gshared bool           g_consoleAvailable = false;
    private __gshared bool           g_shellRegistered   = false;
    private __gshared bool           g_posixUtilitiesRegistered = false;
    private __gshared size_t         g_posixUtilityCount = 0;
    private __gshared bool           g_posixConfigured   = false;

    private immutable char[8]        SHELL_PATH = "/bin/sh\0";
    private __gshared const(char*)[2] g_shellDefaultArgv = [SHELL_PATH.ptr, null];
    private __gshared const(char*)[1] g_shellDefaultEnvp = [null];

    @nogc nothrow private void clearBuffer(ref char[MAX_OBJECT_NAME] buffer)
    {
        foreach (i; 0 .. buffer.length)
        {
            buffer[i] = 0;
        }
    }

    @nogc nothrow private void clearLabel(ref char[MAX_OBJECT_LABEL] buffer)
    {
        foreach (i; 0 .. buffer.length)
        {
            buffer[i] = 0;
        }
    }

    @nogc nothrow private void copyBuffer(ref char[MAX_OBJECT_NAME] dst, ref char[MAX_OBJECT_NAME] src)
    {
        foreach (i; 0 .. dst.length)
        {
            dst[i] = (i < src.length) ? src[i] : 0;
        }
    }

    @nogc nothrow private void setBufferFromString(ref char[MAX_OBJECT_NAME] buffer, immutable(char)[] text)
    {
        size_t index = 0;
        foreach (ch; text)
        {
            if (index + 1 >= buffer.length)
            {
                break;
            }

            buffer[index] = cast(char)ch;
            ++index;
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private void setLabelFromString(ref char[MAX_OBJECT_LABEL] buffer, immutable(char)[] text)
    {
        size_t index = 0;
        foreach (ch; text)
        {
            if (index + 1 >= buffer.length)
            {
                break;
            }

            buffer[index] = cast(char)ch;
            ++index;
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private void setBufferFromCString(ref char[MAX_OBJECT_NAME] buffer, const(char)* text)
    {
        size_t index = 0;
        if (text !is null)
        {
            while (text[index] != 0)
            {
                if (index + 1 >= buffer.length)
                {
                    break;
                }

                buffer[index] = text[index];
                ++index;
            }
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private void setLabelFromCString(ref char[MAX_OBJECT_LABEL] buffer, const(char)* text)
    {
        size_t index = 0;
        if (text !is null)
        {
            while (text[index] != 0)
            {
                if (index + 1 >= buffer.length)
                {
                    break;
                }

                buffer[index] = text[index];
                ++index;
            }
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private size_t bufferLength(ref char[MAX_OBJECT_NAME] buffer)
    {
        size_t index = 0;
        while (index < buffer.length && buffer[index] != 0)
        {
            ++index;
        }
        return index;
    }

    @nogc nothrow private void appendUnsigned(ref char[MAX_OBJECT_NAME] buffer, size_t value)
    {
        char[20] digits;
        size_t count = 0;
        do
        {
            digits[count] = cast(char)('0' + (value % 10));
            value /= 10;
            ++count;
        }
        while (value != 0 && count < digits.length);

        size_t index = bufferLength(buffer);
        while (count > 0 && index + 1 < buffer.length)
        {
            --count;
            buffer[index] = digits[count];
            ++index;
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private size_t allocateObjectSlot()
    {
        foreach (i, ref objectRef; g_objects)
        {
            if (!objectRef.used)
            {
                return i;
            }
        }

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
            if (lhs[i] != rhs[i])
            {
                return false;
            }

            if (lhs[i] == 0)
            {
                return true;
            }
        }

        return true;
    }

    @nogc nothrow private size_t createObjectFromBuffer(KernelObjectKind kind, ref char[MAX_OBJECT_NAME] name, immutable(char)[] type, size_t parent, long primary = 0, long secondary = 0)
    {
        const size_t slot = allocateObjectSlot();
        if (slot == INVALID_OBJECT_ID)
        {
            return INVALID_OBJECT_ID;
        }

        auto obj = &g_objects[slot];
        *obj = KernelObject.init;
        obj.used = true;
        obj.kind = kind;
        obj.parent = parent;
        obj.childCount = 0;
        obj.primary = primary;
        obj.secondary = secondary;
        copyBuffer(obj.name, name);
        setBufferFromString(obj.type, type);
        clearLabel(obj.label);

        if (isValidObject(parent))
        {
            auto parentObj = &g_objects[parent];
            if (parentObj.childCount < parentObj.children.length)
            {
                parentObj.children[parentObj.childCount] = slot;
                ++parentObj.childCount;
            }
        }

        if (g_objectCount < size_t.max)
        {
            ++g_objectCount;
        }

        return slot;
    }

    @nogc nothrow private size_t createObjectLiteral(KernelObjectKind kind, immutable(char)[] name, immutable(char)[] type, size_t parent, long primary = 0, long secondary = 0)
    {
        char[MAX_OBJECT_NAME] buffer;
        clearBuffer(buffer);
        setBufferFromString(buffer, name);
        return createObjectFromBuffer(kind, buffer, type, parent, primary, secondary);
    }

    @nogc nothrow private void detachChild(size_t parent, size_t child)
    {
        if (!isValidObject(parent))
        {
            return;
        }

        auto parentObj = &g_objects[parent];
        foreach (i; 0 .. parentObj.childCount)
        {
            if (parentObj.children[i] == child)
            {
                size_t index = i;
                while (index + 1 < parentObj.childCount)
                {
                    parentObj.children[index] = parentObj.children[index + 1];
                    ++index;
                }
                if (parentObj.childCount > 0)
                {
                    --parentObj.childCount;
                }
                if (parentObj.childCount < parentObj.children.length)
                {
                    parentObj.children[parentObj.childCount] = INVALID_OBJECT_ID;
                }
                return;
            }
        }
    }

    @nogc nothrow private void destroyObject(size_t index)
    {
        if (!isValidObject(index))
        {
            return;
        }

        auto obj = &g_objects[index];
        auto parent = obj.parent;
        if (isValidObject(parent))
        {
            detachChild(parent, index);
        }

        *obj = KernelObject.init;
        if (g_objectCount > 0)
        {
            --g_objectCount;
        }
    }

    @nogc nothrow private void setObjectLabelLiteral(size_t objectId, immutable(char)[] label)
    {
        if (!isValidObject(objectId))
        {
            return;
        }

        setLabelFromString(g_objects[objectId].label, label);
    }

    @nogc nothrow private void setObjectLabelCString(size_t objectId, const(char)* label)
    {
        if (!isValidObject(objectId))
        {
            return;
        }

        setLabelFromCString(g_objects[objectId].label, label);
    }

    @nogc nothrow private size_t findChildByBuffer(size_t parent, ref char[MAX_OBJECT_NAME] name)
    {
        if (!isValidObject(parent))
        {
            return INVALID_OBJECT_ID;
        }

        auto parentObj = &g_objects[parent];
        foreach (i; 0 .. parentObj.childCount)
        {
            size_t childIndex = parentObj.children[i];
            if (!isValidObject(childIndex))
            {
                continue;
            }

            if (buffersEqual(g_objects[childIndex].name, name))
            {
                return childIndex;
            }
        }

        return INVALID_OBJECT_ID;
    }

    @nogc nothrow private void setBufferFromSlice(ref char[MAX_OBJECT_NAME] buffer, const(char)* slice, size_t length)
    {
        size_t index = 0;
        while (index < length && index + 1 < buffer.length)
        {
            buffer[index] = slice[index];
            ++index;
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private size_t ensureNamespaceChild(size_t parent, const(char)* name, size_t length)
    {
        char[MAX_OBJECT_NAME] segment;
        clearBuffer(segment);
        setBufferFromSlice(segment, name, length);

        auto existing = findChildByBuffer(parent, segment);
        if (existing != INVALID_OBJECT_ID)
        {
            return existing;
        }

        return createObjectFromBuffer(KernelObjectKind.Namespace, segment, "namespace", parent);
    }

    @nogc nothrow private size_t ensureExecutableObject(size_t parent, const(char)* name, size_t length, size_t slotIndex)
    {
        char[MAX_OBJECT_NAME] segment;
        clearBuffer(segment);
        setBufferFromSlice(segment, name, length);

        auto existing = findChildByBuffer(parent, segment);
        if (existing != INVALID_OBJECT_ID)
        {
            if (isValidObject(existing))
            {
                g_objects[existing].primary = cast(long)slotIndex;
            }
            return existing;
        }

        auto created = createObjectFromBuffer(KernelObjectKind.Executable, segment, "posix.utility", parent, cast(long)slotIndex);
        if (isValidObject(created))
        {
            setObjectLabelCString(created, segment.ptr);
        }
        return created;
    }

    @nogc nothrow private size_t registerExecutableObject(const(char)* path, size_t slotIndex)
    {
        if (!g_objectRegistryReady || path is null || path[0] == 0)
        {
            return INVALID_OBJECT_ID;
        }

        size_t parent = g_objectRoot;
        size_t index = 0;

        while (path[index] != 0)
        {
            while (path[index] == '/')
            {
                ++index;
            }

            if (path[index] == 0)
            {
                break;
            }

            const size_t start = index;
            while (path[index] != 0 && path[index] != '/')
            {
                ++index;
            }

            const size_t length = index - start;
            if (length == 0)
            {
                continue;
            }

            const bool isLast = (path[index] == 0);
            if (!isLast)
            {
                parent = ensureNamespaceChild(parent, path + start, length);
            }
            else
            {
                parent = ensureExecutableObject(parent, path + start, length, slotIndex);
            }

            if (parent == INVALID_OBJECT_ID)
            {
                break;
            }
        }

        return parent;
    }

    @nogc nothrow private void initializeObjectRegistry()
    {
        if (g_objectRegistryReady)
        {
            return;
        }

        foreach (ref obj; g_objects)
        {
            obj = KernelObject.init;
        }

        g_objectCount = 0;
        g_objectRoot = createObjectLiteral(KernelObjectKind.Namespace, "/", "namespace", INVALID_OBJECT_ID);
        if (!isValidObject(g_objectRoot))
        {
            return;
        }

        g_objectProcNamespace = createObjectLiteral(KernelObjectKind.Namespace, "proc", "namespace", g_objectRoot);
        g_objectBinNamespace  = createObjectLiteral(KernelObjectKind.Namespace, "bin", "namespace", g_objectRoot);
        g_objectDevNamespace  = createObjectLiteral(KernelObjectKind.Namespace, "dev", "namespace", g_objectRoot);

        if (isValidObject(g_objectDevNamespace))
        {
            g_consoleObject = createObjectLiteral(KernelObjectKind.Device, "console", "device.console", g_objectDevNamespace);
            if (isValidObject(g_consoleObject))
            {
                setObjectLabelLiteral(g_consoleObject, "text-console");
            }
        }

        g_objectRegistryReady = true;
    }

    @nogc nothrow private size_t createProcessObject(pid_t pid)
    {
        if (!g_objectRegistryReady)
        {
            return INVALID_OBJECT_ID;
        }

        char[MAX_OBJECT_NAME] name;
        clearBuffer(name);
        setBufferFromString(name, "process:");
        appendUnsigned(name, cast(size_t)pid);

        auto objectId = createObjectFromBuffer(KernelObjectKind.Process, name, "process", g_objectProcNamespace, cast(long)pid);
        if (isValidObject(objectId))
        {
            setObjectLabelLiteral(objectId, "unnamed");
        }

        return objectId;
    }

    @nogc nothrow private size_t cloneProcessObject(pid_t pid, size_t sourceObject)
    {
        auto objectId = createProcessObject(pid);
        if (isValidObject(objectId) && isValidObject(sourceObject))
        {
            setLabelFromCString(g_objects[objectId].label, g_objects[sourceObject].label.ptr);
        }
        return objectId;
    }

    @nogc nothrow private void destroyProcessObject(size_t objectId)
    {
        if (!g_objectRegistryReady)
        {
            return;
        }

        if (!isProcessObject(objectId))
        {
            return;
        }

        destroyObject(objectId);
    }

    @nogc nothrow private bool isEnvironmentObject(size_t index)
    {
        return isValidObject(index) && g_objects[index].kind == KernelObjectKind.Environment;
    }

    @nogc nothrow private size_t createEnvironmentObject(size_t processObject)
    {
        if (!g_objectRegistryReady || !isProcessObject(processObject))
        {
            return INVALID_OBJECT_ID;
        }

        char[MAX_OBJECT_NAME] name;
        clearBuffer(name);
        setBufferFromString(name, "env");

        auto objectId = createObjectFromBuffer(KernelObjectKind.Environment, name, "process.environment", processObject);
        if (isValidObject(objectId))
        {
            setObjectLabelLiteral(objectId, "environment");
        }

        return objectId;
    }

    @nogc nothrow private void destroyEnvironmentObject(size_t objectId)
    {
        if (!g_objectRegistryReady)
        {
            return;
        }

        if (!isEnvironmentObject(objectId))
        {
            return;
        }

        destroyObject(objectId);
    }

    @nogc nothrow private void clearEnvironmentEntry(ref EnvironmentEntry entry)
    {
        entry = EnvironmentEntry.init;
    }

    @nogc nothrow private void clearEnvironmentTable(EnvironmentTable* table)
    {
        if (table is null)
        {
            return;
        }

        foreach (ref entry; table.entries)
        {
            entry = EnvironmentEntry.init;
        }

        foreach (i; 0 .. table.pointerCache.length)
        {
            table.pointerCache[i] = null;
        }

        table.entryCount = 0;
        table.pointerCount = 0;
        table.pointerDirty = true;
    }

    @nogc nothrow private EnvironmentEntry* findEnvironmentEntry(EnvironmentTable* table, const(char)* name, size_t nameLength)
    {
        if (table is null || name is null || nameLength == 0)
        {
            return null;
        }

        foreach (ref entry; table.entries)
        {
            if (!entry.used || entry.nameLength != nameLength)
            {
                continue;
            }

            size_t index = 0;
            while (index < nameLength && entry.name[index] == name[index])
            {
                ++index;
            }

            if (index == nameLength)
            {
                return &entry;
            }
        }

        return null;
    }

    @nogc nothrow private EnvironmentEntry* allocateEnvironmentEntry(EnvironmentTable* table)
    {
        if (table is null)
        {
            return null;
        }

        foreach (ref entry; table.entries)
        {
            if (!entry.used)
            {
                entry = EnvironmentEntry.init;
                entry.used = true;
                if (table.entryCount < size_t.max)
                {
                    ++table.entryCount;
                }
                table.pointerDirty = true;
                return &entry;
            }
        }

        return null;
    }

    @nogc nothrow private bool setEnvironmentEntry(EnvironmentTable* table, const(char)* name, size_t nameLength, const(char)* value, size_t valueLength, bool overwrite = true)
    {
        if (table is null || name is null)
        {
            return false;
        }

        if (nameLength == 0 || nameLength >= MAX_ENV_NAME_LENGTH)
        {
            return false;
        }

        if (valueLength >= MAX_ENV_VALUE_LENGTH)
        {
            return false;
        }

        auto entry = findEnvironmentEntry(table, name, nameLength);
        if (entry is null)
        {
            entry = allocateEnvironmentEntry(table);
        }
        else
        {
            if (!overwrite)
            {
                return true;
            }
            table.pointerDirty = true;
        }

        if (entry is null)
        {
            return false;
        }

        entry.used = true;
        entry.nameLength = nameLength;
        entry.valueLength = valueLength;
        entry.combinedLength = 0;
        entry.dirty = true;

        foreach (i; 0 .. entry.name.length)
        {
            entry.name[i] = (i < nameLength) ? name[i] : 0;
        }

        foreach (i; 0 .. entry.value.length)
        {
            entry.value[i] = (i < valueLength) ? value[i] : 0;
        }

        foreach (i; 0 .. entry.combined.length)
        {
            entry.combined[i] = 0;
        }

        return true;
    }

    @nogc nothrow private bool unsetEnvironmentEntry(EnvironmentTable* table, const(char)* name, size_t nameLength)
    {
        auto entry = findEnvironmentEntry(table, name, nameLength);
        if (entry is null)
        {
            return false;
        }

        *entry = EnvironmentEntry.init;
        if (table.entryCount > 0)
        {
            --table.entryCount;
        }
        table.pointerDirty = true;
        return true;
    }

    @nogc nothrow private void refreshEnvironmentEntry(ref EnvironmentEntry entry)
    {
        if (!entry.used)
        {
            return;
        }

        size_t index = 0;
        foreach (i; 0 .. entry.nameLength)
        {
            if (index + 1 >= entry.combined.length)
            {
                break;
            }
            entry.combined[index] = entry.name[i];
            ++index;
        }

        if (index + 1 >= entry.combined.length)
        {
            entry.combined[entry.combined.length - 1] = 0;
            entry.combinedLength = entry.combined.length - 1;
            entry.dirty = false;
            return;
        }

        entry.combined[index] = '=';
        ++index;

        foreach (i; 0 .. entry.valueLength)
        {
            if (index + 1 >= entry.combined.length)
            {
                break;
            }
            entry.combined[index] = entry.value[i];
            ++index;
        }

        if (index >= entry.combined.length)
        {
            index = entry.combined.length - 1;
        }

        entry.combined[index] = 0;
        entry.combinedLength = index;
        entry.dirty = false;
    }

    @nogc nothrow private const(char)* environmentEntryPair(ref EnvironmentEntry entry)
    {
        if (!entry.used)
        {
            return null;
        }

        if (entry.dirty)
        {
            refreshEnvironmentEntry(entry);
        }

        return entry.combined.ptr;
    }

    @nogc nothrow private void rebuildEnvironmentPointers(EnvironmentTable* table)
    {
        if (table is null || !table.used)
        {
            return;
        }

        if (!table.pointerDirty)
        {
            return;
        }

        size_t index = 0;
        foreach (ref entry; table.entries)
        {
            if (!entry.used)
            {
                continue;
            }

            auto pair = environmentEntryPair(entry);
            if (pair is null)
            {
                continue;
            }

            if (index + 1 >= table.pointerCache.length)
            {
                break;
            }

            table.pointerCache[index] = cast(char*)pair;
            ++index;
        }

        if (index < table.pointerCache.length)
        {
            table.pointerCache[index] = null;
            ++index;
        }

        while (index < table.pointerCache.length)
        {
            table.pointerCache[index] = null;
            ++index;
        }

        table.pointerCount = (index == 0) ? 0 : index - 1;
        table.pointerDirty = false;
    }

    @nogc nothrow private EnvironmentTable* allocateEnvironmentTable(pid_t ownerPid, size_t processObject)
    {
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
                {
                    table.objectId = createEnvironmentObject(processObject);
                }
                return &table;
            }
        }

        return null;
    }

    @nogc nothrow private void ensureEnvironmentObject(EnvironmentTable* table, size_t processObject)
    {
        if (table is null)
        {
            return;
        }

        if (table.objectId != INVALID_OBJECT_ID)
        {
            return;
        }

        if (!g_objectRegistryReady || !isProcessObject(processObject))
        {
            return;
        }

        table.objectId = createEnvironmentObject(processObject);
    }

    @nogc nothrow private void releaseEnvironmentTable(EnvironmentTable* table)
    {
        if (table is null || !table.used)
        {
            return;
        }

        if (table.objectId != INVALID_OBJECT_ID)
        {
            destroyEnvironmentObject(table.objectId);
        }

        clearEnvironmentTable(table);
        table.used = false;
        table.ownerPid = 0;
        table.objectId = INVALID_OBJECT_ID;
    }

    @nogc nothrow private void cloneEnvironmentTable(EnvironmentTable* destination, EnvironmentTable* source)
    {
        if (destination is null)
        {
            return;
        }

        clearEnvironmentTable(destination);

        if (source is null || !source.used)
        {
            return;
        }

        foreach (ref entry; source.entries)
        {
            if (!entry.used)
            {
                continue;
            }

            setEnvironmentEntry(destination, entry.name.ptr, entry.nameLength, entry.value.ptr, entry.valueLength);
        }
    }

    @nogc nothrow private void loadEnvironmentFromVector(EnvironmentTable* table, const(char*)* envp)
    {
        if (table is null)
        {
            return;
        }

        clearEnvironmentTable(table);

        if (envp is null)
        {
            return;
        }

        size_t index = 0;
        while (envp[index] !is null)
        {
            auto kv = envp[index];
            if (kv is null)
            {
                ++index;
                continue;
            }

            size_t nameLength = 0;
            while (kv[nameLength] != 0 && kv[nameLength] != '=')
            {
                ++nameLength;
            }

            if (kv[nameLength] != '=' || nameLength == 0)
            {
                ++index;
                continue;
            }

            const(char)* valuePtr = kv + nameLength + 1;
            size_t valueLength = 0;
            while (valuePtr[valueLength] != 0)
            {
                ++valueLength;
            }

            setEnvironmentEntry(table, kv, nameLength, valuePtr, valueLength);
            ++index;
        }
    }

    @nogc nothrow private void loadEnvironmentFromHost(EnvironmentTable* table)
    {
        if (table is null)
        {
            return;
        }

        clearEnvironmentTable(table);

        version (Posix)
        {
            if (environ is null)
            {
                return;
            }

            int index = 0;
            while (environ[index] !is null)
            {
                auto kv = environ[index];
                if (kv is null)
                {
                    ++index;
                    continue;
                }

                size_t nameLength = 0;
                while (kv[nameLength] != 0 && kv[nameLength] != '=')
                {
                    ++nameLength;
                }

                if (kv[nameLength] != '=' || nameLength == 0)
                {
                    ++index;
                    continue;
                }

                const(char)* valuePtr = kv + nameLength + 1;
                size_t valueLength = 0;
                while (valuePtr[valueLength] != 0)
                {
                    ++valueLength;
                }

                setEnvironmentEntry(table, kv, nameLength, valuePtr, valueLength);
                ++index;
            }
        }
    }

    @nogc nothrow private const(char*)* getEnvironmentVector(Proc* proc)
    {
        if (proc is null)
        {
            return null;
        }

        auto table = proc.environment;
        if (table is null || !table.used)
        {
            return null;
        }

        rebuildEnvironmentPointers(table);
        return cast(const(char*)*)table.pointerCache.ptr;
    }

    @nogc nothrow private bool setEnvironmentValueForProcess(Proc* proc, const(char)* name, size_t nameLength, const(char)* value, size_t valueLength, bool overwrite = true)
    {
        if (proc is null)
        {
            return false;
        }

        auto table = proc.environment;
        if (table is null || !table.used)
        {
            return false;
        }

        return setEnvironmentEntry(table, name, nameLength, value, valueLength, overwrite);
    }

    @nogc nothrow private bool setEnvironmentValueForProcess(Proc* proc, const(char)* name, const(char)* value, bool overwrite = true)
    {
        if (name is null)
        {
            return false;
        }

        const size_t nameLength = cStringLength(name);
        const size_t valueLength = (value is null) ? 0 : cStringLength(value);
        return setEnvironmentValueForProcess(proc, name, nameLength, value, valueLength, overwrite);
    }

    @nogc nothrow private const(char)* readEnvironmentValueFromProcess(Proc* proc, const(char)* name, size_t nameLength)
    {
        if (proc is null)
        {
            return null;
        }

        auto table = proc.environment;
        if (table is null || !table.used)
        {
            return null;
        }

        auto entry = findEnvironmentEntry(table, name, nameLength);
        if (entry is null)
        {
            return null;
        }

        return entry.value.ptr;
    }

    @nogc nothrow private void updateProcessObjectState(ref Proc proc)
    {
        if (!g_objectRegistryReady)
        {
            return;
        }

        if (!isProcessObject(proc.objectId))
        {
            return;
        }

        g_objects[proc.objectId].secondary = cast(long)proc.state;
    }

    @nogc nothrow private void updateProcessObjectLabel(ref Proc proc, const(char)* label)
    {
        if (!g_objectRegistryReady)
        {
            return;
        }

        if (!isProcessObject(proc.objectId))
        {
            return;
        }

        setObjectLabelCString(proc.objectId, label);
    }

    @nogc nothrow private void updateProcessObjectLabelLiteral(ref Proc proc, immutable(char)[] label)
    {
        if (!g_objectRegistryReady)
        {
            return;
        }

        if (!isProcessObject(proc.objectId))
        {
            return;
        }

        setObjectLabelLiteral(proc.objectId, label);
    }

    @nogc nothrow private void assignProcessState(ref Proc proc, ProcState state)
    {
        proc.state = state;
        updateProcessObjectState(proc);
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

        if (fd < 0 || fd >= MAX_FD)
        {
            return false;
        }

        auto current = g_current;
        if (current is null)
        {
            return false;
        }

        const int resolved = current.fds[fd].num;
        if (resolved < 0)
        {
            return false;
        }

        hostFd = resolved;
        return true;
    }

    @nogc nothrow private void configureConsoleFor(ref Proc proc)
    {
        foreach (fd; 0 .. 3)
        {
            if (fd >= proc.fds.length)
            {
                break;
            }

            proc.fds[fd].num = fd;
            proc.fds[fd].flags = FDFlags.NONE;
        }
    }

    private enum EnvBool : int
    {
        unspecified,
        truthy,
        falsy,
    }

    @nogc nothrow private char asciiToLower(char value)
    {
        if (value >= 'A' && value <= 'Z')
        {
            return cast(char)(value + ('a' - 'A'));
        }

        return value;
    }

    @nogc nothrow private bool cStringEqualsIgnoreCaseLiteral(const(char)* lhs, immutable(char)[] rhs)
    {
        if (lhs is null)
        {
            return false;
        }

        size_t index = 0;
        for (; index < rhs.length; ++index)
        {
            const(char) actual = lhs[index];
            if (actual == '\0')
            {
                return false;
            }

            if (asciiToLower(actual) != asciiToLower(rhs[index]))
            {
                return false;
            }
        }

        return lhs[index] == '\0';
    }

    @nogc nothrow private const(char)* readEnvironmentVariable(const(char)* name)
    {
        version (Posix)
        {
            if (name is null || name[0] == '\0')
            {
                return null;
            }

            const size_t nameLength = cStringLength(name);
            if (nameLength == 0)
            {
                return null;
            }

            if (g_current !is null)
            {
                auto processValue = readEnvironmentValueFromProcess(g_current, name, nameLength);
                if (processValue !is null)
                {
                    return processValue;
                }
            }

            auto entries = environ;
            if (entries is null)
            {
                return null;
            }

            size_t index = 0;
            while (entries[index] !is null)
            {
                const(char)* entry = entries[index];
                size_t matchIndex = 0;
                while (matchIndex < nameLength && entry[matchIndex] == name[matchIndex])
                {
                    ++matchIndex;
                }

                if (matchIndex == nameLength && entry[matchIndex] == '=')
                {
                    return entry + nameLength + 1;
                }

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
        if (value is null)
        {
            return EnvBool.unspecified;
        }

        if (cStringEqualsIgnoreCaseLiteral(value, "1")
            || cStringEqualsIgnoreCaseLiteral(value, "true")
            || cStringEqualsIgnoreCaseLiteral(value, "yes")
            || cStringEqualsIgnoreCaseLiteral(value, "on")
            || cStringEqualsIgnoreCaseLiteral(value, "enable")
            || cStringEqualsIgnoreCaseLiteral(value, "enabled"))
        {
            return EnvBool.truthy;
        }

        if (cStringEqualsIgnoreCaseLiteral(value, "0")
            || cStringEqualsIgnoreCaseLiteral(value, "false")
            || cStringEqualsIgnoreCaseLiteral(value, "no")
            || cStringEqualsIgnoreCaseLiteral(value, "off")
            || cStringEqualsIgnoreCaseLiteral(value, "disable")
            || cStringEqualsIgnoreCaseLiteral(value, "disabled"))
        {
            return EnvBool.falsy;
        }

        return EnvBool.unspecified;
    }

    @nogc nothrow private bool detectConsoleAvailability()
    {
        const EnvBool assumeConsole = parseEnvBoolean(readEnvironmentVariable("SH_ASSUME_CONSOLE"));
        if (assumeConsole == EnvBool.truthy)
        {
            return true;
        }
        else if (assumeConsole == EnvBool.falsy)
        {
            return false;
        }

        const EnvBool disableConsole = parseEnvBoolean(readEnvironmentVariable("SH_DISABLE_CONSOLE"));
        if (disableConsole == EnvBool.truthy)
        {
            return false;
        }

        version (Posix)
        {
            // Treat the console as available if any of the standard streams are
            // attached to a TTY.  When the ISO is booted under some hypervisors
            // (for example QEMU with `-serial stdio`), the host may only expose a
            // writable TTY on stdout/stderr while stdin is reported as a pipe.
            // Checking all three descriptors avoids spuriously disabling the
            // interactive shell in those environments.
            return (isatty(STDIN_FILENO) != 0)
                || (isatty(STDOUT_FILENO) != 0)
                || (isatty(STDERR_FILENO) != 0);
        }
        else
        {
            return false;
        }
    }

    // ---- Simple spinlock (stub; replace with real lock in SMP) ----
    private struct Spin { int v; }
    private __gshared Spin g_plock;
    @nogc nothrow private void lock(Spin* /*s*/){ /* UP stub */ }
    @nogc nothrow private void unlock(Spin* /*s*/){}

    // ---- Arch switch hook (single no-op stub; replace in your arch code)
    extern(C) @nogc nothrow void arch_context_switch(Proc* /*oldp*/, Proc* /*newp*/) { /* no-op */ }

    // ---- Helpers ----
    @nogc nothrow private size_t cStringLength(const(char)* str)
    {
        if (str is null)
        {
            return 0;
        }

        size_t length = 0;
        while (str[length] != 0)
        {
            ++length;
        }

        return length;
    }

    @nogc nothrow private bool cStringEquals(const(char)* lhs, const(char)* rhs)
    {
        if (lhs is null || rhs is null)
        {
            return false;
        }

        size_t index = 0;
        for (;;)
        {
            const(char) a = lhs[index];
            const(char) b = rhs[index];
            if (a != b)
            {
                return false;
            }

            if (a == 0)
            {
                return true;
            }

            ++index;
        }
    }

    @nogc nothrow private void clearName(ref char[16] name)
    {
        foreach (i; 0 .. name.length)
        {
            name[i] = 0;
        }
    }

    @nogc nothrow private void setNameFromCString(ref char[16] name, const(char)* source)
    {
        size_t index = 0;

        if (source !is null)
        {
            while (index < name.length - 1)
            {
            const(char) value = source[index];
                name[index] = value;
                ++index;

                if (value == 0)
                {
                    break;
                }
            }
        }

        if (index >= name.length)
        {
            index = name.length - 1;
        }

        if (name[index] != 0)
        {
            name[index] = 0;
            ++index;
        }

        while (index < name.length)
        {
            name[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private void setNameFromLiteral(ref char[16] name, immutable(char)[] literal)
    {
        size_t index = 0;
        immutable size_t limit = name.length - 1;

        foreach (ch; literal)
        {
            if (index >= limit)
            {
                break;
            }

            name[index] = cast(char)ch;
            ++index;
        }

        if (index <= limit)
        {
            name[index] = 0;
            ++index;
        }

        while (index < name.length)
        {
            name[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private ExecutableSlot* findExecutableSlot(const(char)* path)
    {
        if (path is null)
        {
            return null;
        }

        foreach (ref slot; g_execTable)
        {
            if (slot.used && cStringEquals(slot.path.ptr, path))
            {
                return &slot;
            }
        }

        return null;
    }

    @nogc nothrow private size_t indexOfExecutableSlot(ExecutableSlot* slot)
    {
        if (slot is null)
        {
            return INVALID_OBJECT_ID;
        }

        foreach (i, ref candidate; g_execTable)
        {
            if ((&candidate) is slot)
            {
                return i;
            }
        }

        return INVALID_OBJECT_ID;
    }

    @nogc nothrow private int encodeExitStatus(int code)
    {
        return (code & 0xFF) << 8;
    }

    @nogc nothrow private int encodeSignalStatus(int sig)
    {
        return (sig & 0x7F) | 0x80;
    }

    // ---- Utility ----
    @nogc nothrow private void resetProc(ref Proc proc)
    {
        if (proc.environment !is null)
        {
            releaseEnvironmentTable(proc.environment);
            proc.environment = null;
        }

        if (isValidObject(proc.objectId))
        {
            destroyProcessObject(proc.objectId);
        }

        proc = Proc.init;
        proc.objectId = INVALID_OBJECT_ID;
    }

    @nogc nothrow private Proc* findByPid(pid_t pid){
        foreach(ref p; g_ptable) if(p.state!=ProcState.UNUSED && p.pid==pid) return &p;
        return null;
    }
    @nogc nothrow private Proc* allocProc(){
        foreach (ref p; g_ptable) {
            if (p.state == ProcState.UNUSED) {
                resetProc(p);
                p.pid = g_nextPid++;
                p.objectId = createProcessObject(p.pid);
                p.environment = allocateEnvironmentTable(p.pid, p.objectId);
                if (p.environment !is null)
                {
                    ensureEnvironmentObject(p.environment, p.objectId);
                }
                assignProcessState(p, ProcState.EMBRYO);
                return &p;
            }
        }
        return null;
    }

    // ---- Very small round-robin scheduler ----
    @nogc nothrow void schedYield(){
        if(!g_initialized) return;
        if(g_current is null) {
            foreach(ref p; g_ptable){
                if(p.state==ProcState.READY){ g_current = &p; assignProcessState(p, ProcState.RUNNING); break; }
            }
            return;
        }
        lock(&g_plock);
        Proc* oldp = g_current;
        if(oldp.state==ProcState.RUNNING) assignProcessState(*oldp, ProcState.READY);

        size_t idx=0;
        foreach(i, ref p; g_ptable) if((&p) is oldp){ idx=i; break; }
        Proc* next = null;
        foreach(j; 1..MAX_PROC+1){
            auto k = (idx + j) % MAX_PROC;
            if(g_ptable[k].state==ProcState.READY){ next = &g_ptable[k]; break; }
        }
        if(next is null) {
            if(oldp.state!=ProcState.ZOMBIE){ assignProcessState(*oldp, ProcState.RUNNING); unlock(&g_plock); return; }
            foreach(ref p; g_ptable){
                if(p.state==ProcState.READY){ next=&p; break; }
            }
        }
        if(next !is null){
            assignProcessState(*next, ProcState.RUNNING);
            g_current  = next;
            arch_context_switch(oldp, next);
        }
        unlock(&g_plock);
    }

    // ---- POSIX core syscalls (kernel-side) ----
    @nogc nothrow pid_t sys_getpid(){
        return (g_current is null) ? 0 : g_current.pid;
    }

    @nogc nothrow pid_t sys_fork(){
        lock(&g_plock);
        auto np = allocProc();
        if(np is null){ unlock(&g_plock); return setErrno(Errno.EAGAIN); }

        // Duplicate minimal PCB
        np.ppid   = (g_current ? g_current.pid : 0);
        assignProcessState(*np, ProcState.READY);
        np.sigmask= 0;
        np.entry  = (g_current ? g_current.entry : null);
        if (g_current && g_objectRegistryReady && isProcessObject(np.objectId) && isProcessObject(g_current.objectId))
        {
            setObjectLabelCString(np.objectId, g_objects[g_current.objectId].label.ptr);
        }
        if (g_current)
        {
            foreach (i; 0 .. np.fds.length)
            {
                np.fds[i] = g_current.fds[i];
            }
            np.pendingArgv = g_current.pendingArgv;
            np.pendingEnvp = g_current.pendingEnvp;
            np.pendingExec = g_current.pendingExec;
            if (np.environment !is null)
            {
                cloneEnvironmentTable(np.environment, g_current.environment);
                ensureEnvironmentObject(np.environment, np.objectId);
            }
        }
        else if (np.environment !is null)
        {
            clearEnvironmentTable(np.environment);
            ensureEnvironmentObject(np.environment, np.objectId);
        }
        // copy name best-effort
        foreach(i; 0 .. np.name.length) np.name[i] = 0;
        if(g_current) {
            import core.stdc.string : strncpy;
            // Not all kernels have C lib; if not, leave zeros or copy manually
            // Manual copy:
            foreach(i; 0 .. np.name.length) {
                if(i < g_current.name.length) np.name[i] = g_current.name[i];
            }
        }
        unlock(&g_plock);
        return np.pid; // parent gets child's pid
    }

    @nogc nothrow int sys_execve(const(char)* path, const(char*)* argv, const(char*)* envp)
    {
        // require a current process
        if (g_current is null) return setErrno(Errno.ESRCH);

        // work on a local we can change instead of reassigning the parameter
        const(char)* execPath = path;

        // resolve by path, or fall back to argv[0]
        auto resolved = findExecutableSlot(execPath);
        if (resolved is null && argv !is null && argv[0] !is null) {
            resolved = findExecutableSlot(argv[0]);
            if (resolved !is null) execPath = argv[0];
        }
        if (resolved is null) return setErrno(Errno.ENOENT);
        if (resolved.entry is null) return setErrno(Errno.ENOEXEC);

        // set up current proc and run
        auto cur = g_current;                // pointer to Proc
        (*cur).entry = resolved.entry;
        setNameFromCString((*cur).name, execPath);
        updateProcessObjectLabel(*cur, execPath);

        if (cur.environment !is null)
        {
            if (envp !is null)
            {
                loadEnvironmentFromVector(cur.environment, envp);
            }
            ensureEnvironmentObject(cur.environment, cur.objectId);
        }

        (*cur).entry(argv, envp);            // @nogc nothrow
        sys__exit(0);                        // if it ever returns
        return 0;                            // unreachable
    }



    @nogc nothrow pid_t sys_waitpid(pid_t wpid, int* status, int /*options*/){
        foreach(ref p; g_ptable){
            if(p.state==ProcState.ZOMBIE && (wpid<=0 || p.pid==wpid) && p.ppid==(g_current?g_current.pid:0)){
                if(status) *status = p.exitCode;
                auto pid = p.pid;
                resetProc(p);
                return pid;
            }
        }
        return setErrno(Errno.ECHILD);
    }

    @nogc nothrow void sys__exit(int code){
        if(g_current is null) return;
        g_current.exitCode = encodeExitStatus(code);
        assignProcessState(*g_current, ProcState.ZOMBIE);
        schedYield();
        for(;;){} // shouldn't resume
    }

    @nogc nothrow int sys_kill(pid_t pid, int sig){
        auto p = findByPid(pid);
        if(p is null) return setErrno(Errno.ESRCH);
        // non-final switch to avoid covering all enum members
        switch(sig){
            case SIG.KILL, SIG.TERM:
                p.exitCode = encodeSignalStatus(sig);
                assignProcessState(*p, ProcState.ZOMBIE);
                return 0;
            default:
                return setErrno(Errno.ENOSYS);
        }
    }

    // Naive sleep: cooperatively yield
    @nogc nothrow uint sys_sleep(uint seconds){
        foreach(_; 0 .. seconds * 100) { schedYield(); }
        return 0;
    }

    // ---- FD/IO syscalls (stubs) ----
    @nogc nothrow int     sys_open (const(char)* /*path*/, int /*flags*/, int /*mode*/){ return setErrno(Errno.ENOSYS); }
    @nogc nothrow int     sys_close(int /*fd*/){ return setErrno(Errno.ENOSYS); }
    @nogc nothrow ssize_t sys_read (int fd, void* buffer, size_t length)
    {
        int hostFd = -1;
        if (!resolveHostFd(fd, hostFd))
        {
            return cast(ssize_t)setErrno(Errno.EBADF);
        }

        version (Posix)
        {
            auto result = read(hostFd, buffer, length);
            if (result < 0)
            {
                _errno = errno;
                return -1;
            }

            return cast(ssize_t)result;
        }
        else
        {
            return cast(ssize_t)setErrno(Errno.ENOSYS);
        }
    }

    @nogc nothrow ssize_t sys_write(int fd, const void* buffer, size_t length)
    {
        int hostFd = -1;
        if (!resolveHostFd(fd, hostFd))
        {
            return cast(ssize_t)setErrno(Errno.EBADF);
        }

        version (Posix)
        {
            auto result = write(hostFd, buffer, length);
            if (result < 0)
            {
                _errno = errno;
                return -1;
            }

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
    @nogc nothrow pid_t waitpid(pid_t p, int* s, int o){ return sys_waitpid(p,s,o); }
    @nogc nothrow void  _exit(int c){ sys__exit(c); }
    @nogc nothrow int   kill(pid_t p, int s){ return sys_kill(p,s); }
    @nogc nothrow uint  sleep(uint s){ return sys_sleep(s); }

    // Optional weak-ish symbols for linkage expectations
    __gshared const(char*)* environ;
    __gshared const(char*)* __argv;
    __gshared int          __argc;

    struct ProcessInfo
    {
        pid_t pid;
        pid_t ppid;
        ubyte state;
        char[16] name;
    }

    alias ProcessEntry = extern(C) @nogc nothrow void function(const(char*)* argv, const(char*)* envp);

    @nogc nothrow int registerProcessExecutable(const(char)* path, ProcessEntry entry)
    {
        if(path is null || entry is null)
        {
            return setErrno(Errno.EINVAL);
        }

        const size_t length = cStringLength(path);
        if(length == 0 || length >= EXEC_PATH_LENGTH)
        {
            return setErrno(Errno.E2BIG);
        }

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
                    if (objectId != INVALID_OBJECT_ID)
                    {
                        existing.objectId = objectId;
                    }
                }
            }
            return 0;
        }

        foreach(slotIndex, ref slot; g_execTable)
        {
            if(!slot.used)
            {
                slot = ExecutableSlot.init;
                slot.used = true;
                foreach(j; 0 .. slot.path.length) slot.path[j] = 0;
                foreach(j; 0 .. length)
                {
                    slot.path[j] = path[j];
                }
                slot.path[length] = '\0';
                slot.entry = entry;
                slot.objectId = INVALID_OBJECT_ID;
                if (g_objectRegistryReady)
                {
                    auto objectId = registerExecutableObject(slot.path.ptr, slotIndex);
                    if (objectId != INVALID_OBJECT_ID)
                    {
                        slot.objectId = objectId;
                    }
                }
                return 0;
            }
        }

        return setErrno(Errno.ENFILE);
    }

    @nogc nothrow pid_t spawnRegisteredProcess(const(char)* path, const(char*)* argv, const(char*)* envp)
    {
        auto slot = findExecutableSlot(path);
        if(slot is null)
        {
            return setErrno(Errno.ENOENT);
        }

        lock(&g_plock);
        auto proc = allocProc();
        if(proc is null)
        {
            unlock(&g_plock);
            return setErrno(Errno.EAGAIN);
        }

        proc.ppid   = (g_current ? g_current.pid : 0);
        assignProcessState(*proc, ProcState.READY);
        proc.entry  = slot.entry;
        proc.pendingArgv = argv;
        proc.pendingEnvp = envp;
        proc.pendingExec = true;
        setNameFromCString(proc.name, path);
        updateProcessObjectLabel(*proc, path);
        unlock(&g_plock);
        return proc.pid;
    }

    @nogc nothrow int completeProcess(pid_t pid, int exitCode)
    {
        auto proc = findByPid(pid);
        if(proc is null)
        {
            return setErrno(Errno.ESRCH);
        }

        if(proc.state==ProcState.UNUSED || proc.state==ProcState.ZOMBIE)
        {
            return setErrno(Errno.EINVAL);
        }

        proc.exitCode = encodeExitStatus(exitCode);
        assignProcessState(*proc, ProcState.ZOMBIE);
        proc.pendingArgv = null;
        proc.pendingEnvp = null;
        proc.pendingExec = false;
        return 0;
    }

    @nogc nothrow size_t listProcesses(ProcessInfo* buffer, size_t capacity)
    {
        if(buffer is null || capacity == 0)
        {
            return 0;
        }

        size_t count = 0;
        foreach(ref proc; g_ptable)
        {
            if(proc.state == ProcState.UNUSED)
            {
                continue;
            }

            if(count >= capacity)
            {
                break;
            }

            buffer[count].pid   = proc.pid;
            buffer[count].ppid  = proc.ppid;
            buffer[count].state = cast(ubyte)proc.state;
            foreach(i; 0 .. buffer[count].name.length)
            {
                buffer[count].name[i] = proc.name[i];
            }

            ++count;
        }

        return count;
    }

    // ---- Init hook ----
    @nogc nothrow void initializeInterrupts()
    {
        // Minimal OS build does not configure interrupts.
    }

    @nogc nothrow void posixInit(){
        if(g_initialized) return;
        initializeObjectRegistry();
        foreach(ref p; g_ptable) resetProc(p);
        foreach(ref slot; g_execTable)
        {
            slot = ExecutableSlot.init;
            slot.objectId = INVALID_OBJECT_ID;
        }
        g_nextPid = 1;
        g_current = null;
        g_posixUtilitiesRegistered = false;
        g_posixUtilityCount = 0;
        auto initProc = allocProc();
        if(initProc !is null)
        {
            initProc.ppid  = 0;
            assignProcessState(*initProc, ProcState.RUNNING);
            setNameFromLiteral(initProc.name, "kernel");
            updateProcessObjectLabelLiteral(*initProc, "kernel");
            initProc.pendingArgv = null;
            initProc.pendingEnvp = null;
            initProc.pendingExec = false;
            g_current = initProc;
            if (initProc.environment !is null)
            {
                loadEnvironmentFromHost(initProc.environment);
                ensureEnvironmentObject(initProc.environment, initProc.objectId);
            }
            g_consoleAvailable = detectConsoleAvailability();
            configureConsoleFor(*initProc);
        }
        else
        {
            g_consoleAvailable = detectConsoleAvailability();
        }

        g_shellRegistered = false;
        if (g_consoleAvailable)
        {
            const int registration =
                registerProcessExecutable("/bin/sh",
                    cast(ProcessEntry)&shellExecEntry);

            g_shellRegistered = (registration == 0);
        }

        g_initialized = true;
    }
}

/*

version (Posix)
{
    extern(C) @nogc nothrow void shellExecEntry(const(char*)* argv, const(char*)* envp)
    {
        const(char*)* vector = envp;
        if ((vector is null || vector[0] is null) && g_current !is null)
        {
            vector = getEnvironmentVector(g_current);
        }
        runHostShellSession(argv, vector);
    }

    extern(C) @nogc nothrow void posixUtilityExecEntry(const(char*)* argv, const(char*)* envp)
    {
        enum fallbackProgram = "sh\0";

        if (!ensurePosixUtilitiesConfigured())
        {
            printLine("[shell] POSIX utilities unavailable; cannot execute request.");
            sys__exit(127);
        }

        const(char)* invoked = null;
        if (argv !is null && argv[0] !is null)
        {
            invoked = argv[0];
        }

        char[PATH_BUFFER_SIZE] nameBuffer;
        size_t nameLength = 0;
        auto programName = extractProgramName(invoked, nameBuffer.ptr, nameBuffer.length, nameLength);
        if (programName is null || nameLength == 0)
        {
            if (invoked !is null && invoked[0] != '\0')
            {
                programName = invoked;
            }
            else
            {
                programName = fallbackProgram.ptr;
            }
        }

        enum size_t MAX_ARGS = 16;
        char*[MAX_ARGS] args;
        size_t argCount = 0;

        args[argCount] = cast(char*)programName;
        ++argCount;

        if (argv !is null)
        {
            size_t index = (argv[0] !is null) ? 1 : 0;
            while (argv[index] !is null && argCount + 1 < args.length)
            {
                args[argCount] = cast(char*)argv[index];
                ++argCount;
                ++index;
            }
        }

        if (argCount >= args.length)
        {
            argCount = args.length - 1;
        }
        args[argCount] = null;

        const(char*)* vector = null;
        if (envp !is null && envp[0] !is null)
        {
            vector = envp;
        }
        else
        {
            vector = getEnvironmentVector(g_current);
        }

        char** environment = (vector !is null) ? cast(char**)vector : null;

        int exitCode = 127;
        if (executeEmbeddedPosixUtility(programName, cast(const(char*)*)args.ptr, cast(const(char*)*)environment, exitCode))
        {
            sys__exit(exitCode);
        }

        spawnAndWait(programName, args.ptr, environment, &exitCode);
        sys__exit(exitCode);
    }

    private void launchInteractiveShell()
    {
        if (!g_consoleAvailable)
        {
            printLine("[shell] Interactive console not detected; skipping shell launch.");
            return;
        }

        if (!g_shellRegistered)
        {
            printLine("[shell] Shell executable not registered; cannot launch.");
            return;
        }

        const int execResult = sys_execve("/bin/sh", g_shellDefaultArgv.ptr, g_shellDefaultEnvp.ptr);
        if (execResult < 0)
        {
            const int errValue = errnoRef();
            print("[shell] execve('/bin/sh') failed (errno = ");
            printUnsigned(cast(size_t)errValue);
            printLine(")");
            shellState.shellActivated = false;
            shellState.failureReason = "execve(/bin/sh) failed";
        }
    }
}
else
{
    private bool runHostShellSession(const(char*)* /*argv*/, const(char*)* /*envp*/)
    {
        return false;
    }

    extern(C) @nogc nothrow void shellExecEntry(const(char*)* /*argv*/, const(char*)* /*envp*/)
    {
        printLine("[shell] Interactive shell unavailable: host console support missing.");
    }

    extern(C) @nogc nothrow void posixUtilityExecEntry(const(char*)* /*argv*/, const(char*)* /*envp*/)
    {
        printLine("[shell] POSIX utilities unsupported on this target.");
    }

    private void launchInteractiveShell()
    {
        printLine("[shell] Interactive shell unavailable: host console support missing.");
    }
}
*/

version (Posix) {
    extern(C) @nogc nothrow void shellExecEntry(const(char*)* argv, const(char*)* envp) { /* ... */ }
    extern(C) @nogc nothrow void posixUtilityExecEntry(const(char*)* argv, const(char*)* envp) { /* ... */ }
} else {
    extern(C) @nogc nothrow void shellExecEntry(const(char*)* /*argv*/, const(char*)* /*envp*/) { /* ... */ }
    extern(C) @nogc nothrow void posixUtilityExecEntry(const(char*)* /*argv*/, const(char*)* /*envp*/) { /* ... */ }
}