module anonymos.syscalls.capabilities;

// Low-level capability syscalls - the foundation of the entire system

import anonymos.objects;
import anonymos.object_methods;

// ============================================================================
// Capability List (C-List) - Per-Process Capability Table
// ============================================================================

struct CapabilitySlot
{
    Capability cap;
    bool inUse;
    bool revoked;
}

// Per-process capability list
struct CList
{
    CapabilitySlot[256] slots;
    size_t nextFreeSlot;
}

__gshared CList[64] g_processClists;  // One per process
__gshared size_t g_currentProcessIndex = 0;  // Current process (simplified)

// Get current process's C-List
@nogc nothrow CList* getCurrentCList()
{
    return &g_processClists[g_currentProcessIndex];
}

// Allocate capability slot in C-List
@nogc nothrow int allocCapSlot(Capability cap)
{
    auto clist = getCurrentCList();
    
    for (size_t i = 0; i < clist.slots.length; ++i)
    {
        if (!clist.slots[i].inUse)
        {
            clist.slots[i].cap = cap;
            clist.slots[i].inUse = true;
            clist.slots[i].revoked = false;
            return cast(int)i;
        }
    }
    
    return -1; // No free slots
}

// Get capability from C-List
@nogc nothrow Capability* getCapFromCList(int capId)
{
    auto clist = getCurrentCList();
    
    if (capId < 0 || capId >= clist.slots.length)
        return null;
    
    if (!clist.slots[capId].inUse || clist.slots[capId].revoked)
        return null;
    
    return &clist.slots[capId].cap;
}

// ============================================================================
// Method Descriptors
// ============================================================================

struct MethodDescriptor
{
    uint methodId;
    char[64] name;
    uint requiredRights;
    bool takesInput;
    bool returnsOutput;
}

// Get method descriptors for object type
@nogc nothrow size_t getMethodDescriptors(ObjectType type, MethodDescriptor* buffer, size_t bufferSize)
{
    size_t count = 0;
    
    void addMethod(uint id, const(char)[] name, uint rights, bool input, bool output)
    {
        if (count >= bufferSize) return;
        
        buffer[count].methodId = id;
        buffer[count].requiredRights = rights;
        buffer[count].takesInput = input;
        buffer[count].returnsOutput = output;
        
        size_t len = name.length;
        if (len > 63) len = 63;
        for (size_t i = 0; i < len; ++i)
            buffer[count].name[i] = name[i];
        buffer[count].name[len] = 0;
        
        count++;
    }
    
    switch (type)
    {
        case ObjectType.Blob:
            addMethod(1, "read", Rights.Read, true, true);
            addMethod(2, "write", Rights.Write, true, false);
            addMethod(3, "size", Rights.Read, false, true);
            break;
        
        case ObjectType.Directory:
            addMethod(10, "lookup", Rights.Enumerate, true, true);
            addMethod(11, "insert", Rights.Write, true, false);
            addMethod(12, "remove", Rights.Write, true, false);
            addMethod(13, "list", Rights.Enumerate, false, true);
            break;
        
        case ObjectType.Process:
            addMethod(20, "getState", Rights.Read, false, true);
            addMethod(21, "signal", Rights.Call, true, false);
            addMethod(22, "wait", Rights.Call, false, true);
            addMethod(23, "export", Rights.Write, true, false);
            break;
        
        case ObjectType.BlockDevice:
            addMethod(30, "readBlock", Rights.Read, true, true);
            addMethod(31, "writeBlock", Rights.Write, true, false);
            addMethod(32, "flush", Rights.Call, false, false);
            break;
        
        case ObjectType.Channel:
            addMethod(40, "send", Rights.Write, true, false);
            addMethod(41, "recv", Rights.Read, false, true);
            addMethod(42, "shutdown", Rights.Call, false, false);
            break;
        
        case ObjectType.Socket:
            addMethod(50, "bind", Rights.Write, true, false);
            addMethod(51, "connect", Rights.Write, true, false);
            addMethod(52, "send", Rights.Write, true, false);
            addMethod(53, "recv", Rights.Read, false, true);
            break;
        
        default:
            break;
    }
    
    return count;
}

// ============================================================================
// SYSCALL: cap_invoke
// ============================================================================

struct InvokeArgs
{
    const(ubyte)* inBytes;
    size_t inBytesLen;
    const(int)* inCaps;
    size_t inCapsLen;
    ubyte* outBytes;
    size_t outBytesLen;
    int* outCaps;
    size_t outCapsLen;
}

export extern(C) long sys_cap_invoke(int capId, uint methodId, InvokeArgs* args)
{
    // 1. Look up capability in C-List
    auto cap = getCapFromCList(capId);
    if (cap is null) return -9; // EBADF
    
    // 2. Get object
    auto slot = getObject(cap.oid);
    if (slot is null) return -5; // EIO
    
    // 3. Get method descriptor to check rights
    MethodDescriptor[32] methods;
    size_t methodCount = getMethodDescriptors(slot.type, methods.ptr, 32);
    
    uint requiredRights = 0;
    bool methodFound = false;
    
    for (size_t i = 0; i < methodCount; ++i)
    {
        if (methods[i].methodId == methodId)
        {
            requiredRights = methods[i].requiredRights;
            methodFound = true;
            break;
        }
    }
    
    if (!methodFound) return -22; // EINVAL - unknown method
    
    // 4. Check rights
    if ((cap.rights & requiredRights) != requiredRights)
        return -13; // EACCES
    
    // 5. Dispatch to object method
    switch (slot.type)
    {
        case ObjectType.Blob:
            return invokeBlobMethod(cap.oid, methodId, args);
        
        case ObjectType.Directory:
            return invokeDirectoryMethod(cap.oid, methodId, args);
        
        case ObjectType.Process:
            return invokeProcessMethod(cap.oid, methodId, args);
        
        case ObjectType.BlockDevice:
            return invokeBlockDeviceMethod(cap.oid, methodId, args);
        
        case ObjectType.Channel:
            return invokeChannelMethod(cap.oid, methodId, args);
        
        case ObjectType.Socket:
            return invokeSocketMethod(cap.oid, methodId, args);
        
        default:
            return -22; // EINVAL
    }
}

// Blob method dispatch
@nogc nothrow long invokeBlobMethod(ObjectID oid, uint methodId, InvokeArgs* args)
{
    switch (methodId)
    {
        case 1: // read
            if (args.inBytesLen < 16) return -22; // Need offset + length
            ulong offset = *cast(ulong*)args.inBytes;
            ulong length = *cast(ulong*)(args.inBytes + 8);
            
            if (length > args.outBytesLen) length = args.outBytesLen;
            
            return blobRead(oid, offset, length, args.outBytes);
        
        case 2: // write
            if (args.inBytesLen < 8) return -22; // Need offset
            ulong offset = *cast(ulong*)args.inBytes;
            const(ubyte)* data = args.inBytes + 8;
            size_t dataLen = args.inBytesLen - 8;
            
            return blobWrite(oid, offset, data, dataLen);
        
        case 3: // size
            long size = blobSize(oid);
            if (args.outBytesLen >= 8)
                *cast(long*)args.outBytes = size;
            return size;
        
        default:
            return -22;
    }
}

// Directory method dispatch
@nogc nothrow long invokeDirectoryMethod(ObjectID oid, uint methodId, InvokeArgs* args)
{
    switch (methodId)
    {
        case 10: // lookup
            if (args.inBytesLen == 0) return -22;
            
            const(char)[] name = cast(const(char)[])args.inBytes[0 .. args.inBytesLen];
            auto cap = lookup(oid, name);
            
            if (cap.oid.low == 0 && cap.oid.high == 0)
                return -2; // ENOENT
            
            // Allocate capability in C-List
            int newCapId = allocCapSlot(cap);
            if (newCapId < 0) return -12; // ENOMEM
            
            // Return capability ID
            if (args.outCapsLen > 0)
                args.outCaps[0] = newCapId;
            
            return newCapId;
        
        case 11: // insert
            // TODO: Parse name + capability from input
            return -22; // Not implemented yet
        
        case 12: // remove
            if (args.inBytesLen == 0) return -22;
            
            const(char)[] name = cast(const(char)[])args.inBytes[0 .. args.inBytesLen];
            bool success = remove(oid, name);
            
            return success ? 0 : -2;
        
        case 13: // list
            DirListEntry[64] entries;
            size_t count = list(oid, entries.ptr, 64);
            
            // Format output
            size_t pos = 0;
            for (size_t i = 0; i < count && pos < args.outBytesLen; ++i)
            {
                // Write name
                size_t nameLen = 0;
                while (entries[i].name[nameLen] != 0 && nameLen < 64) nameLen++;
                
                for (size_t j = 0; j < nameLen && pos < args.outBytesLen; ++j)
                    args.outBytes[pos++] = cast(ubyte)entries[i].name[j];
                
                if (pos < args.outBytesLen)
                    args.outBytes[pos++] = '\n';
            }
            
            return cast(long)count;
        
        default:
            return -22;
    }
}

// Process method dispatch
@nogc nothrow long invokeProcessMethod(ObjectID oid, uint methodId, InvokeArgs* args)
{
    switch (methodId)
    {
        case 20: // getState
            auto state = processGetState(oid);
            if (args.outBytesLen >= 4)
                *cast(uint*)args.outBytes = cast(uint)state;
            return cast(long)state;
        
        case 21: // signal
            if (args.inBytesLen < 4) return -22;
            int signal = *cast(int*)args.inBytes;
            return processSignal(oid, signal);
        
        case 22: // wait
            return processWait(oid);
        
        case 23: // export
            // TODO: Parse name + capability
            return -22;
        
        default:
            return -22;
    }
}

// BlockDevice method dispatch
@nogc nothrow long invokeBlockDeviceMethod(ObjectID oid, uint methodId, InvokeArgs* args)
{
    switch (methodId)
    {
        case 30: // readBlock
            if (args.inBytesLen < 16) return -22;
            ulong blockIndex = *cast(ulong*)args.inBytes;
            ulong blockCount = *cast(ulong*)(args.inBytes + 8);
            
            return blockDeviceRead(oid, blockIndex, blockCount, args.outBytes);
        
        case 31: // writeBlock
            if (args.inBytesLen < 16) return -22;
            ulong blockIndex = *cast(ulong*)args.inBytes;
            ulong blockCount = *cast(ulong*)(args.inBytes + 8);
            const(ubyte)* data = args.inBytes + 16;
            
            return blockDeviceWrite(oid, blockIndex, data, blockCount);
        
        case 32: // flush
            return blockDeviceFlush(oid);
        
        default:
            return -22;
    }
}

// Channel method dispatch
@nogc nothrow long invokeChannelMethod(ObjectID oid, uint methodId, InvokeArgs* args)
{
    switch (methodId)
    {
        case 40: // send
            // Convert input cap IDs to capabilities
            Capability[10] caps;
            size_t capCount = args.inCapsLen;
            if (capCount > 10) capCount = 10;
            
            for (size_t i = 0; i < capCount; ++i)
            {
                auto cap = getCapFromCList(args.inCaps[i]);
                if (cap !is null)
                    caps[i] = *cap;
            }
            
            return channelSend(oid, args.inBytes, args.inBytesLen, caps.ptr, capCount);
        
        case 41: // recv
            Capability[10] recvCaps;
            size_t capsReceived;
            
            long result = channelRecv(oid, args.outBytes, args.outBytesLen, 
                                     recvCaps.ptr, 10, &capsReceived);
            
            // Allocate received capabilities in C-List
            for (size_t i = 0; i < capsReceived && i < args.outCapsLen; ++i)
            {
                int capId = allocCapSlot(recvCaps[i]);
                args.outCaps[i] = capId;
            }
            
            return result;
        
        case 42: // shutdown
            return channelShutdown(oid);
        
        default:
            return -22;
    }
}

// Socket method dispatch
@nogc nothrow long invokeSocketMethod(ObjectID oid, uint methodId, InvokeArgs* args)
{
    switch (methodId)
    {
        case 50: // bind
            if (args.inBytesLen < 20) return -22; // 16 bytes addr + 4 bytes port
            const(ubyte)* addr = args.inBytes;
            uint port = *cast(uint*)(args.inBytes + 16);
            
            return socketBind(oid, addr, port);
        
        case 51: // connect
            if (args.inBytesLen < 20) return -22;
            const(ubyte)* addr = args.inBytes;
            uint port = *cast(uint*)(args.inBytes + 16);
            
            return socketConnect(oid, addr, port);
        
        case 52: // send
            return socketSend(oid, args.inBytes, args.inBytesLen);
        
        case 53: // recv
            return socketRecv(oid, args.outBytes, args.outBytesLen);
        
        default:
            return -22;
    }
}

// ============================================================================
// SYSCALL: cap_dup
// ============================================================================

export extern(C) int sys_cap_dup(int capId, uint reducedRights)
{
    // 1. Look up original capability
    auto cap = getCapFromCList(capId);
    if (cap is null) return -9; // EBADF
    
    // 2. Create new capability with reduced rights
    Capability newCap;
    newCap.oid = cap.oid;
    newCap.rights = cap.rights & reducedRights;  // Can only reduce rights
    
    // 3. Allocate in C-List
    return allocCapSlot(newCap);
}

// ============================================================================
// SYSCALL: cap_revoke
// ============================================================================

export extern(C) int sys_cap_revoke(int capId)
{
    auto clist = getCurrentCList();
    
    if (capId < 0 || capId >= clist.slots.length)
        return -9; // EBADF
    
    if (!clist.slots[capId].inUse)
        return -9;
    
    // Mark as revoked
    clist.slots[capId].revoked = true;
    
    return 0;
}

// ============================================================================
// SYSCALL: cap_list_methods
// ============================================================================

export extern(C) long sys_cap_list_methods(int capId, MethodDescriptor* buffer, size_t bufferSize)
{
    // 1. Look up capability
    auto cap = getCapFromCList(capId);
    if (cap is null) return -9; // EBADF
    
    // 2. Get object
    auto slot = getObject(cap.oid);
    if (slot is null) return -5; // EIO
    
    // 3. Get method descriptors
    return cast(long)getMethodDescriptors(slot.type, buffer, bufferSize);
}

// ============================================================================
// SYSCALL: cap_grant (transfer capability to another process)
// ============================================================================

export extern(C) int sys_cap_grant(int targetProcessId, int capId)
{
    // 1. Look up capability in current process
    auto cap = getCapFromCList(capId);
    if (cap is null) return -9;
    
    // 2. Check if capability has Grant right
    if ((cap.rights & Rights.Grant) == 0)
        return -13; // EACCES
    
    // 3. Add to target process's C-List
    // (Simplified - would need proper process management)
    size_t oldIndex = g_currentProcessIndex;
    g_currentProcessIndex = targetProcessId;
    
    int newCapId = allocCapSlot(*cap);
    
    g_currentProcessIndex = oldIndex;
    
    return newCapId;
}

// ============================================================================
// Helper: Initialize process C-List with initial capabilities
// ============================================================================

export extern(C) void initProcessCList(size_t processIndex, Capability rootCap, Capability homeCap, Capability procCap)
{
    auto clist = &g_processClists[processIndex];
    
    // Clear all slots
    for (size_t i = 0; i < clist.slots.length; ++i)
    {
        clist.slots[i].inUse = false;
        clist.slots[i].revoked = false;
    }
    
    clist.nextFreeSlot = 0;
    
    // Allocate initial capabilities
    // Slot 0: root
    clist.slots[0].cap = rootCap;
    clist.slots[0].inUse = true;
    clist.slots[0].revoked = false;
    
    // Slot 1: home
    clist.slots[1].cap = homeCap;
    clist.slots[1].inUse = true;
    clist.slots[1].revoked = false;
    
    // Slot 2: proc
    clist.slots[2].cap = procCap;
    clist.slots[2].inUse = true;
    clist.slots[2].revoked = false;
    
    clist.nextFreeSlot = 3;
}
