module minimal_os.object_methods;

// Object method interfaces for typed objects

import minimal_os.objects;

// ============================================================================
// Blob Object Methods
// ============================================================================

// Read from blob
@nogc nothrow long blobRead(ObjectID blobId, ulong offset, ulong length, ubyte* buffer)
{
    auto slot = getObject(blobId);
    if (slot is null || slot.type != ObjectType.Blob) return -1; // EINVAL
    
    if (slot.blob.vmo is null) return -1;
    
    // Check bounds
    if (offset >= slot.blob.size) return 0; // EOF
    if (offset + length > slot.blob.size)
        length = slot.blob.size - offset;
    
    // Copy from VMO
    auto vmo = slot.blob.vmo;
    if (offset + length > vmo.dataLen) return -1;
    
    for (size_t i = 0; i < length; ++i)
        buffer[i] = vmo.dataPtr[offset + i];
    
    return cast(long)length;
}

// Write to blob (creates new VMO if immutable)
@nogc nothrow long blobWrite(ObjectID blobId, ulong offset, const(ubyte)* data, ulong length)
{
    auto slot = getObject(blobId);
    if (slot is null || slot.type != ObjectType.Blob) return -1;
    
    if (slot.blob.vmo is null) return -1;
    
    // If VMO is immutable, we need to create a new one
    if (slot.blob.vmo.immutable_)
    {
        // Create new mutable VMO with updated data
        size_t newSize = offset + length;
        if (newSize < slot.blob.size) newSize = slot.blob.size;
        
        ubyte* newData = cast(ubyte*)kmalloc(newSize);
        if (newData is null) return -12; // ENOMEM
        
        // Copy old data
        for (size_t i = 0; i < slot.blob.vmo.dataLen && i < newSize; ++i)
            newData[i] = slot.blob.vmo.dataPtr[i];
        
        // Write new data
        for (size_t i = 0; i < length; ++i)
            newData[offset + i] = data[i];
        
        // Create new VMO
        ObjectID newVmoId = createVMO(cast(const(ubyte)[])newData[0..newSize], false);
        if (newVmoId.low == 0) return -12;
        
        auto newVmoSlot = getObject(newVmoId);
        if (newVmoSlot is null) return -1;
        
        slot.blob.vmo = &newVmoSlot.vmo;
        slot.blob.size = newSize;
    }
    else
    {
        // Mutable VMO - write directly
        if (offset + length > slot.blob.vmo.dataLen) return -1; // Out of bounds
        
        ubyte* dest = cast(ubyte*)slot.blob.vmo.dataPtr;
        for (size_t i = 0; i < length; ++i)
            dest[offset + i] = data[i];
    }
    
    slot.blob.modifiedTime = 0; // TODO: Get actual time
    
    return cast(long)length;
}

// Get blob size
@nogc nothrow long blobSize(ObjectID blobId)
{
    auto slot = getObject(blobId);
    if (slot is null || slot.type != ObjectType.Blob) return -1;
    
    return cast(long)slot.blob.size;
}

// ============================================================================
// Block Device Object Methods
// ============================================================================

@nogc nothrow long blockDeviceRead(ObjectID deviceId, ulong blockIndex, ulong blockCount, ubyte* buffer)
{
    auto slot = getObject(deviceId);
    if (slot is null || slot.type != ObjectType.BlockDevice) return -1;
    
    if (slot.blockDevice.readBlock is null) return -1;
    
    return slot.blockDevice.readBlock(
        slot.blockDevice.deviceContext,
        blockIndex,
        blockCount,
        buffer
    );
}

@nogc nothrow long blockDeviceWrite(ObjectID deviceId, ulong blockIndex, const(ubyte)* data, ulong blockCount)
{
    auto slot = getObject(deviceId);
    if (slot is null || slot.type != ObjectType.BlockDevice) return -1;
    
    if (slot.blockDevice.writeBlock is null) return -1;
    
    return slot.blockDevice.writeBlock(
        slot.blockDevice.deviceContext,
        blockIndex,
        data,
        blockCount
    );
}

@nogc nothrow long blockDeviceFlush(ObjectID deviceId)
{
    auto slot = getObject(deviceId);
    if (slot is null || slot.type != ObjectType.BlockDevice) return -1;
    
    if (slot.blockDevice.flush is null) return 0; // No-op if not implemented
    
    return slot.blockDevice.flush(slot.blockDevice.deviceContext);
}

// ============================================================================
// Process Object Methods
// ============================================================================

@nogc nothrow ProcessState processGetState(ObjectID processId)
{
    auto slot = getObject(processId);
    if (slot is null || slot.type != ObjectType.Process)
        return ProcessState.Terminated;
    
    return slot.process.state;
}

@nogc nothrow long processSignal(ObjectID processId, int signal)
{
    auto slot = getObject(processId);
    if (slot is null || slot.type != ObjectType.Process) return -1;
    
    // TODO: Implement signal delivery
    return 0;
}

@nogc nothrow long processWait(ObjectID processId)
{
    auto slot = getObject(processId);
    if (slot is null || slot.type != ObjectType.Process) return -1;
    
    // Wait for process to terminate
    while (slot.process.state != ProcessState.Zombie &&
           slot.process.state != ProcessState.Terminated)
    {
        // TODO: Implement proper waiting/blocking
        // For now, just spin (bad!)
    }
    
    return slot.process.exitCode;
}

@nogc nothrow bool processExport(ObjectID processId, const(char)[] name, Capability cap)
{
    auto slot = getObject(processId);
    if (slot is null || slot.type != ObjectType.Process) return false;
    
    // Resize exports if needed
    if (slot.process.exportCount >= slot.process.exportCapacity)
    {
        size_t newCap = slot.process.exportCapacity * 2;
        if (newCap == 0) newCap = 16;
        
        DirEntry* newExports = cast(DirEntry*)kmalloc(DirEntry.sizeof * newCap);
        if (newExports is null) return false;
        
        // Copy old exports
        for (size_t i = 0; i < slot.process.exportCount; ++i)
            newExports[i] = slot.process.exports[i];
        
        slot.process.exports = newExports;
        slot.process.exportCapacity = newCap;
    }
    
    // Add export
    DirEntry* entry = &slot.process.exports[slot.process.exportCount++];
    
    size_t len = name.length;
    if (len > 63) len = 63;
    for (size_t i = 0; i < len; ++i)
        entry.name[i] = name[i];
    entry.name[len] = 0;
    
    entry.cap = cap;
    
    return true;
}

// ============================================================================
// Channel Object Methods (IPC)
// ============================================================================

@nogc nothrow long channelSend(ObjectID channelId, const(ubyte)* data, size_t dataLen, Capability* caps, size_t capCount)
{
    auto slot = getObject(channelId);
    if (slot is null || slot.type != ObjectType.Channel) return -1;
    
    if (slot.channel.state != ChannelState.Open) return -32; // EPIPE
    
    // Check if queue is full
    size_t nextTail = (slot.channel.queueTail + 1) % slot.channel.queueCapacity;
    if (nextTail == slot.channel.queueHead) return -11; // EAGAIN (queue full)
    
    // Allocate message data
    ubyte* msgData = null;
    if (dataLen > 0)
    {
        msgData = cast(ubyte*)kmalloc(dataLen);
        if (msgData is null) return -12; // ENOMEM
        
        for (size_t i = 0; i < dataLen; ++i)
            msgData[i] = data[i];
    }
    
    // Allocate capability array
    Capability* msgCaps = null;
    if (capCount > 0)
    {
        msgCaps = cast(Capability*)kmalloc(Capability.sizeof * capCount);
        if (msgCaps is null) return -12;
        
        for (size_t i = 0; i < capCount; ++i)
            msgCaps[i] = caps[i];
    }
    
    // Add to peer's queue
    auto peerSlot = getObject(slot.channel.peerChannel);
    if (peerSlot is null || peerSlot.type != ObjectType.Channel) return -1;
    
    Message* msg = &peerSlot.channel.messageQueue[peerSlot.channel.queueTail];
    msg.data = msgData;
    msg.dataLen = dataLen;
    msg.caps = msgCaps;
    msg.capCount = capCount;
    
    peerSlot.channel.queueTail = nextTail;
    
    return cast(long)dataLen;
}

@nogc nothrow long channelRecv(ObjectID channelId, ubyte* buffer, size_t bufferSize, Capability* capBuffer, size_t capBufferSize, size_t* capsReceived)
{
    auto slot = getObject(channelId);
    if (slot is null || slot.type != ObjectType.Channel) return -1;
    
    // Check if queue is empty
    if (slot.channel.queueHead == slot.channel.queueTail)
    {
        if (slot.channel.state == ChannelState.Shutdown)
            return 0; // EOF
        return -11; // EAGAIN (no messages)
    }
    
    // Get message
    Message* msg = &slot.channel.messageQueue[slot.channel.queueHead];
    
    // Copy data
    size_t copyLen = msg.dataLen;
    if (copyLen > bufferSize) copyLen = bufferSize;
    
    for (size_t i = 0; i < copyLen; ++i)
        buffer[i] = msg.data[i];
    
    // Copy capabilities
    size_t capCopyCount = msg.capCount;
    if (capCopyCount > capBufferSize) capCopyCount = capBufferSize;
    
    for (size_t i = 0; i < capCopyCount; ++i)
        capBuffer[i] = msg.caps[i];
    
    if (capsReceived !is null)
        *capsReceived = capCopyCount;
    
    // Advance queue
    slot.channel.queueHead = (slot.channel.queueHead + 1) % slot.channel.queueCapacity;
    
    return cast(long)copyLen;
}

@nogc nothrow long channelShutdown(ObjectID channelId)
{
    auto slot = getObject(channelId);
    if (slot is null || slot.type != ObjectType.Channel) return -1;
    
    slot.channel.state = ChannelState.Shutdown;
    
    // Shutdown peer as well
    auto peerSlot = getObject(slot.channel.peerChannel);
    if (peerSlot !is null && peerSlot.type == ObjectType.Channel)
        peerSlot.channel.state = ChannelState.Shutdown;
    
    return 0;
}

// ============================================================================
// Socket Object Methods
// ============================================================================

@nogc nothrow long socketBind(ObjectID socketId, const(ubyte)* addr, uint port)
{
    auto slot = getObject(socketId);
    if (slot is null || slot.type != ObjectType.Socket) return -1;
    
    if (slot.socket.state != SocketState.Unbound) return -22; // EINVAL
    
    // Copy address
    for (size_t i = 0; i < 16; ++i)
        slot.socket.localAddr[i] = addr[i];
    
    slot.socket.localPort = port;
    slot.socket.state = SocketState.Bound;
    
    return 0;
}

@nogc nothrow long socketConnect(ObjectID socketId, const(ubyte)* addr, uint port)
{
    auto slot = getObject(socketId);
    if (slot is null || slot.type != ObjectType.Socket) return -1;
    
    // Copy remote address
    for (size_t i = 0; i < 16; ++i)
        slot.socket.remoteAddr[i] = addr[i];
    
    slot.socket.remotePort = port;
    slot.socket.state = SocketState.Connected;
    
    // TODO: Actual TCP/UDP connection logic
    
    return 0;
}

@nogc nothrow long socketSend(ObjectID socketId, const(ubyte)* data, size_t length)
{
    auto slot = getObject(socketId);
    if (slot is null || slot.type != ObjectType.Socket) return -1;
    
    if (slot.socket.state != SocketState.Connected) return -107; // ENOTCONN
    
    // TODO: Actual network send
    
    return cast(long)length;
}

@nogc nothrow long socketRecv(ObjectID socketId, ubyte* buffer, size_t length)
{
    auto slot = getObject(socketId);
    if (slot is null || slot.type != ObjectType.Socket) return -1;
    
    if (slot.socket.state != SocketState.Connected) return -107;
    
    // TODO: Actual network receive
    
    return 0; // No data for now
}
