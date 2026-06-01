module userland.core.objects;

struct ObjectID
{
    ulong low;
    ulong high;
}

enum SocketType : ubyte
{
    Stream,
    Datagram,
}

__gshared ulong g_nextObjectId = 1;

@nogc nothrow private ObjectID nextObject()
{
    ObjectID id;
    id.low = g_nextObjectId++;
    id.high = 0;
    return id;
}

@nogc nothrow ObjectID createVMO(const(ubyte)[] data, bool executable)
{
    cast(void)data;
    cast(void)executable;
    return nextObject();
}

@nogc nothrow ObjectID createSocket(SocketType socketType)
{
    cast(void)socketType;
    return nextObject();
}

@nogc nothrow int socketBind(ObjectID socket, const(void)* addr, ushort port)
{
    cast(void)socket;
    cast(void)addr;
    cast(void)port;
    return 0;
}

@nogc nothrow int socketListen(ObjectID socket, int backlog)
{
    cast(void)socket;
    cast(void)backlog;
    return 0;
}

@nogc nothrow ObjectID socketAccept(ObjectID socket)
{
    cast(void)socket;
    return ObjectID.init;
}

@nogc nothrow long socketRecv(ObjectID socket, void* buffer, size_t length)
{
    cast(void)socket;
    cast(void)buffer;
    cast(void)length;
    return 0;
}

@nogc nothrow long socketSend(ObjectID socket, const(void)* buffer, size_t length)
{
    cast(void)socket;
    cast(void)buffer;
    return cast(long)length;
}

@nogc nothrow int socketClose(ObjectID socket)
{
    cast(void)socket;
    return 0;
}
