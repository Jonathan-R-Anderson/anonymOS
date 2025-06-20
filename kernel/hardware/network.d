module kernel.hardware.network;

import kernel.logger : log_message;

struct NetPacket {
    ubyte[1500] data;
    size_t len;
}

extern(C) void net_init()
{
    log_message("net_init stub\n");
}

extern(C) void net_send(const(NetPacket)* p)
{
    log_message("net_send stub\n");
}

extern(C) size_t net_receive(NetPacket* p)
{
    log_message("net_receive stub\n");
    return 0;
}
