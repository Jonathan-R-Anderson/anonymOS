module kernel.hardware.network;

import kernel.logger : log_message;

struct NetPacket {
    ubyte[1500] data;
    size_t len;
}

enum MAX_QUEUE = 16;
__gshared NetPacket[MAX_QUEUE] pktQueue;
__gshared size_t qHead;
__gshared size_t qTail;
__gshared bool qInit;

extern(C) void net_init()
{
    qHead = qTail = 0;
    qInit = true;
    log_message("net_init complete\n");
}

extern(C) void net_send(const(NetPacket)* p)
{
    if(!qInit) {
        log_message("net_send called before init\n");
        return;
    }
    size_t next = (qTail + 1) % MAX_QUEUE;
    if(next == qHead) {
        log_message("net_send queue full, dropping packet\n");
        return;
    }
    pktQueue[qTail].len = p.len;
    foreach(i; 0 .. p.len) {
        pktQueue[qTail].data[i] = p.data[i];
    }
    qTail = next;
    log_message("net_send queued packet\n");
}

extern(C) size_t net_receive(NetPacket* p)
{
    if(!qInit || qHead == qTail)
        return 0; // No packet available
    p.len = pktQueue[qHead].len;
    foreach(i; 0 .. p.len)
        p.data[i] = pktQueue[qHead].data[i];
    qHead = (qHead + 1) % MAX_QUEUE;
    log_message("net_receive delivered packet\n");
    return p.len;
}
