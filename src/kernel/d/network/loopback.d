/**
 * network/loopback.d -- 127.0.0.0/8: the machine talking to itself.
 *
 * There was none: connect() to 127.x returned ECONNREFUSED.  The dendritic node cannot run without
 * it -- it serves its S3 API, dashboard and operator API on loopback, and the OS's own clients (the
 * updater, the crash reporter) reach the network through it -- and neither can anything else that
 * talks to a local daemon.
 *
 * It is an interface like the vnet domain interfaces (network/vnet.d): g_netIf == NETIF_LOOPBACK
 * selects it, getLocalIP() answers 127.0.0.1 for it, ipv4Send() hands its packets here, and a TCP
 * connection remembers it (TcpConn.nif).  Sending only queues the datagram; loopbackDrain(), called
 * from the kernel tick, delivers queued datagrams to TCP/UDP/ICMP input with g_netIf set back to
 * loopback -- never re-entering a protocol's input from inside its own output.
 *
 * Each queued datagram carries the sender's domain and whether it is trusted, so a TCP listener can
 * refuse a loopback connection from another domain (network/tcp.d listenerTakes).
 */
module network.loopback;

import network.types;

@nogc nothrow:

/// g_netIf value for the loopback interface (vnet ports are 1 .. VNET_MAX_PORTS-1).
enum int NETIF_LOOPBACK = 0x7F00;

/// Who sent the datagram being delivered (valid during loopbackDrain's dispatch).
__gshared uint g_loopSrcDom     = 0;
__gshared bool g_loopSrcTrusted = false;

/// Who is sending: set by a protocol's output just before ipv4Send (TCP: the connection's owner).
__gshared uint g_netTxDom     = 0;
__gshared bool g_netTxTrusted = false;

/// 127.0.0.1, as an IPv4Address.
public IPv4Address loopbackAddr() { return IPv4Address(127, 0, 0, 1); }

/// Is `ip` in 127.0.0.0/8?
public bool isLoopbackAddr(const ref IPv4Address ip) { return ip.bytes[0] == 127; }

private enum int    LOOP_Q    = 256;
private enum size_t LOOP_MTU  = 1480;     // the largest payload ipv4Send carries (1500 - 20)

private struct LoopPkt {
    bool        used;
    ubyte       proto;
    IPv4Address src, dst;
    uint        dom;
    bool        trusted;
    ushort      len;
    ubyte[LOOP_MTU] data;
}

private __gshared LoopPkt[LOOP_Q] g_loopQ;
private __gshared int g_loopHead = 0, g_loopLen = 0;
__gshared ulong g_loopSent, g_loopDropped, g_loopDelivered;

/// ipv4Send() for the loopback interface: queue the datagram for loopbackDrain.  A full queue drops
/// it, as a congested interface would (TCP resends; nothing else on loopback cares).
public bool loopbackSendIPv4(const ref IPv4Address dst, ubyte proto, const(ubyte)* payload, size_t len) {
    if (payload is null || len == 0 || len > LOOP_MTU) return false;
    if (g_loopLen >= LOOP_Q) { ++g_loopDropped; return true; }
    auto q = &g_loopQ[(g_loopHead + g_loopLen) % LOOP_Q];
    q.used = true;
    q.proto = proto;
    q.src = loopbackAddr();
    q.dst = dst;
    q.dom = g_netTxDom;
    q.trusted = g_netTxTrusted;
    q.len = cast(ushort)len;
    foreach (i; 0 .. len) q.data[i] = payload[i];
    ++g_loopLen;
    ++g_loopSent;
    return true;
}

/// Deliver up to `max` queued datagrams (each may queue replies, which a later call delivers).
/// Returns how many were delivered.
public uint loopbackDrain(uint max) {
    import network.vnet : g_netIf;
    import network.tcp : tcpHandlePacket;
    import network.udp : udpHandlePacket;
    import network.icmp : icmpHandlePacket;
    uint n = 0;
    while (n < max && g_loopLen > 0) {
        // Copy out first: delivering may queue new datagrams into the slot being read.
        LoopPkt p = g_loopQ[g_loopHead];
        g_loopQ[g_loopHead].used = false;
        g_loopHead = (g_loopHead + 1) % LOOP_Q;
        --g_loopLen;
        const int prevIf = g_netIf;
        g_netIf = NETIF_LOOPBACK;
        g_loopSrcDom = p.dom; g_loopSrcTrusted = p.trusted;
        switch (p.proto) {
            case 6:  tcpHandlePacket(p.data.ptr, p.len, p.src); break;
            case 17: udpHandlePacket(p.data.ptr, p.len, p.src); break;
            case 1:  icmpHandlePacket(p.data.ptr, p.len, p.src); break;
            default: break;
        }
        g_loopSrcDom = 0; g_loopSrcTrusted = false;
        g_netIf = prevIf;
        ++g_loopDelivered;
        ++n;
    }
    return n;
}
