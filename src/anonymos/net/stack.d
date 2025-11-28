module anonymos.net.stack;

import anonymos.net.types;
import anonymos.net.ethernet;
import anonymos.net.arp;
import anonymos.net.ipv4;
import anonymos.net.icmp;
import anonymos.net.udp;
import anonymos.net.tcp;
import anonymos.net.dns;
import anonymos.net.tls;
import anonymos.drivers.network : initNetwork, isNetworkAvailable;

private __gshared bool g_stackInitialized = false;
private __gshared bool g_stackRunning = false;

/// Initialize the entire network stack
export extern(C) bool initNetworkStack(const IPv4Address* localIP,
                                        const IPv4Address* gateway,
                                        const IPv4Address* netmask,
                                        const IPv4Address* dnsServer) @nogc nothrow {
    if (g_stackInitialized) return true;
    
    // Initialize network driver
    initNetwork();
    
    if (!isNetworkAvailable()) {
        return false;
    }
    
    // Initialize layers
    initEthernet();
    initIPv4(localIP, gateway, netmask);
    
    // Initialize DNS
    initDNS(dnsServer);
    
    // Initialize TLS
    initTLS();
    
    g_stackInitialized = true;
    g_stackRunning = true;
    
    return true;
}

/// Protocol handler for IPv4
private extern(C) void handleIPv4Protocol(ubyte protocol, const(ubyte)* data, size_t len,
                                 const ref IPv4Address srcIP) @nogc nothrow {
    switch (protocol) {
        case IPProtocol.ICMP:
            icmpHandlePacket(data, len, srcIP);
            break;
            
        case IPProtocol.UDP:
            udpHandlePacket(data, len, srcIP);
            break;
            
        case IPProtocol.TCP:
            tcpHandlePacket(data, len, srcIP);
            break;
            
        default:
            // Unknown protocol
            break;
    }
}

/// Process incoming packets (call this regularly from main loop)
export extern(C) void networkStackPoll() @nogc nothrow {
    if (!g_stackRunning) return;
    
    enum MAX_FRAME_SIZE = 1518;
    ubyte[MAX_FRAME_SIZE] buffer;
    
    EthernetFrame frame;
    int received = receiveEthernetFrame(&frame, buffer.ptr, MAX_FRAME_SIZE);
    
    if (received <= 0) return;
    
    // Check if frame is for us
    if (!isFrameForUs(frame)) return;
    
    // Handle by EtherType
    switch (frame.header.etherType) {
        case EtherType.ARP:
            arpHandlePacket(frame.payload, frame.payloadLength);
            break;
            
        case EtherType.IPv4:
            ipv4HandlePacket(frame.payload, frame.payloadLength, &handleIPv4Protocol);
            break;
            
        default:
            // Unknown EtherType
            break;
    }
}

/// Configure network interface
export extern(C) bool configureNetwork(ubyte a, ubyte b, ubyte c, ubyte d,
                                        ubyte ga, ubyte gb, ubyte gc, ubyte gd,
                                        ubyte na, ubyte nb, ubyte nc, ubyte nd,
                                        ubyte da, ubyte db, ubyte dc, ubyte dd) @nogc nothrow {
    IPv4Address localIP = IPv4Address(a, b, c, d);
    IPv4Address gateway = IPv4Address(ga, gb, gc, gd);
    IPv4Address netmask = IPv4Address(na, nb, nc, nd);
    IPv4Address dnsServer = IPv4Address(da, db, dc, dd);
    
    return initNetworkStack(&localIP, &gateway, &netmask, &dnsServer);
}

/// Get network stack status
export extern(C) bool isNetworkStackRunning() @nogc nothrow {
    return g_stackRunning;
}

/// Stop network stack
export extern(C) void stopNetworkStack() @nogc nothrow {
    g_stackRunning = false;
}

/// Start network stack
export extern(C) void startNetworkStack() @nogc nothrow {
    if (g_stackInitialized) {
        g_stackRunning = true;
    }
}

// ============================================================================
// High-level API wrappers
// ============================================================================

/// Ping a host
export extern(C) bool ping(ubyte a, ubyte b, ubyte c, ubyte d) @nogc nothrow {
    IPv4Address target = IPv4Address(a, b, c, d);
    
    ubyte[32] data;
    for (int i = 0; i < 32; i++) {
        data[i] = cast(ubyte)i;
    }
    
    return icmpSendPing(target, 1, 1, data.ptr, data.length);
}

/// Create and connect TCP socket
export extern(C) int tcpConnectTo(ubyte a, ubyte b, ubyte c, ubyte d, ushort port) @nogc nothrow {
    IPv4Address target = IPv4Address(a, b, c, d);
    
    int sock = tcpSocket();
    if (sock < 0) return -1;
    
    // Bind to ephemeral port
    if (!tcpBind(sock, 50000 + (sock % 10000))) {
        return -1;
    }
    
    if (!tcpConnect(sock, target, port)) {
        tcpClose(sock);
        return -1;
    }
    
    return sock;
}

/// Create UDP socket and bind to port
export extern(C) int udpBindTo(ushort port) @nogc nothrow {
    int sock = udpSocket();
    if (sock < 0) return -1;
    
    if (!udpBind(sock, port)) {
        udpClose(sock);
        return -1;
    }
    
    return sock;
}

/// Send UDP datagram
export extern(C) bool udpSendTo(int sock, ubyte a, ubyte b, ubyte c, ubyte d,
                                 ushort port, const(ubyte)* data, size_t len) @nogc nothrow {
    IPv4Address target = IPv4Address(a, b, c, d);
    return udpSend(sock, target, port, data, len);
}
