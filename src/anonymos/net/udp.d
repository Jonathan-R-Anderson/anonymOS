module anonymos.net.udp;

import anonymos.net.types;
import anonymos.net.ipv4;

/// UDP header
struct UDPHeader {
    ushort srcPort;
    ushort destPort;
    ushort length;      // Header + data
    ushort checksum;
}

/// UDP receive callback type
alias UDPCallback = extern(C) void function(const(ubyte)*, size_t, const ref IPv4Address, ushort) @nogc nothrow;

/// UDP socket
struct UDPSocket {
    ushort localPort;
    bool bound;
    UDPCallback callback;
}

private __gshared UDPSocket[256] g_udpSockets;
private __gshared size_t g_udpSocketCount = 0;

/// Create UDP socket
export extern(C) int udpSocket() @nogc nothrow {
    if (g_udpSocketCount >= g_udpSockets.length) {
        return -1;  // No more sockets available
    }
    
    int sockfd = cast(int)g_udpSocketCount;
    g_udpSockets[sockfd].bound = false;
    g_udpSockets[sockfd].callback = null;
    g_udpSocketCount++;
    
    return sockfd;
}

/// Bind UDP socket to port
export extern(C) bool udpBind(int sockfd, ushort port) @nogc nothrow {
    if (sockfd < 0 || sockfd >= g_udpSocketCount) return false;
    
    // Check if port already in use
    for (size_t i = 0; i < g_udpSocketCount; i++) {
        if (g_udpSockets[i].bound && g_udpSockets[i].localPort == port) {
            return false;
        }
    }
    
    g_udpSockets[sockfd].localPort = port;
    g_udpSockets[sockfd].bound = true;
    
    return true;
}

/// Set UDP receive callback
export extern(C) void udpSetCallback(int sockfd, UDPCallback callback) @nogc nothrow {
    if (sockfd < 0 || sockfd >= g_udpSocketCount) return;
    g_udpSockets[sockfd].callback = callback;
}

/// Send UDP packet
export extern(C) bool udpSend(int sockfd,
                               const ref IPv4Address destIP,
                               ushort destPort,
                               const(ubyte)* data,
                               size_t dataLen) @nogc nothrow {
    if (sockfd < 0 || sockfd >= g_udpSocketCount) return false;
    if (!g_udpSockets[sockfd].bound) return false;
    if (data is null || dataLen == 0) return false;
    
    enum MAX_UDP_SIZE = 1472;  // MTU 1500 - IP header (20) - UDP header (8)
    ubyte[MAX_UDP_SIZE + UDPHeader.sizeof] buffer;
    
    size_t packetSize = UDPHeader.sizeof + dataLen;
    if (packetSize > buffer.length) return false;
    
    // Build UDP header
    UDPHeader* header = cast(UDPHeader*)buffer.ptr;
    header.srcPort = htons(g_udpSockets[sockfd].localPort);
    header.destPort = htons(destPort);
    header.length = htons(cast(ushort)packetSize);
    header.checksum = 0;  // Optional for IPv4
    
    // Copy data
    ubyte* payload = buffer.ptr + UDPHeader.sizeof;
    for (size_t i = 0; i < dataLen; i++) {
        payload[i] = data[i];
    }
    
    // Send via IPv4
    return ipv4Send(destIP, IPProtocol.UDP, buffer.ptr, packetSize);
}

/// Handle received UDP packet
export extern(C) void udpHandlePacket(const(ubyte)* data, size_t len,
                                       const ref IPv4Address srcIP) @nogc nothrow {
    if (data is null || len < UDPHeader.sizeof) return;
    
    const UDPHeader* header = cast(const UDPHeader*)data;
    
    ushort destPort = ntohs(header.destPort);
    ushort srcPort = ntohs(header.srcPort);
    
    // Find socket bound to this port
    for (size_t i = 0; i < g_udpSocketCount; i++) {
        if (g_udpSockets[i].bound && g_udpSockets[i].localPort == destPort) {
            // Deliver to socket
            const(ubyte)* payload = data + UDPHeader.sizeof;
            size_t payloadLen = len - UDPHeader.sizeof;
            
            if (g_udpSockets[i].callback !is null) {
                g_udpSockets[i].callback(payload, payloadLen, srcIP, srcPort);
            }
            
            return;
        }
    }
}

/// Close UDP socket
export extern(C) void udpClose(int sockfd) @nogc nothrow {
    if (sockfd < 0 || sockfd >= g_udpSocketCount) return;
    g_udpSockets[sockfd].bound = false;
    g_udpSockets[sockfd].callback = null;
}
