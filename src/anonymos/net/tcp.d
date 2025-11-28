module anonymos.net.tcp;

import anonymos.net.types;
import anonymos.net.ipv4;

/// TCP header
struct TCPHeader {
    ushort srcPort;
    ushort destPort;
    uint sequenceNum;
    uint ackNum;
    ubyte dataOffsetFlags;  // Data offset (4 bits) + Reserved (3 bits) + Flags (9 bits, but we use next byte)
    ubyte flags;            // Flags: FIN, SYN, RST, PSH, ACK, URG
    ushort windowSize;
    ushort checksum;
    ushort urgentPointer;
}

/// TCP pseudo-header for checksum calculation
struct TCPPseudoHeader {
    IPv4Address srcIP;
    IPv4Address destIP;
    ubyte zero;
    ubyte protocol;
    ushort tcpLength;
}

/// TCP callback types
alias TCPConnectCallback = extern(C) void function(int) @nogc nothrow;
alias TCPDataCallback = extern(C) void function(int, const(ubyte)*, size_t) @nogc nothrow;
alias TCPCloseCallback = extern(C) void function(int) @nogc nothrow;

/// TCP connection
struct TCPConnection {
    IPv4Address remoteIP;
    ushort localPort;
    ushort remotePort;
    TCPState state;
    
    // Sequence numbers
    uint sendSeq;
    uint recvSeq;
    uint sendAck;
    
    // Window
    ushort sendWindow;
    ushort recvWindow;
    
    // Buffers
    ubyte[4096] sendBuffer;
    size_t sendBufferLen;
    ubyte[4096] recvBuffer;
    size_t recvBufferLen;
    
    // Callbacks
    TCPConnectCallback onConnect;
    TCPDataCallback onData;
    TCPCloseCallback onClose;
    
    bool active;
}

private __gshared TCPConnection[256] g_tcpConnections;
private __gshared size_t g_tcpConnectionCount = 0;
private __gshared uint g_initialSeqNum = 1000;

/// Calculate TCP checksum
private ushort tcpChecksum(const ref IPv4Address srcIP,
                           const ref IPv4Address destIP,
                           const(ubyte)* tcpData,
                           size_t tcpLen) @nogc nothrow {
    // Build pseudo-header
    TCPPseudoHeader pseudo;
    pseudo.srcIP = srcIP;
    pseudo.destIP = destIP;
    pseudo.zero = 0;
    pseudo.protocol = IPProtocol.TCP;
    pseudo.tcpLength = htons(cast(ushort)tcpLen);
    
    uint sum = 0;
    
    // Sum pseudo-header
    const(ubyte)* pseudoBytes = cast(const(ubyte)*)&pseudo;
    for (size_t i = 0; i < TCPPseudoHeader.sizeof - 1; i += 2) {
        ushort word = (cast(ushort)pseudoBytes[i] << 8) | pseudoBytes[i + 1];
        sum += word;
    }
    
    // Sum TCP data
    for (size_t i = 0; i < tcpLen - 1; i += 2) {
        ushort word = (cast(ushort)tcpData[i] << 8) | tcpData[i + 1];
        sum += word;
    }
    
    // Add odd byte if present
    if (tcpLen & 1) {
        sum += cast(ushort)tcpData[tcpLen - 1] << 8;
    }
    
    // Fold to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return cast(ushort)~sum;
}

/// Create TCP socket
export extern(C) int tcpSocket() @nogc nothrow {
    if (g_tcpConnectionCount >= g_tcpConnections.length) {
        return -1;
    }
    
    int sockfd = cast(int)g_tcpConnectionCount;
    g_tcpConnections[sockfd].state = TCPState.CLOSED;
    g_tcpConnections[sockfd].active = true;
    g_tcpConnections[sockfd].sendBufferLen = 0;
    g_tcpConnections[sockfd].recvBufferLen = 0;
    g_tcpConnections[sockfd].recvWindow = 4096;
    g_tcpConnections[sockfd].onConnect = null;
    g_tcpConnections[sockfd].onData = null;
    g_tcpConnections[sockfd].onClose = null;
    g_tcpConnectionCount++;
    
    return sockfd;
}

/// Bind TCP socket to port
export extern(C) bool tcpBind(int sockfd, ushort port) @nogc nothrow {
    if (sockfd < 0 || sockfd >= g_tcpConnectionCount) return false;
    
    // Check if port already in use
    for (size_t i = 0; i < g_tcpConnectionCount; i++) {
        if (g_tcpConnections[i].active && 
            g_tcpConnections[i].localPort == port &&
            g_tcpConnections[i].state != TCPState.CLOSED) {
            return false;
        }
    }
    
    g_tcpConnections[sockfd].localPort = port;
    return true;
}

/// Listen for connections
export extern(C) bool tcpListen(int sockfd) @nogc nothrow {
    if (sockfd < 0 || sockfd >= g_tcpConnectionCount) return false;
    
    g_tcpConnections[sockfd].state = TCPState.LISTEN;
    return true;
}

/// Connect to remote host
export extern(C) bool tcpConnect(int sockfd,
                                  const ref IPv4Address remoteIP,
                                  ushort remotePort) @nogc nothrow {
    if (sockfd < 0 || sockfd >= g_tcpConnectionCount) return false;
    
    TCPConnection* conn = &g_tcpConnections[sockfd];
    conn.remoteIP = remoteIP;
    conn.remotePort = remotePort;
    conn.sendSeq = g_initialSeqNum++;
    conn.state = TCPState.SYN_SENT;
    
    // Send SYN packet
    return tcpSendPacket(sockfd, TCPFlags.SYN, null, 0);
}

/// Send TCP packet
private bool tcpSendPacket(int sockfd, ubyte flags,
                           const(ubyte)* data, size_t dataLen) @nogc nothrow {
    if (sockfd < 0 || sockfd >= g_tcpConnectionCount) return false;
    
    TCPConnection* conn = &g_tcpConnections[sockfd];
    
    enum MAX_TCP_SIZE = 1460;  // MTU 1500 - IP header (20) - TCP header (20)
    ubyte[MAX_TCP_SIZE + TCPHeader.sizeof] buffer;
    
    size_t packetSize = TCPHeader.sizeof + dataLen;
    if (packetSize > buffer.length) return false;
    
    // Build TCP header
    TCPHeader* header = cast(TCPHeader*)buffer.ptr;
    header.srcPort = htons(conn.localPort);
    header.destPort = htons(conn.remotePort);
    header.sequenceNum = htonl(conn.sendSeq);
    header.ackNum = htonl(conn.sendAck);
    header.dataOffsetFlags = 0x50;  // Data offset = 5 (20 bytes), no flags in this field
    header.flags = flags;
    header.windowSize = htons(conn.recvWindow);
    header.checksum = 0;
    header.urgentPointer = 0;
    
    // Copy data
    if (data !is null && dataLen > 0) {
        ubyte* payload = buffer.ptr + TCPHeader.sizeof;
        for (size_t i = 0; i < dataLen; i++) {
            payload[i] = data[i];
        }
    }
    
    // Calculate checksum
    IPv4Address localIP;
    getLocalIP(&localIP);
    header.checksum = tcpChecksum(localIP, conn.remoteIP, buffer.ptr, packetSize);
    
    // Update sequence number if sending data or SYN/FIN
    if (dataLen > 0 || (flags & (TCPFlags.SYN | TCPFlags.FIN))) {
        conn.sendSeq += dataLen > 0 ? cast(uint)dataLen : 1;
    }
    
    // Send via IPv4
    return ipv4Send(conn.remoteIP, IPProtocol.TCP, buffer.ptr, packetSize);
}

/// Send data on TCP connection
export extern(C) int tcpSend(int sockfd, const(ubyte)* data, size_t len) @nogc nothrow {
    if (sockfd < 0 || sockfd >= g_tcpConnectionCount) return -1;
    
    TCPConnection* conn = &g_tcpConnections[sockfd];
    
    if (conn.state != TCPState.ESTABLISHED) return -1;
    if (data is null || len == 0) return 0;
    
    // Send with PSH and ACK flags
    if (tcpSendPacket(sockfd, TCPFlags.PSH | TCPFlags.ACK, data, len)) {
        return cast(int)len;
    }
    
    return -1;
}

/// Handle received TCP packet
export extern(C) void tcpHandlePacket(const(ubyte)* data, size_t len,
                                       const ref IPv4Address srcIP) @nogc nothrow {
    if (data is null || len < TCPHeader.sizeof) return;
    
    const TCPHeader* header = cast(const TCPHeader*)data;
    
    ushort srcPort = ntohs(header.srcPort);
    ushort destPort = ntohs(header.destPort);
    uint seqNum = ntohl(header.sequenceNum);
    uint ackNum = ntohl(header.ackNum);
    ubyte flags = header.flags;
    ushort windowSize = ntohs(header.windowSize);
    
    // Find matching connection
    int sockfd = -1;
    for (size_t i = 0; i < g_tcpConnectionCount; i++) {
        TCPConnection* conn = &g_tcpConnections[i];
        if (!conn.active) continue;
        
        // Match by ports and IP
        if (conn.localPort == destPort) {
            if (conn.state == TCPState.LISTEN ||
                (conn.remotePort == srcPort && conn.remoteIP.isEqual(srcIP))) {
                sockfd = cast(int)i;
                break;
            }
        }
    }
    
    if (sockfd < 0) return;
    
    TCPConnection* conn = &g_tcpConnections[sockfd];
    
    // State machine
    switch (conn.state) {
        case TCPState.LISTEN:
            if (flags & TCPFlags.SYN) {
                // Incoming connection
                conn.remoteIP = srcIP;
                conn.remotePort = srcPort;
                conn.recvSeq = seqNum + 1;
                conn.sendAck = conn.recvSeq;
                conn.sendSeq = g_initialSeqNum++;
                conn.sendWindow = windowSize;
                conn.state = TCPState.SYN_RECEIVED;
                
                // Send SYN-ACK
                tcpSendPacket(sockfd, TCPFlags.SYN | TCPFlags.ACK, null, 0);
            }
            break;
            
        case TCPState.SYN_SENT:
            if ((flags & (TCPFlags.SYN | TCPFlags.ACK)) == (TCPFlags.SYN | TCPFlags.ACK)) {
                // SYN-ACK received
                conn.recvSeq = seqNum + 1;
                conn.sendAck = conn.recvSeq;
                conn.sendWindow = windowSize;
                conn.state = TCPState.ESTABLISHED;
                
                // Send ACK
                tcpSendPacket(sockfd, TCPFlags.ACK, null, 0);
                
                // Notify connection established
                if (conn.onConnect !is null) {
                    conn.onConnect(sockfd);
                }
            }
            break;
            
        case TCPState.SYN_RECEIVED:
            if (flags & TCPFlags.ACK) {
                // Connection established
                conn.state = TCPState.ESTABLISHED;
                
                if (conn.onConnect !is null) {
                    conn.onConnect(sockfd);
                }
            }
            break;
            
        case TCPState.ESTABLISHED:
            // Extract payload
            ubyte dataOffset = (header.dataOffsetFlags >> 4) * 4;
            const(ubyte)* payload = data + dataOffset;
            size_t payloadLen = len - dataOffset;
            
            if (payloadLen > 0) {
                // Update receive sequence
                conn.recvSeq = seqNum + cast(uint)payloadLen;
                conn.sendAck = conn.recvSeq;
                
                // Deliver data
                if (conn.onData !is null) {
                    conn.onData(sockfd, payload, payloadLen);
                }
                
                // Send ACK
                tcpSendPacket(sockfd, TCPFlags.ACK, null, 0);
            }
            
            if (flags & TCPFlags.FIN) {
                // Remote is closing
                conn.recvSeq++;
                conn.sendAck = conn.recvSeq;
                conn.state = TCPState.CLOSE_WAIT;
                
                // Send ACK
                tcpSendPacket(sockfd, TCPFlags.ACK, null, 0);
                
                // Notify close
                if (conn.onClose !is null) {
                    conn.onClose(sockfd);
                }
            }
            break;
            
        case TCPState.FIN_WAIT_1:
            if (flags & TCPFlags.ACK) {
                conn.state = TCPState.FIN_WAIT_2;
            }
            if (flags & TCPFlags.FIN) {
                conn.recvSeq++;
                conn.sendAck = conn.recvSeq;
                tcpSendPacket(sockfd, TCPFlags.ACK, null, 0);
                conn.state = TCPState.TIME_WAIT;
            }
            break;
            
        case TCPState.FIN_WAIT_2:
            if (flags & TCPFlags.FIN) {
                conn.recvSeq++;
                conn.sendAck = conn.recvSeq;
                tcpSendPacket(sockfd, TCPFlags.ACK, null, 0);
                conn.state = TCPState.TIME_WAIT;
            }
            break;
            
        case TCPState.CLOSE_WAIT:
            // Waiting for application to close
            break;
            
        default:
            break;
    }
}

/// Close TCP connection
export extern(C) void tcpClose(int sockfd) @nogc nothrow {
    if (sockfd < 0 || sockfd >= g_tcpConnectionCount) return;
    
    TCPConnection* conn = &g_tcpConnections[sockfd];
    
    if (conn.state == TCPState.ESTABLISHED || conn.state == TCPState.CLOSE_WAIT) {
        // Send FIN
        tcpSendPacket(sockfd, TCPFlags.FIN | TCPFlags.ACK, null, 0);
        conn.state = TCPState.FIN_WAIT_1;
    } else {
        conn.state = TCPState.CLOSED;
        conn.active = false;
    }
}

/// Set TCP callbacks
export extern(C) void tcpSetCallbacks(int sockfd,
                                       TCPConnectCallback onConnect,
                                       TCPDataCallback onData,
                                       TCPCloseCallback onClose) @nogc nothrow {
    if (sockfd < 0 || sockfd >= g_tcpConnectionCount) return;
    
    g_tcpConnections[sockfd].onConnect = onConnect;
    g_tcpConnections[sockfd].onData = onData;
    g_tcpConnections[sockfd].onClose = onClose;
}
