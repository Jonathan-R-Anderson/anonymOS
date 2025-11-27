module anonymos.net.icmp;

import anonymos.net.types;
import anonymos.net.ipv4;

/// ICMP types
enum ICMPType : ubyte {
    ECHO_REPLY = 0,
    DEST_UNREACHABLE = 3,
    ECHO_REQUEST = 8,
    TIME_EXCEEDED = 11,
}

/// ICMP header
struct ICMPHeader {
    ubyte type;
    ubyte code;
    ushort checksum;
    ushort identifier;
    ushort sequence;
}

/// Send ICMP echo request (ping)
export extern(C) bool icmpSendPing(const ref IPv4Address destIP,
                                    ushort identifier,
                                    ushort sequence,
                                    const(ubyte)* data,
                                    size_t dataLen) @nogc nothrow {
    enum MAX_ICMP_SIZE = 1024;
    ubyte[MAX_ICMP_SIZE] buffer;
    
    size_t packetSize = ICMPHeader.sizeof + dataLen;
    if (packetSize > MAX_ICMP_SIZE) return false;
    
    // Build ICMP header
    ICMPHeader* header = cast(ICMPHeader*)buffer.ptr;
    header.type = ICMPType.ECHO_REQUEST;
    header.code = 0;
    header.checksum = 0;
    header.identifier = htons(identifier);
    header.sequence = htons(sequence);
    
    // Copy data
    if (data !is null && dataLen > 0) {
        ubyte* payload = buffer.ptr + ICMPHeader.sizeof;
        for (size_t i = 0; i < dataLen; i++) {
            payload[i] = data[i];
        }
    }
    
    // Calculate checksum
    header.checksum = ipChecksum(buffer.ptr, packetSize);
    
    // Send via IPv4
    return ipv4Send(destIP, IPProtocol.ICMP, buffer.ptr, packetSize);
}

/// Send ICMP echo reply (pong)
export extern(C) bool icmpSendPong(const ref IPv4Address destIP,
                                    ushort identifier,
                                    ushort sequence,
                                    const(ubyte)* data,
                                    size_t dataLen) @nogc nothrow {
    enum MAX_ICMP_SIZE = 1024;
    ubyte[MAX_ICMP_SIZE] buffer;
    
    size_t packetSize = ICMPHeader.sizeof + dataLen;
    if (packetSize > MAX_ICMP_SIZE) return false;
    
    // Build ICMP header
    ICMPHeader* header = cast(ICMPHeader*)buffer.ptr;
    header.type = ICMPType.ECHO_REPLY;
    header.code = 0;
    header.checksum = 0;
    header.identifier = htons(identifier);
    header.sequence = htons(sequence);
    
    // Copy data
    if (data !is null && dataLen > 0) {
        ubyte* payload = buffer.ptr + ICMPHeader.sizeof;
        for (size_t i = 0; i < dataLen; i++) {
            payload[i] = data[i];
        }
    }
    
    // Calculate checksum
    header.checksum = ipChecksum(buffer.ptr, packetSize);
    
    // Send via IPv4
    return ipv4Send(destIP, IPProtocol.ICMP, buffer.ptr, packetSize);
}

/// Handle received ICMP packet
export extern(C) void icmpHandlePacket(const(ubyte)* data, size_t len,
                                        const ref IPv4Address srcIP) @nogc nothrow {
    if (data is null || len < ICMPHeader.sizeof) return;
    
    const ICMPHeader* header = cast(const ICMPHeader*)data;
    
    // Verify checksum
    ushort receivedChecksum = header.checksum;
    ICMPHeader* mutableHeader = cast(ICMPHeader*)data;
    mutableHeader.checksum = 0;
    ushort calculatedChecksum = ipChecksum(data, len);
    mutableHeader.checksum = receivedChecksum;
    
    if (receivedChecksum != calculatedChecksum) return;
    
    // Handle different ICMP types
    if (header.type == ICMPType.ECHO_REQUEST) {
        // Respond to ping
        const(ubyte)* payload = data + ICMPHeader.sizeof;
        size_t payloadLen = len - ICMPHeader.sizeof;
        
        ushort identifier = ntohs(header.identifier);
        ushort sequence = ntohs(header.sequence);
        
        icmpSendPong(srcIP, identifier, sequence, payload, payloadLen);
    }
    else if (header.type == ICMPType.ECHO_REPLY) {
        // Ping reply received
        // TODO: Notify waiting ping request
    }
}
