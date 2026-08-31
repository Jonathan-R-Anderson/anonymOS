module network.icmp;

import network.types;
import network.ipv4;

/// ICMP types
enum ICMPType : ubyte {
    ECHO_REPLY = 0,
    DEST_UNREACHABLE = 3,
    ECHO_REQUEST = 8,
    TIME_EXCEEDED = 11,
}

/// ICMP header
struct ICMPHeader {
    align(1):               // wire struct — pack
    ubyte type;
    ubyte code;
    ushort checksum;
    ushort identifier;
    ushort sequence;
}

// N2: count ICMP echo replies received, so a ping can be verified end-to-end.
private __gshared ulong g_icmpEchoReplies = 0;
export extern(C) ulong getIcmpEchoReplies() @nogc nothrow { return g_icmpEchoReplies; }

// Raw-socket tap.  busybox `ping` opens socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) and reads
// replies off that fd, so every ICMP packet has to be visible to userspace and not just to
// the in-kernel handler below.  posix.d registers the tap; it is called for EVERY ICMP
// packet, including echo requests, which is what a raw socket is supposed to see.
//
// The tap runs BEFORE the checksum test on purpose: a raw socket is a wire tap, and Linux
// hands the packet up regardless.  It also runs before the auto-pong, so the in-kernel
// responder keeps working exactly as before whether or not anyone is listening.
alias IcmpRawTap = extern(C) void function(const(ubyte)* data, size_t len,
                                           const ref IPv4Address srcIP) @nogc nothrow;
private __gshared IcmpRawTap g_icmpRawTap = null;
export extern(C) void icmpSetRawTap(IcmpRawTap tap) @nogc nothrow { g_icmpRawTap = tap; }

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
    header.checksum = htons(ipChecksum(buffer.ptr, packetSize));   // network byte order
    
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
    header.checksum = htons(ipChecksum(buffer.ptr, packetSize));   // network byte order
    
    // Send via IPv4
    return ipv4Send(destIP, IPProtocol.ICMP, buffer.ptr, packetSize);
}

/// Handle received ICMP packet
export extern(C) void icmpHandlePacket(const(ubyte)* data, size_t len,
                                        const ref IPv4Address srcIP) @nogc nothrow {
    if (data is null || len < ICMPHeader.sizeof) return;

    // Wire tap first (see icmpSetRawTap): raw sockets must see the packet even if the
    // checksum test below rejects it or the type is one we do not act on.
    if (g_icmpRawTap !is null) g_icmpRawTap(data, len, srcIP);

    const ICMPHeader* header = cast(const ICMPHeader*)data;

    // Verify checksum
    ushort receivedChecksum = header.checksum;
    ICMPHeader* mutableHeader = cast(ICMPHeader*)data;
    mutableHeader.checksum = 0;
    ushort calculatedChecksum = htons(ipChecksum(data, len));      // match the on-wire order
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
        // Ping reply received — record it so a ping can be verified end-to-end.
        ++g_icmpEchoReplies;
    }
}
