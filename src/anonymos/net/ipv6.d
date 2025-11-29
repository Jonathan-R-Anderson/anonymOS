module anonymos.net.ipv6;

import anonymos.net.types;
import anonymos.net.ethernet;

/// IPv6 Header
struct IPv6Header {
    uint vtf;           // Version (4), Traffic Class (8), Flow Label (20)
    ushort payloadLen;  // Payload length
    ubyte nextHeader;   // Next header (protocol)
    ubyte hopLimit;     // Hop limit
    IPv6Address srcIP;  // Source IP
    IPv6Address destIP; // Destination IP
}

private __gshared IPv6Address g_localIPv6;
private __gshared bool g_ipv6Initialized = false;

/// Initialize IPv6 layer
export extern(C) void initIPv6(const IPv6Address* localIP) @nogc nothrow {
    if (localIP !is null) {
        g_localIPv6 = *localIP;
    } else {
        // Default to loopback ::1 if not specified
        g_localIPv6 = IPv6Address(0, 0, 0, 0, 0, 0, 0, 1);
    }
    g_ipv6Initialized = true;
}

/// Handle incoming IPv6 packet
export extern(C) void ipv6HandlePacket(ubyte* packet, size_t length,
                                       void function(ubyte, const(ubyte)*, size_t, const ref IPv6Address) @nogc nothrow protocolHandler) @nogc nothrow {
    if (packet is null || length < IPv6Header.sizeof) return;

    IPv6Header* header = cast(IPv6Header*)packet;
    
    // Check version (must be 6)
    // vtf is in network byte order. Version is top 4 bits of first byte.
    // We can just check the first byte directly.
    ubyte ver = (packet[0] >> 4) & 0x0F;
    if (ver != 6) return;

    // We should check if the packet is for us, but for now let's be promiscuous or assume ethernet filtering did its job.
    // Ideally: if (!header.destIP.isEqual(g_localIPv6) && !header.destIP.isMulticast()) return;

    size_t payloadLength = ntohs(header.payloadLen);
    
    // Safety check on length
    if (IPv6Header.sizeof + payloadLength > length) {
        // Packet truncated or malformed
        return;
    }

    ubyte* payload = packet + IPv6Header.sizeof;
    
    // Dispatch to protocol handler
    if (protocolHandler !is null) {
        protocolHandler(header.nextHeader, payload, payloadLength, header.srcIP);
    }
}

/// Send IPv6 packet (Placeholder)
export extern(C) bool ipv6SendPacket(const ref IPv6Address destIP,
                                     ubyte nextHeader,
                                     const(ubyte)* payload,
                                     size_t payloadLen) @nogc nothrow {
    // TODO: Implement IPv6 sending
    // 1. Resolve MAC address (NDP cache lookup)
    // 2. Construct IPv6 header
    // 3. Send via Ethernet
    return false;
}
