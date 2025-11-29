module anonymos.net.icmpv6;

import anonymos.net.types;
import anonymos.net.ipv6;

/// ICMPv6 Message Types
enum ICMPv6Type : ubyte {
    EchoRequest = 128,
    EchoReply = 129,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
}

/// ICMPv6 Header
struct ICMPv6Header {
    ubyte type;
    ubyte code;
    ushort checksum;
}

/// Handle incoming ICMPv6 packet
export extern(C) void icmpv6HandlePacket(const(ubyte)* data, size_t len,
                                         const ref IPv6Address srcIP) @nogc nothrow {
    if (data is null || len < ICMPv6Header.sizeof) return;

    const ICMPv6Header* header = cast(const ICMPv6Header*)data;

    switch (header.type) {
        case ICMPv6Type.EchoRequest:
            // TODO: Send Echo Reply
            // For now, just acknowledge receipt in logic
            break;
            
        case ICMPv6Type.NeighborSolicitation:
            // TODO: Handle NDP
            break;
            
        default:
            break;
    }
}
