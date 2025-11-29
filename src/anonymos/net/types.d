module anonymos.net.types;

/// Network byte order conversion
@nogc nothrow {
    ushort htons(ushort hostshort) {
        return cast(ushort)((hostshort >> 8) | (hostshort << 8));
    }

    uint htonl(uint hostlong) {
        return ((hostlong >> 24) & 0x000000FF) |
               ((hostlong >> 8)  & 0x0000FF00) |
               ((hostlong << 8)  & 0x00FF0000) |
               ((hostlong << 24) & 0xFF000000);
    }

    ushort ntohs(ushort netshort) {
        return htons(netshort);
    }

    uint ntohl(uint netlong) {
        return htonl(netlong);
    }
}

/// IPv4 address
struct IPv4Address {
    union {
        ubyte[4] bytes;
        uint addr;
    }

    this(ubyte a, ubyte b, ubyte c, ubyte d) @nogc nothrow {
        bytes[0] = a;
        bytes[1] = b;
        bytes[2] = c;
        bytes[3] = d;
    }

    this(uint address) @nogc nothrow {
        addr = address;
    }

    bool isEqual(const ref IPv4Address other) const @nogc nothrow {
        return addr == other.addr;
    }

    bool isBroadcast() const @nogc nothrow {
        return addr == 0xFFFFFFFF;
    }

    bool isMulticast() const @nogc nothrow {
        return (bytes[0] & 0xF0) == 0xE0;
    }
}

/// IPv6 address
struct IPv6Address {
    union {
        ubyte[16] bytes;
        ushort[8] words;
        uint[4] dwords;
    }

    this(const(ubyte)* data) @nogc nothrow {
        for (int i = 0; i < 16; i++) {
            bytes[i] = data[i];
        }
    }

    this(ushort w0, ushort w1, ushort w2, ushort w3,
         ushort w4, ushort w5, ushort w6, ushort w7) @nogc nothrow {
        words[0] = htons(w0);
        words[1] = htons(w1);
        words[2] = htons(w2);
        words[3] = htons(w3);
        words[4] = htons(w4);
        words[5] = htons(w5);
        words[6] = htons(w6);
        words[7] = htons(w7);
    }

    bool isEqual(const ref IPv6Address other) const @nogc nothrow {
        for (int i = 0; i < 16; i++) {
            if (bytes[i] != other.bytes[i]) return false;
        }
        return true;
    }

    bool isLinkLocal() const @nogc nothrow {
        return bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80;
    }

    bool isMulticast() const @nogc nothrow {
        return bytes[0] == 0xFF;
    }
    
    bool isLoopback() const @nogc nothrow {
        for (int i = 0; i < 15; i++) {
            if (bytes[i] != 0) return false;
        }
        return bytes[15] == 1;
    }
}

/// MAC address
struct MACAddress {
    ubyte[6] bytes;

    this(ubyte a, ubyte b, ubyte c, ubyte d, ubyte e, ubyte f) @nogc nothrow {
        bytes[0] = a;
        bytes[1] = b;
        bytes[2] = c;
        bytes[3] = d;
        bytes[4] = e;
        bytes[5] = f;
    }

    bool isEqual(const ref MACAddress other) const @nogc nothrow {
        for (int i = 0; i < 6; i++) {
            if (bytes[i] != other.bytes[i]) return false;
        }
        return true;
    }

    bool isBroadcast() const @nogc nothrow {
        for (int i = 0; i < 6; i++) {
            if (bytes[i] != 0xFF) return false;
        }
        return true;
    }
}

/// Protocol numbers
enum IPProtocol : ubyte {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    IPv6ICMP = 58,
}

/// Ethernet types
enum EtherType : ushort {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
}

/// TCP flags
enum TCPFlags : ubyte {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
}

/// TCP state
enum TCPState {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
}

/// Network buffer
struct NetBuffer {
    ubyte* data;
    size_t length;
    size_t capacity;
    size_t offset;

    @nogc nothrow {
        void reset() {
            offset = 0;
        }

        ubyte* current() {
            return data + offset;
        }

        size_t remaining() const {
            return length - offset;
        }

        void advance(size_t bytes) {
            offset += bytes;
            if (offset > length) offset = length;
        }
    }
}
