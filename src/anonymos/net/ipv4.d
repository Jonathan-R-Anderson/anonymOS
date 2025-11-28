module anonymos.net.ipv4;

import anonymos.net.types;
import anonymos.net.ethernet;
import anonymos.net.arp;

/// IPv4 header
struct IPv4Header {
    ubyte versionIHL;       // Version (4 bits) + IHL (4 bits)
    ubyte tos;              // Type of Service
    ushort totalLength;     // Total length (header + data)
    ushort identification;  // Identification
    ushort flagsFragment;   // Flags (3 bits) + Fragment offset (13 bits)
    ubyte ttl;              // Time to Live
    ubyte protocol;         // Protocol (TCP, UDP, ICMP, etc.)
    ushort headerChecksum;  // Header checksum
    IPv4Address srcIP;      // Source IP
    IPv4Address destIP;     // Destination IP
}

private __gshared IPv4Address g_localIP;
private __gshared IPv4Address g_gateway;
private __gshared IPv4Address g_netmask;
private __gshared ushort g_nextIdentification = 1;

/// Initialize IPv4 layer
export extern(C) void initIPv4(const IPv4Address* localIP,
                                const IPv4Address* gateway,
                                const IPv4Address* netmask) @nogc nothrow {
    if (localIP !is null) g_localIP = *localIP;
    if (gateway !is null) g_gateway = *gateway;
    if (netmask !is null) g_netmask = *netmask;
    
    // Initialize ARP with our IP
    initARP(&g_localIP);
}

/// Calculate IP checksum
export extern(C) ushort ipChecksum(const(ubyte)* data, size_t length) @nogc nothrow {
    uint sum = 0;
    
    // Sum 16-bit words
    for (size_t i = 0; i < length - 1; i += 2) {
        ushort word = (cast(ushort)data[i] << 8) | data[i + 1];
        sum += word;
    }
    
    // Add odd byte if present
    if (length & 1) {
        sum += cast(ushort)data[length - 1] << 8;
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return cast(ushort)~sum;
}

/// Send IPv4 packet
export extern(C) bool ipv4Send(const ref IPv4Address destIP,
                                ubyte protocol,
                                const(ubyte)* payload,
                                size_t payloadLen) @nogc nothrow {
    if (payload is null || payloadLen == 0) return false;
    
    // Allocate buffer
    enum MAX_PACKET_SIZE = 1500;
    ubyte[MAX_PACKET_SIZE] packetBuffer;
    
    size_t packetSize = IPv4Header.sizeof + payloadLen;
    if (packetSize > MAX_PACKET_SIZE) return false;
    
    // Build IPv4 header
    IPv4Header* header = cast(IPv4Header*)packetBuffer.ptr;
    header.versionIHL = 0x45;  // Version 4, IHL 5 (20 bytes)
    header.tos = 0;
    header.totalLength = htons(cast(ushort)packetSize);
    header.identification = htons(g_nextIdentification++);
    header.flagsFragment = 0;  // Don't fragment
    header.ttl = 64;
    header.protocol = protocol;
    header.headerChecksum = 0;  // Calculate later
    header.srcIP = g_localIP;
    header.destIP = destIP;
    
    // Calculate checksum
    header.headerChecksum = ipChecksum(cast(ubyte*)header, IPv4Header.sizeof);
    
    // Copy payload
    ubyte* payloadPtr = packetBuffer.ptr + IPv4Header.sizeof;
    for (size_t i = 0; i < payloadLen; i++) {
        payloadPtr[i] = payload[i];
    }
    
    // Resolve destination MAC
    MACAddress destMac;
    
    // Check if destination is on local network
    bool isLocal = true;
    for (int i = 0; i < 4; i++) {
        if ((destIP.bytes[i] & g_netmask.bytes[i]) != 
            (g_localIP.bytes[i] & g_netmask.bytes[i])) {
            isLocal = false;
            break;
        }
    }
    
    // Use gateway if not local
    IPv4Address targetIP = isLocal ? destIP : g_gateway;
    
    // Resolve MAC address
    if (!arpResolve(targetIP, &destMac, 1000)) {
        return false;  // ARP resolution failed
    }
    
    // Send as Ethernet frame
    return sendEthernetFrame(destMac, EtherType.IPv4,
                             packetBuffer.ptr, packetSize);
}

/// IPv4 protocol handler callback
alias IPv4ProtocolHandler = extern(C) void function(ubyte, const(ubyte)*, size_t, const ref IPv4Address) @nogc nothrow;

/// Handle received IPv4 packet
export extern(C) void ipv4HandlePacket(const(ubyte)* data, size_t len,
                                        IPv4ProtocolHandler callback) @nogc nothrow {
    if (data is null || len < IPv4Header.sizeof) return;
    
    const IPv4Header* header = cast(const IPv4Header*)data;
    
    // Verify version
    if ((header.versionIHL >> 4) != 4) return;
    
    // Get header length
    ubyte ihl = header.versionIHL & 0x0F;
    size_t headerLen = ihl * 4;
    
    if (len < headerLen) return;
    
    // Verify checksum
    ushort receivedChecksum = header.headerChecksum;
    IPv4Header* mutableHeader = cast(IPv4Header*)data;
    mutableHeader.headerChecksum = 0;
    ushort calculatedChecksum = ipChecksum(data, headerLen);
    mutableHeader.headerChecksum = receivedChecksum;
    
    if (receivedChecksum != calculatedChecksum) return;
    
    // Check if packet is for us
    if (!header.destIP.isEqual(g_localIP) && !header.destIP.isBroadcast()) {
        return;
    }
    
    // Extract payload
    const(ubyte)* payload = data + headerLen;
    size_t payloadLen = ntohs(header.totalLength) - headerLen;
    
    // Call protocol handler
    if (callback !is null) {
        callback(header.protocol, payload, payloadLen, header.srcIP);
    }
}

/// Get local IP address
export extern(C) void getLocalIP(IPv4Address* outIP) @nogc nothrow {
    if (outIP !is null) {
        *outIP = g_localIP;
    }
}

/// Set local IP address
export extern(C) void setLocalIPAddress(const IPv4Address* ip) @nogc nothrow {
    if (ip !is null) {
        g_localIP = *ip;
        setLocalIP(ip);  // Update ARP
    }
}

/// Set gateway
export extern(C) void setGateway(const IPv4Address* gateway) @nogc nothrow {
    if (gateway !is null) {
        g_gateway = *gateway;
    }
}

/// Set netmask
export extern(C) void setNetmask(const IPv4Address* netmask) @nogc nothrow {
    if (netmask !is null) {
        g_netmask = *netmask;
    }
}
