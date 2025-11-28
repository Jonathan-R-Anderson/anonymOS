module anonymos.net.arp;

import anonymos.net.types;
import anonymos.net.ethernet;

/// ARP operation codes
enum ARPOperation : ushort {
    REQUEST = 1,
    REPLY = 2,
}

/// ARP packet (for Ethernet/IPv4)
struct ARPPacket {
    ushort hardwareType;    // 1 for Ethernet
    ushort protocolType;    // 0x0800 for IPv4
    ubyte hardwareSize;     // 6 for MAC
    ubyte protocolSize;     // 4 for IPv4
    ushort operation;       // Request or Reply
    MACAddress senderMac;
    IPv4Address senderIP;
    MACAddress targetMac;
    IPv4Address targetIP;
}

/// ARP cache entry
struct ARPCacheEntry {
    IPv4Address ip;
    MACAddress mac;
    ulong timestamp;
    bool valid;
}

private __gshared ARPCacheEntry[256] g_arpCache;
private __gshared size_t g_arpCacheSize = 0;
private __gshared IPv4Address g_localIP;

/// Initialize ARP
export extern(C) void initARP(const IPv4Address* localIP) @nogc nothrow {
    if (localIP !is null) {
        g_localIP = *localIP;
    }
    g_arpCacheSize = 0;
}

/// Set local IP address
export extern(C) void setLocalIP(const IPv4Address* ip) @nogc nothrow {
    if (ip !is null) {
        g_localIP = *ip;
    }
}

/// Lookup MAC address in ARP cache
export extern(C) bool arpLookup(const ref IPv4Address ip, MACAddress* outMac) @nogc nothrow {
    if (outMac is null) return false;
    
    for (size_t i = 0; i < g_arpCacheSize; i++) {
        if (g_arpCache[i].valid && g_arpCache[i].ip.isEqual(ip)) {
            *outMac = g_arpCache[i].mac;
            return true;
        }
    }
    
    return false;
}

/// Add entry to ARP cache
export extern(C) void arpCacheAdd(const ref IPv4Address ip, const ref MACAddress mac) @nogc nothrow {
    // Check if already exists
    for (size_t i = 0; i < g_arpCacheSize; i++) {
        if (g_arpCache[i].valid && g_arpCache[i].ip.isEqual(ip)) {
            g_arpCache[i].mac = mac;
            // Update timestamp (use RDTSC)
            ulong tsc;
            asm @nogc nothrow {
                rdtsc;
                shl RDX, 32;
                or RAX, RDX;
                mov tsc, RAX;
            }
            g_arpCache[i].timestamp = tsc;
            return;
        }
    }
    
    // Add new entry
    if (g_arpCacheSize < g_arpCache.length) {
        g_arpCache[g_arpCacheSize].ip = ip;
        g_arpCache[g_arpCacheSize].mac = mac;
        g_arpCache[g_arpCacheSize].valid = true;
        
        ulong tsc;
        asm @nogc nothrow {
            rdtsc;
            shl RDX, 32;
            or RAX, RDX;
            mov tsc, RAX;
        }
        g_arpCache[g_arpCacheSize].timestamp = tsc;
        
        g_arpCacheSize++;
    }
}

/// Send ARP request
export extern(C) bool arpSendRequest(const ref IPv4Address targetIP) @nogc nothrow {
    ARPPacket packet;
    
    // Fill in ARP packet
    packet.hardwareType = htons(1);  // Ethernet
    packet.protocolType = htons(0x0800);  // IPv4
    packet.hardwareSize = 6;
    packet.protocolSize = 4;
    packet.operation = htons(cast(ushort)ARPOperation.REQUEST);
    
    // Sender info
    getLocalMac(&packet.senderMac);
    packet.senderIP = g_localIP;
    
    // Target info (MAC unknown, that's what we're asking for)
    packet.targetMac = MACAddress(0, 0, 0, 0, 0, 0);
    packet.targetIP = targetIP;
    
    // Send as Ethernet frame
    MACAddress broadcast = MACAddress(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    return sendEthernetFrame(broadcast, EtherType.ARP, 
                             cast(ubyte*)&packet, ARPPacket.sizeof);
}

/// Send ARP reply
export extern(C) bool arpSendReply(const ref IPv4Address targetIP, 
                                    const ref MACAddress targetMac) @nogc nothrow {
    ARPPacket packet;
    
    packet.hardwareType = htons(1);
    packet.protocolType = htons(0x0800);
    packet.hardwareSize = 6;
    packet.protocolSize = 4;
    packet.operation = htons(cast(ushort)ARPOperation.REPLY);
    
    getLocalMac(&packet.senderMac);
    packet.senderIP = g_localIP;
    packet.targetMac = targetMac;
    packet.targetIP = targetIP;
    
    return sendEthernetFrame(targetMac, EtherType.ARP,
                             cast(ubyte*)&packet, ARPPacket.sizeof);
}

/// Handle received ARP packet
export extern(C) void arpHandlePacket(const(ubyte)* data, size_t len) @nogc nothrow {
    if (data is null || len < ARPPacket.sizeof) return;
    
    const ARPPacket* packet = cast(const ARPPacket*)data;
    
    // Convert to host byte order
    ushort operation = ntohs(packet.operation);
    
    // Add sender to cache
    arpCacheAdd(packet.senderIP, packet.senderMac);
    
    // Check if this is for us
    if (!packet.targetIP.isEqual(g_localIP)) return;
    
    if (operation == ARPOperation.REQUEST) {
        // Send reply
        arpSendReply(packet.senderIP, packet.senderMac);
    }
    // If it's a reply, we already added it to cache above
}

/// Resolve IP to MAC (blocking with timeout)
export extern(C) bool arpResolve(const ref IPv4Address ip, MACAddress* outMac, 
                                  uint timeoutMs) @nogc nothrow {
    if (outMac is null) return false;
    
    // Check cache first
    if (arpLookup(ip, outMac)) {
        return true;
    }
    
    // Send ARP request
    if (!arpSendRequest(ip)) {
        return false;
    }
    
    // Wait for reply (simplified - should integrate with event loop)
    uint attempts = timeoutMs / 10;
    for (uint i = 0; i < attempts; i++) {
        // Check cache again
        if (arpLookup(ip, outMac)) {
            return true;
        }
        
        // Busy wait ~10ms
        for (uint j = 0; j < 1000000; j++) {
            asm @nogc nothrow { nop; }
        }
    }
    
    return false;
}
