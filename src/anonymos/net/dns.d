module anonymos.net.dns;

import anonymos.net.types;
import anonymos.net.udp;
import anonymos.net.stack;

/// DNS header
struct DNSHeader {
    ushort id;              // Transaction ID
    ushort flags;           // Flags
    ushort qdcount;         // Question count
    ushort ancount;         // Answer count
    ushort nscount;         // Authority count
    ushort arcount;         // Additional count
}

/// DNS query flags
enum DNSFlags : ushort {
    QUERY = 0x0000,
    RESPONSE = 0x8000,
    RECURSION_DESIRED = 0x0100,
}

/// DNS record type
enum DNSType : ushort {
    A = 1,      // IPv4 address
    NS = 2,     // Name server
    CNAME = 5,  // Canonical name
    MX = 15,    // Mail exchange
    AAAA = 28,  // IPv6 address
}

/// DNS class
enum DNSClass : ushort {
    IN = 1,     // Internet
}

/// DNS cache entry
struct DNSCacheEntry {
    char[256] hostname;
    IPv4Address ip;
    ulong timestamp;
    uint ttl;
    bool valid;
}

private __gshared DNSCacheEntry[256] g_dnsCache;
private __gshared size_t g_dnsCacheSize = 0;
private __gshared IPv4Address g_dnsServer;
private __gshared int g_dnsSocket = -1;
private __gshared ushort g_dnsTransactionId = 1;
private __gshared bool g_dnsResponseReceived = false;
private __gshared IPv4Address g_dnsResolvedIP;

/// Initialize DNS client
export extern(C) void initDNS(const IPv4Address* dnsServer) @nogc nothrow {
    if (dnsServer !is null) {
        g_dnsServer = *dnsServer;
    } else {
        // Default to Google DNS
        g_dnsServer = IPv4Address(8, 8, 8, 8);
    }
    
    // Create UDP socket for DNS
    g_dnsSocket = udpSocket();
    if (g_dnsSocket >= 0) {
        udpBind(g_dnsSocket, 53000);  // Bind to ephemeral port
        udpSetCallback(g_dnsSocket, &dnsReceiveCallback);
    }
    
    g_dnsCacheSize = 0;
}

/// Set DNS server
export extern(C) void setDNSServer(const IPv4Address* server) @nogc nothrow {
    if (server !is null) {
        g_dnsServer = *server;
    }
}

/// DNS receive callback
private extern(C) void dnsReceiveCallback(const(ubyte)* data, size_t len,
                                          const ref IPv4Address srcIP, ushort srcPort) @nogc nothrow {
    if (data is null || len < DNSHeader.sizeof) return;
    
    const DNSHeader* header = cast(const DNSHeader*)data;
    
    // Check if this is a response
    ushort flags = ntohs(header.flags);
    if (!(flags & DNSFlags.RESPONSE)) return;
    
    // Parse response
    ushort ancount = ntohs(header.ancount);
    if (ancount == 0) return;
    
    // Skip questions section
    size_t offset = DNSHeader.sizeof;
    ushort qdcount = ntohs(header.qdcount);
    
    for (ushort i = 0; i < qdcount && offset < len; i++) {
        // Skip name (compressed or uncompressed)
        while (offset < len && data[offset] != 0) {
            if ((data[offset] & 0xC0) == 0xC0) {
                // Compressed name (pointer)
                offset += 2;
                break;
            } else {
                // Label
                offset += data[offset] + 1;
            }
        }
        if (offset < len && data[offset] == 0) offset++;  // Skip null terminator
        offset += 4;  // Skip type and class
    }
    
    // Parse answers
    for (ushort i = 0; i < ancount && offset < len; i++) {
        // Skip name
        while (offset < len && data[offset] != 0) {
            if ((data[offset] & 0xC0) == 0xC0) {
                offset += 2;
                break;
            } else {
                offset += data[offset] + 1;
            }
        }
        if (offset < len && data[offset] == 0) offset++;
        
        if (offset + 10 > len) break;
        
        // Read type, class, TTL, data length
        ushort type = (cast(ushort)data[offset] << 8) | data[offset + 1];
        offset += 2;
        ushort cls = (cast(ushort)data[offset] << 8) | data[offset + 1];
        offset += 2;
        uint ttl = (cast(uint)data[offset] << 24) | (cast(uint)data[offset + 1] << 16) |
                   (cast(uint)data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        ushort dataLen = (cast(ushort)data[offset] << 8) | data[offset + 1];
        offset += 2;
        
        if (type == DNSType.A && dataLen == 4 && offset + 4 <= len) {
            // IPv4 address
            g_dnsResolvedIP.bytes[0] = data[offset];
            g_dnsResolvedIP.bytes[1] = data[offset + 1];
            g_dnsResolvedIP.bytes[2] = data[offset + 2];
            g_dnsResolvedIP.bytes[3] = data[offset + 3];
            g_dnsResponseReceived = true;
            return;
        }
        
        offset += dataLen;
    }
}

/// Encode DNS name
private size_t encodeDNSName(const(char)* hostname, ubyte* buffer, size_t bufferSize) @nogc nothrow {
    size_t offset = 0;
    size_t labelStart = 0;
    size_t i = 0;
    
    while (hostname[i] != '\0' && offset < bufferSize - 1) {
        if (hostname[i] == '.') {
            // Write label length
            size_t labelLen = i - labelStart;
            if (labelLen > 63 || offset + labelLen + 1 > bufferSize) break;
            
            buffer[offset++] = cast(ubyte)labelLen;
            
            // Write label
            for (size_t j = labelStart; j < i; j++) {
                buffer[offset++] = cast(ubyte)hostname[j];
            }
            
            labelStart = i + 1;
        }
        i++;
    }
    
    // Write final label
    if (labelStart < i && offset < bufferSize - 1) {
        size_t labelLen = i - labelStart;
        if (labelLen <= 63 && offset + labelLen + 1 <= bufferSize) {
            buffer[offset++] = cast(ubyte)labelLen;
            for (size_t j = labelStart; j < i; j++) {
                buffer[offset++] = cast(ubyte)hostname[j];
            }
        }
    }
    
    // Null terminator
    if (offset < bufferSize) {
        buffer[offset++] = 0;
    }
    
    return offset;
}

/// Lookup hostname in DNS cache
export extern(C) bool dnsLookupCache(const(char)* hostname, IPv4Address* outIP) @nogc nothrow {
    if (hostname is null || outIP is null) return false;
    
    for (size_t i = 0; i < g_dnsCacheSize; i++) {
        if (!g_dnsCache[i].valid) continue;
        
        // Compare hostname
        bool match = true;
        for (size_t j = 0; j < 256; j++) {
            if (g_dnsCache[i].hostname[j] != hostname[j]) {
                match = false;
                break;
            }
            if (hostname[j] == '\0') break;
        }
        
        if (match) {
            *outIP = g_dnsCache[i].ip;
            return true;
        }
    }
    
    return false;
}

/// Add entry to DNS cache
export extern(C) void dnsAddCache(const(char)* hostname, const ref IPv4Address ip, uint ttl) @nogc nothrow {
    if (hostname is null) return;
    
    // Check if already exists
    for (size_t i = 0; i < g_dnsCacheSize; i++) {
        bool match = true;
        for (size_t j = 0; j < 256; j++) {
            if (g_dnsCache[i].hostname[j] != hostname[j]) {
                match = false;
                break;
            }
            if (hostname[j] == '\0') break;
        }
        
        if (match) {
            g_dnsCache[i].ip = ip;
            g_dnsCache[i].ttl = ttl;
            
            ulong tsc;
            asm @nogc nothrow {
                rdtsc;
                shl RDX, 32;
                or RAX, RDX;
                mov tsc, RAX;
            }
            g_dnsCache[i].timestamp = tsc;
            return;
        }
    }
    
    // Add new entry
    if (g_dnsCacheSize < g_dnsCache.length) {
        // Copy hostname
        for (size_t i = 0; i < 256; i++) {
            g_dnsCache[g_dnsCacheSize].hostname[i] = hostname[i];
            if (hostname[i] == '\0') break;
        }
        
        g_dnsCache[g_dnsCacheSize].ip = ip;
        g_dnsCache[g_dnsCacheSize].ttl = ttl;
        g_dnsCache[g_dnsCacheSize].valid = true;
        
        ulong tsc;
        asm @nogc nothrow {
            rdtsc;
            shl RDX, 32;
            or RAX, RDX;
            mov tsc, RAX;
        }
        g_dnsCache[g_dnsCacheSize].timestamp = tsc;
        
        g_dnsCacheSize++;
    }
}

/// Resolve hostname to IP address
export extern(C) bool dnsResolve(const(char)* hostname, IPv4Address* outIP, uint timeoutMs) @nogc nothrow {
    if (hostname is null || outIP is null) return false;
    if (g_dnsSocket < 0) return false;
    
    // Check cache first
    if (dnsLookupCache(hostname, outIP)) {
        return true;
    }
    
    // Build DNS query
    ubyte[512] queryBuffer;
    size_t queryLen = 0;
    
    // DNS header
    DNSHeader* header = cast(DNSHeader*)queryBuffer.ptr;
    header.id = htons(g_dnsTransactionId++);
    header.flags = htons(DNSFlags.QUERY | DNSFlags.RECURSION_DESIRED);
    header.qdcount = htons(1);
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;
    queryLen = DNSHeader.sizeof;
    
    // Encode hostname
    queryLen += encodeDNSName(hostname, queryBuffer.ptr + queryLen, queryBuffer.length - queryLen);
    
    // Query type (A record)
    if (queryLen + 4 > queryBuffer.length) return false;
    queryBuffer[queryLen++] = 0;
    queryBuffer[queryLen++] = cast(ubyte)DNSType.A;
    
    // Query class (IN)
    queryBuffer[queryLen++] = 0;
    queryBuffer[queryLen++] = cast(ubyte)DNSClass.IN;
    
    // Send query
    g_dnsResponseReceived = false;
    if (!udpSend(g_dnsSocket, g_dnsServer, 53, queryBuffer.ptr, queryLen)) {
        return false;
    }
    
    // Wait for response
    uint attempts = timeoutMs / 10;
    for (uint i = 0; i < attempts; i++) {
        networkStackPoll();
        
        if (g_dnsResponseReceived) {
            *outIP = g_dnsResolvedIP;
            dnsAddCache(hostname, g_dnsResolvedIP, 3600);  // Cache for 1 hour
            return true;
        }
        
        // Wait ~10ms
        for (uint j = 0; j < 1000000; j++) {
            asm @nogc nothrow { nop; }
        }
    }
    
    return false;
}

/// Resolve hostname (convenience function)
export extern(C) bool resolveHostname(const(char)* hostname, ubyte* a, ubyte* b, ubyte* c, ubyte* d) @nogc nothrow {
    IPv4Address ip;
    if (dnsResolve(hostname, &ip, 5000)) {
        if (a !is null) *a = ip.bytes[0];
        if (b !is null) *b = ip.bytes[1];
        if (c !is null) *c = ip.bytes[2];
        if (d !is null) *d = ip.bytes[3];
        return true;
    }
    return false;
}
