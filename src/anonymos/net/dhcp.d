module anonymos.net.dhcp;

import anonymos.net.types;
import anonymos.net.udp;
import anonymos.net.ipv4;
import anonymos.net.stack;
import anonymos.drivers.network : getMacAddress;

/// DHCP Message Type
enum DHCPMessageType : ubyte {
    DISCOVER = 1,
    OFFER    = 2,
    REQUEST  = 3,
    DECLINE  = 4,
    ACK      = 5,
    NAK      = 6,
    RELEASE  = 7,
    INFORM   = 8,
}

/// DHCP Header
struct DHCPHeader {
    ubyte op;           // Message op code / message type (1 = BOOTREQUEST, 2 = BOOTREPLY)
    ubyte htype;        // Hardware address type (1 = Ethernet)
    ubyte hlen;         // Hardware address length (6 for Ethernet)
    ubyte hops;         // Client sets to zero
    uint xid;           // Transaction ID
    ushort secs;        // Seconds elapsed
    ushort flags;       // Flags
    uint ciaddr;        // Client IP address
    uint yiaddr;        // 'Your' (client) IP address
    uint siaddr;        // Server IP address
    uint giaddr;        // Gateway IP address
    ubyte[16] chaddr;   // Client hardware address
    ubyte[64] sname;    // Server host name
    ubyte[128] file;    // Boot file name
    uint magic;         // Magic cookie (0x63825363)
}

/// DHCP State
enum DHCPState {
    INIT,
    SELECTING,
    REQUESTING,
    BOUND,
    RENEWING,
    REBINDING,
}

/// DHCP Client State
struct DHCPClient {
    DHCPState state;
    uint xid;           // Transaction ID
    IPv4Address offeredIP;
    IPv4Address serverIP;
    IPv4Address gateway;
    IPv4Address netmask;
    IPv4Address dnsServer;
    uint leaseTime;
    ulong leaseStart;   // TSC timestamp
    int socket;
}

private __gshared DHCPClient g_dhcpClient;
private __gshared bool g_dhcpInitialized = false;

/// Initialize DHCP client
export extern(C) void initDHCP() @nogc nothrow {
    g_dhcpClient.state = DHCPState.INIT;
    g_dhcpClient.xid = 0x12345678; // TODO: Random
    g_dhcpClient.socket = -1;
    g_dhcpInitialized = true;
}

/// Build DHCP packet
private size_t buildDHCPPacket(ubyte* buffer, size_t bufferSize, DHCPMessageType msgType) @nogc nothrow {
    if (buffer is null || bufferSize < DHCPHeader.sizeof + 312) return 0;
    
    // Clear buffer
    for (size_t i = 0; i < bufferSize; i++) buffer[i] = 0;
    
    DHCPHeader* hdr = cast(DHCPHeader*)buffer;
    hdr.op = 1;      // BOOTREQUEST
    hdr.htype = 1;   // Ethernet
    hdr.hlen = 6;    // MAC address length
    hdr.hops = 0;
    hdr.xid = g_dhcpClient.xid;
    hdr.secs = 0;
    hdr.flags = 0x8000; // Broadcast flag
    hdr.ciaddr = 0;
    hdr.yiaddr = 0;
    hdr.siaddr = 0;
    hdr.giaddr = 0;
    
    // Get MAC address
    getMacAddress(hdr.chaddr.ptr);
    
    // Magic cookie
    hdr.magic = 0x63825363;
    
    // Options start after header
    ubyte* options = buffer + DHCPHeader.sizeof;
    size_t optOffset = 0;
    
    // DHCP Message Type option (53)
    options[optOffset++] = 53;
    options[optOffset++] = 1;
    options[optOffset++] = msgType;
    
    if (msgType == DHCPMessageType.REQUEST) {
        // Requested IP Address option (50)
        options[optOffset++] = 50;
        options[optOffset++] = 4;
        options[optOffset++] = g_dhcpClient.offeredIP.bytes[0];
        options[optOffset++] = g_dhcpClient.offeredIP.bytes[1];
        options[optOffset++] = g_dhcpClient.offeredIP.bytes[2];
        options[optOffset++] = g_dhcpClient.offeredIP.bytes[3];
        
        // Server Identifier option (54)
        options[optOffset++] = 54;
        options[optOffset++] = 4;
        options[optOffset++] = g_dhcpClient.serverIP.bytes[0];
        options[optOffset++] = g_dhcpClient.serverIP.bytes[1];
        options[optOffset++] = g_dhcpClient.serverIP.bytes[2];
        options[optOffset++] = g_dhcpClient.serverIP.bytes[3];
    }
    
    // Parameter Request List option (55)
    options[optOffset++] = 55;
    options[optOffset++] = 4;
    options[optOffset++] = 1;  // Subnet Mask
    options[optOffset++] = 3;  // Router
    options[optOffset++] = 6;  // DNS Server
    options[optOffset++] = 15; // Domain Name
    
    // End option (255)
    options[optOffset++] = 255;
    
    return DHCPHeader.sizeof + optOffset;
}

/// Parse DHCP options
private void parseDHCPOptions(const(ubyte)* options, size_t optLen) @nogc nothrow {
    size_t i = 0;
    
    while (i < optLen) {
        ubyte optType = options[i++];
        
        if (optType == 255) break; // End option
        if (optType == 0) continue; // Pad option
        
        if (i >= optLen) break;
        ubyte optLen2 = options[i++];
        
        if (i + optLen2 > optLen) break;
        
        switch (optType) {
            case 1: // Subnet Mask
                if (optLen2 == 4) {
                    g_dhcpClient.netmask.bytes[0] = options[i];
                    g_dhcpClient.netmask.bytes[1] = options[i+1];
                    g_dhcpClient.netmask.bytes[2] = options[i+2];
                    g_dhcpClient.netmask.bytes[3] = options[i+3];
                }
                break;
                
            case 3: // Router
                if (optLen2 >= 4) {
                    g_dhcpClient.gateway.bytes[0] = options[i];
                    g_dhcpClient.gateway.bytes[1] = options[i+1];
                    g_dhcpClient.gateway.bytes[2] = options[i+2];
                    g_dhcpClient.gateway.bytes[3] = options[i+3];
                }
                break;
                
            case 6: // DNS Server
                if (optLen2 >= 4) {
                    g_dhcpClient.dnsServer.bytes[0] = options[i];
                    g_dhcpClient.dnsServer.bytes[1] = options[i+1];
                    g_dhcpClient.dnsServer.bytes[2] = options[i+2];
                    g_dhcpClient.dnsServer.bytes[3] = options[i+3];
                }
                break;
                
            case 51: // Lease Time
                if (optLen2 == 4) {
                    g_dhcpClient.leaseTime = (cast(uint)options[i] << 24) |
                                            (cast(uint)options[i+1] << 16) |
                                            (cast(uint)options[i+2] << 8) |
                                            cast(uint)options[i+3];
                }
                break;
                
            case 53: // DHCP Message Type
                // Already handled
                break;
                
            case 54: // Server Identifier
                if (optLen2 == 4) {
                    g_dhcpClient.serverIP.bytes[0] = options[i];
                    g_dhcpClient.serverIP.bytes[1] = options[i+1];
                    g_dhcpClient.serverIP.bytes[2] = options[i+2];
                    g_dhcpClient.serverIP.bytes[3] = options[i+3];
                }
                break;
                
            default:
                break;
        }
        
        i += optLen2;
    }
}

/// DHCP receive callback
private extern(C) void dhcpReceiveCallback(const(ubyte)* data, size_t len,
                                           const ref IPv4Address srcIP, ushort srcPort) @nogc nothrow {
    if (data is null || len < DHCPHeader.sizeof) return;
    
    const DHCPHeader* hdr = cast(const DHCPHeader*)data;
    
    // Check if this is a reply for us
    if (hdr.op != 2) return; // Not a BOOTREPLY
    if (hdr.xid != g_dhcpClient.xid) return; // Wrong transaction ID
    
    // Check magic cookie
    if (hdr.magic != 0x63825363) return;
    
    // Parse options
    const(ubyte)* options = data + DHCPHeader.sizeof;
    size_t optLen = len - DHCPHeader.sizeof;
    
    // Find message type
    DHCPMessageType msgType = cast(DHCPMessageType)0;
    for (size_t i = 0; i < optLen; ) {
        if (options[i] == 255) break;
        if (options[i] == 0) { i++; continue; }
        
        ubyte optType = options[i++];
        if (i >= optLen) break;
        ubyte optLen2 = options[i++];
        if (i + optLen2 > optLen) break;
        
        if (optType == 53 && optLen2 == 1) {
            msgType = cast(DHCPMessageType)options[i];
            break;
        }
        
        i += optLen2;
    }
    
    if (msgType == DHCPMessageType.OFFER && g_dhcpClient.state == DHCPState.SELECTING) {
        // Save offered IP
        g_dhcpClient.offeredIP.bytes[0] = cast(ubyte)(hdr.yiaddr & 0xFF);
        g_dhcpClient.offeredIP.bytes[1] = cast(ubyte)((hdr.yiaddr >> 8) & 0xFF);
        g_dhcpClient.offeredIP.bytes[2] = cast(ubyte)((hdr.yiaddr >> 16) & 0xFF);
        g_dhcpClient.offeredIP.bytes[3] = cast(ubyte)((hdr.yiaddr >> 24) & 0xFF);
        
        // Parse options
        parseDHCPOptions(options, optLen);
        
        g_dhcpClient.state = DHCPState.REQUESTING;
    }
    else if (msgType == DHCPMessageType.ACK && g_dhcpClient.state == DHCPState.REQUESTING) {
        // Parse options
        parseDHCPOptions(options, optLen);
        
        // Get TSC for lease tracking
        ulong tsc;
        asm @nogc nothrow {
            rdtsc;
            shl RDX, 32;
            or RAX, RDX;
            mov tsc, RAX;
        }
        g_dhcpClient.leaseStart = tsc;
        
        g_dhcpClient.state = DHCPState.BOUND;
    }
}

/// Perform DHCP discovery
export extern(C) bool dhcpDiscover() @nogc nothrow {
    if (!g_dhcpInitialized) initDHCP();
    
    // Create UDP socket
    if (g_dhcpClient.socket < 0) {
        g_dhcpClient.socket = udpSocket();
        if (g_dhcpClient.socket < 0) return false;
        
        if (!udpBind(g_dhcpClient.socket, 68)) {
            udpClose(g_dhcpClient.socket);
            g_dhcpClient.socket = -1;
            return false;
        }
        
        // Set receive callback
        udpSetCallback(g_dhcpClient.socket, &dhcpReceiveCallback);
    }
    
    // Build DISCOVER packet
    ubyte[548] packet;
    size_t pktLen = buildDHCPPacket(packet.ptr, packet.length, DHCPMessageType.DISCOVER);
    
    // Send to broadcast address
    IPv4Address broadcast = IPv4Address(255, 255, 255, 255);
    if (!udpSend(g_dhcpClient.socket, broadcast, 67, packet.ptr, pktLen)) {
        return false;
    }
    
    g_dhcpClient.state = DHCPState.SELECTING;
    return true;
}

/// Send DHCP request
export extern(C) bool dhcpRequest() @nogc nothrow {
    if (g_dhcpClient.state != DHCPState.REQUESTING) return false;
    
    // Build REQUEST packet
    ubyte[548] packet;
    size_t pktLen = buildDHCPPacket(packet.ptr, packet.length, DHCPMessageType.REQUEST);
    
    // Send to broadcast address
    IPv4Address broadcast = IPv4Address(255, 255, 255, 255);
    if (!udpSend(g_dhcpClient.socket, broadcast, 67, packet.ptr, pktLen)) {
        return false;
    }
    
    return true;
}

/// Get DHCP configuration
export extern(C) bool dhcpGetConfig(IPv4Address* ip, IPv4Address* gateway,
                                     IPv4Address* netmask, IPv4Address* dns) @nogc nothrow {
    if (g_dhcpClient.state != DHCPState.BOUND) return false;
    
    if (ip !is null) *ip = g_dhcpClient.offeredIP;
    if (gateway !is null) *gateway = g_dhcpClient.gateway;
    if (netmask !is null) *netmask = g_dhcpClient.netmask;
    if (dns !is null) *dns = g_dhcpClient.dnsServer;
    
    return true;
}

/// Check if DHCP is bound
export extern(C) bool dhcpIsBound() @nogc nothrow {
    return g_dhcpClient.state == DHCPState.BOUND;
}

/// Perform full DHCP sequence
export extern(C) bool dhcpAcquire(uint timeoutMs) @nogc nothrow {
    if (!dhcpDiscover()) return false;
    
    // Wait for OFFER
    uint attempts = timeoutMs / 100;
    for (uint i = 0; i < attempts; i++) {
        networkStackPoll();
        
        if (g_dhcpClient.state == DHCPState.REQUESTING) {
            // Send REQUEST
            if (!dhcpRequest()) return false;
            
            // Wait for ACK
            for (uint j = 0; j < attempts; j++) {
                networkStackPoll();
                
                if (g_dhcpClient.state == DHCPState.BOUND) {
                    return true;
                }
                
                // Wait ~100ms
                for (uint k = 0; k < 10000000; k++) {
                    asm @nogc nothrow { nop; }
                }
            }
            
            return false;
        }
        
        // Wait ~100ms
        for (uint k = 0; k < 10000000; k++) {
            asm @nogc nothrow { nop; }
        }
    }
    
    return false;
}

/// Renew DHCP lease
export extern(C) void dhcpRenew() @nogc nothrow {
    // TODO: Implement lease renewal
    g_dhcpClient.state = DHCPState.RENEWING;
}
