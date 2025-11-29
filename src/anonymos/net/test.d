module anonymos.net.test;

import anonymos.net.stack;
import anonymos.net.dhcp;
import anonymos.net.dns;
import anonymos.net.tcp;
import anonymos.net.icmp;
import anonymos.net.types;
import anonymos.console : printLine, print;

/// Test network stack functionality
export extern(C) void testNetworkStack() @nogc nothrow {
    printLine("[net-test] ========================================");
    printLine("[net-test] Network Stack Functionality Test");
    printLine("[net-test] ========================================");
    
    // Test 1: DHCP
    printLine("[net-test] Test 1: DHCP Auto-Configuration");
    printLine("[net-test] Sending DHCP DISCOVER...");
    
    if (dhcpAcquire(10000)) {
        printLine("[net-test] ✓ DHCP configuration acquired!");
        
        IPv4Address ip, gateway, netmask, dns;
        if (dhcpGetConfig(&ip, &gateway, &netmask, &dns)) {
            print("[net-test]   IP Address: ");
            printIP(ip);
            print("[net-test]   Gateway:    ");
            printIP(gateway);
            print("[net-test]   Netmask:    ");
            printIP(netmask);
            print("[net-test]   DNS Server: ");
            printIP(dns);
            
            // Configure network stack with DHCP settings
            if (initNetworkStack(&ip, &gateway, &netmask, &dns)) {
                printLine("[net-test] ✓ Network stack initialized with DHCP config");
            }
        }
    } else {
        printLine("[net-test] ✗ DHCP failed, using static config");
        
        // Fallback to static configuration
        IPv4Address ip = IPv4Address(10, 0, 2, 15);
        IPv4Address gateway = IPv4Address(10, 0, 2, 2);
        IPv4Address netmask = IPv4Address(255, 255, 255, 0);
        IPv4Address dns = IPv4Address(8, 8, 8, 8);
        
        if (initNetworkStack(&ip, &gateway, &netmask, &dns)) {
            printLine("[net-test] ✓ Network stack initialized with static config");
        }
    }
    
    printLine("");
    
    // Test 2: Ping
    printLine("[net-test] Test 2: ICMP Ping");
    printLine("[net-test] Pinging 8.8.8.8 (Google DNS)...");
    
    if (ping(8, 8, 8, 8)) {
        printLine("[net-test] ✓ Ping successful!");
    } else {
        printLine("[net-test] ✗ Ping failed");
    }
    
    printLine("");
    
    // Test 3: DNS Resolution
    printLine("[net-test] Test 3: DNS Resolution");
    printLine("[net-test] Resolving mainnet.era.zksync.io...");
    
    IPv4Address zkSyncIP;
    if (dnsResolve("mainnet.era.zksync.io", &zkSyncIP, 5000)) {
        print("[net-test] ✓ Resolved to: ");
        printIP(zkSyncIP);
    } else {
        printLine("[net-test] ✗ DNS resolution failed");
    }
    
    printLine("");
    
    // Test 4: TCP Connection
    printLine("[net-test] Test 4: TCP Connection");
    printLine("[net-test] Connecting to 1.1.1.1:80 (Cloudflare)...");
    
    int sock = tcpConnectTo(1, 1, 1, 1, 80);
    if (sock >= 0) {
        printLine("[net-test] ✓ TCP connection established!");
        
        // Send HTTP GET request
        const(char)* request = "GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n";
        int sent = tcpSend(sock, cast(const(ubyte)*)request, strLen(request));
        
        if (sent > 0) {
            printLine("[net-test] ✓ HTTP request sent");
            
            // Try to receive response
            ubyte[1024] buffer;
            
            // Poll for response
            for (int i = 0; i < 100; i++) {
                networkStackPoll();
                
                int received = tcpReceive(sock, buffer.ptr, buffer.length);
                if (received > 0) {
                    printLine("[net-test] ✓ Received HTTP response!");
                    print("[net-test]   First 100 bytes: ");
                    
                    int printLen = received > 100 ? 100 : received;
                    for (int j = 0; j < printLen; j++) {
                        if (buffer[j] >= 32 && buffer[j] < 127) {
                            char[1] c;
                            c[0] = cast(char)buffer[j];
                            print(c[0..1]);
                        }
                    }
                    printLine("");
                    break;
                }
                
                // Wait a bit
                for (uint k = 0; k < 1000000; k++) {
                    asm @nogc nothrow { nop; }
                }
            }
        }
        
        tcpClose(sock);
    } else {
        printLine("[net-test] ✗ TCP connection failed");
    }
    
    printLine("");
    printLine("[net-test] ========================================");
    printLine("[net-test] Network Stack Test Complete");
    printLine("[net-test] ========================================");
}

private void printIP(const ref IPv4Address ip) @nogc nothrow {
    char[16] buffer;
    int offset = 0;
    
    for (int i = 0; i < 4; i++) {
        if (i > 0) {
            buffer[offset++] = '.';
        }
        
        ubyte b = ip.bytes[i];
        if (b >= 100) {
            buffer[offset++] = cast(char)('0' + (b / 100));
            b %= 100;
        }
        if (b >= 10 || ip.bytes[i] >= 100) {
            buffer[offset++] = cast(char)('0' + (b / 10));
            b %= 10;
        }
        buffer[offset++] = cast(char)('0' + b);
    }
    
    print(buffer[0..offset]);
    printLine("");
}

private size_t strLen(const(char)* s) @nogc nothrow {
    size_t len = 0;
    while (s[len] != 0) len++;
    return len;
}
