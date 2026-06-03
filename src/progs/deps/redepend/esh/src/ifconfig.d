module ifconfig;

import std.stdio;
import std.string;
import std.conv;
import std.format;
import std.algorithm;
import shell.syscalls;

void showIf(int fd, string name) {
    // Get addr
    string ip = "";
    string mask = "";
    string hw = "";
    
    // ADDR
    ifreq req;
    char[] nbuf = name.dup; nbuf.length = 16; nbuf[name.length] = 0;
    req.ifr_name[] = nbuf[];
    
    if(sys_ioctl(fd, SIOCGIFADDR, cast(long)&req) >= 0) {
        if(req.ifr_addr.sa_family == 2) {
             ubyte* p = cast(ubyte*)req.ifr_addr.sa_data.ptr;
             ip = format("%d.%d.%d.%d", p[2], p[3], p[4], p[5]);
        }
    }
    
    // MASK
    if(sys_ioctl(fd, SIOCGIFNETMASK, cast(long)&req) >= 0) {
         if(req.ifr_addr.sa_family == 2) {
             ubyte* p = cast(ubyte*)req.ifr_addr.sa_data.ptr;
             mask = format("%d.%d.%d.%d", p[2], p[3], p[4], p[5]);
        }
    }
    
    // FLAGS
    short flags = 0;
    if(sys_ioctl(fd, SIOCGIFFLAGS, cast(long)&req) >= 0) {
        flags = req.ifr_addr.sa_family; // Actually first short of union
    }
    
    // HWADDR
    if(sys_ioctl(fd, SIOCGIFHWADDR, cast(long)&req) >= 0) {
        ubyte* p = cast(ubyte*)req.ifr_addr.sa_data.ptr;
        hw = format("%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
    }
    
    write(name, "      Link encap:Ethernet  HWaddr ", hw, "\n");
    if(ip.length) write("          inet addr:", ip, "  Bcast:?  Mask:", mask, "\n");
    write("          ");
    if(flags & 1) write("UP ");
    if(flags & 2) write("BROADCAST "); // IFF_BROADCAST = 0x2
    if(flags & 64) write("RUNNING "); // IFF_RUNNING = 0x40
    if(flags & 16) write("POINTOPOINT "); // IFF_POINTOPOINT=0x10
    if(flags & 4096) write("MULTICAST "); // IFF_MULTICAST=0x1000
    writeln(" MTU:1500  Metric:1"); // Mock MTU
    writeln("          RX packets:0 errors:0 dropped:0 overruns:0 frame:0");
    writeln("          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0");
    writeln("          collisions:0 txqueuelen:1000");
    writeln("          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)\n");
}

void ifconfigCommand(string[] tokens) {
    int fd = cast(int)sys_socket(2, 2, 0);
    if(fd < 0) { writeln("ifconfig: socket failed"); return; }
    
    if(tokens.length < 2 || tokens[1] == "-a") {
         ifconf ifc;
         ubyte[4096] buf;
         ifc.ifc_len = 4096;
         ifc.ifc_buf = cast(long)buf.ptr;
         
         if(sys_ioctl(fd, SIOCGIFCONF, cast(long)&ifc) >= 0) {
             int num = ifc.ifc_len / cast(int)ifreq.sizeof;
             ifreq* req = cast(ifreq*)buf.ptr;
             for(int i=0; i<num; i++) {
                 char[] nb = req[i].ifr_name.dup;
                 size_t len=0; while(len<16 && nb[len]!=0) len++;
                 string name = cast(string)nb[0..len];
                 showIf(fd, name);
             }
         }
    } else {
        string ifname = tokens[1];
        if(tokens.length > 2) {
            // SET config
            // ifconfig eth0 1.2.3.4
            // ifconfig eth0 up
            if(tokens[2] == "up") {
                 // get flags, or UP, set flags
                 ifreq req;
                 char[] nbuf = ifname.dup; nbuf.length=16; nbuf[ifname.length]=0; req.ifr_name[]=nbuf[];
                 if(sys_ioctl(fd, SIOCGIFFLAGS, cast(long)&req) >= 0) {
                     req.ifr_addr.sa_family |= 1; // UP
                     sys_ioctl(fd, SIOCSIFFLAGS, cast(long)&req); // Set
                 }
            } else if(tokens[2] == "down") {
                 ifreq req;
                 char[] nbuf = ifname.dup; nbuf.length=16; nbuf[ifname.length]=0; req.ifr_name[]=nbuf[];
                 if(sys_ioctl(fd, SIOCGIFFLAGS, cast(long)&req) >= 0) {
                     req.ifr_addr.sa_family &= ~1; // DOWN
                     sys_ioctl(fd, SIOCSIFFLAGS, cast(long)&req); 
                 }
            } else {
                // assume IP? 1.2.3.4
                // parse IP... lazy parse...
                 ifreq req;
                 char[] nbuf = ifname.dup; nbuf.length=16; nbuf[ifname.length]=0; req.ifr_name[]=nbuf[];
                 req.ifr_addr.sa_family = 2; // AF_INET
                 // Parse IP string to bytes... 
                 // Simple parser for "a.b.c.d"
                 auto parts = tokens[2].split(".");
                 if(parts.length == 4) {
                     ubyte* p = cast(ubyte*)req.ifr_addr.sa_data.ptr;
                     p[2] = to!ubyte(parts[0]);
                     p[3] = to!ubyte(parts[1]);
                     p[4] = to!ubyte(parts[2]);
                     p[5] = to!ubyte(parts[3]);
                     sys_ioctl(fd, SIOCSIFADDR, cast(long)&req);
                     // Also auto-UP?
                     // sys_ioctl(fd, SIOCGIFFLAGS, &req); req.flags |= 1; sys_ioctl(fd, SIOCSIFFLAGS, &req);
                 }
            }
        } else {
            showIf(fd, ifname);
        }
    }
    sys_close(fd);
}
