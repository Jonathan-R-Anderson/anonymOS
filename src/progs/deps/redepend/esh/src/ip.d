module ip;

import std.stdio;
import std.string;
import std.conv;
import std.format;
import shell.syscalls;

void ipCommand(string[] tokens) {
    if(tokens.length < 2 || (tokens.length > 1 && (tokens[1] == "addr" || tokens[1] == "a" || tokens[1] == "link" || tokens[1] == "l"))) {
         // show addresses
         int fd = cast(int)sys_socket(2, 2, 0); // AF_INET, SOCK_DGRAM
         if(fd < 0) {
             writeln("ip: cannot open socket");
             return;
         }
         
         ifconf ifc;
         ubyte[4096] buf;
         ifc.ifc_len = 4096;
         ifc.ifc_buf = cast(long)buf.ptr;
         
         if(sys_ioctl(fd, SIOCGIFCONF, cast(long)&ifc) < 0) {
             writeln("ip: ioctl failed");
             sys_close(fd);
             return;
         }
         
         int num = ifc.ifc_len / cast(int)ifreq.sizeof;
         ifreq* req = cast(ifreq*)buf.ptr;
         
         for(int i=0; i<num; i++) {
             // Handle name string manually to avoid bounds issues
             char[] nameBuf = req[i].ifr_name.dup;
             // find null
             size_t len = 0;
             while(len < 16 && nameBuf[len] != 0) len++;
             string name = cast(string)nameBuf[0..len];
             
             // Get addr
             string ip_addr = "";
             auto sa = req[i].ifr_addr;
             if(sa.sa_family == 2) {
                 ubyte* p = cast(ubyte*)sa.sa_data.ptr; // port(2) + ip(4) 
                 // offset 2 in sa_data is IP? 
                 // sockaddr_in: sin_family (2), sin_port (2), sin_addr (4), sin_zero (8).
                 // sa_data[0..1] is port. sa_data[2..5] is addr.
                 ip_addr = format("%d.%d.%d.%d", p[2], p[3], p[4], p[5]);
             }
             
             // Get flags
             ifreq flagReq;
             flagReq.ifr_name[] = req[i].ifr_name[];
             
             string state = "DOWN";
             if(sys_ioctl(fd, SIOCGIFFLAGS, cast(long)&flagReq) >= 0) {
                 // flags is first short of union, same as sa_family in sockaddr representation
                 ushort flags = flagReq.ifr_addr.sa_family; 
                 if(flags & 1) state = "UP"; // IFF_UP
             }

             writeln(i+1, ": ", name, ": <", state, ">");
             if(ip_addr.length) {
                 writeln("    inet ", ip_addr, "/24 scope global ", name);
             }
         }
         sys_close(fd);
    } else {
        writeln("ip: command not implemented: ", tokens[1]);
    }
}
