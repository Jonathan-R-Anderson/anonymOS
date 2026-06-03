module cksum;

import std.stdio;
import std.string : toStringz;
import shell.syscalls;

private immutable uint[256] crcTable = generateTable();

private immutable(uint[256]) generateTable() {
    uint[256] tab;
    enum uint POLY = 0xEDB88320;
    foreach(i; 0 .. 256) {
        uint c = i;
        foreach(j; 0 .. 8) {
            if(c & 1)
                c = (c >> 1) ^ POLY;
            else
                c >>= 1;
        }
        tab[i] = c;
    }
    return tab;
}

uint cksumBytes(const(ubyte)[] data) {
    uint crc = 0;
    foreach(b; data)
        crc = (crc >> 8) ^ crcTable[(crc ^ b) & 0xFF];
    
    // Length augment (POSIX)
    long len = data.length;
    while(len > 0) {
        ubyte b = len & 0xFF;
        crc = (crc >> 8) ^ crcTable[(crc ^ b) & 0xFF];
        len >>= 8;
    }
    
    return ~crc;
}

uint cksumFile(string fname) {
    int fd = cast(int)sys_open(fname.toStringz, 0);
    if(fd < 0) return 0;
    
    uint crc = 0;
    long totalBytes = 0;
    ubyte[4096] buf;
    long n;
    
    while((n = sys_read(fd, buf.ptr, 4096)) > 0) {
        foreach(b; buf[0..n]) {
             crc = (crc >> 8) ^ crcTable[(crc ^ b) & 0xFF];
        }
        totalBytes += n;
    }
    sys_close(fd);
    
    long len = totalBytes;
    while(len > 0) {
        ubyte b = len & 0xFF;
        crc = (crc >> 8) ^ crcTable[(crc ^ b) & 0xFF];
        len >>= 8;
    }
    return ~crc;
}

uint cksumStdin() {
     uint crc = 0;
    long totalBytes = 0;
    ubyte[4096] buf;
    long n;
    // 0 is stdin
    while((n = sys_read(0, buf.ptr, 4096)) > 0) {
        foreach(b; buf[0..n]) {
             crc = (crc >> 8) ^ crcTable[(crc ^ b) & 0xFF];
        }
        totalBytes += n;
    }
    
    long len = totalBytes;
    while(len > 0) {
        ubyte b = len & 0xFF;
        crc = (crc >> 8) ^ crcTable[(crc ^ b) & 0xFF];
        len >>= 8;
    }
    return ~crc;
}

void cksumCommand(string[] tokens) {
    auto files = tokens.length > 1 ? tokens[1 .. $] : ["-"];
    
    foreach(f; files) {
        uint crc;
        long sz = 0; // Need size for print? I didn't return size in helpers.
        // I should probably duplicate logic or change helpers to return struct.
        // But interpreter.d expects simple return probably.
        
        // Let's just re-implement command logic using helpers if possible, or keep separate?
        // Separate is easier to maintain size print.
        
        int fd = 0;
        if(f != "-") {
            fd = cast(int)sys_open(f.toStringz, 0);
            if(fd < 0) {
                writeln("cksum: ", f, ": Cannot open");
                continue;
            }
        }
        
        uint c = 0;
        long totalBytes = 0;
        ubyte[4096] buf;
        long n;
        
        while((n = sys_read(fd, buf.ptr, 4096)) > 0) {
            foreach(b; buf[0..n]) {
                 c = (c >> 8) ^ crcTable[(c ^ b) & 0xFF];
            }
            totalBytes += n;
        }
        
        long len = totalBytes;
        while(len > 0) {
            ubyte b = len & 0xFF;
            c = (c >> 8) ^ crcTable[(c ^ b) & 0xFF];
            len >>= 8;
        }
        c = ~c;
        
        write(c, " ", totalBytes);
        if(f != "-") write(" ", f);
        writeln();
        
        if(f != "-") sys_close(fd);
    }
}
