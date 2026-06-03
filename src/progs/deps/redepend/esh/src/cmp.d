module cmp;

import std.stdio;
import std.conv;
import std.string;
import shell.syscalls;

bool cmpFiles(string f1, string f2) {
    return cmpFiles(f1, f2, cast(ulong)-1, false, false, false);
}

bool cmpFiles(string f1, string f2, ulong maxBytes, bool silent, bool verbose, bool ignore) {
    int fd1 = cast(int)sys_open(f1.toStringz, 0);
    if(fd1 < 0) return false;
    int fd2 = cast(int)sys_open(f2.toStringz, 0);
    if(fd2 < 0) { sys_close(fd1); return false; }
    
    ubyte[4096] buf1;
    ubyte[4096] buf2;
    bool same = true;
    long totalRead = 0;
    
    while(true) {
        long toRead = 4096;
        if(maxBytes != cast(ulong)-1 && totalRead + toRead > maxBytes) {
            toRead = maxBytes - totalRead;
            if(toRead <= 0) break;
        }
        
        long n1 = sys_read(fd1, buf1.ptr, toRead);
        long n2 = sys_read(fd2, buf2.ptr, toRead);
        if(n1 != n2) { 
            same = false; 
            if(!silent && verbose) writeln("cmp: EOF/Size mismatch");
            break; 
        }
        if(n1 == 0) break;
        if(buf1[0..n1] != buf2[0..n1]) { 
            same = false; 
            if(!silent && verbose) writeln("cmp: Content mismatch");
            break; 
        }
        totalRead += n1;
    }
    sys_close(fd1);
    sys_close(fd2);
    return same;
}

void cmpCommand(string[] tokens) {
    if(tokens.length < 3) {
        writeln("Usage: cmp file1 file2 [skip1 [skip2]]");
        return;
    }
    
    string f1 = tokens[1];
    string f2 = tokens[2];
    long skip1 = 0;
    long skip2 = 0;
    
    if(tokens.length > 3) try { skip1 = to!long(tokens[3]); } catch(Exception){}
    if(tokens.length > 4) try { skip2 = to!long(tokens[4]); } catch(Exception){}
    
    int fd1 = cast(int)sys_open(f1.toStringz, 0);
    if(fd1 < 0) { writeln("cmp: ", f1, ": Cannot open"); return; }
    
    int fd2 = cast(int)sys_open(f2.toStringz, 0);
    if(fd2 < 0) { writeln("cmp: ", f2, ": Cannot open"); sys_close(fd1); return; }
    
    // Skip
    auto skip = (int fd, long n) {
        ubyte[4096] tmp;
        while(n > 0) {
            long r = sys_read(fd, tmp.ptr, (n > 4096 ? 4096 : n));
            if(r <= 0) break;
            n -= r;
        }
    };
    
    if(skip1 > 0) skip(fd1, skip1);
    if(skip2 > 0) skip(fd2, skip2);
    
    ubyte[4096] buf1;
    ubyte[4096] buf2;
    long byteIdx = 1;
    long lineIdx = 1;
    
    bool diff = false;
    
    while(true) {
        long n1 = sys_read(fd1, buf1.ptr, 4096);
        long n2 = sys_read(fd2, buf2.ptr, 4096);
        
        long minN = (n1 < n2) ? n1 : n2;
        
        for(int i=0; i<minN; i++) {
            if(buf1[i] != buf2[i]) {
                writeln(f1, " ", f2, " differ: byte ", byteIdx, ", line ", lineIdx);
                diff = true;
                break;
            }
            if(buf1[i] == '\n') lineIdx++;
            byteIdx++;
        }
        
        if(diff) break;
        
        if(n1 != n2) {
            writeln("cmp: EOF on ", (n1 < n2 ? f1 : f2));
            diff = true; 
            break;
        }
        
        if(n1 == 0) break;
    }
    
    sys_close(fd1);
    sys_close(fd2);
}
