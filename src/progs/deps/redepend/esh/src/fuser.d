module fuser;

import std.stdio;
import std.string;
import std.conv;
import std.algorithm;
import shell.syscalls;

// Helper to check if string is numeric
bool isNumeric(string s) {
    foreach(c; s) if(c < '0' || c > '9') return false;
    return s.length > 0;
}

void fuserCommand(string[] tokens) {
    bool killProcs = false;
    string target;
    
    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        if(tokens[idx] == "-k") killProcs = true;
        idx++;
    }
    if (idx < tokens.length) target = tokens[idx];
    else {
        writeln("Usage: fuser [-k] FILENAME");
        return;
    }
    
    // Resolve target path? Simplistic: assume absolute or full match against buffer
    
    auto procFd = sys_open("/proc".toStringz, 0); // O_RDONLY|O_DIRECTORY
    if (procFd < 0) {
        writeln("fuser: cannot open /proc");
        return;
    }
    
    ubyte[4096] procBuf;
    long nRead;
    int[] pids;
    
    while((nRead = sys_getdents64(cast(int)procFd, procBuf.ptr, 4096)) > 0) {
        size_t pos = 0;
        while(pos < nRead) {
            auto d = cast(linux_dirent64*)(procBuf.ptr + pos);
            string pidStr = to!string(cast(char*)d.d_name.ptr);
            pos += d.d_reclen;
            
            if (!isNumeric(pidStr)) continue;
            
            // Scan /proc/<pid>/fd
            string fdPath = "/proc/" ~ pidStr ~ "/fd";
            auto fdDir = sys_open(fdPath.toStringz, 0);
            if (fdDir >= 0) {
                ubyte[4096] fdBuf;
                long nFdRead;
                while((nFdRead = sys_getdents64(cast(int)fdDir, fdBuf.ptr, 4096)) > 0) {
                    size_t fdPos = 0;
                    while(fdPos < nFdRead) {
                        auto fdEnt = cast(linux_dirent64*)(fdBuf.ptr + fdPos);
                        string fdName = to!string(cast(char*)fdEnt.d_name.ptr);
                        fdPos += fdEnt.d_reclen;
                        
                        if (!isNumeric(fdName)) continue;
                        
                        string linkPath = fdPath ~ "/" ~ fdName;
                        char[1024] linkBuf;
                        long len = sys_readlink(linkPath.toStringz, linkBuf.ptr, 1024);
                        if (len > 0) {
                            string linkTarget = cast(string)linkBuf[0..len];
                            if (linkTarget == target) {
                                // Match!
                                try {
                                    int pid = to!int(pidStr);
                                    bool exists = false;
                                    foreach(p; pids) if(p==pid) exists=true;
                                    if(!exists) {
                                        pids ~= pid;
                                        write(pid, " ");
                                    }
                                } catch(Exception) {}
                            }
                        }
                    }
                }
                sys_close(cast(int)fdDir);
            }
        }
    }
    sys_close(cast(int)procFd);
    writeln();
    
    if (killProcs && pids.length > 0) {
        foreach(pid; pids) {
            sys_kill(pid, 9); // SIGKILL
        }
    }
}
