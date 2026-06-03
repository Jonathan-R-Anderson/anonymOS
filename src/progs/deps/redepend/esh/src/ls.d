module ls;

import std.stdio;
import std.string;
import std.conv;
import shell.syscalls;

void lsCommand(string[] tokens) {
    bool all = false;
    bool longFmt = false;
    size_t idx = 1;
    
    // Parse options
    while (idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if (t == "-a" || t == "--all") all = true;
        else if (t == "-l") longFmt = true;
        else if (t == "--") { idx++; break; }
        idx++;
    }
    
    string path = idx < tokens.length ? tokens[idx] : ".";
    
    // Use syscall to list directory
    auto fd = sys_open(path.toStringz, 0 /* O_RDONLY */);
    if (fd < 0) {
        writeln("ls: cannot access '", path, "': No such file or directory");
        return;
    }
    
    // Read directory entries
    ubyte[4096] buffer;
    long nread;
    
    while ((nread = sys_getdents64(cast(int)fd, buffer.ptr, buffer.length)) > 0) {
        size_t pos = 0;
        while (pos < nread) {
            auto d = cast(linux_dirent64*)(buffer.ptr + pos);
            
            // Get name
            string name = to!string(cast(char*)d.d_name.ptr);
            
            // Skip . and .. unless -a
            if (!all && (name == "." || name == "..")) {
                pos += d.d_reclen;
                continue;
            }
            
            // Skip hidden files unless -a
            if (!all && name.startsWith(".")) {
                pos += d.d_reclen;
                continue;
            }
            
            if (longFmt) {
                // Get file stats
                stat_t st;
                string fullPath = path ~ "/" ~ name;
                auto statFd = sys_open(fullPath.toStringz, 0);
                if (statFd >= 0) {
                    sys_fstat(cast(int)statFd, &st);
                    sys_close(cast(int)statFd);
                    
                    // Print permissions and size
                    char typeChar = '-';
                    if (d.d_type == 4) typeChar = 'd';  // DT_DIR
                    else if (d.d_type == 10) typeChar = 'l';  // DT_LNK
                    
                    writefln("%c%s %8d %s", typeChar, "rwxr-xr-x", st.st_size, name);
                } else {
                    writeln(name);
                }
            } else {
                writeln(name);
            }
            
            pos += d.d_reclen;
        }
    }
    
    sys_close(cast(int)fd);
}
