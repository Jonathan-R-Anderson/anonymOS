module locate;

import std.stdio;
import std.conv;
import std.string : toStringz, indexOf;
import shell.syscalls;

void search(string path, string pattern) {
    auto fd = sys_open(path.toStringz, 0);
    if (fd < 0) return;
    
    ubyte[4096] buffer;
    long nread;
    
    while ((nread = sys_getdents64(cast(int)fd, buffer.ptr, buffer.length)) > 0) {
        size_t pos = 0;
        while (pos < nread) {
            auto d = cast(linux_dirent64*)(buffer.ptr + pos);
            string name = to!string(cast(char*)d.d_name.ptr);
            
            if (name != "." && name != "..") {
                string fullPath = path == "/" ? "/" ~ name : path ~ "/" ~ name;
                
                // Simple substring match like locate usually does
                if (fullPath.indexOf(pattern) >= 0) {
                    writeln(fullPath);
                }
                
                if (d.d_type == 4) { // DT_DIR
                    // Recurse to depth 3-4 to avoid massive spam or loops?
                    // Locate usually searches everything.
                    // We'll trust the user wants to search.
                    // But prevent infinite loops with symlinks - wait, d_type 4 is dir. 
                    // Symlink to dir is DT_LNK (10). DT_DIR is real dir.
                    search(fullPath, pattern);
                }
            }
            pos += d.d_reclen;
        }
    }
    sys_close(cast(int)fd);
}

void locateCommand(string[] tokens) {
    if (tokens.length < 2) {
        writeln("Usage: locate PATTERN");
        return;
    }
    string pattern = tokens[1];
    // Start search from root
    search("/", pattern);
}
