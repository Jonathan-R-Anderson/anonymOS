module du;

import std.stdio;
import std.string;
import std.conv;
import shell.syscalls;

ulong getDirSize(string path) {
    ulong totalSize = 0;
    
    auto fd = sys_open(path.toStringz, 0);
    if (fd < 0) return 0;
    
    ubyte[4096] buffer;
    long nread;
    
    while ((nread = sys_getdents64(cast(int)fd, buffer.ptr, buffer.length)) > 0) {
        size_t pos = 0;
        while (pos < nread) {
            auto d = cast(linux_dirent64*)(buffer.ptr + pos);
            string name = to!string(cast(char*)d.d_name.ptr);
            
            if (name != "." && name != "..") {
                string fullPath = path ~ "/" ~ name;
                
                if (d.d_type == 4) {  // DT_DIR
                    totalSize += getDirSize(fullPath);
                } else if (d.d_type == 8) {  // DT_REG
                    stat_t st;
                    auto fileFd = sys_open(fullPath.toStringz, 0);
                    if (fileFd >= 0) {
                        sys_fstat(cast(int)fileFd, &st);
                        totalSize += st.st_size;
                        sys_close(cast(int)fileFd);
                    }
                }
            }
            
            pos += d.d_reclen;
        }
    }
    
    sys_close(cast(int)fd);
    return totalSize;
}

string formatSize(ulong bytes) {
    if (bytes < 1024) return to!string(bytes) ~ "B";
    if (bytes < 1024 * 1024) return to!string(bytes / 1024) ~ "K";
    if (bytes < 1024 * 1024 * 1024) return to!string(bytes / (1024 * 1024)) ~ "M";
    return to!string(bytes / (1024 * 1024 * 1024)) ~ "G";
}

void duCommand(string[] tokens) {
    bool humanReadable = false;
    bool summarize = false;
    size_t idx = 1;
    
    while (idx < tokens.length && tokens[idx].startsWith("-")) {
        if (tokens[idx] == "-h") humanReadable = true;
        else if (tokens[idx] == "-s") summarize = true;
        idx++;
    }
    
    string path = idx < tokens.length ? tokens[idx] : ".";
    ulong size = getDirSize(path);
    
    if (humanReadable) {
        writeln(formatSize(size), "\t", path);
    } else {
        writeln(size / 1024, "\t", path);
    }
}
