module install;

import std.stdio;
import std.conv;
import std.string : toStringz;
import std.algorithm : startsWith;
import shell.syscalls;

void installCommand(string[] tokens) {
    if (tokens.length < 3) {
        writeln("Usage: install [-m MODE] SOURCE DEST");
        return;
    }
    
    int mode = 493; // 0755
    string source, dest;
    size_t idx = 1;
    
    if (tokens[idx] == "-m") {
        if (idx+1 < tokens.length) {
            try {
                // Parse octal? 
                mode = to!int(tokens[idx+1], 8); // D runtime parse octal? to!int(s, 8)
                idx += 2;
            } catch (Exception e) {
                writeln("install: invalid mode");
                return;
            }
        }
    } else if (tokens[idx].startsWith("-m=")) {
        // handle -m=...
        idx++;
    }
    
    if (idx + 1 >= tokens.length) {
        writeln("install: missing file operand");
        return;
    }
    
    source = tokens[idx];
    dest = tokens[idx+1];
    
    // Copy
    auto fdIn = sys_open(source.toStringz, 0);
    if (fdIn < 0) {
        writeln("install: cannot stat ", source);
        return;
    }
    
    auto fdOut = sys_open(dest.toStringz, 0x241, mode); // O_WRONLY|O_CREAT|O_TRUNC
    if (fdOut < 0) {
        writeln("install: cannot create ", dest);
        sys_close(cast(int)fdIn);
        return;
    }
    
    ubyte[4096] buf;
    long n;
    while ((n = sys_read(cast(int)fdIn, buf.ptr, 4096)) > 0) {
        sys_write(cast(int)fdOut, buf.ptr, n);
    }
    
    sys_close(cast(int)fdIn);
    sys_close(cast(int)fdOut);
    
    // Explicit chmod just in case
    sys_chmod(dest.toStringz, mode);
}
