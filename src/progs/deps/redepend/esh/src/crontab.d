module crontab;

import std.stdio;
import std.string : toStringz;
import shell.syscalls;

void crontabCommand(string[] tokens) {
    bool list = false;
    bool remove = false;
    string file;
    
    for(size_t i=1; i<tokens.length; i++) {
        if(tokens[i] == "-l") list = true;
        else if(tokens[i] == "-r") remove = true;
        else if(tokens[i] == "-e") {
            writeln("crontab: -e not supported (no editor)");
            return;
        } else {
            file = tokens[i];
        }
    }
    
    if (list) {
        auto fd = sys_open("crontab".toStringz, 0);
        if (fd < 0) {
            writeln("no crontab for user");
            return;
        }
        ubyte[4096] buf;
        long n;
        while((n = sys_read(cast(int)fd, buf.ptr, 4096)) > 0) {
            sys_write(1, buf.ptr, n);
        }
        sys_close(cast(int)fd);
    } else if (remove) {
        sys_unlink("crontab".toStringz);
    } else if (file.length > 0) {
        // Copy file to "crontab"
        int fdIn;
        if (file == "-") fdIn = 0;
        else {
            fdIn = cast(int)sys_open(file.toStringz, 0);
            if (fdIn < 0) {
                writeln("crontab: cannot open ", file);
                return;
            }
        }
        
        auto fdOut = sys_open("crontab".toStringz, 0x241, 420); // create/trunc
        if (fdOut < 0) {
            writeln("crontab: cannot update crontab");
            if (fdIn != 0) sys_close(fdIn);
            return;
        }
        
        ubyte[4096] buf;
        long n;
        while((n = sys_read(fdIn, buf.ptr, 4096)) > 0) {
            sys_write(cast(int)fdOut, buf.ptr, n);
        }
        
        if (fdIn != 0) sys_close(fdIn);
        sys_close(cast(int)fdOut);
    } else {
        writeln("Usage: crontab [-l | -r | file]");
    }
}
