module eject;

import std.stdio;
import std.string : toStringz;
import shell.syscalls;

void ejectCommand(string[] tokens) {
    string dev = "/dev/cdrom";
    if(tokens.length > 1) dev = tokens[1];
    
    // O_RDONLY | O_NONBLOCK (0x800)
    int fd = cast(int)sys_open(dev.toStringz, 0 | 0x800); 
    if(fd < 0) {
        if(dev == "/dev/cdrom") {
             string alt = "/dev/sr0";
             fd = cast(int)sys_open(alt.toStringz, 0 | 0x800);
             if(fd >= 0) dev = alt;
        }
    }
    
    if(fd < 0) {
        writeln("eject: unable to find or open device for: ", dev);
        return;
    }
    
    // CDROMEJECT 0x5309
    long ret = sys_ioctl(fd, 0x5309, 0);
    if(ret < 0) {
        writeln("eject: unable to eject, ioctl failed");
    } else {
        writeln("eject: disk ejected");
    }
    sys_close(fd);
}
