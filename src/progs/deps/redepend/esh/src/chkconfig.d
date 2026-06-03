module chkconfig;

import std.stdio;
import std.string;
import std.conv;
import std.algorithm;
import shell.syscalls;

string[] listDir(string path) {
    int fd = cast(int)sys_open(path.toStringz, 0x10000 | 0); // O_DIRECTORY | O_RDONLY
    if (fd < 0) return [];
    string[] res;
    ubyte[4096] buf;
    long n;
    while((n = sys_getdents64(fd, buf.ptr, 4096)) > 0) {
        size_t pos = 0;
        while(pos < n) {
            auto d = cast(linux_dirent64*)(buf.ptr + pos);
            string name = to!string(cast(char*)d.d_name.ptr);
            pos += d.d_reclen;
            if (name != "." && name != "..") res ~= name;
        }
    }
    sys_close(fd);
    return res;
}

bool serviceEnabled(string name, int level) {
    string dir = "/etc/rc" ~ to!string(level) ~ ".d";
    foreach(f; listDir(dir)) {
        if(f.startsWith("S") && f.endsWith(name)) return true;
    }
    return false;
}

string listService(string name) {
    string result;
    foreach(lv; 0..7) {
        bool on = serviceEnabled(name, lv);
        result ~= to!string(lv) ~ ":" ~ (on ? "on" : "off") ~ " ";
    }
    return result.strip;
}

void chkconfigCommand(string[] tokens) {
    if(tokens.length < 2) {
        writeln("Usage: chkconfig --list [name]");
        writeln("       chkconfig name on|off|reset");
        return;
    }
    
    if(tokens[1] == "--list") {
        if(tokens.length > 2) {
            writeln(tokens[2], "\t", listService(tokens[2]));
        } else {
            // list all in init.d
            string[] services = listDir("/etc/init.d");
            foreach(s; services) {
                writeln(s, "\t", listService(s));
            }
        }
        return;
    }
    
    // Manage
    if(tokens.length < 3) return;
    string service = tokens[1];
    string action = tokens[2];
    
    if(action == "on") {
        // Just link in 2,3,4,5 by default
        foreach(lv; [2,3,4,5]) {
            string dir = "/etc/rc" ~ to!string(lv) ~ ".d";
            // Check if S* exists?
            // create S99service -> ../init.d/service
            string target = "../init.d/" ~ service;
            string linkName = dir ~ "/S99" ~ service;
            // unlink old S*
            foreach(f; listDir(dir)) {
                if(f.startsWith("K") && f.endsWith(service)) {
                     sys_unlink((dir ~ "/" ~ f).toStringz);
                }
                if(f.startsWith("S") && f.endsWith(service)) {
                     // already on
                }
            }
            if(!serviceEnabled(service, lv))
                sys_symlink(target.toStringz, linkName.toStringz);
        }
    } else if(action == "off") {
        foreach(lv; [2,3,4,5]) {
            string dir = "/etc/rc" ~ to!string(lv) ~ ".d";
            foreach(f; listDir(dir)) {
                if(f.endsWith(service)) { // Remove S* and K*? chkconfig off usually removes S, adds K
                    sys_unlink((dir ~ "/" ~ f).toStringz);
                }
            }
        }
    }
}
