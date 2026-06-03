module getfacl;

import std.stdio;
import std.string : toStringz;
import shell.syscalls;

string modeToStr(uint mode) {
    char[3] p = ['-', '-', '-'];
    if (mode & 4) p[0] = 'r';
    if (mode & 2) p[1] = 'w';
    if (mode & 1) p[2] = 'x';
    return cast(string)p.dup;
}

void getfaclCommand(string[] tokens) {
    if(tokens.length < 2) {
        writeln("Usage: getfacl FILE...");
        return;
    }
    
    foreach(f; tokens[1..$]) {
        if(f.length == 0 || f[0] == '-') continue; // skip flags simplified
        
        stat_t st;
        long ret = sys_stat(f.toStringz, &st);
        if(ret < 0) {
            writeln("getfacl: ", f, ": Cannot stat");
            continue;
        }
        
        writeln("# file: ", f);
        writeln("# owner: ", st.st_uid);
        writeln("# group: ", st.st_gid);
        
        // user::rwx
        writeln("user::", modeToStr((st.st_mode >> 6) & 7));
        writeln("group::", modeToStr((st.st_mode >> 3) & 7));
        writeln("other::", modeToStr(st.st_mode & 7));
        writeln();
    }
}
