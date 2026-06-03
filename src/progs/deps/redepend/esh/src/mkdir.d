module mkdir;

import std.stdio;
import shell.syscalls;
import std.string : toStringz;

void mkdirCommand(string[] tokens) {
    if (tokens.length < 2) {
        writeln("mkdir: missing operand");
        return;
    }

    bool parents = false;
    size_t start = 1;

    if (tokens[1] == "-p") {
        parents = true;
        start = 2;
    }

    foreach (i; start .. tokens.length) {
        string path = tokens[i];
        if (parents) {
            // Simple recursive mkdir
            // This is a simplified version
            long res = sys_mkdir(path.toStringz, 493);
            if (res < 0 && res != -17 /* EEXIST */) {
                writeln("mkdir: cannot create directory '", path, "': error ", -res);
            }
        } else {
            long res = sys_mkdir(path.toStringz, 493);


            if (res < 0) {
                if (res == -17) {
                    writeln("mkdir: cannot create directory '", path, "': File exists");
                } else {
                    writeln("mkdir: cannot create directory '", path, "': error ", -res);
                }
            }
        }
    }
}
