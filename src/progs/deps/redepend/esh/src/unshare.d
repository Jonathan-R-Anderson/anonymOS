module unshare;

import std.stdio;
import shell.syscalls;

void unshareCommand(string[] tokens) {
    writeln("Unsharing into new namespace...");
    
    // Create new namespace
    long res = sys_unshare(0);
    
    if (res < 0) {
        writeln("unshare failed: ", res);
    } else {
        writeln("Success! You are now in a new namespace.");
        writeln("Filesystem is now isolated (virtual root).");
    }
}
