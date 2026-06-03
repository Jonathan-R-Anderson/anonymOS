module fsck;

import std.stdio;
import shell.syscalls;

void fsckCommand(string[] tokens) {
    writeln("fsck from util-linux 2.39.3");
    writeln("e2fsck 1.47.0 (5-Feb-2023)");
    writeln("/dev/root: clean, 1234/65536 files, 45678/262144 blocks");
}
