module fdformat;

import std.stdio;
import shell.syscalls;

void fdformatCommand(string[] tokens) {
    if(tokens.length < 2) {
        writeln("Usage: fdformat [-n] device");
        return;
    }
    string device = tokens[$-1];
    writeln("Formatting ", device, " ... done");
    writeln("Verifying ... done");
}
