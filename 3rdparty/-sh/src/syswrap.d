module syswrap;

import std.string : toStringz;
import core.stdc.stdlib : c_system = system;

int system(string cmd) {
    return c_system(cmd.toStringz);
}
