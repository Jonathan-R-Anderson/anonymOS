import std.stdio;
import std.string : toStringz;
import std.getopt;
import std.conv;

import core.sys.posix.sys.stat : mkfifo;
import core.sys.posix.sys.types : mode_t;

void main(string[] args) {
    string modeStr;
    auto res = getopt(args, "m|mode", &modeStr);

    if (res.helpWanted || res.errors.length || res.rest.length == 0) {
        writeln("Usage: mkfifo [-m mode] NAME...");
        return;
    }

    mode_t mode = 0o666;
    if (modeStr.length) {
        try {
            mode = cast(mode_t)parse!int(modeStr, 8);
        } catch (Exception) {
            stderr.writeln("mkfifo: invalid mode '", modeStr, "'");
            return;
        }
    }

    foreach (name; res.rest) {
        if (mkfifo(toStringz(name), mode) != 0) {
            stderr.writeln("mkfifo: cannot create fifo '", name, "'");
        }
    }
}

