import std.stdio;
import std.getopt;
import std.conv;
import std.string : toStringz;

import core.sys.posix.sys.stat : mknod, S_IFIFO, S_IFCHR, S_IFBLK;
import core.sys.posix.sys.types : mode_t, dev_t;

void main(string[] args) {
    string modeStr;
    auto res = getopt(args, "m|mode", &modeStr);
    if (res.helpWanted || res.errors.length || res.rest.length < 2) {
        writeln("Usage: mknod [-m mode] NAME TYPE [MAJOR MINOR]");
        writeln("TYPE: p for FIFO, b for block, c for character");
        return;
    }

    string name = res.rest[0];
    string typeStr = res.rest[1];
    char t = typeStr.length ? typeStr[0] : '\0';

    mode_t mode = 0o666;
    if (modeStr.length) {
        try { mode = cast(mode_t)parse!int(modeStr, 8); } catch (Exception) {
            stderr.writeln("mknod: invalid mode '", modeStr, "'");
            return;
        }
    }

    mode_t nodeType;
    switch (t) {
        case 'p': nodeType = S_IFIFO; break;
        case 'b': nodeType = S_IFBLK; break;
        case 'c': nodeType = S_IFCHR; break;
        default:
            stderr.writeln("mknod: invalid type '", typeStr, "'");
            return;
    }
    mode |= nodeType;

    dev_t dev = 0;
    if (t != 'p' && res.rest.length >= 4) {
        uint major = to!uint(res.rest[2]);
        uint minor = to!uint(res.rest[3]);
        dev = (cast(dev_t)(major) << 8) | cast(dev_t)(minor);
    }

    if (mknod(toStringz(name), mode, dev) != 0) {
        stderr.writeln("mknod: failed to create '", name, "'");
    }
}

