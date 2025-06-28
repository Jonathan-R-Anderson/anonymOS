import std.stdio;
import std.getopt;
import std.string : toStringz;
import std.conv;

import core.sys.posix.stdlib : mkstemp, mkdtemp;
import core.sys.posix.unistd : close, unlink;

void main(string[] args) {
    bool dir;
    bool quiet;
    string prefix;
    bool unsafe;

    auto res = getopt(args, "d", &dir, "q", &quiet, "t", &prefix, "u", &unsafe);
    string templ;
    if (res.rest.length) {
        templ = res.rest[0];
    } else if (prefix.length) {
        templ = prefix ~ ".XXXXXX";
    } else {
        templ = "/tmp/tmp.XXXXXX";
    }

    if (templ.count('X') < 6)
        templ ~= "XXXXXX";

    auto buf = (templ ~ "\0").dup; // ensure writable

    char* result;
    int fd = -1;
    if (dir) {
        result = mkdtemp(buf.ptr);
    } else {
        fd = mkstemp(buf.ptr);
        result = fd == -1 ? null : buf.ptr;
    }

    if (result is null) {
        if (!quiet) stderr.writeln("mktemp: failed to create temp");
        return;
    }

    if (!dir && fd != -1 && unsafe) {
        unlink(buf.ptr);
    }
    if (!dir && fd != -1) close(fd);

    writeln(buf[0..buf.length-1]);
}

