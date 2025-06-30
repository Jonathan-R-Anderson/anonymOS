import std.stdio;
import std.getopt;
import std.conv : to, parse;
import std.string : toStringz;
import core.sys.posix.unistd : ftruncate, close, lseek, write, SEEK_SET;
import core.sys.posix.fcntl : open, O_CREAT, O_WRONLY, O_TRUNC;
import core.sys.posix.sys.types : mode_t, off_t;

ulong parseSize(string s) {
    if (s.length == 0) return 0;
    ulong mult = 1;
    char suffix = s[$-1];
    if (suffix == 'b') { mult = 512; s = s[0..$-1]; }
    else if (suffix == 'k') { mult = 1024; s = s[0..$-1]; }
    else if (suffix == 'm') { mult = 1024UL*1024; s = s[0..$-1]; }
    else if (suffix == 'g') { mult = 1024UL*1024*1024; s = s[0..$-1]; }
    return to!ulong(s) * mult;
}

void createFile(string name, ulong size, bool empty) {
    int fd = open(toStringz(name), O_WRONLY | O_CREAT | O_TRUNC, 0o666);
    if (fd == -1) {
        stderr.writeln("mkfile: cannot create ", name);
        return;
    }
    if (empty) {
        ftruncate(fd, cast(off_t)size);
    } else if (size > 0) {
        lseek(fd, cast(off_t)(size - 1), SEEK_SET);
        ubyte c = 0;
        write(fd, &c, 1);
    }
    close(fd);
}

void main(string[] args) {
    bool nflag;
    bool verbose;
    auto res = getopt(args, "n", &nflag, "v", &verbose);
    if (res.helpWanted || res.errors.length || res.rest.length < 2) {
        writeln("Usage: mkfile [-nv] size[b|k|m|g] filename...");
        return;
    }
    ulong size = parseSize(res.rest[0]);
    foreach (name; res.rest[1..$]) {
        createFile(name, size, nflag);
        if (verbose) writeln(name, " ", size);
    }
}

