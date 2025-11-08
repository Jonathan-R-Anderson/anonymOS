/+ 
  tee.d — D port of posixutils “tee” (GPL-2.0)
  Options:
    -a  --append               append to files (default: truncate)
    -i  --ignore-interrupts    ignore SIGINT
  Usage:
    tee [-a] [-i] [FILE...]
+/
module tee;

version (Posix):

import std.stdio;
import std.getopt;
import std.string;
import std.exception;
import core.stdc.stdlib : exit;
import core.stdc.string : strlen;
import core.sys.posix.unistd : read, write, close, STDIN_FILENO, STDOUT_FILENO;
import core.sys.posix.fcntl  : fcntl, open, O_NONBLOCK, F_SETFL, O_WRONLY, O_CREAT, O_TRUNC, O_APPEND;
import core.sys.posix.sys.types : ssize_t;
import core.sys.posix.sys.select : fd_set, FD_ZERO, FD_SET, select;
import core.sys.posix.signal : signal, SIGINT, SIG_IGN;

extern(C) void perror(const char*);

enum TEE_BUF_SZ = 8192;

struct FileEnt {
    string fn;
    int    fd = -1;
    bool   skip = false;
}

bool optAppend = false;
bool optIgnoreSigint = false;

FileEnt[] files;

int freeFlist()
{
    int err = 0;
    foreach (ref fe; files) {
        if (fe.fd >= 0) {
            if (close(fe.fd) < 0) {
                perror(fe.fn.ptr);
                err = 1;
            }
        }
    }
    return err;
}

int teeOutputBytes(const(char)* buf, ssize_t buflen)
{
    ssize_t toWrite;
    const(char)* s;
    int err = 0;

    foreach (ref fe; files) {
        if (fe.skip) continue;

        s = buf;
        toWrite = buflen;

        while (toWrite > 0) {
            auto wrc = write(fe.fd, s, toWrite);
            if (wrc < 1) {
                perror(fe.fn.ptr);
                fe.skip = true; // stop trying this target
                err = 1;
                break;
            }
            s += wrc;
            toWrite -= wrc;
        }
    }
    return err;
}

int teeOutput()
{
    // put stdin into non-blocking mode so select()-driven loop behaves
    auto rc = fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    if (rc < 0) {
        perror("stdin");
        auto e = freeFlist();
        return 1 | e;
    }

    int err = 0;

    while (true) {
        fd_set rdSet;
        FD_ZERO(&rdSet);
        FD_SET(STDIN_FILENO, &rdSet);

        // No write/except sets; block until readable
        rc = select(STDIN_FILENO + 1, &rdSet, null, null, null);
        if (rc < 1) {
            perror("stdin");
            break;
        }

        char[TEE_BUF_SZ] buf;
        auto bread = read(STDIN_FILENO, buf.ptr, buf.length);
        if (bread == 0) {
            // EOF
            break;
        }
        if (bread < 0) {
            perror("stdin");
            rc = 1;
            break;
        }

        err |= teeOutputBytes(buf.ptr, bread);
    }

    err |= freeFlist();
    return err;
}

int openTarget(string fn)
{
    int flags = optAppend
        ? (O_WRONLY | O_CREAT | O_APPEND)
        : (O_WRONLY | O_CREAT | O_TRUNC);

    // 0666 masked by umask at runtime
    enum mode_t = uint;
    int fd = open(fn.ptr, flags, cast(mode_t)0o666);
    if (fd < 0) {
        perror(fn.ptr);
        return -1;
    }
    return fd;
}

int main(string[] args)
{
    // Parse options; leave remaining args as files
    try {
        getopt(args,
            config.passThrough,
            "a|append", &optAppend,
            "i|ignore-interrupts", &optIgnoreSigint
        );
    } catch (Exception e) {
        stderr.writeln("tee: ", e.msg);
        return 2;
    }

    // Install SIGINT ignore if requested (match original timing before I/O)
    if (optIgnoreSigint) {
        if (signal(SIGINT, SIG_IGN) is cast(void*)-1) {
            stderr.writeln("tee: cannot ignore SIGINT");
            return 1;
        }
    }

    // Always include stdout as first target
    files ~= FileEnt("stdout", STDOUT_FILENO, false);

    // The rest of args (after getopt) are file names
    foreach (fn; args[1 .. $]) {
        if (fn.length && fn[0] == '-') {
            // treat as a filename literally beginning with '-' (GNU tee does)
            // users can pass "--" before files if they want, but we don't require it
        }
        auto fd = openTarget(fn);
        if (fd < 0) {
            // keep going (like GNU tee), but remember error
            files ~= FileEnt(fn, -1, true);
        } else {
            files ~= FileEnt(fn, fd, false);
        }
    }

    return teeOutput();
}
