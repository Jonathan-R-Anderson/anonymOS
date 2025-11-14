// mesg.d — D translation of the provided C mesg
module mesg_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio        : writeln, write, writefln, stdout, stderr;
import std.string       : toStringz;
import std.conv         : to;
import std.getopt       : getopt;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.stdio  : perror;
import core.sys.posix.unistd : isatty, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO;
// ⬇️ FIX: import the struct type stat_t (don’t alias it to the function `stat`)
import core.sys.posix.sys.stat : stat_t, fstat, fchmod, S_IWGRP, S_IWOTH;

enum PFX = "mesg: ";

struct StdioFD { int fd; string name; }
immutable StdioFD[] stdioFds = [
    StdioFD(STDIN_FILENO,  "stdin"),
    StdioFD(STDOUT_FILENO, "stdout"),
    StdioFD(STDERR_FILENO, "stderr"),
];

void usage(string prog) {
    stderr.writefln("Usage: %s [y|n]", prog);
    import core.stdc.stdlib : exit;
    exit(2);
}

extern(C) int main(int argc, char** argv) {
    // Collect positional args (0 or 1 expected)
    string[] args;
    args.length = argc;
    foreach (i; 0 .. argc) args[i] = argv[i].to!string;
    auto prog = args[0];

    // No options; accept 0 or 1 positional argument
    auto rem = args[1 .. $];
    if (rem.length > 1) usage(prog);
    string optYN;
    if (rem.length == 1) {
        if (rem[0] != "y" && rem[0] != "n") usage(prog);
        optYN = rem[0];
    }

    // Find a tty among stdin/stdout/stderr
    int ttyFd = -1;
    string ttyName;
    foreach (sf; stdioFds) {
        if (isatty(sf.fd) != 0) {
            ttyFd = sf.fd;
            ttyName = sf.name;
            break;
        }
    }
    if (ttyFd == -1) {
        stderr.writeln("no terminal device found");
        return 2;
    }

    // Stat the tty fd
    stat_t st;
    if (fstat(ttyFd, &st) != 0) {
        perror(ttyName.toStringz);
        return 2;
    }

    const bool writable = ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0);

    // No argument: report current state and return 0 if y, 1 if n
    if (optYN.length == 0) {
        if (writable) {
            writeln("is y");
            return 0;
        } else {
            writeln("is n");
            return 1;
        }
    }

    // mesg y: ensure group/other write bits are set
    if (optYN == "y") {
        if (writable) return 0; // already y
        st.st_mode |= (S_IWGRP | S_IWOTH);
        if (fchmod(ttyFd, st.st_mode) != 0) {
            perror(ttyName.toStringz);
            return 2;
        }
        return 0;
    }

    // mesg n: ensure group/other write bits are cleared
    // (exit 1 after success, matching original)
    if (!writable) return 1; // already n
    st.st_mode &= ~(S_IWGRP | S_IWOTH);
    if (fchmod(ttyFd, st.st_mode) != 0) {
        perror(ttyName.toStringz);
        return 2;
    }
    return 1;
}
