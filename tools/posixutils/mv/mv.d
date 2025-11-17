// mv.d — D implementation of the provided C/C++ mv (non-recursive)
module mv_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio        : writeln, writefln, stderr, readln;
import std.getopt       : getopt, defaultGetoptPrinter, GetoptResult;
import std.string       : toStringz, strip, format;
import std.path         : baseName;
import std.conv         : to;
import std.algorithm    : min;
import std.uni          : toLower;

import core.stdc.errno  : errno, EXDEV, EEXIST;
import core.stdc.string : strerror;
import core.stdc.stdio  : perror, rename; // rename is from stdio.h

import core.sys.posix.unistd :
    access, W_OK, F_OK, isatty, STDIN_FILENO,
    unlink, read, write, close,
    fchown, readlink, symlink;

import core.sys.posix.fcntl  : open, O_RDONLY, O_CREAT, O_TRUNC, O_WRONLY;
import core.sys.posix.sys.types : ssize_t, off_t, uid_t, gid_t, mode_t;
import core.sys.posix.sys.stat :
    stat_t,    // struct type
    stat, lstat, fstat, fchmod,
    S_ISDIR, S_ISREG, S_ISUID, S_ISGID,
    S_ISLNK, S_ISFIFO, mkfifo;

import core.sys.posix.utime : utimbuf, utime;
import core.stdc.stdlib     : exit;

enum PFX = "mv: ";

struct Options {
    bool force;
    bool interactive;
}

void usage(string prog) {
    stderr.writefln("Usage: %s [-f|--force] [-i|--interactive] SRC... DEST", prog);
    exit(1);
}

bool pathExists(string p) {
    return access(p.toStringz, F_OK) == 0;
}

bool shouldAsk(string dest) {
    // Ask only if stdin is a tty AND dest is not writable
    if (isatty(STDIN_FILENO) == 0) return false;
    if (access(dest.toStringz, W_OK) == 0) return false;
    return true;
}

bool askOverwrite(string /*src*/, string dest) {
    // "overwrite 'dest'? " with y/n prompt (default 'n')
    while (true) {
        stderr.writefln("%soverwrite '%s'? ", PFX, dest);
        auto line = readln();               // read from stdin
        if (line is null) return false;
        auto s = line.strip().toLower();
        if (s.length == 0) return false;
        if (s == "y" || s == "yes") return true;
        if (s == "n" || s == "no") return false;
    }
}

ssize_t copyFD(string destLabel, int outfd, string srcLabel, int infd) {
    ubyte[1 << 16] buf; // 64 KiB
    for (;;) {
        auto r = read(infd, buf.ptr, buf.length);
        if (r < 0) {
            perror(srcLabel.toStringz);
            return -1;
        }
        if (r == 0) break;
        ubyte* p = buf.ptr;
        ssize_t left = r;
        while (left > 0) {
            auto w = write(outfd, p, left);
            if (w <= 0) {
                perror(destLabel.toStringz);
                return -1;
            }
            left -= w;
            p += w;
        }
    }
    return 0;
}

int copyAttributes(string fn, int destfd, ref stat_t st, int haveErr) {
    // chown
    if (fchown(destfd, st.st_uid, st.st_gid) != 0) {
        perror(fn.toStringz);
        haveErr = 1;
    }
    // mode without suid/sgid first
    auto mode = st.st_mode;
    auto tmpMode = mode & ~(S_ISUID | S_ISGID);
    if (fchmod(destfd, tmpMode) != 0) {
        perror(fn.toStringz);
        return 1;
    }
    // reapply suid/sgid only if prior steps had no error
    if (!haveErr && mode != tmpMode) {
        if (fchmod(destfd, mode) != 0) {
            perror(fn.toStringz);
            return 1;
        }
    }
    return haveErr;
}

int copyRegularFile(string src, ref stat_t st, string dest) {
    int rc = 0;

    // open src
    int infd = open(src.toStringz, O_RDONLY);
    if (infd < 0) { perror(src.toStringz); return 1; }
    scope(exit) {
        if (infd >= 0)
            if (close(infd) != 0)
                perror(src.toStringz);
    }

    // refresh stat via fstat
    stat_t stNow;
    if (fstat(infd, &stNow) != 0) {
        perror(src.toStringz);
        return 1;
    }
    st = stNow;

    // open dest with 0666 perms (438 decimal)
    int outfd = open(dest.toStringz, O_CREAT | O_TRUNC | O_WRONLY, cast(mode_t)438);
    if (outfd < 0) {
        perror(dest.toStringz);
        return 1;
    }
    scope(exit) {
        if (outfd >= 0)
            if (close(outfd) != 0)
                perror(dest.toStringz);
    }

    if (copyFD(dest, outfd, src, infd) < 0)
        rc = 1;

    // restore times (needs path) — matches the C code using utime(path,...)
    utimbuf utb;
    utb.actime  = st.st_atime;
    utb.modtime = st.st_mtime;
    if (utime(dest.toStringz, &utb) != 0) {
        perror(dest.toStringz);
        rc = 1;
    }

    rc |= copyAttributes(dest, outfd, st, rc);
    return rc;
}

int copySpecial(string src, ref stat_t st, string dest) {
    // Handle symbolic links and FIFOs; other types remain unsupported
    if (S_ISLNK(st.st_mode)) {
        size_t bufSize = cast(size_t)(st.st_size > 0 ? st.st_size + 1 : 256);
        string target;

        while (true) {
            auto buf = new char[bufSize];
            auto len = readlink(src.toStringz, buf.ptr, bufSize);
            if (len < 0) {
                perror(src.toStringz);
                return 1;
            }

            if (len >= bufSize) {
                bufSize *= 2;
                continue; // buffer too small, retry
            }

            target = cast(string) buf[0 .. cast(size_t)len].idup;
            break;
        }

        if (symlink(target.toStringz, dest.toStringz) != 0) {
            perror(dest.toStringz);
            return 1;
        }
        return 0;
    }

    if (S_ISFIFO(st.st_mode)) {
        auto mode = cast(mode_t)(st.st_mode & 0x0FFF);
        if (mkfifo(dest.toStringz, mode) != 0) {
            perror(dest.toStringz);
            return 1;
        }
        return 0;
    }

    stderr.writefln("%sunsupported file type for '%s'", PFX, src);
    return 1;
}

int copyFile(string src, string dest, bool recurse) {
    stat_t st;

    if (lstat(src.toStringz, &st) != 0) {
        perror(src.toStringz);
        return 1;
    }

    if (S_ISDIR(st.st_mode) && !recurse) {
        stderr.writefln("%sattempting to copy directory '%s' as file", PFX, src);
        return 1;
    }

    // If destination exists, remove it (unlink before copy)
    if (pathExists(dest)) {
        if (unlink(dest.toStringz) != 0) {
            perror(dest.toStringz);
            return 1;
        }
    }

    if (S_ISDIR(st.st_mode)) {
        // recursion not implemented (matches C's copy_recurse returning -1)
        stderr.writefln("%srecursive directory copy not implemented for '%s'", PFX, src);
        return 1;
    }

    if (!S_ISREG(st.st_mode))
        return copySpecial(src, st, dest);

    return copyRegularFile(src, st, dest);
}

int moveOne(string src, string dest, ref Options opt, bool recurseForDirCopy) {
    // interactive/force logic for overwriting dest
    if (!opt.force && pathExists(dest) &&
        (opt.interactive || shouldAsk(dest))) {
        if (!askOverwrite(src, dest))
            return 0; // skipping isn't an error for mv
    }

    // Try rename first
    auto r = rename(src.toStringz, dest.toStringz);
    if (r == 0) return 0;

    if (errno != EXDEV) {
        // Different error than cross-device
        stderr.writefln("rename '%s' to '%s': %s", src, dest, strerror(errno));
        return 1;
    }

    // Cross-device: copy then unlink
    auto c = copyFile(src, dest, recurseForDirCopy);
    if (c != 0) return c;

    if (unlink(src.toStringz) != 0) {
        perror(src.toStringz);
        return 1;
    }

    return 0;
}

extern(C) int main(int argc, char** argv) {
    // Gather args
    string[] args; args.length = argc;
    foreach (i; 0 .. argc) args[i] = argv[i].to!string;

    Options opt;
    bool showHelp = false;

    GetoptResult go = getopt(
        args,
        "f|force",       &opt.force,
        "i|interactive", &opt.interactive,
        "h|help",        &showHelp
    );

    if (showHelp) {
        defaultGetoptPrinter("mv - move (rename) files", go.options);
        writeln("\nUsage:\n  ", args[0], " [OPTIONS] SRC... DEST");
        return 0;
    }

    // After getopt, remaining operands are in 'args'
    auto rest = args;
    if (rest.length < 3) usage(rest.length > 0 ? rest[0] : "mv"); // prog + at least 2 operands

    // Drop program name
    auto ops  = rest[1 .. $];
    auto dest = ops[$ - 1];
    auto srcs = ops[0 .. $ - 1];

    // Determine if DEST is a directory
    stat_t st;
    bool destIsDir = (stat(dest.toStringz, &st) == 0) && S_ISDIR(st.st_mode);

    int status = 0;

    if (!destIsDir) {
        // Two-arg form: exactly 1 src and 1 dest required
        if (srcs.length != 1) {
            stderr.writeln("mv: too many arguments when target is not a directory");
            return 1;
        }
        status |= moveOne(srcs[0], dest, opt, /*recurseForDirCopy*/ false);
        return status ? 1 : 0;
    }

    // N → directory form
    foreach (src; srcs) {
        auto base = baseName(src);
        auto outPath  = dest ~ "/" ~ base;
        // For dir→dir across filesystems, original code intended recursion but left TODO.
        status |= moveOne(src, outPath, opt, /*recurseForDirCopy*/ true);
    }

    return status ? 1 : 0;
}
