// ln.d — D implementation of the provided C++ ln utility
module ln_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio          : writeln, writefln, stderr;
import std.getopt         : getopt, defaultGetoptPrinter, GetoptResult;
import std.path           : baseName, buildPath;
import std.string         : toStringz;
import std.conv           : to;
import std.algorithm      : max;
import std.array          : array;
import core.stdc.string   : strerror;
import core.stdc.errno    : errno;
import core.sys.posix.unistd : access, F_OK, unlink, symlink, readlink, link;
import core.sys.posix.sys.stat : stat, lstat, S_ISDIR, S_ISLNK;
import core.sys.posix.sys.types : mode_t;
import core.stdc.stdlib   : exit;

enum PFX = "ln: ";

struct Options {
    bool force;
    bool symbolic;
}

struct FS {
    static bool pathExists(string p) {
        return access(p.toStringz, F_OK) == 0;
    }
    static bool isDir(string p) {
        import core.sys.posix.sys.stat : stat, stat_t;
        stat_t st;
        if (stat(p.toStringz, &st) != 0) return false;
        return S_ISDIR(st.st_mode);
    }
}

/// If doing a hard link and the source is a symlink, dereference once
/// (mirror of the original program’s readlink() step).
string maybeDereferenceOnce(string src) {
    import core.sys.posix.sys.stat : lstat, stat_t, S_ISLNK;
    stat_t st;
    if (lstat(src.toStringz, &st) != 0) {
        // If lstat fails, just return original; link(2) will error below.
        return src;
    }
    if (!S_ISLNK(st.st_mode)) return src;

    // Read the symlink target
    // Use PATH_MAX-ish size; if too small, we’ll just error like the C version.
    enum BUF = 4096;
    char[BUF] buf;
    auto n = readlink(src.toStringz, buf.ptr, buf.length);
    if (n < 0) {
        // Failed to readlink; hard link attempt will error later.
        return src;
    }
    if (n >= BUF) {
        stderr.writeln(PFX ~ "link target too long, skipping");
        // Returning original will likely fail; that matches original behavior (set failure).
        return src;
    }
    return cast(string) buf[0 .. n].idup;
}

int doLink(ref Options opt, string linkTarget, string linkName) {
    // If destination exists
    if (FS.pathExists(linkName)) {
        if (!opt.force) {
            stderr.writefln("%s%s: exists, skipping", PFX, linkName);
            return 1;
        }
        if (unlink(linkName.toStringz) != 0) {
            // perror(link_name)
            stderr.writefln("%s%s", linkName, "");
            // Above line just ensures non-null pointer for perror style; instead:
            import core.stdc.stdio : perror;
            perror(linkName.toStringz);
            return 1;
        }
    }

    if (opt.symbolic) {
        // Create a symbolic link to the given path
        if (symlink(linkTarget.toStringz, linkName.toStringz) != 0) {
            import core.stdc.stdio : perror;
            perror(linkName.toStringz);
            return 1;
        }
        return 0;
    }

    // Hard link behavior: if linkTarget is a symlink, follow it once
    auto targetForHardLink = maybeDereferenceOnce(linkTarget);

    if (link(targetForHardLink.toStringz, linkName.toStringz) != 0) {
        import core.stdc.stdio : perror;
        perror(linkName.toStringz);
        return 1;
    }
    return 0;
}

noreturn void usage(string prog) {
    stderr.writefln(
        "ln - make links between files\n\n" ~
        "Usage:\n" ~
        "  %s [OPTIONS] file... TARGET\n\n" ~
        "Options:\n" ~
        "  -f, --force     Remove existing destination paths to allow the link\n" ~
        "  -s, --symbolic  Create symbolic links instead of hard links\n" ~
        "  -h, --help      Show this help and exit",
        prog
    );
    exit(1);
}

extern(C) int main(int argc, char** argv) {
    string[] args;
    args.length = argc;
    foreach (i; 0 .. argc) args[i] = argv[i].to!string;

    Options opt;
    bool showHelp = false;

    GetoptResult res = getopt(
        args,
        "f|force",    &opt.force,
        "s|symbolic", &opt.symbolic,
        "h|help",     &showHelp
    );

    if (showHelp) {
        defaultGetoptPrinter("ln - make links between files", res.options);
        writeln("\nUsage:\n  ", args[0], " [OPTIONS] file... TARGET");
        return 0;
    }

    auto positional = res.args;
    if (positional.length < 2) {
        usage(args[0]);
    }

    // TARGET is the last positional
    auto target = positional[$-1];
    auto sources = positional[0 .. $-1];

    // Decide form: if TARGET is an existing directory, we’re in N->dir form.
    // Otherwise we require exactly 1 source.
    bool targetIsDir = FS.isDir(target);

    int exitStatus = 0;

    if (targetIsDir) {
        foreach (src; sources) {
            auto base = baseName(src);
            auto dest = buildPath(target, base);
            exitStatus |= doLink(opt, src, dest);
        }
    } else {
        if (sources.length != 1) {
            stderr.writeln(PFX ~ "too many arguments, when target is not directory");
            return 1;
        }
        exitStatus |= doLink(opt, sources[0], target);
    }

    return exitStatus ? 1 : 0;
}
