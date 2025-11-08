/**
 * D port of:
 *   cat - concatenate files and print on the standard output
 *
 * Options:
 *   -u   (ignored; accepted for compatibility)
 *
 * Behavior:
 *   - With no files, read from stdin.
 *   - A lone "-" reads from stdin.
 *   - Streams bytes using POSIX read/write (unbuffered).
 */

module cat_d;

import core.sys.posix.unistd : read, write, close, STDIN_FILENO, STDOUT_FILENO;
import core.sys.posix.fcntl : open, O_RDONLY;
import core.stdc.errno : errno;
import core.stdc.string : strerror;
import std.stdio : stderr, writefln;
import std.string : fromStringz;
import std.meta : AliasSeq;

enum USAGE = "Usage: %s [-u] [FILE...]\n";

private int copyFd(const(char)* srcName, int fd)
{
    ubyte[64 * 1024] buf; // 64 KiB buffer
    while (true)
    {
        auto n = read(fd, buf.ptr, buf.length);
        if (n == 0) // EOF
            break;
        if (n < 0)
        {
            // Interrupted? retry; otherwise error
            // POSIX EINTR is common, but retrying blindly is fine here.
            // If persistent error, we report and fail.
            auto msg = fromStringz(strerror(errno));
            stderr.writefln("cat: read error from %s: %s", (srcName ? fromStringz(srcName) : "<stdin>"), msg);
            return 1;
        }

        size_t off = 0;
        while (off < cast(size_t)n)
        {
            auto m = write(STDOUT_FILENO, buf.ptr + off, cast(size_t)n - off);
            if (m < 0)
            {
                auto msg = fromStringz(strerror(errno));
                stderr.writefln("cat: write error to <stdout>: %s", msg);
                return 1;
            }
            off += cast(size_t)m;
        }
    }
    return 0;
}

private int catPath(string path)
{
    // "-" or empty => stdin
    if (path.length == 0 || path == "-")
        return copyFd(null, STDIN_FILENO);

    // open file read-only
    int fd = open(path.ptr, O_RDONLY);
    if (fd < 0)
    {
        auto msg = fromStringz(strerror(errno));
        stderr.writefln("cat: cannot open %s: %s", path, msg);
        return 1;
    }

    scope (exit) close(fd);
    return copyFd(path.ptr, fd);
}

int main(string[] args)
{
    // Parse very small option set: only -u is accepted (and ignored).
    // Stop option parsing at "--".
    int status = 0;
    bool endOfOpts = false;
    string[] files;

    // Program name for usage text
    auto prog = (args.length > 0) ? args[0] : "cat";

    foreach (i, a; args[1 .. $])
    {
        if (!endOfOpts && a.length > 0 && a[0] == '-')
        {
            if (a == "--") { endOfOpts = true; continue; }
            if (a == "-") { files ~= a; continue; } // stdin as a file name

            // Clustered short options like -u (only -u is recognized)
            // If any unknown option appears, print usage and fail.
            // Accept multiple 'u' (e.g., -uu) and ignore them.
            bool bad = false;
            foreach (ch; a[1 .. $])
            {
                if (ch != 'u') { bad = true; break; }
            }
            if (bad)
            {
                stderr.writefln(USAGE, prog);
                return 1;
            }
            // all 'u' -> ignored
            continue;
        }
        else
        {
            files ~= a;
        }
    }

    // If no files, read stdin
    if (files.length == 0)
        return copyFd(null, STDIN_FILENO);

    foreach (f; files)
        status |= catPath(f);

    return status != 0 ? 1 : 0;
}
