// pathchk.d
module pathchk;

import core.stdc.stdlib : exit;
import core.stdc.stdio : fprintf, perror, stderr;
import core.stdc.string : strlen;
import core.stdc.errno : errno;
import core.sys.posix.unistd : pathconf, _PC_PATH_MAX, _PC_NAME_MAX;
import core.sys.posix.sys.stat : stat_t, lstat; // <- use stat_t (type) and lstat (func)
import std.string : toStringz, startsWith, endsWith;

// POSIX minimums for "portable" mode (per POSIX)
enum size_t POSIX_PATH_MAX_MIN = 256;
enum size_t POSIX_NAME_MAX_MIN = 14;

enum int PATHCHK_ERR = 1;

__gshared bool   optPortable = false;
// Start with POSIX minima; overwrite with pathconf() when not in -p mode.
__gshared size_t gPathMax = POSIX_PATH_MAX_MIN;
__gshared size_t gNameMax = POSIX_NAME_MAX_MIN;

// -------- Portable filename character set (POSIX) --------
// upper/lower letters, digits, period, underscore, hyphen
bool isPortableChar(char c) @safe @nogc nothrow
{
    return  (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            (c == '.') || (c == '_') || (c == '-');
}

// -------- path element split (dirname/basename) ----------
struct PathElem { string dirn; string basen; }

// Similar to GNU basename/dirname logic (simple version).
PathElem pathSplit(string path)
{
    auto p = path;
    if (p.length == 0) return PathElem(".", "");
    // Strip trailing slashes (except for "/")
    while (p.length > 1 && p.endsWith("/")) p = p[0 .. $-1];

    // If now a single slash
    if (p == "/") return PathElem("/", "/");

    // Find last '/'
    long idx = -1;
    for (long i = cast(long)p.length - 1; i >= 0; --i)
    {
        if (p[cast(size_t)i] == '/')
        {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        return PathElem(".", p); // no slash
    }

    auto d = p[0 .. cast(size_t)idx]; // up to but not including '/'
    if (d.length == 0) d = "/";
    auto b = p[cast(size_t)idx + 1 .. $];
    return PathElem(d, b);
}

// Recursively find a filesystem handle that exists (like original find_fshandle)
string findFSHandle(string path)
{
    stat_t stbuf; // <- stat_t, not stat
    if (lstat(path.toStringz, &stbuf) == 0 || path == "/" || path == ".")
        return path;

    auto pe = pathSplit(path);
    return findFSHandle(pe.dirn);
}

// Check a single path component name
int checkComponent(string basen)
{
    auto blen = basen.length; // bytes (UTF-8)
    if (blen > gNameMax) {
        fprintf(stderr, "component %s: length %zu exceeds limit %zu\n".toStringz,
                basen.toStringz, blen, gNameMax);
        return 1;
    }

    if (optPortable) {
        foreach (c; basen) {
            if (!isPortableChar(c)) {
                fprintf(stderr, "component %s contains non-portable char\n".toStringz,
                        basen.toStringz);
                return 1;
            }
        }
    }
    return 0;
}

// Recursively check all components in a path
int checkPath(string path)
{
    auto pe = pathSplit(path);
    int rc = checkComponent(pe.basen);
    if (rc == 0 && pe.dirn != "/" && pe.dirn != ".")
        rc |= checkPath(pe.dirn);
    return rc;
}

// Per-argument actor
int pathchkActor(string fn)
{
    if (optPortable) {
        gPathMax = POSIX_PATH_MAX_MIN;
        gNameMax = POSIX_NAME_MAX_MIN;
    } else {
        string fsh = findFSHandle(fn);

        // pathconf for PATH_MAX
        auto l1 = pathconf(fsh.toStringz, _PC_PATH_MAX);
        if (l1 < 0) {
            perror(fsh.toStringz);
            return 1;
        }
        gPathMax = cast(size_t) l1;

        // pathconf for NAME_MAX
        auto l2 = pathconf(fsh.toStringz, _PC_NAME_MAX);
        if (l2 < 0) {
            perror(fsh.toStringz);
            return 1;
        }
        gNameMax = cast(size_t) l2;
    }

    if (fn.length > gPathMax) {
        fprintf(stderr, "%s: path length %zu exceeds limit %zu\n".toStringz,
                fn.toStringz, fn.length, gPathMax);
        return 1;
    }

    return checkPath(fn);
}

// Simple option parser: supports -p and --
// Usage: pathchk [-p] pathname...
int main(string[] args)
{
    if (args.length < 2) {
        fprintf(stderr, "pathchk - check whether file names are valid or portable\n".toStringz);
        fprintf(stderr, "usage: %s [-p] pathname...\n".toStringz, args[0].toStringz);
        return PATHCHK_ERR;
    }

    size_t i = 1;
    for (; i < args.length; ++i) {
        auto a = args[i];
        if (a == "--") { ++i; break; }
        if (a.length >= 2 && a[0] == '-' && a != "-") {
            if (a == "-p") {
                optPortable = true;
                continue;
            } else {
                fprintf(stderr, "unknown option: %s\n".toStringz, a.toStringz);
                return PATHCHK_ERR;
            }
        } else {
            break; // first non-option
        }
    }

    if (i >= args.length) {
        fprintf(stderr, "pathchk: no pathnames provided\n".toStringz);
        return PATHCHK_ERR;
    }

    int rc = 0;
    for (; i < args.length; ++i) {
        rc |= pathchkActor(args[i]);
    }
    return rc;
}
