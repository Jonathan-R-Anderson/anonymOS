// rmdir.d — D translation of the given rmdir(1) implementation
module rmdir_d;

import core.stdc.stdio : fprintf, stderr, perror;
import core.sys.posix.unistd : rmdir;
import std.string : toStringz, lastIndexOf;

// ----- options -----
__gshared bool optParents = false;

// ----- helpers -----
int doRmdir(string fn)
{
    if (rmdir(fn.toStringz) < 0) {
        perror(fn.toStringz);
        return 1;
    }
    return 0;
}

// POSIX-like dirname behavior (returns parent directory path for `p`)
// - collapses trailing slashes
// - root ("/") stays "/"
// - returns "" when there's no further parent (so caller can stop)
string dirnameOnce(string p)
{
    if (p.length == 0) return "";
    // strip trailing slashes (but keep root)
    while (p.length > 1 && p[$-1] == '/') p = p[0 .. $-1];
    if (p == "/") return "/";

    auto idx = p.lastIndexOf('/');
    if (idx < 0) return "";          // no slash -> stop
    if (idx == 0) return "/";        // "/name" -> "/"
    return p[0 .. idx];              // "dir/base" -> "dir"
}

// ----- main -----
int main(string[] args)
{
    if (args.length < 2) {
        fprintf(stderr, "rmdir - remove empty directories\n");
        fprintf(stderr, "usage: %s [-p] dir...\n", args[0].toStringz);
        return 2;
    }

    // parse options
    size_t i = 1;
    while (i < args.length) {
        auto a = args[i];
        if (a == "--") { ++i; break; }
        if (a.length >= 2 && a[0] == '-' && a != "-") {
            foreach (ch; a[1 .. $]) {
                switch (ch) {
                    case 'p':
                        optParents = true;
                        break;
                    default:
                        fprintf(stderr, "rmdir: unknown option -%c\n", ch);
                        return 2;
                }
            }
            ++i;
        } else break;
    }

    if (i >= args.length) {
        fprintf(stderr, "rmdir: missing operand\n");
        return 2;
    }

    int rc = 0;

    for (; i < args.length; ++i) {
        auto path = args[i];

        int r = doRmdir(path);
        rc |= r;

        if (r != 0 || !optParents)
            continue;

        // Remove parents upward until root or a removal fails
        auto dn = path;
        while (true) {
            dn = dirnameOnce(dn);
            if (dn.length == 0 || dn == "/") {
                // Stop at empty or root (root not removed)
                break;
            }
            r = doRmdir(dn);
            if (r != 0) { rc |= r; break; }
        }
    }

    return rc;
}
