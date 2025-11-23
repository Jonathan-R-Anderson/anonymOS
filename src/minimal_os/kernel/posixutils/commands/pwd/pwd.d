// pwd.d
module pwd;

import core.stdc.stdlib : getenv, exit;
import core.stdc.stdio : printf, fprintf, perror, stderr;
import core.stdc.string : strlen;
import core.stdc.errno : errno, ERANGE;
import core.sys.posix.unistd : getcwd;
import std.string : toStringz, startsWith, split, lastIndexOf;
import std.conv : to;

// ----------------- Options / modes -----------------
enum PwdMode : int { envLogical, physical }
__gshared PwdMode optMode = PwdMode.envLogical;

// ----------------- Path utilities ------------------
struct PathElem { string dirn; string basen; }

// Simple path split akin to dirname/basename
PathElem pathSplit(string path)
{
    auto p = path;
    if (p.length == 0) return PathElem(".", "");
    // strip trailing slashes (but leave root "/")
    while (p.length > 1 && p[$-1] == '/') p = p[0 .. $-1];
    if (p == "/") return PathElem("/", "/");

    auto idx = lastIndexOf(p, '/'); // returns ptrdiff_t, -1 if not found
    if (idx < 0) return PathElem(".", p);
    auto d = p[0 .. idx];
    if (d.length == 0) d = "/";
    auto b = p[idx + 1 .. $];
    return PathElem(d, b);
}

// Return true if any component is "." or ".."
bool hasDotComponents(string path)
{
    if (path.length == 0) return false;
    // Normalize: collapse multiple slashes by simple filtering at split time
    foreach (comp; path.split('/'))
    {
        if (comp.length == 0) continue; // skip empty (from '//' or leading '/')
        if (comp == "." || comp == "..")
            return true;
    }
    return false;
}

// Validate PWD candidate: must be absolute and contain no "." or ".." components
bool pwdValid(string path)
{
    if (path == "/") return true;
    if (!path.startsWith("/")) return false;
    if (hasDotComponents(path)) return false;

    // Original code recursed through components; the check above is equivalent.
    return true;
}

// Growable getcwd (physical path)
string xgetcwd()
{
    size_t len = 256;
    string buf;
    buf.length = len; // allocate

    while (true)
    {
        auto cptr = getcwd(cast(char*)buf.ptr, len);
        if (cptr !is null)
        {
            // C string => D string
            // Find terminating NUL
            size_t n = 0;
            while (n < len && buf.ptr[n] != 0) ++n;
            return buf[0 .. n].idup;
        }

        if (errno != ERANGE)
        {
            perror("getcwd(3) failed".toStringz);
            exit(1);
        }

        // enlarge and retry
        len <<= 1;
        buf.length = len;
    }
}

// ----------------- Minimal option parsing -----------------
/*
 * Supports:
 *   -L  logical (default)
 *   -P  physical
 *   --  to end options
 */
void parseOptions(ref size_t argi, string[] args)
{
    argi = 1;
    while (argi < args.length)
    {
        auto a = args[argi];
        if (a == "--") { ++argi; break; }
        if (a.length >= 2 && a[0] == '-' && a != "-")
        {
            foreach (i, ch; a[1 .. $])
            {
                // Use regular switch here (not 'final switch') so default is allowed
                switch (ch)
                {
                    case 'L': optMode = PwdMode.envLogical; break;
                    case 'P': optMode = PwdMode.physical;  break;
                    default:
                        fprintf(stderr,
                                "pwd: unknown option -%c\n".toStringz, ch);
                        exit(2);
                }
            }
            ++argi;
        }
        else break; // first non-option
    }
}

// ----------------- Main -----------------
int main(string[] args)
{
    size_t argi;
    parseOptions(argi, args);

    // POSIX: pwd takes no non-option operands
    if (argi < args.length)
    {
        fprintf(stderr, "usage: %s [-L|-P]\n".toStringz, args[0].toStringz);
        return 2;
    }

    const(char)* outCStr = null;

    if (optMode == PwdMode.envLogical)
    {
        auto pwdEnv = getenv("PWD");
        if (pwdEnv !is null)
        {
            auto pwdStr = to!string(pwdEnv);
            if (pwdValid(pwdStr))
            {
                outCStr = pwdStr.toStringz;
            }
        }
    }

    // If logical path not acceptable or -P requested, use physical
    if (outCStr is null)
    {
        auto phys = xgetcwd();         // returns D string
        outCStr = phys.toStringz;      // safe: we print immediately
        printf("%s\n", outCStr);
        return 0;
    }

    printf("%s\n", outCStr);
    return 0;
}
