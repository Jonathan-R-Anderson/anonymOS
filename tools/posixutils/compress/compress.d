/**
 * D port of BSD compress(1) / uncompress(1) / zcat(1) front-end
 *
 * Flags:
 *   -b bits   (pass to compressor)
 *   -c        write to stdout (cat mode)
 *   -d        decompress (back-compat)
 *   -f        force (suppress prompt / overwrite / keep even if grows)
 *   -v        verbose
 *
 * Invocation by program name:
 *   "compress"   => default compress
 *   "uncompress" => default decompress
 *   "zcat"       => decompress to stdout (implies -c)
 *
 * Requires a lib that provides "zopen.h" API:
 *   void* compress_zopen(const char* path, const char* mode, int bits);
 *   size_t compress_zread(void* zfp, void* buf, size_t n);
 *   size_t compress_zwrite(void* zfp, const void* buf, size_t n);
 *   int compress_zclose(void* zfp);
 */

module compress_d;

import core.stdc.stdlib : exit, strtol;
import core.stdc.string : strcmp, strlen, memmove, strrchr;
import core.stdc.errno : errno, EPERM, EOPNOTSUPP;
import core.sys.posix.sys.stat : stat, stat_t = stat, fstat, S_ISREG, chmod, chown, S_ISUID, S_ISGID,
                                 S_IRWXU, S_IRWXG, S_IRWXO;
import core.sys.posix.utime : utimbuf, utime;
import core.sys.posix.unistd : unlink, isatty;
import std.stdio : File, stdin, stdout, stderr;
import std.getopt : getopt, config;
import std.string : toStringz, fromStringz;
import std.path : baseName;
import std.conv : to;
import std.algorithm : min;
import std.math : isFinite;

// ---- zopen.h bindings -------------------------------------------------------

extern(C):
void*  compress_zopen(const char* path, const char* mode, int bits);
size_t compress_zread(void* zfp, void* buf, size_t n);
size_t compress_zwrite(void* zfp, const void* buf, size_t n);
int    compress_zclose(void* zfp);

// ---- globals ---------------------------------------------------------------

int eval_;     // exit code accumulator (set to 1 on warnings)
int force_;    // -f
int verbose_;  // -v

// ---- helpers ---------------------------------------------------------------

private void cwarnx(const(char)* fmt, const(char)* a = null)
{
    import std.stdio : writefln;
    if (a is null)
        stderr.writeln(fromStringz(fmt));
    else
        stderr.writefln("%s", fromStringz(fmt).replace("%s", fromStringz(a)));
    eval_ = 1;
}

private void cwarn(const(char)* fmt, const(char)* a = null)
{
    import std.stdio : writefln;
    import core.stdc.string : strerror;
    auto emsg = fromStringz(strerror(errno));
    if (a is null)
        stderr.writefln("%s: %s", fromStringz(fmt), emsg);
    else
        stderr.writefln("%s: %s", fromStringz(a), emsg);
    eval_ = 1;
}

private void setfile(const(char)* name, stat_t* fs)
{
    // Preserve times
    utimbuf utb;
    utb.actime  = fs.st_atime;
    utb.modtime = fs.st_mtime;
    if (utime(name, &utb) != 0)
        cwarn("utimes", name);

    // Preserve ownership (clear suid/sgid on failure)
    // Keep only permission bits + suid/sgid
    auto mode = fs.st_mode & (S_ISUID | S_ISGID | S_IRWXU | S_IRWXG | S_IRWXO);
    if (chown(name, fs.st_uid, fs.st_gid) != 0) {
        if (errno != EPERM)
            cwarn("chown", name);
        mode &= ~(S_ISUID | S_ISGID);
    }
    if (chmod(name, mode) != 0 && errno != EOPNOTSUPP)
        cwarn("chmod", name);
}

private int permission(const(char)* fname)
{
    // Only prompt if stderr is a TTY and not forced
    import core.stdc.stdio : getchar, fileno, stderr;
    if (!isatty(fileno(stderr)))
        return 0;
    stderr.writefln("overwrite %s? ", fromStringz(fname));
    auto first = getchar();
    int ch;
    do { ch = getchar(); } while (ch != '\n' && ch != -1);
    return (first == 'y');
}

// ---- I/O cores -------------------------------------------------------------

private void compressOne(const(char)* in, const(char)* out, int bits)
{
    enum BUFSZ = 1024;
    ubyte[BUFSZ] buf;

    stat_t osb; bool exists = (stat(out, &osb) == 0);
    if (!force_ && exists && S_ISREG(osb.st_mode) && !permission(out))
        return;
    bool oreg = !exists || S_ISREG(osb.st_mode);
    bool isreg = oreg;

    File ifp;
    void* zfp = null;
    scope(exit)
    {
        if (zfp !is null) {
            if (oreg) unlink(out);
            compress_zclose(zfp);
        }
        if (!ifp.isNull) ifp.close();
    }

    // Open input (text "r" matches original; binary vs text irrelevant on POSIX)
    try { ifp = File(fromStringz(in), "r"); }
    catch (Exception) { cwarn("%s", in); return; }

    stat_t isb;
    if (stat(in, &isb) != 0) { // don't fstat
        cwarn("%s", in);
        return;
    }
    if (!S_ISREG(isb.st_mode)) isreg = false;

    zfp = compress_zopen(out, "w", bits);
    if (zfp is null) { cwarn("%s", out); return; }

    while (true) {
        auto n = ifp.rawRead(buf[]).length;
        if (n == 0) break;
        auto wn = compress_zwrite(zfp, buf.ptr, n);
        if (wn != n) { cwarn("%s", out); return; }
    }

    // Close input first
    try { ifp.close(); ifp = File.init; }
    catch (Exception) { cwarn("%s", in); return; }

    if (compress_zclose(zfp) != 0) { zfp = null; cwarn("%s", out); return; }
    zfp = null;

    if (isreg) {
        stat_t sb;
        if (stat(out, &sb) != 0) { cwarn("%s", out); return; }

        if (!force_ && sb.st_size >= isb.st_size) {
            if (verbose_)
                stderr.writefln("%s: file would grow; left unmodified", fromStringz(in));
            eval_ = 2;
            unlink(out);
            return;
        }

        setfile(out, &isb);
        if (unlink(in) != 0)
            cwarn("%s", in);

        if (verbose_) {
            stderr.writef("%s: ", fromStringz(out));
            // Print compression/expansion percent like original
            if (isb.st_size > 0 && sb.st_size > 0) {
                auto ratio = (isb.st_size > sb.st_size)
                    ? (cast(real)sb.st_size / cast(real)isb.st_size) * 100.0
                    : (cast(real)isb.st_size / cast(real)sb.st_size) * 100.0;
                if (!isFinite(ratio)) ratio = 0;
                stderr.writefln("%s%.0f%% %s",
                    "", ratio, (isb.st_size > sb.st_size) ? "compression" : "expansion");
            } else {
                stderr.writeln("0% compression");
            }
        }
    }
}

private void decompressOne(const(char)* in, const(char)* out, int bits)
{
    enum BUFSZ = 1024;
    ubyte[BUFSZ] buf;

    stat_t osb; bool exists = (stat(out, &osb) == 0);
    if (!force_ && exists && S_ISREG(osb.st_mode) && !permission(out))
        return;
    bool oreg = !exists || S_ISREG(osb.st_mode);
    bool isreg = oreg;

    void* zfp = null;
    File ofp;
    scope(exit)
    {
        if (!ofp.isNull) {
            if (oreg) unlink(out);
            ofp.close();
        }
        if (zfp !is null) compress_zclose(zfp);
    }

    zfp = compress_zopen(in, "r", bits);
    if (zfp is null) { cwarn("%s", in); return; }

    stat_t isb;
    if (stat(in, &isb) != 0) { cwarn("%s", in); return; }
    if (!S_ISREG(isb.st_mode)) isreg = false;

    // Read some bytes before truncating destination
    auto n0 = compress_zread(zfp, buf.ptr, BUFSZ);
    if (n0 == 0) {
        cwarn("%s", in);
        return;
    }

    try { ofp = File(fromStringz(out), "w"); }
    catch (Exception) { cwarn("%s", out); return; }

    if (n0 != 0) {
        auto wn = ofp.rawWrite(buf[0 .. n0]);
        if (wn.length != n0) { cwarn("%s", out); return; }
    }

    while (true) {
        auto n = compress_zread(zfp, buf.ptr, BUFSZ);
        if (n == 0) break;
        auto wn = ofp.rawWrite(buf[0 .. n]).length;
        if (wn != n) { cwarn("%s", out); return; }
    }

    if (compress_zclose(zfp) != 0) { zfp = null; cwarn("%s", in); return; }
    zfp = null;

    try { ofp.close(); ofp = File.init; }
    catch (Exception) { cwarn("%s", out); return; }

    if (isreg) {
        setfile(out, &isb);
        if (unlink(in) != 0)
            cwarn("%s", in);
    }
}

// ---- usage -----------------------------------------------------------------

private noreturn void usage(bool iscompress)
{
    if (iscompress)
        stderr.writeln("usage: compress [-cfv] [-b bits] [file ...]");
    else
        stderr.writeln("usage: uncompress [-c] [-b bits] [file ...]");
    exit(1);
}

// ---- main ------------------------------------------------------------------

int main(string[] args)
{
    enum Mode { COMPRESS, DECOMPRESS }
    auto prog = baseName(args.length ? args[0] : "compress");
    bool cat = false;
    Mode style;

    if (prog == "uncompress")       style = Mode.DECOMPRESS;
    else if (prog == "compress")    style = Mode.COMPRESS;
    else if (prog == "zcat")       { style = Mode.DECOMPRESS; cat = true; }
    else { stderr.writeln("unknown program name"); return 1; }

    int bits = 0;

    // getopt parsing (bundling allows -cfv)
    auto opt = getopt(args, config.bundling,
        "b", "bits", (string v) {
            char* endptr;
            bits = cast(int)strtol(v.toStringz, &endptr, 10);
            if (*endptr != '\0')
                { stderr.writefln("illegal bit count -- %s", v); exit(1); }
        },
        "c", "cat to stdout", (ref bool _) { cat = true; },
        "d", "decompress",    (ref bool _) { style = Mode.DECOMPRESS; },
        "f", "force",         (ref bool _) { force_ = 1; },
        "v", "verbose",       (ref bool _) { verbose_ = 1; }
    );

    auto rest = args[opt.index .. $];

    if (rest.length == 0) {
        // stdin → stdout
        final switch (style) {
            case Mode.COMPRESS:   compressOne("/dev/stdin".ptr,  "/dev/stdout".ptr, bits); break;
            case Mode.DECOMPRESS: decompressOne("/dev/stdin".ptr, "/dev/stdout".ptr, bits); break;
        }
        return eval_;
    }

    if (cat && rest.length > 1) {
        stderr.writeln("the -c option permits only a single file argument");
        return 1;
    }

    char[MAX_PATH] newnameBuf;
    foreach (arg; rest) {
        auto a = arg;

        final switch (style) {
        case Mode.COMPRESS:
            if (a == "-") {
                compressOne("/dev/stdin".ptr, "/dev/stdout".ptr, bits);
                break;
            } else if (cat) {
                compressOne(a.toStringz, "/dev/stdout".ptr, bits);
                break;
            }
            // already ends with .Z ?
            if (a.length >= 2 && a[$-2 .. $] == ".Z") {
                cwarnx("%s: name already has trailing .Z".ptr, a.toStringz);
                break;
            }
            // build "<name>.Z"
            if (a.length > newnameBuf.length - 3) {
                cwarnx("%s: name too long".ptr, a.toStringz);
                break;
            }
            // copy + suffix
            {
                import core.stdc.string : memcpy;
                memcpy(newnameBuf.ptr, a.toStringz, a.length);
                newnameBuf[a.length]   = '.';
                newnameBuf[a.length+1] = 'Z';
                newnameBuf[a.length+2] = '\0';
            }
            compressOne(a.toStringz, newnameBuf.ptr, bits);
            break;

        case Mode.DECOMPRESS:
            if (a == "-") {
                decompressOne("/dev/stdin".ptr, "/dev/stdout".ptr, bits);
                break;
            }
            // if no .Z suffix present, try "<name>.Z" -> (cat ? stdout : name)
            if (!(a.length >= 2 && a[$-2 .. $] == ".Z")) {
                if (a.length > newnameBuf.length - 3) {
                    cwarnx("%s: name too long".ptr, a.toStringz);
                    break;
                }
                import core.stdc.string : memcpy;
                memcpy(newnameBuf.ptr, a.toStringz, a.length);
                newnameBuf[a.length]   = '.';
                newnameBuf[a.length+1] = 'Z';
                newnameBuf[a.length+2] = '\0';
                decompressOne(newnameBuf.ptr, cat ? "/dev/stdout".ptr : a.toStringz, bits);
            } else {
                // strip ".Z"
                auto baseLen = a.length - 2;
                if (baseLen > newnameBuf.length - 1) {
                    cwarnx("%s: name too long".ptr, a.toStringz);
                    break;
                }
                import core.stdc.string : memcpy;
                memcpy(newnameBuf.ptr, a.toStringz, baseLen);
                newnameBuf[baseLen] = '\0';
                decompressOne(a.toStringz, cat ? "/dev/stdout".ptr : newnameBuf.ptr, bits);
            }
            break;
        }
    }

    return eval_;
}
