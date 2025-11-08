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
 *   void*  compress_zopen(const char* path, const char* mode, int bits);
 *   size_t compress_zread(void* zfp, void* buf, size_t n);
 *   size_t compress_zwrite(void* zfp, const void* buf, size_t n);
 *   int    compress_zclose(void* zfp);
 */

module compress_d;

import core.stdc.stdlib  : exit;
import core.stdc.string  : strcmp, strlen, memmove, strrchr;
import core.stdc.errno   : errno, EPERM, EOPNOTSUPP;
import core.sys.posix.sys.stat : stat_t, stat, fstat, S_ISREG, chmod,
                                 S_ISUID, S_ISGID, S_IRWXU, S_IRWXG, S_IRWXO;
import core.sys.posix.utime    : utimbuf, utime;
import core.sys.posix.unistd   : unlink, isatty, chown;
import std.stdio        : File, stdin, stdout, stderr, writef, writefln, writeln;
import std.getopt       : getopt, config;
import std.string       : toStringz, fromStringz, replace;
import std.path         : baseName;
import std.conv         : to, ConvException;
import std.algorithm    : min;
import std.math         : isFinite;

// ---- zopen.h bindings -------------------------------------------------------

extern(C)
{
void*  compress_zopen(const char* path, const char* mode, int bits);
size_t compress_zread(void* zfp, void* buf, size_t n);
size_t compress_zwrite(void* zfp, const void* buf, size_t n);
int    compress_zclose(void* zfp);
}

// ---- globals ---------------------------------------------------------------

int eval_;     // exit code accumulator (set to 1 on warnings, 2 if would-grow)
int force_;    // -f
int verbose_;  // -v

// ---- helpers ---------------------------------------------------------------

private void cwarnx(const(char)* fmt, const(char)* a = null)
{
    if (a is null)
        stderr.writeln(fromStringz(fmt));
    else
        stderr.writefln("%s", fromStringz(fmt).replace("%s", fromStringz(a)));
    eval_ = 1;
}

private void cwarn(const(char)* fmt, const(char)* a = null)
{
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
    import core.stdc.stdio : getchar; // only need getchar from C stdio
    // Only prompt if stderr is a TTY and not forced
    if (!isatty(stderr.fileno))
        return 0;
    stderr.writefln("overwrite %s? ", fromStringz(fname));
    auto first = getchar();
    int ch;
    do { ch = getchar(); } while (ch != '\n' && ch != -1);
    return (first == 'y');
}

// ---- I/O cores -------------------------------------------------------------

private void compressOne(const(char)* inPath, const(char)* outPath, int bits)
{
    enum BUFSZ = 1024;
    ubyte[BUFSZ] buf;

    stat_t osb; bool exists = (stat(outPath, &osb) == 0);
    if (!force_ && exists && S_ISREG(osb.st_mode) && !permission(outPath))
        return;
    bool oreg = !exists || S_ISREG(osb.st_mode);
    bool isreg = oreg;

    File ifp;
    void* zfp = null;
    scope(exit)
    {
        if (zfp !is null) {
            if (oreg) unlink(outPath);
            compress_zclose(zfp);
        }
        if (ifp.isOpen) ifp.close();
    }

    // Open input (text "r" matches original; binary vs text irrelevant on POSIX)
    try { ifp = File(fromStringz(inPath), "r"); }
    catch (Exception) { cwarn("%s", inPath); return; }

    stat_t isb;
    if (stat(inPath, &isb) != 0) { // don't fstat
        cwarn("%s", inPath);
        return;
    }
    if (!S_ISREG(isb.st_mode)) isreg = false;

    zfp = compress_zopen(outPath, "w", bits);
    if (zfp is null) { cwarn("%s", outPath); return; }

    while (true) {
        auto chunk = ifp.rawRead(buf[]);
        if (chunk.length == 0) break;
        auto wn = compress_zwrite(zfp, buf.ptr, chunk.length);
        if (wn != chunk.length) { cwarn("%s", outPath); return; }
    }

    // Close input first
    try { ifp.close(); ifp = File.init; }
    catch (Exception) { cwarn("%s", inPath); return; }

    if (compress_zclose(zfp) != 0) { zfp = null; cwarn("%s", outPath); return; }
    zfp = null;

    if (isreg) {
        stat_t sb;
        if (stat(outPath, &sb) != 0) { cwarn("%s", outPath); return; }

        if (!force_ && sb.st_size >= isb.st_size) {
            if (verbose_)
                stderr.writefln("%s: file would grow; left unmodified", fromStringz(inPath));
            eval_ = 2;
            unlink(outPath);
            return;
        }

        setfile(outPath, &isb);
        if (unlink(inPath) != 0)
            cwarn("%s", inPath);

        if (verbose_) {
            stderr.writef("%s: ", fromStringz(outPath));
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

private void decompressOne(const(char)* inPath, const(char)* outPath, int bits)
{
    enum BUFSZ = 1024;
    ubyte[BUFSZ] buf;

    stat_t osb; bool exists = (stat(outPath, &osb) == 0);
    if (!force_ && exists && S_ISREG(osb.st_mode) && !permission(outPath))
        return;
    bool oreg = !exists || S_ISREG(osb.st_mode);
    bool isreg = oreg;

    void* zfp = null;
    File ofp;
    scope(exit)
    {
        if (ofp.isOpen) {
            if (oreg) unlink(outPath);
            ofp.close();
        }
        if (zfp !is null) compress_zclose(zfp);
    }

    zfp = compress_zopen(inPath, "r", bits);
    if (zfp is null) { cwarn("%s", inPath); return; }

    stat_t isb;
    if (stat(inPath, &isb) != 0) { cwarn("%s", inPath); return; }
    if (!S_ISREG(isb.st_mode)) isreg = false;

    // Read some bytes before truncating destination
    auto n0 = compress_zread(zfp, buf.ptr, BUFSZ);
    if (n0 == 0) {
        cwarn("%s", inPath);
        return;
    }

    try { ofp = File(fromStringz(outPath), "w"); }
    catch (Exception) { cwarn("%s", outPath); return; }

    if (n0 != 0)
        ofp.rawWrite(buf[0..n0]); // throws on error

    while (true) {
        auto n = compress_zread(zfp, buf.ptr, BUFSZ);
        if (n == 0) break;
        ofp.rawWrite(buf[0..n]);  // throws on error
    }

    if (compress_zclose(zfp) != 0) { zfp = null; cwarn("%s", inPath); return; }
    zfp = null;

    try { ofp.close(); ofp = File.init; }
    catch (Exception) { cwarn("%s", outPath); return; }

    if (isreg) {
        setfile(outPath, &isb);
        if (unlink(inPath) != 0)
            cwarn("%s", inPath);
    }
}

// ---- usage -----------------------------------------------------------------

private void usage(bool iscompress)
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
            try {
                bits = to!int(v);
            } catch (ConvException) {
                stderr.writefln("illegal bit count -- %s", v);
                exit(1);
            }
        },
        "c", "cat to stdout", (ref bool _) { cat = true; },
        "d", "decompress",    (ref bool _) { style = Mode.DECOMPRESS; },
        "f", "force",         (ref bool _) { force_ = 1; },
        "v", "verbose",       (ref bool _) { verbose_ = 1; }
    );

    auto rest = args[opt.optind .. $];

    if (rest.length == 0) {
        // stdin → stdout
        final switch (style) {
            case Mode.COMPRESS:   compressOne(toStringz("/dev/stdin"),  toStringz("/dev/stdout"), bits); break;
            case Mode.DECOMPRESS: decompressOne(toStringz("/dev/stdin"), toStringz("/dev/stdout"), bits); break;
        }
        return eval_;
    }

    if (cat && rest.length > 1) {
        stderr.writeln("the -c option permits only a single file argument");
        return 1;
    }

    char[4096] newnameBuf;
    foreach (arg; rest) {
        auto a = arg;

        final switch (style) {
        case Mode.COMPRESS:
            if (a == "-") {
                compressOne(toStringz("/dev/stdin"), toStringz("/dev/stdout"), bits);
                break;
            } else if (cat) {
                compressOne(a.toStringz, toStringz("/dev/stdout"), bits);
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
                decompressOne(toStringz("/dev/stdin"), toStringz("/dev/stdout"), bits);
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
                decompressOne(newnameBuf.ptr, cat ? toStringz("/dev/stdout") : a.toStringz, bits);
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
                decompressOne(a.toStringz, cat ? toStringz("/dev/stdout") : newnameBuf.ptr, bits);
            }
            break;
        }
    }

    return eval_;
}
