// split.d — D translation of the provided POSIX utils "split"
module split_d;

version (OSX) {} // parity with original guards

import core.stdc.stdio : perror;
import core.stdc.string : strerror;
import core.stdc.errno : errno;
import core.sys.posix.unistd : write, close, STDIN_FILENO;
import core.sys.posix.fcntl : open, O_WRONLY, O_CREAT, O_TRUNC;
import core.sys.posix.sys.stat : mode_t;
import std.stdio : File, stdin, readln, stdout;
import std.getopt : getopt, GetoptResult;
import std.string : toStringz, lastIndexOf;
import std.conv : to, parse;
import std.algorithm : clamp;
import std.array : appender;
import std.exception : enforce;

// ----------------------------- Types & options -----------------------------

enum PieceMode { none, byByte, byLine }

__gshared int        optSuffixLen  = 2;
__gshared ulong      optPieceSize  = 1000;   // bytes in byByte mode, lines in byLine mode
__gshared PieceMode  optMode       = PieceMode.byLine;
__gshared string     optPrefix     = "x";
__gshared string     optInputFn;             // "" or "-" => stdin

// runtime state
__gshared string suffix;
__gshared ulong  outCount = 0;               // bytes written in current piece (byByte) or lines (byLine)
__gshared int    outFd    = -1;
__gshared string outFn;

// I/O buffer
enum BUF_SZ = 8192;
__gshared ubyte[BUF_SZ] inBuf;

// NAME_MAX (fallback 255 if not available)
enum NAME_MAX = 255;

// ----------------------------- Helpers -----------------------------

// naive path split (for prefix length check)
struct PathElem { string dirn; string basen; }
PathElem pathSplit(string p) {
    auto s = p;
    while (s.length > 1 && s[$-1] == '/') s = s[0 .. $-1];
    if (s == "/") return PathElem("/", "/");
    auto idx = cast(ptrdiff_t) s.lastIndexOf('/');
    if (idx < 0) return PathElem(".", s);
    auto d = s[0 .. idx];
    if (d.length == 0) d = "/";
    auto b = s[idx + 1 .. $];
    return PathElem(d, b);
}

// write all bytes, returning 0 on success, 1 on error (and perror)
int writeAll(int fd, const(void)* buf, size_t len, string fnForErr) {
    auto p = cast(const(ubyte)*) buf;
    size_t rem = len;
    while (rem > 0) {
        auto n = write(fd, p, rem);
        if (n < 0) {
            perror(fnForErr.toStringz);
            return 1;
        }
        p += cast(size_t)n;
        rem -= cast(size_t)n;
    }
    return 0;
}

int incrSuffix() {
    if (suffix.length == 0) {
        suffix = string.init ~ "";
        suffix.length = optSuffixLen;
        suffix[] = 'a';
        return 0;
    }
    for (long i = optSuffixLen - 1; i >= 0; --i) {
        if (suffix[i] != 'z') {
            suffix[i] = cast(char)(suffix[i] + 1);
            return 0;
        }
        suffix[i] = 'a';
    }
    return 1; // overflow
}

int openOutput() {
    if (outFd >= 0) return 0;

    if (incrSuffix() != 0) return 1;

    enforce(outFn.length == 0);
    outFn = optPrefix ~ suffix;

    // 0666 (respect umask)
    int fd = open(outFn.toStringz, O_WRONLY | O_CREAT | O_TRUNC, cast(mode_t)0o666);
    if (fd < 0) {
        perror(outFn.toStringz);
        return 1;
    }
    outFd = fd;
    return 0;
}

int closeOutput() {
    int rc = 0;
    if (outFd < 0) return 0;
    if (close(outFd) < 0) {
        perror(outFn.toStringz);
        rc = 1;
    }
    outFd = -1;
    outFn = "";
    outCount = 0;
    return rc;
}

// for byByte mode: increments by bytes; for byLine mode: by lines (call with incr=1 per line)
int incrOutput(ulong incr) {
    outCount += incr;
    enforce(outCount <= optPieceSize);
    if (outCount == optPieceSize) {
        return closeOutput();
    }
    return 0;
}

int outputBytes(const(ubyte)[] data) {
    size_t off = 0;
    while (off < data.length) {
        if (openOutput() != 0) return 1;

        auto dist = optPieceSize - outCount;          // remaining bytes in this piece
        auto wlen = cast(size_t) (dist < (data.length - off) ? dist : (data.length - off));
        if (wlen == 0) wlen = cast(size_t) (data.length - off); // (shouldn't happen)

        if (writeAll(outFd, data.ptr + off, wlen, outFn) != 0) return 1;
        off += wlen;

        if (incrOutput(wlen) != 0) return 1;
    }
    return 0;
}

int outputLine(string s) {
    if (openOutput() != 0) return 1;
    // write the line as-is (readln preserves newline if present)
    if (writeAll(outFd, s.ptr, s.length, outFn) != 0) return 1;
    return incrOutput(1);
}

// ----------------------------- Workhorses -----------------------------

int splitBytes(File f) {
    // Read raw blocks and forward to outputBytes
    while (true) {
        size_t n = 0;
        try {
            n = f.rawRead(inBuf[]).length;
        } catch (Exception) {
            // I/O error reading input
            perror("(input)".toStringz);
            return 1;
        }
        if (n == 0) break; // EOF
        if (outputBytes(inBuf[0 .. n]) != 0) return 1;
    }
    return 0;
}

int splitLines(File f) {
    // Read line-by-line; D's readln includes the newline when present
    while (true) {
        string s;
        try {
            s = f.readln();
        } catch (Exception) {
            // EOF or read error; if truly EOF we get empty + eof
            if (f.eof) break;
            perror("(input)".toStringz);
            return 1;
        }
        if (s.length == 0 && f.eof) break;
        if (outputLine(s) != 0) return 1;
    }
    return 0;
}

int executeSplit() {
    int rc = 0;

    // Open input
    bool closeIn = false;
    File inF;
    if (optInputFn.length == 0 || optInputFn == "-") {
        inF = stdin;
    } else {
        try {
            inF = File(optInputFn, "rb");
            closeIn = true;
        } catch (Exception) {
            perror(optInputFn.toStringz);
            return 1;
        }
    }

    // Do the split
    final switch (optMode) {
        case PieceMode.byByte:
            rc = splitBytes(inF);
            break;
        case PieceMode.byLine:
            rc = splitLines(inF);
            break;
        default:
            rc = 1; // unreachable in normal use
            break;
    }

    // Close input
    if (closeIn) {
        try { inF.close(); } catch (Exception) {}
    }

    // Close last output if open
    rc |= closeOutput();
    return rc;
}

// ----------------------------- Main -----------------------------

int main(string[] args) {
    // Usage: split [-a N] [-b N[km]] [-l N] [file [prefix]]
    string aArg, bArg, lArg;

    auto r = getopt(args,
        "a", &aArg,       // suffix length
        "b", &bArg,       // bytes per piece (k/m suffix)
        "l", &lArg        // lines per piece
    );

    if (r == GetoptResult.helpWanted) {
        import std.stdio : writeln;
        writeln("split - split a file into pieces");
        writeln("usage: ", (args.length ? args[0] : "split"),
                " [-a N] [-b N[km]] [-l N] [file [prefix]]");
        return 0;
    }
    if (!r) {
        import std.stdio : writeln;
        writeln("invalid options");
        return 2;
    }

    // -a N
    if (aArg.length) {
        int tmp;
        try tmp = aArg.to!int; catch (Exception) { return 2; }
        if (tmp < 1 || tmp >= NAME_MAX) return 2;
        optSuffixLen = tmp;
    }

    // -b N[km]
    if (bArg.length) {
        ulong base = 0;
        char suffix = '\0';
        // parse number and optional unit
        // Accept forms like "1024", "10k", "5m"
        try {
            // Split numeric prefix and optional unit char
            // Find first non-digit
            size_t i = 0;
            while (i < bArg.length && bArg[i] >= '0' && bArg[i] <= '9') ++i;
            enforce(i > 0);
            base = bArg[0 .. i].to!ulong;
            if (i < bArg.length) suffix = cast(char) bArg[i];
        } catch (Exception) {
            return 2;
        }

        ulong mult = 1;
        final switch (cast(char)(suffix | 0x20)) { // tolower
            case 'k': mult = 1024; break;
            case 'm': mult = 1024UL * 1024UL; break;
            case '\0': mult = 1; break;
            default: return 2;
        }

        if (base < 1) return 2;
        optMode = PieceMode.byByte;
        optPieceSize = base * mult;
    }

    // -l N
    if (lArg.length) {
        ulong n;
        try n = lArg.to!ulong; catch (Exception) { return 2; }
        if (n < 1) return 2;
        optMode = PieceMode.byLine;
        optPieceSize = n;
    }

    // Positional args: [file [prefix]]
    auto pos = args[r.index .. $];
    if (pos.length >= 1) optInputFn = pos[0];
    if (pos.length >= 2) optPrefix  = pos[1];
    if (pos.length >  2) {
        import std.stdio : writeln;
        writeln("too many arguments");
        return 2;
    }

    // prefix + suffix length must fit in NAME_MAX
    auto pe = pathSplit(optPrefix);
    if (pe.basen.length + optSuffixLen > NAME_MAX) {
        import std.stdio : writeln;
        writeln("prefix + suffix too large");
        return 1;
    }

    return executeSplit();
}
