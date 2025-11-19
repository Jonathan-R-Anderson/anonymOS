/+
  strings.d — D port of “strings - find printable strings in files”
  Original C: (c) 2004–2006 Jeff Garzik (GPL-2.0)
+/
module strings;

import std.stdio;
import std.file;
import std.getopt : getopt, config;
import std.conv;
import std.exception;
import std.string;
import core.sys.posix.sys.types : off_t;

enum BUFLEN = 8192;

enum OptPrefix {
    none,
    decimal,
    octal,
    hex_
}

struct BufState {
    ubyte[BUFLEN] buf;
    size_t used = 0;       // bytes currently in buffer
    off_t offset = 0;      // absolute file offset corresponding to buf[0]
}

static:
uint      optStrLen  = 4;
OptPrefix optPrefix  = OptPrefix.none;

bool isPrintable(ubyte c) @nogc @safe pure nothrow {
    // ASCII printable (space through ~), like C’s isprint() for bytes
    return c >= 32 && c < 127;
}

// Accept a const view (no ref needed so mutable slices can bind).
ptrdiff_t findSep(const(ubyte)[] s) @safe nothrow {
    // return index of first '\n' or '\0', or -1 if none
    foreach (i, b; s) {
        if (b == 0 || b == '\n')
            return cast(ptrdiff_t)i;
    }
    return -1;
}

void printString(scope const(char)[] s, long startOffset) {
    final switch (optPrefix) {
        case OptPrefix.none:
            writeln(s);
            break;
        case OptPrefix.decimal:
            writef("%d ", startOffset);
            writeln(s);
            break;
        case OptPrefix.octal:
            writef("%o ", startOffset);
            writeln(s);
            break;
        case OptPrefix.hex_:
            writef("%x ", startOffset);
            writeln(s);
            break;
    }
}

bool processBuffer(ref BufState st) {
    // Returns true to stop early (on write error), false to continue
    size_t p   = 0;          // current window start index within st.buf[0..used)
    size_t len = st.used;    // remaining length from p

    while (true) {
        auto window = st.buf[p .. p + len];
        auto sepIdx = findSep(window);
        if (sepIdx < 0) {
            // No separator in current window.
            if (len > BUFLEN / 2) {
                // If window is too big, slide it forward by half.
                const diff = len - (BUFLEN / 2);
                p   += diff;
                len -= diff;

                // Slide buffer contents to front (memmove-equivalent)
                () @trusted { st.buf[0 .. len] = st.buf[p .. p + len]; }();
                st.used   = len;
                st.offset += cast(off_t)p;   // absolute offset advanced by p bytes
            }
            // Need more data either way.
            return false;
        }

        // “Terminate” segment at sep (temporarily treat as C-string)
        const segmentLen = cast(size_t)sepIdx; // bytes until sep

        // Count trailing printable chars up to sep (walk backwards)
        size_t printableRun = 0;
        while (printableRun < segmentLen) {
            auto b = st.buf[p + segmentLen - printableRun - 1];
            if (!isPrintable(b)) break;
            ++printableRun;
        }

        if (printableRun >= optStrLen) {
            // Slice the segment [p .. p+segmentLen)
            auto bytes = st.buf[p .. p + segmentLen];

            // Convert bytes (ASCII) to string without UTF decoding
            auto s = () @trusted { return cast(string)bytes.idup; }();

            // Start byte offset of the detected printable run
            const startOff = st.offset
                           + cast(off_t)p
                           + cast(off_t)(segmentLen - printableRun);

            printString(s, cast(long)startOff);
        }

        // Advance past separator
        p   += segmentLen + 1;
        if (len < segmentLen + 1) break; // defensive
        len -= segmentLen + 1;
        if (len == 0) {
            // consumed all currently buffered data
            st.used = 0;
            return false;
        }
    }

    return false;
}

int processFile(string path) {
    BufState st;

    File f;
    try {
        f = File(path, "rb");
    } catch (Exception e) {
        stderr.writeln(path ~ ": ", e.msg);
        return 1;
    }
    scope(exit) f.close();

    while (true) {
        // Fill buffer
        auto space = BUFLEN - st.used;
        if (space == 0) {
            // Should not happen because processBuffer slides; but guard anyway
            st.used = 0;
            space = BUFLEN;
        }

        size_t rrc = 0;
        try {
            rrc = f.rawRead(st.buf[st.used .. st.used + space]).length;
        } catch (Exception e) {
            stderr.writeln(path ~ ": ", e.msg);
            return 1;
        }

        if (rrc == 0) {
            // EOF — drain any remaining window one last time (there might be no trailing sep)
            // Append a synthetic separator to flush the last segment safely.
            if (st.used > 0) {
                if (st.used < BUFLEN) {
                    st.buf[st.used] = '\n';
                    st.used += 1;
                    if (processBuffer(st)) return 1;
                } else {
                    // Buffer full with no sep: process as-is (no extra byte available)
                    if (processBuffer(st)) return 1;
                }
            }
            break;
        }

        st.used += rrc;

        if (processBuffer(st)) return 1;
    }

    return 0;
}

void usageAndExit(int code) {
    enum help = q{
strings - find printable strings in files

Usage:
  strings [-a] [-n NUMBER] [-t FORMAT] FILE...

Options:
  -a              Scan files in their entirety (ignored for compatibility)
  -n NUMBER       Minimum string length (default: 4)
  -t FORMAT       Prefix each string with its byte offset:
                    d = decimal, o = octal, x = hexadecimal
  -h, --help      Show this help
};
    writeln(help);
    import core.stdc.stdlib : exit;
    exit(code);
}

int main(string[] args) {
    string[] files;

    string radix = null;   // "d", "o", or "x"
    bool allFlag = false;  // compatibility only
    bool helpWanted = false;

    try {
        getopt(args,
            config.passThrough,      // keep non-options in args
            "a",       &allFlag,     // ignored
            "n|bytes", &optStrLen,
            "t|radix", &radix,
            "h|help",  &helpWanted,
        );
    } catch (Exception e) {
        stderr.writeln("Error: ", e.msg);
        usageAndExit(2);
    }

    if (helpWanted) usageAndExit(0);

    if (radix !is null) {
        switch (radix) {
            case "d": optPrefix = OptPrefix.decimal; break;
            case "o": optPrefix = OptPrefix.octal;   break;
            case "x": optPrefix = OptPrefix.hex_;    break;
            default:
                stderr.writeln("Invalid -t FORMAT: use d, o, or x");
                return 2;
        }
    }

    // Remaining args are files
    foreach (a; args[1 .. $]) {
        if (a.length && a[0] == '-') {
            // unrecognized flag passed-through
            stderr.writeln("Unknown option: ", a);
            return 2;
        }
        files ~= a;
    }

    if (files.length == 0) {
        usageAndExit(2);
    }

    int rc = 0;
    foreach (path; files) {
        rc |= processFile(path);
    }
    return rc;
}
