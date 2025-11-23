// wc.d — D translation of the provided C source
//
// Usage: wc [-c|-m] [-l] [-w] [FILE...]
//   -c, --bytes   : count bytes (default "character" field)
//   -m, --chars   : count Unicode characters (code points)
//   -l, --lines   : count newline characters; include a final line if input
//                   doesn't end with '\n'
//   -w, --words   : count words (whitespace-delimited)
// If no -c/-m/-l/-w are specified, prints lines, words, and bytes (POSIX wc).
//
// Build:
//   dmd -O -release wc.d -of=wc
//   # or: ldc2 -O3 -release wc.d -of=wc

import std.stdio : File, stdin, stdout, stderr, writeln, StdioException;
import std.getopt : getopt;
import std.format : format;
import std.utf : decode;
import std.exception : enforce;
import std.conv : to;
static import std.ascii;  // std.ascii.isWhite for byte-mode
static import std.uni;    // std.uni.isWhite  for Unicode-mode
import core.stdc.errno : errno;
import core.stdc.string : strerror;

enum WC_CHAR = 1 << 0; // "character field" (bytes or chars selected by outType)
enum WC_LINE = 1 << 1;
enum WC_WORD = 1 << 2;
enum WC_ALL  = WC_CHAR | WC_LINE | WC_WORD;

enum WCT_BYTE = 0;
enum WCT_CHAR = 1;

enum WC_BUFSZ = 4096;

struct CountInfo {
    ulong bytes;
    ulong chars;
    ulong words;
    ulong lines;
    bool inWord;
    bool inLine;
}

struct Options {
    int outMask = 0;         // which columns to print
    int outType = WCT_BYTE;  // if WC_CHAR set: bytes vs chars
    string[] files;          // empty => read stdin
}

//
// Counting over raw bytes (ASCII whitespace semantics)
//
void countBufBytes(ref CountInfo ci, const(ubyte)[] buf) {
    foreach (b; buf) {
        const c = cast(char)b;
        if (std.ascii.isWhite(c)) {
            if (ci.inWord) {
                ci.inWord = false;
                ci.words++;
            }
            if (c == '\n') {
                ci.inLine = false;
                ci.lines++;
            } else {
                ci.inLine = true;
            }
        } else {
            ci.inWord = true;
        }
        // In byte-mode we accumulate "chars" as bytes; final column selection
        // decides whether to show bytes or chars.
        ci.chars++;
    }
}

//
// Counting over Unicode code points (UTF-8)
// Uses Unicode whitespace semantics (std.uni.isWhite).
// Robust across chunk boundaries and malformed sequences.
//
void countBufUTF8(ref CountInfo ci, ref ubyte[] carry, const(ubyte)[] chunk) {
    auto data = carry ~ chunk;                 // bytes
    auto s = cast(const(char)[]) data;         // reinterpret as UTF-8 code units
    size_t i = 0;
    while (i < s.length) {
        dchar ch;
        auto before = i;
        try {
            ch = decode(s, i); // advances i by code point length
        } catch (Exception) {
            // If near the end, assume incomplete sequence: keep tail for next chunk.
            immutable rem = s.length - before;
            if (rem < 4) {
                carry = data[before .. $].dup; // keep original bytes
                return;
            } else {
                // malformed byte inside stream: skip one byte (in bytes domain)
                i = before + 1;
                continue;
            }
        }

        // Word/line accounting with Unicode whitespace
        if (std.uni.isWhite(ch)) {
            if (ci.inWord) {
                ci.inWord = false;
                ci.words++;
            }
            if (ch == '\n') {
                ci.inLine = false;
                ci.lines++;
            } else {
                ci.inLine = true;
            }
        } else {
            ci.inWord = true;
        }

        ci.chars++; // count code points when -m
    }

    // no incomplete tail
    carry.length = 0;
}

//
// Count an entire stream (File), filling CountInfo.
// outType selects byte vs char counting for the "character" column.
// Words/lines follow the same mode: byte-mode uses ASCII whitespace;
// char-mode uses Unicode whitespace.
//
int countStream(string label, ref File f, int outType, ref CountInfo ci) {
    ubyte[WC_BUFSZ] buf;
    ubyte[] carry; // for UTF-8 split sequences across reads

    ci = CountInfo.init;
    while (true) {
        auto got = f.rawRead(buf[]);     // ubyte[] slice actually filled
        auto n = got.length;
        if (n == 0) break;

        // bytes always counted from the raw read
        ci.bytes += n;

        auto slice = buf[0 .. n];

        if (outType == WCT_CHAR) {
            countBufUTF8(ci, carry, slice);
        } else {
            countBufBytes(ci, slice);
        }

        // If file error (rare), surface it
        if (f.error) {
            auto msg = strerror(errno);
            stderr.writeln(format("%s: %s", label, msg ? msg : "read error"));
            return 1;
        }
    }

    // If the stream ended while "inWord"/"inLine", close them out
    if (ci.inWord) ci.words++;
    if (ci.inLine) ci.lines++;

    return 0;
}

//
// Print a single line with selected columns and (optionally) the filename.
//
void printInfo(string fn, const ref CountInfo info, int outMask, int outType, bool showName) {
    string s;

    // Typical wc order: lines, words, chars(bytes/chars)
    if ((outMask & WC_LINE) != 0) {
        s ~= to!string(info.lines);
    }
    if ((outMask & WC_WORD) != 0) {
        if (s.length) s ~= " ";
        s ~= to!string(info.words);
    }
    if ((outMask & WC_CHAR) != 0) {
        if (s.length) s ~= " ";
        ulong v = (outType == WCT_BYTE) ? info.bytes : info.chars;
        s ~= to!string(v);
    }

    if (showName) {
        writeln(s, " ", fn);
    } else {
        writeln(s);
    }
}

Options parseArgs(string[] args) {
    Options opt;
    bool bytesFlag = false;
    bool charsFlag = false;
    bool linesFlag = false;
    bool wordsFlag = false;

    getopt(args,
        "c|bytes", &bytesFlag,
        "m|chars", &charsFlag,
        "l|lines", &linesFlag,
        "w|words", &wordsFlag,
    );

    // Decide outMask and outType
    if (!(bytesFlag || charsFlag || linesFlag || wordsFlag)) {
        // Default: lines, words, bytes
        opt.outMask = WC_LINE | WC_WORD | WC_CHAR;
        opt.outType = WCT_BYTE;
    } else {
        if (linesFlag) opt.outMask |= WC_LINE;
        if (wordsFlag) opt.outMask |= WC_WORD;
        if (bytesFlag) { opt.outMask |= WC_CHAR; opt.outType = WCT_BYTE; }
        if (charsFlag) { opt.outMask |= WC_CHAR; opt.outType = WCT_CHAR; }
    }

    // Remaining positional args are files; args[0] is program name.
    if (args.length > 1) {
        opt.files = args[1 .. $];
    } else {
        opt.files = []; // stdin
    }
    return opt;
}

int main(string[] args) {
    auto opt = parseArgs(args);

    CountInfo totals;
    int totalFiles = 0;

    // No files => read stdin once
    string[] inputs = opt.files.length ? opt.files : ["(standard input)"];
    immutable showNames = (inputs.length > 1);

    int rc = 0;

    foreach (name; inputs) {
        if (name == "(standard input)") {
            auto f = stdin;
            CountInfo ci;
            auto oneRc = countStream(name, f, opt.outType, ci);
            if (oneRc != 0) { rc = 1; continue; }

            totals.bytes += ci.bytes;
            totals.words += ci.words;
            totals.lines += ci.lines;
            totals.chars += ci.chars;
            totalFiles++;

            printInfo(name, ci, opt.outMask, opt.outType, showNames);
        } else {
            File f;
            try {
                f.open(name, "rb");
            } catch (StdioException e) {
                stderr.writeln(format("%s: %s", name, e.msg));
                rc = 1;
                continue;
            }
            scope(exit) f.close();

            CountInfo ci;
            auto oneRc = countStream(name, f, opt.outType, ci);
            if (oneRc != 0) { rc = 1; continue; }

            totals.bytes += ci.bytes;
            totals.words += ci.words;
            totals.lines += ci.lines;
            totals.chars += ci.chars;
            totalFiles++;

            printInfo(name, ci, opt.outMask, opt.outType, showNames);
        }
    }

    if (totalFiles > 1) {
        // Totals row: respect selected outType for the character column
        printInfo("total", totals, opt.outMask, opt.outType, /*showName*/ false);
    }

    return rc;
}
