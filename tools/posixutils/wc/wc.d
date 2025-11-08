// wc.d — D translation of the provided C source
//
// Usage: wc [-c|-m] [-l] [-w] [FILE...]
//   -c, --bytes   : count bytes (default "character" field)
//   -m, --chars   : count Unicode characters (code points)
//   -l, --lines   : count newline characters; include a final line if input
//                   doesn't end with '\n' (matches the C "in_line" behavior)
//   -w, --words   : count words (whitespace-delimited)
// If no -c/-m/-l/-w are specified, prints lines, words, and bytes (POSIX wc).
//
// Build:
//   dmd -O -release wc.d -of=wc
//   # or: ldc2 -O3 -release wc.d -of=wc

import std.stdio : File, stdin, stdout, stderr, writefln, writeln;
import std.getopt : getopt;
import std.string : toStringz;
import std.ascii : isWhite; // ASCII whitespace for byte-mode
import std.uni : isWhite as uniWhite; // Unicode whitespace for char/word mode
import std.utf : decode; // decode UTF-8 incrementally with index
import std.exception : enforce;
import core.sys.posix.unistd : isatty;
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
    int outMask = 0;      // which columns to print
    int outType = WCT_BYTE; // if WC_CHAR set: bytes vs chars
    string[] files;       // empty => read stdin
}

//
// Counting over raw bytes (ASCII whitespace semantics)
//
void countBufBytes(ref CountInfo info, const(ubyte)[] buf) {
    foreach (b; buf) {
        const c = cast(char)b;
        if (isWhite(c)) {
            if (info.inWord) {
                info.inWord = false;
                info.words++;
            }
            if (c == '\n') {
                info.inLine = false;
                info.lines++;
            } else {
                info.inLine = true;
            }
        } else {
            info.inWord = true;
        }
        info.chars++; // In byte-mode path the C code increments .chars, but final print shows bytes vs chars depending on outType.
    }
}

//
// Counting over Unicode code points (UTF-8)
// Uses Unicode whitespace semantics (std.uni.isWhite).
// Robust across chunk boundaries and malformed sequences:
//  - If a decoding exception occurs and there are >=4 bytes left, advance 1 byte.
//  - If it looks like an incomplete tail at end of chunk, keep leftovers for next read.
//
void countBufUTF8(ref CountInfo info, ref ubyte[] carry, const(ubyte)[] chunk) {
    auto data = carry ~ chunk;
    size_t i = 0;
    while (i < data.length) {
        dchar ch;
        auto before = i;
        try {
            ch = decode(data, i); // advances i by the decoded code point length
        } catch (Exception) {
            // If near the end, assume incomplete sequence: keep tail for next chunk.
            immutable rem = data.length - before;
            if (rem < 4) {
                carry = data[before .. $].dup;
                return;
            } else {
                // malformed byte inside stream: skip one byte and continue
                i = before + 1;
                continue;
            }
        }

        // Word/line accounting with Unicode whitespace
        if (uniWhite(ch)) {
            if (info.inWord) {
                info.inWord = false;
                info.words++;
            }
            if (ch == '\n') {
                info.inLine = false;
                info.lines++;
            } else {
                info.inLine = true;
            }
        } else {
            info.inWord = true;
        }

        info.chars++; // count code points when -m
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
int countStream(string label, ref File f, int outType, ref CountInfo out) {
    ubyte[WC_BUFSZ] buf;
    ubyte[] carry; // for UTF-8 split sequences across reads

    out = CountInfo.init;
    while (true) {
        auto n = f.rawRead(buf[]).length;
        if (n == 0) break;

        // bytes always counted from the raw read
        out.bytes += n;

        if (outType == WCT_CHAR) {
            countBufUTF8(out, carry, buf[0 .. n]);
        } else {
            countBufBytes(out, buf[0 .. n]);
        }

        // If file error (rare), surface it
        if (f.error) {
            // mimic perror(label)
            auto msg = strerror(errno);
            stderr.writefln("%s: %s", label, msg ? msg : "read error");
            return 1;
        }
    }

    // If the stream ended while "inWord"/"inLine", close them out
    if (out.inWord) out.words++;
    if (out.inLine) out.lines++;

    return 0;
}

//
// Print a single line with selected columns and (optionally) the filename.
//
void printInfo(string fn, const ref CountInfo info, int outMask, int outType, bool showName) {
    auto needFilename = showName;
    bool needSpace;

    // Build in the same order as typical wc: lines, words, chars(bytes/chars)
    string s;
    import std.format : format;

    if (outMask & WC_LINE) {
        needSpace = needFilename || (outMask & WC_WORD) || (outMask & WC_CHAR);
        s ~= format("%s%llu", s.length ? " " : "", info.lines);
    }
    if (outMask & WC_WORD) {
        s ~= format("%s%llu", s.length ? " " : "", info.words);
    }
    if (outMask & WC_CHAR) {
        ulong v = (outType == WCT_BYTE) ? info.bytes : info.chars;
        s ~= format("%s%llu", s.length ? " " : "", v);
    }

    if (needFilename) {
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
        opt.outMask = WC_ALL;     // we'll print the "character" field as bytes
        opt.outType = WCT_BYTE;
    } else {
        if (linesFlag) opt.outMask |= WC_LINE;
        if (wordsFlag) opt.outMask |= WC_WORD;
        if (bytesFlag) { opt.outMask |= WC_CHAR; opt.outType = WCT_BYTE; }
        if (charsFlag) { opt.outMask |= WC_CHAR; opt.outType = WCT_CHAR; }
        // If user asked only -c or -m and nothing else, that's fine.
    }

    // Remaining positional args are files
    // args[0] = program name
    if (args.length > 1) {
        opt.files = args[1 .. $];
    } else {
        opt.files = []; // stdin
    }
    return opt;
}

int processOne(string name, ref File f, const Options opt, ref CountInfo totals, ref int totalFiles) {
    CountInfo info;
    auto rc = countStream(name, f, opt.outType, info);
    if (rc != 0) return rc;

    totals.bytes += info.bytes;
    totals.words += info.words;
    totals.lines += info.lines;
    totals.chars += info.chars; // track also chars for completeness

    totalFiles++;
    // Show filename only if more than one file OR stdin mixed with others
    // Here we decide after we know totalFiles later; emulate GNU wc:
    // - If multiple inputs, print filename; otherwise omit.
    // We'll pass showName=true if there are (or will be) >1 inputs.
    // To keep logic simple, the caller will decide showName.
    printInfo(name, info, opt.outMask, opt.outType, /*showName*/ false); // placeholder; adjusted by caller
    return 0;
}

int main(string[] args) {
    auto opt = parseArgs(args);

    // No files => read stdin once
    CountInfo totals;
    int totalFiles = 0;

    // Collect inputs
    string[] inputs = opt.files.length ? opt.files : ["(standard input)"];

    // First pass: count each and print, showing names if multiple inputs.
    immutable showNames = (inputs.length > 1);

    int rc = 0;
    foreach (name; inputs) {
        if (name == "(standard input)") {
            auto f = stdin;
            CountInfo info;
            auto oneRc = countStream(name, f, opt.outType, info);
            if (oneRc != 0) { rc = 1; continue; }

            totals.bytes += info.bytes;
            totals.words += info.words;
            totals.lines += info.lines;
            totals.chars += info.chars;
            totalFiles++;

            printInfo(name, info, opt.outMask, opt.outType, showNames);
        } else {
            File f;
            if (!f.open(name, "rb")) {
                auto msg = strerror(errno);
                stderr.writefln("%s: %s", name, msg ? msg : "open failed");
                rc = 1;
                continue;
            }
            scope(exit) f.close();

            CountInfo info;
            auto oneRc = countStream(name, f, opt.outType, info);
            if (oneRc != 0) { rc = 1; continue; }

            totals.bytes += info.bytes;
            totals.words += info.words;
            totals.lines += info.lines;
            totals.chars += info.chars;
            totalFiles++;

            printInfo(name, info, opt.outMask, opt.outType, showNames);
        }
    }

    if (totalFiles > 1) {
        // For the "character" field in totals, follow the selected outType
        // (bytes if -c or default, chars if -m)
        printInfo("total", totals, opt.outMask, opt.outType, /*showName*/ false);
    }

    return rc;
}
