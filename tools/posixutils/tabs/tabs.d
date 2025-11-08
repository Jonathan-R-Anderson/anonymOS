/+ 
  tabs.d — D port of posixutils “tabs” (GPL-2.0)

  Differences from the C version:
    - Replaces libpu helpers with direct terminfo use:
        setupterm(), tigetstr(), and the global `columns` variable
    - `get_terminal()` → TERM env or `-T` value
    - Output assembled in a bounded buffer (same 4096 cap) and written once
+/
module tabs;

version(Posix):

import std.stdio;
import std.string;
import std.algorithm;
import std.array;
import std.exception;
import std.conv;
import std.getopt;
import std.process : environment;
import core.stdc.stdlib : exit, atoi;
import core.stdc.string : strlen, strcmp, strncpy;
import core.sys.posix.unistd : write, STDOUT_FILENO;

// --- terminfo C bindings (ncurses/terminfo) ---
extern(C):
    int setupterm(const(char)* term, int fildes, int* errret);
    char* tigetstr(const(char)* capname);
    // terminfo exposes these globals after setupterm()
    __gshared int columns; // number of columns
    __gshared int lines;   // (unused here)

// --------- constants / tables ----------
enum tabs_outbuf_sz = 4096;
enum max_tab_stops  = 1024;

__gshared string optTerm; // -T type (optional)

__gshared int nTabs;
__gshared int[max_tab_stops] tabStop;

// Stock tab sets (1-based columns)
__gshared immutable int[] tabset_a  = [ 1,10,16,36,72 ];
__gshared immutable int[] tabset_a2 = [ 1,10,16,40,72 ];
__gshared immutable int[] tabset_c  = [ 1,8,12,16,20,55 ];
__gshared immutable int[] tabset_c2 = [ 1,6,10,14,49 ];
__gshared immutable int[] tabset_c3 = [ 1,6,10,14,18,22,26,30,34,38,42,46,50,54,58,62,67 ];
__gshared immutable int[] tabset_f  = [ 1,7,11,15,19,23 ];
__gshared immutable int[] tabset_p  = [ 1,5,9,13,17,21,25,29,33,37,41,45,49,53,57,61 ];
__gshared immutable int[] tabset_s  = [ 1,10,55 ];
__gshared immutable int[] tabset_u  = [ 1,12,20,44 ];

// --------- usage ----------
void usageAndExit() {
    stderr.write(
"Usage:\n"
"tabs [ -n| -a| -a2| -c| -c2| -c3| -f| -p| -s| -u][+m[n]] [-T type]\n"
"      or\n"
"tabs [-T type][ +[n]] n1[,n2,...]\n");
    exit(1);
}

// --------- tab helpers ----------
void tabPush(int stop) {
    if (nTabs == max_tab_stops) {
        stderr.writeln("tabs: tab stop table limit reached");
        exit(1);
    }
    tabStop[nTabs++] = stop;
}

void tabStock(in int[] stops) {
    enforce(stops.length <= max_tab_stops);
    nTabs = cast(int)stops.length;
    // copy
    foreach (i, v; stops) tabStop[i] = v;
}

void tabRepeating(int tabN) {
    // set every tabN columns up to terminal width
    for (int col = 1; col < columns; ++col) {
        if (tabN != 0 && (col % tabN) == 0) {
            tabPush(col);
        }
    }
}

// --------- minimal tokenizer for spec lists (comma/space separated) ----------
string[] splitSpecs(string s) {
    // Split on commas or whitespace
    string cur;
    string[] out;
    foreach (ch; s) {
        if (ch == ',' || ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f') {
            if (cur.length) {
                out ~= cur;
                cur = "";
            }
        } else {
            cur ~= ch;
        }
    }
    if (cur.length) out ~= cur;
    return out;
}

// --------- command line parsing (replicates C behavior) ----------
void parseCmdline(string[] argv) {
    // 1) Pre-scan -T to init terminfo early
    for (size_t i = 1; i < argv.length; ++i) {
        auto a = argv[i];
        if (a.length >= 2 && a[0..2] == "-T") {
            if (a.length == 2) {
                if (i + 1 < argv.length) {
                    optTerm = argv[i+1];
                }
            } else {
                optTerm = a[2 .. $];
            }
        }
    }

    // Determine terminal type
    string term = optTerm.length ? optTerm : environment.get("TERM", "");
    int err = 0;
    if (setupterm(term.length ? term.ptr : cast(const char*)null, STDOUT_FILENO, &err) != 0) {
        stderr.writeln("tabs: setupterm failed for term type ",
                       term.length ? term : "(null)");
        exit(1);
    }

    // Default: repeating every 8 cols
    tabRepeating(8);

    // 2) Parse options (-0..-9, -a[2], -c[2|3], -f, -p, -s, -u, -T type)
    bool changed = false;
    size_t i = 1;

    // emulate getopt used in C: options may be combined or have optional suffix
    while (i < argv.length) {
        auto a = argv[i];
        if (a.length == 0 || a[0] != '-') break; // reached operands

        // lone "-" not valid for this tool
        if (a == "-") usageAndExit();

        // handle "-T type" and "-Ttype"
        if (a[0..2] == "-T") {
            // already applied in pre-scan; just consume argument if separate
            if (a.length == 2) {
                ++i; // skip value
                if (i >= argv.length) usageAndExit();
            }
            ++i;
            continue;
        }

        // single-letter flags; may be like "-a", "-a2", "-c3", "-5", "-0"
        char flag = a[1];
        string optarg = a.length > 2 ? a[2 .. $] : "";

        final switch (flag) {
            case '0': nTabs = 0; changed = true; ++i; break;
            case '1','2','3','4','5','6','7','8','9':
                tabRepeating(flag - '0'); changed = true; ++i; break;

            case 'a':
                changed = true;
                if (optarg.length == 0)      tabStock(tabset_a);
                else if (optarg == "2")      tabStock(tabset_a2);
                else                          usageAndExit();
                ++i;
                break;

            case 'c':
                changed = true;
                if (optarg.length == 0)      tabStock(tabset_c);
                else if (optarg == "2")      tabStock(tabset_c2);
                else if (optarg == "3")      tabStock(tabset_c3);
                else                          usageAndExit();
                ++i;
                break;

            case 'f': changed = true; tabStock(tabset_f); ++i; break;
            case 'p': changed = true; tabStock(tabset_p); ++i; break;
            case 's': changed = true; tabStock(tabset_s); ++i; break;
            case 'u': changed = true; tabStock(tabset_u); ++i; break;

            default:
                usageAndExit();
        }
    }

    // 3) Operands (explicit tab list / +offset). If none, done
    if (i >= argv.length) return;

    // If we already changed via options, C code errors out (mutually exclusive)
    if (changed) usageAndExit();

    nTabs = 0;

    int col = 1;
    int lastCol = -1;

    while (i < argv.length) {
        string arg = argv[i++];
        auto tokens = splitSpecs(arg);
        foreach (tok; tokens) {
            bool doOffset = false;
            if (tok.length && tok[0] == '+') {
                doOffset = true;
                tok = tok[1 .. $];
            }
            if (tok.length == 0) usageAndExit();

            int offset = atoi(tok.toStringz);

            if (doOffset) {
                if (offset > columns || offset > (col + columns)) {
                    stderr.writeln("tabs: tabspec beyond max-columns specified");
                    exit(1);
                }
                col += offset;
            } else {
                if (offset < col) usageAndExit();
                col = offset;
            }

            if (col == lastCol) usageAndExit();

            tabPush(col);
            lastCol = col;
        }
    }
}

// --------- output buffer and terminal sequences ----------
__gshared char[tabs_outbuf_sz] outbuf;
__gshared uint outbufAvail = tabs_outbuf_sz - 1; // keep trailing NUL

bool pushStr(const(char)* val) {
    if (val is null) return true;
    size_t valLen = strlen(val);
    if (outbufAvail < valLen) return false;

    // Append C-strings into outbuf
    size_t curLen = strlen(outbuf.ptr);
    // copy bytes
    import core.stdc.string : memcpy;
    memcpy(outbuf.ptr + curLen, val, valLen);
    outbuf[curLen + valLen] = 0;
    outbufAvail -= cast(uint)valLen;
    return true;
}

bool pushLiteral(string s) {
    // convenience for small literals
    if (outbufAvail < s.length) return false;
    size_t curLen = strlen(outbuf.ptr);
    import core.stdc.string : memcpy;
    memcpy(outbuf.ptr + curLen, s.ptr, s.length);
    outbuf[curLen + s.length] = 0;
    outbufAvail -= cast(uint)s.length;
    return true;
}

const(char)* tiGetStr(string cap) {
    auto p = tigetstr(cap.ptr);
    return p;
}

void setHardwareTabs() {
    // "tbc" — clear all tabs, "hts" — set a tab at current column
    auto hts = tiGetStr("hts"); // set horizontal tab stop
    if (hts is null) {
        stderr.writeln("tabs: terminal unable to set tabs");
        exit(1);
    }

    // Clear all tabs first (tbc)
    if (!pushStr(tiGetStr("tbc"))) {
        stderr.writeln("tabs: buffer overflow");
        exit(1);
    }

    // Now move across columns, placing hts at specified stops.
    int col = 0;
    foreach (i; 0 .. nTabs) {
        while (col < tabStop[i]) {
            if (!pushLiteral(" ")) {
                stderr.writeln("tabs: buffer overflow");
                exit(1);
            }
            ++col;
        }
        if (!pushStr(hts)) {
            stderr.writeln("tabs: buffer overflow");
            exit(1);
        }
    }

    // Emit sequence at once
    auto len = strlen(outbuf.ptr);
    if (len > 0) {
        // write raw control sequence to stdout
        write(STDOUT_FILENO, outbuf.ptr, len);
    }
}

int main(string[] args) {
    // Initialize output buffer to empty C-string
    outbuf[0] = 0;
    outbufAvail = tabs_outbuf_sz - 1;

    parseCmdline(args);
    setHardwareTabs();
    return 0;
}
