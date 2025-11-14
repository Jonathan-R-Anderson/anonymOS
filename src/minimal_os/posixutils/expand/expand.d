module expand_d;

import core.stdc.stdio;   // FILE, stdin, stdout, stderr, fopen, fclose, fgetc, fputc, fprintf, EOF
import core.stdc.string;  // strlen, memcpy
import core.stdc.stdlib;  // malloc, free

// ---------------- minimal helpers (no Phobos, no foreach) ----------------

bool isDigit(char c) { return c >= '0' && c <= '9'; }

string trimLeft(string s) {
    size_t i = 0;
    while (i < s.length && (s[i] == ' ' || s[i] == '\t')) ++i;
    return s[i .. s.length];
}

string trimRight(string s) {
    size_t j = s.length;
    while (j > 0 && (s[j - 1] == ' ' || s[j - 1] == '\t')) --j;
    return s[0 .. j];
}

string trim(string s) { return trimRight(trimLeft(s)); }

// returns -1 on error
long parseInt(string s) {
    if (s.length == 0) return -1;
    long v = 0;
    for (size_t i = 0; i < s.length; ++i) {
        char c = s[i];
        if (!isDigit(c)) return -1;
        v = v * 10 + (c - '0');
        if (v < 0) return -1; // crude overflow guard
    }
    return v;
}

// Duplicate a C string into an immutable D string
string dupCStr(char* p) {
    size_t n = strlen(p);
    auto buf = new char[](n);
    if (n != 0) memcpy(buf.ptr, p, n);
    return cast(string) buf; // immutable(char)[]
}

// ---------------- expand implementation ----------------

struct ExpandApp {
    // When repeatedTab > 0, we use uniform stops every repeatedTab columns.
    // When repeatedTab == 0, we use explicit stops from stops[].
    uint repeatedTab;
    enum MAX_STOPS = 512;
    uint[MAX_STOPS] stops; // sorted, increasing
    uint nStops;

    void initDefaults() {
        repeatedTab = 8;
        nStops = 0;
    }

    // Parse -t ARG. Supports:
    //  - a single integer N
    //  - a comma-separated list: "4,8,12"
    //  - a whitespace-separated list: "4 8 12"
    bool setTablist(string liststr) {
        string s = trim(liststr);
        if (s.length == 0) return false;

        long single = parseInt(s);
        if (single > 0) {
            repeatedTab = cast(uint) single;
            nStops = 0;
            return true;
        }

        // Explicit list mode
        repeatedTab = 0;
        nStops = 0;

        // detect if commas are present
        bool hasComma = false;
        for (size_t i = 0; i < s.length; ++i) {
            if (s[i] == ',') { hasComma = true; break; }
        }

        size_t i = 0;
        uint prev = 0;
        while (i < s.length) {
            // skip separators
            if (hasComma) {
                while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == ',')) ++i;
            } else {
                while (i < s.length && (s[i] == ' ' || s[i] == '\t')) ++i;
            }
            if (i >= s.length) break;

            // parse number token
            size_t start = i;
            while (i < s.length) {
                char c = s[i];
                bool sep = hasComma ? (c == ',') : (c == ' ' || c == '\t');
                if (sep) break;
                ++i;
            }
            string tok = trim(s[start .. i]);
            long v = parseInt(tok);
            if (v < 1) return false;

            uint u = cast(uint) v;
            if (u <= prev) return false;
            if (nStops >= MAX_STOPS) return false;
            stops[nStops++] = u;
            prev = u;

            // if comma-separated, skip the comma (already skipped above by sep loop)
        }

        if (nStops < 2) return false; // need at least two explicit stops for usefulness
        return true;
    }

    static void outChar(char c) {
        fputc(c, stdout);
    }

    static void outSpace(ref uint col) {
        fputc(' ', stdout);
        ++col;
    }

    void advanceRTab(ref uint col) {
        uint W = repeatedTab;
        uint modv = (col - 1) % W;
        uint spaces = (W == 0) ? 1u : (W - modv);
        for (uint k = 0; k < spaces; ++k) outSpace(col);
    }

    void advanceTabList(ref uint col) {
        if (nStops == 0) { outSpace(col); return; }
        // Find first stop >= col
        uint target = 0;
        for (uint idx = 0; idx < nStops; ++idx) {
            uint stop = stops[idx];
            if (stop >= col) { target = stop; break; }
        }
        if (target == 0) { outSpace(col); return; }
        while (col <= target) outSpace(col);
    }

    int processFP(FILE* fp) {
        uint col = 1;
        for (;;) {
            int ich = fgetc(fp);
            if (ich == EOF) break;
            char ch = cast(char) ich;

            // avoid final switch; use normal switch
            switch (ch) {
                case '\b':
                    outChar(ch);
                    if (col > 1) --col;
                    break;

                case '\r':
                case '\n':
                    outChar(ch);
                    col = 1;
                    break;

                case '\t':
                    if (repeatedTab != 0) advanceRTab(col);
                    else                  advanceTabList(col);
                    break;

                default:
                    outChar(ch);
                    ++col;
                    break;
            }
        }
        return 0;
    }

    // files: empty → stdin; "-" → stdin; else fopen(path,"rb")
    int run(string[] files) {
        if (files.length == 0) return processFP(stdin);

        int rc = 0;
        for (size_t i = 0; i < files.length; ++i) {
            string path = files[i];
            if (path.length == 1 && path[0] == '-') { rc |= processFP(stdin); continue; }
            FILE* fp = fopen(path.ptr, "rb"); // D strings are 0-terminated
            if (fp is null) {
                fprintf(stderr, "%.*s: cannot open\n", cast(int) path.length, path.ptr);
                rc |= 1;
                continue;
            }
            rc |= processFP(fp);
            fclose(fp);
        }
        return rc;
    }
}

// ---------------- argument parsing (plain loops) ----------------

// Parses -tN, -t N, --tabs=N ; writes tabArg and files
void parseArgs(ref string[] args, ref string tabArg, ref string[] files) {
    tabArg = "";
    files = null;

    size_t i = 1; // skip program name
    for (;;) {
        if (i >= args.length) break;
        string a = args[i];

        // "-tN" or "-t"
        if (a.length >= 2 && a[0] == '-' && a[1] == 't') {
            if (a.length > 2) {
                tabArg = a[2 .. a.length]; // "-tN"
                ++i;
            } else {
                if (i + 1 < args.length) {
                    tabArg = args[i + 1];
                    i += 2;
                } else {
                    ++i; // missing arg; continue
                }
            }
            continue;
        }

        // "--tabs=N" manual prefix check
        char[] pref = "--tabs=".dup;
        bool hasPref = false;
        if (a.length > pref.length) {
            hasPref = true;
            for (size_t k = 0; k < pref.length; ++k) {
                if (a[k] != pref[k]) { hasPref = false; break; }
            }
        }
        if (hasPref) {
            tabArg = a[pref.length .. a.length];
            ++i;
            continue;
        }

        // "--" ends options
        if (a.length == 2 && a[0] == '-' && a[1] == '-') { ++i; break; }

        // first non-option → files
        break;
    }

    if (i < args.length) {
        // slice remainder
        files = args[i .. args.length];
    }
}

extern(C) int main(int argc, char** argv) {
    // convert argv → D string[]
    string[] args;
    args.length = cast(size_t) argc;
    for (int i = 0; i < argc; ++i) {
        args[i] = dupCStr(argv[i]);
    }

    ExpandApp app;
    app.initDefaults();

    string tabArg;
    string[] files;
    parseArgs(args, tabArg, files);

    if (tabArg.length != 0) {
        if (!app.setTablist(tabArg)) {
            fprintf(stderr, "expand: invalid tab list\n");
            return 1;
        }
    }

    return app.run(files);
}
