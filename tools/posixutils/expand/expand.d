// expand.d — D translation of the provided C++ "expand" tool
module expand_d;

import std.stdio : File, stdin, stdout, stderr, write, writefln, writeln;
import std.getopt : getopt;
import std.string : split, strip, indexOf, toStringz;
import std.algorithm : any, map;
import std.conv : to;
import std.exception : enforce;
import std.array : array;

/// ExpandApp: processes files/stdin and expands tabs to spaces.
final class ExpandApp {
    // If >0: fixed repeated tab width. If 0: use explicit tab list.
    uint repeatedTab = 8;
    uint lastTab = 0;            // largest explicit tab stop (if any)
    bool[] tabMap;               // tab stops: tabMap[col] == true (1-based index)

    this() {}

    // Parse -t argument (either a single positive integer, or a list)
    // List may be comma-separated or blank-separated; requires ascending, unique, positive integers.
    bool setTablist(string liststr) {
        auto s = liststr.strip;
        if (s.length == 0) return false;

        // Single positive integer?
        if (isAllDigits(s)) {
            auto tmp = s.to!long;
            if (tmp < 1) return false;
            lastTab = cast(uint) tmp;
            repeatedTab = cast(uint) tmp;
            tabMap = null;
            return true;
        }

        // Otherwise: comma-separated if it contains ',', else split on blanks
        string[] parts;
        if (s.indexOf(',') >= 0) parts = s.split(',').map!(a => a.strip).array;
        else                     parts = s.split; // whitespace

        if (parts.length < 2) return false;

        uint last = 0;
        // Build a bitmap sized to the largest stop
        uint maxStop = 0;
        foreach (p; parts) {
            if (!isAllDigits(p)) return false;
            auto curL = p.to!long;
            if (curL < 1) return false;
            auto cur = cast(uint) curL;
            if (cur <= last) return false; // strictly increasing
            last = cur;
            if (cur > maxStop) maxStop = cur;
        }

        tabMap = new bool[maxStop + 1]; // 1-based
        foreach (p; parts) {
            auto cur = cast(uint) p.to!long;
            tabMap[cur] = true;
            lastTab = cur;
        }

        repeatedTab = 0; // disable repeated tabs when explicit list provided
        return true;
    }

    int run(string[] files) {
        if (files.length == 0) {
            return processFile(stdin);
        }

        int rc = 0;
        foreach (path; files) {
            if (path == "-" ) { rc |= processFile(stdin); continue; }
            File f;
            try {
                f = File(path, "rb");
            } catch (Throwable) {
                stderr.writefln("%s: cannot open", path);
                rc |= 1;
                continue;
            }
            rc |= processFile(f);
        }
        return rc;
    }

private:
    static bool isAllDigits(string s) {
        foreach (c; s) if (c < '0' || c > '9') return false;
        return s.length > 0;
    }

    // Output one space and advance column (1-based)
    static void outSpace(ref uint column) {
        stdout.putc(' ');
        ++column;
    }

    // Expand a tab using repeated-tab width (like original)
    void advanceRTab(ref uint column) {
        while ((column % repeatedTab) != 0)
            outSpace(column);
        outSpace(column); // move past the stop (matches original logic)
    }

    // Expand a tab using explicit tab stops
    void advanceTabList(ref uint column) {
        if (column >= lastTab) {
            outSpace(column);
            return;
        }
        while (column < lastTab) {
            outSpace(column);
            if (column < tabMap.length && tabMap[column])
                break;
        }
        outSpace(column); // one more after reaching the stop (matches original)
    }

    int processFile(ref File f) {
        uint column = 1; // columns are 1-based
        while (!f.eof) {
            // File.getc returns int (or -1 at EOF)
            auto ch = f.getc();
            if (ch == -1) break;

            final switch (cast(char) ch) {
                case '\b':
                    stdout.putc(cast(char) ch);
                    if (column > 1) --column;
                    break;
                case '\r':
                case '\n':
                    stdout.putc(cast(char) ch);
                    column = 1;
                    break;
                case '\t':
                    if (repeatedTab != 0) advanceRTab(column);
                    else                  advanceTabList(column);
                    break;
                default:
                    stdout.putc(cast(char) ch);
                    ++column;
                    break;
            }
        }
        // std.stdio doesn't expose ferror directly; assume OK if we got here
        return 0;
    }
}

int main(string[] args) {
    auto app = new ExpandApp();

    string tabArg;
    string[] files;

    try {
        auto help = getopt(args,
            "t|tabs", &tabArg
        );
        files = help.args; // remaining are files (or "-" for stdin)
    } catch (Exception e) {
        stderr.writeln(e.msg);
        return 2;
    }

    if (tabArg.length) {
        if (!app.setTablist(tabArg)) {
            stderr.writeln("expand: invalid tab list");
            return 1;
        }
    }

    return app.run(files);
}
