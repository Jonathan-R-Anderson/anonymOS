// dash line editor: raw terminal input, history, syntax colouring, Tab completion with hints.
module dash.edit;

import dash.rt;
import dash.eval;
import dash.exec;
import dash.complete;

struct Termios { uint c_iflag, c_oflag, c_cflag, c_lflag; ubyte c_line; ubyte[32] c_cc; uint c_ispeed, c_ospeed; }
extern (C) @nogc nothrow {
    int tcgetattr(int, Termios*);
    int tcsetattr(int, int, const(Termios)*);
}
enum ICANON = 0x2, ECHO = 0x8, IEXTEN = 0x8000, IXON = 0x400, ICRNL = 0x100, VMIN = 6, VTIME = 5, TCSADRAIN = 1;

__gshared Termios g_origTerm;
__gshared bool g_haveTerm, g_rawOn;

@nogc nothrow:

void termSave() { g_haveTerm = tcgetattr(0, &g_origTerm) == 0; }
void rawOn() {
    if (!g_haveTerm || g_rawOn) return;
    Termios t = g_origTerm;
    t.c_lflag &= ~(ICANON | ECHO | IEXTEN);
    t.c_iflag &= ~(IXON | ICRNL);
    t.c_cc[VMIN] = 1; t.c_cc[VTIME] = 0;
    tcsetattr(0, TCSADRAIN, &t);
    g_rawOn = true;
}
void rawOff() { if (g_haveTerm && g_rawOn) { tcsetattr(0, TCSADRAIN, &g_origTerm); g_rawOn = false; } }

// ── history ─────────────────────────────────────────────────────────────────────────────────────
__gshared Vec!(char*) g_hist;
__gshared char[512] g_histPath = 0;
void histLoad() {
    auto h = getenv("HOME");
    snprintf(g_histPath.ptr, g_histPath.length, "%s/.dash_history", h ? h : "/home/user");
    const fd = open(g_histPath.ptr, O_RDONLY);
    if (fd < 0) return;
    Buf b; char[4096] t;
    for (;;) { const r = read(fd, t.ptr, t.length); if (r <= 0) break; b.put(t[0 .. cast(size_t)r]); }
    close(fd);
    size_t st = 0;
    foreach (k; 0 .. b.n) if (b.p[k] == '\n') { if (k > st) g_hist.push(cz(b.p[st .. k])); st = k + 1; }
    b.dispose();
    while (g_hist.n > 1000) { free(g_hist[0]); memmove(g_hist.p, g_hist.p + 1, (g_hist.n - 1) * (char*).sizeof); --g_hist.n; }
}
void histAdd(const(char)[] line) {
    if (line.length == 0) return;
    auto z = cz(line);
    if (g_hist.n && strcmp(g_hist.back(), z) == 0) { free(z); return; }
    g_hist.push(z);
    const fd = open(g_histPath.ptr, O_WRONLY | O_CREAT | O_APPEND, 0x180);
    if (fd >= 0) {
        foreach (c; line) { if (c == '\n') { write(fd, " ".ptr, 1); continue; } write(fd, &c, 1); }
        write(fd, "\n".ptr, 1);
        close(fd);
    }
}

// ── colouring ───────────────────────────────────────────────────────────────────────────────────
private void colour(ref Buf o, const(char)[] s) {
    size_t i = 0;
    bool first = true;
    while (i < s.length) {
        const c = s[i];
        if (c == '"') {
            size_t j = i + 1; while (j < s.length && s[j] != '"') { if (s[j] == '\\') ++j; ++j; }
            if (j < s.length) ++j;
            o.put("\x1b[33m"); o.put(s[i .. j]); o.put("\x1b[0m"); i = j; first = false; continue;
        }
        if (c == '-' && i + 1 < s.length && s[i + 1] == '-' && (i + 2 >= s.length || s[i + 2] == ' ') && (i == 0 || s[i - 1] == ' ')) {
            o.put("\x1b[2m"); o.put(s[i .. $]); o.put("\x1b[0m"); return;
        }
        if (isAlpha(c)) {
            size_t j = i; while (j < s.length && (isIdentChar(s[j]) || s[j] == '-')) ++j;
            const w = s[i .. j];
            const(char)[] col = null;
            switch (w) {
                case "let", "in", "where", "if", "then", "else", "case", "of", "do", "data": col = "\x1b[35m"; break;
                default:
                    if (first) {
                        const cls = nameClass(w);
                        col = cls == 2 ? "\x1b[32m" : (cls == 1 || cls == 3) ? "\x1b[36m" : (j < s.length ? "\x1b[31m" : null);
                    }
            }
            if (col) { o.put(col); o.put(w); o.put("\x1b[0m"); } else o.put(w);
            i = j; first = false; continue;
        }
        if (c == '|' || c == ';' || (c == '&' && i + 1 < s.length && s[i + 1] == '&')) {
            size_t j = i + 1; if (j < s.length && (s[j] == '>' || s[j] == '|' || s[j] == '&')) ++j;
            o.put("\x1b[1;34m"); o.put(s[i .. j]); o.put("\x1b[0m"); i = j;
            first = true; continue;
        }
        if (c == '\\' && i + 1 < s.length && s[i + 1] != '\\') { o.put("\x1b[35m\\\x1b[0m"); ++i; continue; }
        if (!isSpace(c)) first = first && (c == '(' || c == '=' );
        o.put(c); ++i;
    }
}

// ── the editor ──────────────────────────────────────────────────────────────────────────────────
private __gshared int g_prevRow;           // cursor row (relative to the prompt's first row) last drawn

private int cols() {
    struct WS { ushort row, col, x, y; }
    WS ws; if (ioctl(1, 0x5413, &ws) == 0 && ws.col > 0) return ws.col;
    return 80;
}
// display width of UTF-8 text without escapes
size_t dispWidth(const(char)[] s) {
    size_t w = 0; bool esc = false;
    foreach (c; s) {
        if (esc) { if (c >= '@' && c <= '~' && c != '[') esc = false; continue; }
        if (c == '\x1b') { esc = true; continue; }
        if ((cast(ubyte)c & 0xC0) != 0x80) ++w;
    }
    return w;
}
private void refresh(const(char)[] prompt, ref Buf line, size_t cursor) {
    Buf o;
    if (g_prevRow > 0) { char[16] t; const n = snprintf(t.ptr, t.length, "\x1b[%dA", g_prevRow); o.put(t[0 .. n]); }
    o.put('\r');
    o.put(prompt);
    colour(o, line.str());
    const W = cols();
    const pw = dispWidth(prompt);
    const endPos = pw + dispWidth(line.str());
    const curPos = pw + dispWidth(line.str()[0 .. cursor]);
    const endRow = cast(int)(endPos / W), curRow = cast(int)(curPos / W), curCol = cast(int)(curPos % W);
    // Text that ends exactly at the right margin leaves the cursor where the terminal's wrap rule
    // says: xterm holds it at the margin (the wrap is pending), wl-term has already moved to the next
    // row.  A space and a CR put both at column 0 of the next row -- endRow -- and the erase below
    // removes the space.  (A bare CRLF here went one row too far on wl-term, and every later
    // redraw of a long line printed the prompt again one row down.)
    if (endPos > 0 && endPos % W == 0) o.put(" \r");
    o.put("\x1b[J");
    const up = endRow - curRow;
    if (up > 0) { char[16] t; const n = snprintf(t.ptr, t.length, "\x1b[%dA", up); o.put(t[0 .. n]); }
    o.put('\r');
    if (curCol > 0) { char[16] t; const n = snprintf(t.ptr, t.length, "\x1b[%dC", curCol); o.put(t[0 .. n]); }
    g_prevRow = curRow;
    write(1, o.p, o.n);
    o.dispose();
}

private bool readByte(out char c) {
    for (;;) {
        const r = read(0, &c, 1);
        if (r == 1) return true;
        if (r < 0 && g_interrupted) return false;
        if (r <= 0) return false;
    }
}

// Read a line.  Returns a malloc'd string, or null at end of input (^D on an empty line).
// On ^C the line is abandoned and an empty string returned.
char* readLine(const(char)[] prompt) {
    oflush();
    rawOn();
    Buf line; line.put("");
    size_t cursor = 0;
    size_t hpos = g_hist.n;
    Buf saved;                      // the line being edited while browsing history
    int tabs = 0;
    g_prevRow = 0;
    g_interrupted = false;
    void histUp() {
        if (hpos > 0) {
            if (hpos == g_hist.n) { saved.clear(); saved.put(line.str()); }
            --hpos; line.clear(); line.putz(g_hist[hpos]); cursor = line.n;
        }
    }
    void histDown() {
        if (hpos < g_hist.n) {
            ++hpos; line.clear();
            if (hpos == g_hist.n) line.put(saved.str()); else line.putz(g_hist[hpos]);
            cursor = line.n;
        }
    }
    refresh(prompt, line, cursor);
    for (;;) {
        char c;
        if (!readByte(c)) {
            if (g_interrupted) {           // ^C: abandon the line
                g_interrupted = false;
                write(1, "^C\r\n".ptr, 4);
                line.clear(); cursor = 0; g_prevRow = 0;
                rawOff(); saved.dispose();
                auto r = cz(""); line.dispose(); return r;
            }
            rawOff(); saved.dispose(); line.dispose(); return null;
        }
        if (c != '\t') tabs = 0;
        switch (c) {
            case '\r': case '\n': {
                // move to the end, then a newline
                cursor = line.n; refresh(prompt, line, cursor);
                write(1, "\r\n".ptr, 2);
                rawOff(); saved.dispose();
                auto r = cz(line.str()); line.dispose();
                return r;
            }
            case 4:                        // ^D
                if (line.n == 0) { write(1, "\r\n".ptr, 2); rawOff(); saved.dispose(); line.dispose(); return null; }
                if (cursor < line.n) { memmove(line.p + cursor, line.p + cursor + 1, line.n - cursor - 1); --line.n; }
                break;
            case 127: case 8:              // backspace
                if (cursor > 0) {
                    // remove one UTF-8 character
                    size_t st = cursor - 1; while (st > 0 && (cast(ubyte)line.p[st] & 0xC0) == 0x80) --st;
                    memmove(line.p + st, line.p + cursor, line.n - cursor); line.n -= cursor - st; cursor = st;
                }
                break;
            case 1: cursor = 0; break;                         // ^A
            case 5: cursor = line.n; break;                    // ^E
            case 2: if (cursor > 0) --cursor; break;           // ^B
            case 6: if (cursor < line.n) ++cursor; break;      // ^F
            case 11: line.n = cursor; break;                   // ^K
            case 21: memmove(line.p, line.p + cursor, line.n - cursor); line.n -= cursor; cursor = 0; break;   // ^U
            case 23: {                                         // ^W
                size_t st = cursor;
                while (st > 0 && line.p[st - 1] == ' ') --st;
                while (st > 0 && line.p[st - 1] != ' ') --st;
                memmove(line.p + st, line.p + cursor, line.n - cursor); line.n -= cursor - st; cursor = st;
                break;
            }
            case 12: write(1, "\x1b[H\x1b[2J".ptr, 7); g_prevRow = 0; break;   // ^L
            case 16: histUp(); break;                          // ^P
            case 14: histDown(); break;                        // ^N
            case '\t': {
                ++tabs;
                Vec!Cand cs; size_t start;
                auto before = line.str()[0 .. cursor];
                complete(before, cs, start);
                const tok = before[start .. $];
                if (cs.n == 0) { write(1, "\x07".ptr, 1); cs.dispose(); break; }
                if (cs.n == 1) {
                    Buf ins; ins.put(cs[0].word[tok.length .. $]);
                    if (!cs[0].noSpace) ins.put(' ');
                    insertAt(line, cursor, ins.str()); cursor += ins.n; ins.dispose();
                    cs.dispose(); break;
                }
                // common prefix
                size_t common = cs[0].word.length;
                foreach (ref x; cs[]) { size_t k = 0; while (k < common && k < x.word.length && x.word[k] == cs[0].word[k]) ++k; common = k; }
                if (common > tok.length) {
                    insertAt(line, cursor, cs[0].word[tok.length .. common]); cursor += common - tok.length;
                    cs.dispose(); break;
                }
                // nothing more to insert: list them (members always show their types)
                showCandidates(cs[]);
                g_prevRow = 0;
                cs.dispose();
                break;
            }
            case 27: {                                         // escape sequences
                char a, b;
                if (!readByte(a)) break;
                if (a != '[' && a != 'O') break;
                if (!readByte(b)) break;
                if (b >= '0' && b <= '9') {
                    char t; if (!readByte(t)) break;
                    if (b == '3' && t == '~') { if (cursor < line.n) { memmove(line.p + cursor, line.p + cursor + 1, line.n - cursor - 1); --line.n; } }
                    else if ((b == '1' || b == '7') && t == '~') cursor = 0;
                    else if ((b == '4' || b == '8') && t == '~') cursor = line.n;
                    break;
                }
                switch (b) {
                    case 'A': histUp(); break;
                    case 'B': histDown(); break;
                    case 'C': if (cursor < line.n) { ++cursor; while (cursor < line.n && (cast(ubyte)line.p[cursor] & 0xC0) == 0x80) ++cursor; } break;
                    case 'D': if (cursor > 0) { --cursor; while (cursor > 0 && (cast(ubyte)line.p[cursor] & 0xC0) == 0x80) --cursor; } break;
                    case 'H': cursor = 0; break;
                    case 'F': cursor = line.n; break;
                    default: break;
                }
                break;
            }
            default:
                if (cast(ubyte)c >= 32 || (cast(ubyte)c & 0x80)) insertAt(line, cursor, (&c)[0 .. 1]), ++cursor;
                break;
        }
        if (line.p) line.p[line.n] = 0;
        refresh(prompt, line, cursor);
    }
}
private void insertAt(ref Buf line, size_t at, const(char)[] s) {
    if (line.n + s.length + 1 >= line.cap) line.grow(line.n + s.length + 2);
    memmove(line.p + at + s.length, line.p + at, line.n - at);
    memcpy(line.p + at, s.ptr, s.length);
    line.n += s.length;
    line.p[line.n] = 0;
}
private void showCandidates(Cand[] cs) {
    Buf o;
    o.put("\r\n");
    const W = cols();
    bool withHints = false;
    foreach (ref c; cs) if (c.hint.length > 8) withHints = true;
    if (withHints && cs.length <= 60) {
        size_t w = 0; foreach (ref c; cs) if (c.word.length > w) w = c.word.length;
        foreach (ref c; cs) {
            o.put("  \x1b[1m"); o.put(c.word); o.put("\x1b[0m");
            foreach (_; c.word.length .. w + 2) o.put(' ');
            o.put("\x1b[2m");
            const room = W > cast(int)w + 6 ? W - cast(int)w - 6 : 10;
            o.put(c.hint.length > room ? c.hint[0 .. room] : c.hint);
            o.put("\x1b[0m\r\n");
        }
    } else {
        size_t w = 0; foreach (ref c; cs) if (c.word.length > w) w = c.word.length;
        const per = (W / (w + 2)) > 0 ? W / (w + 2) : 1;
        size_t col = 0, shown = 0;
        foreach (ref c; cs) {
            if (shown == 300) { o.put("\r\n  ... "); o.puti(cs.length - 300); o.put(" more"); break; }
            o.put(c.word); foreach (_; c.word.length .. w + 2) o.put(' ');
            if (++col == per) { o.put("\r\n"); col = 0; }
            ++shown;
        }
        if (col) o.put("\r\n");
    }
    write(1, o.p, o.n);
    o.dispose();
}
