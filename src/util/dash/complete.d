// dash completion: members after a '.', object names inside a lookup's string, command names,
// dash names and file paths.
module dash.complete;

import dash.rt;
import dash.value;
import dash.eval;
import dash.exec;
import dash.stmt;
import dash.parser;
import dash.lexer;

struct Cand { const(char)[] word; const(char)[] hint; bool noSpace; }

@nogc nothrow:

private bool isWordChar(char c) { return isIdentChar(c) || c == '-' || c == '.' || c == '/' || c == '~' || c == '_' || c == '+' || c == ':'; }

// Evaluate `text` without effects (commands, actions and writes are refused).
Value* pureEval(const(char)[] text) {
    const saved = g_pure; g_pure = true;
    const(char)[] rest;
    auto v = evalExprText(text, null, rest);
    g_pure = saved;
    if (!v) clearErr();
    return v;
}

private void addCand(ref Vec!Cand cs, const(char)[] w, const(char)[] hint, bool noSpace = false) {
    foreach (ref c; cs[]) if (c.word == w) return;
    Cand c; c.word = permDup(w); c.hint = hint; c.noSpace = noSpace; cs.push(c);
}

// Find the start of the expression that ends just before `dot` (a chain like a.b, f(x).y, (e).z, Type).
private size_t exprStart(const(char)[] s, size_t dot) {
    size_t i = dot;
    for (;;) {
        if (i == 0) return 0;
        const c = s[i - 1];
        if (c == ')' || c == ']' || c == '}') {
            // balanced group
            int d = 0; size_t j = i;
            while (j > 0) {
                const x = s[j - 1];
                if (x == ')' || x == ']' || x == '}') ++d;
                else if (x == '(' || x == '[' || x == '{') { --d; if (d == 0) { --j; break; } }
                --j;
            }
            i = j;
            // a function application before a group: f (x) -- stop at the group (the group itself is the value)
            if (i > 0 && s[i - 1] == '.') { --i; continue; }
            return i;
        }
        if (isIdentChar(c)) {
            size_t j = i; while (j > 0 && isIdentChar(s[j - 1])) --j;
            i = j;
            if (i > 0 && s[i - 1] == '.') { --i; continue; }
            return i;
        }
        if (c == '"') {
            size_t j = i - 1; while (j > 0 && s[j - 1] != '"') --j;
            return j > 0 ? j - 1 : 0;
        }
        return i;
    }
}

// Candidates for the line `s` with the cursor at its end.  `start` receives where the word being
// completed begins (the candidates replace s[start .. $]).
void complete(const(char)[] s, ref Vec!Cand cs, out size_t start) {
    size_t i = s.length;
    while (i > 0 && (isIdentChar(s[i - 1]))) --i;
    const word = s[i .. $];
    start = i;

    // 1. members: "<expr>.<partial>"
    if (i > 0 && s[i - 1] == '.' && i >= 2 && (isIdentChar(s[i - 2]) || s[i - 2] == ')' || s[i - 2] == ']' || s[i - 2] == '}' || s[i - 2] == '"')) {
        const es = exprStart(s, i - 1);
        const prefix = s[es .. i - 1];
        Value* v = null; Sym type = uint.max;
        if (prefix.length && isUpper(prefix[0]) && prefix.length == identLen(prefix)) {
            const t = intern(prefix);
            foreach (x; g_typeNames[]) if (x == t) type = t;
        }
        if (type == uint.max) {
            v = pureEval(prefix);
            if (!v) return;
            type = memberType(v);
        }
        Vec!Member ms; membersOf(v, type, ms);
        foreach (ref m; ms[]) {
            if (!startsWith(m.name, word)) continue;
            Buf h; h.put(m.kind == 0 ? "field  " : m.kind == 1 ? "method " : "ext    ");
            if (m.sig.length) { h.put(":: "); h.put(m.sig); }
            if (m.doc.length) { h.put("  -- "); h.put(m.doc); }
            addCand(cs, m.name, permDup(h.str()), true);
            h.dispose();
        }
        ms.dispose();
        return;
    }

    // 2. inside a string: an object's name for a lookup (domain "Wo) or a method's argument
    {
        size_t q = s.length; int quotes = 0;
        foreach (k, c; s) if (c == '"') { ++quotes; q = k; }
        if (quotes % 2 == 1) {
            const partial = s[q + 1 .. $];
            start = q + 1;
            // the word before the quote
            size_t e = q; while (e > 0 && s[e - 1] == ' ') --e;
            size_t b = e; while (b > 0 && (isIdentChar(s[b - 1]) || s[b - 1] == '.')) --b;
            const fn = s[b .. e];
            const(char)[] coll = null, key = "name";
            if (fn == "domain" || endsWith(fn, ".clone")) coll = "domains";
            else if (fn == "identity") coll = "identities";
            else if (fn == "service") coll = "services";
            else if (fn == "user") coll = "users";
            else if (fn == "app") { coll = "apps"; key = "id"; }
            else if (endsWith(fn, ".grant") || endsWith(fn, ".revoke")) {
                // Domain.grant takes an application id; App.grant takes a domain name
                const dot = b + fnDot(fn);
                const recv = s[exprStart(s, dot) .. dot];
                auto rv = recv.length ? pureEval(recv) : null;
                if (rv && rv.t == VT.Obj && symName(rv.name) == "Domain") { coll = "apps"; key = "id"; }
                else coll = "domains";
            }
            else if (endsWith(fn, ".usbOn") || endsWith(fn, ".usbOff")) { coll = "usbDevices"; key = "id"; }
            else if (endsWith(fn, ".allow") || endsWith(fn, ".deny")) coll = "domains";
            else if (endsWith(fn, ".route")) {
                foreach (r; ["direct", "vm:lan-opnsense"]) if (startsWith(r, partial)) addCand(cs, r, "route", true);
                auto ds = pureEval("domains");
                if (ds && ds.t == VT.List) foreach (k; 0 .. ds.n) { auto n = fieldS(ds.items[k], "name"); if (n && n.t == VT.Str) { Buf r; r.put("domain:"); r.put(str(n)); if (startsWith(r.str(), partial)) addCand(cs, r.str(), "through that domain's route", true); r.dispose(); } }
                return;
            }
            else if (endsWith(fn, ".devOn") || endsWith(fn, ".devOff")) {
                foreach (d; ["gpu", "audio", "camera", "mic", "usb", "input", "virt"]) if (startsWith(d, partial)) addCand(cs, d, "device class", true);
                return;
            }
            if (coll) {
                auto l = pureEval(coll);
                if (l && l.t == VT.List) foreach (k; 0 .. l.n) {
                    auto n = fieldS(l.items[k], key);
                    if (n && n.t == VT.Str && startsWith(str(n), partial)) addCand(cs, str(n), coll, true);
                }
                return;
            }
            // otherwise: a file path in a string
            filePaths(partial, cs, true);
            return;
        }
    }

    // 3. which position: the first word of a statement / stage, or an argument
    size_t w0 = i;
    while (w0 > 0 && isWordChar(s[w0 - 1])) --w0;
    const tokenLong = s[w0 .. $];          // including / . - ~ (paths, flags)
    size_t b = w0; while (b > 0 && s[b - 1] == ' ') --b;
    const atStart = b == 0 || s[b - 1] == '|' || s[b - 1] == ';' || s[b - 1] == '&' || s[b - 1] == '(' ||
                    (b >= 2 && s[b - 2 .. b] == "|>") || (b >= 2 && s[b - 2 .. b] == "$(");
    // is the statement a command?
    size_t stmtStart = 0;
    foreach (k; 0 .. b) if (s[k] == ';' || (s[k] == '|' && k + 1 < s.length && s[k + 1] != '>')) stmtStart = k + 1;
    bool forced;
    const sc = classify(trim(s[stmtStart .. $]), forced);

    if (atStart && (tokenLong.length == 0 || (tokenLong[0] != '/' && tokenLong[0] != '.' && tokenLong[0] != '~'))) {
        start = i;
        // commands on $PATH and shell builtins
        foreach (bi; ["cd", "pwd", "exit", "export", "unset", "source", "history", "jobs", "wait", "which", "type",
                      "help", "linux", "echo", "exec", "arm", "dry-run"])
            if (startsWith(bi, word)) addCand(cs, bi, "builtin");
        pathCommands(word, cs);
        dashNames(word, cs);
        foreach (kw; ["let", "if", "case", "do", "data"]) if (startsWith(kw, word)) addCand(cs, kw, "keyword");
        return;
    }
    if (sc == SC.Cmd && !atStart) {
        // arguments of a command: files
        start = w0;
        filePaths(tokenLong, cs, false);
        return;
    }
    // an expression: dash names
    start = i;
    dashNames(word, cs);
    foreach (kw; ["let", "in", "if", "then", "else", "case", "of", "do", "where"]) if (startsWith(kw, word)) addCand(cs, kw, "keyword");
}
private size_t identLen(const(char)[] s) { size_t k = 0; while (k < s.length && isIdentChar(s[k])) ++k; return k; }
private size_t fnDot(const(char)[] fn) { foreach_reverse (k, c; fn) if (c == '.') return k; return 0; }

private void dashNames(const(char)[] word, ref Vec!Cand cs) {
    // object and data types (Type.<Tab> explores one)
    foreach (t; g_typeNames[]) {
        const nm = symName(t);
        if (startsWith(nm, word)) addCand(cs, nm, "type   -- Type.<Tab> or :m Type lists its members", true);
    }
    foreach (s; 0 .. symCount()) {
        const f = globalFlags(cast(Sym)s);
        if (!(f & (GF.User | GF.Lib | GF.ShellVar)) || (f & GF.Ext)) continue;
        const nm = symName(cast(Sym)s);
        if (nm.length == 0 || !isAlpha(nm[0]) || !startsWith(nm, word)) continue;
        const sg = sigOf(cast(Sym)s);
        Buf h; h.put(f & GF.User ? "yours  " : f & GF.ShellVar ? "var    " : "dash   "); if (sg.length) { h.put(":: "); h.put(sg); }
        addCand(cs, nm, permDup(h.str()));
        h.dispose();
    }
}

private void pathCommands(const(char)[] word, ref Vec!Cand cs) {
    auto path = getenv("PATH");
    const(char)[] ps = path ? path[0 .. strlen(path)] : "/bin:/usr/bin";
    size_t st = 0;
    foreach (k; 0 .. ps.length + 1) {
        if (k == ps.length || ps[k] == ':') {
            if (k > st) {
                auto z = cz(ps[st .. k]); auto d = opendir(z); free(z);
                if (d) {
                    for (;;) {
                        auto e = cast(Dirent*)readdir(d); if (e is null) break;
                        const n = e.d_name.ptr[0 .. strlen(e.d_name.ptr)];
                        if (n.length == 0 || n[0] == '.' || !startsWith(n, word)) continue;
                        addCand(cs, n, "command");
                        if (cs.n > 4000) break;
                    }
                    closedir(d);
                }
            }
            st = k + 1;
        }
    }
}

// Complete a path: "dir/par" -> entries of dir starting with "par".
void filePaths(const(char)[] tok, ref Vec!Cand cs, bool inString) {
    size_t slash = tok.length;
    foreach_reverse (k, c; tok) if (c == '/') { slash = k; break; }
    Buf dir;
    const(char)[] base;
    if (slash == tok.length) { dir.put("."); base = tok; }
    else {
        auto d = tok[0 .. slash + 1];
        if (d.length && d[0] == '~') { auto h = getenv("HOME"); dir.putz(h ? h : "/"); dir.put(d[1 .. $]); }
        else dir.put(d.length ? d : "/");
        base = tok[slash + 1 .. $];
    }
    auto dh = opendir(dir.cstr());
    if (dh) {
        for (;;) {
            auto e = cast(Dirent*)readdir(dh); if (e is null) break;
            const n = e.d_name.ptr[0 .. strlen(e.d_name.ptr)];
            if (n == "." || n == "..") continue;
            if (n[0] == '.' && (base.length == 0 || base[0] != '.')) continue;
            if (!startsWith(n, base)) continue;
            Buf full; full.put(slash == tok.length ? "" : tok[0 .. slash + 1]); full.put(n);
            // directory?
            Buf p; p.put(dir.str()); p.put('/'); p.put(n);
            Stat st; const isDir = stat(p.cstr(), &st) == 0 && (st.st_mode & 0xF000) == 0x4000;
            if (isDir) full.put('/');
            addCand(cs, full.str(), isDir ? "directory" : "file", isDir || inString);
            full.dispose(); p.dispose();
        }
        closedir(dh);
    }
    dir.dispose();
}
