// dash statements: what a line is (command, expression, definition, meta), the pipelines that mix
// the two halves, printing results, and the meta commands.
module dash.stmt;

import dash.rt;
import dash.value;
import dash.ast;
import dash.lexer;
import dash.parser;
import dash.eval;
import dash.exec;
import dash.objects;

enum SC : ubyte { Empty, Meta, Cmd, Expr, Def, Let }

@nogc nothrow:

const(char)[] trim(const(char)[] s) {
    size_t a = 0, b = s.length;
    while (a < b && (isSpace(s[a]) || s[a] == '\n')) ++a;
    while (b > a && (isSpace(s[b - 1]) || s[b - 1] == '\n')) --b;
    return s[a .. b];
}
private const(char)[] firstWord(const(char)[] s) {
    size_t e = 0;
    while (e < s.length && (isIdentChar(s[e]) || s[e] == '-' || s[e] == '.' || s[e] == '/')) ++e;
    return s[0 .. e];
}
private const(char)[] identAt(const(char)[] s) {
    size_t e = 0;
    while (e < s.length && isIdentChar(s[e])) ++e;
    return s[0 .. e];
}
private bool isKeyword(const(char)[] w) {
    switch (w) { case "if", "case", "do", "let", "data", "where", "then", "else", "of", "in": return true; default: return false; }
}

// Does the statement define something ("f x y = ...", "f x | g = ...", "f :: T", "x <+> y = ...")?
bool looksLikeDefinition(const(char)[] text) {
    Vec!Tok ts;
    if (!lex(text, ts)) { ts.dispose(); clearErr(); return false; }
    scope (exit) ts.dispose();
    if (ts.n < 2) return false;
    size_t k = 0;
    if (ts[0].t == T.LParen && ts.n > 3 && ts[1].t == T.Op && ts[2].t == T.RParen) k = 3;
    else if (ts[0].t == T.VarId) k = 1;
    else if (ts[0].t == T.ConId && ts[1].t == T.DotField && !ts[1].spaceBefore) k = 2;   // Type.member
    else return false;
    if (ts[k].t == T.DColon) return true;
    if (ts[k].t == T.Comma) return false;
    int depth = 0; bool sawOp = false;
    for (; k < ts.n; ++k) {
        const t = ts[k].t;
        if (t == T.LParen || t == T.LBracket || t == T.LBrace) { ++depth; continue; }
        if (t == T.RParen || t == T.RBracket || t == T.RBrace) { --depth; continue; }
        if (depth > 0) continue;
        if (t == T.Equals) return true;
        if (t == T.Pipe) return true;     // guards
        if (t == T.EOF) return false;
        switch (t) {
            case T.VarId, T.ConId, T.Int, T.Float, T.Str, T.Char, T.At, T.Comma: continue;
            case T.Op: case T.BackOp:
                if (ts[k].s == ":" || ts[k].s == "-") continue;
                if (sawOp) return false; sawOp = true; continue;
            default: return false;
        }
    }
    return false;
}

// What kind of statement is this?
SC classify(const(char)[] text, out bool forced) {
    forced = false;
    if (text.length == 0 || text[0] == '#') return SC.Empty;
    if (text[0] == ':' ) return SC.Meta;
    if (text[0] == '=' && (text.length == 1 || text[1] == ' ')) { forced = true; return SC.Expr; }
    const c = text[0];
    if (isDigit(c) || c == '"' || c == '(' || c == '[' || c == '\\' || c == '{') return SC.Expr;
    if (c == '-' && text.length > 1 && isDigit(text[1])) return SC.Expr;
    if (c == '\'' && text.length >= 3 && text[2] == '\'') return SC.Expr;
    if (!isAlpha(c)) return SC.Cmd;                                  // ./x  /bin/x  ~  $X  'quoted'
    const w = identAt(text);
    const rest = text[w.length .. $];
    // NAME=value (no spaces): a shell variable (optionally before a command)
    if (rest.length && rest[0] == '=' && (rest.length == 1 || rest[1] != '=')) return SC.Cmd;
    if (w == "let") {
        // "let ... in e" is an expression; "let x = 1" defines
        Vec!Tok ts; lex(text, ts);
        bool hasIn = false; foreach (ref t; ts[]) if (t.t == T.KwIn) hasIn = true;
        ts.dispose(); clearErr();
        return hasIn ? SC.Expr : SC.Let;
    }
    if (w == "data") return SC.Def;
    if (isKeyword(w)) return SC.Expr;
    if (isUpper(c)) {
        if (looksLikeDefinition(text)) return SC.Def;                // Type.member x = ...
        return SC.Expr;
    }
    const cls = nameClass(w);
    // a definition -- unless it starts with a command's name you have not defined in dash yourself
    if (looksLikeDefinition(text) && (cls == 0 || cls == 1 || cls == 3)) return SC.Def;
    // "x.field" on a dash name is an expression even when x is also a command (rare)
    if (rest.length > 1 && rest[0] == '.' && isLower(rest[1]) && (cls == 1 || cls == 3)) return SC.Expr;
    switch (cls) {
        case 3: return SC.Expr;       // yours
        case 2: return SC.Cmd;        // a command / builtin
        case 1: return SC.Expr;       // the library
        default: return SC.Cmd;       // unknown: try it as a command ("not found" explains)
    }
}

// ── pipelines: split a statement into command (|) and function (|>) stages ──────────────────────
struct Stage { bool cmd; const(char)[] text; }

void splitStages(const(char)[] s, bool firstCmd, ref Vec!Stage out_) {
    bool cmd = firstCmd;
    size_t st = 0, i = 0;
    int depth = 0;
    while (i < s.length) {
        const c = s[i];
        if (cmd) {
            if (c == '\\' && i + 1 < s.length) { i += 2; continue; }
            if (c == '\'') { ++i; while (i < s.length && s[i] != '\'') ++i; ++i; continue; }
            if (c == '"') { ++i; while (i < s.length && s[i] != '"') { if (s[i] == '\\') ++i; ++i; } ++i; continue; }
            if (c == '$' && i + 1 < s.length && s[i + 1] == '(') {
                int d = 0; ++i;
                while (i < s.length) { if (s[i] == '(') ++d; else if (s[i] == ')') { --d; if (d == 0) { ++i; break; } } ++i; }
                continue;
            }
            if (c == '|' && i + 1 < s.length && s[i + 1] == '>') {
                Stage sg; sg.cmd = true; sg.text = trim(s[st .. i]); out_.push(sg);
                i += 2; st = i; cmd = false; depth = 0; continue;
            }
            ++i; continue;
        }
        // expression stage
        if (c == '"') { ++i; while (i < s.length && s[i] != '"') { if (s[i] == '\\') ++i; ++i; } ++i; continue; }
        if (c == '\'' && i + 2 < s.length && (s[i + 2] == '\'' || (s[i + 1] == '\\' && i + 3 < s.length && s[i + 3] == '\''))) { i += s[i + 1] == '\\' ? 4 : 3; continue; }
        if (c == '-' && i + 1 < s.length && s[i + 1] == '-' && (i + 2 >= s.length || s[i + 2] == ' ')) break;   // comment
        if (c == '$' && i + 1 < s.length && s[i + 1] == '(') {
            int d = 0; ++i;
            while (i < s.length) { if (s[i] == '(') ++d; else if (s[i] == ')') { --d; if (d == 0) { ++i; break; } } ++i; }
            continue;
        }
        if (c == '(' || c == '[' || c == '{') { ++depth; ++i; continue; }
        if (c == ')' || c == ']' || c == '}') { --depth; ++i; continue; }
        if (depth == 0 && c == '|') {
            const next = i + 1 < s.length ? s[i + 1] : 0;
            const prev = i > 0 ? s[i - 1] : 0;
            if (next == '>') {
                Stage sg; sg.cmd = false; sg.text = trim(s[st .. i]); out_.push(sg);
                i += 2; st = i; continue;
            }
            if (next != '|' && prev != '|' && !isSym(prev) && !isSym(next)) {
                Stage sg; sg.cmd = false; sg.text = trim(s[st .. i]); out_.push(sg);
                ++i; st = i; cmd = true; continue;
            }
        }
        ++i;
    }
    Stage sg; sg.cmd = cmd; sg.text = trim(s[st .. $]); out_.push(sg);
}
private bool isSym(char c) {
    switch (c) { case '!', '#', '$', '%', '&', '*', '+', '.', '/', '<', '=', '>', '?', '@', '\\', '^', '-', '~', ':': return true; default: return false; }
}

// Parse and evaluate one expression; anything after a top-level ';' is returned in `rest`.
__gshared bool g_parseFailed;
Value* evalExprText(const(char)[] text, Env* env, out const(char)[] rest) {
    Parser p;
    g_parseFailed = false;
    if (!p.init(text)) { p.dispose(); g_parseFailed = true; return null; }
    auto e = p.expr();
    if (e) {
        if (p.at(T.Semi)) rest = text[p.tok().end .. $];
        else if (!p.at(T.EOF)) { p.fail("unexpected text after the expression"); e = null; }
    }
    p.dispose();
    if (!e) { g_parseFailed = true; return null; }
    return eval(e, env);
}

// `f word word`: a dash function called like a command -- its arguments are shell words (quotes,
// $vars, globs), numbers and Bools read as such.  Used when the line does not work as Haskell.
Value* commandStyleCall(const(char)[] text) {
    const w = identAt(text);
    auto f = getGlobal(intern(w));
    if (!f) return null;
    auto cl = parseCommand(text);
    if (!cl || cl.items.length != 1 || cl.items[0].pipes.length != 1 || cl.items[0].pipes[0].cmds.length != 1) return null;
    auto sc = cl.items[0].pipes[0].cmds[0];
    Vec!(char*) argv;
    foreach (k, ref wd; sc.words) { if (k == 0) continue; if (!expandWord(wd, null, argv)) { argv.dispose(); return null; } }
    auto args = newItems(argv.n);
    foreach (k, a; argv[]) {
        const s = a[0 .. strlen(a)];
        import dash.lib : readValue;
        auto v = readValue(s);
        args[k] = v ? v : mkStr(s);
        free(a);
    }
    const n = argv.n; argv.dispose();
    if (n == 0) return f.t == VT.Func && f.arity > f.n ? apply(f, args, 0) : f;
    return apply(f, args, n);
}
private bool notInScopeErr() { return startsWith(errText(), "not in scope: "); }

// Where a top-level ';' ends the first statement of a line (size_t.max: none).  Quotes and (), [],
// {} nest (so `$(a; b)`, `{ x = 1; y = 2 }`, ';' as a Char stay whole); ';;' is not a separator;
// a comment (`--` in an expression, `#` in a command) ends the code.
private size_t topLevelSemi(const(char)[] s, bool cmd) {
    int depth = 0;
    for (size_t i = 0; i < s.length; ++i) {
        const c = s[i];
        const bool wordStart = i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t';
        if (c == '\\' && i + 1 < s.length) { ++i; continue; }
        if (c == '"') { ++i; while (i < s.length && s[i] != '"') { if (s[i] == '\\') ++i; ++i; } continue; }
        if (c == '\'' && (i == 0 || !isIdentChar(s[i - 1]))) {      // 'quoted' or a 'c' Char (not x')
            ++i; while (i < s.length && s[i] != '\'') { if (!cmd && s[i] == '\\') ++i; ++i; }
            continue;
        }
        if (c == '(' || c == '[' || c == '{') { ++depth; continue; }
        if (c == ')' || c == ']' || c == '}') { if (depth) --depth; continue; }
        if (depth) continue;
        if (!cmd && c == '-' && i + 1 < s.length && s[i + 1] == '-' && wordStart) return size_t.max;
        if (cmd && c == '#' && wordStart) return size_t.max;
        if (c == ';') {
            if (i + 1 < s.length && s[i + 1] == ';') { ++i; continue; }
            return i;
        }
    }
    return size_t.max;
}

// ── running a statement ─────────────────────────────────────────────────────────────────────────
__gshared bool g_quiet;          // scripts: do not print definitions' echoes (none are printed anyway)

void reportError() {
    if (!g_errSet) return;
    Buf b; b.put("\x1b[31mdash: "); b.put(errText()); b.put("\x1b[0m\n");
    errOut(b.str()); b.dispose();
    clearErr();
    g_lastStatus = 1;              // a failed statement fails the script (`-c`, $?, the prompt)
}

// Run one statement.  Errors are reported here.
void runStatement(const(char)[] text) {
    text = trim(text);
    bool forced;
    const sc = classify(text, forced);
    final switch (sc) {
        case SC.Empty: return;
        case SC.Meta: meta(text); return;
        case SC.Def: {
            Parser p;
            if (!p.init(text)) { p.dispose(); reportError(); return; }
            Vec!(Decl*) ds;
            for (;;) {
                auto d = p.decl();
                if (!d) break;
                ds.push(d);
                if (p.accept(T.Semi)) { if (p.at(T.EOF)) break; continue; }
                if (!p.at(T.EOF)) { p.fail("unexpected text after the definition"); break; }
                break;
            }
            if (!g_errSet) defineGlobal(ds[]);
            ds.dispose(); p.dispose();
            reportError();
            return;
        }
        case SC.Let: {
            Parser p;
            if (!p.init(text)) { p.dispose(); reportError(); return; }
            p.next();                                   // 'let'
            Decl*[] ds;
            if (p.decls(ds)) {
                if (!p.at(T.EOF) && !p.at(T.Semi)) p.fail("unexpected text after 'let'");
                else {
                    // each name defined here is yours (and consecutive equations group)
                    defineGlobal(ds);
                }
            }
            p.dispose();
            reportError();
            return;
        }
        case SC.Expr: case SC.Cmd: {
            // `;` separates statements: each part is classified on its own (`pwd; me.domain`)
            const cut = topLevelSemi(text, sc == SC.Cmd);
            if (cut != size_t.max) {
                runStatement(text[0 .. cut]);
                if (!g_exitRequested && !g_interrupted) runStatement(text[cut + 1 .. $]);
                return;
            }
            if (forced) text = trim(text[1 .. $]);
            Vec!Stage stages;
            splitStages(text, sc == SC.Cmd, stages);
            runStages(stages[]);
            stages.dispose();
            reportError();
            return;
        }
    }
}

void runStages(Stage[] stages) {
    Value* cur = null;
    foreach (k, ref sg; stages) {
        if (g_errSet || g_interrupted) return;
        const last = k + 1 == stages.length;
        const nextIsFn = !last && !stages[k + 1].cmd;
        if (sg.text.length == 0) { setErr(k == 0 ? "empty statement" : "an empty pipeline stage"); return; }
        if (sg.cmd) {
            if (cur is null) {
                if (nextIsFn || (!last && stages[k + 1].cmd)) {
                    Buf o; runCapture(sg.text, null, o);
                    cur = linesToList(o.str()); o.dispose();
                } else {
                    runCommandText(sg.text, null);
                    return;
                }
            } else {
                Buf input; linesOf(input, cur);
                if (last) { runWithInput(sg.text, null, input.str(), null); input.dispose(); return; }
                Buf o; runWithInput(sg.text, null, input.str(), &o); input.dispose();
                cur = linesToList(o.str()); o.dispose();
            }
        } else {
            const(char)[] rest;
            auto v = evalExprText(sg.text, null, rest);
            if (!v && k == 0 && !g_interrupted && (g_parseFailed || notInScopeErr())) {
                // "report ." / "greet bob": a dash function used like a command
                const w = identAt(sg.text);
                auto f = w.length ? getGlobal(intern(w)) : null;
                if (f && f.t == VT.Func && (globalFlags(intern(w)) & (GF.User | GF.Lib))) {
                    Buf saved; saved.put(errText());
                    clearErr();
                    v = commandStyleCall(sg.text);
                    if (!v && !g_errSet) setErr(saved.str());
                    saved.dispose();
                }
            }
            if (!v) return;
            if (rest.length && stages.length == 1) {        // "e1; e2"
                if (cur is null) display(v);
                runStatement(rest);
                return;
            }
            if (cur is null) cur = v;
            else { cur = apply1(v, cur); if (!cur) return; }
        }
    }
    if (cur !is null && !g_errSet) { display(cur); setGlobal(intern("it"), cur, GF.User); g_lastStatus = 0; }
}

// ── printing results ────────────────────────────────────────────────────────────────────────────
private int termCols() {
    struct WS { ushort row, col, x, y; }
    WS ws;
    if (ioctl(1, 0x5413, &ws) == 0 && ws.col > 10) return ws.col;
    return 100;
}
private void cellText(ref Buf b, Value* v) {
    if (v.t == VT.Str) b.put(str(v));
    else if (v.t == VT.List && v.n <= 8) { foreach (k; 0 .. v.n) { if (k) b.put(", "); cellText(b, v.items[k]); } }
    else if (v.t == VT.Ctor && v.name == S_Nothing) b.put("-");
    else if (v.t == VT.Ctor && v.name == S_Just && v.n == 1) cellText(b, v.items[0]);
    else showValue(b, v);
}
void display(Value* v) {
    switch (v.t) {
        case VT.Unit: return;
        case VT.Str: out_(str(v)); if (v.n == 0 || v.s[v.n - 1] != '\n') outc('\n'); break;
        case VT.List: {
            if (v.n == 0) { out_("[]\n"); break; }
            bool allStr = true, allRec = true;
            foreach (k; 0 .. v.n) { if (v.items[k].t != VT.Str) allStr = false; if (v.items[k].t != VT.Record && v.items[k].t != VT.Obj) allRec = false; }
            if (allStr) { foreach (k; 0 .. v.n) { out_(str(v.items[k])); outc('\n'); } break; }
            if (allRec) { table(v); break; }
            Buf b; showValue(b, v); out_(b.str()); outc('\n'); b.dispose();
            break;
        }
        case VT.Record: case VT.Obj: {
            if (v.t == VT.Obj) { out_("\x1b[1m"); out_(symName(v.name)); out_("\x1b[0m\n"); }
            size_t w = 0; foreach (k; 0 .. v.n) if (symName(v.keys[k]).length > w) w = symName(v.keys[k]).length;
            foreach (k; 0 .. v.n) {
                out_("  "); out_(symName(v.keys[k]));
                foreach (_; symName(v.keys[k]).length .. w) outc(' ');
                out_("  "); Buf b; cellText(b, v.items[k]);
                const cols = termCols() - cast(int)w - 6;
                out_(b.n > cols && cols > 10 ? b.str()[0 .. cols] : b.str()); outc('\n'); b.dispose();
            }
            if (v.t == VT.Obj) {
                size_t nm = 0; const t = memberType(v);
                foreach (ref m; g_methods[]) if (m.type == t) ++nm;
                if (nm) { out_("\x1b[2m  ("); outi(nm); out_(" methods -- :m or Tab after a '.' to explore)\x1b[0m\n"); }
            }
            break;
        }
        case VT.Func: {
            out_("<function "); out_(symName(v.name));
            Buf b; typeOf(b, v); out_(" :: "); out_(b.str()); b.dispose();
            out_(">\n"); break;
        }
        default: { Buf b; showValue(b, v); out_(b.str()); outc('\n'); b.dispose(); }
    }
    oflush();
}
private void table(Value* l) {
    Vec!Sym cols;
    foreach (k; 0 .. l.n) { auto r = l.items[k]; foreach (j; 0 .. r.n) { bool have = false; foreach (c; cols[]) if (c == r.keys[j]) have = true; if (!have) cols.push(r.keys[j]); } }
    const nc = cols.n;
    auto width = cast(size_t*)calloc(nc, size_t.sizeof);
    auto cells = cast(Buf*)calloc(l.n * nc, Buf.sizeof);
    foreach (c; 0 .. nc) width[c] = symName(cols[c]).length;
    foreach (k; 0 .. l.n) foreach (c; 0 .. nc) {
        auto v = field(l.items[k], cols[c]);
        auto cb = &cells[k * nc + c];
        if (v) cellText(*cb, v);
        if (cb.n > 32) { cb.n = 31; cb.put("~"); }
        if (cb.n > width[c]) width[c] = cb.n;
    }
    // as many columns as fit
    const tw = termCols();
    size_t used = 0, shown = 0;
    foreach (c; 0 .. nc) { if (used + width[c] + 2 > tw && shown > 0) break; used += width[c] + 2; ++shown; }
    out_("\x1b[1m");
    foreach (c; 0 .. shown) { out_(symName(cols[c])); if (c + 1 < shown) foreach (_; symName(cols[c]).length .. width[c] + 2) outc(' '); }
    out_("\x1b[0m\n");
    foreach (k; 0 .. l.n) {
        foreach (c; 0 .. shown) { auto cb = &cells[k * nc + c]; out_(cb.str()); if (c + 1 < shown) foreach (_; cb.n .. width[c] + 2) outc(' '); }
        outc('\n');
    }
    if (shown < nc) {
        out_("\x1b[2m(");
        outi(nc - shown); out_(" more field"); if (nc - shown > 1) outc('s'); out_(": ");
        foreach (c; shown .. nc) { if (c > shown) out_(", "); out_(symName(cols[c])); }
        out_(" -- e.g. map (.");
        out_(symName(cols[shown])); out_(") it)\x1b[0m\n");
    }
    foreach (k; 0 .. l.n * nc) cells[k].dispose();
    free(cells); free(width); cols.dispose();
}

// ── members: what a value (or a type) offers ────────────────────────────────────────────────────
struct Member { const(char)[] name; const(char)[] sig; const(char)[] doc; ubyte kind; }   // 0 field, 1 method, 2 extension
void membersOf(Value* v, Sym type, ref Vec!Member out_) {
    if (v && (v.t == VT.Record || v.t == VT.Obj)) {
        foreach (k; 0 .. v.n) {
            Member m; m.name = symName(v.keys[k]); m.kind = 0;
            Buf b; typeOf(b, v.items[k]); m.sig = permDup(b.str()); b.dispose();
            foreach (ref fd; g_fieldDocs[]) if (fd.type == type && fd.name == v.keys[k]) m.doc = fd.doc;
            out_.push(m);
        }
    } else {
        foreach (ref fd; g_fieldDocs[]) if (fd.type == type) { Member m; m.name = symName(fd.name); m.sig = fd.sig; m.doc = fd.doc; m.kind = 0; out_.push(m); }
    }
    foreach (ref me; g_methods[]) if (me.type == type) {
        Member m; m.name = symName(me.name); m.sig = me.sig; m.doc = me.doc; m.kind = 1; out_.push(m);
    }
    if (v && v.t == VT.Str) foreach (ref me; g_methods[]) if (me.type == intern("List")) {
        bool dup = false; foreach (ref x; out_[]) if (x.name == symName(me.name)) dup = true;
        if (!dup) { Member m; m.name = symName(me.name); m.sig = me.sig; m.doc = me.doc; m.kind = 1; out_.push(m); }
    }
    // extensions: globals named "Type.member"
    const tn = symName(type);
    foreach (s; 0 .. symCount()) {
        const nm = symName(cast(Sym)s);
        if (nm.length > tn.length + 1 && nm[0 .. tn.length] == tn && nm[tn.length] == '.' && (globalFlags(cast(Sym)s) & GF.Ext)) {
            Member m; m.name = nm[tn.length + 1 .. $]; m.kind = 2;
            m.sig = sigOf(cast(Sym)s); m.doc = "your extension";
            out_.push(m);
        }
    }
}
void printMembers(Value* v, Sym type) {
    Vec!Member ms;
    membersOf(v, type, ms);
    out_("\x1b[1m"); out_(symName(type)); out_("\x1b[0m");
    outc('\n');
    size_t w = 0; foreach (ref m; ms[]) if (m.name.length > w) w = m.name.length;
    foreach (kind; 0 .. 3) {
        bool header = false;
        foreach (ref m; ms[]) {
            if (m.kind != kind) continue;
            if (!header) { out_(kind == 0 ? "  fields\n" : kind == 1 ? "  methods\n" : "  extensions\n"); header = true; }
            out_("    ."); out_(m.name); foreach (_; m.name.length .. w + 1) outc(' ');
            if (m.sig.length) { out_(":: "); out_(m.sig); }
            if (m.doc.length) { out_("\x1b[2m  -- "); out_(m.doc); out_("\x1b[0m"); }
            outc('\n');
        }
    }
    if (ms.n == 0) out_("  (no members)\n");
    ms.dispose();
    oflush();
}

// ── meta commands ───────────────────────────────────────────────────────────────────────────────
void meta(const(char)[] text) {
    size_t e = 1; while (e < text.length && !isSpace(text[e])) ++e;
    const cmd = text[1 .. e];
    const arg = trim(text[e .. $]);
    switch (cmd) {
        case "q": case "quit": g_exitRequested = true; g_exitCode = 0; return;
        case "t": case "type": {
            if (arg.length == 0) { out_("usage: :t expression\n"); return; }
            // a bare name with a declared signature: show the signature without running anything
            const w = identAt(arg);
            if (w.length == arg.length && sigOf(intern(w)).length) { out_(arg); out_(" :: "); out_(sigOf(intern(w))); outc('\n'); oflush(); return; }
            const saved = g_pure; g_pure = true;
            const(char)[] rest;
            auto v = evalExprText(arg, null, rest);
            g_pure = saved;
            if (!v) { reportError(); return; }
            Buf b; typeOf(b, v); out_(arg); out_(" :: "); out_(b.str()); outc('\n'); b.dispose(); oflush();
            return;
        }
        case "m": case "members": {
            if (arg.length == 0) { out_("usage: :m value   or   :m Type\n"); return; }
            if (isUpper(arg[0]) && identAt(arg).length == arg.length) { printMembers(null, intern(arg)); return; }
            const saved = g_pure; g_pure = true;
            const(char)[] rest;
            auto v = evalExprText(arg, null, rest);
            g_pure = saved;
            if (!v) { reportError(); return; }
            printMembers(v, memberType(v));
            return;
        }
        case "doc": case "d": case "i": case "info": {
            const s = intern(arg);
            auto v = getGlobal(s);
            if (!v && !sigOf(s).length) { out_("no dash name '"); out_(arg); out_("'\n"); oflush(); return; }
            out_(arg);
            if (sigOf(s).length) { out_(" :: "); out_(sigOf(s)); }
            outc('\n');
            if (docOf(s).length) { out_("  "); out_(docOf(s)); outc('\n'); }
            if (globalFlags(s) & GF.User) out_("  (defined by you)\n");
            oflush();
            return;
        }
        case "load": case "l": {
            if (arg.length == 0) { out_("usage: :load file\n"); return; }
            if (g_runFile) g_runFile(arg);
            return;
        }
        case "env": {
            foreach (s; 0 .. symCount()) {
                if (!(globalFlags(cast(Sym)s) & (GF.User | GF.ShellVar))) continue;
                auto v = getGlobal(cast(Sym)s); if (!v) continue;
                out_(symName(cast(Sym)s)); out_(" :: ");
                Buf b; typeOf(b, v); out_(b.str()); b.dispose(); outc('\n');
            }
            oflush();
            return;
        }
        case "h": case "help": case "?": help(arg); return;
        default:
            out_("unknown meta command :"); out_(cmd); out_("  (:help lists them)\n"); oflush();
    }
}
alias RunFileFn = void function(const(char)[] path) @nogc nothrow;
__gshared RunFileFn g_runFile;

void help(const(char)[] topic) {
    if (topic == "objects" || topic == "o") {
        out_(
"\x1b[1mThe object model\x1b[0m  (every value below prints as a table; Tab after a '.' explores it)\n" ~
"  domains  domain \"Work\"            Domain: .start .stop .pause .route \"vm:lan-opnsense\" .grant \"wl-files\"\n" ~
"                                      .usbOn \"vid:pid\" .clone \"New\" .snapshot .caps .fs .apps\n" ~
"  identities  identity \"Banking\"   Identity: .trust .ceiling .caps .switch\n" ~
"  services  service \"x\"            Service: .state .rights .caps\n" ~
"  users  namespaces  procs  apps  usbDevices  objects  network  system  me\n" ~
"  :m Domain        every field, method and extension of a type\n" ~
"  Domain.running d = d.state == \"running\"      -- add your own member (an extension)\n" ~
"  domains |> filter (.running) |> map (.name)\n" ~
"  arm / dry-run    destructive methods (delete, identity switch, namespace enter) need `arm` first\n");
        oflush(); return;
    }
    if (topic == "haskell" || topic == "expr") {
        out_(
"\x1b[1mExpressions\x1b[0m\n" ~
"  1 + 2 * 3     \"a\" ++ \"b\"     [1..10]     [x*x | x <- [1..10], even x]     (1, \"one\")\n" ~
"  \\x -> x + 1     map (*2) xs     f . g     f $ x     x |> f     xs !! 0\n" ~
"  if c then a else b     case xs of { [] -> 0; (x:_) -> x }     let y = 2 in y * y\n" ~
"  { name = \"x\", n = 1 }   r.name   r { n = 2 }   (.name)\n" ~
"\x1b[1mDefinitions\x1b[0m\n" ~
"  double x = x * 2\n  fact 0 = 1\n  fact n = n * fact (n - 1)\n  sign n | n < 0 = -1 | otherwise = 1\n" ~
"  data Shape = Circle Float | Rect Float Float\n  :t e   :m value   :doc name   :{ ... :} for multi-line input\n");
        oflush(); return;
    }
    if (topic == "commands" || topic == "bash") {
        out_(
"\x1b[1mCommands\x1b[0m (bash syntax)\n" ~
"  ls -la | grep x > out.txt     a && b || c     cmd &     NAME=value     export NAME=v\n" ~
"  \"$name\" uses a dash binding or an environment variable;  $((expr)) embeds any dash expression\n" ~
"  $(cmd)  inside a command: its output;  inside an expression: its output lines\n" ~
"\x1b[1mBetween the halves\x1b[0m\n" ~
"  ls |> filter (isSuffixOf \".d\") |> length        command output -> function (as lines)\n" ~
"  domains |> map (.name) | sort                    value -> command (as lines)\n" ~
"  files <- ls /tmp      (in a do block: bind a command's output)\n");
        oflush(); return;
    }
    out_(
"\x1b[1mdash\x1b[0m -- bash where you run programs, Haskell where you compute, over the OS's objects.\n" ~
"  ls -la /tmp                                  a command\n" ~
"  [x * 2 | x <- [1..5]]                        an expression\n" ~
"  double x = x * 2                             a definition\n" ~
"  domains |> filter (\\d -> d.state == \"running\")   the object model\n" ~
"  w.<Tab>                                      explore an object's fields and methods\n" ~
"  linux                                        drop into the Linux shell (zsh); exit returns here\n" ~
"  :help objects | :help commands | :help haskell     :t e   :m x   :doc f   :quit\n" ~
"  The full manual:  less /dash.md\n");
    oflush();
}
