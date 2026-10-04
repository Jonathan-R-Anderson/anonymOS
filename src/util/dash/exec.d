// dash commands: the bash half.  Parses a command line (words, quoting, expansions, pipes,
// && || ; &, redirections) and runs it (fork/exec, pipelines, capture, builtins, `linux`).
module dash.exec;

import dash.rt;
import dash.value;

// ── hooks into the evaluator ────────────────────────────────────────────────────────────────────
alias LookupFn = Value* function(const(char)[] name, void* env) @nogc nothrow;   // $name: a dash binding
alias EvalTextFn = Value* function(const(char)[] text, void* env) @nogc nothrow; // $(( expr ))
alias BuiltinFn = int function(const(char)*[] argv, void* env) @nogc nothrow;   // dash-level builtins
__gshared LookupFn g_lookupVar;
__gshared EvalTextFn g_evalText;
__gshared BuiltinFn g_dashBuiltin;       // returns -1 when argv[0] is not one of its builtins
__gshared int g_lastStatus;
__gshared Vec!int g_jobs;                // background pids

// ── the command AST ─────────────────────────────────────────────────────────────────────────────
enum WP : ubyte { Lit, Var, CmdSub, ExprSub, Tilde }
struct WPart { WP k; const(char)[] s; bool quoted; bool glob; }
struct Word { WPart[] parts; }
enum RK : ubyte { Out, Append, In, ErrOut, ErrAppend, ErrToOut, Both, HereDoc, HereStr }
struct Redir { RK k; Word target; }
struct Simple { const(char)[][] assignNames; Word[] assignVals; Word[] words; Redir[] redirs; }
// A command in a pipeline: a simple command, or a compound one (the shell's control flow).
enum CK : ubyte { Simple, If, While, Until, For, Case, Group, Subshell, FuncDef }
struct Cmd {
    CK k;
    Simple* sc;               // CK.Simple
    CmdList*[] conds;         // If: one per if/elif; While/Until: the condition
    CmdList*[] bodies;        // If: one per if/elif, then the else; loops, { }, ( ): the body; Case: one per arm
    bool hasElse;
    const(char)[] name;       // For: the variable; FuncDef: the function's name
    Word[] words; bool hasIn; // For: the list (no `in`: the positional parameters)
    Word subject;             // Case: the word matched
    Word[][] pats;            // Case: each arm's patterns
    Cmd* fbody;               // FuncDef: the body
    Redir[] redirs;           // redirections after a compound command (`done > out`)
}
struct Pipeline { Cmd*[] cmds; bool negate; }
struct AndOr { Pipeline*[] pipes; ubyte[] ops; bool background; }
struct CmdList { AndOr*[] items; }

@nogc nothrow:

private T* anew(T)() { return cast(T*)calloc(1, T.sizeof); }
private T[] one(T)(T x) { auto p = cast(T*)malloc(T.sizeof); *p = x; return p[0 .. 1]; }
// The reserved words that end each part of a compound command (static: no GC in betterC).
private immutable const(char)[][] KW_THEN = ["then"], KW_IFBODY = ["elif", "else", "fi"], KW_FI = ["fi"],
    KW_DO = ["do"], KW_DONE = ["done"], KW_ESAC = ["esac"], KW_RBRACE = ["}"];
private Word litWord(const(char)[] t) {
    auto p = cast(WPart*)calloc(1, WPart.sizeof);
    p.k = WP.Lit; p.s = permDup(t); p.quoted = true;
    Word w; w.parts = p[0 .. 1]; return w;
}
private T[] slice(T)(ref Vec!T v) {
    if (v.n == 0) return null;
    auto p = cast(T*)malloc(v.n * T.sizeof); memcpy(p, v.p, v.n * T.sizeof);
    auto r = p[0 .. v.n]; v.dispose(); return r;
}

// ── parsing ─────────────────────────────────────────────────────────────────────────────────────
struct CmdParser {
    const(char)[] s; size_t i;
    bool failed;
    @nogc nothrow:
    int depthParen;                    // inside ( ... ): a ')' ends the list
    Vec!(Redir*) pendHd;               // here-documents whose bodies start after this line
    Vec!(bool) pendHdStrip;            // <<- : leading tabs go
    Vec!(const(char)[]) pendHdDelim;
    Vec!(bool) pendHdQuoted;           // a quoted delimiter: the body is literal
    bool fail(const(char)[] m) { if (!failed) { failed = true; setErr("command syntax: ", m); } return false; }
    bool fail3(const(char)[] a, const(char)[] b, const(char)[] c) {
        if (!failed) { failed = true; setErr("command syntax: ", a, b, c); } return false;
    }
    void skipSpace() { while (i < s.length && isSpace(s[i])) ++i; }
    bool atEnd() { return i >= s.length; }
    char peek(size_t k = 0) { return i + k < s.length ? s[i + k] : 0; }
    // A newline at command level: the here-documents of the line just ended are read from here.
    void newline() { ++i; if (pendHd.n) readHeredocs(); }
    // Separators (';', newlines) and comments between commands.  A ';;' (end of a case arm) stays.
    void skipSeps() {
        for (;;) {
            skipSpace();
            if (peek() == ';' && peek(1) != ';') { ++i; continue; }
            if (peek() == '\n') { newline(); continue; }
            if (peek() == '#') { while (i < s.length && s[i] != '\n') ++i; continue; }
            break;
        }
    }
    // The bare word at the cursor, not consumed: what a reserved word is compared against -- and only
    // in command position (`echo done` is an argument).
    const(char)[] peekWord() {
        size_t j = i;
        while (j < s.length && isSpace(s[j])) ++j;
        size_t e = j;
        while (e < s.length && !isSpace(s[e]) && s[e] != '\n' && s[e] != ';' && s[e] != '&' && s[e] != '|'
               && s[e] != '<' && s[e] != '>' && s[e] != '(' && s[e] != ')') ++e;
        return s[j .. e];
    }
    bool atWord(const(char)[] w) { return peekWord() == w; }
    void takeWord(const(char)[] w) { skipSpace(); i += w.length; }
    bool expect(const(char)[] w) {
        skipSeps();
        if (!atWord(w)) return fail3("expected '", w, "'");
        takeWord(w);
        return true;
    }

    // A list of and-or items: to the end, or to a reserved word of `terms` in command position (the
    // end of a part of a compound command), a ')' closing a subshell, or a case arm's ';;'.
    CmdList* list(const(char[])[] terms = null) {
        auto cl = anew!CmdList();
        Vec!(AndOr*) items;
        for (;;) {
            skipSeps();
            if (atEnd() || failed) break;
            if (peek() == ')' && depthParen > 0) break;
            if (peek() == ';' && peek(1) == ';') break;
            if (terms.length) {
                const w = peekWord();
                bool stop = false;
                foreach (t; terms) if (w == t) { stop = true; break; }
                if (stop) break;
            }
            const before = i;
            auto ao = andOr(); if (!ao) { items.dispose(); return null; }
            skipSpace();
            if (peek() == '&' && peek(1) != '&') { ao.background = true; ++i; }
            items.push(ao);
            skipSpace();
            if (peek() == ';' && peek(1) == ';') continue;     // the top of the loop stops there
            if (peek() == ';') { ++i; continue; }
            if (peek() == '\n') { newline(); continue; }
            if (peek() == '&' || atEnd() || peek() == '#') continue;
            if (peek() == ')') {
                if (depthParen > 0) continue;
                fail("unexpected ')'"); items.dispose(); return null;
            }
            if (i == before) { fail("unexpected text"); items.dispose(); return null; }
        }
        cl.items = slice(items);
        return cl;
    }
    AndOr* andOr() {
        auto ao = anew!AndOr();
        Vec!(Pipeline*) ps; Vec!ubyte ops;
        for (;;) {
            auto p = pipeline(); if (!p) { ps.dispose(); ops.dispose(); return null; }
            ps.push(p);
            skipSpace();
            if (peek() == '&' && peek(1) == '&') { i += 2; ops.push(1); continue; }
            if (peek() == '|' && peek(1) == '|') { i += 2; ops.push(2); continue; }
            break;
        }
        ao.pipes = slice(ps); ao.ops = slice(ops);
        return ao;
    }
    Pipeline* pipeline() {
        auto pl = anew!Pipeline();
        skipSpace();
        if (peek() == '!' && (peek(1) == ' ' || peek(1) == '\t')) { pl.negate = true; ++i; }
        Vec!(Cmd*) cs;
        for (;;) {
            auto c = command(); if (!c) { cs.dispose(); return null; }
            cs.push(c);
            skipSpace();
            if (peek() == '|' && peek(1) != '|' && peek(1) != '>') { ++i; continue; }
            break;
        }
        pl.cmds = slice(cs);
        return pl;
    }
    Simple* simple() {
        auto sc = anew!Simple();
        Vec!Word ws; Vec!Redir rs; Vec!(const(char)[]) an; Vec!Word av;
        for (;;) {
            skipSpace();
            const c = peek();
            if (atEnd() || c == ';' || c == '\n' || c == '#' || (c == '|') || (c == '&' && peek(1) != '>') || c == ')') break;
            // redirections: [n]> [n]>> < 2>&1 &> <<here <<<string
            {
                const r = redirection(rs);
                if (r < 0) { ws.dispose(); rs.dispose(); an.dispose(); av.dispose(); return null; }
                if (r > 0) continue;
            }
            // NAME=value before the command word
            if (ws.n == 0) {
                size_t j = i;
                if (j < s.length && (isAlpha(s[j]))) {
                    while (j < s.length && (isIdentChar(s[j]) && s[j] != '\'')) ++j;
                    if (j < s.length && s[j] == '=' && (j + 1 >= s.length || s[j + 1] != '=')) {
                        an.push(s[i .. j]); i = j + 1;
                        Word w; if (!word(w)) { ws.dispose(); rs.dispose(); an.dispose(); av.dispose(); return null; }
                        av.push(w);
                        continue;
                    }
                }
            }
            Word w;
            if (!word(w)) { ws.dispose(); rs.dispose(); an.dispose(); av.dispose(); return null; }
            if (w.parts.length == 0) break;
            ws.push(w);
        }
        const hd0 = pendHd.n;
        sc.words = slice(ws); sc.redirs = slice(rs); sc.assignNames = slice(an); sc.assignVals = slice(av);
        notePendingHeredocs(sc.redirs, hd0);
        return sc;
    }

    // One redirection at the cursor: 1 parsed (into rs), 0 none here, -1 a syntax error.
    // A here-document's body is read at the end of its line (readHeredocs); its delimiter is held in
    // the target word until then.
    int redirection(ref Vec!Redir rs) {
        if (i >= s.length) return 0;
        size_t j = i; int fd = -1;
        if (isDigit(s[j]) && j + 1 < s.length && (s[j + 1] == '>' || s[j + 1] == '<')) { fd = s[j] - '0'; ++j; }
        if (!(j < s.length && (s[j] == '>' || s[j] == '<' || (s[j] == '&' && j + 1 < s.length && s[j + 1] == '>')))) return 0;
        Redir r;
        bool heredoc = false, strip = false;
        if (s[j] == '&') { r.k = RK.Both; j += 2; }
        else if (s[j] == '<' && j + 2 < s.length && s[j + 1] == '<' && s[j + 2] == '<') { r.k = RK.HereStr; j += 3; }
        else if (s[j] == '<' && j + 1 < s.length && s[j + 1] == '<') {
            r.k = RK.HereDoc; j += 2; heredoc = true;
            if (j < s.length && s[j] == '-') { strip = true; ++j; }
        }
        else if (s[j] == '<') { r.k = RK.In; ++j; }
        else if (j + 1 < s.length && s[j + 1] == '>') { r.k = fd == 2 ? RK.ErrAppend : RK.Append; j += 2; }
        else if (j + 2 < s.length && s[j + 1] == '&' && s[j + 2] == '1' && fd == 2) { r.k = RK.ErrToOut; j += 3; }
        else { r.k = fd == 2 ? RK.ErrOut : RK.Out; ++j; }
        i = j;
        if (heredoc) {
            skipSpace();
            const st = i;
            bool quoted = false;
            Buf d;
            while (i < s.length && !isSpace(s[i]) && s[i] != '\n' && s[i] != ';' && s[i] != '|' && s[i] != '&' && s[i] != '<' && s[i] != '>') {
                if (s[i] == '\'' || s[i] == '"') { quoted = true; ++i; continue; }
                if (s[i] == '\\' && i + 1 < s.length) { quoted = true; d.put(s[i + 1]); i += 2; continue; }
                d.put(s[i]); ++i;
            }
            if (i == st || d.n == 0) { d.dispose(); fail("a here-document needs a delimiter"); return -1; }
            r.target = litWord(d.str());            // replaced by the body at the end of the line
            pendHdDelim.push(permDup(d.str())); pendHdStrip.push(strip); pendHdQuoted.push(quoted);
            d.dispose();
            rs.push(r);
            return 1;
        }
        if (r.k != RK.ErrToOut) {
            skipSpace();
            if (!word(r.target)) return -1;
            if (r.target.parts.length == 0) { fail("a redirection needs a file"); return -1; }
        }
        rs.push(r);
        return 1;
    }
    // After a command's redirections are final (sliced), remember where its here-documents' bodies go.
    void notePendingHeredocs(Redir[] rd, size_t firstNew) {
        size_t seen = 0;
        foreach (ref r; rd) if (r.k == RK.HereDoc) { if (seen++ >= 0) pendHd.push(&r); }
        cast(void)firstNew;
    }
    // At the end of a line: each pending here-document's body is the lines up to its delimiter.
    void readHeredocs() {
        foreach (k; 0 .. pendHd.n) {
            Buf body_;
            const(char)[] delim = pendHdDelim[k];
            const strip = pendHdStrip[k];
            bool done = false;
            while (i < s.length && !done) {
                size_t e = i; while (e < s.length && s[e] != '\n') ++e;
                auto line = s[i .. e];
                i = e < s.length ? e + 1 : e;
                size_t a = 0;
                if (strip) while (a < line.length && line[a] == '\t') ++a;
                if (line[a .. $] == delim) { done = true; break; }
                body_.put(line[a .. $]); body_.put('\n');
            }
            Word w;
            if (pendHdQuoted[k]) w = litWord(body_.str());
            else {                                  // $var, $(cmd), $((e)) and \ escapes, as in "..."
                CmdParser sub; sub.s = permDup(body_.str()); sub.i = 0;
                if (!sub.dqWord(w)) { failed = true; }
            }
            pendHd[k].target = w;
            body_.dispose();
        }
        pendHd.clear(); pendHdDelim.clear(); pendHdStrip.clear(); pendHdQuoted.clear();
    }
    // The whole text as the inside of a double-quoted string (a here-document body).
    bool dqWord(ref Word w) {
        Vec!WPart ps; Buf lit;
        void flush() { if (lit.n) { WPart p; p.k = WP.Lit; p.s = permDup(lit.str()); p.quoted = true; ps.push(p); lit.clear(); } }
        while (i < s.length) {
            if (s[i] == '\\' && i + 1 < s.length && (s[i + 1] == '$' || s[i + 1] == '\\' || s[i + 1] == '`')) { lit.put(s[i + 1]); i += 2; continue; }
            if (s[i] == '$' && i + 1 < s.length) { flush(); if (!dollar(ps, true)) { lit.dispose(); ps.dispose(); return false; } continue; }
            lit.put(s[i]); ++i;
        }
        flush(); lit.dispose();
        if (ps.n == 0) { WPart p; p.k = WP.Lit; p.s = ""; p.quoted = true; ps.push(p); }
        w.parts = slice(ps);
        return true;
    }

    // ── compound commands ──────────────────────────────────────────────────────────────────────
    Cmd* command() {
        skipSpace();
        const w = peekWord();
        switch (w) {
            case "if":       return ifCmd();
            case "while":    return loopCmd(CK.While);
            case "until":    return loopCmd(CK.Until);
            case "for":      return forCmd();
            case "case":     return caseCmd();
            case "function": return funcCmd(true);
            case "{":        return groupCmd();
            case "[[":       return dblBracket();
            default: break;
        }
        if (peek() == '(' && peek(1) != '(') return subshellCmd();
        {   // name() body: a function definition
            size_t j = i;
            while (j < s.length && (isAlpha(s[j]) || isDigit(s[j]) || s[j] == '_' || s[j] == '-' || s[j] == '.')) ++j;
            size_t k = j; while (k < s.length && (s[k] == ' ' || s[k] == '\t')) ++k;
            if (j > i && isAlpha(s[i]) && k + 1 < s.length && s[k] == '(' && s[k + 1] == ')') return funcCmd(false);
        }
        auto c = anew!Cmd(); c.k = CK.Simple;
        c.sc = simple(); if (!c.sc) return null;
        return c;
    }
    bool trailingRedirs(Cmd* c) {
        Vec!Redir rs;
        for (;;) {
            skipSpace();
            const r = redirection(rs);
            if (r < 0) { rs.dispose(); return false; }
            if (r == 0) break;
        }
        c.redirs = slice(rs);
        notePendingHeredocs(c.redirs, 0);
        return true;
    }
    Cmd* ifCmd() {
        auto c = anew!Cmd(); c.k = CK.If;
        Vec!(CmdList*) cs, bs;
        takeWord("if");
        for (;;) {
            auto cond = list(KW_THEN); if (!cond) return null;
            if (!expect("then")) return null;
            auto body_ = list(KW_IFBODY); if (!body_) return null;
            cs.push(cond); bs.push(body_);
            skipSeps();
            if (atWord("elif")) { takeWord("elif"); continue; }
            if (atWord("else")) {
                takeWord("else");
                auto eb = list(KW_FI); if (!eb) return null;
                bs.push(eb); c.hasElse = true;
            }
            if (!expect("fi")) return null;
            break;
        }
        c.conds = slice(cs); c.bodies = slice(bs);
        return trailingRedirs(c) ? c : null;
    }
    Cmd* loopCmd(CK k) {
        auto c = anew!Cmd(); c.k = k;
        takeWord(k == CK.While ? "while" : "until");
        auto cond = list(KW_DO); if (!cond) return null;
        if (!expect("do")) return null;
        auto body_ = list(KW_DONE); if (!body_) return null;
        if (!expect("done")) return null;
        c.conds = one(cond); c.bodies = one(body_);
        return trailingRedirs(c) ? c : null;
    }
    Cmd* forCmd() {
        auto c = anew!Cmd(); c.k = CK.For;
        takeWord("for"); skipSpace();
        const st = i;
        while (i < s.length && (isAlpha(s[i]) || isDigit(s[i]) || s[i] == '_')) ++i;
        if (i == st) { fail("for: a variable name is needed"); return null; }
        c.name = permDup(s[st .. i]);
        const save = i;
        skipSpace(); while (peek() == '\n') { newline(); skipSpace(); }
        if (atWord("in")) {
            takeWord("in"); c.hasIn = true;
            Vec!Word ws;
            for (;;) {
                skipSpace();
                if (atEnd() || peek() == ';' || peek() == '\n') break;
                Word w; if (!word(w)) { ws.dispose(); return null; }
                if (w.parts.length == 0) break;
                ws.push(w);
            }
            c.words = slice(ws);
        } else i = save;
        if (!expect("do")) return null;
        auto body_ = list(KW_DONE); if (!body_) return null;
        if (!expect("done")) return null;
        c.bodies = one(body_);
        return trailingRedirs(c) ? c : null;
    }
    Cmd* caseCmd() {
        auto c = anew!Cmd(); c.k = CK.Case;
        takeWord("case"); skipSpace();
        if (!word(c.subject) || c.subject.parts.length == 0) { fail("case: a word is needed"); return null; }
        if (!expect("in")) return null;
        Vec!(Word[]) arms; Vec!(CmdList*) bodies;
        for (;;) {
            skipSeps();
            if (atWord("esac")) { takeWord("esac"); break; }
            if (atEnd()) { fail("case: missing 'esac'"); return null; }
            if (peek() == '(') ++i;
            Vec!Word ps;
            for (;;) {
                skipSpace();
                Word w; if (!word(w)) return null;
                if (w.parts.length == 0) { fail("case: a pattern is needed"); return null; }
                ps.push(w); skipSpace();
                if (peek() == '|') { ++i; continue; }
                if (peek() == ')') { ++i; break; }
                fail("case: expected ')' after a pattern"); return null;
            }
            auto body_ = list(KW_ESAC); if (!body_) return null;
            arms.push(slice(ps)); bodies.push(body_);
            skipSpace();
            if (peek() == ';' && (peek(1) == ';' || peek(1) == '&')) { i += 2; if (peek() == '&') ++i; }
        }
        c.pats = slice(arms); c.bodies = slice(bodies);
        return trailingRedirs(c) ? c : null;
    }
    Cmd* groupCmd() {
        auto c = anew!Cmd(); c.k = CK.Group;
        takeWord("{");
        auto body_ = list(KW_RBRACE); if (!body_) return null;
        if (!expect("}")) return null;
        c.bodies = one(body_);
        return trailingRedirs(c) ? c : null;
    }
    Cmd* subshellCmd() {
        auto c = anew!Cmd(); c.k = CK.Subshell;
        ++i; ++depthParen;
        auto body_ = list(); --depthParen;
        if (!body_) return null;
        skipSeps();
        if (peek() != ')') { fail("expected ')'"); return null; }
        ++i;
        c.bodies = one(body_);
        return trailingRedirs(c) ? c : null;
    }
    Cmd* funcCmd(bool keyword) {
        auto c = anew!Cmd(); c.k = CK.FuncDef;
        if (keyword) { takeWord("function"); skipSpace(); }
        const st = i;
        while (i < s.length && (isAlpha(s[i]) || isDigit(s[i]) || s[i] == '_' || s[i] == '-' || s[i] == '.')) ++i;
        if (i == st) { fail("function: a name is needed"); return null; }
        c.name = permDup(s[st .. i]);
        skipSpace();
        if (peek() == '(') { ++i; skipSpace(); if (peek() != ')') { fail("expected ')' after the function name"); return null; } ++i; }
        skipSeps();
        auto b = command(); if (!b) return null;
        if (b.k == CK.Simple || b.k == CK.FuncDef) { fail("a function body is a compound command ({ ... })"); return null; }
        c.fbody = b;
        return c;
    }
    // [[ expression ]]: its && || ! ( ) < > are operands of the test, not the shell's.
    Cmd* dblBracket() {
        takeWord("[[");
        Vec!Word ws;
        ws.push(litWord("[["));
        for (;;) {
            skipSpace();
            if (atEnd() || peek() == '\n') { ws.dispose(); fail("expected ']]'"); return null; }
            if (atWord("]]")) { takeWord("]]"); break; }
            const c0 = peek();
            if ((c0 == '&' && peek(1) == '&') || (c0 == '|' && peek(1) == '|')) { ws.push(litWord(s[i .. i + 2])); i += 2; continue; }
            if (c0 == '(' || c0 == ')' || c0 == '<' || c0 == '>') { ws.push(litWord(s[i .. i + 1])); ++i; continue; }
            Word w; if (!word(w)) { ws.dispose(); return null; }
            if (w.parts.length == 0) { ws.dispose(); fail("[[: unexpected text"); return null; }
            ws.push(w);
        }
        ws.push(litWord("]]"));
        auto sc = anew!Simple(); sc.words = slice(ws);
        auto c = anew!Cmd(); c.k = CK.Simple; c.sc = sc;
        return trailingRedirs(c) ? c : null;
    }
    // One word: a run of literal text, quotes and expansions up to unquoted whitespace/operator.
    bool word(ref Word w) {
        Vec!WPart ps;
        Buf lit; bool litGlob = false;
        void flushLit(bool quoted) {
            if (lit.n) { WPart p; p.k = WP.Lit; p.s = permDup(lit.str()); p.quoted = quoted; p.glob = litGlob && !quoted; ps.push(p); lit.clear(); litGlob = false; }
        }
        bool first = true;
        while (i < s.length) {
            const c = s[i];
            if (isSpace(c) || c == '\n' || c == ';' || c == '|' || c == '<' || c == '>' || c == ')' ||
                (c == '&')) break;
            if (c == '#' && first) break;
            if (c == '~' && first && (i + 1 >= s.length || s[i + 1] == '/' || isSpace(s[i + 1]))) {
                WPart p; p.k = WP.Tilde; ps.push(p); ++i; first = false; continue;
            }
            first = false;
            if (c == '\\' && i + 1 < s.length) { lit.put(s[i + 1]); i += 2; continue; }
            if (c == '\'') {
                flushLit(false);
                ++i; const st = i;
                while (i < s.length && s[i] != '\'') ++i;
                if (i >= s.length) { lit.dispose(); ps.dispose(); return fail("unterminated '"); }
                WPart p; p.k = WP.Lit; p.s = permDup(s[st .. i]); p.quoted = true; ps.push(p);
                ++i; continue;
            }
            if (c == '"') {
                flushLit(false);
                ++i;
                while (i < s.length && s[i] != '"') {
                    if (s[i] == '\\' && i + 1 < s.length && (s[i + 1] == '"' || s[i + 1] == '\\' || s[i + 1] == '$' || s[i + 1] == '`')) { lit.put(s[i + 1]); i += 2; continue; }
                    if (s[i] == '$') { flushLit(true); if (!dollar(ps, true)) { lit.dispose(); ps.dispose(); return false; } continue; }
                    lit.put(s[i]); ++i;
                }
                if (i >= s.length) { lit.dispose(); ps.dispose(); return fail("unterminated \""); }
                ++i;
                flushLit(true);
                // an empty "" is still a word
                if (ps.n == 0 || (ps.back().k == WP.Lit && ps.back().s.length == 0)) {}
                if (ps.n == 0) { WPart p; p.k = WP.Lit; p.s = ""; p.quoted = true; ps.push(p); }
                continue;
            }
            if (c == '$' && i + 1 < s.length) {
                flushLit(false);
                if (!dollar(ps, false)) { lit.dispose(); ps.dispose(); return false; }
                continue;
            }
            if (c == '*' || c == '?' || c == '[') litGlob = true;
            lit.put(c); ++i;
        }
        flushLit(false);
        lit.dispose();
        w.parts = slice(ps);
        return true;
    }
    // $name ${name} $? $$ $(cmd) $((expr))
    bool dollar(ref Vec!WPart ps, bool quoted) {
        ++i;   // '$'
        WPart p; p.quoted = quoted;
        if (peek() == '(' && peek(1) == '(') {
            i += 2; const st = i; int d = 2;
            while (i < s.length) {
                if (s[i] == '(') ++d;
                else if (s[i] == ')') { --d; if (d == 0) break; }
                else if (s[i] == '"') { ++i; while (i < s.length && s[i] != '"') { if (s[i] == '\\') ++i; ++i; } }
                ++i;
            }
            if (i >= s.length || i < st + 1) return fail("unterminated $((");
            // the text ends before the first of the two closing parens
            p.k = WP.ExprSub; p.s = permDup(s[st .. i - 1]);
            ++i; ps.push(p); return true;
        }
        if (peek() == '(') {
            ++i; const st = i; int d = 1;
            while (i < s.length) {
                if (s[i] == '(') ++d;
                else if (s[i] == ')') { --d; if (d == 0) break; }
                else if (s[i] == '\'' || s[i] == '"') { const q = s[i]; ++i; while (i < s.length && s[i] != q) { if (q == '"' && s[i] == '\\') ++i; ++i; } }
                ++i;
            }
            if (i >= s.length) return fail("unterminated $(");
            p.k = WP.CmdSub; p.s = permDup(s[st .. i]); ++i; ps.push(p); return true;
        }
        if (peek() == '{') {
            ++i; const st = i; int d = 1;
            while (i < s.length) {
                if (s[i] == '{') ++d;
                else if (s[i] == '}') { --d; if (d == 0) break; }
                else if (s[i] == '\\' && i + 1 < s.length) ++i;
                ++i;
            }
            if (i >= s.length) return fail("unterminated ${");
            p.k = WP.Var; p.s = permDup(s[st .. i]); ++i; ps.push(p); return true;
        }
        if (peek() == '?' || peek() == '$' || peek() == '#' || peek() == '@' || peek() == '*' || peek() == '!' || isDigit(peek())) {
            p.k = WP.Var; p.s = permDup(s[i .. i + 1]); ++i; ps.push(p); return true;
        }
        const st = i;
        while (i < s.length && (isAlpha(s[i]) || isDigit(s[i]))) ++i;
        if (i == st) { WPart l; l.k = WP.Lit; l.s = "$"; l.quoted = quoted; ps.push(l); return true; }
        p.k = WP.Var; p.s = permDup(s[st .. i]); ps.push(p); return true;
    }
}

CmdList* parseCommand(const(char)[] text) {
    CmdParser p; p.s = text; p.i = 0;
    auto l = p.list();
    if (p.failed) return null;
    return l;
}

// ── expansion ───────────────────────────────────────────────────────────────────────────────────
// Brace expansion of an unquoted word: a{b,c}d -> abd acd, {1..5}, {a..e}; nested braces work.
private void braceExpand(const(char)[] t, ref Vec!(char*) outv) {
    // the first top-level {..} that has a ',' or '..' in it
    for (size_t a = 0; a < t.length; ++a) {
        if (t[a] != '{' || (a > 0 && t[a - 1] == '$')) continue;
        int d = 0; size_t b = size_t.max; bool comma = false, range = false;
        for (size_t k = a; k < t.length; ++k) {
            if (t[k] == '{') ++d;
            else if (t[k] == '}') { if (--d == 0) { b = k; break; } }
            else if (d == 1 && t[k] == ',') comma = true;
            else if (d == 1 && t[k] == '.' && k + 1 < t.length && t[k + 1] == '.') range = true;
        }
        if (b == size_t.max || (!comma && !range)) continue;
        const pre = t[0 .. a], inner = t[a + 1 .. b], post = t[b + 1 .. $];
        void emit(const(char)[] mid) {
            Buf x; x.put(pre); x.put(mid); x.put(post);
            braceExpand(x.str(), outv); x.dispose();
        }
        if (comma) {
            size_t st = 0; int dd = 0;
            foreach (k; 0 .. inner.length + 1) {
                if (k < inner.length && inner[k] == '{') ++dd;
                if (k < inner.length && inner[k] == '}') --dd;
                if (k == inner.length || (inner[k] == ',' && dd == 0)) { emit(inner[st .. k]); st = k + 1; }
            }
            return;
        }
        size_t dots = 0; while (dots + 1 < inner.length && !(inner[dots] == '.' && inner[dots + 1] == '.')) ++dots;
        const lo = inner[0 .. dots], hi = inner[dots + 2 .. $];
        if (lo.length == 1 && hi.length == 1 && !isDigit(lo[0]) && !isDigit(hi[0])) {
            const int step = lo[0] <= hi[0] ? 1 : -1;
            for (int ch = lo[0]; ; ch += step) { char[1] cc = [cast(char)ch]; emit(cc[]); if (ch == hi[0]) break; }
            return;
        }
        Buf lb; lb.put(lo); Buf hb; hb.put(hi);
        char* e1; char* e2;
        const long x = strtoll(lb.cstr(), &e1, 10), y = strtoll(hb.cstr(), &e2, 10);
        const bool ok = *e1 == 0 && *e2 == 0 && lo.length && hi.length;
        lb.dispose(); hb.dispose();
        if (!ok) continue;
        const long step = x <= y ? 1 : -1;
        for (long v = x; ; v += step) { char[24] nb; const n = snprintf(nb.ptr, nb.length, "%ld", v); emit(nb[0 .. n]); if (v == y) break; }
        return;
    }
    outv.push(cz(t));
}
private bool hasBraceExpansion(ref Word w) {
    foreach (ref p; w.parts) if (p.k != WP.Lit || p.quoted) return false;
    foreach (ref p; w.parts) foreach (k, c; p.s) if (c == '{') {
        foreach (c2; p.s[k .. $]) if (c2 == ',' || c2 == '.') return true;
    }
    return false;
}

// Expand a word into zero or more argv strings (malloc'd; appended to out).
bool expandWord(ref Word w, void* env, ref Vec!(char*) outv, bool noGlob = false) {
    // a{b,c}: brace expansion first (only an all-literal unquoted word), each result globbed
    if (!noGlob && hasBraceExpansion(w)) {
        Buf t; foreach (ref p; w.parts) t.put(p.s);
        Vec!(char*) bs; braceExpand(t.str(), bs); t.dispose();
        foreach (b; bs[]) {
            bool g = false; for (auto q = b; *q; ++q) if (*q == '*' || *q == '?' || *q == '[') g = true;
            GlobT gl;
            if (g && glob(b, 0, null, &gl) == 0 && gl.gl_pathc > 0) {
                foreach (k; 0 .. gl.gl_pathc) outv.push(cz(gl.gl_pathv[k][0 .. strlen(gl.gl_pathv[k])]));
                globfree(&gl); free(b);
            } else outv.push(b);
        }
        bs.dispose();
        return true;
    }
    // "$@": one argv per positional parameter, even quoted
    if (w.parts.length == 1 && w.parts[0].k == WP.Var && w.parts[0].s == "@") {
        foreach (a; g_pos) outv.push(cz(a[0 .. strlen(a)]));
        return true;
    }
    // A word that is one unquoted expansion of a list becomes one argv per element.
    if (w.parts.length == 1 && !w.parts[0].quoted && (w.parts[0].k == WP.Var || w.parts[0].k == WP.ExprSub)) {
        Value* v = expansionValue(w.parts[0], env);
        if (v is null && g_errSet) return false;
        if (v !is null && v.t == VT.List) {
            foreach (k; 0 .. v.n) { Buf b; textOf(b, v.items[k]); outv.push(b.cstr()); }
            return true;
        }
    }
    Buf b; bool doGlob = false; bool splitCmd = false;
    foreach (ref p; w.parts) {
        final switch (p.k) {
            case WP.Lit: b.put(p.s); if (p.glob) doGlob = true; break;
            case WP.Tilde: { auto h = getenv("HOME"); b.putz(h ? h : "/home/user"); break; }
            case WP.Var: case WP.ExprSub: {
                Value* v = expansionValue(p, env);
                if (v is null) { if (g_errSet) { b.dispose(); return false; } break; }
                if (v.t == VT.List) { foreach (k; 0 .. v.n) { if (k) b.put(' '); textOf(b, v.items[k]); } }
                else textOf(b, v);
                break;
            }
            case WP.CmdSub: {
                Buf o;
                runCapture(p.s, env, o);
                // trailing newlines go; unquoted, the output splits into words
                while (o.n && (o.p[o.n - 1] == '\n')) --o.n;
                if (!p.quoted && w.parts.length == 1) {
                    size_t st = 0;
                    foreach (k; 0 .. o.n + 1) {
                        if (k == o.n || o.p[k] == ' ' || o.p[k] == '\n' || o.p[k] == '\t') {
                            if (k > st) outv.push(cz(o.p[st .. k]));
                            st = k + 1;
                        }
                    }
                    o.dispose(); b.dispose(); splitCmd = true;
                    return true;
                }
                b.put(o.str()); o.dispose();
                break;
            }
        }
    }
    if (doGlob && !noGlob) {
        GlobT g;
        if (glob(b.cstr(), 0, null, &g) == 0 && g.gl_pathc > 0) {
            foreach (k; 0 .. g.gl_pathc) outv.push(cz(g.gl_pathv[k][0 .. strlen(g.gl_pathv[k])]));
            globfree(&g);
            b.dispose();
            return true;
        }
    }
    outv.push(b.cstr());
    return true;
}
// ── parameters: $1.. $# $@ $* $0 $! and ${...} expansion ─────────────────────────────────────────
__gshared char*[] g_pos;                 // the positional parameters (a script's or a function's args)
__gshared const(char)[] g_arg0 = "dash"; // $0
__gshared int g_lastBg;                  // $!: the last background job's pid
private bool isSpecialParam(const(char)[] n) {
    if (n.length == 0) return false;
    if (n.length == 1 && (n[0] == '#' || n[0] == '@' || n[0] == '*' || n[0] == '?' || n[0] == '$' || n[0] == '!')) return true;
    foreach (c; n) if (!isDigit(c)) return false;
    return true;
}
// The text of a parameter; false when it is unset.
private bool paramText(const(char)[] n, void* env, ref Buf out_) {
    if (n.length == 0) return false;
    if (isDigit(n[0])) {
        long k = 0; foreach (c; n) k = k * 10 + (c - '0');
        if (k == 0) { out_.put(g_arg0); return true; }
        if (k > g_pos.length) return false;
        out_.putz(g_pos[k - 1]); return true;
    }
    switch (n) {
        case "#": { char[16] b; const m = snprintf(b.ptr, b.length, "%d", cast(int)g_pos.length); out_.put(b[0 .. m]); return true; }
        case "@": case "*": foreach (k, a; g_pos) { if (k) out_.put(' '); out_.putz(a); } return true;
        case "?": { char[16] b; const m = snprintf(b.ptr, b.length, "%d", g_lastStatus); out_.put(b[0 .. m]); return true; }
        case "$": { char[16] b; const m = snprintf(b.ptr, b.length, "%d", getpid()); out_.put(b[0 .. m]); return true; }
        case "!": { if (g_lastBg == 0) return false; char[16] b; const m = snprintf(b.ptr, b.length, "%d", g_lastBg); out_.put(b[0 .. m]); return true; }
        default: break;
    }
    if (g_lookupVar) { auto v = g_lookupVar(n, env); if (v) { textOf(out_, v); return true; } }
    auto z = cz(n); auto e = getenv(z); free(z);
    if (e) { out_.putz(e); return true; }
    return false;
}
// The operand of a ${name op word}: itself a word ($vars, $(cmd), quotes) -- expanded to text.
private void operandText(const(char)[] w, void* env, ref Buf out_) {
    CmdParser sub; sub.s = w; sub.i = 0;
    Word wd;
    if (!sub.dqWord(wd)) return;
    Vec!(char*) v;
    if (expandWord(wd, env, v, true)) foreach (k, x; v[]) { if (k) out_.put(' '); out_.putz(x); }
    foreach (x; v[]) free(x); v.dispose();
}
private bool matchAt(const(char)[] pat, const(char)[] s_) {
    auto zp = cz(pat), zs = cz(s_);
    const r = fnmatch(zp, zs, 0) == 0;
    free(zp); free(zs);
    return r;
}
// ${name} ${#name} ${name:-w} ${name-w} ${name:=w} ${name:+w} ${name:?w} ${name#p} ${name##p} ${name%p}
// ${name%%p} ${name/p/r} ${name//p/r} ${name:off} ${name:off:len} ${name^} ${name^^} ${name,} ${name,,}
private Value* paramExpand(const(char)[] spec, void* env) {
    bool lengthOf = false;
    if (spec.length > 1 && spec[0] == '#') { lengthOf = true; spec = spec[1 .. $]; }
    size_t n = 0;
    if (spec.length && (isDigit(spec[0]))) { while (n < spec.length && isDigit(spec[n])) ++n; }
    else if (spec.length && (spec[0] == '#' || spec[0] == '@' || spec[0] == '*' || spec[0] == '?' || spec[0] == '$' || spec[0] == '!')) n = 1;
    else while (n < spec.length && (isAlpha(spec[n]) || isDigit(spec[n]) || spec[n] == '_')) ++n;
    const name = spec[0 .. n];
    const op = spec[n .. $];
    Buf val; const bool set = paramText(name, env, val);
    scope (exit) val.dispose();
    if (lengthOf) return mkInt(cast(long)val.n);
    if (op.length == 0) return set ? mkStr(val.str()) : mkStr("");
    const bool colon = op[0] == ':';
    const empty = !set || (colon && val.n == 0);
    if (op.length >= 2 && colon && (op[1] == '-' || op[1] == '=' || op[1] == '+' || op[1] == '?') ||
        (op[0] == '-' || op[0] == '=' || op[0] == '+' || op[0] == '?')) {
        const c = colon ? op[1] : op[0];
        const w = op[colon ? 2 : 1 .. $];
        const bool unset_ = colon ? empty : !set;
        Buf o;
        switch (c) {
            case '-': if (unset_) operandText(w, env, o); else o.put(val.str()); break;
            case '=':
                if (unset_) { operandText(w, env, o); if (g_setShellVar) g_setShellVar(name, o.str()); }
                else o.put(val.str());
                break;
            case '+': if (!unset_) operandText(w, env, o); break;
            default:
                if (unset_) {
                    Buf m; operandText(w, env, m);
                    setErr(name, ": ", m.n ? m.str() : "parameter null or not set");
                    m.dispose(); o.dispose(); return null;
                }
                o.put(val.str());
        }
        auto r = mkStr(o.str()); o.dispose(); return r;
    }
    const(char)[] v = val.str();
    if (op[0] == '#' || op[0] == '%') {                       // remove a prefix / suffix
        const bool longest = op.length > 1 && op[1] == op[0];
        Buf pb; operandText(op[longest ? 2 : 1 .. $], env, pb);
        const pat = pb.str();
        const(char)[] r = v;
        if (op[0] == '#') {
            if (longest) { for (size_t k = v.length + 1; k-- > 0; ) if (matchAt(pat, v[0 .. k])) { r = v[k .. $]; break; } }
            else foreach (k; 0 .. v.length + 1) if (matchAt(pat, v[0 .. k])) { r = v[k .. $]; break; }
        } else {
            if (longest) { foreach (k; 0 .. v.length + 1) if (matchAt(pat, v[k .. $])) { r = v[0 .. k]; break; } }
            else for (size_t k = v.length + 1; k-- > 0; ) if (matchAt(pat, v[k .. $])) { r = v[0 .. k]; break; }
        }
        auto res = mkStr(r); pb.dispose(); return res;
    }
    if (op[0] == '/') {                                       // replace the first / every match
        const bool all = op.length > 1 && op[1] == '/';
        auto body_ = op[all ? 2 : 1 .. $];
        size_t sl = 0; while (sl < body_.length && body_[sl] != '/') { if (body_[sl] == '\\') ++sl; ++sl; }
        Buf pb; operandText(body_[0 .. sl < body_.length ? sl : body_.length], env, pb);
        Buf rb; if (sl < body_.length) operandText(body_[sl + 1 .. $], env, rb);
        Buf o;
        size_t k = 0;
        bool replaced = false;
        while (k <= v.length) {
            size_t best = size_t.max;
            if (!(replaced && !all) && pb.n)
                for (size_t e = v.length; e > k; --e) if (matchAt(pb.str(), v[k .. e])) { best = e; break; }
            if (best != size_t.max) { o.put(rb.str()); k = best; replaced = true; continue; }
            if (k < v.length) o.put(v[k]);
            ++k;
        }
        auto res = mkStr(o.str()); o.dispose(); pb.dispose(); rb.dispose(); return res;
    }
    if (colon) {                                              // ${name:offset[:length]}
        Buf ob; size_t q = 1; while (q < op.length && op[q] != ':') ob.put(op[q++]);
        long off = strtoll(ob.cstr(), null, 10); ob.dispose();
        if (off < 0) off += cast(long)v.length;
        if (off < 0) off = 0;
        if (off > cast(long)v.length) off = cast(long)v.length;
        long len = cast(long)v.length - off;
        if (q < op.length) {
            Buf lb; lb.put(op[q + 1 .. $]); long l = strtoll(lb.cstr(), null, 10); lb.dispose();
            if (l < 0) l += cast(long)v.length - off;
            if (l < len) len = l < 0 ? 0 : l;
        }
        return mkStr(v[cast(size_t)off .. cast(size_t)(off + len)]);
    }
    if (op[0] == '^' || op[0] == ',') {                       // case
        const bool allc = op.length > 1 && op[1] == op[0];
        Buf o; o.put(v);
        foreach (k; 0 .. (allc ? o.n : (o.n ? 1 : 0))) {
            const c = o.p[k];
            if (op[0] == '^' && c >= 'a' && c <= 'z') o.p[k] = cast(char)(c - 32);
            if (op[0] == ',' && c >= 'A' && c <= 'Z') o.p[k] = cast(char)(c + 32);
        }
        auto res = mkStr(o.str()); o.dispose(); return res;
    }
    setErr("${", spec, "}: bad substitution");
    return null;
}

private Value* expansionValue(ref WPart p, void* env) {
    if (p.k == WP.ExprSub) return g_evalText ? g_evalText(p.s, env) : null;
    if (p.s == "?") return mkInt(g_lastStatus);
    if (p.s == "$") return mkInt(getpid());
    if (p.s == "#") return mkInt(cast(long)g_pos.length);
    if (p.s == "@" || p.s == "*") {
        auto l = mkList(g_pos.length);
        foreach (k, a; g_pos) l.items[k] = mkStrZ(a);
        return l;
    }
    if (isSpecialParam(p.s)) { Buf b; paramText(p.s, env, b); auto r = mkStr(b.str()); b.dispose(); return r; }
    {   // ${...} forms (anything that is not a plain name)
        bool plain = p.s.length > 0;
        foreach (c; p.s) if (!(isAlpha(c) || isDigit(c) || c == '_')) { plain = false; break; }
        if (!plain) return paramExpand(p.s, env);
    }
    if (g_lookupVar) { auto v = g_lookupVar(p.s, env); if (v) return v; }
    auto z = cz(p.s); auto e = getenv(z); free(z);
    return e ? mkStrZ(e) : mkStr("");
}

// ── running ─────────────────────────────────────────────────────────────────────────────────────
__gshared bool g_inChild;         // true in a forked child: builtins that exit, exit the child
// Control flow: `break n` / `continue n` count loops left to unwind; `return` ends the function.
__gshared int g_breakN, g_contN, g_loopDepth, g_funcDepth, g_sourceDepth;
__gshared bool g_returnPending;
__gshared int g_returnValue;
bool ctlPending() { return g_breakN > 0 || g_contN > 0 || g_returnPending || g_exitRequested || g_interrupted; }

// Shell functions (name() { ... } / function name { ... }): they win over builtins and commands.
private struct ShFunc { const(char)[] name; Cmd* body_; }
__gshared Vec!ShFunc g_funcs;
Cmd* findFunc(const(char)[] n) { foreach (ref f; g_funcs[]) if (f.name == n) return f.body_; return null; }
void defineFunction(Cmd* c) {
    foreach (ref f; g_funcs[]) if (f.name == c.name) { f.body_ = c.fbody; return; }
    ShFunc f; f.name = c.name; f.body_ = c.fbody; g_funcs.push(f);
}
bool removeFunction(const(char)[] n) {
    foreach (k, ref f; g_funcs[]) if (f.name == n) {
        foreach (j; k .. g_funcs.n - 1) g_funcs.p[j] = g_funcs.p[j + 1];
        --g_funcs.n; return true;
    }
    return false;
}
// `local` saves a variable's previous value; the function's return restores it.
private struct SavedVar { const(char)[] name; Value* v; ubyte flags; }
private __gshared Vec!SavedVar g_locals;
private void saveVarForLocal(const(char)[] name) {
    import dash.eval : getGlobal, globalFlags;
    const sym = intern(name);
    SavedVar sv; sv.name = permDup(name); sv.v = getGlobal(sym); sv.flags = globalFlags(sym);
    g_locals.push(sv);
}
private void restoreLocals(size_t mark) {
    import dash.eval : setGlobal;
    while (g_locals.n > mark) {
        auto sv = g_locals.p[g_locals.n - 1];
        --g_locals.n;
        setGlobal(intern(sv.name), sv.v, sv.flags);
    }
}
int callFunction(Cmd* body_, char*[] argv, void* env) {
    auto savedPos = g_pos;
    auto np = (cast(char**)calloc(argv.length > 1 ? argv.length - 1 : 1, (char*).sizeof))[0 .. argv.length > 1 ? argv.length - 1 : 0];
    foreach (k; 1 .. argv.length) np[k - 1] = cz(argv[k][0 .. strlen(argv[k])]);
    g_pos = np;
    const mark = g_locals.n;
    ++g_funcDepth;
    int st = runCompound(body_, env);
    if (g_returnPending) { st = g_returnValue; g_returnPending = false; }
    --g_funcDepth;
    restoreLocals(mark);
    foreach (a; np) free(a); free(np.ptr);
    g_pos = savedPos;
    return st;
}

// Apply a list of redirections in the CURRENT process.
private bool applyRedirList(Redir[] rd, void* env) {
    Simple tmp; tmp.redirs = rd;
    return applyRedirs(&tmp, env);
}

// Run a compound command in this process (a lone one in the shell; in a pipeline, in its child).
int runCompound(Cmd* c, void* env) {
    final switch (c.k) {
        case CK.Simple: return 0;
        case CK.FuncDef: defineFunction(c); return 0;
        case CK.If:
            foreach (k, cond; c.conds) {
                const st = runList(cond, env);
                if (ctlPending()) return st;
                if (st == 0) return runList(c.bodies[k], env);
            }
            return c.hasElse ? runList(c.bodies[$ - 1], env) : 0;
        case CK.While: case CK.Until: {
            int st = 0;
            ++g_loopDepth;
            for (;;) {
                if (g_interrupted || g_exitRequested || g_returnPending) break;
                const cst = runList(c.conds[0], env);
                if (g_breakN) { --g_breakN; break; }
                if (g_contN) { --g_contN; if (g_contN) break; continue; }
                if (g_interrupted || g_exitRequested || g_returnPending) break;
                if ((c.k == CK.While) != (cst == 0)) break;
                st = runList(c.bodies[0], env);
                if (g_breakN) { --g_breakN; break; }
                if (g_contN) { --g_contN; if (g_contN) break; continue; }
            }
            --g_loopDepth;
            g_lastStatus = st;
            return st;
        }
        case CK.For: {
            Vec!(char*) items;
            if (c.hasIn) { foreach (ref w; c.words) if (!expandWord(w, env, items)) { foreach (x; items[]) free(x); items.dispose(); return 1; } }
            else foreach (a; g_pos) items.push(cz(a[0 .. strlen(a)]));
            int st = 0;
            ++g_loopDepth;
            foreach (x; items[]) {
                if (g_interrupted || g_exitRequested || g_returnPending) break;
                if (g_setShellVar) g_setShellVar(c.name, x[0 .. strlen(x)]);
                st = runList(c.bodies[0], env);
                if (g_breakN) { --g_breakN; break; }
                if (g_contN) { --g_contN; if (g_contN) break; continue; }
            }
            --g_loopDepth;
            foreach (x; items[]) free(x); items.dispose();
            g_lastStatus = st;
            return st;
        }
        case CK.Case: {
            Vec!(char*) sv; if (!expandWord(c.subject, env, sv, true)) { sv.dispose(); return 1; }
            Buf subj; foreach (k, x; sv[]) { if (k) subj.put(' '); subj.putz(x); free(x); } sv.dispose();
            scope (exit) subj.dispose();
            foreach (k, pats; c.pats) foreach (ref pw; pats) {
                Vec!(char*) pv; if (!expandWord(pw, env, pv, true)) { pv.dispose(); return 1; }
                Buf pat; foreach (q, x; pv[]) { if (q) pat.put(' '); pat.putz(x); free(x); } pv.dispose();
                const hit = fnmatch(pat.cstr(), subj.cstr(), 0) == 0;
                pat.dispose();
                if (hit) return runList(c.bodies[k], env);
            }
            return 0;
        }
        case CK.Group: return runList(c.bodies[0], env);
        case CK.Subshell: {
            oflush();
            const pid = fork();
            if (pid == 0) {
                g_inChild = true;
                const rc = runList(c.bodies[0], env);
                oflush();
                _exit(g_exitRequested ? g_exitCode : rc);
            }
            if (pid < 0) { errOut("dash: fork failed\n"); return 1; }
            int stw = 0;
            while (waitpid(pid, &stw, 0) < 0) { if (!g_interrupted) break; g_interrupted = false; }
            return decodeStatus(stw);
        }
    }
}

// Search PATH for `name`; returns a malloc'd path or null.
char* findInPath(const(char)[] name) {
    if (name.length == 0) return null;
    foreach (c; name) if (c == '/') { auto z = cz(name); if (access(z, X_OK) == 0) return z; free(z); return null; }
    auto path = getenv("PATH");
    const(char)[] ps = path ? path[0 .. strlen(path)] : "/bin:/usr/bin:/sbin:/usr/sbin";
    size_t st = 0;
    foreach (k; 0 .. ps.length + 1) {
        if (k == ps.length || ps[k] == ':') {
            if (k > st) {
                Buf b; b.put(ps[st .. k]); b.put('/'); b.put(name);
                if (access(b.cstr(), X_OK) == 0) return b.p;
                b.dispose();
            }
            st = k + 1;
        }
    }
    return null;
}

bool isShellBuiltin(const(char)[] n) {
    switch (n) {
        case "cd", "pwd", "exit", "export", "unset", "source", ".", "history", "jobs", "wait", "which",
             "type", "help", "linux", "echo", "true", "false", "exec", "alias", "set",
             "test", "[", "[[", "read", "shift", "local", "return", "break", "continue", "eval", ":",
             "command", "printenv":
            return true;
        default: return false;
    }
}

// Apply a simple command's redirections in the CURRENT process (a child, or around a builtin).
// A here-document's or here-string's text on stdin: a channel for a small body, a removed temporary
// file for a large one (dash writes it before the command runs, so a channel could fill up).
private bool stdinFromText(const(char)[] text) {
    if (text.length <= 16384) {
        int[2] pf;
        if (pipe(pf.ptr) != 0) return false;
        size_t o = 0;
        while (o < text.length) { const w = write(pf[1], text.ptr + o, text.length - o); if (w <= 0) break; o += cast(size_t)w; }
        close(pf[1]); dup2(pf[0], 0); close(pf[0]);
        return true;
    }
    char[64] tp; snprintf(tp.ptr, tp.length, "/tmp/.dash-heredoc-%d", getpid());
    const fd = open(tp.ptr, O_RDWR | O_CREAT | O_TRUNC, 0x180);
    if (fd < 0) return false;
    size_t o = 0;
    while (o < text.length) { const w = write(fd, text.ptr + o, text.length - o); if (w <= 0) break; o += cast(size_t)w; }
    close(fd);
    const rfd = open(tp.ptr, O_RDONLY);
    unlink(tp.ptr);
    if (rfd < 0) return false;
    dup2(rfd, 0); close(rfd);
    return true;
}
private bool applyRedirs(Simple* sc, void* env) {
    foreach (ref r; sc.redirs) {
        if (r.k == RK.ErrToOut) { dup2(1, 2); continue; }
        if (r.k == RK.HereDoc || r.k == RK.HereStr) {
            Vec!(char*) t;
            if (!expandWord(r.target, env, t, true)) { t.dispose(); return false; }
            Buf b; foreach (q, x; t[]) { if (q) b.put(' '); b.putz(x); free(x); } t.dispose();
            if (r.k == RK.HereStr) b.put('\n');
            const ok = stdinFromText(b.str());
            b.dispose();
            if (!ok) { errOut("dash: here-document: cannot make its input\n"); return false; }
            continue;
        }
        Vec!(char*) t;
        if (!expandWord(r.target, env, t, true) || t.n == 0) { foreach (x; t[]) free(x); t.dispose(); return false; }
        const(char)* f = t[0];
        int fd;
        final switch (r.k) {
            case RK.Out: fd = open(f, O_WRONLY | O_CREAT | O_TRUNC, 0x1A4); if (fd >= 0) { dup2(fd, 1); close(fd); } break;
            case RK.Append: fd = open(f, O_WRONLY | O_CREAT | O_APPEND, 0x1A4); if (fd >= 0) { dup2(fd, 1); close(fd); } break;
            case RK.In: fd = open(f, O_RDONLY); if (fd >= 0) { dup2(fd, 0); close(fd); } break;
            case RK.ErrOut: fd = open(f, O_WRONLY | O_CREAT | O_TRUNC, 0x1A4); if (fd >= 0) { dup2(fd, 2); close(fd); } break;
            case RK.ErrAppend: fd = open(f, O_WRONLY | O_CREAT | O_APPEND, 0x1A4); if (fd >= 0) { dup2(fd, 2); close(fd); } break;
            case RK.Both: fd = open(f, O_WRONLY | O_CREAT | O_TRUNC, 0x1A4); if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); } break;
            case RK.ErrToOut: case RK.HereDoc: case RK.HereStr: break;
        }
        if (fd < 0) {
            Buf m; m.put("dash: "); m.putz(f); m.put(": cannot open\n"); errOut(m.str()); m.dispose();
            foreach (x; t[]) free(x); t.dispose();
            return false;
        }
        foreach (x; t[]) free(x); t.dispose();
    }
    return true;
}

private void resetChildSignals() {
    signal(SIGINT, SIG_DFL); signal(SIGQUIT, SIG_DFL); signal(SIGPIPE, SIG_DFL); signal(SIGTSTP, SIG_DFL);
}

// exec argv (PATH search); only returns on failure (in a child: then _exit(127)).
private void execArgv(char*[] argv) {
    auto path = findInPath(argv[0][0 .. strlen(argv[0])]);
    if (path is null) {
        Buf m; m.put("dash: "); m.putz(argv[0]); m.put(": command not found\n"); errOut(m.str()); m.dispose();
        _exit(127);
    }
    Vec!(char*) a; foreach (x; argv) a.push(x); a.push(null);
    execve(path, cast(const(char*)*)a.p, cast(const(char*)*)environ);
    Buf m; m.put("dash: "); m.putz(argv[0]); m.put(": cannot execute\n"); errOut(m.str()); m.dispose();
    _exit(126);
}

private int decodeStatus(int st) {
    if ((st & 0x7f) == 0) return (st >> 8) & 0xff;          // exited
    return 128 + (st & 0x7f);                               // killed by a signal
}

// Run a pipeline.  inFd/outFd: -1 = inherit.  Returns the exit status of the last command.
int runPipeline(Pipeline* pl, void* env, int inFd, int outFd, bool background = false) {
    const n = pl.cmds.length;
    // a lone compound command runs in the shell itself (its variables and `cd` stay)
    if (n == 1 && pl.cmds[0].k != CK.Simple && inFd < 0 && outFd < 0 && !background) {
        auto c = pl.cmds[0];
        if (c.k == CK.FuncDef) { defineFunction(c); return 0; }
        oflush();
        int so = -1, s1 = -1, s2 = -1;
        if (c.redirs.length) { so = dup(0); s1 = dup(1); s2 = dup(2); }
        int rc = 1;
        if (applyRedirList(c.redirs, env)) rc = runCompound(c, env);
        oflush();
        if (c.redirs.length) { dup2(so, 0); dup2(s1, 1); dup2(s2, 2); close(so); close(s1); close(s2); }
        return pl.negate ? (rc == 0) : rc;
    }
    // expand every simple command's words first (expansions may run commands / evaluate dash
    // expressions); the words of [[ ]] are neither split nor globbed
    Vec!(char*)[] argvs = (cast(Vec!(char*)*)calloc(n, (Vec!(char*)).sizeof))[0 .. n];
    scope (exit) { foreach (ref a; argvs) { foreach (x; a[]) free(x); a.dispose(); } free(argvs.ptr); }
    foreach (k; 0 .. n) {
        if (pl.cmds[k].k != CK.Simple) continue;
        auto ws = pl.cmds[k].sc.words;
        const bool dbl = ws.length && ws[0].parts.length == 1 && ws[0].parts[0].s == "[[" && ws[0].parts[0].quoted;
        foreach (ref w; ws) if (!expandWord(w, env, argvs[k], dbl)) return 1;
    }
    // a lone shell function runs in the shell itself
    if (n == 1 && argvs[0].n && inFd < 0 && outFd < 0 && !background) {
        auto f = findFunc(argvs[0][0][0 .. strlen(argvs[0][0])]);
        if (f) {
            oflush();
            int so = dup(0), s1 = dup(1), s2 = dup(2);
            int rc = 1;
            if (applyRedirs(pl.cmds[0].sc, env)) rc = callFunction(f, argvs[0][], env);
            oflush();
            dup2(so, 0); dup2(s1, 1); dup2(s2, 2); close(so); close(s1); close(s2);
            return pl.negate ? (rc == 0) : rc;
        }
    }
    // a lone assignment: NAME=value (sets a dash shell variable)
    if (n == 1 && argvs[0].n == 0) {
        auto sc = pl.cmds[0].sc;
        foreach (j, nm; sc.assignNames) {
            Vec!(char*) v;
            if (!expandWord(sc.assignVals[j], env, v, true)) { v.dispose(); return 1; }
            Buf b; foreach (q, x; v[]) { if (q) b.put(' '); b.putz(x); free(x); } v.dispose();
            if (g_setShellVar) g_setShellVar(nm, b.str());
            b.dispose();
        }
        return 0;
    }
    // a lone object command (ls, ps, cp ...) runs in the shell and answers with objects
    if (n == 1 && outFd < 0 && inFd < 0 && !background && argvs[0].n && g_objCommand) {
        oflush();
        int so = dup(0), s1 = dup(1), s2 = dup(2);
        int rc = 0;
        bool done = false;
        if (applyRedirs(pl.cmds[0].sc, env)) done = runObjCommand(argvs[0][], &rc);
        oflush();
        dup2(so, 0); dup2(s1, 1); dup2(s2, 2); close(so); close(s1); close(s2);
        if (done) return pl.negate ? (rc == 0) : rc;
    }
    // a lone builtin runs in the shell itself (so `cd`, `export`, `break`, `local` change the shell)
    if (n == 1 && outFd < 0 && inFd < 0 && !background && argvs[0].n) {
        const(char)[] name = argvs[0][0][0 .. strlen(argvs[0][0])];
        if (isShellBuiltin(name) || (g_isDashCommand && g_isDashCommand(name))) {
            int so = dup(0), s1 = dup(1), s2 = dup(2);
            int rc = 1;
            oflush();
            if (applyRedirs(pl.cmds[0].sc, env)) rc = runBuiltin(argvs[0][], env, pl.cmds[0].sc);
            oflush();
            dup2(so, 0); dup2(s1, 1); dup2(s2, 2); close(so); close(s1); close(s2);
            return pl.negate ? (rc == 0) : rc;
        }
    }
    oflush();
    int prevRead = inFd;
    Vec!int pids;
    foreach (k; 0 .. n) {
        int[2] pf = [-1, -1];
        if (k + 1 < n) { if (pipe(pf.ptr) != 0) { errOut("dash: pipe failed\n"); break; } }
        const pid = fork();
        if (pid == 0) {
            g_inChild = true;
            resetChildSignals();
            if (prevRead >= 0) { dup2(prevRead, 0); close(prevRead); }
            if (k + 1 < n) { dup2(pf[1], 1); close(pf[1]); close(pf[0]); }
            else if (outFd >= 0) { dup2(outFd, 1); close(outFd); }
            // a compound stage runs here, in its child
            if (pl.cmds[k].k != CK.Simple) {
                if (!applyRedirList(pl.cmds[k].redirs, env)) _exit(1);
                const rc = runCompound(pl.cmds[k], env);
                oflush();
                _exit(g_exitRequested ? g_exitCode : rc);
            }
            // per-command environment prefix
            auto sc = pl.cmds[k].sc;
            foreach (j, nm; sc.assignNames) {
                Vec!(char*) v; expandWord(sc.assignVals[j], env, v, true);
                Buf b; foreach (q, x; v[]) { if (q) b.put(' '); b.putz(x); }
                auto zn = cz(nm); setenv(zn, b.cstr(), 1);
            }
            if (!applyRedirs(sc, env)) _exit(1);
            if (argvs[k].n == 0) _exit(0);
            const(char)[] name = argvs[k][0][0 .. strlen(argvs[k][0])];
            if (auto f = findFunc(name)) { const rc = callFunction(f, argvs[k][], env); oflush(); _exit(rc); }
            { int orc; if (runObjCommand(argvs[k][], &orc)) _exit(orc); }
            if (isShellBuiltin(name) || (g_isDashCommand && g_isDashCommand(name))) {
                const rc = runBuiltin(argvs[k][], env, sc);
                oflush();
                _exit(rc);
            }
            execArgv(argvs[k][]);
        }
        if (pid < 0) { errOut("dash: fork failed\n"); break; }
        pids.push(pid);
        if (prevRead >= 0 && prevRead != inFd) close(prevRead);
        if (k + 1 < n) { close(pf[1]); prevRead = pf[0]; }
    }
    if (background) {
        foreach (pid; pids[]) g_jobs.push(pid);
        if (pids.n) g_lastBg = pids.back();
        if (pids.n) { outc('['); outi(g_jobs.n); out_("] "); outi(pids.back()); outc('\n'); oflush(); }
        pids.dispose();
        return 0;
    }
    int status = 0;
    foreach (k, pid; pids[]) {
        int st = 0;
        while (waitpid(pid, &st, 0) < 0) { if (!g_interrupted) break; g_interrupted = false; }
        if (k + 1 == pids.n) status = decodeStatus(st);
    }
    pids.dispose();
    if (status == 128 + SIGINT) outc('\n');
    return pl.negate ? (status == 0) : status;
}

int runAndOr(AndOr* ao, void* env, int outFd) {
    int st = runPipeline(ao.pipes[0], env, -1, outFd, ao.background && ao.pipes.length == 1);
    foreach (k, op; ao.ops) {
        if (ctlPending()) break;
        if ((op == 1 && st != 0) || (op == 2 && st == 0)) continue;
        st = runPipeline(ao.pipes[k + 1], env, -1, outFd, ao.background && k + 2 == ao.pipes.length);
    }
    g_lastStatus = st;
    return st;
}

int runList(CmdList* cl, void* env, int outFd = -1) {
    int st = 0;
    foreach (ao; cl.items) {
        if (ctlPending()) break;
        st = runAndOr(ao, env, outFd);
    }
    g_lastStatus = st;
    return st;
}

// Run a command line; returns its status (and leaves g_err set on a syntax error).
int runCommandText(const(char)[] text, void* env) {
    auto cl = parseCommand(text);
    if (cl is null) return 2;
    return runList(cl, env);
}

// Run a command line with its stdout captured into `outb`.  Returns the status.
int runCapture(const(char)[] text, void* env, ref Buf outb) {
    auto cl = parseCommand(text);
    if (cl is null) return 2;
    int[2] pf;
    if (pipe(pf.ptr) != 0) return 1;
    oflush();
    const pid = fork();
    if (pid == 0) {
        g_inChild = true;
        resetChildSignals();
        close(pf[0]);
        dup2(pf[1], 1); close(pf[1]);
        const rc = runList(cl, env);
        oflush();
        _exit(rc);
    }
    close(pf[1]);
    char[4096] buf;
    for (;;) {
        const r = read(pf[0], buf.ptr, buf.length);
        if (r <= 0) break;
        outb.put(buf[0 .. cast(size_t)r]);
    }
    close(pf[0]);
    int st = 0;
    if (pid > 0) waitpid(pid, &st, 0);
    g_lastStatus = decodeStatus(st);
    return g_lastStatus;
}

// Run a command line with `input` written to its stdin (a value flowing into a command stage).
int runWithInput(const(char)[] text, void* env, const(char)[] input, Buf* capture) {
    auto cl = parseCommand(text);
    if (cl is null) return 2;
    int[2] pin; if (pipe(pin.ptr) != 0) return 1;
    int[2] pout = [-1, -1];
    if (capture) { if (pipe(pout.ptr) != 0) return 1; }
    oflush();
    // a writer child feeds the input so a large value cannot deadlock against the reader
    const wpid = fork();
    if (wpid == 0) {
        close(pin[0]); if (capture) { close(pout[0]); close(pout[1]); }
        size_t o = 0;
        while (o < input.length) { const w = write(pin[1], input.ptr + o, input.length - o); if (w <= 0) break; o += cast(size_t)w; }
        _exit(0);
    }
    close(pin[1]);
    const pid = fork();
    if (pid == 0) {
        g_inChild = true;
        resetChildSignals();
        dup2(pin[0], 0); close(pin[0]);
        if (capture) { close(pout[0]); dup2(pout[1], 1); close(pout[1]); }
        const rc = runList(cl, env);
        oflush();
        _exit(rc);
    }
    close(pin[0]);
    if (capture) {
        close(pout[1]);
        char[4096] buf;
        for (;;) { const r = read(pout[0], buf.ptr, buf.length); if (r <= 0) break; capture.put(buf[0 .. cast(size_t)r]); }
        close(pout[0]);
    }
    int st = 0;
    if (pid > 0) waitpid(pid, &st, 0);
    if (wpid > 0) { int ws; waitpid(wpid, &ws, 0); }
    g_lastStatus = decodeStatus(st);
    return g_lastStatus;
}

// ── builtins ────────────────────────────────────────────────────────────────────────────────────
alias SetVarFn = void function(const(char)[] name, const(char)[] value) @nogc nothrow;
alias IsDashCmdFn = bool function(const(char)[] name) @nogc nothrow;
__gshared SetVarFn g_setShellVar;
__gshared IsDashCmdFn g_isDashCommand;   // dash-level builtins (help, :-style verbs, obj/ns/...)
__gshared bool g_exitRequested; __gshared int g_exitCode;

private void say(const(char)[] a, const(char)[] b = null, const(char)[] c = null) { out_(a); out_(b); out_(c); }
__gshared void function(const(char)[] path) @nogc nothrow g_sourceFile;   // main.d: runFile
// Object commands (dash.fsobj: ls, ps, cp, ...) and how a value is shown (dash.stmt.display).
alias ObjCmdFn = Value* function(const(char)[][] argv, out bool handled) @nogc nothrow;
__gshared ObjCmdFn g_objCommand;
__gshared void function(Value* v) @nogc nothrow g_displayValue;
// Run argv as an object command if it is one: true when it was (its answer printed -- a table on a
// terminal, otherwise text lines -- and *status set).
private bool runObjCommand(char*[] argv, int* status) {
    if (!g_objCommand || argv.length == 0) return false;
    Vec!(const(char)[]) av;
    foreach (a; argv) av.push(a[0 .. strlen(a)]);
    bool handled;
    auto v = g_objCommand(av[], handled);
    av.dispose();
    if (!handled) return false;
    if (v is null) {
        Buf m; m.put("dash: "); m.put(errText()); m.put('\n'); errOut(m.str()); m.dispose();
        clearErr();
        *status = 1;
        return true;
    }
    if (v.t != VT.Unit) {
        if (isatty(1) && g_displayValue) g_displayValue(v);
        else { Buf t; linesOf(t, v); out_(t.str()); t.dispose(); }
    }
    oflush();
    *status = 0;
    return true;
}

// ── test / [ / [[ ]] ────────────────────────────────────────────────────────────────────────────
private bool isNum(const(char)[] a, out long v) {
    if (a.length == 0) return false;
    size_t k = (a[0] == '-' || a[0] == '+') ? 1 : 0;
    if (k == a.length) return false;
    foreach (c; a[k .. $]) if (!isDigit(c)) return false;
    Buf b; b.put(a); v = strtoll(b.cstr(), null, 10); b.dispose();
    return true;
}
private bool fileTest(char op, const(char)[] path) {
    import dash.native : nstat, NStat;
    auto z = cz(path);
    scope (exit) free(z);
    NStat st;
    if (op == 'L' || op == 'h') return nstat(z, st, true) == 0 && (st.mode & 0xF000) == 0xA000;
    if (nstat(z, st) != 0) return false;
    switch (op) {
        case 'e': return true;
        case 'f': return (st.mode & 0xF000) == 0x8000;
        case 'd': return (st.mode & 0xF000) == 0x4000;
        case 'p': return (st.mode & 0xF000) == 0x1000;
        case 'S': return (st.mode & 0xF000) == 0xC000;
        case 'b': return (st.mode & 0xF000) == 0x6000;
        case 'c': return (st.mode & 0xF000) == 0x2000;
        case 's': return st.size > 0;
        case 'r': return access(z, R_OK) == 0;
        case 'w': return access(z, W_OK) == 0;
        case 'x': return access(z, X_OK) == 0;
        default: return false;
    }
}
// A tiny regular-expression matcher for [[ s =~ re ]]: . [set] [^set] * + ? ^ $ and \x (no groups).
private bool reMatchHere(const(char)[] re, const(char)[] t) {
    if (re.length == 0) return true;
    if (re == "$") return t.length == 0;
    // one atom
    size_t alen = 1;
    if (re[0] == '\\' && re.length > 1) alen = 2;
    else if (re[0] == '[') { alen = 1; if (alen < re.length && re[alen] == '^') ++alen; if (alen < re.length && re[alen] == ']') ++alen; while (alen < re.length && re[alen] != ']') ++alen; if (alen < re.length) ++alen; }
    const atom = re[0 .. alen];
    bool matches(char c) {
        if (atom[0] == '.') return true;
        if (atom[0] == '\\') return atom.length > 1 && c == atom[1];
        if (atom[0] == '[') {
            size_t k = 1; bool neg = false;
            if (k < atom.length && atom[k] == '^') { neg = true; ++k; }
            bool hit = false;
            while (k < atom.length && atom[k] != ']' || (k == 1 + (neg ? 1 : 0) && k < atom.length && atom[k] == ']')) {
                if (k + 2 < atom.length && atom[k + 1] == '-' && atom[k + 2] != ']') { if (c >= atom[k] && c <= atom[k + 2]) hit = true; k += 3; }
                else { if (c == atom[k]) hit = true; ++k; }
            }
            return hit != neg;
        }
        return c == atom[0];
    }
    const rest = re[alen .. $];
    if (rest.length && (rest[0] == '*' || rest[0] == '+' || rest[0] == '?')) {
        const q = rest[0];
        const after = rest[1 .. $];
        size_t n = 0;
        while (n < t.length && matches(t[n]) && (q != '?' || n < 1)) ++n;
        for (size_t k = n + 1; k-- > (q == '+' ? 1 : 0); ) if (reMatchHere(after, t[k .. $])) return true;
        return false;
    }
    return t.length > 0 && matches(t[0]) && reMatchHere(rest, t[1 .. $]);
}
private bool reMatch(const(char)[] re, const(char)[] t) {
    if (re.length && re[0] == '^') return reMatchHere(re[1 .. $], t);
    foreach (k; 0 .. t.length + 1) if (reMatchHere(re, t[k .. $])) return true;
    return false;
}
// test's expression grammar (also [[ ]]: `dbl` adds && || and pattern matching for == !=).
private struct TestEval {
    const(char)[][] a; size_t i; bool dbl; bool bad;
    @nogc nothrow:
    bool at(const(char)[] w) { return i < a.length && a[i] == w; }
    bool orE() {
        bool v = andE();
        while (at(dbl ? "||" : "-o")) { ++i; const r = andE(); v = v || r; }
        return v;
    }
    bool andE() {
        bool v = notE();
        while (at(dbl ? "&&" : "-a")) { ++i; const r = notE(); v = v && r; }
        return v;
    }
    bool notE() {
        if (at("!")) { ++i; return !notE(); }
        return prim();
    }
    bool prim() {
        if (i >= a.length) { bad = true; return false; }
        if (at("(")) { ++i; const v = orE(); if (!at(")")) bad = true; else ++i; return v; }
        // binary
        if (i + 2 < a.length) {
            const op = a[i + 1];
            const bool isBin = op == "=" || op == "==" || op == "!=" || op == "<" || op == ">" || op == "=~" ||
                               op == "-eq" || op == "-ne" || op == "-lt" || op == "-le" || op == "-gt" || op == "-ge" ||
                               op == "-nt" || op == "-ot";
            if (isBin) {
                const l = a[i], r = a[i + 2];
                i += 3;
                switch (op) {
                    case "=": case "==": return dbl ? matchAt(r, l) : l == r;
                    case "!=": return dbl ? !matchAt(r, l) : l != r;
                    case "<": return cmpStr(l, r) < 0;
                    case ">": return cmpStr(l, r) > 0;
                    case "=~": return reMatch(r, l);
                    case "-nt": case "-ot": {
                        import dash.native : nstat, NStat;
                        NStat x, y; auto zl = cz(l), zr = cz(r);
                        const okx = nstat(zl, x) == 0, oky = nstat(zr, y) == 0; free(zl); free(zr);
                        if (op == "-nt") return okx && (!oky || x.mtime > y.mtime);
                        return oky && (!okx || x.mtime < y.mtime);
                    }
                    default: {
                        long x, y;
                        if (!isNum(l, x) || !isNum(r, y)) { bad = true; return false; }
                        switch (op) {
                            case "-eq": return x == y; case "-ne": return x != y; case "-lt": return x < y;
                            case "-le": return x <= y; case "-gt": return x > y; default: return x >= y;
                        }
                    }
                }
            }
        }
        // unary
        if (a[i].length == 2 && a[i][0] == '-' && i + 1 < a.length) {
            const op = a[i][1];
            const arg = a[i + 1];
            switch (op) {
                case 'z': i += 2; return arg.length == 0;
                case 'n': i += 2; return arg.length != 0;
                case 't': { i += 2; long fd; if (!isNum(arg, fd)) return false; return isatty(cast(int)fd) != 0; }
                case 'e': case 'f': case 'd': case 'L': case 'h': case 'p': case 'S': case 'b': case 'c':
                case 's': case 'r': case 'w': case 'x':
                    i += 2; return fileTest(op, arg);
                case 'v': { i += 2; Buf b; const set = paramText(arg, null, b); b.dispose(); return set; }
                default: break;
            }
        }
        return a[i++].length != 0;                         // a lone string: true when not empty
    }
}
private int cmpStr(const(char)[] x, const(char)[] y) {
    const n = x.length < y.length ? x.length : y.length;
    foreach (k; 0 .. n) if (x[k] != y[k]) return x[k] < y[k] ? -1 : 1;
    return x.length < y.length ? -1 : (x.length > y.length ? 1 : 0);
}
private int runTest(const(char)[][] args, bool dbl) {
    if (args.length == 0) return 1;
    TestEval t; t.a = args; t.dbl = dbl;
    const v = t.orE();
    if (t.bad || t.i != args.length) { errOut(dbl ? "dash: [[: bad expression\n" : "dash: test: bad expression\n"); return 2; }
    return v ? 0 : 1;
}

// read [-r] [-p prompt] [name...]: one line of stdin into shell variables (REPLY without names).
private int readBuiltin(char*[] argv) {
    bool raw = false;
    size_t k = 1;
    for (; k < argv.length && argv[k][0] == '-'; ++k) {
        if (strcmp(argv[k], "-r") == 0) raw = true;
        else if (strcmp(argv[k], "-p") == 0 && k + 1 < argv.length) { ++k; out_(argv[k][0 .. strlen(argv[k])]); oflush(); }
        else if (strcmp(argv[k], "--") == 0) { ++k; break; }
        else break;
    }
    Buf line; bool got = false, eof = false;
    for (;;) {
        char c;
        const r = read(0, &c, 1);
        if (r <= 0) { eof = true; break; }
        got = true;
        if (c == '\n') break;
        if (!raw && c == '\\') {
            char d; if (read(0, &d, 1) <= 0) { eof = true; break; }
            if (d == '\n') continue;
            line.put(d); continue;
        }
        line.put(c);
    }
    scope (exit) line.dispose();
    if (eof && !got) return 1;
    auto names = argv[k .. $];
    const(char)[] t = line.str();
    bool ws(char c) { return c == ' ' || c == '\t' || c == '\n'; }
    if (names.length == 0) { if (g_setShellVar) g_setShellVar("REPLY", t); return 0; }
    size_t p = 0;
    foreach (j, nm; names) {
        while (p < t.length && ws(t[p])) ++p;
        const(char)[] val;
        if (j + 1 == names.length) {                       // the last name takes the rest
            size_t e = t.length; while (e > p && ws(t[e - 1])) --e;
            val = t[p .. e]; p = t.length;
        } else {
            const st = p; while (p < t.length && !ws(t[p])) ++p;
            val = t[st .. p];
        }
        if (g_setShellVar) g_setShellVar(nm[0 .. strlen(nm)], val);
    }
    return eof ? 1 : 0;
}

int runBuiltin(char*[] argv, void* env, Simple* sc) {
    const(char)[] name = argv[0][0 .. strlen(argv[0])];
    const(char)[] arg(size_t k) { return k < argv.length ? argv[k][0 .. strlen(argv[k])] : null; }
    switch (name) {
        case "cd": {
            const(char)* dir = argv.length > 1 ? argv[1] : getenv("HOME");
            if (dir is null) dir = "/";
            if (argv.length > 1 && strcmp(argv[1], "-") == 0) { auto o = getenv("OLDPWD"); if (o) dir = o; }
            char[1024] old; getcwd(old.ptr, old.length);
            if (chdir(dir) != 0) { say("cd: ", dir[0 .. strlen(dir)], ": no such directory\n"); return 1; }
            setenv("OLDPWD", old.ptr, 1);
            char[1024] now; if (getcwd(now.ptr, now.length)) setenv("PWD", now.ptr, 1);
            return 0;
        }
        case "pwd": { char[1024] b; if (getcwd(b.ptr, b.length)) { outz(b.ptr); outc('\n'); } return 0; }
        case "exit": {
            g_exitRequested = true;
            g_exitCode = argv.length > 1 ? cast(int)strtoll(argv[1], null, 10) : g_lastStatus;
            if (g_inChild) { oflush(); _exit(g_exitCode); }
            return g_exitCode;
        }
        case "true": case ":": return 0;
        case "false": return 1;
        case "test": case "[": {
            Vec!(const(char)[]) as;
            size_t end = argv.length;
            if (name == "[") {
                if (argv.length < 2 || strcmp(argv[$ - 1], "]") != 0) { errOut("dash: [: missing ']'\n"); return 2; }
                end = argv.length - 1;
            }
            foreach (q; 1 .. end) as.push(arg(q));
            const r = runTest(as[], false); as.dispose(); return r;
        }
        case "[[": {
            Vec!(const(char)[]) as;
            foreach (q; 1 .. argv.length - 1) as.push(arg(q));   // between [[ and ]]
            const r = runTest(as[], true); as.dispose(); return r;
        }
        case "read": return readBuiltin(argv);
        case "shift": {
            long n = 1; if (argv.length > 1 && !isNum(arg(1), n)) n = 1;
            if (n < 0 || n > g_pos.length) return 1;
            g_pos = g_pos[cast(size_t)n .. $];
            return 0;
        }
        case "set": {
            // set -- args: the positional parameters; set -e / -x / +e / +x are accepted (no effect yet)
            size_t q = 1;
            while (q < argv.length && (argv[q][0] == '-' || argv[q][0] == '+') && strcmp(argv[q], "--") != 0) ++q;
            if (q < argv.length && strcmp(argv[q], "--") == 0) ++q;
            if (q < argv.length || (argv.length > 1 && strcmp(argv[argv.length - 1], "--") == 0)) {
                auto np = (cast(char**)calloc(argv.length - q + 1, (char*).sizeof))[0 .. argv.length - q];
                foreach (j; q .. argv.length) np[j - q] = cz(arg(j));
                g_pos = np;
            }
            return 0;
        }
        case "local": {
            if (g_funcDepth == 0) { errOut("dash: local: only inside a function\n"); return 1; }
            foreach (q; 1 .. argv.length) {
                const(char)[] a = arg(q);
                size_t eq = a.length; foreach (j, c; a) if (c == '=') { eq = j; break; }
                saveVarForLocal(a[0 .. eq]);
                if (g_setShellVar) g_setShellVar(a[0 .. eq], eq < a.length ? a[eq + 1 .. $] : "");
            }
            return 0;
        }
        case "return": {
            if (g_funcDepth == 0 && g_sourceDepth == 0) { errOut("dash: return: only inside a function or a sourced file\n"); return 1; }
            long n = g_lastStatus; if (argv.length > 1) isNum(arg(1), n);
            g_returnPending = true; g_returnValue = cast(int)(n & 0xFF);
            return g_returnValue;
        }
        case "break": case "continue": {
            if (g_loopDepth == 0) { say("dash: ", name, ": only inside a loop\n"); return 1; }
            long n = 1; if (argv.length > 1 && (!isNum(arg(1), n) || n < 1)) n = 1;
            if (n > g_loopDepth) n = g_loopDepth;
            if (name == "break") g_breakN = cast(int)n; else g_contN = cast(int)n;
            return 0;
        }
        case "eval": {
            Buf t; foreach (q; 1 .. argv.length) { if (q > 1) t.put(' '); t.put(arg(q)); }
            const r = runCommandText(permDup(t.str()), env); t.dispose();
            return r;
        }
        case "source": case ".": {
            if (argv.length < 2) { say("dash: ", name, ": a file is needed\n"); return 2; }
            if (!g_sourceFile) return 1;
            auto saved = g_pos;
            if (argv.length > 2) {
                auto np = (cast(char**)calloc(argv.length - 2, (char*).sizeof))[0 .. argv.length - 2];
                foreach (j; 2 .. argv.length) np[j - 2] = cz(arg(j));
                g_pos = np;
            }
            ++g_sourceDepth;
            g_sourceFile(permDup(arg(1)));
            --g_sourceDepth;
            g_returnPending = false;
            g_pos = saved;
            return g_lastStatus;
        }
        case "printenv": {
            if (argv.length == 1) { for (auto e = environ; *e; ++e) { outz(*e); outc('\n'); } return 0; }
            int rc = 0;
            foreach (q; 1 .. argv.length) { auto v = getenv(argv[q]); if (v) { outz(v); outc('\n'); } else rc = 1; }
            return rc;
        }
        case "command": {
            if (argv.length < 2) return 0;
            const(char)[] cn = arg(1);
            if (isShellBuiltin(cn)) return runBuiltin(argv[1 .. $], env, sc);
            oflush();
            const pid = fork();
            if (pid == 0) { g_inChild = true; resetChildSignals(); execArgv(argv[1 .. $]); }
            int st = 0; while (waitpid(pid, &st, 0) < 0) { if (!g_interrupted) break; g_interrupted = false; }
            return decodeStatus(st);
        }
        case "echo": {
            size_t k = 1; bool nl = true, esc = false;
            while (k < argv.length && argv[k][0] == '-' && (strcmp(argv[k], "-n") == 0 || strcmp(argv[k], "-e") == 0 || strcmp(argv[k], "-ne") == 0 || strcmp(argv[k], "-en") == 0)) {
                if (strchr(argv[k], 'n')) nl = false;
                if (strchr(argv[k], 'e')) esc = true;
                ++k;
            }
            foreach (j; k .. argv.length) {
                if (j > k) outc(' ');
                const(char)[] a = arg(j);
                if (!esc) { out_(a); continue; }
                for (size_t q = 0; q < a.length; ++q) {
                    if (a[q] == '\\' && q + 1 < a.length) {
                        ++q;
                        switch (a[q]) { case 'n': outc('\n'); break; case 't': outc('\t'); break; case 'e': outc('\x1b'); break; case '\\': outc('\\'); break; default: outc('\\'); outc(a[q]); }
                    } else outc(a[q]);
                }
            }
            if (nl) outc('\n');
            return 0;
        }
        case "export": {
            if (argv.length == 1) { for (auto e = environ; *e; ++e) { out_("export "); outz(*e); outc('\n'); } return 0; }
            foreach (k; 1 .. argv.length) {
                const(char)[] a = arg(k);
                size_t eq = a.length;
                foreach (q, c; a) if (c == '=') { eq = q; break; }
                auto zn = cz(a[0 .. eq]);
                if (eq < a.length) { auto zv = cz(a[eq + 1 .. $]); setenv(zn, zv, 1); free(zv); }
                else if (g_lookupVar) { auto v = g_lookupVar(a, env); if (v) { Buf b; textOf(b, v); setenv(zn, b.cstr(), 1); b.dispose(); } }
                free(zn);
            }
            return 0;
        }
        case "unset": {
            bool fn = false;
            foreach (k; 1 .. argv.length) {
                if (strcmp(argv[k], "-f") == 0) { fn = true; continue; }
                if (strcmp(argv[k], "-v") == 0) { fn = false; continue; }
                if (fn) { removeFunction(arg(k)); continue; }
                unsetenv(argv[k]);
                import dash.eval : setGlobal, globalFlags, GF;
                const sym = intern(arg(k));
                if (globalFlags(sym) & GF.ShellVar) setGlobal(sym, null, 0);
            }
            return 0;
        }
        case "wait": {
            foreach (pid; g_jobs[]) { int st; waitpid(pid, &st, 0); }
            g_jobs.clear();
            return 0;
        }
        case "jobs": {
            foreach (k, pid; g_jobs[]) {
                int st; const r = waitpid(pid, &st, 1 /*WNOHANG*/);
                outc('['); outi(k + 1); out_("] "); outi(pid); out_(r == 0 ? "  running\n" : "  done\n");
            }
            return 0;
        }
        case "which": case "type": {
            int rc = 0;
            foreach (k; 1 .. argv.length) {
                const(char)[] a = arg(k);
                if (findFunc(a)) { say(a, ": shell function\n"); continue; }
                if (g_isDashCommand && g_isDashCommand(a)) { say(a, ": dash builtin\n"); continue; }
                if (isShellBuiltin(a)) { say(a, ": shell builtin\n"); continue; }
                auto p = findInPath(a);
                if (p) { outz(p); outc('\n'); free(p); } else { say(a, " not found\n"); rc = 1; }
            }
            return rc;
        }
        case "exec": {
            if (argv.length < 2) return 0;
            oflush();
            resetChildSignals();
            execArgv(argv[1 .. $]);
            return 127;
        }
        case "linux": return runLinux(argv[1 .. $]);
        default:
            if (g_dashBuiltin) { const r = g_dashBuiltin(cast(const(char)*[])argv, env); if (r >= 0) return r; }
            say("dash: ", name, ": not a builtin\n");
            return 1;
    }
}

// `linux` -- drop into the Linux shell on this terminal; `linux cmd args` runs one command there.
// The child leaves the native personality for good (the kernel's one-way ratchet): exec'ing the
// Linux zsh drops the native-launch authorization for it and everything it starts.  This shell
// keeps its own authority and resumes when the Linux shell exits.
__gshared void function() @nogc nothrow g_beforeForeground;   // restore the terminal for a child
int runLinux(char*[] args) {
    oflush();
    if (g_beforeForeground) g_beforeForeground();
    const pid = fork();
    if (pid == 0) {
        resetChildSignals();
        // DM13: this process tree drops to the Linux personality (refused if already there: fine)
        const fd = open("/config/domain.action", O_WRONLY);
        if (fd >= 0) { immutable m = "mode self linux\n"; write(fd, m.ptr, m.length); close(fd); }
        setenv("EPIN_SHELL", "linux", 1);
        setenv("SHELL", "/bin/zsh", 1);
        // zsh, else busybox sh (which cannot read zsh's prompt escapes: give it a plain one)
        if (args.length == 0) {
            const(char)*[2] av; av[0] = "-zsh"; av[1] = null;
            execve("/bin/zsh", av.ptr, cast(const(char*)*)environ);
            setenv("SHELL", "/bin/sh", 1); setenv("PS1", "[linux] \\u:\\w \\$ ", 1);
            av[0] = "-sh";
            execve("/bin/sh", av.ptr, cast(const(char*)*)environ);
        } else {
            Buf cmd; foreach (k, a; args) { if (k) cmd.put(' '); cmd.putz(a); }
            const(char)*[4] av; av[0] = "zsh"; av[1] = "-c"; av[2] = cmd.cstr(); av[3] = null;
            execve("/bin/zsh", av.ptr, cast(const(char*)*)environ);
            av[0] = "sh";
            execve("/bin/sh", av.ptr, cast(const(char*)*)environ);
        }
        errOut("dash: linux: no Linux shell (/bin/zsh or /bin/sh) in this domain\n");
        _exit(127);
    }
    if (pid < 0) { errOut("dash: linux: fork failed\n"); return 1; }
    if (args.length == 0) { out_("\x1b[2m(entering the Linux shell -- `exit` returns to dash)\x1b[0m\n"); oflush(); }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) { if (!g_interrupted) break; g_interrupted = false; }
    if (args.length == 0) { out_("\x1b[2m(back in dash)\x1b[0m\n"); oflush(); }
    return decodeStatus(st);
}
