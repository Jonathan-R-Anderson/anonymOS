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
enum RK : ubyte { Out, Append, In, ErrOut, ErrAppend, ErrToOut, Both }
struct Redir { RK k; Word target; }
struct Simple { const(char)[][] assignNames; Word[] assignVals; Word[] words; Redir[] redirs; }
struct Pipeline { Simple*[] cmds; bool negate; }
struct AndOr { Pipeline*[] pipes; ubyte[] ops; bool background; }
struct CmdList { AndOr*[] items; }

@nogc nothrow:

private T* anew(T)() { return cast(T*)calloc(1, T.sizeof); }
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
    bool fail(const(char)[] m) { if (!failed) { failed = true; setErr("command syntax: ", m); } return false; }
    void skipSpace() { while (i < s.length && isSpace(s[i])) ++i; }
    bool atEnd() { return i >= s.length; }
    char peek(size_t k = 0) { return i + k < s.length ? s[i + k] : 0; }

    CmdList* list() {
        auto cl = anew!CmdList();
        Vec!(AndOr*) items;
        for (;;) {
            skipSpace();
            while (peek() == ';' || peek() == '\n') { ++i; skipSpace(); }
            if (atEnd() || peek() == '#') break;
            auto ao = andOr(); if (!ao) { items.dispose(); return null; }
            skipSpace();
            if (peek() == '&' && peek(1) != '&') { ao.background = true; ++i; }
            items.push(ao);
            skipSpace();
            if (peek() == ';' || peek() == '\n') { ++i; continue; }
            if (peek() == '&') continue;
            if (atEnd() || peek() == '#') break;
            if (peek() == ')') { fail("unexpected ')'"); items.dispose(); return null; }
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
        Vec!(Simple*) cs;
        for (;;) {
            auto c = simple(); if (!c) { cs.dispose(); return null; }
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
            // redirections: [n]> [n]>> < 2>&1 &>
            {
                size_t j = i; int fd = -1;
                if (isDigit(s[j]) && j + 1 < s.length && (s[j + 1] == '>' || s[j + 1] == '<')) { fd = s[j] - '0'; ++j; }
                if (j < s.length && (s[j] == '>' || s[j] == '<' || (s[j] == '&' && j + 1 < s.length && s[j + 1] == '>'))) {
                    Redir r;
                    if (s[j] == '&') { r.k = RK.Both; j += 2; }
                    else if (s[j] == '<') { r.k = RK.In; ++j; }
                    else if (j + 1 < s.length && s[j + 1] == '>') { r.k = fd == 2 ? RK.ErrAppend : RK.Append; j += 2; }
                    else if (j + 2 < s.length && s[j + 1] == '&' && s[j + 2] == '1' && fd == 2) { r.k = RK.ErrToOut; j += 3; }
                    else { r.k = fd == 2 ? RK.ErrOut : RK.Out; ++j; }
                    i = j;
                    if (r.k != RK.ErrToOut) {
                        skipSpace();
                        if (!word(r.target)) { ws.dispose(); rs.dispose(); an.dispose(); av.dispose(); return null; }
                        if (r.target.parts.length == 0) { fail("a redirection needs a file"); ws.dispose(); rs.dispose(); an.dispose(); av.dispose(); return null; }
                    }
                    rs.push(r);
                    continue;
                }
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
        sc.words = slice(ws); sc.redirs = slice(rs); sc.assignNames = slice(an); sc.assignVals = slice(av);
        return sc;
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
            ++i; const st = i;
            while (i < s.length && s[i] != '}') ++i;
            if (i >= s.length) return fail("unterminated ${");
            p.k = WP.Var; p.s = permDup(s[st .. i]); ++i; ps.push(p); return true;
        }
        if (peek() == '?' || peek() == '$' || peek() == '#' || isDigit(peek())) {
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
// Expand a word into zero or more argv strings (malloc'd; appended to out).
bool expandWord(ref Word w, void* env, ref Vec!(char*) outv, bool noGlob = false) {
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
private Value* expansionValue(ref WPart p, void* env) {
    if (p.k == WP.ExprSub) return g_evalText ? g_evalText(p.s, env) : null;
    if (p.s == "?") return mkInt(g_lastStatus);
    if (p.s == "$") return mkInt(getpid());
    if (g_lookupVar) { auto v = g_lookupVar(p.s, env); if (v) return v; }
    auto z = cz(p.s); auto e = getenv(z); free(z);
    return e ? mkStrZ(e) : mkStr("");
}

// ── running ─────────────────────────────────────────────────────────────────────────────────────
__gshared bool g_inChild;         // true in a forked child: builtins that exit, exit the child

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
             "type", "help", "linux", "echo", "true", "false", "exec", "alias", "set":
            return true;
        default: return false;
    }
}

// Apply a simple command's redirections in the CURRENT process (a child, or around a builtin).
private bool applyRedirs(Simple* sc, void* env) {
    foreach (ref r; sc.redirs) {
        if (r.k == RK.ErrToOut) { dup2(1, 2); continue; }
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
            case RK.ErrToOut: break;
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
    // expand every command's words first (expansions may run commands/evaluate dash expressions)
    Vec!(char*)[] argvs = (cast(Vec!(char*)*)calloc(n, (Vec!(char*)).sizeof))[0 .. n];
    scope (exit) { foreach (ref a; argvs) { foreach (x; a[]) free(x); a.dispose(); } free(argvs.ptr); }
    foreach (k; 0 .. n) {
        foreach (ref w; pl.cmds[k].words) if (!expandWord(w, env, argvs[k])) return 1;
    }
    // a lone assignment: NAME=value (sets a dash shell variable)
    if (n == 1 && argvs[0].n == 0) {
        auto sc = pl.cmds[0];
        foreach (j, nm; sc.assignNames) {
            Vec!(char*) v;
            if (!expandWord(sc.assignVals[j], env, v, true)) { v.dispose(); return 1; }
            Buf b; foreach (q, x; v[]) { if (q) b.put(' '); b.putz(x); free(x); } v.dispose();
            if (g_setShellVar) g_setShellVar(nm, b.str());
            b.dispose();
        }
        return 0;
    }
    // a lone builtin runs in the shell itself (so `cd` and `export` change the shell)
    if (n == 1 && outFd < 0 && inFd < 0 && !background && argvs[0].n && !g_inChild) {
        const(char)[] name = argvs[0][0][0 .. strlen(argvs[0][0])];
        if (isShellBuiltin(name) || (g_isDashCommand && g_isDashCommand(name))) {
            int so = dup(0), s1 = dup(1), s2 = dup(2);
            int rc = 1;
            oflush();
            if (applyRedirs(pl.cmds[0], env)) rc = runBuiltin(argvs[0][], env, pl.cmds[0]);
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
            // per-command environment prefix
            auto sc = pl.cmds[k];
            foreach (j, nm; sc.assignNames) {
                Vec!(char*) v; expandWord(sc.assignVals[j], env, v, true);
                Buf b; foreach (q, x; v[]) { if (q) b.put(' '); b.putz(x); }
                auto zn = cz(nm); setenv(zn, b.cstr(), 1);
            }
            if (!applyRedirs(sc, env)) _exit(1);
            if (argvs[k].n == 0) _exit(0);
            const(char)[] name = argvs[k][0][0 .. strlen(argvs[k][0])];
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
        if (g_interrupted) break;
        if ((op == 1 && st != 0) || (op == 2 && st == 0)) continue;
        st = runPipeline(ao.pipes[k + 1], env, -1, outFd, ao.background && k + 2 == ao.pipes.length);
    }
    g_lastStatus = st;
    return st;
}

int runList(CmdList* cl, void* env, int outFd = -1) {
    int st = 0;
    foreach (ao; cl.items) {
        if (g_interrupted) break;
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
        case "true": return 0;
        case "false": return 1;
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
        case "unset": foreach (k; 1 .. argv.length) unsetenv(argv[k]); return 0;
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
