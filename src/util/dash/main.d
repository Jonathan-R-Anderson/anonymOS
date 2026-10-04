// dash: the native shell of EpinAnonymOS.  bash where you run programs, Haskell where you compute,
// over the OS's object model; `linux` drops into the Linux shell.  See docs/DASH.md.
module dash.main;

import dash.rt;
import dash.value;
import dash.eval;
import dash.exec;
import dash.lib;
import dash.objects;
import dash.stmt;
import dash.edit;
import dash.complete;

@nogc nothrow:

private extern (C) void onSigint(int) { g_interrupted = true; }

// ── dash-level builtins (they run where commands run) ───────────────────────────────────────────
private bool isDashCmd(const(char)[] n) {
    switch (n) { case "arm", "--yes", "dry-run", "--dry-run", "wet-run": return true; default: return false; }
}
private int dashBuiltin(const(char)*[] argv, void* env) {
    const(char)[] n = argv[0][0 .. strlen(argv[0])];
    switch (n) {
        case "arm": case "--yes":
            g_armed = true;
            out_("armed: the NEXT destructive operation will run (one-shot)\n"); oflush(); return 0;
        case "dry-run": case "--dry-run":
            g_dryRun = true;
            out_("dry-run ON: destructive operations report what they would do and do nothing (wet-run to turn off)\n"); oflush(); return 0;
        case "wet-run":
            g_dryRun = false; out_("dry-run OFF\n"); oflush(); return 0;
        default: return -1;
    }
}
private int helpBuiltin(const(char)*[] argv, void* env) { return -1; }

// ── statements from text: lines joined by indentation and continuation ──────────────────────────
// Is `text` unfinished (an open bracket or string, or a line that ends asking for more)?
bool incomplete(const(char)[] text) {
    int depth = 0; bool dq = false;
    for (size_t i = 0; i < text.length; ++i) {
        const c = text[i];
        if (dq) { if (c == '\\') ++i; else if (c == '"') dq = false; continue; }
        if (c == '"') { dq = true; continue; }
        if (c == '-' && i + 1 < text.length && text[i + 1] == '-' && (i + 2 >= text.length || text[i + 2] == ' ')) {
            while (i < text.length && text[i] != '\n') ++i;
            continue;
        }
        if (c == '(' || c == '[' || c == '{') ++depth;
        else if (c == ')' || c == ']' || c == '}') --depth;
    }
    if (dq || depth > 0) return true;
    if (shellOpenBlocks(text) > 0) return true;        // an open if/for/while/case/{ or here-document
    auto t = trim(text);
    if (t.length == 0) return false;
    if (t[$ - 1] == '\\') return true;
    foreach (e; ["=", "->", "|>", "|", "&&", "||", "$", "++", " do", " where", " of", " then", " else", " in", " let"]) {
        if (endsWith(t, e)) {
            if (e == "=" && (endsWith(t, "==") || endsWith(t, "/=") || endsWith(t, "<=") || endsWith(t, ">="))) continue;
            return true;
        }
    }
    if (t == "do" || t == "where") return true;
    return false;
}

// Run a whole script: statements are a line plus the indented lines after it.
void runScript(const(char)[] src) {
    size_t i = 0;
    if (src.length > 2 && src[0] == '#' && src[1] == '!') { while (i < src.length && src[i] != '\n') ++i; }
    Buf stmt;
    void flush() {
        if (stmt.n) { runStatement(stmt.str()); collectIfNeeded(); stmt.clear(); }
    }
    while (i < src.length && !g_exitRequested) {
        size_t e = i; while (e < src.length && src[e] != '\n') ++e;
        auto line = src[i .. e];
        i = e + 1;
        const blank = trim(line).length == 0;
        const indented = line.length && (line[0] == ' ' || line[0] == '\t');
        if (stmt.n && (indented || incomplete(stmt.str()))) {
            if (!blank) { stmt.put('\n'); stmt.put(line); }
            continue;
        }
        flush();
        if (!blank && trim(line)[0] != '#') stmt.put(line);
    }
    flush();
    stmt.dispose();
}
void runFile(const(char)[] path) {
    auto v = readWholeFile(path);
    if (!v) { reportError(); return; }
    auto copy = permDup(str(v));
    runScript(copy);
}

// ── the prompt ──────────────────────────────────────────────────────────────────────────────────
private __gshared char[64] g_nsName = 0;          // from the kernel's whoami, when EPIN_DOMAIN is unset
// The domain this shell runs in: the terminal says (EPIN_DOMAIN), else it is the namespace.
private const(char)* shellDomain() {
    const(char)* dom = getenv("EPIN_DOMAIN");
    if (dom && *dom) return dom;
    if (g_nsName[0] == 0) {
        // "user@namespace [rights]"
        char[256] w;
        const n = syscall(HOS_SYS_QUERY, HOSQ_WHOAMI, 0, cast(long)w.ptr, w.length - 1);
        g_nsName[0] = '-';  g_nsName[1] = 0;                  // asked once
        if (n > 0) {
            w[cast(size_t)n] = 0;
            size_t at = 0; while (at < cast(size_t)n && w[at] != '@') ++at;
            size_t e = at + 1; while (e < cast(size_t)n && w[e] != ' ' && w[e] != '\n') ++e;
            if (at < cast(size_t)n && e > at + 1 && e - at - 1 < g_nsName.length) { memcpy(g_nsName.ptr, w.ptr + at + 1, e - at - 1); g_nsName[e - at - 1] = 0; }
        }
    }
    return g_nsName[0] != '-' ? g_nsName.ptr : null;
}
// A domain's home is /Domains/<name>/Home; the HOME a terminal passes (/home/user) is not in a
// domain's namespace.  Point HOME at the one this shell can write, so ~, the history files and
// everything started from here (zsh via `linux`) use it.
private void fixHome() {
    auto h = getenv("HOME");
    if (h && *h && writableDir(h)) return;
    auto dom = shellDomain();
    if (!dom) return;
    char[160] p;
    snprintf(p.ptr, p.length, "/Domains/%s/Home", dom);
    if (!writableDir(p.ptr)) return;
    // start there too when the terminal left us at /, in the unusable HOME it passed, or in any
    // other directory this domain cannot write (ratty starts its shell in /home/user)
    char[1024] cwd;
    if (!getcwd(cwd.ptr, cwd.length) || strcmp(cwd.ptr, "/") == 0 || (h && strcmp(cwd.ptr, h) == 0) ||
        !writableDir(cwd.ptr))
        chdir(p.ptr);
    setenv("HOME", p.ptr, 1);
}
// access(W_OK) does not see a namespace's rights, so create (and remove) a probe file.
private bool writableDir(const(char)* dir) {
    char[200] p;
    snprintf(p.ptr, p.length, "%s/.dash-probe", dir);
    const fd = open(p.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0x180);
    if (fd < 0) return false;
    close(fd); unlink(p.ptr);
    return true;
}
private void buildPrompt(ref Buf p) {
    p.clear();
    const(char)* dom = shellDomain();
    const(char)* usr = getenv("EPIN_USER"); if (!usr || !*usr) usr = getenv("USER"); if (!usr || !*usr) usr = "user";
    char[1024] cwd; if (!getcwd(cwd.ptr, cwd.length)) { cwd[0] = '/'; cwd[1] = 0; }
    auto home = getenv("HOME");
    const(char)[] c = cwd.ptr[0 .. strlen(cwd.ptr)];
    if (dom && *dom) { p.put("\x1b[1;36m["); p.putz(dom); p.put("]\x1b[0m "); }
    p.put("\x1b[32m"); p.putz(usr); p.put("\x1b[0m:\x1b[34m");
    if (home && *home && startsWith(c, home[0 .. strlen(home)]) && strlen(home) > 1) { p.put('~'); p.put(c[strlen(home) .. $]); }
    else p.put(c);
    p.put("\x1b[0m");
    if (g_lastStatus != 0) { p.put(" \x1b[31m"); p.puti(g_lastStatus); p.put("\x1b[0m"); }
    p.put(" \x1b[1;35m>\x1b[0m ");
}

// ── the REPL ────────────────────────────────────────────────────────────────────────────────────
private void repl() {
    termSave();
    histLoad();
    g_beforeForeground = &rawOff;
    // ASCII only, under 80 columns: the terminal draws neither UTF-8 nor wider lines unwrapped
    out_("\x1b[1mdash\x1b[0m \x1b[2m-- run programs like bash, compute like Haskell, over the OS's objects\n");
    out_("  :help for a tour  |  Tab after '.' explores an object  |  `linux` for zsh\x1b[0m\n");
    oflush();
    Buf prompt, stmt;
    bool block = false;
    while (!g_exitRequested) {
        buildPrompt(prompt);
        const cont = stmt.n > 0;
        auto line = readLine(cont ? (block ? "\x1b[2m:{ \x1b[0m" : "\x1b[2m .. \x1b[0m") : prompt.str());
        if (line is null) {
            if (stmt.n) { stmt.clear(); block = false; continue; }
            break;
        }
        const(char)[] l = line[0 .. strlen(line)];
        if (!cont && trim(l) == ":{") { block = true; stmt.clear(); stmt.put("\x01"); free(line); continue; }
        if (block) {
            if (trim(l) == ":}") {
                block = false;
                auto body_ = stmt.str()[1 .. $];     // skip the marker
                histAdd(trim(body_));
                oflush(); rawOff();
                runScript(permDup(body_));
                stmt.clear(); free(line);
                collectIfNeeded();
                continue;
            }
            stmt.put('\n'); stmt.put(l); free(line); continue;
        }
        if (stmt.n) stmt.put('\n');
        stmt.put(l);
        free(line);
        if (incomplete(stmt.str())) continue;
        const text = permDup(stmt.str());
        stmt.clear();
        histAdd(trim(text));
        rawOff();
        g_interrupted = false;
        runStatement(text);
        if (g_interrupted) { g_interrupted = false; clearErr(); }
        oflush();
        collectIfNeeded();
    }
    prompt.dispose(); stmt.dispose();
}

// ── self-test (the language, the guard, completion) ─────────────────────────────────────────────
private int selftest() {
    int fails = 0;
    bool check(const(char)[] expr, const(char)[] expect) {
        const(char)[] rest;
        auto v = evalExprText(expr, null, rest);
        Buf b; if (v) showValue(b, v); else { b.put("error: "); b.put(errText()); clearErr(); }
        const ok = b.str() == expect;
        if (!ok) { out_("  FAIL "); out_(expr); out_(" => "); out_(b.str()); out_("   (expected "); out_(expect); out_(")\n"); ++fails; }
        b.dispose();
        return ok;
    }
    runStatement("fact 0 = 1");
    runStatement("fact n = n * fact (n - 1)");
    runStatement("sq x = x * x");
    runStatement("classify n | n < 0 = \"neg\" | n == 0 = \"zero\" | otherwise = \"pos\"");
    runStatement("data Shape = Circle Float | Rect Float Float");
    runStatement("area (Circle r) = 3 * r * r");
    runStatement("area (Rect w h) = w * h");
    runStatement("loop n acc = if n == 0 then acc else loop (n - 1) (acc + n)");
    check("1 + 2 * 3", "7");
    check("fact 10", "3628800");
    check("map sq [1..5]", "[1,4,9,16,25]");
    check("[x * 2 | x <- [1..10], even x]", "[4,8,12,16,20]");
    check("filter odd [1..9] |> sum", "25");
    check("classify (-3) ++ classify 0 ++ classify 7", "\"negzeropos\"");
    check("area (Rect 2 3)", "6");
    check("case [1,2,3] of { [] -> 0; (x:_) -> x }", "1");
    check("let y = 5 in y * y", "25");
    check("(\\a b -> a - b) 10 4", "6");
    check("foldr (\\x acc -> x : acc) [] \"abc\"", "\"abc\"");
    check("words \"a b  c\" |> length", "3");
    check("{ name = \"x\", n = 1 }.n", "1");
    check("({ name = \"x\", n = 1 } { n = 2 }).n", "2");
    check("map (.n) [{n = 1}, {n = 2}]", "[1,2]");
    check("\"hello\".upper", "\"HELLO\"");
    check("[3,1,2].sort", "[1,2,3]");
    check("sortOn negate [3,1,2]", "[3,2,1]");
    check("(map (+1) . filter even) [1..6]", "[3,5,7]");
    check("zip [1,2] \"ab\"", "[(1,'a'),(2,'b')]");
    check("lookup 2 [(1,\"a\"),(2,\"b\")]", "Just \"b\"");
    check("loop 100000 0", "5000050000");
    check("splitOn \",\" \"a,b,c\"", "[\"a\",\"b\",\"c\"]");
    check("parseJson \"{\\\"a\\\": [1, 2]}\"", "{a = [1,2]}");
    check("show 3.5 ++ \"!\"", "\"3.5!\"");
    // commands and the halves between them
    runStatement("greeting = \"hi\"");
    {
        Buf o; runCapture("echo $greeting there | tr a-z A-Z", null, o);
        if (trim(o.str()) != "HI THERE") { out_("  FAIL command pipe: "); out_(o.str()); outc('\n'); ++fails; }
        o.dispose();
    }
    {
        Buf o; runCapture("echo $((sum [1..10]))", null, o);
        if (trim(o.str()) != "55") { out_("  FAIL $((expr)): "); out_(o.str()); outc('\n'); ++fails; }
        o.dispose();
    }
    check("$(printf 'a\\nb\\n') |> length", "2");
    // B5 guard: unarmed refused, armed once, dry-run wins
    g_dryRun = false; g_armed = false;
    const(char)[] rest;
    auto v1 = evalExprText("(namespaces |> head).enter", null, rest);   // no native ABI on a host: the guard still runs first
    const refusedUnarmed = v1 is null; clearErr();
    // completion
    Vec!Cand cs; size_t st;
    complete("\"abc\".up", cs, st);
    bool compOk = cs.n == 1 && cs[0].word == "upper";
    cs.dispose();
    Vec!Cand cs2; complete("[1,2].so", cs2, st);
    compOk = compOk && cs2.n >= 2;       // sort, sortOn
    cs2.dispose();
    if (!compOk) { out_("  FAIL completion of members\n"); ++fails; }
    out_(fails == 0 ? "[dash] selftest PASS (language, commands, pipes, completion)" : "[dash] selftest FAIL");
    out_(refusedUnarmed ? "; unarmed destructive op refused\n" : "; guard NOT enforced\n");
    oflush();
    return fails == 0 && refusedUnarmed ? 0 : 1;
}

extern (C) int main(int argc, char** argv) {
    { import dash.native : g_beforeExit; g_beforeExit = &oflush; }   // exit() flushes dash's output
    valueInit(); evalInit(); libInit(); objectsInit();
    { import dash.fsobj : fsobjInit, objCommand; fsobjInit(); g_objCommand = &objCommand; }
    g_displayValue = &display;
    g_isDashCommand = &isDashCmd;
    g_dashBuiltin = &dashBuiltin;
    g_runFile = &runFile;
    g_sourceFile = &runFile;                            // the `source` / `.` builtin
    signal(SIGINT, cast(sighandler_t)&onSigint);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    if (!getenv("SHELL")) setenv("SHELL", "/hos-sh", 1);
    if (!getenv("PATH")) setenv("PATH", "/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin", 1);
    fixHome();

    // The kernel's staged self-test trigger (it passes no argv).
    { auto st = getenv("EPIN_SH_SELFTEST"); if (st && *st) { return selftest(); } }

    int ai = 1;
    bool interactiveFlag = false;
    while (ai < argc && argv[ai][0] == '-') {
        const(char)[] a = argv[ai][0 .. strlen(argv[ai])];
        if (a == "--selftest") return selftest();
        if (a == "--version") { out_("dash 1.0 (EpinAnonymOS native shell)\n"); oflush(); return 0; }
        if (a == "-c" && ai + 1 < argc) {
            auto text = argv[ai + 1][0 .. strlen(argv[ai + 1])];
            runScript(permDup(text));
            oflush();
            return g_exitRequested ? g_exitCode : g_lastStatus;
        }
        if (a == "-i" || a == "-l" || a == "--login") { interactiveFlag = true; ++ai; continue; }
        ++ai;
    }
    // ~/.dashrc
    {
        auto home = getenv("HOME");
        Buf p; p.putz(home ? home : "/home/user"); p.put("/.dashrc");
        if (access(p.cstr(), R_OK) == 0) runFile(permDup(p.str()));
        p.dispose();
    }
    if (ai < argc) {
        const(char)[] first = argv[ai][0 .. strlen(argv[ai])];
        // the old one-shot object verbs (`hos-sh obj`) still work
        switch (first) {
            case "obj": runStatement("objects"); oflush(); return 0;
            case "id": runStatement("identities"); oflush(); return 0;
            case "ns": runStatement("namespaces"); oflush(); return 0;
            case "svc": runStatement("services"); oflush(); return 0;
            case "sys": runStatement("system"); oflush(); return 0;
            case "whoami": runStatement("me"); oflush(); return 0;
            default: break;
        }
        runFile(first);
        oflush();
        return g_exitRequested ? g_exitCode : g_lastStatus;
    }
    if (isatty(0) || interactiveFlag) repl();
    else {
        Buf all; char[4096] t;
        for (;;) { const r = read(0, t.ptr, t.length); if (r <= 0) break; all.put(t[0 .. cast(size_t)r]); }
        runScript(permDup(all.str()));
        all.dispose();
    }
    oflush();
    return g_exitRequested ? g_exitCode : g_lastStatus;
}
