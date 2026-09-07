// ─────────────────────────────────────────────────────────────────────────────
// hos-sh — the native EpinAnonymOS object shell (-sh / dash)
// SHELL_AND_COMMANDS_ROADMAP Track B1/B3.
//
// Written in D (-betterC), the same language as the microkernel, and driving the
// kernel's OWN object model through the native syscall ABI (HOS_SYS_QUERY = 0x4000)
// rather than the Linux-compat layer.  This is the "actual OS shell" the Domain
// Manager offers as the Native option — it inspects objects, identity domains,
// namespaces and services that busybox cannot see.
//
// Built with ldc2 -betterC and linked against musl for crt0 + stdio (printf/fgets);
// the object commands go straight to the kernel via syscall().
// ─────────────────────────────────────────────────────────────────────────────
module hos_sh;

extern(C) @nogc nothrow {
    long   syscall(long n, long a, long b, long c, long d);
    int    printf(const(char)* fmt, ...);
    char*  fgets(char* s, int size, void* stream);
    size_t fwrite(const(void)* ptr, size_t sz, size_t n, void* stream);
    int    fflush(void* stream);
    size_t strlen(const(char)* s);
    int    strcmp(const(char)* a, const(char)* b);
    int    strncmp(const(char)* a, const(char)* b, size_t n);
    char*  getcwd(char* buf, size_t size);
    int    chdir(const(char)* path);
    int    pipe(int* fds);   // Z4b.4: a §8 channel for the object_send/recv self-test
    extern __gshared void* stdin;
    extern __gshared void* stdout;
}

enum long HOS_SYS_QUERY = 0x4000;
enum long HOSQ_OBJECTS    = 1;
enum long HOSQ_IDENTITIES = 2;
enum long HOSQ_NAMESPACES = 3;
enum long HOSQ_SERVICES   = 4;
enum long HOSQ_SYS        = 5;
enum long HOSQ_WHOAMI     = 6;
enum long HOSQ_OPEN       = 7;   // Z4a: object_open(path, rights) -> handle
enum long HOSQ_READ       = 8;   // object_read(handle, buf, len)  -> bytes
enum long HOSQ_CLOSE      = 10;  // object_close(handle)           -> 0
enum long HOSQ_SUBSCRIBE  = 17;  // Z4b.3: object_subscribe(events) -> 0
enum long HOSQ_SEND       = 18;  // Z4b.4: object_send(chan_fd, src, n) -> bytes
enum long HOSQ_RECV       = 19;  // Z4b.4: object_recv(chan_fd, dst, n) -> bytes
enum long HOSQ_CAP_GRANT  = 20;  // Z4c.3: cap_grant(srcHandle, wantRights) -> newHandle/-errno
enum long HOSQ_NS_CLONE   = 21;  // Z4c.3: namespace_clone() -> nsObjId/-errno
enum long HOSQ_NS_ENTER   = 22;  // Z4c.3: namespace_enter(nsObjId) -> 0/-errno
enum long HOSQ_ID_SWITCH  = 23;  // L4.2: identity_switch(name) -> 0/-errno (de-escalation only)
enum long CAP_RIGHT_READ_V = 1;  // CAP_RIGHT_READ = bit 0
enum long SIG_CHLD_BIT = 1 << 17, SIG_INT_BIT = 1 << 2;  // §6 event bits (SIGCHLD / SIGINT)

__gshared char[8192] g_buf;
__gshared char[128]  g_who;   // "user@namespace" (cached)
__gshared char[256]  g_cwd;

// ── SHELL_AND_COMMANDS B5 — destructive-operation guard ──────────────────────────────────────
//
// ns-enter, cap-grant, cap-derive and identity-switch CHANGE the caller's security context:
// they move a process between namespaces, mint an attenuated capability, or drop it into another
// identity.  They used to fire the moment the form was evaluated, so a typo in a REPL over the
// object model was indistinguishable from an intention.
//
// Two guards, and they answer different questions:
//   --dry-run  "what WOULD this do" -- reports the verb and its arguments, calls nothing.
//   --yes      "I meant it" -- without it a destructive verb is REFUSED, not merely warned about.
//
// ARMING IS ONE-SHOT.  `--yes` authorises the next destructive verb and is consumed by it, so a
// script that arms once cannot silently authorise a second operation it never mentioned.  That is
// the difference between confirming an action and switching the safety off.
//
// Dry-run takes precedence over armed: if a caller passes both, nothing executes.  A caller who
// asked what would happen gets an answer, not an action.
__gshared int g_dryRun = 0;
__gshared int g_armed  = 0;
__gshared long g_lastGuardVerdict = 0;   // 0 = executed, 1 = dry-run, 2 = refused

// Returns true if the caller may proceed.  Prints the reason when it says no, because a silent
// refusal in a shell reads as a bug in the shell.
bool guardDestructive(const(char)* verb, long a, long b) @nogc nothrow {
    if (g_dryRun) {
        printf("dry-run: %s(%ld, %ld) -- not executed\n", verb, a, b);
        g_lastGuardVerdict = 1;
        return false;
    }
    if (!g_armed) {
        printf("refused: %s is destructive; re-run with --yes (or `arm`) to authorise it\n", verb);
        g_lastGuardVerdict = 2;
        return false;
    }
    g_armed = 0;               // one-shot: consumed by this operation
    g_lastGuardVerdict = 0;
    return true;
}

// B5 completion.  The data source is the SAME query the user would run, so completion cannot drift
// from reality: it lists what `id` / `ns` / `svc` actually report, filtered by prefix.  Returns the
// number of matches, so a caller (and the self-test) can act on it without parsing stdout.
int completeNames(long op, const(char)* prefix, int printThem) @nogc nothrow {
    const long n = syscall(HOS_SYS_QUERY, op, 0, cast(long)g_buf.ptr, cast(long)(g_buf.length - 1));
    if (n <= 0) return 0;
    g_buf[cast(size_t)n] = 0;
    size_t plen = 0; while (prefix !is null && prefix[plen] != 0) ++plen;
    int hits = 0;
    size_t i = 0;
    while (i < cast(size_t)n) {
        // Each line's first whitespace-delimited token is the name.
        size_t st = i;
        while (i < cast(size_t)n && g_buf[i] != '\n') ++i;
        size_t end = i;
        if (i < cast(size_t)n) ++i;
        while (st < end && (g_buf[st] == ' ' || g_buf[st] == '\t')) ++st;
        size_t tok = st;
        while (tok < end && g_buf[tok] != ' ' && g_buf[tok] != '\t') ++tok;
        if (tok == st) continue;
        bool match = true;
        for (size_t k = 0; k < plen; ++k) {
            if (st + k >= tok || g_buf[st + k] != prefix[k]) { match = false; break; }
        }
        if (!match) continue;
        ++hits;
        if (printThem) { fwrite(&g_buf[st], 1, tok - st, stdout); printf("\n"); }
    }
    if (printThem) fflush(stdout);
    return hits;
}

// Run a native object-model query and print its text result.

void runQuery(long op, const(char)* header) @nogc nothrow {
    const long n = syscall(HOS_SYS_QUERY, op, 0, cast(long)g_buf.ptr, cast(long)(g_buf.length - 1));
    if (n < 0) { printf("hos-sh: native query failed (errno %ld)\n", -n); return; }
    if (header !is null) printf("%s", header);
    if (n == 0) { printf("  (none)\n"); return; }
    fwrite(g_buf.ptr, 1, cast(size_t)n, stdout);
    fflush(stdout);
}

// B5 `man` — the per-topic detail `help` deliberately does not carry.  help() is a one-screen
// reminder; man answers "what does this verb actually do to my process".
void manPage(const(char)* cmd) @nogc nothrow {
    const(char)* t = cmd + 3; while (*t == ' ') ++t;
    if (*t == 0) {
        printf("man <topic>.  Topics: destructive, complete, identity, namespace, cap\n");
        return;
    }
    if (strncmp(t, "destructive".ptr, 11) == 0) {
        printf("DESTRUCTIVE VERBS — ns-enter, cap-grant, cap-derive, identity-switch\n");
        printf("  These change the CALLING process's security context: they move it between\n");
        printf("  namespaces, mint an attenuated capability, or drop it into another identity.\n");
        printf("  They are refused unless armed.\n\n");
        printf("    arm            authorise the NEXT destructive verb (one-shot, consumed by it)\n");
        printf("    dry-run        report what a destructive verb WOULD do and execute nothing\n\n");
        printf("  dry-run wins over arm: asking what would happen never performs it.\n");
        printf("  Every one of these is audited by the kernel whether it succeeds or is refused\n");
        printf("  (AuditKind.NativeVerbOk / NativeVerbDeny).\n");
    } else if (strncmp(t, "complete".ptr, 8) == 0) {
        printf("complete <prefix> — names matching <prefix> across identities, namespaces and\n");
        printf("  services.  The source is the same query `id` / `ns` / `svc` print, so a\n");
        printf("  completion cannot offer a name the object model does not actually have.\n");
    } else if (strncmp(t, "identity".ptr, 8) == 0) {
        printf("identity — (identity) => #(user ns caps).  (identity-switch \"Name\") is\n");
        printf("  DE-ESCALATION ONLY: the kernel refuses a switch that would gain rights.\n");
    } else if (strncmp(t, "namespace".ptr, 9) == 0) {
        printf("namespace — (ns-clone) copies the caller's namespace and returns its id;\n");
        printf("  (ns-enter id) enters one the caller OWNS.  Entering another task's is refused.\n");
    } else if (strncmp(t, "cap".ptr, 3) == 0) {
        printf("cap — (cap-grant h rights) mints an ATTENUATED handle: rights are intersected\n");
        printf("  with what the source holds, so a derive can never widen authority.\n");
    } else {
        printf("man: no such topic '%s'\n", t);
    }
}

// B5 self-test.  Runs headlessly (`hos-sh --selftest`) because the alternative is a human typing
// into a terminal, and a guard nobody can test is a guard nobody should trust.  It checks the
// REFUSAL paths, which are the ones that matter: a destructive verb must not fire unarmed, and
// dry-run must not fire even when armed.
int b5SelfTest() @nogc nothrow {
    int pass = 1;

    // 1. Unarmed destructive verb is REFUSED (verdict 2) and does not call the kernel.
    g_dryRun = 0; g_armed = 0;
    const bool r1 = guardDestructive("ns-enter".ptr, 1, 0);
    if (r1 || g_lastGuardVerdict != 2) pass = 0;

    // 2. Armed -> permitted (verdict 0), and the arm is CONSUMED.
    g_armed = 1;
    const bool r2 = guardDestructive("ns-enter".ptr, 1, 0);
    const bool r3 = guardDestructive("ns-enter".ptr, 1, 0);   // second call: no longer armed
    if (!r2 || g_lastGuardVerdict != 2 || r3) pass = 0;

    // 3. dry-run beats armed: asking what would happen must never perform it.
    g_dryRun = 1; g_armed = 1;
    const bool r4 = guardDestructive("cap-grant".ptr, 7, 1);
    if (r4 || g_lastGuardVerdict != 1) pass = 0;
    g_dryRun = 0; g_armed = 0;

    // 4. Completion returns real names: "Sys" must match the System identity, and a prefix that
    //    cannot exist must match nothing.  Both directions, so a stub that always returns 0 or
    //    always returns 1 fails.
    const int cHit  = completeNames(HOSQ_IDENTITIES, "Sys".ptr, 0);
    const int cMiss = completeNames(HOSQ_IDENTITIES, "zzzznope".ptr, 0);
    if (cHit < 1 || cMiss != 0) pass = 0;

    printf("[4.5] B5: unarmed-refused=%d armed-once=%d dryrun-wins=%d complete(hit=%d,miss=%d) -- %s\n",
           (!r1 && g_lastGuardVerdict != 0) ? 1 : 0,
           (r2 && !r3) ? 1 : 0,
           (!r4) ? 1 : 0,
           cHit, cMiss,
           pass ? "B5 PASS".ptr : "B5 FAIL".ptr);
    fflush(stdout);
    return 0;
}

void help() @nogc nothrow {

    printf("-sh — a Lisp (LFE) over the object model.  Forms evaluate to data:\n");
    printf("  values   1   \"str\"   foo   (list 1 2 3)   (tuple 1 2)   ()   true / false\n");
    printf("  define   (defun sq (x) (* x x))     then  (sq 9) => 81   (recursion ok)\n");
    printf("  lambda   ((lambda (x) (+ x 1)) 41) => 42\n");
    printf("  let      (let ((a 3) (b 4)) (+ (* a a) (* b b))) => 25\n");
    printf("  if/case  (if (> n 0) (quote pos) (quote neg))\n");
    printf("           (case (ns-clone) (0 (quote fail)) (n (ns-enter n)))   ; pattern match + (when g)\n");
    printf("  lists    (car L) (cdr L) (cons h t) (length L) (++ a b)   tuples (element i T)\n");
    printf("  arith    (+ - * /)    compare (== /= < > >= =<)\n");
    printf("  objects  (obj) (id) (ns) (svc) (sys) (whoami)    (ns-clone) (ns-enter id) (cap-grant h r)\n");
    printf("  security (identity)=>#(user ns caps)  (namespace)  (caps)  (cap-derive h r)  (identity-switch \"Name\")\n");
    printf("  safety   arm | dry-run | complete <prefix> | man <topic>   (destructive verbs need `arm`)\n");
    printf("  shell    (cat \"/p\")  (cd \"/p\")  (print x)  (reset)  (exit)\n");
}

// ── L3: a real LFE (Lisp-Flavored Erlang) interpreter ───────────────────────────────────────
// L2 evaluated forms to a flat value; L3 makes the native shell a *programmable Lisp over the
// object model*: a cell-based value model (ints, atoms, strings, cons lists, tuples, closures),
// lexical environments, `defun`/`lambda`/`let`, `if`/`case` with pattern matching + guards,
// recursion, and the object-ABI verbs as ordinary functions whose results are first-class data.
// Ported from the upstream `-sh` model (deps/lfe-sh, vendored L1) into betterC: fixed grow-only
// arenas (AST nodes / interned strings / value cells), no GC — `(reset)` clears a session.
// (Macros + list comprehensions: remaining L3 polish.)

enum SK : ubyte { Num, Sym, Str, List }
struct Node { SK kind; int aoff; int len; long num; int head; int next; }
__gshared Node[4096]   g_nodes;     // AST — persistent across REPL lines (defun bodies live here)
__gshared int          g_nnodes;
__gshared char[16384]  g_strarena;  // interned atom/string text — persistent
__gshared int          g_strn;
__gshared const(char)* g_src;       // current line being parsed
__gshared int          g_pos;
__gshared int          g_exitReq;
__gshared int          g_resetReq;

enum CT : ubyte { Nil, Int, Atom, Str, Cons, Tuple, Fun, Err }
struct Cell { CT t; long i; int s; int n; int a; int d; }
//  Int: i.  Atom/Str: s=arena off, n=len.  Cons: a=car cell, d=cdr cell.
//  Tuple: a=elements (a cons-list cell), i=count.  Fun: a=params NODE, d=body NODE, i=env cell.
__gshared Cell[8192] g_cells;
__gshared int g_ncells;
__gshared int g_globalEnv;          // top-level env: a cons-list of (name . val) bindings
__gshared bool g_inited;
__gshared int g_trueCell, g_falseCell;
enum int NIL = 0;                   // cell 0 is the canonical Nil

int allocCell(CT t) @nogc nothrow {
    if (g_ncells >= cast(int)g_cells.length) return NIL;            // soft OOM -> Nil
    const int c = g_ncells++;
    g_cells[c].t=t; g_cells[c].i=0; g_cells[c].s=0; g_cells[c].n=0; g_cells[c].a=0; g_cells[c].d=0;
    return c;
}
int mkInt(long x) @nogc nothrow { const int c=allocCell(CT.Int); g_cells[c].i=x; return c; }
int mkAtom(int off, int len) @nogc nothrow { const int c=allocCell(CT.Atom); g_cells[c].s=off; g_cells[c].n=len; return c; }
int mkStr(int off, int len) @nogc nothrow { const int c=allocCell(CT.Str); g_cells[c].s=off; g_cells[c].n=len; return c; }
int mkCons(int car, int cdr) @nogc nothrow { const int c=allocCell(CT.Cons); g_cells[c].a=car; g_cells[c].d=cdr; return c; }
int mkFun(int params, int body, int env) @nogc nothrow { const int c=allocCell(CT.Fun); g_cells[c].a=params; g_cells[c].d=body; g_cells[c].i=env; return c; }

int internRange(const(char)* s, int len) @nogc nothrow {
    if (g_strn + len > cast(int)g_strarena.length) return 0;
    const int off = g_strn;
    for (int k=0; k<len; ++k) g_strarena[off+k]=s[k];
    g_strn += len;
    return off;
}
int internLit(string lit) @nogc nothrow { return internRange(lit.ptr, cast(int)lit.length); }

void ensureInit() @nogc nothrow {
    if (g_inited) return;
    g_inited = true;
    g_ncells = 0; g_strn = 0; g_nnodes = 0;
    allocCell(CT.Nil);                                     // cell 0 == NIL
    g_trueCell  = mkAtom(internLit("true"), 4);
    g_falseCell = mkAtom(internLit("false"), 5);
    g_globalEnv = NIL;
}

bool symEqA(int off, int len, string lit) @nogc nothrow {
    if (len != cast(int)lit.length) return false;
    for (int k=0; k<len; ++k) if (g_strarena[off+k] != lit[k]) return false;
    return true;
}
bool arenaEq(int o1, int o2, int len) @nogc nothrow {
    for (int k=0; k<len; ++k) if (g_strarena[o1+k] != g_strarena[o2+k]) return false;
    return true;
}
bool isNumTok(const(char)* s, int n) @nogc nothrow {
    if (n==0) return false;
    int i=0; if (s[0]=='-') { if (n==1) return false; i=1; }
    for (; i<n; ++i) if (s[i]<'0' || s[i]>'9') return false;
    return true;
}
long toLong(const(char)* s, int n) @nogc nothrow {
    int i=0; long sign=1; if (s[0]=='-') { sign=-1; i=1; }
    long v=0; for (; i<n; ++i) v = v*10 + (s[i]-'0'); return v*sign;
}

// ── parser: s-expression text -> AST nodes (strings interned into the arena) ────────────────
void pskip() @nogc nothrow { while (g_src[g_pos]==' ' || g_src[g_pos]=='\t') ++g_pos; }
int allocNode(SK k) @nogc nothrow {
    if (g_nnodes >= cast(int)g_nodes.length) return -1;
    const int n=g_nnodes++;
    g_nodes[n].kind=k; g_nodes[n].aoff=0; g_nodes[n].len=0; g_nodes[n].num=0; g_nodes[n].head=-1; g_nodes[n].next=-1;
    return n;
}
int parseExpr() @nogc nothrow {
    pskip();
    const char c = g_src[g_pos];
    if (c==0) return -1;
    if (c=='\'') { ++g_pos; return parseQuoteSugar(); }  // 'x  ->  (quote x)
    if (c=='(') { ++g_pos; return parseList(); }
    if (c=='"') return parseStr();
    return parseAtom();
}
int parseQuoteSugar() @nogc nothrow {
    const int lst = allocNode(SK.List); if (lst<0) return -1;
    const int q = allocNode(SK.Sym); if (q<0) return -1;
    g_nodes[q].aoff = internLit("quote"); g_nodes[q].len = 5;
    const int inner = parseExpr();
    g_nodes[lst].head = q; g_nodes[q].next = inner;
    return lst;
}
int parseList() @nogc nothrow {
    const int n = allocNode(SK.List); if (n<0) return -1;
    int last=-1;
    for (;;) {
        pskip();
        const char c=g_src[g_pos];
        if (c==0) break;
        if (c==')') { ++g_pos; break; }
        const int ch=parseExpr(); if (ch<0) break;
        if (last<0) g_nodes[n].head=ch; else g_nodes[last].next=ch;
        last=ch;
    }
    return n;
}
int parseStr() @nogc nothrow {
    ++g_pos; const int start=g_pos;
    while (g_src[g_pos]!=0 && g_src[g_pos]!='"') ++g_pos;
    const int n=allocNode(SK.Str); if (n<0) return -1;
    g_nodes[n].aoff=internRange(g_src+start, g_pos-start); g_nodes[n].len=g_pos-start;
    if (g_src[g_pos]=='"') ++g_pos;
    return n;
}
int parseAtom() @nogc nothrow {
    const int start=g_pos;
    while (g_src[g_pos]!=0) { const char c=g_src[g_pos]; if (c==' '||c=='\t'||c=='('||c==')') break; ++g_pos; }
    const int len=g_pos-start;
    const bool num = isNumTok(g_src+start, len);
    const int n=allocNode(num?SK.Num:SK.Sym); if (n<0) return -1;
    if (num) g_nodes[n].num=toLong(g_src+start, len);
    else { g_nodes[n].aoff=internRange(g_src+start, len); g_nodes[n].len=len; }
    return n;
}

// ── environment: a cons-list of (name . value) bindings, with a global fallback ─────────────
int envExtend(int env, int nameAtom, int val) @nogc nothrow { return mkCons(mkCons(nameAtom, val), env); }
int envLookup(int env, int off, int len) @nogc nothrow {
    int e=env;
    while (e!=NIL && g_cells[e].t==CT.Cons) {
        const int b=g_cells[e].a, nm=g_cells[b].a;
        if (g_cells[nm].t==CT.Atom && g_cells[nm].n==len && arenaEq(g_cells[nm].s, off, len)) return g_cells[b].d;
        e=g_cells[e].d;
    }
    return -1;
}

bool truthy(int c) @nogc nothrow {
    if (c==NIL) return false;
    if (g_cells[c].t==CT.Int) return g_cells[c].i != 0;
    if (g_cells[c].t==CT.Atom) return !(g_cells[c].n==5 && symEqA(g_cells[c].s,5,"false"));
    return true;
}
int boolCell(bool b) @nogc nothrow { return b ? g_trueCell : g_falseCell; }
long asInt(int c) @nogc nothrow { return (g_cells[c].t==CT.Int) ? g_cells[c].i : 0; }
bool valEq(int x, int y) @nogc nothrow {
    if (g_cells[x].t != g_cells[y].t) return false;
    final switch (g_cells[x].t) {
        case CT.Nil:  return true;
        case CT.Int:  return g_cells[x].i == g_cells[y].i;
        case CT.Atom: case CT.Str:
            return g_cells[x].n==g_cells[y].n && arenaEq(g_cells[x].s, g_cells[y].s, g_cells[x].n);
        case CT.Cons: return x==y;
        case CT.Tuple: case CT.Fun: case CT.Err: return x==y;
    }
}
__gshared char[256] g_argbuf;
const(char)* cstrCell(int c) @nogc nothrow {
    int n = (g_cells[c].t==CT.Str || g_cells[c].t==CT.Atom) ? g_cells[c].n : 0;
    if (n > cast(int)g_argbuf.length-1) n = cast(int)g_argbuf.length-1;
    for (int k=0; k<n; ++k) g_argbuf[k]=g_strarena[g_cells[c].s+k];
    g_argbuf[n]=0; return g_argbuf.ptr;
}
int whoCell() @nogc nothrow { const int l=cast(int)strlen(g_who.ptr); return mkStr(internRange(g_who.ptr, l), l); }

// L4.1 — the security model as LFE data.  The i-th element of a tuple (1-based).
int tupleElem(int t, long ix) @nogc nothrow {
    if (g_cells[t].t != CT.Tuple) return NIL;
    int e=g_cells[t].a; long k=1;
    while (e!=NIL && g_cells[e].t==CT.Cons) { if (k==ix) return g_cells[e].a; ++k; e=g_cells[e].d; }
    return NIL;
}
// Parse the kernel whoami line "user@namespace [perms]" into a #(user namespace caps) tuple
// (user/namespace atoms, caps a list of atoms).  Re-queried each call so it reflects (identity-switch).
int buildIdentity() @nogc nothrow {
    loadWho();
    const(char)* w = g_who.ptr; const int len = cast(int)strlen(w);
    int at=-1, br=-1, brEnd=-1;
    for (int i=0;i<len;++i){ const char c=w[i]; if(c=='@'&&at<0) at=i; else if(c=='['&&br<0) br=i; else if(c==']') brEnd=i; }
    const int uEnd=(at>=0)?at:len;
    const int uAtom = mkAtom(internRange(w, uEnd), uEnd);
    const int nsStart=(at>=0)?at+1:0; int nsEnd=nsStart;
    while (nsEnd<len && w[nsEnd]!=' ' && w[nsEnd]!='[') ++nsEnd;
    const int nsAtom = mkAtom(internRange(w+nsStart, nsEnd-nsStart), nsEnd-nsStart);
    int caps=NIL, last=NIL;
    if (br>=0 && brEnd>br) { int p=br+1;
        while (p<brEnd) { while (p<brEnd && w[p]==' ') ++p; const int s=p; while (p<brEnd && w[p]!=' ') ++p;
            if (p>s) { const int cc=mkCons(mkAtom(internRange(w+s,p-s), p-s), NIL);
                if (caps==NIL) caps=cc; else g_cells[last].d=cc; last=cc; } } }
    const int t = allocCell(CT.Tuple);
    g_cells[t].a = mkCons(uAtom, mkCons(nsAtom, mkCons(caps, NIL))); g_cells[t].i = 3;
    return t;
}

// ── evaluator ───────────────────────────────────────────────────────────────────────────────
int eval(int nd, int env) @nogc nothrow {
    if (nd < 0) return NIL;
    final switch (g_nodes[nd].kind) {
        case SK.Num: return mkInt(g_nodes[nd].num);
        case SK.Str: return mkStr(g_nodes[nd].aoff, g_nodes[nd].len);
        case SK.Sym: {
            int v = envLookup(env, g_nodes[nd].aoff, g_nodes[nd].len);
            if (v < 0 && env != g_globalEnv) v = envLookup(g_globalEnv, g_nodes[nd].aoff, g_nodes[nd].len);
            return (v >= 0) ? v : mkAtom(g_nodes[nd].aoff, g_nodes[nd].len);   // unbound symbol -> atom
        }
        case SK.List: return evalList(nd, env);
    }
}

int applyFun(int fn, int firstArg, int callerEnv) @nogc nothrow {
    const int paramsNode = g_cells[fn].a;
    const int bodyNode   = g_cells[fn].d;
    int newEnv = cast(int)g_cells[fn].i;                  // captured env
    int p = (paramsNode>=0) ? g_nodes[paramsNode].head : -1;
    int arg = firstArg;
    while (p>=0) {
        const int av = (arg>=0) ? eval(arg, callerEnv) : NIL;
        newEnv = envExtend(newEnv, mkAtom(g_nodes[p].aoff, g_nodes[p].len), av);
        p = g_nodes[p].next;
        arg = (arg>=0) ? g_nodes[arg].next : -1;
    }
    return eval(bodyNode, newEnv);
}

// pattern match: returns the extended env on success, -1 on mismatch
int matchPat(int pn, int val, int env) @nogc nothrow {
    final switch (g_nodes[pn].kind) {
        case SK.Num: return (g_cells[val].t==CT.Int && g_cells[val].i==g_nodes[pn].num) ? env : -1;
        case SK.Str: return (g_cells[val].t==CT.Str && g_cells[val].n==g_nodes[pn].len
                             && arenaEq(g_cells[val].s, g_nodes[pn].aoff, g_nodes[pn].len)) ? env : -1;
        case SK.Sym:
            if (g_nodes[pn].len==1 && g_strarena[g_nodes[pn].aoff]=='_') return env;   // wildcard
            return envExtend(env, mkAtom(g_nodes[pn].aoff, g_nodes[pn].len), val);     // variable -> bind
        case SK.List: {
            const int head=g_nodes[pn].head;
            if (head<0) return (val==NIL) ? env : -1;
            if (g_nodes[head].kind==SK.Sym) {
                const int ho=g_nodes[head].aoff, hl=g_nodes[head].len, a0=g_nodes[head].next;
                if (symEqA(ho,hl,"quote"))                  // (quote atom) -> match an atom literal
                    return (g_cells[val].t==CT.Atom && g_cells[val].n==g_nodes[a0].len
                            && arenaEq(g_cells[val].s, g_nodes[a0].aoff, g_nodes[a0].len)) ? env : -1;
                if (symEqA(ho,hl,"tuple")) { if (g_cells[val].t!=CT.Tuple) return -1; return matchSeq(a0, g_cells[val].a, env); }
                if (symEqA(ho,hl,"list"))  { if (!(val==NIL || g_cells[val].t==CT.Cons)) return -1; return matchSeq(a0, val, env); }
                if (symEqA(ho,hl,"cons"))  { if (g_cells[val].t!=CT.Cons) return -1;
                    const int e=matchPat(a0, g_cells[val].a, env); if (e<0) return -1;
                    return matchPat(g_nodes[a0].next, g_cells[val].d, e); }
            }
            return -1;
        }
    }
}
int matchSeq(int pn, int vcell, int env) @nogc nothrow {
    int p=pn, v=vcell, e=env;
    while (p>=0) {
        if (v==NIL || g_cells[v].t!=CT.Cons) return -1;
        e = matchPat(p, g_cells[v].a, e); if (e<0) return -1;
        p=g_nodes[p].next; v=g_cells[v].d;
    }
    return (v==NIL) ? e : -1;
}

int evalLet(int a0, int env) @nogc nothrow {
    int newEnv = env;
    int b = (a0>=0) ? g_nodes[a0].head : -1;
    while (b>=0) {
        const int nameNode = g_nodes[b].head;
        const int valNode  = (nameNode>=0) ? g_nodes[nameNode].next : -1;
        newEnv = envExtend(newEnv, mkAtom(g_nodes[nameNode].aoff, g_nodes[nameNode].len), eval(valNode, env));
        b = g_nodes[b].next;
    }
    int body = (a0>=0) ? g_nodes[a0].next : -1;
    int r=NIL; while (body>=0) { r=eval(body, newEnv); body=g_nodes[body].next; }
    return r;
}
int evalCase(int a0, int env) @nogc nothrow {
    if (a0 < 0) return NIL;                                        // malformed (case ...)
    const int val = eval(a0, env);
    int clause = g_nodes[a0].next;
    while (clause>=0) {
        const int pat = g_nodes[clause].head;
        if (pat>=0) {
            const int e = matchPat(pat, val, env);
            if (e>=0) {
                int body = g_nodes[pat].next;
                if (body>=0 && g_nodes[body].kind==SK.List) {       // optional (when guard)
                    const int gh = g_nodes[body].head;
                    if (gh>=0 && g_nodes[gh].kind==SK.Sym && symEqA(g_nodes[gh].aoff, g_nodes[gh].len, "when")) {
                        if (!truthy(eval(g_nodes[gh].next, e))) { clause=g_nodes[clause].next; continue; }
                        body = g_nodes[body].next;
                    }
                }
                int r=NIL; while (body>=0) { r=eval(body, e); body=g_nodes[body].next; }
                return r;
            }
        }
        clause = g_nodes[clause].next;
    }
    return NIL;
}
int buildList(int firstArg, int env) @nogc nothrow {       // (list a b c) -> a cons-list of eval'd args
    if (firstArg<0) return NIL;
    const int hd = eval(firstArg, env);
    return mkCons(hd, buildList(g_nodes[firstArg].next, env));
}
int evalList(int nd, int env) @nogc nothrow {
    const int head = g_nodes[nd].head;
    if (head < 0) return NIL;                                          // ()
    if (g_nodes[head].kind == SK.Sym) {
        const int ho=g_nodes[head].aoff, hl=g_nodes[head].len, a0=g_nodes[head].next;
        const int a1=(a0>=0)?g_nodes[a0].next:-1;

        // special forms (control evaluation of arguments)
        if (symEqA(ho,hl,"quote")) return quoteNode(a0);
        if (symEqA(ho,hl,"if")) return truthy(eval(a0,env)) ? eval(a1,env) : eval((a1>=0)?g_nodes[a1].next:-1, env);
        if (symEqA(ho,hl,"progn")||symEqA(ho,hl,"begin")) { int r=NIL,ai=a0; while(ai>=0){r=eval(ai,env);ai=g_nodes[ai].next;} return r; }
        if (symEqA(ho,hl,"let")) return evalLet(a0, env);
        if (symEqA(ho,hl,"lambda")) return mkFun(a0, a1, env);
        if (symEqA(ho,hl,"defun")) {
            if (a0<0 || a1<0) return NIL;                          // malformed (defun ...)
            const int fn = mkFun(a1, (a1>=0)?g_nodes[a1].next:-1, g_globalEnv);
            const int nameAtom = mkAtom(g_nodes[a0].aoff, g_nodes[a0].len);
            g_globalEnv = envExtend(g_globalEnv, nameAtom, fn);
            return nameAtom;
        }
        if (symEqA(ho,hl,"case")) return evalCase(a0, env);
        if (symEqA(ho,hl,"reset")) { g_resetReq=1; return NIL; }
        if (symEqA(ho,hl,"exit")||symEqA(ho,hl,"quit")) { g_exitReq=1; return NIL; }

        // arithmetic (variadic; args evaluate first -> forms nest/compose)
        if (hl==1 && (g_strarena[ho]=='+'||g_strarena[ho]=='-'||g_strarena[ho]=='*'||g_strarena[ho]=='/')) {
            const char op=g_strarena[ho]; int ai=a0; if (ai<0) return mkInt(0);
            long acc=asInt(eval(ai,env)); ai=g_nodes[ai].next;
            while (ai>=0) { const long v=asInt(eval(ai,env));
                if (op=='+') acc+=v; else if (op=='-') acc-=v; else if (op=='*') acc*=v; else acc = v ? acc/v : 0;
                ai=g_nodes[ai].next; }
            return mkInt(acc);
        }
        // comparison -> a boolean atom
        if (symEqA(ho,hl,"==")) return boolCell(valEq(eval(a0,env), eval(a1,env)));
        if (symEqA(ho,hl,"/=")) return boolCell(!valEq(eval(a0,env), eval(a1,env)));
        if (symEqA(ho,hl,"<"))  return boolCell(asInt(eval(a0,env)) <  asInt(eval(a1,env)));
        if (symEqA(ho,hl,">"))  return boolCell(asInt(eval(a0,env)) >  asInt(eval(a1,env)));
        if (symEqA(ho,hl,">=")) return boolCell(asInt(eval(a0,env)) >= asInt(eval(a1,env)));
        if (symEqA(ho,hl,"=<")||symEqA(ho,hl,"<=")) return boolCell(asInt(eval(a0,env)) <= asInt(eval(a1,env)));

        // list / tuple data
        if (symEqA(ho,hl,"list")) return buildList(a0, env);
        if (symEqA(ho,hl,"cons")) return mkCons(eval(a0,env), eval(a1,env));
        if (symEqA(ho,hl,"car")||symEqA(ho,hl,"hd")) { const int x=eval(a0,env); return (g_cells[x].t==CT.Cons)?g_cells[x].a:NIL; }
        if (symEqA(ho,hl,"cdr")||symEqA(ho,hl,"tl")) { const int x=eval(a0,env); return (g_cells[x].t==CT.Cons)?g_cells[x].d:NIL; }
        if (symEqA(ho,hl,"length")) { int x=eval(a0,env), c=0; while(x!=NIL && g_cells[x].t==CT.Cons){++c;x=g_cells[x].d;} return mkInt(c); }
        if (symEqA(ho,hl,"tuple")) { const int el=buildList(a0,env); const int t=allocCell(CT.Tuple); g_cells[t].a=el;
            int cnt=0,e=el; while(e!=NIL&&g_cells[e].t==CT.Cons){++cnt;e=g_cells[e].d;} g_cells[t].i=cnt; return t; }
        if (symEqA(ho,hl,"element")) { const long ix=asInt(eval(a0,env)); const int t=eval(a1,env);
            if (g_cells[t].t!=CT.Tuple) return NIL; int e=g_cells[t].a; long k=1;
            while(e!=NIL&&g_cells[e].t==CT.Cons){ if(k==ix) return g_cells[e].a; ++k; e=g_cells[e].d; } return NIL; }

        // object-model verbs as functions (enumeration prints; mutations return their result as data)
        if (symEqA(ho,hl,"obj")||symEqA(ho,hl,"objects"))    { runQuery(HOSQ_OBJECTS,    "TYPE                COUNT\n".ptr); return NIL; }
        if (symEqA(ho,hl,"id")||symEqA(ho,hl,"identities"))  { runQuery(HOSQ_IDENTITIES, "IDENTITY DOMAINS\n".ptr); return NIL; }
        if (symEqA(ho,hl,"ns")||symEqA(ho,hl,"namespaces"))  { runQuery(HOSQ_NAMESPACES, "NAMESPACES\n".ptr); return NIL; }
        if (symEqA(ho,hl,"svc")||symEqA(ho,hl,"services"))   { runQuery(HOSQ_SERVICES,   "SERVICES\n".ptr); return NIL; }
        if (symEqA(ho,hl,"sys")) { runQuery(HOSQ_SYS, null); return NIL; }
        if (symEqA(ho,hl,"whoami")) return whoCell();
        if (symEqA(ho,hl,"ns-clone")) return mkInt(syscall(HOS_SYS_QUERY, HOSQ_NS_CLONE, 0, 0, 0));
        if (symEqA(ho,hl,"ns-enter")) { const long v = asInt(eval(a0,env));
            if (!guardDestructive("ns-enter".ptr, v, 0)) return mkInt(-1);
            return mkInt(syscall(HOS_SYS_QUERY, HOSQ_NS_ENTER, v, 0, 0)); }
        if (symEqA(ho,hl,"cap-grant")) { const long h = asInt(eval(a0,env)), r = asInt(eval(a1,env));
            if (!guardDestructive("cap-grant".ptr, h, r)) return mkInt(-1);
            return mkInt(syscall(HOS_SYS_QUERY, HOSQ_CAP_GRANT, h, r, 0)); }
        if (symEqA(ho,hl,"subscribe")) return mkInt(syscall(HOS_SYS_QUERY, HOSQ_SUBSCRIBE, asInt(eval(a0,env)), 0, 0));

        // L4 — the security model as first-class forms (the prompt's fields, manipulable as LFE)
        if (symEqA(ho,hl,"identity"))  return buildIdentity();                       // #(user ns caps)
        if (symEqA(ho,hl,"namespace")) return tupleElem(buildIdentity(), 2);         // my namespace atom
        if (symEqA(ho,hl,"caps"))      return tupleElem(buildIdentity(), 3);         // my rights, a list of atoms
        if (symEqA(ho,hl,"cap-derive")) { const long h = asInt(eval(a0,env)), r = asInt(eval(a1,env));
            if (!guardDestructive("cap-derive".ptr, h, r)) return mkInt(-1);
            return mkInt(syscall(HOS_SYS_QUERY, HOSQ_CAP_GRANT, h, r, 0)); }
        if (symEqA(ho,hl,"identity-switch")) { auto nm = cstrCell(eval(a0,env));
            if (!guardDestructive("identity-switch".ptr, 0, 0)) return mkInt(-1);
            return mkInt(syscall(HOS_SYS_QUERY, HOSQ_ID_SWITCH, 0, cast(long)nm, 0)); }

        // shell side-effects
        if (symEqA(ho,hl,"print")) { int ai=a0; while(ai>=0){ printCell(eval(ai,env)); printf("\n"); ai=g_nodes[ai].next; } fflush(stdout); return NIL; }
        if (symEqA(ho,hl,"cat")) { catFile(cstrCell(eval(a0,env))); return NIL; }
        if (symEqA(ho,hl,"cd"))  { const(char)* p=(a0>=0)?cstrCell(eval(a0,env)):"/".ptr; if (chdir(p)!=0) printf("hos-sh: cd: %s: no such directory\n", p); return NIL; }
        if (symEqA(ho,hl,"help")) { help(); return NIL; }
    }

    // application: the head evaluates to a closure (user-defined via defun/lambda)
    const int fn = eval(head, env);
    if (g_cells[fn].t == CT.Fun) return applyFun(fn, g_nodes[head].next, env);
    printf("hos-sh: cannot apply '%.*s' (try (help))\n", g_nodes[head].len, g_strarena.ptr + g_nodes[head].aoff);
    return allocCell(CT.Err);
}

int quoteNode(int nd) @nogc nothrow {
    if (nd<0) return NIL;
    final switch (g_nodes[nd].kind) {
        case SK.Num: return mkInt(g_nodes[nd].num);
        case SK.Str: return mkStr(g_nodes[nd].aoff, g_nodes[nd].len);
        case SK.Sym: return mkAtom(g_nodes[nd].aoff, g_nodes[nd].len);
        case SK.List: {                                    // a quoted list -> a cons-list of quoted elems
            int first=NIL, last=NIL, ch=g_nodes[nd].head;
            while (ch>=0) { const int cell=mkCons(quoteNode(ch), NIL);
                if (first==NIL) first=cell; else g_cells[last].d=cell; last=cell; ch=g_nodes[ch].next; }
            return first;
        }
    }
}

void printCell(int c) @nogc nothrow {
    switch (g_cells[c].t) {
        case CT.Nil: printf("()"); break;
        case CT.Int: printf("%ld", g_cells[c].i); break;
        case CT.Atom: fwrite(g_strarena.ptr+g_cells[c].s, 1, cast(size_t)g_cells[c].n, stdout); break;
        case CT.Str: printf("\""); fwrite(g_strarena.ptr+g_cells[c].s, 1, cast(size_t)g_cells[c].n, stdout); printf("\""); break;
        case CT.Cons: { printf("("); int e=c; bool first=true;
            while (e!=NIL && g_cells[e].t==CT.Cons) { if(!first) printf(" "); first=false; printCell(g_cells[e].a); e=g_cells[e].d; }
            if (e!=NIL) { printf(" . "); printCell(e); } printf(")"); break; }
        case CT.Tuple: { printf("#("); int e=g_cells[c].a; bool first=true;
            while (e!=NIL && g_cells[e].t==CT.Cons) { if(!first) printf(" "); first=false; printCell(g_cells[e].a); e=g_cells[e].d; } printf(")"); break; }
        case CT.Fun: printf("#<fun>"); break;
        default: break;
    }
}
// top-level REPL print: a Str prints raw (the object tables are big text); others print as data.
void printResult(int c) @nogc nothrow {
    if (c==NIL) return;
    if (g_cells[c].t==CT.Str) { if (g_cells[c].n>0) { fwrite(g_strarena.ptr+g_cells[c].s, 1, cast(size_t)g_cells[c].n, stdout); printf("\n"); fflush(stdout); } return; }
    if (g_cells[c].t==CT.Err) return;
    printCell(c); printf("\n"); fflush(stdout);
}

// Z4a.2: read a file through the NATIVE FS verbs (object_open/read/close) — never a Linux
// open().  Proves the native-ABI filesystem path end-to-end from a native-personality task.
void catFile(const(char)* path) @nogc nothrow {
    while (*path == ' ') ++path;
    const long h = syscall(HOS_SYS_QUERY, HOSQ_OPEN, CAP_RIGHT_READ_V, cast(long)path, 0);
    if (h < 0) { printf("hos-sh: cat: %s: native open failed (errno %ld)\n", path, -h); return; }
    char[512] buf = void;
    for (;;) {
        const long n = syscall(HOS_SYS_QUERY, HOSQ_READ, h, cast(long)buf.ptr, cast(long)buf.length);
        if (n <= 0) break;
        fwrite(buf.ptr, 1, cast(size_t)n, stdout);
    }
    fflush(stdout);
    syscall(HOS_SYS_QUERY, HOSQ_CLOSE, h, 0, 0);
}

// Z4b.3/Z4c.3 — exercise the native event + mutation verbs (object_subscribe, namespace_clone/
// enter, cap_grant) from a native-personality task, printing each result.  A live proof that the
// mutation surface works AND that the security gates hold (deny-by-default, attenuation-only).
void z4test() @nogc nothrow {
    const long s = syscall(HOS_SYS_QUERY, HOSQ_SUBSCRIBE, SIG_CHLD_BIT | SIG_INT_BIT, 0, 0);
    printf("subscribe(SIGCHLD|SIGINT) -> %ld\n", s);
    int[2] fds;
    if (pipe(fds.ptr) == 0) {
        const long w = syscall(HOS_SYS_QUERY, HOSQ_SEND, fds[1], cast(long)"hos-ipc".ptr, 7);
        char[16] rb = 0;
        const long r = syscall(HOS_SYS_QUERY, HOSQ_RECV, fds[0], cast(long)rb.ptr, 7);
        printf("object_send/recv over a channel -> sent %ld, recv %ld: \"%s\"\n", w, r, rb.ptr);
    }
    const long nid = syscall(HOS_SYS_QUERY, HOSQ_NS_CLONE, 0, 0, 0);
    printf("namespace_clone() -> %ld\n", nid);
    if (nid > 0) {
        const long e1 = syscall(HOS_SYS_QUERY, HOSQ_NS_ENTER, nid, 0, 0);
        printf("namespace_enter(%ld) -> %ld  (my clone: expect 0)\n", nid, e1);
        const long e2 = syscall(HOS_SYS_QUERY, HOSQ_NS_ENTER, nid + 4242, 0, 0);
        printf("namespace_enter(%ld) -> %ld  (not mine: expect -1 EPERM)\n", nid + 4242, e2);
    }
    const long g = syscall(HOS_SYS_QUERY, HOSQ_CAP_GRANT, 1, CAP_RIGHT_READ_V, 0);
    if (g >= 0) printf("cap_grant(h1, READ) -> new handle %ld (attenuated)\n", g);
    else        printf("cap_grant(h1, READ) -> %ld (deny-by-default: no usable source cap)\n", g);
}

// Build "user@namespace" from the native whoami query (once).
void loadWho() @nogc nothrow {
    const long n = syscall(HOS_SYS_QUERY, HOSQ_WHOAMI, 0, cast(long)g_who.ptr, cast(long)(g_who.length - 1));
    if (n > 0) g_who[cast(size_t)n] = 0;
    else { g_who[0]='u'; g_who[1]='s'; g_who[2]='e'; g_who[3]='r'; g_who[4]=0; }
}

// Dispatch one command line.  Returns 0 to exit the shell, 1 to keep going.  Shared by the
// interactive loop and the Z4c non-interactive (`hos-sh <verb>`) mode.
int runCommand(char* cmd) @nogc nothrow {
    while (*cmd == ' ' || *cmd == '\t') ++cmd;
    if (*cmd == 0) return 1;

    // L3 — LFE interpreter: parse + evaluate every top-level form on the line, sharing the
    // session's global environment (so `(defun ..)` persists for later lines).  Bare words
    // (below) still drive the simple dispatch the zsh integration spawns (`/hos-sh obj`).
    if (*cmd == '(' || *cmd == '\'') {
        ensureInit();
        g_src = cmd; g_pos = 0; g_exitReq = 0;
        for (;;) {
            pskip();
            if (g_src[g_pos] == 0) break;
            printResult(eval(parseExpr(), g_globalEnv));
        }
        if (g_resetReq) { g_inited = false; g_resetReq = 0; }   // clear the session on next form
        return g_exitReq ? 0 : 1;
    }

    if      (strcmp(cmd, "exit".ptr) == 0 || strcmp(cmd, "quit".ptr) == 0) return 0;
    else if (strcmp(cmd, "help".ptr) == 0) help();
    else if (strcmp(cmd, "cd".ptr) == 0) chdir("/".ptr);
    else if (strncmp(cmd, "cd ".ptr, 3) == 0) {
        char* arg = cmd + 3; while (*arg == ' ') ++arg;
        if (chdir(arg) != 0) printf("hos-sh: cd: %s: no such directory\n", arg);
    }
    else if (strncmp(cmd, "cat ".ptr, 4) == 0) catFile(cmd + 4);
    else if (strncmp(cmd, "obj".ptr, 3) == 0) runQuery(HOSQ_OBJECTS,    "TYPE                COUNT\n".ptr);
    else if (strncmp(cmd, "id".ptr,  2) == 0) runQuery(HOSQ_IDENTITIES, "IDENTITY DOMAINS\n".ptr);
    else if (strncmp(cmd, "ns".ptr,  2) == 0) runQuery(HOSQ_NAMESPACES, "NAMESPACES\n".ptr);
    else if (strncmp(cmd, "svc".ptr, 3) == 0) runQuery(HOSQ_SERVICES,   "SERVICES\n".ptr);
    else if (strcmp(cmd, "sys".ptr) == 0)     runQuery(HOSQ_SYS,        null);
    // Z6.1: print the kernel identity line (HOSQ_WHOAMI: "user@namespace [<rights ceiling>]").
    // Native zsh uses `/hos-sh whoami` to build a prompt that shows the full native identity.
    else if (strcmp(cmd, "whoami".ptr) == 0)  printf("%s\n", g_who.ptr);
    else if (strcmp(cmd, "z4".ptr) == 0)      z4test();  // Z4b.3/Z4c.3 native verb self-test
    // ── B5 ────────────────────────────────────────────────────────────────────────────────
    else if (strcmp(cmd, "--dry-run".ptr) == 0 || strcmp(cmd, "dry-run".ptr) == 0) {
        g_dryRun = 1; printf("dry-run ON: destructive verbs report and do nothing\n");
    }
    else if (strcmp(cmd, "--yes".ptr) == 0 || strcmp(cmd, "arm".ptr) == 0) {
        g_armed = 1; printf("armed: the NEXT destructive verb will execute (one-shot)\n");
    }
    else if (strncmp(cmd, "complete".ptr, 8) == 0) {
        const(char)* pfx = cmd + 8; while (*pfx == ' ') ++pfx;
        int t = 0;
        t += completeNames(HOSQ_IDENTITIES, pfx, 1);
        t += completeNames(HOSQ_NAMESPACES, pfx, 1);
        t += completeNames(HOSQ_SERVICES,   pfx, 1);
        if (t == 0) printf("  (no completions)\n");
    }
    else if (strcmp(cmd, "man".ptr) == 0 || strncmp(cmd, "man ".ptr, 4) == 0) manPage(cmd);
    else if (strcmp(cmd, "--selftest".ptr) == 0) return b5SelfTest();
    else printf("hos-sh: unknown command '%s' (try 'help')\n", cmd);
    return 1;
}

// LFE-in-zsh (the architecture fix): the SAME evaluator compiles as a library entry for the zsh
// `anonymos` module (built with -d-version=LfeLib), so the native zsh evaluates LFE forms
// IN-PROCESS via an `lfe` builtin — one shell (zsh) with LFE inside it, not a separate `-sh`.
version(LfeLib) {
    extern(C) void lfe_eval_line(const(char)* line) @nogc nothrow {
        ensureInit();
        g_src = line; g_pos = 0; g_exitReq = 0;
        for (;;) { pskip(); if (g_src[g_pos] == 0) break; printResult(eval(parseExpr(), g_globalEnv)); }
        if (g_resetReq) { g_inited = false; g_resetReq = 0; }
    }
} else {
extern(C) int main(int argc, char** argv) @nogc nothrow {
    loadWho();

    // Z4c.1: non-interactive mode — `hos-sh <verb> [args]` runs one command and exits.  This
    // is how native zsh exposes the object model at its prompt: obj/id/ns/svc/sys are zsh
    // functions that spawn `/hos-sh <verb>` (which self-gates to the native ABI by name), so
    // the kernel object model is reachable from zsh without zsh itself holding the N0 gate.
    if (argc > 1) {
        char[256] cmd = void;
        size_t p = 0;
        for (int i = 1; i < argc && p + 1 < cmd.length; ++i) {
            if (i > 1 && p + 1 < cmd.length) cmd[p++] = ' ';
            const(char)* a = argv[i];
            while (*a != 0 && p + 1 < cmd.length) cmd[p++] = *a++;
        }
        cmd[p] = 0;
        runCommand(cmd.ptr);
        return 0;
    }

    printf("\nEpinAnonymOS native object shell  (-sh, LFE — a programmable Lisp over the object model)\n");
    printf("Type (help).  e.g. (defun sq (x) (* x x))  then  (sq 9)\n\n");

    char[256] line = void;
    for (;;) {
        // Prompt: user@namespace:/current/path$
        if (getcwd(g_cwd.ptr, g_cwd.length) is null) { g_cwd[0]='/'; g_cwd[1]=0; }
        printf("%s:%s$ ", g_who.ptr, g_cwd.ptr);
        fflush(stdout);
        if (fgets(line.ptr, cast(int)line.length, stdin) is null) break;

        size_t l = strlen(line.ptr);
        while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = 0;
        if (!runCommand(line.ptr)) break;
    }
    printf("bye\n");
    return 0;
}
}   // version(LfeLib) else
