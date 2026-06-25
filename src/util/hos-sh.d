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
enum long CAP_RIGHT_READ_V = 1;  // CAP_RIGHT_READ = bit 0
enum long SIG_CHLD_BIT = 1 << 17, SIG_INT_BIT = 1 << 2;  // §6 event bits (SIGCHLD / SIGINT)

__gshared char[8192] g_buf;
__gshared char[128]  g_who;   // "user@namespace" (cached)
__gshared char[256]  g_cwd;

// Run a native object-model query and print its text result.
void runQuery(long op, const(char)* header) @nogc nothrow {
    const long n = syscall(HOS_SYS_QUERY, op, 0, cast(long)g_buf.ptr, cast(long)(g_buf.length - 1));
    if (n < 0) { printf("hos-sh: native query failed (errno %ld)\n", -n); return; }
    if (header !is null) printf("%s", header);
    if (n == 0) { printf("  (none)\n"); return; }
    fwrite(g_buf.ptr, 1, cast(size_t)n, stdout);
    fflush(stdout);
}

void help() @nogc nothrow {
    printf("LFE forms — evaluated to data; object-ABI verbs are functions, results compose:\n");
    printf("  (obj) (id) (ns) (svc) (sys)   enumerate objects/identities/namespaces/services\n");
    printf("  (whoami)                      the identity line, as data\n");
    printf("  (ns-clone)                    clone my namespace -> new id (data)\n");
    printf("  (ns-enter <id>)               enter an owned namespace -> 0/-errno\n");
    printf("  (cap-grant <h> <rights>)      attenuating capability grant -> new handle\n");
    printf("  (subscribe <events>)          §6 event subscription\n");
    printf("  (+ - * /) e.g. (+ 1 (* 2 3))  arithmetic; args evaluate first, so forms NEST\n");
    printf("  (ns-enter (ns-clone))         composition: clone yields the id enter consumes\n");
    printf("  (cat \"/path\") (cd \"/path\")     read a file / change path (native FS verbs)\n");
    printf("  (print x ...)  (help)  (exit)  print values / this list / leave\n");
}

// ── L2: a real LFE (Lisp-Flavored Erlang) evaluator ─────────────────────────────────────────
// L0 only *read* a form into the bare command; L2 *evaluates* it.  An s-expression parses to an
// AST and evaluates to DATA (a number or text), so the object-ABI verbs are LFE functions whose
// results further forms consume — composition, not text streams:
//     (+ 1 (* 2 3))        => 7
//     (ns-enter (ns-clone)) => 0           ; clone returns an id, enter consumes it
//     (obj)                => the object table (as data)
// Ported from the upstream `-sh` evaluation model (deps/lfe-sh, vendored in L1) into betterC: a
// fixed node pool + value tags, no GC / exceptions.  Bare words still work for the zsh integration.

enum SK : ubyte { Num, Sym, Str, List }
struct Node { SK kind; int off; int len; long num; int head; int next; }
__gshared Node[256] g_nodes;
__gshared int g_nnodes;
__gshared const(char)* g_src;   // the form text being parsed/evaluated
__gshared int g_pos;
__gshared int g_exitReq;        // (exit)/(quit) sets this

enum VK : ubyte { Nil, Num, Str, Err }
struct Val { VK kind; long num; const(char)* sp; int slen; }
Val vnil() @nogc nothrow { Val v; v.kind=VK.Nil; v.num=0; v.sp=null; v.slen=0; return v; }
Val vnum(long x) @nogc nothrow { Val v; v.kind=VK.Num; v.num=x; v.sp=null; v.slen=0; return v; }
Val vstr(const(char)* s, int n) @nogc nothrow { Val v; v.kind=VK.Str; v.num=0; v.sp=s; v.slen=n; return v; }
Val verr() @nogc nothrow { Val v; v.kind=VK.Err; v.num=0; v.sp=null; v.slen=0; return v; }

int allocNode(SK k) @nogc nothrow {
    if (g_nnodes >= cast(int)g_nodes.length) return -1;
    const int n = g_nnodes++;
    g_nodes[n].kind=k; g_nodes[n].off=0; g_nodes[n].len=0; g_nodes[n].num=0;
    g_nodes[n].head=-1; g_nodes[n].next=-1;
    return n;
}
bool isNum(const(char)* s, int n) @nogc nothrow {
    if (n==0) return false;
    int i=0; if (s[0]=='-') { if (n==1) return false; i=1; }
    for (; i<n; ++i) if (s[i]<'0' || s[i]>'9') return false;
    return true;
}
long toLong(const(char)* s, int n) @nogc nothrow {
    int i=0; long sign=1; if (s[0]=='-') { sign=-1; i=1; }
    long v=0; for (; i<n; ++i) v = v*10 + (s[i]-'0'); return v*sign;
}
bool symEq(const(char)* s, int n, string lit) @nogc nothrow {
    if (n != cast(int)lit.length) return false;
    for (int i=0; i<n; ++i) if (s[i] != lit[i]) return false;
    return true;
}

void pskip() @nogc nothrow { while (g_src[g_pos]==' ' || g_src[g_pos]=='\t') ++g_pos; }
int parseExpr() @nogc nothrow {
    pskip();
    const char c = g_src[g_pos];
    if (c==0) return -1;
    if (c=='(') { ++g_pos; return parseList(); }
    if (c=='"') return parseStr();
    return parseAtom();
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
    g_nodes[n].off=start; g_nodes[n].len=g_pos-start;
    if (g_src[g_pos]=='"') ++g_pos;
    return n;
}
int parseAtom() @nogc nothrow {
    const int start=g_pos;
    while (g_src[g_pos]!=0) { const char c=g_src[g_pos]; if (c==' '||c=='\t'||c=='('||c==')') break; ++g_pos; }
    const int len=g_pos-start;
    const bool num = isNum(g_src+start, len);
    const int n=allocNode(num?SK.Num:SK.Sym); if (n<0) return -1;
    g_nodes[n].off=start; g_nodes[n].len=len;
    if (num) g_nodes[n].num=toLong(g_src+start, len);
    return n;
}

// A null-terminated copy of a string Value (for chdir/open which need a C string).
__gshared char[256] g_argbuf;
const(char)* cstr(Val v) @nogc nothrow {
    int n = (v.kind==VK.Str) ? v.slen : 0;
    if (n > cast(int)g_argbuf.length-1) n = cast(int)g_argbuf.length-1;
    for (int i=0; i<n; ++i) g_argbuf[i]=v.sp[i];
    g_argbuf[n]=0; return g_argbuf.ptr;
}
// A native enumeration query returned AS DATA (its text), so a form can yield the object table.
Val queryVal(long op) @nogc nothrow {
    const long n = syscall(HOS_SYS_QUERY, op, 0, cast(long)g_buf.ptr, cast(long)(g_buf.length-1));
    if (n <= 0) return vnil();
    return vstr(g_buf.ptr, cast(int)n);
}
void printVal(Val v) @nogc nothrow {
    final switch (v.kind) {
        case VK.Nil: case VK.Err: break;
        case VK.Num: printf("%ld\n", v.num); break;
        case VK.Str:
            if (v.slen>0) { fwrite(v.sp, 1, cast(size_t)v.slen, stdout);
                if (v.sp[v.slen-1] != '\n') printf("\n"); fflush(stdout); }
            break;
    }
}

Val eval(int n) @nogc nothrow {
    if (n<0) return vnil();
    final switch (g_nodes[n].kind) {
        case SK.Num:  return vnum(g_nodes[n].num);
        case SK.Str:  return vstr(g_src+g_nodes[n].off, g_nodes[n].len);
        case SK.Sym:  return vstr(g_src+g_nodes[n].off, g_nodes[n].len);  // bare symbol -> itself
        case SK.List: return evalList(n);
    }
}
Val evalList(int ln) @nogc nothrow {
    const int head = g_nodes[ln].head;
    if (head < 0) return vnil();                                  // ()
    if (g_nodes[head].kind != SK.Sym) return eval(head);          // ((..)) -> evaluate the head form
    const(char)* op = g_src + g_nodes[head].off;
    const int ol = g_nodes[head].len;
    const int a0 = g_nodes[head].next;                            // first argument node (-1 if none)

    // arithmetic — args evaluate first, so nesting composes: (+ 1 (* 2 3)) -> 7
    if (ol==1 && (op[0]=='+'||op[0]=='-'||op[0]=='*'||op[0]=='/')) {
        int ai=a0; if (ai<0) return vnum(0);
        long acc = eval(ai).num; ai=g_nodes[ai].next;
        while (ai>=0) { const long v=eval(ai).num;
            switch (op[0]) { case '+': acc+=v; break; case '-': acc-=v; break;
                case '*': acc*=v; break; case '/': acc = v ? acc/v : 0; break; default: break; }
            ai=g_nodes[ai].next; }
        return vnum(acc);
    }
    // object-model enumeration forms -> the table AS DATA
    if (symEq(op,ol,"objects")  || symEq(op,ol,"obj")) return queryVal(HOSQ_OBJECTS);
    if (symEq(op,ol,"identities")|| symEq(op,ol,"id"))  return queryVal(HOSQ_IDENTITIES);
    if (symEq(op,ol,"namespaces")|| symEq(op,ol,"ns"))  return queryVal(HOSQ_NAMESPACES);
    if (symEq(op,ol,"services") || symEq(op,ol,"svc")) return queryVal(HOSQ_SERVICES);
    if (symEq(op,ol,"sys"))    return queryVal(HOSQ_SYS);
    if (symEq(op,ol,"whoami")) return vstr(g_who.ptr, cast(int)strlen(g_who.ptr));
    // native mutation/event verbs -> their result AS DATA (handle / id / status), composable
    if (symEq(op,ol,"ns-clone"))  return vnum(syscall(HOS_SYS_QUERY, HOSQ_NS_CLONE, 0, 0, 0));
    if (symEq(op,ol,"ns-enter"))  return vnum(syscall(HOS_SYS_QUERY, HOSQ_NS_ENTER, eval(a0).num, 0, 0));
    if (symEq(op,ol,"cap-grant")) { const long s=eval(a0).num;
        const long r=(a0>=0) ? eval(g_nodes[a0].next).num : 0;
        return vnum(syscall(HOS_SYS_QUERY, HOSQ_CAP_GRANT, s, r, 0)); }
    if (symEq(op,ol,"subscribe")) return vnum(syscall(HOS_SYS_QUERY, HOSQ_SUBSCRIBE, eval(a0).num, 0, 0));
    // shell builtins (side effects -> Nil)
    if (symEq(op,ol,"cat")) { catFile(cstr(eval(a0))); return vnil(); }
    if (symEq(op,ol,"cd"))  { const(char)* p=(a0>=0) ? cstr(eval(a0)) : "/".ptr;
        if (chdir(p)!=0) printf("hos-sh: cd: %s: no such directory\n", p); return vnil(); }
    if (symEq(op,ol,"print")||symEq(op,ol,"echo")) { int ai=a0; while (ai>=0) { printVal(eval(ai)); ai=g_nodes[ai].next; } return vnil(); }
    if (symEq(op,ol,"help")) { help(); return vnil(); }
    if (symEq(op,ol,"exit")||symEq(op,ol,"quit")) { g_exitReq=1; return vnil(); }
    printf("hos-sh: unknown form '%.*s' (try (help))\n", ol, op);
    return verr();
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
    // §6 event subscription (SIGCHLD + SIGINT) — formalizes the already-working delivery.
    const long s = syscall(HOS_SYS_QUERY, HOSQ_SUBSCRIBE, SIG_CHLD_BIT | SIG_INT_BIT, 0, 0);
    printf("subscribe(SIGCHLD|SIGINT) -> %ld\n", s);

    // §8 channel message-passing — a self-pipe proves object_send/recv move bytes over a channel.
    int[2] fds;
    if (pipe(fds.ptr) == 0) {
        const long w = syscall(HOS_SYS_QUERY, HOSQ_SEND, fds[1], cast(long)"hos-ipc".ptr, 7);
        char[16] rb = 0;
        const long r = syscall(HOS_SYS_QUERY, HOSQ_RECV, fds[0], cast(long)rb.ptr, 7);
        printf("object_send/recv over a channel -> sent %ld, recv %ld: \"%s\"\n", w, r, rb.ptr);
    }

    // §11 namespace clone (a private copy of my namespace) + enter it; then prove the gate.
    const long nid = syscall(HOS_SYS_QUERY, HOSQ_NS_CLONE, 0, 0, 0);
    printf("namespace_clone() -> %ld\n", nid);
    if (nid > 0) {
        const long e1 = syscall(HOS_SYS_QUERY, HOSQ_NS_ENTER, nid, 0, 0);
        printf("namespace_enter(%ld) -> %ld  (my clone: expect 0)\n", nid, e1);
        const long e2 = syscall(HOS_SYS_QUERY, HOSQ_NS_ENTER, nid + 4242, 0, 0);
        printf("namespace_enter(%ld) -> %ld  (not mine: expect -1 EPERM)\n", nid + 4242, e2);
    }

    // §7 capability grant — attenuation only.  Grant READ derived from handle 1; the kernel
    // intersects with what I hold and my identity ceiling, so it can only shrink (or be denied).
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

    // L2 — LFE evaluator: an s-expression parses to an AST and EVALUATES to data (a number or
    // text); object-ABI verbs are functions whose results further forms consume.  Bare words
    // (below) still drive the simple dispatch the zsh integration spawns (`/hos-sh obj`).
    if (*cmd == '(') {
        g_src = cmd; g_pos = 0; g_nnodes = 0; g_exitReq = 0;
        printVal(eval(parseExpr()));
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
    else printf("hos-sh: unknown command '%s' (try 'help')\n", cmd);
    return 1;
}

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

    printf("\nEpinAnonymOS native object shell  (-sh, LFE syntax)\n");
    printf("Drives the microkernel object model with Lisp-flavored (LFE) forms. Type (help).\n\n");

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
