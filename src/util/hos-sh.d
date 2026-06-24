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
enum long CAP_RIGHT_READ_V = 1;  // CAP_RIGHT_READ = bit 0

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
    printf("native object forms (LFE / Lisp-flavored s-expressions; bare words also work):\n");
    printf("  (obj)         list kernel objects by type (File, Process, Identity, ...)\n");
    printf("  (id)          list identity domains (trust, rights ceiling, state)\n");
    printf("  (ns)          list namespaces\n");
    printf("  (svc)         list services and their state\n");
    printf("  (sys)         system object summary\n");
    printf("  (cat \"/path\") read a file through the NATIVE FS verbs (object_open/read)\n");
    printf("  (cd \"/path\")  change the current path (prompt shows user@namespace:/path)\n");
    printf("  (help)        this list\n");
    printf("  (exit)        leave the native shell\n");
}

// Minimal LFE (Lisp Flavored Erlang) reader: rewrite an s-expression `(head arg ...)`
// into the bare "head arg ..." form the dispatcher already understands — outer parens
// dropped, "string" atoms unquoted, nested grouping flattened.  The native AnonymOS
// shell follows the LFE syntax/structure of the `-sh` project; this is the first step
// (the object commands as LFE forms).  Bare words still work for convenience.
__gshared char[512] g_lfe;
char* lfeNormalize(char* s) @nogc nothrow {
    const(char)* p = s + 1;             // caller guarantees s[0] == '('
    size_t o = 0;
    int depth = 1;
    while (*p != 0 && o + 1 < g_lfe.length) {
        const char c = *p;
        if (c == '(') { ++depth; ++p; continue; }
        if (c == ')') { if (--depth <= 0) break; ++p; continue; }
        if (c == '"') {                 // unquote a string atom
            ++p;
            while (*p != 0 && *p != '"' && o + 1 < g_lfe.length) g_lfe[o++] = *p++;
            if (*p == '"') ++p;
            continue;
        }
        if (c == ' ' || c == '\t') { if (o > 0 && g_lfe[o-1] != ' ') g_lfe[o++] = ' '; ++p; continue; }
        g_lfe[o++] = c; ++p;
    }
    while (o > 0 && g_lfe[o-1] == ' ') --o;
    g_lfe[o] = 0;
    return g_lfe.ptr;
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

    // LFE: an s-expression `(head arg ...)` is read into the bare command form.
    if (*cmd == '(') {
        cmd = lfeNormalize(cmd);
        while (*cmd == ' ') ++cmd;
        if (*cmd == 0) return 1;
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
