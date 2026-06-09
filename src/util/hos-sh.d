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
    extern __gshared void* stdin;
    extern __gshared void* stdout;
}

enum long HOS_SYS_QUERY = 0x4000;
enum long HOSQ_OBJECTS    = 1;
enum long HOSQ_IDENTITIES = 2;
enum long HOSQ_NAMESPACES = 3;
enum long HOSQ_SERVICES   = 4;
enum long HOSQ_SYS        = 5;

__gshared char[8192] g_buf;

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
    printf("native object commands:\n");
    printf("  obj     list kernel objects by type (File, Process, Identity, ...)\n");
    printf("  id      list identity domains (trust, rights ceiling, state)\n");
    printf("  ns      list namespaces\n");
    printf("  svc     list services and their state\n");
    printf("  sys     system object summary\n");
    printf("  help    this list\n");
    printf("  exit    leave the native shell\n");
}

extern(C) int main() @nogc nothrow {
    printf("\nEpinAnonymOS native object shell  (-sh / dash)\n");
    printf("Drives the microkernel object model directly. Type 'help'.\n\n");

    char[256] line = void;
    for (;;) {
        printf("hos> ");
        fflush(stdout);
        if (fgets(line.ptr, cast(int)line.length, stdin) is null) break;

        size_t l = strlen(line.ptr);
        while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = 0;
        char* cmd = line.ptr;
        while (*cmd == ' ' || *cmd == '\t') ++cmd;
        if (*cmd == 0) continue;

        if      (strcmp(cmd, "exit".ptr) == 0 || strcmp(cmd, "quit".ptr) == 0) break;
        else if (strcmp(cmd, "help".ptr) == 0) help();
        else if (strncmp(cmd, "obj".ptr, 3) == 0) runQuery(HOSQ_OBJECTS,    "TYPE                COUNT\n".ptr);
        else if (strncmp(cmd, "id".ptr,  2) == 0) runQuery(HOSQ_IDENTITIES, "IDENTITY DOMAINS\n".ptr);
        else if (strncmp(cmd, "ns".ptr,  2) == 0) runQuery(HOSQ_NAMESPACES, "NAMESPACES\n".ptr);
        else if (strncmp(cmd, "svc".ptr, 3) == 0) runQuery(HOSQ_SERVICES,   "SERVICES\n".ptr);
        else if (strcmp(cmd, "sys".ptr) == 0)     runQuery(HOSQ_SYS,        null);
        else printf("hos-sh: unknown command '%s' (try 'help')\n", cmd);
    }
    printf("bye\n");
    return 0;
}
