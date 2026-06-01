#include <stdio.h>
#include <dlfcn.h>
#include <spawn.h>
#include <sys/wait.h>
extern char** environ;
int main(void) {
    puts("DYNHELLO: main running via ld.so");

    // Validate CLONE_VFORK: posix_spawn emits clone(CLONE_VM|CLONE_VFORK|SIGCHLD).
    // The child execs a nonexistent binary -> ENOENT -> _exit; the kernel must
    // resume this (suspended) parent. If vfork is broken, this hangs.
    pid_t pid = 0;
    char* av[] = { (char*)"/nonexistent-binary", NULL };
    int rc = posix_spawn(&pid, "/nonexistent-binary", NULL, NULL, av, environ);
    printf("DYNHELLO: posix_spawn rc=%d pid=%d\n", rc, (int)pid);
    if (rc == 0 && pid > 0) {
        int st = 0;
        waitpid(pid, &st, 0);
        printf("DYNHELLO: child reaped status=%d\n", st);
    }
    puts("DYNHELLO: vfork path returned (no hang)");

    void* h = dlopen("libfoo.so", RTLD_NOW);
    if (!h) { puts("DYNHELLO: dlopen libfoo.so FAILED"); return 1; }
    int (*foo)(void) = (int (*)(void))dlsym(h, "foo");
    if (foo && foo() == 4242) puts("DYNHELLO: dlopen+dlsym+call OK");
    else puts("DYNHELLO: dlsym/foo FAILED");
    puts("DYNHELLO: ALL DONE");
    return 0;
}
