/*
 * hos-dbus-test.c -- M0 EXTERNAL-auth smoke test: a real dbus-send client (static-musl launcher).
 *
 * Kernel-spawned a bit after hos-dbus-launch so the bus is already listening.  It execve()s dbus-send
 * GetId, which does the full connect + EXTERNAL (SO_PEERCRED) auth + Hello/register + method-call
 * round-trip against the system bus.  A printed 32-hex bus id on serial proves EXTERNAL auth works over
 * the kernel's native AF_UNIX -- the gating prerequisite for every later NetworkManager client.
 */
#include <string.h>
#include <unistd.h>

static void logline(const char *s){ (void)!write(2, s, strlen(s)); (void)!write(2, "\n", 1); }

int main(void)
{
    logline("[dbus-test] exec dbus-send --system GetId (EXTERNAL-auth round-trip)");
    char *argv[] = { "/dbus-send", "--system", "--print-reply",
                     "--dest=org.freedesktop.DBus", "/org/freedesktop/DBus",
                     "org.freedesktop.DBus.GetId", 0 };
    char *envp[] = { "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };
    execve("/dbus-send", argv, envp);
    logline("[dbus-test] execve(/dbus-send) FAILED");
    return 1;
}
