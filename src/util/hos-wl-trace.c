/*
 * hos-wl-trace.c -- ROADMAP 2.3: run a Wayland client with libwayland's protocol tracing on.
 *
 * GTK clients here connect to the compositor socket successfully, exchange messages, receive
 * replies, and then never map a toplevel -- while wl-calendar, launched by the same keybinding
 * onto the same socket, maps in six seconds.  Every theory so far has been killed by evidence
 * (wrong socket, never accepted, CPU starvation, application weight), and the one tool that
 * answers the question directly is WAYLAND_DEBUG=1, which makes libwayland print every request
 * and event.
 *
 * A launcher is needed because there is no other way to set an environment variable for one app:
 *   - the kernel's env block does not reach these processes.  A keybinding launch is Hyprland
 *     forking a child, so the child inherits Hyprland's environment, not the one the kernel
 *     builds for programs it execs itself.
 *   - Hyprland execs the command directly, with no shell, so "VAR=x prog" is not parsed -- and
 *     there is no /bin/sh on this system in any case.
 *
 * So: setenv here, then execv the real client.  argv[1..] is the program and its arguments; with
 * no argument it defaults to /gtk-hello, the smallest GTK client available.
 *
 * Output goes to fd 2, which is the console, which is serial.log under QEMU.
 */
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static void logline(const char *s){ (void)!write(2, s, strlen(s)); (void)!write(2, "\n", 1); }

int main(int argc, char **argv)
{
    const char *prog = (argc > 1) ? argv[1] : "/gtk-hello";

    /* Point stdout and stderr at the console BEFORE anything else.  A process Hyprland forked
     * does not inherit a console on fd 1/2 -- an earlier run of this launcher exec'd its target
     * correctly (gtk-hello appeared as 22 tasks) while not one of its own log lines, written to
     * fd 2 before the exec, reached serial.log.  Since WAYLAND_DEBUG output goes to stderr, the
     * whole point of this program is lost without the redirect: the trace would be written and
     * discarded, looking exactly like the variable never having been set. */
    int con = open("/dev/console", O_WRONLY);
    if (con >= 0) {
        dup2(con, 1);
        dup2(con, 2);
        if (con > 2) close(con);
    }

    /* 1 rather than "client" or "server": libwayland treats any non-empty value as on, and the
     * client is the only side running under this launcher. */
    setenv("WAYLAND_DEBUG", "1", 1);

    /* Boot modules land at "/", so ld-musl needs that on its search path to resolve the shared
     * libraries a dynamically linked GTK client pulls in.  Same reasoning as hos-dbus-launch. */
    setenv("LD_LIBRARY_PATH", "/", 1);

    logline("[wltrace] WAYLAND_DEBUG=1");
    logline("[wltrace] exec:");
    logline(prog);

    /* Hand argv straight through from argv[1], so the traced program sees exactly the arguments
     * it would have been given directly. */
    char *defargv[2];
    if (argc > 1) {
        execv(prog, &argv[1]);
    } else {
        defargv[0] = (char *)prog;
        defargv[1] = 0;
        execv(prog, defargv);
    }

    /* execv only returns on failure. */
    logline("[wltrace] exec FAILED -- is the program staged as a boot module?");
    return 1;
}
