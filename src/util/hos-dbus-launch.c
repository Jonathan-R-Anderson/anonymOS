/*
 * hos-dbus-launch.c -- M0: bring up the REAL system dbus-daemon (static-musl launcher).
 *
 * The system D-Bus is pure local AF_UNIX IPC; it needs NEITHER the LKL nor the net-provider shim, so
 * it starts independently and early.  This wrapper (kernel-spawned, so it gets a fixed env) sets up the
 * machine-id + a minimal system.conf, then execve()s dbus-daemon so it BECOMES the persistent bus.  The
 * EXTERNAL-auth round-trip is proven separately by hos-dbus-test (a real dbus-send client), spawned a bit
 * later -- we avoid fork() here because the cooperative kernel does not reliably resume a forked parent.
 *
 * Boot modules land at "/", so LD_LIBRARY_PATH=/ lets ld-musl resolve libdbus-1.so.3.  Logs -> fd 2 ->
 * console -> serial.log under QEMU.
 */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void logline(const char *s){ (void)!write(2, s, strlen(s)); (void)!write(2, "\n", 1); }
static void writefile(const char *path, const char *data){
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) { (void)!write(fd, data, strlen(data)); close(fd); }
}

int main(void)
{
    mkdir("/run", 0755);       mkdir("/run/dbus", 0755);
    mkdir("/etc", 0755);       mkdir("/etc/dbus-1", 0755);
    mkdir("/var", 0755);       mkdir("/var/lib", 0755);   mkdir("/var/lib/dbus", 0755);

    /* A valid 32-hex machine-id is required for GetId / activation. */
    const char *mid = "2222222222222222aaaaaaaaaaaaaaaa\n";
    writefile("/etc/machine-id", mid);
    writefile("/var/lib/dbus/machine-id", mid);

    /* Minimal permissive system bus config (tightened for NM at M4).  --system would read the
     * compiled-in build-prefix config (absent in the VM), so hos-dbus-test / clients point the
     * daemon at this file via --config-file; the config declares <type>system</type> + the
     * standard listen socket, so clients using --system still find the bus. */
    const char *cfg =
        "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n"
        "<busconfig>\n"
        "  <type>system</type>\n"
        "  <listen>unix:path=/run/dbus/system_bus_socket</listen>\n"
        "  <auth>EXTERNAL</auth>\n"
        "  <policy context=\"default\">\n"
        "    <allow user=\"*\"/>\n"
        "    <allow own=\"*\"/>\n"
        "    <allow send_type=\"method_call\"/>\n"
        "    <allow send_type=\"signal\"/>\n"
        "    <allow send_type=\"method_return\"/>\n"
        "    <allow send_type=\"error\"/>\n"
        "    <allow receive_type=\"method_call\"/>\n"
        "    <allow receive_type=\"signal\"/>\n"
        "    <allow receive_type=\"method_return\"/>\n"
        "    <allow receive_type=\"error\"/>\n"
        "  </policy>\n"
        "</busconfig>\n";
    writefile("/etc/dbus-1/system.conf", cfg);

    logline("[dbus-launch] M0: exec dbus-daemon --config-file=/etc/dbus-1/system.conf --nofork (persistent bus)");
    char *argv[] = { "/dbus-daemon", "--config-file=/etc/dbus-1/system.conf", "--nofork", "--print-address", 0 };
    char *envp[] = { "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };
    execve("/dbus-daemon", argv, envp);
    logline("[dbus-launch] execve(/dbus-daemon) FAILED (missing binary/interp/lib?)");
    return 1;
}
