/*
 * hos-nmcli-test.c -- "boot-doctor": diagnose the dbus/provider/NetworkManager launch chain and write
 * the verdict to /run/boot-status.txt (static-musl).  Runs UNGATED at boot (not gated on NM having
 * launched), because the open question is exactly whether NM launched at all.  ps / /proc/comm /
 * /proc/cmdline / dmesg are all unimplemented on this kernel and ls can't see AF_UNIX sockets, so this
 * probes by connect()ing directly:
 *   - /run/dbus/system_bus_socket   (is the system bus up?)
 *   - /run/hos-net.sock             (did lkl-boot's provider come up? = the gate NM waits on)
 *   - org.freedesktop.NetworkManager Version via dbus-send (did NM register?)
 * The verdict file is overwritten each iteration; `cat /run/boot-status.txt` in a terminal shows it.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <dirent.h>
#include "hos-net-proto.h"

static void napms(long ms){ struct timespec t = { ms/1000, (ms%1000)*1000000L }; nanosleep(&t, 0); }

/* connect to an AF_UNIX path; return 0 on success else the positive errno. */
static int probe_connect(const char *path){
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return errno;
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX; strncpy(sa.sun_path, path, sizeof(sa.sun_path)-1);
    int r = connect(s, (struct sockaddr*)&sa, sizeof sa);
    int e = errno; close(s);
    return r == 0 ? 0 : e;
}
/* ENOENT(2) = socket absent (listener down); EACCES/EPERM = present but cap-gated; ECONNREFUSED = stale. */
static const char *present(int e){ return (e == 0 || e == EACCES || e == EPERM || e == ECONNREFUSED) ? "PRESENT" : "absent"; }

static int nm_registered(void){
    pid_t p = fork();
    if (p == 0) {
        int nul = open("/dev/null", O_WRONLY); if (nul >= 0){ dup2(nul,1); dup2(nul,2); }
        char *argv[] = { "/dbus-send", "--system", "--print-reply",
                         "--dest=org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager",
                         "org.freedesktop.DBus.Properties.Get",
                         "string:org.freedesktop.NetworkManager", "string:Version", 0 };
        char *envp[] = { "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };
        execve("/dbus-send", argv, envp); _exit(127);
    }
    if (p < 0) return 0;
    int st = 0; waitpid(p, &st, 0);
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 1 : 0;
}

/* Run argv (a /dbus-send invocation), capture its stdout+stderr into buf, return child exit code. */
static int run_capture(char *const argv[], char *buf, int buflen){
    int pfd[2]; if (pipe(pfd) != 0) return -1;
    pid_t p = fork();
    if (p == 0){ close(pfd[0]); dup2(pfd[1],1); dup2(pfd[1],2); close(pfd[1]);
        char *envp[] = { "PATH=/", "HOME=/", "LD_LIBRARY_PATH=/", 0 };
        execve(argv[0], argv, envp); _exit(127); }
    if (p < 0){ close(pfd[0]); close(pfd[1]); return -1; }
    close(pfd[1]);
    int total=0, r; while (total < buflen-1 && (r=read(pfd[0], buf+total, buflen-1-total))>0) total+=r;
    buf[total]=0; close(pfd[0]);
    int st=0; waitpid(p,&st,0); return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}
static void emit(const char *s){ (void)!write(2, s, strlen(s)); (void)!write(1, s, strlen(s)); }
static int extract_objpath(const char *reply, char *out, int outlen){
    const char *p = strstr(reply, "object path"); if (!p) return 0;
    p = strchr(p, '"'); if (!p) return 0; p++;
    int i=0; while (*p && *p!='"' && i<outlen-1) out[i++]=*p++; out[i]=0; return i>0;
}
/* Ask NM whether it sees + manages wlan0 (DeviceType 2 = WIFI, State: 10=unmanaged 20=unavailable
 * 30=disconnected 100=activated).  Answers the M3 question: does NM manage the (hwsim) wifi device? */
/* List /sys/class/net so we know what sysfs entries exist (NM's platform reads these to classify a device
 * as wifi via wireless/phy80211; a rtnetlink-only interface with no sysfs entry is often skipped). */
static void probe_sysfs_net(void){
    emit("=== /sys/class/net entries ===\n");
    DIR *d = opendir("/sys/class/net");
    if (!d) { emit("(/sys/class/net absent -> NM has NO sysfs to classify devices)\n"); return; }
    struct dirent *e; int n=0;
    while ((e = readdir(d))) { if (e->d_name[0]=='.') continue; emit("  "); emit(e->d_name);
        char p[256]; snprintf(p,sizeof p,"/sys/class/net/%s/phy80211", e->d_name);
        struct stat st; if (stat(p,&st)==0) emit("  [has phy80211 = WIFI]"); emit("\n"); n++; }
    closedir(d);
    if (!n) emit("(empty)\n");
}
static void probe_wifi(void){
    static char reply[16384];
    char *ad[] = { "/dbus-send","--system","--print-reply","--dest=org.freedesktop.NetworkManager",
                   "/org/freedesktop/NetworkManager","org.freedesktop.NetworkManager.GetAllDevices", 0 };
    run_capture(ad, reply, sizeof reply);
    emit("=== NM GetAllDevices (every device NM enumerated) ===\n"); emit(reply); emit("\n");
    char *a1[] = { "/dbus-send","--system","--print-reply","--dest=org.freedesktop.NetworkManager",
                   "/org/freedesktop/NetworkManager","org.freedesktop.NetworkManager.GetDeviceByIpIface",
                   "string:wlan0", 0 };
    int rc = run_capture(a1, reply, sizeof reply);
    emit("\n=== NM WIFI PROBE: GetDeviceByIpIface(wlan0) ===\n"); emit(reply); emit("\n");
    if (rc != 0){ emit("VERDICT: NM does NOT see wlan0 (unmanaged/absent) -> no wifi backend\n"); return; }
    char path[256];
    if (!extract_objpath(reply, path, sizeof path)){ emit("(could not parse device path)\n"); return; }
    char *a2[] = { "/dbus-send","--system","--print-reply","--dest=org.freedesktop.NetworkManager",
                   path, "org.freedesktop.DBus.Properties.GetAll",
                   "string:org.freedesktop.NetworkManager.Device", 0 };
    run_capture(a2, reply, sizeof reply);
    emit("=== wlan0 Device props (look: DeviceType=2 wifi, State, Managed) ===\n"); emit(reply); emit("\n");
}
/* Echo the device/wifi-relevant lines of NM's own debug log (redirected to /run/nm.log by hos-nm-launch)
 * to the serial, so we can see WHY NM does or doesn't enumerate/manage wlan0. */
static void emit_nm_log(void){
    int fd = open("/run/nm.log", O_RDONLY);
    if (fd < 0){ emit("(/run/nm.log absent -- NM log redirect failed)\n"); return; }
    static char buf[131072]; int total=0, r;
    while (total < (int)sizeof buf - 1 && (r=read(fd, buf+total, sizeof buf-1-total))>0) total+=r;
    buf[total]=0; close(fd);
    emit("=== NM log: lines naming an interface / device (/run/nm.log) ===\n");
    static const char *keys[] = { "wlan", "Wi-Fi", "wifi", "802-11", "unmanaged", "unavailable",
                                  "unknown", "phy", "manage", "supplicant", "rfkill", "nl80211",
                                  "ifindex", "iface", "link ", "(lo)", "(eth", "ethernet", "device added",
                                  "found device", "device[", "l3cfg", "new device", "nl-link:",
                                  "m3-link", 0 };
    char *line = buf; int emitted = 0;
    while (line && *line){
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        int hit = 0; for (int i=0; keys[i]; i++) if (strstr(line, keys[i])) { hit=1; break; }
        if (hit){ emit(line); emit("\n"); if (++emitted > 150) { emit("...(truncated)\n"); break; } }
        line = nl ? nl+1 : 0;
    }
    if (!emitted) emit("(no interface lines matched)\n");
    /* Also dump the raw tail so we see the full picture regardless of keyword matching. */
    emit("=== NM log RAW TAIL (last ~16KB) ===\n");
    int tailoff = total > 16000 ? total - 16000 : 0;
    emit(buf + tailoff);
    emit("\n=== end NM log ===\n");
}

/* M5: echo wpa_supplicant's own debug log (redirected to /run/wpa.log by hos-wpa-launch) so we can see
 * whether NM's CreateInterface(wlan0) reached wpa and what wpa did with the (hwsim) radio. */
static void emit_wpa_log(void){
    int fd = open("/run/wpa.log", O_RDONLY);
    if (fd < 0){ emit("(/run/wpa.log absent -- wpa not started or redirect failed)\n"); return; }
    static char wbuf[131072]; int total=0, r;
    while (total < (int)sizeof wbuf - 1 && (r=read(fd, wbuf+total, sizeof wbuf-1-total))>0) total+=r;
    wbuf[total]=0; close(fd);
    emit("=== wpa_supplicant log RAW TAIL (last ~20KB of /run/wpa.log) ===\n");
    int tailoff = total > 20000 ? total - 20000 : 0;
    emit(wbuf + tailoff);
    emit("\n=== end wpa log ===\n");
}

/* M6: echo /run/wifi/networks (what hos-wifi-agent bridged from NM) so we can see the menu's data. */
static void emit_wifi_networks(void){
    int fd = open("/run/wifi/networks", O_RDONLY);
    if (fd < 0){ emit("=== /run/wifi/networks ABSENT (wifi-agent not up yet) ===\n"); return; }
    static char nbuf[16384]; int total=0, r;
    while (total < (int)sizeof nbuf - 1 && (r=read(fd, nbuf+total, sizeof nbuf-1-total))>0) total+=r;
    nbuf[total]=0; close(fd);
    emit("=== /run/wifi/networks (hos-wifi-agent output) ===\n"); emit(nbuf);
    emit("=== end wifi networks ===\n");
}

static void write_one(const char *path, const char *s){
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) { (void)!write(fd, s, strlen(s)); close(fd); }
}
/* EpinAnonymOS AF_UNIX read/write are NON-blocking (return -1/EAGAIN when the rx buffer is empty or the
 * tx buffer is full while the peer is still open), so emulate blocking by retrying on EAGAIN with a short
 * nap.  A plain `read()>0` loop bails the instant the provider hasn't replied yet -> false failure. */
static int read_full(int fd, void *buf, int n){
    int got = 0;
    for (int spins = 0; got < n && spins < 3000; ) {
        int r = read(fd, (char*)buf + got, n - got);
        if (r > 0) { got += r; spins = 0; continue; }
        if (r < 0 && errno == EAGAIN) { napms(2); spins++; continue; }
        break;   /* r==0 (EOF) or a real error */
    }
    return got == n;
}
static int write_full(int fd, const void *buf, int n){
    int put = 0;
    for (int spins = 0; put < n && spins < 3000; ) {
        int r = write(fd, (const char*)buf + put, n - put);
        if (r > 0) { put += r; spins = 0; continue; }
        if (r < 0 && errno == EAGAIN) { napms(2); spins++; continue; }
        break;
    }
    return put == n;
}
/* Fetch the shim's netlink trace from the net-provider (NSP_GETTRACE) and write it where the sandboxed
 * terminal can read it.  The shim ships its trace lines to the provider over the (safe) socket; the
 * provider accumulates them in memory.  We — a separate, file-safe process — pull them and write the file,
 * so nothing in NM's fault-prone LD_PRELOAD context ever touches the filesystem.  Retry the connect: the
 * provider's tiny accept backlog often refuses the first attempt. */
static void note(const char *dst, const char *s){   /* write a note to BOTH the file and the boot log */
    write_one(dst, s);
    (void)!write(1, s, strlen(s)); (void)!write(2, s, strlen(s));
}
static void fetch_trace(const char *dst){
    static char buf[NSP_MAXBUF];
    int s = -1, tries = 0;
    for (int i = 0; i < 200; i++) {
        tries = i + 1;
        s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s < 0) { napms(20); continue; }
        struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
        sa.sun_family = AF_UNIX; strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path)-1);
        if (connect(s, (struct sockaddr*)&sa, sizeof sa) == 0) break;
        close(s); s = -1; napms(20);
    }
    if (s < 0) { note(dst, "gettrace: (could not connect to net-provider)\n"); return; }

    nsp_req rq; memset(&rq, 0, sizeof rq); rq.op = NSP_GETTRACE;
    nsp_resp rs; memset(&rs, 0, sizeof rs);
    int wok = write_full(s, &rq, sizeof rq);
    int rok = wok && read_full(s, &rs, sizeof rs);
    { char d[128]; snprintf(d,sizeof d,"gettrace: dst=%s connect_try=%d write_ok=%d reply_ok=%d ret=%lld buflen=%u\n",
                           dst, tries, wok, rok, (long long)rs.ret, rs.buflen); (void)!write(2,d,strlen(d)); (void)!write(1,d,strlen(d)); }
    if (!rok) { close(s); note(dst, "gettrace: (request/reply failed)\n"); return; }
    unsigned n = rs.buflen; if (n > sizeof buf) n = sizeof buf;
    if (n && !read_full(s, buf, n)) { close(s); note(dst, "gettrace: (truncated reply)\n"); return; }
    close(s);
    if (!n) { note(dst, "gettrace: (provider trace is EMPTY -- NM sent no OVER-CAP/STUCK line)\n"); return; }
    int out = open(dst, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (out >= 0) { (void)!write(out, buf, n); close(out); }
    /* Also echo to stdout/stderr: the boot-doctor's output reaches the framebuffer boot log, so the
     * discriminator is visible even if the terminal/desktop never comes up or crashes. */
    (void)!write(1, "=== shim netlink trace (from net-provider) ===\n", 47);
    (void)!write(1, buf, n);
    (void)!write(2, buf, n);
}
static void write_status(const char *s){
    write_one("/run/boot-status.txt", s);
    write_one("/tmp/boot-status.txt", s);   /* /tmp is a plain ramfs; /run might not persist here */
    (void)!write(1, s, strlen(s));           /* stdout + stderr, in case one is redirected */
    (void)!write(2, s, strlen(s));
}
/* Append "hdr (N bytes):\n<last ~1400 bytes of path>" into dst; reports absence/size so we can tell
 * "NM never wrote a log" (0 bytes) from "log not materialized/absent". */
static int tail_append(const char *path, const char *hdr, char *dst, int cap){
    if (cap < 64) return 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return snprintf(dst, cap, "\n%s: NOT PRESENT (errno %d)\n", hdr, errno);
    long sz = (long)lseek(fd, 0, SEEK_END);
    long start = sz > 1400 ? sz - 1400 : 0; lseek(fd, start, SEEK_SET);
    int hn = snprintf(dst, cap, "\n%s (%ld bytes):\n", hdr, sz);
    int n = (int)read(fd, dst + hn, cap - hn - 1); close(fd);
    if (n < 0) n = 0; dst[hn + n] = 0;
    return hn + n;
}

int main(void)
{
    (void)!write(1, "boot-doctor: starting checks...\n", 31);
    (void)!write(2, "boot-doctor: starting checks...\n", 31);
    /* DEBUG BOOTS bypass NetworkManager (direct wpa_supplicant), so NM never registers and this 20-iter
     * NM poll just churns dbus-daemon (part of the freeze storm) toward a foregone "NM stuck" verdict.
     * Skip it on the direct-wpa path. */
    if (access("/epin-debug-net.conf", F_OK) == 0) {
        const char *m = "boot-doctor: debug-net boot -> skipping NM poll (direct wpa)\n";
        (void)!write(2, m, strlen(m));
        return 0;
    }
    /* Check the two sockets ONCE (each connect spawns a provider handler thread; don't churn them).
     * Their state doesn't change once up.  Then poll NM (dbus-send forks are reaped via wait4). */
    int db = probe_connect("/run/dbus/system_bus_socket");
    int pv = probe_connect("/run/hos-net.sock");
    const int prov_absent = (strcmp(present(pv), "absent") == 0);
    int ok = 0;
    for (int i = 1; i <= 20; i++) {
        int nm = nm_registered();
        const char *verdict =
            nm ? "NM IS UP + registered -- the full stack works on real hardware (M2b OK)."
          : (strcmp(present(pv), "absent") == 0)
               ? "PROVIDER SOCKET ABSENT -> lkl-boot's net-provider never came up -> NM's launch gate never fires. Chase LKL/provider."
          : (strcmp(present(db), "absent") == 0)
               ? "dbus socket absent -> the system bus did not start."
               : "provider+dbus PRESENT but NM not registered -> NM launched but is stuck/crashed before D-Bus.";
        char buf[640];
        snprintf(buf, sizeof buf,
            "=== EpinAnonymOS boot-doctor (iter %d/20) ===\n"
            "dbus   /run/dbus/system_bus_socket : %s (errno %d)\n"
            "prov   /run/hos-net.sock           : %s (errno %d)\n"
            "NM     registered on the bus       : %s\n"
            "VERDICT: %s\n",
            i, present(db), db, present(pv), pv, nm ? "YES" : "no", verdict);
        write_status(buf);
        if (nm) { ok = 1; break; }
        if (prov_absent) break;      /* NM can't launch without the provider — verdict won't change */
        napms(3000);
    }
    /* NM never registered (the laptop "no adapter" case): fold NM's + wpa's log tails into the ONE file
     * the user can read in-window (there is no terminal, and NM's held-open /run/nm.log may not be listable
     * on its own).  The last line = WHERE NM stalled before D-Bus.  Give NM a moment to write more first. */
    if (!ok && !prov_absent) {
        napms(8000);   /* let NM's stuck netlink recv hit the shim's STUCK detector (tries 1/5/30) */
        /* Pull the shim's STUCK trace from the provider (which netlink op NM waits on + whether the
         * provider is even replying) into a materialized file, then fold everything into boot-status. */
        fetch_trace("/run/nm-provtrace.txt");
        static char big[5400];
        int p = snprintf(big, sizeof big,
            "=== boot-doctor: NM stuck before D-Bus (stalls at 'populate platform cache' -> 1st netlink dump) ===\n"
            "dbus=%s prov=%s\n", present(db), present(pv));
        p += tail_append("/run/nm-provtrace.txt", "--- shim netlink STUCK trace (op NM waits on) ---", big + p, (int)sizeof(big) - p);
        p += tail_append("/run/nm.log", "--- /run/nm.log (tail) ---", big + p, (int)sizeof(big) - p);
        write_status(big);
    }
    /* M3/M4: once NM is up, ask it whether it sees + manages wlan0 (the hwsim device in QEMU / the AX210
     * on hardware).  Give NM a few seconds to enumerate devices first, then probe twice (scan may take a
     * moment to register the interface). */
    if (ok) {
        napms(5000);
        probe_sysfs_net();
        probe_wifi();
        napms(20000);   /* M5: give NM time to manage wlan0 + create the wpa iface + first scan */
        emit("--- re-probe after 20s (device may have settled) ---\n");
        probe_sysfs_net();
        probe_wifi();
        emit_nm_log();   /* M3: echo NM's log incl. the shim's nl-link: RTM_NEWLINK ifname dump */
        emit_wpa_log();  /* M5: echo wpa_supplicant's log (CreateInterface + hwsim radio) */
        emit_wifi_networks(); /* M6: echo hos-wifi-agent's /run/wifi/networks (the menu's data) */
    }
    return ok ? 0 : 1;
}
