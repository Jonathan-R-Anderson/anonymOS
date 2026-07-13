/*
 * hos-wpa-agent.c — the Wi-Fi menu backend that drives wpa_supplicant DIRECTLY (no NetworkManager,
 * no D-Bus).  Replaces hos-wifi-agent (the NM<->menu D-Bus bridge) on direct-wpa boots.
 *
 * WHY: NetworkManager is a heavyweight daemon that (a) fires thousands of netlink calls to build a
 * "platform cache" and (b) registers its D-Bus name only AFTER that slow init — so on this OS it
 * hangs at `platform-linux: create`, the menu shows "Wi-Fi unavailable", and the NM+dbus+nmcli
 * chain churns CPU and starves Weston.  wpa_supplicant already does the real work (associate +
 * 4-way handshake) with a tiny fraction of the calls, and the kernel-supervised udhcpc gets the
 * lease.  This agent is the thin glue that (1) publishes scan results to the menu and (2) turns a
 * menu connect request into a wpa association — reusing only pieces already proven on the FW13.
 *
 * DATA IN  — scan: the LKL net-provider's NSP_SCAN (hos-net-proto.h) over /run/hos-net.sock returns
 *            the heard SSIDs; we publish them to /run/wifi/networks in the exact byte format the
 *            menu (wl-wifi-menu.c), quick-settings and layer-bar already parse.
 * DATA OUT — connect: the menu writes /run/wifi/connect = "SSID\nPASSWORD\n"; we rewrite wpa's
 *            runtime config /run/wpa-net.conf with that network block and SIGHUP the running
 *            wpa_supplicant (pid in /run/wpa.pid, written by hos-wpa-launch) so it re-reads the
 *            config and associates.  The kernel-supervised udhcpc then leases and writes
 *            /run/wifi/dhcp-ok — which is how the menu learns "connected" (we mirror hos-wifi-agent's
 *            dhcp-ok -> state=100 + active-row synthesis; wpa association status is not queried).
 *
 * Runs under NO LD_PRELOAD (static musl): its provider socket is a plain AF_UNIX (unrouted), and it
 * makes no LKL-routed syscalls.  All waits park in poll() on a real fd (this kernel does NOT block on
 * poll(NULL,0,ms)/nfds==0, and usleep/nanosleep don't park — a busy sleep starves Weston).
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "hos-net-proto.h"

#define WPA_CONF   "/run/wpa-net.conf"
#define WPA_PIDF   "/run/wpa.pid"
#define NET_FILE   "/run/wifi/networks"
#define NET_TMP    "/run/wifi/networks.tmp"
#define CONNECT_F  "/run/wifi/connect"
#define ERROR_F    "/run/wifi/error"
#define DHCP_OK    "/run/wifi/dhcp-ok"

#define MAX_NETS 64
static char  g_ssid[MAX_NETS][64];
static int   g_nnets = 0;
static char  g_connect_ssid[64] = {0};   /* the SSID we last asked wpa to join (for the active/checkmark row) */
static int   g_quietScans = 0;           /* skip scans for a few cycles after a connect: let wpa own the radio */

/* ---- parking: poll() on the read end of a never-written pipe actually blocks on this kernel ---- */
static int g_nap_fd = -1;
static void napms(long ms)
{
    if (g_nap_fd < 0) { int pp[2]; if (pipe(pp) == 0) g_nap_fd = pp[0]; }
    while (ms > 0) {
        int chunk = ms > 60000 ? 60000 : (int)ms;
        struct pollfd p = { g_nap_fd, POLLIN, 0 };
        int rc = poll(&p, 1, chunk);
        if (rc < 0 && errno == EINTR) continue;
        ms -= chunk;
    }
}

/* ---- NSP RPC to the LKL net-provider (framing per hos-net-proto.h) ---- */
/* EpinAnonymOS AF_UNIX read/write are non-blocking (-EAGAIN when empty/full while the peer lives).
 * PARK on the socket fd (poll blocks on a real fd) rather than nanosleep — a 2ms nap-per-byte while
 * waiting for the provider's (slow) scan reply busy-spins a core and starves Weston. */
static void fd_park(int fd, short ev){ struct pollfd p = { fd, ev, 0 }; poll(&p, 1, 1000); }
static int rd_full(int fd, void *b, size_t n){ size_t g=0; while(g<n){long r=read(fd,(char*)b+g,n-g); if(r>0){g+=(size_t)r;continue;} if(r<0&&errno==EAGAIN){fd_park(fd,POLLIN);continue;} return 0;} return 1; }
static int wr_full(int fd, const void *b, size_t n){ size_t p=0; while(p<n){long r=write(fd,(const char*)b+p,n-p); if(r>0){p+=(size_t)r;continue;} if(r<0&&errno==EAGAIN){fd_park(fd,POLLOUT);continue;} return 0;} return 1; }

static int prov_connect(void)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un sa; memset(&sa,0,sizeof sa);
    sa.sun_family = AF_UNIX; strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path)-1);
    if (connect(s,(struct sockaddr*)&sa,sizeof sa) != 0) { close(s); return -1; }
    return s;
}

/* one round-trip; returns resp.ret, fills rbuf/rblen with reply data.  <= -1000 = framing error. */
static long nsp(int s, uint32_t op, int fd, int a0, int a1, int a2,
                void *rbuf, uint32_t rbufmax, uint32_t *rblen)
{
    nsp_req rq; memset(&rq,0,sizeof rq);
    rq.op=op; rq.fd=fd; rq.a0=a0; rq.a1=a1; rq.a2=a2;
    if (!wr_full(s,&rq,sizeof rq)) return -1000;
    nsp_resp rs;
    if (!rd_full(s,&rs,sizeof rs)) return -1001;
    char junk[512];
    if (rs.buflen) {
        uint32_t take = rs.buflen < rbufmax ? rs.buflen : rbufmax;
        if (rbuf && take && !rd_full(s,rbuf,take)) return -1002;
        if (rblen) *rblen = take;
        for (uint32_t left = rs.buflen - take; left; ){ uint32_t c=left<sizeof junk?left:sizeof junk; if(!rd_full(s,junk,c))return -1002; left-=c; }
    } else if (rblen) *rblen = 0;
    if (rs.addrlen) { for (uint32_t left=rs.addrlen; left; ){ uint32_t c=left<sizeof junk?left:sizeof junk; if(!rd_full(s,junk,c))return -1003; left-=c; } }
    return (long)rs.ret;
}

/* ---- scan: ask the provider (NSP_SCAN) for heard SSIDs; dedup into g_ssid[].  Returns -1 on a
 *      transport/framing error (caller drops+reconnects the provider socket), else the AP count. ---- */
static void add_ssid(const char *ss)
{
    if (!ss[0]) return;                          /* skip hidden APs */
    for (int i=0;i<g_nnets;i++) if (!strcmp(g_ssid[i], ss)) return;   /* dedup by SSID */
    if (g_nnets >= MAX_NETS) return;
    snprintf(g_ssid[g_nnets], sizeof g_ssid[0], "%s", ss);
    g_nnets++;
}
static int do_scan(int s)
{
    static char buf[16384];
    uint32_t got = 0;
    long r = nsp(s, NSP_SCAN, -1, 0,0,0, buf, sizeof buf - 1, &got);
    if (r <= -1000) return -1;                   /* framing error -> tell the caller to reconnect */
    if (got == 0) return 0;                      /* valid but nothing heard this cycle — keep the old list */
    if (got >= sizeof buf) got = sizeof buf - 1;
    buf[got] = 0;
    g_nnets = 0;
    /* provider emits "SSID: <name>\n" per heard AP, then a "DONE N AP(s)..." trailer. */
    for (char *line = buf; line && *line; ) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (!strncmp(line, "SSID: ", 6)) {
            const char *nm = line + 6;
            if (strcmp(nm, "(hidden)") != 0) {
                char clean[64]; int j = 0;
                for (const char *p = nm; *p && j < (int)sizeof clean - 1; p++)
                    clean[j++] = (*p=='\t' || *p=='\n') ? ' ' : *p;   /* sanitize field separators */
                clean[j] = 0;
                add_ssid(clean);
            }
        }
        line = nl ? nl + 1 : 0;
    }
    return g_nnets;
}

/* ---- publish /run/wifi/networks in the exact menu format (atomic tmp+rename) ---- */
static void write_networks(void)
{
    int have_lease = (access(DHCP_OK, F_OK) == 0);
    unsigned state = have_lease ? 100u : 30u;    /* 100=connected(lease present) else 30=disconnected */

    int fd = open(NET_TMP, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) return;
    char line[256];
    /* header: #dev<TAB>devpath<TAB>iface<TAB>state  (devpath empty; iface must be non-empty so the
     * menu shows "ready", not "no adapter"; exactly 3 tabs). */
    int m = snprintf(line, sizeof line, "#dev\t\twlan0\t%u\n", state);
    if (m > 0) (void)!write(fd, line, (size_t)m);
    for (int i=0;i<g_nnets;i++) {
        /* active(checkmark) = the SSID we joined once a lease exists (association status here comes
         * from the udhcpc lease marker, not from wpa). */
        int active = (have_lease && g_connect_ssid[0] && !strcmp(g_ssid[i], g_connect_ssid)) ? 1 : 0;
        /* sec="wpa" => the menu opens a password dialog; an OPEN network is chosen by leaving the
         * password blank (do_connect writes key_mgmt=NONE when the password is empty).  strength is
         * a placeholder mid value; real signal + open/secure detection await the nl80211-scan upgrade. */
        m = snprintf(line, sizeof line, "%s\t%u\t%s\t%d\t%s\n", g_ssid[i], 60u, "wpa", active, g_ssid[i]);
        if (m > 0) (void)!write(fd, line, (size_t)m);
    }
    close(fd);
    rename(NET_TMP, NET_FILE);
}

/* ---- connect: menu wrote /run/wifi/connect = "SSID\nPASSWORD\n" ---- */
static int is_hex64(const char *s)
{
    int n = 0;
    for (; *s; s++, n++) { char c = *s;
        if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) return 0; }
    return n == 64;
}
static void set_error(const char *msg)
{
    int ef = open(ERROR_F, O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (ef >= 0) { (void)!write(ef, msg, strlen(msg)); close(ef); }
}
/* returns 1 if a valid config was written (caller should reload wpa), 0 if the creds were rejected
 * (an error was published for the menu; do NOT reload). */
static int write_wpa_conf(const char *ssid, const char *psk)
{
    /* Sanitize: wpa config strings are double-quoted; drop embedded quotes/backslashes/newlines so a
     * crafted SSID/PSK can't break out of the block. */
    char es[128], ep[128]; int j;
    j=0; for (const char *p=ssid; *p && j<(int)sizeof es-1; p++) if (*p!='"'&&*p!='\\'&&*p!='\n'&&*p!='\r') es[j++]=*p; es[j]=0;
    j=0; for (const char *p=psk;  *p && j<(int)sizeof ep-1; p++) if (*p!='"'&&*p!='\\'&&*p!='\n'&&*p!='\r') ep[j++]=*p; ep[j]=0;

    /* wpa enforces SSID length 1..32 (SSID_MAX_LEN) and rejects the whole config otherwise, which
     * terminates the one-shot wpa process.  Scanned SSIDs are capped at 32 upstream, but guard here
     * too so a malformed request can never emit a config wpa would reject. */
    if (es[0] == 0 || strlen(es) > 32) { set_error("Invalid network name"); return 0; }

    char cfg[512]; int m;
    if (ep[0]) {                                 /* secured (WPA-PSK) */
        size_t pl = strlen(ep);
        int hex = is_hex64(ep);
        if (!hex && (pl < 8 || pl > 63)) {       /* wpa rejects a passphrase outside 8..63 -> reject up front */
            set_error("Password must be 8-63 characters");
            return 0;
        }
        if (hex)                                 /* 64 hex chars = a raw PMK: no quotes */
            m = snprintf(cfg, sizeof cfg,
                "update_config=0\nap_scan=1\nnetwork={\n\tssid=\"%s\"\n\tpsk=%s\n\tkey_mgmt=WPA-PSK\n\tscan_ssid=1\n}\n", es, ep);
        else                                     /* passphrase: quoted */
            m = snprintf(cfg, sizeof cfg,
                "update_config=0\nap_scan=1\nnetwork={\n\tssid=\"%s\"\n\tpsk=\"%s\"\n\tkey_mgmt=WPA-PSK\n\tscan_ssid=1\n}\n", es, ep);
    } else {                                     /* open network */
        m = snprintf(cfg, sizeof cfg,
            "update_config=0\nap_scan=1\nnetwork={\n\tssid=\"%s\"\n\tkey_mgmt=NONE\n\tscan_ssid=1\n}\n", es);
    }
    int fd = open(WPA_CONF, O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (fd < 0) { set_error("Could not write Wi-Fi config"); return 0; }
    if (m > 0) (void)!write(fd, cfg, (size_t)m);
    close(fd);
    return 1;
}

/* SIGHUP the running wpa_supplicant so it re-reads WPA_CONF and associates to the new network. */
static void reload_wpa(void)
{
    int fd = open(WPA_PIDF, O_RDONLY);
    if (fd < 0) return;
    char b[32]; int n = (int)read(fd, b, sizeof b - 1); close(fd);
    if (n <= 0) return;
    b[n] = 0;
    long pid = atol(b);
    if (pid > 1) kill((int)pid, SIGHUP);
}

static int check_connect(void)
{
    int fd = open(CONNECT_F, O_RDONLY);
    if (fd < 0) return 0;
    char buf[512];
    int n = (int)read(fd, buf, sizeof buf - 1);
    close(fd);
    unlink(CONNECT_F);                            /* consume destructively */
    if (n <= 0) return 0;
    buf[n] = 0;
    char ssid[128] = {0}, psk[128] = {0};
    char *nl = strchr(buf, '\n');
    if (nl) { *nl = 0; snprintf(ssid, sizeof ssid, "%s", buf);
              char *p2 = nl+1; char *nl2 = strchr(p2,'\n'); if (nl2) *nl2=0; snprintf(psk, sizeof psk, "%s", p2); }
    else    { snprintf(ssid, sizeof ssid, "%s", buf); }
    if (!ssid[0]) return 0;

    unlink(DHCP_OK);                              /* stale lease must not mark the new attempt "connected" */
    unlink(ERROR_F);                              /* clear any previous failure */
    snprintf(g_connect_ssid, sizeof g_connect_ssid, "%s", ssid);
    if (write_wpa_conf(ssid, psk)) {
        reload_wpa();                             /* valid creds -> tell wpa to associate */
        g_quietScans = 4;                         /* give wpa the radio to associate (no scan contention) */
    } else {
        g_connect_ssid[0] = 0;                    /* rejected creds: don't leave a phantom pending SSID */
    }
    return 1;
}

/* On a boot-seeded association (creds from /epin-debug-net.conf baked into /run/wpa-net.conf by
 * hos-wpa-launch), no menu connect ran, so g_connect_ssid is empty and the checkmark would never
 * light even with a lease.  Seed it from the config's ssid=. */
static void seed_connect_ssid(void)
{
    int fd = open(WPA_CONF, O_RDONLY);
    if (fd < 0) return;
    char b[512]; int n = (int)read(fd, b, sizeof b - 1); close(fd);
    if (n <= 0) return; b[n] = 0;
    char *p = strstr(b, "ssid=\"");
    if (!p) return;
    p += 6;
    char *q = strchr(p, '"');
    if (!q) return;
    int len = (int)(q - p);
    if (len > 0 && len < (int)sizeof g_connect_ssid) { memcpy(g_connect_ssid, p, len); g_connect_ssid[len] = 0; }
}

int main(void)
{
    mkdir("/run", 0755);
    mkdir("/run/wifi", 0755);
    seed_connect_ssid();

    int s = -1, cyc = 0;
    for (;;) {
        if (s < 0) { s = prov_connect(); if (s < 0) { napms(1000); continue; } }

        if (check_connect()) write_networks();    /* service a pending connect promptly */

        /* Scan cadence: freely while disconnected (finding networks), but back off once a lease
         * exists (~every 6th cycle) and stay quiet for a few cycles right after a connect — an
         * agent-triggered WEXT scan contends with wpa's own nl80211 scan / active association. */
        int have_lease = (access(DHCP_OK, F_OK) == 0);
        if (g_quietScans > 0) {
            g_quietScans--;
        } else if (!have_lease || (cyc % 6) == 0) {
            if (do_scan(s) < 0) { close(s); s = -1; }   /* provider dropped -> reconnect next cycle */
        }
        write_networks();

        /* ~5s outer cadence, but poll /run/wifi/connect every 200ms so a click acts fast. */
        for (int k = 0; k < 25; k++) {
            if (check_connect()) write_networks();
            napms(200);
        }
        cyc++;
    }
    return 0;
}
