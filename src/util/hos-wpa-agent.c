/*
 * hos-wpa-agent.c — the Wi-Fi menu backend that drives wpa_supplicant DIRECTLY (no NetworkManager,
 * no D-Bus).  Replaces hos-wifi-agent (the NM<->menu D-Bus bridge) on direct-wpa boots.
 *
 * WHY: NetworkManager is a heavyweight daemon that hangs at its platform-cache init, registers its
 * D-Bus name too late, and churns CPU.  wpa_supplicant already does the real work (associate + 4-way)
 * with a fraction of the calls, and the kernel-supervised udhcpc gets the lease.  This agent is the
 * thin glue that (1) publishes scan results to the menu and (2) turns a menu connect request into a
 * wpa association.
 *
 * SCAN — nl80211 NL80211_CMD_GET_SCAN (the exact generic-netlink path wpa_supplicant uses): a routed
 * AF_NETLINK socket through the LKL provider (/run/hos-net.sock, framed NSP RPC per hos-net-proto.h)
 * DUMPs the cfg80211 BSS cache (populated by wpa's own scans AND our own nl80211 TRIGGER_SCAN). It
 * reads the cache FIRST each cycle (results land ~1-5s after a trigger) and TRIGGERs a fresh scan only
 * while it OWNS the radio — disconnected AND not mid-association — so it never knocks wpa off-channel
 * during its scan/4-way (never a raw WEXT SIOCSIWSCAN — nl80211 only, no WEXT conflict). It
 * carries signal (BSS_SIGNAL_MBM) + security (RSN/WPA IEs + capability privacy bit).  Ported from the
 * proven hos-wifi.c H1b client.  Results -> /run/wifi/networks in the exact byte format wl-wifi-menu,
 * wl-quicksettings and wl-layer-bar parse.
 * CONNECT — the menu writes /run/wifi/connect = "SSID\nPASSWORD\n"; we atomically replace
 * /run/wpa-net.conf and SIGHUP the already-running wpa (pid in /run/wpa.pid).  Keeping that process
 * alive is important: it already owns initialized nl80211 route/event sockets and the radio.  A
 * process restart needlessly tears those down and can block while recreating them through the
 * provider.  The kernel-supervised udhcpc then leases and writes /run/wifi/dhcp-ok.
 *
 * Runs static-musl, NO LD_PRELOAD: its provider socket is a plain AF_UNIX (unrouted); the LKL only
 * sees the NSP RPC payload.  All waits park in poll() on a real fd (poll(NULL,0,ms)/nfds==0 and
 * usleep/nanosleep do NOT park on this kernel — a busy sleep starves Weston).
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

/* --- netlink / rtnetlink / nl80211 uABI (stable; defined inline, per hos-wifi.c) --- */
#define NL_AF_NETLINK   16
#define NL_SOCK_RAW      3
#define NL_NETLINK_ROUTE 0
#define NL_NETLINK_GENERIC 16
#define RTM_GETLINK     18
#define RTM_NEWLINK     16
#define NLM_F_REQUEST 0x0001
#define NLM_F_ACK     0x0004
#define NLM_F_DUMP    0x0300
#define NLMSG_ERROR      2
#define NLMSG_DONE       3
#define IFLA_IFNAME      3
#define NLA(x) (((x) + 3) & ~3)
#define GENL_ID_CTRL       16
#define CTRL_CMD_GETFAMILY  3
#define CTRL_ATTR_FAMILY_ID 1
#define CTRL_ATTR_FAMILY_NAME 2
#define NL80211_CMD_GET_SCAN 32
#define NL80211_CMD_TRIGGER_SCAN 33
#define NL80211_ATTR_IFINDEX 3
#define NL80211_ATTR_SCAN_SSIDS 45
#define NL80211_ATTR_BSS     47
#define NL80211_BSS_CAPABILITY           5
#define NL80211_BSS_INFORMATION_ELEMENTS 6
#define NL80211_BSS_SIGNAL_MBM           7
#define WLAN_EID_SSID 0
#define WLAN_EID_RSN  48
#define WLAN_EID_VENDOR 221
#define IOCTL_SIOCGIFFLAGS 0x8913
#define IOCTL_SIOCSIFFLAGS 0x8914
#define NET_IFF_UP 0x1
struct nl_hdr  { uint32_t len; uint16_t type; uint16_t flags; uint32_t seq; uint32_t pid; };
struct nl_ifi  { uint8_t family; uint8_t pad; uint16_t type; int32_t index; uint32_t flags; uint32_t change; };
struct nl_rta  { uint16_t len; uint16_t type; };
struct nl_addr { uint16_t family; uint16_t pad; uint32_t pid; uint32_t groups; };
struct genl_hdr { uint8_t cmd; uint8_t version; uint16_t reserved; };
/* Linux x86_64 struct ifreq: IFNAMSIZ name followed by a 24-byte union. */
struct net_ifreq { char name[16]; union { int16_t flags; unsigned char pad[24]; } u; };
_Static_assert(sizeof(struct net_ifreq) == 40, "Linux ifreq ABI size");

#define WPA_CONF   "/run/wpa-net.conf"
#define WPA_TMP    "/run/wpa-net.conf.tmp"
#define WPA_PIDF   "/run/wpa.pid"
#define WPA_READY  "/run/wpa-ready"
#define NET_FILE   "/run/wifi/networks"
#define NET_TMP    "/run/wifi/networks.tmp"
#define CONNECT_F  "/run/wifi/connect"
#define ERROR_F    "/run/wifi/error"
#define DHCP_OK    "/run/wifi/dhcp-ok"

#define MAX_NETS 64
static char  g_ssid[MAX_NETS][64];
static int   g_sig[MAX_NETS];             /* 0..100 signal strength */
static char  g_sec[MAX_NETS][8];          /* "open" / "wep" / "wpa" / "wpa2" */
static int   g_nnets = 0;
static int   g_ifindex = -1;              /* wlan0 ifindex (resolved once) */
static int   g_famid   = -1;              /* nl80211 generic-netlink family id (resolved once) */
static int   g_linkUpLogged = 0;
static char  g_connect_ssid[64] = {0};    /* the SSID we last asked wpa to join (for the active/checkmark row) */
static int   g_cyc = 0;                   /* main-loop cycle counter (file-scope for the assoc-timeout gate) */
static int   g_scanRetained = 0;          /* latest empty scan kept the last known-good network rows */
static int   g_connectCyc = -1000;        /* cycle of the last connect (menu or boot-seed); the agent goes
                                             read-only for a BOUNDED window after, so it never triggers a scan
                                             that knocks wpa off-channel mid-association. Bounded so a FAILED
                                             connect still resumes scanning instead of leaving the menu empty. */

/* Diagnostic log -> /run/wpa-agent.log (writes to a /run log file are mirrored into /run/klog, so this
 * is visible in the Logs app (SUPER+L) and on serial — the only window into a real-HW run). */
static void slog(const char *m)
{
    int fd = open("/run/wpa-agent.log", O_CREAT|O_WRONLY|O_APPEND, 0644);
    if (fd < 0) return;
    (void)!write(fd, "[wpa-agent] ", 12);
    (void)!write(fd, m, strlen(m));
    (void)!write(fd, "\n", 1);
    close(fd);
}

/* Live one-line status published to /run/wifi/agent-status — wl-wifi-menu shows it in the menu when
 * the network list is empty, so the user can SEE where the scan stands (adapter/nl80211/scan count)
 * without a terminal or the Logs app.  Also mirrored to the log. */
static char g_diag[192] = {0};
static void set_diag(const char *m)
{
    if (!strcmp(g_diag, m)) return;                 /* unchanged — don't rewrite/relog */
    snprintf(g_diag, sizeof g_diag, "%s", m);
    slog(m);
    int fd = open("/run/wifi/agent-status.tmp", O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) return;
    (void)!write(fd, g_diag, strlen(g_diag));
    close(fd);
    rename("/run/wifi/agent-status.tmp", "/run/wifi/agent-status");
}

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
/* PARK on the socket fd rather than spinning.  Do not interpret a count of poll wakeups as elapsed
 * time: EpinAnonymOS may wake poll spuriously, which made a long but bounded NSP_SCAN hit the old
 * "20 wakeups" limit almost immediately.  Provider-side scans have their own 15-second deadline;
 * EOF or a real read/write error still terminates the RPC and drives the reconnect path. */
static void fd_park(int fd, short ev){ struct pollfd p = { fd, ev, 0 }; poll(&p, 1, 1000); }
static int rd_full(int fd, void *b, size_t n){ size_t g=0; while(g<n){long r=read(fd,(char*)b+g,n-g); if(r>0){g+=(size_t)r; continue;} if(r<0&&errno==EAGAIN){fd_park(fd,POLLIN); continue;} return 0;} return 1; }
static int wr_full(int fd, const void *b, size_t n){ size_t p=0; while(p<n){long r=write(fd,(const char*)b+p,n-p); if(r>0){p+=(size_t)r; continue;} if(r<0&&errno==EAGAIN){fd_park(fd,POLLOUT); continue;} return 0;} return 1; }

static int prov_connect(void)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un sa; memset(&sa,0,sizeof sa);
    sa.sun_family = AF_UNIX; strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path)-1);
    if (connect(s,(struct sockaddr*)&sa,sizeof sa) != 0) { close(s); return -1; }
    /* Keep the native provider stream blocking.  During real AX210 firmware startup the single LKL
     * CPU can legitimately take more than the client-side EAGAIN budget to answer RTM_GETLINK;
     * forcing O_NONBLOCK made the agent abandon that healthy first request and report a false
     * provider error.  Potentially slow scan/link-up exchanges use their own connections below, so
     * a delayed reply there cannot desynchronise this main control stream. */
    return s;
}

/* one round-trip (full form: optional send buf+addr, optional reply buf+addr).  <= -1000 = framing error. */
static long nsp(int s, uint32_t op, int fd, int a0, int a1, int a2,
                const void *sbuf, uint32_t sblen, const void *saddr, uint32_t salen,
                void *rbuf, uint32_t rbufmax, uint32_t *rblen,
                void *raddr, uint32_t raddrmax, uint32_t *ralen)
{
    nsp_req rq; memset(&rq,0,sizeof rq);
    rq.op=op; rq.fd=fd; rq.a0=a0; rq.a1=a1; rq.a2=a2; rq.buflen=sblen; rq.addrlen=salen;
    if (!wr_full(s,&rq,sizeof rq)) return -1000;
    if (sblen && !wr_full(s,sbuf,sblen)) return -1000;
    if (salen && !wr_full(s,saddr,salen)) return -1000;
    nsp_resp rs;
    if (!rd_full(s,&rs,sizeof rs)) return -1001;
    char junk[512];
    if (rs.buflen) {
        uint32_t take = rs.buflen < rbufmax ? rs.buflen : rbufmax;
        if (rbuf && take && !rd_full(s,rbuf,take)) return -1002;
        if (rblen) *rblen = take;
        for (uint32_t left = rs.buflen - take; left; ){ uint32_t c=left<sizeof junk?left:sizeof junk; if(!rd_full(s,junk,c))return -1002; left-=c; }
    } else if (rblen) *rblen = 0;
    if (rs.addrlen) {
        uint32_t take = rs.addrlen < raddrmax ? rs.addrlen : raddrmax;
        if (raddr && take && !rd_full(s,raddr,take)) return -1003;
        if (ralen) *ralen = take;
        for (uint32_t left = rs.addrlen - take; left; ){ uint32_t c=left<sizeof junk?left:sizeof junk; if(!rd_full(s,junk,c))return -1003; left-=c; }
    } else if (ralen) *ralen = 0;
    return (long)rs.ret;
}

/* rtnetlink RTM_GETLINK dump -> wlan0's ifindex, or -1. (ported from hos-wifi.c) */
static int __attribute__((unused)) resolve_ifindex(int s)
{
    long nfd = nsp(s, NSP_SOCKET, -1, NL_AF_NETLINK, NL_SOCK_RAW, NL_NETLINK_ROUTE, 0,0,0,0, 0,0,0,0,0,0);
    if (nfd < 0) return -1;
    struct nl_addr sa; memset(&sa,0,sizeof sa); sa.family = NL_AF_NETLINK;
    nsp(s, NSP_BIND, (int)nfd, 0,0,0, 0,0, &sa, sizeof sa, 0,0,0,0,0,0);
    unsigned char req[64]; memset(req,0,sizeof req);
    struct nl_hdr *h = (struct nl_hdr *)req;
    struct nl_ifi *ifi = (struct nl_ifi *)(req + NLA(sizeof *h));
    h->len = NLA(sizeof *h) + (uint32_t)sizeof *ifi; h->type = RTM_GETLINK;
    h->flags = NLM_F_REQUEST | NLM_F_DUMP; h->seq = 1; ifi->family = 0;
    struct nl_addr kern; memset(&kern,0,sizeof kern); kern.family = NL_AF_NETLINK;
    if (nsp(s, NSP_SENDTO, (int)nfd, 0,0,0, req, h->len, &kern, sizeof kern, 0,0,0,0,0,0) < 0) {
        nsp(s,NSP_CLOSE,(int)nfd,0,0,0,0,0,0,0,0,0,0,0,0,0); return -1;
    }
    static unsigned char rb[16384];
    int wlan = -1, done = 0;
    for (int iter = 0; iter < 32 && !done; iter++) {
        uint32_t rlen = 0;
        long r = nsp(s, NSP_RECVFROM, (int)nfd, (int)sizeof rb, 0, 0, 0,0,0,0, rb, sizeof rb, &rlen, 0,0,0);
        if (r <= -1000) { nsp(s,NSP_CLOSE,(int)nfd,0,0,0,0,0,0,0,0,0,0,0,0,0); return -2; }  /* transport error */
        if (r <= 0 || rlen == 0) break;
        uint32_t off = 0;
        while (off + sizeof(struct nl_hdr) <= rlen) {
            struct nl_hdr *mh = (struct nl_hdr *)(rb + off);
            if (mh->len < sizeof(struct nl_hdr) || off + mh->len > rlen) break;
            if (mh->type == NLMSG_DONE || mh->type == NLMSG_ERROR) { done = 1; break; }
            if (mh->type == RTM_NEWLINK) {
                struct nl_ifi *mi = (struct nl_ifi *)((unsigned char *)mh + NLA(sizeof(struct nl_hdr)));
                int idx = mi->index;
                uint32_t a = NLA(sizeof(struct nl_hdr)) + NLA(sizeof(struct nl_ifi));
                while (a + sizeof(struct nl_rta) <= mh->len) {
                    struct nl_rta *rta = (struct nl_rta *)((unsigned char *)mh + a);
                    if (rta->len < sizeof(struct nl_rta) || a + rta->len > mh->len) break;
                    if (rta->type == IFLA_IFNAME) {
                        const char *nm = (const char *)rta + sizeof(struct nl_rta);
                        if (strcmp(nm, "wlan0") == 0) wlan = idx;
                    }
                    a += NLA(rta->len);
                }
            }
            off += NLA(mh->len);
        }
    }
    nsp(s, NSP_CLOSE, (int)nfd, 0,0,0, 0,0,0,0, 0,0,0,0,0,0);
    return wlan;
}

/* resolve the "nl80211" generic-netlink family id (ported from hos-wifi.c) */
static int genl_resolve(int s, int nfd)
{
    unsigned char req[128]; memset(req, 0, sizeof req);
    struct nl_hdr  *h = (struct nl_hdr *)req;
    struct genl_hdr *g = (struct genl_hdr *)(req + NLA(sizeof *h));
    uint32_t attroff = NLA(sizeof *h) + NLA(sizeof *g);
    struct nl_rta *a = (struct nl_rta *)(req + attroff);
    const char *fam = "nl80211"; uint16_t faml = (uint16_t)(strlen(fam) + 1);
    a->type = CTRL_ATTR_FAMILY_NAME; a->len = (uint16_t)(sizeof(struct nl_rta) + faml);
    memcpy((char *)a + sizeof(struct nl_rta), fam, faml);
    h->len = attroff + NLA(a->len); h->type = GENL_ID_CTRL; h->flags = NLM_F_REQUEST; h->seq = 2;
    g->cmd = CTRL_CMD_GETFAMILY; g->version = 1;
    struct nl_addr kern; memset(&kern, 0, sizeof kern); kern.family = NL_AF_NETLINK;
    if (nsp(s, NSP_SENDTO, nfd, 0,0,0, req, h->len, &kern, sizeof kern, 0,0,0,0,0,0) < 0) return -1;
    static unsigned char rb[8192]; uint32_t rlen = 0;
    long r = nsp(s, NSP_RECVFROM, nfd, (int)sizeof rb, 0, 0, 0,0,0,0, rb, sizeof rb, &rlen, 0,0,0);
    if (r <= 0 || rlen < sizeof(struct nl_hdr)) return -1;
    struct nl_hdr *mh = (struct nl_hdr *)rb;
    if (mh->type == NLMSG_ERROR) return -1;
    uint32_t end = mh->len < rlen ? mh->len : rlen;
    uint32_t a2 = NLA(sizeof(struct nl_hdr)) + NLA(sizeof(struct genl_hdr));
    while (a2 + sizeof(struct nl_rta) <= end) {
        struct nl_rta *at = (struct nl_rta *)(rb + a2);
        if (at->len < sizeof(struct nl_rta) || a2 + at->len > end) break;
        if (at->type == CTRL_ATTR_FAMILY_ID) return (int)*(uint16_t *)((char *)at + sizeof(struct nl_rta));
        a2 += NLA(at->len);
    }
    return -1;
}

static void add_net(const char *ss, int sig, const char *sec)
{
    if (!ss[0]) return;                          /* skip hidden APs */
    for (int i=0;i<g_nnets;i++) if (!strcmp(g_ssid[i], ss)) {         /* dedup by SSID, keep strongest */
        if (sig > g_sig[i]) { g_sig[i] = sig; snprintf(g_sec[i], sizeof g_sec[0], "%s", sec); }
        return;
    }
    if (g_nnets >= MAX_NETS) return;
    snprintf(g_ssid[g_nnets], sizeof g_ssid[0], "%s", ss);
    g_sig[g_nnets] = sig;
    snprintf(g_sec[g_nnets], sizeof g_sec[0], "%s", sec);
    g_nnets++;
}

/* Atomic provider-side scan.  The trigger, asynchronous wait, and WEXT result parsing all happen
 * inside lkl-boot, so this synchronous RPC cannot confuse nl80211 multicast events with request
 * replies or leak/reuse raw LKL netlink fd numbers across reconnects. */
static int provider_scan(int s)
{
    static char rb[NSP_MAXBUF + 1];
    char old_ssid[MAX_NETS][64], old_sec[MAX_NETS][8];
    int old_sig[MAX_NETS], old_nnets = g_nnets;
    if (old_nnets > 0) {
        memcpy(old_ssid, g_ssid, sizeof old_ssid);
        memcpy(old_sec,  g_sec,  sizeof old_sec);
        memcpy(old_sig,  g_sig,  sizeof old_sig);
    }
    g_scanRetained = 0;
    uint32_t rlen = 0;
    long aps = nsp(s, NSP_SCAN, -1, 0,0,0, 0,0,0,0,
                   rb, NSP_MAXBUF, &rlen, 0,0,0);
    if (aps <= -1000) return -1;
    if (rlen > NSP_MAXBUF) rlen = NSP_MAXBUF;
    rb[rlen] = 0;
    if (aps < 0) {
        char m[128]; snprintf(m, sizeof m, "provider scan failed ret=%ld: %.80s", aps, rb); slog(m);
        return 0;
    }

    g_nnets = 0;
    char *line = rb;
    while (line && *line) {
        char *next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (!strncmp(line, "NET\t", 4)) {
            char ssid[64] = {0}, sec[8] = "open"; int sig = 50;
            if (sscanf(line + 4, "%63[^\t]\t%d\t%7s", ssid, &sig, sec) == 3)
                add_net(ssid, sig, sec);
        }
        line = next;
    }
    /* A scan can transiently return an empty WEXT cache while wpa/cfg80211 is updating it.  Do not
     * erase a list that was just proven valid; retain it until another non-empty scan replaces it. */
    if (g_nnets == 0 && old_nnets > 0) {
        memcpy(g_ssid, old_ssid, sizeof old_ssid);
        memcpy(g_sec,  old_sec,  sizeof old_sec);
        memcpy(g_sig,  old_sig,  sizeof old_sig);
        g_nnets = old_nnets;
        g_scanRetained = 1;
    }
    return (int)aps;
}

/* resolve + cache the nl80211 generic-netlink family id (own short-lived socket). */
static void __attribute__((unused)) resolve_famid(int s)
{
    long nfd = nsp(s, NSP_SOCKET, -1, NL_AF_NETLINK, NL_SOCK_RAW, NL_NETLINK_GENERIC, 0,0,0,0, 0,0,0,0,0,0);
    if (nfd < 0) return;
    struct nl_addr sa; memset(&sa, 0, sizeof sa); sa.family = NL_AF_NETLINK;
    nsp(s, NSP_BIND, (int)nfd, 0,0,0, 0,0, &sa, sizeof sa, 0,0,0,0,0,0);
    int f = genl_resolve(s, (int)nfd);
    nsp(s, NSP_CLOSE, (int)nfd, 0,0,0, 0,0,0,0, 0,0,0,0,0,0);
    if (f > 0) g_famid = f;
}

/* Set IFF_UP with the ioctl route already proven by lkl-boot's epin_wifi_bringup().  nl80211
 * TRIGGER_SCAN requires a running wireless dev and returns -ENETDOWN otherwise.  Do not use
 * RTM_NEWLINK here: that operation terminates this OS's routed provider stream. */
static int __attribute__((unused)) link_up_ioctl(int s)
{
    long fd = nsp(s, NSP_SOCKET, -1, 2 /*AF_INET*/, 2 /*SOCK_DGRAM*/, 0,
                  0,0,0,0, 0,0,0,0,0,0);
    if (fd < 0) {
        char m[80]; snprintf(m, sizeof m, "link_up ioctl: socket failed ret=%ld", fd); slog(m);
        return 0;
    }
    struct net_ifreq ifr; memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.name, "wlan0", sizeof(ifr.name) - 1);
    uint32_t outlen = 0;
    long gr = nsp(s, NSP_IOCTL, (int)fd, IOCTL_SIOCGIFFLAGS, 0,0,
                  &ifr, sizeof ifr, 0,0, &ifr, sizeof ifr, &outlen, 0,0,0);
    long sr = gr;
    if (gr >= 0) {
        ifr.u.flags |= NET_IFF_UP;
        sr = nsp(s, NSP_IOCTL, (int)fd, IOCTL_SIOCSIFFLAGS, 0,0,
                 &ifr, sizeof ifr, 0,0, &ifr, sizeof ifr, &outlen, 0,0,0);
    }
    if (sr > -1000) nsp(s, NSP_CLOSE, (int)fd, 0,0,0, 0,0,0,0, 0,0,0,0,0,0);
    if (gr < 0 || sr < 0) {
        char m[96]; snprintf(m, sizeof m, "link_up ioctl failed get=%ld set=%ld", gr, sr); slog(m);
        return 0;
    }
    if (!g_linkUpLogged) { slog("link_up wlan0 via SIOCSIFFLAGS: OK"); g_linkUpLogged = 1; }
    return 1;
}

/* Fire an active scan so the cfg80211 BSS cache stays fresh even when wpa (no configured network) is
 * idle and not scanning on its own.  Results land asynchronously (~1-5s) and are read by the GET_SCAN
 * dump on a later cycle.  Fire-and-forget on a short-lived socket (closing drops the ACK / -EBUSY that
 * wpa's own concurrent scan would return — both are fine). */
static int __attribute__((unused)) nl80211_trigger(int s)
{
    if (g_famid <= 0 || g_ifindex < 0) return 0;
    long nfd = nsp(s, NSP_SOCKET, -1, NL_AF_NETLINK, NL_SOCK_RAW, NL_NETLINK_GENERIC, 0,0,0,0, 0,0,0,0,0,0);
    if (nfd < 0) {
        char m[80]; snprintf(m, sizeof m, "TRIGGER_SCAN: netlink socket failed ret=%ld", nfd); slog(m);
        return 0;
    }
    struct nl_addr sa; memset(&sa, 0, sizeof sa); sa.family = NL_AF_NETLINK;
    nsp(s, NSP_BIND, (int)nfd, 0,0,0, 0,0, &sa, sizeof sa, 0,0,0,0,0,0);

    unsigned char req[128]; memset(req, 0, sizeof req);
    struct nl_hdr  *h = (struct nl_hdr *)req;
    struct genl_hdr *g = (struct genl_hdr *)(req + NLA(sizeof *h));
    uint32_t o = NLA(sizeof *h) + NLA(sizeof *g);
    struct nl_rta *a = (struct nl_rta *)(req + o);        /* NL80211_ATTR_IFINDEX */
    a->type = NL80211_ATTR_IFINDEX; a->len = (uint16_t)(sizeof(struct nl_rta) + 4);
    *(uint32_t *)((char *)a + sizeof(struct nl_rta)) = (uint32_t)g_ifindex;
    o += NLA(a->len);
    struct nl_rta *ss = (struct nl_rta *)(req + o);       /* NL80211_ATTR_SCAN_SSIDS (nested): one empty SSID = active wildcard */
    struct nl_rta *ss1 = (struct nl_rta *)((char *)ss + NLA(sizeof(struct nl_rta)));
    ss1->type = 1; ss1->len = (uint16_t)sizeof(struct nl_rta);   /* zero-length payload = wildcard SSID */
    ss->type = NL80211_ATTR_SCAN_SSIDS; ss->len = (uint16_t)(NLA(sizeof(struct nl_rta)) + NLA(ss1->len));
    o += NLA(ss->len);
    h->len = o; h->type = (uint16_t)g_famid; h->flags = NLM_F_REQUEST | NLM_F_ACK; h->seq = 4;
    g->cmd = NL80211_CMD_TRIGGER_SCAN; g->version = 0;
    struct nl_addr kern; memset(&kern, 0, sizeof kern); kern.family = NL_AF_NETLINK;
    long sr = nsp(s, NSP_SENDTO, (int)nfd, 0,0,0, req, h->len, &kern, sizeof kern, 0,0,0,0,0,0);
    if (sr < 0) {
        char m[88]; snprintf(m, sizeof m, "TRIGGER_SCAN: send failed ret=%ld", sr); slog(m);
        if (sr > -1000) nsp(s, NSP_CLOSE, (int)nfd, 0,0,0, 0,0,0,0, 0,0,0,0,0,0);
        return 0;
    }
    /* EpinAnonymOS diag: NLM_F_ACK asks cfg80211 for an ACK/error reply so we learn whether the
     * scan TRIGGER was accepted or REJECTED (and why). The driver's REG SCAN START only fires if
     * cfg80211 accepted; no REG SCAN START + rejection here = cfg80211 refused the scan. */
    int accepted = 0;
    {
        unsigned char ackb[256]; uint32_t acklen = 0; long rr = 0;
        /* Retry a couple times: the provider returns -11 (EAGAIN) on its 1s ppoll timeout, and the
         * ack can land slightly after the sendto RPC returns — one retry reliably captures the real
         * err=0 / err=-NN instead of the ambiguous "no reply". */
        for (int t = 0; t < 3; t++) {
            rr = nsp(s, NSP_RECVFROM, (int)nfd, (int)sizeof ackb, 0, 0, 0,0,0,0, ackb, sizeof ackb, &acklen, 0,0,0);
            if (rr <= -1000 || acklen > 0) break;
        }
        char m[96];
        if (rr <= -1000) snprintf(m, sizeof m, "TRIGGER_SCAN: no ACK (transport %ld)", rr);
        else if (acklen >= NLA(sizeof(struct nl_hdr)) + 4) {
            struct nl_hdr *mh = (struct nl_hdr *)ackb;
            if (mh->type == NLMSG_ERROR) {
                int err = *(int *)(ackb + NLA(sizeof(struct nl_hdr)));   /* nlmsgerr.error */
                accepted = (err == 0);
                snprintf(m, sizeof m, "TRIGGER_SCAN %s err=%d", err ? "REJECTED" : "accepted", err);
            } else snprintf(m, sizeof m, "TRIGGER_SCAN reply type=%u len=%u", mh->type, acklen);
        } else snprintf(m, sizeof m, "TRIGGER_SCAN: short/no reply len=%u r=%ld", acklen, rr);
        slog(m);
    }
    nsp(s, NSP_CLOSE, (int)nfd, 0,0,0, 0,0,0,0, 0,0,0,0,0,0);
    return accepted;
}

/* nl80211 GET_SCAN dump -> fill g_ssid/g_sig/g_sec.  Returns BSS count, or -1 on a transport error
 * (caller drops+reconnects the provider socket). (ported/extended from hos-wifi.c) */
static int __attribute__((unused)) nl80211_scan(int s)
{
    if (g_ifindex < 0) return 0;
    long nfd = nsp(s, NSP_SOCKET, -1, NL_AF_NETLINK, NL_SOCK_RAW, NL_NETLINK_GENERIC, 0,0,0,0, 0,0,0,0,0,0);
    if (nfd < 0) return 0;
    struct nl_addr sa; memset(&sa, 0, sizeof sa); sa.family = NL_AF_NETLINK;
    nsp(s, NSP_BIND, (int)nfd, 0,0,0, 0,0, &sa, sizeof sa, 0,0,0,0,0,0);
    int famid = g_famid;
    if (famid <= 0) { nsp(s,NSP_CLOSE,(int)nfd,0,0,0,0,0,0,0,0,0,0,0,0,0); return 0; }

    unsigned char req[128]; memset(req, 0, sizeof req);
    struct nl_hdr  *h = (struct nl_hdr *)req;
    struct genl_hdr *g = (struct genl_hdr *)(req + NLA(sizeof *h));
    uint32_t attroff = NLA(sizeof *h) + NLA(sizeof *g);
    struct nl_rta *a = (struct nl_rta *)(req + attroff);
    a->type = NL80211_ATTR_IFINDEX; a->len = (uint16_t)(sizeof(struct nl_rta) + 4);
    *(uint32_t *)((char *)a + sizeof(struct nl_rta)) = (uint32_t)g_ifindex;
    h->len = attroff + NLA(a->len); h->type = (uint16_t)famid;
    h->flags = NLM_F_REQUEST | NLM_F_DUMP; h->seq = 3;
    g->cmd = NL80211_CMD_GET_SCAN; g->version = 0;
    struct nl_addr kern; memset(&kern, 0, sizeof kern); kern.family = NL_AF_NETLINK;
    if (nsp(s, NSP_SENDTO, (int)nfd, 0,0,0, req, h->len, &kern, sizeof kern, 0,0,0,0,0,0) < 0) {
        nsp(s,NSP_CLOSE,(int)nfd,0,0,0,0,0,0,0,0,0,0,0,0,0); return 0;
    }

    static unsigned char rb[32768];
    int bss = 0, done = 0, transport_err = 0;
    g_nnets = 0;
    for (int iter = 0; iter < 64 && !done; iter++) {
        uint32_t rlen = 0;
        long r = nsp(s, NSP_RECVFROM, (int)nfd, (int)sizeof rb, 0, 0, 0,0,0,0, rb, sizeof rb, &rlen, 0,0,0);
        if (r <= -1000) { transport_err = 1; break; }
        if (r <= 0 || rlen == 0) break;
        uint32_t off = 0;
        while (off + sizeof(struct nl_hdr) <= rlen) {
            struct nl_hdr *mh = (struct nl_hdr *)(rb + off);
            if (mh->len < sizeof(struct nl_hdr) || off + mh->len > rlen) break;
            if (mh->type == NLMSG_DONE || mh->type == NLMSG_ERROR) { done = 1; break; }
            if (mh->type == (uint16_t)famid) {
                uint32_t a2 = NLA(sizeof(struct nl_hdr)) + NLA(sizeof(struct genl_hdr));
                while (a2 + sizeof(struct nl_rta) <= mh->len) {
                    struct nl_rta *at = (struct nl_rta *)((unsigned char *)mh + a2);
                    if (at->len < sizeof(struct nl_rta) || a2 + at->len > mh->len) break;
                    if (at->type == NL80211_ATTR_BSS) {
                        bss++;
                        char ssid[64]; ssid[0] = 0;
                        int sig = 0, cap = 0, has_rsn = 0, has_wpa = 0;
                        uint32_t b = a2 + NLA(sizeof(struct nl_rta)), bend = a2 + at->len;
                        while (b + sizeof(struct nl_rta) <= bend) {
                            struct nl_rta *bt = (struct nl_rta *)((unsigned char *)mh + b);
                            if (bt->len < sizeof(struct nl_rta) || b + bt->len > bend) break;
                            unsigned char *val = (unsigned char *)bt + sizeof(struct nl_rta);
                            uint32_t vlen = bt->len - sizeof(struct nl_rta);
                            if (bt->type == NL80211_BSS_SIGNAL_MBM && vlen >= 4) {
                                int mbm = *(int32_t *)val, dbm = mbm / 100;
                                sig = (dbm >= -50) ? 100 : (dbm <= -100) ? 0 : (dbm + 100) * 2;
                            } else if (bt->type == NL80211_BSS_CAPABILITY && vlen >= 2) {
                                cap = *(uint16_t *)val;
                            } else if (bt->type == NL80211_BSS_INFORMATION_ELEMENTS) {
                                uint32_t p = 0;
                                while (p + 2 <= vlen) {
                                    uint8_t id = val[p], ln = val[p+1];
                                    if (p + 2 + ln > vlen) break;
                                    if (id == WLAN_EID_SSID) {
                                        uint8_t sl = ln < 32 ? ln : 32;
                                        memcpy(ssid, val + p + 2, sl); ssid[sl] = 0;
                                        for (int k=0;k<sl;k++) if (ssid[k]=='\t'||ssid[k]=='\n') ssid[k]=' ';
                                    } else if (id == WLAN_EID_RSN) {
                                        has_rsn = 1;
                                    } else if (id == WLAN_EID_VENDOR && ln >= 4 &&
                                               val[p+2]==0x00 && val[p+3]==0x50 && val[p+4]==0xF2 && val[p+5]==0x01) {
                                        has_wpa = 1;
                                    }
                                    p += 2 + ln;
                                }
                            }
                            b += NLA(bt->len);
                        }
                        const char *sec = has_rsn ? "wpa2" : has_wpa ? "wpa" : (cap & 0x10) ? "wep" : "open";
                        add_net(ssid, sig, sec);
                    }
                    a2 += NLA(at->len);
                }
            }
            off += NLA(mh->len);
        }
    }
    nsp(s, NSP_CLOSE, (int)nfd, 0,0,0, 0,0,0,0, 0,0,0,0,0,0);
    return transport_err ? -1 : bss;
}

/* ---- publish /run/wifi/networks in the exact menu format (atomic tmp+rename) ---- */
static void write_networks(void)
{
    int have_lease = (access(DHCP_OK, F_OK) == 0);
    unsigned state = have_lease ? 100u : 30u;    /* 100=connected(lease present) else 30=disconnected */
    int fd = open(NET_TMP, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) return;
    char line[256];
    /* header: #dev<TAB>devpath<TAB>iface<TAB>state (devpath empty; iface non-empty so the menu shows
     * "ready", not "no adapter"; exactly 3 tabs). */
    int m = snprintf(line, sizeof line, "#dev\t\twlan0\t%u\n", state);
    if (m > 0) (void)!write(fd, line, (size_t)m);
    for (int i=0;i<g_nnets;i++) {
        int active = (have_lease && g_connect_ssid[0] && !strcmp(g_ssid[i], g_connect_ssid)) ? 1 : 0;
        m = snprintf(line, sizeof line, "%s\t%u\t%s\t%d\t%s\n",
                     g_ssid[i], (unsigned)g_sig[i], g_sec[i], active, g_ssid[i]);
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
/* returns 1 if a valid config was written (caller reloads wpa), 0 if creds were rejected (error set). */
static int write_wpa_conf(const char *ssid, const char *psk)
{
    char es[128], ep[128]; int j;
    j=0; for (const char *p=ssid; *p && j<(int)sizeof es-1; p++) if (*p!='"'&&*p!='\\'&&*p!='\n'&&*p!='\r') es[j++]=*p; es[j]=0;
    j=0; for (const char *p=psk;  *p && j<(int)sizeof ep-1; p++) if (*p!='"'&&*p!='\\'&&*p!='\n'&&*p!='\r') ep[j++]=*p; ep[j]=0;

    /* wpa enforces SSID 1..32; an over-length SSID makes wpa_config_read return NULL -> wpa terminates. */
    if (es[0] == 0 || strlen(es) > 32) { set_error("Invalid network name"); return 0; }

    char cfg[512]; int m;
    if (ep[0]) {                                 /* secured (WPA-PSK) */
        size_t pl = strlen(ep);
        int hex = is_hex64(ep);
        if (!hex && (pl < 8 || pl > 63)) { set_error("Password must be 8-63 characters"); return 0; }
        if (hex)                                 /* 64 hex chars = raw PMK: no quotes */
            m = snprintf(cfg, sizeof cfg,
                "update_config=0\nap_scan=1\nnetwork={\n\tssid=\"%s\"\n\tpsk=%s\n\tkey_mgmt=WPA-PSK\n\tscan_ssid=1\n}\n", es, ep);
        else
            m = snprintf(cfg, sizeof cfg,
                "update_config=0\nap_scan=1\nnetwork={\n\tssid=\"%s\"\n\tpsk=\"%s\"\n\tkey_mgmt=WPA-PSK\n\tscan_ssid=1\n}\n", es, ep);
    } else {                                     /* open */
        m = snprintf(cfg, sizeof cfg,
            "update_config=0\nap_scan=1\nnetwork={\n\tssid=\"%s\"\n\tkey_mgmt=NONE\n\tscan_ssid=1\n}\n", es);
    }
    int fd = open(WPA_TMP, O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (fd < 0) { set_error("Could not write Wi-Fi config"); return 0; }
    int wrote = (m > 0) ? (int)write(fd, cfg, (size_t)m) : -1;
    close(fd);
    if (wrote != m || rename(WPA_TMP, WPA_CONF) != 0) {
        unlink(WPA_TMP);
        set_error("Could not save Wi-Fi config");
        return 0;
    }
    return 1;
}

static int reload_wpa(void)
{
    int fd = open(WPA_PIDF, O_RDONLY);
    if (fd < 0) { slog("cannot reload wpa: /run/wpa.pid is missing"); return 0; }
    char b[32]; int n = (int)read(fd, b, sizeof b - 1); close(fd);
    if (n <= 0) { slog("cannot reload wpa: empty /run/wpa.pid"); return 0; }
    b[n] = 0;
    long pid = atol(b);
    if (pid <= 1) { slog("cannot reload wpa: invalid pid"); return 0; }
    if (kill((int)pid, SIGHUP) != 0) {
        char m[96]; snprintf(m, sizeof m, "cannot reload wpa pid %ld: errno=%d", pid, errno); slog(m);
        return 0;
    }
    { char m[96]; snprintf(m, sizeof m, "SIGHUP sent to wpa pid %ld; configuration reload requested", pid); slog(m); }
    return 1;
}

static int check_connect(void)
{
    /* Leave a boot-seeded request queued until wpa has completed nl80211 initialization and
     * installed its SIGHUP handler.  Consuming it earlier would either kill wpa (default SIGHUP) or
     * reproduce the credentials-before-driver ordering failure this handshake prevents. */
    if (access(CONNECT_F, F_OK) == 0 && access(WPA_READY, F_OK) != 0) return 0;
    int fd = open(CONNECT_F, O_RDONLY);
    if (fd < 0) return 0;
    char buf[512];
    int n = (int)read(fd, buf, sizeof buf - 1);
    close(fd);
    unlink(CONNECT_F);
    if (n <= 0) return 0;
    buf[n] = 0;
    char ssid[128] = {0}, psk[128] = {0};
    char *nl = strchr(buf, '\n');
    if (nl) { *nl = 0; snprintf(ssid, sizeof ssid, "%s", buf);
              char *p2 = nl+1; char *nl2 = strchr(p2,'\n'); if (nl2) *nl2=0; snprintf(psk, sizeof psk, "%s", p2); }
    else    { snprintf(ssid, sizeof ssid, "%s", buf); }
    if (!ssid[0]) return 0;

    { char m[128]; snprintf(m, sizeof m, "connecting to '%s' (%s)...", ssid, psk[0]?"secured":"open"); set_diag(m); }
    unlink(DHCP_OK);
    unlink(ERROR_F);
    snprintf(g_connect_ssid, sizeof g_connect_ssid, "%s", ssid);
    if (write_wpa_conf(ssid, psk)) {
        if (reload_wpa()) g_connectCyc = g_cyc;
        else { set_error("Wi-Fi service is not running"); g_connect_ssid[0] = 0; }
    } else g_connect_ssid[0] = 0;
    return 1;
}

/* Seed g_connect_ssid from the config's ssid= so a boot-seeded association still lights the checkmark. */
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
    if (len > 0 && len < (int)sizeof g_connect_ssid) {
        memcpy(g_connect_ssid, p, len); g_connect_ssid[len] = 0;
        g_connectCyc = 0;   /* a network is boot-seeded: let wpa own the radio for the first ~9 cycles */
    }
}

int main(void)
{
    mkdir("/run", 0755);
    mkdir("/run/wifi", 0755);
    seed_connect_ssid();
    set_diag("Wi-Fi agent starting...");
    write_networks();   /* publish the adapter immediately -> menu shows "ready", not "no adapter" */

    int s = -1;
    for (;;) {
        if (s < 0) {
            s = prov_connect();
            if (s < 0) set_diag("connecting to the Wi-Fi provider...");
            else slog("provider connected");
        }
        if (check_connect()) write_networks();

        int have_lease = (access(DHCP_OK, F_OK) == 0);
        if (s >= 0) {
            int associating = (g_connect_ssid[0] && !have_lease && (g_cyc - g_connectCyc) < 9);
            /* Scan every ~15s until something is found, then only every ~60s.  Frequent WEXT scans
             * contend with wpa_supplicant and sometimes observe cfg80211's cache between updates. */
            int scan_period = (have_lease || g_nnets > 0) ? 12 : 3;
            if (!associating && (g_cyc % scan_period) == 0) {
                set_diag("scanning on wlan0 (provider-side)...");
                int n = provider_scan(s);
                if (n < 0) {
                    set_diag("provider error while scanning - reconnecting"); close(s); s = -1;
                }
                else {
                    if (!have_lease) {
                        char m[96];
                        if (g_scanRetained) snprintf(m, sizeof m, "scan empty; keeping %d known network(s)", g_nnets);
                        else if (g_nnets > 0) snprintf(m, sizeof m, "scan OK: %d network(s) in range", g_nnets);
                        else snprintf(m, sizeof m, "scan complete: %d AP(s), no named networks", n);
                        set_diag(m);
                    }
                }
            } else if (associating && !have_lease) {
                set_diag("associating... (wpa_supplicant owns the radio)");
            }
        }
        write_networks();

        for (int k = 0; k < 25; k++) {
            if (check_connect()) write_networks();
            napms(200);
        }
        g_cyc++;
    }
    return 0;
}
