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
 * DUMPs the cfg80211 BSS cache that wpa's own scans populate — so it never TRIGGERS a scan (no WEXT
 * SIOCSIWSCAN conflict with wpa's nl80211 scans, which returned nothing on the real AX210) and it
 * carries signal (BSS_SIGNAL_MBM) + security (RSN/WPA IEs + capability privacy bit).  Ported from the
 * proven hos-wifi.c H1b client.  Results -> /run/wifi/networks in the exact byte format wl-wifi-menu,
 * wl-quicksettings and wl-layer-bar parse.
 * CONNECT — the menu writes /run/wifi/connect = "SSID\nPASSWORD\n"; we rewrite /run/wpa-net.conf and
 * SIGHUP wpa (pid in /run/wpa.pid) so it re-reads the config and associates.  The kernel-supervised
 * udhcpc then leases and writes /run/wifi/dhcp-ok — how the menu learns "connected".
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
struct nl_hdr  { uint32_t len; uint16_t type; uint16_t flags; uint32_t seq; uint32_t pid; };
struct nl_ifi  { uint8_t family; uint8_t pad; uint16_t type; int32_t index; uint32_t flags; uint32_t change; };
struct nl_rta  { uint16_t len; uint16_t type; };
struct nl_addr { uint16_t family; uint16_t pad; uint32_t pid; uint32_t groups; };
struct genl_hdr { uint8_t cmd; uint8_t version; uint16_t reserved; };

#define WPA_CONF   "/run/wpa-net.conf"
#define WPA_PIDF   "/run/wpa.pid"
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
static char  g_connect_ssid[64] = {0};    /* the SSID we last asked wpa to join (for the active/checkmark row) */
static int   g_quietScans = 0;            /* skip scans for a few cycles after a connect: let wpa own the radio */

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
/* PARK on the socket fd (poll blocks on a real fd) rather than nanosleep; bound the wait (~20 parks
 * with no progress) so a hung provider can't wedge the agent. */
static void fd_park(int fd, short ev){ struct pollfd p = { fd, ev, 0 }; poll(&p, 1, 1000); }
static int rd_full(int fd, void *b, size_t n){ size_t g=0; int w=0; while(g<n){long r=read(fd,(char*)b+g,n-g); if(r>0){g+=(size_t)r; w=0; continue;} if(r<0&&errno==EAGAIN){ if(++w>20) return 0; fd_park(fd,POLLIN); continue;} return 0;} return 1; }
static int wr_full(int fd, const void *b, size_t n){ size_t p=0; int w=0; while(p<n){long r=write(fd,(const char*)b+p,n-p); if(r>0){p+=(size_t)r; w=0; continue;} if(r<0&&errno==EAGAIN){ if(++w>20) return 0; fd_park(fd,POLLOUT); continue;} return 0;} return 1; }

static int prov_connect(void)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un sa; memset(&sa,0,sizeof sa);
    sa.sun_family = AF_UNIX; strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path)-1);
    if (connect(s,(struct sockaddr*)&sa,sizeof sa) != 0) { close(s); return -1; }
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
static int resolve_ifindex(int s)
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

/* resolve + cache the nl80211 generic-netlink family id (own short-lived socket). */
static void resolve_famid(int s)
{
    long nfd = nsp(s, NSP_SOCKET, -1, NL_AF_NETLINK, NL_SOCK_RAW, NL_NETLINK_GENERIC, 0,0,0,0, 0,0,0,0,0,0);
    if (nfd < 0) return;
    struct nl_addr sa; memset(&sa, 0, sizeof sa); sa.family = NL_AF_NETLINK;
    nsp(s, NSP_BIND, (int)nfd, 0,0,0, 0,0, &sa, sizeof sa, 0,0,0,0,0,0);
    int f = genl_resolve(s, (int)nfd);
    nsp(s, NSP_CLOSE, (int)nfd, 0,0,0, 0,0,0,0, 0,0,0,0,0,0);
    if (f > 0) g_famid = f;
}

/* Fire an active scan so the cfg80211 BSS cache stays fresh even when wpa (no configured network) is
 * idle and not scanning on its own.  Results land asynchronously (~1-5s) and are read by the GET_SCAN
 * dump on a later cycle.  Fire-and-forget on a short-lived socket (closing drops the ACK / -EBUSY that
 * wpa's own concurrent scan would return — both are fine). */
static void nl80211_trigger(int s)
{
    if (g_famid <= 0 || g_ifindex < 0) return;
    long nfd = nsp(s, NSP_SOCKET, -1, NL_AF_NETLINK, NL_SOCK_RAW, NL_NETLINK_GENERIC, 0,0,0,0, 0,0,0,0,0,0);
    if (nfd < 0) return;
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
    h->len = o; h->type = (uint16_t)g_famid; h->flags = NLM_F_REQUEST; h->seq = 4;
    g->cmd = NL80211_CMD_TRIGGER_SCAN; g->version = 0;
    struct nl_addr kern; memset(&kern, 0, sizeof kern); kern.family = NL_AF_NETLINK;
    nsp(s, NSP_SENDTO, (int)nfd, 0,0,0, req, h->len, &kern, sizeof kern, 0,0,0,0,0,0);   /* fire-and-forget */
    nsp(s, NSP_CLOSE, (int)nfd, 0,0,0, 0,0,0,0, 0,0,0,0,0,0);
}

/* nl80211 GET_SCAN dump -> fill g_ssid/g_sig/g_sec.  Returns BSS count, or -1 on a transport error
 * (caller drops+reconnects the provider socket). (ported/extended from hos-wifi.c) */
static int nl80211_scan(int s)
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
    int fd = open(WPA_CONF, O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (fd < 0) { set_error("Could not write Wi-Fi config"); return 0; }
    if (m > 0) (void)!write(fd, cfg, (size_t)m);
    close(fd);
    return 1;
}

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
    unlink(CONNECT_F);
    if (n <= 0) return 0;
    buf[n] = 0;
    char ssid[128] = {0}, psk[128] = {0};
    char *nl = strchr(buf, '\n');
    if (nl) { *nl = 0; snprintf(ssid, sizeof ssid, "%s", buf);
              char *p2 = nl+1; char *nl2 = strchr(p2,'\n'); if (nl2) *nl2=0; snprintf(psk, sizeof psk, "%s", p2); }
    else    { snprintf(ssid, sizeof ssid, "%s", buf); }
    if (!ssid[0]) return 0;

    { char m[96]; snprintf(m, sizeof m, "connect request: ssid='%s' (%s)", ssid, psk[0]?"secured":"open"); slog(m); }
    unlink(DHCP_OK);
    unlink(ERROR_F);
    snprintf(g_connect_ssid, sizeof g_connect_ssid, "%s", ssid);
    if (write_wpa_conf(ssid, psk)) { reload_wpa(); g_quietScans = 4; }
    else g_connect_ssid[0] = 0;
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
    if (len > 0 && len < (int)sizeof g_connect_ssid) { memcpy(g_connect_ssid, p, len); g_connect_ssid[len] = 0; }
}

int main(void)
{
    mkdir("/run", 0755);
    mkdir("/run/wifi", 0755);
    seed_connect_ssid();
    slog("start (direct-wpa Wi-Fi backend, nl80211 scan)");
    write_networks();   /* publish the adapter immediately -> menu shows "ready", not "no adapter" */

    int s = -1, cyc = 0, connfail = 0;
    for (;;) {
        if (s < 0) {
            s = prov_connect();
            if (s < 0) { if ((connfail++ % 12) == 0) slog("provider /run/hos-net.sock not reachable yet"); }
            else { connfail = 0; slog("provider connected"); }
        }
        if (s >= 0 && g_ifindex < 0) {
            g_ifindex = resolve_ifindex(s);
            if (g_ifindex == -2) { slog("provider RPC error resolving ifindex; reconnecting"); close(s); s = -1; }
            else if (g_ifindex < 0) slog("wlan0 not found yet (no ifindex)");
            else { char m[40]; snprintf(m, sizeof m, "wlan0 ifindex=%d", g_ifindex); slog(m); }
        }
        if (s >= 0 && g_ifindex >= 0 && g_famid < 0) {
            resolve_famid(s);
            if (g_famid > 0) { char m[40]; snprintf(m, sizeof m, "nl80211 family id=%d", g_famid); slog(m); }
        }

        if (check_connect()) write_networks();

        int have_lease = (access(DHCP_OK, F_OK) == 0);
        if (s >= 0 && g_ifindex >= 0 && g_famid > 0) {
            if (g_quietScans > 0) {
                g_quietScans--;
            } else if (!have_lease || (cyc % 6) == 0) {
                nl80211_trigger(s);          /* fire a fresh scan (results land async, read next cycle) */
                int n = nl80211_scan(s);     /* read the cfg80211 BSS cache (previous trigger's + wpa's results) */
                if (n < 0) { slog("provider RPC error scanning; reconnecting"); close(s); s = -1; }
                else { char m[56]; snprintf(m, sizeof m, "scan: %d network(s) (%d BSS)", g_nnets, n); slog(m); }
            }
        }
        write_networks();

        for (int k = 0; k < 25; k++) {
            if (check_connect()) write_networks();
            napms(200);
        }
        cyc++;
    }
    return 0;
}
