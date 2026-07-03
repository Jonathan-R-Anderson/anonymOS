/*
 * hos-wifi — native EpinAnonymOS WiFi/network client (H1b).
 *
 * A normal native process with NO device caps.  It reaches the LKL's network stack ONLY through
 * the DEVCLASS_NET-gated provider socket (/run/hos-net.sock), using the socket-remoting RPC
 * (hos-net-proto.h): it opens a REMOTE AF_NETLINK socket in the LKL, binds it, sends an rtnetlink
 * RTM_GETLINK dump, receives + parses the reply, and lists the interface names (incl. wlan0) it
 * discovered — proving that raw netlink from a native process reaches the real wlan0 through the
 * cap gate.  This is the exact AF_NETLINK path wpa_supplicant/NetworkManager use.
 *
 * Results are reported via NSP_LOG (the provider prints them through lkl-boot's on-screen stderr),
 * since a spawned process's own stderr isn't mirrored to the boot framebuffer.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "hos-net-proto.h"

/* --- netlink / rtnetlink (stable uABI, defined inline) --- */
#define NL_AF_NETLINK   16
#define NL_SOCK_RAW      3
#define NL_NETLINK_ROUTE 0
#define RTM_GETLINK     18
#define RTM_NEWLINK     16
#define NLM_F_REQUEST 0x0001
#define NLM_F_DUMP    0x0300
#define NLMSG_ERROR      2
#define NLMSG_DONE       3
#define IFLA_IFNAME      3
#define NLA(x) (((x) + 3) & ~3)     /* NLMSG_ALIGN / RTA_ALIGN (4-byte) */

struct nl_hdr  { uint32_t len; uint16_t type; uint16_t flags; uint32_t seq; uint32_t pid; };
struct nl_ifi  { uint8_t family; uint8_t pad; uint16_t type; int32_t index; uint32_t flags; uint32_t change; };
struct nl_rta  { uint16_t len; uint16_t type; };   /* == struct nlattr */
struct nl_addr { uint16_t family; uint16_t pad; uint32_t pid; uint32_t groups; };

/* --- generic netlink / nl80211 (the exact surface wpa_supplicant uses) --- */
#define NL_NETLINK_GENERIC 16
#define GENL_ID_CTRL       16
#define CTRL_CMD_GETFAMILY  3
#define CTRL_ATTR_FAMILY_ID 1
#define CTRL_ATTR_FAMILY_NAME 2
#define NL80211_CMD_GET_SCAN 32
#define NL80211_ATTR_IFINDEX 3
#define NL80211_ATTR_BSS     47
#define NL80211_BSS_INFORMATION_ELEMENTS 6
#define WLAN_EID_SSID 0
struct genl_hdr { uint8_t cmd; uint8_t version; uint16_t reserved; };
#define NLM_F_ACK 0x04

/* EpinAnonymOS AF_UNIX read/write are non-blocking (return -EAGAIN when empty/full, peer open);
 * retry on EAGAIN with a short yield = blocking emulation.  0 (EOF) / other error ends. */
static void nap_yield(void){ struct timespec ts={0,2000000L}; nanosleep(&ts,NULL); }
static int rd_full(int fd, void *b, size_t n){ size_t g=0; while(g<n){long r=read(fd,(char*)b+g,n-g); if(r>0){g+=(size_t)r; continue;} if(r<0&&errno==EAGAIN){nap_yield(); continue;} return 0;} return 1; }
static int wr_full(int fd, const void *b, size_t n){ size_t p=0; while(p<n){long r=write(fd,(const char*)b+p,n-p); if(r>0){p+=(size_t)r; continue;} if(r<0&&errno==EAGAIN){nap_yield(); continue;} return 0;} return 1; }

/* One RPC round-trip.  Sends the request (+ optional send-buffer / send-addr), reads the reply
 * (+ optional reply data into rbuf / reply addr into raddr).  Returns resp.ret, or <=-1000 on a
 * framing error. */
static long nsp(int s, uint32_t op, int fd, int a0, int a1, int a2,
                const void *sbuf, uint32_t sblen, const void *saddr, uint32_t salen,
                void *rbuf, uint32_t rbufmax, uint32_t *rblen,
                void *raddr, uint32_t raddrmax, uint32_t *ralen)
{
    nsp_req rq; memset(&rq, 0, sizeof rq);
    rq.op = op; rq.fd = fd; rq.a0 = a0; rq.a1 = a1; rq.a2 = a2;
    rq.buflen = sblen; rq.addrlen = salen;
    if (!wr_full(s, &rq, sizeof rq)) return -1000;
    if (sblen && !wr_full(s, sbuf, sblen)) return -1000;
    if (salen && !wr_full(s, saddr, salen)) return -1000;

    nsp_resp rs;
    if (!rd_full(s, &rs, sizeof rs)) return -1001;
    char junk[512];
    if (rs.buflen) {
        uint32_t take = rs.buflen < rbufmax ? rs.buflen : rbufmax;
        if (rbuf && take && !rd_full(s, rbuf, take)) return -1002;
        if (rblen) *rblen = take;
        for (uint32_t left = rs.buflen - take; left; ) {   /* drain any overflow */
            uint32_t c = left < sizeof junk ? left : sizeof junk;
            if (!rd_full(s, junk, c)) return -1002;
            left -= c;
        }
    } else if (rblen) *rblen = 0;
    if (rs.addrlen) {
        uint32_t take = rs.addrlen < raddrmax ? rs.addrlen : raddrmax;
        if (raddr && take && !rd_full(s, raddr, take)) return -1003;
        if (ralen) *ralen = take;
        for (uint32_t left = rs.addrlen - take; left; ) {
            uint32_t c = left < sizeof junk ? left : sizeof junk;
            if (!rd_full(s, junk, c)) return -1003;
            left -= c;
        }
    } else if (ralen) *ralen = 0;
    return (long)rs.ret;
}

static void nsp_log(int s, const char *msg)
{
    (void)nsp(s, NSP_LOG, -1, 0, 0, 0, msg, (uint32_t)strlen(msg), 0, 0, 0, 0, 0, 0, 0, 0);
}

static void nap_ms(long ms){ struct timespec ts={ms/1000,(ms%1000)*1000000L}; nanosleep(&ts,NULL); }

/* rtnetlink RTM_GETLINK dump through the provider -> collect interface names.
 * Returns wlan0's ifindex (needed for nl80211), or -1 if not found. */
static int rtnetlink_list_ifaces(int s)
{
    int wlan_ifindex = -1;
    long nfd = nsp(s, NSP_SOCKET, -1, NL_AF_NETLINK, NL_SOCK_RAW, NL_NETLINK_ROUTE,
                   0,0,0,0, 0,0,0, 0,0,0);
    if (nfd < 0) { char m[96]; snprintf(m,sizeof m,"H1b rtnetlink: SOCKET failed ret=%ld",nfd); nsp_log(s,m); return -1; }

    struct nl_addr sa; memset(&sa,0,sizeof sa); sa.family = NL_AF_NETLINK;
    long br = nsp(s, NSP_BIND, (int)nfd, 0,0,0, 0,0, &sa, sizeof sa, 0,0,0,0,0,0);
    if (br < 0) { char m[96]; snprintf(m,sizeof m,"H1b rtnetlink: BIND failed ret=%ld",br); nsp_log(s,m);
                  nsp(s,NSP_CLOSE,(int)nfd,0,0,0,0,0,0,0,0,0,0,0,0,0); return -1; }

    /* build RTM_GETLINK dump request */
    unsigned char req[64]; memset(req,0,sizeof req);
    struct nl_hdr *h = (struct nl_hdr *)req;
    struct nl_ifi *ifi = (struct nl_ifi *)(req + NLA(sizeof *h));
    h->len   = NLA(sizeof *h) + (uint32_t)sizeof *ifi;
    h->type  = RTM_GETLINK;
    h->flags = NLM_F_REQUEST | NLM_F_DUMP;
    h->seq   = 1;
    ifi->family = 0; /* AF_UNSPEC = all */
    struct nl_addr kern; memset(&kern,0,sizeof kern); kern.family = NL_AF_NETLINK;
    long sr = nsp(s, NSP_SENDTO, (int)nfd, 0,0,0/*flags*/, req, h->len, &kern, sizeof kern, 0,0,0,0,0,0);
    if (sr < 0) { char m[96]; snprintf(m,sizeof m,"H1b rtnetlink: SENDTO failed ret=%ld",sr); nsp_log(s,m);
                  nsp(s,NSP_CLOSE,(int)nfd,0,0,0,0,0,0,0,0,0,0,0,0,0); return -1; }
    nsp_log(s, "H1b rtnetlink: socket+bind+send OK, receiving dump...");

    /* receive + parse the (possibly multi-part) dump */
    static unsigned char rb[16384];
    char names[512]; names[0] = 0; int count = 0, done = 0;
    for (int iter = 0; iter < 32 && !done; iter++) {
        uint32_t rlen = 0;
        long r = nsp(s, NSP_RECVFROM, (int)nfd, (int)sizeof rb, 0, 0/*flags*/,
                     0,0,0,0, rb, sizeof rb, &rlen, 0,0,0);
        if (r <= 0 || rlen == 0) break;
        uint32_t off = 0;
        while (off + sizeof(struct nl_hdr) <= rlen) {
            struct nl_hdr *mh = (struct nl_hdr *)(rb + off);
            if (mh->len < sizeof(struct nl_hdr) || off + mh->len > rlen) break;
            if (mh->type == NLMSG_DONE || mh->type == NLMSG_ERROR) { done = 1; break; }
            if (mh->type == RTM_NEWLINK) {
                struct nl_ifi *mi = (struct nl_ifi *)((unsigned char *)mh + NLA(sizeof(struct nl_hdr)));
                int this_index = mi->index;
                uint32_t a = NLA(sizeof(struct nl_hdr)) + NLA(sizeof(struct nl_ifi));
                while (a + sizeof(struct nl_rta) <= mh->len) {
                    struct nl_rta *rta = (struct nl_rta *)((unsigned char *)mh + a);
                    if (rta->len < sizeof(struct nl_rta) || a + rta->len > mh->len) break;
                    if (rta->type == IFLA_IFNAME) {
                        const char *nm = (const char *)rta + sizeof(struct nl_rta);
                        if (strlen(names) + strlen(nm) + 2 < sizeof names) { strcat(names, nm); strcat(names, " "); }
                        if (strcmp(nm, "wlan0") == 0) wlan_ifindex = this_index;
                        count++;
                    }
                    a += NLA(rta->len);
                }
            }
            off += NLA(mh->len);
        }
    }
    nsp(s, NSP_CLOSE, (int)nfd, 0,0,0, 0,0,0,0, 0,0,0,0,0,0);

    char msg[600];
    snprintf(msg, sizeof msg, "H1b rtnetlink RTM_GETLINK via cap-gated provider: %d iface(s) = %s(wlan0 ifindex=%d)",
             count, names, wlan_ifindex);
    nsp_log(s, msg);
    fprintf(stderr, ">>> hos-wifi: %s\n", msg);
    return wlan_ifindex;
}

/* Resolve the "nl80211" generic-netlink family id via the genl controller (GENL_ID_CTRL). */
static int genl_resolve_nl80211(int s, int nfd)
{
    unsigned char req[128]; memset(req, 0, sizeof req);
    struct nl_hdr  *h = (struct nl_hdr *)req;
    struct genl_hdr *g = (struct genl_hdr *)(req + NLA(sizeof *h));
    uint32_t attroff = NLA(sizeof *h) + NLA(sizeof *g);
    struct nl_rta *a = (struct nl_rta *)(req + attroff);
    const char *fam = "nl80211"; uint16_t faml = (uint16_t)(strlen(fam) + 1);
    a->type = CTRL_ATTR_FAMILY_NAME;
    a->len  = (uint16_t)(sizeof(struct nl_rta) + faml);
    memcpy((char *)a + sizeof(struct nl_rta), fam, faml);
    h->len   = attroff + NLA(a->len);
    h->type  = GENL_ID_CTRL;
    h->flags = NLM_F_REQUEST;
    h->seq   = 2;
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
        if (at->type == CTRL_ATTR_FAMILY_ID)
            return (int)*(uint16_t *)((char *)at + sizeof(struct nl_rta));
        a2 += NLA(at->len);
    }
    return -1;
}

/* nl80211 NL80211_CMD_GET_SCAN dump through the provider -> parse BSS info-elements -> SSIDs.
 * This is the exact generic-netlink path wpa_supplicant uses to read scan results. */
static void nl80211_get_scan(int s, int ifindex)
{
    if (ifindex < 0) { nsp_log(s, "H1b nl80211: no wlan0 ifindex - skipping"); return; }
    long nfd = nsp(s, NSP_SOCKET, -1, NL_AF_NETLINK, NL_SOCK_RAW, NL_NETLINK_GENERIC, 0,0,0,0, 0,0,0,0,0,0);
    if (nfd < 0) { nsp_log(s, "H1b nl80211: SOCKET(GENERIC) failed"); return; }
    struct nl_addr sa; memset(&sa, 0, sizeof sa); sa.family = NL_AF_NETLINK;
    nsp(s, NSP_BIND, (int)nfd, 0,0,0, 0,0, &sa, sizeof sa, 0,0,0,0,0,0);

    int famid = genl_resolve_nl80211(s, (int)nfd);
    if (famid <= 0) { char m[96]; snprintf(m,sizeof m,"H1b nl80211: family resolve failed (%d)",famid); nsp_log(s,m);
                      nsp(s,NSP_CLOSE,(int)nfd,0,0,0,0,0,0,0,0,0,0,0,0,0); return; }
    { char m[80]; snprintf(m,sizeof m,"H1b nl80211: resolved genl family id=%d", famid); nsp_log(s,m); }

    unsigned char req[128]; memset(req, 0, sizeof req);
    struct nl_hdr  *h = (struct nl_hdr *)req;
    struct genl_hdr *g = (struct genl_hdr *)(req + NLA(sizeof *h));
    uint32_t attroff = NLA(sizeof *h) + NLA(sizeof *g);
    struct nl_rta *a = (struct nl_rta *)(req + attroff);
    a->type = NL80211_ATTR_IFINDEX;
    a->len  = (uint16_t)(sizeof(struct nl_rta) + 4);
    *(uint32_t *)((char *)a + sizeof(struct nl_rta)) = (uint32_t)ifindex;
    h->len   = attroff + NLA(a->len);
    h->type  = (uint16_t)famid;
    h->flags = NLM_F_REQUEST | NLM_F_DUMP;
    h->seq   = 3;
    g->cmd = NL80211_CMD_GET_SCAN; g->version = 0;
    struct nl_addr kern; memset(&kern, 0, sizeof kern); kern.family = NL_AF_NETLINK;
    if (nsp(s, NSP_SENDTO, (int)nfd, 0,0,0, req, h->len, &kern, sizeof kern, 0,0,0,0,0,0) < 0) {
        nsp_log(s, "H1b nl80211: GET_SCAN sendto failed");
        nsp(s,NSP_CLOSE,(int)nfd,0,0,0,0,0,0,0,0,0,0,0,0,0); return;
    }

    static unsigned char rb[16384];
    char ssids[512]; ssids[0] = 0; int bss = 0, done = 0;
    for (int iter = 0; iter < 64 && !done; iter++) {
        uint32_t rlen = 0;
        long r = nsp(s, NSP_RECVFROM, (int)nfd, (int)sizeof rb, 0, 0, 0,0,0,0, rb, sizeof rb, &rlen, 0,0,0);
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
                        uint32_t b = a2 + NLA(sizeof(struct nl_rta)), bend = a2 + at->len;
                        while (b + sizeof(struct nl_rta) <= bend) {
                            struct nl_rta *bt = (struct nl_rta *)((unsigned char *)mh + b);
                            if (bt->len < sizeof(struct nl_rta) || b + bt->len > bend) break;
                            if (bt->type == NL80211_BSS_INFORMATION_ELEMENTS) {
                                unsigned char *ie = (unsigned char *)bt + sizeof(struct nl_rta);
                                uint32_t ielen = bt->len - sizeof(struct nl_rta), p = 0;
                                while (p + 2 <= ielen) {
                                    uint8_t id = ie[p], ln = ie[p+1];
                                    if (p + 2 + ln > ielen) break;
                                    if (id == WLAN_EID_SSID) {
                                        char nm[33]; uint8_t sl = ln < 32 ? ln : 32;
                                        memcpy(nm, ie + p + 2, sl); nm[sl] = 0;
                                        const char *disp = sl ? nm : "(hidden)";
                                        if (strlen(ssids) + strlen(disp) + 2 < sizeof ssids) { strcat(ssids, disp); strcat(ssids, " "); }
                                    }
                                    p += 2 + ln;
                                }
                            }
                            b += NLA(bt->len);
                        }
                    }
                    a2 += NLA(at->len);
                }
            }
            off += NLA(mh->len);
        }
    }
    nsp(s, NSP_CLOSE, (int)nfd, 0,0,0, 0,0,0,0, 0,0,0,0,0,0);
    char msg[600];
    snprintf(msg, sizeof msg, "H1b nl80211 GET_SCAN via provider: %d BSS(es); SSIDs = %s", bss, ssids);
    nsp_log(s, msg);
    fprintf(stderr, ">>> hos-wifi: %s\n", msg);
}

int main(void)
{
    fprintf(stderr, ">>> hos-wifi: native client starting; dialing the cap-gated net provider...\n");

    int s = -1;
    for (int i = 0; i < 1200; i++) {           /* retry ~120s: provider+wlan0 come up async */
        s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s >= 0) {
            struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
            sa.sun_family = AF_UNIX;
            strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path) - 1);
            if (connect(s, (struct sockaddr *)&sa, sizeof sa) == 0) break;
            int e = errno; close(s); s = -1;
            if (e == 13 /*EACCES*/) {
                fprintf(stderr, ">>> hos-wifi: DENIED by cap gate (no DEVCLASS_NET) -- security works\n");
                return 2;
            }
        }
        nap_ms(100);
    }
    if (s < 0) { fprintf(stderr, ">>> hos-wifi: could not reach provider %s\n", NSP_PATH); return 1; }

    nsp_log(s, "hos-wifi connected (native process, no device cap) -- starting H1b probes");

    /* (1) raw AF_NETLINK rtnetlink through the remoting RPC -> list interfaces + wlan0 ifindex */
    int wlan_idx = rtnetlink_list_ifaces(s);

    /* (2) nl80211 (generic netlink) GET_SCAN through the RPC -> the exact wpa_supplicant surface */
    nl80211_get_scan(s, wlan_idx);

    /* (3) the high-level scan convenience op (also proves the WEXT SSID path still works) */
    long aps = nsp(s, NSP_SCAN, -1, 0,0,0, 0,0,0,0, 0,0,0,0,0,0);
    char m[96]; snprintf(m, sizeof m, "H1b NSP_SCAN via provider: ret=%ld AP(s)", aps);
    nsp_log(s, m);

    nsp_log(s, "hos-wifi H1b DONE -- native netlink reached wlan0 through the cap-gated provider");
    close(s);
    return 0;
}
