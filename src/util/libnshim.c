/*
 * libnshim.c -> libnshim.so — H1b.3 transparent socket-family interposer (LD_PRELOAD).
 *
 * Injected via LD_PRELOAD into an UNMODIFIED dynamic-musl program (e.g. wpa_supplicant).  It
 * interposes the libc socket-family calls and, for sockets in the network families the LKL owns
 * (AF_NETLINK / AF_PACKET / AF_INET / AF_INET6), routes every operation to lkl-boot's cap-gated
 * provider over the socket-remoting RPC (hos-net-proto.h) — so the app's netlink/packet/inet
 * traffic reaches the real wlan0 through the DEVCLASS_NET gate.  AF_UNIX and everything else fall
 * straight through to the genuine libc function (resolved via dlsym(RTLD_NEXT, ...)).
 *
 * A routed socket is represented to the app by a real AF_UNIX placeholder fd (reserves the fd
 * number, pollable) mapped to the provider-side remote LKL fd.  poll() is emulated by asking the
 * provider (NSP_POLL) for each routed fd and real-polling the rest.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <net/if.h>
#include <poll.h>
#include <sys/select.h>
#include "hos-net-proto.h"

#ifndef SIOCGIFNAME
#define SIOCGIFNAME 0x8910
#endif
#ifndef SIOCGIFINDEX
#define SIOCGIFINDEX 0x8933
#endif

#define MAXFD 4096   /* hoisted here: used by the trace state below, before the routed-fd table */
static int wrf(int fd, const void *b, unsigned n);   /* forward decl (defined below with rdf) */

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif
#ifndef AF_PACKET
#define AF_PACKET 17
#endif

/* --- real libc entry points (via RTLD_NEXT) --- */
static int (*r_socket)(int,int,int);
static int (*r_bind)(int,const struct sockaddr*,socklen_t);
static int (*r_connect)(int,const struct sockaddr*,socklen_t);
static ssize_t (*r_sendto)(int,const void*,size_t,int,const struct sockaddr*,socklen_t);
static ssize_t (*r_recvfrom)(int,void*,size_t,int,struct sockaddr*,socklen_t*);
static ssize_t (*r_sendmsg)(int,const struct msghdr*,int);
static ssize_t (*r_recvmsg)(int,struct msghdr*,int);
static int (*r_setsockopt)(int,int,int,const void*,socklen_t);
static int (*r_getsockopt)(int,int,int,void*,socklen_t*);
static int (*r_getsockname)(int,struct sockaddr*,socklen_t*);
static int (*r_close)(int);
static int (*r_ioctl)(int,unsigned long,void*);
static int (*r_poll)(struct pollfd*,nfds_t,int);
static ssize_t (*r_read)(int,void*,size_t);
static ssize_t (*r_write)(int,const void*,size_t);
static ssize_t (*r_writev)(int,const struct iovec*,int);
static ssize_t (*r_readv)(int,const struct iovec*,int);
static int (*r_fcntl)(int,int,...);
static int (*r_open)(const char*,int,...);
static int (*r_select)(int,fd_set*,fd_set*,fd_set*,struct timeval*);
static int (*r_getpeername)(int,struct sockaddr*,socklen_t*);
static int (*r_shutdown)(int,int);

static void resolve(void)
{
    if (r_socket) return;
#define R(f) r_##f = dlsym(RTLD_NEXT, #f)
    R(socket); R(bind); R(connect); R(sendto); R(recvfrom); R(sendmsg); R(recvmsg);
    R(setsockopt); R(getsockopt); R(getsockname); R(close); R(ioctl); R(poll); R(read); R(write); R(fcntl);
    R(open); R(select); R(writev); R(readv); R(getpeername); R(shutdown);
#undef R
}

/* Netlink-trace file log (M3 laptop diagnosis): append NM's netlink TX/RX to a file the terminal can
 * cat, so a stuck platform-init shows exactly which request has no reply.  Uses the REAL syscalls. */
/* NETLINK TRACE (M3): accumulate into a HEAP buffer + stderr (serial under QEMU).  Do NOT write a file
 * per netlink op — the shim's per-op open/write/close of a ramfs file thousands of times on real
 * hardware CORRUPTED the fs.  Instead flush the whole buffer to /run/shim-nm.log ONLY on a STUCK event
 * (write_trace_file, bounded to a few calls). */
/* NETLINK TRACE (M4): stderr only (invisible on the laptop; visible in QEMU serial).  The shim must NOT
 * write files — a file write from NM's LD_PRELOAD context faults/corrupts the laptop.  The trace reaches
 * the laptop via shim_log() (a SOCKET write to the provider, which is safe): the provider accumulates
 * these NSP_LOG lines in memory, and the boot-doctor retrieves them with NSP_GETTRACE and writes the
 * file.  So diagnostics go: shim -> provider (accumulate) -> boot-doctor (NSP_GETTRACE) -> /run file. */
static void flog(const char *msg)
{
    unsigned n = strlen(msg);
    r_write(2, msg, n); r_write(2, "\n", 1);
}

/* DHCP data-path diagnostic: count AF_PACKET frames TX'd/RX'd on this process's routed sockets.
 * NM's internal DHCP client sends DISCOVER + receives OFFER over an AF_PACKET socket; if TX fires
 * but RX never does, the OFFER isn't coming back through LKL (data-path RX / router).  Capped so it
 * can't spam.  (wpa's EAPOL also uses AF_PACKET, so in /run/wpa.log this confirms the trace works.) */
static int g_pktTx = 0, g_pktRx = 0, g_pktSetup = 0;

/* --- routed-fd table: app fd -> provider remote LKL fd --- */
static int  g_remote[MAXFD];
static char g_routed[MAXFD];
static int  g_dom[MAXFD];      /* domain of a routed socket (for nl80211 scan counting) */
static char g_nonblock[MAXFD]; /* app set this routed fd non-blocking (O_NONBLOCK / SOCK_NONBLOCK) */
static unsigned short g_last_tx[MAXFD];    /* last netlink nlmsg_type sent on a routed fd (M3 trace) */
static unsigned char  g_last_cmd[MAXFD];   /* last genl cmd (nl80211) sent on a routed fd */
static unsigned int   g_last_txlen[MAXFD]; /* last netlink TX payload length on a routed fd */
static long           g_last_truelen[MAXFD]; /* last netlink RX true datagram length (H3 discriminator) */
/* LOST-REPLY RECOVERY state (recvfrom): a blocking netlink read whose request's reply got lost used
 * to burn the full retry cap (240 x the provider's 1s recv-poll = ~4min of dead boot time) before
 * surfacing.  Track whether a reply is outstanding, and keep a copy of the last request so an
 * IDEMPOTENT read (dump / rtnetlink GET / genl GETFAMILY) can simply be re-issued after ~5s. */
#define NSHIM_REQSAVE 4096
static int            g_nlproto[MAXFD];      /* netlink protocol (NETLINK_ROUTE/GENERIC) of a routed fd */
static unsigned short g_last_nlflags[MAXFD]; /* nlmsghdr.nlmsg_flags of the last request */
static char           g_pending[MAXFD];      /* a NLM_F_REQUEST was sent; its reply not yet complete */
static char           g_rx_since_tx[MAXFD];  /* something arrived since the last request (mid-dump) */
static char          *g_req_save[MAXFD];     /* saved bytes of the last request (<= NSHIM_REQSAVE) */
static unsigned       g_req_savelen[MAXFD];  /* 0 = nothing re-issuable saved */

static int routed(int fd){ return fd >= 0 && fd < MAXFD && g_routed[fd]; }

/* H3/Option-B visibility: when HOS_SHIM_LOG=1, the shim reports wpa's key milestones through the
 * provider's NSP_LOG (the channel that IS visible on the laptop framebuffer, unlike a spawned
 * process's own stderr).  Set once in the constructor. */
#include <stdlib.h>
static int g_log = 0;
static int g_ap_total = 0;
__attribute__((constructor)) static void nshim_cfg(void){ g_log = getenv("HOS_SHIM_LOG") != 0; }

/* --- provider connection POOL (was a single mutex-serialized connection) ---
 * A single shared connection + one global mutex meant a BLOCKING recvfrom — whose provider side
 * (lkl-boot.c NSP_RECVFROM) ppolls up to 1s for a reply — held the lock for that whole second,
 * freezing EVERY other routed syscall in the process.  NM is heavily multi-threaded and opens many
 * netlink sockets, so its entire boot enumeration serialized behind each blocking read.
 *
 * Now: a small POOL of connections, each with its own mutex.  A routed call is pinned to a slot by
 * its LKL remote fd (fd % NSP_POOL): (a) all traffic for ONE socket always uses ONE connection, so
 * netlink's per-socket request/response ordering is preserved, while (b) calls on DIFFERENT sockets
 * proceed concurrently on different connections.  The provider already spawns one serve-thread per
 * accepted connection (lkl-boot.c epin_net_conn_thread), and all its threads share the single LKL
 * kernel's global fd table, so any connection may operate on any LKL fd — no provider change needed.
 * fd-less control ops (NSP_SOCKET create; rfd < 0) use slot 0. */
#define NSP_POOL 16
static int             g_conn[NSP_POOL];
static pthread_mutex_t g_connlock[NSP_POOL];
static pthread_once_t  g_pool_once = PTHREAD_ONCE_INIT;
static void pool_init(void){ for (int i=0;i<NSP_POOL;i++){ g_conn[i] = -1; pthread_mutex_init(&g_connlock[i], 0); } }
/* Set once the provider has ever answered.  Before that (early boot) provider_connect is PATIENT —
 * the provider is racing to come up.  After that, a reconnect (triggered by the framing self-heal
 * below) FAST-FAILS instead of burning the full 10s retry under the slot mutex: if the provider has
 * genuinely died, every routed call would otherwise stall 10s and block all fds sharing that slot. */
static int g_ever_connected = 0;

/* EpinAnonymOS AF_UNIX read/write are NON-blocking (-EAGAIN on empty rx / full tx while the peer
 * lives), so blocking is emulated.  Wait EVENT-DRIVEN in poll() (the kernel parks the task and its
 * tick re-checks readiness, so we wake within ~1ms of data) — NOT a fixed nanosleep: the old 2ms
 * nap put a scheduling quantum under every RPC byte-wait, and across the thousands of netlink
 * round-trips in NM's boot enumeration those quanta summed to tens of seconds of WiFi bring-up.
 * The poll timeout is only a safety re-check bound; readiness normally wakes us first. */
static void fdwait(int fd, short ev){
    if (!r_poll){ struct timespec t={0,2000000L}; nanosleep(&t,0); return; }
    struct pollfd p={fd,ev,0}; r_poll(&p,1,1000);
}
static int rdf(int fd, void *b, unsigned n){ unsigned g=0; while(g<n){ long r=r_read(fd,(char*)b+g,n-g); if(r>0){g+=r;continue;} if(r<0&&errno==EAGAIN){fdwait(fd,POLLIN);continue;} return 0;} return 1; }
static int wrf(int fd, const void *b, unsigned n){ unsigned p=0; while(p<n){ long r=r_write(fd,(const char*)b+p,n-p); if(r>0){p+=r;continue;} if(r<0&&errno==EAGAIN){fdwait(fd,POLLOUT);continue;} return 0;} return 1; }

static int provider_connect(void)
{
    int s = r_socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un sa; memset(&sa,0,sizeof sa);
    sa.sun_family = AF_UNIX; strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path)-1);
    /* PATIENT (200x50ms=10s) only until the provider first answers — it is racing to come up at boot.
     * Afterwards a reconnect FAST-FAILS (3x50ms=150ms) so a dead provider can't stall every syscall
     * for 10s under the slot mutex. */
    int tries = g_ever_connected ? 3 : 200;
    for (int i=0;i<tries;i++){ if (r_connect(s,(struct sockaddr*)&sa,sizeof sa)==0){ g_ever_connected = 1; return s; }
                             struct timespec t={0,50000000L}; nanosleep(&t,0); }
    r_close(s); return -1;
}

/* one RPC round-trip; returns resp.ret (or a large negative on framing error).  Caller holds nothing;
 * this locks g_lock internally. */
static long nsp(uint32_t op, int rfd, int a0,int a1,int a2,
                const void *sbuf, uint32_t sblen, const void *saddr, uint32_t salen,
                void *rbuf, uint32_t rbufmax, uint32_t *rblen,
                void *raddr, uint32_t raddrmax, uint32_t *ralen)
{
    long ret = -1000;
    pthread_once(&g_pool_once, pool_init);
    /* slot 0 is the CONTROL plane (socket create + close); data-plane ops hash to slots 1..NSP_POOL-1
     * by fd.  Two reasons: (1) a create-cleanup NSP_CLOSE must reuse the SAME warm connection the
     * create used — a cold hash-slot could need a fresh native fd, impossible in the EMFILE path that
     * triggers that cleanup, which would leak the LKL socket; keeping close on slot 0 avoids it.
     * (2) reserving slot 0 for control means a blocking recvfrom (which parks its slot up to 1s) never
     * lands on slot 0, so it can never head-of-line-block a create/close.  A data op keeps per-fd
     * affinity (same fd -> same slot 1..15) so netlink per-socket ordering holds; close is a socket's
     * LAST op (app-serialized after all its data ops complete) so routing it to slot 0 cannot reorder
     * against them. */
    int slot = (rfd >= 0 && op != NSP_CLOSE) ? (1 + (rfd % (NSP_POOL - 1))) : 0;
    pthread_mutex_lock(&g_connlock[slot]);
    if (g_conn[slot] < 0) g_conn[slot] = provider_connect();
    if (g_conn[slot] < 0) { pthread_mutex_unlock(&g_connlock[slot]); return -1000; }
    int c = g_conn[slot];

    nsp_req rq; memset(&rq,0,sizeof rq);
    rq.op=op; rq.fd=rfd; rq.a0=a0; rq.a1=a1; rq.a2=a2; rq.buflen=sblen; rq.addrlen=salen;
    if (!wrf(c,&rq,sizeof rq)) goto out;
    if (sblen && !wrf(c,sbuf,sblen)) goto out;
    if (salen && !wrf(c,saddr,salen)) goto out;

    nsp_resp rs;
    if (!rdf(c,&rs,sizeof rs)) goto out;
    char junk[512];
    if (rs.buflen) {
        uint32_t take = rs.buflen < rbufmax ? rs.buflen : rbufmax;
        if (take && rbuf && !rdf(c,rbuf,take)) goto out;
        if (rblen) *rblen = take;
        for (uint32_t left = rs.buflen - take; left; ){ uint32_t cc=left<sizeof junk?left:sizeof junk; if(!rdf(c,junk,cc))goto out; left-=cc; }
    } else if (rblen) *rblen = 0;
    if (rs.addrlen) {
        uint32_t take = rs.addrlen < raddrmax ? rs.addrlen : raddrmax;
        if (take && raddr && !rdf(c,raddr,take)) goto out;
        if (ralen) *ralen = take;
        for (uint32_t left = rs.addrlen - take; left; ){ uint32_t cc=left<sizeof junk?left:sizeof junk; if(!rdf(c,junk,cc))goto out; left-=cc; }
    } else if (ralen) *ralen = 0;
    ret = (long)rs.ret;
out:
    /* A framing failure (ret still the -1000 transport sentinel) leaves this stream byte-desynced;
     * drop the slot's connection so the NEXT call reconnects fresh instead of corrupting every
     * future RPC on it.  The pool confines the damage to one slot, not the whole process. */
    if (ret == -1000) { r_close(c); g_conn[slot] = -1; }
    pthread_mutex_unlock(&g_connlock[slot]);
    return ret;
}

static int should_route(int domain)
{
    return domain==AF_NETLINK || domain==AF_PACKET || domain==AF_INET || domain==AF_INET6;
}

/* report a milestone to the provider (visible channel).  Uses its own short-lived connection so
 * it never interferes with the main routed-socket connection/mutex. */
static void shim_log(const char *msg)
{
    if (!g_log) return;
    int s = r_socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return;
    struct sockaddr_un sa; memset(&sa,0,sizeof sa);
    sa.sun_family = AF_UNIX; strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path)-1);
    if (r_connect(s,(struct sockaddr*)&sa,sizeof sa)!=0){ r_close(s); return; }
    nsp_req rq; memset(&rq,0,sizeof rq); rq.op=NSP_LOG; rq.buflen=(uint32_t)strlen(msg);
    if (wrf(s,&rq,sizeof rq) && (rq.buflen==0||wrf(s,msg,rq.buflen))){ nsp_resp rs; rdf(s,&rs,sizeof rs); }
    r_close(s);
}

/* count nl80211 scan-result BSSes in a received netlink buffer (each BSS = one AP): walk nlmsgs,
 * look past the 20-byte nlmsg+genl headers for an attribute of type 47 (NL80211_ATTR_BSS). */
static int count_bss(const unsigned char *b, unsigned n)
{
    int aps = 0; unsigned off = 0;
    while (off + 16 <= n) {
        uint32_t len = *(const uint32_t*)(b+off);
        if (len < 16 || off+len > n) break;
        unsigned a = off + 20;                       /* nlmsghdr(16)+genlmsghdr(4) */
        while (a + 4 <= off+len) {
            uint16_t alen = *(const uint16_t*)(b+a);
            uint16_t atyp = *(const uint16_t*)(b+a+2);
            if (alen < 4 || a+alen > off+len) break;
            if (atyp == 47) { aps++; break; }        /* NL80211_ATTR_BSS */
            a += (alen+3)&~3;
        }
        off += (len+3)&~3;
    }
    return aps;
}

/* set errno from a negative provider return; return -1 (or 0 mapping handled by caller). */
static long fail(long r){ if (r < 0 && r > -1000) errno = (int)(-r); else if (r <= -1000) errno = EIO; return -1; }

/* Is this received netlink buffer the END of the outstanding request's reply?  A dump ends with
 * NLMSG_DONE(3); an ack/error is NLMSG_ERROR(2); a plain (non-NLM_F_MULTI) reply is complete in
 * itself.  Used to clear g_pending so the lost-reply logic knows when nothing is owed anymore. */
static int nl_reply_complete(const unsigned char *b, unsigned n)
{
    unsigned off = 0;
    while (off + 16 <= n) {
        uint32_t len  = *(const uint32_t*)(b+off);
        uint16_t type = *(const uint16_t*)(b+off+4);
        uint16_t flg  = *(const uint16_t*)(b+off+6);
        if (len < 16 || off+len > n) break;
        if (type == 3 /*NLMSG_DONE*/ || type == 2 /*NLMSG_ERROR*/) return 1;
        if (!(flg & 0x2 /*NLM_F_MULTI*/)) return 1;
        off += (len+3)&~3;
    }
    return 0;
}

/* May the saved request be safely RE-SENT after its reply was lost?  Only idempotent reads:
 * any NLM_F_DUMP, an rtnetlink RTM_GET* (type%4==2 on NETLINK_ROUTE), or genl-ctrl GETFAMILY.
 * State-changing requests (NEW/DEL/SET, nl80211 TRIGGER_SCAN/CONNECT...) are never re-sent. */
static int nl_resendable(int fd)
{
    if ((g_last_nlflags[fd] & 0x300 /*NLM_F_DUMP=ROOT|MATCH*/) == 0x300) return 1;
    if (g_nlproto[fd] == 0 /*NETLINK_ROUTE*/ && g_last_tx[fd] >= 16 && (g_last_tx[fd] & 3) == 2) return 1;
    if (g_nlproto[fd] == 16 /*NETLINK_GENERIC*/ && g_last_tx[fd] == 16 /*nlctrl*/ && g_last_cmd[fd] == 3 /*CTRL_CMD_GETFAMILY*/) return 1;
    return 0;
}

/* ===================== interposed libc functions ===================== */

int socket(int domain, int type, int protocol)
{
    resolve();
    /* UNGATED (AF_PACKET socket() is rare) — definitively answers 'did the DHCP client ever call
     * socket(AF_PACKET)?': if this never logs during the NM DHCP phase, n-dhcp4 stalls BEFORE creating
     * its packet socket (its start-delay timer never fires) → an external DHCP client is the fix. */
    if (domain == AF_PACKET) {
        char m[96]; snprintf(m, sizeof m, "shim: >> socket(AF_PACKET) type=0x%x proto=0x%x ENTERED (dhcp-diag)", type, protocol); flog(m);
    }
    if (!should_route(domain)) {
        if (domain == AF_PACKET && g_pktSetup < 128) {
            char m[96]; snprintf(m, sizeof m, "shim: AF_PACKET socket() NOT routed (should_route=0) type=0x%x proto=0x%x (dhcp-diag)", type, protocol); flog(m); g_pktSetup++;
        }
        return r_socket(domain, type, protocol);
    }
    long R = nsp(NSP_SOCKET, -1, domain, type, protocol, 0,0,0,0, 0,0,0,0,0,0);
    if (R < 0) {
        if (domain == AF_PACKET && g_pktSetup < 128) {
            char m[96]; snprintf(m, sizeof m, "shim: AF_PACKET socket(type=0x%x,proto=0x%x) NSP_SOCKET FAILED R=%ld (dhcp-diag)", type, protocol, R); flog(m); g_pktSetup++;
        }
        return (int)fail(R);
    }
    int ph = r_socket(AF_UNIX, SOCK_STREAM, 0);      /* placeholder fd number */
    if (ph < 0 || ph >= MAXFD) { nsp(NSP_CLOSE,(int)R,0,0,0,0,0,0,0,0,0,0,0,0,0); errno=EMFILE; return -1; }
    g_routed[ph] = 1; g_remote[ph] = (int)R; g_dom[ph] = domain;
    g_nonblock[ph] = (type & 04000 /*SOCK_NONBLOCK*/) ? 1 : 0;
    g_nlproto[ph] = (domain == AF_NETLINK) ? protocol : -1;
    g_pending[ph] = 0; g_rx_since_tx[ph] = 0; g_req_savelen[ph] = 0;   /* fd numbers get reused */
    if (g_log) { char m[80]; snprintf(m,sizeof m,"shim: wpa opened routed socket (family %d) -> LKL fd %ld", domain, R); shim_log(m); }
    if (domain == AF_PACKET && g_pktSetup < 128) {
        char m[96]; snprintf(m, sizeof m, "shim: AF_PACKET socket(type=0x%x,proto=0x%x) -> LKL fd %ld (dhcp-diag)", type, protocol, R); flog(m); g_pktSetup++;
    }
    return ph;
}

int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    resolve();
    if (!routed(fd)) return r_bind(fd, addr, len);
    long r = nsp(NSP_BIND, g_remote[fd], 0,0,0, 0,0, addr, len, 0,0,0,0,0,0);
    if (fd >= 0 && fd < MAXFD && g_dom[fd] == AF_PACKET && g_pktSetup < 128) {
        char m[64]; snprintf(m, sizeof m, "shim: AF_PACKET bind -> %ld (dhcp-diag)", r); flog(m); g_pktSetup++;
    }
    return r==0 ? 0 : (int)fail(r);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    resolve();
    if (!routed(fd)) return r_connect(fd, addr, len);
    long r = nsp(NSP_CONNECT, g_remote[fd], 0,0,0, 0,0, addr, len, 0,0,0,0,0,0);
    return r==0 ? 0 : (int)fail(r);
}

/* The placeholder is not connected in the native kernel, so peer and half-close operations must be
 * executed by the LKL provider that owns the real socket. */
int getpeername(int fd, struct sockaddr *addr, socklen_t *alen)
{
    resolve();
    if (!routed(fd)) return r_getpeername(fd, addr, alen);
    uint32_t ga = 0;
    long r = nsp(NSP_GETPEERNAME, g_remote[fd], alen ? *alen : 0, 0,0,
                 0,0,0,0, 0,0,0, addr, addr&&alen ? *alen : 0, &ga);
    if (r != 0) return (int)fail(r);
    if (alen) *alen = ga;
    return 0;
}

int shutdown(int fd, int how)
{
    resolve();
    if (!routed(fd)) return r_shutdown(fd, how);
    long r = nsp(NSP_SHUTDOWN, g_remote[fd], how,0,0, 0,0,0,0, 0,0,0,0,0,0);
    return r == 0 ? 0 : (int)fail(r);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *addr, socklen_t alen)
{
    resolve();
    if (!routed(fd)) return r_sendto(fd, buf, len, flags, addr, alen);
    /* record the last netlink request on this fd so the STUCK diagnostic (recvfrom) can name the op a
     * genuine no-reply hang is blocked on — and keep its BYTES so a lost reply to an idempotent read
     * can be recovered by simply re-issuing the request (LOST-REPLY RECOVERY in recvfrom). */
    if (fd >= 0 && fd < MAXFD && g_dom[fd] == AF_NETLINK && len >= 16) {
        const unsigned char *b = buf;
        g_last_tx[fd]  = *(const unsigned short*)(b+4);   /* nlmsghdr.nlmsg_type */
        g_last_cmd[fd] = (len >= 20) ? b[16] : 0;          /* genlmsghdr.cmd (nl80211) */
        g_last_txlen[fd] = (unsigned)len;
        g_last_nlflags[fd] = *(const unsigned short*)(b+6);/* nlmsghdr.nlmsg_flags */
        g_pending[fd] = (g_last_nlflags[fd] & 0x1 /*NLM_F_REQUEST*/) ? 1 : 0;
        g_rx_since_tx[fd] = 0;
        g_req_savelen[fd] = 0;
        if (g_pending[fd] && len <= NSHIM_REQSAVE) {
            if (!g_req_save[fd]) g_req_save[fd] = malloc(NSHIM_REQSAVE);
            if (g_req_save[fd]) { memcpy(g_req_save[fd], buf, len); g_req_savelen[fd] = (unsigned)len; }
        }
    }
    if (fd >= 0 && fd < MAXFD && g_dom[fd] == AF_PACKET && g_pktTx < 128) {
        char m[80]; snprintf(m, sizeof m, "shim: AF_PACKET TX len=%zu (dhcp-diag)", len); flog(m); g_pktTx++;
    }
    long r = nsp(NSP_SENDTO, g_remote[fd], 0,0,flags, buf,(uint32_t)len, addr,(uint32_t)alen, 0,0,0,0,0,0);
    return r>=0 ? (ssize_t)r : (ssize_t)fail(r);
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *addr, socklen_t *alen)
{
    resolve();
    if (!routed(fd)) return r_recvfrom(fd, buf, len, flags, addr, alen);
    uint32_t got=0, ga=0;
    /* Honor blocking semantics: for a BLOCKING socket (not O_NONBLOCK, no MSG_DONTWAIT), the
     * provider's per-call 1s recv-poll (lkl-boot.c NSP_RECVFROM) returning -EAGAIN must NOT surface
     * to the app (libnl's blocking recvmsg mishandles it) — retry until data arrives.  For
     * non-blocking, return EAGAIN.  One retry ~= 1 second.
     * LOST-REPLY RECOVERY: when a request is outstanding (g_pending) and NOTHING of its reply has
     * arrived, a lost reply used to burn the full old 240-try cap (~4min of dead boot) before
     * surfacing — now an idempotent read (nl_resendable) is simply RE-ISSUED after ~5s, and the
     * outstanding-request cap is 60s.  Pure event waits (mcast listeners, nothing owed) keep the
     * long 240s cap so a legitimately quiet blocking socket isn't broken. */
    int blocking = !g_nonblock[fd] && !(flags & 0x40 /*MSG_DONTWAIT*/);
    int nlfd = (fd >= 0 && fd < MAXFD && g_dom[fd] == AF_NETLINK);
    long r;
    for (int tries = 0; ; tries++) {
        got = 0; ga = 0;
        r = nsp(NSP_RECVFROM, g_remote[fd], (int)len, 0, flags, 0,0,0,0,
                buf,(uint32_t)len,&got, addr, addr&&alen?*alen:0, &ga);
        if (r == -11 /*EAGAIN*/ && blocking && tries < ((nlfd && g_pending[fd]) ? 60 : 240)) {
            /* M3 trace: NM's platform init is stuck here waiting for a reply that never comes.
             * Log which request (the last TX on this netlink fd) it is blocked on. */
            if (nlfd && (tries == 1 || tries == 5 || tries == 30)) {
                char m[160]; snprintf(m,sizeof m,"nm-trace: STUCK fd=%d %d-EAGAIN waiting reply nlmsg_type=%u genl_cmd=%u len_last=%u prev_rx_true_len=%ld cap=%u%s",
                                      fd, tries, g_last_tx[fd], g_last_cmd[fd], g_last_txlen[fd], g_last_truelen[fd], (unsigned)NSP_HARDCAP,
                                      (g_last_truelen[fd] > (long)NSP_HARDCAP) ? " *** PREV RX EXCEEDED HARDCAP ***" : "");
                flog(m);
                shim_log(m);   /* genuine no-reply hang: surface it (bounded: only tries 1/5/30) */
            }
            /* Re-issue a lost idempotent request (same bytes = same nlmsg_seq, so the app's reply
             * matching is untouched).  Only when NO part of the reply ever arrived — a mid-dump
             * loss must NOT be re-sent (the app already consumed earlier parts; a re-run would
             * duplicate them) and instead surfaces via the 60s cap. */
            if (nlfd && g_pending[fd] && !g_rx_since_tx[fd] && g_req_savelen[fd] &&
                (tries == 5 || tries == 20) && nl_resendable(fd)) {
                char m[120]; snprintf(m,sizeof m,"nm-trace: RE-REQUEST fd=%d after %ds nlmsg_type=%u genl_cmd=%u (reply lost)",
                                      fd, tries, g_last_tx[fd], g_last_cmd[fd]);
                flog(m); shim_log(m);
                nsp(NSP_SENDTO, g_remote[fd], 0,0,0, g_req_save[fd], g_req_savelen[fd], 0,0, 0,0,0,0,0,0);
            }
            continue;
        }
        break;
    }
    /* record the true datagram length for the STUCK diagnostic (above) to report on a genuine hang,
     * and advance the lost-reply state machine: data arrived; a DONE/ERROR/non-MULTI message means
     * the outstanding request has been fully answered. */
    if (nlfd && r >= 0) {
        g_last_truelen[fd] = r;
        g_rx_since_tx[fd] = 1;
        if (got && nl_reply_complete((const unsigned char*)buf, got)) g_pending[fd] = 0;
    }
    if (fd >= 0 && fd < MAXFD && g_dom[fd] == AF_PACKET && r >= 0 && g_pktRx < 128) {
        char m[80]; snprintf(m, sizeof m, "shim: AF_PACKET RX len=%ld (dhcp-diag)", (long)r); flog(m); g_pktRx++;
    }
    if (r < 0) return (ssize_t)fail(r);
    if (addr && alen) *alen = ga;
    if (g_log && got && g_dom[fd]==AF_NETLINK) {           /* count nl80211 scan-result BSSes */
        int aps = count_bss((const unsigned char*)buf, got);
        if (aps > 0) { g_ap_total += aps; char m[80]; snprintf(m,sizeof m,"shim: wpa scan results via LKL: +%d AP(s) (total %d)", aps, g_ap_total); shim_log(m); }
    }
    /* r is the TRUE datagram length (provider forces MSG_TRUNC); got is the bytes actually copied.
     * Honor the caller's MSG_TRUNC: return the true length so libnl's PEEK-to-size path works. */
    return (flags & 0x20 /*MSG_TRUNC*/) ? (ssize_t)r : (ssize_t)got;
}

ssize_t send(int fd, const void *buf, size_t len, int flags){ return sendto(fd,buf,len,flags,0,0); }
ssize_t recv(int fd, void *buf, size_t len, int flags){ return recvfrom(fd,buf,len,flags,0,0); }

/* netlink/packet clients use sendmsg/recvmsg; flatten a single-iov msghdr to sendto/recvfrom. */
/* HEAP-allocated per-thread scratch that GROWS on demand (NOT static __thread array): at 128KB a static
 * __thread array x2 x every NM thread overran musl's static-TLS budget and faulted on real hardware.  A
 * thread-local POINTER + size (16 bytes TLS) + a lazily (re)alloc'd buffer keeps the big buffer off TLS.
 * `need` = the caller's real request (libnl's iovtotal); we grow to it so a large AX210 datagram is
 * received WHOLE instead of truncated.  Floor NSP_MAXBUF (avoid churn on the common small reads), ceil
 * NSP_HARDCAP (bound the alloc).  On realloc failure keep the old buffer; the caller null-checks. */
static char *nsh_scratch(size_t need)
{
    static __thread char  *tmp = 0;
    static __thread size_t cap = 0;
    if (need < NSP_MAXBUF)  need = NSP_MAXBUF;
    if (need > NSP_HARDCAP) need = NSP_HARDCAP;
    if (cap < need) {
        char *nb = realloc(tmp, need);
        if (!nb) return 0;         /* keep old block (realloc left it intact), but signal ENOMEM: the
                                    * caller MUST NOT read `need` bytes into a buffer smaller than need. */
        tmp = nb; cap = need;
    }
    return tmp;                    /* guaranteed: cap >= need, so the returned buffer holds `need` bytes */
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
    resolve();
    if (!routed(fd)) return r_sendmsg(fd, msg, flags);
    size_t want=0; for (int i=0;i<msg->msg_iovlen;i++) want += msg->msg_iov[i].iov_len;
    /* netlink TX requests are tiny; keep TX bounded to the provider's fixed NSP_MAXBUF reqbuf so an
     * oversize send fails cleanly here (EMSGSIZE) instead of tripping the provider's guard and killing
     * the shared connection.  Only the RX path grows (large AX210 GET_WIPHY replies). */
    if (want > NSP_MAXBUF) { errno=EMSGSIZE; return -1; }
    char *tmp = nsh_scratch(want);
    if (!tmp) { errno = ENOMEM; return -1; }
    size_t total=0;
    for (int i=0;i<msg->msg_iovlen;i++){ size_t l=msg->msg_iov[i].iov_len;
        memcpy(tmp+total, msg->msg_iov[i].iov_base, l); total+=l; }
    return sendto(fd, tmp, total, flags, (struct sockaddr*)msg->msg_name, msg->msg_namelen);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
    resolve();
    if (!routed(fd)) return r_recvmsg(fd, msg, flags);
    /* Read up to the caller's REAL buffer size (libnl sized it via a prior MSG_PEEK|MSG_TRUNC), not a
     * fixed 128KB — otherwise a large AX210 datagram is truncated here and libnl desyncs.  Grow the
     * scratch to match (capped at NSP_HARDCAP). */
    size_t iovtotal = 0; for (int i=0;i<msg->msg_iovlen;i++) iovtotal += msg->msg_iov[i].iov_len;
    size_t want = iovtotal ? iovtotal : NSP_MAXBUF;
    if (want > NSP_HARDCAP) want = NSP_HARDCAP;
    char *tmp = nsh_scratch(want);
    if (!tmp) { errno = ENOMEM; return -1; }
    socklen_t al = msg->msg_namelen;
    ssize_t n = recvfrom(fd, tmp, want, flags, (struct sockaddr*)msg->msg_name, &al);
    if (n < 0) return -1;
    msg->msg_namelen = al;
    /* NM/libnl set SO_PASSCRED on the netlink socket and DROP any datagram whose recvmsg lacks an
     * SCM_CREDENTIALS cmsg with creds.pid==0 (kernel) — nm-linux-platform.c _netlink_recv_handle
     * `goto stop` on `!creds_has || creds.pid`.  The provider relays only the payload, so synthesise
     * the kernel credential here: every message the LKL delivers on a netlink socket originates in the
     * (LKL) kernel, so pid=0/uid=0/gid=0 is exactly correct.  Without this, NM ingests ZERO links. */
    if (fd >= 0 && fd < MAXFD && g_dom[fd] == AF_NETLINK && msg->msg_control &&
        msg->msg_controllen >= CMSG_SPACE(sizeof(struct ucred))) {
        struct cmsghdr *cm = CMSG_FIRSTHDR(msg);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type  = SCM_CREDENTIALS;
        cm->cmsg_len   = CMSG_LEN(sizeof(struct ucred));
        struct ucred uc = { 0, 0, 0 };   /* pid=0 => kernel-originated */
        memcpy(CMSG_DATA(cm), &uc, sizeof uc);
        msg->msg_controllen = CMSG_SPACE(sizeof(struct ucred));
    } else {
        msg->msg_controllen = 0;
    }
    /* n is the TRUE datagram length (may exceed our buffer via MSG_TRUNC); only min(n,want) bytes are
     * actually present in tmp. */
    size_t valid = ((size_t)n < want) ? (size_t)n : want;
    size_t off=0;
    for (int i=0;i<msg->msg_iovlen && off<valid;i++){ size_t l=msg->msg_iov[i].iov_len; if (l>valid-off) l=valid-off;
        memcpy(msg->msg_iov[i].iov_base, tmp+off, l); off+=l; }
    /* CRITICAL: surface MSG_TRUNC when the datagram was larger than the caller's buffers — this is the
     * signal libnl's nl_recv() uses (PEEK-then-size) to grow its buffer and retry.  Previously this was
     * hardcoded to 0, so libnl silently under-read a truncated GET_WIPHY reply and hung. */
    msg->msg_flags = ((size_t)n > iovtotal) ? 0x20 /*MSG_TRUNC*/ : 0;
    return n;   /* TRUE length so the caller sizes correctly */
}

int setsockopt(int fd, int level, int optname, const void *val, socklen_t len)
{
    resolve();
    if (!routed(fd)) return r_setsockopt(fd, level, optname, val, len);
    /* SO_ATTACH_FILTER(26)/SO_ATTACH_BPF(50): optval is a `struct sock_fprog { u16 len; sock_filter
     * *filter; }` whose `filter` member is a pointer into THIS (client) process.  The provider forwards
     * the 16-byte sock_fprog verbatim and the LKL's copy_from_user(fprog->filter, len*8) then derefs
     * that CLIENT pointer inside the PROVIDER's address space -> fatal "no region" fault (crashes the
     * provider's per-connection thread mid wpa interface-init).  The BPF filter is a RX optimisation and
     * is redundant with the AF_PACKET socket's bind protocol (ETH_P_PAE) / userspace demux, so no-op it
     * (return success) rather than crash the provider.  (A full fix would marshal the filter array into
     * the RPC and reconstruct fprog in the provider.) */
    if (level == 1 /*SOL_SOCKET*/ && (optname == 26 || optname == 50)) {
        if (fd >= 0 && fd < MAXFD && g_dom[fd] == AF_PACKET && g_pktSetup < 128) {
            char m[80]; snprintf(m, sizeof m, "shim: AF_PACKET setsockopt lvl=%d opt=%d (BPF no-op) (dhcp-diag)", level, optname); flog(m); g_pktSetup++;
        }
        return 0;
    }
    long r = nsp(NSP_SETSOCKOPT, g_remote[fd], level, optname, 0, val,(uint32_t)len, 0,0, 0,0,0,0,0,0);
    if (fd >= 0 && fd < MAXFD && g_dom[fd] == AF_PACKET && g_pktSetup < 128) {
        char m[80]; snprintf(m, sizeof m, "shim: AF_PACKET setsockopt lvl=%d opt=%d -> %ld (dhcp-diag)", level, optname, r); flog(m); g_pktSetup++;
    }
    return r==0 ? 0 : (int)fail(r);
}

int getsockopt(int fd, int level, int optname, void *val, socklen_t *len)
{
    resolve();
    if (!routed(fd)) return r_getsockopt(fd, level, optname, val, len);
    uint32_t got=0;
    long r = nsp(NSP_GETSOCKOPT, g_remote[fd], level, optname, len?*len:0, 0,0,0,0, val, len?*len:0, &got, 0,0,0);
    if (r != 0) return (int)fail(r);
    if (len) *len = got;
    return 0;
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *len)
{
    resolve();
    if (!routed(fd)) return r_getsockname(fd, addr, len);
    uint32_t ga=0;
    long r = nsp(NSP_GETSOCKNAME, g_remote[fd], len?*len:0, 0,0, 0,0,0,0, 0,0,0, addr, len?*len:0, &ga);
    if (r != 0) return (int)fail(r);
    if (len) *len = ga;
    return 0;
}

int close(int fd)
{
    resolve();
    if (routed(fd)) { nsp(NSP_CLOSE, g_remote[fd], 0,0,0,0,0,0,0,0,0,0,0,0,0); g_routed[fd]=0; }
    return r_close(fd);
}

/* Track O_NONBLOCK for routed fds so recvfrom knows whether to block; pass through otherwise. */
int fcntl(int fd, int cmd, ...)
{
    resolve();
    long arg;
    __builtin_va_list ap; __builtin_va_start(ap, cmd); arg = __builtin_va_arg(ap, long); __builtin_va_end(ap);
    if (!routed(fd)) return r_fcntl(fd, cmd, arg);
    if (cmd == 3 /*F_GETFL*/) return 02 /*O_RDWR*/ | (g_nonblock[fd] ? 04000 : 0);
    if (cmd == 4 /*F_SETFL*/) { g_nonblock[fd] = (arg & 04000 /*O_NONBLOCK*/) ? 1 : 0; return 0; }
    return 0;   /* other fcntl on the placeholder: benign success */
}

int ioctl(int fd, unsigned long req, ...)
{
    resolve();
    void *arg;
    __builtin_va_list ap; __builtin_va_start(ap, req); arg = __builtin_va_arg(ap, void*); __builtin_va_end(ap);
    if (!routed(fd)) return r_ioctl(fd, req, arg);
    /* pass a bounded copy of the arg struct (ifreq is 40 bytes; use 256 to be safe) */
    unsigned char io[256];
    memcpy(io, arg, sizeof io);
    uint32_t got=0;
    long r = nsp(NSP_IOCTL, g_remote[fd], (int)req, 0,0, io, sizeof io, 0,0, io, sizeof io, &got, 0,0,0);
    if (g_log) { char m[96]; snprintf(m,sizeof m,"shim: wpa ioctl(0x%lx) on wlan0 -> ret=%ld%s", req, r, r>=0?"  (interface EXISTS on real hw)":"  (errno on QEMU=no-wlan0)"); shim_log(m); }
    if (r < 0) return (int)fail(r);
    if (got) memcpy(arg, io, got < sizeof io ? got : sizeof io);
    return (int)r;
}

/* musl's if_indextoname()/if_nametoindex() do the SIOCGIF{NAME,INDEX} ioctl on an AF_UNIX socket, which
 * the shim does NOT route -> the ioctl never reaches the LKL that owns wlan0 -> NM's supplicant setup
 * fails with "Cannot find interface N" (nm-supplicant-manager.c _create_iface_dbus_start).  Override both
 * to use a ROUTED AF_INET socket so the ioctl is carried to the LKL via NSP_IOCTL.  (socket/ioctl/close
 * below resolve to the shim's own routed overrides.) */
char *if_indextoname(unsigned int index, char *name)
{
    resolve();
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    ifr.ifr_ifindex = (int)index;
    int r = ioctl(fd, SIOCGIFNAME, &ifr);
    int e = errno;
    close(fd);
    if (r < 0) { errno = e ? e : 19 /*ENODEV*/; return 0; }
    strncpy(name, ifr.ifr_name, IF_NAMESIZE - 1);
    name[IF_NAMESIZE - 1] = 0;
    return name;
}

unsigned int if_nametoindex(const char *name)
{
    resolve();
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    int r = ioctl(fd, SIOCGIFINDEX, &ifr);
    close(fd);
    if (r < 0) return 0;
    return (unsigned int)ifr.ifr_ifindex;
}

/* poll(): route each routed fd through NSP_POLL, real-poll the rest, loop until ready/timeout.
 * EVENT-DRIVEN WAITING (WiFi boot-latency fix — the old loop r_poll'd locals with timeout 0 and
 * flat-slept 10ms per round, taxing EVERY main-loop wakeup of NM/wpa/udhcpc with up to 10ms; over
 * the thousands of netlink round-trips of NM's boot enumeration that summed to tens of seconds):
 *  - ONE routed fd and NO locals (udhcpc's lease select, libnl waits): a provider-side BLOCKING
 *    NSP_POLL (a1 = timeout, ppoll'd against the LKL fd) — readiness returns the instant it
 *    happens, no quantum at all.  Sliced to 100ms so the mutex-serialized shared connection is
 *    never held long (another thread's RPC interleaves between slices).
 *  - MIXED set (NM's GLib loop: D-Bus/timer fds + routed netlink): non-blocking NSP_POLL rounds
 *    for the routed fds, then wait INSIDE r_poll(locals) so a local event wakes us instantly and
 *    is returned on the spot; the wait starts at 1ms (hot bring-up traffic) and backs off x2 to
 *    50ms (idle) so routed readiness is seen within ~1ms when it matters without idle CPU churn
 *    (idle NSP_POLL rounds: 20/s vs the old flat 100/s). */
int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    resolve();
    int n_routed = 0, n_local = 0;
    for (nfds_t i=0;i<nfds;i++) { if (routed(fds[i].fd)) n_routed++; else n_local++; }
    if (!n_routed) return r_poll(fds, nfds, timeout);

    struct timespec start; clock_gettime(CLOCK_MONOTONIC, &start);
    int wait_ms = 1;                                   /* adaptive: 1ms hot -> 50ms idle */
    for (;;) {
        int remaining = -1;                            /* ms left; -1 = infinite */
        if (timeout >= 0) {
            struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
            long el = (now.tv_sec-start.tv_sec)*1000 + (now.tv_nsec-start.tv_nsec)/1000000;
            remaining = (timeout > el) ? (int)(timeout - el) : 0;
        }

        if (n_routed == 1 && n_local == 0 && timeout != 0) {
            /* single routed fd, nothing local: block provider-side (fully event-driven) */
            struct pollfd *f = &fds[0];
            for (nfds_t i=0;i<nfds;i++) if (routed(fds[i].fd)) { f = &fds[i]; break; }
            f->revents = 0;
            int slice = (remaining < 0 || remaining > 100) ? 100 : remaining;
            long rv = nsp(NSP_POLL, g_remote[f->fd], f->events, slice, 0, 0,0,0,0, 0,0,0,0,0,0);
            if (rv > 0) { f->revents = (short)rv; return 1; }
            if (rv < 0) { struct timespec nap = {0, 50000000L}; nanosleep(&nap, 0); }  /* dead provider: don't hot-spin */
            if (remaining >= 0 && remaining <= slice) return 0;
            continue;
        }

        int ready = 0;
        for (nfds_t i=0;i<nfds;i++) {
            fds[i].revents = 0;
            if (routed(fds[i].fd)) {
                long rv = nsp(NSP_POLL, g_remote[fds[i].fd], fds[i].events, 0 /*non-blocking*/, 0, 0,0,0,0, 0,0,0,0,0,0);
                if (rv > 0) { fds[i].revents = (short)rv; ready++; }
            } else {
                struct pollfd one = { fds[i].fd, fds[i].events, 0 };
                if (r_poll(&one, 1, 0) > 0) { fds[i].revents = one.revents; ready++; }
            }
        }
        if (ready) return ready;
        if (timeout == 0 || remaining == 0) return 0;

        int w = wait_ms;
        if (remaining >= 0 && w > remaining) w = remaining;
        if (n_local) {
            /* wait ON the local fds: a local event (D-Bus message, GLib timerfd) ends the wait
             * instantly and is reported right here, skipping a whole extra round. */
            struct pollfd lp[64]; int ln = 0;
            for (nfds_t i=0;i<nfds && ln<64;i++)
                if (!routed(fds[i].fd)) { lp[ln].fd=fds[i].fd; lp[ln].events=fds[i].events; lp[ln].revents=0; ln++; }
            int lr = r_poll(lp, (nfds_t)ln, w);
            if (lr > 0) {
                int nr = 0, k = 0;
                for (nfds_t i=0;i<nfds;i++) {
                    fds[i].revents = 0;
                    if (!routed(fds[i].fd) && k < ln) { fds[i].revents = lp[k].revents; if (lp[k].revents) nr++; k++; }
                }
                if (nr) return nr;
            }
        } else {
            struct timespec nap = { w/1000, (long)(w%1000)*1000000L }; nanosleep(&nap, 0);
        }
        if (wait_ms < 50) { wait_ms *= 2; if (wait_ms > 50) wait_ms = 50; }
    }
}

/* wpa mostly uses recvmsg/sendmsg, but guard read/write on routed fds too. */
ssize_t read(int fd, void *buf, size_t n){ resolve(); if(routed(fd)) return recvfrom(fd,buf,n,0,0,0); return r_read(fd,buf,n); }
ssize_t write(int fd, const void *buf, size_t n){ resolve(); if(routed(fd)) return sendto(fd,buf,n,0,0,0); return r_write(fd,buf,n); }
/* writev/readv MUST be interposed too: Dropbear's dbclient (the scp transport) writes every encrypted
 * SSH packet with writev() (packet.c write_packet).  Without this, writev() on a routed socket hits the
 * shim's UNCONNECTED AF_UNIX placeholder fd (r_socket at socket()) and fails ENOTCONN "Socket not
 * connected" — the connect/read go through fine, but the first packet write dies.  Route both through
 * the existing sendmsg/recvmsg, which coalesce/scatter the iov to NSP_SENDTO/NSP_RECVFROM on the LKL. */
ssize_t writev(int fd, const struct iovec *iov, int iovcnt){
    resolve();
    if(!routed(fd)) return r_writev(fd, iov, iovcnt);
    struct msghdr m; memset(&m, 0, sizeof m);
    m.msg_iov = (struct iovec*)iov; m.msg_iovlen = iovcnt;
    return sendmsg(fd, &m, 0);
}
ssize_t readv(int fd, const struct iovec *iov, int iovcnt){
    resolve();
    if(!routed(fd)) return r_readv(fd, iov, iovcnt);
    struct msghdr m; memset(&m, 0, sizeof m);
    m.msg_iov = (struct iovec*)iov; m.msg_iovlen = iovcnt;
    return recvmsg(fd, &m, 0);
}

/* select(): dropbear's dbclient (the scp transport) is select-driven — without this, a routed
 * TCP socket's placeholder fd is select()ed against the LOCAL kernel (never ready) and the SSH
 * session hangs forever after connect.  Translate the fd_sets onto this shim's own poll()
 * (which already splits routed fds -> NSP_POLL and local fds -> real poll), then rebuild the
 * sets from revents.  Returns the select-style count of ready BITS across all three sets.
 * (The residual-timeout writeback into *tv is not emulated; dropbear recomputes each loop.) */
int select(int nfds, fd_set *rf, fd_set *wf, fd_set *ef, struct timeval *tv)
{
    resolve();
    if (nfds > FD_SETSIZE) nfds = FD_SETSIZE;
    int any_routed = 0;
    for (int fd = 0; fd < nfds && !any_routed; fd++) {
        if (!routed(fd)) continue;
        if ((rf && FD_ISSET(fd, rf)) || (wf && FD_ISSET(fd, wf)) || (ef && FD_ISSET(fd, ef)))
            any_routed = 1;
    }
    if (!any_routed) return r_select(nfds, rf, wf, ef, tv);

    struct pollfd pf[128];
    int n = 0;
    for (int fd = 0; fd < nfds && n < 128; fd++) {
        short ev = 0;
        if (rf && FD_ISSET(fd, rf)) ev |= POLLIN;
        if (wf && FD_ISSET(fd, wf)) ev |= POLLOUT;
        if (ef && FD_ISSET(fd, ef)) ev |= POLLPRI;
        if (!ev) continue;
        pf[n].fd = fd; pf[n].events = ev; pf[n].revents = 0; n++;
    }
    int timeout = -1;
    if (tv) {
        long ms = tv->tv_sec * 1000L + (tv->tv_usec + 999) / 1000;
        timeout = (ms < 0) ? 0 : (ms > 0x7fffffffL ? -1 : (int)ms);
    }
    int rc = poll(pf, (nfds_t)n, timeout);   /* this .so's poll: routed+local hybrid */
    if (rf) FD_ZERO(rf);
    if (wf) FD_ZERO(wf);
    if (ef) FD_ZERO(ef);
    if (rc <= 0) return rc;
    int bits = 0;
    for (int i = 0; i < n; i++) {
        if (!pf[i].revents) continue;
        /* report a condition only where the caller asked for it on THAT fd; ERR/HUP surface
         * as readable+writable per select semantics so callers notice the failure. */
        if ((pf[i].events & POLLIN)  && rf && (pf[i].revents & (POLLIN|POLLERR|POLLHUP)))  { FD_SET(pf[i].fd, rf); bits++; }
        if ((pf[i].events & POLLOUT) && wf && (pf[i].revents & (POLLOUT|POLLERR|POLLHUP))) { FD_SET(pf[i].fd, wf); bits++; }
        if ((pf[i].events & POLLPRI) && ef && (pf[i].revents & POLLPRI))                    { FD_SET(pf[i].fd, ef); bits++; }
    }
    return bits;
}
