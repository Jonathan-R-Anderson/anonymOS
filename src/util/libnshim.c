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
#include <sys/un.h>
#include <net/if.h>
#include <poll.h>
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
static int (*r_fcntl)(int,int,...);
static int (*r_open)(const char*,int,...);

static void resolve(void)
{
    if (r_socket) return;
#define R(f) r_##f = dlsym(RTLD_NEXT, #f)
    R(socket); R(bind); R(connect); R(sendto); R(recvfrom); R(sendmsg); R(recvmsg);
    R(setsockopt); R(getsockopt); R(getsockname); R(close); R(ioctl); R(poll); R(read); R(write); R(fcntl);
    R(open);
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

/* --- routed-fd table: app fd -> provider remote LKL fd --- */
static int  g_remote[MAXFD];
static char g_routed[MAXFD];
static int  g_dom[MAXFD];      /* domain of a routed socket (for nl80211 scan counting) */
static char g_nonblock[MAXFD]; /* app set this routed fd non-blocking (O_NONBLOCK / SOCK_NONBLOCK) */
static unsigned short g_last_tx[MAXFD];    /* last netlink nlmsg_type sent on a routed fd (M3 trace) */
static unsigned char  g_last_cmd[MAXFD];   /* last genl cmd (nl80211) sent on a routed fd */
static unsigned int   g_last_txlen[MAXFD]; /* last netlink TX payload length on a routed fd */
static long           g_last_truelen[MAXFD]; /* last netlink RX true datagram length (H3 discriminator) */

static int routed(int fd){ return fd >= 0 && fd < MAXFD && g_routed[fd]; }

/* H3/Option-B visibility: when HOS_SHIM_LOG=1, the shim reports wpa's key milestones through the
 * provider's NSP_LOG (the channel that IS visible on the laptop framebuffer, unlike a spawned
 * process's own stderr).  Set once in the constructor. */
#include <stdlib.h>
static int g_log = 0;
static int g_ap_total = 0;
__attribute__((constructor)) static void nshim_cfg(void){ g_log = getenv("HOS_SHIM_LOG") != 0; }

/* --- one persistent provider connection, mutex-serialized --- */
static int g_conn = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int rdf(int fd, void *b, unsigned n){ unsigned g=0; while(g<n){ long r=r_read(fd,(char*)b+g,n-g); if(r>0){g+=r;continue;} if(r<0&&errno==EAGAIN){struct timespec t={0,2000000L};nanosleep(&t,0);continue;} return 0;} return 1; }
static int wrf(int fd, const void *b, unsigned n){ unsigned p=0; while(p<n){ long r=r_write(fd,(const char*)b+p,n-p); if(r>0){p+=r;continue;} if(r<0&&errno==EAGAIN){struct timespec t={0,2000000L};nanosleep(&t,0);continue;} return 0;} return 1; }

static int provider_connect(void)
{
    int s = r_socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un sa; memset(&sa,0,sizeof sa);
    sa.sun_family = AF_UNIX; strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path)-1);
    for (int i=0;i<200;i++){ if (r_connect(s,(struct sockaddr*)&sa,sizeof sa)==0) return s;
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
    pthread_mutex_lock(&g_lock);
    if (g_conn < 0) g_conn = provider_connect();
    if (g_conn < 0) { pthread_mutex_unlock(&g_lock); return -1000; }

    nsp_req rq; memset(&rq,0,sizeof rq);
    rq.op=op; rq.fd=rfd; rq.a0=a0; rq.a1=a1; rq.a2=a2; rq.buflen=sblen; rq.addrlen=salen;
    if (!wrf(g_conn,&rq,sizeof rq)) goto out;
    if (sblen && !wrf(g_conn,sbuf,sblen)) goto out;
    if (salen && !wrf(g_conn,saddr,salen)) goto out;

    nsp_resp rs;
    if (!rdf(g_conn,&rs,sizeof rs)) goto out;
    char junk[512];
    if (rs.buflen) {
        uint32_t take = rs.buflen < rbufmax ? rs.buflen : rbufmax;
        if (take && rbuf && !rdf(g_conn,rbuf,take)) goto out;
        if (rblen) *rblen = take;
        for (uint32_t left = rs.buflen - take; left; ){ uint32_t c=left<sizeof junk?left:sizeof junk; if(!rdf(g_conn,junk,c))goto out; left-=c; }
    } else if (rblen) *rblen = 0;
    if (rs.addrlen) {
        uint32_t take = rs.addrlen < raddrmax ? rs.addrlen : raddrmax;
        if (take && raddr && !rdf(g_conn,raddr,take)) goto out;
        if (ralen) *ralen = take;
        for (uint32_t left = rs.addrlen - take; left; ){ uint32_t c=left<sizeof junk?left:sizeof junk; if(!rdf(g_conn,junk,c))goto out; left-=c; }
    } else if (ralen) *ralen = 0;
    ret = (long)rs.ret;
out:
    pthread_mutex_unlock(&g_lock);
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

/* ===================== interposed libc functions ===================== */

int socket(int domain, int type, int protocol)
{
    resolve();
    if (!should_route(domain)) return r_socket(domain, type, protocol);
    long R = nsp(NSP_SOCKET, -1, domain, type, protocol, 0,0,0,0, 0,0,0,0,0,0);
    if (R < 0) return (int)fail(R);
    int ph = r_socket(AF_UNIX, SOCK_STREAM, 0);      /* placeholder fd number */
    if (ph < 0 || ph >= MAXFD) { nsp(NSP_CLOSE,(int)R,0,0,0,0,0,0,0,0,0,0,0,0,0); errno=EMFILE; return -1; }
    g_routed[ph] = 1; g_remote[ph] = (int)R; g_dom[ph] = domain;
    g_nonblock[ph] = (type & 04000 /*SOCK_NONBLOCK*/) ? 1 : 0;
    if (g_log) { char m[80]; snprintf(m,sizeof m,"shim: wpa opened routed socket (family %d) -> LKL fd %ld", domain, R); shim_log(m); }
    return ph;
}

int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    resolve();
    if (!routed(fd)) return r_bind(fd, addr, len);
    long r = nsp(NSP_BIND, g_remote[fd], 0,0,0, 0,0, addr, len, 0,0,0,0,0,0);
    return r==0 ? 0 : (int)fail(r);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    resolve();
    if (!routed(fd)) return r_connect(fd, addr, len);
    long r = nsp(NSP_CONNECT, g_remote[fd], 0,0,0, 0,0, addr, len, 0,0,0,0,0,0);
    return r==0 ? 0 : (int)fail(r);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *addr, socklen_t alen)
{
    resolve();
    if (!routed(fd)) return r_sendto(fd, buf, len, flags, addr, alen);
    /* record the last netlink request on this fd so the STUCK diagnostic (recvfrom) can name the op a
     * genuine no-reply hang is blocked on. */
    if (fd >= 0 && fd < MAXFD && g_dom[fd] == AF_NETLINK && len >= 20) {
        const unsigned char *b = buf;
        g_last_tx[fd]  = *(const unsigned short*)(b+4);   /* nlmsghdr.nlmsg_type */
        g_last_cmd[fd] = b[16];                            /* genlmsghdr.cmd (nl80211) */
        g_last_txlen[fd] = (unsigned)len;
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
     * provider's per-call 5s poll-timeout returning -EAGAIN must NOT surface to the app (libnl's
     * blocking recvmsg mishandles it) — retry until data arrives.  For non-blocking, return EAGAIN. */
    int blocking = !g_nonblock[fd] && !(flags & 0x40 /*MSG_DONTWAIT*/);
    long r;
    for (int tries = 0; ; tries++) {
        got = 0; ga = 0;
        r = nsp(NSP_RECVFROM, g_remote[fd], (int)len, 0, flags, 0,0,0,0,
                buf,(uint32_t)len,&got, addr, addr&&alen?*alen:0, &ga);
        if (r == -11 /*EAGAIN*/ && blocking && tries < 240) {
            /* M3 trace: NM's platform init is stuck here waiting for a reply that never comes.
             * Log which request (the last TX on this netlink fd) it is blocked on. */
            if (fd >= 0 && fd < MAXFD && g_dom[fd] == AF_NETLINK && (tries == 1 || tries == 5 || tries == 30)) {
                char m[160]; snprintf(m,sizeof m,"nm-trace: STUCK fd=%d %d-EAGAIN waiting reply nlmsg_type=%u genl_cmd=%u len_last=%u prev_rx_true_len=%ld cap=%u%s",
                                      fd, tries, g_last_tx[fd], g_last_cmd[fd], g_last_txlen[fd], g_last_truelen[fd], (unsigned)NSP_HARDCAP,
                                      (g_last_truelen[fd] > (long)NSP_HARDCAP) ? " *** PREV RX EXCEEDED HARDCAP ***" : "");
                flog(m);
                shim_log(m);   /* genuine no-reply hang: surface it (bounded: only tries 1/5/30) */
            }
            continue;   /* ~20min cap; data normally <5s */
        }
        break;
    }
    /* record the true datagram length for the STUCK diagnostic (above) to report on a genuine hang. */
    if (fd >= 0 && fd < MAXFD && g_dom[fd] == AF_NETLINK && r >= 0) g_last_truelen[fd] = r;
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
    if (level == 1 /*SOL_SOCKET*/ && (optname == 26 || optname == 50)) return 0;
    long r = nsp(NSP_SETSOCKOPT, g_remote[fd], level, optname, 0, val,(uint32_t)len, 0,0, 0,0,0,0,0,0);
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

/* poll(): route each routed fd through NSP_POLL, real-poll the rest, loop until ready/timeout. */
int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    resolve();
    int any_routed = 0;
    for (nfds_t i=0;i<nfds;i++) if (routed(fds[i].fd)) { any_routed = 1; break; }
    if (!any_routed) return r_poll(fds, nfds, timeout);

    struct timespec start; clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
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
        if (timeout == 0) return 0;
        if (timeout > 0) {
            struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
            long ms = (now.tv_sec-start.tv_sec)*1000 + (now.tv_nsec-start.tv_nsec)/1000000;
            if (ms >= timeout) return 0;
        }
        struct timespec nap = {0, 10000000L}; nanosleep(&nap, 0);   /* 10ms poll granularity */
    }
}

/* wpa mostly uses recvmsg/sendmsg, but guard read/write on routed fds too. */
ssize_t read(int fd, void *buf, size_t n){ resolve(); if(routed(fd)) return recvfrom(fd,buf,n,0,0,0); return r_read(fd,buf,n); }
ssize_t write(int fd, const void *buf, size_t n){ resolve(); if(routed(fd)) return sendto(fd,buf,n,0,0,0); return r_write(fd,buf,n); }
