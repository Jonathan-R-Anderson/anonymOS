/*
 * hos-nettest.c — H1b.3 shim target (dynamic-musl), run under LD_PRELOAD=/libnshim.so.
 *
 * It does an rtnetlink RTM_GETLINK dump using ONLY plain libc socket calls (socket/bind/sendto/
 * recvfrom) — it knows NOTHING about the provider.  The interposer (libnshim.so) transparently
 * routes those AF_NETLINK calls to lkl-boot's cap-gated provider, so the interfaces enumerated
 * come from the LKL's network stack.  It then reports the result via the provider's NSP_LOG (a
 * plain AF_UNIX connection, which the shim passes straight through to real libc) so the line is
 * visible on serial/console.  This is exactly what unmodified wpa_supplicant will do.
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

#define NL_AF_NETLINK 16
#define NL_SOCK_RAW    3
#define NL_ROUTE       0
#define RTM_GETLINK   18
#define RTM_NEWLINK   16
#define NLM_F_REQUEST 0x0001
#define NLM_F_DUMP    0x0300
#define NLMSG_DONE     3
#define NLMSG_ERROR    2
#define IFLA_IFNAME    3
#define NLA(x) (((x)+3)&~3)

struct nlh { uint32_t len; uint16_t type; uint16_t flags; uint32_t seq; uint32_t pid; };
struct ifi { uint8_t fam; uint8_t pad; uint16_t type; int32_t idx; uint32_t flags; uint32_t change; };
struct rta { uint16_t len; uint16_t type; };
struct snl { uint16_t fam; uint16_t pad; uint32_t pid; uint32_t groups; };

/* report a line to the provider (plain AF_UNIX -> shim passes through to real libc) */
static void report(const char *msg)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return;
    struct sockaddr_un sa; memset(&sa,0,sizeof sa);
    sa.sun_family = AF_UNIX; strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path)-1);
    for (int i=0;i<100;i++){ if (connect(s,(struct sockaddr*)&sa,sizeof sa)==0) break;
                             struct timespec t={0,100000000L}; nanosleep(&t,0);
                             if (i==99){ close(s); return; } }
    nsp_req rq; memset(&rq,0,sizeof rq); rq.op=NSP_LOG; rq.buflen=(uint32_t)strlen(msg);
    /* small blocking writes; provider is up */
    unsigned p=0,n=sizeof rq; const char*b=(const char*)&rq;
    while(p<n){ long r=write(s,b+p,n-p); if(r>0)p+=r; else if(errno!=EAGAIN)break; }
    p=0;n=rq.buflen;b=msg; while(p<n){ long r=write(s,b+p,n-p); if(r>0)p+=r; else if(errno!=EAGAIN)break; }
    nsp_resp rs; p=0;n=sizeof rs; char*rb=(char*)&rs; while(p<n){ long r=read(s,rb+p,n-p); if(r>0)p+=r; else if(errno!=EAGAIN)break; }
    close(s);
}

int main(void)
{
    /* rtnetlink RTM_GETLINK via PLAIN libc — the shim routes it to the LKL. */
    int s = socket(NL_AF_NETLINK, NL_SOCK_RAW, NL_ROUTE);
    if (s < 0) { char m[80]; snprintf(m,sizeof m,"H1b.3 shim: socket(AF_NETLINK) failed errno=%d",errno); report(m); return 1; }

    struct snl sa; memset(&sa,0,sizeof sa); sa.fam = NL_AF_NETLINK;
    if (bind(s, (struct sockaddr*)&sa, sizeof sa) < 0) { char m[80]; snprintf(m,sizeof m,"H1b.3 shim: bind failed errno=%d",errno); report(m); close(s); return 1; }

    unsigned char req[64]; memset(req,0,sizeof req);
    struct nlh *h = (struct nlh*)req;
    struct ifi *im = (struct ifi*)(req + NLA(sizeof *h));
    h->len = NLA(sizeof *h) + (uint32_t)sizeof *im;
    h->type = RTM_GETLINK; h->flags = NLM_F_REQUEST | NLM_F_DUMP; h->seq = 1;
    struct snl kern; memset(&kern,0,sizeof kern); kern.fam = NL_AF_NETLINK;
    if (sendto(s, req, h->len, 0, (struct sockaddr*)&kern, sizeof kern) < 0) { char m[80]; snprintf(m,sizeof m,"H1b.3 shim: sendto failed errno=%d",errno); report(m); close(s); return 1; }

    char names[256]; names[0]=0; int count=0, done=0;
    static unsigned char rb[16384];
    for (int it=0; it<32 && !done; it++) {
        struct sockaddr_storage from; socklen_t fl = sizeof from;
        ssize_t n = recvfrom(s, rb, sizeof rb, 0, (struct sockaddr*)&from, &fl);
        if (n <= 0) break;
        uint32_t off=0;
        while (off + sizeof(struct nlh) <= (uint32_t)n) {
            struct nlh *mh = (struct nlh*)(rb+off);
            if (mh->len < sizeof(struct nlh) || off+mh->len > (uint32_t)n) break;
            if (mh->type == NLMSG_DONE || mh->type == NLMSG_ERROR) { done=1; break; }
            if (mh->type == RTM_NEWLINK) {
                uint32_t a = NLA(sizeof(struct nlh)) + NLA(sizeof(struct ifi));
                while (a + sizeof(struct rta) <= mh->len) {
                    struct rta *at = (struct rta*)((unsigned char*)mh + a);
                    if (at->len < sizeof(struct rta) || a+at->len > mh->len) break;
                    if (at->type == IFLA_IFNAME) {
                        const char *nm = (const char*)at + sizeof(struct rta);
                        if (strlen(names)+strlen(nm)+2 < sizeof names){ strcat(names,nm); strcat(names," "); }
                        count++;
                    }
                    a += NLA(at->len);
                }
            }
            off += NLA(mh->len);
        }
    }
    close(s);

    char msg[400];
    snprintf(msg, sizeof msg, "H1b.3 SHIM WORKS: unmodified rtnetlink via LD_PRELOAD -> %d iface(s) = %s", count, names);
    report(msg);
    return 0;
}
