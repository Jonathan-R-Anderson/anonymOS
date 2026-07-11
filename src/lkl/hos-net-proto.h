/*
 * hos-net-proto.h — cap-gated LKL network-provider RPC (H1b).
 *
 * Shared by the provider (src/lkl/lkl-boot.c, running inside the LKL host process) and native
 * clients (src/util/hos-wifi.c; later the wpa_supplicant/NetworkManager syscall-shim).  The
 * client speaks these framed requests over the DEVCLASS_NET-gated AF_UNIX socket NSP_PATH; the
 * provider executes each as the corresponding lkl_sys_* against the real wlan0 and replies.
 *
 * Wire framing (stream socket, all little-endian host order — same arch both ends):
 *     [nsp_req][buflen bytes][addrlen bytes]   ->   [nsp_resp][buflen bytes][addrlen bytes]
 */
#ifndef HOS_NET_PROTO_H
#define HOS_NET_PROTO_H
#include <stdint.h>

#define NSP_PATH   "/run/hos-net.sock"
/* 128KB: the real AX210's nl80211 GET_WIPHY split-dump datagrams (bands/HE/VHT capa, cipher suites,
 * iface combinations) + the large CTRL_GETFAMILY NEWFAMILY reply can approach/exceed 64KB.  A single
 * netlink recvfrom drains one datagram; if the buffer is smaller the tail is silently DISCARDED and
 * libnl's dump walker desyncs and never sees NLMSG_DONE -> NM hangs.  (QEMU never hits this: no wiphy,
 * tiny rtnetlink dumps.) */
#define NSP_MAXBUF 131072
/* NSP_MAXBUF is now only the INITIAL/floor buffer size, NOT a hard truncation point.  A single netlink
 * SOCK_DGRAM recvfrom drains one whole datagram; the real AX210's nl80211 GET_WIPHY (+ the big
 * CTRL_GETFAMILY NEWFAMILY) can exceed 128KB, and the tail is DISCARDED if the buffer is too small (a 2nd
 * recv can't recover it) -> libnl desyncs, never sees NLMSG_DONE, NM hangs.  So both ends GROW their
 * receive buffer to whatever the client actually requested (libnl sizes it via MSG_PEEK|MSG_TRUNC), up to
 * this shared sanity cap.  2MB dwarfs any realistic nl80211 datagram while bounding every allocation. */
#define NSP_HARDCAP (2u * 1024u * 1024u)

enum {
    NSP_SOCKET      = 1,  /* a0=domain a1=type a2=protocol            -> ret = lkl fd            */
    NSP_BIND        = 2,  /* fd, addr(addrlen)                        -> ret                     */
    NSP_CONNECT     = 3,  /* fd, addr(addrlen)                        -> ret                     */
    NSP_SENDTO      = 4,  /* fd, a2=flags, buf(buflen), addr(opt)     -> ret                     */
    NSP_RECVFROM    = 5,  /* fd, a0=maxlen, a2=flags                  -> ret; resp buf=data,addr=src */
    NSP_SETSOCKOPT  = 6,  /* fd, a0=level a1=optname, buf=optval      -> ret                     */
    NSP_GETSOCKOPT  = 7,  /* fd, a0=level a1=optname a2=maxlen        -> ret; resp buf=optval     */
    NSP_GETSOCKNAME = 8,  /* fd, a0=maxlen                            -> ret; resp addr           */
    NSP_CLOSE       = 9,  /* fd                                       -> ret                     */
    NSP_POLL        = 10, /* fd, a0=events a1=timeout_ms              -> ret = revents            */
    NSP_SCAN        = 11, /* (convenience) WEXT scan wlan0            -> resp buf = SSID text     */
    NSP_LOG         = 12, /* buf = text                              -> provider prints it (visible) */
    NSP_IOCTL       = 13, /* fd, a0=cmd, buf=arg-struct(in)          -> ret; resp buf=arg-struct(out) */
    NSP_GETTRACE    = 14, /* (no args)                               -> resp buf = accumulated NSP_LOG text (M4 diag) */
    NSP_GETPEERNAME = 15, /* fd, a0=maxlen                            -> ret; resp addr           */
    NSP_SHUTDOWN    = 16, /* fd, a0=how                               -> ret                     */
};

typedef struct {
    uint32_t op;
    int32_t  fd;
    int32_t  a0, a1, a2;
    uint32_t buflen;      /* trailing send buffer / optval length */
    uint32_t addrlen;     /* trailing sockaddr length             */
} nsp_req;

typedef struct {
    int64_t  ret;         /* syscall return (>=0) or -errno       */
    uint32_t buflen;      /* trailing returned data length        */
    uint32_t addrlen;     /* trailing returned sockaddr length    */
} nsp_resp;

#endif /* HOS_NET_PROTO_H */
