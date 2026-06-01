module core.syscalls.socket;

alias ssize_t = long;

enum AF_UNIX = 1;
enum AF_INET = 2;
enum SOCK_STREAM = 1;
enum SOCK_DGRAM = 2;

struct sockaddr
{
    ushort sa_family;
    char[14] sa_data;
}

struct sockaddr_un
{
    ushort sun_family;
    char[108] sun_path;
}

struct iovec
{
    void* iov_base;
    size_t iov_len;
}

struct msghdr
{
    void* msg_name;
    uint msg_namelen;
    iovec* msg_iov;
    size_t msg_iovlen;
    void* msg_control;
    size_t msg_controllen;
    int msg_flags;
}

// Ancillary message header for SCM_RIGHTS fd passing
struct cmsghdr
{
    size_t cmsg_len;    // Total length, including header
    int    cmsg_level;  // Originating protocol (SOL_SOCKET)
    int    cmsg_type;   // Protocol-specific type (SCM_RIGHTS)
    // Followed by data payload
}

enum SOL_SOCKET = 1;
enum SCM_RIGHTS = 1;

enum MSG_PEEK    = 0x02;
enum MSG_TRUNC   = 0x20;
enum MSG_DONTWAIT = 0x40;
enum MSG_CMSG_CLOEXEC = 0x40000000;

extern(C) @nogc nothrow:

int sys_socket(int domain, int type, int protocol);
int sys_bind(int sockfd, sockaddr* addr, uint addrlen);
int sys_listen(int sockfd, int backlog);
int sys_accept(int sockfd, sockaddr* addr, uint* addrlen);
int sys_connect(int sockfd, const(sockaddr)* addr, uint addrlen);
ssize_t sys_sendmsg(int sockfd, msghdr* msg, int flags);
ssize_t sys_recvmsg(int sockfd, msghdr* msg, int flags);
ssize_t sys_sendto(int sockfd, const(void)* buf, size_t len, int flags, const(sockaddr)* dest_addr, uint addrlen);
ssize_t sys_recvfrom(int sockfd, void* buf, size_t len, int flags, sockaddr* src_addr, uint* addrlen);