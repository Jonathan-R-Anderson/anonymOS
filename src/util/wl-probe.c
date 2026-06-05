// wl-probe.c - GUI roadmap G1 (client-launch mechanism) proof.
//
// A tiny freestanding (no libc, raw syscalls) second userspace process. The kernel
// launches it alongside Hyprland; it retries connecting an AF_UNIX socket to the
// Wayland display socket (/run/user/1000/wayland-0) until Hyprland binds it, then
// reports the result to the console (serial). A successful connect proves both that
// a second process started and that it reached the compositor's socket.
//
// Built freestanding/static like the other src/util clients (-nostdlib -e _start).

typedef unsigned long  size_t;
typedef long           ssize_t;
#define NULL ((void*)0)

static inline long sc1(long n,long a){long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a):"rcx","r11","memory");return r;}
static inline long sc3(long n,long a,long b,long c){long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");return r;}

#define SYS_write       1
#define SYS_close       3
#define SYS_nanosleep   35
#define SYS_socket      41
#define SYS_connect     42
#define SYS_exit_group  231

static ssize_t sys_write(int fd,const void*b,size_t n){return sc3(SYS_write,fd,(long)b,(long)n);}
static int  sys_close(int fd){return (int)sc1(SYS_close,fd);}
static int  sys_socket(int d,int t,int p){return (int)sc3(SYS_socket,d,t,p);}
static int  sys_connect(int fd,const void*a,int l){return (int)sc3(SYS_connect,fd,(long)a,l);}
static void sys_exit(int c){sc1(SYS_exit_group,c);for(;;){}}

struct timespec { long tv_sec; long tv_nsec; };
static void msleep(long ms){ struct timespec ts={ ms/1000, (ms%1000)*1000000L }; sc3(SYS_nanosleep,(long)&ts,0,0); }

static size_t slen(const char*s){size_t n=0;while(s[n])n++;return n;}
static void print(const char*s){ sys_write(1,s,slen(s)); }

#define AF_UNIX     1
#define SOCK_STREAM 1
struct sockaddr_un { unsigned short sun_family; char sun_path[108]; };

void _start(void)
{
    static const char path[] = "/run/user/1000/wayland-0";
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    size_t pl = slen(path);
    for (size_t i = 0; i < pl; ++i) addr.sun_path[i] = path[i];
    addr.sun_path[pl] = 0;
    int addrlen = (int)(2 + pl + 1);

    print("WLPROBE: started; waiting for wayland-0 ...\n");

    int connected_fd = -1;
    for (int attempt = 0; attempt < 120 && connected_fd < 0; ++attempt) {
        int fd = sys_socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd >= 0) {
            if (sys_connect(fd, &addr, addrlen) == 0) { connected_fd = fd; break; }
            sys_close(fd);
        }
        msleep(500); // wait ~0.5s for Hyprland to bind the display socket
    }

    if (connected_fd >= 0) {
        print("WLPROBE: connected to /run/user/1000/wayland-0 OK -- G1 DONE\n");
        sys_close(connected_fd);
    } else {
        print("WLPROBE: gave up; wayland-0 never accepted a connection\n");
    }
    sys_exit(0);
}
