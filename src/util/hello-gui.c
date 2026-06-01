// hello-gui.c — Shared-memory GUI client for EpinAnonymOS (Phase 4)
// Receives a memfd from the compositor via SCM_RIGHTS, mmaps it, and draws a
// live animated gradient + text directly into the shared window buffer using a
// timerfd for frame pacing.

typedef unsigned long  uint64_t;
typedef unsigned int   uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char  uint8_t;
typedef int            int32_t;
typedef long           ssize_t;
typedef unsigned long  size_t;
#define NULL ((void*)0)

#include "gui_font.h"

static inline long sc1(long n,long a){long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a):"rcx","r11","memory");return r;}
static inline long sc2(long n,long a,long b){long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a),"S"(b):"rcx","r11","memory");return r;}
static inline long sc3(long n,long a,long b,long c){long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");return r;}
static inline long sc4(long n,long a,long b,long c,long d){register long r10 __asm__("r10")=d;long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a),"S"(b),"d"(c),"r"(r10):"rcx","r11","memory");return r;}
static inline long sc6(long n,long a,long b,long c,long d,long e,long f){register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return r;}

#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_socket 41
#define SYS_connect 42
#define SYS_recvmsg 47
#define SYS_sched_yield 24
#define SYS_exit_group 231
#define SYS_timerfd_create 283
#define SYS_timerfd_settime 286

static ssize_t sys_read(int fd,void*b,size_t n){return sc3(SYS_read,fd,(long)b,(long)n);}
static ssize_t sys_write(int fd,const void*b,size_t n){return sc3(SYS_write,fd,(long)b,(long)n);}
static int sys_close(int fd){return (int)sc1(SYS_close,fd);}
static void* sys_mmap(void*a,size_t l,int p,int f,int fd,long o){return (void*)sc6(SYS_mmap,(long)a,(long)l,p,f,fd,o);}
static int sys_socket(int d,int t,int p){return (int)sc3(SYS_socket,d,t,p);}
static int sys_connect(int fd,const void*a,int l){return (int)sc3(SYS_connect,fd,(long)a,l);}
static long sys_recvmsg(int fd,void*m,int f){return sc3(SYS_recvmsg,fd,(long)m,f);}
static void sys_yield(void){sc1(SYS_sched_yield,0);}
static void sys_exit(int c){sc1(SYS_exit_group,c);}
static int sys_timerfd_create(int c,int f){return (int)sc2(SYS_timerfd_create,c,f);}
static int sys_timerfd_settime(int fd,int fl,const void*nv,void*ov){return (int)sc4(SYS_timerfd_settime,fd,fl,(long)nv,(long)ov);}

static size_t slen(const char*s){size_t n=0;while(s[n])n++;return n;}
size_t strlen(const char*s){return slen(s);}
void* memset(void*d,int c,size_t n){uint8_t*p=d;while(n--)*p++=(uint8_t)c;return d;}
void* memcpy(void*d,const void*s,size_t n){uint8_t*p=d;const uint8_t*q=s;while(n--)*p++=*q++;return d;}
static void print(const char*s){sys_write(1,s,slen(s));}
static void println(const char*s){print(s);print("\n");}
static ssize_t write_all(int fd,const void*b,size_t n){const char*p=b;size_t d=0;while(d<n){ssize_t r=sys_write(fd,p+d,n-d);if(r>0)d+=r;else if(r==0||r==-32)return -1;else sys_yield();}return (ssize_t)n;}
static ssize_t read_all(int fd,void*b,size_t n){char*p=b;size_t d=0;while(d<n){ssize_t r=sys_read(fd,p+d,n-d);if(r>0)d+=r;else if(r==0)return (ssize_t)d;else sys_yield();}return (ssize_t)n;}

// ── msghdr / cmsg ───────────────────────────────────────────────────────────
struct iovec { void* iov_base; size_t iov_len; };
struct msghdr { void* msg_name; unsigned msg_namelen; struct iovec* msg_iov; size_t msg_iovlen; void* msg_control; size_t msg_controllen; int msg_flags; };
struct cmsghdr { size_t cmsg_len; int cmsg_level; int cmsg_type; };

// Receive `len` payload bytes + one fd via SCM_RIGHTS.  Returns fd or -1.
static int recv_fd(int sock, void* payload, size_t len){
    struct iovec iov={payload,len};
    uint8_t cbuf[sizeof(struct cmsghdr)+sizeof(int)];
    struct msghdr msg={0};
    msg.msg_iov=&iov; msg.msg_iovlen=1;
    msg.msg_control=cbuf; msg.msg_controllen=sizeof cbuf;
    for(;;){
        long r=sys_recvmsg(sock,&msg,0);
        if(r>0) break;
        if(r==0) return -1;
        sys_yield();
    }
    if(msg.msg_controllen>=sizeof(struct cmsghdr)){
        struct cmsghdr*cm=(struct cmsghdr*)cbuf;
        if(cm->cmsg_level==1 && cm->cmsg_type==1)
            return *(int*)(cbuf+sizeof(struct cmsghdr));
    }
    return -1;
}

// ── protocol ──────────────────────────────────────────────────────────────────
#define MSG_CREATE_WINDOW  1
#define MSG_WINDOW_CREATED 2
#define MSG_REPAINT        6
#define MSG_KEY_EVENT      7
typedef struct { uint32_t type, len; } MsgHdr;
typedef struct { int32_t x,y,w,h; char title[64]; } MsgCreateWindow;
typedef struct { int32_t window_id, w, h, stride; } MsgWindowCreated;
typedef struct { int32_t window_id; } MsgSimple;
typedef struct { int32_t keycode, value; } MsgKeyEvent;

struct sockaddr_un { uint16_t sun_family; char sun_path[108]; };
struct itimerspec { long it_iv_s, it_iv_ns, it_v_s, it_v_ns; };

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_PATH "/run/compositor.sock"
#define PROT_RW 3
#define MAP_SHARED 1
#define WIN_W 400
#define WIN_H 300

static int g_fd, g_wid, g_w, g_h, g_stride;
static uint32_t *g_px;
static int g_last_key=0;

static void send_repaint(void){ MsgHdr h={MSG_REPAINT,sizeof(MsgSimple)}; MsgSimple p={g_wid}; write_all(g_fd,&h,sizeof h); write_all(g_fd,&p,sizeof p); }

static void draw(int frame){
    // Animated vertical gradient that scrolls with the frame counter.
    for(int row=0;row<g_h;row++){
        int t=(row+frame)&0xFF;
        uint32_t b=0x40+(t*0xB0/0xFF), r=0x20+(((g_h-row)+frame)&0xFF)*0x60/0xFF;
        uint32_t color=(r<<16)|(0x20<<8)|b;
        for(int col=0;col<g_w;col++) g_px[row*g_stride+col]=color;
    }
    gf_text(g_px,g_stride,g_w,g_h,16,24,"Hello from EpinAnonymOS!",0x00FFFFFF,-1);
    gf_text(g_px,g_stride,g_w,g_h,16,44,"Shared-memory window (memfd)",0x00FFFF80,-1);
    gf_text(g_px,g_stride,g_w,g_h,16,72,"Type keys; ESC to quit.",0x0080FF80,-1);
    char buf[40]; int v=frame; char*p=buf+39;*p=0; if(v==0)*--p='0'; while(v){*--p='0'+(v%10);v/=10;}
    gf_text(g_px,g_stride,g_w,g_h,16,108,"frame:",0x00FFD0D0,-1);
    gf_text(g_px,g_stride,g_w,g_h,72,108,p,0x00FFD0D0,-1);
    if(g_last_key){
        char kb[24]; int kv=g_last_key; char*q=kb+23;*q=0; if(kv==0)*--q='0'; while(kv){*--q='0'+(kv%10);kv/=10;}
        gf_text(g_px,g_stride,g_w,g_h,16,140,"last key:",0x00FFFFFF,-1);
        gf_text(g_px,g_stride,g_w,g_h,96,140,q,0x0000FF00,-1);
    }
    send_repaint();
}

void _start(void){
    println("[hello-gui] starting (Phase 4)");
    g_fd=sys_socket(AF_UNIX,SOCK_STREAM,0);
    if(g_fd<0){println("[hello-gui] socket fail");sys_exit(1);}
    struct sockaddr_un a={0}; a.sun_family=AF_UNIX;
    size_t pl=slen(SOCK_PATH); memcpy(a.sun_path,SOCK_PATH,pl+1);
    int conn=-1;
    for(int i=0;i<100000 && conn<0;i++){ conn=sys_connect(g_fd,&a,(int)(2+pl+1)); if(conn<0) sys_yield(); }
    if(conn<0){println("[hello-gui] connect fail");sys_exit(1);}
    println("[hello-gui] connected");

    // Request a window.
    MsgHdr h={MSG_CREATE_WINDOW,sizeof(MsgCreateWindow)};
    MsgCreateWindow cw={0}; cw.x=220; cw.y=160; cw.w=WIN_W; cw.h=WIN_H;
    const char*t="hello-gui"; memcpy(cw.title,t,slen(t)+1);
    write_all(g_fd,&h,sizeof h); write_all(g_fd,&cw,sizeof cw);

    // Read reply header, then payload+memfd via SCM_RIGHTS.
    MsgHdr rh; if(read_all(g_fd,&rh,sizeof rh)!=(ssize_t)sizeof(rh)||rh.type!=MSG_WINDOW_CREATED){println("[hello-gui] no window");sys_exit(1);}
    MsgWindowCreated wc;
    int memfd=recv_fd(g_fd,&wc,sizeof wc);
    if(memfd<0||wc.window_id==0){println("[hello-gui] no memfd");sys_exit(1);}
    g_wid=wc.window_id; g_w=wc.w; g_h=wc.h; g_stride=wc.stride;
    size_t bytes=(size_t)g_stride*g_h*4;
    g_px=sys_mmap(NULL,bytes,PROT_RW,MAP_SHARED,memfd,0);
    if(g_px==(void*)-1){println("[hello-gui] mmap fail");sys_exit(1);}
    println("[hello-gui] window mapped");

    // 30 fps frame timer via timerfd.
    int tfd=sys_timerfd_create(1 /*CLOCK_MONOTONIC*/,0);
    struct itimerspec its={0,33*1000000L,0,33*1000000L}; // 33ms interval & initial
    sys_timerfd_settime(tfd,0,&its,NULL);

    int frame=0;
    draw(frame);
    while(1){
        // Drain key events (non-blocking).
        MsgHdr ih;
        ssize_t r=sys_read(g_fd,&ih,sizeof ih);
        if(r==0){println("[hello-gui] compositor gone");sys_exit(0);}
        if(r==(ssize_t)sizeof(ih) && ih.type==MSG_KEY_EVENT){
            MsgKeyEvent e; read_all(g_fd,&e,sizeof e);
            if(e.value==1){ if(e.keycode==1){println("[hello-gui] ESC");sys_exit(0);} g_last_key=e.keycode; }
        }
        // Wait for the next frame tick.
        uint64_t exp; ssize_t tr=sys_read(tfd,&exp,sizeof exp);
        if(tr==8){ frame++; draw(frame); }
        sys_yield();
    }
}
