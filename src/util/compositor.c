// compositor.c — Shared-memory framebuffer compositor for EpinAnonymOS (Phase 4)
// Freestanding: raw x86_64 syscalls, no libc.
//
// Each window's pixels live in a memfd that the compositor creates and passes to
// the client over the Unix socket via SCM_RIGHTS.  The client mmaps the same
// physical pages and draws directly; the compositor just blits + handles input,
// Z-order (raise on focus) and Alt+Tab.

typedef unsigned long  uint64_t;
typedef unsigned int   uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char  uint8_t;
typedef long           int64_t;
typedef int            int32_t;
typedef long           ssize_t;
typedef unsigned long  size_t;
#define NULL ((void*)0)

#include "gui_font.h"

// ── syscalls ──────────────────────────────────────────────────────────────────
static inline long sc1(long n,long a){long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a):"rcx","r11","memory");return r;}
static inline long sc2(long n,long a,long b){long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a),"S"(b):"rcx","r11","memory");return r;}
static inline long sc3(long n,long a,long b,long c){long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");return r;}
static inline long sc4(long n,long a,long b,long c,long d){register long r10 __asm__("r10")=d;long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a),"S"(b),"d"(c),"r"(r10):"rcx","r11","memory");return r;}
static inline long sc6(long n,long a,long b,long c,long d,long e,long f){register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long r;__asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return r;}

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_poll 7
#define SYS_mmap 9
#define SYS_ioctl 16
#define SYS_socket 41
#define SYS_accept 43
#define SYS_sendmsg 46
#define SYS_bind 49
#define SYS_listen 50
#define SYS_ftruncate 77
#define SYS_sched_yield 24
#define SYS_unlink 87
#define SYS_memfd_create 319
#define SYS_exit_group 231

static ssize_t sys_read(int fd,void*b,size_t n){return sc3(SYS_read,fd,(long)b,(long)n);}
static ssize_t sys_write(int fd,const void*b,size_t n){return sc3(SYS_write,fd,(long)b,(long)n);}
static int sys_open(const char*p,int f,int m){return (int)sc3(SYS_open,(long)p,f,m);}
static int sys_close(int fd){return (int)sc1(SYS_close,fd);}
static long sys_ioctl(int fd,unsigned long c,void*a){return sc3(SYS_ioctl,fd,(long)c,(long)a);}
static void* sys_mmap(void*a,size_t l,int p,int f,int fd,long o){return (void*)sc6(SYS_mmap,(long)a,(long)l,p,f,fd,o);}
static void sys_yield(void){sc1(SYS_sched_yield,0);}
static void sys_exit(int c){sc1(SYS_exit_group,c);}
static long sys_unlink(const char*p){return sc1(SYS_unlink,(long)p);}
static int sys_socket(int d,int t,int p){return (int)sc3(SYS_socket,d,t,p);}
static int sys_bind(int fd,const void*a,int l){return (int)sc3(SYS_bind,fd,(long)a,l);}
static int sys_listen(int fd,int b){return (int)sc2(SYS_listen,fd,b);}
static int sys_accept(int fd,void*a,int*l){return (int)sc3(SYS_accept,fd,(long)a,(long)l);}
static int sys_memfd_create(const char*n,unsigned f){return (int)sc2(SYS_memfd_create,(long)n,f);}
static int sys_ftruncate(int fd,long l){return (int)sc2(SYS_ftruncate,fd,l);}
static long sys_sendmsg(int fd,const void*m,int f){return sc3(SYS_sendmsg,fd,(long)m,f);}

struct pollfd { int fd; short events; short revents; };
static int sys_poll(struct pollfd*f,int n,int ms){return (int)sc3(SYS_poll,(long)f,n,ms);}

// ── msghdr / cmsg for SCM_RIGHTS ──────────────────────────────────────────────
struct iovec { void* iov_base; size_t iov_len; };
struct msghdr {
    void* msg_name; unsigned msg_namelen;
    struct iovec* msg_iov; size_t msg_iovlen;
    void* msg_control; size_t msg_controllen; int msg_flags;
};
struct cmsghdr { size_t cmsg_len; int cmsg_level; int cmsg_type; };
#define SOL_SOCKET 1
#define SCM_RIGHTS 1

// Send `payload` (len bytes) plus one fd over `sock` via SCM_RIGHTS.
static int send_fd(int sock, const void* payload, size_t len, int fd) {
    struct iovec iov = { (void*)payload, len };
    uint8_t cbuf[sizeof(struct cmsghdr) + sizeof(int)];
    struct cmsghdr* cm = (struct cmsghdr*)cbuf;
    cm->cmsg_len = sizeof(struct cmsghdr) + sizeof(int);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    *(int*)(cbuf + sizeof(struct cmsghdr)) = fd;
    struct msghdr msg = {0};
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = cbuf; msg.msg_controllen = cm->cmsg_len;
    return (int)sys_sendmsg(sock, &msg, 0);
}

// ── helpers ───────────────────────────────────────────────────────────────────
static size_t slen(const char*s){size_t n=0;while(s[n])n++;return n;}
size_t strlen(const char*s){return slen(s);}
void* memset(void*d,int c,size_t n){uint8_t*p=d;while(n--)*p++=(uint8_t)c;return d;}
void* memcpy(void*d,const void*s,size_t n){uint8_t*p=d;const uint8_t*q=s;while(n--)*p++=*q++;return d;}
void* memmove(void*d,const void*s,size_t n){uint8_t*p=d;const uint8_t*q=s;if(p<q){while(n--)*p++=*q++;}else{p+=n;q+=n;while(n--)*--p=*--q;}return d;}
static void print(const char*s){sys_write(1,s,slen(s));}
static void println(const char*s){print(s);print("\n");}
static ssize_t write_all(int fd,const void*b,size_t n){const char*p=b;size_t d=0;while(d<n){ssize_t r=sys_write(fd,p+d,n-d);if(r>0)d+=r;else if(r==0||r==-32)return -1;else sys_yield();}return (ssize_t)n;}
static ssize_t read_all(int fd,void*b,size_t n){char*p=b;size_t d=0;while(d<n){ssize_t r=sys_read(fd,p+d,n-d);if(r>0)d+=r;else if(r==0)return (ssize_t)d;else sys_yield();}return (ssize_t)n;}

// ── protocol ──────────────────────────────────────────────────────────────────
#define MSG_CREATE_WINDOW  1
#define MSG_WINDOW_CREATED 2   // reply carries memfd via SCM_RIGHTS
#define MSG_DESTROY_WINDOW 3
#define MSG_REPAINT        6
#define MSG_KEY_EVENT      7   // compositor → client

typedef struct { uint32_t type, len; } MsgHdr;
typedef struct { int32_t x,y,w,h; char title[64]; } MsgCreateWindow;
typedef struct { int32_t window_id, w, h, stride; } MsgWindowCreated;
typedef struct { int32_t window_id; } MsgSimple;
typedef struct { int32_t keycode, value; } MsgKeyEvent;

// ── DRM ───────────────────────────────────────────────────────────────────────
#define DRM_IOCTL_MODE_GETRESOURCES 0xC04064A0UL
#define DRM_IOCTL_MODE_GETCRTC      0xC06864A1UL
#define DRM_IOCTL_MODE_CREATE_DUMB  0xC02064B2UL
#define DRM_IOCTL_MODE_MAP_DUMB     0xC01064B3UL
struct drm_mode_card_res { uint64_t fb,crtc,conn,enc; uint32_t nfb,ncrtc,nconn,nenc,minw,maxw,minh,maxh; };
struct drm_mode_modeinfo { uint32_t clock; uint16_t hd,hss,hse,ht,hsk,vd,vss,vse,vt,vsc; uint32_t vr,fl,ty; char name[32]; };
struct drm_mode_crtc { uint64_t scp; uint32_t nc,crtc_id,fb_id,x,y,gs,mv; struct drm_mode_modeinfo mode; };
struct drm_mode_create_dumb { uint32_t height,width,bpp,flags,handle,pitch; uint64_t size; };
struct drm_mode_map_dumb { uint32_t handle,pad; uint64_t offset; };

// ── input ───────────────────────────────────────────────────────────────────
struct input_event { uint64_t s,us; uint16_t type,code; int32_t value; };
#define EV_SYN 0
#define EV_KEY 1
#define EV_REL 2
#define REL_X 0
#define REL_Y 1
#define BTN_LEFT 0x110
#define KEY_TAB 15
#define KEY_LEFTALT 56
#define POLLIN 1
#define O_RDWR 2
#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_PATH "/run/compositor.sock"
#define PROT_RW 3
#define MAP_SHARED 1

// ── state ─────────────────────────────────────────────────────────────────────
#define MAX_WINDOWS 8
#define TITLE_H 20
#define BORDER 1

typedef struct {
    int valid, id, x, y, w, h, stride_px, client_idx;
    uint32_t *shm;        // mmap'd shared pixel buffer
    char title[64];
} Window;
typedef struct { int valid, fd; } Client;

static int g_drm_fd=-1, g_kbd=-1, g_mouse=-1, g_srv=-1;
static uint32_t *g_fb; static int g_fb_w,g_fb_h,g_pitch_px; static uint32_t g_crtc;
static int g_mx,g_my, g_next_wid=1, g_alt_down=0;
static Window g_wins[MAX_WINDOWS];
static Client g_clients[MAX_WINDOWS];
static int g_zorder[MAX_WINDOWS];   // window slot indices, back→front
static int g_zcount=0;
static int g_focus=-1;              // slot index of focused window

// ── z-order ───────────────────────────────────────────────────────────────────
static void z_raise(int slot){
    int at=-1; for(int i=0;i<g_zcount;i++) if(g_zorder[i]==slot){at=i;break;}
    if(at<0){ if(g_zcount<MAX_WINDOWS) g_zorder[g_zcount++]=slot; at=g_zcount-1; }
    for(int i=at;i<g_zcount-1;i++) g_zorder[i]=g_zorder[i+1];
    g_zorder[g_zcount-1]=slot;
    g_focus=slot;
}
static void z_remove(int slot){
    int at=-1; for(int i=0;i<g_zcount;i++) if(g_zorder[i]==slot){at=i;break;}
    if(at<0) return;
    for(int i=at;i<g_zcount-1;i++) g_zorder[i]=g_zorder[i+1];
    g_zcount--;
    g_focus = (g_zcount>0) ? g_zorder[g_zcount-1] : -1;
}
static void alt_tab(void){
    if(g_zcount<2) return;
    int bottom=g_zorder[0];
    z_raise(bottom);
}

// ── fb drawing ─────────────────────────────────────────────────────────────────
static void fbfill(int x,int y,int w,int h,uint32_t c){gf_fill(g_fb,g_pitch_px,g_fb_w,g_fb_h,x,y,w,h,c);}
static void fbtext(int x,int y,const char*s,uint32_t fg,long bg){gf_text(g_fb,g_pitch_px,g_fb_w,g_fb_h,x,y,s,fg,bg);}

static const uint16_t g_cursor[16]={0x8000,0xC000,0xE000,0xF000,0xF800,0xFC00,0xFE00,0xFF00,0xFF80,0xFC00,0xEC00,0xC600,0x0600,0x0300,0x0300,0x0000};
static void draw_cursor(int cx,int cy){for(int r=0;r<16;r++)for(int c=0;c<16;c++)if((g_cursor[r]>>(15-c))&1)gf_put(g_fb,g_pitch_px,g_fb_w,g_fb_h,cx+c,cy+r,0x00FFFFFF);}

static void composite(void){
    fbfill(0,0,g_fb_w,g_fb_h,0x00203050);
    fbfill(0,g_fb_h-24,g_fb_w,24,0x00101830);
    fbtext(8,g_fb_h-16,"EpinAnonymOS  [Alt+Tab to switch]",0x00AAAAFF,0x00101830);

    for(int zi=0; zi<g_zcount; zi++){
        int s=g_zorder[zi]; Window*w=&g_wins[s];
        if(!w->valid) continue;
        int bx=w->x-BORDER, by=w->y-TITLE_H-BORDER;
        int bw=w->w+2*BORDER, bh=w->h+TITLE_H+2*BORDER;
        fbfill(bx+4,by+4,bw,bh,0x00080818);             // shadow
        fbfill(bx,by,bw,bh,0x00304070);                  // border
        uint32_t bar=(s==g_focus)?0x004060C0:0x00304060;
        fbfill(w->x,w->y-TITLE_H,w->w,TITLE_H,bar);
        fbtext(w->x+4,w->y-TITLE_H+6,w->title,0x00FFFFFF,bar);
        fbfill(w->x+w->w-16,w->y-TITLE_H+4,12,12,0x00C03030);
        fbtext(w->x+w->w-14,w->y-TITLE_H+5,"X",0x00FFFFFF,0x00C03030);
        // blit shared pixels
        for(int row=0;row<w->h;row++){
            int fy=w->y+row; if(fy<0||fy>=g_fb_h) continue;
            uint32_t*src=&w->shm[row*w->stride_px];
            for(int col=0;col<w->w;col++){
                int fx=w->x+col; if(fx<0||fx>=g_fb_w) continue;
                g_fb[fy*g_pitch_px+fx]=src[col];
            }
        }
    }
    draw_cursor(g_mx,g_my);
}

// ── window lookup ───────────────────────────────────────────────────────────
static Window* win_by_id(int id){for(int i=0;i<MAX_WINDOWS;i++)if(g_wins[i].valid&&g_wins[i].id==id)return &g_wins[i];return NULL;}
static int slot_by_id(int id){for(int i=0;i<MAX_WINDOWS;i++)if(g_wins[i].valid&&g_wins[i].id==id)return i;return -1;}
static int hit_top(int x,int y){ // topmost window slot under (x,y), or -1
    for(int zi=g_zcount-1; zi>=0; zi--){int s=g_zorder[zi];Window*w=&g_wins[s];if(!w->valid)continue;
        if(x>=w->x&&x<w->x+w->w&&y>=w->y-TITLE_H&&y<w->y+w->h)return s;}
    return -1;
}

// ── input ─────────────────────────────────────────────────────────────────────
static void key_to_focus(int code,int val){
    if(g_focus<0) return; Window*w=&g_wins[g_focus]; if(!w->valid) return;
    Client*c=&g_clients[w->client_idx]; if(!c->valid) return;
    MsgHdr h={MSG_KEY_EVENT,sizeof(MsgKeyEvent)}; MsgKeyEvent e={code,val};
    write_all(c->fd,&h,sizeof h); write_all(c->fd,&e,sizeof e);
}
static void handle_kbd(void){
    struct input_event ev;
    while(sys_read(g_kbd,&ev,sizeof ev)==(ssize_t)sizeof(ev)){
        if(ev.type!=EV_KEY) continue;
        if(ev.code==KEY_LEFTALT){ g_alt_down=ev.value?1:0; continue; }
        if(ev.code==KEY_TAB && ev.value==1 && g_alt_down){ alt_tab(); continue; }
        key_to_focus((int)ev.code,(int)ev.value);
    }
}
static int g_dragging=-1, g_drag_ox, g_drag_oy;
static void handle_mouse(void){
    struct input_event ev;
    while(sys_read(g_mouse,&ev,sizeof ev)==(ssize_t)sizeof(ev)){
        if(ev.type==EV_REL){
            if(ev.code==REL_X){g_mx+=ev.value;if(g_mx<0)g_mx=0;if(g_mx>=g_fb_w)g_mx=g_fb_w-1;}
            if(ev.code==REL_Y){g_my+=ev.value;if(g_my<0)g_my=0;if(g_my>=g_fb_h)g_my=g_fb_h-1;}
        } else if(ev.type==EV_KEY && ev.code==BTN_LEFT){
            if(ev.value==1){
                // close button?
                for(int zi=g_zcount-1; zi>=0; zi--){int s=g_zorder[zi];Window*w=&g_wins[s];if(!w->valid)continue;
                    if(g_mx>=w->x+w->w-16&&g_mx<w->x+w->w-4&&g_my>=w->y-TITLE_H+4&&g_my<w->y-TITLE_H+16){
                        Client*c=&g_clients[w->client_idx];
                        if(c->valid){sys_close(c->fd);c->valid=0;}
                        w->valid=0; z_remove(s); goto done;
                    }
                }
                int s=hit_top(g_mx,g_my);
                if(s>=0){ z_raise(s); Window*w=&g_wins[s];
                    if(g_my<w->y){ g_dragging=s; g_drag_ox=g_mx-w->x; g_drag_oy=g_my-w->y; }
                }
            } else if(ev.value==0){ g_dragging=-1; }
        } else if(ev.type==EV_SYN){
            if(g_dragging>=0){Window*w=&g_wins[g_dragging];w->x=g_mx-g_drag_ox;w->y=g_my-g_drag_oy;}
        }
        done:;
    }
}

// ── client IPC ─────────────────────────────────────────────────────────────────
static int alloc_client(void){for(int i=0;i<MAX_WINDOWS;i++)if(!g_clients[i].valid)return i;return -1;}
static Window* alloc_window(void){for(int i=0;i<MAX_WINDOWS;i++)if(!g_wins[i].valid)return &g_wins[i];return NULL;}

static void handle_client(int ci){
    Client*c=&g_clients[ci]; MsgHdr hdr;
    ssize_t r=sys_read(c->fd,&hdr,sizeof hdr);
    if(r<=0){ // disconnect: destroy its windows
        for(int i=0;i<MAX_WINDOWS;i++) if(g_wins[i].valid&&g_wins[i].client_idx==ci){g_wins[i].valid=0;z_remove(i);}
        sys_close(c->fd); c->valid=0; return;
    }
    if(r!=(ssize_t)sizeof(hdr)) return;
    if(hdr.type==MSG_CREATE_WINDOW){
        MsgCreateWindow pl; if(read_all(c->fd,&pl,sizeof pl)<0) return;
        Window*w=alloc_window();
        if(!w){ MsgHdr rh={MSG_WINDOW_CREATED,sizeof(MsgWindowCreated)}; MsgWindowCreated rj={0,0,0,0}; write_all(c->fd,&rh,sizeof rh); write_all(c->fd,&rj,sizeof rj); return; }
        int wpx=pl.w, hpx=pl.h;
        if(wpx<16)wpx=16; if(hpx<16)hpx=16;
        // Create a memfd, size it, and map it in the compositor.
        int mfd=sys_memfd_create("win",0);
        if(mfd<0) return;
        size_t bytes=(size_t)wpx*hpx*4;
        if(sys_ftruncate(mfd,(long)bytes)<0){ sys_close(mfd); return; }
        uint32_t*shm=sys_mmap(NULL,bytes,PROT_RW,MAP_SHARED,mfd,0);
        if(shm==(void*)-1){ sys_close(mfd); return; }
        w->valid=1; w->id=g_next_wid++;
        w->x=pl.x; w->y=pl.y+TITLE_H; w->w=wpx; w->h=hpx; w->stride_px=wpx;
        w->client_idx=ci; w->shm=shm;
        memcpy(w->title,pl.title,sizeof w->title); w->title[63]=0;
        memset(shm,0,bytes);
        int slot=(int)(w-g_wins);
        z_raise(slot);
        // Reply, passing the memfd to the client via SCM_RIGHTS.
        MsgHdr rh={MSG_WINDOW_CREATED,sizeof(MsgWindowCreated)};
        MsgWindowCreated resp={w->id, wpx, hpx, wpx};
        // header first (plain), then payload+fd in one SCM_RIGHTS message
        write_all(c->fd,&rh,sizeof rh);
        send_fd(c->fd,&resp,sizeof resp,mfd);
        sys_close(mfd); // client holds its own copy now
    } else if(hdr.type==MSG_DESTROY_WINDOW){
        MsgSimple pl; if(read_all(c->fd,&pl,sizeof pl)<0) return;
        int s=slot_by_id(pl.window_id); if(s>=0){g_wins[s].valid=0;z_remove(s);}
    } else if(hdr.type==MSG_REPAINT){
        MsgSimple pl; read_all(c->fd,&pl,sizeof pl); // pixels already in shm; nothing to copy
    }
}

// ── DRM init ───────────────────────────────────────────────────────────────────
static int drm_init(void){
    g_drm_fd=sys_open("/dev/dri/card0",O_RDWR,0);
    if(g_drm_fd<0){println("[comp] no DRM");return -1;}
    uint32_t crtcs[4]={0}; struct drm_mode_card_res res={0};
    res.crtc=(uint64_t)crtcs; res.ncrtc=4;
    if(sys_ioctl(g_drm_fd,DRM_IOCTL_MODE_GETRESOURCES,&res)){println("[comp] GETRES fail");return -1;}
    g_crtc=res.ncrtc>0?crtcs[0]:1;
    struct drm_mode_crtc crtc={0}; crtc.crtc_id=g_crtc;
    sys_ioctl(g_drm_fd,DRM_IOCTL_MODE_GETCRTC,&crtc);
    g_fb_w=crtc.mode.hd>0?crtc.mode.hd:1280; g_fb_h=crtc.mode.vd>0?crtc.mode.vd:800;
    struct drm_mode_create_dumb d={0}; d.width=g_fb_w; d.height=g_fb_h; d.bpp=32;
    if(sys_ioctl(g_drm_fd,DRM_IOCTL_MODE_CREATE_DUMB,&d)){println("[comp] DUMB fail");return -1;}
    g_pitch_px=(int)(d.pitch/4);
    struct drm_mode_map_dumb md={0}; md.handle=d.handle;
    if(sys_ioctl(g_drm_fd,DRM_IOCTL_MODE_MAP_DUMB,&md)){println("[comp] MAP fail");return -1;}
    g_fb=sys_mmap(NULL,(size_t)d.size,PROT_RW,MAP_SHARED,g_drm_fd,(long)md.offset);
    if(g_fb==(void*)-1){println("[comp] mmap fail");return -1;}
    g_mx=g_fb_w/2; g_my=g_fb_h/2;
    return 0;
}

struct sockaddr_un { uint16_t sun_family; char sun_path[108]; };
static int server_init(void){
    sys_unlink(SOCK_PATH);
    int fd=sys_socket(AF_UNIX,SOCK_STREAM,0);
    if(fd<0){println("[comp] socket fail");return -1;}
    struct sockaddr_un a={0}; a.sun_family=AF_UNIX;
    size_t pl=slen(SOCK_PATH); memcpy(a.sun_path,SOCK_PATH,pl+1);
    if(sys_bind(fd,&a,(int)(2+pl+1))){println("[comp] bind fail");return -1;}
    if(sys_listen(fd,8)){println("[comp] listen fail");return -1;}
    g_srv=fd; println("[comp] listening on " SOCK_PATH); return 0;
}

void _start(void){
    println("[comp] EpinAnonymOS Compositor (Phase 4 / shared memory)");
    if(drm_init()<0) sys_exit(1);
    if(server_init()<0) sys_exit(1);
    g_kbd=sys_open("/dev/input/event0",O_RDWR,0);
    g_mouse=sys_open("/dev/input/event1",O_RDWR,0);
    println("[comp] entering main loop");
    struct pollfd pf[3+MAX_WINDOWS];
    while(1){
        int n=0;
        pf[n].fd=g_kbd;pf[n].events=POLLIN;n++;
        pf[n].fd=g_mouse;pf[n].events=POLLIN;n++;
        pf[n].fd=g_srv;pf[n].events=POLLIN;n++;
        for(int i=0;i<MAX_WINDOWS;i++) if(g_clients[i].valid){pf[n].fd=g_clients[i].fd;pf[n].events=POLLIN;n++;}
        sys_poll(pf,n,0);
        if(pf[0].revents&POLLIN) handle_kbd();
        if(pf[1].revents&POLLIN) handle_mouse();
        if(pf[2].revents&POLLIN){
            struct sockaddr_un a; int al=sizeof a;
            int cfd=sys_accept(g_srv,&a,&al);
            if(cfd>=0){int ci=alloc_client(); if(ci>=0){g_clients[ci].valid=1;g_clients[ci].fd=cfd;} else sys_close(cfd);}
        }
        int base=3;
        for(int i=0;i<MAX_WINDOWS;i++){ if(!g_clients[i].valid) continue;
            if(pf[base].revents&POLLIN) handle_client(i);
            base++;
        }
        composite();
        sys_yield();
    }
}
