/*
 * wl-logview.c -- a safe, scrollable log/file viewer (Wayland + FreeType).
 *
 * There is no terminal on the desktop (an interactive shell busy-loops the PTY and starves the
 * compositor), so this read-only viewer lets you READ the diagnostic logs — including the FULL boot
 * and driver log, which on real hardware has no serial capture and can't be photographed as it scrolls.
 *   /run/klog          : the kernel log RAM ring — kernel klog + ALL program stdout/stderr merged live
 *                        (lkl-boot/iwlwifi, dbus, NetworkManager, wpa, boot-doctor).  This is tab 0.
 *   Tab / Left / Right : cycle sources (/run/klog, installer.log, sshd.log, scp.log, nm.log, wpa.log, boot-status.txt, wifi/networks, dbus.log)
 *   /                  : FILTER — type a substring (e.g. "iwl") to show ONLY matching lines; Enter=apply,
 *                        Esc=clear, Backspace=delete.  The one fast way to find something in a 5000-line log.
 *   Up / Down / PageUp / PageDown / Home : scroll;  End : jump to bottom and tail-follow
 *   f                  : toggle tail-follow (auto-scroll to newest);  r : reload
 * Opens at the TOP and does NOT auto-scroll by default (so it holds still while you read early boot).
 * TAIL-reads the last 2 MiB of each source and auto-reloads ~1 s.  Reuses wl-wifi-menu's proven scaffolding
 * (registry/seat/xdg/double-buffered wl_shm/FreeType, and the COMPLETE wl_pointer_listener so real pointer
 * input doesn't crash the client).
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <wayland-client.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include "xdg-shell-client-protocol.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum { WIN_W = 1000, WIN_H = 700, HEADER_H = 40, PX = 13, LINEH = 17,
       MAXLINES = 40000, READCAP = 2*1024*1024 };   /* tail-read the last READCAP bytes; index up to MAXLINES lines */

/* /run/klog is the kernel log RAM ring: kernel klog + ALL program stdout/stderr (lkl-boot/iwlwifi,
 * dbus, NetworkManager, wpa, boot-doctor) merged live — the one place to read the whole boot. */
static const char *FILES[] = {
    "/run/klog", "/run/installer.log", "/run/sshd.log", "/run/scp.log", "/run/nm.log", "/run/wpa.log", "/run/boot-status.txt", "/run/wifi/networks", "/run/dbus.log",
};
enum { NFILES = (int)(sizeof(FILES)/sizeof(FILES[0])) };

struct app {
    struct wl_display *display; struct wl_registry *registry;
    struct wl_compositor *compositor; struct wl_shm *shm; struct wl_seat *seat;
    struct wl_keyboard *keyboard; struct wl_pointer *pointer; struct xdg_wm_base *wm_base;
    struct wl_surface *surface; struct xdg_surface *xdg_surface; struct xdg_toplevel *toplevel;
    struct { struct wl_buffer *wl; uint32_t *px; int busy; } bufs[2];
    int configured, dirty;
    uint32_t *pixels; FT_Library ft; FT_Face face;
    unsigned char *font_data; size_t font_size, buffer_size;
    int width, height, stride, font_ready, running;
    double ptr_y;

    char *text; int textlen;       // current file content
    int  *lineoff; int nlines;     // ALL line start offsets
    int  *fidx;   int nfilt;       // filtered view: indices into lineoff of lines that match filter[] (all lines if no filter)
    char filter[80]; int flen;     // case-insensitive substring filter ('/' to edit)
    int  filtering;                // 1 = editing the filter string (keys go to text input, not nav)
    int  cur;                      // current file index
    int  scroll;                   // top visible line (index into fidx)
    int  rows;                     // visible rows
    int  follow;                   // tail-follow: snap to bottom as the log grows (off by default; End turns on)
};

static void log_line(const char *s){ fputs(s,stdout); fputc('\n',stdout); fflush(stdout); }
static int create_memfd(const char *n){ return (int)syscall(SYS_memfd_create, n, MFD_CLOEXEC); }

static int init_freetype(struct app *a){
    int fd = open("/usr/share/fonts/noto/NotoSans-Regular.ttf", O_RDONLY); if (fd<0) return -1;
    off_t sz = lseek(fd,0,SEEK_END); lseek(fd,0,SEEK_SET);
    a->font_data = malloc(sz); if(!a->font_data){close(fd);return -1;}
    if (read(fd,a->font_data,sz)!=sz){close(fd);return -1;} close(fd); a->font_size=sz;
    if (FT_Init_FreeType(&a->ft)!=0) return -1;
    if (FT_New_Memory_Face(a->ft,a->font_data,(FT_Long)sz,0,&a->face)!=0) return -1;
    a->font_ready=1; return 0;
}
static uint32_t blend(uint32_t d,uint32_t s,unsigned al){ if(al>=255)return s; if(!al)return d; unsigned iv=255-al;
    unsigned sr=(s>>16)&0xff,sg=(s>>8)&0xff,sb=s&0xff,dr=(d>>16)&0xff,dg=(d>>8)&0xff,db=d&0xff;
    return 0xff000000u|(((sr*al+dr*iv+127)/255)<<16)|(((sg*al+dg*iv+127)/255)<<8)|((sb*al+db*iv+127)/255); }
static void draw_text_n(struct app *a, const char *t, int len, int x, int y, int maxx, int px, uint32_t col){
    if (!a->font_ready) return;
    if (FT_Set_Pixel_Sizes(a->face,0,(FT_UInt)px)!=0) return;
    int base = px; if (a->face->size && a->face->size->metrics.ascender>0) base=(int)(a->face->size->metrics.ascender>>6);
    int pen_x=x, pen_y=y+base;
    for (int i=0;i<len;i++){ unsigned char ch=(unsigned char)t[i]; if(ch=='\t'){ pen_x += px*2; continue; }
        if (ch<0x20||ch>=0x7f) ch='?';
        if (FT_Load_Char(a->face,ch,FT_LOAD_RENDER|FT_LOAD_TARGET_NORMAL)!=0) continue;
        FT_GlyphSlot g=a->face->glyph; int adv=(int)(g->advance.x>>6); if (pen_x+adv>maxx) break;
        FT_Bitmap *bm=&g->bitmap; int gx=pen_x+g->bitmap_left, gy=pen_y-g->bitmap_top;
        int pitch=bm->pitch; const unsigned char *bs=bm->buffer; if(pitch<0){pitch=-pitch;bs=bm->buffer-(int)(bm->rows-1)*pitch;}
        for (int row=0;row<(int)bm->rows;row++){ int py=gy+row; if(py<0||py>=a->height)continue;
            const unsigned char *sr=bs+row*pitch;
            for (int c=0;c<(int)bm->width;c++){ int pxp=gx+c; if(pxp<0||pxp>=a->width)continue;
                unsigned al=(bm->pixel_mode==FT_PIXEL_MODE_GRAY)?sr[c]:((sr[c>>3]&(0x80>>(c&7)))?255:0);
                uint32_t *dp=&a->pixels[py*a->width+pxp]; *dp=blend(*dp,col,al); } }
        pen_x+=adv;
    }
}
static void fill(struct app *a,int x,int y,int w,int h,uint32_t c){ for(int j=y;j<y+h;j++){if(j<0||j>=a->height)continue;
    for(int i=x;i<x+w;i++){if(i<0||i>=a->width)continue;a->pixels[j*a->width+i]=c;}} }

static int bottom_scroll(struct app *a){ int b=a->nfilt-a->rows; return b<0?0:b; }

/* case-insensitive substring search of the line [off,end) for filter[] */
static int line_matches(struct app *a,int off,int end){
    if (a->flen==0) return 1;
    for (int i=off;i+a->flen<=end;i++){
        int j=0; for(;j<a->flen;j++){ char c=a->text[i+j],f=a->filter[j];
            if(c>='A'&&c<='Z')c+=32; if(f>='A'&&f<='Z')f+=32; if(c!=f)break; }
        if (j==a->flen) return 1;
    }
    return 0;
}
/* build fidx[] = indices into lineoff of lines matching filter[] (or all lines when filter empty) */
static void rebuild_view(struct app *a){
    if (!a->fidx) a->fidx=malloc(sizeof(int)*MAXLINES);
    a->nfilt=0;
    for (int ln=0;ln<a->nlines;ln++){
        int off=a->lineoff[ln]; int end=(ln+1<a->nlines)?a->lineoff[ln+1]-1:a->textlen;
        if (line_matches(a,off,end)) a->fidx[a->nfilt++]=ln;
    }
    if (a->nfilt==0) a->fidx[a->nfilt++]=-1;   // sentinel: show a "(no matches)" placeholder row
}

/* load FILES[cur] into text + index line offsets.  TAIL-read the last READCAP bytes (a boot log grows
 * to many MB and the NEWEST lines are the ones that matter), keeping the last MAXLINES lines addressable.
 * Then rebuild the filtered view.  Only snaps to the bottom when follow is on (off by default). */
static void load_current(struct app *a){
    if (a->rows<=0) a->rows=(a->height-HEADER_H-6)/LINEH;
    free(a->text); a->text=0; a->textlen=0; a->nlines=0;
    int fd=open(FILES[a->cur],O_RDONLY);
    if (fd<0){ a->text=strdup("(file not present)"); a->textlen=strlen(a->text); }
    else { off_t sz=lseek(fd,0,SEEK_END);
        off_t start=(sz>READCAP)?(sz-READCAP):0;        /* read only the tail window */
        int cap=(int)(sz-start);
        lseek(fd,start,SEEK_SET);
        a->text=malloc((size_t)cap+1);
        int n=0; while(n<cap){ int r=(int)read(fd,a->text+n,(size_t)(cap-n)); if(r<=0)break; n+=r; }
        close(fd); if(n<0)n=0; a->text[n]=0; a->textlen=n;
        if (start>0){ /* dropped a partial first line — skip to the first whole line */
            int i=0; while(i<n && a->text[i]!='\n') i++;
            if (i<n){ i++; memmove(a->text,a->text+i,(size_t)(n-i+1)); n-=i; a->textlen=n; } }
        if (n==0){ free(a->text); a->text=strdup("(empty)"); a->textlen=strlen(a->text); } }
    if (!a->lineoff) a->lineoff=malloc(sizeof(int)*MAXLINES);
    a->nlines=0; a->lineoff[a->nlines++]=0;
    for (int i=0;i<a->textlen;i++) if (a->text[i]=='\n'){
        if (a->nlines>=MAXLINES){                        /* overflow: drop oldest quarter, keep NEWEST lines */
            int drop=MAXLINES/4;
            memmove(a->lineoff,a->lineoff+drop,(size_t)(a->nlines-drop)*sizeof(int));
            a->nlines-=drop;
        }
        a->lineoff[a->nlines++]=i+1;
    }
    rebuild_view(a);
    if (a->follow) a->scroll=bottom_scroll(a);
}

static void draw(struct app *a){
    const uint32_t BG=0xff11141bu,HDR=0xff1b2230u,TXT=0xffd8dee9u,ACC=0xff4da3ffu,DIM=0xff8b94a3u,FIL=0xffffd479u;
    fill(a,0,0,a->width,a->height,BG);
    fill(a,0,0,a->width,HEADER_H,HDR);
    char hdr[224];
    if (a->filtering || a->flen>0)
        snprintf(hdr,sizeof hdr,"%s   filter: %s%s   [%d/%d]%s",
                 FILES[a->cur], a->filter, a->filtering?"_":"", a->nfilt, a->nlines, a->follow?"  FOLLOW":"");
    else
        snprintf(hdr,sizeof hdr,"%s   [%d lines]   line %d/%d%s",
                 FILES[a->cur], a->nlines, a->scroll+1, a->nlines, a->follow?"   FOLLOW":"");
    draw_text_n(a,hdr,(int)strlen(hdr),12,11,a->width-372,15,(a->filtering||a->flen>0)?FIL:ACC);
    const char *hint = a->filtering ? "type to filter   Enter=apply   Esc=clear   Bksp=delete"
                                    : "Tab=source  /=filter  wheel/PgUp/PgDn=scroll  Home/End  r=reload";
    draw_text_n(a,hint,(int)strlen(hint),a->width-372,13,a->width-12,10,DIM);
    a->rows=(a->height-HEADER_H-6)/LINEH;
    for (int r=0;r<a->rows;r++){ int vi=a->scroll+r; if(vi>=a->nfilt)break;
        int ln=a->fidx[vi];
        if (ln<0){ draw_text_n(a,"(no lines match filter)",23,10,HEADER_H+4+r*LINEH,a->width-6,PX,DIM); break; }
        int off=a->lineoff[ln]; int end=(ln+1<a->nlines)?a->lineoff[ln+1]-1:a->textlen;
        int len=end-off; if(len<0)len=0; if(len>400)len=400;
        draw_text_n(a,a->text+off,len,10,HEADER_H+4+r*LINEH,a->width-6,PX,TXT); }
}

/* --- double-buffer --- */
static void commit(struct app *a);
static void buffer_release(void *d, struct wl_buffer *wl){ struct app*a=d; for(int i=0;i<2;i++) if(a->bufs[i].wl==wl)a->bufs[i].busy=0;
    if(a->dirty){a->dirty=0;commit(a);} }
static const struct wl_buffer_listener buffer_listener={.release=buffer_release};
static int create_buffers(struct app *a){
    int fd=create_memfd("epin-logview"); if(fd<0)return -1; size_t tot=a->buffer_size*2;
    if(ftruncate(fd,(off_t)tot)<0){close(fd);return -1;}
    unsigned char *base=mmap(NULL,tot,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0); if(base==MAP_FAILED){close(fd);return -1;}
    struct wl_shm_pool *pool=wl_shm_create_pool(a->shm,fd,(int)tot);
    for(int i=0;i<2;i++){ a->bufs[i].px=(uint32_t*)(base+(size_t)i*a->buffer_size);
        a->bufs[i].wl=wl_shm_pool_create_buffer(pool,(int)((size_t)i*a->buffer_size),a->width,a->height,a->stride,WL_SHM_FORMAT_XRGB8888);
        if(!a->bufs[i].wl){wl_shm_pool_destroy(pool);close(fd);return -1;} wl_buffer_add_listener(a->bufs[i].wl,&buffer_listener,a); a->bufs[i].busy=0; }
    wl_shm_pool_destroy(pool); close(fd); return 0;
}
static void commit(struct app *a){ if(!a->configured)return; int i=a->bufs[0].busy?1:0; if(a->bufs[i].busy){a->dirty=1;return;}
    a->pixels=a->bufs[i].px; draw(a); a->bufs[i].busy=1;
    wl_surface_attach(a->surface,a->bufs[i].wl,0,0); wl_surface_damage_buffer(a->surface,0,0,a->width,a->height);
    wl_surface_commit(a->surface); wl_display_flush(a->display); }

static void clampscroll(struct app *a){ int max=a->nfilt-1; if(max<0)max=0; if(a->scroll>max)a->scroll=max; if(a->scroll<0)a->scroll=0; }

/* evdev keycode -> ASCII for filter text entry (letters/digits + a few symbols); 0 = not printable */
static char keycode_ascii(uint32_t k){
    static const char row1[]="1234567890-=";      /* keycodes 2..13 */
    static const char row2[]="qwertyuiop[]";      /* keycodes 16..27 */
    static const char row3[]="asdfghjkl;'";       /* keycodes 30..40 */
    static const char row4[]="zxcvbnm,./";        /* keycodes 44..53 */
    if (k>=2 && k<=13)  return row1[k-2];
    if (k>=16 && k<=27) return row2[k-16];
    if (k>=30 && k<=40) return row3[k-30];
    if (k>=44 && k<=53) return row4[k-44];
    if (k==57) return ' ';
    return 0;
}

/* --- input --- */
static void p_enter(void*d,struct wl_pointer*p,uint32_t s,struct wl_surface*sf,wl_fixed_t x,wl_fixed_t y){(void)d;(void)p;(void)s;(void)sf;(void)x;(void)y;}
static void p_leave(void*d,struct wl_pointer*p,uint32_t s,struct wl_surface*sf){(void)d;(void)p;(void)s;(void)sf;}
static void p_motion(void*d,struct wl_pointer*p,uint32_t t,wl_fixed_t x,wl_fixed_t y){(void)p;(void)t;(void)x;struct app*a=d;a->ptr_y=wl_fixed_to_double(y);}
static void p_button(void*d,struct wl_pointer*p,uint32_t se,uint32_t t,uint32_t b,uint32_t st){(void)d;(void)p;(void)se;(void)t;(void)b;(void)st;}
static void p_axis(void*d,struct wl_pointer*p,uint32_t t,uint32_t ax,wl_fixed_t v){ (void)p;(void)t; struct app*a=d;
    if (ax==0){ a->scroll += (v>0)?3:-3; a->follow=0; clampscroll(a);       /* manual scroll drops follow */
                if (a->scroll>=bottom_scroll(a)) a->follow=1;               /* ...unless you land at bottom */
                commit(a); } }   /* vertical wheel scroll */
static void p_frame(void*d,struct wl_pointer*p){(void)d;(void)p;}
static void p_asrc(void*d,struct wl_pointer*p,uint32_t s){(void)d;(void)p;(void)s;}
static void p_astop(void*d,struct wl_pointer*p,uint32_t t,uint32_t a2){(void)d;(void)p;(void)t;(void)a2;}
static void p_adisc(void*d,struct wl_pointer*p,uint32_t a2,int32_t v){(void)d;(void)p;(void)a2;(void)v;}
static const struct wl_pointer_listener pointer_listener={.enter=p_enter,.leave=p_leave,.motion=p_motion,.button=p_button,
    .axis=p_axis,.frame=p_frame,.axis_source=p_asrc,.axis_stop=p_astop,.axis_discrete=p_adisc};

static void k_keymap(void*d,struct wl_keyboard*k,uint32_t f,int32_t fd,uint32_t sz){(void)d;(void)k;(void)f;(void)sz;if(fd>=0)close(fd);}
static void k_enter(void*d,struct wl_keyboard*k,uint32_t s,struct wl_surface*sf,struct wl_array*ks){(void)d;(void)k;(void)s;(void)sf;(void)ks;}
static void k_leave(void*d,struct wl_keyboard*k,uint32_t s,struct wl_surface*sf){(void)d;(void)k;(void)s;(void)sf;}
static void k_key(void*d,struct wl_keyboard*k,uint32_t se,uint32_t t,uint32_t key,uint32_t st){(void)k;(void)se;(void)t;struct app*a=d;
    if(st!=1)return;
    /* --- filter-edit mode: ALL keys go to text input (so typing 'r'/'f'/Tab filters, not navigates) --- */
    if (a->filtering){
        if (key==28){ a->filtering=0; }                                  /* Enter = apply, keep filter */
        else if (key==1){ a->filtering=0; a->flen=0; a->filter[0]=0; rebuild_view(a); a->scroll=0; } /* Esc = clear filter */
        else if (key==14){ if(a->flen>0){ a->filter[--a->flen]=0; rebuild_view(a); a->scroll=0; } }  /* Backspace */
        else { char c=keycode_ascii(key); if(c && a->flen<(int)sizeof(a->filter)-1){ a->filter[a->flen++]=c; a->filter[a->flen]=0; rebuild_view(a); a->scroll=0; } }
        clampscroll(a); commit(a); return;
    }
    switch(key){
        case 103: a->scroll--; a->follow=0; break;                 /* Up */
        case 108: a->scroll++; break;                              /* Down */
        case 104: a->scroll-=a->rows-1; a->follow=0; break;        /* PageUp */
        case 109: a->scroll+=a->rows-1; break;                     /* PageDown */
        case 102: a->scroll=0; a->follow=0; break;                 /* Home */
        case 107: a->scroll=bottom_scroll(a); a->follow=1; break;  /* End = jump to bottom + follow */
        case 53: a->filtering=1; break;                            /* '/' = edit filter (incremental) */
        case 15: case 105: a->cur=(a->cur+1)%NFILES; a->scroll=0; a->follow=0; load_current(a); break; /* Tab / Left->next (open at top) */
        case 106: a->cur=(a->cur+NFILES-1)%NFILES; a->scroll=0; a->follow=0; load_current(a); break;   /* Right->prev (open at top) */
        case 33: a->follow=!a->follow; if(a->follow)a->scroll=bottom_scroll(a); break;  /* f = toggle follow */
        case 19: load_current(a); break;              /* r = reload */
        case 1: a->running=0; break;                  /* Esc = quit */
        default: return;
    }
    clampscroll(a);
    if (a->scroll>=bottom_scroll(a)) a->follow=1;   /* scrolling down to the bottom re-enables follow */
    commit(a);
}
static void k_mods(void*d,struct wl_keyboard*k,uint32_t se,uint32_t a2,uint32_t b,uint32_t c,uint32_t e){(void)d;(void)k;(void)se;(void)a2;(void)b;(void)c;(void)e;}
static void k_rep(void*d,struct wl_keyboard*k,int32_t r,int32_t dl){(void)d;(void)k;(void)r;(void)dl;}
static const struct wl_keyboard_listener keyboard_listener={.keymap=k_keymap,.enter=k_enter,.leave=k_leave,.key=k_key,.modifiers=k_mods,.repeat_info=k_rep};

static void seat_caps(void*d,struct wl_seat*s,uint32_t caps){ struct app*a=d;
    if((caps&WL_SEAT_CAPABILITY_KEYBOARD)&&!a->keyboard){a->keyboard=wl_seat_get_keyboard(s);wl_keyboard_add_listener(a->keyboard,&keyboard_listener,a);}
    if((caps&WL_SEAT_CAPABILITY_POINTER)&&!a->pointer){a->pointer=wl_seat_get_pointer(s);wl_pointer_add_listener(a->pointer,&pointer_listener,a);} }
static void seat_name(void*d,struct wl_seat*s,const char*n){(void)d;(void)s;(void)n;}
static const struct wl_seat_listener seat_listener={.capabilities=seat_caps,.name=seat_name};
static void wm_ping(void*d,struct xdg_wm_base*b,uint32_t s){(void)d;xdg_wm_base_pong(b,s);}
static const struct xdg_wm_base_listener wm_base_listener={.ping=wm_ping};
static void tl_conf(void*d,struct xdg_toplevel*t,int32_t w,int32_t h,struct wl_array*s){(void)d;(void)t;(void)w;(void)h;(void)s;}
static void tl_close(void*d,struct xdg_toplevel*t){(void)t;struct app*a=d;a->running=0;}
static void tl_bounds(void*d,struct xdg_toplevel*t,int32_t w,int32_t h){(void)d;(void)t;(void)w;(void)h;}
static void tl_wmcap(void*d,struct xdg_toplevel*t,struct wl_array*c){(void)d;(void)t;(void)c;}
static const struct xdg_toplevel_listener toplevel_listener={.configure=tl_conf,.close=tl_close,.configure_bounds=tl_bounds,.wm_capabilities=tl_wmcap};
static void xs_conf(void*d,struct xdg_surface*s,uint32_t serial){struct app*a=d;xdg_surface_ack_configure(s,serial);a->configured=1;commit(a);}
static const struct xdg_surface_listener xdg_surface_listener={.configure=xs_conf};
static void reg_global(void*d,struct wl_registry*r,uint32_t name,const char*iface,uint32_t ver){struct app*a=d;
    if(!strcmp(iface,wl_compositor_interface.name))a->compositor=wl_registry_bind(r,name,&wl_compositor_interface,ver<4?ver:4);
    else if(!strcmp(iface,wl_shm_interface.name))a->shm=wl_registry_bind(r,name,&wl_shm_interface,1);
    else if(!strcmp(iface,xdg_wm_base_interface.name)){a->wm_base=wl_registry_bind(r,name,&xdg_wm_base_interface,ver<6?ver:6);xdg_wm_base_add_listener(a->wm_base,&wm_base_listener,a);}
    else if(!strcmp(iface,wl_seat_interface.name)){a->seat=wl_registry_bind(r,name,&wl_seat_interface,ver<5?ver:5);wl_seat_add_listener(a->seat,&seat_listener,a);} }
static void reg_rm(void*d,struct wl_registry*r,uint32_t n){(void)d;(void)r;(void)n;}
static const struct wl_registry_listener registry_listener={.global=reg_global,.global_remove=reg_rm};

int main(void){
    static struct app app; memset(&app,0,sizeof app);
    app.running=1; app.width=WIN_W; app.height=WIN_H; app.stride=WIN_W*4; app.buffer_size=(size_t)app.stride*WIN_H;
    app.rows=(WIN_H-HEADER_H-6)/LINEH; app.follow=0; app.scroll=0;   /* open at the TOP, no auto-scroll (End turns on follow) */
    signal(SIGCHLD,SIG_IGN);
    init_freetype(&app);
    load_current(&app);
    log_line("LOGVIEW: starting");
    app.display=wl_display_connect(NULL); if(!app.display){log_line("LOGVIEW: no display");return 1;}
    app.registry=wl_display_get_registry(app.display); wl_registry_add_listener(app.registry,&registry_listener,&app);
    wl_display_roundtrip(app.display);
    if(!app.compositor||!app.shm||!app.wm_base){log_line("LOGVIEW: missing globals");return 1;}
    if(create_buffers(&app)<0){log_line("LOGVIEW: buffer failed");return 1;}
    app.surface=wl_compositor_create_surface(app.compositor);
    app.xdg_surface=xdg_wm_base_get_xdg_surface(app.wm_base,app.surface);
    xdg_surface_add_listener(app.xdg_surface,&xdg_surface_listener,&app);
    app.toplevel=xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel,&toplevel_listener,&app);
    xdg_toplevel_set_title(app.toplevel,"Logs"); xdg_toplevel_set_app_id(app.toplevel,"epin-logview");
    wl_surface_commit(app.surface); wl_display_flush(app.display);
    int wlfd=wl_display_get_fd(app.display);
    int tick=0;
    while(app.running){
        while(wl_display_prepare_read(app.display)!=0) wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);
        struct pollfd pfd={.fd=wlfd,.events=POLLIN,.revents=0};
        int pr=poll(&pfd,1,1000);
        if(pr>0&&(pfd.revents&POLLIN)){wl_display_read_events(app.display);wl_display_dispatch_pending(app.display);}
        else { wl_display_cancel_read(app.display); if(pr<0){if(errno==EINTR)continue;break;}
               if(pr==0){ (void)tick; load_current(&app); clampscroll(&app); commit(&app); } }  /* auto-reload every ~1s (tail-follows a live log) */
    }
    return 0;
}
