/*
 * wl-wifi-menu.c -- M6: the top-right Wi-Fi menu (Wayland + Cairo/FreeType client).
 *
 * A pure file-driven renderer, exactly like wl-domain-manager: it reads /run/wifi/networks (written by
 * hos-wifi-agent from NetworkManager's live D-Bus state) and paints a list of nearby networks with a
 * signal bar + a lock for secured ones.  Clicking a network opens a password field (open networks
 * connect immediately); on Enter it writes /run/wifi/connect ("SSID\nPASSWORD\n") which the agent turns
 * into NM.AddAndActivateConnection.  The list live-refreshes every second.
 *
 * Wayland scaffolding (registry / seat / xdg / persistent wl_shm buffer / FreeType text / evdev keymap)
 * is the proven wl-domain-manager pattern.
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
#include <sys/wait.h>
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

enum { WIN_W = 360, WIN_H = 600, ROW_H = 44, HEADER_H = 44, MAX_NETS = 64 };

struct net { char ssid[64]; int strength; char sec[12]; int active; };

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    struct wl_pointer *pointer;
    struct xdg_wm_base *wm_base;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;
    struct { struct wl_buffer *wl; uint32_t *px; int busy; } bufs[2];  // double-buffered
    int configured, dirty;         // dirty = a redraw was deferred because both buffers were busy
    struct wl_callback *frame_cb;
    uint32_t *pixels;              // the buffer draw_menu()/draw_text() currently target
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    int font_ready, running, post_map_frame_armed, post_map_frame_done, sync_after_commit;
    double pointer_x, pointer_y;

    struct net nets[MAX_NETS];
    int n_nets;
    char iface[32];
    unsigned dev_state;            // NM device state (30=disconnected,100=activated,...)
    int hover;                     // hovered row (-1 none)

    int  editing;                  // password dialog open
    char edit_ssid[64];            // network being connected
    char editbuf[96];              // typed password
    char pending_ssid[64];         // submitted SSID; close only after it becomes active
    char connect_error[160];       // agent/NM rejection shown instead of silent failure
    int  editlen;
    int  shift;
    unsigned last_hash;
    char diag[2000];               // /run/boot-status.txt (shown when there's no adapter, since there is no terminal)
    char agent_status[256];        // /run/wifi/agent-status — hos-wpa-agent's live one-line state (shown when the list is empty)
};

static void log_line(const char *s){ fputs(s, stdout); fputc('\n', stdout); fflush(stdout); }
static int create_memfd(const char *name){ return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC); }

static int load_file(const char *path, unsigned char **out, size_t *out_size){
    int fd = open(path, O_RDONLY); if (fd < 0) return -1;
    size_t cap = 8192, n = 0; unsigned char *b = malloc(cap);
    if (!b){ close(fd); return -1; }
    for (;;){ if (n + 4096 > cap){ cap *= 2; unsigned char *nb = realloc(b, cap); if (!nb){ free(b); close(fd); return -1; } b = nb; }
        ssize_t r = read(fd, b + n, 4096); if (r <= 0) break; n += (size_t)r; }
    close(fd); *out = b; *out_size = n; return 0;
}
static int init_freetype(struct app *app){
    const char *path = "/usr/share/fonts/noto/NotoSans-Regular.ttf";
    if (load_file(path, &app->font_data, &app->font_size) < 0) return -1;
    if (FT_Init_FreeType(&app->ft) != 0) return -1;
    if (FT_New_Memory_Face(app->ft, app->font_data, (FT_Long)app->font_size, 0, &app->face) != 0) return -1;
    app->font_ready = 1; return 0;
}
static uint32_t blend_xrgb(uint32_t dst, uint32_t src, unsigned int a){
    if (a >= 255) return src; if (a == 0) return dst; unsigned int inv = 255 - a;
    unsigned int sr=(src>>16)&0xff,sg=(src>>8)&0xff,sb=src&0xff, dr=(dst>>16)&0xff,dg=(dst>>8)&0xff,db=dst&0xff;
    return 0xff000000u | (((sr*a+dr*inv+127)/255)<<16) | (((sg*a+dg*inv+127)/255)<<8) | ((sb*a+db*inv+127)/255);
}
static void draw_text(struct app *app, const char *text, int x, int y, int max_w, int px, uint32_t color){
    if (!app->font_ready || !text || max_w <= 0) return;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0) return;
    int baseline = px;
    if (app->face->size && app->face->size->metrics.ascender > 0) baseline = (int)(app->face->size->metrics.ascender >> 6);
    int pen_x = x, pen_y = y + baseline;
    for (const unsigned char *p = (const unsigned char*)text; *p; ++p){
        unsigned char ch = *p; if (ch < 0x20 || ch >= 0x7f) ch = '?';
        if (FT_Load_Char(app->face, ch, FT_LOAD_RENDER|FT_LOAD_TARGET_NORMAL) != 0) continue;
        FT_GlyphSlot g = app->face->glyph; int advance = (int)(g->advance.x >> 6);
        if (pen_x + advance > x + max_w) break;
        FT_Bitmap *bm = &g->bitmap; int gx = pen_x + g->bitmap_left, gy = pen_y - g->bitmap_top;
        int pitch = bm->pitch; const unsigned char *base = bm->buffer;
        if (pitch < 0){ pitch = -pitch; base = bm->buffer - (int)(bm->rows-1)*pitch; }
        for (int row = 0; row < (int)bm->rows; row++){ int pyp = gy+row; if (pyp<0||pyp>=app->height) continue;
            const unsigned char *sr = base + row*pitch;
            for (int col = 0; col < (int)bm->width; col++){ int pxp = gx+col; if (pxp<0||pxp>=app->width) continue;
                unsigned int alpha = (bm->pixel_mode==FT_PIXEL_MODE_GRAY) ? sr[col]
                                   : ((sr[col>>3] & (0x80>>(col&7))) ? 255 : 0);
                uint32_t *d = &app->pixels[pyp*app->width+pxp]; *d = blend_xrgb(*d, color, alpha); } }
        pen_x += advance;
    }
}
static void fill_rect(struct app *app, int x, int y, int w, int h, uint32_t c){
    for (int j=y;j<y+h;j++){ if (j<0||j>=app->height) continue;
        for (int i=x;i<x+w;i++){ if (i<0||i>=app->width) continue; app->pixels[j*app->width+i]=c; } }
}

/* raw evdev codes from wl_keyboard (no xkb keymap here) -> printable chars, unshifted + shifted. */
static const char EVDEV_CHAR[128] = {
    [2]='1',[3]='2',[4]='3',[5]='4',[6]='5',[7]='6',[8]='7',[9]='8',[10]='9',[11]='0',[12]='-',[13]='=',
    [16]='q',[17]='w',[18]='e',[19]='r',[20]='t',[21]='y',[22]='u',[23]='i',[24]='o',[25]='p',[26]='[',[27]=']',
    [30]='a',[31]='s',[32]='d',[33]='f',[34]='g',[35]='h',[36]='j',[37]='k',[38]='l',[39]=';',[40]='\'',[43]='\\',
    [44]='z',[45]='x',[46]='c',[47]='v',[48]='b',[49]='n',[50]='m',[51]=',',[52]='.',[53]='/',[57]=' ',
};
static const char EVDEV_SHIFT[128] = {
    [2]='!',[3]='@',[4]='#',[5]='$',[6]='%',[7]='^',[8]='&',[9]='*',[10]='(',[11]=')',[12]='_',[13]='+',
    [16]='Q',[17]='W',[18]='E',[19]='R',[20]='T',[21]='Y',[22]='U',[23]='I',[24]='O',[25]='P',[26]='{',[27]='}',
    [30]='A',[31]='S',[32]='D',[33]='F',[34]='G',[35]='H',[36]='J',[37]='K',[38]='L',[39]=':',[40]='"',[43]='|',
    [44]='Z',[45]='X',[46]='C',[47]='V',[48]='B',[49]='N',[50]='M',[51]='<',[52]='>',[53]='?',[57]=' ',
};

/* --- data: parse /run/wifi/networks --- */
static unsigned fnv1a(const unsigned char *b, size_t n){ unsigned h=2166136261u; for (size_t i=0;i<n;i++){ h^=b[i]; h*=16777619u; } return h; }

static void load_networks(struct app *app){
    unsigned char *buf; size_t sz;
    app->n_nets = 0; app->iface[0]=0; app->dev_state = 0;
    /* hos-wpa-agent's live status (adapter/nl80211/scan count) — shown when the list is empty so the
     * user can see where the scan stands without a terminal or the Logs app. */
    app->agent_status[0] = 0;
    { int afd = open("/run/wifi/agent-status", O_RDONLY);
      if (afd >= 0) { int an = (int)read(afd, app->agent_status, sizeof(app->agent_status)-1); close(afd);
                      if (an > 0) { app->agent_status[an] = 0; char *anl = strchr(app->agent_status, '\n'); if (anl) *anl = 0; } } }
    if (load_file("/run/wifi/networks", &buf, &sz) < 0) return;
    char *p = (char*)buf; char *end = (char*)buf + sz;
    while (p < end){
        char *nl = memchr(p, '\n', (size_t)(end-p)); if (!nl) nl = end;
        *nl = 0;
        if (p[0] == '#'){
            /* #dev\tdevpath\tiface\tstate */
            char *t1 = strchr(p, '\t'); char *t2 = t1?strchr(t1+1,'\t'):0; char *t3 = t2?strchr(t2+1,'\t'):0;
            /* Terminate the iface field at t3 BEFORE copying it: without this the copy
             * dragged "\t<state>" along, and in the NM-down header-only case ("#dev\t\t\t0")
             * iface became "\t0" (non-empty) which suppressed the diagnostics panel
             * exactly when the user needed it. */
            if (t3){ *t3 = 0; app->dev_state = (unsigned)atoi(t3+1); }
            if (t2){ *t2=0; strncpy(app->iface, t2+1, sizeof(app->iface)-1); }
        } else if (p[0] && app->n_nets < MAX_NETS){
            /* ssid\tstrength\tsec\tactive\tpath */
            struct net parsed; memset(&parsed, 0, sizeof parsed);
            struct net *n = &parsed;
            char *f[5]; int nf=0; char *s=p;
            for (char *q=p; q<=nl && nf<5; q++){ if (*q=='\t'||q==nl){ *q=0; f[nf++]=s; s=q+1; } }
            if (nf >= 4){
                strncpy(n->ssid, f[0], sizeof(n->ssid)-1); n->ssid[sizeof(n->ssid)-1]=0;
                n->strength = atoi(f[1]);
                strncpy(n->sec, f[2], sizeof(n->sec)-1); n->sec[sizeof(n->sec)-1]=0;
                n->active = atoi(f[3]);
                if (n->ssid[0]) {
                    /* NM reports one AccessPoint object per BSSID, so mesh and
                     * multi-band networks otherwise appear several times.  The
                     * picker connects by SSID; show one row using the strongest
                     * observation, while retaining an active duplicate. */
                    int old = -1;
                    for (int i=0; i<app->n_nets; i++)
                        if (strcmp(app->nets[i].ssid, n->ssid)==0){ old=i; break; }
                    if (old < 0) app->nets[app->n_nets++] = parsed;
                    else if (parsed.active || (!app->nets[old].active && parsed.strength > app->nets[old].strength))
                        app->nets[old] = parsed;
                }
            }
        }
        p = nl + 1;
    }
    free(buf);
}

/* --- rendering --- */
static void draw_signal(struct app *app, int x, int y, int strength, uint32_t on, uint32_t off){
    for (int b=0;b<4;b++){ int bh = 4 + b*4; int active = (strength > b*25);
        fill_rect(app, x + b*6, y + (16-bh), 4, bh, active?on:off); }
}
/* Append the LAST `cap` bytes of `path` into dst (there is no terminal to `tail` it). */
static void tail_into(const char *path, char *dst, int cap){
    dst[0]=0;
    int fd = open(path, O_RDONLY); if (fd < 0) return;
    off_t sz = lseek(fd, 0, SEEK_END);
    off_t start = (sz > cap-1) ? sz-(cap-1) : 0;
    lseek(fd, start, SEEK_SET);
    int n = (int)read(fd, dst, cap-1); close(fd);
    if (n < 0) n = 0; dst[n] = 0;
}
/* Show the boot-doctor verdict + the TAIL of NM's own --debug log (where it stalls before D-Bus),
 * since there's no terminal on the desktop to read /run/boot-status.txt or /run/nm.log. */
static void load_diag(struct app *app){
    char bs[700]="", nm[900]="";
    tail_into("/run/boot-status.txt", bs, sizeof bs);
    tail_into("/run/nm.log", nm, sizeof nm);
    if (nm[0]) snprintf(app->diag, sizeof app->diag, "%s\n--- NM log (last lines) ---\n%s", bs, nm);
    else       snprintf(app->diag, sizeof app->diag, "%s", bs);
}
/* Word-wrapped multi-line text; returns the y after the last line. */
static int draw_wrapped(struct app *app, const char *text, int x, int y, int w, int px, int lineh, uint32_t color){
    if (!app->font_ready || !text) return y;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0) return y;
    char line[128]; int li = 0;
    for (const char *p = text; ; p++){
        if (*p == '\n' || *p == 0 || li >= (int)sizeof(line)-1){
            line[li] = 0;
            if (li) { draw_text(app, line, x, y, w, px, color); y += lineh; }
            else if (*p == '\n') y += lineh/2;   /* blank line */
            li = 0;
            if (*p == 0) break;
            if (y > app->height - lineh) break;
            continue;
        }
        /* greedy width wrap: ~ (w / (px*0.55)) chars per line */
        int maxc = (int)(w / (px*0.55)); if (maxc < 8) maxc = 8; if (maxc > (int)sizeof(line)-1) maxc = sizeof(line)-1;
        if (li >= maxc && *p == ' '){ line[li]=0; draw_text(app, line, x, y, w, px, color); y += lineh; li=0; if (y > app->height-lineh) break; continue; }
        if (*p != '\r') line[li++] = *p;
    }
    return y;
}
static void draw_menu(struct app *app){
    const uint32_t BG=0xff1b1f27u, HDR=0xff11141bu, ROW=0xff232834u, ROWH=0xff2d3444u,
                   TXT=0xfff2f5fau, DIM=0xff8b94a3u, ACC=0xff4da3ffu, ON=0xff4da3ffu, OFF=0xff3a4150u;
    fill_rect(app, 0, 0, app->width, app->height, BG);
    fill_rect(app, 0, 0, app->width, HEADER_H, HDR);
    draw_text(app, "Wi-Fi", 14, 13, 200, 18, TXT);
    const char *st = app->pending_ssid[0] ? "connecting..." :
                     app->dev_state>=100 ? "connected" : app->dev_state==30 ? "not connected" :
                     app->dev_state>=40 ? "connecting..." : app->iface[0] ? "ready" : "no adapter";
    draw_text(app, st, app->width-140, 16, 128, 12, DIM);

    if (app->n_nets == 0){
        draw_text(app, app->iface[0] ? "Scanning for networks..." : "Wi-Fi unavailable",
                  16, HEADER_H+20, app->width-32, 13, DIM);
        /* hos-wpa-agent's live self-diagnosis (adapter/nl80211/scan count) so an empty list is
         * explained ON-SCREEN — no terminal / Logs app needed to see where the scan stands. */
        if (app->agent_status[0])
            draw_wrapped(app, app->agent_status, 16, HEADER_H+44, app->width-32, 11, 14, ACC);
        /* No adapter + no terminal to diagnose: show the boot-doctor's verdict right here. */
        if (!app->iface[0] && app->diag[0]){
            int y = HEADER_H + 80;
            fill_rect(app, 0, y-6, app->width, 1, 0xff2d3444u);
            draw_text(app, "diagnostics (/run/boot-status.txt):", 12, y, app->width-24, 11, ACC);
            draw_wrapped(app, app->diag, 12, y+18, app->width-24, 11, 14, DIM);
        }
    }
    for (int i=0;i<app->n_nets;i++){
        int y = HEADER_H + i*ROW_H; if (y+ROW_H > app->height) break;
        struct net *n = &app->nets[i];
        fill_rect(app, 0, y, app->width, ROW_H-1, (i==app->hover)?ROWH:ROW);
        if (n->active) fill_rect(app, 0, y, 3, ROW_H-1, ACC);
        draw_text(app, n->ssid, 16, y+8, app->width-120, 15, n->active?ACC:TXT);
        const char *slabel = n->active ? "connected" : (strcmp(n->sec,"open")==0?"open":"secured");
        draw_text(app, slabel, 16, y+26, 180, 11, DIM);
        /* signal bars right-aligned */
        draw_signal(app, app->width-40, y+14, n->strength, ON, OFF);
        /* lock glyph for secured */
        if (strcmp(n->sec,"open")!=0) draw_text(app, "*", app->width-56, y+12, 12, 15, DIM);
    }

    if (app->pending_ssid[0]){
        int py = app->height - 54;
        char line[160];
        snprintf(line, sizeof line, "Connecting to %s...", app->pending_ssid);
        fill_rect(app, 0, py, app->width, 54, 0xff0d1e2bu);
        fill_rect(app, 0, py, app->width, 2, ACC);
        draw_text(app, line, 16, py+17, app->width-32, 13, ACC);
    } else if (app->connect_error[0]){
        int py = app->height - 70;
        fill_rect(app, 0, py, app->width, 70, 0xff35191du);
        draw_text(app, "Connection failed", 16, py+11, app->width-32, 13, 0xffff7b83u);
        draw_text(app, app->connect_error, 16, py+34, app->width-32, 11, TXT);
    }

    if (app->editing){
        /* modal password panel over the bottom */
        int ph = 120, py = app->height - ph;
        fill_rect(app, 0, py, app->width, ph, 0xff0d0f14u);
        fill_rect(app, 0, py, app->width, 2, ACC);
        char head[128]; snprintf(head, sizeof head, "Password for %s", app->edit_ssid);
        draw_text(app, head, 16, py+12, app->width-32, 13, TXT);
        /* masked field */
        char masked[97]; int L = app->editlen; if (L>96) L=96; for (int i=0;i<L;i++) masked[i]='*'; masked[L]=0;
        fill_rect(app, 16, py+40, app->width-32, 28, 0xff232834u);
        draw_text(app, masked[0]?masked:" ", 24, py+46, app->width-48, 15, TXT);
        draw_text(app, "Enter = connect    Esc = cancel", 16, py+80, app->width-32, 11, DIM);
    }
}

/* --- double-buffered wl_shm (one memfd, two slices) --- */
static void redraw_commit(struct app *app);   /* fwd */
static void buffer_release(void *d, struct wl_buffer *wl){ struct app *a = d;
    for (int i=0;i<2;i++) if (a->bufs[i].wl == wl) a->bufs[i].busy = 0;
    if (a->dirty){ a->dirty = 0; redraw_commit(a); }   /* a deferred redraw can now proceed */
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static int create_buffers(struct app *app){
    int fd = create_memfd("epin-wifi-menu"); if (fd < 0) return -1;
    size_t total = app->buffer_size * 2;
    if (ftruncate(fd, (off_t)total) < 0){ close(fd); return -1; }
    unsigned char *base = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED){ close(fd); return -1; }
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int)total);
    for (int i=0;i<2;i++){
        app->bufs[i].px = (uint32_t*)(base + (size_t)i*app->buffer_size);
        app->bufs[i].wl = wl_shm_pool_create_buffer(pool, (int)((size_t)i*app->buffer_size),
                                                    app->width, app->height, app->stride, WL_SHM_FORMAT_XRGB8888);
        if (!app->bufs[i].wl){ wl_shm_pool_destroy(pool); close(fd); return -1; }
        wl_buffer_add_listener(app->bufs[i].wl, &buffer_listener, app);
        app->bufs[i].busy = 0;
    }
    wl_shm_pool_destroy(pool); close(fd);
    return 0;
}
/* Draw into a FREE buffer and commit it; if both are in use, mark dirty and redraw on the next release
 * (never modify a buffer the compositor may still be reading -> that vanished the window on real HW). */
static void redraw_commit(struct app *app){
    if (!app->configured) return;
    int i = app->bufs[0].busy ? 1 : 0;
    if (app->bufs[i].busy){ app->dirty = 1; return; }
    app->pixels = app->bufs[i].px;
    draw_menu(app);
    app->bufs[i].busy = 1;
    wl_surface_attach(app->surface, app->bufs[i].wl, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
}

/* write the connect request for the agent, then reset the dialog. */
static void submit_connect(struct app *app, const char *ssid, const char *psk){
    mkdir("/run", 0755); mkdir("/run/wifi", 0755);
    unlink("/run/wifi/error");
    app->connect_error[0] = 0;
    int fd = open("/run/wifi/connect", O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (fd >= 0){ char line[256]; int n = snprintf(line, sizeof line, "%s\n%s\n", ssid, psk?psk:"");
        (void)!write(fd, line, n); close(fd); }
    strncpy(app->pending_ssid, ssid, sizeof(app->pending_ssid)-1);
    app->pending_ssid[sizeof(app->pending_ssid)-1] = 0;
    char m[128]; snprintf(m, sizeof m, "WIFIMENU: connect '%s'", ssid); log_line(m);
}

/* --- input --- */
static void row_click(struct app *app, int row){
    /* Ignore pointer clicks and key-repeat Enter events while NM is activating.
     * Without this guard, the Enter that submitted a password was followed by
     * compositor repeat presses: one reopened the secured row and the next
     * submitted an empty password, cancelling the valid attempt with NM reason
     * `new-activation`. */
    if (app->pending_ssid[0]) return;
    if (row < 0 || row >= app->n_nets) return;
    struct net *n = &app->nets[row];
    if (strcmp(n->sec, "open") == 0){ submit_connect(app, n->ssid, ""); return; }
    strncpy(app->edit_ssid, n->ssid, sizeof(app->edit_ssid)-1); app->edit_ssid[sizeof(app->edit_ssid)-1]=0;
    app->editbuf[0]=0; app->editlen=0; app->editing=1; app->shift=0;
    redraw_commit(app);
}

static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; a->hover=-1; redraw_commit(a); }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y);
    int nh = -1; if (!a->editing && a->pointer_y >= HEADER_H){ int r=((int)a->pointer_y - HEADER_H)/ROW_H; if (r>=0 && r<a->n_nets) nh=r; }
    if (nh != a->hover){ a->hover = nh; redraw_commit(a); } }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/ || state != 1) return;
    if (a->editing) return;   /* password panel is keyboard-driven */
    if (a->pointer_y >= HEADER_H){ int r=((int)a->pointer_y - HEADER_H)/ROW_H; row_click(a, r); } }
static void pointer_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v){ (void)d;(void)p;(void)t;(void)ax;(void)v; }
/* wl_pointer >= v5 also emits frame/axis_source/axis_stop/axis_discrete — these listener slots MUST be
 * non-NULL or libwayland calls a NULL fn-ptr on the first real pointer 'frame' event and the client
 * crashes (this vanished the window on real HW; QEMU headless sends no pointer events so it never fired). */
static void pointer_frame(void *d, struct wl_pointer *p){ (void)d;(void)p; }
static void pointer_axis_source(void *d, struct wl_pointer *p, uint32_t s){ (void)d;(void)p;(void)s; }
static void pointer_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t a){ (void)d;(void)p;(void)t;(void)a; }
static void pointer_axis_discrete(void *d, struct wl_pointer *p, uint32_t a, int32_t dsc){ (void)d;(void)p;(void)a;(void)dsc; }
static const struct wl_pointer_listener pointer_listener = {
    .enter=pointer_enter,.leave=pointer_leave,.motion=pointer_motion,.button=pointer_button,.axis=pointer_axis,
    .frame=pointer_frame,.axis_source=pointer_axis_source,.axis_stop=pointer_axis_stop,.axis_discrete=pointer_axis_discrete };

static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t sz){ (void)d;(void)k;(void)f;(void)sz; if (fd>=0) close(fd); }
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf, struct wl_array *ks){ (void)d;(void)k;(void)s;(void)sf;(void)ks; }
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf){ (void)d;(void)k;(void)s;(void)sf; }
static void kb_key(void *d, struct wl_keyboard *k, uint32_t se, uint32_t t, uint32_t key, uint32_t state){ (void)k;(void)se;(void)t; struct app*a=d;
    if (key==42||key==54){ a->shift = (state==1); return; }
    if (state != 1) return;              /* press only */
    if (!a->editing){
        if (a->pending_ssid[0]) return;  /* activation owns input until success/error */
        /* Keyboard navigation for the network list.  Previously all keys were
         * discarded here, so pressing Enter on a visible SSID did literally
         * nothing unless it had first been clicked with the pointer. */
        if (a->n_nets <= 0) return;
        if (key==103 /* KEY_UP */){
            if (a->hover < 0) a->hover = a->n_nets - 1;
            else if (a->hover > 0) a->hover--;
            redraw_commit(a); return;
        }
        if (key==108 /* KEY_DOWN */){
            if (a->hover < 0) a->hover = 0;
            else if (a->hover + 1 < a->n_nets) a->hover++;
            redraw_commit(a); return;
        }
        if (key==28 /* KEY_ENTER */){
            if (a->hover < 0) a->hover = 0;
            row_click(a, a->hover);
            return;
        }
        return;
    }
    if (key==1){ a->editing=0; a->editbuf[0]=0; a->editlen=0; redraw_commit(a); return; }   /* Esc */
    if (key==28){ a->editing=0; submit_connect(a, a->edit_ssid, a->editbuf); a->editbuf[0]=0; a->editlen=0; redraw_commit(a); return; } /* Enter */
    if (key==14){ if (a->editlen>0) a->editbuf[--a->editlen]=0; redraw_commit(a); return; }  /* Backspace */
    if (key < 128){ char c = a->shift ? EVDEV_SHIFT[key] : EVDEV_CHAR[key];
        if (c && a->editlen < (int)sizeof(a->editbuf)-1){ a->editbuf[a->editlen++]=c; a->editbuf[a->editlen]=0; redraw_commit(a); } } }
static void kb_modifiers(void *d, struct wl_keyboard *k, uint32_t se, uint32_t md, uint32_t ml, uint32_t lo, uint32_t g){ (void)d;(void)k;(void)se;(void)md;(void)ml;(void)lo;(void)g; }
static void kb_repeat(void *d, struct wl_keyboard *k, int32_t r, int32_t delay){ (void)d;(void)k;(void)r;(void)delay; }
static const struct wl_keyboard_listener keyboard_listener = {
    .keymap=kb_keymap,.enter=kb_enter,.leave=kb_leave,.key=kb_key,.modifiers=kb_modifiers,.repeat_info=kb_repeat };

static void seat_caps(void *d, struct wl_seat *seat, uint32_t caps){ struct app*a=d;
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !a->keyboard){ a->keyboard = wl_seat_get_keyboard(seat); wl_keyboard_add_listener(a->keyboard,&keyboard_listener,a); }
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !a->pointer){ a->pointer = wl_seat_get_pointer(seat); wl_pointer_add_listener(a->pointer,&pointer_listener,a); } }
static void seat_name(void *d, struct wl_seat *s, const char *n){ (void)d;(void)s;(void)n; }
static const struct wl_seat_listener seat_listener = { .capabilities=seat_caps, .name=seat_name };

static void wm_base_ping(void *d, struct xdg_wm_base *b, uint32_t serial){ (void)d; xdg_wm_base_pong(b, serial); }
static const struct xdg_wm_base_listener wm_base_listener = { .ping=wm_base_ping };
static void toplevel_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s){ (void)d;(void)t;(void)w;(void)h;(void)s; }
static void toplevel_close(void *d, struct xdg_toplevel *t){ (void)t; struct app*a=d; a->running=0; }
static void toplevel_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h){ (void)d;(void)t;(void)w;(void)h; }
static void toplevel_wmcap(void *d, struct xdg_toplevel *t, struct wl_array *c){ (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure=toplevel_configure,.close=toplevel_close,.configure_bounds=toplevel_bounds,.wm_capabilities=toplevel_wmcap };

static void xdg_surface_configure(void *d, struct xdg_surface *s, uint32_t serial){ struct app*a=d;
    xdg_surface_ack_configure(s, serial);
    a->configured = 1;
    redraw_commit(a); }
static const struct xdg_surface_listener xdg_surface_listener = { .configure=xdg_surface_configure };

static void registry_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver){ struct app*a=d;
    if (!strcmp(iface, wl_compositor_interface.name)) a->compositor = wl_registry_bind(r,name,&wl_compositor_interface, ver<4?ver:4);
    else if (!strcmp(iface, wl_shm_interface.name)) a->shm = wl_registry_bind(r,name,&wl_shm_interface,1);
    else if (!strcmp(iface, xdg_wm_base_interface.name)){ a->wm_base = wl_registry_bind(r,name,&xdg_wm_base_interface, ver<6?ver:6); xdg_wm_base_add_listener(a->wm_base,&wm_base_listener,a); }
    else if (!strcmp(iface, wl_seat_interface.name)){ a->seat = wl_registry_bind(r,name,&wl_seat_interface, ver<5?ver:5); wl_seat_add_listener(a->seat,&seat_listener,a); } }
static void registry_remove(void *d, struct wl_registry *r, uint32_t n){ (void)d;(void)r;(void)n; }
static const struct wl_registry_listener registry_listener = { .global=registry_global, .global_remove=registry_remove };

static void live_refresh(struct app *app){
    unsigned char *buf; size_t sz; unsigned h = 0;
    if (app->pending_ssid[0]){
        unsigned char *eb; size_t es;
        if (load_file("/run/wifi/error", &eb, &es) == 0){
            size_t n = es < sizeof(app->connect_error)-1 ? es : sizeof(app->connect_error)-1;
            memcpy(app->connect_error, eb, n); app->connect_error[n] = 0; free(eb);
            app->pending_ssid[0] = 0;
            redraw_commit(app);
        }
    }
    if (load_file("/run/wifi/networks", &buf, &sz) == 0){ h = fnv1a(buf, sz); free(buf); }
    if (h != app->last_hash){
        app->last_hash = h;
        load_networks(app);
        /* A consumed request only proves that Enter reached the agent.  Dismiss
         * after NetworkManager confirms that this exact SSID is active; failed
         * authentication therefore leaves the menu open for another attempt. */
        if (app->pending_ssid[0]){
            for (int i=0; i<app->n_nets; i++){
                if (app->nets[i].active && strcmp(app->nets[i].ssid, app->pending_ssid)==0){
                    log_line("WIFIMENU: connection active; closing menu");
                    app->running = 0;
                    return;
                }
            }
        }
        if (!app->editing) redraw_commit(app);
    }
    /* Diagnostics (no adapter): refresh only every ~4s AND redraw only when the content actually changed
     * — a blind redraw+file-read every second was needless load (and on the laptop repeatedly read NM's
     * held-open /run/nm.log), a plausible contributor to the desktop hang. */
    static int slow = 0; static unsigned diaghash = 0;
    if (!app->iface[0] && !app->editing && (++slow % 4) == 0){
        load_diag(app);
        unsigned dh = fnv1a((const unsigned char*)app->diag, strlen(app->diag));
        if (dh != diaghash){ diaghash = dh; redraw_commit(app); }
    }
}

/* Single-instance drop-down semantics: the menu records its pid in /run/wifi/menu.pid.
 * If a second instance starts (the panel wifi glyph was clicked again — from ANY
 * launcher: Weston desktop-shell, wl-quicksettings, or the Hyprland layer bar), it
 * SIGTERMs the running one and exits — so the same click that would have stacked a
 * duplicate window instead COLLAPSES the open menu.  Expand / collapse, one window. */
#define MENU_PIDFILE "/run/wifi/menu.pid"
static int single_instance_toggle(void){
    FILE *f = fopen(MENU_PIDFILE, "r");
    if (f){
        long oldpid = 0;
        if (fscanf(f, "%ld", &oldpid) == 1 && oldpid > 0){
            fclose(f);
            if (kill((pid_t)oldpid, SIGTERM) == 0){
                /* a live menu existed: this click collapses it; we're done */
                unlink(MENU_PIDFILE);
                return 1;
            }
            /* stale pidfile (menu died without cleanup) — fall through and take over */
        } else {
            fclose(f);
        }
    }
    f = fopen(MENU_PIDFILE, "w");
    if (f){ fprintf(f, "%ld\n", (long)getpid()); fclose(f); }
    return 0;
}

int main(void){
    static struct app app; memset(&app, 0, sizeof app);
    app.running = 1; app.hover = -1;
    app.width = WIN_W; app.height = WIN_H; app.stride = WIN_W*4; app.buffer_size = (size_t)app.stride*WIN_H;
    signal(SIGCHLD, SIG_IGN);
    if (single_instance_toggle()) return 0;   /* second click = collapse the open menu */
    /* SIGTERM/SIGINT keep their DEFAULT disposition on purpose: the kernel's default
     * action terminates us even while parked in poll() (a handler would only be
     * delivered at a blocking read on this kernel), the fd cleanup on exit makes the
     * compositor drop the window immediately, and a stale pidfile is handled by the
     * next instance's takeover path. */
    init_freetype(&app);
    load_networks(&app);
    load_diag(&app);

    log_line("WIFIMENU: starting top-right Wi-Fi menu");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("WIFIMENU: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base){ log_line("WIFIMENU: missing globals"); return 1; }
    if (create_buffers(&app) < 0){ log_line("WIFIMENU: buffer failed"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Wi-Fi");
    xdg_toplevel_set_app_id(app.toplevel, "epin-wifi-menu");
    /* FLOAT under the tiling WM: marking the toplevel fixed-size (min==max at our
     * natural popover dimensions) makes the desktop-shell tiler's epin_is_tileable()
     * return false, so this drop-down menu is left as a floating popover instead of
     * being stretched into a tile. */
    xdg_toplevel_set_min_size(app.toplevel, WIN_W, WIN_H);
    xdg_toplevel_set_max_size(app.toplevel, WIN_W, WIN_H);
    wl_surface_commit(app.surface);
    wl_display_flush(app.display);

    int wlfd = wl_display_get_fd(app.display);
    while (app.running){
        while (wl_display_prepare_read(app.display) != 0) wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);
        struct pollfd pfd = { .fd=wlfd, .events=POLLIN, .revents=0 };
        int pr = poll(&pfd, 1, 1000);
        if (pr > 0 && (pfd.revents & POLLIN)){ wl_display_read_events(app.display); wl_display_dispatch_pending(app.display); }
        else { wl_display_cancel_read(app.display); if (pr < 0){ if (errno==EINTR) continue; break; }
               if (pr == 0) live_refresh(&app); }
    }
    /* Collapse cleanly: drop the pidfile claim and destroy the window so the
     * compositor removes it immediately (a plain exit also works — the kernel
     * closes our fds and the compositor sees peerClosed — but be explicit). */
    unlink(MENU_PIDFILE);
    if (app.toplevel)    xdg_toplevel_destroy(app.toplevel);
    if (app.xdg_surface) xdg_surface_destroy(app.xdg_surface);
    if (app.surface)     wl_surface_destroy(app.surface);
    wl_display_flush(app.display);
    return 0;
}
