/*
 * wl-clocks.c -- a Clocks app (Wayland + wl_shm + FreeType client).
 *
 * Top: the current local time LARGE (HH:MM:SS) + the date, refreshed every second from the poll()
 * timeout (time()/localtime()).  Below: a stopwatch (mm:ss.cs) driven by CLOCK_MONOTONIC with three
 * labeled buttons Start / Stop / Reset, hit-tested against wl_pointer.  There are no server-side
 * decorations, so we draw our own CSD titlebar "Clocks" + a close box (clicking it exits).
 *
 * All Wayland scaffolding (registry / seat / xdg / double-buffered wl_shm / FreeType text / v5 pointer
 * listener) is copied VERBATIM from the proven wl-wifi-menu client -- only the drawn content differs.
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

enum { WIN_W = 340, WIN_H = 300, TITLE_H = 28 };

/* stopwatch button geometry */
enum { BTN_Y = 232, BTN_H = 42, BTN_MARGIN = 16, BTN_GAP = 8 };

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
    void *map_base; size_t map_total;   // backing mmap for bufs (kept so resize can tear it down)
    int cfg_w, cfg_h;                   // last compositor-requested tile size (0 = none yet)
    int configured, dirty;         // dirty = a redraw was deferred because both buffers were busy
    uint32_t *pixels;              // the buffer draw()/draw_text() currently target
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    int font_ready, running;
    double pointer_x, pointer_y;

    /* stopwatch state */
    int    sw_running;
    double sw_accum;               // accumulated seconds while stopped
    double sw_start;               // CLOCK_MONOTONIC seconds at last Start
    int    hover_btn;              // 0=Start 1=Stop 2=Reset 3=close, -1=none
};

static void log_line(const char *s){ fputs(s, stdout); fputc('\n', stdout); fflush(stdout); }
static int create_memfd(const char *name){ return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC); }

static double now_mono(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (double)ts.tv_sec + (double)ts.tv_nsec/1e9; }

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
/* pixel width of a string at the given size (for centering) */
static int text_width(struct app *app, const char *text, int px){
    if (!app->font_ready || !text) return 0;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0) return 0;
    int w = 0;
    for (const unsigned char *p = (const unsigned char*)text; *p; ++p){
        unsigned char ch = *p; if (ch < 0x20 || ch >= 0x7f) ch = '?';
        if (FT_Load_Char(app->face, ch, FT_LOAD_DEFAULT) != 0) continue;
        w += (int)(app->face->glyph->advance.x >> 6);
    }
    return w;
}
static void draw_text_centered(struct app *app, const char *text, int cx, int y, int px, uint32_t color){
    int w = text_width(app, text, px);
    draw_text(app, text, cx - w/2, y, w + 8, px, color);
}
static void fill_rect(struct app *app, int x, int y, int w, int h, uint32_t c){
    for (int j=y;j<y+h;j++){ if (j<0||j>=app->height) continue;
        for (int i=x;i<x+w;i++){ if (i<0||i>=app->width) continue; app->pixels[j*app->width+i]=c; } }
}

/* --- geometry helpers --- */
static void btn_rect(struct app *app, int idx, int *x, int *y, int *w, int *h){
    int avail = app->width - 2*BTN_MARGIN - 2*BTN_GAP;
    int bw = avail/3;
    *x = BTN_MARGIN + idx*(bw + BTN_GAP);
    *y = app->height - BTN_MARGIN - BTN_H;   /* anchor the button row to the bottom of the tile */
    *w = bw; *h = BTN_H;
}
static int point_in(double px, double py, int x, int y, int w, int h){
    return px >= x && px < x+w && py >= y && py < y+h;
}
/* close box: top-right of the titlebar */
static void close_rect(struct app *app, int *x, int *y, int *w, int *h){ *x = app->width - 24; *y = 6; *w = 16; *h = 16; }

/* --- rendering --- */
static void draw(struct app *app){
    const uint32_t BG=0xff1b1f27u, HDR=0xff11141bu, TXT=0xfff2f5fau, DIM=0xff8b94a3u,
                   PANEL=0xff232834u, BTN=0xff2d3444u, BTNH=0xff3a4a63u,
                   GRN=0xff43c46eu, RED=0xffd45252u, AMBER=0xffe0a94du, CLOSE=0xffd45252u;
    fill_rect(app, 0, 0, app->width, app->height, BG);

    /* --- CSD titlebar --- */
    fill_rect(app, 0, 0, app->width, TITLE_H, HDR);
    draw_text(app, "Clocks", 12, 6, 200, 15, TXT);
    { int cx,cy,cw,ch; close_rect(app,&cx,&cy,&cw,&ch);
      fill_rect(app, cx, cy, cw, ch, app->hover_btn==3 ? CLOSE : BTN);
      draw_text(app, "x", cx+5, cy+1, 12, 13, TXT); }

    /* --- clock: large local time + date --- */
    time_t t = time(NULL); struct tm lt; localtime_r(&t, &lt);
    char tbuf[16], dbuf[64];
    snprintf(tbuf, sizeof tbuf, "%02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);
    strftime(dbuf, sizeof dbuf, "%A, %d %B %Y", &lt);
    draw_text_centered(app, tbuf, app->width/2, TITLE_H + 18, 44, TXT);
    draw_text_centered(app, dbuf, app->width/2, TITLE_H + 74, 13, DIM);

    /* divider */
    fill_rect(app, 12, 128, app->width-24, 1, 0xff2d3444u);

    /* --- stopwatch --- */
    draw_text(app, "STOPWATCH", 16, 138, 200, 11, DIM);
    double el = app->sw_accum; if (app->sw_running) el += now_mono() - app->sw_start;
    if (el < 0) el = 0;
    long tcs = (long)(el * 100.0);
    int cs   = (int)(tcs % 100);
    int secs = (int)((tcs / 100) % 60);
    int mins = (int)(tcs / 6000);
    char sbuf[16]; snprintf(sbuf, sizeof sbuf, "%02d:%02d.%02d", mins, secs, cs);
    /* elapsed panel */
    fill_rect(app, 16, 158, app->width-32, 60, PANEL);
    fill_rect(app, 16, 158, 3, 60, app->sw_running ? GRN : AMBER);
    draw_text_centered(app, sbuf, app->width/2, 168, 36, app->sw_running ? TXT : DIM);

    /* buttons */
    const char *labels[3] = { "Start", "Stop", "Reset" };
    uint32_t accent[3] = { GRN, RED, AMBER };
    for (int i=0;i<3;i++){
        int bx,by,bw,bh; btn_rect(app,i,&bx,&by,&bw,&bh);
        fill_rect(app, bx, by, bw, bh, app->hover_btn==i ? BTNH : BTN);
        fill_rect(app, bx, by+bh-3, bw, 3, accent[i]);
        int lw = text_width(app, labels[i], 15);
        draw_text(app, labels[i], bx + (bw-lw)/2, by + (bh-18)/2, bw, 15, TXT);
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
    int fd = create_memfd("epin-clocks"); if (fd < 0) return -1;
    size_t total = app->buffer_size * 2;
    if (ftruncate(fd, (off_t)total) < 0){ close(fd); return -1; }
    unsigned char *base = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED){ close(fd); return -1; }
    app->map_base = base; app->map_total = total;   /* kept for resize teardown */
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
/* Tear down the current buffers + their backing mmap so create_buffers() can rebuild at a new size.
 * Destroying an attached buffer is legal; we immediately attach+commit a fresh one after recreating. */
static void destroy_buffers(struct app *app){
    for (int i=0;i<2;i++){
        if (app->bufs[i].wl){ wl_buffer_destroy(app->bufs[i].wl); app->bufs[i].wl = NULL; }
        app->bufs[i].px = NULL; app->bufs[i].busy = 0;
    }
    if (app->map_base && app->map_base != MAP_FAILED) munmap(app->map_base, app->map_total);
    app->map_base = NULL; app->map_total = 0;
    app->dirty = 0;   /* any deferred redraw referred to the now-destroyed buffers */
}
/* Draw into a FREE buffer and commit it; if both are in use, mark dirty and redraw on the next release
 * (never modify a buffer the compositor may still be reading -> that vanished the window on real HW). */
static void redraw_commit(struct app *app){
    if (!app->configured) return;
    int i = app->bufs[0].busy ? 1 : 0;
    if (app->bufs[i].busy){ app->dirty = 1; return; }
    app->pixels = app->bufs[i].px;
    draw(app);
    app->bufs[i].busy = 1;
    wl_surface_attach(app->surface, app->bufs[i].wl, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
}

/* --- input --- */
static void handle_click(struct app *app){
    /* close box */
    { int cx,cy,cw,ch; close_rect(app,&cx,&cy,&cw,&ch);
      if (point_in(app->pointer_x, app->pointer_y, cx, cy, cw, ch)){ log_line("CLOCKS: close"); exit(0); } }
    /* stopwatch buttons */
    for (int i=0;i<3;i++){
        int bx,by,bw,bh; btn_rect(app,i,&bx,&by,&bw,&bh);
        if (!point_in(app->pointer_x, app->pointer_y, bx, by, bw, bh)) continue;
        if (i == 0){ if (!app->sw_running){ app->sw_start = now_mono(); app->sw_running = 1; } }        /* Start */
        else if (i == 1){ if (app->sw_running){ app->sw_accum += now_mono() - app->sw_start; app->sw_running = 0; } } /* Stop */
        else { app->sw_running = 0; app->sw_accum = 0; }                                                 /* Reset */
        redraw_commit(app);
        return;
    }
}

static int hit_test_btn(struct app *app){
    int cx,cy,cw,ch; close_rect(app,&cx,&cy,&cw,&ch);
    if (point_in(app->pointer_x, app->pointer_y, cx, cy, cw, ch)) return 3;
    for (int i=0;i<3;i++){ int bx,by,bw,bh; btn_rect(app,i,&bx,&by,&bw,&bh);
        if (point_in(app->pointer_x, app->pointer_y, bx, by, bw, bh)) return i; }
    return -1;
}

static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; if (a->hover_btn!=-1){ a->hover_btn=-1; redraw_commit(a); } }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y);
    int nh = hit_test_btn(a);
    if (nh != a->hover_btn){ a->hover_btn = nh; redraw_commit(a); } }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/ || state != 1) return;
    handle_click(a); }
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
    if (state != 1) return;              /* press only */
    if (key==1){ log_line("CLOCKS: esc"); exit(0); }              /* Esc quits */
    if (key==57){ /* Space toggles the stopwatch */
        if (a->sw_running){ a->sw_accum += now_mono() - a->sw_start; a->sw_running = 0; }
        else { a->sw_start = now_mono(); a->sw_running = 1; }
        redraw_commit(a); return; }
    if (key==19){ a->sw_running = 0; a->sw_accum = 0; redraw_commit(a); return; }  /* R = reset */
}
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
static void toplevel_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s){ (void)t;(void)s; struct app*a=d;
    if (w > 0 && h > 0){ a->cfg_w = w; a->cfg_h = h; }   /* remember the compositor-dictated tile size */
}
static void toplevel_close(void *d, struct xdg_toplevel *t){ (void)t; struct app*a=d; a->running=0; }
static void toplevel_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h){ (void)d;(void)t;(void)w;(void)h; }
static void toplevel_wmcap(void *d, struct xdg_toplevel *t, struct wl_array *c){ (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure=toplevel_configure,.close=toplevel_close,.configure_bounds=toplevel_bounds,.wm_capabilities=toplevel_wmcap };

static void xdg_surface_configure(void *d, struct xdg_surface *s, uint32_t serial){ struct app*a=d;
    xdg_surface_ack_configure(s, serial);
    /* Honor a compositor-driven resize: rebuild the wl_shm buffers at the new size before redrawing.
     * The initial configure (no size hint, cfg_w/cfg_h==0) keeps the natural WIN_W x WIN_H buffers. */
    if (a->cfg_w > 0 && a->cfg_h > 0 && (a->cfg_w != a->width || a->cfg_h != a->height)){
        a->width = a->cfg_w; a->height = a->cfg_h;
        a->stride = a->width * 4; a->buffer_size = (size_t)a->stride * a->height;
        destroy_buffers(a);
        if (create_buffers(a) < 0){ log_line("CLOCKS: resize buffer failed"); a->running = 0; return; }
    }
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

int main(void){
    static struct app app; memset(&app, 0, sizeof app);
    app.running = 1; app.hover_btn = -1;
    app.width = WIN_W; app.height = WIN_H; app.stride = WIN_W*4; app.buffer_size = (size_t)app.stride*WIN_H;
    signal(SIGCHLD, SIG_IGN);
    init_freetype(&app);

    log_line("CLOCKS: starting");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("CLOCKS: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base){ log_line("CLOCKS: missing globals"); return 1; }
    if (create_buffers(&app) < 0){ log_line("CLOCKS: buffer failed"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Clocks");
    xdg_toplevel_set_app_id(app.toplevel, "epin-clocks");
    wl_surface_commit(app.surface);
    wl_display_flush(app.display);

    int wlfd = wl_display_get_fd(app.display);
    while (app.running){
        while (wl_display_prepare_read(app.display) != 0) wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);
        /* refresh fast (centiseconds) while the stopwatch runs, otherwise once per second for the clock */
        int timeout = app.sw_running ? 40 : 1000;
        struct pollfd pfd = { .fd=wlfd, .events=POLLIN, .revents=0 };
        int pr = poll(&pfd, 1, timeout);
        if (pr > 0 && (pfd.revents & POLLIN)){ wl_display_read_events(app.display); wl_display_dispatch_pending(app.display); }
        else { wl_display_cancel_read(app.display); if (pr < 0){ if (errno==EINTR) continue; break; }
               if (pr == 0) redraw_commit(&app); }   /* timeout: tick the clock / stopwatch */
    }
    return 0;
}
