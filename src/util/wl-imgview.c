/*
 * wl-imgview.c -- a native PNG image viewer for the EpinAnonymOS Weston desktop.
 *
 * argv[1] = a PNG file path.  Decodes it with libpng's simplified API into a BGRA buffer (which matches
 * this compositor's XRGB8888 wl_shm framebuffer), then blits it scaled-to-fit (nearest-neighbour, aspect
 * preserved) into a fixed 720x540 window with our own CSD titlebar (basename + red close box).
 *   +/-  zoom      arrows pan      0 reset-to-fit      Esc / close-box  exit
 *
 * All Wayland scaffolding (registry / seat / xdg / double-buffered wl_shm / FreeType text / evdev keymap /
 * the complete v5 wl_pointer listener) is copied VERBATIM from the proven wl-wifi-menu.c client.
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
#include <png.h>
#include "xdg-shell-client-protocol.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum { WIN_W = 720, WIN_H = 540, TITLE_H = 26 };

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
    void *map_base; size_t map_size;   // current shm mapping (tracked for teardown on resize)
    int pending_w, pending_h;          // size from the latest toplevel_configure (0 = compositor deferred)
    int configured, dirty;
    uint32_t *pixels;              // the buffer draw() currently targets
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    int font_ready, running;
    double pointer_x, pointer_y;

    /* image state */
    uint32_t *img;                 // decoded BGRA pixels
    int iw, ih;                    // image dimensions
    char path[512];
    char base[256];                // basename for titlebar
    int have_img;

    /* view state */
    double zoom;                   // multiplier on top of fit-scale
    double pan_x, pan_y;           // pan offset in content pixels

    /* drag-to-pan */
    int dragging;
    double drag_x, drag_y;
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

/* --- image load (libpng simplified API -> BGRA to match XRGB8888 wl_shm framebuffer) --- */
static void load_image(struct app *app){
    app->have_img = 0;
    if (app->img){ free(app->img); app->img = NULL; }
    if (!app->path[0]) return;
    png_image image; memset(&image, 0, sizeof image);
    image.version = PNG_IMAGE_VERSION;
    if (!png_image_begin_read_from_file(&image, app->path)){
        char m[600]; snprintf(m, sizeof m, "IMGVIEW: begin_read failed: %s", image.message); log_line(m);
        return;
    }
    image.format = PNG_FORMAT_BGRA;   /* memory bytes B,G,R,A == uint32 0xAARRGGBB (little-endian) */
    size_t sz = PNG_IMAGE_SIZE(image);
    uint32_t *buf = malloc(sz ? sz : 4);
    if (!buf){ png_image_free(&image); log_line("IMGVIEW: oom"); return; }
    if (!png_image_finish_read(&image, NULL /*bg*/, buf, 0 /*row_stride*/, NULL)){
        char m[600]; snprintf(m, sizeof m, "IMGVIEW: finish_read failed: %s", image.message); log_line(m);
        free(buf); png_image_free(&image); return;
    }
    app->img = buf;
    app->iw = (int)image.width;
    app->ih = (int)image.height;
    app->have_img = 1;
    char m[600]; snprintf(m, sizeof m, "IMGVIEW: loaded %s (%dx%d)", app->path, app->iw, app->ih); log_line(m);
}

/* content-area (below titlebar) fit scale so the whole image is visible */
static double fit_scale(struct app *app){
    int cw = app->width, ch = app->height - TITLE_H;
    if (app->iw <= 0 || app->ih <= 0 || cw <= 0 || ch <= 0) return 1.0;
    double sx = (double)cw / app->iw, sy = (double)ch / app->ih;
    double s = sx < sy ? sx : sy;
    if (s <= 0) s = 1.0;
    return s;
}

/* --- rendering --- */
static void draw(struct app *app){
    const uint32_t BG=0xff11141bu, TITLE=0xff232834u, TXT=0xfff2f5fau, DIM=0xff8b94a3u,
                   CLOSE=0xffe0524du, CLOSEX=0xfff2f5fau;
    /* content backdrop */
    fill_rect(app, 0, 0, app->width, app->height, BG);

    int cy0 = TITLE_H;
    int cw = app->width, ch = app->height - TITLE_H;

    if (!app->have_img){
        const char *msg = "No image (usage: wl-imgview FILE.png)";
        int px = 16; int approx = (int)(strlen(msg) * px * 0.52);
        draw_text(app, msg, (app->width - approx)/2, cy0 + ch/2 - px/2, app->width, px, DIM);
    } else {
        double scale = fit_scale(app) * app->zoom;
        if (scale <= 0) scale = 1.0;
        double dw = app->iw * scale, dh = app->ih * scale;
        /* centre, then apply pan */
        double offx = (cw - dw) / 2.0 + app->pan_x;
        double offy = (ch - dh) / 2.0 + app->pan_y;
        for (int dy = 0; dy < ch; dy++){
            int py = cy0 + dy;
            uint32_t *drow = &app->pixels[py*app->width];
            double sy = (dy - offy) / scale;
            int syi = (int)sy;
            if (sy < 0 || syi < 0 || syi >= app->ih) continue;
            const uint32_t *srow = &app->img[(size_t)syi*app->iw];
            for (int dx = 0; dx < cw; dx++){
                double sx = (dx - offx) / scale;
                int sxi = (int)sx;
                if (sx < 0 || sxi < 0 || sxi >= app->iw) continue;
                uint32_t s = srow[sxi];
                unsigned a = (s >> 24) & 0xff;
                drow[dx] = (a >= 255) ? (0xff000000u | (s & 0x00ffffffu))
                                      : blend_xrgb(drow[dx], s, a);
            }
        }
    }

    /* CSD titlebar drawn last, on top */
    fill_rect(app, 0, 0, app->width, TITLE_H, TITLE);
    draw_text(app, app->have_img ? app->base : "wl-imgview", 12, 5, app->width - TITLE_H - 20, 15, TXT);
    /* red close box top-right */
    int bx = app->width - TITLE_H;
    fill_rect(app, bx, 0, TITLE_H, TITLE_H, CLOSE);
    /* draw an 'x' with two short diagonals via single pixels */
    for (int k = 0; k < 10; k++){
        int cxx = bx + 8 + k, cyy = 8 + k;
        if (cxx>=0&&cxx<app->width&&cyy>=0&&cyy<app->height) app->pixels[cyy*app->width+cxx]=CLOSEX;
        int cxx2 = bx + 8 + k, cyy2 = 17 - k;
        if (cxx2>=0&&cxx2<app->width&&cyy2>=0&&cyy2<app->height) app->pixels[cyy2*app->width+cxx2]=CLOSEX;
    }
    /* zoom readout bottom-left */
    if (app->have_img){
        char z[64]; snprintf(z, sizeof z, "%dx%d  %d%%", app->iw, app->ih,
                             (int)(fit_scale(app)*app->zoom*100.0 + 0.5));
        draw_text(app, z, 10, app->height - 20, 300, 12, DIM);
    }
}

/* --- double-buffered wl_shm (one memfd, two slices) --- */
static void redraw_commit(struct app *app);
static void buffer_release(void *d, struct wl_buffer *wl){ struct app *a = d;
    for (int i=0;i<2;i++) if (a->bufs[i].wl == wl) a->bufs[i].busy = 0;
    if (a->dirty){ a->dirty = 0; redraw_commit(a); }
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static int create_buffers(struct app *app){
    int fd = create_memfd("epin-imgview"); if (fd < 0) return -1;
    size_t total = app->buffer_size * 2;
    if (ftruncate(fd, (off_t)total) < 0){ close(fd); return -1; }
    unsigned char *base = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED){ close(fd); return -1; }
    app->map_base = base; app->map_size = total;
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
static void redraw_commit(struct app *app){
    if (!app->configured || !app->bufs[0].wl) return;
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

/* --- resize: honour a compositor-driven size (e.g. the tiling WM's set_size) --- */
static void destroy_buffers(struct app *app){
    for (int i=0;i<2;i++){
        if (app->bufs[i].wl) wl_buffer_destroy(app->bufs[i].wl);
        app->bufs[i].wl = NULL; app->bufs[i].px = NULL; app->bufs[i].busy = 0;
    }
    if (app->map_base && app->map_base != MAP_FAILED && app->map_size)
        munmap(app->map_base, app->map_size);
    app->map_base = NULL; app->map_size = 0;
    app->pixels = NULL; app->dirty = 0;
}
/* draw() is fully size-relative (image is scaled-to-fit, CSD/text keyed off width/height),
 * so rebuilding the shm buffers at the new dimensions reflows the content automatically. */
static void resize_to(struct app *app, int w, int h){
    if (w <= 0 || h <= 0) return;
    if (w == app->width && h == app->height) return;
    destroy_buffers(app);
    app->width = w; app->height = h;
    app->stride = w * 4; app->buffer_size = (size_t)app->stride * h;
    if (create_buffers(app) < 0){ log_line("IMGVIEW: resize buffer alloc failed"); app->running = 0; }
}

/* --- input --- */
static int in_close_box(struct app *a){
    return a->pointer_x >= a->width - TITLE_H && a->pointer_x < a->width &&
           a->pointer_y >= 0 && a->pointer_y < TITLE_H;
}

static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; a->dragging=0; }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    double nx=wl_fixed_to_double(x), ny=wl_fixed_to_double(y);
    if (a->dragging && a->have_img){ a->pan_x += nx - a->drag_x; a->pan_y += ny - a->drag_y; a->drag_x=nx; a->drag_y=ny; a->pointer_x=nx; a->pointer_y=ny; redraw_commit(a); return; }
    a->pointer_x=nx; a->pointer_y=ny; }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/) return;
    if (state == 1){
        if (in_close_box(a)) exit(0);
        if (a->pointer_y >= TITLE_H){ a->dragging=1; a->drag_x=a->pointer_x; a->drag_y=a->pointer_y; }
    } else {
        a->dragging=0;
    } }
static void pointer_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v){ (void)p;(void)t;(void)ax; struct app*a=d;
    if (!a->have_img) return; double dv=wl_fixed_to_double(v);
    if (dv < 0) a->zoom *= 1.1; else if (dv > 0) a->zoom /= 1.1;
    if (a->zoom < 0.05) a->zoom = 0.05; if (a->zoom > 40.0) a->zoom = 40.0;
    redraw_commit(a); }
/* wl_pointer >= v5 also emits frame/axis_source/axis_stop/axis_discrete — these listener slots MUST be
 * non-NULL or libwayland calls a NULL fn-ptr on the first real pointer 'frame' event and the client crashes. */
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
    double panstep = 40.0;
    switch (key){
        case 1:   a->running = 0; return;                              /* Esc */
        case 13: case 78:  a->zoom *= 1.25; break;                      /* '=' / KP_+  zoom in */
        case 12: case 74:  a->zoom /= 1.25; break;                      /* '-' / KP_-  zoom out */
        case 11:  a->zoom = 1.0; a->pan_x = a->pan_y = 0; break;        /* '0' reset-to-fit */
        case 103: a->pan_y += panstep; break;                          /* Up */
        case 108: a->pan_y -= panstep; break;                          /* Down */
        case 105: a->pan_x += panstep; break;                          /* Left */
        case 106: a->pan_x -= panstep; break;                          /* Right */
        default: return;
    }
    if (a->zoom < 0.05) a->zoom = 0.05; if (a->zoom > 40.0) a->zoom = 40.0;
    redraw_commit(a); }
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
    /* store the compositor-dictated tile size; 0 means "you pick" so keep our default. Applied in xdg_surface_configure. */
    if (w > 0) a->pending_w = w;
    if (h > 0) a->pending_h = h; }
static void toplevel_close(void *d, struct xdg_toplevel *t){ (void)t; struct app*a=d; a->running=0; }
static void toplevel_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h){ (void)d;(void)t;(void)w;(void)h; }
static void toplevel_wmcap(void *d, struct xdg_toplevel *t, struct wl_array *c){ (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure=toplevel_configure,.close=toplevel_close,.configure_bounds=toplevel_bounds,.wm_capabilities=toplevel_wmcap };

static void xdg_surface_configure(void *d, struct xdg_surface *s, uint32_t serial){ struct app*a=d;
    xdg_surface_ack_configure(s, serial);
    /* apply the latest toplevel_configure size before drawing; rebuild buffers only if it actually changed */
    int nw = a->pending_w > 0 ? a->pending_w : a->width;
    int nh = a->pending_h > 0 ? a->pending_h : a->height;
    if (nw != a->width || nh != a->height) resize_to(a, nw, nh);
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

int main(int argc, char **argv){
    static struct app app; memset(&app, 0, sizeof app);
    app.running = 1; app.zoom = 1.0;
    app.width = WIN_W; app.height = WIN_H; app.stride = WIN_W*4; app.buffer_size = (size_t)app.stride*WIN_H;
    signal(SIGCHLD, SIG_IGN);
    init_freetype(&app);

    if (argc > 1 && argv[1][0]){
        strncpy(app.path, argv[1], sizeof(app.path)-1);
        const char *slash = strrchr(app.path, '/');
        const char *b = slash ? slash+1 : app.path;
        strncpy(app.base, b, sizeof(app.base)-1);
        load_image(&app);
    }

    log_line("IMGVIEW: starting image viewer");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("IMGVIEW: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base){ log_line("IMGVIEW: missing globals"); return 1; }
    if (create_buffers(&app) < 0){ log_line("IMGVIEW: buffer failed"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, app.have_img ? app.base : "wl-imgview");
    xdg_toplevel_set_app_id(app.toplevel, "epin-imgview");
    wl_surface_commit(app.surface);
    wl_display_flush(app.display);

    int wlfd = wl_display_get_fd(app.display);
    while (app.running){
        while (wl_display_prepare_read(app.display) != 0) wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);
        struct pollfd pfd = { .fd=wlfd, .events=POLLIN, .revents=0 };
        int pr = poll(&pfd, 1, 1000);
        if (pr > 0 && (pfd.revents & POLLIN)){ wl_display_read_events(app.display); wl_display_dispatch_pending(app.display); }
        else { wl_display_cancel_read(app.display); if (pr < 0){ if (errno==EINTR) continue; break; } }
    }
    return 0;
}
