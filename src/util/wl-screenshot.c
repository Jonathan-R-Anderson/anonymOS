/*
 * wl-screenshot.c -- a native Wayland screenshot tool for EpinAnonymOS.
 *
 * A small self-contained client: draws its own titlebar chrome (Weston has no server-side decorations),
 * a "Capture Whole Screen" button and a "Save to:" path.  On capture it reads the Linux framebuffer
 * device /dev/fb0 (EpinAnonymOS provides it), grabs the current screen contents and encodes them to a PNG
 * with libpng's simplified write API, then shows the result ("Saved: <path> (WxH)") plus a small preview
 * thumbnail scaled into the card.  A capture that fails (e.g. /dev/fb0 missing) degrades gracefully and
 * never crashes.
 *
 * Wayland scaffolding (registry / seat / xdg / persistent double-buffered wl_shm buffer / FreeType text /
 * evdev keymap / v5 pointer listener) is the proven wl-wifi-menu / wl-domain-manager pattern, reused
 * verbatim.  The only substantive additions are the framebuffer capture + PNG encode.
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
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <linux/fb.h>
#include <png.h>
#include <wayland-client.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include "xdg-shell-client-protocol.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef FBIOGET_VSCREENINFO
#define FBIOGET_VSCREENINFO 0x4600
#endif

enum { WIN_W = 420, WIN_H = 220, TITLE_H = 30,
       THUMB_W = 148, THUMB_H = 84 };

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
    uint32_t *pixels;              // the buffer draw()/draw_text() currently target
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    int pending_w, pending_h;      // last size dictated by the compositor's tiler (0 = none yet)
    unsigned char *map_base;       // current shm pool mmap (kept so resize can munmap it)
    size_t map_size;
    int font_ready, running;
    double pointer_x, pointer_y;

    char savepath[128];            // where the PNG is written (default /run/screenshot.png)
    char status[256];              // status line shown in the card
    int  status_state;             // 0 neutral, 1 ok, 2 error
    int  hover_capture, hover_close;
    int  have_thumb;               // a preview thumbnail is ready
    uint32_t thumb[THUMB_W*THUMB_H];
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
/* pixel width of a string at size px (for centering) */
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
static void fill_rect(struct app *app, int x, int y, int w, int h, uint32_t c){
    for (int j=y;j<y+h;j++){ if (j<0||j>=app->height) continue;
        for (int i=x;i<x+w;i++){ if (i<0||i>=app->width) continue; app->pixels[j*app->width+i]=c; } }
}
static void draw_frame(struct app *app, int x, int y, int w, int h, uint32_t c){
    fill_rect(app, x, y, w, 1, c); fill_rect(app, x, y+h-1, w, 1, c);
    fill_rect(app, x, y, 1, h, c); fill_rect(app, x+w-1, y, 1, h, c);
}

/* (This tool has no text-entry field, so the wl-wifi-menu evdev->char translation tables are omitted;
 * the wl_keyboard listener below only handles Esc / Enter / Space by raw keycode.) */

/* --- capture geometry (kept in one place so draw + hit-test agree) --- */
static void capture_button_rect(int *x, int *y, int *w, int *h){ *x=16; *y=62; *w=WIN_W-32; *h=46; }
static void close_box_rect(int *x, int *y, int *w, int *h){ *w=TITLE_H; *h=TITLE_H; *x=WIN_W-TITLE_H; *y=0; }
static int point_in(double px, double py, int x, int y, int w, int h){
    return px>=x && px<x+w && py>=y && py<y+h;
}

/* --- framebuffer capture + PNG encode --- */
/* Build the aspect-fit preview thumbnail from freshly-captured full-res pixels (byte order B,G,R,X,
 * i.e. a u32 of 0x00RRGGBB, which is exactly our XRGB layout once the top byte is forced opaque). */
static void make_thumb(struct app *app, const uint32_t *fb, uint32_t sw, uint32_t sh){
    for (int i=0;i<THUMB_W*THUMB_H;i++) app->thumb[i] = 0xff10141bu;   /* letterbox */
    if (!sw || !sh) return;
    double s = (double)THUMB_W/sw; double sv = (double)THUMB_H/sh; if (sv < s) s = sv;
    int dw = (int)(sw*s), dh = (int)(sh*s); if (dw<1) dw=1; if (dh<1) dh=1;
    if (dw>THUMB_W) dw=THUMB_W; if (dh>THUMB_H) dh=THUMB_H;
    int ox = (THUMB_W-dw)/2, oy = (THUMB_H-dh)/2;
    for (int j=0;j<dh;j++){ uint32_t syy = (uint32_t)(j/s); if (syy>=sh) syy=sh-1;
        for (int i=0;i<dw;i++){ uint32_t sxx = (uint32_t)(i/s); if (sxx>=sw) sxx=sw-1;
            uint32_t p = fb[(size_t)syy*sw+sxx];
            app->thumb[(oy+j)*THUMB_W+(ox+i)] = 0xff000000u | (p & 0x00ffffffu); } }
    app->have_thumb = 1;
}

static void set_status(struct app *app, int state, const char *msg){
    app->status_state = state;
    strncpy(app->status, msg, sizeof(app->status)-1); app->status[sizeof(app->status)-1]=0;
    log_line(msg);
}

static void do_capture(struct app *app){
    int fd = open("/dev/fb0", O_RDONLY);
    if (fd < 0){ char m[160]; snprintf(m,sizeof m,"Capture failed: cannot open /dev/fb0 (%s)", strerror(errno)); set_status(app,2,m); return; }
    struct fb_var_screeninfo var; memset(&var, 0, sizeof var);
    if (ioctl(fd, FBIOGET_VSCREENINFO, &var) < 0){ char m[160]; snprintf(m,sizeof m,"Capture failed: FBIOGET_VSCREENINFO (%s)", strerror(errno)); close(fd); set_status(app,2,m); return; }
    uint32_t xres = var.xres, yres = var.yres, bpp = var.bits_per_pixel;
    if (xres == 0 || yres == 0){ close(fd); set_status(app,2,"Capture failed: framebuffer reports 0x0"); return; }
    if (bpp != 32){ char m[128]; snprintf(m,sizeof m,"Capture failed: need 32bpp, got %ubpp", bpp); close(fd); set_status(app,2,m); return; }

    size_t nbytes = (size_t)xres * (size_t)yres * (size_t)(bpp/8);
    uint8_t *px = calloc(1, nbytes ? nbytes : 1);
    if (!px){ close(fd); set_status(app,2,"Capture failed: out of memory"); return; }
    size_t got = 0;
    while (got < nbytes){ ssize_t r = read(fd, px+got, nbytes-got);
        if (r < 0){ if (errno==EINTR) continue; break; }
        if (r == 0) break; got += (size_t)r; }
    close(fd);
    if (got != nbytes){ char m[160]; snprintf(m,sizeof m,"Capture failed: short read %zu/%zu bytes", got, nbytes); free(px); set_status(app,2,m); return; }

    /* libpng simplified write API: BGRA matches the framebuffer's B,G,R,X byte order; row_stride 0 lets
     * libpng default it to width*4.  png_image_write_to_file returns non-zero on success. */
    png_image image; memset(&image, 0, sizeof image);
    image.version = PNG_IMAGE_VERSION;
    image.width  = xres;
    image.height = yres;
    image.format = PNG_FORMAT_BGRA;
    if (!png_image_write_to_file(&image, app->savepath, 0 /*convert_to_8bit*/, px, 0 /*row_stride*/, NULL /*colormap*/)){
        char m[200]; snprintf(m,sizeof m,"Capture failed: PNG write (%s)", image.message[0]?image.message:"error");
        png_image_free(&image); free(px); set_status(app,2,m); return;
    }
    png_image_free(&image);

    make_thumb(app, (const uint32_t*)px, xres, yres);
    free(px);
    char m[200]; snprintf(m,sizeof m,"Saved: %s (%ux%u)", app->savepath, xres, yres); set_status(app,1,m);
}

/* --- rendering --- */
static void draw_thumb_block(struct app *app, int bx, int by){
    for (int j=0;j<THUMB_H;j++){ int y=by+j; if (y<0||y>=app->height) continue;
        for (int i=0;i<THUMB_W;i++){ int x=bx+i; if (x<0||x>=app->width) continue;
            app->pixels[y*app->width+x] = app->thumb[j*THUMB_W+i]; } }
}
static void draw(struct app *app){
    const uint32_t BG=0xff1b1f27u, TITLE=0xff11141bu, TXT=0xfff2f5fau, DIM=0xff8b94a3u, ACC=0xff4da3ffu,
                   BTN=0xff2d3444u, BTNH=0xff3a4a66u, BORDER=0xff3a4150u,
                   OK=0xff4ad07au, ERR=0xffff6b6bu, CLOSEH=0xffb3384au;
    fill_rect(app, 0, 0, app->width, app->height, BG);

    /* --- our own titlebar chrome (no server-side decorations) --- */
    fill_rect(app, 0, 0, app->width, TITLE_H, TITLE);
    draw_text(app, "Screenshot", 14, 8, app->width-60, 16, TXT);
    int cx,cy,cw,ch; close_box_rect(&cx,&cy,&cw,&ch);
    if (app->hover_close) fill_rect(app, cx, cy, cw, ch, CLOSEH);
    /* an X glyph, centered in the close box */
    { int xw = text_width(app, "x", 15); draw_text(app, "x", cx + (cw-xw)/2, cy + 6, cw, 15, app->hover_close?TXT:DIM); }
    fill_rect(app, 0, TITLE_H, app->width, 1, BORDER);

    /* instruction */
    draw_text(app, "Capture the whole screen to a PNG file.", 16, TITLE_H+8, app->width-32, 13, DIM);

    /* big capture button */
    int bx,by,bw,bh; capture_button_rect(&bx,&by,&bw,&bh);
    fill_rect(app, bx, by, bw, bh, app->hover_capture?BTNH:BTN);
    draw_frame(app, bx, by, bw, bh, app->hover_capture?ACC:BORDER);
    { const char *lbl = "Capture Whole Screen"; int lw = text_width(app, lbl, 17);
      draw_text(app, lbl, bx + (bw-lw)/2, by + (bh-17)/2, bw, 17, TXT); }

    /* save path */
    draw_text(app, "Save to:", 16, 120, 80, 12, DIM);
    draw_text(app, app->savepath, 74, 120, app->width-90, 12, ACC);

    /* status line (color-coded) */
    uint32_t sc = app->status_state==1 ? OK : app->status_state==2 ? ERR : DIM;
    draw_text(app, app->status, 16, 144, app->width-32, 12, sc);

    /* preview thumbnail (after a successful capture), bottom-right with a frame */
    if (app->have_thumb){
        int tx = app->width - THUMB_W - 16, ty = 130;
        draw_thumb_block(app, tx, ty);
        draw_frame(app, tx-1, ty-1, THUMB_W+2, THUMB_H+2, BORDER);
    }
}

/* --- double-buffered wl_shm (one memfd, two slices) --- */
static void redraw_commit(struct app *app);   /* fwd */
static void buffer_release(void *d, struct wl_buffer *wl){ struct app *a = d;
    for (int i=0;i<2;i++) if (a->bufs[i].wl == wl) a->bufs[i].busy = 0;
    if (a->dirty){ a->dirty = 0; redraw_commit(a); }   /* a deferred redraw can now proceed */
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

/* Release the current shm pool mapping and its two wl_buffers.  Safe to call with nothing allocated
 * (startup) and safe while a buffer is still "busy": destroying an in-use wl_shm buffer is allowed --
 * the compositor keeps its own mapping of the shared fd alive, so our munmap does not pull the pixels
 * out from under it. */
static void destroy_buffers(struct app *app){
    for (int i=0;i<2;i++){
        if (app->bufs[i].wl){ wl_buffer_destroy(app->bufs[i].wl); app->bufs[i].wl = NULL; }
        app->bufs[i].px = NULL;
        app->bufs[i].busy = 0;
    }
    if (app->map_base){ munmap(app->map_base, app->map_size); app->map_base = NULL; app->map_size = 0; }
    app->dirty = 0;
}

static int create_buffers(struct app *app){
    destroy_buffers(app);              /* also reused as the resize path: drop the previous pool first */
    int fd = create_memfd("epin-screenshot"); if (fd < 0) return -1;
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
/* Draw into a FREE buffer and commit it; if both are in use, mark dirty and redraw on the next release
 * (never modify a buffer the compositor may still be reading -> that vanished the window on real HW). */
static void redraw_commit(struct app *app){
    if (!app->configured) return;
    if (!app->bufs[0].wl || !app->bufs[1].wl) return;   /* buffers gone (a failed resize) */
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
static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; if (a->hover_capture||a->hover_close){ a->hover_capture=a->hover_close=0; redraw_commit(a);} }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y);
    int bx,by,bw,bh; capture_button_rect(&bx,&by,&bw,&bh);
    int cx,cy,cw,ch; close_box_rect(&cx,&cy,&cw,&ch);
    int hc = point_in(a->pointer_x,a->pointer_y,bx,by,bw,bh);
    int hx = point_in(a->pointer_x,a->pointer_y,cx,cy,cw,ch);
    if (hc!=a->hover_capture || hx!=a->hover_close){ a->hover_capture=hc; a->hover_close=hx; redraw_commit(a); } }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/ || state != 1) return;
    int cx,cy,cw,ch; close_box_rect(&cx,&cy,&cw,&ch);
    if (point_in(a->pointer_x,a->pointer_y,cx,cy,cw,ch)){ a->running=0; return; }
    int bx,by,bw,bh; capture_button_rect(&bx,&by,&bw,&bh);
    if (point_in(a->pointer_x,a->pointer_y,bx,by,bw,bh)){ do_capture(a); redraw_commit(a); } }
static void pointer_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v){ (void)d;(void)p;(void)t;(void)ax;(void)v; }
/* wl_pointer >= v5 also emits frame/axis_source/axis_stop/axis_discrete -- these listener slots MUST be
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
    if (key==1){ a->running=0; return; }                       /* Esc -> exit */
    if (key==28 || key==57){ do_capture(a); redraw_commit(a); } /* Enter or Space -> capture */
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
    if (w > 0) a->pending_w = w;      /* the tiler dictates our size here; 0 = "you choose" */
    if (h > 0) a->pending_h = h; }
static void toplevel_close(void *d, struct xdg_toplevel *t){ (void)t; struct app*a=d; a->running=0; }
static void toplevel_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h){ (void)d;(void)t;(void)w;(void)h; }
static void toplevel_wmcap(void *d, struct xdg_toplevel *t, struct wl_array *c){ (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure=toplevel_configure,.close=toplevel_close,.configure_bounds=toplevel_bounds,.wm_capabilities=toplevel_wmcap };

static void xdg_surface_configure(void *d, struct xdg_surface *s, uint32_t serial){ struct app*a=d;
    xdg_surface_ack_configure(s, serial);
    /* Honor a compositor-driven resize: rebuild the shm buffers at the new size, then repaint.
     * draw() lays every element out from app->width/height on each frame, so the content reflows
     * for free -- no fixed content array to rescale. */
    if (a->pending_w > 0 && a->pending_h > 0 &&
        (a->pending_w != a->width || a->pending_h != a->height)){
        a->width = a->pending_w; a->height = a->pending_h;
        a->stride = a->width * 4; a->buffer_size = (size_t)a->stride * a->height;
        if (create_buffers(a) < 0) log_line("SCREENSHOT: resize buffer alloc failed");
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
    app.running = 1;
    app.width = WIN_W; app.height = WIN_H; app.stride = WIN_W*4; app.buffer_size = (size_t)app.stride*WIN_H;
    strncpy(app.savepath, "/run/screenshot.png", sizeof(app.savepath)-1);
    set_status(&app, 0, "Ready.");
    signal(SIGCHLD, SIG_IGN);
    init_freetype(&app);

    log_line("SCREENSHOT: starting screenshot tool");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("SCREENSHOT: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base){ log_line("SCREENSHOT: missing globals"); return 1; }
    if (create_buffers(&app) < 0){ log_line("SCREENSHOT: buffer failed"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Screenshot");
    xdg_toplevel_set_app_id(app.toplevel, "epin-screenshot");
    wl_surface_commit(app.surface);
    wl_display_flush(app.display);

    int wlfd = wl_display_get_fd(app.display);
    while (app.running){
        while (wl_display_prepare_read(app.display) != 0) wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);
        struct pollfd pfd = { .fd=wlfd, .events=POLLIN, .revents=0 };
        int pr = poll(&pfd, 1, -1);
        if (pr > 0 && (pfd.revents & POLLIN)){ wl_display_read_events(app.display); wl_display_dispatch_pending(app.display); }
        else { wl_display_cancel_read(app.display); if (pr < 0){ if (errno==EINTR) continue; break; } }
    }
    return 0;
}
