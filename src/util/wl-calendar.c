/*
 * wl-calendar.c -- a clock/calendar popover (Wayland + FreeType client).
 *
 * A fixed-size popover: a big HH:MM clock, the long date line, and a month calendar grid computed
 * from localtime()/mktime().  Today's cell is highlighted with a filled accent square.  "<" and ">"
 * hit-boxes page the displayed month.  The clock ticks once/second via the poll() timeout.
 *
 * All Wayland scaffolding (registry / seat / xdg / double-buffered wl_shm / FreeType text / evdev)
 * is copied verbatim from the proven wl-wifi-menu client; only the drawing + hit-testing differ.
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

enum { WIN_W = 300, WIN_H = 360, TITLE_H = 26 };

/* calendar layout */
enum {
    CLOCK_Y   = 34,   CLOCK_PX = 42,
    DATE_Y    = 88,   DATE_PX  = 13,
    NAV_Y     = 110,  NAV_PX   = 15,
    WDAY_Y    = 140,  WDAY_PX  = 12,
    GRID_X0   = 6,    GRID_Y0  = 160,
    CELL_W    = 41,   CELL_H   = 30,
    ARROW_W   = 26,   ARROW_H  = 24,
    CLOSE_W   = 26,
};

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
    uint32_t *pixels;              // the buffer draw_calendar()/draw_text() currently target
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    /* ROADMAP 3.2: the shm mapping, kept so a resize can release it.  create_buffers() used to
     * map and forget, which was fine while the window could never change size. */
    unsigned char *map_base;
    size_t map_total;
    /* Size the compositor last asked for, applied on the next xdg_surface.configure. */
    int pending_width, pending_height;
    int font_ready, running;
    double pointer_x, pointer_y;

    int disp_year;                 // displayed month/year (paged by < >)
    int disp_month;                // 0-11
    int hover_prev, hover_next, hover_close;
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
/* pixel width of `text` at size `px` (for centering headings/day numbers). */
static int measure_text(struct app *app, const char *text, int px){
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
    int w = measure_text(app, text, px);
    draw_text(app, text, cx - w/2, y, w + 4, px, color);
}
static void fill_rect(struct app *app, int x, int y, int w, int h, uint32_t c){
    for (int j=y;j<y+h;j++){ if (j<0||j>=app->height) continue;
        for (int i=x;i<x+w;i++){ if (i<0||i>=app->width) continue; app->pixels[j*app->width+i]=c; } }
}

/* --- calendar math --- */
static const char *MONTHS[12] = { "January","February","March","April","May","June",
                                  "July","August","September","October","November","December" };
static const char *WDAYS[7]   = { "Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday" };
static const char  WINIT[7]   = { 'S','M','T','W','T','F','S' };

static int days_in_month(int year, int mon /*0-11*/){
    static const int d[12] = { 31,28,31,30,31,30,31,31,30,31,30,31 };
    if (mon == 1){ int leap = (year%4==0 && (year%100!=0 || year%400==0)); return leap ? 29 : 28; }
    return d[mon];
}
/* weekday (0=Sun..6=Sat) of day 1 of the given month. */
static int first_wday(int year, int mon){
    struct tm t; memset(&t, 0, sizeof t);
    t.tm_year = year - 1900; t.tm_mon = mon; t.tm_mday = 1; t.tm_hour = 12; t.tm_isdst = -1;
    mktime(&t);
    return t.tm_wday;
}

/* --- rendering --- */
static void draw_calendar(struct app *app){
    const uint32_t BG=0xff1b1f27u, TITLE=0xff11141bu, TXT=0xfff2f5fau, DIM=0xff8b94a3u,
                   ACC=0xff4da3ffu, CLOSE=0xffb03a3au, CLOSEH=0xffe05555u,
                   ARR=0xff232834u, ARRH=0xff2d3444u, TODAYTX=0xff11141bu;

    /* ROADMAP 3.2: derive the grid from the ACTUAL window size rather than the compiled default.
     * CELL_W/CELL_H were sized for exactly WIN_W (7*41 + 2*6 = 299 ~ 300), so at any other width
     * the grid either stopped short of the edge or ran off it.  The header above the grid keeps
     * its fixed heights -- the clock and date are type, not a layout that stretches -- while the
     * cells absorb whatever space is left, which is what makes a tiled size usable.
     * A floor of 1 keeps a degenerate configure from producing a zero or negative step. */
    int cell_w = (app->width - 2*GRID_X0) / 7;   if (cell_w < 1) cell_w = 1;
    int cell_h = (app->height - GRID_Y0 - GRID_X0) / 6;  if (cell_h < 1) cell_h = 1;

    fill_rect(app, 0, 0, app->width, app->height, BG);

    /* --- CSD titlebar --- */
    fill_rect(app, 0, 0, app->width, TITLE_H, TITLE);
    draw_text(app, "Calendar", 12, 5, 200, 15, TXT);
    /* close box top-right */
    fill_rect(app, app->width-CLOSE_W, 0, CLOSE_W, TITLE_H, app->hover_close?CLOSEH:CLOSE);
    draw_text(app, "x", app->width-CLOSE_W+9, 4, 20, 15, 0xffffffffu);

    /* current time (from the real clock) */
    time_t now = time(NULL);
    struct tm lt; localtime_r(&now, &lt);
    char hm[8];  snprintf(hm, sizeof hm, "%02d:%02d", lt.tm_hour, lt.tm_min);
    draw_text_centered(app, hm, app->width/2, CLOCK_Y, CLOCK_PX, TXT);

    char dateline[64];
    snprintf(dateline, sizeof dateline, "%s, %s %d, %d",
             WDAYS[lt.tm_wday], MONTHS[lt.tm_mon], lt.tm_mday, lt.tm_year + 1900);
    draw_text_centered(app, dateline, app->width/2, DATE_Y, DATE_PX, DIM);

    /* --- month nav header:  <   Month Year   >  --- */
    fill_rect(app, GRID_X0, NAV_Y, ARROW_W, ARROW_H, app->hover_prev?ARRH:ARR);
    draw_text(app, "<", GRID_X0+9, NAV_Y+3, 20, 16, TXT);
    fill_rect(app, app->width-GRID_X0-ARROW_W, NAV_Y, ARROW_W, ARROW_H, app->hover_next?ARRH:ARR);
    draw_text(app, ">", app->width-GRID_X0-ARROW_W+9, NAV_Y+3, 20, 16, TXT);
    char mh[32]; snprintf(mh, sizeof mh, "%s %d", MONTHS[app->disp_month], app->disp_year);
    draw_text_centered(app, mh, app->width/2, NAV_Y+3, NAV_PX, TXT);

    /* --- weekday initials --- */
    for (int c = 0; c < 7; c++){
        char s[2] = { WINIT[c], 0 };
        int cx = GRID_X0 + c*cell_w + cell_w/2;
        draw_text_centered(app, s, cx, WDAY_Y, WDAY_PX, (c==0||c==6)?ACC:DIM);
    }

    /* --- day grid --- */
    int fw = first_wday(app->disp_year, app->disp_month);
    int ndays = days_in_month(app->disp_year, app->disp_month);
    int is_this_month = (app->disp_year == lt.tm_year + 1900 && app->disp_month == lt.tm_mon);

    for (int day = 1; day <= ndays; day++){
        int idx = fw + (day - 1);
        int row = idx / 7, col = idx % 7;
        int cx0 = GRID_X0 + col*cell_w;
        int cy0 = GRID_Y0 + row*cell_h;
        int cxc = cx0 + cell_w/2;
        uint32_t col_tx = (col==0||col==6) ? ACC : TXT;

        if (is_this_month && day == lt.tm_mday){
            /* highlight TODAY with a filled accent square behind the number */
            int inset = 3;
            fill_rect(app, cx0+inset, cy0+inset, cell_w-2*inset, cell_h-2*inset, ACC);
            col_tx = TODAYTX;
        }
        char ds[4]; snprintf(ds, sizeof ds, "%d", day);
        draw_text_centered(app, ds, cxc, cy0 + (cell_h-WDAY_PX)/2 - 1, WDAY_PX+1, col_tx);
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
    int fd = create_memfd("epin-calendar"); if (fd < 0) return -1;
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
    app->map_base  = base;
    app->map_total = total;
    wl_shm_pool_destroy(pool); close(fd);
    return 0;
}

/* ROADMAP 3.2: rebuild both buffers at a new size.
 *
 * Without this the window told Hyprland min == max via xdg_toplevel_set_max_size(), which makes
 * Hyprland float it -- so windows overlapped instead of tiling, and the layout was never at
 * fault.  Dropping set_max_size alone is not enough: a tiled window is then handed a size it
 * cannot render at, which is how wl-domain-manager collapsed to a 562x181 sliver.  The window has
 * to be able to reflow first, which is what this plus the metrics in draw_calendar() provide.
 *
 * Destroying a buffer the compositor may still hold is fine -- the release arrives against a dead
 * proxy and is ignored.  What is NOT fine is drawing into a busy buffer, which is why both busy
 * flags are cleared here: the new buffers are genuinely untouched. */
static int resize_buffers(struct app *app, int w, int h)
{
    if (w <= 0 || h <= 0) return 0;
    if (w == app->width && h == app->height && app->bufs[0].wl) return 0;

    for (int i = 0; i < 2; i++) {
        if (app->bufs[i].wl) { wl_buffer_destroy(app->bufs[i].wl); app->bufs[i].wl = NULL; }
        app->bufs[i].px = NULL;
        app->bufs[i].busy = 0;
    }
    if (app->map_base && app->map_base != MAP_FAILED) munmap(app->map_base, app->map_total);
    app->map_base = NULL; app->map_total = 0;
    app->pixels = NULL;

    app->width  = w;
    app->height = h;
    app->stride = w * 4;
    app->buffer_size = (size_t)app->stride * (size_t)h;
    return create_buffers(app);
}
/* Draw into a FREE buffer and commit it; if both are in use, mark dirty and redraw on the next release
 * (never modify a buffer the compositor may still be reading -> that vanished the window on real HW). */
static void redraw_commit(struct app *app){
    if (!app->configured) return;
    int i = app->bufs[0].busy ? 1 : 0;
    if (app->bufs[i].busy){ app->dirty = 1; return; }
    app->pixels = app->bufs[i].px;
    draw_calendar(app);
    app->bufs[i].busy = 1;
    wl_surface_attach(app->surface, app->bufs[i].wl, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
}

/* --- month paging --- */
static void page_month(struct app *app, int delta){
    app->disp_month += delta;
    while (app->disp_month < 0){ app->disp_month += 12; app->disp_year--; }
    while (app->disp_month > 11){ app->disp_month -= 12; app->disp_year++; }
    redraw_commit(app);
}

/* --- input --- */
static int in_box(struct app *a, int x, int y, int w, int h){
    return a->pointer_x >= x && a->pointer_x < x+w && a->pointer_y >= y && a->pointer_y < y+h;
}
static void update_hover(struct app *a){
    int hp = in_box(a, GRID_X0, NAV_Y, ARROW_W, ARROW_H);
    int hn = in_box(a, a->width-GRID_X0-ARROW_W, NAV_Y, ARROW_W, ARROW_H);
    int hc = in_box(a, a->width-CLOSE_W, 0, CLOSE_W, TITLE_H);
    if (hp!=a->hover_prev || hn!=a->hover_next || hc!=a->hover_close){
        a->hover_prev=hp; a->hover_next=hn; a->hover_close=hc; redraw_commit(a);
    }
}

static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); update_hover(a); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; a->hover_prev=a->hover_next=a->hover_close=0; redraw_commit(a); }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); update_hover(a); }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/ || state != 1) return;
    if (in_box(a, a->width-CLOSE_W, 0, CLOSE_W, TITLE_H)) exit(0);
    if (in_box(a, GRID_X0, NAV_Y, ARROW_W, ARROW_H)){ page_month(a, -1); return; }
    if (in_box(a, a->width-GRID_X0-ARROW_W, NAV_Y, ARROW_W, ARROW_H)){ page_month(a, +1); return; }
}
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
    if (key==1){ a->running=0; return; }         /* Esc = quit */
    if (key==105){ page_month(a, -1); return; }   /* Left arrow  = prev month */
    if (key==106){ page_month(a, +1); return; }   /* Right arrow = next month */
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
/* ROADMAP 3.2: remember the size Hyprland asks for.  This used to discard w and h entirely,
 * which was consistent with the window declaring itself unresizable -- and is exactly why a
 * tiled size could never be honoured. */
static void toplevel_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s){
    struct app *a = d; (void)t; (void)s;
    if (w > 0) a->pending_width  = w;
    if (h > 0) a->pending_height = h;
}
static void toplevel_close(void *d, struct xdg_toplevel *t){ (void)t; struct app*a=d; a->running=0; }
static void toplevel_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h){ (void)d;(void)t;(void)w;(void)h; }
static void toplevel_wmcap(void *d, struct xdg_toplevel *t, struct wl_array *c){ (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure=toplevel_configure,.close=toplevel_close,.configure_bounds=toplevel_bounds,.wm_capabilities=toplevel_wmcap };

static void xdg_surface_configure(void *d, struct xdg_surface *s, uint32_t serial){ struct app*a=d;
    xdg_surface_ack_configure(s, serial);
    /* ROADMAP 3.2: adopt the size the compositor asked for.  The first configure is legitimately
     * 0x0 -- "pick your own size" -- and the real tile geometry only arrives after the window
     * maps, so a post-map configure must be honoured rather than ignored.  wl-installer carries
     * the same note, having been fixed for exactly this. */
    int want_w = a->pending_width  > 0 ? a->pending_width  : a->width;
    int want_h = a->pending_height > 0 ? a->pending_height : a->height;
    if (want_w != a->width || want_h != a->height){
        if (resize_buffers(a, want_w, want_h) < 0){ log_line("CALENDAR: resize failed"); return; }
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
    signal(SIGCHLD, SIG_IGN);
    init_freetype(&app);

    /* start on the current month */
    time_t now = time(NULL); struct tm lt; localtime_r(&now, &lt);
    app.disp_year = lt.tm_year + 1900; app.disp_month = lt.tm_mon;

    log_line("CALENDAR: starting clock/calendar popover");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("CALENDAR: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base){ log_line("CALENDAR: missing globals"); return 1; }
    if (create_buffers(&app) < 0){ log_line("CALENDAR: buffer failed"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Calendar");
    xdg_toplevel_set_app_id(app.toplevel, "epin-calendar");
    /* FLOAT: min==max fixes the size so the tiler treats us as a floating popover. */
    /* ROADMAP 3.2: a minimum, but NO maximum.  Hyprland floats any toplevel whose min equals its
     * max, so declaring both was the window opting out of tiling -- the layout was never at
     * fault.  The minimum stays: below roughly this size the grid stops being legible, and a
     * floor is a real constraint rather than a refusal to resize. */
    xdg_toplevel_set_min_size(app.toplevel, WIN_W, WIN_H);
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
               if (pr == 0) redraw_commit(&app);   /* tick: redraw so the clock advances */
        }
    }
    return 0;
}
