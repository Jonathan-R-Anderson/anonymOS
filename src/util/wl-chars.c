/*
 * wl-chars.c -- a Unicode CHARACTER PICKER (Wayland + FreeType client).
 *
 * A scrollable grid of Unicode characters rendered with FreeType.  Click a cell to "copy" that
 * character: its UTF-8 bytes are written to /run/clipboard and printed to stdout, and the last-picked
 * glyph is shown large in a status strip.  Scroll with the mouse wheel or the Up/Down/PageUp/PageDown
 * keys.  CSD titlebar "Characters" + a close box (top-right) that exits.
 *
 * The Wayland scaffolding (registry / seat / xdg / persistent double-buffered wl_shm / FreeType text /
 * evdev keymap / poll loop) is the proven wl-wifi-menu pattern, reused verbatim.  draw_text() here is
 * extended to decode UTF-8 so it can render arbitrary codepoints (the wifi menu only drew ASCII).
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

enum {
    WIN_W = 500, WIN_H = 440,
    TITLE_H = 28,          /* CSD titlebar strip                */
    STATUS_H = 64,         /* bottom "last picked" strip        */
    CELL = 36,             /* grid cell size (px)               */
    MARGIN = 8,            /* left/right grid inset             */
    MAX_CP = 1024
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
    int configured, dirty;
    uint32_t *pixels;              // the buffer draw_grid()/draw_text() currently target
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    int font_ready, running;
    double pointer_x, pointer_y;

    uint32_t cp[MAX_CP];           // the codepoints in the grid (glyph-filtered)
    int n_cp;
    int scroll_row;                // top row of the grid currently shown
    int hover;                     // hovered cell index (-1 none)
    uint32_t last_cp;              // last picked codepoint
    int has_pick;
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

/* Decode one UTF-8 sequence at p; store the codepoint and return the pointer past it. */
static const unsigned char *utf8_next(const unsigned char *p, uint32_t *cp){
    unsigned char c = p[0];
    if (c < 0x80){ *cp = c; return p+1; }
    if ((c & 0xE0) == 0xC0 && (p[1]&0xC0)==0x80){ *cp = ((uint32_t)(c&0x1F)<<6)|(p[1]&0x3F); return p+2; }
    if ((c & 0xF0) == 0xE0 && (p[1]&0xC0)==0x80 && (p[2]&0xC0)==0x80){
        *cp = ((uint32_t)(c&0x0F)<<12)|((uint32_t)(p[1]&0x3F)<<6)|(p[2]&0x3F); return p+3; }
    if ((c & 0xF8) == 0xF0 && (p[1]&0xC0)==0x80 && (p[2]&0xC0)==0x80 && (p[3]&0xC0)==0x80){
        *cp = ((uint32_t)(c&0x07)<<18)|((uint32_t)(p[1]&0x3F)<<12)|((uint32_t)(p[2]&0x3F)<<6)|(p[3]&0x3F); return p+4; }
    *cp = '?'; return p+1;   /* invalid byte */
}
/* Encode a codepoint to UTF-8 bytes in out[] (not NUL-terminated); returns byte count. */
static int utf8_encode(uint32_t cp, char out[4]){
    if (cp < 0x80){ out[0]=(char)cp; return 1; }
    if (cp < 0x800){ out[0]=(char)(0xC0|(cp>>6)); out[1]=(char)(0x80|(cp&0x3F)); return 2; }
    if (cp < 0x10000){ out[0]=(char)(0xE0|(cp>>12)); out[1]=(char)(0x80|((cp>>6)&0x3F)); out[2]=(char)(0x80|(cp&0x3F)); return 3; }
    out[0]=(char)(0xF0|(cp>>18)); out[1]=(char)(0x80|((cp>>12)&0x3F)); out[2]=(char)(0x80|((cp>>6)&0x3F)); out[3]=(char)(0x80|(cp&0x3F)); return 4;
}

/* draw_text: same rasterizer as wl-wifi-menu, but UTF-8 aware so any codepoint renders. */
static void draw_text(struct app *app, const char *text, int x, int y, int max_w, int px, uint32_t color){
    if (!app->font_ready || !text || max_w <= 0) return;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0) return;
    int baseline = px;
    if (app->face->size && app->face->size->metrics.ascender > 0) baseline = (int)(app->face->size->metrics.ascender >> 6);
    int pen_x = x, pen_y = y + baseline;
    const unsigned char *p = (const unsigned char*)text;
    while (*p){
        uint32_t cp; p = utf8_next(p, &cp);
        if (cp < 0x20) continue;
        if (FT_Load_Char(app->face, cp, FT_LOAD_RENDER|FT_LOAD_TARGET_NORMAL) != 0) continue;
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
/* Width of a single-glyph UTF-8 string at size px (for centering in a cell). */
static int glyph_width(struct app *app, uint32_t cp, int px){
    if (!app->font_ready) return px/2;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0) return px/2;
    if (FT_Load_Char(app->face, cp, FT_LOAD_RENDER|FT_LOAD_TARGET_NORMAL) != 0) return px/2;
    return (int)(app->face->glyph->advance.x >> 6);
}
static void fill_rect(struct app *app, int x, int y, int w, int h, uint32_t c){
    for (int j=y;j<y+h;j++){ if (j<0||j>=app->height) continue;
        for (int i=x;i<x+w;i++){ if (i<0||i>=app->width) continue; app->pixels[j*app->width+i]=c; } }
}

/* --- grid geometry --- */
static int grid_cols(struct app *app){ int c = (app->width - 2*MARGIN)/CELL; return c<1?1:c; }
static int grid_visible_rows(struct app *app){ int h = app->height - TITLE_H - STATUS_H; int r = h/CELL; return r<0?0:r; }
static int grid_total_rows(struct app *app){ int cols = grid_cols(app); return (app->n_cp + cols - 1)/cols; }
static int max_scroll(struct app *app){ int m = grid_total_rows(app) - grid_visible_rows(app); return m<0?0:m; }

/* Which codepoint index is under (px,py)? -1 if none. */
static int cell_at(struct app *app, double dx, double dy){
    if (dy < TITLE_H || dy >= app->height - STATUS_H) return -1;
    if (dx < MARGIN) return -1;
    int cols = grid_cols(app);
    int c = ((int)dx - MARGIN)/CELL; if (c < 0 || c >= cols) return -1;
    int vr = ((int)dy - TITLE_H)/CELL; if (vr < 0 || vr >= grid_visible_rows(app)) return -1;
    int idx = (app->scroll_row + vr)*cols + c;
    if (idx < 0 || idx >= app->n_cp) return -1;
    return idx;
}

/* --- codepoint table (glyph-filtered ranges the bundled face can actually draw) --- */
static void build_codepoints(struct app *app){
    static const uint32_t R[][2] = {
        {0x0021, 0x007E},   /* ASCII punctuation / symbols        */
        {0x00A1, 0x00FF},   /* Latin-1 supplement letters+symbols */
        {0x2190, 0x21FF},   /* arrows                             */
        {0x2500, 0x257F},   /* box drawing                        */
    };
    app->n_cp = 0;
    for (unsigned r = 0; r < sizeof(R)/sizeof(R[0]); r++){
        for (uint32_t cp = R[r][0]; cp <= R[r][1]; cp++){
            if (app->n_cp >= MAX_CP) return;
            if (app->font_ready && FT_Get_Char_Index(app->face, cp) == 0) continue; /* skip .notdef */
            app->cp[app->n_cp++] = cp;
        }
    }
    /* Font not loaded (dev host has no font): still show the full ranges so the grid is populated. */
    if (!app->font_ready){
        app->n_cp = 0;
        for (unsigned r = 0; r < sizeof(R)/sizeof(R[0]); r++)
            for (uint32_t cp = R[r][0]; cp <= R[r][1] && app->n_cp < MAX_CP; cp++)
                app->cp[app->n_cp++] = cp;
    }
}

/* --- rendering --- */
static void draw_grid(struct app *app){
    const uint32_t BG=0xff1b1f27u, TITLE=0xff11141bu, CLOSE=0xffc0392bu, CLOSEH=0xffe74c3cu,
                   TXT=0xfff2f5fau, DIM=0xff8b94a3u, ACC=0xff4da3ffu,
                   CELLBG=0xff232834u, CELLHOV=0xff3a4d66u, STATUSBG=0xff0d0f14u;
    fill_rect(app, 0, 0, app->width, app->height, BG);

    /* titlebar */
    fill_rect(app, 0, 0, app->width, TITLE_H, TITLE);
    draw_text(app, "Characters", 12, 6, app->width-80, 16, TXT);
    int cbx = app->width - 26, cby = 4, cbs = 20;
    int close_hover = (app->pointer_x >= cbx && app->pointer_x < cbx+cbs && app->pointer_y >= cby && app->pointer_y < cby+cbs);
    fill_rect(app, cbx, cby, cbs, cbs, close_hover?CLOSEH:CLOSE);
    draw_text(app, "x", cbx+6, cby+2, cbs, 15, TXT);

    /* grid */
    int cols = grid_cols(app), vrows = grid_visible_rows(app);
    for (int vr = 0; vr < vrows; vr++){
        int row = app->scroll_row + vr;
        for (int c = 0; c < cols; c++){
            int idx = row*cols + c;
            if (idx >= app->n_cp) break;
            int cx = MARGIN + c*CELL, cy = TITLE_H + vr*CELL;
            fill_rect(app, cx, cy, CELL-2, CELL-2, (idx==app->hover)?CELLHOV:CELLBG);
            char u[8]; int n = utf8_encode(app->cp[idx], u); u[n]=0;
            int gw = glyph_width(app, app->cp[idx], 22);
            int tx = cx + (CELL-2 - gw)/2; if (tx < cx+1) tx = cx+1;
            draw_text(app, u, tx, cy+6, CELL, 22, TXT);
        }
    }

    /* scroll indicator (right edge of grid area) */
    int ms = max_scroll(app);
    if (ms > 0){
        int gx0 = TITLE_H, gh = app->height - TITLE_H - STATUS_H;
        int bar_x = app->width - 4;
        int track_h = gh;
        int knob_h = track_h * grid_visible_rows(app) / grid_total_rows(app); if (knob_h < 12) knob_h = 12;
        int knob_y = gx0 + (track_h - knob_h) * app->scroll_row / ms;
        fill_rect(app, bar_x, gx0, 3, track_h, 0xff1b1f27u);
        fill_rect(app, bar_x, knob_y, 3, knob_h, DIM);
    }

    /* status strip */
    int sy = app->height - STATUS_H;
    fill_rect(app, 0, sy, app->width, STATUS_H, STATUSBG);
    fill_rect(app, 0, sy, app->width, 2, ACC);
    if (app->has_pick){
        /* big glyph swatch on the left */
        fill_rect(app, 12, sy+10, 44, 44, CELLBG);
        char u[8]; int n = utf8_encode(app->last_cp, u); u[n]=0;
        int gw = glyph_width(app, app->last_cp, 34);
        draw_text(app, u, 12 + (44-gw)/2, sy+14, 44, 34, TXT);
        char info[96]; snprintf(info, sizeof info, "U+%04X", app->last_cp);
        draw_text(app, info, 66, sy+14, app->width-80, 16, TXT);
        draw_text(app, "copied to /run/clipboard", 66, sy+38, app->width-80, 12, DIM);
    } else {
        draw_text(app, "Click a character to copy it.", 12, sy+16, app->width-24, 14, DIM);
        draw_text(app, "Wheel / Up / Down / PgUp / PgDn to scroll.", 12, sy+36, app->width-24, 12, DIM);
    }
}

/* --- double-buffered wl_shm (one memfd, two slices) --- */
static void redraw_commit(struct app *app);   /* fwd */
static void buffer_release(void *d, struct wl_buffer *wl){ struct app *a = d;
    for (int i=0;i<2;i++) if (a->bufs[i].wl == wl) a->bufs[i].busy = 0;
    if (a->dirty){ a->dirty = 0; redraw_commit(a); }
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static int create_buffers(struct app *app){
    int fd = create_memfd("epin-chars"); if (fd < 0) return -1;
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
static void redraw_commit(struct app *app){
    if (!app->configured) return;
    int i = app->bufs[0].busy ? 1 : 0;
    if (app->bufs[i].busy){ app->dirty = 1; return; }
    app->pixels = app->bufs[i].px;
    draw_grid(app);
    app->bufs[i].busy = 1;
    wl_surface_attach(app->surface, app->bufs[i].wl, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
}

/* --- copy the picked character --- */
static void pick(struct app *app, int idx){
    if (idx < 0 || idx >= app->n_cp) return;
    uint32_t cp = app->cp[idx];
    char u[4]; int n = utf8_encode(cp, u);
    mkdir("/run", 0755);
    int fd = open("/run/clipboard", O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (fd >= 0){ (void)!write(fd, u, (size_t)n); close(fd); }
    char utz[5]; memcpy(utz, u, (size_t)n); utz[n]=0;
    (void)!write(1, utz, (size_t)n); (void)!write(1, "\n", 1);
    char m[64]; snprintf(m, sizeof m, "CHARS: picked U+%04X (%s)", cp, utz); log_line(m);
    app->last_cp = cp; app->has_pick = 1;
    redraw_commit(app);
}

static void scroll_by(struct app *app, int rows){
    int ns = app->scroll_row + rows;
    int ms = max_scroll(app);
    if (ns < 0) ns = 0; if (ns > ms) ns = ms;
    if (ns != app->scroll_row){ app->scroll_row = ns; redraw_commit(app); }
}

/* --- input --- */
static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; a->hover=-1; a->pointer_x=-1; a->pointer_y=-1; redraw_commit(a); }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y);
    int nh = cell_at(a, a->pointer_x, a->pointer_y);
    /* redraw on hover change OR when the pointer is over the close box (for its hover tint) */
    int cbx = a->width - 26; int over_close = (a->pointer_x >= cbx && a->pointer_y < TITLE_H);
    if (nh != a->hover){ a->hover = nh; redraw_commit(a); }
    else if (over_close || a->pointer_y < TITLE_H) redraw_commit(a); }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/ || state != 1) return;
    /* close box */
    int cbx = a->width - 26, cby = 4, cbs = 20;
    if (a->pointer_x >= cbx && a->pointer_x < cbx+cbs && a->pointer_y >= cby && a->pointer_y < cby+cbs){ exit(0); }
    int idx = cell_at(a, a->pointer_x, a->pointer_y);
    if (idx >= 0) pick(a, idx); }
static void pointer_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v){ (void)p;(void)t; struct app*a=d;
    if (ax != 0 /*WL_POINTER_AXIS_VERTICAL_SCROLL*/) return;
    double dv = wl_fixed_to_double(v);
    int rows = (int)(dv/10.0); if (rows == 0) rows = (dv>0)?1:(dv<0?-1:0);
    scroll_by(a, rows); }
/* wl_pointer >= v5 slots MUST all be non-NULL or libwayland calls a NULL fn-ptr on the first frame event. */
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
    if (state != 1) return;               /* press only */
    switch (key){
        case 103: scroll_by(a, -1); break;                 /* Up        */
        case 108: scroll_by(a, +1); break;                 /* Down      */
        case 104: scroll_by(a, -grid_visible_rows(a)); break;  /* PageUp   */
        case 109: scroll_by(a, +grid_visible_rows(a)); break;  /* PageDown */
        case 102: a->scroll_row = 0; redraw_commit(a); break;              /* Home */
        case 107: a->scroll_row = max_scroll(a); redraw_commit(a); break;  /* End  */
        case 1:   a->running = 0; break;                   /* Esc = quit */
        default: break;
    } }
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

int main(void){
    static struct app app; memset(&app, 0, sizeof app);
    app.running = 1; app.hover = -1; app.pointer_x = -1; app.pointer_y = -1;
    app.width = WIN_W; app.height = WIN_H; app.stride = WIN_W*4; app.buffer_size = (size_t)app.stride*WIN_H;
    signal(SIGPIPE, SIG_IGN);
    init_freetype(&app);
    build_codepoints(&app);

    log_line("CHARS: starting character picker");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("CHARS: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base){ log_line("CHARS: missing globals"); return 1; }
    if (create_buffers(&app) < 0){ log_line("CHARS: buffer failed"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Characters");
    xdg_toplevel_set_app_id(app.toplevel, "epin-chars");
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
