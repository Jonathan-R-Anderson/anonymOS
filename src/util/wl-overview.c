/*
 * wl-overview.c -- an Activities / app-grid OVERVIEW (like GNOME's app grid) for the EpinAnonymOS desktop.
 *
 * A dark backdrop, a search field across the top, and a grid of colored app tiles below.  Each tile is a
 * filled colored square with the app's first letter big in the centre and the app label under it.  Typing
 * live-filters the tiles by case-insensitive substring of the label; Backspace deletes, Esc exits.  Clicking
 * a visible tile -- or pressing Enter when exactly one tile matches -- fork/execve()s that program and the
 * overview exits.
 *
 * Wayland scaffolding (registry / seat / xdg / persistent double-buffered wl_shm / FreeType text / evdev
 * keymap / full v5 pointer listener) is copied VERBATIM from the proven wl-wifi-menu client.
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

extern char **environ;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum { WIN_W = 920, WIN_H = 620,
       TITLEBAR_H = 28, CLOSE_W = 28,
       SEARCH_Y = 46, SEARCH_H = 40, SEARCH_MARGIN = 220,
       GRID_COLS = 5, CELL_PITCH_X = 160, CELL_PITCH_Y = 150,
       ICON = 96, GRID_Y = 116,
       MAX_APPS = 32 };

/* app list: LABEL -> EXEC path (each tile gets a cycled accent colour) */
struct appentry { const char *label; const char *exec; };
static const struct appentry APPS[] = {
    { "Files",          "/wl-files" },
    /* /hos-wifiterm = wl-term with EPIN_SHELL=light (zsh -f -i), software (wl_shm) rendered — works on
     * the FW13 Pixman desktop.  /gl-term is GLES2/EGL and FAILS without a GPU; a full login-zsh wl-term
     * fork-storms.  (GL terminal is still on SUPER+Y for the virgl/GPU desktop.) */
    { "Terminal",       "/hos-wifiterm" },
    { "Settings",       "/wl-domain-manager" },
    { "Logs",           "/wl-logview" },
    { "Wi-Fi",          "/wl-wifi-menu" },
    { "Calculator",     "/wl-calc" },
    { "System Monitor", "/wl-sysmon" },
    { "Clocks",         "/wl-clocks" },
    { "Image Viewer",   "/wl-imgview" },
    { "Characters",     "/wl-chars" },
    { "Calendar",       "/wl-calendar" },
    { "Text Editor",    "/wl-editor" },
    { "Screenshot",     "/wl-screenshot" },
};
enum { N_APPS = (int)(sizeof(APPS)/sizeof(APPS[0])) };

/* distinct accent colours cycled across the tiles */
static const uint32_t PALETTE[] = {
    0xff4da3ffu, 0xffff6f61u, 0xff5ecb8au, 0xffb98cffu, 0xffffb347u,
    0xff45c8d8u, 0xffe86ab0u, 0xff8bd450u,
};
enum { N_PAL = (int)(sizeof(PALETTE)/sizeof(PALETTE[0])) };

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
    uint32_t *pixels;
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    int font_ready, running;
    double pointer_x, pointer_y;

    char search[64];
    int  searchlen;
    int  shift;
    int  hover;                    // hovered filtered position (-1 none)
    int  filt[MAX_APPS];           // app indices currently visible
    int  n_filt;
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
/* measure the pixel width a string would occupy at size px (for centring). */
static int text_width(struct app *app, const char *text, int px){
    if (!app->font_ready || !text) return 0;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0) return 0;
    int w = 0;
    for (const unsigned char *p = (const unsigned char*)text; *p; ++p){
        unsigned char ch = *p; if (ch < 0x20 || ch >= 0x7f) ch = '?';
        if (FT_Load_Char(app->face, ch, FT_LOAD_RENDER|FT_LOAD_TARGET_NORMAL) != 0) continue;
        w += (int)(app->face->glyph->advance.x >> 6);
    }
    return w;
}
static void draw_text_centered(struct app *app, const char *text, int cx, int y, int max_w, int px, uint32_t color){
    int w = text_width(app, text, px);
    draw_text(app, text, cx - w/2, y, max_w, px, color);
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

/* --- filtering: case-insensitive substring of the label --- */
static int ci_contains(const char *hay, const char *needle){
    if (!needle[0]) return 1;
    for (const char *h = hay; *h; h++){
        const char *a = h, *b = needle;
        while (*a && *b){ int ca = *a, cb = *b;
            if (ca>='A'&&ca<='Z') ca += 32; if (cb>='A'&&cb<='Z') cb += 32;
            if (ca != cb) break; a++; b++; }
        if (!*b) return 1;
    }
    return 0;
}
static void recompute_filter(struct app *app){
    app->n_filt = 0;
    for (int i=0;i<N_APPS && app->n_filt<MAX_APPS;i++)
        if (ci_contains(APPS[i].label, app->search)) app->filt[app->n_filt++] = i;
    if (app->hover >= app->n_filt) app->hover = -1;
}

/* geometry of the filtered tile at position `pos` (0..n_filt-1) */
static void tile_cell(struct app *app, int pos, int *cx, int *cy){
    int col = pos % GRID_COLS, row = pos / GRID_COLS;
    int gx = (app->width - GRID_COLS*CELL_PITCH_X) / 2;
    *cx = gx + col*CELL_PITCH_X;
    *cy = GRID_Y + row*CELL_PITCH_Y;
}
/* which filtered tile is under (px,py); -1 if none */
static int tile_hit(struct app *app, int px, int py){
    for (int pos=0; pos<app->n_filt; pos++){
        int cx, cy; tile_cell(app, pos, &cx, &cy);
        int ix = cx + (CELL_PITCH_X-ICON)/2;
        if (px>=ix && px<ix+ICON && py>=cy && py<cy+ICON) return pos;
    }
    return -1;
}

/* --- rendering --- */
static void draw_overview(struct app *app){
    const uint32_t BG=0xff14171fu, TITLE=0xff0d0f14u, TXT=0xfff2f5fau, DIM=0xff8b94a3u,
                   ACC=0xff4da3ffu, FIELD=0xff232834u, CLOSE=0xffcc3b3bu;
    fill_rect(app, 0, 0, app->width, app->height, BG);

    /* --- own chrome: titlebar + close box (no server-side decorations) --- */
    fill_rect(app, 0, 0, app->width, TITLEBAR_H, TITLE);
    draw_text(app, "Activities", 12, 6, 300, 15, TXT);
    fill_rect(app, app->width-CLOSE_W, 0, CLOSE_W, TITLEBAR_H, CLOSE);
    draw_text(app, "x", app->width-CLOSE_W+9, 5, CLOSE_W, 15, 0xffffffffu);

    /* --- search field --- */
    int sx = SEARCH_MARGIN, sw = app->width - 2*SEARCH_MARGIN;
    fill_rect(app, sx, SEARCH_Y, sw, SEARCH_H, FIELD);
    fill_rect(app, sx, SEARCH_Y+SEARCH_H-2, sw, 2, ACC);
    if (app->searchlen)
        draw_text(app, app->search, sx+14, SEARCH_Y+11, sw-28, 17, TXT);
    else
        draw_text(app, "Type to search apps...", sx+14, SEARCH_Y+11, sw-28, 17, DIM);

    /* --- grid --- */
    if (app->n_filt == 0){
        draw_text_centered(app, "No matching apps", app->width/2, GRID_Y+40, app->width, 16, DIM);
        return;
    }
    for (int pos=0; pos<app->n_filt; pos++){
        int idx = app->filt[pos];
        int cx, cy; tile_cell(app, pos, &cx, &cy);
        int ix = cx + (CELL_PITCH_X-ICON)/2;
        uint32_t accent = PALETTE[idx % N_PAL];
        int hovered = (pos == app->hover);

        /* hover halo behind the icon */
        if (hovered) fill_rect(app, ix-6, cy-6, ICON+12, ICON+12, 0xff2d3444u);
        /* the tile square */
        fill_rect(app, ix, cy, ICON, ICON, accent);
        /* a darker inner border to fake a rounded/raised look */
        fill_rect(app, ix, cy, ICON, 3, 0xff000000u | ((accent>>1)&0x7f7f7fu));
        fill_rect(app, ix, cy+ICON-3, ICON, 3, 0xff000000u | ((accent>>1)&0x7f7f7fu));
        /* big first letter, centred */
        char letter[2] = { APPS[idx].label[0], 0 };
        if (letter[0]>='a'&&letter[0]<='z') letter[0] -= 32;
        draw_text_centered(app, letter, ix+ICON/2, cy+ICON/2-30, ICON, 56, 0xff0d0f14u);
        /* label under the tile, centred in the cell */
        draw_text_centered(app, APPS[idx].label, cx+CELL_PITCH_X/2, cy+ICON+8, CELL_PITCH_X-4, 15,
                           hovered?TXT:DIM);
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
    int fd = create_memfd("epin-overview"); if (fd < 0) return -1;
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
    draw_overview(app);
    app->bufs[i].busy = 1;
    wl_surface_attach(app->surface, app->bufs[i].wl, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
}

/* --- launch a program, then exit the overview --- */
static void launch_and_exit(struct app *app, const char *exec){
    char m[128]; snprintf(m, sizeof m, "OVERVIEW: launch '%s'", exec); log_line(m);
    pid_t pid = fork();
    if (pid == 0){
        for (int fd = 3; fd < 64; fd++) close(fd);   /* don't leak the Wayland socket into the child */
        setsid();
        char *argv[] = { (char*)exec, NULL };
        execve(exec, argv, environ);
        _exit(127);
    }
    (void)app;
    exit(0);
}

/* --- input --- */
static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; if (a->hover!=-1){ a->hover=-1; redraw_commit(a); } }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y);
    int nh = tile_hit(a, (int)a->pointer_x, (int)a->pointer_y);
    if (nh != a->hover){ a->hover = nh; redraw_commit(a); } }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/ || state != 1) return;
    int px = (int)a->pointer_x, py = (int)a->pointer_y;
    /* close box */
    if (py < TITLEBAR_H && px >= a->width-CLOSE_W){ exit(0); }
    int pos = tile_hit(a, px, py);
    if (pos >= 0 && pos < a->n_filt) launch_and_exit(a, APPS[a->filt[pos]].exec); }
static void pointer_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v){ (void)d;(void)p;(void)t;(void)ax;(void)v; }
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
    if (state != 1) return;                          /* press only */
    if (key==1){ exit(0); }                          /* Esc */
    if (key==28){                                    /* Enter: launch iff exactly one match */
        if (a->n_filt == 1){ launch_and_exit(a, APPS[a->filt[0]].exec); } return; }
    if (key==14){ if (a->searchlen>0){ a->search[--a->searchlen]=0; recompute_filter(a); redraw_commit(a); } return; }  /* Backspace */
    if (key < 128){ char c = a->shift ? EVDEV_SHIFT[key] : EVDEV_CHAR[key];
        if (c && a->searchlen < (int)sizeof(a->search)-1){ a->search[a->searchlen++]=c; a->search[a->searchlen]=0; recompute_filter(a); redraw_commit(a); } } }
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
    app.running = 1; app.hover = -1;
    app.width = WIN_W; app.height = WIN_H; app.stride = WIN_W*4; app.buffer_size = (size_t)app.stride*WIN_H;
    signal(SIGCHLD, SIG_IGN);
    init_freetype(&app);
    recompute_filter(&app);

    log_line("OVERVIEW: starting app-grid overview");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("OVERVIEW: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base){ log_line("OVERVIEW: missing globals"); return 1; }
    if (create_buffers(&app) < 0){ log_line("OVERVIEW: buffer failed"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Activities");
    xdg_toplevel_set_app_id(app.toplevel, "epin-overview");
    /* FLOAT under the tiling WM: min==max marks us fixed-size so the tiler
     * (epin_is_tileable()) skips us and leaves this overview as a floating popover. */
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
        else { wl_display_cancel_read(app.display); if (pr < 0){ if (errno==EINTR) continue; break; } }
    }
    return 0;
}
