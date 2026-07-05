/*
 * wl-layer-bar.c -- the GNOME-Shell-style top bar for the Hyprland desktop.
 *
 * This is the Hyprland counterpart of the Weston desktop-shell panel (which is a
 * Weston-private toytoolkit widget and cannot be reused on wlroots).  Hyprland
 * implements the standard wlr-layer-shell protocol, so this is a plain Wayland
 * client that anchors a full-width, 28px opaque-black bar to the TOP layer with an
 * exclusive zone (so tiled windows never overlap it).  Look + behaviour mirror the
 * GNOME/Weston bar:
 *
 *   [ Activities ]                    Wed Jul  4  16:30                 wifi vol batt
 *        |                                   |                              |
 *   /wl-overview                       /wl-calendar               /wl-wifi-menu (wifi)
 *                                                                 /wl-quicksettings (vol/batt)
 *
 * The Wi-Fi indicator reads /run/wifi/networks (same source as the Weston bar) and,
 * clicked, opens /wl-wifi-menu so you can pick a network + enter its password.
 *
 * Hide/show (the config-panel toggle): the bar polls /run/hos-bar.hidden once a
 * second AND toggles on SIGUSR1.  When hidden it unmaps its surface and drops its
 * exclusive zone (windows reclaim the strip); when shown it re-maps.  The Settings
 * panel writes/removes /run/hos-bar.hidden; a Hyprland `bind = SUPER,B,...` can also
 * `kill -USR1` this process.
 *
 * All Wayland scaffolding (registry / seat / double-buffered wl_shm / FreeType text /
 * the full v5 wl_pointer listener) is the proven wl-quicksettings/wl-wifi-menu pattern.
 * Drawing is fill_rect() + draw_text() + a few glyphs, no cairo.
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
#include "wlr-layer-shell-unstable-v1-client-protocol.h"

extern char **environ;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum { BAR_H = 28 };                 /* GNOME top-bar height */

/* opaque-black bar, white text -- matches panel-color=0xff000000 on Weston */
#define COL_BG      0xff000000u
#define COL_TEXT    0xfff2f2f2u
#define COL_DIM     0xff9aa0a6u
#define COL_HOVER   0x22ffffffu      /* (alpha blended) hover pill */

/* clickable regions */
enum { R_NONE = 0, R_ACTIVITIES, R_CLOCK, R_WIFI, R_INDICATORS };

/* hide-state flag file the Settings panel writes to toggle the bar */
#define HIDE_FLAG "/run/hos-bar.hidden"

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_seat *seat;
    struct wl_pointer *pointer;
    struct wl_output *output;
    struct zwlr_layer_shell_v1 *layer_shell;
    struct zwlr_layer_surface_v1 *layer_surface;
    struct wl_surface *surface;

    struct { struct wl_buffer *wl; uint32_t *px; int busy; } bufs[2];
    uint32_t *pixels;
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    int font_ready, running, configured;
    double pointer_x, pointer_y;

    /* content state */
    char clock_str[64];
    int  wifi_bars;          /* -1 no adapter, 0..4 signal */
    int  hover;              /* hovered region for highlight */
    int  hidden;             /* bar currently unmapped */
    /* layout hit boxes (computed each redraw) */
    int  act_x0, act_x1;     /* Activities */
    int  clk_x0, clk_x1;     /* Clock */
    int  wifi_x0, wifi_x1;   /* Wi-Fi glyph */
    int  ind_x0, ind_x1;     /* volume+battery */
};

static volatile sig_atomic_t g_toggle = 0;
static void on_usr1(int s){ (void)s; g_toggle = 1; }

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
static void fill_rect(struct app *app, int x, int y, int w, int h, uint32_t c){
    if (!app->pixels) return;
    unsigned int a = (c >> 24) & 0xff;
    for (int yy = y; yy < y + h; yy++){ if (yy < 0 || yy >= app->height) continue;
        for (int xx = x; xx < x + w; xx++){ if (xx < 0 || xx >= app->width) continue;
            uint32_t *d = &app->pixels[yy*app->width + xx];
            *d = (a >= 255) ? (0xff000000u | (c & 0xffffff)) : blend_xrgb(*d, c & 0xffffff, a); } }
}
/* returns the pixel advance width of `text` at size px (for centering / right-align) */
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

/* --- indicator glyphs (fill_rect only), sized for a 28px bar --- */
static void draw_wifi_glyph(struct app *app, int x, int cy, int bars){
    /* four ascending bars; lit ones bright, unlit dim; a slash when no adapter */
    for (int b = 0; b < 4; b++){
        int bh = 4 + b*3;
        uint32_t c = (bars < 0) ? COL_DIM : (bars >= b+1 ? COL_TEXT : 0xff4a4f55u);
        fill_rect(app, x + b*5, cy + 6 - bh, 3, bh, c);
    }
    if (bars < 0){
        for (int i = 0; i < 14; i++) fill_rect(app, x + i, cy - 6 + i, 2, 2, COL_DIM);
    }
}
static void draw_speaker_glyph(struct app *app, int x, int cy){
    fill_rect(app, x,     cy-3, 4, 6, COL_TEXT);
    fill_rect(app, x+4,   cy-5, 3, 10, COL_TEXT);
    fill_rect(app, x+9,   cy-4, 2, 8, COL_TEXT);
    fill_rect(app, x+12,  cy-6, 2, 12, COL_TEXT);
}
static void draw_battery_glyph(struct app *app, int x, int cy){
    fill_rect(app, x,    cy-5, 22, 11, COL_TEXT);      /* body */
    fill_rect(app, x+1,  cy-4, 20, 9,  COL_BG);        /* interior */
    fill_rect(app, x+22, cy-2, 2, 4,   COL_TEXT);      /* nub */
    fill_rect(app, x+2,  cy-3, 15, 6,  COL_TEXT);      /* ~70% charge */
}

/* signal strength -> 0..4 bars, from the ACTIVE row of /run/wifi/networks
 * (format: '# header' then 'SSID\tSTRENGTH\tSECURITY\tACTIVE\tPATH' rows). */
static int wifi_bars(void){
    FILE *f = fopen("/run/wifi/networks", "r");
    char line[512]; int bars = -1, have_dev = 0;
    if (!f) return -1;
    while (fgets(line, sizeof line, f)){
        char *save = NULL, *strength, *active;
        if (line[0] == '#'){ have_dev = 1; continue; }
        strtok_r(line, "\t", &save);                 /* SSID */
        strength = strtok_r(NULL, "\t", &save);
        strtok_r(NULL, "\t", &save);                 /* SECURITY */
        active = strtok_r(NULL, "\t", &save);
        if (active && (active[0]=='1'||active[0]=='y'||active[0]=='Y'||active[0]=='*')){
            int s = strength ? atoi(strength) : 0;
            bars = s>=80?4 : s>=55?3 : s>=30?2 : s>=5?1 : 0;
        }
    }
    fclose(f);
    if (bars < 0 && have_dev) return 0;
    return bars;
}

static void build_clock(struct app *app){
    time_t t = time(NULL); struct tm tmv;
    if (localtime_r(&t, &tmv)) strftime(app->clock_str, sizeof app->clock_str, "%a %b %e  %H:%M", &tmv);
    else snprintf(app->clock_str, sizeof app->clock_str, "--:--");
}

static void launch(const char *path){
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0){
        setsid();
        /* a fresh client must not inherit our Wayland connection fd or socket env */
        unsetenv("WAYLAND_SOCKET");
        for (int fd = 3; fd < 64; fd++) close(fd);
        char *const argv[] = { (char*)path, NULL };
        execve(path, argv, environ);
        _exit(127);
    }
}

/* --- rendering --- */
static void draw_bar(struct app *app){
    if (!app->pixels) return;
    fill_rect(app, 0, 0, app->width, app->height, COL_BG);
    int cy = app->height / 2;

    /* Activities (left) */
    const char *act = "Activities";
    int aw = text_width(app, act, 14);
    app->act_x0 = 0; app->act_x1 = 12 + aw + 12;
    if (app->hover == R_ACTIVITIES) fill_rect(app, app->act_x0+3, 3, app->act_x1-6, app->height-6, COL_HOVER);
    draw_text(app, act, 12, cy - 8, aw + 4, 14, COL_TEXT);

    /* Clock (centered) */
    int cw = text_width(app, app->clock_str, 13);
    int cx = (app->width - cw) / 2;
    app->clk_x0 = cx - 8; app->clk_x1 = cx + cw + 8;
    if (app->hover == R_CLOCK) fill_rect(app, app->clk_x0, 3, app->clk_x1-app->clk_x0, app->height-6, COL_HOVER);
    draw_text(app, app->clock_str, cx, cy - 8, cw + 4, 13, COL_TEXT);

    /* Indicators (right): battery, volume, wifi -- laid out from the right edge */
    int x = app->width - 14;
    x -= 24; draw_battery_glyph(app, x, cy);   int bat_x = x;
    x -= 22; draw_speaker_glyph(app, x, cy);   int vol_x = x;
    x -= 24; draw_wifi_glyph(app, x, cy, app->wifi_bars);  int wifi_x = x;
    app->wifi_x0 = wifi_x - 4; app->wifi_x1 = wifi_x + 20;
    app->ind_x0 = vol_x - 4;  app->ind_x1 = bat_x + 28;
    if (app->hover == R_WIFI)       fill_rect(app, app->wifi_x0, 3, app->wifi_x1-app->wifi_x0, app->height-6, COL_HOVER);
    else if (app->hover == R_INDICATORS) fill_rect(app, app->ind_x0, 3, app->ind_x1-app->ind_x0, app->height-6, COL_HOVER);
}

static void buffer_release(void *d, struct wl_buffer *wl){ struct app *a = d;
    for (int i=0;i<2;i++) if (a->bufs[i].wl == wl) a->bufs[i].busy = 0; }
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static int create_buffers(struct app *app){
    int fd = create_memfd("hos-bar");
    if (fd < 0) return -1;
    size_t total = app->buffer_size * 2;
    if (ftruncate(fd, (off_t)total) < 0){ close(fd); return -1; }
    void *data = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED){ close(fd); return -1; }
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int32_t)total);
    for (int i=0;i<2;i++){
        app->bufs[i].wl = wl_shm_pool_create_buffer(pool, (int)((size_t)i*app->buffer_size),
                              app->width, app->height, app->stride, WL_SHM_FORMAT_XRGB8888);
        wl_buffer_add_listener(app->bufs[i].wl, &buffer_listener, app);
        app->bufs[i].px = (uint32_t*)((unsigned char*)data + (size_t)i*app->buffer_size);
        app->bufs[i].busy = 0;
    }
    wl_shm_pool_destroy(pool);
    close(fd);
    return 0;
}

static void redraw_commit(struct app *app){
    if (!app->configured || app->hidden) return;
    int i = app->bufs[0].busy ? 1 : 0;
    if (app->bufs[i].busy) return;
    app->pixels = app->bufs[i].px;
    draw_bar(app);
    app->bufs[i].busy = 1;
    wl_surface_attach(app->surface, app->bufs[i].wl, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
}

static void set_hidden(struct app *app, int hide){
    if (hide == app->hidden) return;
    app->hidden = hide;
    if (hide){
        zwlr_layer_surface_v1_set_exclusive_zone(app->layer_surface, 0);
        wl_surface_attach(app->surface, NULL, 0, 0);
        wl_surface_commit(app->surface);
    } else {
        zwlr_layer_surface_v1_set_exclusive_zone(app->layer_surface, BAR_H);
        wl_surface_commit(app->surface);
        redraw_commit(app);
    }
    wl_display_flush(app->display);
}

/* --- pointer --- */
static int hit_region(struct app *app, double px, double py){
    (void)py;
    if (px >= app->act_x0  && px < app->act_x1)  return R_ACTIVITIES;
    if (px >= app->wifi_x0 && px < app->wifi_x1) return R_WIFI;
    if (px >= app->ind_x0  && px < app->ind_x1)  return R_INDICATORS;
    if (px >= app->clk_x0  && px < app->clk_x1)  return R_CLOCK;
    return R_NONE;
}
static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; if (a->hover){ a->hover=R_NONE; redraw_commit(a);} }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y);
    int h = hit_region(a, a->pointer_x, a->pointer_y);
    if (h != a->hover){ a->hover = h; redraw_commit(a); } }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/ || state != 1 /*pressed*/) return;
    switch (hit_region(a, a->pointer_x, a->pointer_y)){
        case R_ACTIVITIES: launch("/wl-overview");      break;
        case R_CLOCK:      launch("/wl-calendar");      break;
        case R_WIFI:       launch("/wl-wifi-menu");     break;   /* pick network + password */
        case R_INDICATORS: launch("/wl-quicksettings"); break;
        default: break;
    } }
static void pointer_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v){ (void)d;(void)p;(void)t;(void)ax;(void)v; }
static void pointer_frame(void *d, struct wl_pointer *p){ (void)d;(void)p; }
static void pointer_axis_source(void *d, struct wl_pointer *p, uint32_t s){ (void)d;(void)p;(void)s; }
static void pointer_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t a){ (void)d;(void)p;(void)t;(void)a; }
static void pointer_axis_discrete(void *d, struct wl_pointer *p, uint32_t a, int32_t dsc){ (void)d;(void)p;(void)a;(void)dsc; }
static const struct wl_pointer_listener pointer_listener = {
    .enter=pointer_enter,.leave=pointer_leave,.motion=pointer_motion,.button=pointer_button,.axis=pointer_axis,
    .frame=pointer_frame,.axis_source=pointer_axis_source,.axis_stop=pointer_axis_stop,.axis_discrete=pointer_axis_discrete };

static void seat_caps(void *d, struct wl_seat *seat, uint32_t caps){ struct app*a=d;
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !a->pointer){ a->pointer = wl_seat_get_pointer(seat); wl_pointer_add_listener(a->pointer,&pointer_listener,a); } }
static void seat_name(void *d, struct wl_seat *s, const char *n){ (void)d;(void)s;(void)n; }
static const struct wl_seat_listener seat_listener = { .capabilities=seat_caps, .name=seat_name };

/* --- layer surface --- */
static void layer_configure(void *d, struct zwlr_layer_surface_v1 *s, uint32_t serial, uint32_t w, uint32_t h){
    struct app *a = d;
    { char b[64]; snprintf(b,sizeof b,"BAR: configure %ux%u -> render", w, h); log_line(b); }
    zwlr_layer_surface_v1_ack_configure(s, serial);
    int nw = (int)w, nh = (int)h ? (int)h : BAR_H;
    if (nw <= 0) nw = 1;
    if (!a->configured || nw != a->width){
        a->width = nw; a->height = nh; a->stride = nw*4; a->buffer_size = (size_t)a->stride*nh;
        /* (re)create buffers at the compositor-chosen width */
        for (int i=0;i<2;i++) if (a->bufs[i].wl){ wl_buffer_destroy(a->bufs[i].wl); a->bufs[i].wl=NULL; }
        if (create_buffers(a) < 0){ log_line("BAR: buffer alloc failed"); a->running=0; return; }
    }
    a->configured = 1;
    redraw_commit(a);
}
static void layer_closed(void *d, struct zwlr_layer_surface_v1 *s){ (void)s; struct app*a=d; a->running=0; }
static const struct zwlr_layer_surface_v1_listener layer_listener = { .configure=layer_configure, .closed=layer_closed };

static void registry_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver){ struct app*a=d;
    if (!strcmp(iface, wl_compositor_interface.name)) a->compositor = wl_registry_bind(r,name,&wl_compositor_interface, ver<4?ver:4);
    else if (!strcmp(iface, wl_shm_interface.name)) a->shm = wl_registry_bind(r,name,&wl_shm_interface,1);
    else if (!strcmp(iface, zwlr_layer_shell_v1_interface.name)) a->layer_shell = wl_registry_bind(r,name,&zwlr_layer_shell_v1_interface, ver<4?ver:4);
    else if (!strcmp(iface, wl_output_interface.name) && !a->output) a->output = wl_registry_bind(r,name,&wl_output_interface, ver<2?ver:2);
    else if (!strcmp(iface, wl_seat_interface.name)){ a->seat = wl_registry_bind(r,name,&wl_seat_interface, ver<5?ver:5); wl_seat_add_listener(a->seat,&seat_listener,a); } }
static void registry_remove(void *d, struct wl_registry *r, uint32_t n){ (void)d;(void)r;(void)n; }
static const struct wl_registry_listener registry_listener = { .global=registry_global, .global_remove=registry_remove };

/* once-a-second tick: refresh clock + wifi + honour the hide flag file / SIGUSR1 */
static void tick(struct app *app){
    int changed = 0;
    char prev[64]; strncpy(prev, app->clock_str, sizeof prev); prev[sizeof prev - 1] = 0;
    build_clock(app);
    if (strcmp(prev, app->clock_str)) changed = 1;
    int nb = wifi_bars();
    if (nb != app->wifi_bars){ app->wifi_bars = nb; changed = 1; }

    struct stat st;
    int want_hidden = (stat(HIDE_FLAG, &st) == 0);
    if (g_toggle){ g_toggle = 0; want_hidden = !app->hidden;      /* SIGUSR1 toggles */
        /* keep the flag file consistent so the Settings panel + bar agree */
        if (want_hidden){ int fd=open(HIDE_FLAG,O_CREAT|O_WRONLY,0644); if (fd>=0) close(fd); }
        else unlink(HIDE_FLAG);
    }
    if (want_hidden != app->hidden) set_hidden(app, want_hidden);
    else if (changed) redraw_commit(app);
}

int main(void){
    static struct app app; memset(&app, 0, sizeof app);
    app.running = 1; app.hover = R_NONE; app.wifi_bars = -1;
    signal(SIGCHLD, SIG_IGN);
    signal(SIGUSR1, on_usr1);
    init_freetype(&app);
    build_clock(&app);
    app.wifi_bars = wifi_bars();

    log_line("BAR: starting GNOME-style top bar (wlr-layer-shell)");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("BAR: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.layer_shell){ log_line("BAR: missing globals (need wlr-layer-shell)"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.layer_surface = zwlr_layer_shell_v1_get_layer_surface(app.layer_shell, app.surface,
                            app.output, ZWLR_LAYER_SHELL_V1_LAYER_TOP, "panel");
    zwlr_layer_surface_v1_add_listener(app.layer_surface, &layer_listener, &app);
    zwlr_layer_surface_v1_set_anchor(app.layer_surface,
        ZWLR_LAYER_SURFACE_V1_ANCHOR_TOP | ZWLR_LAYER_SURFACE_V1_ANCHOR_LEFT | ZWLR_LAYER_SURFACE_V1_ANCHOR_RIGHT);
    zwlr_layer_surface_v1_set_size(app.layer_surface, 0, BAR_H);           /* 0 width -> full output width */
    zwlr_layer_surface_v1_set_exclusive_zone(app.layer_surface, BAR_H);    /* reserve the strip */
    zwlr_layer_surface_v1_set_keyboard_interactivity(app.layer_surface, 0);/* never steal focus */
    wl_surface_commit(app.surface);                                        /* triggers the first configure */
    wl_display_flush(app.display);
    log_line("BAR: layer surface committed, awaiting configure");

    int wlfd = wl_display_get_fd(app.display);
    while (app.running){
        while (wl_display_prepare_read(app.display) != 0) wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);
        struct pollfd pfd = { .fd=wlfd, .events=POLLIN, .revents=0 };
        int pr = poll(&pfd, 1, 1000);
        if (pr > 0 && (pfd.revents & POLLIN)){ wl_display_read_events(app.display); wl_display_dispatch_pending(app.display); }
        else { wl_display_cancel_read(app.display); if (pr < 0){ if (errno==EINTR){ tick(&app); continue; } break; }
               if (pr == 0) tick(&app); }
    }
    return 0;
}
