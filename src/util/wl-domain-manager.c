// wl-domain-manager.c — IDENTITY_DOMAIN GUI: a Qubes-style Domain Manager + per-
// domain control panel.
//
// Pops up at boot (spawned by the Weston desktop shell).  The left pane lists the
// system's security domains — the kernel's Identity objects (core/identity.d) —
// each in its identity color.  Selecting one opens a control panel on the right
// with the domain's policy knobs: memory cap (incl. Unlimited), disk access,
// network policy, clipboard policy, whether processes require secure IPC, the
// shell flavor (Linux / Windows / native OS), and per-class device access.  The
// "Launch Terminal" / "Launch Files" buttons actually fork+exec an app INTO the
// selected domain, passing every setting through the environment (EPIN_DOMAIN,
// EPIN_DOMAIN_COLOR, EPIN_SHELL, EPIN_MEM_CAP, EPIN_DISK, EPIN_NET, EPIN_CLIP,
// EPIN_SECURE_IPC) — the launched terminal draws an unspoofable domain-colored
// border and honors the shell flavor + memory cap.
//
// Window decorations are the compositor's job; this client only paints its content
// surface (Cairo shapes in one pass, antialiased FreeType text in a second pass).
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <math.h>
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
#include <wayland-client.h>
#include <cairo/cairo.h>
#include <ft2build.h>
#include FT_FREETYPE_H

#include "xdg-shell-client-protocol.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

extern char **environ;

enum {
    DEFAULT_WIDTH  = 980,
    DEFAULT_HEIGHT = 600,
    HEADER_H       = 70,
    LIST_W         = 300,     // left domain list width
    ROW_H          = 44,      // list row height
    FOOTER_H       = 32,
    PAD            = 20,
};

// Right control-panel geometry.
enum {
    RP_X    = LIST_W,
    LABEL_X = RP_X + 26,
    PILL_X  = RP_X + 196,
    PILL_W  = 250,
    PILL_H  = 28,
    CTL_H   = 42,
    RY0     = HEADER_H + 54,   // first control row y
    N_CTL   = 6,              // cyclable control rows
};

// --- option tables --------------------------------------------------------

enum { MEM_256, MEM_512, MEM_1G, MEM_2G, MEM_4G, MEM_8G, MEM_UNLIM, MEM_N };
static const char *MEM_LBL[]   = {"256 MB","512 MB","1 GB","2 GB","4 GB","8 GB","Unlimited"};
static const long  MEM_BYTES[] = {256L<<20,512L<<20,1L<<30,2L<<30,4L<<30,8L<<30,0};

enum { DISK_NONE, DISK_RO, DISK_RW, DISK_N };
static const char *DISK_LBL[] = {"None","Read-only","Read-write"};
static const char *DISK_ENV[] = {"none","ro","rw"};

enum { NET_NONE, NET_NAT, NET_VPN, NET_TOR, NET_LOCAL, NET_DISP, NET_N };
static const char *NET_LBL[] = {"None","NAT","VPN","Tor","Local-only","Disposable"};
static const char *NET_ENV[] = {"none","nat","vpn","tor","local","disposable"};

enum { CLIP_DENY, CLIP_ASK, CLIP_SAME, CLIP_DOWN, CLIP_N };
static const char *CLIP_LBL[] = {"Deny","Ask","Same-domain","Down-trust"};
static const char *CLIP_ENV[] = {"deny","ask","same","downtrust"};

enum { SH_LINUX, SH_WINDOWS, SH_NATIVE, SH_N };
static const char *SHELL_LBL[] = {"Linux","Windows (n/a)","Native OS (n/a)"};
static const char *SHELL_ENV[] = {"linux","windows","native"};

struct domain {
    const char *name;
    uint32_t    color;   // 0xAARRGGBB — mirrors the kernel IdentityRec.color
    int         trust;   // 0..100
};
static const struct domain DOMAINS[] = {
    {"System",      0xFF808080u, 100},
    {"Personal",    0xFF2E7D32u,  50},
    {"Work",        0xFF1565C0u,  60},
    {"Banking",     0xFFFFD600u,  80},
    {"Development",  0xFF6A1B9Au,  40},
    {"Untrusted",   0xFFB71C1Cu,  10},
    {"Disposable",  0xFFFF6D00u,   5},
};
enum { N_DOMAINS = (int)(sizeof(DOMAINS) / sizeof(DOMAINS[0])) };

struct dconf {
    int mem, disk, net, clip;
    int secure_ipc;          // 0/1
    int shell;
    int dev_cam, dev_mic, dev_usb;
};

// Per-domain defaults (Qubes-like: higher trust = tighter, banking locked down).
static const struct dconf DEFAULTS[N_DOMAINS] = {
    /* System      */ {MEM_UNLIM, DISK_RW,  NET_NAT,   CLIP_DOWN, 1, SH_LINUX, 1,1,1},
    /* Personal    */ {MEM_2G,    DISK_RW,  NET_NAT,   CLIP_ASK,  0, SH_LINUX, 1,1,1},
    /* Work        */ {MEM_2G,    DISK_RW,  NET_VPN,   CLIP_SAME, 1, SH_LINUX, 1,1,1},
    /* Banking     */ {MEM_1G,    DISK_RW,  NET_VPN,   CLIP_DENY, 1, SH_LINUX, 0,0,0},
    /* Development */ {MEM_4G,    DISK_RW,  NET_LOCAL, CLIP_ASK,  0, SH_LINUX, 0,0,1},
    /* Untrusted   */ {MEM_512,   DISK_RO,  NET_TOR,   CLIP_DENY, 0, SH_LINUX, 0,0,0},
    /* Disposable  */ {MEM_512,   DISK_NONE,NET_DISP,  CLIP_DENY, 0, SH_LINUX, 0,0,0},
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
    struct wl_buffer *buffer;
    struct wl_callback *frame_cb;
    uint32_t *pixels;
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size;
    size_t buffer_size;
    int width, height, stride;
    int committed, font_ready, sync_after_commit;
    int post_map_frame_armed, post_map_frame_done;
    int running;
    double pointer_x, pointer_y;
    int sel;                       // selected domain
    struct dconf cfg[N_DOMAINS];   // per-domain settings (mutable)
};

static void log_line(const char *s) { fputs(s, stdout); fputc('\n', stdout); fflush(stdout); }
static int create_memfd(const char *name) { return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC); }

static void rounded_rect(cairo_t *cr, double x, double y, double w, double h, double r)
{
    const double pi = 3.14159265358979323846;
    if (r > w / 2) r = w / 2;
    if (r > h / 2) r = h / 2;
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -pi / 2.0, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, pi / 2.0);
    cairo_arc(cr, x + r, y + h - r, r, pi / 2.0, pi);
    cairo_arc(cr, x + r, y + r, r, pi, 3.0 * pi / 2.0);
    cairo_close_path(cr);
}
static void cairo_argb(cairo_t *cr, uint32_t c)
{
    cairo_set_source_rgb(cr, ((c >> 16) & 0xff) / 255.0, ((c >> 8) & 0xff) / 255.0, (c & 0xff) / 255.0);
}

static int load_file(const char *path, unsigned char **out, size_t *out_size)
{
    *out = NULL; *out_size = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0) { close(fd); return -1; }
    unsigned char *buf = malloc((size_t)st.st_size);
    if (!buf) { close(fd); return -1; }
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + got, (size_t)st.st_size - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    *out = buf; *out_size = got;
    return 0;
}

static int init_freetype(struct app *app)
{
    const char *path = "/usr/share/fonts/noto/NotoSans-Regular.ttf";
    if (load_file(path, &app->font_data, &app->font_size) < 0) return -1;
    if (FT_Init_FreeType(&app->ft) != 0) return -1;
    if (FT_New_Memory_Face(app->ft, app->font_data, (FT_Long)app->font_size, 0, &app->face) != 0) return -1;
    app->font_ready = 1;
    printf("DOMAINMGR: loaded %s (%zu bytes)\n", path, app->font_size);
    fflush(stdout);
    return 0;
}

static uint32_t blend_xrgb(uint32_t dst, uint32_t src, unsigned int alpha)
{
    if (alpha >= 255) return src;
    if (alpha == 0) return dst;
    unsigned int inv = 255 - alpha;
    unsigned int sr = (src >> 16) & 0xff, sg = (src >> 8) & 0xff, sb = src & 0xff;
    unsigned int dr = (dst >> 16) & 0xff, dg = (dst >> 8) & 0xff, db = dst & 0xff;
    unsigned int r = (sr * alpha + dr * inv + 127) / 255;
    unsigned int g = (sg * alpha + dg * inv + 127) / 255;
    unsigned int b = (sb * alpha + db * inv + 127) / 255;
    return 0xff000000u | (r << 16) | (g << 8) | b;
}

static void draw_text(struct app *app, const char *text, int x, int y, int max_w, int px, uint32_t color)
{
    if (!app->font_ready || !text || max_w <= 0) return;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0) return;
    int baseline = px;
    if (app->face->size && app->face->size->metrics.ascender > 0)
        baseline = (int)(app->face->size->metrics.ascender >> 6);
    int pen_x = x, pen_y = y + baseline;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        unsigned char ch = *p;
        if (ch < 0x20 || ch >= 0x7f) ch = '?';
        if (FT_Load_Char(app->face, (FT_ULong)ch, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) != 0) continue;
        FT_GlyphSlot g = app->face->glyph;
        int advance = (int)(g->advance.x >> 6);
        if (pen_x + advance > x + max_w) break;
        FT_Bitmap *bm = &g->bitmap;
        int gx = pen_x + g->bitmap_left, gy = pen_y - g->bitmap_top;
        int pitch = bm->pitch;
        const unsigned char *base = bm->buffer;
        if (pitch < 0) { pitch = -pitch; base = bm->buffer - (int)(bm->rows - 1) * pitch; }
        for (int row = 0; row < (int)bm->rows; row++) {
            int pyp = gy + row;
            if (pyp < 0 || pyp >= app->height) continue;
            const unsigned char *src_row = base + row * pitch;
            for (int col = 0; col < (int)bm->width; col++) {
                int pxpos = gx + col;
                if (pxpos < 0 || pxpos >= app->width) continue;
                unsigned int alpha = 0;
                if (bm->pixel_mode == FT_PIXEL_MODE_GRAY) alpha = src_row[col];
                else if (bm->pixel_mode == FT_PIXEL_MODE_MONO) alpha = (src_row[col >> 3] & (0x80 >> (col & 7))) ? 255 : 0;
                uint32_t *dst = &app->pixels[pyp * app->width + pxpos];
                *dst = blend_xrgb(*dst, color, alpha);
            }
        }
        pen_x += advance;
    }
}

// --- control model --------------------------------------------------------

static const char *CTL_LABEL[N_CTL] = {
    "Memory cap", "Disk access", "Network", "Clipboard", "Secure IPC", "Shell"
};

static void ctl_value(const struct dconf *c, int i, char *out, size_t n)
{
    switch (i) {
        case 0: snprintf(out, n, "%s", MEM_LBL[c->mem]); break;
        case 1: snprintf(out, n, "%s", DISK_LBL[c->disk]); break;
        case 2: snprintf(out, n, "%s", NET_LBL[c->net]); break;
        case 3: snprintf(out, n, "%s", CLIP_LBL[c->clip]); break;
        case 4: snprintf(out, n, "%s", c->secure_ipc ? "Required" : "Optional"); break;
        case 5: snprintf(out, n, "%s", SHELL_LBL[c->shell]); break;
        default: out[0] = 0;
    }
}

static void ctl_cycle(struct dconf *c, int i, int dir)
{
    switch (i) {
        case 0: c->mem  = (c->mem  + MEM_N  + dir) % MEM_N;  break;
        case 1: c->disk = (c->disk + DISK_N + dir) % DISK_N; break;
        case 2: c->net  = (c->net  + NET_N  + dir) % NET_N;  break;
        case 3: c->clip = (c->clip + CLIP_N + dir) % CLIP_N; break;
        case 4: c->secure_ipc ^= 1; break;
        case 5: c->shell = (c->shell + SH_N + dir) % SH_N; break;
    }
}

// Geometry of the two launch buttons and three device chips (shared by draw + hit).
static void launch_btn_rect(int idx, int *x, int *y, int *w, int *h)
{
    *y = RY0 + 7 * CTL_H + 8; *h = 38;
    if (idx == 0) { *x = LABEL_X; *w = 200; }
    else          { *x = LABEL_X + 214; *w = 170; }
}
static void dev_chip_rect(int idx, int *x, int *y, int *w, int *h)
{
    *y = RY0 + 6 * CTL_H + (CTL_H - 26) / 2; *h = 26; *w = 78;
    *x = PILL_X + idx * (78 + 8);
}

// --- drawing --------------------------------------------------------------

static void draw_manager(struct app *app)
{
    cairo_surface_t *surface = cairo_image_surface_create_for_data(
        (unsigned char *)app->pixels, CAIRO_FORMAT_RGB24, app->width, app->height, app->stride);
    cairo_t *cr = cairo_create(surface);

    // Backdrop + panes.
    cairo_set_source_rgb(cr, 0.118, 0.137, 0.165); cairo_paint(cr);
    cairo_set_source_rgb(cr, 0.102, 0.118, 0.145);                 // left list pane
    cairo_rectangle(cr, 0, HEADER_H, LIST_W, app->height - HEADER_H); cairo_fill(cr);

    // Header band.
    cairo_set_source_rgb(cr, 0.086, 0.102, 0.125);
    cairo_rectangle(cr, 0, 0, app->width, HEADER_H); cairo_fill(cr);
    { // shield crest
        double sx = PAD + 12, sy = 18, sw = 26, sh = 32;
        cairo_set_source_rgb(cr, 0.36, 0.62, 0.96);
        cairo_move_to(cr, sx, sy); cairo_line_to(cr, sx + sw, sy);
        cairo_line_to(cr, sx + sw, sy + sh * 0.55);
        cairo_curve_to(cr, sx + sw, sy + sh, sx + sw / 2, sy + sh, sx + sw / 2, sy + sh);
        cairo_curve_to(cr, sx + sw / 2, sy + sh, sx, sy + sh, sx, sy + sh * 0.55);
        cairo_close_path(cr); cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.93, 0.96, 1.0); cairo_set_line_width(cr, 2.0);
        cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
        cairo_move_to(cr, sx + sw * 0.30, sy + sh * 0.42);
        cairo_line_to(cr, sx + sw * 0.46, sy + sh * 0.60);
        cairo_line_to(cr, sx + sw * 0.74, sy + sh * 0.26); cairo_stroke(cr);
    }
    cairo_set_source_rgb(cr, 0.22, 0.27, 0.33);
    cairo_rectangle(cr, 0, HEADER_H - 1, app->width, 1); cairo_fill(cr);
    cairo_rectangle(cr, LIST_W, HEADER_H, 1, app->height - HEADER_H); cairo_fill(cr); // pane divider

    // Left: domain list rows.
    for (int i = 0; i < N_DOMAINS; i++) {
        const struct domain *d = &DOMAINS[i];
        int ry = HEADER_H + 6 + i * ROW_H;
        if (i == app->sel) {
            cairo_set_source_rgb(cr, 0.16, 0.20, 0.27);
            cairo_rectangle(cr, 0, ry, LIST_W, ROW_H); cairo_fill(cr);
            cairo_argb(cr, d->color);
            cairo_rectangle(cr, 0, ry, 4, ROW_H); cairo_fill(cr);
        }
        double cy = ry + ROW_H / 2.0;
        cairo_argb(cr, d->color);
        rounded_rect(cr, PAD, cy - 9, 18, 18, 5); cairo_fill(cr);
        cairo_set_source_rgba(cr, 1, 1, 1, 0.18);
        rounded_rect(cr, PAD, cy - 9, 18, 18, 5); cairo_set_line_width(cr, 1.0); cairo_stroke(cr);
        // mini trust bar
        double tx = PAD + 150, tw = 96, th = 6, tyy = cy - th / 2;
        cairo_set_source_rgb(cr, 0.22, 0.26, 0.32);
        rounded_rect(cr, tx, tyy, tw, th, th / 2); cairo_fill(cr);
        cairo_argb(cr, d->color);
        rounded_rect(cr, tx, tyy, tw * (d->trust / 100.0), th, th / 2); cairo_fill(cr);
    }

    // Right: control panel for the selected domain.
    struct dconf *c = &app->cfg[app->sel];
    cairo_argb(cr, DOMAINS[app->sel].color);             // domain accent dot by panel title
    rounded_rect(cr, LABEL_X, HEADER_H + 18, 14, 14, 4); cairo_fill(cr);

    for (int i = 0; i < N_CTL; i++) {
        int ry = RY0 + i * CTL_H;
        // pill background
        cairo_set_source_rgb(cr, 0.157, 0.184, 0.224);
        rounded_rect(cr, PILL_X, ry + (CTL_H - PILL_H) / 2, PILL_W, PILL_H, 7); cairo_fill(cr);
        // a little colored marker for Secure-IPC-required / shell-unavailable states
        if (i == 4 && c->secure_ipc) { cairo_set_source_rgb(cr, 0.30, 0.78, 0.45); rounded_rect(cr, PILL_X + 8, ry + CTL_H/2 - 4, 8, 8, 2); cairo_fill(cr); }
        if (i == 5 && c->shell != SH_LINUX) { cairo_set_source_rgb(cr, 0.92, 0.55, 0.20); rounded_rect(cr, PILL_X + 8, ry + CTL_H/2 - 4, 8, 8, 2); cairo_fill(cr); }
        // row separator
        cairo_set_source_rgb(cr, 0.10, 0.12, 0.15);
        cairo_rectangle(cr, LABEL_X, ry + CTL_H - 1, app->width - LABEL_X - PAD, 1); cairo_fill(cr);
    }

    // Devices row: three toggle chips.
    {
        int ry = RY0 + 6 * CTL_H;
        cairo_set_source_rgb(cr, 0.10, 0.12, 0.15);
        cairo_rectangle(cr, LABEL_X, ry + CTL_H - 1, app->width - LABEL_X - PAD, 1); cairo_fill(cr);
        int on[3] = {c->dev_cam, c->dev_mic, c->dev_usb};
        for (int k = 0; k < 3; k++) {
            int x, y, w, h; dev_chip_rect(k, &x, &y, &w, &h);
            if (on[k]) cairo_set_source_rgb(cr, 0.20, 0.46, 0.34);
            else       cairo_set_source_rgb(cr, 0.157, 0.184, 0.224);
            rounded_rect(cr, x, y, w, h, 7); cairo_fill(cr);
        }
    }

    // Launch buttons.
    for (int b = 0; b < 2; b++) {
        int x, y, w, h; launch_btn_rect(b, &x, &y, &w, &h);
        if (b == 0) cairo_argb(cr, DOMAINS[app->sel].color);
        else        cairo_set_source_rgb(cr, 0.20, 0.24, 0.30);
        rounded_rect(cr, x, y, w, h, 9); cairo_fill(cr);
    }

    // Footer band.
    cairo_set_source_rgb(cr, 0.086, 0.102, 0.125);
    cairo_rectangle(cr, 0, app->height - FOOTER_H, app->width, FOOTER_H); cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.22, 0.27, 0.33);
    cairo_rectangle(cr, 0, app->height - FOOTER_H, app->width, 1); cairo_fill(cr);

    cairo_destroy(cr);
    cairo_surface_flush(surface);
    cairo_surface_destroy(surface);

    // --- text pass ---
    draw_text(app, "Domain Manager", PAD + 52, 14, 360, 22, 0xfff2f5fau);
    draw_text(app, "Qubes-style security domains  -  click a domain, set its policy, launch apps into it",
              PAD + 52, 44, app->width - 80, 12, 0xff8b94a3u);

    for (int i = 0; i < N_DOMAINS; i++) {
        const struct domain *d = &DOMAINS[i];
        int ry = HEADER_H + 6 + i * ROW_H;
        uint32_t nameCol = 0xff000000u | (d->color & 0x00ffffffu);
        draw_text(app, d->name, PAD + 30, ry + (ROW_H - 15) / 2, 120, 15, nameCol);
        char tb[8]; snprintf(tb, sizeof(tb), "%d", d->trust);
        draw_text(app, tb, PAD + 252, ry + (ROW_H - 12) / 2, 36, 11, 0xff97a1b0u);
    }

    // Panel title + controls text.
    char title[96];
    snprintf(title, sizeof(title), "%s  -  controls", DOMAINS[app->sel].name);
    draw_text(app, title, LABEL_X + 22, HEADER_H + 16, 360, 17, 0xfff0f3f8u);

    struct dconf *cc = &app->cfg[app->sel];
    for (int i = 0; i < N_CTL; i++) {
        int ry = RY0 + i * CTL_H;
        draw_text(app, CTL_LABEL[i], LABEL_X, ry + (CTL_H - 14) / 2, 170, 14, 0xffb7c1d0u);
        char val[48]; ctl_value(cc, i, val, sizeof(val));
        int vx = PILL_X + ((i == 4 && cc->secure_ipc) || (i == 5 && cc->shell != SH_LINUX) ? 24 : 14);
        draw_text(app, val, vx, ry + (CTL_H - 14) / 2, PILL_W - 28, 14, 0xfff2f5fau);
    }

    // Devices row text.
    {
        int ry = RY0 + 6 * CTL_H;
        draw_text(app, "Devices", LABEL_X, ry + (CTL_H - 14) / 2, 170, 14, 0xffb7c1d0u);
        const char *names[3] = {"Camera", "Mic", "USB"};
        int on[3] = {cc->dev_cam, cc->dev_mic, cc->dev_usb};
        for (int k = 0; k < 3; k++) {
            int x, y, w, h; dev_chip_rect(k, &x, &y, &w, &h);
            draw_text(app, names[k], x + 10, y + 6, w - 14, 12, on[k] ? 0xffeafff0u : 0xff8d97a6u);
        }
    }

    // Buttons text.
    for (int b = 0; b < 2; b++) {
        int x, y, w, h; launch_btn_rect(b, &x, &y, &w, &h);
        const char *lbl = (b == 0) ? "Launch Terminal" : "Launch Files";
        uint32_t col = (b == 0) ? 0xff10141au : 0xffe8edf5u;
        draw_text(app, lbl, x + 18, y + 12, w - 24, 14, col);
    }

    // Footer status.
    char foot[200];
    long mb = MEM_BYTES[cc->mem];
    char memstr[24];
    if (mb == 0) snprintf(memstr, sizeof(memstr), "uncapped");
    else snprintf(memstr, sizeof(memstr), "%ld MB", mb >> 20);
    snprintf(foot, sizeof(foot), "%s: mem %s, %s, net %s, clip %s, secure-IPC %s, shell %s",
             DOMAINS[app->sel].name, memstr, DISK_LBL[cc->disk], NET_LBL[cc->net],
             CLIP_LBL[cc->clip], cc->secure_ipc ? "required" : "optional", SHELL_LBL[cc->shell]);
    draw_text(app, foot, PAD, app->height - FOOTER_H + 9, app->width - 2 * PAD, 12, 0xff9aa4b3u);
}

// --- buffer / commit ------------------------------------------------------

static int publish_pixels(struct app *app)
{
    if (!app->pixels || app->buffer_size == 0) return -1;
    int fd = create_memfd("epin-domain-manager");
    if (fd < 0) { perror("DOMAINMGR: memfd_create"); return -1; }
    if (ftruncate(fd, (off_t)app->buffer_size) < 0) { perror("DOMAINMGR: ftruncate"); close(fd); return -1; }
    void *shm_pixels = mmap(NULL, app->buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shm_pixels == MAP_FAILED) { perror("DOMAINMGR: mmap"); close(fd); return -1; }
    memcpy(shm_pixels, app->pixels, app->buffer_size);
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int)app->buffer_size);
    struct wl_buffer *buffer = wl_shm_pool_create_buffer(pool, 0, app->width, app->height,
                                                         app->stride, WL_SHM_FORMAT_XRGB8888);
    wl_shm_pool_destroy(pool);
    munmap(shm_pixels, app->buffer_size);
    close(fd);
    if (!buffer) { log_line("DOMAINMGR: create_buffer failed"); return -1; }
    app->buffer = buffer;
    return 0;
}

static void redraw_commit(struct app *app, const char *marker)
{
    if (!app->buffer) return;
    draw_manager(app);
    if (publish_pixels(app) < 0) return;
    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    if (marker) { printf("DOMAINMGR: %s\n", marker); fflush(stdout); }
}

static int create_shm_buffer(struct app *app, int width, int height)
{
    app->width = width > 0 ? width : DEFAULT_WIDTH;
    app->height = height > 0 ? height : DEFAULT_HEIGHT;
    app->stride = app->width * 4;
    app->buffer_size = (size_t)app->stride * (size_t)app->height;
    app->pixels = malloc(app->buffer_size);
    if (!app->pixels) { perror("DOMAINMGR: malloc"); return -1; }
    if (!app->font_ready) init_freetype(app);
    draw_manager(app);
    return publish_pixels(app);
}

// --- launch ---------------------------------------------------------------

static void launch_app(struct app *app, const char *exe)
{
    if (app->sel < 0 || app->sel >= N_DOMAINS) return;
    int d = app->sel;
    const struct domain *dm = &DOMAINS[d];
    struct dconf *c = &app->cfg[d];

    pid_t pid = fork();
    if (pid < 0) { perror("DOMAINMGR: fork"); return; }
    if (pid == 0) {
        // The Manager connected via WAYLAND_SOCKET (fd-passing).  Clear it so the
        // child opens a fresh connection to the named wayland-0 socket.
        unsetenv("WAYLAND_SOCKET");
        setenv("WAYLAND_DISPLAY", "wayland-0", 1);
        char buf[40];
        setenv("EPIN_DOMAIN", dm->name, 1);
        snprintf(buf, sizeof(buf), "0x%08x", dm->color); setenv("EPIN_DOMAIN_COLOR", buf, 1);
        setenv("EPIN_SHELL", SHELL_ENV[c->shell], 1);
        snprintf(buf, sizeof(buf), "%ld", MEM_BYTES[c->mem]); setenv("EPIN_MEM_CAP", buf, 1);
        setenv("EPIN_DISK", DISK_ENV[c->disk], 1);
        setenv("EPIN_NET", NET_ENV[c->net], 1);
        setenv("EPIN_CLIP", CLIP_ENV[c->clip], 1);
        setenv("EPIN_SECURE_IPC", c->secure_ipc ? "1" : "0", 1);
        char *argv[] = { (char *)exe, NULL };
        execve(exe, argv, environ);
        _exit(127);
    }
    char m[96];
    snprintf(m, sizeof(m), "launched %s in domain '%s' (pid %d)", exe, dm->name, (int)pid);
    log_line(m);
}

// --- input ----------------------------------------------------------------

static void handle_click(struct app *app)
{
    double x = app->pointer_x, y = app->pointer_y;

    // Left list: select a domain.
    if (x < RP_X) {
        int top = HEADER_H + 6;
        if (y >= top && y < top + N_DOMAINS * ROW_H) {
            int r = (int)((y - top) / ROW_H);
            if (r >= 0 && r < N_DOMAINS && r != app->sel) {
                app->sel = r;
                redraw_commit(app, "select domain");
            }
        }
        return;
    }

    struct dconf *c = &app->cfg[app->sel];

    // Cyclable control rows.
    for (int i = 0; i < N_CTL; i++) {
        int ry = RY0 + i * CTL_H;
        if (y >= ry && y < ry + CTL_H && x >= LABEL_X) {
            ctl_cycle(c, i, 1);
            redraw_commit(app, "set control");
            return;
        }
    }
    // Device chips.
    {
        int ry = RY0 + 6 * CTL_H;
        if (y >= ry && y < ry + CTL_H) {
            for (int k = 0; k < 3; k++) {
                int bx, by, bw, bh; dev_chip_rect(k, &bx, &by, &bw, &bh);
                if (x >= bx && x <= bx + bw && y >= by && y <= by + bh) {
                    if (k == 0) c->dev_cam ^= 1;
                    else if (k == 1) c->dev_mic ^= 1;
                    else c->dev_usb ^= 1;
                    redraw_commit(app, "toggle device");
                    return;
                }
            }
        }
    }
    // Launch buttons.
    for (int b = 0; b < 2; b++) {
        int bx, by, bw, bh; launch_btn_rect(b, &bx, &by, &bw, &bh);
        if (x >= bx && x <= bx + bw && y >= by && y <= by + bh) {
            launch_app(app, b == 0 ? "/wl-term" : "/wl-files");
            redraw_commit(app, "launch");
            return;
        }
    }
}

static void pointer_enter(void *data, struct wl_pointer *p, uint32_t serial, struct wl_surface *s, wl_fixed_t sx, wl_fixed_t sy)
{ struct app *app = data; (void)p; (void)serial; (void)s; app->pointer_x = wl_fixed_to_double(sx); app->pointer_y = wl_fixed_to_double(sy); }
static void pointer_leave(void *data, struct wl_pointer *p, uint32_t serial, struct wl_surface *s) { (void)data; (void)p; (void)serial; (void)s; }
static void pointer_motion(void *data, struct wl_pointer *p, uint32_t time, wl_fixed_t sx, wl_fixed_t sy)
{ struct app *app = data; (void)p; (void)time; app->pointer_x = wl_fixed_to_double(sx); app->pointer_y = wl_fixed_to_double(sy); }
static void pointer_button(void *data, struct wl_pointer *p, uint32_t serial, uint32_t time, uint32_t button, uint32_t state)
{ struct app *app = data; (void)p; (void)serial; (void)time; if (button == 0x110 && state == WL_POINTER_BUTTON_STATE_PRESSED) handle_click(app); }
static void pointer_axis(void *data, struct wl_pointer *p, uint32_t time, uint32_t axis, wl_fixed_t value) { (void)data; (void)p; (void)time; (void)axis; (void)value; }
static void pointer_frame(void *data, struct wl_pointer *p) { (void)data; (void)p; }
static void pointer_axis_source(void *data, struct wl_pointer *p, uint32_t s) { (void)data; (void)p; (void)s; }
static void pointer_axis_stop(void *data, struct wl_pointer *p, uint32_t t, uint32_t a) { (void)data; (void)p; (void)t; (void)a; }
static void pointer_axis_discrete(void *data, struct wl_pointer *p, uint32_t a, int32_t d) { (void)data; (void)p; (void)a; (void)d; }
static const struct wl_pointer_listener pointer_listener = {
    .enter = pointer_enter, .leave = pointer_leave, .motion = pointer_motion, .button = pointer_button,
    .axis = pointer_axis, .frame = pointer_frame, .axis_source = pointer_axis_source,
    .axis_stop = pointer_axis_stop, .axis_discrete = pointer_axis_discrete,
};

static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t sz) { (void)d; (void)k; (void)f; (void)sz; if (fd >= 0) close(fd); }
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su, struct wl_array *keys) { (void)d; (void)k; (void)s; (void)su; (void)keys; }
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su) { (void)d; (void)k; (void)s; (void)su; }
static void kb_key(void *data, struct wl_keyboard *k, uint32_t serial, uint32_t time, uint32_t key, uint32_t state)
{
    struct app *app = data; (void)k; (void)serial; (void)time;
    if (state != WL_KEYBOARD_KEY_STATE_PRESSED) return;
    // Up=103 Down=108 Enter=28 Esc=1.
    if (key == 108 && app->sel < N_DOMAINS - 1) { app->sel++; redraw_commit(app, "key"); }
    else if (key == 103 && app->sel > 0)        { app->sel--; redraw_commit(app, "key"); }
    else if (key == 28)                         { launch_app(app, "/wl-term"); }
    else if (key == 1)                          { app->running = 0; }
}
static void kb_mods(void *d, struct wl_keyboard *k, uint32_t s, uint32_t dep, uint32_t la, uint32_t lo, uint32_t grp) { (void)d; (void)k; (void)s; (void)dep; (void)la; (void)lo; (void)grp; }
static void kb_repeat(void *d, struct wl_keyboard *k, int32_t rate, int32_t delay) { (void)d; (void)k; (void)rate; (void)delay; }
static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = kb_keymap, .enter = kb_enter, .leave = kb_leave, .key = kb_key, .modifiers = kb_mods, .repeat_info = kb_repeat,
};

static void seat_capabilities(void *data, struct wl_seat *seat, uint32_t caps)
{
    struct app *app = data;
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !app->keyboard) {
        app->keyboard = wl_seat_get_keyboard(seat);
        wl_keyboard_add_listener(app->keyboard, &keyboard_listener, app);
    }
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !app->pointer) {
        app->pointer = wl_seat_get_pointer(seat);
        wl_pointer_add_listener(app->pointer, &pointer_listener, app);
    }
}
static void seat_name(void *d, struct wl_seat *s, const char *n) { (void)d; (void)s; (void)n; }
static const struct wl_seat_listener seat_listener = { .capabilities = seat_capabilities, .name = seat_name };

static void wm_base_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial) { (void)data; xdg_wm_base_pong(wm_base, serial); }
static const struct xdg_wm_base_listener wm_base_listener = {.ping = wm_base_ping};

static void toplevel_configure(void *data, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s) { (void)data; (void)t; (void)w; (void)h; (void)s; }
static void toplevel_close(void *data, struct xdg_toplevel *t) { struct app *app = data; (void)t; app->running = 0; }
static void toplevel_configure_bounds(void *data, struct xdg_toplevel *t, int32_t w, int32_t h) { (void)data; (void)t; (void)w; (void)h; }
static void toplevel_wm_capabilities(void *data, struct xdg_toplevel *t, struct wl_array *c) { (void)data; (void)t; (void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure = toplevel_configure, .close = toplevel_close,
    .configure_bounds = toplevel_configure_bounds, .wm_capabilities = toplevel_wm_capabilities,
};

static void frame_done(void *data, struct wl_callback *callback, uint32_t time)
{
    struct app *app = data; (void)time;
    if (callback) wl_callback_destroy(callback);
    app->frame_cb = NULL;
    if (app->post_map_frame_done) return;
    app->post_map_frame_done = 1;
    draw_manager(app);
    if (publish_pixels(app) == 0) {
        wl_surface_attach(app->surface, app->buffer, 0, 0);
        wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
        wl_surface_commit(app->surface);
    }
    printf("DOMAINMGR: post-map redraw committed %dx%d\n", app->width, app->height);
    fflush(stdout);
}
static const struct wl_callback_listener frame_listener = {.done = frame_done};

static void xdg_surface_configure(void *data, struct xdg_surface *surface, uint32_t serial)
{
    struct app *app = data;
    xdg_surface_ack_configure(surface, serial);
    if (app->committed) return;
    if (create_shm_buffer(app, DEFAULT_WIDTH, DEFAULT_HEIGHT) < 0) { log_line("DOMAINMGR: buffer failed"); app->running = 0; return; }
    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    if (!app->post_map_frame_armed) {
        app->post_map_frame_armed = 1;
        app->frame_cb = wl_surface_frame(app->surface);
        wl_callback_add_listener(app->frame_cb, &frame_listener, app);
    }
    wl_surface_commit(app->surface);
    app->committed = 1;
    app->sync_after_commit = 1;
    printf("DOMAINMGR: committed wl_shm window %dx%d\n", app->width, app->height);
    fflush(stdout);
}
static const struct xdg_surface_listener xdg_surface_listener = {.configure = xdg_surface_configure};

static void registry_global(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version)
{
    struct app *app = data;
    if (strcmp(interface, wl_compositor_interface.name) == 0)
        app->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, version < 4 ? version : 4);
    else if (strcmp(interface, wl_shm_interface.name) == 0)
        app->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
    else if (strcmp(interface, xdg_wm_base_interface.name) == 0) {
        app->wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface, version < 6 ? version : 6);
        xdg_wm_base_add_listener(app->wm_base, &wm_base_listener, app);
    } else if (strcmp(interface, wl_seat_interface.name) == 0) {
        app->seat = wl_registry_bind(registry, name, &wl_seat_interface, version < 5 ? version : 5);
        wl_seat_add_listener(app->seat, &seat_listener, app);
    }
}
static void registry_global_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener registry_listener = { .global = registry_global, .global_remove = registry_global_remove };

int main(void)
{
    static struct app app;
    memset(&app, 0, sizeof(app));
    app.running = 1;
    app.sel = 0;
    for (int i = 0; i < N_DOMAINS; i++) app.cfg[i] = DEFAULTS[i];

    signal(SIGCHLD, SIG_IGN);   // auto-reap launched apps (no zombies)

    log_line("DOMAINMGR: starting Qubes-style Domain Manager + control panel");
    app.display = wl_display_connect(NULL);
    if (!app.display) { perror("DOMAINMGR: wl_display_connect"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base) { log_line("DOMAINMGR: missing globals"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Domain Manager");
    xdg_toplevel_set_app_id(app.toplevel, "epin-domain-manager");
    xdg_toplevel_set_min_size(app.toplevel, DEFAULT_WIDTH, DEFAULT_HEIGHT);
    wl_surface_commit(app.surface);
    wl_display_flush(app.display);

    while (app.running) {
        int ret = wl_display_dispatch(app.display);
        if (ret < 0) { perror("DOMAINMGR: dispatch"); break; }
        if (app.sync_after_commit) {
            app.sync_after_commit = 0;
            wl_display_roundtrip(app.display);
        }
    }
    return app.committed ? 0 : 1;
}
