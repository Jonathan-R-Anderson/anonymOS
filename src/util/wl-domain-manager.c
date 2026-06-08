// wl-domain-manager.c — IDENTITY_DOMAIN GUI: a Qubes-style Domain Manager.
//
// Pops up at boot (spawned by the Weston desktop shell) and shows the system's
// security domains — the kernel's Identity objects (core/identity.d) — as a
// colored table: each domain's name in its identity color, a color swatch, a
// trust bar, and its network + clipboard policy.  The colors mirror exactly the
// kernel's boot IdentityRec.color values, the same colors the compositor draws as
// each window's unspoofable border (IDENTITY_DOMAIN §6).  Clicking a row selects a
// domain (the seam where "launch an app into this domain" will hook once the
// identity-launch path is wired to userspace).
//
// Window decorations are the compositor's job; this client only paints its content
// surface (Cairo shapes in one pass, antialiased FreeType text in a second pass —
// the same two-pass approach as wl-files.c).
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

enum {
    DEFAULT_WIDTH  = 660,
    DEFAULT_HEIGHT = 470,
    HEADER_H       = 70,
    COLHDR_H       = 28,
    ROW_H          = 44,
    FOOTER_H       = 34,
    PAD            = 20,
};

// Column x positions (content surface is DEFAULT_WIDTH wide).
enum {
    COL_SWATCH = PAD,
    COL_NAME   = PAD + 34,
    COL_TRUST  = 250,
    COL_NET    = 400,
    COL_CLIP   = 520,
};

// The security domains — mirrors the kernel's 7 boot identities
// (core/identity.d identityInitDefaults): name, IdentityRec.color (0xAARRGGBB),
// trust 0..100, network policy, clipboard policy.  ASCII labels only (the text
// renderer maps non-ASCII to '?').
struct domain {
    const char *name;
    uint32_t    color;
    int         trust;
    const char *net;
    const char *clip;
};

static const struct domain DOMAINS[] = {
    {"System",      0xFF808080u, 100, "NAT",        "Down-trust"},
    {"Personal",    0xFF2E7D32u,  50, "NAT",        "Ask"},
    {"Work",        0xFF1565C0u,  60, "VPN",        "Same-domain"},
    {"Banking",     0xFFFFD600u,  80, "VPN",        "Deny"},
    {"Development",  0xFF6A1B9Au,  40, "Local-only", "Ask"},
    {"Untrusted",   0xFFB71C1Cu,  10, "Tor",        "Deny"},
    {"Disposable",  0xFFFF6D00u,   5, "Disposable", "Deny"},
};
enum { N_DOMAINS = (int)(sizeof(DOMAINS) / sizeof(DOMAINS[0])) };

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
    int width;
    int height;
    int stride;
    int committed;
    int font_ready;
    int sync_after_commit;
    int post_map_frame_armed;
    int post_map_frame_done;
    int running;
    double pointer_x;
    double pointer_y;
    int sel;   // selected domain row, -1 = none
};

static void log_line(const char *s)
{
    fputs(s, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static int create_memfd(const char *name)
{
    return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC);
}

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
    cairo_set_source_rgb(cr, ((c >> 16) & 0xff) / 255.0,
                             ((c >> 8) & 0xff) / 255.0,
                             (c & 0xff) / 255.0);
}

static int load_file(const char *path, unsigned char **out, size_t *out_size)
{
    *out = NULL;
    *out_size = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        close(fd);
        return -1;
    }
    unsigned char *buf = malloc((size_t)st.st_size);
    if (!buf) {
        close(fd);
        return -1;
    }
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + got, (size_t)st.st_size - got);
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    close(fd);
    *out = buf;
    *out_size = got;
    return 0;
}

static int init_freetype(struct app *app)
{
    const char *path = "/usr/share/fonts/noto/NotoSans-Regular.ttf";
    if (load_file(path, &app->font_data, &app->font_size) < 0)
        return -1;
    if (FT_Init_FreeType(&app->ft) != 0)
        return -1;
    if (FT_New_Memory_Face(app->ft, app->font_data, (FT_Long)app->font_size, 0, &app->face) != 0)
        return -1;
    app->font_ready = 1;
    printf("DOMAINMGR: loaded %s (%zu bytes)\n", path, app->font_size);
    fflush(stdout);
    return 0;
}

static uint32_t blend_xrgb(uint32_t dst, uint32_t src, unsigned int alpha)
{
    if (alpha >= 255)
        return src;
    if (alpha == 0)
        return dst;
    unsigned int inv = 255 - alpha;
    unsigned int sr = (src >> 16) & 0xff, sg = (src >> 8) & 0xff, sb = src & 0xff;
    unsigned int dr = (dst >> 16) & 0xff, dg = (dst >> 8) & 0xff, db = dst & 0xff;
    unsigned int r = (sr * alpha + dr * inv + 127) / 255;
    unsigned int g = (sg * alpha + dg * inv + 127) / 255;
    unsigned int b = (sb * alpha + db * inv + 127) / 255;
    return 0xff000000u | (r << 16) | (g << 8) | b;
}

// Antialiased text straight into the XRGB pixel buffer (truncates to max_w).
static void draw_text(struct app *app, const char *text, int x, int y, int max_w, int px, uint32_t color)
{
    if (!app->font_ready || !text || max_w <= 0)
        return;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0)
        return;
    int baseline = px;
    if (app->face->size && app->face->size->metrics.ascender > 0)
        baseline = (int)(app->face->size->metrics.ascender >> 6);
    int pen_x = x;
    int pen_y = y + baseline;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        unsigned char ch = *p;
        if (ch < 0x20 || ch >= 0x7f)
            ch = '?';
        if (FT_Load_Char(app->face, (FT_ULong)ch, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) != 0)
            continue;
        FT_GlyphSlot g = app->face->glyph;
        int advance = (int)(g->advance.x >> 6);
        if (pen_x + advance > x + max_w)
            break;
        FT_Bitmap *bm = &g->bitmap;
        int gx = pen_x + g->bitmap_left;
        int gy = pen_y - g->bitmap_top;
        int pitch = bm->pitch;
        const unsigned char *base = bm->buffer;
        if (pitch < 0) {
            pitch = -pitch;
            base = bm->buffer - (int)(bm->rows - 1) * pitch;
        }
        for (int row = 0; row < (int)bm->rows; row++) {
            int pyp = gy + row;
            if (pyp < 0 || pyp >= app->height)
                continue;
            const unsigned char *src_row = base + row * pitch;
            for (int col = 0; col < (int)bm->width; col++) {
                int pxpos = gx + col;
                if (pxpos < 0 || pxpos >= app->width)
                    continue;
                unsigned int alpha = 0;
                if (bm->pixel_mode == FT_PIXEL_MODE_GRAY)
                    alpha = src_row[col];
                else if (bm->pixel_mode == FT_PIXEL_MODE_MONO)
                    alpha = (src_row[col >> 3] & (0x80 >> (col & 7))) ? 255 : 0;
                uint32_t *dst = &app->pixels[pyp * app->width + pxpos];
                *dst = blend_xrgb(*dst, color, alpha);
            }
        }
        pen_x += advance;
    }
}

static int row_at(struct app *app, double y)
{
    (void)app;
    int top = HEADER_H + COLHDR_H;
    if (y < top || y >= top + N_DOMAINS * ROW_H)
        return -1;
    int r = (int)((y - top) / ROW_H);
    return (r >= 0 && r < N_DOMAINS) ? r : -1;
}

static void draw_manager(struct app *app)
{
    // --- Pass 1: Cairo shapes. ---
    cairo_surface_t *surface = cairo_image_surface_create_for_data(
        (unsigned char *)app->pixels, CAIRO_FORMAT_RGB24, app->width, app->height, app->stride);
    cairo_t *cr = cairo_create(surface);

    // Backdrop (Qubes-ish dark slate).
    cairo_set_source_rgb(cr, 0.118, 0.137, 0.165);
    cairo_paint(cr);

    // Header band.
    cairo_set_source_rgb(cr, 0.086, 0.102, 0.125);
    cairo_rectangle(cr, 0, 0, app->width, HEADER_H);
    cairo_fill(cr);
    // Shield crest at the left of the header.
    {
        double sx = PAD + 12, sy = 18, sw = 26, sh = 32;
        cairo_set_source_rgb(cr, 0.36, 0.62, 0.96);
        cairo_move_to(cr, sx, sy);
        cairo_line_to(cr, sx + sw, sy);
        cairo_line_to(cr, sx + sw, sy + sh * 0.55);
        cairo_curve_to(cr, sx + sw, sy + sh, sx + sw / 2, sy + sh, sx + sw / 2, sy + sh);
        cairo_curve_to(cr, sx + sw / 2, sy + sh, sx, sy + sh, sx, sy + sh * 0.55);
        cairo_close_path(cr);
        cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.93, 0.96, 1.0);
        cairo_set_line_width(cr, 2.0);
        cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
        cairo_move_to(cr, sx + sw * 0.30, sy + sh * 0.42);
        cairo_line_to(cr, sx + sw * 0.46, sy + sh * 0.60);
        cairo_line_to(cr, sx + sw * 0.74, sy + sh * 0.26);
        cairo_stroke(cr);
    }
    // Header underline.
    cairo_set_source_rgb(cr, 0.22, 0.27, 0.33);
    cairo_rectangle(cr, 0, HEADER_H - 1, app->width, 1);
    cairo_fill(cr);

    // Column-header band.
    cairo_set_source_rgb(cr, 0.149, 0.173, 0.208);
    cairo_rectangle(cr, 0, HEADER_H, app->width, COLHDR_H);
    cairo_fill(cr);

    // Domain rows.
    int top = HEADER_H + COLHDR_H;
    for (int i = 0; i < N_DOMAINS; i++) {
        const struct domain *d = &DOMAINS[i];
        int ry = top + i * ROW_H;
        if (i == app->sel) {
            cairo_set_source_rgb(cr, 0.16, 0.20, 0.27);
            cairo_rectangle(cr, 0, ry, app->width, ROW_H);
            cairo_fill(cr);
            cairo_argb(cr, d->color);                 // accent bar in the domain color
            cairo_rectangle(cr, 0, ry, 4, ROW_H);
            cairo_fill(cr);
        } else if (i & 1) {
            cairo_set_source_rgb(cr, 0.133, 0.157, 0.188);
            cairo_rectangle(cr, 0, ry, app->width, ROW_H);
            cairo_fill(cr);
        }
        // Color swatch (rounded) + soft ring.
        double cy = ry + ROW_H / 2.0;
        cairo_argb(cr, d->color);
        rounded_rect(cr, COL_SWATCH, cy - 9, 18, 18, 5);
        cairo_fill(cr);
        cairo_set_source_rgba(cr, 1, 1, 1, 0.18);
        rounded_rect(cr, COL_SWATCH, cy - 9, 18, 18, 5);
        cairo_set_line_width(cr, 1.0);
        cairo_stroke(cr);

        // Trust bar (track + color fill proportional to trust).
        double tx = COL_TRUST, tw = 110, th = 8, tyy = cy - th / 2.0;
        cairo_set_source_rgb(cr, 0.22, 0.26, 0.32);
        rounded_rect(cr, tx, tyy, tw, th, th / 2.0);
        cairo_fill(cr);
        cairo_argb(cr, d->color);
        rounded_rect(cr, tx, tyy, tw * (d->trust / 100.0), th, th / 2.0);
        cairo_fill(cr);
    }

    // Row separators.
    cairo_set_source_rgb(cr, 0.10, 0.12, 0.15);
    for (int i = 1; i < N_DOMAINS; i++) {
        int ry = top + i * ROW_H;
        cairo_rectangle(cr, PAD, ry, app->width - 2 * PAD, 1);
        cairo_fill(cr);
    }

    // Footer band.
    cairo_set_source_rgb(cr, 0.086, 0.102, 0.125);
    cairo_rectangle(cr, 0, app->height - FOOTER_H, app->width, FOOTER_H);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.22, 0.27, 0.33);
    cairo_rectangle(cr, 0, app->height - FOOTER_H, app->width, 1);
    cairo_fill(cr);

    cairo_destroy(cr);
    cairo_surface_flush(surface);
    cairo_surface_destroy(surface);

    // --- Pass 2: text. ---
    draw_text(app, "Domain Manager", PAD + 52, 14, 360, 22, 0xfff2f5fau);
    draw_text(app, "EpinAnonymOS security domains  -  every window is bordered in its domain color",
              PAD + 52, 44, app->width - 80, 12, 0xff8b94a3u);

    int hy = HEADER_H + 8;
    draw_text(app, "DOMAIN",    COL_NAME,  hy, 180, 11, 0xff7c8696u);
    draw_text(app, "TRUST",     COL_TRUST, hy, 110, 11, 0xff7c8696u);
    draw_text(app, "NETWORK",   COL_NET,   hy, 110, 11, 0xff7c8696u);
    draw_text(app, "CLIPBOARD", COL_CLIP,  hy, 130, 11, 0xff7c8696u);

    int top2 = HEADER_H + COLHDR_H;
    for (int i = 0; i < N_DOMAINS; i++) {
        const struct domain *d = &DOMAINS[i];
        int ry = top2 + i * ROW_H;
        int ty = ry + (ROW_H - 16) / 2;
        // Domain name in its own identity color (forced opaque XRGB).
        uint32_t nameCol = 0xff000000u | (d->color & 0x00ffffffu);
        draw_text(app, d->name, COL_NAME, ty, COL_TRUST - COL_NAME - 8, 16, nameCol);
        char tbuf[8];
        snprintf(tbuf, sizeof(tbuf), "%d", d->trust);
        draw_text(app, tbuf, COL_TRUST + 116, ty + 1, 36, 12, 0xffb6c0d0u);
        draw_text(app, d->net,  COL_NET,  ty + 1, COL_CLIP - COL_NET - 8, 13, 0xffc2ccdau);
        draw_text(app, d->clip, COL_CLIP, ty + 1, app->width - COL_CLIP - PAD, 13, 0xffc2ccdau);
    }

    char foot[160];
    if (app->sel >= 0 && app->sel < N_DOMAINS)
        snprintf(foot, sizeof(foot), "Selected: %s   -   click a domain to launch apps isolated in it (Qubes-style)",
                 DOMAINS[app->sel].name);
    else
        snprintf(foot, sizeof(foot), "%d domains   -   click a domain to launch apps isolated in it (Qubes-style)",
                 N_DOMAINS);
    draw_text(app, foot, PAD, app->height - FOOTER_H + 10, app->width - 2 * PAD, 12, 0xff9aa4b3u);
}

static int publish_pixels(struct app *app)
{
    if (!app->pixels || app->buffer_size == 0)
        return -1;
    int fd = create_memfd("epin-domain-manager");
    if (fd < 0) {
        perror("DOMAINMGR: memfd_create");
        return -1;
    }
    if (ftruncate(fd, (off_t)app->buffer_size) < 0) {
        perror("DOMAINMGR: ftruncate");
        close(fd);
        return -1;
    }
    void *shm_pixels = mmap(NULL, app->buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shm_pixels == MAP_FAILED) {
        perror("DOMAINMGR: mmap");
        close(fd);
        return -1;
    }
    memcpy(shm_pixels, app->pixels, app->buffer_size);
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int)app->buffer_size);
    struct wl_buffer *buffer = wl_shm_pool_create_buffer(pool, 0, app->width, app->height,
                                                         app->stride, WL_SHM_FORMAT_XRGB8888);
    wl_shm_pool_destroy(pool);
    munmap(shm_pixels, app->buffer_size);
    close(fd);
    if (!buffer) {
        log_line("DOMAINMGR: wl_shm_pool_create_buffer failed");
        return -1;
    }
    app->buffer = buffer;
    return 0;
}

static void redraw_commit(struct app *app, const char *marker)
{
    if (!app->buffer)
        return;
    draw_manager(app);
    if (publish_pixels(app) < 0)
        return;
    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    if (marker) {
        printf("DOMAINMGR: %s\n", marker);
        fflush(stdout);
    }
}

static int create_shm_buffer(struct app *app, int width, int height)
{
    app->width = width > 0 ? width : DEFAULT_WIDTH;
    app->height = height > 0 ? height : DEFAULT_HEIGHT;
    app->stride = app->width * 4;
    app->buffer_size = (size_t)app->stride * (size_t)app->height;
    app->pixels = malloc(app->buffer_size);
    if (!app->pixels) {
        perror("DOMAINMGR: malloc");
        return -1;
    }
    if (!app->font_ready)
        init_freetype(app);
    draw_manager(app);
    return publish_pixels(app);
}

static void wm_base_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial)
{
    (void)data;
    xdg_wm_base_pong(wm_base, serial);
}
static const struct xdg_wm_base_listener wm_base_listener = {.ping = wm_base_ping};

static void toplevel_configure(void *data, struct xdg_toplevel *toplevel,
                               int32_t width, int32_t height, struct wl_array *states)
{
    (void)data; (void)toplevel; (void)width; (void)height; (void)states;
}
static void toplevel_close(void *data, struct xdg_toplevel *toplevel)
{
    struct app *app = data;
    (void)toplevel;
    app->running = 0;
}
static void toplevel_configure_bounds(void *data, struct xdg_toplevel *t, int32_t w, int32_t h)
{
    (void)data; (void)t; (void)w; (void)h;
}
static void toplevel_wm_capabilities(void *data, struct xdg_toplevel *t, struct wl_array *c)
{
    (void)data; (void)t; (void)c;
}
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure = toplevel_configure,
    .close = toplevel_close,
    .configure_bounds = toplevel_configure_bounds,
    .wm_capabilities = toplevel_wm_capabilities,
};

static void frame_done(void *data, struct wl_callback *callback, uint32_t time)
{
    struct app *app = data;
    (void)time;
    if (callback)
        wl_callback_destroy(callback);
    app->frame_cb = NULL;
    if (app->post_map_frame_done)
        return;
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
    if (app->committed)
        return;
    if (create_shm_buffer(app, DEFAULT_WIDTH, DEFAULT_HEIGHT) < 0) {
        log_line("DOMAINMGR: create_shm_buffer failed");
        app->running = 0;
        return;
    }
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

// --- input ---------------------------------------------------------------

static void handle_click(struct app *app)
{
    int r = row_at(app, app->pointer_y);
    if (r < 0)
        return;
    app->sel = r;
    char msg[64];
    snprintf(msg, sizeof(msg), "selected domain '%s'", DOMAINS[r].name);
    redraw_commit(app, msg);
}

static void pointer_enter(void *data, struct wl_pointer *p, uint32_t serial,
                          struct wl_surface *s, wl_fixed_t sx, wl_fixed_t sy)
{
    struct app *app = data;
    (void)p; (void)serial; (void)s;
    app->pointer_x = wl_fixed_to_double(sx);
    app->pointer_y = wl_fixed_to_double(sy);
}
static void pointer_leave(void *data, struct wl_pointer *p, uint32_t serial, struct wl_surface *s)
{
    (void)data; (void)p; (void)serial; (void)s;
}
static void pointer_motion(void *data, struct wl_pointer *p, uint32_t time, wl_fixed_t sx, wl_fixed_t sy)
{
    struct app *app = data;
    (void)p; (void)time;
    app->pointer_x = wl_fixed_to_double(sx);
    app->pointer_y = wl_fixed_to_double(sy);
}
static void pointer_button(void *data, struct wl_pointer *p, uint32_t serial, uint32_t time,
                           uint32_t button, uint32_t state)
{
    struct app *app = data;
    (void)p; (void)serial; (void)time;
    if (button != 0x110 || state != WL_POINTER_BUTTON_STATE_PRESSED)
        return;
    handle_click(app);
}
static void pointer_axis(void *data, struct wl_pointer *p, uint32_t time, uint32_t axis, wl_fixed_t value)
{
    (void)data; (void)p; (void)time; (void)axis; (void)value;
}
static void pointer_frame(void *data, struct wl_pointer *p) { (void)data; (void)p; }
static void pointer_axis_source(void *data, struct wl_pointer *p, uint32_t s) { (void)data; (void)p; (void)s; }
static void pointer_axis_stop(void *data, struct wl_pointer *p, uint32_t t, uint32_t a) { (void)data; (void)p; (void)t; (void)a; }
static void pointer_axis_discrete(void *data, struct wl_pointer *p, uint32_t a, int32_t d) { (void)data; (void)p; (void)a; (void)d; }
static const struct wl_pointer_listener pointer_listener = {
    .enter = pointer_enter,
    .leave = pointer_leave,
    .motion = pointer_motion,
    .button = pointer_button,
    .axis = pointer_axis,
    .frame = pointer_frame,
    .axis_source = pointer_axis_source,
    .axis_stop = pointer_axis_stop,
    .axis_discrete = pointer_axis_discrete,
};

static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t sz)
{
    (void)d; (void)k; (void)f; (void)sz;
    if (fd >= 0)
        close(fd);
}
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su, struct wl_array *keys)
{
    (void)d; (void)k; (void)s; (void)su; (void)keys;
}
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su)
{
    (void)d; (void)k; (void)s; (void)su;
}
static void kb_key(void *data, struct wl_keyboard *k, uint32_t serial, uint32_t time, uint32_t key, uint32_t state)
{
    struct app *app = data;
    (void)k; (void)serial; (void)time;
    if (state != WL_KEYBOARD_KEY_STATE_PRESSED)
        return;
    // Up=103, Down=108, Esc=1.
    if (key == 108 && app->sel < N_DOMAINS - 1)
        app->sel++;
    else if (key == 103 && app->sel > 0)
        app->sel--;
    else if (key == 1)
        app->running = 0;
    else
        return;
    redraw_commit(app, "key");
}
static void kb_mods(void *d, struct wl_keyboard *k, uint32_t s, uint32_t dep, uint32_t la, uint32_t lo, uint32_t grp)
{
    (void)d; (void)k; (void)s; (void)dep; (void)la; (void)lo; (void)grp;
}
static void kb_repeat(void *d, struct wl_keyboard *k, int32_t rate, int32_t delay)
{
    (void)d; (void)k; (void)rate; (void)delay;
}
static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = kb_keymap,
    .enter = kb_enter,
    .leave = kb_leave,
    .key = kb_key,
    .modifiers = kb_mods,
    .repeat_info = kb_repeat,
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
static void seat_name(void *d, struct wl_seat *s, const char *n)
{
    (void)d; (void)s; (void)n;
}
static const struct wl_seat_listener seat_listener = {
    .capabilities = seat_capabilities,
    .name = seat_name,
};

static void registry_global(void *data, struct wl_registry *registry, uint32_t name,
                            const char *interface, uint32_t version)
{
    struct app *app = data;
    if (strcmp(interface, wl_compositor_interface.name) == 0) {
        app->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, version < 4 ? version : 4);
    } else if (strcmp(interface, wl_shm_interface.name) == 0) {
        app->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
    } else if (strcmp(interface, xdg_wm_base_interface.name) == 0) {
        app->wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface, version < 6 ? version : 6);
        xdg_wm_base_add_listener(app->wm_base, &wm_base_listener, app);
    } else if (strcmp(interface, wl_seat_interface.name) == 0) {
        app->seat = wl_registry_bind(registry, name, &wl_seat_interface, version < 5 ? version : 5);
        wl_seat_add_listener(app->seat, &seat_listener, app);
    }
}
static void registry_global_remove(void *d, struct wl_registry *r, uint32_t n)
{
    (void)d; (void)r; (void)n;
}
static const struct wl_registry_listener registry_listener = {
    .global = registry_global,
    .global_remove = registry_global_remove,
};

int main(void)
{
    static struct app app;
    memset(&app, 0, sizeof(app));
    app.running = 1;
    app.sel = -1;

    log_line("DOMAINMGR: starting Qubes-style Domain Manager");
    app.display = wl_display_connect(NULL);
    if (!app.display) {
        perror("DOMAINMGR: wl_display_connect");
        return 1;
    }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base) {
        log_line("DOMAINMGR: missing required Wayland globals");
        return 1;
    }

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
    log_line("DOMAINMGR: requested xdg_toplevel configure");

    while (app.running) {
        int ret = wl_display_dispatch(app.display);
        if (ret < 0) {
            perror("DOMAINMGR: wl_display_dispatch");
            break;
        }
        if (app.sync_after_commit) {
            app.sync_after_commit = 0;
            if (wl_display_roundtrip(app.display) < 0)
                perror("DOMAINMGR: post-commit roundtrip");
        }
    }
    return app.committed ? 0 : 1;
}
