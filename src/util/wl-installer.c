#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pango/pangocairo.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <wayland-client.h>
#include <ft2build.h>
#include FT_FREETYPE_H

#include "xdg-shell-client-protocol.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum {
    DEFAULT_WIDTH = 560,
    DEFAULT_HEIGHT = 360,
};

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_output *output;
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
    int pending_width;
    int pending_height;
    int committed;
    int font_ready;
    int entry_focused;
    int button_active;
    int shift;
    int sync_after_commit;
    int post_map_frame_armed;
    int post_map_frame_done;
    int running;
    int screen;          /* 0 = welcome (Install / Try Live), 1 = install/progress */
    int installing;      /* 1 while the install loop is driving batches */
    int install_done;    /* 1 once the install finished */
    int install_failed;  /* 1 if /config/install.action could not be opened */
    int progress;        /* install progress, 0..1000 permille */
    double pointer_x;
    double pointer_y;
    char entry_text[64];
    int entry_len;
};

/* Button hit-rects, computed from the window size so draw + click agree.
 * which: 0 = Install, 1 = Try Live, 2 = Back. */
enum { BTN_INSTALL = 0, BTN_LIVE = 1, BTN_BACK = 2 };
static void btn_rect(struct app *app, int which,
                     double *x, double *y, double *w, double *h)
{
    double W = app->width, H = app->height;
    if (which == BTN_BACK) { *x = 48; *y = H - 76; *w = 150; *h = 50; return; }
    *y = H - 96; *h = 58;
    double bw = (W - 48 - 48 - 24) / 2;      /* two buttons, 48px side margins, 24px gap */
    *w = bw;
    *x = (which == BTN_INSTALL) ? 48 : (W - 48 - bw);
}

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
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -pi / 2.0, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, pi / 2.0);
    cairo_arc(cr, x + r, y + h - r, r, pi / 2.0, pi);
    cairo_arc(cr, x + r, y + r, r, pi, 3.0 * pi / 2.0);
    cairo_close_path(cr);
}

static int load_file(const char *path, unsigned char **out, size_t *out_size)
{
    *out = NULL;
    *out_size = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    size_t cap = 65536;
    size_t len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) {
        close(fd);
        return -1;
    }

    for (;;) {
        if (len == cap) {
            size_t next = cap * 2;
            unsigned char *nb = realloc(buf, next);
            if (!nb) {
                free(buf);
                close(fd);
                return -1;
            }
            buf = nb;
            cap = next;
        }
        ssize_t n = read(fd, buf + len, cap - len);
        if (n > 0) {
            len += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            free(buf);
            close(fd);
            return -1;
        }
        break;
    }

    close(fd);
    if (len == 0) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_size = len;
    return 0;
}

static int init_freetype(struct app *app)
{
    const char *path = "/usr/share/fonts/noto/NotoSans-Regular.ttf";
    if (load_file(path, &app->font_data, &app->font_size) < 0)
        return -1;
    if (FT_Init_FreeType(&app->ft) != 0)
        return -1;
    if (FT_New_Memory_Face(app->ft, app->font_data, (FT_Long)app->font_size, 0,
                           &app->face) != 0)
        return -1;
    app->font_ready = 1;
    printf("G11FONT: loaded %s (%zu bytes) -- G11 FONT\n", path, app->font_size);
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

static void draw_text_ft(struct app *app, const char *text, int x, int y,
                         int max_w, int px, uint32_t color)
{
    if (!app->font_ready || !text || max_w <= 0)
        return;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0)
        return;

    int line_h = px + 6;
    int baseline = px;
    if (app->face->size && app->face->size->metrics.ascender > 0)
        baseline = (int)(app->face->size->metrics.ascender >> 6);

    int pen_x = x;
    int pen_y = y + baseline;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        unsigned char ch = *p;
        if (ch == '\n') {
            pen_x = x;
            pen_y += line_h;
            continue;
        }
        if (ch < 0x20 || ch >= 0x7f)
            ch = '?';
        if (FT_Load_Char(app->face, (FT_ULong)ch, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) != 0)
            continue;

        FT_GlyphSlot g = app->face->glyph;
        int advance = (int)(g->advance.x >> 6);
        if (pen_x > x && pen_x + advance > x + max_w) {
            pen_x = x;
            pen_y += line_h;
        }

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
            int py = gy + row;
            if (py < 0 || py >= app->height)
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
                uint32_t *dst = &app->pixels[py * app->width + pxpos];
                *dst = blend_xrgb(*dst, color, alpha);
            }
        }
        pen_x += advance;
    }
}

static void draw_demo(struct app *app)
{
    cairo_surface_t *surface = cairo_image_surface_create_for_data(
        (unsigned char *)app->pixels,
        CAIRO_FORMAT_RGB24,
        app->width,
        app->height,
        app->stride);
    cairo_t *cr = cairo_create(surface);

    /* full-window gradient (no inner card — clean welcome) */
    cairo_pattern_t *grad = cairo_pattern_create_linear(0, 0, app->width, app->height);
    cairo_pattern_add_color_stop_rgb(grad, 0.0, 0.07, 0.13, 0.22);
    cairo_pattern_add_color_stop_rgb(grad, 0.55, 0.06, 0.30, 0.40);
    cairo_pattern_add_color_stop_rgb(grad, 1.0, 0.16, 0.12, 0.34);
    cairo_rectangle(cr, 0, 0, app->width, app->height);
    cairo_set_source(cr, grad);
    cairo_fill(cr);
    cairo_pattern_destroy(grad);

    double bx, by, bw, bh;
    if (app->screen == 0) {
        /* Install (primary, teal) + Try Live (secondary, light) */
        btn_rect(app, BTN_INSTALL, &bx, &by, &bw, &bh);
        rounded_rect(cr, bx, by, bw, bh, 10);
        cairo_set_source_rgb(cr, 0.05, 0.55, 0.50);
        cairo_fill(cr);
        btn_rect(app, BTN_LIVE, &bx, &by, &bw, &bh);
        rounded_rect(cr, bx, by, bw, bh, 10);
        cairo_set_source_rgb(cr, 0.88, 0.91, 0.95);
        cairo_fill(cr);
    } else {
        /* progress bar: track + fill proportional to app->progress (0..1000) */
        double pbx = 48, pbw = app->width - 96, pbh = 20;
        double pby = 184;
        rounded_rect(cr, pbx, pby, pbw, pbh, 8);
        cairo_set_source_rgb(cr, 0.10, 0.16, 0.26);              /* track */
        cairo_fill(cr);
        int pg = app->progress; if (pg < 0) pg = 0; if (pg > 1000) pg = 1000;
        double fillw = pbw * pg / 1000.0;
        if (fillw > 1.0) {
            rounded_rect(cr, pbx, pby, fillw, pbh, 8);
            if (app->install_failed) cairo_set_source_rgb(cr, 0.80, 0.30, 0.25);      /* red */
            else if (app->install_done) cairo_set_source_rgb(cr, 0.20, 0.70, 0.45);   /* green */
            else cairo_set_source_rgb(cr, 0.05, 0.62, 0.56);                          /* teal */
            cairo_fill(cr);
        }

        btn_rect(app, BTN_BACK, &bx, &by, &bw, &bh);
        rounded_rect(cr, bx, by, bw, bh, 10);
        cairo_set_source_rgb(cr, 0.30, 0.35, 0.44);
        cairo_fill(cr);
    }

    cairo_destroy(cr);
    cairo_surface_flush(surface);
    cairo_surface_destroy(surface);

    /* heading */
    draw_text_ft(app, "Welcome to EpinAnonymOS", 48, 60, app->width - 96, 22, 0xffffffffu);

    if (app->screen == 0) {
        draw_text_ft(app, "Install EpinAnonymOS to a disk, or try the live",
                     48, 104, app->width - 96, 13, 0xffd6deeau);
        draw_text_ft(app, "session first without changing anything.",
                     48, 126, app->width - 96, 13, 0xffd6deeau);
        btn_rect(app, BTN_INSTALL, &bx, &by, &bw, &bh);
        draw_text_ft(app, "Install to Disk", (int)bx + 36, (int)by + 36, (int)bw, 15, 0xffffffffu);
        btn_rect(app, BTN_LIVE, &bx, &by, &bw, &bh);
        draw_text_ft(app, "Try Live Session", (int)bx + 32, (int)by + 36, (int)bw, 15, 0xff14203au);
    } else {
        const char *line1, *line2;
        if (app->install_failed) {
            line1 = "Install unavailable on this image.";
            line2 = "Boot the installer ISO (make hos-install.iso) to install.";
        } else if (app->install_done) {
            line1 = "Installation complete.";
            line2 = "Power off, remove the install medium, then boot the disk.";
        } else {
            line1 = "Installing EpinAnonymOS to the target disk...";
            line2 = "Writing the GPT + EFI System Partition + boot image.";
        }
        draw_text_ft(app, line1, 48, 104, app->width - 96, 13, 0xffd6deeau);
        draw_text_ft(app, line2, 48, 126, app->width - 96, 13, 0xffd6deeau);

        /* percentage label above the bar */
        char pct[16]; int p10 = app->progress / 10; if (p10 > 100) p10 = 100;
        snprintf(pct, sizeof pct, "%d%%", p10);
        draw_text_ft(app, pct, app->width - 96, 158, 80, 14, 0xffffffffu);

        btn_rect(app, BTN_BACK, &bx, &by, &bw, &bh);
        draw_text_ft(app, app->install_done ? "Done" : "Back", (int)bx + 54, (int)by + 32, (int)bw, 15, 0xffffffffu);
    }
}

static int publish_pixels(struct app *app)
{
    if (!app->pixels || app->buffer_size == 0)
        return -1;

    int fd = create_memfd("epin-g11-cairo");
    if (fd < 0) {
        perror("G11CAIRO: memfd_create");
        return -1;
    }
    if (ftruncate(fd, (off_t)app->buffer_size) < 0) {
        perror("G11CAIRO: ftruncate");
        close(fd);
        return -1;
    }

    void *shm_pixels = mmap(NULL, app->buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shm_pixels == MAP_FAILED) {
        perror("G11CAIRO: mmap");
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
        log_line("G11CAIRO: wl_shm_pool_create_buffer failed");
        return -1;
    }

    app->buffer = buffer;
    return 0;
}

static void redraw_commit(struct app *app, const char *marker)
{
    if (!app->buffer)
        return;
    draw_demo(app);
    if (publish_pixels(app) < 0)
        return;
    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    if (marker) {
        printf("G11INPUT: %s -- G11 INPUT\n", marker);
        fflush(stdout);
    }
}

/* INSTALLER §D: advance the install by one batch and refresh the progress reading (0..1000).
 * Each "install" write to /config/install.action does ~4 MiB in the kernel, then we poll
 * /config/install.progress so the bar tracks the real on-disk write. */
static void install_step(struct app *app)
{
    int fd = open("/config/install.action", O_WRONLY);
    if (fd >= 0) { ssize_t wn = write(fd, "install", 7); (void)wn; close(fd); }
    int pf = open("/config/install.progress", O_RDONLY);
    if (pf >= 0) {
        char b[16];
        ssize_t n = read(pf, b, sizeof b - 1);
        close(pf);
        if (n > 0) { b[n] = 0; app->progress = atoi(b); }
    }
}

static int create_shm_buffer(struct app *app, int width, int height)
{
    app->width = width > 0 ? width : DEFAULT_WIDTH;
    app->height = height > 0 ? height : DEFAULT_HEIGHT;
    app->stride = app->width * 4;
    size_t size = (size_t)app->stride * (size_t)app->height;
    app->buffer_size = size;

    app->pixels = malloc(size);
    if (!app->pixels) {
        perror("G11CAIRO: malloc");
        return -1;
    }
    if (!app->font_ready)
        init_freetype(app);
    draw_demo(app);
    return publish_pixels(app);
}

static void wm_base_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial)
{
    (void)data;
    xdg_wm_base_pong(wm_base, serial);
}

static const struct xdg_wm_base_listener wm_base_listener = {
    .ping = wm_base_ping,
};

static void toplevel_configure(void *data, struct xdg_toplevel *toplevel,
                               int32_t width, int32_t height, struct wl_array *states)
{
    struct app *app = data;
    (void)toplevel;
    (void)states;
    if (width > 0)
        app->pending_width = width;
    if (height > 0)
        app->pending_height = height;
}

static void toplevel_close(void *data, struct xdg_toplevel *toplevel)
{
    struct app *app = data;
    (void)toplevel;
    app->running = 0;
}

static void toplevel_configure_bounds(void *data, struct xdg_toplevel *toplevel,
                                      int32_t width, int32_t height)
{
    (void)data;
    (void)toplevel;
    (void)width;
    (void)height;
}

static void toplevel_wm_capabilities(void *data, struct xdg_toplevel *toplevel,
                                     struct wl_array *capabilities)
{
    (void)data;
    (void)toplevel;
    (void)capabilities;
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
    if (app->post_map_frame_done || !app->buffer)
        return;

    app->post_map_frame_done = 1;
    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    printf("G11CAIRO: post-map redraw committed %dx%d -- G11 REDRAW\n",
           app->width, app->height);
    fflush(stdout);
}

static const struct wl_callback_listener frame_listener = {
    .done = frame_done,
};

static void xdg_surface_configure(void *data, struct xdg_surface *surface,
                                  uint32_t serial)
{
    struct app *app = data;
    xdg_surface_ack_configure(surface, serial);
    if (app->committed)
        return;

    int width = DEFAULT_WIDTH;
    int height = DEFAULT_HEIGHT;
    if (app->pending_width > 0 && app->pending_width < width)
        width = app->pending_width;
    if (app->pending_height > 0 && app->pending_height < height)
        height = app->pending_height;
    if (create_shm_buffer(app, width, height) < 0) {
        app->running = 0;
        return;
    }

    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    if (!app->post_map_frame_armed) {
        app->frame_cb = wl_surface_frame(app->surface);
        wl_callback_add_listener(app->frame_cb, &frame_listener, app);
        app->post_map_frame_armed = 1;
    }
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    app->committed = 1;
    app->sync_after_commit = 1;
    printf("G11CAIRO: committed Cairo/FreeType wl_shm window %dx%d -- G11 COMMIT\n",
           app->width, app->height);
    fflush(stdout);
}

static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = xdg_surface_configure,
};

static const char keymap_plain[59] = {
    0,0,'1','2','3','4','5','6','7','8','9','0','-','=',0,0,
    'q','w','e','r','t','y','u','i','o','p','[',']',0,0,'a','s',
    'd','f','g','h','j','k','l',';','\'','`',0,'\\','z','x','c','v',
    'b','n','m',',','.','/',0,0,0,' '
};

static const char keymap_shift[59] = {
    0,0,'!','@','#','$','%','^','&','*','(',')','_','+',0,0,
    'Q','W','E','R','T','Y','U','I','O','P','{','}',0,0,'A','S',
    'D','F','G','H','J','K','L',':','"','~',0,'|','Z','X','C','V',
    'B','N','M','<','>','?',0,0,0,' '
};

static void entry_append_key(struct app *app, uint32_t code)
{
    if (!app->entry_focused)
        return;
    if (code == 14) {
        if (app->entry_len > 0)
            app->entry_text[--app->entry_len] = 0;
        redraw_commit(app, "entry edit");
        return;
    }
    if (code == 28) {
        app->button_active = 1;
        redraw_commit(app, "entry submit");
        return;
    }
    if (code >= sizeof(keymap_plain))
        return;
    char ch = app->shift ? keymap_shift[code] : keymap_plain[code];
    if (!ch || app->entry_len >= (int)sizeof(app->entry_text) - 1)
        return;
    app->entry_text[app->entry_len++] = ch;
    app->entry_text[app->entry_len] = 0;
    redraw_commit(app, "entry edit");
}

static void keyboard_keymap(void *data, struct wl_keyboard *keyboard,
                            uint32_t format, int32_t fd, uint32_t size)
{
    (void)data;
    (void)keyboard;
    (void)format;
    (void)size;
    if (fd >= 0)
        close(fd);
}

static void keyboard_enter(void *data, struct wl_keyboard *keyboard,
                           uint32_t serial, struct wl_surface *surface,
                           struct wl_array *keys)
{
    struct app *app = data;
    (void)keyboard;
    (void)serial;
    (void)surface;
    (void)keys;
    app->entry_focused = 1;
    redraw_commit(app, "keyboard focus");
}

static void keyboard_leave(void *data, struct wl_keyboard *keyboard,
                           uint32_t serial, struct wl_surface *surface)
{
    struct app *app = data;
    (void)keyboard;
    (void)serial;
    (void)surface;
    app->entry_focused = 0;
    redraw_commit(app, "keyboard blur");
}

static void keyboard_key(void *data, struct wl_keyboard *keyboard,
                         uint32_t serial, uint32_t time,
                         uint32_t code, uint32_t state)
{
    struct app *app = data;
    (void)keyboard;
    (void)serial;
    (void)time;
    int down = state == WL_KEYBOARD_KEY_STATE_PRESSED;
    if (code == 42 || code == 54) {
        app->shift = down;
        return;
    }
    if (down)
        entry_append_key(app, code);
}

static void keyboard_modifiers(void *data, struct wl_keyboard *keyboard,
                               uint32_t serial, uint32_t depressed,
                               uint32_t latched, uint32_t locked,
                               uint32_t group)
{
    (void)data;
    (void)keyboard;
    (void)serial;
    (void)depressed;
    (void)latched;
    (void)locked;
    (void)group;
}

static void keyboard_repeat_info(void *data, struct wl_keyboard *keyboard,
                                 int32_t rate, int32_t delay)
{
    (void)data;
    (void)keyboard;
    (void)rate;
    (void)delay;
}

static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = keyboard_keymap,
    .enter = keyboard_enter,
    .leave = keyboard_leave,
    .key = keyboard_key,
    .modifiers = keyboard_modifiers,
    .repeat_info = keyboard_repeat_info,
};

static void pointer_enter(void *data, struct wl_pointer *pointer,
                          uint32_t serial, struct wl_surface *surface,
                          wl_fixed_t sx, wl_fixed_t sy)
{
    struct app *app = data;
    (void)pointer;
    (void)serial;
    (void)surface;
    app->pointer_x = wl_fixed_to_double(sx);
    app->pointer_y = wl_fixed_to_double(sy);
}

static void pointer_leave(void *data, struct wl_pointer *pointer,
                          uint32_t serial, struct wl_surface *surface)
{
    (void)data;
    (void)pointer;
    (void)serial;
    (void)surface;
}

static void pointer_motion(void *data, struct wl_pointer *pointer,
                           uint32_t time, wl_fixed_t sx, wl_fixed_t sy)
{
    struct app *app = data;
    (void)pointer;
    (void)time;
    app->pointer_x = wl_fixed_to_double(sx);
    app->pointer_y = wl_fixed_to_double(sy);
}

static int in_rect(struct app *app, double x, double y, double w, double h)
{
    return app->pointer_x >= x && app->pointer_x < x + w &&
           app->pointer_y >= y && app->pointer_y < y + h;
}

static void pointer_button(void *data, struct wl_pointer *pointer,
                           uint32_t serial, uint32_t time,
                           uint32_t button, uint32_t state)
{
    struct app *app = data;
    (void)pointer;
    (void)serial;
    (void)time;
    if (button != 0x110 || state != WL_POINTER_BUTTON_STATE_PRESSED)
        return;

    double x, y, w, h;
    if (app->screen == 0) {
        btn_rect(app, BTN_LIVE, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h)) {
            /* Try Live Session: close the installer -> the live desktop behind it. */
            printf("INSTALLER: 'Try Live Session' -- closing to the live desktop\n");
            app->running = 0;
            return;
        }
        btn_rect(app, BTN_INSTALL, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h)) {
            /* INSTALLER §D: kick off the in-OS installer.  The install runs in batches: the
             * main loop repeatedly writes "install" to /config/install.action (each write
             * advances a batch) and reads /config/install.progress (0..1000) to drive the
             * progress bar, until done.  Verify the control file exists up front. */
            app->screen = 1;
            app->progress = 0;
            app->install_done = 0;
            int fd = open("/config/install.action", O_WRONLY);
            if (fd >= 0) {
                close(fd);
                app->installing = 1;
                app->install_failed = 0;
                printf("INSTALLER: 'Install to Disk' -> starting install\n");
            } else {
                app->installing = 0;
                app->install_failed = 1;
                printf("INSTALLER: 'Install to Disk' -- no /config/install.action "
                       "(boot the INSTALL image: scripts/mk-install-iso.sh)\n");
            }
            redraw_commit(app, "install-info");
            return;
        }
    } else {
        if (app->installing) return;     /* can't go back mid-install */
        btn_rect(app, BTN_BACK, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h)) {
            /* "Done" after a finished install closes to the live desktop; "Back" otherwise. */
            if (app->install_done) { app->running = 0; return; }
            app->screen = 0;
            redraw_commit(app, "back");
            return;
        }
    }
}

static void pointer_axis(void *data, struct wl_pointer *pointer,
                         uint32_t time, uint32_t axis, wl_fixed_t value)
{
    (void)data;
    (void)pointer;
    (void)time;
    (void)axis;
    (void)value;
}

/* wl_pointer v5+ sends a frame event (opcode 5) after each pointer event group,
 * plus axis_source/axis_stop/axis_discrete for scrolling. libwayland calls these
 * listener slots unconditionally; leaving them NULL crashes the client the moment
 * the compositor delivers one (e.g. on the first mouse motion). Provide no-op
 * handlers. */
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

static void seat_capabilities(void *data, struct wl_seat *seat, uint32_t caps)
{
    struct app *app = data;
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !app->keyboard) {
        app->keyboard = wl_seat_get_keyboard(seat);
        wl_keyboard_add_listener(app->keyboard, &keyboard_listener, app);
        log_line("G11INPUT: keyboard subscribed");
    }
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !app->pointer) {
        app->pointer = wl_seat_get_pointer(seat);
        wl_pointer_add_listener(app->pointer, &pointer_listener, app);
        log_line("G11INPUT: pointer subscribed");
    }
}

static void seat_name(void *data, struct wl_seat *seat, const char *name)
{
    (void)data;
    (void)seat;
    (void)name;
}

static const struct wl_seat_listener seat_listener = {
    .capabilities = seat_capabilities,
    .name = seat_name,
};

static void output_geometry(void *data, struct wl_output *output,
                            int32_t x, int32_t y,
                            int32_t physical_width, int32_t physical_height,
                            int32_t subpixel,
                            const char *make, const char *model,
                            int32_t transform)
{
    (void)data;
    (void)output;
    (void)x;
    (void)y;
    (void)physical_width;
    (void)physical_height;
    (void)subpixel;
    (void)make;
    (void)model;
    (void)transform;
}

static void output_mode(void *data, struct wl_output *output,
                        uint32_t flags, int32_t width,
                        int32_t height, int32_t refresh)
{
    (void)data;
    (void)output;
    (void)flags;
    (void)width;
    (void)height;
    (void)refresh;
}

static void output_done(void *data, struct wl_output *output)
{
    (void)data;
    (void)output;
}

static void output_scale(void *data, struct wl_output *output, int32_t factor)
{
    (void)data;
    (void)output;
    (void)factor;
}

static void output_name(void *data, struct wl_output *output, const char *name)
{
    (void)data;
    (void)output;
    (void)name;
}

static void output_description(void *data, struct wl_output *output,
                               const char *description)
{
    (void)data;
    (void)output;
    (void)description;
}

static const struct wl_output_listener output_listener = {
    .geometry = output_geometry,
    .mode = output_mode,
    .done = output_done,
    .scale = output_scale,
    .name = output_name,
    .description = output_description,
};

static void registry_global(void *data, struct wl_registry *registry, uint32_t name,
                            const char *interface, uint32_t version)
{
    struct app *app = data;
    if (strcmp(interface, wl_compositor_interface.name) == 0) {
        app->compositor = wl_registry_bind(registry, name, &wl_compositor_interface,
                                           version < 4 ? version : 4);
    } else if (strcmp(interface, wl_output_interface.name) == 0 && !app->output) {
        uint32_t bind_version = version < 4 ? version : 4;
        app->output = wl_registry_bind(registry, name, &wl_output_interface,
                                       bind_version);
        wl_output_add_listener(app->output, &output_listener, app);
    } else if (strcmp(interface, wl_shm_interface.name) == 0) {
        app->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
    } else if (strcmp(interface, xdg_wm_base_interface.name) == 0) {
        app->wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface,
                                        version < 6 ? version : 6);
        xdg_wm_base_add_listener(app->wm_base, &wm_base_listener, app);
    } else if (strcmp(interface, wl_seat_interface.name) == 0) {
        app->seat = wl_registry_bind(registry, name, &wl_seat_interface,
                                     version < 5 ? version : 5);
        wl_seat_add_listener(app->seat, &seat_listener, app);
    }
}

static void registry_global_remove(void *data, struct wl_registry *registry,
                                   uint32_t name)
{
    (void)data;
    (void)registry;
    (void)name;
}

static const struct wl_registry_listener registry_listener = {
    .global = registry_global,
    .global_remove = registry_global_remove,
};

int main(void)
{
    struct app app;
    memset(&app, 0, sizeof(app));
    app.running = 1;

    log_line("INSTALLER: starting EpinAnonymOS install entry -- D4.1 START");
    app.display = wl_display_connect(NULL);
    if (!app.display) {
        perror("G11CAIRO: wl_display_connect");
        return 1;
    }

    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);

    if (!app.compositor || !app.shm || !app.wm_base) {
        log_line("G11CAIRO: missing required Wayland globals");
        return 1;
    }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Install EpinAnonymOS to Disk");
    xdg_toplevel_set_app_id(app.toplevel, "epinanonymos-installer");
    xdg_toplevel_set_min_size(app.toplevel, 420, 260);

    wl_surface_commit(app.surface);
    wl_display_flush(app.display);
    log_line("G11CAIRO: requested xdg_toplevel configure");

    while (app.running) {
        /* While installing, don't block on input — drive a batch, refresh the bar, push a
         * frame, and repeat until /config/install.progress reaches 1000. */
        if (app.installing) {
            install_step(&app);
            redraw_commit(&app, "installing");
            if (wl_display_roundtrip(app.display) < 0) break;
            if (app.progress >= 1000) {
                app.installing = 0;
                app.install_done = 1;
                redraw_commit(&app, "install-done");
                wl_display_roundtrip(app.display);
                printf("INSTALLER: install complete (100%%)\n");
            }
            continue;
        }
        int ret = wl_display_dispatch(app.display);
        if (ret < 0) {
            perror("G11CAIRO: wl_display_dispatch");
            break;
        }
        if (app.sync_after_commit) {
            app.sync_after_commit = 0;
            if (wl_display_roundtrip(app.display) < 0)
                perror("G11CAIRO: post-commit roundtrip");
            else
                log_line("G11CAIRO: post-commit roundtrip complete -- G11 SYNC");
        }
    }

    return app.committed ? 0 : 1;
}
