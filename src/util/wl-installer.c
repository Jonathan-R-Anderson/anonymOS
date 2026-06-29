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
    DEFAULT_WIDTH = 760,
    DEFAULT_HEIGHT = 560,
};

enum {
    SCREEN_WELCOME = 0,
    SCREEN_ACCOUNT,
    SCREEN_SECURITY,
    SCREEN_DECOY,
    SCREEN_REVIEW,
    SCREEN_PROGRESS,
};

enum {
    FIELD_HOSTNAME = 0,
    FIELD_REAL_USER,
    FIELD_REAL_PASSWORD,
    FIELD_HIDDEN_PASSWORD,
    FIELD_OUTER_PASSWORD,
    FIELD_DECOY_BOOT_PASSWORD,
    FIELD_DECOY_USER,
    FIELD_DECOY_FULLNAME,
    FIELD_DECOY_PASSWORD,
    FIELD_DECOY_HOSTNAME,
    FIELD_COUNT,
};

enum {
    ENC_NONE = 0,
    ENC_FULL,
    ENC_HIDDEN,
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
    int shift;
    int sync_after_commit;
    int post_map_frame_armed;
    int post_map_frame_done;
    int running;
    int screen;
    int installing;      /* 1 while the install loop is driving batches */
    int install_done;    /* 1 once the install finished */
    int install_failed;  /* 1 if /config/install.action could not be opened */
    int progress;        /* install progress, 0..1000 permille */
    int focused_field;
    int encryption_mode;
    int install_config_written;
    double pointer_x;
    double pointer_y;
    char field_text[FIELD_COUNT][96];
    int field_len[FIELD_COUNT];
};

/* Button hit-rects, computed from the window size so draw + click agree.
 * which: 0 = primary, 1 = secondary, 2 = back. */
enum { BTN_PRIMARY = 0, BTN_SECONDARY = 1, BTN_BACK = 2 };
static void btn_rect(struct app *app, int which,
                     double *x, double *y, double *w, double *h)
{
    double W = app->width, H = app->height;
    *y = H - 76;
    *h = 48;
    if (which == BTN_BACK) {
        *x = 44;
        *w = 132;
        return;
    }
    *w = 170;
    if (which == BTN_SECONDARY)
        *x = W - 44 - *w - 188;
    else
        *x = W - 44 - *w;
}

static void log_line(const char *s)
{
    fputs(s, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static void set_field(struct app *app, int field, const char *value)
{
    if (field < 0 || field >= FIELD_COUNT || !value)
        return;
    size_t n = strlen(value);
    if (n >= sizeof(app->field_text[field]))
        n = sizeof(app->field_text[field]) - 1;
    memcpy(app->field_text[field], value, n);
    app->field_text[field][n] = 0;
    app->field_len[field] = (int)n;
}

static const char *field_label(int field)
{
    switch (field) {
    case FIELD_HOSTNAME: return "Main OS hostname";
    case FIELD_REAL_USER: return "Main OS account";
    case FIELD_REAL_PASSWORD: return "Main OS login password";
    case FIELD_HIDDEN_PASSWORD: return "Hidden OS boot password";
    case FIELD_OUTER_PASSWORD: return "Outer volume password";
    case FIELD_DECOY_BOOT_PASSWORD: return "Decoy OS boot password";
    case FIELD_DECOY_USER: return "Decoy OS account";
    case FIELD_DECOY_FULLNAME: return "Decoy OS full name";
    case FIELD_DECOY_PASSWORD: return "Decoy OS login password";
    case FIELD_DECOY_HOSTNAME: return "Decoy OS hostname";
    default: return "";
    }
}

static int field_secret(int field)
{
    return field == FIELD_REAL_PASSWORD ||
           field == FIELD_HIDDEN_PASSWORD ||
           field == FIELD_OUTER_PASSWORD ||
           field == FIELD_DECOY_BOOT_PASSWORD ||
           field == FIELD_DECOY_PASSWORD;
}

static const char *screen_title(struct app *app)
{
    switch (app->screen) {
    case SCREEN_WELCOME: return "Install EpinAnonymOS";
    case SCREEN_ACCOUNT: return "Main OS Account";
    case SCREEN_SECURITY: return "Encryption";
    case SCREEN_DECOY: return "Decoy OS";
    case SCREEN_REVIEW: return "Review";
    case SCREEN_PROGRESS: return "Installing";
    default: return "Install EpinAnonymOS";
    }
}

static const char *primary_label(struct app *app)
{
    switch (app->screen) {
    case SCREEN_WELCOME: return "Install";
    case SCREEN_REVIEW: return "Install";
    case SCREEN_PROGRESS: return app->install_done ? "Done" : "Installing";
    default: return "Next";
    }
}

static int fields_for_screen(struct app *app, int out[], int max)
{
    int n = 0;
    if (app->screen == SCREEN_ACCOUNT) {
        int f[] = { FIELD_HOSTNAME, FIELD_REAL_USER, FIELD_REAL_PASSWORD };
        for (size_t i = 0; i < sizeof(f) / sizeof(f[0]) && n < max; i++) out[n++] = f[i];
    } else if (app->screen == SCREEN_SECURITY) {
        if (app->encryption_mode == ENC_FULL && n < max)
            out[n++] = FIELD_HIDDEN_PASSWORD;
        if (app->encryption_mode == ENC_HIDDEN) {
            int f[] = { FIELD_HIDDEN_PASSWORD, FIELD_OUTER_PASSWORD, FIELD_DECOY_BOOT_PASSWORD };
            for (size_t i = 0; i < sizeof(f) / sizeof(f[0]) && n < max; i++) out[n++] = f[i];
        }
    } else if (app->screen == SCREEN_DECOY) {
        int f[] = { FIELD_DECOY_USER, FIELD_DECOY_FULLNAME, FIELD_DECOY_PASSWORD, FIELD_DECOY_HOSTNAME };
        for (size_t i = 0; i < sizeof(f) / sizeof(f[0]) && n < max; i++) out[n++] = f[i];
    }
    return n;
}

static void field_rect(struct app *app, int ordinal,
                       double *x, double *y, double *w, double *h)
{
    *x = 260;
    *y = 148 + ordinal * 76;
    *w = app->width - 304;
    *h = 44;
}

static void segment_rect(struct app *app, int which,
                         double *x, double *y, double *w, double *h)
{
    double gap = 10;
    *x = 260 + which * ((app->width - 304 - 2 * gap) / 3.0 + gap);
    *y = 128;
    *w = (app->width - 304 - 2 * gap) / 3.0;
    *h = 44;
}

static void focus_first_field(struct app *app)
{
    int fields[8];
    int n = fields_for_screen(app, fields, 8);
    app->focused_field = n > 0 ? fields[0] : -1;
}

static void cycle_focus(struct app *app)
{
    int fields[8];
    int n = fields_for_screen(app, fields, 8);
    if (n <= 0) {
        app->focused_field = -1;
        return;
    }
    for (int i = 0; i < n; i++) {
        if (fields[i] == app->focused_field) {
            app->focused_field = fields[(i + 1) % n];
            return;
        }
    }
    app->focused_field = fields[0];
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

static void draw_button(struct app *app, cairo_t *cr, int which, const char *label, int enabled)
{
    double x, y, w, h;
    btn_rect(app, which, &x, &y, &w, &h);
    rounded_rect(cr, x, y, w, h, 8);
    if (!enabled)
        cairo_set_source_rgb(cr, 0.23, 0.27, 0.32);
    else if (which == BTN_PRIMARY)
        cairo_set_source_rgb(cr, 0.05, 0.52, 0.48);
    else
        cairo_set_source_rgb(cr, 0.28, 0.33, 0.40);
    cairo_fill(cr);
    draw_text_ft(app, label, (int)x + 26, (int)y + 31, (int)w - 38, 14,
                 enabled ? 0xffffffffu : 0xff9aa3adu);
}

static void draw_steps(struct app *app)
{
    const char *steps[] = { "Welcome", "Account", "Encryption", "Decoy", "Review", "Install" };
    for (int i = 0; i < 6; i++) {
        uint32_t color = (i == app->screen) ? 0xffffffffu : 0xffa9b4c2u;
        draw_text_ft(app, steps[i], 44, 126 + i * 38, 160, 13, color);
    }
}

static void masked_value(struct app *app, int field, char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
        return;
    if (!field_secret(field)) {
        snprintf(out, out_sz, "%s", app->field_text[field]);
        return;
    }
    int n = app->field_len[field];
    if (n <= 0) {
        out[0] = 0;
        return;
    }
    if ((size_t)n >= out_sz)
        n = (int)out_sz - 1;
    for (int i = 0; i < n; i++)
        out[i] = '*';
    out[n] = 0;
}

static void draw_field(struct app *app, cairo_t *cr, int field, int ordinal)
{
    double x, y, w, h;
    field_rect(app, ordinal, &x, &y, &w, &h);
    draw_text_ft(app, field_label(field), (int)x, (int)y - 22, (int)w, 12, 0xffc8d2dfu);
    rounded_rect(cr, x, y, w, h, 7);
    if (field == app->focused_field)
        cairo_set_source_rgb(cr, 0.13, 0.21, 0.28);
    else
        cairo_set_source_rgb(cr, 0.09, 0.14, 0.19);
    cairo_fill(cr);
    if (field == app->focused_field) {
        rounded_rect(cr, x + 0.5, y + 0.5, w - 1, h - 1, 7);
        cairo_set_source_rgb(cr, 0.16, 0.70, 0.62);
        cairo_set_line_width(cr, 1.5);
        cairo_stroke(cr);
    }
    char shown[112];
    masked_value(app, field, shown, sizeof shown);
    if (shown[0])
        draw_text_ft(app, shown, (int)x + 14, (int)y + 29, (int)w - 28, 14, 0xffffffffu);
    else
        draw_text_ft(app, "Required", (int)x + 14, (int)y + 29, (int)w - 28, 14, 0xff778391u);
}

static void draw_segments(struct app *app, cairo_t *cr)
{
    const char *labels[] = { "None", "Full Disk", "Hidden OS" };
    for (int i = 0; i < 3; i++) {
        double x, y, w, h;
        segment_rect(app, i, &x, &y, &w, &h);
        rounded_rect(cr, x, y, w, h, 7);
        if (app->encryption_mode == i)
            cairo_set_source_rgb(cr, 0.05, 0.52, 0.48);
        else
            cairo_set_source_rgb(cr, 0.09, 0.14, 0.19);
        cairo_fill(cr);
        draw_text_ft(app, labels[i], (int)x + 16, (int)y + 28, (int)w - 24, 13, 0xffffffffu);
    }
}

static const char *encryption_name(struct app *app)
{
    if (app->encryption_mode == ENC_FULL)
        return "Full disk";
    if (app->encryption_mode == ENC_HIDDEN)
        return "Hidden OS";
    return "None";
}

static void draw_review(struct app *app)
{
    char line[160];
    snprintf(line, sizeof line, "Main OS: %s on %s", app->field_text[FIELD_REAL_USER],
             app->field_text[FIELD_HOSTNAME]);
    draw_text_ft(app, line, 260, 138, app->width - 304, 14, 0xffffffffu);
    snprintf(line, sizeof line, "Encryption: %s", encryption_name(app));
    draw_text_ft(app, line, 260, 176, app->width - 304, 14, 0xffffffffu);
    if (app->encryption_mode == ENC_HIDDEN) {
        snprintf(line, sizeof line, "Decoy OS: %s on %s", app->field_text[FIELD_DECOY_USER],
                 app->field_text[FIELD_DECOY_HOSTNAME]);
        draw_text_ft(app, line, 260, 214, app->width - 304, 14, 0xffffffffu);
        draw_text_ft(app, "Hidden and decoy boot passwords are set.", 260, 252,
                     app->width - 304, 13, 0xffc8d2dfu);
    }
    draw_text_ft(app, "The disk will be overwritten when you continue.", 260, 318,
                 app->width - 304, 13, 0xffffd08au);
}

static void draw_progress(struct app *app, cairo_t *cr)
{
    const char *line1, *line2;
    if (app->install_failed) {
        line1 = "Install unavailable on this image.";
        line2 = "Boot hos-install.iso to install.";
    } else if (app->install_done) {
        line1 = "Installation complete.";
        line2 = "Power off, remove the install medium, then boot the disk.";
    } else {
        line1 = "Installing EpinAnonymOS to the target disk...";
        line2 = "Writing the GPT, EFI System Partition, and boot image.";
    }
    draw_text_ft(app, line1, 260, 138, app->width - 304, 14, 0xffffffffu);
    draw_text_ft(app, line2, 260, 166, app->width - 304, 13, 0xffc8d2dfu);

    double pbx = 260, pbw = app->width - 304, pbh = 20, pby = 228;
    rounded_rect(cr, pbx, pby, pbw, pbh, 8);
    cairo_set_source_rgb(cr, 0.09, 0.14, 0.19);
    cairo_fill(cr);
    int pg = app->progress; if (pg < 0) pg = 0; if (pg > 1000) pg = 1000;
    double fillw = pbw * pg / 1000.0;
    if (fillw > 1.0) {
        rounded_rect(cr, pbx, pby, fillw, pbh, 8);
        if (app->install_failed) cairo_set_source_rgb(cr, 0.80, 0.30, 0.25);
        else if (app->install_done) cairo_set_source_rgb(cr, 0.20, 0.68, 0.45);
        else cairo_set_source_rgb(cr, 0.05, 0.52, 0.48);
        cairo_fill(cr);
    }
    char pct[16];
    int p10 = pg / 10;
    snprintf(pct, sizeof pct, "%d%%", p10 > 100 ? 100 : p10);
    draw_text_ft(app, pct, app->width - 96, 204, 80, 14, 0xffffffffu);
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

    cairo_rectangle(cr, 0, 0, app->width, app->height);
    cairo_set_source_rgb(cr, 0.06, 0.08, 0.10);
    cairo_fill(cr);
    cairo_rectangle(cr, 0, 0, 220, app->height);
    cairo_set_source_rgb(cr, 0.09, 0.13, 0.17);
    cairo_fill(cr);
    cairo_rectangle(cr, 220, 0, app->width - 220, app->height);
    cairo_set_source_rgb(cr, 0.07, 0.10, 0.13);
    cairo_fill(cr);

    draw_button(app, cr, BTN_PRIMARY, primary_label(app),
                app->screen != SCREEN_PROGRESS || app->install_done);
    if (app->screen == SCREEN_WELCOME)
        draw_button(app, cr, BTN_SECONDARY, "Try Live", 1);
    if (app->screen != SCREEN_WELCOME && app->screen != SCREEN_PROGRESS)
        draw_button(app, cr, BTN_BACK, "Back", 1);

    if (app->screen == SCREEN_SECURITY)
        draw_segments(app, cr);

    int fields[8];
    int n = fields_for_screen(app, fields, 8);
    for (int i = 0; i < n; i++)
        draw_field(app, cr, fields[i], i + (app->screen == SCREEN_SECURITY ? 1 : 0));

    if (app->screen == SCREEN_PROGRESS)
        draw_progress(app, cr);

    cairo_destroy(cr);
    cairo_surface_flush(surface);
    cairo_surface_destroy(surface);

    draw_text_ft(app, "EpinAnonymOS", 44, 58, 160, 22, 0xffffffffu);
    draw_steps(app);
    draw_text_ft(app, screen_title(app), 260, 58, app->width - 304, 24, 0xffffffffu);

    if (app->screen == SCREEN_WELCOME) {
        draw_text_ft(app, "Choose the installation settings before anything is written to disk.",
                     260, 124, app->width - 304, 14, 0xffc8d2dfu);
        draw_text_ft(app, "This installer collects the main account, encryption mode, hidden OS password, and decoy OS account.",
                     260, 164, app->width - 304, 13, 0xffc8d2dfu);
    } else if (app->screen == SCREEN_SECURITY) {
        if (app->encryption_mode == ENC_NONE)
            draw_text_ft(app, "No disk encryption will be configured.", 260, 220, app->width - 304, 13, 0xffc8d2dfu);
        else if (app->encryption_mode == ENC_FULL)
            draw_text_ft(app, "Set the password used to unlock the installed OS at boot.", 260, 300, app->width - 304, 13, 0xffc8d2dfu);
    } else if (app->screen == SCREEN_REVIEW) {
        draw_review(app);
    }
}

static void buffer_release(void *data, struct wl_buffer *buffer)
{
    struct app *app = data;
    if (app->buffer == buffer)
        app->buffer = NULL;
    wl_buffer_destroy(buffer);
}

static const struct wl_buffer_listener buffer_listener = {
    .release = buffer_release,
};

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

    wl_buffer_add_listener(buffer, &buffer_listener, app);
    app->buffer = buffer;
    return 0;
}

static void redraw_commit(struct app *app, const char *marker)
{
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

static void write_all_len(int fd, const char *s, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, s, len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return;
        s += n;
        len -= (size_t)n;
    }
}

static void append_mem(char *buf, size_t cap, size_t *pos, const char *s, size_t len)
{
    if (*pos >= cap)
        return;
    if (len > cap - *pos)
        len = cap - *pos;
    memcpy(buf + *pos, s, len);
    *pos += len;
}

static void append_cstr(char *buf, size_t cap, size_t *pos, const char *s)
{
    append_mem(buf, cap, pos, s, strlen(s));
}

static void append_json_string(char *buf, size_t cap, size_t *pos,
                               const char *key, const char *value, int comma)
{
    append_cstr(buf, cap, pos, "  \"");
    append_cstr(buf, cap, pos, key);
    append_cstr(buf, cap, pos, "\": \"");
    for (const unsigned char *p = (const unsigned char *)value; p && *p; p++) {
        char b[8];
        if (*p == '"' || *p == '\\') {
            b[0] = '\\'; b[1] = (char)*p; b[2] = 0;
            append_cstr(buf, cap, pos, b);
        } else if (*p >= 0x20 && *p < 0x7f) {
            b[0] = (char)*p; b[1] = 0;
            append_cstr(buf, cap, pos, b);
        }
    }
    append_cstr(buf, cap, pos, comma ? "\",\n" : "\"\n");
}

#define INSTALL_CONFIG_MAX 4096

static size_t build_install_config(struct app *app, char *buf, size_t cap)
{
    size_t pos = 0;
    if (cap == 0)
        return 0;
    append_cstr(buf, cap, &pos, "{\n");
    append_json_string(buf, cap, &pos, "schema", "epin.install.v1", 1);
    append_json_string(buf, cap, &pos, "hostname", app->field_text[FIELD_HOSTNAME], 1);
    append_json_string(buf, cap, &pos, "user", app->field_text[FIELD_REAL_USER], 1);
    append_json_string(buf, cap, &pos, "userPassword", app->field_text[FIELD_REAL_PASSWORD], 1);
    append_json_string(buf, cap, &pos, "encryption", encryption_name(app), 1);
    append_json_string(buf, cap, &pos, "hiddenPassword", app->field_text[FIELD_HIDDEN_PASSWORD], 1);
    append_json_string(buf, cap, &pos, "outerPassword", app->field_text[FIELD_OUTER_PASSWORD], 1);
    append_json_string(buf, cap, &pos, "decoyBootPassword", app->field_text[FIELD_DECOY_BOOT_PASSWORD], 1);
    append_json_string(buf, cap, &pos, "decoyUser", app->field_text[FIELD_DECOY_USER], 1);
    append_json_string(buf, cap, &pos, "decoyFullName", app->field_text[FIELD_DECOY_FULLNAME], 1);
    append_json_string(buf, cap, &pos, "decoyPassword", app->field_text[FIELD_DECOY_PASSWORD], 1);
    append_json_string(buf, cap, &pos, "decoyHostname", app->field_text[FIELD_DECOY_HOSTNAME], 0);
    append_cstr(buf, cap, &pos, "}\n");
    if (pos >= cap)
        pos = cap - 1;
    buf[pos] = 0;
    return pos;
}

static int write_install_config(struct app *app)
{
    char json[INSTALL_CONFIG_MAX];
    char command[INSTALL_CONFIG_MAX + 8];
    const size_t json_len = build_install_config(app, json, sizeof json);
    if (json_len == 0)
        return 0;

    int fd = open("/tmp/install.json", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        write_all_len(fd, json, json_len);
        close(fd);
    }

    memcpy(command, "config ", 7);
    memcpy(command + 7, json, json_len);
    int cfd = open("/config/install.action", O_WRONLY);
    if (cfd < 0)
        return 0;
    write_all_len(cfd, command, json_len + 7);
    close(cfd);
    app->install_config_written = 1;
    return 1;
}

static void start_install(struct app *app)
{
    int config_ok = write_install_config(app);
    app->screen = SCREEN_PROGRESS;
    app->progress = 0;
    app->install_done = 0;
    int fd = open("/config/install.action", O_WRONLY);
    if (fd >= 0 && config_ok) {
        close(fd);
        app->installing = 1;
        app->install_failed = 0;
        printf("INSTALLER: starting install with wizard config (%s encryption)\n", encryption_name(app));
    } else {
        if (fd >= 0)
            close(fd);
        app->installing = 0;
        app->install_failed = 1;
        printf("INSTALLER: no /config/install.action (boot hos-install.iso)\n");
    }
    fflush(stdout);
    redraw_commit(app, "install-info");
}

static void go_next(struct app *app)
{
    if (app->screen == SCREEN_WELCOME)
        app->screen = SCREEN_ACCOUNT;
    else if (app->screen == SCREEN_ACCOUNT)
        app->screen = SCREEN_SECURITY;
    else if (app->screen == SCREEN_SECURITY)
        app->screen = app->encryption_mode == ENC_HIDDEN ? SCREEN_DECOY : SCREEN_REVIEW;
    else if (app->screen == SCREEN_DECOY)
        app->screen = SCREEN_REVIEW;
    else if (app->screen == SCREEN_REVIEW) {
        start_install(app);
        return;
    }
    focus_first_field(app);
    redraw_commit(app, "next");
}

static void go_back(struct app *app)
{
    if (app->screen == SCREEN_ACCOUNT)
        app->screen = SCREEN_WELCOME;
    else if (app->screen == SCREEN_SECURITY)
        app->screen = SCREEN_ACCOUNT;
    else if (app->screen == SCREEN_DECOY)
        app->screen = SCREEN_SECURITY;
    else if (app->screen == SCREEN_REVIEW)
        app->screen = app->encryption_mode == ENC_HIDDEN ? SCREEN_DECOY : SCREEN_SECURITY;
    focus_first_field(app);
    redraw_commit(app, "back");
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
    if (code == 15) {
        cycle_focus(app);
        redraw_commit(app, "field focus");
        return;
    }
    if (code == 14) {
        int f = app->focused_field;
        if (f >= 0 && f < FIELD_COUNT && app->field_len[f] > 0)
            app->field_text[f][--app->field_len[f]] = 0;
        redraw_commit(app, "entry edit");
        return;
    }
    if (code == 28) {
        if (app->screen != SCREEN_PROGRESS)
            go_next(app);
        return;
    }
    int f = app->focused_field;
    if (f < 0 || f >= FIELD_COUNT)
        return;
    if (code >= sizeof(keymap_plain))
        return;
    char ch = app->shift ? keymap_shift[code] : keymap_plain[code];
    if (!ch || app->field_len[f] >= (int)sizeof(app->field_text[f]) - 1)
        return;
    app->field_text[f][app->field_len[f]++] = ch;
    app->field_text[f][app->field_len[f]] = 0;
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
    if (app->screen == SCREEN_WELCOME) {
        btn_rect(app, BTN_SECONDARY, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h)) {
            /* Try Live Session: close the installer -> the live desktop behind it. */
            printf("INSTALLER: 'Try Live Session' -- closing to the live desktop\n");
            app->running = 0;
            return;
        }
        btn_rect(app, BTN_PRIMARY, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h)) {
            go_next(app);
            return;
        }
        return;
    }

    if (app->screen == SCREEN_PROGRESS) {
        if (app->installing) return;     /* can't go back mid-install */
        btn_rect(app, BTN_PRIMARY, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h)) {
            if (app->install_done) { app->running = 0; return; }
            return;
        }
        return;
    }

    if (app->screen == SCREEN_SECURITY) {
        for (int i = 0; i < 3; i++) {
            segment_rect(app, i, &x, &y, &w, &h);
            if (in_rect(app, x, y, w, h)) {
                app->encryption_mode = i;
                focus_first_field(app);
                redraw_commit(app, "encryption");
                return;
            }
        }
    }

    int fields[8];
    int n = fields_for_screen(app, fields, 8);
    for (int i = 0; i < n; i++) {
        field_rect(app, i + (app->screen == SCREEN_SECURITY ? 1 : 0), &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h)) {
            app->focused_field = fields[i];
            app->entry_focused = 1;
            redraw_commit(app, "field focus");
            return;
        }
    }

    btn_rect(app, BTN_BACK, &x, &y, &w, &h);
    if (in_rect(app, x, y, w, h)) {
        go_back(app);
        return;
    }
    btn_rect(app, BTN_PRIMARY, &x, &y, &w, &h);
    if (in_rect(app, x, y, w, h)) {
        go_next(app);
        return;
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
    app.screen = SCREEN_WELCOME;
    app.focused_field = -1;
    app.encryption_mode = ENC_HIDDEN;
    set_field(&app, FIELD_HOSTNAME, "epin");
    set_field(&app, FIELD_REAL_USER, "user");
    set_field(&app, FIELD_DECOY_USER, "decoy");
    set_field(&app, FIELD_DECOY_FULLNAME, "Decoy User");
    set_field(&app, FIELD_DECOY_HOSTNAME, "decoy-pc");

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
    xdg_toplevel_set_min_size(app.toplevel, DEFAULT_WIDTH, DEFAULT_HEIGHT);

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
