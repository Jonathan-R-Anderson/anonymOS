// wl-files.c — GUI roadmap G17: a minimal Cairo/FreeType Wayland file manager.
//
// A Finder/Nautilus-style browser: a left "Places" sidebar, a toolbar with a
// back button and the current path, and a main pane that lists the current
// directory's folders and files with vector icons. Navigation: click a place or
// the back button, double-click a folder (or press Enter on it) to open it.
// Window decorations (titlebar/controls/shadow/border) are supplied by the
// compositor (G16); this client only paints its content surface.
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include <cairo/cairo.h>
#include <ft2build.h>
#include FT_FREETYPE_H

#include "xdg-shell-client-protocol.h"
#include "wl-deco.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum {
    DEFAULT_WIDTH  = 760,
    DEFAULT_HEIGHT = 480,
    SIDEBAR_W      = 172,
    TOOLBAR_H      = 46,
    STATUS_H       = 26,
    ROW_H          = 30,
    MAX_ENTRIES    = 512,
};

struct entry {
    char name[256];
    int  is_dir;
    int  is_up;
    long long size;      /* bytes, from stat(); -1 when unknown */
};

struct place {
    const char *label;
    const char *path;
};

static const struct place PLACES[] = {
    {"Home", "/"},
    {"System", "/usr"},
    {"Share", "/usr/share"},
    {"Fonts", "/usr/share/fonts"},
    {"Themes", "/usr/share/themes"},
    {"Backgrounds", "/usr/share/backgrounds"},
    {"Config", "/etc"},
};
enum { N_PLACES = (int)(sizeof(PLACES) / sizeof(PLACES[0])) };

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_output *output;
    struct wl_shm *shm;
    struct wl_seat *seat;
    int maximized;
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
    int sync_after_commit;
    int post_map_frame_armed;
    int post_map_frame_done;
    int running;
    double pointer_x;
    double pointer_y;

    char cwd[512];
    struct entry entries[MAX_ENTRIES];
    int  n_entries;
    int  sel;
    int  scroll;       // first visible list row
    int  place_sel;
    double last_click_t;
    int    last_click_row;

    /* APPS B5 — File Search.  Filtering happens at LOAD time (read_dir skips non-matching
     * names) rather than through a separate index array, so every existing consumer of
     * entries[]/n_entries -- the draw loop, hit-testing, double-click, keyboard selection --
     * keeps working untouched.  A filter-index indirection would have required changing all
     * of them, for no visible benefit at 512 entries.
     *
     * The roadmap recorded this item as blocked on "wl-files has no wl_keyboard listener at
     * all, so typing needs the whole xkb path added first".  That was wrong on both counts:
     * the listener has always been here (kb_key already drives Up/Down/Enter/Backspace), and
     * no client in this tree uses xkb -- all 17 map raw evdev keycodes directly. */
    char search[64];
    int  search_len;
    int  searching;      /* 1 = typing a filter; keys go to the box, not to navigation */
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

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
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
    printf("G17FILES: loaded %s (%zu bytes) -- G17 FONT\n", path, app->font_size);
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

static void path_join(char *out, size_t n, const char *dir, const char *name)
{
    if (strcmp(dir, "/") == 0)
        snprintf(out, n, "/%s", name);
    else
        snprintf(out, n, "%s/%s", dir, name);
}

static int entry_cmp(const void *a, const void *b)
{
    const struct entry *ea = a, *eb = b;
    if (ea->is_up != eb->is_up)
        return ea->is_up ? -1 : 1;
    if (ea->is_dir != eb->is_dir)
        return ea->is_dir ? -1 : 1;
    return strcasecmp(ea->name, eb->name);
}

/* Human-readable byte count.  Directories and unstattable entries get an empty string rather
 * than a zero, so the column never asserts a size it does not know. */
static void human_size(char *out, size_t cap, long long b)
{
    if (b < 0)              { out[0] = 0; return; }
    if (b < 1024)             snprintf(out, cap, "%lld B", b);
    else if (b < 1024LL*1024) snprintf(out, cap, "%.1f KB", (double)b / 1024.0);
    else if (b < 1024LL*1024*1024) snprintf(out, cap, "%.1f MB", (double)b / (1024.0*1024.0));
    else                      snprintf(out, cap, "%.1f GB", (double)b / (1024.0*1024.0*1024.0));
}

/* Case-insensitive substring test for the File Search filter.  Written out rather than using
 * strcasestr(), which is a GNU extension and not in musl's default namespace here. */
static int name_matches(const char *name, const char *needle)
{
    if (!needle[0])
        return 1;
    for (const char *h = name; *h; h++) {
        const char *a = h, *b = needle;
        while (*a && *b) {
            int ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
            int cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
            if (ca != cb)
                break;
            a++; b++;
        }
        if (!*b)
            return 1;
    }
    return 0;
}

/* Raw evdev keycode -> ASCII, for the search box.  Same table as wl-logview's filter entry;
 * no xkb involved, which is how every client in this tree reads the keyboard. */
static char files_keycode_ascii(uint32_t k)
{
    static const char row1[] = "1234567890-=";   /* keycodes  2..13 */
    static const char row2[] = "qwertyuiop[]";   /* keycodes 16..27 */
    static const char row3[] = "asdfghjkl;'";    /* keycodes 30..40 */
    static const char row4[] = "zxcvbnm,./";     /* keycodes 44..53 */
    if (k >= 2  && k <= 13) return row1[k - 2];
    if (k >= 16 && k <= 27) return row2[k - 16];
    if (k >= 30 && k <= 40) return row3[k - 30];
    if (k >= 44 && k <= 53) return row4[k - 44];
    if (k == 57) return ' ';
    return 0;
}

static void read_dir(struct app *app)
{
    app->n_entries = 0;
    app->sel = 0;
    app->scroll = 0;

    if (strcmp(app->cwd, "/") != 0) {
        struct entry *e = &app->entries[app->n_entries++];
        snprintf(e->name, sizeof(e->name), "..");
        e->is_dir = 1;
        e->is_up = 1;
        e->size = -1;
    }

    DIR *d = opendir(app->cwd);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL && app->n_entries < MAX_ENTRIES) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
            /* stat() unconditionally now: the size column needs it, and it also settles is_dir
             * without trusting d_type (which is DT_UNKNOWN on several filesystems here). */
            char p[512];
            struct stat st;
            int have = 0;
            path_join(p, sizeof(p), app->cwd, de->d_name);
            if (stat(p, &st) == 0)
                have = 1;
            int is_dir = 0;
            if (have)
                is_dir = S_ISDIR(st.st_mode) ? 1 : 0;
#ifdef DT_DIR
            else if (de->d_type == DT_DIR)
                is_dir = 1;
#endif
            /* File Search: skip names that do not contain the filter, case-insensitively.
             * ".." is added before this loop and is deliberately never filtered out, so there
             * is always a way back up even when the filter matches nothing. */
            if (app->search_len > 0 && !name_matches(de->d_name, app->search))
                continue;

            struct entry *e = &app->entries[app->n_entries++];
            snprintf(e->name, sizeof(e->name), "%s", de->d_name);
            e->is_dir = is_dir;
            e->is_up = 0;
            e->size = (have && !is_dir) ? (long long)st.st_size : -1;
        }
        closedir(d);
    }

    qsort(app->entries, (size_t)app->n_entries, sizeof(struct entry), entry_cmp);
    printf("G17FILES: listed %s (%d entries) -- G17 LIST\n", app->cwd, app->n_entries);
    fflush(stdout);
}

static void navigate(struct app *app, const char *path)
{
    if (!path || !path[0])
        return;
    /* A filter belongs to the directory it was typed in.  Carrying it into a new one hides
     * most of the destination for no reason the user asked for. */
    app->searching = 0;
    app->search_len = 0;
    app->search[0] = 0;
    snprintf(app->cwd, sizeof(app->cwd), "%s", path);
    read_dir(app);
}

static void go_up(struct app *app)
{
    if (strcmp(app->cwd, "/") == 0)
        return;
    app->searching = 0;
    app->search_len = 0;
    app->search[0] = 0;
    char *slash = strrchr(app->cwd, '/');
    if (!slash)
        return;
    if (slash == app->cwd)
        app->cwd[1] = '\0';
    else
        *slash = '\0';
    read_dir(app);
}

static void open_entry(struct app *app, int idx)
{
    if (idx < 0 || idx >= app->n_entries)
        return;
    struct entry *e = &app->entries[idx];
    if (e->is_up) {
        go_up(app);
        return;
    }
    if (e->is_dir) {
        char p[512];
        path_join(p, sizeof(p), app->cwd, e->name);
        navigate(app, p);
    }
}

static int list_visible_rows(struct app *app)
{
    return (app->height - TOOLBAR_H - STATUS_H) / ROW_H;
}

// --- icons ---------------------------------------------------------------

static void draw_folder_icon(cairo_t *cr, double x, double y, double s)
{
    cairo_set_source_rgb(cr, 0.93, 0.74, 0.33);
    rounded_rect(cr, x, y + s * 0.18, s, s * 0.66, s * 0.10);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.86, 0.66, 0.26);
    rounded_rect(cr, x, y + s * 0.08, s * 0.5, s * 0.28, s * 0.08);
    cairo_fill(cr);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.22);
    rounded_rect(cr, x + s * 0.06, y + s * 0.26, s - s * 0.12, s * 0.12, s * 0.05);
    cairo_fill(cr);
}

static void draw_file_icon(cairo_t *cr, double x, double y, double s)
{
    const double w = s * 0.74, h = s * 0.86;
    const double ix = x + (s - w) / 2, iy = y + (s - h) / 2;
    const double fold = s * 0.24;
    cairo_set_source_rgb(cr, 0.98, 0.98, 1.0);
    cairo_move_to(cr, ix, iy);
    cairo_line_to(cr, ix + w - fold, iy);
    cairo_line_to(cr, ix + w, iy + fold);
    cairo_line_to(cr, ix + w, iy + h);
    cairo_line_to(cr, ix, iy + h);
    cairo_close_path(cr);
    cairo_fill_preserve(cr);
    cairo_set_source_rgb(cr, 0.62, 0.66, 0.74);
    cairo_set_line_width(cr, 1.2);
    cairo_stroke(cr);
    cairo_set_source_rgb(cr, 0.80, 0.84, 0.90);
    cairo_move_to(cr, ix + w - fold, iy);
    cairo_line_to(cr, ix + w - fold, iy + fold);
    cairo_line_to(cr, ix + w, iy + fold);
    cairo_stroke(cr);
}

static void draw_files(struct app *app)
{
    const int vis   = list_visible_rows(app);
    const int x0    = SIDEBAR_W;
    const int listw = app->width - SIDEBAR_W;

    // --- Pass 1: all Cairo shapes/icons (one surface; matches wl-cairo-demo,
    // which destroys the surface before any direct-to-buffer text so the two
    // do not fight over the shared pixels). ---
    cairo_surface_t *surface = cairo_image_surface_create_for_data(
        (unsigned char *)app->pixels, CAIRO_FORMAT_RGB24, app->width, app->height, app->stride);
    cairo_t *cr = cairo_create(surface);

    cairo_set_source_rgb(cr, 0.96, 0.97, 0.98);
    cairo_paint(cr);

    // Sidebar.
    cairo_set_source_rgb(cr, 0.90, 0.92, 0.95);
    cairo_rectangle(cr, 0, 0, SIDEBAR_W, app->height);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.82, 0.85, 0.89);
    cairo_rectangle(cr, SIDEBAR_W - 1, 0, 1, app->height);
    cairo_fill(cr);
    for (int i = 0; i < N_PLACES; i++) {
        int ry = 36 + i * 34;
        if (i == app->place_sel) {
            cairo_set_source_rgba(cr, 0.22, 0.51, 0.92, 0.16);
            rounded_rect(cr, 8, ry, SIDEBAR_W - 16, 30, 8);
            cairo_fill(cr);
        }
        draw_folder_icon(cr, 16, ry + 5, 20);
    }

    // Toolbar.
    cairo_set_source_rgb(cr, 0.99, 0.99, 1.0);
    cairo_rectangle(cr, SIDEBAR_W, 0, app->width - SIDEBAR_W, TOOLBAR_H);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.86, 0.88, 0.92);
    cairo_rectangle(cr, SIDEBAR_W, TOOLBAR_H - 1, app->width - SIDEBAR_W, 1);
    cairo_fill(cr);
    rounded_rect(cr, SIDEBAR_W + 12, 9, 30, 28, 7);
    cairo_set_source_rgb(cr, 0.93, 0.94, 0.96);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.30, 0.36, 0.44);
    cairo_set_line_width(cr, 2.4);
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    cairo_move_to(cr, SIDEBAR_W + 31, 16);
    cairo_line_to(cr, SIDEBAR_W + 24, 23);
    cairo_line_to(cr, SIDEBAR_W + 31, 30);
    cairo_stroke(cr);
    rounded_rect(cr, SIDEBAR_W + 52, 9, app->width - SIDEBAR_W - 64 - 3 * DECO_BTN_H, 28, 7);
    cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    cairo_fill_preserve(cr);
    cairo_set_source_rgb(cr, 0.84, 0.87, 0.91);
    cairo_set_line_width(cr, 1.0);
    cairo_stroke(cr);

    // File list rows.
    for (int r = 0; r < vis; r++) {
        int idx = app->scroll + r;
        if (idx >= app->n_entries)
            break;
        struct entry *e = &app->entries[idx];
        int ry = TOOLBAR_H + r * ROW_H;
        if (idx == app->sel) {
            cairo_set_source_rgb(cr, 0.22, 0.51, 0.92);
            cairo_rectangle(cr, x0, ry, listw, ROW_H);
            cairo_fill(cr);
        } else if (r & 1) {
            cairo_set_source_rgb(cr, 0.965, 0.972, 0.982);
            cairo_rectangle(cr, x0, ry, listw, ROW_H);
            cairo_fill(cr);
        }
        if (e->is_dir)
            draw_folder_icon(cr, x0 + 12, ry + 5, 20);
        else
            draw_file_icon(cr, x0 + 12, ry + 5, 20);
    }

    // Status bar + identity chip.
    cairo_set_source_rgb(cr, 0.90, 0.92, 0.95);
    cairo_rectangle(cr, 0, app->height - STATUS_H, app->width, STATUS_H);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.82, 0.85, 0.89);
    cairo_rectangle(cr, 0, app->height - STATUS_H, app->width, 1);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.30, 0.76, 0.66);
    rounded_rect(cr, 10, app->height - STATUS_H + 6, 12, 12, 3);
    cairo_fill(cr);

    cairo_destroy(cr);
    cairo_surface_flush(surface);
    cairo_surface_destroy(surface);

    // --- Pass 2: all antialiased text directly into the buffer. ---
    draw_text(app, "PLACES", 16, 14, SIDEBAR_W - 24, 11, 0xff7a828fu);
    for (int i = 0; i < N_PLACES; i++) {
        int ry = 36 + i * 34;
        draw_text(app, PLACES[i].label, 46, ry + 8, SIDEBAR_W - 56, 13,
                  i == app->place_sel ? 0xff1b2430u : 0xff37404bu);
    }
    draw_text(app, app->cwd, SIDEBAR_W + 64, 17, app->width - SIDEBAR_W - 84 - 3 * DECO_BTN_H, 13, 0xff2a3340u);
    for (int r = 0; r < vis; r++) {
        int idx = app->scroll + r;
        if (idx >= app->n_entries)
            break;
        struct entry *e = &app->entries[idx];
        int ry = TOOLBAR_H + r * ROW_H;
        uint32_t col = (idx == app->sel) ? 0xffffffffu : (e->is_dir ? 0xff1c2530u : 0xff39424eu);
        draw_text(app, e->name, x0 + 42, ry + 8, listw - 150, 13, col);
        char szbuf[32];
        human_size(szbuf, sizeof szbuf, e->size);
        if (szbuf[0])
            draw_text(app, szbuf, x0 + listw - 96, ry + 8, 88, 12, col);
    }
    char status[160];
    /* Free space is real (statvfs on the current directory).  The identity/domain text that used
     * to sit here was hardcoded "system"/"trusted" regardless of the actual domain, so it is gone
     * rather than left asserting something this client never queried. */
    struct statvfs vfs;
    char freebuf[64];
    if (statvfs(app->cwd, &vfs) == 0 && vfs.f_blocks > 0) {
        char f[32], t[32];
        human_size(f, sizeof f, (long long)vfs.f_bavail * (long long)vfs.f_frsize);
        human_size(t, sizeof t, (long long)vfs.f_blocks * (long long)vfs.f_frsize);
        snprintf(freebuf, sizeof freebuf, "   %s free of %s", f, t);
    } else freebuf[0] = 0;
    /* File Search state lives in the status bar rather than a floating box: this window has no
     * resize path (see roadmap 3.2), so anything that changes the layout risks the fixed-pixel
     * collapse the domain manager documents.  A status line costs no geometry.
     * The filter is applied in read_dir(), so n_entries is already the MATCH count. */
    if (app->searching)
        snprintf(status, sizeof(status), "Search: %s_   %d match%s   (Esc clears)",
                 app->search, app->n_entries,
                 app->n_entries == 1 ? "" : "es");
    else
        snprintf(status, sizeof(status), "%d items%s   —   press / to search",
                 app->n_entries, freebuf);
    draw_text(app, status, 28, app->height - STATUS_H + 6, app->width - 40, 11,
              app->searching ? 0xff2a6fd6u : 0xff48515du);

    // window-control buttons (minimize / maximize / close) at the top-right.
    wl_deco_draw(app->pixels, app->width, app->width, app->height, 0xff7a828fu);
}

// Create the shm buffer ONCE and keep it mapped (app->pixels IS the shared
// memory).  Creating a fresh memfd per frame leaked the kernel's small pool of
// memfd slots (the compositor holds each buffer's fd), freezing the whole desktop
// after a few dozen redraws.  Now: one memfd, draw in place, re-attach+commit.
static int create_buffer_once(struct app *app)
{
    if (app->buffer)
        return 0;
    int fd = create_memfd("epin-g17-files");
    if (fd < 0) {
        perror("G17FILES: memfd_create");
        return -1;
    }
    if (ftruncate(fd, (off_t)app->buffer_size) < 0) {
        perror("G17FILES: ftruncate");
        close(fd);
        return -1;
    }
    app->pixels = (uint32_t *)mmap(NULL, app->buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (app->pixels == MAP_FAILED) {
        perror("G17FILES: mmap");
        close(fd);
        app->pixels = NULL;
        return -1;
    }
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int)app->buffer_size);
    app->buffer = wl_shm_pool_create_buffer(pool, 0, app->width, app->height,
                                            app->stride, WL_SHM_FORMAT_XRGB8888);
    wl_shm_pool_destroy(pool);
    close(fd);
    if (!app->buffer) {
        log_line("G17FILES: wl_shm_pool_create_buffer failed");
        return -1;
    }
    return 0;
}

static void redraw_commit(struct app *app, const char *marker)
{
    if (!app->buffer || !app->pixels)
        return;
    draw_files(app);                   // draw directly into the persistent shared buffer
    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    if (marker) {
        printf("G17FILES: %s -- G17 INPUT\n", marker);
        fflush(stdout);
    }
}

static int create_shm_buffer(struct app *app, int width, int height)
{
    app->width = width > 0 ? width : DEFAULT_WIDTH;
    app->height = height > 0 ? height : DEFAULT_HEIGHT;
    app->stride = app->width * 4;
    app->buffer_size = (size_t)app->stride * (size_t)app->height;
    if (!app->font_ready)
        init_freetype(app);
    if (create_buffer_once(app) < 0)
        return -1;
    draw_files(app);
    return 0;
}

// Compositor-driven resize (tiling WM): tear down the persistent buffer and its
// mapping, then rebuild at the new geometry.  The directory list reflows for
// free because draw_files() derives every layout metric from app->width/height.
// munmap MUST run before create_shm_buffer overwrites app->buffer_size, so it
// uses the OLD size that is still live here.
static int resize_buffer(struct app *app, int width, int height)
{
    if (app->buffer) {
        wl_buffer_destroy(app->buffer);
        app->buffer = NULL;
    }
    if (app->pixels && app->pixels != MAP_FAILED) {
        munmap(app->pixels, app->buffer_size);
        app->pixels = NULL;
    }
    // Pre-clamp the scroll offset for the new row count so the reflowed list
    // stays in range once draw_files() runs inside create_shm_buffer().
    {
        int h = height > 0 ? height : DEFAULT_HEIGHT;
        int vis = (h - TOOLBAR_H - STATUS_H) / ROW_H;
        if (vis < 1)
            vis = 1;
        if (app->scroll > app->n_entries - vis)
            app->scroll = app->n_entries - vis;
        if (app->scroll < 0)
            app->scroll = 0;
    }
    return create_shm_buffer(app, width, height);
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
    draw_files(app);
    if (app->buffer) {
        wl_surface_attach(app->surface, app->buffer, 0, 0);
        wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
        wl_surface_commit(app->surface);
    }
    printf("G17FILES: post-map redraw committed %dx%d -- G17 REDRAW\n", app->width, app->height);
    fflush(stdout);
}
static const struct wl_callback_listener frame_listener = {.done = frame_done};

static void xdg_surface_configure(void *data, struct xdg_surface *surface, uint32_t serial)
{
    struct app *app = data;
    xdg_surface_ack_configure(surface, serial);

    // Honor the compositor's (tiling WM) suggested size so the window fills its
    // tile; fall back to the natural size when the compositor sends 0x0.
    int want_w = app->pending_width  > 0 ? app->pending_width  : DEFAULT_WIDTH;
    int want_h = app->pending_height > 0 ? app->pending_height : DEFAULT_HEIGHT;

    if (app->committed) {
        // Post-map resize: only rebuild when the tile size actually changed.
        if (want_w == app->width && want_h == app->height)
            return;
        if (resize_buffer(app, want_w, want_h) < 0) {
            log_line("G17FILES: resize_buffer failed");
            return;
        }
        wl_surface_attach(app->surface, app->buffer, 0, 0);
        wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
        wl_surface_commit(app->surface);
        wl_display_flush(app->display);
        printf("G17FILES: resized wl_shm window %dx%d -- G17 RESIZE\n", app->width, app->height);
        fflush(stdout);
        return;
    }

    // First commit: map at the configured size and reflow the list to fit.
    if (create_shm_buffer(app, want_w, want_h) < 0) {
        log_line("G17FILES: create_shm_buffer failed");
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
    printf("G17FILES: committed wl_shm window %dx%d -- G17 COMMIT\n", app->width, app->height);
    fflush(stdout);
}
static const struct xdg_surface_listener xdg_surface_listener = {.configure = xdg_surface_configure};

// --- input ---------------------------------------------------------------

static void handle_click(struct app *app)
{
    double x = app->pointer_x, y = app->pointer_y;

    // Sidebar place click.
    if (x < SIDEBAR_W) {
        for (int i = 0; i < N_PLACES; i++) {
            int ry = 36 + i * 34;
            if (y >= ry && y <= ry + 30) {
                app->place_sel = i;
                navigate(app, PLACES[i].path);
                redraw_commit(app, "place");
                return;
            }
        }
        return;
    }

    // Back button.
    if (y < TOOLBAR_H) {
        if (x >= SIDEBAR_W + 12 && x <= SIDEBAR_W + 42) {
            go_up(app);
            redraw_commit(app, "back");
        }
        return;
    }

    // File list row.
    if (y >= TOOLBAR_H && y < app->height - STATUS_H) {
        int r = (int)((y - TOOLBAR_H) / ROW_H);
        int idx = app->scroll + r;
        if (idx < 0 || idx >= app->n_entries)
            return;
        double t = now_seconds();
        int dbl = (idx == app->last_click_row && (t - app->last_click_t) < 0.40);
        app->last_click_row = idx;
        app->last_click_t = t;
        app->sel = idx;
        if (dbl) {
            open_entry(app, idx);
            redraw_commit(app, "open");
        } else {
            redraw_commit(app, "select");
        }
    }
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
    (void)p; (void)time;
    if (button != 0x110 || state != WL_POINTER_BUTTON_STATE_PRESSED)
        return;
    switch (wl_deco_hit(app->pointer_x, app->pointer_y, app->width)) {
        case 4: app->running = 0; return;                            // close
        case 2: xdg_toplevel_set_minimized(app->toplevel); return;
        case 3: if (app->maximized) { xdg_toplevel_unset_maximized(app->toplevel); app->maximized = 0; }
                else              { xdg_toplevel_set_maximized(app->toplevel);   app->maximized = 1; } return;
        default: break;
    }
    // drag the toolbar (the path-bar strip) to move the window
    if (app->pointer_y < TOOLBAR_H && app->pointer_x >= SIDEBAR_W + 52) {
        xdg_toplevel_move(app->toplevel, app->seat, serial); return;
    }
    handle_click(app);
}
static void pointer_axis(void *data, struct wl_pointer *p, uint32_t time, uint32_t axis, wl_fixed_t value)
{
    struct app *app = data;
    (void)p; (void)time;
    if (axis != 0)
        return;
    int dir = wl_fixed_to_double(value) > 0 ? 1 : -1;
    int vis = list_visible_rows(app);
    app->scroll += dir * 3;
    if (app->scroll > app->n_entries - vis)
        app->scroll = app->n_entries - vis;
    if (app->scroll < 0)
        app->scroll = 0;
    redraw_commit(app, NULL);
}
/* wl_pointer v5+ delivers frame/axis_source/axis_stop/axis_discrete; libwayland
 * calls these slots unconditionally, so leaving them NULL crashes the client on
 * the first mouse motion. Provide no-op handlers. */
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
    int vis = list_visible_rows(app);

    /* ── APPS B5: File Search ──────────────────────────────────────────────────────────────
     * '/' starts a filter, printable keys extend it, Backspace shortens it, Esc clears it.
     * Each change re-reads the directory, which is where the filter is applied, so the list,
     * hit-testing and selection all stay consistent with no extra bookkeeping.
     *
     * Navigation keys keep working while searching -- Up/Down/Enter still move and open --
     * because a search that forces you to stop typing to pick a result is worse than one
     * that does not.  Only Backspace changes meaning: it edits the query rather than going
     * up a directory, which is what a text field has to do to be usable at all. */
    if (key == 53 && !app->searching) {          /* '/' opens the search box */
        app->searching = 1;
        app->search_len = 0;
        app->search[0] = 0;
        redraw_commit(app, "search-open");
        return;
    }
    if (app->searching) {
        if (key == 1) {                          /* Esc: cancel, restore the full listing */
            app->searching = 0;
            app->search_len = 0;
            app->search[0] = 0;
            read_dir(app);
            redraw_commit(app, "search-cancel");
            return;
        }
        if (key == 14) {                         /* Backspace edits the query, not the path */
            if (app->search_len > 0) {
                app->search[--app->search_len] = 0;
                read_dir(app);
                redraw_commit(app, "search-edit");
            }
            return;
        }
        char c = files_keycode_ascii(key);
        if (c && app->search_len < (int)sizeof(app->search) - 1) {
            app->search[app->search_len++] = c;
            app->search[app->search_len] = 0;
            read_dir(app);
            redraw_commit(app, "search-edit");
            return;
        }
        /* fall through: Up/Down/Enter still navigate the filtered list */
    }

    // Linux evdev keycodes: Up=103, Down=108, Enter=28, Backspace=14.
    if (key == 108 && app->sel < app->n_entries - 1)
        app->sel++;
    else if (key == 103 && app->sel > 0)
        app->sel--;
    else if (key == 28)
        open_entry(app, app->sel);
    else if (key == 14)
        go_up(app);
    else
        return;
    if (app->sel < app->scroll)
        app->scroll = app->sel;
    if (app->sel >= app->scroll + vis)
        app->scroll = app->sel - vis + 1;
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
        log_line("G17FILES: keyboard subscribed");
    }
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !app->pointer) {
        app->pointer = wl_seat_get_pointer(seat);
        wl_pointer_add_listener(app->pointer, &pointer_listener, app);
        log_line("G17FILES: pointer subscribed");
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
    // The entry table makes `struct app` large (~135KB); keep it out of the
    // limited initial stack of a spawned process by placing it in BSS.
    static struct app app;
    memset(&app, 0, sizeof(app));
    app.running = 1;
    app.place_sel = 2; // "Share"
    snprintf(app.cwd, sizeof(app.cwd), "%s", "/usr/share");

    log_line("G17FILES: starting Cairo/FreeType file manager -- G17 START");
    app.display = wl_display_connect(NULL);
    if (!app.display) {
        perror("G17FILES: wl_display_connect");
        return 1;
    }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base) {
        log_line("G17FILES: missing required Wayland globals");
        return 1;
    }

    read_dir(&app);

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Files");
    xdg_toplevel_set_app_id(app.toplevel, "epin-files");
    xdg_toplevel_set_min_size(app.toplevel, 540, 360);

    wl_surface_commit(app.surface);
    wl_display_flush(app.display);
    log_line("G17FILES: requested xdg_toplevel configure");

    while (app.running) {
        int ret = wl_display_dispatch(app.display);
        if (ret < 0) {
            perror("G17FILES: wl_display_dispatch");
            break;
        }
        if (app.sync_after_commit) {
            app.sync_after_commit = 0;
            if (wl_display_roundtrip(app.display) < 0)
                perror("G17FILES: post-commit roundtrip");
            else
                log_line("G17FILES: post-commit roundtrip complete -- G17 SYNC");
        }
    }
    return app.committed ? 0 : 1;
}
