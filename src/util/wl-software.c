/*
 * wl-software.c — the Software Center: one searchable catalog over the package repositories of
 * every major Linux distribution, for the Linux compatibility layer.
 *
 * Until now there was no way to reach any software from the desktop: /store-app printed a line to
 * prove an object-store app could launch, and the kernel's package "repository" was six invented
 * names in a table (core/pkgrepo.d).  This window lists REAL packages — name, version, licence,
 * download and installed size, one-line summary — harvested from the distributions' own indexes by
 * scripts/pack-software-catalog.py and shipped in the image as software.blob, so the whole catalog
 * is browsable with no network at all.
 *
 * It is honest about what it can install.  This OS's Linux personality runs musl binaries, which is
 * what Alpine ships, so Alpine's apk packages are marked installable and an install request goes to
 * the kernel (/config/software.action) which fetches and unpacks it into the active domain.  Debian,
 * Ubuntu, Fedora, Arch and openSUSE packages are built against glibc and Flathub ships sandboxed
 * bundles: those rows say so, and show the upstream command instead of pretending.
 *
 * Rendering follows the installer (src/util/wl-installer.c): one persistent wl_shm buffer pair,
 * cairo for shapes, a glyph cache over FreeType for text, and a dirty flag drained on the frame
 * callback so a keystroke never costs more than one composite.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <poll.h>
#include <unistd.h>
#include <wayland-client.h>
#include <cairo/cairo.h>
#include <ft2build.h>
#include FT_FREETYPE_H

#include "xdg-shell-client-protocol.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum { DEFAULT_WIDTH = 1000, DEFAULT_HEIGHT = 700, MIN_WIDTH = 820, MIN_HEIGHT = 600 };

/* ── catalog (see scripts/pack-software-catalog.py FORMAT) ─────────────────────────────── */
/* The kernel serves the catalog from its boot module, beside /config/disks.json, rather than
 * unpacking it into the filesystem overlay: every desktop app here runs in a domain's restricted
 * namespace (ROADMAP 4.0b), and an overlay copy is not reachable from inside one.  CATALOG_PATH is
 * overridable so the offline render harness can point at a build tree. */
#ifndef CATALOG_PATH
#define CATALOG_PATH "/config/software.catalog"
#endif

/* PACKED, all three: the packer writes these with Python's '<' (no alignment padding), so a C
 * struct that inserts its natural 4 bytes before the u64 reads every field after it from the wrong
 * offset -- which showed up as an empty sidebar (cat_count came back as 52, cat_off pointed into
 * the header) rather than as a crash. */
struct __attribute__((packed)) cat_hdr {
    char     magic[8];          /* "HOSSOFT1" */
    uint32_t version;
    uint32_t repo_count;
    uint32_t pkg_count;
    uint32_t repo_off;
    uint32_t pkg_off;
    uint32_t str_off;
    uint32_t str_len;
    uint64_t built_epoch;
    uint32_t cat_count;
    uint32_t cat_off;
};
struct __attribute__((packed)) cat_repo {
    uint32_t name, distro, pkgmgr, base_url, arch;
    uint32_t total_pkgs, included_pkgs;
    uint8_t  installable, pad0, pad1, pad2;
    uint32_t reserved;
    uint32_t accent;            /* 0xRRGGBB badge colour */
};
struct __attribute__((packed)) cat_pkg {
    uint32_t name, ver, desc, license;
    uint32_t size_kb, inst_kb;
    uint16_t repo, category;
};

_Static_assert(sizeof(struct cat_hdr)  == 52, "catalog header must match the packer");
_Static_assert(sizeof(struct cat_repo) == 40, "catalog repo record must match the packer");
_Static_assert(sizeof(struct cat_pkg)  == 28, "catalog package record must match the packer");

/* ── glyph cache (same shape as the installer's) ───────────────────────────────────────── */
enum { GLYPH_FIRST = 0x20, GLYPH_LAST = 0x7e, GLYPH_CHARS = GLYPH_LAST - GLYPH_FIRST + 1,
       GLYPH_MAX_PX = 32, GLYPH_SIZE_SLOTS = 8 };
struct glyph { int loaded; unsigned char *bitmap; int width, rows, pitch, left, top, advance; };
struct glyph_size { int px; int ascender; struct glyph glyphs[GLYPH_CHARS]; };

enum { SIDEBAR_W = 206, ROW_H = 46, SEARCH_H = 38 };
enum { FILTER_NONE = -1 };

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
    struct wl_callback *frame_cb;

    struct wl_buffer *buffer[2];
    int               busy[2];
    uint32_t         *pixels[2];      /* both views of the one memfd */
    int               draw_idx;
    size_t            pool_size;

    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size;
    struct glyph_size glyph_sizes[GLYPH_SIZE_SLOTS];
    int glyph_cur_px;
    int font_ready;

    uint32_t *px;                     /* the buffer being drawn into */
    int width, height, stride;
    int pending_width, pending_height;
    int committed, running, dirty, frame_pending;
    int clip_top, clip_bottom;

    /* catalog */
    void *cat;
    size_t cat_len;
    const struct cat_hdr *hdr;
    const struct cat_repo *repos;
    const struct cat_pkg *pkgs;
    const char *strs;
    const uint32_t *cat_names;

    /* view state */
    int  *filtered;                   /* indices into pkgs */
    int   n_filtered;
    int   cat_filter;                 /* 0 = All, else category index */
    int   repo_filter;                /* FILTER_NONE = every repository */
    char  search[64];
    int   search_len;
    int   sel;                        /* index into filtered[] */
    int   scroll;                     /* first visible row */
    double ptr_x, ptr_y;
    int   shift;

    /* install */
    char  status[192];
    int   status_kind;                /* 0 info, 1 working, 2 ok, 3 refused/error */
    int   action_fd;
};

/* ── tiny helpers ──────────────────────────────────────────────────────────────────────── */
static const char *S(struct app *a, uint32_t off)
{
    if (!a->strs || off >= a->hdr->str_len) return "";
    return a->strs + off;
}
static int lower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
static int ci_contains(const char *hay, const char *needle)
{
    if (!*needle) return 1;
    for (const char *h = hay; *h; h++) {
        const char *a = h, *b = needle;
        while (*a && *b && lower((unsigned char)*a) == lower((unsigned char)*b)) { a++; b++; }
        if (!*b) return 1;
    }
    return 0;
}
static void fmt_size(uint32_t kb, char *out, size_t cap)
{
    if (kb == 0)            snprintf(out, cap, "-");
    else if (kb < 1024)     snprintf(out, cap, "%u kB", kb);
    else if (kb < 1024*1024) snprintf(out, cap, "%.1f MB", kb / 1024.0);
    else                    snprintf(out, cap, "%.1f GB", kb / (1024.0 * 1024.0));
}

/* ── FreeType + glyph cache ────────────────────────────────────────────────────────────── */
static int load_file(const char *path, unsigned char **out, size_t *out_size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t cap = 1 << 20, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) { close(fd); return -1; }
    for (;;) {
        if (len == cap) {
            unsigned char *nb = realloc(buf, cap * 2);
            if (!nb) { free(buf); close(fd); return -1; }
            buf = nb; cap *= 2;
        }
        ssize_t n = read(fd, buf + len, cap - len);
        if (n > 0) { len += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    close(fd);
    if (!len) { free(buf); return -1; }
    *out = buf; *out_size = len;
    return 0;
}

static int init_freetype(struct app *a)
{
    if (load_file("/usr/share/fonts/noto/NotoSans-Regular.ttf", &a->font_data, &a->font_size) < 0)
        return -1;
    if (FT_Init_FreeType(&a->ft) != 0) return -1;
    if (FT_New_Memory_Face(a->ft, a->font_data, (FT_Long)a->font_size, 0, &a->face) != 0) return -1;
    a->font_ready = 1;
    return 0;
}

static inline unsigned int div255(unsigned int x) { return (x + 1 + (x >> 8)) >> 8; }
static uint32_t blend(uint32_t dst, uint32_t src, unsigned int alpha)
{
    if (alpha >= 255) return src;
    if (!alpha) return dst;
    unsigned int inv = 255 - alpha;
    unsigned int r = div255(((src >> 16) & 0xff) * alpha + ((dst >> 16) & 0xff) * inv);
    unsigned int g = div255(((src >> 8) & 0xff) * alpha + ((dst >> 8) & 0xff) * inv);
    unsigned int b = div255((src & 0xff) * alpha + (dst & 0xff) * inv);
    return 0xff000000u | (r << 16) | (g << 8) | b;
}

static struct glyph_size *slot_for(struct app *a, int px)
{
    if (px <= 0 || px > GLYPH_MAX_PX) return NULL;
    struct glyph_size *free_slot = NULL;
    for (int i = 0; i < GLYPH_SIZE_SLOTS; i++) {
        if (a->glyph_sizes[i].px == px) return &a->glyph_sizes[i];
        if (!free_slot && a->glyph_sizes[i].px == 0) free_slot = &a->glyph_sizes[i];
    }
    if (free_slot) free_slot->px = px;
    return free_slot;
}

static const struct glyph *cached_glyph(struct app *a, int px, unsigned char ch)
{
    if (ch < GLYPH_FIRST || ch > GLYPH_LAST) ch = '?';
    struct glyph_size *slot = slot_for(a, px);
    if (!slot) return NULL;
    struct glyph *gl = &slot->glyphs[ch - GLYPH_FIRST];
    if (gl->loaded) return gl;
    if (a->glyph_cur_px != px) {
        if (FT_Set_Pixel_Sizes(a->face, 0, (FT_UInt)px) != 0) return NULL;
        a->glyph_cur_px = px;
    }
    if (slot->ascender == 0 && a->face->size && a->face->size->metrics.ascender > 0)
        slot->ascender = (int)(a->face->size->metrics.ascender >> 6);
    if (FT_Load_Char(a->face, (FT_ULong)ch, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) != 0) return NULL;
    FT_GlyphSlot g = a->face->glyph;
    FT_Bitmap *bm = &g->bitmap;
    int pitch = bm->pitch;
    const unsigned char *base = bm->buffer;
    if (pitch < 0) base = bm->buffer + (size_t)(bm->rows - 1) * (size_t)(-pitch);
    gl->width = (int)bm->width; gl->rows = (int)bm->rows; gl->pitch = (int)bm->width;
    gl->left = g->bitmap_left; gl->top = g->bitmap_top; gl->advance = (int)(g->advance.x >> 6);
    size_t n = (size_t)gl->rows * (size_t)gl->pitch;
    if (n) {
        gl->bitmap = malloc(n);
        if (!gl->bitmap) return NULL;
        for (int row = 0; row < gl->rows; row++) {
            const unsigned char *src = base + row * pitch;
            unsigned char *dst = gl->bitmap + (size_t)row * gl->pitch;
            if (bm->pixel_mode == FT_PIXEL_MODE_MONO)
                for (int c = 0; c < gl->width; c++) dst[c] = (src[c >> 3] & (0x80 >> (c & 7))) ? 255 : 0;
            else memcpy(dst, src, (size_t)gl->width);
        }
    } else gl->bitmap = NULL;
    gl->loaded = 1;
    return gl;
}

static void blit_glyph(struct app *a, const struct glyph *gl, int pen_x, int pen_y, uint32_t color)
{
    if (!gl->bitmap) return;
    int gx = pen_x + gl->left, gy = pen_y - gl->top;
    int lo = a->clip_top, hi = a->clip_bottom > 0 ? a->clip_bottom : a->height;
    for (int row = 0; row < gl->rows; row++) {
        int py = gy + row;
        if (py < 0 || py >= a->height || py < lo || py >= hi) continue;
        const unsigned char *src = gl->bitmap + (size_t)row * gl->pitch;
        uint32_t *line = &a->px[py * a->width];
        for (int col = 0; col < gl->width; col++) {
            int pxp = gx + col;
            if (pxp < 0 || pxp >= a->width) continue;
            unsigned int al = src[col];
            if (al) line[pxp] = blend(line[pxp], color, al);
        }
    }
}

static int text_width(struct app *a, const char *s, int px)
{
    int w = 0;
    if (!a->font_ready || !s) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p && *p != '\n'; p++) {
        const struct glyph *gl = cached_glyph(a, px, *p);
        if (gl) w += gl->advance;
    }
    return w;
}

/* Draw one line, ellipsised at max_w.  Returns the drawn width. */
static int draw_text(struct app *a, const char *text, int x, int y, int max_w, int px, uint32_t color)
{
    if (!a->font_ready || !text || max_w <= 0) return 0;
    struct glyph_size *slot = slot_for(a, px);
    int baseline = px;
    if (slot) {
        if (slot->ascender == 0) (void)cached_glyph(a, px, 'H');
        if (slot->ascender > 0) baseline = slot->ascender;
    }
    int ell = text_width(a, "...", px);
    int pen = x, pen_y = y + baseline;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        unsigned char ch = (*p < 0x20 || *p >= 0x7f) ? '?' : *p;
        const struct glyph *gl = cached_glyph(a, px, ch);
        if (!gl) continue;
        if (pen + gl->advance > x + max_w - (p[1] ? ell : 0)) {
            if (p[1]) {                       /* more text follows: mark the truncation */
                for (const char *e = "..."; *e; e++) {
                    const struct glyph *eg = cached_glyph(a, px, (unsigned char)*e);
                    if (!eg || pen + eg->advance > x + max_w) break;
                    blit_glyph(a, eg, pen, pen_y, color);
                    pen += eg->advance;
                }
            }
            break;
        }
        blit_glyph(a, gl, pen, pen_y, color);
        pen += gl->advance;
    }
    return pen - x;
}

/* Word-wrap into at most max_lines lines of max_w pixels. */
static void draw_wrapped(struct app *a, const char *text, int x, int y, int max_w, int px,
                         uint32_t color, int max_lines, int pitch)
{
    if (!text || !*text) return;
    const char *p = text;
    for (int line = 0; line < max_lines && *p; line++) {
        const char *brk = NULL, *q = p;
        int w = 0;
        while (*q) {
            const struct glyph *gl = cached_glyph(a, px, (unsigned char)(*q < 0x20 || *q >= 0x7f ? '?' : *q));
            int adv = gl ? gl->advance : 0;
            if (w + adv > max_w) break;
            if (*q == ' ') brk = q;
            w += adv; q++;
        }
        int len = (int)(*q ? ((brk && line + 1 < max_lines) ? brk - p : q - p) : q - p);
        char buf[512];
        if (len > (int)sizeof buf - 1) len = (int)sizeof buf - 1;
        memcpy(buf, p, (size_t)len); buf[len] = 0;
        if (*q && line + 1 == max_lines) {           /* last line and more remains: ellipsise */
            draw_text(a, buf, x, y + line * pitch, max_w, px, color);
            return;
        }
        draw_text(a, buf, x, y + line * pitch, max_w, px, color);
        p += len;
        while (*p == ' ') p++;
    }
}

static void rounded(cairo_t *cr, double x, double y, double w, double h, double r)
{
    if (r * 2 > h) r = h / 2;
    if (r * 2 > w) r = w / 2;
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r,     r, -1.5708, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0,       1.5708);
    cairo_arc(cr, x + r,     y + h - r, r, 1.5708,  3.1416);
    cairo_arc(cr, x + r,     y + r,     r, 3.1416,  4.7124);
    cairo_close_path(cr);
}
static void set_rgb(cairo_t *cr, uint32_t c)
{
    cairo_set_source_rgb(cr, ((c >> 16) & 0xff) / 255.0, ((c >> 8) & 0xff) / 255.0, (c & 0xff) / 255.0);
}

/* ── catalog loading + filtering ───────────────────────────────────────────────────────── */
static int catalog_open(struct app *a)
{
    int fd = open(CATALOG_PATH, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "wl-software: open %s: errno %d\n", CATALOG_PATH, errno); return -1; }
    struct stat st;
    size_t len = (fstat(fd, &st) == 0 && st.st_size > 0) ? (size_t)st.st_size : 0;
    if (len && len < sizeof(struct cat_hdr)) {
        fprintf(stderr, "wl-software: %s is only %zu bytes\n", CATALOG_PATH, len);
        close(fd); return -1;
    }
    /* mmap first (the catalog is 6-7 MB and read-only, so mapping it costs nothing), but this
     * kernel's overlay files are RAM-backed nodes that do not support mmap -- and that is where
     * the catalog lives on the guest.  So fall back to reading it in; the client then owns the
     * buffer instead of the mapping, which every later access is already written against. */
    /* READ it, never mmap it.  The catalog is served by the kernel as a synthetic /config node
     * (posix.d), and mmap on one of those hands back zeroed anonymous memory rather than the
     * file -- which passes the open and then fails the magic check, i.e. looks like a corrupt
     * catalog instead of an unsupported mapping.  A 6.8 MB read is cheap and always correct. */
    int mapped = 0;
    void *m = MAP_FAILED;
    {
        /* A synthetic /config node reports no size and cannot be mapped: read it to EOF, growing
         * as we go.  That is also the path an ordinary file takes when mmap is unavailable. */
        size_t cap = len ? len : (8u << 20), got = 0;
        m = malloc(cap);
        if (!m) { close(fd); fprintf(stderr, "wl-software: out of memory for %zu bytes\n", cap); return -1; }
        for (;;) {
            if (got == cap) {
                void *nb = realloc(m, cap * 2);
                if (!nb) { free(m); close(fd); fprintf(stderr, "wl-software: out of memory\n"); return -1; }
                m = nb; cap *= 2;
            }
            ssize_t n = read(fd, (char *)m + got, cap - got);
            if (n > 0) { got += (size_t)n; continue; }
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        if (got < sizeof(struct cat_hdr)) {
            fprintf(stderr, "wl-software: read only %zu bytes from %s (errno %d)\n", got, CATALOG_PATH, errno);
            free(m); close(fd); return -1;
        }
        len = got;
    }
    close(fd);
    const struct cat_hdr *h = m;
    if (memcmp(h->magic, "HOSSOFT1", 8) != 0 || h->version != 1) {
        fprintf(stderr, "wl-software: %s is not a v1 catalog\n", CATALOG_PATH);
        if (mapped) munmap(m, len); else free(m);
        return -1;
    }
    if ((size_t)h->str_off + h->str_len > len) {
        fprintf(stderr, "wl-software: catalog string pool runs past the file\n");
        if (mapped) munmap(m, len); else free(m);
        return -1;
    }
    a->cat = m; a->cat_len = len; a->hdr = h;
    a->repos = (const struct cat_repo *)((const char *)m + h->repo_off);
    a->pkgs  = (const struct cat_pkg  *)((const char *)m + h->pkg_off);
    a->strs  = (const char *)m + h->str_off;
    a->cat_names = (const uint32_t *)((const char *)m + h->cat_off);
    a->filtered = malloc(sizeof(int) * (h->pkg_count ? h->pkg_count : 1));
    return a->filtered ? 0 : -1;
}

static void refilter(struct app *a)
{
    a->n_filtered = 0;
    if (!a->hdr) return;
    for (uint32_t i = 0; i < a->hdr->pkg_count; i++) {
        const struct cat_pkg *p = &a->pkgs[i];
        if (a->repo_filter != FILTER_NONE && p->repo != (uint16_t)a->repo_filter) continue;
        if (a->cat_filter > 0 && p->category != (uint16_t)a->cat_filter) continue;
        if (a->search_len) {
            /* name first (the cheap, most useful match), then the summary */
            if (!ci_contains(S(a, p->name), a->search) && !ci_contains(S(a, p->desc), a->search))
                continue;
        }
        a->filtered[a->n_filtered++] = (int)i;
    }
    if (a->sel >= a->n_filtered) a->sel = a->n_filtered ? a->n_filtered - 1 : 0;
    if (a->sel < 0) a->sel = 0;
    a->scroll = 0;
}

/* ── install endpoint (/config/software.action + .status) ──────────────────────────────── */
static void set_status(struct app *a, int kind, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(a->status, sizeof a->status, fmt, ap);
    va_end(ap);
    a->status_kind = kind;
}

static void read_status_file(struct app *a)
{
    int fd = open("/config/software.status", O_RDONLY);
    if (fd < 0) return;
    char buf[192];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = 0;
    for (char *p = buf; *p; p++) if (*p == '\n' || *p == '\r') { *p = 0; break; }
    if (!buf[0]) return;
    /* the kernel prefixes its verdict: "ok ", "busy ", "refused " */
    if (!strncmp(buf, "ok ", 3))            set_status(a, 2, "%s", buf + 3);
    else if (!strncmp(buf, "busy ", 5))     set_status(a, 1, "%s", buf + 5);
    else if (!strncmp(buf, "refused ", 8))  set_status(a, 3, "%s", buf + 8);
    else                                    set_status(a, 0, "%s", buf);
}

static void request_install(struct app *a)
{
    if (!a->n_filtered) return;
    const struct cat_pkg *p = &a->pkgs[a->filtered[a->sel]];
    const struct cat_repo *r = &a->repos[p->repo];
    if (!r->installable) {
        set_status(a, 3, "%s packages are built for %s (glibc); this system's Linux layer is musl. "
                         "Run: %s install %s",
                   S(a, r->pkgmgr), S(a, r->distro), S(a, r->pkgmgr), S(a, p->name));
        return;
    }
    char cmd[256];
    int n = snprintf(cmd, sizeof cmd, "install %s %s %s", S(a, r->pkgmgr), S(a, p->name), S(a, r->base_url));
    int fd = open("/config/software.action", O_WRONLY);
    if (fd < 0) {
        set_status(a, 3, "no install endpoint on this system (/config/software.action: errno %d)", errno);
        return;
    }
    ssize_t w = write(fd, cmd, (size_t)n);
    close(fd);
    if (w < 0) { set_status(a, 3, "install request failed (errno %d)", errno); return; }
    set_status(a, 1, "requested %s from %s...", S(a, p->name), S(a, r->name));
    read_status_file(a);
}

/* ── layout ────────────────────────────────────────────────────────────────────────────── */
/* The sidebar lists every category AND every repository, so its pitch has to come from the window:
 * at a fixed 26 px the repository list ran off the bottom of an 820x600 window (23 rows + headers
 * needs 686 px).  Both the painter and the hit test call this, so they cannot disagree. */
static int side_pitch(struct app *a)
{
    int rows = (int)a->hdr->cat_count + (int)a->hdr->repo_count + 1;   /* +1 for the section header */
    int avail = a->height - 78;
    int p = rows > 0 ? avail / rows : 26;
    if (p > 26) p = 26;
    if (p < 15) p = 15;
    return p;
}
static int detail_h(struct app *a) { (void)a; return 172; }
static int list_top(struct app *a) { (void)a; return 62 + SEARCH_H; }
static int list_bottom(struct app *a) { return a->height - detail_h(a) - 12; }
static int visible_rows(struct app *a)
{
    int h = list_bottom(a) - list_top(a);
    return h > 0 ? h / ROW_H : 0;
}
static void install_btn(struct app *a, double *x, double *y, double *w, double *h)
{
    *w = 132; *h = 38;
    *x = a->width - 24 - *w;
    *y = a->height - detail_h(a) + 14;
}

/* ── drawing ───────────────────────────────────────────────────────────────────────────── */
static void draw(struct app *a)
{
    cairo_surface_t *surf = cairo_image_surface_create_for_data((unsigned char *)a->px,
                                                                CAIRO_FORMAT_RGB24,
                                                                a->width, a->height, a->stride);
    cairo_t *cr = cairo_create(surf);

    /* chrome */
    cairo_rectangle(cr, 0, 0, a->width, a->height); set_rgb(cr, 0x0f1418); cairo_fill(cr);
    cairo_rectangle(cr, 0, 0, SIDEBAR_W, a->height); set_rgb(cr, 0x161d23); cairo_fill(cr);

    /* search box */
    rounded(cr, SIDEBAR_W + 24, 52, a->width - SIDEBAR_W - 48, SEARCH_H, 8);
    set_rgb(cr, 0x1b242c); cairo_fill(cr);

    /* sidebar selection pills */
    int sp = side_pitch(a);
    int y = 62;
    for (uint32_t i = 0; i < a->hdr->cat_count; i++) {
        if (a->cat_filter == (int)i && a->repo_filter == FILTER_NONE) {
            rounded(cr, 10, y - 3, SIDEBAR_W - 20, sp - 1, 6); set_rgb(cr, 0x0d3f45); cairo_fill(cr);
        }
        y += sp;
    }
    y += sp;
    for (uint32_t i = 0; i < a->hdr->repo_count; i++) {
        if (a->repo_filter == (int)i) {
            rounded(cr, 10, y - 3, SIDEBAR_W - 20, sp - 1, 6); set_rgb(cr, 0x0d3f45); cairo_fill(cr);
        }
        y += sp;
    }

    /* package rows */
    int top = list_top(a), rows = visible_rows(a);
    for (int i = 0; i < rows && a->scroll + i < a->n_filtered; i++) {
        int idx = a->filtered[a->scroll + i];
        const struct cat_pkg *p = &a->pkgs[idx];
        const struct cat_repo *r = &a->repos[p->repo];
        double ry = top + i * ROW_H;
        int selected = (a->scroll + i) == a->sel;
        rounded(cr, SIDEBAR_W + 24, ry, a->width - SIDEBAR_W - 48, ROW_H - 6, 7);
        set_rgb(cr, selected ? 0x15303a : 0x141b21); cairo_fill(cr);
        /* repo badge */
        rounded(cr, SIDEBAR_W + 34, ry + 12, 12, ROW_H - 30, 3);
        set_rgb(cr, r->accent); cairo_fill(cr);
    }

    /* detail card */
    double cardy = a->height - detail_h(a);
    rounded(cr, SIDEBAR_W + 24, cardy, a->width - SIDEBAR_W - 48, detail_h(a) - 16, 8);
    set_rgb(cr, 0x131b21); cairo_fill(cr);
    if (a->n_filtered) {
        const struct cat_pkg *p = &a->pkgs[a->filtered[a->sel]];
        const struct cat_repo *r = &a->repos[p->repo];
        double bx, by, bw, bh;
        install_btn(a, &bx, &by, &bw, &bh);
        rounded(cr, bx, by, bw, bh, 8);
        set_rgb(cr, r->installable ? 0x0d8577 : 0x2b343d); cairo_fill(cr);
    }

    cairo_destroy(cr);
    cairo_surface_flush(surf);
    cairo_surface_destroy(surf);

    /* ── text over the shapes ── */
    draw_text(a, "Software", 20, 18, SIDEBAR_W - 30, 19, 0xffffffffu);
    char sub[64];
    snprintf(sub, sizeof sub, "%u packages", a->hdr->pkg_count);
    draw_text(a, sub, 20, 42, SIDEBAR_W - 30, 11, 0xff7f8c99u);

    y = 62;
    for (uint32_t i = 0; i < a->hdr->cat_count; i++) {
        int on = (a->cat_filter == (int)i && a->repo_filter == FILTER_NONE);
        draw_text(a, S(a, a->cat_names[i]), 20, y, SIDEBAR_W - 34, 12,
                  on ? 0xffffffffu : 0xff9aa6b4u);
        y += sp;
    }
    /* "*" marks the repositories whose packages can actually run here (musl); saying it in the
     * section header keeps the legend on screen at every window size. */
    draw_text(a, "REPOSITORIES   * = INSTALLABLE", 20, y + 2, SIDEBAR_W - 30, 9, 0xff5f6b78u);
    y += sp;
    for (uint32_t i = 0; i < a->hdr->repo_count; i++) {
        const struct cat_repo *r = &a->repos[i];
        int on = (a->repo_filter == (int)i);
        char label[64];
        snprintf(label, sizeof label, "%s%s", S(a, r->name), r->installable ? " *" : "");
        draw_text(a, label, 20, y, SIDEBAR_W - 34, 12,
                  on ? 0xffffffffu : (r->installable ? 0xffa9c6c2u : 0xff9aa6b4u));
        y += sp;
    }

    /* search + result line */
    if (a->search_len)
        draw_text(a, a->search, SIDEBAR_W + 38, 52 + 10, a->width - SIDEBAR_W - 76, 14, 0xffffffffu);
    else
        draw_text(a, "Type to search 73,000 packages by name or description",
                  SIDEBAR_W + 38, 52 + 10, a->width - SIDEBAR_W - 76, 13, 0xff6d7884u);
    char head[128];
    const char *scope = (a->repo_filter != FILTER_NONE) ? S(a, a->repos[a->repo_filter].name)
                      : (a->cat_filter > 0 ? S(a, a->cat_names[a->cat_filter]) : "All repositories");
    snprintf(head, sizeof head, "%s  -  %d result%s", scope, a->n_filtered, a->n_filtered == 1 ? "" : "s");
    draw_text(a, head, SIDEBAR_W + 24, 22, a->width - SIDEBAR_W - 48, 13, 0xffc8d2dfu);

    int top2 = list_top(a), rows2 = visible_rows(a);
    for (int i = 0; i < rows2 && a->scroll + i < a->n_filtered; i++) {
        const struct cat_pkg *p = &a->pkgs[a->filtered[a->scroll + i]];
        int ry = top2 + i * ROW_H;
        int tx = SIDEBAR_W + 56;
        int selected = (a->scroll + i) == a->sel;
        int name_w = text_width(a, S(a, p->name), 14);
        draw_text(a, S(a, p->name), tx, ry + 5, a->width - tx - 150, 14,
                  selected ? 0xffffffffu : 0xffe6ecf2u);
        draw_text(a, S(a, p->ver), tx + name_w + 10, ry + 7, 160, 11, 0xff7f8c99u);
        {   /* which distribution this row came from, next to the accent bar */
            const struct cat_repo *rr = &a->repos[p->repo];
            int dw = text_width(a, S(a, rr->distro), 10);
            draw_text(a, S(a, rr->distro), a->width - 40 - dw, ry + 4, 120, 10, 0xff6d7884u);
        }
        draw_text(a, S(a, p->desc), tx, ry + 24, a->width - tx - 150, 11, 0xff8b96a4u);
        char sz[24];
        fmt_size(p->inst_kb ? p->inst_kb : p->size_kb, sz, sizeof sz);
        int sw = text_width(a, sz, 11);
        draw_text(a, sz, a->width - 40 - sw, ry + 16, 80, 11, 0xff6d7884u);
    }
    if (!a->n_filtered)
        draw_text(a, "No package matches that search.", SIDEBAR_W + 40, top2 + 12,
                  a->width - SIDEBAR_W - 80, 13, 0xff8b96a4u);

    /* detail */
    double cardy2 = a->height - detail_h(a);
    if (a->n_filtered) {
        const struct cat_pkg *p = &a->pkgs[a->filtered[a->sel]];
        const struct cat_repo *r = &a->repos[p->repo];
        int x = SIDEBAR_W + 44, w = a->width - x - 180;
        draw_text(a, S(a, p->name), x, (int)cardy2 + 12, w, 17, 0xffffffffu);
        char meta[220], dl[24], is[24];
        fmt_size(p->size_kb, dl, sizeof dl);
        fmt_size(p->inst_kb, is, sizeof is);
        snprintf(meta, sizeof meta, "%s  -  %s %s  -  download %s, installed %s%s%s",
                 S(a, p->ver), S(a, r->distro), S(a, r->pkgmgr), dl, is,
                 S(a, p->license)[0] ? "  -  " : "", S(a, p->license));
        draw_text(a, meta, x, (int)cardy2 + 36, w, 11, 0xff8b96a4u);
        draw_wrapped(a, S(a, p->desc), x, (int)cardy2 + 56, w, 12, 0xffc8d2dfu, 2, 17);
        const char *note = a->status[0] ? a->status : NULL;
        if (!note) {
            static char fallback[220];
            if (r->installable)
                snprintf(fallback, sizeof fallback,
                         "Alpine builds against musl, the same libc this system's Linux layer runs: "
                         "Install fetches it from %s.", S(a, r->base_url));
            else
                snprintf(fallback, sizeof fallback,
                         "Catalog entry: %s ships this for %s (glibc). On that system: %s install %s",
                         S(a, r->name), S(a, r->distro), S(a, r->pkgmgr), S(a, p->name));
            note = fallback;
        }
        uint32_t nc = a->status_kind == 3 ? 0xffff8a8au : a->status_kind == 2 ? 0xff57d977u
                    : a->status_kind == 1 ? 0xffffd08au : 0xff7f8c99u;
        draw_wrapped(a, note, x, (int)cardy2 + 96, w, 11, nc, 3, 15);

        double bx, by, bw, bh;
        install_btn(a, &bx, &by, &bw, &bh);
        const char *blabel = r->installable ? "Install" : "Not for musl";
        int lw = text_width(a, blabel, 13);
        draw_text(a, blabel, (int)(bx + (bw - lw) / 2), (int)by + 11, (int)bw, 13,
                  r->installable ? 0xffffffffu : 0xff7f8c99u);
    }

    /* footer hints */
    draw_text(a, "Up/Down select   Enter install   Esc clear search   Tab next repository",
              SIDEBAR_W + 24, a->height - 16, a->width - SIDEBAR_W - 48, 10, 0xff5f6b78u);
}

/* ── buffers / commit ──────────────────────────────────────────────────────────────────── */
static int create_memfd(const char *name)
{
    return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC);
}

static void buffer_release(void *data, struct wl_buffer *b)
{
    struct app *a = data;
    for (int i = 0; i < 2; i++) if (a->buffer[i] == b) a->busy[i] = 0;
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static int create_buffers(struct app *a, int w, int h)
{
    a->width = w > 0 ? w : DEFAULT_WIDTH;
    a->height = h > 0 ? h : DEFAULT_HEIGHT;
    a->stride = a->width * 4;
    size_t one = (size_t)a->stride * (size_t)a->height;
    a->pool_size = one * 2;
    int fd = create_memfd("epin-software");
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)a->pool_size) < 0) { close(fd); return -1; }
    void *m = mmap(NULL, a->pool_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) { close(fd); return -1; }
    struct wl_shm_pool *pool = wl_shm_create_pool(a->shm, fd, (int)a->pool_size);
    for (int i = 0; i < 2; i++) {
        a->pixels[i] = (uint32_t *)((char *)m + one * (size_t)i);
        a->buffer[i] = wl_shm_pool_create_buffer(pool, (int32_t)(one * (size_t)i), a->width, a->height,
                                                 a->stride, WL_SHM_FORMAT_XRGB8888);
        a->busy[i] = 0;
        if (!a->buffer[i]) { wl_shm_pool_destroy(pool); close(fd); return -1; }
        wl_buffer_add_listener(a->buffer[i], &buffer_listener, a);
    }
    wl_shm_pool_destroy(pool);
    close(fd);
    return 0;
}

static void destroy_buffers(struct app *a)
{
    for (int i = 0; i < 2; i++) {
        if (a->buffer[i]) { wl_buffer_destroy(a->buffer[i]); a->buffer[i] = NULL; }
        a->busy[i] = 0;
    }
    if (a->pixels[0]) { munmap(a->pixels[0], a->pool_size); a->pixels[0] = a->pixels[1] = NULL; }
}

static void frame_done(void *data, struct wl_callback *cb, uint32_t t);
static const struct wl_callback_listener frame_listener = { .done = frame_done };

static void render(struct app *a)
{
    if (!a->buffer[0] || !a->buffer[1]) return;
    int idx = -1;
    for (int i = 0; i < 2; i++) if (!a->busy[i]) { idx = i; break; }
    if (idx < 0) return;                       /* both held by the compositor: stay dirty */
    a->px = a->pixels[idx];
    a->clip_top = 0; a->clip_bottom = 0;
    draw(a);
    a->busy[idx] = 1;
    a->dirty = 0;
    wl_surface_attach(a->surface, a->buffer[idx], 0, 0);
    wl_surface_damage_buffer(a->surface, 0, 0, a->width, a->height);
    a->frame_cb = wl_surface_frame(a->surface);
    wl_callback_add_listener(a->frame_cb, &frame_listener, a);
    a->frame_pending = 1;
    wl_surface_commit(a->surface);
    wl_display_flush(a->display);
}

static void frame_done(void *data, struct wl_callback *cb, uint32_t t)
{
    struct app *a = data;
    (void)t;
    if (cb) wl_callback_destroy(cb);
    a->frame_cb = NULL;
    a->frame_pending = 0;
    if (a->dirty) render(a);
}

/* ── wayland plumbing ──────────────────────────────────────────────────────────────────── */
static void wm_ping(void *d, struct xdg_wm_base *b, uint32_t s) { (void)d; xdg_wm_base_pong(b, s); }
static const struct xdg_wm_base_listener wm_listener = { .ping = wm_ping };

static void tl_configure(void *data, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *st)
{
    struct app *a = data; (void)t; (void)st;
    if (w > 0) a->pending_width = w;
    if (h > 0) a->pending_height = h;
}
static void tl_close(void *data, struct xdg_toplevel *t) { (void)t; ((struct app *)data)->running = 0; }
static void tl_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h) { (void)d;(void)t;(void)w;(void)h; }
static void tl_caps(void *d, struct xdg_toplevel *t, struct wl_array *c) { (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener tl_listener = {
    .configure = tl_configure, .close = tl_close,
    .configure_bounds = tl_bounds, .wm_capabilities = tl_caps,
};

static void surf_configure(void *data, struct xdg_surface *s, uint32_t serial)
{
    struct app *a = data;
    xdg_surface_ack_configure(s, serial);
    int w = a->pending_width > 0 ? a->pending_width : DEFAULT_WIDTH;
    int h = a->pending_height > 0 ? a->pending_height : DEFAULT_HEIGHT;
    if (w < MIN_WIDTH) w = MIN_WIDTH;
    if (h < MIN_HEIGHT) h = MIN_HEIGHT;
    if (a->committed && w == a->width && h == a->height) return;
    destroy_buffers(a);
    if (create_buffers(a, w, h) < 0) { a->running = 0; return; }
    a->committed = 1;
    a->dirty = 1;
    if (!a->frame_pending) render(a);
}
static const struct xdg_surface_listener surf_listener = { .configure = surf_configure };

/* PS/2 set-1 scancodes, as the other native clients here map them. */
static const char km_plain[59] = {
    0,0,'1','2','3','4','5','6','7','8','9','0','-','=',0,0,
    'q','w','e','r','t','y','u','i','o','p','[',']',0,0,'a','s',
    'd','f','g','h','j','k','l',';','\'','`',0,'\\','z','x','c','v',
    'b','n','m',',','.','/',0,0,0,' '
};
static const char km_shift[59] = {
    0,0,'!','@','#','$','%','^','&','*','(',')','_','+',0,0,
    'Q','W','E','R','T','Y','U','I','O','P','{','}',0,0,'A','S',
    'D','F','G','H','J','K','L',':','"','~',0,'|','Z','X','C','V',
    'B','N','M','<','>','?',0,0,0,' '
};

static void ensure_visible(struct app *a)
{
    int rows = visible_rows(a);
    if (a->sel < a->scroll) a->scroll = a->sel;
    if (rows > 0 && a->sel >= a->scroll + rows) a->scroll = a->sel - rows + 1;
    if (a->scroll < 0) a->scroll = 0;
}

static void kb_key(void *data, struct wl_keyboard *k, uint32_t serial, uint32_t time,
                   uint32_t code, uint32_t state)
{
    struct app *a = data; (void)k; (void)serial; (void)time;
    int down = state == WL_KEYBOARD_KEY_STATE_PRESSED;
    if (code == 42 || code == 54) { a->shift = down; return; }
    if (!down) return;
    int rows = visible_rows(a);
    switch (code) {
    case 103: if (a->sel > 0) a->sel--; ensure_visible(a); break;                 /* Up */
    case 108: if (a->sel + 1 < a->n_filtered) a->sel++; ensure_visible(a); break; /* Down */
    case 104: a->sel -= rows; if (a->sel < 0) a->sel = 0; ensure_visible(a); break;   /* PgUp */
    case 109: a->sel += rows; if (a->sel >= a->n_filtered) a->sel = a->n_filtered ? a->n_filtered - 1 : 0;
              ensure_visible(a); break;                                            /* PgDn */
    case 28:  request_install(a); break;                                           /* Enter */
    case 1:                                                                         /* Esc */
        if (a->search_len) { a->search_len = 0; a->search[0] = 0; a->status[0] = 0; refilter(a); }
        else a->running = 0;
        break;
    case 15:                                                                        /* Tab */
        a->repo_filter = (a->repo_filter + 1 >= (int)a->hdr->repo_count) ? FILTER_NONE : a->repo_filter + 1;
        a->status[0] = 0;
        refilter(a);
        break;
    case 14:                                                                        /* Backspace */
        if (a->search_len) { a->search[--a->search_len] = 0; refilter(a); }
        break;
    default: {
        if (code >= sizeof km_plain) break;
        char ch = a->shift ? km_shift[code] : km_plain[code];
        if (!ch || a->search_len >= (int)sizeof a->search - 1) break;
        a->search[a->search_len++] = ch;
        a->search[a->search_len] = 0;
        a->status[0] = 0;
        refilter(a);
        break;
    }
    }
    a->dirty = 1;
    if (!a->frame_pending) render(a);
}
static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t s)
{ (void)d;(void)k;(void)f;(void)s; if (fd >= 0) close(fd); }
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su, struct wl_array *ks)
{ (void)d;(void)k;(void)s;(void)su;(void)ks; }
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su)
{ (void)d;(void)k;(void)s;(void)su; }
static void kb_mods(void *d, struct wl_keyboard *k, uint32_t s, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t g)
{ (void)d;(void)k;(void)s;(void)a1;(void)a2;(void)a3;(void)g; }
static void kb_rep(void *d, struct wl_keyboard *k, int32_t r, int32_t dl) { (void)d;(void)k;(void)r;(void)dl; }
static const struct wl_keyboard_listener kb_listener = {
    .keymap = kb_keymap, .enter = kb_enter, .leave = kb_leave,
    .key = kb_key, .modifiers = kb_mods, .repeat_info = kb_rep,
};

static void ptr_motion(void *data, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y)
{
    struct app *a = data; (void)p; (void)t;
    a->ptr_x = wl_fixed_to_double(x); a->ptr_y = wl_fixed_to_double(y);
}
static void ptr_enter(void *data, struct wl_pointer *p, uint32_t s, struct wl_surface *su,
                      wl_fixed_t x, wl_fixed_t y)
{ (void)p;(void)s;(void)su; ptr_motion(data, NULL, 0, x, y); }
static void ptr_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *su)
{ (void)d;(void)p;(void)s;(void)su; }

static void ptr_button(void *data, struct wl_pointer *p, uint32_t serial, uint32_t time,
                       uint32_t button, uint32_t state)
{
    struct app *a = data; (void)p; (void)serial; (void)time;
    if (button != 0x110 || state != WL_POINTER_BUTTON_STATE_PRESSED) return;
    double x = a->ptr_x, y = a->ptr_y;

    if (x < SIDEBAR_W) {                                   /* sidebar: category or repository */
        int sp = side_pitch(a);
        int cy = 62;
        for (uint32_t i = 0; i < a->hdr->cat_count; i++, cy += sp)
            if (y >= cy - 3 && y < cy + sp - 3) {
                a->cat_filter = (int)i; a->repo_filter = FILTER_NONE; a->status[0] = 0;
                refilter(a); goto done;
            }
        cy += sp;
        for (uint32_t i = 0; i < a->hdr->repo_count; i++, cy += sp)
            if (y >= cy - 3 && y < cy + sp - 3) {
                a->repo_filter = (a->repo_filter == (int)i) ? FILTER_NONE : (int)i;
                a->status[0] = 0;
                refilter(a); goto done;
            }
        return;
    }
    {   /* install button */
        double bx, by, bw, bh;
        install_btn(a, &bx, &by, &bw, &bh);
        if (x >= bx && x < bx + bw && y >= by && y < by + bh) { request_install(a); goto done; }
    }
    {   /* package row */
        int top = list_top(a), rows = visible_rows(a);
        for (int i = 0; i < rows && a->scroll + i < a->n_filtered; i++) {
            double ry = top + i * ROW_H;
            if (y >= ry && y < ry + ROW_H - 6) { a->sel = a->scroll + i; a->status[0] = 0; goto done; }
        }
    }
    return;
done:
    a->dirty = 1;
    if (!a->frame_pending) render(a);
}

static void ptr_axis(void *data, struct wl_pointer *p, uint32_t t, uint32_t axis, wl_fixed_t val)
{
    struct app *a = data; (void)p; (void)t;
    if (axis != 0) return;
    int before = a->scroll;
    a->scroll += wl_fixed_to_double(val) > 0 ? 3 : -3;
    int maxs = a->n_filtered - visible_rows(a);
    if (maxs < 0) maxs = 0;
    if (a->scroll > maxs) a->scroll = maxs;
    if (a->scroll < 0) a->scroll = 0;
    if (a->scroll == before) return;
    a->dirty = 1;
    if (!a->frame_pending) render(a);
}
static void ptr_frame(void *d, struct wl_pointer *p) { (void)d; (void)p; }
static void ptr_axis_src(void *d, struct wl_pointer *p, uint32_t s) { (void)d;(void)p;(void)s; }
static void ptr_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t a) { (void)d;(void)p;(void)t;(void)a; }
static void ptr_axis_disc(void *d, struct wl_pointer *p, uint32_t a, int32_t v) { (void)d;(void)p;(void)a;(void)v; }
static const struct wl_pointer_listener ptr_listener = {
    .enter = ptr_enter, .leave = ptr_leave, .motion = ptr_motion, .button = ptr_button,
    .axis = ptr_axis, .frame = ptr_frame, .axis_source = ptr_axis_src,
    .axis_stop = ptr_axis_stop, .axis_discrete = ptr_axis_disc,
};

static void seat_caps(void *data, struct wl_seat *seat, uint32_t caps)
{
    struct app *a = data;
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !a->keyboard) {
        a->keyboard = wl_seat_get_keyboard(seat);
        wl_keyboard_add_listener(a->keyboard, &kb_listener, a);
    }
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !a->pointer) {
        a->pointer = wl_seat_get_pointer(seat);
        wl_pointer_add_listener(a->pointer, &ptr_listener, a);
    }
}
static void seat_name(void *d, struct wl_seat *s, const char *n) { (void)d;(void)s;(void)n; }
static const struct wl_seat_listener seat_listener = { .capabilities = seat_caps, .name = seat_name };

static void reg_global(void *data, struct wl_registry *reg, uint32_t name,
                       const char *iface, uint32_t ver)
{
    struct app *a = data;
    if (!strcmp(iface, "wl_compositor"))
        a->compositor = wl_registry_bind(reg, name, &wl_compositor_interface, ver < 4 ? ver : 4);
    else if (!strcmp(iface, "wl_shm"))
        a->shm = wl_registry_bind(reg, name, &wl_shm_interface, 1);
    else if (!strcmp(iface, "xdg_wm_base")) {
        a->wm_base = wl_registry_bind(reg, name, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(a->wm_base, &wm_listener, a);
    } else if (!strcmp(iface, "wl_seat")) {
        a->seat = wl_registry_bind(reg, name, &wl_seat_interface, ver < 5 ? ver : 5);
        wl_seat_add_listener(a->seat, &seat_listener, a);
    }
}
static void reg_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d;(void)r;(void)n; }
static const struct wl_registry_listener reg_listener = { .global = reg_global, .global_remove = reg_remove };

int main(void)
{
    struct app a;
    memset(&a, 0, sizeof a);
    a.running = 1;
    a.repo_filter = FILTER_NONE;
    a.action_fd = -1;

    if (catalog_open(&a) < 0) {
        fprintf(stderr, "wl-software: no usable catalog at %s (see the line above); an image "
                        "without software.blob has none — build it with "
                        "scripts/pack-software-catalog.py\n", CATALOG_PATH);
        return 1;
    }
    refilter(&a);
    printf("[software] catalog: %u packages, %u repositories\n", a.hdr->pkg_count, a.hdr->repo_count);
    fflush(stdout);

    a.display = wl_display_connect(NULL);
    if (!a.display) { perror("wl-software: wl_display_connect"); return 1; }
    a.registry = wl_display_get_registry(a.display);
    wl_registry_add_listener(a.registry, &reg_listener, &a);
    wl_display_roundtrip(a.display);
    if (!a.compositor || !a.shm || !a.wm_base) {
        fprintf(stderr, "wl-software: missing Wayland globals\n");
        return 1;
    }
    if (init_freetype(&a) < 0) fprintf(stderr, "wl-software: no font; text will be blank\n");

    a.surface = wl_compositor_create_surface(a.compositor);
    a.xdg_surface = xdg_wm_base_get_xdg_surface(a.wm_base, a.surface);
    xdg_surface_add_listener(a.xdg_surface, &surf_listener, &a);
    a.toplevel = xdg_surface_get_toplevel(a.xdg_surface);
    xdg_toplevel_add_listener(a.toplevel, &tl_listener, &a);
    xdg_toplevel_set_title(a.toplevel, "Software");
    xdg_toplevel_set_app_id(a.toplevel, "epinanonymos-software");
    xdg_toplevel_set_min_size(a.toplevel, MIN_WIDTH, MIN_HEIGHT);
    wl_surface_commit(a.surface);
    wl_display_flush(a.display);

    struct pollfd pfd = { .fd = wl_display_get_fd(a.display), .events = POLLIN };
    while (a.running) {
        while (wl_display_prepare_read(a.display) != 0)
            wl_display_dispatch_pending(a.display);
        wl_display_flush(a.display);
        /* 700 ms: only to re-read /config/software.status while an install is in flight. */
        int pr = poll(&pfd, 1, a.status_kind == 1 ? 700 : -1);
        if (pr > 0) wl_display_read_events(a.display);
        else        wl_display_cancel_read(a.display);
        if (wl_display_dispatch_pending(a.display) < 0) break;
        if (pr == 0 && a.status_kind == 1) {
            int k = a.status_kind;
            char prev[sizeof a.status];
            memcpy(prev, a.status, sizeof prev);
            read_status_file(&a);
            if (k != a.status_kind || strcmp(prev, a.status)) a.dirty = 1;
        }
        if (a.dirty && !a.frame_pending) render(&a);
    }
    return 0;
}
