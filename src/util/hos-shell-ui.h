/*
 * hos-shell-ui.h -- what the desktop shell's clients draw alike: the application icon art and the
 * DOMAIN BADGE every icon carries.
 *
 * Used by the desktop (wl-wallpaper), the launcher dock (wl-dock), the app grid (wl-overview) and the
 * first-boot overlay (wl-welcome).  Header-only -- static functions -- so each client keeps its own
 * single-file build; it needs cairo (with cairo-ft for text) and FreeType.
 *
 * The icon art is vector (cairo), so it scales and needs no image assets.  The badge makes an icon
 * say which domain the program runs in: a ring in the domain's colour around the tile and the
 * domain's short tag, small, at its bottom left.  Colour and tag come from the kernel's
 * /config/domains.json ("color", "abbr" -- the tag is set in ~/.config/anonymos/domains.conf), and
 * where a program runs from /config/appgate.json "placement".
 */
#ifndef HOS_SHELL_UI_H
#define HOS_SHELL_UI_H

#include <cairo/cairo.h>
#include <cairo/cairo-ft.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define HOS_ACCENT  0x0d8577u
#define HOS_ACCENT2 0x14a595u

/* ── cairo shapes ──────────────────────────────────────────────────────────────────────────── */
static inline void hos_set_rgb(cairo_t *cr, uint32_t c)
{
    cairo_set_source_rgb(cr, ((c >> 16) & 0xff) / 255.0, ((c >> 8) & 0xff) / 255.0, (c & 0xff) / 255.0);
}
static inline void hos_set_rgba(cairo_t *cr, uint32_t c, double al)
{
    cairo_set_source_rgba(cr, ((c >> 16) & 0xff) / 255.0, ((c >> 8) & 0xff) / 255.0, (c & 0xff) / 255.0, al);
}
static inline void hos_rr_path(cairo_t *cr, double x, double y, double w, double h, double r)
{
    if (r * 2 > h) r = h / 2;
    if (r * 2 > w) r = w / 2;
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r,     r, -M_PI / 2, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0,         M_PI / 2);
    cairo_arc(cr, x + r,     y + h - r, r, M_PI / 2,  M_PI);
    cairo_arc(cr, x + r,     y + r,     r, M_PI,      3 * M_PI / 2);
    cairo_close_path(cr);
}

/* ── icon art ──────────────────────────────────────────────────────────────────────────────── */
enum { HOS_G_HOME, HOS_G_TERMINAL, HOS_G_SOFTWARE, HOS_G_VMS, HOS_G_DOMAINS, HOS_G_TRASH,
       HOS_G_FOLDER, HOS_G_FILE, HOS_G_IMAGE, HOS_G_TEXT, HOS_G_LAUNCHER };

static inline uint32_t hos_tile_color(int glyph)
{
    switch (glyph) {
    case HOS_G_HOME:     return HOS_ACCENT;
    case HOS_G_TERMINAL: return 0x2a3641u;
    case HOS_G_SOFTWARE: return 0xe8590cu;
    case HOS_G_VMS:      return 0x1971c2u;
    case HOS_G_DOMAINS:  return 0x7048e8u;
    case HOS_G_TRASH:    return 0x4b5563u;
    default:             return 0x3b4652u;
    }
}
static inline uint32_t hos_hash_color(const char *s)
{
    static const uint32_t pal[] = { 0x1971c2u, 0xe8590cu, 0x2f9e44u, 0x7048e8u, 0xc2255cu, 0x0c8599u,
                                    0xf08c00u, 0x5c7cfau };
    unsigned h = 5381;
    for (; *s; s++) h = h * 33 + (unsigned char)*s;
    return pal[h % (sizeof pal / sizeof pal[0])];
}

/* A rounded tile: soft drop shadow (so it lifts off a busy wallpaper), a top-lit gradient, a faint
 * inner rim. */
static inline void hos_tile_base(cairo_t *cr, double x, double y, double s, uint32_t c)
{
    double r = s * 0.24;
    double cr_ = ((c >> 16) & 0xff) / 255.0, cg = ((c >> 8) & 0xff) / 255.0, cb = (c & 0xff) / 255.0;
    hos_rr_path(cr, x + 1, y + 2.5, s - 2, s - 1, r);
    cairo_set_source_rgba(cr, 0, 0, 0, 0.42);
    cairo_fill(cr);
    cairo_pattern_t *g = cairo_pattern_create_linear(0, y, 0, y + s);
    cairo_pattern_add_color_stop_rgb(g, 0, cr_ + (1 - cr_) * 0.16, cg + (1 - cg) * 0.16, cb + (1 - cb) * 0.16);
    cairo_pattern_add_color_stop_rgb(g, 1, cr_ * 0.9, cg * 0.9, cb * 0.9);
    hos_rr_path(cr, x, y, s, s, r);
    cairo_set_source(cr, g);
    cairo_fill(cr);
    cairo_pattern_destroy(g);
    hos_rr_path(cr, x + 0.5, y + 0.5, s - 1, s - 1, r);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.14);
    cairo_set_line_width(cr, 1);
    cairo_stroke(cr);
}

static inline void hos_page_shape(cairo_t *cr, double x, double y, double s)
{
    double ix = x + s * 0.18, iy = y + s * 0.05, w = s * 0.64, h = s * 0.9, fold = s * 0.2;
    cairo_move_to(cr, ix, iy);
    cairo_line_to(cr, ix + w - fold, iy);
    cairo_line_to(cr, ix + w, iy + fold);
    cairo_line_to(cr, ix + w, iy + h);
    cairo_line_to(cr, ix, iy + h);
    cairo_close_path(cr);
}
/* A sheet of paper with a folded corner. */
static inline void hos_draw_page(cairo_t *cr, double x, double y, double s)
{
    cairo_save(cr);
    cairo_translate(cr, 1, 2);
    hos_page_shape(cr, x, y, s);
    cairo_set_source_rgba(cr, 0, 0, 0, 0.4);
    cairo_fill(cr);
    cairo_restore(cr);
    hos_page_shape(cr, x, y, s);
    hos_set_rgb(cr, 0xf4f6f9u);
    cairo_fill_preserve(cr);
    hos_set_rgb(cr, 0xaab4c1u);
    cairo_set_line_width(cr, 1);
    cairo_stroke(cr);
    double ix = x + s * 0.18, iy = y + s * 0.05, w = s * 0.64, fold = s * 0.2;
    cairo_move_to(cr, ix + w - fold, iy);
    cairo_line_to(cr, ix + w - fold, iy + fold);
    cairo_line_to(cr, ix + w, iy + fold);
    cairo_close_path(cr);
    hos_set_rgb(cr, 0xd3dae3u);
    cairo_fill(cr);
}

/* A padlock disc: shown on an icon the desktop may not start. */
static inline void hos_lock_badge(cairo_t *cr, double cx, double cy)
{
    cairo_new_sub_path(cr);
    cairo_arc(cr, cx, cy, 9, 0, 2 * M_PI);
    hos_set_rgb(cr, 0x1b232bu);
    cairo_fill_preserve(cr);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.6);
    cairo_set_line_width(cr, 1);
    cairo_stroke(cr);
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_rectangle(cr, cx - 4.5, cy - 1.5, 9, 6.5);
    cairo_fill(cr);
    cairo_new_sub_path(cr);
    cairo_arc(cr, cx, cy - 1.5, 3, M_PI, 2 * M_PI);
    cairo_set_line_width(cr, 1.6);
    cairo_stroke(cr);
}

/* The art of one icon in an s x s square -- everything but text: a launcher's initial and a file's
 * extension are drawn by the caller in its own fonts, over the tile / badge this leaves for them.
 * `name` picks a launcher's tile colour; `ext` non-empty draws a file's extension badge;
 * `trash_full` puts paper in the bin. */
static inline void hos_icon_art(cairo_t *cr, int glyph, double x, double y, double s,
                                const char *name, const char *ext, int trash_full)
{
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    uint32_t tc = hos_tile_color(glyph);
    double lw = s * 0.07;
    switch (glyph) {
    case HOS_G_HOME:                                        /* a house */
        hos_tile_base(cr, x, y, s, tc);
        cairo_set_source_rgb(cr, 1, 1, 1);
        cairo_set_line_width(cr, lw);
        cairo_move_to(cr, x + s * 0.2, y + s * 0.5);
        cairo_line_to(cr, x + s * 0.5, y + s * 0.23);
        cairo_line_to(cr, x + s * 0.8, y + s * 0.5);
        cairo_stroke(cr);
        cairo_rectangle(cr, x + s * 0.29, y + s * 0.47, s * 0.42, s * 0.31);
        cairo_fill(cr);
        hos_set_rgb(cr, tc);
        cairo_rectangle(cr, x + s * 0.45, y + s * 0.59, s * 0.1, s * 0.19);
        cairo_fill(cr);
        break;
    case HOS_G_TERMINAL:                                    /* a prompt on a screen */
        hos_tile_base(cr, x, y, s, tc);
        hos_rr_path(cr, x + s * 0.15, y + s * 0.2, s * 0.7, s * 0.6, s * 0.07);
        hos_set_rgb(cr, 0x0c1116u);
        cairo_fill(cr);
        cairo_set_line_width(cr, lw);
        hos_set_rgb(cr, HOS_ACCENT2);
        cairo_move_to(cr, x + s * 0.27, y + s * 0.37);
        cairo_line_to(cr, x + s * 0.4, y + s * 0.5);
        cairo_line_to(cr, x + s * 0.27, y + s * 0.63);
        cairo_stroke(cr);
        cairo_set_source_rgb(cr, 1, 1, 1);
        cairo_move_to(cr, x + s * 0.47, y + s * 0.64);
        cairo_line_to(cr, x + s * 0.68, y + s * 0.64);
        cairo_stroke(cr);
        break;
    case HOS_G_SOFTWARE:                                    /* a shopping bag with a download arrow */
        hos_tile_base(cr, x, y, s, tc);
        cairo_set_source_rgb(cr, 1, 1, 1);
        hos_rr_path(cr, x + s * 0.24, y + s * 0.37, s * 0.52, s * 0.42, s * 0.05);
        cairo_fill(cr);
        cairo_set_line_width(cr, s * 0.06);
        cairo_new_sub_path(cr);
        cairo_arc(cr, x + s * 0.5, y + s * 0.37, s * 0.13, M_PI, 2 * M_PI);
        cairo_stroke(cr);
        hos_set_rgb(cr, tc);
        cairo_set_line_width(cr, s * 0.055);
        cairo_move_to(cr, x + s * 0.5, y + s * 0.46);
        cairo_line_to(cr, x + s * 0.5, y + s * 0.68);
        cairo_move_to(cr, x + s * 0.41, y + s * 0.6);
        cairo_line_to(cr, x + s * 0.5, y + s * 0.69);
        cairo_line_to(cr, x + s * 0.59, y + s * 0.6);
        cairo_stroke(cr);
        break;
    case HOS_G_VMS:                                         /* a monitor with a play mark */
        hos_tile_base(cr, x, y, s, tc);
        cairo_set_source_rgb(cr, 1, 1, 1);
        cairo_set_line_width(cr, s * 0.06);
        hos_rr_path(cr, x + s * 0.17, y + s * 0.22, s * 0.66, s * 0.44, s * 0.05);
        cairo_stroke(cr);
        cairo_move_to(cr, x + s * 0.5, y + s * 0.67);
        cairo_line_to(cr, x + s * 0.5, y + s * 0.77);
        cairo_move_to(cr, x + s * 0.35, y + s * 0.78);
        cairo_line_to(cr, x + s * 0.65, y + s * 0.78);
        cairo_stroke(cr);
        cairo_move_to(cr, x + s * 0.44, y + s * 0.34);
        cairo_line_to(cr, x + s * 0.61, y + s * 0.44);
        cairo_line_to(cr, x + s * 0.44, y + s * 0.54);
        cairo_close_path(cr);
        cairo_fill(cr);
        break;
    case HOS_G_DOMAINS:                                     /* a shield (the delegation authority) */
        hos_tile_base(cr, x, y, s, tc);
        cairo_set_source_rgb(cr, 1, 1, 1);
        cairo_move_to(cr, x + s * 0.5, y + s * 0.16);
        cairo_line_to(cr, x + s * 0.78, y + s * 0.27);
        cairo_curve_to(cr, x + s * 0.78, y + s * 0.6, x + s * 0.65, y + s * 0.75, x + s * 0.5, y + s * 0.86);
        cairo_curve_to(cr, x + s * 0.35, y + s * 0.75, x + s * 0.22, y + s * 0.6, x + s * 0.22, y + s * 0.27);
        cairo_close_path(cr);
        cairo_fill(cr);
        hos_set_rgb(cr, tc);
        cairo_set_line_width(cr, s * 0.07);
        cairo_move_to(cr, x + s * 0.38, y + s * 0.5);
        cairo_line_to(cr, x + s * 0.47, y + s * 0.6);
        cairo_line_to(cr, x + s * 0.63, y + s * 0.39);
        cairo_stroke(cr);
        break;
    case HOS_G_TRASH: {                                     /* a bin; paper sticks out when full */
        hos_tile_base(cr, x, y, s, tc);
        cairo_set_source_rgb(cr, 1, 1, 1);
        cairo_set_line_width(cr, s * 0.055);
        if (trash_full) {
            cairo_save(cr);
            cairo_set_source_rgba(cr, 1, 1, 1, 0.9);
            cairo_rectangle(cr, x + s * 0.36, y + s * 0.13, s * 0.14, s * 0.18);
            cairo_rectangle(cr, x + s * 0.52, y + s * 0.16, s * 0.12, s * 0.15);
            cairo_fill(cr);
            cairo_restore(cr);
        }
        cairo_move_to(cr, x + s * 0.22, y + s * 0.32);
        cairo_line_to(cr, x + s * 0.78, y + s * 0.32);
        cairo_stroke(cr);
        cairo_move_to(cr, x + s * 0.28, y + s * 0.36);
        cairo_line_to(cr, x + s * 0.33, y + s * 0.82);
        cairo_line_to(cr, x + s * 0.67, y + s * 0.82);
        cairo_line_to(cr, x + s * 0.72, y + s * 0.36);
        cairo_stroke(cr);
        cairo_set_line_width(cr, s * 0.04);
        for (int k = 0; k < 3; k++) {
            double lx = x + s * (0.4 + k * 0.1);
            cairo_move_to(cr, lx, y + s * 0.44);
            cairo_line_to(cr, lx, y + s * 0.73);
        }
        cairo_stroke(cr);
        break;
    }
    case HOS_G_FOLDER: {                                    /* a folder */
        cairo_save(cr);
        cairo_translate(cr, 1, 2);
        hos_rr_path(cr, x + s * 0.05, y + s * 0.14, s * 0.9, s * 0.72, s * 0.08);
        cairo_set_source_rgba(cr, 0, 0, 0, 0.38);
        cairo_fill(cr);
        cairo_restore(cr);
        hos_set_rgb(cr, 0xd4962au);
        hos_rr_path(cr, x + s * 0.05, y + s * 0.12, s * 0.38, s * 0.2, s * 0.06);
        cairo_fill(cr);
        hos_rr_path(cr, x + s * 0.05, y + s * 0.18, s * 0.9, s * 0.66, s * 0.08);
        cairo_fill(cr);
        cairo_pattern_t *g = cairo_pattern_create_linear(0, y + s * 0.3, 0, y + s * 0.86);
        cairo_pattern_add_color_stop_rgb(g, 0, 0.98, 0.80, 0.38);
        cairo_pattern_add_color_stop_rgb(g, 1, 0.92, 0.68, 0.24);
        hos_rr_path(cr, x + s * 0.05, y + s * 0.3, s * 0.9, s * 0.56, s * 0.08);
        cairo_set_source(cr, g);
        cairo_fill(cr);
        cairo_pattern_destroy(g);
        cairo_set_source_rgba(cr, 1, 1, 1, 0.3);
        cairo_set_line_width(cr, 1.2);
        cairo_move_to(cr, x + s * 0.12, y + s * 0.34);
        cairo_line_to(cr, x + s * 0.88, y + s * 0.34);
        cairo_stroke(cr);
        break;
    }
    case HOS_G_IMAGE:                                       /* a page holding a landscape */
        hos_draw_page(cr, x, y, s);
        cairo_rectangle(cr, x + s * 0.26, y + s * 0.3, s * 0.48, s * 0.42);
        hos_set_rgb(cr, 0x4dabf7u);
        cairo_fill(cr);
        cairo_move_to(cr, x + s * 0.26, y + s * 0.72);
        cairo_line_to(cr, x + s * 0.42, y + s * 0.48);
        cairo_line_to(cr, x + s * 0.54, y + s * 0.62);
        cairo_line_to(cr, x + s * 0.62, y + s * 0.54);
        cairo_line_to(cr, x + s * 0.74, y + s * 0.72);
        cairo_close_path(cr);
        hos_set_rgb(cr, 0x2f9e44u);
        cairo_fill(cr);
        cairo_new_sub_path(cr);
        cairo_arc(cr, x + s * 0.63, y + s * 0.4, s * 0.05, 0, 2 * M_PI);
        hos_set_rgb(cr, 0xffd43bu);
        cairo_fill(cr);
        break;
    case HOS_G_TEXT:                                        /* a page of lines */
        hos_draw_page(cr, x, y, s);
        hos_set_rgb(cr, 0x98a3b3u);
        cairo_set_line_width(cr, 1.6);
        for (int k = 0; k < 6; k++) {
            double ly = y + s * (0.3 + k * 0.09);
            cairo_move_to(cr, x + s * 0.28, ly);
            cairo_line_to(cr, x + s * (k == 5 ? 0.55 : 0.72), ly);
        }
        cairo_stroke(cr);
        break;
    case HOS_G_FILE:                                        /* a page with an extension badge */
        hos_draw_page(cr, x, y, s);
        if (ext && ext[0]) {
            hos_rr_path(cr, x + s * 0.1, y + s * 0.56, s * 0.56, s * 0.22, 3);
            hos_set_rgb(cr, hos_hash_color(ext));
            cairo_fill(cr);
        }
        break;
    case HOS_G_LAUNCHER:                                    /* a launcher: a coloured tile (+ initial) */
    default:
        hos_tile_base(cr, x, y, s, hos_hash_color(name ? name : ""));
        break;
    }
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_BUTT);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_MITER);
}

/* Which icon a program gets, from its command line (a .desktop Exec=). */
static inline int hos_glyph_for_exec(const char *exec)
{
    char first[128];
    size_t i = 0;
    while (exec && exec[i] && exec[i] != ' ' && i < sizeof first - 1) { first[i] = exec[i]; i++; }
    first[i] = 0;
    const char *b = strrchr(first, '/');
    b = b ? b + 1 : first;
    if (!strcmp(b, "wl-files"))                                        return HOS_G_HOME;
    if (!strcmp(b, "hos-wifiterm") || !strcmp(b, "wl-term") || !strcmp(b, "gl-term") ||
        !strcmp(b, "hos-term") || !strcmp(b, "ratty"))                return HOS_G_TERMINAL;
    if (!strcmp(b, "wl-software") || !strcmp(b, "store-app"))         return HOS_G_SOFTWARE;
    if (!strcmp(b, "wl-vmm"))                                          return HOS_G_VMS;
    if (!strcmp(b, "wl-domain-manager"))                               return HOS_G_DOMAINS;
    return HOS_G_LAUNCHER;
}

/* ── text (cairo over a FreeType face) ─────────────────────────────────────────────────────── */
struct hos_font { FT_Library lib; FT_Face face; cairo_font_face_t *cf; unsigned char *data; };

/* Load a TTF/OTF; 0 on success.  The font file's bytes stay owned by the font. */
static inline int hos_font_load(struct hos_font *f, const char *path)
{
    memset(f, 0, sizeof *f);
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    size_t cap = 1 << 16, n = 0;
    unsigned char *b = malloc(cap);
    for (;;) {
        if (!b) { fclose(fp); return -1; }
        size_t r = fread(b + n, 1, cap - n, fp);
        n += r;
        if (r == 0) break;
        if (n == cap) { cap *= 2; unsigned char *nb = realloc(b, cap); if (!nb) { free(b); b = NULL; continue; } b = nb; }
    }
    fclose(fp);
    if (FT_Init_FreeType(&f->lib) != 0 || FT_New_Memory_Face(f->lib, b, (FT_Long)n, 0, &f->face) != 0) {
        free(b); return -1;
    }
    f->data = b;
    f->cf = cairo_ft_font_face_create_for_ft_face(f->face, 0);
    return f->cf ? 0 : -1;
}
/* The first font of a list that loads (the image ships Noto; a host test may point elsewhere). */
static inline int hos_font_load_any(struct hos_font *f, const char *const *paths)
{
    for (; *paths; paths++) if (hos_font_load(f, *paths) == 0) return 0;
    return -1;
}
static inline double hos_text_width(cairo_t *cr, struct hos_font *f, double px, const char *s)
{
    if (!f->cf || !s) return 0;
    cairo_set_font_face(cr, f->cf);
    cairo_set_font_size(cr, px);
    cairo_text_extents_t te;
    cairo_text_extents(cr, s, &te);
    return te.x_advance;
}
/* Draw `s` with its top at y (not its baseline). */
static inline void hos_text(cairo_t *cr, struct hos_font *f, double px, double x, double y,
                            uint32_t color, double alpha, const char *s)
{
    if (!f->cf || !s) return;
    cairo_set_font_face(cr, f->cf);
    cairo_set_font_size(cr, px);
    cairo_font_extents_t fe;
    cairo_font_extents(cr, &fe);
    hos_set_rgba(cr, color, alpha);
    cairo_move_to(cr, x, y + fe.ascent);
    cairo_show_text(cr, s);
    cairo_new_path(cr);
}
static inline void hos_text_center(cairo_t *cr, struct hos_font *f, double px, double cx, double y,
                                   uint32_t color, double alpha, const char *s)
{
    hos_text(cr, f, px, cx - hos_text_width(cr, f, px, s) / 2, y, color, alpha, s);
}
/* `s` cut to fit `maxw` pixels, with an ellipsis ("..."), into out. */
static inline void hos_text_fit(cairo_t *cr, struct hos_font *f, double px, const char *s, double maxw,
                                char *out, size_t cap)
{
    snprintf(out, cap, "%s", s);
    if (hos_text_width(cr, f, px, out) <= maxw) return;
    size_t n = strlen(out);
    while (n > 0) {
        out[--n] = 0;
        char t[512];
        snprintf(t, sizeof t, "%s...", out);
        if (hos_text_width(cr, f, px, t) <= maxw) { snprintf(out, cap, "%s", t); return; }
    }
}

/* ── the domains, as the kernel publishes them ─────────────────────────────────────────────── */
struct hos_domain { char name[40]; char abbr[8]; uint32_t color; };

/* Test hook: a directory standing in for / when the kernel's files are read (the clients'
 * offscreen self-tests on a development host).  "" in the OS. */
static const char *hos_root = "";
static inline FILE *hos_fopen_root(const char *path, const char *mode)
{
    if (!hos_root[0] || path[0] != '/') return fopen(path, mode);
    char p[1024];
    snprintf(p, sizeof p, "%s%s", hos_root, path);
    return fopen(p, mode);
}

/* A whole small file, NUL-terminated (malloc'd), or NULL. */
static inline char *hos_read_file(const char *path)
{
    FILE *fp = hos_fopen_root(path, "r");
    if (!fp) return NULL;
    size_t cap = 4096, n = 0;
    char *b = malloc(cap);
    while (b) {
        size_t r = fread(b + n, 1, cap - n - 1, fp);
        n += r;
        if (r == 0) break;
        if (n + 1 >= cap) { cap *= 2; char *nb = realloc(b, cap); if (!nb) { free(b); b = NULL; break; } b = nb; }
    }
    fclose(fp);
    if (b) b[n] = 0;
    return b;
}
/* The string value of "key": "..." at or after p (within the same object), into out. */
static inline int hos_json_str(const char *p, const char *end, const char *key, char *out, size_t cap)
{
    char k[48];
    snprintf(k, sizeof k, "\"%s\"", key);
    const char *q = strstr(p, k);
    if (!q || (end && q >= end)) return 0;
    q += strlen(k);
    while (*q == ' ' || *q == ':') q++;
    if (*q != '"') return 0;
    q++;
    size_t n = 0;
    while (*q && *q != '"' && n + 1 < cap) { if (*q == '\\' && q[1]) q++; out[n++] = *q++; }
    out[n] = 0;
    return 1;
}
/* Every domain in /config/domains.json (templates too), into a malloc'd array; the count, or 0. */
static inline int hos_domains_load(struct hos_domain **out)
{
    *out = NULL;
    char *js = hos_read_file("/config/domains.json");
    if (!js) return 0;
    int n = 0, cap = 0;
    struct hos_domain *v = NULL;
    for (const char *p = js; (p = strchr(p, '{')); ) {
        const char *end = strchr(p, '}');
        if (!end) break;
        struct hos_domain d;
        memset(&d, 0, sizeof d);
        char col[24] = "";
        if (hos_json_str(p, end, "name", d.name, sizeof d.name)) {
            if (hos_json_str(p, end, "color", col, sizeof col)) d.color = (uint32_t)strtoul(col, NULL, 16) & 0xffffffu;
            else d.color = 0x808080u;
            if (!hos_json_str(p, end, "abbr", d.abbr, sizeof d.abbr)) {
                size_t k = 0;
                for (const char *c = d.name; *c && k < 3; c++) if (isalnum((unsigned char)*c)) d.abbr[k++] = (char)toupper((unsigned char)*c);
                d.abbr[k] = 0;
            }
            if (n == cap) {
                cap = cap ? cap * 2 : 16;
                struct hos_domain *nv = realloc(v, (size_t)cap * sizeof *v);
                if (!nv) break;
                v = nv;
            }
            v[n++] = d;
        }
        p = end + 1;
    }
    free(js);
    *out = v;
    return n;
}
static inline const struct hos_domain *hos_domain_find(const struct hos_domain *d, int n, const char *name)
{
    if (!name || !name[0]) return NULL;
    for (int i = 0; i < n; i++) if (!strcmp(d[i].name, name)) return &d[i];
    return NULL;
}

/* Where a program runs when the desktop starts it: /config/appgate.json "placement" names the domain
 * per program image (a registry app), and anything else -- an installed package -- runs in the
 * session domain.  `appgate` is that file's text (hos_read_file); out gets the domain name, or ""
 * when it runs unconfined. */
static inline void hos_placement_of(const char *appgate, const char *exec, char *out, size_t cap)
{
    out[0] = 0;
    if (!appgate) return;
    char first[128];
    size_t i = 0;
    while (exec && exec[i] && exec[i] != ' ' && i < sizeof first - 1) { first[i] = exec[i]; i++; }
    first[i] = 0;
    const char *b = strrchr(first, '/');
    b = b ? b + 1 : first;
    const char *pl = strstr(appgate, "\"placement\"");
    if (pl) {
        char k[160];
        snprintf(k, sizeof k, "\"%s\":", b);
        const char *q = strstr(pl, k);
        if (q) {
            q += strlen(k);
            while (*q == ' ') q++;
            if (*q != '"') return;                              /* null: unconfined */
            q++;
            size_t n = 0;
            while (*q && *q != '"' && n + 1 < cap) out[n++] = *q++;
            out[n] = 0;
            return;
        }
    }
    hos_json_str(appgate, NULL, "session", out, cap);          /* a package: the session domain */
}

/* The domain badge on an s x s icon at (x, y): a ring in the domain's colour around the tile, and
 * the domain's tag in small letters on a pill at the icon's bottom left -- so an icon always says
 * which domain the program is in. */
static inline void hos_domain_badge(cairo_t *cr, struct hos_font *f, double x, double y, double s,
                                    const struct hos_domain *d)
{
    if (!d) return;
    const double ring = s >= 48 ? 2.5 : 2;
    hos_rr_path(cr, x - ring / 2 - 1, y - ring / 2 - 1, s + ring + 2, s + ring + 2, s * 0.24 + ring);
    hos_set_rgb(cr, d->color);
    cairo_set_line_width(cr, ring);
    cairo_stroke(cr);
    if (!d->abbr[0]) return;
    const double px = s >= 64 ? 10 : 8.5;
    const double tw = hos_text_width(cr, f, px, d->abbr);
    const double ph = px + 4, pw = tw + 7;
    const double bx = x - 2, by = y + s - ph + 2;
    hos_rr_path(cr, bx, by, pw, ph, ph / 2);
    hos_set_rgb(cr, d->color);
    cairo_fill_preserve(cr);
    cairo_set_source_rgba(cr, 0, 0, 0, 0.35);
    cairo_set_line_width(cr, 1);
    cairo_stroke(cr);
    /* dark text on a light domain colour, white on a dark one */
    const double lum = 0.299 * ((d->color >> 16) & 0xff) + 0.587 * ((d->color >> 8) & 0xff) + 0.114 * (d->color & 0xff);
    hos_text(cr, f, px, bx + 3.5, by + 1.5, lum > 150 ? 0x10141au : 0xffffffu, 1, d->abbr);
}

/* One request to the compositor's IPC socket (Hyprland: "j/binds", "j/monitors", "eval <lua>");
 * returns its reply (malloc'd, NUL-terminated) or NULL. */
#define HOS_HYPR_DIR "/run/user/1000/hypr"
static __attribute__((unused)) char *hos_hypr_request(const char *req)
{
    DIR *d = opendir(HOS_HYPR_DIR);
    if (!d) return NULL;
    char path[256] = "";
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof path, HOS_HYPR_DIR "/%s/.socket.sock", e->d_name);
        break;
    }
    closedir(d);
    if (!path[0]) return NULL;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0 || write(fd, req, strlen(req)) < 0) { close(fd); return NULL; }
    size_t cap = 1 << 16, n = 0;
    char *b = malloc(cap);
    for (;;) {
        if (!b) break;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, 2000) <= 0) break;
        ssize_t r = read(fd, b + n, cap - n - 1);
        if (r <= 0) break;
        n += (size_t)r;
        if (n + 1 >= cap) { cap *= 2; char *nb = realloc(b, cap); if (!nb) { free(b); b = NULL; break; } b = nb; }
    }
    close(fd);
    if (b) b[n] = 0;
    return b;
}

#endif /* HOS_SHELL_UI_H */
