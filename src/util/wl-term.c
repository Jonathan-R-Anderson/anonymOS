// wl-term.c — GUI roadmap G4/G9: a minimal software-rendered Wayland terminal.
//
// A wl_shm client that paints an 80x24 character grid with antialiased FreeType
// text when the bundled Noto Sans Mono asset is available, takes keyboard input
// via wl_keyboard, and hosts an interactive busybox shell on a kernel
// pseudo-terminal (/dev/ptmx + /dev/pts/N).  Everything read from the master is
// also mirrored to stdout as "G4OUT: ..." so the prompt and typed-command output
// are checkable on serial.
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <wayland-client.h>
#include <ft2build.h>
#include FT_FREETYPE_H

#include "xdg-shell-client-protocol.h"
#include "gui_font.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef TIOCGPTN
#define TIOCGPTN   0x80045430
#define TIOCSPTLCK 0x40045431
#endif

extern char **environ;

enum { COLS = 80, ROWS = 24 };
enum { SB_CAP = 1000 };            // scrollback ring capacity (lines)
enum { SCROLLBAR_W = 10 };         // scrollbar width (base px, scaled)
enum { BASE_FONT_PX = 17, BASE_CELL_W = 10, BASE_CELL_H = 20 };

static const uint32_t COL_BG     = 0xff101418;
static const uint32_t COL_FG     = 0xfff2f2f2;
static const uint32_t COL_CURSOR = 0xff30c030;

// Client-side window decorations: a titlebar with minimize / maximize / close
// buttons, drawn into the pixel buffer; the titlebar is also draggable (move).
#define DECO_BASE_H 26          // titlebar height in base (scale=1) px
#define BTN_LEFT_CODE 0x110     // linux/input BTN_LEFT
static const uint32_t COL_DECO_BG = 0xff2a3140;   // titlebar bg (no-domain default)
static const uint32_t COL_DECO_FG = 0xfff2f2f2;   // titlebar text + button glyphs
static const uint32_t COL_DECO_SEP = 0xff10141a;  // hairline under the titlebar
static const uint32_t COL_SB_TRACK = 0xff20262e;  // scrollback scrollbar track (subtle)
static const uint32_t COL_SB_THUMB = 0xff5a6675;  // scrollbar thumb (brighter)

// Z7.1: ANSI SGR colour support.  The 16-colour base palette (ARGB, opaque) — a
// muted "Tango"-ish set that reads well on the dark COL_BG; indices 0-7 normal,
// 8-15 bright.  256-colour (38;5;N) and 24-bit truecolour (38;2;R;G;B) build on it.
static const uint32_t ANSI16[16] = {
    0xff263238, 0xffe53935, 0xff43a047, 0xfffdd835,  // black  red     green  yellow
    0xff3b82f6, 0xffab47bc, 0xff00acc1, 0xffd0d4d8,  // blue   magenta cyan   white
    0xff546e7a, 0xffff6e6e, 0xff81c784, 0xfffff176,  // br-blk br-red  br-grn br-yel
    0xff64b5f6, 0xffce93d8, 0xff4dd0e1, 0xfff5f5f5   // br-blu br-mag  br-cyn br-wht
};
static uint32_t ansi256(int n) {
    if (n < 0)   n = 0;
    if (n > 255) n = 255;
    if (n < 16)  return ANSI16[n];
    if (n < 232) {                      // 6x6x6 colour cube
        n -= 16;
        int r = n / 36, g = (n / 6) % 6, b = n % 6;
        int R = r ? r * 40 + 55 : 0, G = g ? g * 40 + 55 : 0, B = b ? b * 40 + 55 : 0;
        return 0xff000000u | ((uint32_t)R << 16) | ((uint32_t)G << 8) | (uint32_t)B;
    }
    int v = (n - 232) * 10 + 8;         // 24-step grayscale ramp
    return 0xff000000u | ((uint32_t)v << 16) | ((uint32_t)v << 8) | (uint32_t)v;
}

// IDENTITY_DOMAIN: the security domain this terminal was launched into (set by the
// Domain Manager via EPIN_DOMAIN / EPIN_DOMAIN_COLOR).  Drawn as an unspoofable
// colored border + window title so the user always sees which domain a terminal
// belongs to (the same identity color the kernel stamps on windows, §6).
static int      g_has_domain = 0;
static char     g_domain[64] = {0};
static uint32_t g_domain_color = 0xff3b82f6u;

struct app {
    struct wl_display    *display;
    struct wl_registry   *registry;
    struct wl_compositor *compositor;
    struct wl_shm        *shm;
    struct xdg_wm_base   *wm_base;
    struct wl_seat       *seat;
    struct wl_keyboard   *keyboard;
    struct wl_surface    *surface;
    struct xdg_surface   *xdg_surface;
    struct xdg_toplevel  *toplevel;
    struct wl_pointer    *pointer;
    double                px, py;       // pointer position (surface coords)
    uint32_t              ptr_serial;   // latest pointer event serial (for the move grab)
    int                   maximized;
    int                   deco_h;       // titlebar height (scaled px)
    char                  title[96];
    struct wl_buffer     *buffer;
    struct wl_callback   *frame_cb;
    uint32_t             *pixels;
    size_t                pix_bytes;    // mmap'd size of *pixels (for munmap on resize)
    int                   width, height;
    int                   cfg_w, cfg_h; // last compositor-requested surface size (tiling WM)
    int                   cell_w, cell_h;
    int                   font_px, baseline;
    int                   scale;
    int                   committed;
    int                   post_map_frame_armed;
    int                   post_map_frame_done;
    int                   running;

    int                   ptm;     // PTY master fd
    int                   shift, ctrl;

    char                  grid[ROWS][COLS];
    uint32_t              fgc[ROWS][COLS];   // Z7.1: per-cell foreground (ARGB)
    uint32_t              bgc[ROWS][COLS];   // Z7.1: per-cell background (0 = default COL_BG)
    uint32_t              pen_fg, pen_bg;    // current SGR pen
    int                   pen_rev;           // reverse video (SGR 7)
    int                   cur_r, cur_c;
    int                   dirty;

    // Scrollback ring (oldest at logical 0). When full, sb_head is the oldest physical slot.
    char                  sb_ch[SB_CAP][COLS];
    uint32_t              sb_fg[SB_CAP][COLS];
    uint32_t              sb_bg[SB_CAP][COLS];
    int                   sb_head;        // index where the next evicted line is written
    int                   sb_count;       // valid lines (<= SB_CAP)
    int                   view_offset;    // 0 = following live bottom; >0 = scrolled up
    int                   sb_dragging;    // dragging the scrollbar thumb
    double                sb_drag_y0;     // py at drag start
    int                   sb_drag_off0;   // view_offset at drag start

    int                   esc;      // ANSI escape state machine
    char                  csi[24];  // accumulated CSI parameter/intermediate bytes
    int                   csi_len;

    char                  mirror[256];
    int                   mirror_len;

    FT_Library            ft;
    FT_Face               face;
    unsigned char        *font_data;
    size_t                font_size;
    int                   font_ready;
};

static void log_line(const char *s) { fputs(s, stdout); fputc('\n', stdout); fflush(stdout); }

static int create_memfd(const char *name) { return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC); }

static int env_int(const char *name, int def, int min, int max) {
    const char *s = getenv(name);
    if (!s || !*s) return def;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s) return def;
    if (v < min) v = min;
    if (v > max) v = max;
    return (int)v;
}

static void init_layout(struct app *a) {
    a->scale = env_int("HOS_DISPLAY_SCALE", 1, 1, 2);
    a->font_px = BASE_FONT_PX * a->scale;
    a->cell_w = BASE_CELL_W * a->scale;
    a->cell_h = BASE_CELL_H * a->scale;
    a->deco_h = DECO_BASE_H * a->scale;             // reserve a titlebar strip on top
    a->width = COLS * a->cell_w + SCROLLBAR_W * a->scale;  // grid + a strip for the scrollback bar
    a->height = ROWS * a->cell_h + a->deco_h;
    a->baseline = (BASE_FONT_PX - 3) * a->scale;
}

// Reflow the fixed ROWS×COLS grid to fill a compositor-dictated W×H surface (the
// tiling window manager calls weston_desktop_surface_set_size on our window).  The
// grid dimensions are compile-time constants, so we do NOT change the number of
// rows/columns — that would need a full dynamic-grid rewrite; instead we scale the
// per-cell pixel size and the FreeType raster size so the 80×24 grid stretches to
// fill whatever tile is assigned.  deco_h (titlebar) and the scrollbar strip keep
// their fixed widths.  All rendering helpers clip to width/height, so any size is
// safe.  This is called from the xdg_surface configure handler after ack.
static void apply_size(struct app *a, int w, int h) {
    if (w < 1) w = 1;
    if (h < 1) h = 1;
    a->width  = w;
    a->height = h;
    int content_w = w - SCROLLBAR_W * a->scale;   // usable grid area (minus scrollbar)
    int content_h = h - a->deco_h;                // usable grid area (minus titlebar)
    if (content_w < COLS) content_w = COLS;       // guarantee >=1px per column
    if (content_h < ROWS) content_h = ROWS;       // guarantee >=1px per row
    a->cell_w = content_w / COLS; if (a->cell_w < 1) a->cell_w = 1;
    a->cell_h = content_h / ROWS; if (a->cell_h < 1) a->cell_h = 1;
    // Pick a font pixel size that fits BOTH cell dimensions, preserving the glyph
    // proportion the base layout uses (a 10×20 cell at 17px).
    int fpw = a->cell_w * BASE_FONT_PX / BASE_CELL_W;
    int fph = a->cell_h * BASE_FONT_PX / BASE_CELL_H;
    a->font_px = fpw < fph ? fpw : fph;
    if (a->font_px < 6) a->font_px = 6;
    a->baseline = a->font_px - 2;                 // fallback (used by the 8×8 bitmap path)
    if (a->font_ready && FT_Set_Pixel_Sizes(a->face, 0, (FT_UInt)a->font_px) == 0) {
        if (a->face->size && a->face->size->metrics.ascender > 0)
            a->baseline = (int)(a->face->size->metrics.ascender >> 6) + a->scale;
    }
}

static int load_file(const char *path, unsigned char **out, size_t *out_size) {
    *out = NULL;
    *out_size = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    size_t cap = 65536;
    size_t len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) { close(fd); return -1; }

    for (;;) {
        if (len == cap) {
            size_t next = cap * 2;
            unsigned char *nb = realloc(buf, next);
            if (!nb) { free(buf); close(fd); return -1; }
            buf = nb;
            cap = next;
        }
        ssize_t n = read(fd, buf + len, cap - len);
        if (n > 0) {
            len += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { free(buf); close(fd); return -1; }
        break;
    }
    close(fd);
    if (len == 0) { free(buf); return -1; }
    *out = buf;
    *out_size = len;
    return 0;
}

static int init_freetype(struct app *a) {
    const char *env_font = getenv("HOS_TERMINAL_FONT");
    const char *fallbacks[] = {
        "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
        "/usr/share/fonts/NotoSansMono-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
        NULL,
    };

    for (int i = -1; ; i++) {
        const char *path = (i < 0) ? env_font : fallbacks[i];
        if (!path && i < 0) continue;
        if (!path) break;
        if (!*path) continue;
        unsigned char *data = NULL;
        size_t size = 0;
        if (load_file(path, &data, &size) < 0)
            continue;

        if (FT_Init_FreeType(&a->ft) == 0 &&
            FT_New_Memory_Face(a->ft, data, (FT_Long)size, 0, &a->face) == 0 &&
            FT_Set_Pixel_Sizes(a->face, 0, (FT_UInt)a->font_px) == 0) {
            a->font_data = data;
            a->font_size = size;
            a->font_ready = 1;
            if (a->face->size && a->face->size->metrics.ascender > 0)
                a->baseline = (int)(a->face->size->metrics.ascender >> 6) + a->scale;
            printf("G9FONT: loaded %s (%zu bytes), font_px=%d cell=%dx%d window=%dx%d -- G9 FONT\n",
                   path, size, a->font_px, a->cell_w, a->cell_h, a->width, a->height);
            fflush(stdout);
            return 0;
        }

        if (a->face) { FT_Done_Face(a->face); a->face = NULL; }
        if (a->ft) { FT_Done_FreeType(a->ft); a->ft = NULL; }
        free(data);
    }

    printf("G9FONT: failed to load Noto Sans Mono; using 8x8 bitmap fallback, cell=%dx%d window=%dx%d\n",
           a->cell_w, a->cell_h, a->width, a->height);
    fflush(stdout);
    return -1;
}

static uint32_t blend_over(uint32_t dst, uint32_t src, unsigned int alpha) {
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

static void render_ft_glyph(struct app *a, int x, int y, unsigned char ch, uint32_t fg) {
    if (!a->font_ready || ch < 0x20 || ch >= 0x7f) return;
    if (FT_Load_Char(a->face, (FT_ULong)ch, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) != 0)
        return;
    FT_GlyphSlot g = a->face->glyph;
    FT_Bitmap *bm = &g->bitmap;
    int gx = x + g->bitmap_left;
    int gy = y + a->baseline - g->bitmap_top;
    int pitch = bm->pitch;
    const unsigned char *base = bm->buffer;
    if (pitch < 0) {
        pitch = -pitch;
        base = bm->buffer - (int)(bm->rows - 1) * pitch;
    }
    for (int row = 0; row < (int)bm->rows; row++) {
        int py = gy + row;
        if (py < 0 || py >= a->height) continue;
        const unsigned char *src_row = base + row * pitch;
        for (int col = 0; col < (int)bm->width; col++) {
            int px = gx + col;
            if (px < 0 || px >= a->width) continue;
            unsigned int alpha = 0;
            if (bm->pixel_mode == FT_PIXEL_MODE_GRAY) {
                alpha = src_row[col];
            } else if (bm->pixel_mode == FT_PIXEL_MODE_MONO) {
                alpha = (src_row[col >> 3] & (0x80 >> (col & 7))) ? 255 : 0;
            }
            uint32_t *dst = &a->pixels[py * a->width + px];
            *dst = blend_over(*dst, fg, alpha);
        }
    }
}

// ── window decorations (titlebar + min/max/close buttons) ────────────────────
static void put_px(struct app *a, int x, int y, uint32_t c) {
    if (x < 0 || y < 0 || x >= a->width || y >= a->height) return;
    a->pixels[y * a->width + x] = c;
}
// Button column x-origins (square buttons, right-aligned). Returns button width.
static int deco_btns(struct app *a, int *minx, int *maxx, int *closex) {
    int w = a->deco_h;
    *closex = a->width - w;
    *maxx   = a->width - 2 * w;
    *minx   = a->width - 3 * w;
    return w;
}
// Hit-test a pointer in surface coords: 0=content, 1=titlebar(drag), 2=min, 3=max, 4=close.
static int deco_hit(struct app *a, double x, double y) {
    if (y < 0 || y >= a->deco_h) return 0;
    int minx, maxx, closex; deco_btns(a, &minx, &maxx, &closex);
    if (x >= closex) return 4;
    if (x >= maxx)   return 3;
    if (x >= minx)   return 2;
    return 1;
}
static void draw_deco(struct app *a) {
    const uint32_t bg = g_has_domain ? g_domain_color : COL_DECO_BG;
    gf_fill(a->pixels, a->width, a->width, a->height, 0, 0, a->width, a->deco_h, bg);
    gf_fill(a->pixels, a->width, a->width, a->height, 0, a->deco_h - 1, a->width, 1, COL_DECO_SEP);

    int minx, maxx, closex, bw; bw = deco_btns(a, &minx, &maxx, &closex);
    const int pad = a->deco_h / 3;

    // title text on the left, truncated before the buttons
    int tx = 6 * a->scale;
    int ty = (a->deco_h - a->cell_h) / 2; if (ty < 0) ty = 0;
    for (const char *p = a->title; *p && tx + a->cell_w < minx - 4; ++p) {
        if (*p != ' ') render_ft_glyph(a, tx, ty, (unsigned char)*p, COL_DECO_FG);
        tx += a->cell_w;
    }
    // minimize: a horizontal bar near the bottom
    gf_fill(a->pixels, a->width, a->width, a->height,
            minx + pad, a->deco_h - pad - 2, bw - 2 * pad, 2, COL_DECO_FG);
    // maximize: a hollow square
    {
        int x0 = maxx + pad, y0 = pad, s = a->deco_h - 2 * pad;
        gf_fill(a->pixels, a->width, a->width, a->height, x0, y0, s, 1, COL_DECO_FG);
        gf_fill(a->pixels, a->width, a->width, a->height, x0, y0 + s - 1, s, 1, COL_DECO_FG);
        gf_fill(a->pixels, a->width, a->width, a->height, x0, y0, 1, s, COL_DECO_FG);
        gf_fill(a->pixels, a->width, a->width, a->height, x0 + s - 1, y0, 1, s, COL_DECO_FG);
    }
    // close: an X (two diagonals)
    {
        int x0 = closex + pad, y0 = pad, s = a->deco_h - 2 * pad;
        for (int i = 0; i < s; i++) {
            put_px(a, x0 + i, y0 + i, COL_DECO_FG);
            put_px(a, x0 + s - 1 - i, y0 + i, COL_DECO_FG);
        }
    }
}

static void frame_done(void *data, struct wl_callback *cb, uint32_t time)
{
    (void)time;
    struct app *a = data;
    wl_callback_destroy(cb);
    if (a && a->frame_cb == cb)
        a->frame_cb = NULL;
    if (!a)
        return;
    a->post_map_frame_armed = 0;
    a->post_map_frame_done = 1;
    a->dirty = 1;
    log_line("G9FRAME: post-map frame callback; scheduling terminal redraw -- G9 FRAME");
}

static const struct wl_callback_listener frame_listener = { .done = frame_done };

// ── terminal grid ────────────────────────────────────────────────────────────
static void grid_clear(struct app *a) {
    for (int r = 0; r < ROWS; r++)
        for (int c = 0; c < COLS; c++) {
            a->grid[r][c] = ' ';
            a->fgc[r][c] = COL_FG;
            a->bgc[r][c] = 0;
        }
    a->cur_r = a->cur_c = 0;
    a->pen_fg = COL_FG; a->pen_bg = 0; a->pen_rev = 0;
}

static void grid_scroll(struct app *a) {
    // Push the row about to be discarded (row 0) into the scrollback ring.
    int slot = a->sb_head;
    memcpy(a->sb_ch[slot], a->grid[0], COLS);
    memcpy(a->sb_fg[slot], a->fgc[0],  COLS * sizeof(uint32_t));
    memcpy(a->sb_bg[slot], a->bgc[0],  COLS * sizeof(uint32_t));
    a->sb_head = (a->sb_head + 1) % SB_CAP;
    if (a->sb_count < SB_CAP) a->sb_count++;
    // Keep a scrolled-up view stable: the virtual sequence grew one line at the bottom.
    if (a->view_offset > 0 && a->view_offset < a->sb_count) a->view_offset++;
    for (int r = 0; r < ROWS - 1; r++) {
        memcpy(a->grid[r], a->grid[r + 1], COLS);
        memcpy(a->fgc[r],  a->fgc[r + 1],  COLS * sizeof(uint32_t));
        memcpy(a->bgc[r],  a->bgc[r + 1],  COLS * sizeof(uint32_t));
    }
    for (int c = 0; c < COLS; c++) {
        a->grid[ROWS - 1][c] = ' ';
        a->fgc[ROWS - 1][c] = COL_FG;
        a->bgc[ROWS - 1][c] = 0;
    }
}

static void clamp_view(struct app *a) {
    if (a->view_offset < 0) a->view_offset = 0;
    if (a->view_offset > a->sb_count) a->view_offset = a->sb_count;   // max = scroll to oldest line
}
// Resolve screen row sr (0..ROWS-1) to a source: 1 + ring pointers if from scrollback, else 0 +
// *live_r (a live-grid row).  Virtual sequence: [ring 0..sb_count) then [live grid 0..ROWS).
static int view_src(struct app *a, int sr, char **ch, uint32_t **fg, uint32_t **bg, int *live_r) {
    int src_i = (a->sb_count - a->view_offset) + sr;   // view_offset<=sb_count -> src_i>=0
    if (src_i < a->sb_count) {
        int slot = (a->sb_count == SB_CAP) ? (a->sb_head + src_i) % SB_CAP : src_i; // full: head=oldest
        *ch = a->sb_ch[slot]; *fg = a->sb_fg[slot]; *bg = a->sb_bg[slot];
        return 1;
    }
    *live_r = src_i - a->sb_count;
    return 0;
}
// Scrollbar geometry in surface coords. Returns 0 if there is no history (no bar).
static int scrollbar_geom(struct app *a, int *tx, int *ty, int *tw, int *th, int *thumb_y, int *thumb_h) {
    if (a->sb_count <= 0) return 0;
    int w = SCROLLBAR_W * a->scale;
    *tw = w; *tx = a->width - w;
    *ty = a->deco_h;
    *th = a->height - a->deco_h - (g_has_domain ? 4 * a->scale : 0); // keep off the bottom domain border
    int total = a->sb_count + ROWS;
    int h = (int)((double)ROWS / total * (*th));
    if (h < 16) h = 16;
    if (h > *th) h = *th;
    int travel = *th - h;
    // bottom-anchored: view_offset 0 (following) -> thumb at the bottom; max -> top.
    int up = (a->sb_count > 0) ? (int)((double)a->view_offset / a->sb_count * travel) : 0;
    *thumb_y = *ty + (travel - up);
    *thumb_h = h;
    return 1;
}
static void draw_scrollbar(struct app *a) {
    int tx, ty, tw, th, thy, thh;
    if (!scrollbar_geom(a, &tx, &ty, &tw, &th, &thy, &thh)) return;
    gf_fill(a->pixels, a->width, a->width, a->height, tx, ty, tw, th, COL_SB_TRACK);
    gf_fill(a->pixels, a->width, a->width, a->height, tx + 1, thy + 1, tw - 2, thh - 2, COL_SB_THUMB);
}

static void grid_newline(struct app *a) {
    a->cur_c = 0;
    if (++a->cur_r >= ROWS) { a->cur_r = ROWS - 1; grid_scroll(a); }
}

// Z3 (terminal coverage): execute a CSI sequence "ESC [ <params> <final>".  Implements
// the subset zsh's ZLE actually emits to redraw an edited line — cursor movement, column
// addressing, and erase — so history recall / in-line editing render correctly (without
// these, replacing a line just appends, e.g. "second-cmdfirst-cmd").  SGR colours (m) and
// private modes (?...) are accepted and ignored.
// Blank cell (r,c): space with the default colours (used by the erase ops so a
// cleared cell drops any colour it carried).
static inline void cell_blank(struct app *a, int r, int c) {
    a->grid[r][c] = ' '; a->fgc[r][c] = COL_FG; a->bgc[r][c] = 0;
}

static void vt_exec_csi(struct app *a, char final) {
    int params[16]; int np = 0, v = 0, have = 0;
    for (int i = 0; i < a->csi_len; i++) {
        char ch = a->csi[i];
        if (ch >= '0' && ch <= '9') { v = v * 10 + (ch - '0'); have = 1; }
        else if (ch == ';') { if (np < 16) params[np++] = have ? v : -1; v = 0; have = 0; }
        // ignore intermediate/private bytes ('?', ' ', etc.) for parameter parsing
    }
    if (np < 16) params[np++] = have ? v : -1;   // always at least one param (-1 if absent)
    int p0 = params[0];                           // absent => -1 (matches the original semantics)
    int p1 = (np >= 2) ? params[1] : -1;
    int n = (p0 > 0) ? p0 : 1;
    switch (final) {
        case 'C': a->cur_c += n; if (a->cur_c >= COLS) a->cur_c = COLS - 1; break;        // cursor right
        case 'D': a->cur_c -= n; if (a->cur_c < 0) a->cur_c = 0; break;                   // cursor left
        case 'A': a->cur_r -= n; if (a->cur_r < 0) a->cur_r = 0; break;                   // cursor up
        case 'B': a->cur_r += n; if (a->cur_r >= ROWS) a->cur_r = ROWS - 1; break;        // cursor down
        case 'G': a->cur_c = (p0 > 0 ? p0 - 1 : 0);                                       // column absolute
                  if (a->cur_c >= COLS) a->cur_c = COLS - 1; if (a->cur_c < 0) a->cur_c = 0; break;
        case 'H': case 'f': {                                                            // cursor position r;c (1-based)
            int rr = (p0 > 0 ? p0 - 1 : 0), cc = (p1 > 0 ? p1 - 1 : 0);
            a->cur_r = rr < 0 ? 0 : (rr >= ROWS ? ROWS - 1 : rr);
            a->cur_c = cc < 0 ? 0 : (cc >= COLS ? COLS - 1 : cc);
            break;
        }
        case 'K': {                                                                      // erase line (0 EOL, 1 BOL, 2 all)
            int mode = (p0 < 0 ? 0 : p0);
            int start = (mode == 1) ? 0 : a->cur_c;
            int end   = (mode == 0) ? COLS - 1 : a->cur_c;
            for (int c = start; c <= end && c < COLS; c++) cell_blank(a, a->cur_r, c);
            break;
        }
        case 'J': {                                                                      // erase display (0 to end, 2 all)
            int mode = (p0 < 0 ? 0 : p0);
            if (mode == 2) { for (int r = 0; r < ROWS; r++) for (int c = 0; c < COLS; c++) cell_blank(a, r, c); }
            else { for (int c = a->cur_c; c < COLS; c++) cell_blank(a, a->cur_r, c);
                   for (int r = a->cur_r + 1; r < ROWS; r++) for (int c = 0; c < COLS; c++) cell_blank(a, r, c); }
            break;
        }
        case 'P': for (int c = a->cur_c; c < COLS; c++) {                                 // delete n chars (shift left)
                      if (c + n < COLS) { a->grid[a->cur_r][c] = a->grid[a->cur_r][c + n];
                                          a->fgc[a->cur_r][c] = a->fgc[a->cur_r][c + n];
                                          a->bgc[a->cur_r][c] = a->bgc[a->cur_r][c + n]; }
                      else cell_blank(a, a->cur_r, c); } break;
        case '@': for (int c = COLS - 1; c >= a->cur_c; c--) {                            // insert n blanks (shift right)
                      if (c - n >= a->cur_c) { a->grid[a->cur_r][c] = a->grid[a->cur_r][c - n];
                                               a->fgc[a->cur_r][c] = a->fgc[a->cur_r][c - n];
                                               a->bgc[a->cur_r][c] = a->bgc[a->cur_r][c - n]; }
                      else cell_blank(a, a->cur_r, c); } break;
        case 'm': {                                                                      // Z7.1: SGR — set colour pen
            if (np == 1 && p0 <= 0) { a->pen_fg = COL_FG; a->pen_bg = 0; a->pen_rev = 0; break; }  // reset
            for (int i = 0; i < np; i++) {
                int p = params[i] < 0 ? 0 : params[i];
                if      (p == 0)  { a->pen_fg = COL_FG; a->pen_bg = 0; a->pen_rev = 0; }
                else if (p == 7)  a->pen_rev = 1;
                else if (p == 27) a->pen_rev = 0;
                else if (p == 39) a->pen_fg = COL_FG;
                else if (p == 49) a->pen_bg = 0;
                else if (p >= 30 && p <= 37)   a->pen_fg = ANSI16[p - 30];
                else if (p >= 90 && p <= 97)   a->pen_fg = ANSI16[p - 90 + 8];
                else if (p >= 40 && p <= 47)   a->pen_bg = ANSI16[p - 40];
                else if (p >= 100 && p <= 107) a->pen_bg = ANSI16[p - 100 + 8];
                else if (p == 38 || p == 48) {
                    uint32_t col = COL_FG; int ok = 0;
                    if (i + 2 < np && params[i + 1] == 5) { col = ansi256(params[i + 2]); i += 2; ok = 1; }
                    else if (i + 4 < np && params[i + 1] == 2) {
                        int R = params[i + 2] & 0xff, G = params[i + 3] & 0xff, B = params[i + 4] & 0xff;
                        col = 0xff000000u | ((uint32_t)R << 16) | ((uint32_t)G << 8) | (uint32_t)B;
                        i += 4; ok = 1;
                    }
                    if (ok) { if (p == 38) a->pen_fg = col; else a->pen_bg = col; }
                }
                // 1/2/22/23 (bold/faint/normal) accepted, no glyph-weight change
            }
            break;
        }
        default: break;                                                                  // l/h (modes), … ignored
    }
}

// Feed one byte of shell output through a tiny VT interpreter.
static void vt_byte(struct app *a, unsigned char b) {
    if (a->esc == 1) {
        if (b == '[') { a->esc = 2; a->csi_len = 0; return; }                  // CSI
        // OSC (set title etc., ESC ]) and the DCS/SOS/PM/APC string families are terminated by
        // BEL or ST (ESC \).  Consume them silently — programs like Oh My Zsh / vim emit OSC
        // title sequences constantly, and without this the payload leaks onto the screen.
        if (b == ']' || b == 'P' || b == 'X' || b == '^' || b == '_') { a->esc = 3; return; }
        a->esc = 0; return;                                                    // other 2-byte escapes: ignore
    }
    if (a->esc == 2) {
        if (b >= 0x40 && b <= 0x7e) { vt_exec_csi(a, (char)b); a->esc = 0; return; }
        if (a->csi_len < (int)sizeof(a->csi)) a->csi[a->csi_len++] = (char)b;  // accumulate params
        return;
    }
    if (a->esc == 3) {                                                         // inside OSC/string
        if (b == 0x07) { a->esc = 0; return; }                                 // BEL terminates
        if (b == 0x1b) { a->esc = 4; return; }                                 // maybe ST (ESC \)
        return;                                                                // discard the body
    }
    if (a->esc == 4) { a->esc = 0; return; }                                   // ST terminator — done
    switch (b) {
        case 0x1b: a->esc = 1; return;
        case '\r': a->cur_c = 0; return;
        case '\n': grid_newline(a); return;
        case '\b': if (a->cur_c > 0) a->cur_c--; return;
        case '\t': a->cur_c = (a->cur_c + 8) & ~7; if (a->cur_c >= COLS) a->cur_c = COLS - 1; return;
        case 0x07: return; // bell
        default: break;
    }
    if (b < 0x20 || b >= 0x7f) return;
    a->grid[a->cur_r][a->cur_c] = (char)b;
    // Z7.1: stamp the current colour pen onto the cell; reverse video swaps fg/bg.
    a->fgc[a->cur_r][a->cur_c] = a->pen_rev ? (a->pen_bg ? a->pen_bg : COL_BG) : a->pen_fg;
    a->bgc[a->cur_r][a->cur_c] = a->pen_rev ? a->pen_fg : a->pen_bg;
    if (++a->cur_c >= COLS) grid_newline(a);
}

static void render(struct app *a) {
    if (!a->pixels) return;
    const int top = a->deco_h;                       // terminal grid starts below the titlebar
    gf_fill(a->pixels, a->width, a->width, a->height, 0, 0, a->width, a->height, COL_BG);
    const int content_w = a->width - SCROLLBAR_W * a->scale;  // glyphs stop before the scrollbar strip
    for (int r = 0; r < ROWS; r++) {
        char *rch; uint32_t *rfg, *rbg; int live_r;          // scrollback-aware row source
        int from_ring = view_src(a, r, &rch, &rfg, &rbg, &live_r);
        char     *gch = from_ring ? rch : a->grid[live_r];
        uint32_t *gfg = from_ring ? rfg : a->fgc[live_r];
        uint32_t *gbg = from_ring ? rbg : a->bgc[live_r];
        for (int c = 0; c < COLS; c++) {
            int x = c * a->cell_w;
            if (x + a->cell_w > content_w) break;
            int y = top + r * a->cell_h;
            uint32_t bg = gbg[c];
            if (bg)                                          // Z7.1: per-cell background block
                gf_fill(a->pixels, a->width, a->width, a->height, x, y, a->cell_w, a->cell_h, bg);
            char ch = gch[c];
            if (ch != ' ') {
                uint32_t fg = gfg[c];                        // Z7.1: per-cell foreground
                if (a->font_ready)
                    render_ft_glyph(a, x, y, (unsigned char)ch, fg);
                else
                    gf_glyph(a->pixels, a->width, a->width, a->height,
                             x, y + (a->cell_h - 8) / 2, ch, fg, -1);
            }
        }
    }
    // cursor block — only when following the live bottom (hidden while viewing scrollback)
    if (a->view_offset == 0) {
        gf_fill(a->pixels, a->width, a->width, a->height,
                a->cur_c * a->cell_w, top + a->cur_r * a->cell_h,
                a->cell_w, a->cell_h, COL_CURSOR);
        char cc = a->grid[a->cur_r][a->cur_c];
        if (cc != ' ') {
            int x = a->cur_c * a->cell_w;
            int y = top + a->cur_r * a->cell_h;
            if (a->font_ready)
                render_ft_glyph(a, x, y, (unsigned char)cc, COL_BG);
            else
                gf_glyph(a->pixels, a->width, a->width, a->height,
                         x, y + (a->cell_h - 8) / 2, cc, COL_BG, -1);
        }
    }
    draw_scrollbar(a);   // scrollback bar (drawn before the domain border so the border stays intact)
    // IDENTITY_DOMAIN §6: unspoofable colored border (left/right/bottom; the titlebar
    // covers the top), drawn before the titlebar so app pixels never reach the ring.
    if (g_has_domain) {
        int t = 4 * a->scale;
        gf_fill(a->pixels, a->width, a->width, a->height, 0, a->height - t, a->width, t, g_domain_color);
        gf_fill(a->pixels, a->width, a->width, a->height, 0, 0, t, a->height, g_domain_color);
        gf_fill(a->pixels, a->width, a->width, a->height, a->width - t, 0, t, a->height, g_domain_color);
    }
    // window decorations on top (the titlebar doubles as the domain indicator).
    draw_deco(a);
}

static void commit(struct app *a) {
    render(a);
    if (a->post_map_frame_armed && !a->frame_cb) {
        a->frame_cb = wl_surface_frame(a->surface);
        wl_callback_add_listener(a->frame_cb, &frame_listener, a);
    }
    wl_surface_attach(a->surface, a->buffer, 0, 0);
    wl_surface_damage_buffer(a->surface, 0, 0, a->width, a->height);
    wl_surface_commit(a->surface);
    wl_display_flush(a->display);
    a->dirty = 0;
    if (a->post_map_frame_done) {
        a->post_map_frame_done = 0;
        printf("G9FRAME: committed post-map terminal redraw %dx%d -- G9 REDRAW\n", a->width, a->height);
        fflush(stdout);
    }
}

// Mirror shell output to serial, one line at a time, prefixed "G4OUT:".
static void mirror_byte(struct app *a, unsigned char b) {
    if (b == '\n' || a->mirror_len >= (int)sizeof(a->mirror) - 1) {
        a->mirror[a->mirror_len] = 0;
        printf("G4OUT: %s\n", a->mirror);
        fflush(stdout);
        a->mirror_len = 0;
        return;
    }
    if (b >= 0x20 && b < 0x7f)
        a->mirror[a->mirror_len++] = (char)b;
}

// ── shm buffer ───────────────────────────────────────────────────────────────
static int create_shm_buffer(struct app *a) {
    const int stride = a->width * 4;
    const size_t size = (size_t)stride * (size_t)a->height;
    int fd = create_memfd("epin-g4-term");
    if (fd < 0) { perror("G4TERM: memfd_create"); return -1; }
    if (ftruncate(fd, (off_t)size) < 0) { perror("G4TERM: ftruncate"); close(fd); return -1; }
    a->pixels = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (a->pixels == MAP_FAILED) { perror("G4TERM: mmap"); close(fd); return -1; }
    a->pix_bytes = size;   // remembered so a resize can munmap the old mapping
    struct wl_shm_pool *pool = wl_shm_create_pool(a->shm, fd, (int)size);
    a->buffer = wl_shm_pool_create_buffer(pool, 0, a->width, a->height, stride, WL_SHM_FORMAT_XRGB8888);
    wl_shm_pool_destroy(pool);
    close(fd);
    return a->buffer ? 0 : -1;
}

// ── pseudo-terminal + shell ──────────────────────────────────────────────────
// Fill the grid with a centered multi-line notice (used for shell flavors that are
// not yet implemented — no pty/shell is spawned in that case).
static void term_notice(struct app *a, const char *l1, const char *l2, const char *l3) {
    for (int r = 0; r < ROWS; r++)
        for (int c = 0; c < COLS; c++)
            cell_blank(a, r, c);
    const char *lines[3] = { l1, l2, l3 };
    for (int i = 0; i < 3; i++) {
        if (!lines[i]) continue;
        int r = 4 + i * 2;
        for (int c = 0; lines[i][c] && c < COLS - 4; c++)
            a->grid[r][3 + c] = lines[i][c];
    }
    a->cur_r = ROWS - 1;
    a->cur_c = 0;
    a->dirty = 1;
}

static int spawn_shell(struct app *a) {
    // IDENTITY_DOMAIN: honor the requested shell flavor (Z11).  Both run real zsh now:
    // "linux" = zsh in the Linux personality (/bin/zsh), "native" = zsh in the native
    // personality (/hos-zsh, the object shell); "windows" = not implemented (notice).
    const char *flavor = getenv("EPIN_SHELL");
    const int is_native = (flavor && strcmp(flavor, "native") == 0);
    // "light" = zsh with NO startup files (zsh -f -i): skips compinit / oh-my-zsh / powerlevel10k,
    // which otherwise fork a storm of short-lived processes at startup.  Used for lightweight/utility
    // terminals (e.g. the temporary WiFi-check terminal) so they don't starve the cooperative
    // scheduler or exhaust the task table.
    const int is_light = (flavor && strcmp(flavor, "light") == 0);
    if (flavor && *flavor && strcmp(flavor, "linux") != 0 && !is_native && !is_light) {
        char l1[80];
        snprintf(l1, sizeof(l1), "Domain: %s", g_has_domain ? g_domain : "(none)");
        term_notice(a, l1, "Windows subsystem is not implemented yet.",
                    "Pick the 'Linux' or 'Native' shell in the Domain Manager.");
        a->ptm = -1;
        printf("G4TERM: shell flavor '%s' not implemented; showing notice\n", flavor);
        fflush(stdout);
        return 0;
    }
    // The shell binary depends on the flavor; the PTY plumbing + argv[0] are shared.
    // BOTH personalities run zsh — ONE shell, two personalities (ZSH_INTEGRATION_ROADMAP):
    //  - Linux:  /bin/zsh  (Z1) — real upstream zsh, the POSIX Linux-personality login shell,
    //    confined to Linux (HOS_SYS_QUERY -> ENOSYS; the native-launch authorization is dropped
    //    on this exec, L5.2).
    //  - Native: /hos-zsh (Z4) — the SAME zsh launched into the native personality, with **LFE
    //    embedded inside it**: the `zsh/anonymos` module gives in-process obj/id/ns/svc/sys object
    //    builtins (Z4c.4) AND an `lfe` builtin running the full LFE evaluator (L2–L4) in-process.
    //    So the native shell is zsh + LFE, not a separate shell.
    const char *shell_path = is_native ? "/hos-zsh" : "/bin/zsh";
    char *const shell_arg0 = "-zsh";

    int m = open("/dev/ptmx", O_RDWR | O_NONBLOCK);
    if (m < 0) { perror("G4TERM: open /dev/ptmx"); return -1; }
    int lock = 0;
    ioctl(m, TIOCSPTLCK, &lock);   // unlockpt
    unsigned int n = 0;
    if (ioctl(m, TIOCGPTN, &n) < 0) { perror("G4TERM: TIOCGPTN"); close(m); return -1; }
    char pts[32];
    snprintf(pts, sizeof(pts), "/dev/pts/%u", n);
    printf("G4TERM: pty master ready, slave = %s\n", pts); fflush(stdout);

    // Track C1: tell the pty its real window size so full-screen apps (vi, top, less,
    // and a future terminal emulator) lay out to the visible grid via TIOCGWINSZ.
    struct winsize ws = { .ws_row = ROWS, .ws_col = COLS,
                          .ws_xpixel = (unsigned short)a->width,
                          .ws_ypixel = (unsigned short)a->height };
    ioctl(m, TIOCSWINSZ, &ws);

    // fork() goes through the kernel's forkTask path, which gives the child a
    // private copy of the fd table — so the child's dup2 of the slave onto
    // 0/1/2 does not disturb the terminal's own descriptors.  (posix_spawn here
    // uses vfork, which shares the fd table and would corrupt the parent.)
    pid_t pid = fork();
    if (pid < 0) { perror("G4TERM: fork"); close(m); return -1; }
    if (pid == 0) {
        // child: wire the slave to stdin/stdout/stderr, then exec the shell.
        close(m);
        // IDENTITY_DOMAIN: apply the domain's memory cap to the shell (0 = no cap).
        const char *mc = getenv("EPIN_MEM_CAP");
        if (mc && *mc) {
            long bytes = strtol(mc, NULL, 10);
            if (bytes > 0) {
                struct rlimit rl;
                rl.rlim_cur = (rlim_t)bytes;
                rl.rlim_max = (rlim_t)bytes;
                setrlimit(RLIMIT_AS, &rl);
            }
        }
        int s = open(pts, O_RDWR);
        if (s < 0) _exit(127);
        dup2(s, 0); dup2(s, 1); dup2(s, 2);
        if (s > 2) close(s);
        // Track A A3: give the shell a real PATH (so `which`/exec find /bin/<applet>)
        // and a HOME, then start in the user's home directory.  Commands themselves
        // run via busybox standalone (fork + applet), so they work even without PATH.
        setenv("PATH", "/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin", 1);
        setenv("HOME", "/root", 1);
        setenv("TERM", "linux", 1);
        // Z1: give zsh a username so %n (and \u) resolve; the passwd DB has uid 1000=user.
        setenv("USER", "user", 1);
        setenv("LOGNAME", "user", 1);
        // Rich PS1 so the Linux (zsh) shell prompt shows the same four fields as the
        // native shell: username, permissions, namespace (domain), and the working dir —
        // `[<domain>] <user> [<perms>]:<cwd>$`.  The domain + permission flags come from
        // the per-domain policy the Domain Manager passes in the environment; zsh expands
        // %n (user), %~ (cwd, ~-abbreviated) and %# (%/# by privilege) live.  Both zsh
        // flavors get it now (Z4a.5: the native shell is also zsh); a future native prompt
        // can derive the fields from the kernel via HOS_SYS_QUERY instead of the env.
        {
            const char *dom  = getenv("EPIN_DOMAIN");
            const char *disk = getenv("EPIN_DISK");        // none / ro / rw
            const char *net  = getenv("EPIN_NET");         // none / nat / vpn / tor / local / disposable
            const char *sipc = getenv("EPIN_SECURE_IPC");  // "1" / "0"
            if (!dom || !*dom) dom = "linux";
            char caps[96]; int cl = 0; caps[0] = 0;
            if (disk && *disk && strcmp(disk, "none"))
                cl += snprintf(caps + cl, sizeof(caps) - cl, "fs:%s ", disk);
            if (net && *net && strcmp(net, "none"))
                cl += snprintf(caps + cl, sizeof(caps) - cl, "net:%s ", net);
            if (sipc && !strcmp(sipc, "1"))
                cl += snprintf(caps + cl, sizeof(caps) - cl, "ipc ");
            if (cl > 0 && caps[cl - 1] == ' ') caps[cl - 1] = 0;   // trim trailing space
            // Embed the username literally rather than zsh's %n: assigning the special
            // USERNAME parameter (which %n reads) attempts a setuid, so a zshrc fallback
            // can't set it, and getpwuid races zsh startup leaving %n empty.
            const char *usr = getenv("EPIN_USER");
            if (!usr || !*usr) usr = getenv("USER");
            if (!usr || !*usr) usr = "user";
            // zsh prompt escapes (%% -> literal %): [<dom>] <user> [<perms>]:%~%#
            char ps1[256];
            snprintf(ps1, sizeof(ps1), "[%s] %s [%s]:%%~%%# ", dom, usr, caps);
            setenv("PS1", ps1, 1);
        }
        // Make EPIN_SHELL in the child reflect the shell actually launched, so the zshrc's
        // native-only object-command block (Z4c) keys off the real flavor — not just whatever
        // the Domain Manager passed in.
        setenv("EPIN_SHELL", is_native ? "native" : (is_light ? "light" : "linux"), 1);
        // Launch the chosen shell on the pty.  Login zsh (argv0="-zsh") reads the rc files;
        // the "light" shell runs `zsh -f -i` (interactive, NO rc files) so it starts instantly.
        char *argv_norm[]  = { shell_arg0, NULL };
        char *argv_light[] = { "zsh", "-f", "-i", NULL };
        execve(shell_path, is_light ? argv_light : argv_norm, environ);
        _exit(127);
    }

    printf("G4TERM: spawned shell pid=%d on %s -- G4 SHELL\n", (int)pid, pts); fflush(stdout);
    a->ptm = m;
    return 0;
}

static void drain_pty(struct app *a) {
    unsigned char buf[512];
    for (;;) {
        ssize_t n = read(a->ptm, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) { vt_byte(a, buf[i]); mirror_byte(a, buf[i]); }
        a->dirty = 1;
    }
}

// ── keyboard ─────────────────────────────────────────────────────────────────
static const char kmap[59] = {
/*0*/0,0,'1','2','3','4','5','6','7','8','9','0','-','=',0,0,
/*16*/'q','w','e','r','t','y','u','i','o','p','[',']',0,0,'a','s',
/*32*/'d','f','g','h','j','k','l',';','\'','`',0,'\\','z','x','c','v',
/*48*/'b','n','m',',','.','/',0,0,0,' '
};
static const char kmap_shift[59] = {
/*0*/0,0,'!','@','#','$','%','^','&','*','(',')','_','+',0,0,
/*16*/'Q','W','E','R','T','Y','U','I','O','P','{','}',0,0,'A','S',
/*32*/'D','F','G','H','J','K','L',':','"','~',0,'|','Z','X','C','V',
/*48*/'B','N','M','<','>','?',0,0,0,' '
};

// Z3 (PTY/terminal split): the navigation/editing keys a real shell line editor needs.
// zsh's ZLE (and any full-screen app) reads these as terminfo escape sequences, not
// single bytes — the linux-console set (TERM=linux): cursor keys \E[A..D, Home/End/Ins/
// Del/PgUp/PgDn as \E[N~.  Without them the shell has no history (Up/Down), no in-line
// cursor movement (Left/Right), and no Delete.  The terminal only transports these bytes;
// what they DO (history, completion menus, …) is entirely zsh's.
static const char *special_key_seq(uint32_t code) {
    switch (code) {
        case 103: return "\x1b[A";   // Up        -> up-line-or-history
        case 108: return "\x1b[B";   // Down      -> down-line-or-history
        case 106: return "\x1b[C";   // Right     -> forward-char
        case 105: return "\x1b[D";   // Left      -> backward-char
        case 102: return "\x1b[1~";  // Home      -> beginning-of-line
        case 107: return "\x1b[4~";  // End       -> end-of-line
        case 110: return "\x1b[2~";  // Insert
        case 111: return "\x1b[3~";  // Delete    -> delete-char
        case 104: return "\x1b[5~";  // PageUp
        case 109: return "\x1b[6~";  // PageDown
        default:  return NULL;
    }
}

static void key_to_pty(struct app *a, uint32_t code) {
    const char *seq = special_key_seq(code);
    if (seq) {
        if (a->ptm >= 0) write(a->ptm, seq, strlen(seq));
        printf("G4KEY: code=%u -> ESC-seq\n", code); fflush(stdout);
        return;
    }
    char c = 0;
    switch (code) {
        case 1:  c = 0x1b; break;          // ESC
        case 14: c = 0x7f; break;          // Backspace -> DEL (VERASE)
        case 15: c = '\t'; break;
        case 28: c = '\r'; break;          // Enter
        default:
            if (code < 59) c = a->shift ? kmap_shift[code] : kmap[code];
            break;
    }
    if (!c) return;
    if (a->ctrl && ((c | 0x20) >= 'a' && (c | 0x20) <= 'z')) c = (char)((c | 0x20) - 'a' + 1);
    if (a->ptm >= 0) { unsigned char b = (unsigned char)c; write(a->ptm, &b, 1); }
    printf("G4KEY: code=%u -> 0x%02x\n", code, (unsigned char)c); fflush(stdout);
}

static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t fmt, int32_t fd, uint32_t sz)
{ (void)d; (void)k; (void)fmt; (void)sz; if (fd >= 0) close(fd); }
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf, struct wl_array *ks)
{
    (void)k; (void)s; (void)sf; (void)ks;
    struct app *a = d;
    if (a) a->dirty = 1;
    log_line("G4KEY: keyboard enter -- G4 FOCUS");
}
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf)
{ (void)d; (void)k; (void)s; (void)sf; }
static void kb_key(void *data, struct wl_keyboard *k, uint32_t serial, uint32_t time,
                   uint32_t code, uint32_t state)
{
    (void)k; (void)serial; (void)time;
    struct app *a = data;
    int down = (state == WL_KEYBOARD_KEY_STATE_PRESSED);
    if (code == 42 || code == 54) { a->shift = down; return; } // L/R shift
    if (code == 29 || code == 97) { a->ctrl = down; return; }  // L/R ctrl
    if (!down) return;
    // Shift+PageUp / Shift+PageDown = local scrollback scroll, NOT sent to the PTY.
    if (a->shift && code == 104) { a->view_offset += ROWS; clamp_view(a); a->dirty = 1; return; }
    if (a->shift && code == 109) { a->view_offset -= ROWS; clamp_view(a); a->dirty = 1; return; }
    if (a->view_offset != 0) { a->view_offset = 0; a->dirty = 1; } // typing snaps back to live
    key_to_pty(a, code);
}
static void kb_mods(void *d, struct wl_keyboard *k, uint32_t s, uint32_t dep, uint32_t lat,
                    uint32_t lock, uint32_t grp)
{ (void)d; (void)k; (void)s; (void)dep; (void)lat; (void)lock; (void)grp; }
static void kb_repeat(void *d, struct wl_keyboard *k, int32_t rate, int32_t delay)
{ (void)d; (void)k; (void)rate; (void)delay; }

static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = kb_keymap, .enter = kb_enter, .leave = kb_leave,
    .key = kb_key, .modifiers = kb_mods, .repeat_info = kb_repeat,
};

// ── pointer (for the titlebar: drag-to-move + the min/max/close buttons) ──────
static void ptr_enter(void *d, struct wl_pointer *p, uint32_t serial,
                      struct wl_surface *s, wl_fixed_t sx, wl_fixed_t sy) {
    (void)p; (void)s; struct app *a = d;
    a->ptr_serial = serial; a->px = wl_fixed_to_double(sx); a->py = wl_fixed_to_double(sy);
}
static void ptr_leave(void *d, struct wl_pointer *p, uint32_t serial, struct wl_surface *s)
{ (void)d; (void)p; (void)serial; (void)s; }
static void ptr_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t sx, wl_fixed_t sy) {
    (void)p; (void)t; struct app *a = d;
    a->px = wl_fixed_to_double(sx); a->py = wl_fixed_to_double(sy);
    if (a->sb_dragging) {
        int tx, ty, tw, th, thy, thh;
        if (!scrollbar_geom(a, &tx, &ty, &tw, &th, &thy, &thh)) return;
        int travel = th - thh;
        if (travel <= 0) return;
        double dy = a->py - a->sb_drag_y0;                       // drag DOWN -> toward live -> smaller offset
        int doff = (int)(-dy * (double)a->sb_count / travel);
        a->view_offset = a->sb_drag_off0 + doff;
        clamp_view(a); a->dirty = 1;
    }
}
static void ptr_button(void *d, struct wl_pointer *p, uint32_t serial, uint32_t t,
                       uint32_t button, uint32_t state) {
    (void)p; (void)t; struct app *a = d;
    if (button != BTN_LEFT_CODE) return;
    if (state == WL_POINTER_BUTTON_STATE_RELEASED) { a->sb_dragging = 0; return; }
    a->ptr_serial = serial;
    // Scrollbar first (it lives below the titlebar at the right edge — disjoint from deco_hit).
    int tx, ty, tw, th, thy, thh;
    if (scrollbar_geom(a, &tx, &ty, &tw, &th, &thy, &thh) &&
        a->px >= tx && a->px < tx + tw && a->py >= ty && a->py < ty + th) {
        if (a->py >= thy && a->py < thy + thh) {                 // on the thumb -> start drag
            a->sb_dragging = 1; a->sb_drag_y0 = a->py; a->sb_drag_off0 = a->view_offset;
        } else if (a->py < thy) {                                // above the thumb -> page up (older)
            a->view_offset += ROWS; clamp_view(a); a->dirty = 1;
        } else {                                                 // below the thumb -> page down
            a->view_offset -= ROWS; clamp_view(a); a->dirty = 1;
        }
        return;
    }
    switch (deco_hit(a, a->px, a->py)) {
        case 1: xdg_toplevel_move(a->toplevel, a->seat, serial); break;   // drag the titlebar
        case 2: xdg_toplevel_set_minimized(a->toplevel); break;
        case 3: if (a->maximized) { xdg_toplevel_unset_maximized(a->toplevel); a->maximized = 0; }
                else              { xdg_toplevel_set_maximized(a->toplevel);   a->maximized = 1; }
                a->dirty = 1; break;
        case 4: a->running = 0; break;                                    // close
        default: break;
    }
}
static void ptr_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t axis, wl_fixed_t v)
{
    (void)p; (void)t; struct app *a = d;
    if (axis != 0) return;                       // 0 = vertical scroll
    double dv = wl_fixed_to_double(v);           // >0 = scroll down (toward live)
    a->view_offset += (dv > 0) ? -3 : 3;         // 3 lines per notch (wheel is a bonus; QMP can't send it)
    clamp_view(a); a->dirty = 1;
}
static void ptr_frame(void *d, struct wl_pointer *p) { (void)d; (void)p; }
static void ptr_axis_source(void *d, struct wl_pointer *p, uint32_t s) { (void)d; (void)p; (void)s; }
static void ptr_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax)
{ (void)d; (void)p; (void)t; (void)ax; }
static void ptr_axis_discrete(void *d, struct wl_pointer *p, uint32_t ax, int32_t disc)
{ (void)d; (void)p; (void)ax; (void)disc; }
static const struct wl_pointer_listener pointer_listener = {
    .enter = ptr_enter, .leave = ptr_leave, .motion = ptr_motion, .button = ptr_button,
    .axis = ptr_axis, .frame = ptr_frame, .axis_source = ptr_axis_source,
    .axis_stop = ptr_axis_stop, .axis_discrete = ptr_axis_discrete,
};

static void seat_caps(void *data, struct wl_seat *seat, uint32_t caps) {
    struct app *a = data;
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !a->pointer) {
        a->pointer = wl_seat_get_pointer(seat);
        wl_pointer_add_listener(a->pointer, &pointer_listener, a);
        log_line("G4TERM: wl_seat has pointer; subscribed (window decorations live)");
    }
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !a->keyboard) {
        a->keyboard = wl_seat_get_keyboard(seat);
        wl_keyboard_add_listener(a->keyboard, &keyboard_listener, a);
        log_line("G4TERM: wl_seat has keyboard; subscribed");
    }
}
static void seat_name(void *d, struct wl_seat *s, const char *n) { (void)d; (void)s; (void)n; }
static const struct wl_seat_listener seat_listener = { .capabilities = seat_caps, .name = seat_name };

// ── xdg-shell / registry ─────────────────────────────────────────────────────
static void wm_base_ping(void *d, struct xdg_wm_base *wm, uint32_t serial) { (void)d; xdg_wm_base_pong(wm, serial); }
static const struct xdg_wm_base_listener wm_base_listener = { .ping = wm_base_ping };

static void xdg_surface_configure(void *data, struct xdg_surface *surface, uint32_t serial) {
    struct app *a = data;
    xdg_surface_ack_configure(surface, serial);

    // The tiling WM dictates our surface size via toplevel_configure (cfg_w/cfg_h).
    // When it hasn't asked for a specific size (0), keep our natural size.
    int want_w = (a->cfg_w > 0) ? a->cfg_w : a->width;
    int want_h = (a->cfg_h > 0) ? a->cfg_h : a->height;

    if (!a->committed) {
        if (want_w != a->width || want_h != a->height) apply_size(a, want_w, want_h);
        if (create_shm_buffer(a) < 0) { a->running = 0; return; }
        grid_clear(a);
        a->post_map_frame_armed = 1;
        commit(a);
        a->committed = 1;
        printf("G4TERM: committed terminal window %dx%d -- G4 COMMIT\n", a->width, a->height); fflush(stdout);
        return;
    }

    // Already mapped: honor a compositor-driven resize.  Reflow the grid to the new
    // size, recreate the shm buffer, and repaint — but do NOT clear the grid (that
    // would wipe the shell's output) and do NOT early-return on 'committed' when the
    // size actually changed.  The old buffer is freed only AFTER the new one is
    // committed, so the compositor never reads freed/unmapped memory.
    if (want_w != a->width || want_h != a->height) {
        struct wl_buffer *old_buf = a->buffer;
        uint32_t         *old_px = a->pixels;
        size_t            old_bytes = a->pix_bytes;
        apply_size(a, want_w, want_h);
        if (create_shm_buffer(a) < 0) { a->running = 0; return; }
        a->dirty = 1;
        commit(a);                              // renders + attaches + commits the NEW buffer
        if (old_buf) wl_buffer_destroy(old_buf);
        if (old_px && old_px != MAP_FAILED && old_bytes) munmap(old_px, old_bytes);
        printf("G4TERM: resized terminal window %dx%d -- G4 RESIZE\n", a->width, a->height); fflush(stdout);
    }
}
static const struct xdg_surface_listener xdg_surface_listener = { .configure = xdg_surface_configure };

static void toplevel_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s)
{
    (void)t; (void)s;
    struct app *a = d;
    // Record the compositor's requested size (>0); xdg_surface_configure applies it.
    if (a && w > 0 && h > 0) { a->cfg_w = w; a->cfg_h = h; }
}
static void toplevel_close(void *data, struct xdg_toplevel *t) { (void)t; ((struct app *)data)->running = 0; }
static void toplevel_cfg_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h)
{ (void)d; (void)t; (void)w; (void)h; }
static void toplevel_wm_caps(void *d, struct xdg_toplevel *t, struct wl_array *c) { (void)d; (void)t; (void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure = toplevel_configure, .close = toplevel_close,
    .configure_bounds = toplevel_cfg_bounds, .wm_capabilities = toplevel_wm_caps,
};

static void registry_global(void *data, struct wl_registry *reg, uint32_t name,
                            const char *iface, uint32_t version) {
    struct app *a = data;
    if (strcmp(iface, wl_compositor_interface.name) == 0) {
        a->compositor = wl_registry_bind(reg, name, &wl_compositor_interface, version < 4 ? version : 4);
    } else if (strcmp(iface, wl_shm_interface.name) == 0) {
        a->shm = wl_registry_bind(reg, name, &wl_shm_interface, 1);
    } else if (strcmp(iface, xdg_wm_base_interface.name) == 0) {
        a->wm_base = wl_registry_bind(reg, name, &xdg_wm_base_interface, version < 6 ? version : 6);
        xdg_wm_base_add_listener(a->wm_base, &wm_base_listener, a);
    } else if (strcmp(iface, wl_seat_interface.name) == 0) {
        a->seat = wl_registry_bind(reg, name, &wl_seat_interface, version < 5 ? version : 5);
        wl_seat_add_listener(a->seat, &seat_listener, a);
    }
}
static void registry_global_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener registry_listener = {
    .global = registry_global, .global_remove = registry_global_remove,
};

int main(void) {
    static struct app a;   // BSS, not the stack: the scrollback ring makes this ~740 KB
    memset(&a, 0, sizeof(a));
    a.running = 1;
    a.ptm = -1;

    // IDENTITY_DOMAIN: which security domain were we launched into?
    const char *dom = getenv("EPIN_DOMAIN");
    if (dom && *dom) {
        g_has_domain = 1;
        snprintf(g_domain, sizeof(g_domain), "%s", dom);
        const char *dc = getenv("EPIN_DOMAIN_COLOR");
        if (dc && *dc)
            g_domain_color = (uint32_t)strtoul(dc, NULL, 0);
        printf("G4TERM: domain=%s color=0x%08x\n", g_domain, g_domain_color);
        fflush(stdout);
    }

    log_line("G4TERM: starting software terminal");

    // Spawn the shell BEFORE connecting to Wayland: fork() copies the whole
    // address space, and forking a live Wayland connection corrupts its socket
    // stream.  Doing it first means the fork is cheap and the child inherits no
    // Wayland fds.  The shell's early output simply buffers in the pty until the
    // terminal connects and drains it.
    if (spawn_shell(&a) < 0) return 1;
    init_layout(&a);
    init_freetype(&a);

    a.display = wl_display_connect(NULL);
    if (!a.display) { perror("G4TERM: wl_display_connect"); return 1; }

    a.registry = wl_display_get_registry(a.display);
    wl_registry_add_listener(a.registry, &registry_listener, &a);
    wl_display_roundtrip(a.display);
    if (!a.compositor || !a.shm || !a.wm_base) { log_line("G4TERM: missing globals"); return 1; }

    a.surface     = wl_compositor_create_surface(a.compositor);
    a.xdg_surface = xdg_wm_base_get_xdg_surface(a.wm_base, a.surface);
    xdg_surface_add_listener(a.xdg_surface, &xdg_surface_listener, &a);
    a.toplevel    = xdg_surface_get_toplevel(a.xdg_surface);
    xdg_toplevel_add_listener(a.toplevel, &toplevel_listener, &a);
    if (g_has_domain)
        snprintf(a.title, sizeof(a.title), "[%s] EpinAnonymOS Terminal", g_domain);
    else
        snprintf(a.title, sizeof(a.title), "EpinAnonymOS Terminal");
    xdg_toplevel_set_title(a.toplevel, a.title);
    xdg_toplevel_set_app_id(a.toplevel, "epin-g4-term");
    wl_surface_commit(a.surface);
    wl_display_roundtrip(a.display);   // drive the first configure → commit

    int wlfd = wl_display_get_fd(a.display);
    while (a.running) {
        // Standard prepare_read pattern so we can also poll the PTY master fd.
        while (wl_display_prepare_read(a.display) != 0)
            wl_display_dispatch_pending(a.display);
        wl_display_flush(a.display);

        struct pollfd pfds[2] = {
            { .fd = wlfd,   .events = POLLIN },
            { .fd = a.ptm,  .events = POLLIN },
        };
        poll(pfds, 2, 16);

        if (pfds[0].revents & POLLIN) wl_display_read_events(a.display);
        else                          wl_display_cancel_read(a.display);
        wl_display_dispatch_pending(a.display);

        if (pfds[1].revents & POLLIN) drain_pty(&a);
        if (a.dirty && a.committed) commit(&a);
    }
    return 0;
}
