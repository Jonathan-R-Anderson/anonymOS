/*
 * wl-editor.c -- a native multi-line TEXT EDITOR for EpinAnonymOS (Wayland + FreeType client).
 *
 * There is no terminal-hosted editor on the desktop that's convenient for quick edits, so this is a
 * self-contained GUI editor: a growable array of lines, a monospaced glyph grid, a solid/blinking
 * caret, vertical + horizontal scroll, a client-drawn titlebar with a red close box, and a status
 * line (Ln/Col, filename, modified marker).
 *
 *   argv[1]  optional file to OPEN (absent -> empty buffer, saves to /run/untitled.txt)
 *   typing   inserts; Enter splits; Backspace/Delete; arrows/Home/End move; PageUp/PageDown scroll
 *   Ctrl+S   save (writes the whole buffer via open(O_CREAT|O_WRONLY|O_TRUNC)+write+close)
 *   Ctrl+Q   quit (also the red close box)
 *
 * The Wayland scaffolding (registry / seat / xdg / persistent double-buffered wl_shm / FreeType text /
 * evdev keymap / the COMPLETE v5 wl_pointer_listener) is the proven wl-wifi-menu / wl-logview pattern,
 * reused verbatim -- a partial pointer listener (NULL .frame) crashes on the first real mouse move, and
 * a per-frame memfd or single buffer freezes the desktop, so those are copied whole.
 */
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <wayland-client.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include "xdg-shell-client-protocol.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum {
    WIN_W = 720, WIN_H = 560,
    TITLE_H = 28,                 /* client-drawn titlebar */
    STATUS_H = 22,                /* bottom status line */
    TEXT_X = 8,                   /* left text margin */
    PX = 15, LINEH = 19,          /* glyph size + line pitch */
    CLOSE_W = 20, CLOSE_H = 20,
};
/* Size-dependent layout reads the LIVE window size (a->width/a->height) so the client reflows
 * when the tiling WM resizes it.  These macros therefore assume a `struct app *a` is in scope
 * wherever they are used -- true in every function below; main() spells out app.width/app.height. */
#define CLOSE_X (a->width - CLOSE_W - 6)
#define CLOSE_Y ((TITLE_H - CLOSE_H) / 2)
#define TEXT_TOP (TITLE_H + 2)
#define TEXT_BOT (a->height - STATUS_H)
#define TEXT_W  (a->width - TEXT_X - 4)

struct line { char *buf; int len; int cap; };   /* buf is always NUL-terminated */

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
    uint32_t *pixels;              // the buffer draw() currently targets
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    int pending_w, pending_h;                       /* last size the compositor asked for (applied on ack) */
    unsigned char *shm_base; size_t shm_map_size;   /* live wl_shm mapping, tracked so resize can munmap it */
    int font_ready, running;
    double pointer_x, pointer_y;

    /* --- editor state --- */
    struct line *lines; int nlines; int lines_cap;
    int cur_line, cur_col;         // insertion point
    int scroll_row, scroll_col;    // top-left visible cell
    int rows, vis_cols;            // visible grid extent
    int cell_w;                    // monospace advance in px
    int modified;
    int caret_on;                  // blink state
    char path[512];                // save target
    char fname[256];               // basename for the titlebar
    char status[128];              // transient message ("Saved" / "Save failed: N")
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
/* Monospace face preferred (grid alignment), proportional Noto as a fallback. */
static int init_freetype(struct app *app){
    const char *paths[] = {
        "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
        "/usr/share/fonts/NotoSansMono-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
        "/usr/share/fonts/noto/NotoSans-Regular.ttf",
    };
    int loaded = -1;
    for (unsigned i = 0; i < sizeof(paths)/sizeof(paths[0]); i++)
        if (load_file(paths[i], &app->font_data, &app->font_size) == 0){ loaded = 0; break; }
    if (loaded < 0) return -1;
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
static void fill_rect(struct app *app, int x, int y, int w, int h, uint32_t c){
    for (int j=y;j<y+h;j++){ if (j<0||j>=app->height) continue;
        for (int i=x;i<x+w;i++){ if (i<0||i>=app->width) continue; app->pixels[j*app->width+i]=c; } }
}

/* raw evdev codes from wl_keyboard (no xkb keymap here) -> printable chars, unshifted + shifted. */
static const char EVDEV_CHAR[128] = {
    [2]='1',[3]='2',[4]='3',[5]='4',[6]='5',[7]='6',[8]='7',[9]='8',[10]='9',[11]='0',[12]='-',[13]='=',
    [16]='q',[17]='w',[18]='e',[19]='r',[20]='t',[21]='y',[22]='u',[23]='i',[24]='o',[25]='p',[26]='[',[27]=']',
    [30]='a',[31]='s',[32]='d',[33]='f',[34]='g',[35]='h',[36]='j',[37]='k',[38]='l',[39]=';',[40]='\'',[41]='`',[43]='\\',
    [44]='z',[45]='x',[46]='c',[47]='v',[48]='b',[49]='n',[50]='m',[51]=',',[52]='.',[53]='/',[57]=' ',
};
static const char EVDEV_SHIFT[128] = {
    [2]='!',[3]='@',[4]='#',[5]='$',[6]='%',[7]='^',[8]='&',[9]='*',[10]='(',[11]=')',[12]='_',[13]='+',
    [16]='Q',[17]='W',[18]='E',[19]='R',[20]='T',[21]='Y',[22]='U',[23]='I',[24]='O',[25]='P',[26]='{',[27]='}',
    [30]='A',[31]='S',[32]='D',[33]='F',[34]='G',[35]='H',[36]='J',[37]='K',[38]='L',[39]=':',[40]='"',[41]='~',[43]='|',
    [44]='Z',[45]='X',[46]='C',[47]='V',[48]='B',[49]='N',[50]='M',[51]='<',[52]='>',[53]='?',[57]=' ',
};

/* --- line / buffer model ------------------------------------------------- */
static void line_init(struct line *l){ l->cap = 16; l->buf = malloc(l->cap); l->buf[0] = 0; l->len = 0; }
static void line_reserve(struct line *l, int need){          /* room for `need` chars + NUL */
    if (need + 1 <= l->cap) return;
    int nc = l->cap ? l->cap : 16; while (nc < need + 1) nc *= 2;
    l->buf = realloc(l->buf, nc); l->cap = nc;
}
static void line_insert(struct line *l, int pos, char c){
    if (pos < 0) pos = 0; if (pos > l->len) pos = l->len;
    line_reserve(l, l->len + 1);
    memmove(l->buf + pos + 1, l->buf + pos, (size_t)(l->len - pos + 1));  /* includes NUL */
    l->buf[pos] = c; l->len++;
}
static void line_delete(struct line *l, int pos){
    if (pos < 0 || pos >= l->len) return;
    memmove(l->buf + pos, l->buf + pos + 1, (size_t)(l->len - pos));       /* includes NUL */
    l->len--;
}
static void lines_reserve(struct app *a, int need){
    if (need <= a->lines_cap) return;
    int nc = a->lines_cap ? a->lines_cap : 16; while (nc < need) nc *= 2;
    a->lines = realloc(a->lines, (size_t)nc * sizeof(struct line)); a->lines_cap = nc;
}
static void lines_insert(struct app *a, int idx){            /* insert an empty line at idx */
    if (idx < 0) idx = 0; if (idx > a->nlines) idx = a->nlines;
    lines_reserve(a, a->nlines + 1);
    memmove(&a->lines[idx + 1], &a->lines[idx], (size_t)(a->nlines - idx) * sizeof(struct line));
    line_init(&a->lines[idx]); a->nlines++;
}
static void lines_remove(struct app *a, int idx){
    if (idx < 0 || idx >= a->nlines) return;
    free(a->lines[idx].buf);
    memmove(&a->lines[idx], &a->lines[idx + 1], (size_t)(a->nlines - idx - 1) * sizeof(struct line));
    a->nlines--;
}
static void buffer_clear(struct app *a){
    for (int i = 0; i < a->nlines; i++) free(a->lines[i].buf);
    a->nlines = 0; lines_reserve(a, 1); line_init(&a->lines[0]); a->nlines = 1;
    a->cur_line = a->cur_col = a->scroll_row = a->scroll_col = 0;
}

/* Load `path` into the line array; a missing file is fine (fresh buffer to be created on save). */
static void load_path(struct app *a, const char *path){
    buffer_clear(a);
    if (!path) return;
    unsigned char *buf; size_t sz;
    if (load_file(path, &buf, &sz) < 0) return;     /* new/absent file -> empty buffer */
    int li = 0;
    for (size_t i = 0; i < sz; i++){
        char b = (char)buf[i];
        if (b == '\n'){ lines_insert(a, a->nlines); li = a->nlines - 1; }
        else if (b == '\r'){ continue; }
        else { struct line *l = &a->lines[li]; line_insert(l, l->len, b); }
    }
    free(buf);
}

/* Write every line back to disk, '\n'-separated (writable via the rtfs runtime overlay). */
static void do_save(struct app *a){
    int fd = open(a->path, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0){ snprintf(a->status, sizeof a->status, "Save failed: %d", errno); return; }
    int ok = 1;
    for (int i = 0; i < a->nlines; i++){
        if (a->lines[i].len > 0 && write(fd, a->lines[i].buf, (size_t)a->lines[i].len) < 0) ok = 0;
        if (i < a->nlines - 1 && write(fd, "\n", 1) < 0) ok = 0;
    }
    if (a->nlines > 0 && write(fd, "\n", 1) < 0) ok = 0;   /* trailing newline (POSIX text file) */
    close(fd);
    if (ok){ a->modified = 0; snprintf(a->status, sizeof a->status, "Saved"); }
    else     snprintf(a->status, sizeof a->status, "Save failed: %d", errno);
    { char m[600]; snprintf(m, sizeof m, "EDITOR: save '%s' -> %s", a->path, a->status); log_line(m); }
}

/* --- rendering ----------------------------------------------------------- */
static void draw(struct app *a){
    const uint32_t BG=0xff1b1f27u, HDR=0xff11141bu, TXT=0xfff2f5fau, DIM=0xff8b94a3u,
                   CARET=0xff4da3ffu, OK=0xff5fd08au, CLOSE=0xffd05f5fu,
                   STATUSBG=0xff11141bu, LN=0xff2d3444u;
    fill_rect(a, 0, 0, a->width, a->height, BG);

    /* titlebar */
    fill_rect(a, 0, 0, a->width, TITLE_H, HDR);
    char title[320];
    snprintf(title, sizeof title, "Text Editor - %s%s", a->fname, a->modified ? " *" : "");
    draw_text(a, title, 12, 6, a->width - 220, 16, TXT);
    if (a->status[0]){
        int sw = 160;
        uint32_t col = (strncmp(a->status, "Saved", 5) == 0) ? OK : CLOSE;
        draw_text(a, a->status, CLOSE_X - sw - 8, 7, sw, 13, col);
    }
    /* red close box */
    fill_rect(a, CLOSE_X, CLOSE_Y, CLOSE_W, CLOSE_H, CLOSE);
    draw_text(a, "x", CLOSE_X + 6, CLOSE_Y + 2, CLOSE_W, 15, 0xff11141bu);
    fill_rect(a, 0, TITLE_H, a->width, 1, LN);

    /* text grid */
    a->rows = (TEXT_BOT - TEXT_TOP) / LINEH;
    a->vis_cols = a->cell_w > 0 ? TEXT_W / a->cell_w : 0;
    for (int r = 0; r < a->rows; r++){
        int ln = a->scroll_row + r; if (ln >= a->nlines) break;
        struct line *l = &a->lines[ln];
        int off = a->scroll_col; if (off > l->len) off = l->len;
        draw_text(a, l->buf + off, TEXT_X, TEXT_TOP + r*LINEH, TEXT_W, PX, TXT);
    }
    /* caret */
    if (a->caret_on){
        int cvr = a->cur_line - a->scroll_row, cvc = a->cur_col - a->scroll_col;
        if (cvr >= 0 && cvr < a->rows && cvc >= 0 && cvc <= a->vis_cols){
            int cx = TEXT_X + cvc * a->cell_w, cy = TEXT_TOP + cvr * LINEH;
            fill_rect(a, cx, cy, 2, LINEH - 2, CARET);
        }
    }

    /* status line */
    fill_rect(a, 0, TEXT_BOT, a->width, STATUS_H, STATUSBG);
    fill_rect(a, 0, TEXT_BOT, a->width, 1, LN);
    char st[400];
    snprintf(st, sizeof st, "Ln %d, Col %d   %s%s",
             a->cur_line + 1, a->cur_col + 1, a->path, a->modified ? "   [modified]" : "");
    draw_text(a, st, 10, TEXT_BOT + 4, a->width - 20, 12, DIM);
}

/* --- double-buffered wl_shm (one memfd, two slices) ---------------------- */
static void redraw_commit(struct app *app);   /* fwd */
static void buffer_release(void *d, struct wl_buffer *wl){ struct app *a = d;
    for (int i=0;i<2;i++) if (a->bufs[i].wl == wl) a->bufs[i].busy = 0;
    if (a->dirty){ a->dirty = 0; redraw_commit(a); }   /* a deferred redraw can now proceed */
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static int create_buffers(struct app *app){
    int fd = create_memfd("epin-editor"); if (fd < 0) return -1;
    size_t total = app->buffer_size * 2;
    if (ftruncate(fd, (off_t)total) < 0){ close(fd); return -1; }
    unsigned char *base = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED){ close(fd); return -1; }
    app->shm_base = base; app->shm_map_size = total;   /* remembered so resize_buffers() can munmap it */
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
/* Draw into a FREE buffer and commit it; if both are in use, mark dirty and redraw on the next release
 * (never modify a buffer the compositor may still be reading -> that vanished the window on real HW). */
static void redraw_commit(struct app *app){
    if (!app->configured) return;
    int i = app->bufs[0].busy ? 1 : 0;
    if (app->bufs[i].busy){ app->dirty = 1; return; }
    app->pixels = app->bufs[i].px;
    draw(app);
    app->bufs[i].busy = 1;
    wl_surface_attach(app->surface, app->bufs[i].wl, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
}

/* --- editing operations -------------------------------------------------- */
static void ensure_visible(struct app *a){
    if (a->cur_line < a->scroll_row) a->scroll_row = a->cur_line;
    if (a->rows > 0 && a->cur_line >= a->scroll_row + a->rows) a->scroll_row = a->cur_line - a->rows + 1;
    if (a->scroll_row < 0) a->scroll_row = 0;
    if (a->cur_col < a->scroll_col) a->scroll_col = a->cur_col;
    if (a->vis_cols > 0 && a->cur_col >= a->scroll_col + a->vis_cols) a->scroll_col = a->cur_col - a->vis_cols + 1;
    if (a->scroll_col < 0) a->scroll_col = 0;
}
static void clamp_col(struct app *a){
    int len = a->lines[a->cur_line].len;
    if (a->cur_col > len) a->cur_col = len;
    if (a->cur_col < 0) a->cur_col = 0;
}

/* --- compositor-driven resize (tiling WM) -------------------------------- */
/* Tear down the current shm pool/buffers + mapping.  Safe because on resize we immediately
 * attach a freshly-created buffer; the destroyed proxies emit no further release events. */
static void destroy_buffers(struct app *a){
    for (int i=0;i<2;i++){
        if (a->bufs[i].wl){ wl_buffer_destroy(a->bufs[i].wl); a->bufs[i].wl = NULL; }
        a->bufs[i].px = NULL; a->bufs[i].busy = 0;
    }
    if (a->shm_base && a->shm_map_size) munmap(a->shm_base, a->shm_map_size);
    a->shm_base = NULL; a->shm_map_size = 0;
}
/* Adopt the size the compositor dictated: rebuild the double-buffered shm at (w,h), then let
 * draw() reflow the text grid into the new extent.  Returns -1 (and stops the client) on failure. */
static int resize_buffers(struct app *a, int w, int h){
    if (w < 160) w = 160;                       /* floor keeps the layout math non-negative */
    if (h < 120) h = 120;
    if (w == a->width && h == a->height) return 0;
    destroy_buffers(a);
    a->width = w; a->height = h; a->stride = w * 4; a->buffer_size = (size_t)a->stride * h;
    a->dirty = 0;                               /* any deferred redraw referred to the old buffers */
    if (create_buffers(a) < 0){ log_line("EDITOR: resize buffer failed"); a->running = 0; return -1; }
    a->rows     = (TEXT_BOT - TEXT_TOP) / LINEH;
    a->vis_cols = a->cell_w > 0 ? TEXT_W / a->cell_w : 0;
    ensure_visible(a);                          /* keep the caret/scroll valid in the new viewport */
    return 0;
}
static void ed_insert_char(struct app *a, char c){
    line_insert(&a->lines[a->cur_line], a->cur_col, c);
    a->cur_col++; a->modified = 1;
}
static void ed_newline(struct app *a){
    lines_insert(a, a->cur_line + 1);                 /* may realloc a->lines */
    struct line *cur = &a->lines[a->cur_line];
    struct line *nl  = &a->lines[a->cur_line + 1];
    int tail = cur->len - a->cur_col;
    if (tail > 0){
        line_reserve(nl, tail);
        memcpy(nl->buf, cur->buf + a->cur_col, (size_t)tail);
        nl->buf[tail] = 0; nl->len = tail;
    }
    cur->buf[a->cur_col] = 0; cur->len = a->cur_col;
    a->cur_line++; a->cur_col = 0; a->modified = 1;
}
static void ed_backspace(struct app *a){
    if (a->cur_col > 0){
        line_delete(&a->lines[a->cur_line], a->cur_col - 1); a->cur_col--; a->modified = 1;
    } else if (a->cur_line > 0){
        struct line *prev = &a->lines[a->cur_line - 1];
        struct line *cur  = &a->lines[a->cur_line];
        int pl = prev->len;
        line_reserve(prev, prev->len + cur->len);
        memcpy(prev->buf + prev->len, cur->buf, (size_t)cur->len + 1);   /* includes NUL */
        prev->len += cur->len;
        lines_remove(a, a->cur_line);
        a->cur_line--; a->cur_col = pl; a->modified = 1;
    }
}
static void ed_delete(struct app *a){
    struct line *cur = &a->lines[a->cur_line];
    if (a->cur_col < cur->len){
        line_delete(cur, a->cur_col); a->modified = 1;
    } else if (a->cur_line < a->nlines - 1){
        struct line *nx = &a->lines[a->cur_line + 1];
        line_reserve(cur, cur->len + nx->len);
        memcpy(cur->buf + cur->len, nx->buf, (size_t)nx->len + 1);
        cur->len += nx->len;
        lines_remove(a, a->cur_line + 1);
        a->modified = 1;
    }
}

/* --- input --------------------------------------------------------------- */
static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)d;(void)p;(void)s;(void)sf; }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/ || state != 1) return;
    double x = a->pointer_x, y = a->pointer_y;
    if (x >= CLOSE_X && x < CLOSE_X + CLOSE_W && y >= CLOSE_Y && y < CLOSE_Y + CLOSE_H){ a->running = 0; return; }
    if (y >= TEXT_TOP && y < TEXT_BOT && x >= TEXT_X && a->cell_w > 0){    /* click-to-place caret */
        int r = ((int)y - TEXT_TOP) / LINEH; int ln = a->scroll_row + r;
        if (ln >= a->nlines) ln = a->nlines - 1; if (ln < 0) ln = 0;
        a->cur_line = ln;
        int col = a->scroll_col + ((int)x - TEXT_X + a->cell_w/2) / a->cell_w;
        if (col < 0) col = 0;
        a->cur_col = col; clamp_col(a);
        a->caret_on = 1; ensure_visible(a); redraw_commit(a);
    }
}
static void pointer_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v){ (void)p;(void)t; struct app*a=d;
    if (ax == 0){ a->scroll_row += (wl_fixed_to_double(v) > 0) ? 3 : -3;
        int max = a->nlines - 1; if (max < 0) max = 0;
        if (a->scroll_row > max) a->scroll_row = max; if (a->scroll_row < 0) a->scroll_row = 0;
        redraw_commit(a); } }
/* wl_pointer >= v5 also emits frame/axis_source/axis_stop/axis_discrete — these listener slots MUST be
 * non-NULL or libwayland calls a NULL fn-ptr on the first real pointer 'frame' event and the client
 * crashes (this vanished the window on real HW; QEMU headless sends no pointer events so it never fired). */
static void pointer_frame(void *d, struct wl_pointer *p){ (void)d;(void)p; }
static void pointer_axis_source(void *d, struct wl_pointer *p, uint32_t s){ (void)d;(void)p;(void)s; }
static void pointer_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t a){ (void)d;(void)p;(void)t;(void)a; }
static void pointer_axis_discrete(void *d, struct wl_pointer *p, uint32_t a, int32_t dsc){ (void)d;(void)p;(void)a;(void)dsc; }
static const struct wl_pointer_listener pointer_listener = {
    .enter=pointer_enter,.leave=pointer_leave,.motion=pointer_motion,.button=pointer_button,.axis=pointer_axis,
    .frame=pointer_frame,.axis_source=pointer_axis_source,.axis_stop=pointer_axis_stop,.axis_discrete=pointer_axis_discrete };

static int g_shift = 0, g_ctrl = 0;
static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t sz){ (void)d;(void)k;(void)f;(void)sz; if (fd>=0) close(fd); }
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf, struct wl_array *ks){ (void)d;(void)k;(void)s;(void)sf;(void)ks; }
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf){ (void)d;(void)k;(void)s;(void)sf; }
static void kb_key(void *d, struct wl_keyboard *k, uint32_t se, uint32_t t, uint32_t key, uint32_t state){ (void)k;(void)se;(void)t; struct app*a=d;
    if (key==42||key==54){ g_shift = (state==1); return; }   /* L/R shift */
    if (key==29||key==97){ g_ctrl  = (state==1); return; }   /* L/R ctrl  */
    if (state != 1) return;                                  /* press only */
    a->caret_on = 1;
    a->status[0] = 0;                                        /* clear any transient message */

    if (g_ctrl){
        if (key==31){ do_save(a); }                          /* Ctrl+S */
        else if (key==16){ a->running = 0; return; }         /* Ctrl+Q */
        redraw_commit(a); return;                            /* swallow other Ctrl combos */
    }

    switch (key){
        case 28: ed_newline(a); break;                       /* Enter */
        case 14: ed_backspace(a); break;                     /* Backspace */
        case 111: ed_delete(a); break;                       /* Delete */
        case 15:                                             /* Tab -> 4 spaces */
            for (int i=0;i<4;i++) ed_insert_char(a, ' ');
            break;
        case 103:                                            /* Up */
            if (a->cur_line > 0){ a->cur_line--; clamp_col(a); } break;
        case 108:                                            /* Down */
            if (a->cur_line < a->nlines-1){ a->cur_line++; clamp_col(a); } break;
        case 105:                                            /* Left */
            if (a->cur_col > 0) a->cur_col--;
            else if (a->cur_line > 0){ a->cur_line--; a->cur_col = a->lines[a->cur_line].len; } break;
        case 106:                                            /* Right */
            if (a->cur_col < a->lines[a->cur_line].len) a->cur_col++;
            else if (a->cur_line < a->nlines-1){ a->cur_line++; a->cur_col = 0; } break;
        case 102: a->cur_col = 0; break;                     /* Home */
        case 107: a->cur_col = a->lines[a->cur_line].len; break; /* End */
        case 104:                                            /* PageUp */
            a->cur_line -= (a->rows>1?a->rows-1:1); if (a->cur_line<0) a->cur_line=0; clamp_col(a); break;
        case 109:                                            /* PageDown */
            a->cur_line += (a->rows>1?a->rows-1:1); if (a->cur_line>a->nlines-1) a->cur_line=a->nlines-1; clamp_col(a); break;
        default:
            if (key < 128){ char c = g_shift ? EVDEV_SHIFT[key] : EVDEV_CHAR[key];
                if (c) ed_insert_char(a, c); }
            break;
    }
    ensure_visible(a); redraw_commit(a);
}
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
static void toplevel_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s){ (void)t;(void)s; struct app*a=d;
    /* Record the compositor's requested size; 0 means "you pick", so keep the current size then.
     * The change is applied when the paired xdg_surface.configure is acked (see below). */
    if (w > 0) a->pending_w = w;
    if (h > 0) a->pending_h = h; }
static void toplevel_close(void *d, struct xdg_toplevel *t){ (void)t; struct app*a=d; a->running=0; }
static void toplevel_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h){ (void)d;(void)t;(void)w;(void)h; }
static void toplevel_wmcap(void *d, struct xdg_toplevel *t, struct wl_array *c){ (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure=toplevel_configure,.close=toplevel_close,.configure_bounds=toplevel_bounds,.wm_capabilities=toplevel_wmcap };

static void xdg_surface_configure(void *d, struct xdg_surface *s, uint32_t serial){ struct app*a=d;
    xdg_surface_ack_configure(s, serial);
    /* Honor the compositor-driven (tiled) size: recreate the shm buffers when it changed, then
     * redraw so the text grid reflows to fill the tile.  Skips no-op/floating (0-size) configures. */
    if (a->pending_w > 0 && a->pending_h > 0 &&
        (a->pending_w != a->width || a->pending_h != a->height)){
        if (resize_buffers(a, a->pending_w, a->pending_h) < 0) return;   /* fatal: main loop exits */
    }
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

static void measure_cell(struct app *a){
    a->cell_w = (PX * 3) / 5;                                /* fallback guess */
    if (!a->font_ready) return;
    if (FT_Set_Pixel_Sizes(a->face, 0, (FT_UInt)PX) != 0) return;
    if (FT_Load_Char(a->face, 'M', FT_LOAD_DEFAULT) != 0) return;
    int adv = (int)(a->face->glyph->advance.x >> 6);
    if (adv > 0) a->cell_w = adv;
}

int main(int argc, char **argv){
    static struct app app; memset(&app, 0, sizeof app);
    app.running = 1;
    app.width = WIN_W; app.height = WIN_H; app.stride = WIN_W*4; app.buffer_size = (size_t)app.stride*WIN_H;
    app.rows = (app.height - STATUS_H - TEXT_TOP) / LINEH;
    app.caret_on = 1;
    signal(SIGCHLD, SIG_IGN);

    const char *open_path = (argc > 1) ? argv[1] : NULL;
    strncpy(app.path, open_path ? open_path : "/run/untitled.txt", sizeof(app.path)-1);
    { char tmp[512]; strncpy(tmp, app.path, sizeof tmp - 1); tmp[sizeof tmp -1]=0;
      char *bn = basename(tmp); strncpy(app.fname, bn, sizeof(app.fname)-1); }

    init_freetype(&app);
    measure_cell(&app);
    app.vis_cols = app.cell_w > 0 ? (app.width - TEXT_X - 4) / app.cell_w : 0;
    load_path(&app, open_path);

    log_line("EDITOR: starting text editor");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("EDITOR: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base){ log_line("EDITOR: missing globals"); return 1; }
    if (create_buffers(&app) < 0){ log_line("EDITOR: buffer failed"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Text Editor");
    xdg_toplevel_set_app_id(app.toplevel, "epin-editor");
    wl_surface_commit(app.surface);
    wl_display_flush(app.display);

    int wlfd = wl_display_get_fd(app.display);
    while (app.running){
        while (wl_display_prepare_read(app.display) != 0) wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);
        struct pollfd pfd = { .fd=wlfd, .events=POLLIN, .revents=0 };
        int pr = poll(&pfd, 1, 500);
        if (pr > 0 && (pfd.revents & POLLIN)){ wl_display_read_events(app.display); wl_display_dispatch_pending(app.display); }
        else { wl_display_cancel_read(app.display); if (pr < 0){ if (errno==EINTR) continue; break; }
               if (pr == 0){ app.caret_on = !app.caret_on; redraw_commit(&app); } }   /* ~2 Hz caret blink */
    }
    return 0;
}
