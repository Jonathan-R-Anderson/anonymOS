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
enum { BASE_FONT_PX = 17, BASE_CELL_W = 10, BASE_CELL_H = 20 };

static const uint32_t COL_BG     = 0xff101418;
static const uint32_t COL_FG     = 0xfff2f2f2;
static const uint32_t COL_CURSOR = 0xff30c030;

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
    struct wl_buffer     *buffer;
    struct wl_callback   *frame_cb;
    uint32_t             *pixels;
    int                   width, height;
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
    int                   cur_r, cur_c;
    int                   dirty;
    int                   esc;      // ANSI escape state machine

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
    a->width = COLS * a->cell_w;
    a->height = ROWS * a->cell_h;
    a->baseline = (BASE_FONT_PX - 3) * a->scale;
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
        for (int c = 0; c < COLS; c++)
            a->grid[r][c] = ' ';
    a->cur_r = a->cur_c = 0;
}

static void grid_scroll(struct app *a) {
    for (int r = 0; r < ROWS - 1; r++)
        memcpy(a->grid[r], a->grid[r + 1], COLS);
    for (int c = 0; c < COLS; c++)
        a->grid[ROWS - 1][c] = ' ';
}

static void grid_newline(struct app *a) {
    a->cur_c = 0;
    if (++a->cur_r >= ROWS) { a->cur_r = ROWS - 1; grid_scroll(a); }
}

// Feed one byte of shell output through a tiny VT interpreter.
static void vt_byte(struct app *a, unsigned char b) {
    // Swallow ANSI/VT escape sequences so they don't render as garbage.
    if (a->esc == 1) { a->esc = (b == '[') ? 2 : 0; return; }
    if (a->esc == 2) { if (b >= 0x40 && b <= 0x7e) a->esc = 0; return; }
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
    if (++a->cur_c >= COLS) grid_newline(a);
}

static void render(struct app *a) {
    if (!a->pixels) return;
    gf_fill(a->pixels, a->width, a->width, a->height, 0, 0, a->width, a->height, COL_BG);
    for (int r = 0; r < ROWS; r++)
        for (int c = 0; c < COLS; c++) {
            char ch = a->grid[r][c];
            if (ch != ' ') {
                int x = c * a->cell_w;
                int y = r * a->cell_h;
                if (a->font_ready)
                    render_ft_glyph(a, x, y, (unsigned char)ch, COL_FG);
                else
                    gf_glyph(a->pixels, a->width, a->width, a->height,
                             x, y + (a->cell_h - 8) / 2, ch, COL_FG, -1);
            }
        }
    // cursor block
    gf_fill(a->pixels, a->width, a->width, a->height,
            a->cur_c * a->cell_w, a->cur_r * a->cell_h,
            a->cell_w, a->cell_h, COL_CURSOR);
    char cc = a->grid[a->cur_r][a->cur_c];
    if (cc != ' ') {
        int x = a->cur_c * a->cell_w;
        int y = a->cur_r * a->cell_h;
        if (a->font_ready)
            render_ft_glyph(a, x, y, (unsigned char)cc, COL_BG);
        else
            gf_glyph(a->pixels, a->width, a->width, a->height,
                     x, y + (a->cell_h - 8) / 2, cc, COL_BG, -1);
    }
    // IDENTITY_DOMAIN §6: unspoofable colored border in the domain color, drawn LAST
    // so app/terminal pixels can never reach the border ring.
    if (g_has_domain) {
        int t = 4 * a->scale;
        gf_fill(a->pixels, a->width, a->width, a->height, 0, 0, a->width, t, g_domain_color);
        gf_fill(a->pixels, a->width, a->width, a->height, 0, a->height - t, a->width, t, g_domain_color);
        gf_fill(a->pixels, a->width, a->width, a->height, 0, 0, t, a->height, g_domain_color);
        gf_fill(a->pixels, a->width, a->width, a->height, a->width - t, 0, t, a->height, g_domain_color);
    }
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
            a->grid[r][c] = ' ';
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
    // IDENTITY_DOMAIN: honor the requested shell flavor. "linux" = busybox (Linux
    // personality), "native" = the EpinAnonymOS object shell (/hos-sh, Track B),
    // "windows" = not implemented (notice).
    const char *flavor = getenv("EPIN_SHELL");
    const int is_native = (flavor && strcmp(flavor, "native") == 0);
    if (flavor && *flavor && strcmp(flavor, "linux") != 0 && !is_native) {
        char l1[80];
        snprintf(l1, sizeof(l1), "Domain: %s", g_has_domain ? g_domain : "(none)");
        term_notice(a, l1, "Windows subsystem is not implemented yet.",
                    "Pick the 'Linux' or 'Native' shell in the Domain Manager.");
        a->ptm = -1;
        printf("G4TERM: shell flavor '%s' not implemented; showing notice\n", flavor);
        fflush(stdout);
        return 0;
    }
    // The shell binary + argv[0] depend on the flavor; the PTY plumbing is shared.
    const char *shell_path = is_native ? "/hos-sh" : "/-sh";
    char *const shell_arg0 = is_native ? "hos-sh" : "-sh";

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
        // Launch the chosen shell on the pty.  For busybox, argv[0]="-sh" makes ash
        // an interactive login shell; for the native shell, /hos-sh.
        char *argv[] = { shell_arg0, NULL };
        execve(shell_path, argv, environ);
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

static void key_to_pty(struct app *a, uint32_t code) {
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
    if (down) key_to_pty(a, code);
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

static void seat_caps(void *data, struct wl_seat *seat, uint32_t caps) {
    struct app *a = data;
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
    if (a->committed) return;
    if (create_shm_buffer(a) < 0) { a->running = 0; return; }
    grid_clear(a);
    a->post_map_frame_armed = 1;
    commit(a);
    a->committed = 1;
    printf("G4TERM: committed terminal window %dx%d -- G4 COMMIT\n", a->width, a->height); fflush(stdout);
}
static const struct xdg_surface_listener xdg_surface_listener = { .configure = xdg_surface_configure };

static void toplevel_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s)
{ (void)d; (void)t; (void)w; (void)h; (void)s; }
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
    struct app a;
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
    char title[96];
    if (g_has_domain)
        snprintf(title, sizeof(title), "[%s] EpinAnonymOS Terminal", g_domain);
    else
        snprintf(title, sizeof(title), "EpinAnonymOS Terminal");
    xdg_toplevel_set_title(a.toplevel, title);
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
