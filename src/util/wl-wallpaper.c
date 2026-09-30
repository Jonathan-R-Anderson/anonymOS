/*
 * wl-wallpaper.c -- the DESKTOP of the EpinAnonymOS Hyprland session: the wallpaper, the desktop
 * icons on it, selection (click, Ctrl+click, rubber band) and the right-click menu.
 *
 * Hyprland (wlroots) paints only a solid misc:background_color; it renders no image wallpaper and
 * no desktop, and this image ships no wallpaper daemon or desktop-icon program -- quickshell,
 * hyprpaper, swww and nautilus-desktop are all absent.  So the desktop is drawn here, by a plain
 * wlr-layer-shell client on the BACKGROUND layer, one layer below wl-layer-bar (which uses the same
 * protocol for the top bar).  Wallpaper and icons are ONE surface: the icons can never drift off
 * the image they sit on, and there is exactly one thing underneath every window.
 *
 * Wallpaper.  The default image is the dendritic network's radial keyspace topology -- the graph
 * the dendritic website embedded (backend/templates/includes/peer-canvas.html).  It is rendered to
 * a PNG at build time by tools/wallpaper-gen and shipped both in the Hyprland config tree
 * (~/.config/hypr/wallpapers/dendritic-network.png) and as a boot module (/dendritic-network.png),
 * so at least one path resolves however early this runs.  It is decoded with libpng's simplified
 * API into BGRA -- which matches the XRGB8888 wl_shm framebuffer exactly, the same trick wl-imgview
 * uses -- and scaled ONCE per output size to "contain" the output, letterboxed with the image's own
 * ground (#0d1117 for the default, so the fill is seamless).  That scaled copy is kept and memcpy'd
 * under every frame, so a rubber-band drag costs a copy, not a rescale.  No GPU and no async
 * resource gatherer, so it is immune to the CAsyncResourceGatherer/mallocng crash that sinks
 * Hyprland's own stock wallpaper under musl (see src/kernel/d/core/exports.d).  "Change Wallpaper..."
 * picks another PNG (or a solid colour); the choice is kept in ~/.config/wl-desktop/wallpaper.
 *
 * Icons.  A grid down the left edge, column-major like GNOME/Windows: the fixed shortcuts (Home,
 * Terminal, Software, Virtual Machines, Domains, Trash), then one icon per entry of ~/Desktop
 * (folders first; nothing is created when it does not exist).  Every glyph is vector-drawn with
 * cairo in the wl-vmm/wl-files house style (dark, teal 0x0d8577/0x14a595) -- no image assets -- and
 * every label is FreeType text (Noto Sans, the wl-vmm glyph cache, Latin-1) with a shadow so it
 * reads on any wallpaper.  ~/Desktop is re-read every two seconds.  Icons can be dragged to another
 * cell (dropping on Trash trashes, dropping on a folder moves into it); the cells the user chose
 * are kept in ~/.config/wl-desktop/icons, and "Arrange Icons" puts everything back in order.
 *
 * Input.  Click selects, Ctrl+click toggles, a left-drag on empty desktop draws a translucent
 * rubber band that selects every icon it touches, live.  Double-click / Enter opens.  Right-click
 * opens a context menu -- a real xdg_popup made a child of this layer surface with
 * zwlr_layer_surface_v1.get_popup, so Hyprland draws it ABOVE every window (layer popups are
 * rendered last, see Renderer.cpp) and ends it on an outside click via its popup grab.  Without
 * xdg_wm_base the same menu is drawn inside the desktop surface instead.  The keyboard shortcuts
 * shown in the menus (Enter, F2, Delete, Ctrl+C, Alt+Enter, Ctrl+A, Ctrl+Shift+N) work while the
 * desktop has keyboard focus.
 *
 * Keyboard focus.  The layer surface starts with keyboard_interactivity NONE.  Hyprland focuses an
 * ON_DEMAND layer surface on mere HOVER when input:follow_mouse = 1 (InputManager.cpp, the "else"
 * branch of mouseMoveUnified), so a permanently ON_DEMAND desktop would steal the keyboard from the
 * window being typed in whenever the pointer rested on empty desktop.  Instead the desktop turns
 * ON_DEMAND (2 -- NOT 1, which is EXCLUSIVE in this protocol) when it is clicked, and back to NONE
 * when the pointer leaves it for a window or panel.  A click does not by itself move Hyprland's
 * keyboard focus to a layer surface, so after a left click the desktop "pulses" EXCLUSIVE ->
 * ON_DEMAND in two back-to-back commits: the EXCLUSIVE commit focuses it (LayerSurface::onCommit),
 * the ON_DEMAND one immediately gives up the exclusivity (WLDESKTOP_FOCUS_PULSE=0 disables this).
 *
 * Launching mirrors wl-layer-bar / wl-overview exactly: fork, setsid, drop WAYLAND_SOCKET and every
 * inherited fd, execve the boot-module path with this environment.  This is unconfined desktop
 * chrome (appreg.d: wl-wallpaper is INFRA|CHROME), so the kernel's appgate places the child by
 * image -- Files/Terminal/editor/viewer into the session domain (when delegated), Software/Virtual
 * Machines/Domains into System -- exactly as from the app grid.  A refused exec comes back as
 * EACCES in the child, which exits 126 (127 = not found); the reaped status is shown as a notice
 * on the desktop.  /config/appgate.json ("desktop") dims shortcuts the desktop may not launch.
 *
 * Self-test: `wl-wallpaper --render-png PREFIX [--image PNG]` renders the desktop and each popup
 * to PREFIX-*.png with no compositor (fonts from WLDESKTOP_FONTDIR, size from WLDESKTOP_SIZE=WxH).
 *
 * Single output: it dresses the first wl_output offered, which is the whole story on the
 * single-head VM this targets.  A multi-head host would leave the other outputs bare.
 */
#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include <png.h>
#include <cairo/cairo.h>
#include "hos-shell-ui.h"         /* the icon art and the domain badge, shared with the dock */
#include <ft2build.h>
#include FT_FREETYPE_H
#include "xdg-shell-client-protocol.h"
#include "wlr-layer-shell-unstable-v1-client-protocol.h"

extern char **environ;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

/* ── colours ───────────────────────────────────────────────────────────────────────────── */
/* The ground colour of the generated wallpaper (tools/wallpaper-gen: #0d1117).  The solid fill
 * before an image loads, and the default "Solid" wallpaper. */
#define COL_BG      0x0d1117u
#define C_ACCENT    0x0d8577u
#define C_ACCENT2   0x14a595u
#define C_TEXT      0xe6ecf2u
#define C_WHITE     0xffffffu
#define C_DIM       0x8b96a4u
#define C_FAINT     0x5f6b78u
#define C_MENU      0x19222au
#define C_MENU_LINE 0x2c3843u
#define C_RED       0xff7b7bu
#define C_DANGER    0xc92a2au

/* Paths tried in order; argv[1] (or --image) overrides.  The config-tree copy is the "real"
 * location; the boot-module copy is the always-present early fallback. */
static const char *DEFAULT_PATHS[] = {
    "/home/user/.config/hypr/wallpapers/dendritic-network.png",
    "/dendritic-network.png",
    NULL,
};

/* ── geometry ──────────────────────────────────────────────────────────────────────────── */
/* The grid starts right of the launcher bar (wl-dock), which covers the left edge: its width is
 * dock.conf's `width`, 64 by default.  This surface ignores exclusive zones, so it has to know. */
static int g_grid_x = 10;
#define GRID_X g_grid_x
static void grid_x_init(const char *home)
{
    if (access("/wl-dock", X_OK) != 0) return;                /* no dock in this image */
    int w = 64;
    char p[512];
    snprintf(p, sizeof p, "%s/.config/anonymos/dock.conf", home);
    FILE *f = fopen(p, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof line, f)) {
            const char *q = line; while (*q == ' ' || *q == '\t') q++;
            if (!strncmp(q, "width", 5)) { const char *e = strchr(q, '='); if (e) { int v = atoi(e + 1); if (v >= 40 && v <= 160) w = v; } }
        }
        fclose(f);
    }
    g_grid_x = w + 10;
}
enum {
    BAR_H     = 28,              /* wl-layer-bar's strip: the grid starts below it */
    GRID_Y    = BAR_H + 10,
    CELL_W    = 100,
    CELL_H    = 100,
    TILE      = 48,              /* the glyph tile */
    TILE_Y    = 8,               /* tile top inside its cell */
    LABEL_GAP = 6,
    LABEL_PX  = 12,
    LINE_H    = 16,
    LABEL_W   = CELL_W - 12,
    MAX_ICONS = 256,
    DRAG_SLOP = 5,
    DBL_MS    = 450,
    MENU_PAD  = 6, ITEM_H = 28, SEP_H = 9, MENU_MIN_W = 236, MENU_PX = 13,
    WP_MAX    = 24,
    MAX_LAUNCH = 16,
};

/* evdev key codes (Wayland delivers raw evdev codes; see km_plain below) */
enum {
    KEY_ESC = 1, KEY_BACKSPACE = 14, KEY_ENTER = 28, KEY_LCTRL = 29, KEY_A = 30, KEY_LSHIFT = 42,
    KEY_C = 46, KEY_N = 49, KEY_RSHIFT = 54, KEY_LALT = 56, KEY_SPACE = 57, KEY_F2 = 60,
    KEY_F10 = 68, KEY_KPENTER = 96, KEY_RCTRL = 97, KEY_RALT = 100, KEY_HOME = 102, KEY_UP = 103,
    KEY_LEFT = 105, KEY_RIGHT = 106, KEY_END = 107, KEY_DOWN = 108, KEY_DELETE = 111,
    KEY_MENU = 127,
};
enum { BTN_LEFT = 0x110, BTN_RIGHT = 0x111 };

/* ── glyph cache (wl-vmm's, widened to Latin-1 so "Café" is not "Caf??") ────────────── */
enum { GLYPH_FIRST = 0x20, GLYPH_LAST = 0xff, GLYPH_CHARS = GLYPH_LAST - GLYPH_FIRST + 1,
       GLYPH_MAX_PX = 40, GLYPH_SIZE_SLOTS = 8 };
struct glyph { int loaded; unsigned char *bitmap; int width, rows, pitch, left, top, advance; };
struct glyph_size { int px; int ascender; struct glyph glyphs[GLYPH_CHARS]; };
struct font { FT_Face face; unsigned char *data; size_t size; struct glyph_size sizes[GLYPH_SIZE_SLOTS];
              int cur_px; int ok; };
enum { F_REG, F_BOLD, F_COUNT };

/* ── model ─────────────────────────────────────────────────────────────────────────────── */
enum { K_APP, K_TRASH, K_DIR, K_FILE, K_IMAGE, K_TEXT, K_LAUNCHER };
enum { G_HOME, G_TERMINAL, G_SOFTWARE, G_VMS, G_DOMAINS, G_TRASH, G_FOLDER, G_FILE, G_IMAGE,
       G_TEXT, G_LAUNCHER };

struct icon {
    char key[280];            /* position-file key: "@home" for shortcuts, "d:<file>" for ~/Desktop */
    char fname[256];          /* ~/Desktop entry name ("" for shortcuts) */
    char name[256];           /* label (a launcher's Name=) */
    char path[512];           /* the file, or what a shortcut opens */
    char exec[256];           /* command line: shortcuts and .desktop launchers */
    char image[48];           /* appgate image basename of a shortcut ("wl-files") */
    char ext[8];              /* upper-case extension badge for plain files */
    int kind, glyph, fixed;
    int col, row;             /* grid cell, -1 = no room */
    int placed;               /* 0 auto, 1 the user put it there (saved), 2 auto but sticky */
    int sel;
    int allowed;              /* appgate: the desktop may launch it */
    int nlines;               /* label lines when not expanded */
    int is_dir;
    long long size;
    time_t mtime;
    mode_t mode;
};

struct fixed_def { const char *key, *label, *exec, *image; int glyph, kind; };
static const struct fixed_def FIXED[] = {
    { "@home",     "Home",             "/wl-files",          "wl-files",          G_HOME,     K_APP },
    /* /hos-wifiterm, like the app grid's Terminal tile (system/applications/terminal.desktop). */
    { "@terminal", "Terminal",         "/hos-wifiterm",      "hos-wifiterm",      G_TERMINAL, K_APP },
    { "@software", "Software",         "/wl-software",       "wl-software",       G_SOFTWARE, K_APP },
    { "@vms",      "Virtual Machines", "/wl-vmm",            "wl-vmm",            G_VMS,      K_APP },
    { "@domains",  "Domains",          "/wl-domain-manager", "wl-domain-manager", G_DOMAINS,  K_APP },
    { "@trash",    "Trash",            "/wl-files",          "wl-files",          G_TRASH,    K_TRASH },
};
enum { N_FIXED = (int)(sizeof FIXED / sizeof FIXED[0]) };

struct saved_pos { char key[280]; int col, row; };
struct wpchoice { char label[64]; char path[400]; uint32_t color; };
struct launch { pid_t pid; long long t0; char label[64]; char prog[64]; };

/* ── drawing targets ───────────────────────────────────────────────────────────────────── */
struct canvas { uint32_t *px; int w, h, stride; cairo_surface_t *cs; cairo_t *cr; };
struct app;
struct shmbuf { struct wl_buffer *wl; uint32_t *px; int busy; int owner; struct app *a; };
struct pool { struct shmbuf b[2]; void *map; size_t size; int w, h, stride; };

/* ── popups (context menu, wallpaper picker, properties, confirmation) ─────────────────── */
enum { POP_NONE, POP_MENU, POP_WALLPAPER, POP_PROPS, POP_CONFIRM };
enum {
    ACT_NONE, ACT_OPEN_TERMINAL, ACT_OPEN_FILES, ACT_NEW_FOLDER, ACT_ARRANGE, ACT_SELECT_ALL,
    ACT_WALLPAPER, ACT_DISPLAY, ACT_OPEN, ACT_OPEN_WITH_FILES, ACT_RENAME, ACT_TRASH, ACT_COPY_PATH,
    ACT_PROPERTIES, ACT_EMPTY_TRASH, ACT_SET_WALLPAPER, ACT_PICK_WALLPAPER, ACT_CLOSE_POPUP,
    ACT_CONFIRM_EMPTY,
};
struct mitem { char label[64]; char accel[16]; int action, arg, enabled, sep, checked; };
struct pbtn { int x, y, w, h, action, style; char label[24]; };
struct prow { char k[24]; char v[200]; };

struct popup {
    int kind;
    struct wl_surface *surf;
    struct xdg_surface *xs;
    struct xdg_popup *xp;
    struct wl_callback *frame_cb;
    int frame_pending, dirty, configured;
    long long frame_ms;
    struct pool pool;
    int inline_mode;           /* drawn inside the desktop surface (no xdg_wm_base) */
    int x, y, w, h;            /* position in desktop coordinates, size */
    struct mitem items[24];
    int nitems, hover, moved, pressed_inside;
    struct pbtn btns[3];
    int nbtns, btn_hover;
    char title[256], sub[128], msg[256];
    struct prow rows[8];
    int nrows;
    int glyph_icon;            /* 1: `glyph` heads the properties, 0: the multi-selection folder */
    struct icon glyph;         /* a copy -- a rescan may reorder the icons while the popup is up */
};

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_output *output;
    struct wl_seat *seat;
    struct wl_pointer *pointer;
    struct wl_keyboard *keyboard;
    struct xdg_wm_base *wm_base;
    struct zwlr_layer_shell_v1 *layer_shell;
    uint32_t layer_shell_ver;
    struct wl_data_device_manager *ddm;
    struct wl_data_device *ddev;
    struct wl_data_source *clip_src;
    char *clip_text;
    struct wl_surface *surface;
    struct zwlr_layer_surface_v1 *layer_surface;
    struct wl_callback *frame_cb;
    struct pool pool;
    int width, height;
    int configured, running, dirty, frame_pending, full_damage;
    long long frame_ms;
    int kbi;                   /* committed keyboard_interactivity */
    int engaged;               /* the user clicked the desktop since the pointer last left it */
    int offscreen;             /* --render-png: no compositor */
    int no_persist;            /* --render-png: write nothing under ~/.config */

    /* drawing */
    struct canvas *cv;
    FT_Library ft;
    struct font fonts[F_COUNT];
    uint32_t *bg;              /* the wallpaper scaled to the output: copied under every frame */
    int bg_w, bg_h;
    int marking;               /* accumulate the drawn bounding box (damage) */
    int dx0, dy0, dx1, dy1;    /* this frame's drawn bbox */
    int px0, py0, px1, py1;    /* the previous frame's */

    /* wallpaper */
    uint32_t *img;
    int iw, ih;
    uint32_t img_ground;       /* letterbox fill: the image's corner pixel */
    char wp_path[400];         /* the image in use, "" = solid colour */
    uint32_t wp_color;
    struct wpchoice wp[WP_MAX];
    int nwp;

    /* icons */
    struct icon icons[MAX_ICONS];
    int nicons, cols, rows;
    int hover, cursor;
    char home[256], desk_dir[300], trash_files[340], trash_info[340], cfg_dir[300];
    int trash_full;
    char *appgate;             /* /config/appgate.json, whole: placements for the domain badges */
    struct hos_domain *doms;   /* /config/domains.json: each domain's colour and tag */
    int ndoms;
    struct hos_font badge_font;
    struct saved_pos saved[MAX_ICONS];
    int nsaved;

    /* input */
    struct wl_surface *ptr_surf, *kb_surf;
    double ptr_x, ptr_y;       /* desktop coordinates */
    double pop_px, pop_py;     /* popup-local coordinates */
    int ptr_on_main;
    int ctrl, shift, alt;
    uint32_t serial;           /* last input serial (popup grab, clipboard) */
    int press;                 /* left gesture: 0 none, 1 on an icon, 2 on empty desktop */
    int press_idx, press_keep; /* press_keep: pressed an already-selected icon of a multi-selection */
    double press_x, press_y;
    int dragging, band, drop_target;
    unsigned char band_base[MAX_ICONS];
    int click_idx;
    uint32_t click_ms;
    int menu_x, menu_y;        /* where the last context menu was asked for */

    /* inline rename */
    int edit_idx;
    char edit[256];

    struct popup pop;

    char notice[220];
    int notice_err;
    long long notice_until;

    /* appgate */
    char *desk_list;           /* /config/appgate.json "desktop": [ ... ] text, NULL = unknown */
    char session[48];
    long long next_tick, next_gate;
    struct launch launches[MAX_LAUNCH];
};

static void request_redraw(struct app *a);
static void pop_request_redraw(struct app *a);
static void pop_close(struct app *a);
static void do_action(struct app *a, int action, int arg);
static int scan_desktop(struct app *a, int force);
static void layout_icons(struct app *a);
static void set_kbi(struct app *a, int on);
static void focus_pulse(struct app *a);

static volatile sig_atomic_t g_quit;
static void on_signal(int sig) { (void)sig; g_quit = 1; }

/* ── small helpers ─────────────────────────────────────────────────────────────────────── */
static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static void log_line(const char *m) { fprintf(stderr, "WALL: %s\n", m); fflush(stderr); }
static void logf_(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void logf_(const char *fmt, ...)
{
    char b[400];
    va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    log_line(b);
}
/* A transient line at the bottom of the desktop: how a refused launch or a failed file operation
 * is explained, instead of a program that silently never appeared. */
static void notice(struct app *a, int err, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void notice(struct app *a, int err, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vsnprintf(a->notice, sizeof a->notice, fmt, ap); va_end(ap);
    a->notice_err = err;
    a->notice_until = now_ms() + (err ? 7000 : 4000);
    logf_("%s%s", err ? "error: " : "", a->notice);
    request_redraw(a);
}
static void copy_str(char *dst, size_t cap, const char *src) { snprintf(dst, cap, "%s", src ? src : ""); }
static const char *base_name(const char *p) { const char *s = strrchr(p, '/'); return s ? s + 1 : p; }
static int imin(int x, int y) { return x < y ? x : y; }
static int imax(int x, int y) { return x > y ? x : y; }
static void fmt_bytes(long long b, char *out, size_t cap)
{
    if (b < 1024) snprintf(out, cap, "%lld bytes", b);
    else if (b < 1024LL * 1024) snprintf(out, cap, "%.1f KB (%lld bytes)", b / 1024.0, b);
    else if (b < 1024LL * 1024 * 1024) snprintf(out, cap, "%.1f MB (%lld bytes)", b / 1048576.0, b);
    else snprintf(out, cap, "%.2f GB", b / 1073741824.0);
}
static int mkdir_p(const char *path)
{
    char tmp[512];
    copy_str(tmp, sizeof tmp, path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) { *p = '/'; return -1; }
        *p = '/';
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}
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

/* One UTF-8 code point; malformed bytes come back as '?' one at a time. */
static uint32_t utf8_next(const char **ps)
{
    const unsigned char *s = (const unsigned char *)*ps;
    uint32_t c = s[0];
    int n;
    if (c < 0x80) n = 0;
    else if ((c & 0xe0) == 0xc0) { c &= 0x1f; n = 1; }
    else if ((c & 0xf0) == 0xe0) { c &= 0x0f; n = 2; }
    else if ((c & 0xf8) == 0xf0) { c &= 0x07; n = 3; }
    else { *ps += 1; return '?'; }
    for (int i = 1; i <= n; i++) {
        if ((s[i] & 0xc0) != 0x80) { *ps += 1; return '?'; }
        c = (c << 6) | (s[i] & 0x3f);
    }
    *ps += 1 + n;
    return c;
}

/* ── FreeType ──────────────────────────────────────────────────────────────────────────── */
static void init_fonts(struct app *a)
{
    static const char *const names[F_COUNT] = { "NotoSans-Regular.ttf", "NotoSans-Bold.ttf" };
    const char *dir = getenv("WLDESKTOP_FONTDIR");
    if (!dir || !*dir) dir = "/usr/share/fonts/noto";
    if (FT_Init_FreeType(&a->ft) != 0) { log_line("FreeType init failed -- icons without labels"); return; }
    for (int i = 0; i < F_COUNT; i++) {
        struct font *f = &a->fonts[i];
        char path[400];
        snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        if (load_file(path, &f->data, &f->size) == 0)
            f->ok = FT_New_Memory_Face(a->ft, f->data, (FT_Long)f->size, 0, &f->face) == 0;
        if (!f->ok && i != F_REG && a->fonts[F_REG].ok) {      /* bold missing: reuse the regular face */
            f->data = a->fonts[F_REG].data; f->size = a->fonts[F_REG].size;
            f->ok = FT_New_Memory_Face(a->ft, f->data, (FT_Long)f->size, 0, &f->face) == 0;
        }
        if (!f->ok) logf_("font %s unavailable", path);
    }
    char bp[400];
    snprintf(bp, sizeof bp, "%s/%s", dir, names[F_REG]);
    if (hos_font_load(&a->badge_font, bp) != 0) logf_("badge font %s unavailable", bp);
}

static inline unsigned int div255(unsigned int x) { return (x + 1 + (x >> 8)) >> 8; }
/* Glyph coverage over an OPAQUE pixel (the desktop, or a popup's solid body). */
static uint32_t blend(uint32_t dst, uint32_t src, unsigned int alpha)
{
    if (alpha >= 255) return 0xff000000u | src;
    if (!alpha) return dst;
    unsigned int inv = 255 - alpha;
    unsigned int r = div255(((src >> 16) & 0xff) * alpha + ((dst >> 16) & 0xff) * inv);
    unsigned int g = div255(((src >> 8) & 0xff) * alpha + ((dst >> 8) & 0xff) * inv);
    unsigned int b = div255((src & 0xff) * alpha + (dst & 0xff) * inv);
    return 0xff000000u | (r << 16) | (g << 8) | b;
}

static struct glyph_size *slot_for(struct font *f, int px)
{
    if (px <= 0 || px > GLYPH_MAX_PX) return NULL;
    struct glyph_size *free_slot = NULL;
    for (int i = 0; i < GLYPH_SIZE_SLOTS; i++) {
        if (f->sizes[i].px == px) return &f->sizes[i];
        if (!free_slot && f->sizes[i].px == 0) free_slot = &f->sizes[i];
    }
    if (free_slot) free_slot->px = px;
    return free_slot;
}

static const struct glyph *cached_glyph(struct font *f, int px, uint32_t cp)
{
    if (!f->ok) return NULL;
    if (cp < GLYPH_FIRST || cp > GLYPH_LAST || (cp >= 0x7f && cp < 0xa0)) cp = '?';
    struct glyph_size *slot = slot_for(f, px);
    if (!slot) return NULL;
    struct glyph *gl = &slot->glyphs[cp - GLYPH_FIRST];
    if (gl->loaded) return gl;
    if (f->cur_px != px) {
        if (FT_Set_Pixel_Sizes(f->face, 0, (FT_UInt)px) != 0) return NULL;
        f->cur_px = px;
    }
    if (slot->ascender == 0 && f->face->size && f->face->size->metrics.ascender > 0)
        slot->ascender = (int)(f->face->size->metrics.ascender >> 6);
    if (FT_Load_Char(f->face, (FT_ULong)cp, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) != 0) return NULL;
    FT_GlyphSlot g = f->face->glyph;
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

static int glyph_adv(struct app *a, int fid, int px, uint32_t cp)
{
    const struct glyph *gl = cached_glyph(&a->fonts[fid], px, cp);
    return gl ? gl->advance : 0;
}
static int text_width(struct app *a, int fid, int px, const char *s)
{
    int w = 0;
    if (!s) return 0;
    for (const char *p = s; *p && *p != '\n';) w += glyph_adv(a, fid, px, utf8_next(&p));
    return w;
}
static int baseline_of(struct app *a, int fid, int px)
{
    struct font *f = &a->fonts[fid];
    struct glyph_size *slot = slot_for(f, px);
    if (!slot) return px;
    if (slot->ascender == 0) (void)cached_glyph(f, px, 'H');
    return slot->ascender > 0 ? slot->ascender : px;
}

static void blit_glyph(struct app *a, const struct glyph *gl, int pen_x, int pen_y, uint32_t color,
                       unsigned int alpha)
{
    struct canvas *c = a->cv;
    if (!gl->bitmap) return;
    int gx = pen_x + gl->left, gy = pen_y - gl->top;
    for (int row = 0; row < gl->rows; row++) {
        int py = gy + row;
        if (py < 0 || py >= c->h) continue;
        const unsigned char *src = gl->bitmap + (size_t)row * gl->pitch;
        uint32_t *line = &c->px[(size_t)py * (size_t)(c->stride / 4)];
        for (int col = 0; col < gl->width; col++) {
            int pxp = gx + col;
            if (pxp < 0 || pxp >= c->w) continue;
            unsigned int al = src[col];
            if (alpha < 255) al = div255(al * alpha);
            if (al) line[pxp] = blend(line[pxp], color, al);
        }
    }
}

/* One line of text at (x, y) = top-left, ellipsised to max_w.  `alpha` scales the coverage (for
 * shadows and drag ghosts).  Cairo drawing may be interleaved: the surface is flushed before the
 * glyph blit and marked dirty after, exactly as in wl-vmm. */
static int text_draw(struct app *a, int fid, int px, int x, int y, int max_w, uint32_t color,
                     unsigned int alpha, const char *s)
{
    struct font *f = &a->fonts[fid];
    if (!a->cv || !f->ok || !s || max_w <= 0) return 0;
    cairo_surface_flush(a->cv->cs);
    int pen = x, pen_y = y + baseline_of(a, fid, px);
    int ell = text_width(a, fid, px, s) > max_w ? text_width(a, fid, px, "...") : 0;
    for (const char *p = s; *p;) {
        const struct glyph *gl = cached_glyph(f, px, utf8_next(&p));
        if (!gl) continue;
        if (ell && pen + gl->advance > x + max_w - ell) {
            for (const char *e = "..."; *e; e++) {
                const struct glyph *eg = cached_glyph(f, px, (uint32_t)*e);
                if (!eg) break;
                blit_glyph(a, eg, pen, pen_y, color, alpha);
                pen += eg->advance;
            }
            break;
        }
        blit_glyph(a, gl, pen, pen_y, color, alpha);
        pen += gl->advance;
    }
    cairo_surface_mark_dirty(a->cv->cs);
    return pen - x;
}
static void text_center(struct app *a, int fid, int px, int x, int y, int w, uint32_t color, const char *s)
{
    int tw = text_width(a, fid, px, s);
    text_draw(a, fid, px, x + (w - imin(tw, w)) / 2, y, w, color, 255, s);
}
/* Light text that stays legible on any wallpaper: a hard 1px shadow plus a softer one below it. */
static void text_shadowed(struct app *a, int px, int x, int y, int max_w, uint32_t color,
                          unsigned int alpha, const char *s)
{
    text_draw(a, F_REG, px, x + 1, y + 2, max_w, 0x000000, div255(110 * alpha), s);
    text_draw(a, F_REG, px, x + 1, y + 1, max_w, 0x000000, div255(235 * alpha), s);
    text_draw(a, F_REG, px, x, y, max_w, color, alpha, s);
}

/* Word-wrap a label into at most `maxlines` lines of `maxw` px, the last one ellipsised.  A word
 * wider than a line is broken inside (file names often have no spaces at all). */
struct lines { int n; char s[5][132]; int w[5]; };
static void wrap_label(struct app *a, const char *name, int maxw, int maxlines, struct lines *out)
{
    enum { MAXCP = 256 };
    int offs[MAXCP + 1], adv[MAXCP];
    int ncp = 0;
    const char *p = name;
    while (*p && ncp < MAXCP) {
        offs[ncp] = (int)(p - name);
        adv[ncp] = glyph_adv(a, F_REG, LABEL_PX, utf8_next(&p));
        ncp++;
    }
    offs[ncp] = (int)(p - name);
    if (maxlines > 5) maxlines = 5;
    out->n = 0;
    int i = 0;
    while (i < ncp && out->n < maxlines) {
        while (i < ncp && name[offs[i]] == ' ') i++;          /* no leading blanks on a wrapped line */
        if (i >= ncp) break;
        int last = out->n == maxlines - 1;
        int w = 0, j = i, brk = -1;
        while (j < ncp && w + adv[j] <= maxw) { if (name[offs[j]] == ' ') brk = j; w += adv[j]; j++; }
        int end, next;
        if (j >= ncp) { end = ncp; next = ncp; }
        else if (last) {                                        /* ellipsise the final line */
            int ell = text_width(a, F_REG, LABEL_PX, "...");
            int k = i; w = 0;
            while (k < ncp && w + adv[k] + ell <= maxw) { w += adv[k]; k++; }
            int len = offs[k] - offs[i];
            if (len > 124) len = 124;
            memcpy(out->s[out->n], name + offs[i], (size_t)len);
            memcpy(out->s[out->n] + len, "...", 4);
            out->w[out->n] = w + ell;
            out->n++;
            return;
        } else if (brk > i) { end = brk; next = brk + 1; }
        else { end = j > i ? j : i + 1; next = end; }
        int len = offs[end] - offs[i];
        if (len > 128) len = 128;
        memcpy(out->s[out->n], name + offs[i], (size_t)len);
        out->s[out->n][len] = 0;
        int lw = 0;
        for (int k = i; k < end; k++) lw += adv[k];
        out->w[out->n] = lw;
        out->n++;
        i = next;
    }
    if (out->n == 0) { out->s[0][0] = 0; out->w[0] = 0; out->n = 1; }
}

/* ── cairo shapes ──────────────────────────────────────────────────────────────────────── */
#define set_rgb  hos_set_rgb
#define set_rgba hos_set_rgba
#define rr_path  hos_rr_path
static void rfill(struct app *a, double x, double y, double w, double h, double r, uint32_t c, double al)
{ rr_path(a->cv->cr, x, y, w, h, r); set_rgba(a->cv->cr, c, al); cairo_fill(a->cv->cr); }
static void rstroke(struct app *a, double x, double y, double w, double h, double r, uint32_t c, double al)
{
    rr_path(a->cv->cr, x + 0.5, y + 0.5, w - 1, h - 1, r);
    set_rgba(a->cv->cr, c, al);
    cairo_set_line_width(a->cv->cr, 1);
    cairo_stroke(a->cv->cr);
}

/* Grow this frame's damage box (desktop surface only). */
static void mark(struct app *a, int x, int y, int w, int h)
{
    if (!a->marking || w <= 0 || h <= 0) return;
    if (a->dx1 <= a->dx0) { a->dx0 = x; a->dy0 = y; a->dx1 = x + w; a->dy1 = y + h; return; }
    a->dx0 = imin(a->dx0, x); a->dy0 = imin(a->dy0, y);
    a->dx1 = imax(a->dx1, x + w); a->dy1 = imax(a->dy1, y + h);
}

/* ── icon art: hos-shell-ui.h (shared with the dock and the app grid) ─────────────────────── */
/* The art of one icon in an s x s square, its text (a launcher's initial, a file's extension -- in
 * this client's own glyph fonts) and, on an application, the badge of the domain it runs in.
 * `with_text` = false for drag ghosts, drawn through a cairo group the glyph blitter (which writes
 * pixels directly) cannot join. */
static void draw_icon_art(struct app *a, const struct icon *ic, double x, double y, double s, int with_text)
{
    cairo_t *cr = a->cv->cr;
    hos_icon_art(cr, ic->glyph, x, y, s, ic->name, ic->ext, a->trash_full);
    if (ic->glyph == G_FILE && ic->ext[0] && with_text)
        text_center(a, F_BOLD, 9, (int)(x + s * 0.1), (int)(y + s * 0.56 + 1), (int)(s * 0.56), C_WHITE, ic->ext);
    if ((ic->glyph == G_LAUNCHER || ic->glyph > G_TEXT) && with_text && ic->name[0]) {
        char ch[8];
        const char *p = ic->name;
        uint32_t cp = utf8_next(&p);
        if (cp < 0x80) { ch[0] = (char)toupper((int)cp); ch[1] = 0; }
        else { size_t n = (size_t)(p - ic->name); if (n > 7) n = 7; memcpy(ch, ic->name, n); ch[n] = 0; }
        int px = (int)(s * 0.46);
        text_center(a, F_BOLD, px, (int)x, (int)(y + (s - px * 1.36) / 2), (int)s, C_WHITE, ch);
    }
    if (!ic->allowed) {                                     /* appgate: not launchable from here */
        rr_path(cr, x, y, s, s, s * 0.24);
        cairo_set_source_rgba(cr, 0, 0, 0, 0.45);
        cairo_fill(cr);
        hos_lock_badge(cr, x + s - 6, y + s - 6);
    }
    /* the domain it runs in: a ring of the domain's colour and its tag (not on the Trash, which is
     * the desktop's own, nor on plain files) */
    if ((ic->kind == K_APP || ic->kind == K_LAUNCHER) && a->appgate) {
        char pl[48];
        hos_placement_of(a->appgate, ic->exec, pl, sizeof pl);
        hos_domain_badge(cr, &a->badge_font, x, y, s, hos_domain_find(a->doms, a->ndoms, pl));
    }
}

/* ── layout ────────────────────────────────────────────────────────────────────────────── */
struct ibox { int x, y, w, h; };
static void cell_origin(int col, int row, int *x, int *y) { *x = GRID_X + col * CELL_W; *y = GRID_Y + row * CELL_H; }
/* The highlight box -- tile and label -- which is also the unit of hit-testing and of the
 * rubber band's "touches" test. */
static struct ibox icon_box(struct app *a, int i)
{
    const struct icon *ic = &a->icons[i];
    if (ic->col < 0) return (struct ibox){ 0, 0, 0, 0 };
    int cx, cy;
    cell_origin(ic->col, ic->row, &cx, &cy);
    int lines = ic->nlines > 0 ? ic->nlines : 1;
    return (struct ibox){ cx + 6, cy + 3, CELL_W - 12, TILE_Y - 3 + TILE + LABEL_GAP + lines * LINE_H + 4 };
}
static int icon_at(struct app *a, double x, double y)
{
    for (int i = 0; i < a->nicons; i++) {
        struct ibox b = icon_box(a, i);
        if (b.w && x >= b.x && x < b.x + b.w && y >= b.y && y < b.y + b.h) return i;
    }
    return -1;
}
static int cell_at(struct app *a, double x, double y, int *col, int *row)
{
    if (x < GRID_X || y < GRID_Y) return 0;
    *col = (int)((x - GRID_X) / CELL_W);
    *row = (int)((y - GRID_Y) / CELL_H);
    return *col < a->cols && *row < a->rows;
}
static int icon_in_cell(struct app *a, int col, int row, int except_selected)
{
    for (int i = 0; i < a->nicons; i++)
        if (a->icons[i].col == col && a->icons[i].row == row && !(except_selected && a->icons[i].sel)) return i;
    return -1;
}

/* Cells the user chose (placed = 1) are honoured first; every other icon takes the next free
 * cell, column-major, and then KEEPS it (placed = 2) so a file appearing on the desktop fills a
 * gap instead of shuffling everything after it.  "Arrange Icons" drops placed back to 0. */
static void layout_icons(struct app *a)
{
    if (a->width <= 0 || a->height <= 0) return;
    a->rows = imax(1, (a->height - GRID_Y - 8) / CELL_H);
    a->cols = imax(1, (a->width - GRID_X - 8) / CELL_W);
    int ncell = a->cols * a->rows;
    unsigned char *occ = calloc((size_t)ncell, 1);
    if (!occ) return;
    for (int i = 0; i < a->nicons; i++) {
        struct icon *ic = &a->icons[i];
        struct lines L;
        wrap_label(a, ic->name, LABEL_W, 2, &L);
        ic->nlines = L.n;
        if (ic->placed && ic->col >= 0 && ic->row >= 0 && ic->col < a->cols && ic->row < a->rows
            && !occ[ic->col * a->rows + ic->row])
            occ[ic->col * a->rows + ic->row] = 1;
        else ic->col = ic->row = -2;                        /* needs a cell */
    }
    int k = 0;
    for (int i = 0; i < a->nicons; i++) {
        struct icon *ic = &a->icons[i];
        if (ic->col != -2) continue;
        while (k < ncell && occ[k]) k++;
        if (k >= ncell) { ic->col = ic->row = -1; ic->placed = 0; continue; }
        occ[k] = 1;
        ic->col = k / a->rows;
        ic->row = k % a->rows;
        if (!ic->placed) ic->placed = 2;
    }
    free(occ);
}

/* ~/.config/wl-desktop/icons: "col row key" for every icon the user put somewhere. */
static void load_positions(struct app *a)
{
    char p[400];
    snprintf(p, sizeof p, "%s/icons", a->cfg_dir);
    FILE *f = fopen(p, "r");
    if (!f) return;
    char line[400];
    while (a->nsaved < MAX_ICONS && fgets(line, sizeof line, f)) {
        int c, r, n = 0;
        if (sscanf(line, "%d %d %n", &c, &r, &n) < 2 || n <= 0) continue;
        char *k = line + n;
        k[strcspn(k, "\r\n")] = 0;
        if (!*k || c < 0 || r < 0) continue;
        struct saved_pos *s = &a->saved[a->nsaved++];
        copy_str(s->key, sizeof s->key, k);
        s->col = c; s->row = r;
    }
    fclose(f);
}
static void save_positions(struct app *a)
{
    if (a->no_persist) return;
    if (mkdir_p(a->cfg_dir) != 0) return;
    char p[400], t[410];
    snprintf(p, sizeof p, "%s/icons", a->cfg_dir);
    snprintf(t, sizeof t, "%s.tmp", p);
    FILE *f = fopen(t, "w");
    if (!f) return;
    a->nsaved = 0;
    for (int i = 0; i < a->nicons; i++) {
        struct icon *ic = &a->icons[i];
        if (ic->placed != 1 || ic->col < 0) continue;
        fprintf(f, "%d %d %s\n", ic->col, ic->row, ic->key);
        struct saved_pos *s = &a->saved[a->nsaved++];
        copy_str(s->key, sizeof s->key, ic->key);
        s->col = ic->col; s->row = ic->row;
    }
    fclose(f);
    rename(t, p);
}
static void apply_saved(struct app *a, struct icon *ic)
{
    for (int k = 0; k < a->nsaved; k++)
        if (!strcmp(a->saved[k].key, ic->key)) { ic->col = a->saved[k].col; ic->row = a->saved[k].row; ic->placed = 1; return; }
}

/* ── the model: shortcuts + ~/Desktop ──────────────────────────────────────────────────── */
static void init_fixed(struct app *a)
{
    for (int i = 0; i < N_FIXED; i++) {
        struct icon *ic = &a->icons[i];
        memset(ic, 0, sizeof *ic);
        copy_str(ic->key, sizeof ic->key, FIXED[i].key);
        copy_str(ic->name, sizeof ic->name, FIXED[i].label);
        copy_str(ic->exec, sizeof ic->exec, FIXED[i].exec);
        copy_str(ic->image, sizeof ic->image, FIXED[i].image);
        copy_str(ic->path, sizeof ic->path, FIXED[i].kind == K_TRASH ? a->trash_files
                                           : FIXED[i].glyph == G_HOME ? a->home : FIXED[i].exec);
        ic->kind = FIXED[i].kind;
        ic->glyph = FIXED[i].glyph;
        ic->fixed = 1;
        ic->allowed = 1;
        ic->col = ic->row = -1;
        apply_saved(a, ic);
    }
    a->nicons = N_FIXED;
}

static int has_ext(const char *name, const char *const *exts)
{
    const char *dot = strrchr(name, '.');
    if (!dot || dot == name) return 0;
    for (; *exts; exts++) if (!strcasecmp(dot + 1, *exts)) return 1;
    return 0;
}
/* Text if the first 512 bytes hold no NUL and hardly any control characters. */
static int sniff_text(const char *path, long long size)
{
    if (size == 0) return 1;
    if (size > 8LL * 1024 * 1024) return 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    unsigned char b[512];
    ssize_t n = read(fd, b, sizeof b);
    close(fd);
    if (n <= 0) return n == 0;
    int bad = 0;
    for (ssize_t i = 0; i < n; i++) {
        if (!b[i]) return 0;
        if (b[i] < 0x20 && b[i] != '\n' && b[i] != '\r' && b[i] != '\t' && b[i] != '\f') bad++;
    }
    return bad * 20 < n;
}
/* Name=, Exec= (field codes like %U dropped) and Icon= of a .desktop launcher on the desktop. */
static int parse_launcher(const char *path, char *name, size_t ncap, char *exec, size_t ecap, char *iconn, size_t icap)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    name[0] = exec[0] = iconn[0] = 0;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strncmp(line, "Name=", 5) && !name[0]) copy_str(name, ncap, line + 5);
        else if (!strncmp(line, "Icon=", 5) && !iconn[0]) copy_str(iconn, icap, line + 5);
        else if (!strncmp(line, "Exec=", 5) && !exec[0]) {
            size_t o = 0;
            for (char *t = strtok(line + 5, " "); t; t = strtok(NULL, " ")) {
                if (t[0] == '%') continue;
                o += (size_t)snprintf(exec + o, o < ecap ? ecap - o : 0, "%s%s", o ? " " : "", t);
                if (o >= ecap) { exec[ecap - 1] = 0; break; }
            }
        }
    }
    fclose(f);
    return exec[0] != 0;
}

static void classify(struct icon *ic)
{
    static const char *const img_ext[] = { "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "ico", NULL };
    static const char *const txt_ext[] = { "txt", "md", "c", "h", "cc", "cpp", "hpp", "d", "rs", "go", "py",
        "sh", "lua", "js", "ts", "json", "xml", "html", "htm", "css", "conf", "cfg", "ini", "log", "yaml",
        "yml", "toml", "csv", "mk", "cmake", "patch", "diff", "rst", "tex", "desktop", NULL };
    ic->ext[0] = 0;
    ic->allowed = 1;
    if (ic->is_dir) { ic->kind = K_DIR; ic->glyph = G_FOLDER; copy_str(ic->name, sizeof ic->name, ic->fname); return; }
    copy_str(ic->name, sizeof ic->name, ic->fname);
    size_t l = strlen(ic->fname);
    if (l > 8 && !strcasecmp(ic->fname + l - 8, ".desktop")) {
        char nm[256], ex[256], in[64];
        if (parse_launcher(ic->path, nm, sizeof nm, ex, sizeof ex, in, sizeof in)) {
            ic->kind = K_LAUNCHER;
            if (nm[0]) copy_str(ic->name, sizeof ic->name, nm);
            copy_str(ic->exec, sizeof ic->exec, ex);
            ic->glyph = !strcmp(in, "terminal") ? G_TERMINAL : !strcmp(in, "package") ? G_SOFTWARE
                      : !strcmp(in, "security") ? G_DOMAINS : !strcmp(in, "folder") ? G_FOLDER : G_LAUNCHER;
            return;
        }
    }
    const char *dot = strrchr(ic->fname, '.');
    if (dot && dot != ic->fname && strlen(dot + 1) <= 4) {
        int k = 0;
        for (const char *p = dot + 1; *p && k < 4; p++) ic->ext[k++] = (char)toupper((unsigned char)*p);
        ic->ext[k] = 0;
    }
    if (has_ext(ic->fname, img_ext)) { ic->kind = K_IMAGE; ic->glyph = G_IMAGE; }
    else if (has_ext(ic->fname, txt_ext) || (!(ic->mode & 0111) && sniff_text(ic->path, ic->size))) {
        ic->kind = K_TEXT; ic->glyph = G_TEXT;
    } else { ic->kind = K_FILE; ic->glyph = G_FILE; }
}

static int dir_has_entries(const char *path)
{
    DIR *d = opendir(path);
    if (!d) return 0;
    struct dirent *e;
    int any = 0;
    while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) { any = 1; break; }
    closedir(d);
    return any;
}

struct dinfo { char name[256]; int is_dir; long long size; time_t mtime; mode_t mode; };
static int cmp_dinfo(const void *x, const void *y)
{
    const struct dinfo *p = x, *q = y;
    if (p->is_dir != q->is_dir) return q->is_dir - p->is_dir;       /* folders first */
    int c = strcasecmp(p->name, q->name);
    return c ? c : strcmp(p->name, q->name);
}

/* Re-read ~/Desktop.  Returns 1 when the icon set changed (and relayouts); selection, cells and
 * the rename in progress follow each entry by file name. */
static int scan_desktop(struct app *a, int force)
{
    static struct dinfo ents[MAX_ICONS];
    static struct icon old[MAX_ICONS];
    int n = 0;
    DIR *d = opendir(a->desk_dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) && n < MAX_ICONS - N_FIXED) {
            if (e->d_name[0] == '.') continue;              /* hidden files, "." and ".." */
            char p[600];
            snprintf(p, sizeof p, "%s/%s", a->desk_dir, e->d_name);
            struct stat st;
            if (stat(p, &st) != 0) continue;
            struct dinfo *di = &ents[n++];
            copy_str(di->name, sizeof di->name, e->d_name);
            di->is_dir = S_ISDIR(st.st_mode);
            di->size = (long long)st.st_size;
            di->mtime = st.st_mtime;
            di->mode = st.st_mode;
        }
        closedir(d);
    }
    if (n > 1) qsort(ents, (size_t)n, sizeof ents[0], cmp_dinfo);

    int tf = dir_has_entries(a->trash_files);
    int changed = force || tf != a->trash_full || n != a->nicons - N_FIXED;
    a->trash_full = tf;
    for (int i = 0; !changed && i < n; i++) {
        const struct icon *ic = &a->icons[N_FIXED + i];
        if (strcmp(ic->fname, ents[i].name) || ic->is_dir != ents[i].is_dir || ic->size != ents[i].size
            || ic->mtime != ents[i].mtime)
            changed = 1;
    }
    if (!changed) return 0;

    int nold = a->nicons - N_FIXED;
    memcpy(old, &a->icons[N_FIXED], sizeof old[0] * (size_t)nold);
    char edit_name[256] = "";
    if (a->edit_idx >= N_FIXED) copy_str(edit_name, sizeof edit_name, a->icons[a->edit_idx].fname);
    char hover_name[256] = "", cursor_name[256] = "";
    if (a->hover >= N_FIXED && a->hover < a->nicons) copy_str(hover_name, sizeof hover_name, a->icons[a->hover].fname);
    if (a->cursor >= N_FIXED && a->cursor < a->nicons) copy_str(cursor_name, sizeof cursor_name, a->icons[a->cursor].fname);
    if (a->edit_idx >= N_FIXED) a->edit_idx = -1;
    if (a->hover >= N_FIXED) a->hover = -1;
    if (a->cursor >= N_FIXED) a->cursor = -1;

    for (int i = 0; i < n; i++) {
        struct icon *ic = &a->icons[N_FIXED + i];
        const struct icon *prev = NULL;
        for (int k = 0; k < nold; k++) if (!strcmp(old[k].fname, ents[i].name)) { prev = &old[k]; break; }
        memset(ic, 0, sizeof *ic);
        copy_str(ic->fname, sizeof ic->fname, ents[i].name);
        snprintf(ic->key, sizeof ic->key, "d:%s", ents[i].name);
        snprintf(ic->path, sizeof ic->path, "%s/%s", a->desk_dir, ents[i].name);
        ic->is_dir = ents[i].is_dir;
        ic->size = ents[i].size;
        ic->mtime = ents[i].mtime;
        ic->mode = ents[i].mode;
        ic->col = ic->row = -1;
        if (prev && prev->size == ic->size && prev->mtime == ic->mtime && prev->is_dir == ic->is_dir) {
            /* unchanged: keep the classification instead of re-sniffing the file */
            ic->kind = prev->kind; ic->glyph = prev->glyph; ic->allowed = prev->allowed;
            copy_str(ic->name, sizeof ic->name, prev->name);
            copy_str(ic->exec, sizeof ic->exec, prev->exec);
            copy_str(ic->ext, sizeof ic->ext, prev->ext);
        } else classify(ic);
        if (prev) { ic->sel = prev->sel; ic->col = prev->col; ic->row = prev->row; ic->placed = prev->placed; }
        else apply_saved(a, ic);
        int idx = N_FIXED + i;
        if (edit_name[0] && !strcmp(edit_name, ic->fname)) a->edit_idx = idx;
        if (hover_name[0] && !strcmp(hover_name, ic->fname)) a->hover = idx;
        if (cursor_name[0] && !strcmp(cursor_name, ic->fname)) a->cursor = idx;
    }
    a->nicons = N_FIXED + n;
    layout_icons(a);
    return 1;
}

/* ── appgate: what the desktop may launch, and the session domain's name ────────────────── */
static int json_str(const char *from, const char *key, char *out, size_t cap)
{
    char pat[40];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *k = strstr(from, pat);
    if (!k) return 0;
    k += strlen(pat);
    while (*k == ' ' || *k == ':' || *k == '\t') k++;
    if (*k != '"') return 0;                                /* null / a number: not a string */
    const char *e = strchr(k + 1, '"');
    if (!e) return 0;
    size_t n = (size_t)(e - k - 1);
    if (n >= cap) n = cap - 1;
    memcpy(out, k + 1, n);
    out[n] = 0;
    return 1;
}
static void read_appgate(struct app *a)
{
    FILE *f = hos_fopen_root("/config/appgate.json", "r");
    if (!f) return;
    static char buf[16384];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char sess[48];
    if (json_str(buf, "session", sess, sizeof sess)) copy_str(a->session, sizeof a->session, sess);
    free(a->appgate); a->appgate = strdup(buf);
    free(a->doms); a->ndoms = hos_domains_load(&a->doms);
    char *k = strstr(buf, "\"desktop\"");
    char *br = k ? strchr(k, '[') : NULL;
    char *be = br ? strchr(br, ']') : NULL;
    if (!br || !be) return;
    *be = 0;
    free(a->desk_list);
    a->desk_list = strdup(br + 1);
    int changed = 0;
    for (int i = 0; i < N_FIXED; i++) {
        struct icon *ic = &a->icons[i];
        char q[64];
        snprintf(q, sizeof q, "\"%s\"", ic->image);
        int ok = !a->desk_list || strstr(a->desk_list, q) != NULL;
        if (ok != ic->allowed) { ic->allowed = ok; changed = 1; }
    }
    if (changed) request_redraw(a);
}

/* ── launching (the wl-layer-bar / wl-overview mechanism) ─────────────────────────────── */
static void launch_argv(struct app *a, char *const argv[], const char *label)
{
    if (a->offscreen) return;
    pid_t pid = fork();
    if (pid < 0) { notice(a, 1, "Could not start %s: %s", label, strerror(errno)); return; }
    if (pid == 0) {
        setsid();
        /* a fresh client must not inherit our Wayland connection fd or socket env */
        unsetenv("WAYLAND_SOCKET");
        for (int fd = 3; fd < 128; fd++) close(fd);
        execve(argv[0], argv, environ);
        /* appgate refuses with EACCES; tell the parent which failure it was through the status */
        _exit((errno == EACCES || errno == EPERM) ? 126 : 127);
    }
    logf_("launch %s%s%s (%s) pid %d", argv[0], argv[1] ? " " : "", argv[1] ? argv[1] : "", label, (int)pid);
    for (int i = 0; i < MAX_LAUNCH; i++) {
        struct launch *l = &a->launches[i];
        if (l->pid > 0) continue;
        l->pid = pid;
        l->t0 = now_ms();
        copy_str(l->label, sizeof l->label, label);
        copy_str(l->prog, sizeof l->prog, argv[0]);
        break;
    }
}
static void launch2(struct app *a, const char *prog, const char *arg, const char *label)
{
    char *argv[3] = { (char *)prog, (char *)arg, NULL };
    launch_argv(a, argv, label);
}
/* A .desktop Exec= line: split on spaces, as the app grid does ("/wl-sysmon --view=cpu"). */
static void launch_cmdline(struct app *a, const char *cmd, const char *label)
{
    char buf[512];
    copy_str(buf, sizeof buf, cmd);
    char *argv[16];
    int n = 0;
    for (char *t = strtok(buf, " "); t && n < 15; t = strtok(NULL, " ")) argv[n++] = t;
    argv[n] = NULL;
    if (!n) return;
    if (argv[0][0] != '/') { notice(a, 1, "%s: \"%s\" is not an absolute program path", label, argv[0]); return; }
    launch_argv(a, argv, label);
}
/* Reap children; a launch that died at once with 126/127 never ran -- say why. */
static void reap_children(struct app *a)
{
    for (;;) {
        int st = 0;
        pid_t pid = waitpid(-1, &st, WNOHANG);
        if (pid <= 0) break;
        for (int i = 0; i < MAX_LAUNCH; i++) {
            struct launch *l = &a->launches[i];
            if (l->pid != pid) continue;
            int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
            if (code == 126)
                notice(a, 1, "%s is not delegated to %s - use Domains to delegate it", l->label,
                       a->session[0] ? a->session : "this domain");
            else if (code == 127)
                notice(a, 1, "Could not start %s: %s is missing", l->label, l->prog);
            l->pid = 0;
        }
    }
    long long now = now_ms();
    for (int i = 0; i < MAX_LAUNCH; i++)                    /* it ran: stop watching (still reaped above) */
        if (a->launches[i].pid > 0 && now - a->launches[i].t0 > 15000) a->launches[i].pid = 0;
}
static int launches_pending(struct app *a)
{
    for (int i = 0; i < MAX_LAUNCH; i++) if (a->launches[i].pid > 0) return 1;
    return 0;
}

static int is_png(const struct icon *ic) { return ic->kind == K_IMAGE && !strcasecmp(ic->ext, "PNG"); }

/* Open one icon with the program that handles it. */
static void open_icon(struct app *a, int i)
{
    struct icon *ic = &a->icons[i];
    switch (ic->kind) {
    case K_APP:
        /* Home hands the home folder to Files (see the report: wl-files does not read argv yet). */
        launch2(a, ic->exec, ic->glyph == G_HOME ? a->home : NULL, ic->name);
        break;
    case K_TRASH:
        mkdir_p(a->trash_files);
        launch2(a, "/wl-files", a->trash_files, "Files");
        break;
    case K_DIR: launch2(a, "/wl-files", ic->path, "Files"); break;
    case K_LAUNCHER: launch_cmdline(a, ic->exec, ic->name); break;
    case K_IMAGE:
        if (is_png(ic)) launch2(a, "/wl-imgview", ic->path, "Image Viewer");
        else notice(a, 1, "The Image Viewer opens PNG images only - \"%s\" is %s", ic->name, ic->ext);
        break;
    case K_TEXT: launch2(a, "/wl-editor", ic->path, "Text Editor"); break;
    default: notice(a, 1, "No application can open \"%s\"", ic->name); break;
    }
}

/* ── wallpaper ─────────────────────────────────────────────────────────────────────────── */
/* Decode a PNG into a freshly malloc'd BGRA buffer (libpng simplified API, exactly as wl-imgview
 * does).  Returns 0 on success and replaces img/iw/ih. */
static int load_image(struct app *a, const char *path)
{
    png_image image;
    memset(&image, 0, sizeof image);
    image.version = PNG_IMAGE_VERSION;
    if (!png_image_begin_read_from_file(&image, path)) return -1;
    image.format = PNG_FORMAT_BGRA;                          /* bytes B,G,R,A == uint32 0xAARRGGBB (LE) */
    size_t sz = PNG_IMAGE_SIZE(image);
    uint32_t *buf = malloc(sz);
    if (!buf) { png_image_free(&image); return -1; }
    if (!png_image_finish_read(&image, NULL, buf, 0, NULL)) { free(buf); png_image_free(&image); return -1; }
    free(a->img);
    a->img = buf;
    a->iw = (int)image.width;
    a->ih = (int)image.height;
    a->img_ground = buf[0] & 0xffffffu;                     /* the corner: letterbox in the image's own ground */
    copy_str(a->wp_path, sizeof a->wp_path, path);
    return 0;
}

/* Bilinear sample of the decoded image at floating (fx,fy), clamped to bounds. */
static uint32_t sample(const struct app *a, double fx, double fy)
{
    if (fx < 0) fx = 0;
    if (fy < 0) fy = 0;
    if (fx > a->iw - 1) fx = a->iw - 1;
    if (fy > a->ih - 1) fy = a->ih - 1;
    int x0 = (int)fx, y0 = (int)fy;
    int x1 = x0 + 1 < a->iw ? x0 + 1 : x0;
    int y1 = y0 + 1 < a->ih ? y0 + 1 : y0;
    double tx = fx - x0, ty = fy - y0;
    const uint32_t *im = a->img;
    const uint32_t cs[4] = { im[y0 * a->iw + x0], im[y0 * a->iw + x1], im[y1 * a->iw + x0], im[y1 * a->iw + x1] };
    const double ws[4] = { (1 - tx) * (1 - ty), tx * (1 - ty), (1 - tx) * ty, tx * ty };
    double r = 0, g = 0, b = 0;
    for (int i = 0; i < 4; i++) {
        r += ((cs[i] >> 16) & 0xff) * ws[i];
        g += ((cs[i] >> 8) & 0xff) * ws[i];
        b += (cs[i] & 0xff) * ws[i];
    }
    return 0xff000000u | ((uint32_t)(r + 0.5) << 16) | ((uint32_t)(g + 0.5) << 8) | (uint32_t)(b + 0.5);
}

/* The wallpaper at the output's size: the image scaled to "contain" the output and centred, the
 * rest filled with its ground so the letterbox is invisible -- or the solid colour. */
static void build_bg(struct app *a)
{
    if (a->width <= 0 || a->height <= 0) return;
    size_t n = (size_t)a->width * (size_t)a->height;
    if (a->bg_w != a->width || a->bg_h != a->height || !a->bg) {
        free(a->bg);
        a->bg = malloc(n * 4);
        a->bg_w = a->width; a->bg_h = a->height;
    }
    if (!a->bg) { log_line("oom: no wallpaper cache"); a->bg_w = a->bg_h = 0; return; }
    uint32_t *px = a->bg;
    if (!a->img) {
        uint32_t c = 0xff000000u | a->wp_color;
        for (size_t i = 0; i < n; i++) px[i] = c;
        return;
    }
    uint32_t ground = 0xff000000u | a->img_ground;
    double s = (double)a->width / a->iw, sy = (double)a->height / a->ih;
    if (sy < s) s = sy;
    double placedW = a->iw * s, placedH = a->ih * s;
    double ox = (a->width - placedW) / 2.0, oy = (a->height - placedH) / 2.0;
    for (int y = 0; y < a->height; y++) {
        uint32_t *row = px + (size_t)y * a->width;
        double srcy = (y - oy) / s;
        int inRowY = (y >= (int)oy && y < (int)(oy + placedH));
        for (int x = 0; x < a->width; x++) {
            if (inRowY && x >= (int)ox && x < (int)(ox + placedW)) row[x] = sample(a, (x - ox) / s, srcy);
            else row[x] = ground;
        }
    }
}

static void add_wp(struct app *a, const char *label, const char *path, uint32_t color)
{
    if (a->nwp >= WP_MAX) return;
    for (int i = 0; i < a->nwp; i++) if (path && path[0] && !strcmp(base_name(a->wp[i].path), base_name(path))) return;
    struct wpchoice *w = &a->wp[a->nwp++];
    copy_str(w->label, sizeof w->label, label);
    copy_str(w->path, sizeof w->path, path);
    w->color = color;
}
/* The choices "Change Wallpaper..." offers: every PNG in the usual wallpaper places, then colours. */
static void collect_wallpapers(struct app *a)
{
    a->nwp = 0;
    char dirs[4][360];
    snprintf(dirs[0], sizeof dirs[0], "%s/.config/hypr/wallpapers", a->home);
    snprintf(dirs[1], sizeof dirs[1], "/usr/share/backgrounds");
    snprintf(dirs[2], sizeof dirs[2], "%s/Pictures", a->home);
    snprintf(dirs[3], sizeof dirs[3], "%s", a->desk_dir);
    for (int k = 0; k < 4; k++) {
        DIR *d = opendir(dirs[k]);
        if (!d) continue;
        struct dirent *e;
        while ((e = readdir(d)) && a->nwp < WP_MAX - 4) {
            size_t l = strlen(e->d_name);
            if (e->d_name[0] == '.' || l < 5 || strcasecmp(e->d_name + l - 4, ".png")) continue;
            char path[400], label[64];
            snprintf(path, sizeof path, "%s/%s", dirs[k], e->d_name);
            snprintf(label, sizeof label, "%.*s", (int)(l - 4 < 60 ? l - 4 : 60), e->d_name);
            for (char *p = label; *p; p++) if (*p == '-' || *p == '_') *p = ' ';
            label[0] = (char)toupper((unsigned char)label[0]);
            add_wp(a, label, path, 0);
        }
        closedir(d);
    }
    if (a->wp_path[0]) add_wp(a, base_name(a->wp_path), a->wp_path, 0);   /* the boot-module fallback */
    add_wp(a, "Solid: Midnight", "", COL_BG);
    add_wp(a, "Solid: Deep Teal", "", 0x0b3b3au);
    add_wp(a, "Solid: Graphite", "", 0x2b2f36u);
    add_wp(a, "Solid: Slate Blue", "", 0x1f2a44u);
}
static void save_wallpaper_choice(struct app *a)
{
    if (a->no_persist || mkdir_p(a->cfg_dir) != 0) return;
    char p[400];
    snprintf(p, sizeof p, "%s/wallpaper", a->cfg_dir);
    FILE *f = fopen(p, "w");
    if (!f) return;
    if (a->img && a->wp_path[0]) fprintf(f, "%s\n", a->wp_path);
    else fprintf(f, "#%06x\n", a->wp_color & 0xffffffu);
    fclose(f);
}
static int load_wallpaper_choice(struct app *a)
{
    char p[400], line[420];
    snprintf(p, sizeof p, "%s/wallpaper", a->cfg_dir);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    int ok = 0;
    if (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#') { a->wp_color = (uint32_t)strtoul(line + 1, NULL, 16) & 0xffffffu; ok = 1; }
        else if (line[0] == '/') ok = load_image(a, line) == 0;
    }
    fclose(f);
    return ok;
}
static void set_wallpaper(struct app *a, const char *path, uint32_t color)
{
    if (path && path[0]) {
        if (load_image(a, path) != 0) { notice(a, 1, "Could not load \"%s\" as a PNG image", base_name(path)); return; }
    } else {
        free(a->img);
        a->img = NULL;
        a->wp_path[0] = 0;
        a->wp_color = color;
    }
    build_bg(a);
    save_wallpaper_choice(a);
    a->full_damage = 1;
    request_redraw(a);
}

/* ── file operations ───────────────────────────────────────────────────────────────────── */
/* "name", then "name (2).ext", "name (3).ext", ... -- the first that does not exist in dir. */
static void unique_name(const char *dir, const char *name, int is_dir, char *out, size_t cap)
{
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    if (access(p, F_OK) != 0) { copy_str(out, cap, name); return; }
    const char *dot = is_dir ? NULL : strrchr(name, '.');
    if (dot == name) dot = NULL;
    int stem = dot ? (int)(dot - name) : (int)strlen(name);
    for (int k = 2; k < 10000; k++) {
        snprintf(out, cap, "%.*s (%d)%s", stem, name, k, dot ? dot : "");
        snprintf(p, sizeof p, "%s/%s", dir, out);
        if (access(p, F_OK) != 0) return;
    }
}
static void url_escape(const char *s, char *out, size_t cap)
{
    size_t o = 0;
    for (; *s && o + 4 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if (isalnum(c) || strchr("/-._~", c)) out[o++] = (char)c;
        else o += (size_t)snprintf(out + o, cap - o, "%%%02X", c);
    }
    out[o] = 0;
}
/* The freedesktop.org Trash: the item moves into Trash/files, and Trash/info records where it came
 * from, so Files (or any trash-aware tool) can put it back. */
static int trash_one(struct app *a, const struct icon *ic)
{
    if (mkdir_p(a->trash_files) != 0 || mkdir_p(a->trash_info) != 0) return -1;
    char nm[300], dst[700];
    unique_name(a->trash_files, ic->fname, ic->is_dir, nm, sizeof nm);
    snprintf(dst, sizeof dst, "%s/%s", a->trash_files, nm);
    if (rename(ic->path, dst) != 0) return -1;
    char info[700], esc[1600], when[40];
    snprintf(info, sizeof info, "%s/%s.trashinfo", a->trash_info, nm);
    url_escape(ic->path, esc, sizeof esc);
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%S", &tm);
    FILE *f = fopen(info, "w");
    if (f) { fprintf(f, "[Trash Info]\nPath=%s\nDeletionDate=%s\n", esc, when); fclose(f); }
    return 0;
}
static void trash_selected(struct app *a)
{
    int moved = 0, failed = 0, skipped = 0;
    char first_err[120] = "";
    for (int i = 0; i < a->nicons; i++) {
        struct icon *ic = &a->icons[i];
        if (!ic->sel) continue;
        if (ic->fixed) { skipped++; continue; }
        if (trash_one(a, ic) == 0) moved++;
        else { failed++; if (!first_err[0]) snprintf(first_err, sizeof first_err, "%s", strerror(errno)); }
    }
    if (failed) notice(a, 1, "Could not move %d item%s to the Trash: %s", failed, failed == 1 ? "" : "s", first_err);
    else if (moved) notice(a, 0, "Moved %d item%s to the Trash", moved, moved == 1 ? "" : "s");
    else if (skipped) notice(a, 1, "Shortcuts cannot be moved to the Trash");
    scan_desktop(a, 1);
    request_redraw(a);
}
/* Delete a tree.  Names are collected before anything is removed, so removal never races the
 * directory walk. */
static int rm_rf(const char *path, int depth)
{
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) return unlink(path);
    if (depth > 48) return -1;
    for (int round = 0; round < 64; round++) {
        DIR *d = opendir(path);
        if (!d) break;
        char (*names)[256] = malloc(128 * sizeof *names);
        if (!names) { closedir(d); return -1; }
        int n = 0;
        struct dirent *e;
        while (n < 128 && (e = readdir(d)))
            if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) copy_str(names[n++], sizeof names[0], e->d_name);
        closedir(d);
        int gone = 0;
        for (int i = 0; i < n; i++) {
            char p[1024];
            snprintf(p, sizeof p, "%s/%s", path, names[i]);
            if (rm_rf(p, depth + 1) == 0) gone++;
        }
        free(names);
        if (!n || !gone) break;
    }
    return depth ? rmdir(path) : 0;
}
static void empty_trash(struct app *a)
{
    rm_rf(a->trash_files, 0);
    rm_rf(a->trash_info, 0);
    int left = dir_has_entries(a->trash_files);
    notice(a, left, left ? "Some items could not be deleted from the Trash" : "The Trash is empty");
    scan_desktop(a, 1);
    request_redraw(a);
}
/* Drag onto a desktop folder: move the selected desktop items into it. */
static void move_selected_into(struct app *a, int target)
{
    struct icon *dst = &a->icons[target];
    int moved = 0, failed = 0;
    for (int i = 0; i < a->nicons; i++) {
        struct icon *ic = &a->icons[i];
        if (!ic->sel || ic->fixed || i == target) continue;
        char nm[300], p[900];
        unique_name(dst->path, ic->fname, ic->is_dir, nm, sizeof nm);
        snprintf(p, sizeof p, "%s/%s", dst->path, nm);
        if (rename(ic->path, p) == 0) moved++;
        else failed++;
    }
    if (failed) notice(a, 1, "Could not move %d item%s into \"%s\"", failed, failed == 1 ? "" : "s", dst->name);
    else if (moved) notice(a, 0, "Moved %d item%s into \"%s\"", moved, moved == 1 ? "" : "s", dst->name);
    scan_desktop(a, 1);
}

static int nsel(struct app *a)
{
    int n = 0;
    for (int i = 0; i < a->nicons; i++) n += a->icons[i].sel != 0;
    return n;
}
static int first_sel(struct app *a)
{
    for (int i = 0; i < a->nicons; i++) if (a->icons[i].sel) return i;
    return -1;
}
static void clear_sel(struct app *a) { for (int i = 0; i < a->nicons; i++) a->icons[i].sel = 0; }

static void edit_begin(struct app *a, int idx)
{
    if (idx < 0 || a->icons[idx].fixed) return;
    a->edit_idx = idx;
    copy_str(a->edit, sizeof a->edit, a->icons[idx].fname);
    request_redraw(a);
    /* The typing must reach the desktop: after "Rename..." / "New Folder" from a menu the grab has
     * just ended and Hyprland may have handed the keyboard to a window under the pointer. */
    set_kbi(a, 1);
    focus_pulse(a);
}
static void edit_cancel(struct app *a) { if (a->edit_idx >= 0) { a->edit_idx = -1; request_redraw(a); } }
static void edit_commit(struct app *a)
{
    if (a->edit_idx < 0) return;
    struct icon *ic = &a->icons[a->edit_idx];
    a->edit_idx = -1;
    char nm[256];
    const char *s = a->edit;
    while (*s == ' ') s++;
    copy_str(nm, sizeof nm, s);
    for (size_t l = strlen(nm); l && nm[l - 1] == ' ';) nm[--l] = 0;
    request_redraw(a);
    if (!nm[0] || !strcmp(nm, ic->fname)) return;
    if (strchr(nm, '/') || !strcmp(nm, ".") || !strcmp(nm, "..")) { notice(a, 1, "A name cannot contain \"/\""); return; }
    char dst[600];
    snprintf(dst, sizeof dst, "%s/%s", a->desk_dir, nm);
    if (access(dst, F_OK) == 0) { notice(a, 1, "\"%s\" already exists on the desktop", nm); return; }
    if (rename(ic->path, dst) != 0) { notice(a, 1, "Could not rename \"%s\": %s", ic->fname, strerror(errno)); return; }
    /* Keep it where it was: the rescan matches entries by file name, so rename the record too. */
    copy_str(ic->fname, sizeof ic->fname, nm);
    snprintf(ic->key, sizeof ic->key, "d:%s", nm);
    copy_str(ic->path, sizeof ic->path, dst);
    ic->mtime = 0;              /* a rename keeps the mtime: force a fresh label + classification */
    if (ic->placed == 1) save_positions(a);
    scan_desktop(a, 1);
}

static void new_folder(struct app *a)
{
    if (mkdir_p(a->desk_dir) != 0) { notice(a, 1, "Could not create %s: %s", a->desk_dir, strerror(errno)); return; }
    char nm[64], p[400];
    for (int k = 1; k < 1000; k++) {
        if (k == 1) snprintf(nm, sizeof nm, "New Folder");
        else snprintf(nm, sizeof nm, "New Folder %d", k);
        snprintf(p, sizeof p, "%s/%s", a->desk_dir, nm);
        if (access(p, F_OK) != 0) break;
    }
    if (mkdir(p, 0755) != 0) { notice(a, 1, "Could not create \"%s\": %s", nm, strerror(errno)); return; }
    scan_desktop(a, 1);
    for (int i = N_FIXED; i < a->nicons; i++) {
        struct icon *ic = &a->icons[i];
        if (strcmp(ic->fname, nm)) continue;
        int c, r;
        if (cell_at(a, a->menu_x, a->menu_y, &c, &r) && icon_in_cell(a, c, r, 0) < 0) {
            ic->col = c; ic->row = r; ic->placed = 1;        /* where the menu was opened, like GNOME */
            layout_icons(a);
            save_positions(a);
        }
        clear_sel(a);
        ic->sel = 1;
        a->cursor = i;
        edit_begin(a, i);                                    /* name it right away */
        break;
    }
    request_redraw(a);
}

static void arrange_icons(struct app *a)
{
    for (int i = 0; i < a->nicons; i++) a->icons[i].placed = 0;
    layout_icons(a);
    save_positions(a);
    request_redraw(a);
}

/* ── clipboard (wl_data_device, as gl-term does it) ──────────────────────────────────────── */
static void clip_send(void *data, struct wl_data_source *src, const char *mime, int32_t fd)
{
    struct app *a = data; (void)src; (void)mime;
    if (a->clip_text) {
        const char *p = a->clip_text;
        size_t left = strlen(p);
        while (left) {
            ssize_t w = write(fd, p, left);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) break;
            p += w; left -= (size_t)w;
        }
    }
    close(fd);
}
static void clip_cancelled(void *data, struct wl_data_source *src)
{
    struct app *a = data;
    if (a->clip_src == src) a->clip_src = NULL;
    wl_data_source_destroy(src);
}
static void clip_target(void *d, struct wl_data_source *s, const char *m) { (void)d; (void)s; (void)m; }
static void clip_dnd_drop(void *d, struct wl_data_source *s) { (void)d; (void)s; }
static void clip_dnd_fin(void *d, struct wl_data_source *s) { (void)d; (void)s; }
static void clip_action(void *d, struct wl_data_source *s, uint32_t act) { (void)d; (void)s; (void)act; }
static const struct wl_data_source_listener clip_listener = {
    .target = clip_target, .send = clip_send, .cancelled = clip_cancelled,
    .dnd_drop_performed = clip_dnd_drop, .dnd_finished = clip_dnd_fin, .action = clip_action,
};
/* Offers from other clients are never read here: drop them so they do not pile up. */
static void ddev_offer(void *d, struct wl_data_device *dd, struct wl_data_offer *o) { (void)d; (void)dd; (void)o; }
static void ddev_enter(void *d, struct wl_data_device *dd, uint32_t s, struct wl_surface *sf, wl_fixed_t x,
                       wl_fixed_t y, struct wl_data_offer *o)
{ (void)d; (void)dd; (void)s; (void)sf; (void)x; (void)y; if (o) wl_data_offer_destroy(o); }
static void ddev_leave(void *d, struct wl_data_device *dd) { (void)d; (void)dd; }
static void ddev_motion(void *d, struct wl_data_device *dd, uint32_t t, wl_fixed_t x, wl_fixed_t y)
{ (void)d; (void)dd; (void)t; (void)x; (void)y; }
static void ddev_drop(void *d, struct wl_data_device *dd) { (void)d; (void)dd; }
static void ddev_selection(void *d, struct wl_data_device *dd, struct wl_data_offer *o)
{ (void)d; (void)dd; if (o) wl_data_offer_destroy(o); }
static const struct wl_data_device_listener ddev_listener = {
    .data_offer = ddev_offer, .enter = ddev_enter, .leave = ddev_leave, .motion = ddev_motion,
    .drop = ddev_drop, .selection = ddev_selection,
};
static void copy_paths(struct app *a)
{
    size_t cap = 256, len = 0;
    char *txt = malloc(cap);
    if (!txt) return;
    txt[0] = 0;
    int n = 0;
    for (int i = 0; i < a->nicons; i++) {
        if (!a->icons[i].sel) continue;
        const char *p = a->icons[i].path;
        size_t need = len + strlen(p) + 2;
        if (need > cap) {
            while (need > cap) cap *= 2;
            char *nt = realloc(txt, cap);
            if (!nt) { free(txt); return; }
            txt = nt;
        }
        len += (size_t)snprintf(txt + len, cap - len, "%s%s", n ? "\n" : "", p);
        n++;
    }
    if (!n) { free(txt); return; }
    if (a->offscreen || !a->ddm || !a->seat) { notice(a, 1, "No clipboard is available"); free(txt); return; }
    if (!a->ddev) {
        a->ddev = wl_data_device_manager_get_data_device(a->ddm, a->seat);
        wl_data_device_add_listener(a->ddev, &ddev_listener, a);
    }
    free(a->clip_text);
    a->clip_text = txt;
    if (a->clip_src) wl_data_source_destroy(a->clip_src);
    a->clip_src = wl_data_device_manager_create_data_source(a->ddm);
    wl_data_source_add_listener(a->clip_src, &clip_listener, a);
    wl_data_source_offer(a->clip_src, "text/plain;charset=utf-8");
    wl_data_source_offer(a->clip_src, "text/plain");
    wl_data_source_offer(a->clip_src, "UTF8_STRING");
    wl_data_device_set_selection(a->ddev, a->clip_src, a->serial);
    wl_display_flush(a->display);
    if (n == 1) notice(a, 0, "Copied %s", txt);
    else notice(a, 0, "Copied %d paths", n);
}

/* ── shm buffers ───────────────────────────────────────────────────────────────────────── */
static void render_main(struct app *a);
static void render_popup(struct app *a);
static void buf_release(void *data, struct wl_buffer *wl)
{
    struct shmbuf *b = data; (void)wl;
    struct app *a = b->a;
    b->busy = 0;
    /* a redraw that found both buffers with the compositor runs now */
    if (b->owner == 0) { if (a->dirty && !a->frame_pending) render_main(a); }
    else if (a->pop.dirty && !a->pop.frame_pending) render_popup(a);
}
static const struct wl_buffer_listener buf_listener = { .release = buf_release };

/* Two buffers in one memfd pool, reused frame after frame (the old one-buffer-per-frame scheme
 * was fine for a picture painted once, not for a rubber band). */
static int pool_create(struct app *a, struct pool *p, int w, int h, int owner, uint32_t fmt)
{
    memset(p, 0, sizeof *p);
    p->w = w; p->h = h; p->stride = w * 4;
    size_t one = (size_t)p->stride * (size_t)h;
    p->size = one * 2;
    int fd = (int)syscall(SYS_memfd_create, "hos-desktop", MFD_CLOEXEC);
    if (fd < 0) { log_line("memfd failed"); return -1; }
    if (ftruncate(fd, (off_t)p->size) != 0) { close(fd); log_line("ftruncate failed"); return -1; }
    void *m = mmap(NULL, p->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) { close(fd); log_line("mmap failed"); return -1; }
    struct wl_shm_pool *sp = wl_shm_create_pool(a->shm, fd, (int32_t)p->size);
    for (int i = 0; i < 2; i++) {
        struct shmbuf *b = &p->b[i];
        b->px = (uint32_t *)((char *)m + one * (size_t)i);
        b->wl = wl_shm_pool_create_buffer(sp, (int32_t)(one * (size_t)i), w, h, p->stride, fmt);
        b->owner = owner;
        b->a = a;
        wl_buffer_add_listener(b->wl, &buf_listener, b);
    }
    wl_shm_pool_destroy(sp);
    close(fd);
    p->map = m;
    return 0;
}
static void pool_destroy(struct pool *p)
{
    for (int i = 0; i < 2; i++) if (p->b[i].wl) wl_buffer_destroy(p->b[i].wl);
    if (p->map) munmap(p->map, p->size);
    memset(p, 0, sizeof *p);
}
static struct shmbuf *pool_acquire(struct pool *p)
{
    for (int i = 0; i < 2; i++) if (p->b[i].wl && !p->b[i].busy) return &p->b[i];
    return NULL;
}
static void canvas_begin(struct canvas *c, uint32_t *px, int w, int h, cairo_format_t fmt)
{
    c->px = px; c->w = w; c->h = h; c->stride = w * 4;
    c->cs = cairo_image_surface_create_for_data((unsigned char *)px, fmt, w, h, c->stride);
    c->cr = cairo_create(c->cs);
}
static void canvas_end(struct canvas *c)
{
    cairo_destroy(c->cr);
    cairo_surface_flush(c->cs);
    cairo_surface_destroy(c->cs);
    c->cr = NULL; c->cs = NULL;
}

/* ── drawing: the desktop ──────────────────────────────────────────────────────────────── */
static void draw_edit_box(struct app *a, int cx, int ly)
{
    int tw = text_width(a, F_REG, LABEL_PX, a->edit);
    int w = imin(imax(CELL_W + 16, tw + 16), 280);
    int x = cx + CELL_W / 2 - w / 2;
    if (x < 2) x = 2;
    rfill(a, x, ly - 2, w, LINE_H + 6, 4, 0xf4f7fau, 1);
    rstroke(a, x, ly - 2, w, LINE_H + 6, 4, C_ACCENT2, 1);
    int inner = w - 12;
    /* long names scroll so the caret end stays visible */
    const char *s = a->edit;
    while (*s && text_width(a, F_REG, LABEL_PX, s) > inner - 2) utf8_next(&s);
    int drawn = text_draw(a, F_REG, LABEL_PX, x + 6, ly + 1, inner, 0x101418u, 255, s);
    cairo_t *cr = a->cv->cr;
    set_rgb(cr, 0x101418u);
    cairo_rectangle(cr, x + 6 + drawn + 1, ly + 1, 1.2, LINE_H);
    cairo_fill(cr);
    mark(a, x - 2, ly - 4, w + 4, LINE_H + 10);
}

static void draw_icon(struct app *a, int i, int x, int y, double alpha)
{
    struct icon *ic = &a->icons[i];
    cairo_t *cr = a->cv->cr;
    int hovered = i == a->hover && !a->dragging && !a->band;
    int drop = i == a->drop_target;
    int editing = i == a->edit_idx;
    struct lines L;
    wrap_label(a, ic->name, LABEL_W, (ic->sel || editing) ? 4 : 2, &L);
    int boxh = TILE_Y - 3 + TILE + LABEL_GAP + L.n * LINE_H + 4;
    int bx = x + 6, by = y + 3, bw = CELL_W - 12;
    if (alpha >= 1 && (ic->sel || hovered || drop)) {
        if (ic->sel) { rfill(a, bx, by, bw, boxh, 7, C_ACCENT2, 0.24); rstroke(a, bx, by, bw, boxh, 7, C_ACCENT2, 0.85); }
        else if (drop) { rfill(a, bx, by, bw, boxh, 7, C_ACCENT2, 0.36); rstroke(a, bx, by, bw, boxh, 7, C_ACCENT2, 1); }
        else rfill(a, bx, by, bw, boxh, 7, C_WHITE, 0.10);
    }
    double tx = x + (CELL_W - TILE) / 2.0, ty = y + TILE_Y;
    if (alpha < 1) {
        cairo_push_group(cr);
        draw_icon_art(a, ic, tx, ty, TILE, 0);
        cairo_pop_group_to_source(cr);
        cairo_paint_with_alpha(cr, alpha);
    } else draw_icon_art(a, ic, tx, ty, TILE, 1);
    int ly = y + TILE_Y + TILE + LABEL_GAP;
    if (editing) draw_edit_box(a, x, ly);
    else if (ic->sel && alpha >= 1) {
        int mw = 0;
        for (int k = 0; k < L.n; k++) mw = imax(mw, L.w[k]);
        rfill(a, x + (CELL_W - mw) / 2 - 5, ly - 1, mw + 10, L.n * LINE_H + 3, 4, C_ACCENT, 0.95);
        for (int k = 0; k < L.n; k++)
            text_draw(a, F_REG, LABEL_PX, x + (CELL_W - L.w[k]) / 2, ly + k * LINE_H, LABEL_W + 4, C_WHITE, 255, L.s[k]);
    } else {
        unsigned int al = (unsigned int)(alpha * 255);
        for (int k = 0; k < L.n; k++)
            text_shadowed(a, LABEL_PX, x + (CELL_W - L.w[k]) / 2, ly + k * LINE_H, LABEL_W + 4, C_WHITE, al, L.s[k]);
    }
    mark(a, x, y, CELL_W, imax(boxh + 6, TILE_Y + TILE + LABEL_GAP + L.n * LINE_H + 8));
}

static void draw_band(struct app *a)
{
    int x0 = (int)fmin(a->press_x, a->ptr_x), y0 = (int)fmin(a->press_y, a->ptr_y);
    int x1 = (int)fmax(a->press_x, a->ptr_x), y1 = (int)fmax(a->press_y, a->ptr_y);
    cairo_t *cr = a->cv->cr;
    cairo_rectangle(cr, x0, y0, x1 - x0, y1 - y0);
    set_rgba(cr, C_ACCENT2, 0.20);
    cairo_fill(cr);
    cairo_rectangle(cr, x0 + 0.5, y0 + 0.5, imax(0, x1 - x0 - 1), imax(0, y1 - y0 - 1));
    set_rgba(cr, C_ACCENT2, 0.95);
    cairo_set_line_width(cr, 1);
    cairo_stroke(cr);
    mark(a, x0 - 1, y0 - 1, x1 - x0 + 2, y1 - y0 + 2);
}

static void draw_notice(struct app *a)
{
    int tw = text_width(a, F_REG, 13, a->notice);
    int w = imin(tw + 44, a->width - 40), h = 34;
    int x = (a->width - w) / 2, y = a->height - h - 28;
    rfill(a, x + 1, y + 3, w, h, 9, 0x000000, 0.35);
    rfill(a, x, y, w, h, 9, 0x131b21u, 0.95);
    rstroke(a, x, y, w, h, 9, a->notice_err ? C_RED : C_ACCENT2, 0.9);
    cairo_t *cr = a->cv->cr;
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + 17, y + h / 2.0, 4, 0, 2 * M_PI);
    set_rgb(cr, a->notice_err ? C_RED : C_ACCENT2);
    cairo_fill(cr);
    text_draw(a, F_REG, 13, x + 28, y + 8, w - 38, C_TEXT, 255, a->notice);
    mark(a, x - 2, y - 2, w + 6, h + 8);
}

static void draw_popup_content(struct app *a, int ox, int oy);

/* Everything over the wallpaper.  Unselected icons first, selected ones last so their expanded
 * labels lie on top of the neighbours below. */
static void draw_desktop(struct app *a)
{
    double ddx = a->ptr_x - a->press_x, ddy = a->ptr_y - a->press_y;
    for (int pass = 0; pass < 2; pass++)
        for (int i = 0; i < a->nicons; i++) {
            struct icon *ic = &a->icons[i];
            if (ic->col < 0 || (!!ic->sel) != pass) continue;
            int x, y;
            cell_origin(ic->col, ic->row, &x, &y);
            draw_icon(a, i, x, y, (a->dragging && ic->sel) ? 0.35 : 1.0);
        }
    if (a->dragging)
        for (int i = 0; i < a->nicons; i++) {
            struct icon *ic = &a->icons[i];
            if (ic->col < 0 || !ic->sel) continue;
            int x, y;
            cell_origin(ic->col, ic->row, &x, &y);
            draw_icon(a, i, x + (int)ddx, y + (int)ddy, 0.75);
        }
    if (a->band) draw_band(a);
    if (a->pop.kind && a->pop.inline_mode) {
        draw_popup_content(a, a->pop.x, a->pop.y);
        mark(a, a->pop.x - 2, a->pop.y - 2, a->pop.w + 4, a->pop.h + 4);
    }
    if (a->notice[0]) draw_notice(a);
}

static void compose_desktop(struct app *a, struct canvas *cv)
{
    size_t n = (size_t)cv->w * (size_t)cv->h;
    if (a->bg && a->bg_w == cv->w && a->bg_h == cv->h) memcpy(cv->px, a->bg, n * 4);
    else for (size_t i = 0; i < n; i++) cv->px[i] = 0xff000000u | COL_BG;
    cairo_surface_mark_dirty(cv->cs);
    a->cv = cv;
    a->marking = 1;
    a->dx0 = a->dy0 = a->dx1 = a->dy1 = 0;
    draw_desktop(a);
    a->marking = 0;
    a->cv = NULL;
}

/* ── frame pacing ──────────────────────────────────────────────────────────────────────── */
static void frame_done(void *data, struct wl_callback *cb, uint32_t t)
{
    struct app *a = data; (void)t;
    wl_callback_destroy(cb);
    if (cb == a->frame_cb) { a->frame_cb = NULL; a->frame_pending = 0; }
    if (a->dirty && !a->frame_pending) render_main(a);
}
static const struct wl_callback_listener frame_listener = { .done = frame_done };

static void render_main(struct app *a)
{
    if (a->offscreen || !a->configured || a->width <= 0 || a->height <= 0) return;
    if (!a->pool.b[0].wl || a->pool.w != a->width || a->pool.h != a->height) {
        pool_destroy(&a->pool);
        if (pool_create(a, &a->pool, a->width, a->height, 0, WL_SHM_FORMAT_XRGB8888) < 0) return;
        a->full_damage = 1;
    }
    struct shmbuf *b = pool_acquire(&a->pool);
    if (!b) { a->dirty = 1; return; }
    struct canvas cv;
    canvas_begin(&cv, b->px, a->width, a->height, CAIRO_FORMAT_RGB24);
    compose_desktop(a, &cv);
    canvas_end(&cv);
    b->busy = 1;
    a->dirty = 0;
    wl_surface_attach(a->surface, b->wl, 0, 0);
    /* Everything outside this frame's and the last frame's drawn boxes is untouched wallpaper in
     * both, so only their union needs re-uploading -- a rubber band does not re-send the screen. */
    if (a->full_damage) {
        wl_surface_damage_buffer(a->surface, 0, 0, a->width, a->height);
        a->full_damage = 0;
    } else {
        int x0 = a->dx0, y0 = a->dy0, x1 = a->dx1, y1 = a->dy1;
        if (a->px1 > a->px0) {
            if (x1 <= x0) { x0 = a->px0; y0 = a->py0; x1 = a->px1; y1 = a->py1; }
            else { x0 = imin(x0, a->px0); y0 = imin(y0, a->py0); x1 = imax(x1, a->px1); y1 = imax(y1, a->py1); }
        }
        x0 = imax(0, x0); y0 = imax(0, y0); x1 = imin(a->width, x1); y1 = imin(a->height, y1);
        if (x1 > x0 && y1 > y0) wl_surface_damage_buffer(a->surface, x0, y0, x1 - x0, y1 - y0);
        else wl_surface_damage_buffer(a->surface, 0, 0, 1, 1);
    }
    a->px0 = a->dx0; a->py0 = a->dy0; a->px1 = a->dx1; a->py1 = a->dy1;
    a->frame_cb = wl_surface_frame(a->surface);
    wl_callback_add_listener(a->frame_cb, &frame_listener, a);
    a->frame_pending = 1;
    a->frame_ms = now_ms();
    wl_surface_commit(a->surface);
    wl_display_flush(a->display);
}
static void request_redraw(struct app *a)
{
    a->dirty = 1;
    if (!a->frame_pending) render_main(a);
}

/* ── popups: content ───────────────────────────────────────────────────────────────────── */
static void menu_add(struct popup *p, const char *label, const char *accel, int action, int arg, int enabled)
{
    if (p->nitems >= (int)(sizeof p->items / sizeof p->items[0])) return;
    struct mitem *m = &p->items[p->nitems++];
    memset(m, 0, sizeof *m);
    copy_str(m->label, sizeof m->label, label);
    copy_str(m->accel, sizeof m->accel, accel);
    m->action = action; m->arg = arg; m->enabled = enabled;
}
static void menu_sep(struct popup *p)
{
    if (!p->nitems || p->items[p->nitems - 1].sep || p->nitems >= (int)(sizeof p->items / sizeof p->items[0])) return;
    struct mitem *m = &p->items[p->nitems++];
    memset(m, 0, sizeof *m);
    m->sep = 1;
}
static void menu_size(struct app *a)
{
    struct popup *p = &a->pop;
    int w = MENU_MIN_W, h = MENU_PAD * 2, checks = 0;
    for (int i = 0; i < p->nitems; i++) checks |= p->items[i].checked;
    for (int i = 0; i < p->nitems; i++) {
        const struct mitem *m = &p->items[i];
        if (m->sep) { h += SEP_H; continue; }
        h += ITEM_H;
        int need = 32 + (checks ? 16 : 0) + text_width(a, F_REG, MENU_PX, m->label)
                 + (m->accel[0] ? 28 + text_width(a, F_REG, 12, m->accel) : 0);
        w = imax(w, need);
    }
    p->w = imin(w, 420);
    p->h = h;
}
static void build_desktop_menu(struct app *a)
{
    struct popup *p = &a->pop;
    p->nitems = 0;
    menu_add(p, "Open Terminal", "", ACT_OPEN_TERMINAL, 0, 1);
    menu_add(p, "Open Files", "", ACT_OPEN_FILES, 0, 1);
    menu_sep(p);
    menu_add(p, "New Folder", "Ctrl+Shift+N", ACT_NEW_FOLDER, 0, 1);
    menu_sep(p);
    menu_add(p, "Arrange Icons", "", ACT_ARRANGE, 0, 1);
    menu_add(p, "Select All", "Ctrl+A", ACT_SELECT_ALL, 0, a->nicons > 0);
    menu_sep(p);
    menu_add(p, "Change Wallpaper...", "", ACT_WALLPAPER, 0, 1);
    /* No display-settings program ships (resolution comes from display.conf at build time). */
    menu_add(p, "Display Settings", "", ACT_DISPLAY, 0, 0);
    menu_size(a);
}
static void build_selection_menu(struct app *a)
{
    struct popup *p = &a->pop;
    p->nitems = 0;
    int n = 0, desk = 0, dirs = 0, trash = 0, png = -1;
    for (int i = 0; i < a->nicons; i++) {
        struct icon *ic = &a->icons[i];
        if (!ic->sel) continue;
        n++;
        if (!ic->fixed) desk++;
        if (ic->kind == K_DIR || ic->kind == K_TRASH || ic->glyph == G_HOME) dirs++;
        if (ic->kind == K_TRASH) trash = 1;
        if (is_png(ic)) png = i;
    }
    int one = first_sel(a);
    menu_add(p, "Open", "Enter", ACT_OPEN, 0, n > 0);
    if (dirs) menu_add(p, "Open With Files", "", ACT_OPEN_WITH_FILES, 0, 1);
    menu_sep(p);
    menu_add(p, "Rename...", "F2", ACT_RENAME, 0, n == 1 && one >= 0 && !a->icons[one].fixed);
    menu_add(p, "Move to Trash", "Delete", ACT_TRASH, 0, desk > 0);
    if (trash) menu_add(p, "Empty Trash...", "", ACT_EMPTY_TRASH, 0, a->trash_full);
    if (n == 1 && png >= 0) menu_add(p, "Set as Wallpaper", "", ACT_SET_WALLPAPER, png, 1);
    menu_sep(p);
    menu_add(p, "Copy Path", "Ctrl+C", ACT_COPY_PATH, 0, n > 0);
    menu_add(p, "Properties", "Alt+Enter", ACT_PROPERTIES, 0, n > 0);
    menu_size(a);
}
static void build_wallpaper_menu(struct app *a)
{
    struct popup *p = &a->pop;
    p->nitems = 0;
    collect_wallpapers(a);
    int any_img = 0;
    for (int i = 0; i < a->nwp; i++) {
        const struct wpchoice *w = &a->wp[i];
        if (!w->path[0] && any_img) { menu_sep(p); any_img = 0; }
        if (w->path[0]) any_img = 1;
        menu_add(p, w->label, "", ACT_PICK_WALLPAPER, i, 1);
        p->items[p->nitems - 1].checked = w->path[0] ? (a->img && !strcmp(w->path, a->wp_path))
                                                     : (!a->img && w->color == a->wp_color);
    }
    menu_size(a);
}
static const char *kind_name(const struct icon *ic)
{
    switch (ic->kind) {
    case K_APP: return "Application shortcut";
    case K_TRASH: return "Trash";
    case K_DIR: return "Folder";
    case K_LAUNCHER: return "Application launcher (.desktop)";
    case K_IMAGE: return "Image";
    case K_TEXT: return "Text document";
    default: return "File";
    }
}
static void prop_row(struct popup *p, const char *k, const char *v)
{
    if (p->nrows >= 8) return;
    copy_str(p->rows[p->nrows].k, sizeof p->rows[0].k, k);
    copy_str(p->rows[p->nrows].v, sizeof p->rows[0].v, v);
    p->nrows++;
}
static int count_entries(const char *path)
{
    DIR *d = opendir(path);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    closedir(d);
    return n;
}
static void popup_buttons(struct popup *p, const char *l1, int a1, int s1, const char *l2, int a2, int s2)
{
    p->nbtns = 0;
    int bw = 104, bh = 30, y = p->h - 44, x = p->w - 16;
    if (l2) {
        x -= bw;
        p->btns[p->nbtns++] = (struct pbtn){ x, y, bw, bh, a2, s2, "" };
        copy_str(p->btns[p->nbtns - 1].label, sizeof p->btns[0].label, l2);
        x -= 10;
    }
    x -= bw;
    p->btns[p->nbtns++] = (struct pbtn){ x, y, bw, bh, a1, s1, "" };
    copy_str(p->btns[p->nbtns - 1].label, sizeof p->btns[0].label, l1);
}
static void build_props(struct app *a)
{
    struct popup *p = &a->pop;
    p->nrows = 0;
    p->glyph_icon = -1;
    int n = nsel(a), idx = first_sel(a);
    char v[200];
    if (n == 1 && idx >= 0) {
        struct icon *ic = &a->icons[idx];
        p->glyph_icon = 1;
        p->glyph = *ic;
        copy_str(p->title, sizeof p->title, ic->name);
        copy_str(p->sub, sizeof p->sub, kind_name(ic));
        if (ic->kind == K_APP) {
            prop_row(p, "Command", ic->exec);
            prop_row(p, "Opens in", (!strcmp(ic->image, "wl-files") || !strcmp(ic->image, "hos-wifiterm"))
                                        ? (a->session[0] ? a->session : "the session domain") : "System");
            if (!ic->allowed) prop_row(p, "Status", "Not delegated to this desktop (see Domains)");
            if (ic->glyph == G_HOME) prop_row(p, "Folder", a->home);
        } else {
            if (ic->kind == K_TRASH) {
                int c = count_entries(a->trash_files);
                snprintf(v, sizeof v, "%d item%s", c < 0 ? 0 : c, c == 1 ? "" : "s");
                prop_row(p, "Contents", v);
                prop_row(p, "Location", a->trash_files);
            } else {
                if (ic->kind == K_DIR) {
                    int c = count_entries(ic->path);
                    snprintf(v, sizeof v, "%d item%s", c < 0 ? 0 : c, c == 1 ? "" : "s");
                    prop_row(p, "Contents", v);
                } else { fmt_bytes(ic->size, v, sizeof v); prop_row(p, "Size", v); }
                if (ic->kind == K_LAUNCHER) prop_row(p, "Command", ic->exec);
                if (strcmp(ic->name, ic->fname)) prop_row(p, "File name", ic->fname);
                prop_row(p, "Location", a->desk_dir);
                struct tm tm;
                localtime_r(&ic->mtime, &tm);
                strftime(v, sizeof v, "%a %d %b %Y  %H:%M", &tm);
                prop_row(p, "Modified", v);
                snprintf(v, sizeof v, "%c%c%c%c%c%c%c%c%c  (%03o)", ic->mode & 0400 ? 'r' : '-',
                         ic->mode & 0200 ? 'w' : '-', ic->mode & 0100 ? 'x' : '-', ic->mode & 040 ? 'r' : '-',
                         ic->mode & 020 ? 'w' : '-', ic->mode & 010 ? 'x' : '-', ic->mode & 04 ? 'r' : '-',
                         ic->mode & 02 ? 'w' : '-', ic->mode & 01 ? 'x' : '-', (unsigned)(ic->mode & 0777));
                prop_row(p, "Permissions", v);
            }
        }
    } else {
        int files = 0, dirs = 0, apps = 0;
        long long total = 0;
        for (int i = 0; i < a->nicons; i++) {
            struct icon *ic = &a->icons[i];
            if (!ic->sel) continue;
            if (ic->fixed) apps++;
            else if (ic->is_dir) dirs++;
            else { files++; total += ic->size; }
        }
        snprintf(p->title, sizeof p->title, "%d items selected", n);
        copy_str(p->sub, sizeof p->sub, "Multiple selection");
        snprintf(v, sizeof v, "%d", dirs);  prop_row(p, "Folders", v);
        snprintf(v, sizeof v, "%d", files); prop_row(p, "Files", v);
        if (apps) { snprintf(v, sizeof v, "%d", apps); prop_row(p, "Shortcuts", v); }
        fmt_bytes(total, v, sizeof v);
        prop_row(p, "Total size", v);
    }
    p->w = 400;
    p->h = 78 + p->nrows * 22 + 16 + 54;
    popup_buttons(p, "Close", ACT_CLOSE_POPUP, 1, NULL, 0, 0);
}
static void build_confirm_empty(struct app *a)
{
    struct popup *p = &a->pop;
    int c = count_entries(a->trash_files);
    copy_str(p->title, sizeof p->title, "Empty the Trash?");
    if (c == 1) copy_str(p->msg, sizeof p->msg, "The item in the Trash will be deleted permanently.");
    else snprintf(p->msg, sizeof p->msg, "All %d items in the Trash will be deleted permanently.", c < 0 ? 0 : c);
    p->w = 400;
    p->h = 140;
    popup_buttons(p, "Cancel", ACT_CLOSE_POPUP, 0, "Empty Trash", ACT_CONFIRM_EMPTY, 2);
}

/* ── popups: drawing ───────────────────────────────────────────────────────────────────── */
static int menu_item_y(struct popup *p, int idx)
{
    int y = MENU_PAD;
    for (int i = 0; i < idx; i++) y += p->items[i].sep ? SEP_H : ITEM_H;
    return y;
}
static int menu_item_at(struct popup *p, double ly)
{
    int y = MENU_PAD;
    for (int i = 0; i < p->nitems; i++) {
        int h = p->items[i].sep ? SEP_H : ITEM_H;
        if (ly >= y && ly < y + h) return (p->items[i].sep || !p->items[i].enabled) ? -1 : i;
        y += h;
    }
    return -1;
}
static int btn_at(struct popup *p, double lx, double ly)
{
    for (int i = 0; i < p->nbtns; i++) {
        const struct pbtn *b = &p->btns[i];
        if (lx >= b->x && lx < b->x + b->w && ly >= b->y && ly < b->y + b->h) return i;
    }
    return -1;
}
static void draw_buttons(struct app *a, int ox, int oy)
{
    struct popup *p = &a->pop;
    for (int i = 0; i < p->nbtns; i++) {
        const struct pbtn *b = &p->btns[i];
        int hov = i == p->btn_hover;
        uint32_t c = b->style == 2 ? (hov ? 0xe03131u : C_DANGER) : b->style == 1 ? (hov ? C_ACCENT2 : C_ACCENT)
                   : (hov ? 0x33414du : 0x26313bu);
        rfill(a, ox + b->x, oy + b->y, b->w, b->h, 6, c, 1);
        text_center(a, F_BOLD, 12, ox + b->x, oy + b->y + 7, b->w, C_WHITE, b->label);
    }
}
static void draw_popup_frame(struct app *a, int ox, int oy)
{
    struct popup *p = &a->pop;
    rfill(a, ox, oy, p->w, p->h, 9, C_MENU, 1);
    rstroke(a, ox, oy, p->w, p->h, 9, C_MENU_LINE, 1);
}
static void draw_menu(struct app *a, int ox, int oy)
{
    struct popup *p = &a->pop;
    cairo_t *cr = a->cv->cr;
    int checks = 0;
    for (int i = 0; i < p->nitems; i++) checks |= p->items[i].checked;
    draw_popup_frame(a, ox, oy);
    for (int i = 0; i < p->nitems; i++) {
        const struct mitem *m = &p->items[i];
        int y = oy + menu_item_y(p, i);
        if (m->sep) {
            cairo_rectangle(cr, ox + 10, y + SEP_H / 2, p->w - 20, 1);
            set_rgb(cr, C_MENU_LINE);
            cairo_fill(cr);
            continue;
        }
        int hov = i == p->hover && m->enabled;
        if (hov) rfill(a, ox + 5, y, p->w - 10, ITEM_H, 5, C_ACCENT, 1);
        int tx = ox + 16 + (checks ? 16 : 0);
        if (m->checked) {
            cairo_new_sub_path(cr);
            cairo_arc(cr, ox + 20, y + ITEM_H / 2.0, 3.5, 0, 2 * M_PI);
            set_rgb(cr, hov ? C_WHITE : C_ACCENT2);
            cairo_fill(cr);
        }
        uint32_t tc = !m->enabled ? C_FAINT : hov ? C_WHITE : C_TEXT;
        int aw = m->accel[0] ? text_width(a, F_REG, 12, m->accel) : 0;
        text_draw(a, F_REG, MENU_PX, tx, y + 6, p->w - (tx - ox) - (aw ? aw + 30 : 14), tc, 255, m->label);
        if (aw) text_draw(a, F_REG, 12, ox + p->w - 16 - aw, y + 7, aw + 4,
                          !m->enabled ? C_FAINT : hov ? 0xd8f3efu : C_DIM, 255, m->accel);
    }
}
static void draw_props(struct app *a, int ox, int oy)
{
    struct popup *p = &a->pop;
    draw_popup_frame(a, ox, oy);
    if (p->glyph_icon > 0) draw_icon_art(a, &p->glyph, ox + 18, oy + 18, 42, 1);
    else {
        struct icon many;
        memset(&many, 0, sizeof many);
        many.glyph = G_FOLDER; many.allowed = 1;
        draw_icon_art(a, &many, ox + 18, oy + 18, 42, 1);
    }
    text_draw(a, F_BOLD, 15, ox + 74, oy + 20, p->w - 92, C_TEXT, 255, p->title);
    text_draw(a, F_REG, 12, ox + 74, oy + 44, p->w - 92, C_DIM, 255, p->sub);
    for (int i = 0; i < p->nrows; i++) {
        int y = oy + 78 + i * 22;
        text_draw(a, F_REG, 12, ox + 18, y, 96, C_DIM, 255, p->rows[i].k);
        text_draw(a, F_REG, 12, ox + 120, y, p->w - 138, C_TEXT, 255, p->rows[i].v);
    }
    cairo_rectangle(a->cv->cr, ox + 1, oy + p->h - 58, p->w - 2, 1);
    set_rgb(a->cv->cr, C_MENU_LINE);
    cairo_fill(a->cv->cr);
    draw_buttons(a, ox, oy);
}
static void draw_confirm(struct app *a, int ox, int oy)
{
    struct popup *p = &a->pop;
    draw_popup_frame(a, ox, oy);
    text_draw(a, F_BOLD, 15, ox + 20, oy + 20, p->w - 40, C_TEXT, 255, p->title);
    text_draw(a, F_REG, 12, ox + 20, oy + 48, p->w - 40, C_DIM, 255, p->msg);
    draw_buttons(a, ox, oy);
}
static void draw_popup_content(struct app *a, int ox, int oy)
{
    switch (a->pop.kind) {
    case POP_MENU: case POP_WALLPAPER: draw_menu(a, ox, oy); break;
    case POP_PROPS: draw_props(a, ox, oy); break;
    case POP_CONFIRM: draw_confirm(a, ox, oy); break;
    default: break;
    }
}

/* ── popups: the xdg_popup surface ─────────────────────────────────────────────────────── */
static void pop_frame_done(void *data, struct wl_callback *cb, uint32_t t)
{
    struct app *a = data; (void)t;
    wl_callback_destroy(cb);
    if (cb == a->pop.frame_cb) { a->pop.frame_cb = NULL; a->pop.frame_pending = 0; }
    if (a->pop.dirty && !a->pop.frame_pending) render_popup(a);
}
static const struct wl_callback_listener pop_frame_listener = { .done = pop_frame_done };

static void render_popup(struct app *a)
{
    struct popup *p = &a->pop;
    if (!p->kind || p->inline_mode || !p->configured || !p->surf) return;
    struct shmbuf *b = pool_acquire(&p->pool);
    if (!b) { p->dirty = 1; return; }
    struct canvas cv;
    canvas_begin(&cv, b->px, p->w, p->h, CAIRO_FORMAT_ARGB32);
    cairo_set_operator(cv.cr, CAIRO_OPERATOR_CLEAR);          /* transparent outside the rounded body */
    cairo_paint(cv.cr);
    cairo_set_operator(cv.cr, CAIRO_OPERATOR_OVER);
    a->cv = &cv;
    draw_popup_content(a, 0, 0);
    a->cv = NULL;
    canvas_end(&cv);
    b->busy = 1;
    p->dirty = 0;
    wl_surface_attach(p->surf, b->wl, 0, 0);
    wl_surface_damage_buffer(p->surf, 0, 0, p->w, p->h);
    p->frame_cb = wl_surface_frame(p->surf);
    wl_callback_add_listener(p->frame_cb, &pop_frame_listener, a);
    p->frame_pending = 1;
    p->frame_ms = now_ms();
    wl_surface_commit(p->surf);
    wl_display_flush(a->display);
}
static void pop_request_redraw(struct app *a)
{
    if (!a->pop.kind) return;
    if (a->pop.inline_mode) { request_redraw(a); return; }
    a->pop.dirty = 1;
    if (!a->pop.frame_pending) render_popup(a);
}

static void pop_xs_configure(void *data, struct xdg_surface *xs, uint32_t serial)
{
    struct app *a = data;
    xdg_surface_ack_configure(xs, serial);
    struct popup *p = &a->pop;
    if (!p->kind || xs != p->xs) return;
    if (!p->pool.b[0].wl && pool_create(a, &p->pool, p->w, p->h, 1, WL_SHM_FORMAT_ARGB8888) < 0) { pop_close(a); return; }
    p->configured = 1;
    p->dirty = 1;
    if (!p->frame_pending) render_popup(a);
}
static const struct xdg_surface_listener pop_xs_listener = { .configure = pop_xs_configure };
static void pop_configure(void *data, struct xdg_popup *xp, int32_t x, int32_t y, int32_t w, int32_t h)
{
    struct app *a = data; (void)w; (void)h;
    if (xp == a->pop.xp) { a->pop.x = x; a->pop.y = y; }    /* where the compositor put it (after flips) */
}
static void pop_done(void *data, struct xdg_popup *xp)
{
    struct app *a = data;
    if (xp != a->pop.xp) return;
    /* Hyprland ends the grab only for a click on something else -- a window (a click on empty
     * desktop reaches the popup itself, out of bounds).  The user went to that window: stop being
     * keyboard-interactive, or the desktop would take the keyboard the next time it is hovered. */
    pop_close(a);
    if (!a->ptr_on_main) { a->engaged = 0; set_kbi(a, 0); }
}
static void pop_repositioned(void *data, struct xdg_popup *xp, uint32_t token) { (void)data; (void)xp; (void)token; }
static const struct xdg_popup_listener pop_listener = {
    .configure = pop_configure, .popup_done = pop_done, .repositioned = pop_repositioned,
};

static void pop_close(struct app *a)
{
    struct popup *p = &a->pop;
    if (!p->kind) return;
    int was_inline = p->inline_mode;
    if (p->frame_cb) wl_callback_destroy(p->frame_cb);
    if (p->xp) xdg_popup_destroy(p->xp);
    if (p->xs) xdg_surface_destroy(p->xs);
    if (p->surf) {
        if (a->ptr_surf == p->surf) a->ptr_surf = NULL;
        if (a->kb_surf == p->surf) a->kb_surf = NULL;
        wl_surface_destroy(p->surf);
    }
    pool_destroy(&p->pool);
    memset(p, 0, sizeof *p);
    p->hover = p->btn_hover = -1;
    p->glyph_icon = -1;
    if (was_inline) request_redraw(a);
    if (a->display) wl_display_flush(a->display);
}

/* Show the popup prepared in a->pop.  mode 0: at (ax, ay), opening down-right and flipping at the
 * screen edges; mode 1: centred on the screen.  A real xdg_popup whenever xdg_wm_base exists (so
 * it is drawn above windows), else drawn into the desktop surface. */
static void pop_show(struct app *a, int ax, int ay, int mode)
{
    struct popup *p = &a->pop;
    p->hover = p->btn_hover = -1;
    p->moved = p->pressed_inside = 0;
    if (a->offscreen) return;
    if (a->wm_base && a->layer_surface) {
        p->surf = wl_compositor_create_surface(a->compositor);
        p->xs = xdg_wm_base_get_xdg_surface(a->wm_base, p->surf);
        xdg_surface_add_listener(p->xs, &pop_xs_listener, a);
        struct xdg_positioner *pos = xdg_wm_base_create_positioner(a->wm_base);
        xdg_positioner_set_size(pos, p->w, p->h);
        if (mode == 1) {
            xdg_positioner_set_anchor_rect(pos, a->width / 2 - 1, a->height / 2 - 1, 2, 2);
            xdg_positioner_set_anchor(pos, XDG_POSITIONER_ANCHOR_NONE);
            xdg_positioner_set_gravity(pos, XDG_POSITIONER_GRAVITY_NONE);
            p->x = a->width / 2 - p->w / 2; p->y = a->height / 2 - p->h / 2;
        } else {
            xdg_positioner_set_anchor_rect(pos, imax(0, ax), imax(0, ay), 1, 1);
            xdg_positioner_set_anchor(pos, XDG_POSITIONER_ANCHOR_TOP_LEFT);
            xdg_positioner_set_gravity(pos, XDG_POSITIONER_GRAVITY_BOTTOM_RIGHT);
            p->x = ax; p->y = ay;
        }
        xdg_positioner_set_constraint_adjustment(pos,
            XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_FLIP_X | XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_FLIP_Y |
            XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_SLIDE_X | XDG_POSITIONER_CONSTRAINT_ADJUSTMENT_SLIDE_Y);
        p->xp = xdg_surface_get_popup(p->xs, NULL, pos);
        xdg_positioner_destroy(pos);
        xdg_popup_add_listener(p->xp, &pop_listener, a);
        zwlr_layer_surface_v1_get_popup(a->layer_surface, p->xp);
        /* The grab gives the menu the keyboard and makes an outside click end it (popup_done). */
        if (a->seat) xdg_popup_grab(p->xp, a->seat, a->serial);
        wl_surface_commit(p->surf);
        wl_display_flush(a->display);
        return;
    }
    p->inline_mode = 1;
    if (mode == 1) { p->x = (a->width - p->w) / 2; p->y = (a->height - p->h) / 2; }
    else {
        p->x = ax + p->w <= a->width ? ax : ax - p->w;
        p->y = ay + p->h <= a->height ? ay : ay - p->h;
    }
    p->x = imax(0, imin(p->x, a->width - p->w));
    p->y = imax(0, imin(p->y, a->height - p->h));
    request_redraw(a);
}

static void open_menu(struct app *a, int kind, int ax, int ay)
{
    pop_close(a);
    a->pop.kind = kind;
    if (kind == POP_WALLPAPER) build_wallpaper_menu(a);
    else if (nsel(a)) build_selection_menu(a);
    else build_desktop_menu(a);
    pop_show(a, ax, ay, 0);
}
static void open_props(struct app *a)
{
    if (!nsel(a)) return;
    pop_close(a);
    a->pop.kind = POP_PROPS;
    build_props(a);
    int i = a->cursor >= 0 && a->icons[a->cursor].sel ? a->cursor : first_sel(a);
    struct ibox b = icon_box(a, i);
    pop_show(a, b.x + b.w + 6, b.y, b.w ? 0 : 1);
}
static void open_confirm_empty(struct app *a)
{
    pop_close(a);
    a->pop.kind = POP_CONFIRM;
    build_confirm_empty(a);
    pop_show(a, 0, 0, 1);
}

/* ── actions ───────────────────────────────────────────────────────────────────────────── */
static void open_selected(struct app *a, int files_only)
{
    int opened = 0;
    for (int i = 0; i < a->nicons && opened < 12; i++) {
        struct icon *ic = &a->icons[i];
        if (!ic->sel) continue;
        if (files_only) {
            if (ic->kind == K_DIR || ic->kind == K_TRASH) open_icon(a, i);
            else if (ic->glyph == G_HOME) launch2(a, "/wl-files", a->home, "Files");
            else continue;
        } else open_icon(a, i);
        opened++;
    }
    if (opened == 12 && nsel(a) > 12) notice(a, 0, "Opened the first 12 items");
}
static void do_action(struct app *a, int action, int arg)
{
    switch (action) {
    case ACT_OPEN_TERMINAL: launch2(a, "/hos-wifiterm", NULL, "Terminal"); break;
    case ACT_OPEN_FILES:
        launch2(a, "/wl-files", access(a->desk_dir, F_OK) == 0 ? a->desk_dir : a->home, "Files");
        break;
    case ACT_NEW_FOLDER: new_folder(a); break;
    case ACT_ARRANGE: arrange_icons(a); break;
    case ACT_SELECT_ALL:
        for (int i = 0; i < a->nicons; i++) a->icons[i].sel = a->icons[i].col >= 0;
        request_redraw(a);
        break;
    case ACT_WALLPAPER: open_menu(a, POP_WALLPAPER, a->menu_x, a->menu_y); break;
    case ACT_PICK_WALLPAPER:
        if (arg >= 0 && arg < a->nwp) set_wallpaper(a, a->wp[arg].path, a->wp[arg].color);
        break;
    case ACT_SET_WALLPAPER: if (arg >= 0 && arg < a->nicons) set_wallpaper(a, a->icons[arg].path, 0); break;
    case ACT_DISPLAY: break;
    case ACT_OPEN: open_selected(a, 0); break;
    case ACT_OPEN_WITH_FILES: open_selected(a, 1); break;
    case ACT_RENAME: if (nsel(a) == 1) edit_begin(a, first_sel(a)); break;
    case ACT_TRASH: trash_selected(a); break;
    case ACT_COPY_PATH: copy_paths(a); break;
    case ACT_PROPERTIES: open_props(a); break;
    case ACT_EMPTY_TRASH: if (a->trash_full) open_confirm_empty(a); break;
    case ACT_CONFIRM_EMPTY: pop_close(a); empty_trash(a); break;
    case ACT_CLOSE_POPUP: pop_close(a); break;
    default: break;
    }
}
static void menu_activate(struct app *a, int idx)
{
    struct popup *p = &a->pop;
    if (idx < 0 || idx >= p->nitems || p->items[idx].sep || !p->items[idx].enabled) return;
    int action = p->items[idx].action, arg = p->items[idx].arg;
    pop_close(a);
    do_action(a, action, arg);
}

/* ── keyboard focus (see the header: NONE <-> ON_DEMAND, never EXCLUSIVE for longer than a pulse) */
static void set_kbi(struct app *a, int on)
{
    if (a->offscreen || !a->layer_surface || a->layer_shell_ver < 4) return;
    uint32_t v = on ? ZWLR_LAYER_SURFACE_V1_KEYBOARD_INTERACTIVITY_ON_DEMAND : ZWLR_LAYER_SURFACE_V1_KEYBOARD_INTERACTIVITY_NONE;
    if ((uint32_t)a->kbi == v) return;
    a->kbi = (int)v;
    zwlr_layer_surface_v1_set_keyboard_interactivity(a->layer_surface, v);
    wl_surface_commit(a->surface);
    wl_display_flush(a->display);
}
static void focus_pulse(struct app *a)
{
    const char *e = getenv("WLDESKTOP_FOCUS_PULSE");
    if (a->offscreen || !a->layer_surface || a->layer_shell_ver < 4 || (e && e[0] == '0')) return;
    if (a->kb_surf == a->surface || a->pop.kind) return;
    zwlr_layer_surface_v1_set_keyboard_interactivity(a->layer_surface, ZWLR_LAYER_SURFACE_V1_KEYBOARD_INTERACTIVITY_EXCLUSIVE);
    wl_surface_commit(a->surface);
    zwlr_layer_surface_v1_set_keyboard_interactivity(a->layer_surface, ZWLR_LAYER_SURFACE_V1_KEYBOARD_INTERACTIVITY_ON_DEMAND);
    wl_surface_commit(a->surface);
    a->kbi = ZWLR_LAYER_SURFACE_V1_KEYBOARD_INTERACTIVITY_ON_DEMAND;
    wl_display_flush(a->display);
}

/* ── pointer: the desktop ──────────────────────────────────────────────────────────────── */
static void update_hover(struct app *a)
{
    int h = (a->ptr_on_main && !a->band && !a->dragging && !(a->pop.kind && a->pop.inline_mode))
            ? icon_at(a, a->ptr_x, a->ptr_y) : -1;
    if (h != a->hover) { a->hover = h; request_redraw(a); }
}
static void band_update(struct app *a)
{
    int x0 = (int)fmin(a->press_x, a->ptr_x), y0 = (int)fmin(a->press_y, a->ptr_y);
    int x1 = (int)fmax(a->press_x, a->ptr_x), y1 = (int)fmax(a->press_y, a->ptr_y);
    for (int i = 0; i < a->nicons; i++) {
        struct ibox b = icon_box(a, i);
        int hit = b.w && b.x < x1 && b.x + b.w > x0 && b.y < y1 && b.y + b.h > y0;
        a->icons[i].sel = a->band_base[i] || hit;
    }
    request_redraw(a);
}
static void drag_update(struct app *a)
{
    int t = icon_at(a, a->ptr_x, a->ptr_y);
    if (t >= 0 && (a->icons[t].sel || !(a->icons[t].kind == K_DIR || a->icons[t].kind == K_TRASH))) t = -1;
    a->drop_target = t;
    request_redraw(a);
}
/* Drop: onto the Trash trashes, onto a desktop folder moves in, anywhere else re-cells the icons,
 * keeping their arrangement relative to the one grabbed. */
static void drop_icons(struct app *a)
{
    int t = a->drop_target;
    a->drop_target = -1;
    if (t >= 0) {
        if (a->icons[t].kind == K_TRASH) trash_selected(a);
        else move_selected_into(a, t);
        return;
    }
    double ddx = a->ptr_x - a->press_x, ddy = a->ptr_y - a->press_y;
    int cells = a->cols * a->rows;
    unsigned char *occ = calloc((size_t)cells, 1);
    if (!occ) return;
    for (int i = 0; i < a->nicons; i++) {
        const struct icon *ic = &a->icons[i];
        if (!ic->sel && ic->col >= 0) occ[ic->col * a->rows + ic->row] = 1;
    }
    for (int i = 0; i < a->nicons; i++) {
        struct icon *ic = &a->icons[i];
        if (!ic->sel || ic->col < 0) continue;
        int x, y;
        cell_origin(ic->col, ic->row, &x, &y);
        int c = (int)floor((x + ddx - GRID_X) / CELL_W + 0.5), r = (int)floor((y + ddy - GRID_Y) / CELL_H + 0.5);
        c = imax(0, imin(a->cols - 1, c));
        r = imax(0, imin(a->rows - 1, r));
        int best = -1, bestd = 1 << 30;
        for (int k = 0; k < cells; k++) {                    /* nearest free cell to where it was dropped */
            if (occ[k]) continue;
            int dc = k / a->rows - c, dr = k % a->rows - r, d = dc * dc + dr * dr;
            if (d < bestd) { bestd = d; best = k; }
        }
        if (best < 0) continue;
        occ[best] = 1;
        ic->col = best / a->rows;
        ic->row = best % a->rows;
        ic->placed = 1;
    }
    free(occ);
    save_positions(a);
    request_redraw(a);
}

static void open_context_menu(struct app *a, double x, double y)
{
    edit_commit(a);
    int idx = icon_at(a, x, y);
    if (idx >= 0) {
        if (!a->icons[idx].sel) { clear_sel(a); a->icons[idx].sel = 1; }
        a->cursor = idx;
    } else clear_sel(a);
    a->menu_x = (int)x; a->menu_y = (int)y;
    request_redraw(a);
    open_menu(a, POP_MENU, (int)x, (int)y);
}
/* A click that closed a popup is still a click (outside a real popup it arrives on the popup
 * surface under Hyprland's grab): select what it hit, or open the menu there. */
static void forward_click(struct app *a, double x, double y, uint32_t button)
{
    a->ptr_x = x; a->ptr_y = y;
    if (button == BTN_RIGHT) { open_context_menu(a, x, y); return; }
    if (button != BTN_LEFT) return;
    int idx = icon_at(a, x, y);
    if (idx >= 0 && a->ctrl) a->icons[idx].sel = !a->icons[idx].sel;
    else if (idx >= 0) { clear_sel(a); a->icons[idx].sel = 1; }
    else if (!a->ctrl) clear_sel(a);
    if (idx >= 0) a->cursor = idx;
    request_redraw(a);
}

static void pop_motion(struct app *a, double lx, double ly);
static void pop_button(struct app *a, double lx, double ly, uint32_t button, int pressed);

static void main_motion(struct app *a)
{
    if (a->pop.kind && a->pop.inline_mode && !a->press) { pop_motion(a, a->ptr_x - a->pop.x, a->ptr_y - a->pop.y); return; }
    if (a->press == 1) {
        if (!a->dragging && hypot(a->ptr_x - a->press_x, a->ptr_y - a->press_y) > DRAG_SLOP) {
            a->dragging = 1;
            edit_commit(a);
        }
        if (a->dragging) drag_update(a);
        return;
    }
    if (a->press == 2) {
        if (!a->band && hypot(a->ptr_x - a->press_x, a->ptr_y - a->press_y) > 3) a->band = 1;
        if (a->band) band_update(a);
        return;
    }
    update_hover(a);
}

static void main_button(struct app *a, uint32_t button, int pressed, uint32_t time)
{
    double x = a->ptr_x, y = a->ptr_y;
    if (a->pop.kind && a->pop.inline_mode) {
        double lx = x - a->pop.x, ly = y - a->pop.y;
        if (lx >= 0 && ly >= 0 && lx < a->pop.w && ly < a->pop.h) { pop_button(a, lx, ly, button, pressed); return; }
        if (pressed) pop_close(a);
    } else if (a->pop.kind && pressed) pop_close(a);        /* a stray press while a real popup is up */
    if (pressed) {
        a->engaged = 1;
        set_kbi(a, 1);
    }
    if (button == BTN_RIGHT) {
        if (pressed) open_context_menu(a, x, y);
        return;
    }
    if (button != BTN_LEFT) return;

    if (pressed) {
        int idx = icon_at(a, x, y);
        if (a->edit_idx >= 0 && idx == a->edit_idx) return;  /* clicking into the name being edited */
        if (a->edit_idx >= 0) { edit_commit(a); idx = icon_at(a, x, y); }   /* a rename rescans */
        a->press_x = x; a->press_y = y;
        a->dragging = a->band = 0;
        a->drop_target = -1;
        if (idx >= 0) {
            int dbl = idx == a->click_idx && (uint32_t)(time - a->click_ms) < DBL_MS;
            a->click_idx = idx; a->click_ms = time;
            a->cursor = idx;
            if (dbl && !a->ctrl) {
                clear_sel(a);
                a->icons[idx].sel = 1;
                a->click_idx = -1;
                a->press = 0;
                request_redraw(a);
                open_icon(a, idx);
                return;
            }
            if (a->ctrl) { a->icons[idx].sel = !a->icons[idx].sel; a->press = 0; request_redraw(a); return; }
            a->press_keep = a->icons[idx].sel && nsel(a) > 1;
            if (!a->icons[idx].sel) { clear_sel(a); a->icons[idx].sel = 1; }
            a->press = 1;
            a->press_idx = idx;
        } else {
            a->click_idx = -1;
            if (!a->ctrl && !a->shift) clear_sel(a);
            for (int i = 0; i < a->nicons; i++) a->band_base[i] = (unsigned char)a->icons[i].sel;
            a->press = 2;
        }
        request_redraw(a);
        return;
    }
    /* release */
    if (a->press == 1) {
        if (a->dragging) drop_icons(a);
        else if (a->press_keep) { clear_sel(a); a->icons[a->press_idx].sel = 1; }
    }
    a->press = 0;
    a->dragging = a->band = 0;
    a->drop_target = -1;
    a->press_keep = 0;
    update_hover(a);
    request_redraw(a);
    focus_pulse(a);
}

/* ── pointer: the popup (popup-local coordinates; outside = beyond its bounds) ─────────── */
static void pop_motion(struct app *a, double lx, double ly)
{
    struct popup *p = &a->pop;
    int inside = lx >= 0 && ly >= 0 && lx < p->w && ly < p->h;
    if (p->kind == POP_MENU || p->kind == POP_WALLPAPER) {
        int h = inside ? menu_item_at(p, ly) : -1;
        if (inside) p->moved = 1;
        if (h != p->hover) { p->hover = h; pop_request_redraw(a); }
    } else {
        int h = inside ? btn_at(p, lx, ly) : -1;
        if (h != p->btn_hover) { p->btn_hover = h; pop_request_redraw(a); }
    }
}
static void pop_button(struct app *a, double lx, double ly, uint32_t button, int pressed)
{
    struct popup *p = &a->pop;
    int inside = lx >= 0 && ly >= 0 && lx < p->w && ly < p->h;
    if (pressed) {
        if (!inside) {
            double mx = lx + p->x, my = ly + p->y;
            int was_inline = p->inline_mode;
            pop_close(a);
            if (!was_inline) forward_click(a, mx, my, button);
            return;
        }
        p->pressed_inside = 1;
        return;
    }
    if (!inside) return;
    if (p->kind == POP_MENU || p->kind == POP_WALLPAPER) {
        /* Activate on release -- after a press in the menu, or a press-drag-release from the
         * right-click that opened it.  The opening click's own release (no motion) does nothing. */
        int idx = menu_item_at(p, ly);
        if (idx >= 0 && (p->pressed_inside || (p->moved && button == BTN_RIGHT))) menu_activate(a, idx);
        return;
    }
    int b = btn_at(p, lx, ly);
    if (b >= 0 && p->pressed_inside && button == BTN_LEFT) do_action(a, p->btns[b].action, 0);
}

/* ── keyboard ──────────────────────────────────────────────────────────────────────────── */
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

/* The action a key chord stands for (the accelerators shown in the menus). */
static int key_action(struct app *a, uint32_t code)
{
    if ((code == KEY_ENTER || code == KEY_KPENTER) && a->alt) return ACT_PROPERTIES;
    if (code == KEY_ENTER || code == KEY_KPENTER) return ACT_OPEN;
    if (code == KEY_F2) return ACT_RENAME;
    if (code == KEY_DELETE) return ACT_TRASH;
    if (code == KEY_C && a->ctrl) return ACT_COPY_PATH;
    if (code == KEY_A && a->ctrl) return ACT_SELECT_ALL;
    if (code == KEY_N && a->ctrl && a->shift) return ACT_NEW_FOLDER;
    return ACT_NONE;
}

static void edit_key(struct app *a, uint32_t code)
{
    size_t len = strlen(a->edit);
    if (code == KEY_ESC) { edit_cancel(a); return; }
    if (code == KEY_ENTER || code == KEY_KPENTER) { edit_commit(a); return; }
    if (code == KEY_BACKSPACE) {
        while (len && ((unsigned char)a->edit[len - 1] & 0xc0) == 0x80) len--;   /* a whole UTF-8 char */
        if (len) len--;
        a->edit[len] = 0;
    } else if (code < sizeof km_plain && !a->ctrl && !a->alt) {
        char ch = a->shift ? km_shift[code] : km_plain[code];
        if (ch && ch != '/' && len + 1 < sizeof a->edit) { a->edit[len] = ch; a->edit[len + 1] = 0; }
    }
    request_redraw(a);
}

static void move_cursor(struct app *a, int dx, int dy)
{
    int cur = a->cursor >= 0 && a->cursor < a->nicons && a->icons[a->cursor].col >= 0 ? a->cursor : first_sel(a);
    int best = -1;
    if (cur < 0) { for (int i = 0; i < a->nicons; i++) if (a->icons[i].col >= 0) { best = i; break; } }
    else {
        long bestscore = 1L << 40;
        for (int i = 0; i < a->nicons; i++) {
            const struct icon *ic = &a->icons[i];
            if (i == cur || ic->col < 0) continue;
            int ddc = ic->col - a->icons[cur].col, ddr = ic->row - a->icons[cur].row;
            int primary = dx ? ddc * dx : ddr * dy, secondary = dx ? abs(ddr) : abs(ddc);
            if (primary <= 0) continue;
            long score = (long)primary * primary + 4L * secondary * secondary;
            if (score < bestscore) { bestscore = score; best = i; }
        }
    }
    if (best < 0) return;
    if (!a->shift) clear_sel(a);
    a->icons[best].sel = 1;
    a->cursor = best;
    request_redraw(a);
}

static void popup_key(struct app *a, uint32_t code)
{
    struct popup *p = &a->pop;
    if (code == KEY_ESC) { pop_close(a); return; }
    if (p->kind == POP_PROPS) { if (code == KEY_ENTER || code == KEY_KPENTER) pop_close(a); return; }
    if (p->kind == POP_CONFIRM) {
        if (code == KEY_ENTER || code == KEY_KPENTER) do_action(a, ACT_CONFIRM_EMPTY, 0);
        return;
    }
    if (code == KEY_UP || code == KEY_DOWN || code == KEY_HOME || code == KEY_END) {
        int step = (code == KEY_UP || code == KEY_END) ? -1 : 1;
        int i = code == KEY_HOME ? -1 : code == KEY_END ? p->nitems : p->hover;
        for (int k = 0; k < p->nitems; k++) {
            i += step;
            if (i < 0) i = p->nitems - 1;
            if (i >= p->nitems) i = 0;
            if (!p->items[i].sep && p->items[i].enabled) { p->hover = i; break; }
        }
        pop_request_redraw(a);
        return;
    }
    if ((code == KEY_ENTER || code == KEY_KPENTER || code == KEY_SPACE) && !a->alt) { menu_activate(a, p->hover); return; }
    /* the accelerator of an item works while its menu is open */
    int act = key_action(a, code);
    for (int i = 0; act != ACT_NONE && i < p->nitems; i++)
        if (p->items[i].action == act && p->items[i].enabled) { menu_activate(a, i); return; }
}

static void desktop_key(struct app *a, uint32_t code)
{
    if (a->edit_idx >= 0) { edit_key(a, code); return; }
    switch (code) {
    case KEY_ESC:
        a->press = a->band = a->dragging = 0;
        clear_sel(a);
        request_redraw(a);
        return;
    case KEY_UP: move_cursor(a, 0, -1); return;
    case KEY_DOWN: move_cursor(a, 0, 1); return;
    case KEY_LEFT: move_cursor(a, -1, 0); return;
    case KEY_RIGHT: move_cursor(a, 1, 0); return;
    case KEY_MENU: case KEY_F10:
        if (code == KEY_F10 && !a->shift) return;
        {
            int i = a->cursor >= 0 && a->cursor < a->nicons && a->icons[a->cursor].sel ? a->cursor : first_sel(a);
            struct ibox b = i >= 0 ? icon_box(a, i) : (struct ibox){ GRID_X + CELL_W, GRID_Y, 0, 0 };
            a->menu_x = b.x + b.w / 2; a->menu_y = b.y + b.h / 2;
            open_menu(a, POP_MENU, a->menu_x, a->menu_y);
        }
        return;
    default: break;
    }
    int act = key_action(a, code);
    if (act == ACT_NEW_FOLDER) { a->menu_x = a->menu_y = -1; }
    if (act != ACT_NONE) do_action(a, act, 0);
}

static void kb_key(void *data, struct wl_keyboard *k, uint32_t serial, uint32_t time, uint32_t code, uint32_t state)
{
    struct app *a = data; (void)k; (void)time;
    int down = state == WL_KEYBOARD_KEY_STATE_PRESSED;
    if (code == KEY_LSHIFT || code == KEY_RSHIFT) { a->shift = down; return; }
    if (code == KEY_LCTRL || code == KEY_RCTRL) { a->ctrl = down; return; }
    if (code == KEY_LALT || code == KEY_RALT) { a->alt = down; return; }
    if (!down) return;
    a->serial = serial;
    if (a->pop.kind) popup_key(a, code);
    else desktop_key(a, code);
}
static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t s)
{ (void)d; (void)k; (void)f; (void)s; if (fd >= 0) close(fd); }
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su, struct wl_array *keys)
{
    struct app *a = d; (void)k; (void)s;
    a->kb_surf = su;
    a->shift = a->ctrl = a->alt = 0;
    uint32_t *kc;
    wl_array_for_each(kc, keys) {                             /* modifiers already held on entry */
        if (*kc == KEY_LSHIFT || *kc == KEY_RSHIFT) a->shift = 1;
        if (*kc == KEY_LCTRL || *kc == KEY_RCTRL) a->ctrl = 1;
        if (*kc == KEY_LALT || *kc == KEY_RALT) a->alt = 1;
    }
}
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su)
{
    struct app *a = d; (void)k; (void)s;
    if (a->kb_surf == su) a->kb_surf = NULL;
    a->shift = a->ctrl = a->alt = 0;
    /* Focus moved from the desktop to a window: a rename in progress is committed, as in GNOME.
     * Strictly the desktop surface -- a leave for a popup just destroyed arrives with su == NULL,
     * and must not end the rename its "Rename..." item has just started. */
    if (a->edit_idx >= 0 && su && su == a->surface && !a->pop.kind) edit_commit(a);
}
/* Depressed modifiers with the standard xkb masks (Shift 1, Control 4, Mod1/Alt 8). */
static void kb_mods(void *d, struct wl_keyboard *k, uint32_t s, uint32_t dep, uint32_t lat, uint32_t lck, uint32_t g)
{
    struct app *a = d; (void)k; (void)s; (void)lat; (void)lck; (void)g;
    a->shift = (dep & 1) != 0;
    a->ctrl = (dep & 4) != 0;
    a->alt = (dep & 8) != 0;
}
static void kb_rep(void *d, struct wl_keyboard *k, int32_t r, int32_t dl) { (void)d; (void)k; (void)r; (void)dl; }
static const struct wl_keyboard_listener kb_listener = {
    .keymap = kb_keymap, .enter = kb_enter, .leave = kb_leave, .key = kb_key, .modifiers = kb_mods,
    .repeat_info = kb_rep,
};

/* ── pointer: routing between the desktop and the popup surface ────────────────────────── */
static void ptr_motion(void *data, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y)
{
    struct app *a = data; (void)p; (void)t;
    double fx = wl_fixed_to_double(x), fy = wl_fixed_to_double(y);
    if (a->pop.kind && !a->pop.inline_mode && a->ptr_surf && a->ptr_surf == a->pop.surf) {
        a->pop_px = fx; a->pop_py = fy;                      /* popup-local; beyond its size under the grab */
        pop_motion(a, fx, fy);
        return;
    }
    if (a->ptr_surf != a->surface) return;
    a->ptr_x = fx; a->ptr_y = fy;
    main_motion(a);
}
static void ptr_enter(void *data, struct wl_pointer *p, uint32_t serial, struct wl_surface *su, wl_fixed_t x, wl_fixed_t y)
{
    struct app *a = data; (void)serial;
    a->ptr_surf = su;
    if (su && su == a->surface) a->ptr_on_main = 1;
    ptr_motion(data, p, 0, x, y);
}
static void ptr_leave(void *data, struct wl_pointer *p, uint32_t serial, struct wl_surface *su)
{
    struct app *a = data; (void)p; (void)serial;
    if (su && su == a->pop.surf) {
        if (a->pop.hover != -1 || a->pop.btn_hover != -1) { a->pop.hover = a->pop.btn_hover = -1; pop_request_redraw(a); }
    }
    if (su && su == a->surface) {                            /* NULL = a destroyed popup, not the desktop */
        a->ptr_on_main = 0;
        if (a->hover != -1) { a->hover = -1; request_redraw(a); }
        /* Left the desktop for a window or the bar: stop taking the keyboard on hover (the popup
         * grab also moves the pointer off the desktop -- keep it then). */
        if (!a->pop.kind && !a->press) { a->engaged = 0; set_kbi(a, 0); }
    }
    if (a->ptr_surf == su) a->ptr_surf = NULL;
}
static void ptr_button(void *data, struct wl_pointer *p, uint32_t serial, uint32_t time, uint32_t button, uint32_t state)
{
    struct app *a = data; (void)p;
    int pressed = state == WL_POINTER_BUTTON_STATE_PRESSED;
    if (pressed) a->serial = serial;
    if (a->pop.kind && !a->pop.inline_mode && a->ptr_surf && a->ptr_surf == a->pop.surf) {
        pop_button(a, a->pop_px, a->pop_py, button, pressed);
        return;
    }
    if (a->ptr_surf != a->surface) return;
    main_button(a, button, pressed, time);
}
static void ptr_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v) { (void)d; (void)p; (void)t; (void)ax; (void)v; }
static void ptr_frame(void *d, struct wl_pointer *p) { (void)d; (void)p; }
static void ptr_axis_src(void *d, struct wl_pointer *p, uint32_t s) { (void)d; (void)p; (void)s; }
static void ptr_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax) { (void)d; (void)p; (void)t; (void)ax; }
static void ptr_axis_disc(void *d, struct wl_pointer *p, uint32_t ax, int32_t v) { (void)d; (void)p; (void)ax; (void)v; }
static const struct wl_pointer_listener ptr_listener = {
    .enter = ptr_enter, .leave = ptr_leave, .motion = ptr_motion, .button = ptr_button, .axis = ptr_axis,
    .frame = ptr_frame, .axis_source = ptr_axis_src, .axis_stop = ptr_axis_stop, .axis_discrete = ptr_axis_disc,
};

static void seat_caps(void *data, struct wl_seat *seat, uint32_t caps)
{
    struct app *a = data;
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !a->pointer) {
        a->pointer = wl_seat_get_pointer(seat);
        wl_pointer_add_listener(a->pointer, &ptr_listener, a);
    }
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !a->keyboard) {
        a->keyboard = wl_seat_get_keyboard(seat);
        wl_keyboard_add_listener(a->keyboard, &kb_listener, a);
    }
}
static void seat_name(void *d, struct wl_seat *s, const char *n) { (void)d; (void)s; (void)n; }
static const struct wl_seat_listener seat_listener = { .capabilities = seat_caps, .name = seat_name };

static void wm_ping(void *d, struct xdg_wm_base *b, uint32_t s) { (void)d; xdg_wm_base_pong(b, s); }
static const struct xdg_wm_base_listener wm_listener = { .ping = wm_ping };

/* ── layer surface ─────────────────────────────────────────────────────────────────────── */
static void layer_configure(void *d, struct zwlr_layer_surface_v1 *s, uint32_t serial, uint32_t w, uint32_t h)
{
    struct app *a = d;
    zwlr_layer_surface_v1_ack_configure(s, serial);
    int nw = w ? (int)w : a->width, nh = h ? (int)h : a->height;
    int resized = nw != a->width || nh != a->height;
    a->width = nw; a->height = nh;
    logf_("configure %dx%d -> render", a->width, a->height);
    a->configured = 1;
    if (resized || !a->bg) {
        build_bg(a);
        layout_icons(a);
    }
    a->full_damage = 1;
    a->dirty = 1;
    if (!a->frame_pending) render_main(a);
}
static void layer_closed(void *d, struct zwlr_layer_surface_v1 *s) { (void)s; ((struct app *)d)->running = 0; }
static const struct zwlr_layer_surface_v1_listener layer_listener = {
    .configure = layer_configure, .closed = layer_closed,
};

static void registry_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver)
{
    struct app *a = d;
    if (!strcmp(iface, wl_compositor_interface.name))
        a->compositor = wl_registry_bind(r, name, &wl_compositor_interface, ver < 4 ? ver : 4);
    else if (!strcmp(iface, wl_shm_interface.name))
        a->shm = wl_registry_bind(r, name, &wl_shm_interface, 1);
    else if (!strcmp(iface, zwlr_layer_shell_v1_interface.name)) {
        /* v4 for keyboard_interactivity ON_DEMAND (Hyprland offers 5) */
        a->layer_shell_ver = ver < 4 ? ver : 4;
        a->layer_shell = wl_registry_bind(r, name, &zwlr_layer_shell_v1_interface, a->layer_shell_ver);
    } else if (!strcmp(iface, wl_output_interface.name) && !a->output)
        a->output = wl_registry_bind(r, name, &wl_output_interface, ver < 2 ? ver : 2);
    else if (!strcmp(iface, wl_seat_interface.name) && !a->seat) {
        a->seat = wl_registry_bind(r, name, &wl_seat_interface, ver < 5 ? ver : 5);
        wl_seat_add_listener(a->seat, &seat_listener, a);
    } else if (!strcmp(iface, xdg_wm_base_interface.name)) {
        a->wm_base = wl_registry_bind(r, name, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(a->wm_base, &wm_listener, a);
    } else if (!strcmp(iface, wl_data_device_manager_interface.name))
        a->ddm = wl_registry_bind(r, name, &wl_data_device_manager_interface, ver < 3 ? ver : 3);
}
static void registry_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener registry_listener = {
    .global = registry_global, .global_remove = registry_remove,
};

/* ── self-test: render the desktop and the popups to PNG files, no compositor ─────────── */
static int write_canvas(struct canvas *cv, const char *prefix, const char *what)
{
    char p[600];
    snprintf(p, sizeof p, "%s-%s.png", prefix, what);
    cairo_surface_flush(cv->cs);
    cairo_status_t st = cairo_surface_write_to_png(cv->cs, p);
    printf("render-png: %s %s\n", p, st == CAIRO_STATUS_SUCCESS ? "ok" : cairo_status_to_string(st));
    return st == CAIRO_STATUS_SUCCESS ? 0 : 1;
}
static int render_popup_png(struct app *a, const char *prefix, const char *what)
{
    uint32_t *px = calloc((size_t)a->pop.w * (size_t)a->pop.h, 4);
    if (!px) return 1;
    struct canvas cv;
    canvas_begin(&cv, px, a->pop.w, a->pop.h, CAIRO_FORMAT_ARGB32);
    a->cv = &cv;
    draw_popup_content(a, 0, 0);
    a->cv = NULL;
    int rc = write_canvas(&cv, prefix, what);
    canvas_end(&cv);
    free(px);
    return rc;
}
static int render_png_selftest(struct app *a, const char *prefix)
{
    const char *sz = getenv("WLDESKTOP_SIZE");
    a->width = 1280; a->height = 800;
    if (sz && sscanf(sz, "%dx%d", &a->width, &a->height) != 2) { a->width = 1280; a->height = 800; }
    a->configured = 1;
    build_bg(a);
    scan_desktop(a, 1);
    layout_icons(a);
    int rc = 0;
    uint32_t *px = malloc((size_t)a->width * (size_t)a->height * 4);
    if (!px) return 1;
    struct canvas cv;
    /* 1: plain desktop, the Terminal hovered, Home + the first desktop item selected, a band */
    a->hover = 1;
    a->icons[0].sel = 1;
    if (a->nicons > N_FIXED) a->icons[N_FIXED].sel = 1;
    for (int i = 0; i < a->nicons; i++) a->band_base[i] = (unsigned char)a->icons[i].sel;
    a->press = 2; a->band = 1;
    a->press_x = GRID_X + CELL_W * 0.6; a->press_y = GRID_Y + CELL_H * 3.4;
    a->ptr_x = GRID_X + CELL_W * 2.3; a->ptr_y = GRID_Y + CELL_H * 5.2;
    band_update(a);                                          /* selects what the band touches */
    notice(a, 0, "Moved 1 item to the Trash");
    canvas_begin(&cv, px, a->width, a->height, CAIRO_FORMAT_RGB24);
    compose_desktop(a, &cv);
    rc |= write_canvas(&cv, prefix, "desktop");
    canvas_end(&cv);
    /* 2: rename in progress + a drag with a drop target */
    a->band = 0; a->press = 0; a->notice[0] = 0; a->hover = -1;
    clear_sel(a);
    if (a->nicons > N_FIXED) { a->icons[N_FIXED].sel = 1; edit_begin(a, N_FIXED); }
    canvas_begin(&cv, px, a->width, a->height, CAIRO_FORMAT_RGB24);
    compose_desktop(a, &cv);
    rc |= write_canvas(&cv, prefix, "rename");
    canvas_end(&cv);
    a->edit_idx = -1;
    /* 3: menus and dialogs */
    clear_sel(a);
    a->pop.kind = POP_MENU; build_desktop_menu(a); a->pop.hover = 3;
    rc |= render_popup_png(a, prefix, "menu");
    a->icons[1].sel = 1; if (a->nicons > N_FIXED) a->icons[N_FIXED].sel = 1;
    a->pop.kind = POP_MENU; build_selection_menu(a); a->pop.hover = 0;
    rc |= render_popup_png(a, prefix, "selmenu");
    clear_sel(a); a->icons[N_FIXED - 1].sel = 1;
    a->pop.kind = POP_MENU; build_selection_menu(a); a->pop.hover = -1;
    rc |= render_popup_png(a, prefix, "trashmenu");
    clear_sel(a); a->icons[a->nicons > N_FIXED ? N_FIXED : 0].sel = 1;
    a->pop.kind = POP_PROPS; build_props(a); a->pop.btn_hover = 0;
    rc |= render_popup_png(a, prefix, "props");
    a->pop.kind = POP_CONFIRM; build_confirm_empty(a); a->pop.btn_hover = 1;
    rc |= render_popup_png(a, prefix, "confirm");
    a->pop.kind = POP_WALLPAPER; build_wallpaper_menu(a); a->pop.hover = 0;
    rc |= render_popup_png(a, prefix, "wallpaper");
    /* 4: the inline (no xdg_wm_base) menu inside the desktop */
    clear_sel(a);
    a->pop.kind = POP_MENU; build_desktop_menu(a); a->pop.inline_mode = 1; a->pop.hover = 1;
    a->pop.x = 300; a->pop.y = 200;
    canvas_begin(&cv, px, a->width, a->height, CAIRO_FORMAT_RGB24);
    compose_desktop(a, &cv);
    rc |= write_canvas(&cv, prefix, "inline");
    canvas_end(&cv);
    free(px);
    printf("render-png: %d icons (%d from %s), grid %dx%d\n", a->nicons, a->nicons - N_FIXED, a->desk_dir, a->cols, a->rows);
    return rc;
}

/* ── main ──────────────────────────────────────────────────────────────────────────────── */
static void init_paths(struct app *a)
{
    const char *h = getenv("HOME");
    copy_str(a->home, sizeof a->home, h && h[0] == '/' ? h : "/home/user");
    snprintf(a->desk_dir, sizeof a->desk_dir, "%s/Desktop", a->home);
    snprintf(a->trash_files, sizeof a->trash_files, "%s/.local/share/Trash/files", a->home);
    snprintf(a->trash_info, sizeof a->trash_info, "%s/.local/share/Trash/info", a->home);
    snprintf(a->cfg_dir, sizeof a->cfg_dir, "%s/.config/wl-desktop", a->home);
}

int main(int argc, char **argv)
{
    static struct app app;
    struct app *a = &app;
    memset(a, 0, sizeof *a);
    a->running = 1;
    a->hover = a->cursor = a->edit_idx = a->click_idx = a->drop_target = a->press_idx = -1;
    a->pop.hover = a->pop.btn_hover = a->pop.glyph_icon = -1;
    a->wp_color = COL_BG;
    a->next_tick = a->next_gate = 0;

    const char *render_prefix = NULL, *image = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--render-png") && i + 1 < argc) render_prefix = argv[++i];
        else if (!strcmp(argv[i], "--image") && i + 1 < argc) image = argv[++i];
        else if (argv[i][0] != '-') image = argv[i];        /* the old interface: argv[1] = the PNG */
    }
    if (render_prefix && getenv("WLDESKTOP_ROOT")) hos_root = getenv("WLDESKTOP_ROOT");   /* test data */

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    init_paths(a);
    init_fonts(a);
    load_positions(a);

    /* The explicit image, then the user's choice, then each default path; a miss is a solid ground. */
    int have = image && load_image(a, image) == 0;
    if (!have) have = load_wallpaper_choice(a);
    if (!have) {
        char hp[400];
        snprintf(hp, sizeof hp, "%.300s/.config/hypr/wallpapers/dendritic-network.png", a->home);
        have = load_image(a, hp) == 0;
    }
    for (int i = 0; !have && DEFAULT_PATHS[i]; i++) have = load_image(a, DEFAULT_PATHS[i]) == 0;
    if (a->img) logf_("loaded %dx%d %s", a->iw, a->ih, a->wp_path);
    else log_line("no wallpaper image -- solid background");

    grid_x_init(a->home);
    init_fixed(a);
    if (render_prefix) { a->offscreen = a->no_persist = 1; read_appgate(a); return render_png_selftest(a, render_prefix); }

    a->display = wl_display_connect(NULL);
    if (!a->display) { log_line("no wayland display"); return 1; }
    a->registry = wl_display_get_registry(a->display);
    wl_registry_add_listener(a->registry, &registry_listener, a);
    wl_display_roundtrip(a->display);
    if (!a->compositor || !a->shm || !a->layer_shell) {
        log_line("missing globals (need wlr-layer-shell) -- exiting");
        return 1;   /* harmless on Weston, which offers no zwlr_layer_shell */
    }
    if (!a->wm_base) log_line("no xdg_wm_base -- menus are drawn inside the desktop");
    if (a->layer_shell_ver < 4) log_line("layer-shell < v4 -- no keyboard shortcuts (needs ON_DEMAND)");
    read_appgate(a);
    scan_desktop(a, 1);

    a->surface = wl_compositor_create_surface(a->compositor);
    a->layer_surface = zwlr_layer_shell_v1_get_layer_surface(
        a->layer_shell, a->surface, a->output, ZWLR_LAYER_SHELL_V1_LAYER_BACKGROUND, "wallpaper");
    zwlr_layer_surface_v1_add_listener(a->layer_surface, &layer_listener, a);
    zwlr_layer_surface_v1_set_anchor(a->layer_surface,
        ZWLR_LAYER_SURFACE_V1_ANCHOR_TOP | ZWLR_LAYER_SURFACE_V1_ANCHOR_BOTTOM |
        ZWLR_LAYER_SURFACE_V1_ANCHOR_LEFT | ZWLR_LAYER_SURFACE_V1_ANCHOR_RIGHT);
    zwlr_layer_surface_v1_set_size(a->layer_surface, 0, 0);                   /* 0,0 -> full output */
    zwlr_layer_surface_v1_set_exclusive_zone(a->layer_surface, -1);          /* span under panels */
    /* NONE until clicked (a layer surface that maps interactive grabs the keyboard at map time) */
    zwlr_layer_surface_v1_set_keyboard_interactivity(a->layer_surface, ZWLR_LAYER_SURFACE_V1_KEYBOARD_INTERACTIVITY_NONE);
    /* The input region is left at its default -- the whole surface -- so Hyprland routes pointer
     * events on empty desktop here (vectorToLayerSurface skips surfaces with an empty region). */
    wl_surface_commit(a->surface);                                            /* triggers first configure */
    wl_display_flush(a->display);
    log_line("desktop layer surface committed, awaiting configure");

    int wlfd = wl_display_get_fd(a->display);
    a->next_tick = now_ms() + 2000;
    a->next_gate = now_ms() + 5000;
    while (a->running && !g_quit) {
        while (wl_display_prepare_read(a->display) != 0) wl_display_dispatch_pending(a->display);
        wl_display_flush(a->display);
        long long now = now_ms();
        long long due = a->next_tick;
        if (a->notice[0] && a->notice_until < due) due = a->notice_until;
        if (a->frame_pending && a->frame_ms + 300 < due) due = a->frame_ms + 300;
        if (a->pop.frame_pending && a->pop.frame_ms + 300 < due) due = a->pop.frame_ms + 300;
        if (launches_pending(a) && now + 150 < due) due = now + 150;
        int timeout = due > now ? (int)(due - now) : 0;
        struct pollfd pfd = { .fd = wlfd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, timeout);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            if (wl_display_read_events(a->display) < 0) break;
            wl_display_dispatch_pending(a->display);
        } else {
            wl_display_cancel_read(a->display);
            if (pr < 0 && errno != EINTR) break;
            if (pr > 0 && (pfd.revents & (POLLERR | POLLHUP))) { log_line("compositor hung up"); break; }
        }
        now = now_ms();
        reap_children(a);
        /* Frame callbacks are paced by the compositor; one that never comes (desktop fully covered,
         * or a renderer path that skips it) must not freeze the desktop's redraws. */
        if (a->frame_pending && now - a->frame_ms > 300) {
            if (a->frame_cb) wl_callback_destroy(a->frame_cb);
            a->frame_cb = NULL;
            a->frame_pending = 0;
            if (a->dirty) render_main(a);
        }
        if (a->pop.frame_pending && now - a->pop.frame_ms > 300) {
            if (a->pop.frame_cb) wl_callback_destroy(a->pop.frame_cb);
            a->pop.frame_cb = NULL;
            a->pop.frame_pending = 0;
            if (a->pop.dirty) render_popup(a);
        }
        if (a->notice[0] && now >= a->notice_until) { a->notice[0] = 0; request_redraw(a); }
        if (now >= a->next_tick) {
            a->next_tick = now + 2000;
            if (!a->press && scan_desktop(a, 0)) request_redraw(a);
            if (now >= a->next_gate) { a->next_gate = now + 5000; read_appgate(a); }
        }
    }
    log_line("exiting");
    return 0;
}
