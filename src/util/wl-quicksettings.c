/*
 * wl-quicksettings.c -- a GNOME-43 "Quick Settings" aggregate menu (Wayland + wl_shm + FreeType).
 *
 * A small dark card with:
 *   (1) a Wi-Fi row (active SSID read from /run/wifi/networks; click launches /wl-wifi-menu),
 *   (2) a cosmetic Volume slider (0..100; drag the knob -- there is NO audio mixer backend yet),
 *   (3) a Battery row (AC under QEMU -- no battery backend),
 *   (4) an action row: Settings (launches /wl-domain-manager), Lock, Restart, Power Off, Log Out.
 *       Lock/Restart/Power/Log Out each write a one-line command to /run/session.action.
 *
 * All Wayland scaffolding (registry / seat / xdg / double-buffered wl_shm / FreeType text / evdev keymap /
 * the full v5 wl_pointer listener) is the proven wl-wifi-menu pattern, reused verbatim.  Drawing is
 * fill_rect() + draw_text() only (no cairo); icons/sliders are approximated with filled rectangles.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/reboot.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <wayland-client.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include "xdg-shell-client-protocol.h"

extern char **environ;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum { WIN_W = 320, WIN_H = 536 };

/* --- layout geometry (shared by the renderer and the hit-tester) --- */
enum {
    TITLE_H  = 30,
    CLOSE_Y = 4,  CLOSE_W = 22, CLOSE_H = 22,
    CARD_X   = 12,

    HEADER_Y = 32,  HEADER_H = 76,   /* Q0.2: avatar + user + current domain + identity */

    WIFI_Y   = 112, WIFI_H = 60,
    CLOCK_Y  = 184, CLOCK_H = 64,   /* was the volume slider -- see the note at draw time */
    BAT_Y    = 260, BAT_H  = 52,
    TOPBAR_Y = 320, TOPBAR_H = 44,   /* Hyprland top-bar hide/show toggle */

    ACT_Y    = 376, ACT_H  = 64,   /* four square buttons */
    LOGOUT_Y = 452, LOGOUT_H = 48,

};

/* ROADMAP 3.2: the two horizontal metrics derive from the CURRENT width.
 *
 * They were enum constants baked from WIN_W -- CLOSE_X = WIN_W - 26, CARD_W = WIN_W - 24 -- so at
 * any other width the close button sat away from the corner and every card stopped short of, or
 * ran past, the edge.  Worse than the drawing being wrong: hit_region() shares these values, so
 * the clickable regions would have stayed where the 320px layout put them while the cards moved.
 *
 * Macros over the app pointer rather than fields, so there is exactly one definition and the
 * renderer and hit-tester cannot drift apart.  The VERTICAL stack stays fixed: these are
 * fixed-height rows, and min_size keeps the window tall enough for all of them.
 */
#define CLOSE_X_OF(a) ((a)->width - 26)
#define CARD_W_OF(a)  ((a)->width - 24)

/* clickable regions returned by hit_region() */
enum { R_NONE=0, R_CLOSE, R_WIFI, R_SYSTEM, R_SETTINGS, R_LOCK, R_RESTART, R_POWER, R_LOGOUT,
       R_GEAR,      /* titlebar: main view -> settings view */
       R_BACK };   /* titlebar: settings view -> main view */

/* ROADMAP 3.0b: the settings view's own regions, numbered above every R_* above so the two
 * views' codes cannot collide.  Row i contributes two: the decrement/toggle and the increment. */
enum { R_SET0 = 100 };
#define R_SET_DEC(i) (R_SET0 + (i)*2)
#define R_SET_INC(i) (R_SET0 + (i)*2 + 1)

/* settings-view layout: a header before each section, then fixed-height rows */
enum { V_MAIN = 0, V_SETTINGS = 1 };
enum { SET_TOP = TITLE_H + 8, SEC_H = 24, SROW_H = 36 };

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
    uint32_t *pixels;
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    /* ROADMAP 3.2: the shm mapping (released on resize) and the size the compositor last asked
     * for, applied on the next xdg_surface.configure. */
    unsigned char *map_base; size_t map_total;
    int pending_width, pending_height;
    int font_ready, running;
    double pointer_x, pointer_y;

    /* content state */
    char active_ssid[64];
    int  wifi_connected;
    char user[48], domain[48], identity[48];  /* Q0.2 header (domain/identity-aware) */
    int  cpu_pct, mem_pct;                     /* Q2.4 live system stats */
    char ip[24];
    unsigned long long cpu_prev_total, cpu_prev_idle;
    /* No volume/dragging state: there is no audio backend, so there was nothing to hold. */
    int  hover;             /* hovered region for highlight (R_*) */
    int  view;              /* V_MAIN or V_SETTINGS (ROADMAP 3.0b) */
    int  sel;               /* settings view: keyboard-selected row */
    unsigned last_hash;
};

static void log_line(const char *s){ fputs(s, stdout); fputc('\n', stdout); fflush(stdout); }

/* ── ROADMAP 3.0b: the input/appearance configuration backend ──────────────────────────────────
 *
 * 3.0b was blocked as "four panels of controls that change nothing", and that was the honest
 * state: input and theme settings lived only in system/hypr/custom/general.lua, which is baked
 * into the image at build time, so a running desktop had no way to change them.
 *
 * Hyprland already exposes one: the same IPC socket hyprctl talks to.  Writing
 * "keyword input:sensitivity 0.4" to it applies the setting live, exactly as editing the config
 * and reloading would.  The wire format is the bare command with no framing (see
 * hyprland/hyprtester/src/hyprctlCompat.cpp) and the reply is "ok" on success.
 *
 * Finding the socket is the one wrinkle.  hyprctl locates it via HYPRLAND_INSTANCE_SIGNATURE,
 * and this kernel does not export that variable, so instead we enumerate /run/user/1000/hypr and
 * take the single instance directory -- there is exactly one compositor on this system, which is
 * a safe assumption here and would not be on a multi-seat desktop.
 */
#define HYPR_DIR "/run/user/1000/hypr"

static int hypr_socket_path(char *out, size_t cap)
{
    DIR *d = opendir(HYPR_DIR);
    if (!d) return -1;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;          /* skip . and .. */
        snprintf(out, cap, HYPR_DIR "/%s/.socket.sock", e->d_name);
        found = 1;
        break;                                       /* exactly one instance */
    }
    closedir(d);
    return found ? 0 : -1;
}

/* Send one hyprctl command.  Returns 0 if Hyprland accepted it.
 * reply may be NULL when the caller only cares whether it worked. */
static int hypr_ipc(const char *cmd, char *reply, size_t replycap)
{
    char path[256];
    if (hypr_socket_path(path, sizeof path) < 0) return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, path, sizeof sa.sun_path - 1);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(fd); return -1; }

    size_t len = strlen(cmd);
    if (write(fd, cmd, len) != (ssize_t)len) { close(fd); return -1; }

    char buf[256];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n > 0 ? n : 0] = 0;
    if (reply && replycap) { strncpy(reply, buf, replycap - 1); reply[replycap-1] = 0; }
    /* Hyprland answers "ok" for an accepted keyword; anything else is its error text. */
    return (n >= 2 && buf[0] == 'o' && buf[1] == 'k') ? 0 : -1;
}

/* --- ROADMAP 3.0b: the settings model -------------------------------------------------------
 *
 * Ten rows over four sections, each one a Hyprland keyword.  A change does two things:
 *
 *   LIVE     hypr_ipc("keyword <kw> <v>")  -- takes effect immediately, no restart.
 *   PERSIST  two files under /home, which `persist = /home` (src/desktop.conf) keeps across
 *            reboots.  settings.conf is the source of truth this app reads back; settings.lua
 *            is GENERATED from it and require()d last by hyprland.lua, so Hyprland re-applies
 *            the same values at every boot without this app having to run.
 *
 * What is deliberately NOT offered:
 *
 *   input:sensitivity / accel_profile.  custom/general.lua pins these to flat + 0 and explains
 *   why at length: two cursors exist here -- the kernel paints its own into the framebuffer and
 *   the compositor tracks the evdev stream separately -- and any acceleration curve makes them
 *   drift, so clicks land where the user is not pointing.  A pointer-speed slider would be a
 *   control that breaks aiming, so the row says so instead of offering it.
 *
 *   decoration:rounding.  Also pinned in general.lua, and for a measured reason: rounding is a
 *   per-fragment SDF, and on softpipe without LLVM that took the desktop to roughly one frame
 *   per second.  Exposing it would let the user make the machine unusable from inside a
 *   settings panel.
 */
enum { ST_INT, ST_BOOL, ST_NOTE };
enum { S_KB_RATE, S_KB_DELAY, S_M_NATSCROLL, S_M_FOLLOW, S_NOTE_SPEED,
       S_TP_TAP, S_TP_NATSCROLL, S_TP_DWT, S_A_BORDER, S_A_GAPS, S_COUNT };

struct setting_def {
    const char *section;   /* non-NULL: this row starts a new section, with this header */
    const char *label;
    const char *key;       /* name in settings.conf */
    const char *keyword;   /* hyprctl keyword path */
    int kind, lo, hi, step, def;
    const char *note;      /* ST_NOTE only */
};

static const struct setting_def SETTINGS[S_COUNT] = {
 [S_KB_RATE]      = { "Keyboard",   "Repeat rate",          "kb_rate",     "input:repeat_rate",
                      ST_INT,  10, 60,  5,  25, NULL },
 [S_KB_DELAY]     = { NULL,         "Repeat delay",         "kb_delay",    "input:repeat_delay",
                      ST_INT, 200,1000, 50, 600, NULL },
 [S_M_NATSCROLL]  = { "Mouse",      "Natural scroll",       "m_natscroll", "input:natural_scroll",
                      ST_BOOL, 0, 1, 1, 0, NULL },
 [S_M_FOLLOW]     = { NULL,         "Focus follows mouse",  "m_follow",    "input:follow_mouse",
                      ST_BOOL, 0, 1, 1, 1, NULL },
 [S_NOTE_SPEED]   = { NULL,         "Pointer speed",        NULL,          NULL,
                      ST_NOTE, 0, 0, 0, 0, "Locked 1:1 -- keeps the two cursors aligned" },
 [S_TP_TAP]       = { "Touchpad",   "Tap to click",         "tp_tap",      "input:touchpad:tap-to-click",
                      ST_BOOL, 0, 1, 1, 1, NULL },
 [S_TP_NATSCROLL] = { NULL,         "Natural scroll",       "tp_natscroll","input:touchpad:natural_scroll",
                      ST_BOOL, 0, 1, 1, 1, NULL },
 [S_TP_DWT]       = { NULL,         "Disable while typing", "tp_dwt",      "input:touchpad:disable_while_typing",
                      ST_BOOL, 0, 1, 1, 1, NULL },
 [S_A_BORDER]     = { "Appearance", "Border size",          "a_border",    "general:border_size",
                      ST_INT, 0, 8, 1, 2, NULL },
 [S_A_GAPS]       = { NULL,         "Window gaps",          "a_gaps",      "general:gaps_out",
                      ST_INT, 0, 30, 2, 5, NULL },
};

static int g_setval[S_COUNT];

/* Hyprland's answer to the last keyword sent -- "ok", or its error text.  Shown in the footer
 * because this app is forked by Hyprland and inherits no console, so a reply that is only
 * logged cannot be read.  It is also the honest thing to surface: the panel should say what the
 * compositor said, not assume it agreed. */
static char g_last_ipc[96] = "";

#define SETTINGS_DIR  "/home/user/.config/hos"
#define SETTINGS_CONF SETTINGS_DIR "/settings.conf"
#define HYPR_CUSTOM   "/home/user/.config/hypr/custom"
#define SETTINGS_LUA  HYPR_CUSTOM "/settings.lua"

/* mkdir -p, without a shell (there is no /bin/sh in this image). */
static void mkdir_p(const char *path)
{
    char tmp[256];
    size_t n = strlen(path);
    if (n >= sizeof tmp) return;
    memcpy(tmp, path, n + 1);
    for (char *p = tmp + 1; *p; p++)
        if (*p == '/') { *p = 0; mkdir(tmp, 0755); *p = '/'; }
    mkdir(tmp, 0755);
}

static const char *bool_word(int v){ return v ? "true" : "false"; }

/* Emit the Lua that Hyprland reads at startup.  Values only -- no logic -- so a corrupt or
 * half-written file can at worst restore defaults, never break the config chain. */
static void settings_write_lua(void)
{
    mkdir_p(HYPR_CUSTOM);
    FILE *f = fopen(SETTINGS_LUA, "w");
    if (!f) return;
    fprintf(f,
        "-- GENERATED by wl-quicksettings (ROADMAP 3.0b).  Edits here are overwritten.\n"
        "-- hyprland.lua require()s this LAST, so it wins over custom/general.lua.\n"
        "hl.config({\n"
        "    input = {\n"
        "        repeat_rate    = %d,\n"
        "        repeat_delay   = %d,\n"
        "        natural_scroll = %s,\n"
        "        follow_mouse   = %d,\n"
        "        touchpad = {\n"
        "            [\"tap-to-click\"]    = %s,\n"
        "            natural_scroll       = %s,\n"
        "            disable_while_typing = %s\n"
        "        }\n"
        "    },\n"
        "    general = {\n"
        "        border_size = %d,\n"
        "        gaps_out    = %d\n"
        "    }\n"
        "})\n",
        g_setval[S_KB_RATE], g_setval[S_KB_DELAY],
        bool_word(g_setval[S_M_NATSCROLL]), g_setval[S_M_FOLLOW],
        bool_word(g_setval[S_TP_TAP]), bool_word(g_setval[S_TP_NATSCROLL]),
        bool_word(g_setval[S_TP_DWT]),
        g_setval[S_A_BORDER], g_setval[S_A_GAPS]);
    fclose(f);
}

static void settings_save(void)
{
    mkdir_p(SETTINGS_DIR);
    FILE *f = fopen(SETTINGS_CONF, "w");
    if (f) {
        for (int i = 0; i < S_COUNT; i++)
            if (SETTINGS[i].key) fprintf(f, "%s=%d\n", SETTINGS[i].key, g_setval[i]);
        fclose(f);
    }
    settings_write_lua();
}

/* Returns 1 if a saved file was read, 0 if defaults were used. */
static int settings_load(void)
{
    for (int i = 0; i < S_COUNT; i++) g_setval[i] = SETTINGS[i].def;
    FILE *f = fopen(SETTINGS_CONF, "r");
    if (!f) return 0;
    char line[128];
    while (fgets(line, sizeof line, f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        int v = atoi(eq + 1);
        for (int i = 0; i < S_COUNT; i++)
            if (SETTINGS[i].key && !strcmp(SETTINGS[i].key, line)) {
                if (v < SETTINGS[i].lo) v = SETTINGS[i].lo;      /* a hand-edited file must not */
                if (v > SETTINGS[i].hi) v = SETTINGS[i].hi;      /* be able to push a bad value */
                g_setval[i] = v;
                break;
            }
    }
    fclose(f);
    return 1;
}

/* Push one setting to the running compositor. */
static int settings_apply_one(int i)
{
    const struct setting_def *s = &SETTINGS[i];
    if (!s->keyword) return 0;
    char cmd[160];
    if (s->kind == ST_BOOL && i != S_M_FOLLOW)     /* follow_mouse is an int 0..3, not a bool */
        snprintf(cmd, sizeof cmd, "keyword %s %s", s->keyword, bool_word(g_setval[i]));
    else
        snprintf(cmd, sizeof cmd, "keyword %s %d", s->keyword, g_setval[i]);
    int rc = hypr_ipc(cmd, g_last_ipc, sizeof g_last_ipc);
    if (!g_last_ipc[0]) snprintf(g_last_ipc, sizeof g_last_ipc, "no reply (socket?)");
    for (char *p = g_last_ipc; *p; p++) if (*p == '\n') *p = ' ';   /* keep the footer one line */
    return rc;
}

static void settings_apply_all(void)
{
    for (int i = 0; i < S_COUNT; i++) settings_apply_one(i);
}
static int create_memfd(const char *name){ return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC); }

static int load_file(const char *path, unsigned char **out, size_t *out_size){
    int fd = open(path, O_RDONLY); if (fd < 0) return -1;
    size_t cap = 8192, n = 0; unsigned char *b = malloc(cap);
    if (!b){ close(fd); return -1; }
    for (;;){ if (n + 4096 > cap){ cap *= 2; unsigned char *nb = realloc(b, cap); if (!nb){ free(b); close(fd); return -1; } b = nb; }
        ssize_t r = read(fd, b + n, 4096); if (r <= 0) break; n += (size_t)r; }
    close(fd); *out = b; *out_size = n; return 0;
}
static int init_freetype(struct app *app){
    const char *path = "/usr/share/fonts/noto/NotoSans-Regular.ttf";
    if (load_file(path, &app->font_data, &app->font_size) < 0) return -1;
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
/* Q1: rounded-rect fill (corner pixels outside radius r are skipped -> GNOME-style rounded tiles).
 * Same O(w*h) cost as fill_rect; on this small card it is negligible.  Real anti-aliasing + translucency
 * come with the cairo renderer (roadmap Q1.1) once a build loop is available. */
static void fill_round_rect(struct app *app, int x, int y, int w, int h, int r, uint32_t c){
    if (r < 0) r = 0;
    if (r*2 > w) r = w/2;
    if (r*2 > h) r = h/2;
    int r2 = r*r;
    for (int j=0;j<h;j++){ int py=y+j; if (py<0||py>=app->height) continue;
        for (int i=0;i<w;i++){ int px=x+i; if (px<0||px>=app->width) continue;
            int cx=-1, cy=-1;
            if      (i<r     && j<r)     { cx=r;     cy=r;     }
            else if (i>=w-r  && j<r)     { cx=w-r-1; cy=r;     }
            else if (i<r     && j>=h-r)  { cx=r;     cy=h-r-1; }
            else if (i>=w-r  && j>=h-r)  { cx=w-r-1; cy=h-r-1; }
            if (cx>=0){ int dx=i-cx, dy=j-cy; if (dx*dx+dy*dy > r2) continue; }
            app->pixels[py*app->width+px]=c; } }
}

/* --- data: active Wi-Fi SSID from /run/wifi/networks (header '#dev...', rows SSID\tSTR\tSEC\tACTIVE\tPATH) --- */
static unsigned fnv1a(const unsigned char *b, size_t n){ unsigned h=2166136261u; for (size_t i=0;i<n;i++){ h^=b[i]; h*=16777619u; } return h; }

static void load_wifi(struct app *app){
    unsigned char *buf; size_t sz;
    app->active_ssid[0] = 0; app->wifi_connected = 0;
    if (load_file("/run/wifi/networks", &buf, &sz) < 0) return;
    char *p = (char*)buf; char *end = (char*)buf + sz;
    while (p < end){
        char *nl = memchr(p, '\n', (size_t)(end-p)); if (!nl) nl = end;
        *nl = 0;
        if (p[0] && p[0] != '#'){
            char *f[5]; int nf=0; char *s=p;
            for (char *q=p; q<=nl && nf<5; q++){ if (*q=='\t'||q==nl){ *q=0; f[nf++]=s; s=q+1; } }
            if (nf >= 4){
                char *a = f[3];
                if (a[0]=='1' || a[0]=='y' || a[0]=='Y' || a[0]=='*'){
                    strncpy(app->active_ssid, f[0], sizeof(app->active_ssid)-1);
                    app->active_ssid[sizeof(app->active_ssid)-1]=0;
                    app->wifi_connected = 1;
                    break;
                }
            }
        }
        p = nl + 1;
    }
    free(buf);
}

/* --- Q0.2: current user / domain / identity for the header.  Reads optional one-line /run markers if a
 * session/Domain-Manager daemon publishes them; falls back to sensible defaults otherwise.  Q2.3 wires
 * the real Domain Manager / identity.d source (switch-domain, capability set, sandbox state). --- */
static void read_line_file(const char *path, char *out, size_t cap){
    out[0] = 0;
    unsigned char *buf; size_t sz;
    if (load_file(path, &buf, &sz) < 0) return;
    size_t n = 0;
    while (n < sz && n + 1 < cap && buf[n] != '\n' && buf[n] != '\r'){ out[n] = (char)buf[n]; n++; }
    out[n] = 0;
    free(buf);
}
static void load_identity(struct app *app){
    read_line_file("/run/session.user",    app->user,     sizeof app->user);
    read_line_file("/run/domain.current",  app->domain,   sizeof app->domain);
    read_line_file("/run/identity.current", app->identity, sizeof app->identity);
    if (!app->user[0]){ const char *u = getenv("USER");
        if (u){ strncpy(app->user, u, sizeof(app->user)-1); app->user[sizeof(app->user)-1] = 0; } }
}

/* Q2.4: live system stats. read_small() null-terminates (load_file does not), so strstr/strtoull are
 * safe.  CPU% is a delta across ticks (needs the previous sample), so load_stats runs every ~1s. */
static int read_small(const char *path, char *out, size_t cap){
    int fd = open(path, O_RDONLY); if (fd < 0) return -1;
    ssize_t n = read(fd, out, cap - 1); close(fd);
    if (n < 0) n = 0; out[n] = 0; return (int)n;
}
static void load_stats(struct app *app){
    char b[4096];
    if (read_small("/proc/stat", b, sizeof b) > 0 && !strncmp(b, "cpu", 3)){
        char *p = b + 3;
        unsigned long long v[10]; int nv = 0;
        while (nv < 10){ while (*p==' '||*p=='\t') p++; if (*p<'0'||*p>'9') break; v[nv++] = strtoull(p, &p, 10); }
        unsigned long long total = 0; for (int i=0;i<nv;i++) total += v[i];
        unsigned long long idle = (nv>4) ? v[3]+v[4] : (nv>3 ? v[3] : 0);
        unsigned long long dt = total - app->cpu_prev_total, di = idle - app->cpu_prev_idle;
        if (app->cpu_prev_total && dt > 0){ int pct = (int)((100*(dt-di))/dt); app->cpu_pct = pct<0?0:(pct>100?100:pct); }
        app->cpu_prev_total = total; app->cpu_prev_idle = idle;
    }
    if (read_small("/proc/meminfo", b, sizeof b) > 0){
        char *mt = strstr(b, "MemTotal:"), *ma = strstr(b, "MemAvailable:");
        unsigned long long total = mt ? strtoull(mt+9, NULL, 10) : 0;
        unsigned long long avail = ma ? strtoull(ma+13, NULL, 10) : 0;
        if (total > 0){ int pct = (int)((100*(total-avail))/total); app->mem_pct = pct<0?0:(pct>100?100:pct); }
    }
    read_line_file("/run/wifi/dhcp-ok", app->ip, sizeof app->ip);
}

/* Q0.3: publish panel state to /run/quicksettings.state so the object FS can surface it as
 * /objects/desktop/quicksettings (the kernel-side /objects view is a follow-up).  Written at startup
 * and whenever the live state changes. */
static void publish_state(struct app *app){
    mkdir("/run", 0755);
    int fd = open("/run/quicksettings.state", O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) return;
    char b[320];
    int n = snprintf(b, sizeof b,
        "user=%s\ndomain=%s\nidentity=%s\nwifi=%s\nssid=%s\ncpu=%d\nmem=%d\nip=%s\n",
        app->user[0]?app->user:"user",
        app->domain[0]?app->domain:"Personal",
        app->identity[0]?app->identity:"Default",
        app->wifi_connected?"on":"off",
        app->active_ssid,
        app->cpu_pct, app->mem_pct, app->ip[0]?app->ip:"none");
    if (n > 0) (void)!write(fd, b, (size_t)n);
    close(fd);
}

/* --- fork a Wayland client; close all fds>2 in the child or the socket leaks and the window lingers --- */
static void launch(const char *path){
    pid_t pid = fork();
    if (pid == 0){
        for (int fd=3; fd<64; fd++) close(fd);
        setsid();
        char *argv[] = { (char*)path, NULL };
        execve(path, argv, environ);
        _exit(127);
    }
}
/* --- session command --- write a one-line marker to /run/session.action (for lock/logout, which
 * a future session daemon will consume) AND, for restart/poweroff, ask the kernel directly via
 * reboot(2).  reboot() is cap-gated (needs CAP_RIGHT_ADMIN_REBOOT), so it only powers off/restarts
 * for a privileged console session — the kernel's capability model decides; a denied call is a
 * no-op EPERM and the desktop keeps running. --- */
static void session_action(const char *cmd){
    mkdir("/run", 0755);
    int fd = open("/run/session.action", O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd >= 0){ char line[32]; int n = snprintf(line, sizeof line, "%s\n", cmd);
        (void)!write(fd, line, n); close(fd); }
    char m[64]; snprintf(m, sizeof m, "QSETTINGS: session '%s'", cmd); log_line(m);
    if      (!strcmp(cmd, "poweroff")) reboot(RB_POWER_OFF);   /* LINUX_REBOOT_CMD_POWER_OFF */
    else if (!strcmp(cmd, "reboot"))   reboot(RB_AUTOBOOT);    /* LINUX_REBOOT_CMD_RESTART   */
}

/* --- hit-testing: which region is under (px,py)? --- */
/* Takes the app because the button pitch derives from the current card width (ROADMAP 3.2). */
static void act_btn_rect(struct app *app, int i, int *x, int *y, int *w, int *h){
    int bw = (CARD_W_OF(app) - 3*8) / 4;            /* four buttons, three 8px gaps */
    *x = CARD_X + i*(bw+8); *y = ACT_Y; *w = bw; *h = ACT_H;
}
static int in_rect(double px, double py, int x, int y, int w, int h){
    return px>=x && px<x+w && py>=y && py<y+h;
}

/* ROADMAP 3.0b: settings-view geometry.  Defined once and shared by the renderer and the
 * hit-tester, for the reason the 3.2 CARD_W_OF()/CLOSE_X_OF() macros exist: when the two
 * compute their rectangles separately they drift, and the clickable area stops matching what
 * is drawn. */
#define GEAR_X_OF(a) ((a)->width - 52)
enum { GEAR_Y = CLOSE_Y, GEAR_W = CLOSE_W, GEAR_H = CLOSE_H };

/* Top of row `idx`, counting the section headers above it. */
static int setting_row_y(int idx){
    int y = SET_TOP;
    for (int i = 0; i <= idx; i++){
        if (SETTINGS[i].section) y += SEC_H;
        if (i < idx)             y += SROW_H;
    }
    return y;
}
/* Control rects on row idx: which=0 is [-] or the toggle pill, which=1 is [+]. */
static void setting_ctl_rect(struct app *app, int idx, int which, int *x, int *y, int *w, int *h){
    int ry = setting_row_y(idx);
    if (SETTINGS[idx].kind == ST_BOOL){
        *w = 46; *h = 22;
        *x = CARD_X + CARD_W_OF(app) - 12 - *w; *y = ry + (SROW_H - 6 - *h)/2;
    } else {
        /* centred on the CARD (SROW_H-6 tall), not on the row pitch -- the 6px is the gap
         * between cards, and counting it would sit every control 3px low. */
        *w = 24; *h = 24; *y = ry + (SROW_H - 6 - *h)/2;
        int px = CARD_X + CARD_W_OF(app) - 12 - *w;
        *x = which ? px : px - 4 - *w;
    }
}
static int hit_settings_region(struct app *app, double px, double py){
    if (in_rect(px,py,CLOSE_X_OF(app),CLOSE_Y,CLOSE_W,CLOSE_H)) return R_CLOSE;
    if (in_rect(px,py,GEAR_X_OF(app),GEAR_Y,GEAR_W,GEAR_H))     return R_BACK;
    for (int i=0;i<S_COUNT;i++){
        if (SETTINGS[i].kind == ST_NOTE) continue;
        int x,y,w,h;
        setting_ctl_rect(app,i,0,&x,&y,&w,&h);
        if (in_rect(px,py,x,y,w,h)) return R_SET_DEC(i);
        if (SETTINGS[i].kind == ST_INT){
            setting_ctl_rect(app,i,1,&x,&y,&w,&h);
            if (in_rect(px,py,x,y,w,h)) return R_SET_INC(i);
        }
    }
    return R_NONE;
}
static int hit_region(struct app *app, double px, double py){
    if (app->view == V_SETTINGS) return hit_settings_region(app, px, py);
    if (in_rect(px,py,CLOSE_X_OF(app),CLOSE_Y,CLOSE_W,CLOSE_H)) return R_CLOSE;
    if (in_rect(px,py,GEAR_X_OF(app),GEAR_Y,GEAR_W,GEAR_H))     return R_GEAR;
    if (in_rect(px,py,CARD_X,WIFI_Y,CARD_W_OF(app),WIFI_H))     return R_WIFI;
    if (in_rect(px,py,CARD_X,TOPBAR_Y,CARD_W_OF(app),TOPBAR_H)) return R_SYSTEM;
    static const int reg[4] = { R_SETTINGS, R_LOCK, R_RESTART, R_POWER };
    for (int i=0;i<4;i++){ int bx,by,bw,bh; act_btn_rect(app,i,&bx,&by,&bw,&bh);
        if (in_rect(px,py,bx,by,bw,bh)) return reg[i]; }
    if (in_rect(px,py,CARD_X,LOGOUT_Y,CARD_W_OF(app),LOGOUT_H)) return R_LOGOUT;
    return R_NONE;
}

/* --- glyph approximations (fill_rect only) --- */
static void draw_wifi_glyph(struct app *app, int x, int y, uint32_t on){
    /* four rising signal bars */
    for (int b=0;b<4;b++){ int bh = 4 + b*4; fill_rect(app, x + b*5, y + (16-bh), 3, bh, on); }
}
static void draw_battery_glyph(struct app *app, int x, int y, uint32_t on, uint32_t fillc){
    fill_rect(app, x, y+2, 26, 14, on);           /* body outline */
    fill_rect(app, x+1, y+3, 24, 12, 0xff232834u);/* interior */
    fill_rect(app, x+26, y+6, 2, 6, on);          /* nub */
    fill_rect(app, x+2, y+4, 22, 10, fillc);      /* charge (full on AC) */
}

/* --- rendering --- */
/* --- ROADMAP 3.0b: the settings view ---
 *
 * Same renderer primitives as the main view (fill_rect / fill_round_rect / draw_text), and the
 * rectangles come from setting_ctl_rect(), which the hit-tester also calls.  A row past the
 * bottom edge is skipped rather than clipped: min_size keeps the window tall enough for the
 * whole stack, so this only fires if a compositor ignores that. */
static void draw_settings(struct app *app){
    const uint32_t BG=0xff1b1f27u, TITLE=0xff11141bu, ROW=0xff232834u, ROWH=0xff2d3444u,
                   TXT=0xfff2f5fau, DIM=0xff8b94a3u, ACC=0xff4da3ffu,
                   BTN=0xff2a3140u, OFF=0xff3a4250u, CLOSEC=0xffe0564au;
    fill_rect(app, 0, 0, app->width, app->height, BG);

    fill_rect(app, 0, 0, app->width, TITLE_H, TITLE);
    draw_text(app, "Settings", 14, 7, 200, 15, TXT);
    draw_text(app, "arrows move  -/+ change  Esc back", 96, 10, 240, 10, DIM);
    fill_rect(app, GEAR_X_OF(app), GEAR_Y, GEAR_W, GEAR_H, (app->hover==R_BACK)?ROWH:BTN);
    draw_text(app, "<", GEAR_X_OF(app)+8, GEAR_Y+3, 16, 14, TXT);
    fill_rect(app, CLOSE_X_OF(app), CLOSE_Y, CLOSE_W, CLOSE_H, (app->hover==R_CLOSE)?CLOSEC:ROWH);
    draw_text(app, "x", CLOSE_X_OF(app)+7, CLOSE_Y+3, 16, 14, TXT);

    for (int i=0;i<S_COUNT;i++){
        const struct setting_def *s = &SETTINGS[i];
        int ry = setting_row_y(i);
        if (ry + SROW_H > app->height) break;
        if (s->section) draw_text(app, s->section, CARD_X+2, ry-SEC_H+4, 200, 12, ACC);
        int selected = (i == app->sel);
        fill_round_rect(app, CARD_X, ry, CARD_W_OF(app), SROW_H-6, 10, selected ? ROWH : ROW);
        if (selected) fill_rect(app, CARD_X, ry+4, 3, SROW_H-14, ACC);   /* keyboard cursor */

        if (s->kind == ST_NOTE){
            draw_text(app, s->label, CARD_X+12, ry+3,  CARD_W_OF(app)-24, 12, DIM);
            draw_text(app, s->note,  CARD_X+12, ry+16, CARD_W_OF(app)-24, 11, DIM);
            continue;
        }
        draw_text(app, s->label, CARD_X+12, ry+8, CARD_W_OF(app)-130, 13, TXT);

        int x,y,w,h;
        if (s->kind == ST_BOOL){
            int on = g_setval[i];
            setting_ctl_rect(app, i, 0, &x, &y, &w, &h);
            fill_round_rect(app, x, y, w, h, h/2, on ? ACC : OFF);
            fill_round_rect(app, on ? (x+w-h+2) : (x+2), y+2, h-4, h-4, (h-4)/2, TXT);
        } else {
            char v[16]; snprintf(v, sizeof v, "%d", g_setval[i]);
            setting_ctl_rect(app, i, 0, &x, &y, &w, &h);
            draw_text(app, v, x-44, y+5, 40, 13, TXT);
            fill_round_rect(app, x, y, w, h, 6, (app->hover==R_SET_DEC(i))?ROWH:BTN);
            draw_text(app, "-", x+9, y+4, 16, 14, TXT);
            setting_ctl_rect(app, i, 1, &x, &y, &w, &h);
            fill_round_rect(app, x, y, w, h, 6, (app->hover==R_SET_INC(i))?ROWH:BTN);
            draw_text(app, "+", x+8, y+4, 16, 14, TXT);
        }
    }

    /* Footer: the persistence state, READ BACK from disk rather than remembered.  It tells the
     * user their settings will outlive the session, and it is the only way to see that the two
     * files were actually written -- this app is forked by Hyprland and so has no console, which
     * is what made a log line useless for the same question during 3.0b. */
    {
        char foot[128]; struct stat sc, sl;
        int okc = (stat(SETTINGS_CONF, &sc) == 0), okl = (stat(SETTINGS_LUA, &sl) == 0);
        if (okc && okl)
            snprintf(foot, sizeof foot, "Saved: settings.conf %ldB + settings.lua %ldB",
                     (long)sc.st_size, (long)sl.st_size);
        else if (okc || okl)
            snprintf(foot, sizeof foot, "Partly saved: conf %s, lua %s",
                     okc ? "ok" : "MISSING", okl ? "ok" : "MISSING");
        else
            snprintf(foot, sizeof foot, "Defaults -- nothing saved yet");
        draw_text(app, foot, CARD_X+2, app->height-20, CARD_W_OF(app), 11, DIM);
        if (g_last_ipc[0]){
            char rep[160];
            snprintf(rep, sizeof rep, "hyprland: %s", g_last_ipc);
            draw_text(app, rep, CARD_X+2, app->height-34, CARD_W_OF(app), 11, DIM);
        }
    }
}

static void draw_menu(struct app *app){
    if (app->view == V_SETTINGS){ draw_settings(app); return; }
    const uint32_t BG=0xff1b1f27u, TITLE=0xff11141bu, ROW=0xff232834u, ROWH=0xff2d3444u,
                   TXT=0xfff2f5fau, DIM=0xff8b94a3u, ACC=0xff4da3ffu,
                   OK=0xff57d977u, DANGER=0xffe0564au, CLOSEC=0xffe0564au;
    fill_rect(app, 0, 0, app->width, app->height, BG);

    /* --- CSD titlebar --- */
    fill_rect(app, 0, 0, app->width, TITLE_H, TITLE);
    draw_text(app, "System", 14, 7, 200, 15, TXT);
    fill_rect(app, CLOSE_X_OF(app), CLOSE_Y, CLOSE_W, CLOSE_H, (app->hover==R_CLOSE)?CLOSEC:ROWH);
    draw_text(app, "x", CLOSE_X_OF(app)+7, CLOSE_Y+3, 16, 14, TXT);
    /* ROADMAP 3.0b: the gear, left of the close button -- opens the settings view.  It is in
     * the titlebar rather than the button row because the four buttons there are session
     * actions (Domains/Lock/Restart/Power) and none of them could be given up. */
    fill_rect(app, GEAR_X_OF(app), GEAR_Y, GEAR_W, GEAR_H, (app->hover==R_GEAR)?ROWH:0xff2a3140u);
    for (int r=0;r<3;r++){                       /* three sliders, drawn with fill_rect like every icon here */
        int gy = GEAR_Y + 6 + r*5;
        fill_rect(app, GEAR_X_OF(app)+4, gy, 14, 2, TXT);
        fill_rect(app, GEAR_X_OF(app)+4 + (r==1?9:4), gy-1, 3, 4, ACC);
    }

    /* --- Q0.2 identity header: avatar + username + current domain + current identity --- */
    {
        fill_round_rect(app, CARD_X, HEADER_Y, CARD_W_OF(app), HEADER_H, 14, ROW);
        int asz = 52, ax = CARD_X+8, ay = HEADER_Y+(HEADER_H-asz)/2;
        fill_round_rect(app, ax, ay, asz, asz, asz/2, ACC);    /* circular avatar */
        char initial[2]; initial[0] = app->user[0] ? (char)(app->user[0] & ~0x20) : 'U'; initial[1] = 0;
        draw_text(app, initial, ax+asz/2-8, ay+asz/2-14, asz, 26, TITLE);
        int tx = ax + asz + 14, tw = CARD_X+CARD_W_OF(app) - (ax+asz+14) - 10;
        draw_text(app, app->user[0] ? app->user : "user", tx, HEADER_Y+12, tw, 16, TXT);
        char dl[80]; snprintf(dl, sizeof dl, "Domain:   %s", app->domain[0]   ? app->domain   : "Personal");
        draw_text(app, dl, tx, HEADER_Y+36, tw, 12, DIM);
        char il[80]; snprintf(il, sizeof il, "Identity: %s", app->identity[0] ? app->identity : "Default");
        draw_text(app, il, tx, HEADER_Y+54, tw, 12, DIM);
    }

    /* --- Wi-Fi row --- */
    fill_round_rect(app, CARD_X, WIFI_Y, CARD_W_OF(app), WIFI_H, 12, (app->hover==R_WIFI)?ROWH:ROW);
    draw_wifi_glyph(app, CARD_X+14, WIFI_Y+14, app->wifi_connected?ACC:DIM);
    draw_text(app, "Wi-Fi", CARD_X+48, WIFI_Y+9, 160, 15, TXT);
    draw_text(app, app->wifi_connected ? app->active_ssid : "Not connected",
              CARD_X+48, WIFI_Y+31, CARD_W_OF(app)-64, 12, app->wifi_connected?OK:DIM);
    /* --- Date & time row ---
     *
     * This is where the Volume slider used to be.  That slider was draggable, showed a filled
     * track and a knob, published volume=N to /run/quicksettings.state -- and changed nothing:
     * this image has no audio driver and no mixer, as the file header said all along.  A control
     * that looks live and is inert is worse than an absent one, so it is gone rather than greyed
     * out; the row returns when Tier 5 (audio driver + PipeWire) lands, and nothing read the
     * volume key.  A clock is real, needs no backend, and is on the Tier 1 list. */
    fill_round_rect(app, CARD_X, CLOCK_Y, CARD_W_OF(app), CLOCK_H, 12, ROW);
    {
        time_t now = time(NULL);
        struct tm tmv, *tmp = localtime_r(&now, &tmv);
        char hhmm[16] = "--:--", date[64] = "date unavailable";
        if (tmp) {
            strftime(hhmm, sizeof hhmm, "%H:%M", tmp);
            strftime(date, sizeof date, "%A, %e %B %Y", tmp);
        }
        draw_text(app, hhmm, CARD_X+16, CLOCK_Y+8,  120, 22, TXT);
        draw_text(app, date, CARD_X+16, CLOCK_Y+36, CARD_W_OF(app)-32, 12, DIM);
    }


    /* --- Battery row --- */
    fill_round_rect(app, CARD_X, BAT_Y, CARD_W_OF(app), BAT_H, 12, ROW);
    draw_battery_glyph(app, CARD_X+14, BAT_Y+16, DIM, OK);
    draw_text(app, "Battery", CARD_X+52, BAT_Y+9, 160, 15, TXT);
    /* QEMU exposes no battery, and there is no ACPI battery backend, so this is a statement
     * of fact rather than a reading.  It must not render as a charge percentage. */
    draw_text(app, "On AC power", CARD_X+52, BAT_Y+31, 160, 12, DIM);

    /* --- Q2.4 System row: live CPU / RAM / IP (click -> /wl-sysmon) --- */
    {
        fill_round_rect(app, CARD_X, TOPBAR_Y, CARD_W_OF(app), TOPBAR_H, 12, (app->hover==R_SYSTEM)?ROWH:ROW);
        draw_text(app, "System", CARD_X+16, TOPBAR_Y+5, 120, 14, TXT);
        char sl[96];
        snprintf(sl, sizeof sl, "CPU %d%%   RAM %d%%   %s",
                 app->cpu_pct, app->mem_pct, app->ip[0] ? app->ip : "no IP");
        draw_text(app, sl, CARD_X+16, TOPBAR_Y+24, CARD_W_OF(app)-24, 12, DIM);
    }

    /* --- action buttons (Settings / Lock / Restart / Power) --- */
    /* "Domains", not "Settings": the launcher now has a Settings tile (this app) and a separate
     * Domains tile, so a Settings button here that opens the domain manager would contradict it. */
    static const char *labels[4] = { "Domains", "Lock", "Restart", "Power" };
    static const int   reg[4]    = { R_SETTINGS, R_LOCK, R_RESTART, R_POWER };
    for (int i=0;i<4;i++){
        int bx,by,bw,bh; act_btn_rect(app,i,&bx,&by,&bw,&bh);
        int hot = (app->hover==reg[i]);
        uint32_t bc = (i==3) ? (hot?DANGER:0xff3a2530u) : (hot?ROWH:0xff2a3140u);
        fill_round_rect(app, bx, by, bw, bh, 10, bc);
        /* tiny centered icon block + label under it */
        uint32_t ic = (i==3)?DANGER:ACC;
        fill_rect(app, bx + bw/2 - 8, by + 12, 16, 16, ic);
        int lw = (int)strlen(labels[i]) * 6;
        draw_text(app, labels[i], bx + (bw-lw)/2, by + bh - 22, bw, 12, TXT);
    }

    /* --- Log Out (full width) --- */
    fill_round_rect(app, CARD_X, LOGOUT_Y, CARD_W_OF(app), LOGOUT_H, 12, (app->hover==R_LOGOUT)?ROWH:0xff2a3140u);
    draw_text(app, "Log Out", CARD_X + CARD_W_OF(app)/2 - 26, LOGOUT_Y + 16, CARD_W_OF(app), 15, TXT);
}

/* --- double-buffered wl_shm (one memfd, two slices) --- */
static void redraw_commit(struct app *app);   /* fwd */
static void buffer_release(void *d, struct wl_buffer *wl){ struct app *a = d;
    for (int i=0;i<2;i++) if (a->bufs[i].wl == wl) a->bufs[i].busy = 0;
    if (a->dirty){ a->dirty = 0; redraw_commit(a); }
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static int create_buffers(struct app *app){
    int fd = create_memfd("epin-quicksettings"); if (fd < 0) return -1;
    size_t total = app->buffer_size * 2;
    if (ftruncate(fd, (off_t)total) < 0){ close(fd); return -1; }
    unsigned char *base = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED){ close(fd); return -1; }
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int)total);
    for (int i=0;i<2;i++){
        app->bufs[i].px = (uint32_t*)(base + (size_t)i*app->buffer_size);
        app->bufs[i].wl = wl_shm_pool_create_buffer(pool, (int)((size_t)i*app->buffer_size),
                                                    app->width, app->height, app->stride, WL_SHM_FORMAT_XRGB8888);
        if (!app->bufs[i].wl){ wl_shm_pool_destroy(pool); close(fd); return -1; }
        wl_buffer_add_listener(app->bufs[i].wl, &buffer_listener, app);
        app->bufs[i].busy = 0;
    }
    app->map_base = base; app->map_total = total;
    wl_shm_pool_destroy(pool); close(fd);
    return 0;
}
static void redraw_commit(struct app *app){
    if (!app->configured) return;
    int i = app->bufs[0].busy ? 1 : 0;
    if (app->bufs[i].busy){ app->dirty = 1; return; }
    app->pixels = app->bufs[i].px;
    draw_menu(app);
    app->bufs[i].busy = 1;
    wl_surface_attach(app->surface, app->bufs[i].wl, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
}

/* --- input --- */
static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; a->hover=R_NONE; redraw_commit(a); }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y);
    int nh = hit_region(a, a->pointer_x, a->pointer_y);
    if (nh != a->hover){ a->hover = nh; redraw_commit(a); } }
/* ROADMAP 3.0b: one place where a setting actually changes, shared by the mouse and the
 * keyboard.  Live over IPC first, then persisted -- the saved copy exists to survive a reboot,
 * not to be what makes the setting take effect. */
static void settings_adjust(struct app *app, int i, int dir){
    const struct setting_def *s = &SETTINGS[i];
    if (s->kind == ST_NOTE) return;
    int v = g_setval[i];
    if (s->kind == ST_BOOL) v = !v;
    else {
        v += dir * s->step;
        if (v < s->lo) v = s->lo;
        if (v > s->hi) v = s->hi;
    }
    if (v != g_setval[i]){
        g_setval[i] = v;
        settings_apply_one(i);
        settings_save();
    }
    redraw_commit(app);
}
/* Next selectable row in direction dir, skipping the note row and stopping at the ends. */
static void settings_move_sel(struct app *app, int dir){
    for (int i = app->sel + dir; i >= 0 && i < S_COUNT; i += dir)
        if (SETTINGS[i].kind != ST_NOTE){ app->sel = i; redraw_commit(app); return; }
}

static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    /* Presses only.  Without the state check a release re-fires the action, so every click
     * would act twice -- two launches, or two poweroffs. */
    if (button != 0x110 /*BTN_LEFT*/ || state != 1) return;

    int r = hit_region(a, a->pointer_x, a->pointer_y);
    switch (r){
        case R_CLOSE:    exit(0);
        case R_GEAR:     a->view = V_SETTINGS; redraw_commit(a); break;
        case R_BACK:     a->view = V_MAIN;     redraw_commit(a); break;
        case R_WIFI:     launch("/wl-wifi-menu"); break;
        case R_SYSTEM:   launch("/wl-sysmon"); break;
        case R_SETTINGS: launch("/wl-domain-manager"); break;
        case R_LOCK:     session_action("lock"); break;
        case R_RESTART:  session_action("reboot"); break;
        case R_POWER:    session_action("poweroff"); break;
        case R_LOGOUT:   session_action("logout"); break;
        default:
            /* ROADMAP 3.0b: a settings row.  Apply live over IPC first so the change is
             * immediate, then persist -- in that order, because the persisted copy exists to
             * survive a reboot, not to be what makes the setting take effect. */
            if (r >= R_SET0){
                int i = (r - R_SET0) / 2, inc = (r - R_SET0) & 1;
                a->sel = i;              /* clicking a row also selects it for the keyboard */
                settings_adjust(a, i, inc ? +1 : -1);
            }
            break;
    } }
static void pointer_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v){ (void)d;(void)p;(void)t;(void)ax;(void)v; }
/* wl_pointer >= v5 also emits frame/axis_source/axis_stop/axis_discrete -- these listener slots MUST be
 * non-NULL or libwayland calls a NULL fn-ptr on the first real 'frame' event and the client crashes. */
static void pointer_frame(void *d, struct wl_pointer *p){ (void)d;(void)p; }
static void pointer_axis_source(void *d, struct wl_pointer *p, uint32_t s){ (void)d;(void)p;(void)s; }
static void pointer_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t a){ (void)d;(void)p;(void)t;(void)a; }
static void pointer_axis_discrete(void *d, struct wl_pointer *p, uint32_t a, int32_t dsc){ (void)d;(void)p;(void)a;(void)dsc; }
static const struct wl_pointer_listener pointer_listener = {
    .enter=pointer_enter,.leave=pointer_leave,.motion=pointer_motion,.button=pointer_button,.axis=pointer_axis,
    .frame=pointer_frame,.axis_source=pointer_axis_source,.axis_stop=pointer_axis_stop,.axis_discrete=pointer_axis_discrete };

static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t sz){ (void)d;(void)k;(void)f;(void)sz; if (fd>=0) close(fd); }
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf, struct wl_array *ks){ (void)d;(void)k;(void)s;(void)sf;(void)ks; }
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf){ (void)d;(void)k;(void)s;(void)sf; }
/* ROADMAP 3.0b: the panel is fully keyboard-driven.
 *
 * That is a feature in its own right -- a settings panel nobody can reach without a working
 * pointer is not much of a settings panel -- and it is also what makes this testable.  The two
 * cursors in this guest do not track each other under synthetic relative motion: driving the
 * QEMU monitor's mouse_move moved the kernel-drawn cursor 610px while the compositor's own
 * pointer, the one clicks are dispatched against, moved 343.  sendkey has no such problem.
 *
 * Keycodes are evdev, which is what the compositor forwards. */
static void kb_key(void *d, struct wl_keyboard *k, uint32_t se, uint32_t t, uint32_t key, uint32_t state){ (void)k;(void)se;(void)t; struct app*a=d;
    if (state != 1) return;
    if (a->view == V_SETTINGS){
        switch (key){
            case 1:                                    /* Esc: back to the main view, not quit */
                a->view = V_MAIN; redraw_commit(a); return;
            case 103: settings_move_sel(a, -1); return; /* Up    */
            case 108: settings_move_sel(a, +1); return; /* Down  */
            case 105: case 12:                         /* Left,  '-' */
                settings_adjust(a, a->sel, -1); return;
            case 106: case 13:                         /* Right, '=' */
                settings_adjust(a, a->sel, +1); return;
            case 28: case 57:                          /* Enter, Space: toggle */
                if (SETTINGS[a->sel].kind == ST_BOOL) settings_adjust(a, a->sel, +1);
                return;
            case 31:                                   /* S: back out of settings */
                a->view = V_MAIN; redraw_commit(a); return;
            default: return;
        }
    }
    if (key==1) a->running = 0;        /* Esc closes the main view */
    if (key==31){ a->view = V_SETTINGS; redraw_commit(a); }   /* S opens settings */ }
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
/* ROADMAP 3.2: record the size Hyprland asks for; this used to discard w and h. */
static void toplevel_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s){
    struct app*a=d; (void)t; (void)s;
    if (w > 0) a->pending_width  = w;
    if (h > 0) a->pending_height = h;
}
static void toplevel_close(void *d, struct xdg_toplevel *t){ (void)t; struct app*a=d; a->running=0; }
static void toplevel_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h){ (void)d;(void)t;(void)w;(void)h; }
static void toplevel_wmcap(void *d, struct xdg_toplevel *t, struct wl_array *c){ (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure=toplevel_configure,.close=toplevel_close,.configure_bounds=toplevel_bounds,.wm_capabilities=toplevel_wmcap };

/* ROADMAP 3.2: rebuild both buffers at a new size.  The horizontal metrics reflow through
 * CLOSE_X_OF()/CARD_W_OF(); the vertical stack is fixed-height rows and min_size keeps the window
 * tall enough for all of them. */
static int resize_buffers(struct app *app, int w, int h){
    if (w <= 0 || h <= 0) return 0;
    if (w == app->width && h == app->height && app->bufs[0].wl) return 0;
    for (int i = 0; i < 2; i++){
        if (app->bufs[i].wl){ wl_buffer_destroy(app->bufs[i].wl); app->bufs[i].wl = NULL; }
        app->bufs[i].px = NULL; app->bufs[i].busy = 0;
    }
    if (app->map_base && app->map_base != MAP_FAILED) munmap(app->map_base, app->map_total);
    app->map_base = NULL; app->map_total = 0; app->pixels = NULL;
    app->width = w; app->height = h; app->stride = w * 4;
    app->buffer_size = (size_t)app->stride * (size_t)h;
    return create_buffers(app);
}

static void xdg_surface_configure(void *d, struct xdg_surface *s, uint32_t serial){ struct app*a=d;
    xdg_surface_ack_configure(s, serial);
    int ww = a->pending_width  > 0 ? a->pending_width  : a->width;
    int wh = a->pending_height > 0 ? a->pending_height : a->height;
    if (ww != a->width || wh != a->height){
        if (resize_buffers(a, ww, wh) < 0){ log_line("QUICKSET: resize failed"); return; }
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

static void live_refresh(struct app *app){
    unsigned char *buf; size_t sz; unsigned h = 0;
    if (load_file("/run/wifi/networks", &buf, &sz) == 0){ h = fnv1a(buf, sz); free(buf); }
    if (h != app->last_hash){ app->last_hash = h; load_wifi(app); }
    load_stats(app);        /* CPU%/RAM/IP refresh every tick */
    publish_state(app);
    redraw_commit(app);     /* redraw each ~1s tick to update the System row */
}

int main(void){
    static struct app app; memset(&app, 0, sizeof app);
    app.running = 1; app.hover = R_NONE; app.view = V_MAIN;
    app.width = WIN_W; app.height = WIN_H; app.stride = WIN_W*4; app.buffer_size = (size_t)app.stride*WIN_H;
    signal(SIGCHLD, SIG_IGN);
    init_freetype(&app);
    load_wifi(&app);
    load_identity(&app);
    load_stats(&app);
    publish_state(&app);

    /* ROADMAP 3.0b: load the saved settings, and re-assert them on the running compositor.
     * Redundant when hyprland.lua already read custom/settings.lua at boot -- and that is the
     * point: it costs one socket write per setting and leaves the panel correct even if that
     * require() did not happen.  Nothing is sent when no file has been saved yet, so opening
     * this app never changes a setting on its own. */
    if (settings_load()) settings_apply_all();

    log_line("QSETTINGS: starting quick-settings menu");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("QSETTINGS: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base){ log_line("QSETTINGS: missing globals"); return 1; }
    if (create_buffers(&app) < 0){ log_line("QSETTINGS: buffer failed"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "System");
    xdg_toplevel_set_app_id(app.toplevel, "epin-quicksettings");
    /* Float as a fixed-size popover: min==max size makes the tiling WM's
     * epin_is_tileable() return false so this card is left floating. */
    xdg_toplevel_set_min_size(app.toplevel, WIN_W, WIN_H);
    /* ROADMAP 3.2: no maximum -- min == max is what made Hyprland float this window. */
    wl_surface_commit(app.surface);
    wl_display_flush(app.display);

    int wlfd = wl_display_get_fd(app.display);
    while (app.running){
        while (wl_display_prepare_read(app.display) != 0) wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);
        struct pollfd pfd = { .fd=wlfd, .events=POLLIN, .revents=0 };
        int pr = poll(&pfd, 1, 1000);
        if (pr > 0 && (pfd.revents & POLLIN)){ wl_display_read_events(app.display); wl_display_dispatch_pending(app.display); }
        else { wl_display_cancel_read(app.display); if (pr < 0){ if (errno==EINTR) continue; break; }
               if (pr == 0) live_refresh(&app); }
    }
    return 0;
}
