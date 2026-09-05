// wl-domain-manager.c — IDENTITY_DOMAIN GUI: a Qubes-style Domain Manager + per-
// domain control panel.
//
// Pops up at boot (spawned by the Weston desktop shell).  The left pane lists the
// system's security domains — the kernel's Identity objects (core/identity.d) —
// each in its identity color.  Selecting one opens a control panel on the right
// with the domain's policy knobs: memory cap (incl. Unlimited), disk access,
// network policy, clipboard policy, whether processes require secure IPC, the
// shell flavor (Linux / Windows / native OS), and per-class device access.  The
// "Launch Terminal" / "Launch Files" buttons actually fork+exec an app INTO the
// selected domain, passing every setting through the environment (EPIN_DOMAIN,
// EPIN_DOMAIN_COLOR, EPIN_SHELL, EPIN_MEM_CAP, EPIN_DISK, EPIN_NET, EPIN_CLIP,
// EPIN_SECURE_IPC) — the launched terminal draws an unspoofable domain-colored
// border and honors the shell flavor + memory cap.
//
// Window decorations are the compositor's job; this client only paints its content
// surface (Cairo shapes in one pass, antialiased FreeType text in a second pass).
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <wayland-client.h>
#include <cairo/cairo.h>
#include <ft2build.h>
#include FT_FREETYPE_H

#include "xdg-shell-client-protocol.h"
#include "wl-deco.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

extern char **environ;

enum {
    DEFAULT_WIDTH  = 1180,
    DEFAULT_HEIGHT = 680,     // DM10.7: taller, for the tabbed panels
    HEADER_H       = 56,      // title bar
    LIST_W         = 240,     // left domain list width
    ROW_H          = 40,      // list row height
    FOOTER_H       = 30,
    PAD            = 20,
};

// DM10.7: tabbed-layout geometry (toolbar of verbs → split panes → tabbed right panel).
enum {
    TOOLBAR_H = 38,
    BODY_Y    = HEADER_H + TOOLBAR_H,           // split panes start here
    RP_X      = LIST_W,
    LABEL_X   = RP_X + 24,
    DOMHDR_H  = 36,                             // domain name + status row (right pane)
    TABBAR_H  = 32,
    TAB_Y     = BODY_Y + DOMHDR_H + TABBAR_H,   // tab content start
    N_TABS    = 10,   // ROADMAP 1.5 added Users, Services, Startup (system-scoped)
};

// --- option tables --------------------------------------------------------

enum { MEM_256, MEM_512, MEM_1G, MEM_2G, MEM_4G, MEM_8G, MEM_UNLIM, MEM_N };
static const char *MEM_LBL[]   = {"256 MB","512 MB","1 GB","2 GB","4 GB","8 GB","Unlimited"};
static const long  MEM_BYTES[] = {256L<<20,512L<<20,1L<<30,2L<<30,4L<<30,8L<<30,0};

enum { DISK_NONE, DISK_RO, DISK_RW, DISK_N };
static const char *DISK_LBL[] = {"None","Read-only","Read-write"};
static const char *DISK_ENV[] = {"none","ro","rw"};

enum { NET_NONE, NET_NAT, NET_VPN, NET_TOR, NET_LOCAL, NET_DISP, NET_N };
static const char *NET_LBL[] = {"None","NAT","VPN","Tor","Local-only","Disposable"};
static const char *NET_ENV[] = {"none","nat","vpn","tor","local","disposable"};

enum { CLIP_DENY, CLIP_ASK, CLIP_SAME, CLIP_DOWN, CLIP_N };
static const char *CLIP_LBL[] = {"Deny","Ask","Same-domain","Down-trust"};
static const char *CLIP_ENV[] = {"deny","ask","same","downtrust"};

enum { SH_LINUX, SH_WINDOWS, SH_NATIVE, SH_N };
// Z11/L5: ONE shell (zsh), two personalities — "Linux (zsh)" runs /bin/zsh (POSIX, confined), and
// "Native (zsh+LFE)" runs /hos-zsh: the same zsh in the native personality with LFE embedded inside
// it (in-process obj/id/ns object builtins + an `lfe` builtin for the full LFE evaluator, L2–L4).
static const char *SHELL_LBL[] = {"Linux (zsh)","Windows (n/a)","Native (zsh+LFE)"};
static const char *SHELL_ENV[] = {"linux","windows","native"};

// R1: which terminal *emulator* "Launch Terminal" runs — the C wl-term (default) or the Rust
// hos-term (ratty-cpu).  Both host the chosen Shell (EPIN_SHELL); this picks the emulator, not the
// shell.  (Replaces the SUPER+R keybind: the terminal is selected here, per the domain.)
enum { TERM_WL, TERM_HOS, TERM_GL, TERM_N };
static const char *TERM_LBL[] = {"Default (wl-term)", "Rust (hos-term)", "GL (gl-term)"};
static const char *TERM_BIN[] = {"/wl-term", "/hos-term", "/gl-term"};

struct domain {
    const char *name;
    uint32_t    color;   // 0xAARRGGBB — mirrors the kernel IdentityRec.color
    int         trust;   // 0..100
};
static const struct domain DOMAINS[] = {
    {"System",      0xFF808080u, 100},
    {"Personal",    0xFF2E7D32u,  50},
    {"Work",        0xFF1565C0u,  60},
    {"Banking",     0xFFFFD600u,  80},
    {"Development",  0xFF6A1B9Au,  40},
    {"Untrusted",   0xFFB71C1Cu,  10},
    {"Disposable",  0xFFFF6D00u,   5},
};
enum { N_DOMAINS = (int)(sizeof(DOMAINS) / sizeof(DOMAINS[0])) };

struct dconf {
    int mem, disk, net, clip;
    int secure_ipc;          // 0/1
    int shell;
    int dev_cam, dev_mic, dev_usb;
    int term;                // TERM_WL / TERM_HOS — the terminal emulator to launch
};

// Per-domain defaults (Qubes-like: higher trust = tighter, banking locked down).
static const struct dconf DEFAULTS[N_DOMAINS] = {
    /* System      */ {MEM_UNLIM, DISK_RW,  NET_NAT,   CLIP_DOWN, 1, SH_LINUX, 1,1,1},
    /* Personal    */ {MEM_2G,    DISK_RW,  NET_NAT,   CLIP_ASK,  0, SH_LINUX, 1,1,1},
    /* Work        */ {MEM_2G,    DISK_RW,  NET_VPN,   CLIP_SAME, 1, SH_LINUX, 1,1,1},
    /* Banking     */ {MEM_1G,    DISK_RW,  NET_VPN,   CLIP_DENY, 1, SH_LINUX, 0,0,0},
    /* Development */ {MEM_4G,    DISK_RW,  NET_LOCAL, CLIP_ASK,  0, SH_LINUX, 0,0,1},
    /* Untrusted   */ {MEM_512,   DISK_RO,  NET_TOR,   CLIP_DENY, 0, SH_LINUX, 0,0,0},
    /* Disposable  */ {MEM_512,   DISK_NONE,NET_DISP,  CLIP_DENY, 0, SH_LINUX, 0,0,0},
};

// DOMAIN_MANAGER DM10: a domain as read from the declarative config (/config/domains.json) —
// generated by the kernel from system.json.  This replaces the hardcoded DOMAINS[] as the source
// of truth, so the GUI reflects DM0-DM6: manifest domains, templates, persist mode, live state.
#define MAX_DOMS 32
struct gdomain {
    char     name[32];
    uint32_t color;           // the bound identity's color (0xAARRGGBB)
    char     identity[32];    // the security identity the domain binds to
    char     type[16];        // "domain" | "template"
    char     persist[16];     // "ephemeral" | "home-only" | "full"
    char     state[16];       // "Defined" | "Running" | ...
    unsigned objId;           // this domain's object id
    unsigned templObjId;      // the referenced template's object id (0 = none)
    unsigned devices;         // DM10.7: §7 peripheral device mask (Permissions tab)
    char     distro[16];      // DM11: Linux-compat distribution
    char     pkgmgr[16];      // DM11: package manager
};

// DM10.7: a repository package, parsed from /config/packages.json (Packages tab).
#define MAX_PKGS 16
struct gpkg { char name[32]; char ver[12]; int sizeKb; unsigned reqCaps; };

// DM12: an installed signed template, parsed from /config/templates.json (Appearance tab).
#define MAX_TMPL 8
struct gtemplate { char name[32]; char publisher[24]; char ver[16]; };

// ROADMAP 1.5 (APPS B3) — three SYSTEM-scoped views: Users, Services, Startup.
//
// Every one of these reads a live kernel table; none of them invents data.  That matters here
// because the roadmap has twice had to delete fake UI from this project (the Quick Settings
// volume slider with no audio backend; the old "Startup" tab in THIS file, which drew a
// hardcoded "Terminal (gl-term)" string and a "(planned)" note and could not do anything).
//
//   Users    <- /config/users.json     rendered from g_users  by hoscall.d CFG_USERS
//   Services <- /config/services.json  rendered from g_svcs   by hoscall.d CFG_SERVICES
//   Startup  <- /desktop.conf          the boot module the kernel itself parses for autostart
//
// /desktop.conf is a boot MODULE rather than a file on a mounted filesystem, but sys_open()
// falls through to findBootModule(), so open("/desktop.conf") works from a client exactly like
// a regular file.  It is the same text the kernel reads in desktopAutostartAt(), so this view
// shows what will actually be launched, not a second copy that could drift out of step.
#define MAX_SYSUSERS 24
struct gsysuser { char name[32]; unsigned uid, gid, rights; };

#define MAX_SYSSVCS 32
struct gsyssvc { char name[40]; char state[12]; unsigned rights, ver; };

#define MAX_STARTUP 24
struct gstartup { char cmd[96]; int live; };   // live = an `autostart-live` (install-media only) entry

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
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
    int width, height, stride;
    int pending_w, pending_h;      // tiling WM: last compositor-requested size (0 = unset)
    int committed, font_ready, sync_after_commit;
    int post_map_frame_armed, post_map_frame_done;
    int running;
    double pointer_x, pointer_y;
    int sel;                       // selected domain
    struct dconf cfg[MAX_DOMS];    // per-domain launch settings (mutable)
    struct gdomain doms[MAX_DOMS]; // DM10: the domains, read from the declarative config
    int n_doms;                    // number loaded
    char fs_view[1280];            // DM10.2: the selected domain's restricted-FS RuntimeView
    int  editing;                  // DM10.5: text-input dialog is open
    char editbuf[96];              // the typed value (domain name OR a filesystem path)
    int  editlen;
    int  edit_mode;                // DM10.7: 0=clone-name, 1=fs ro, 2=fs rw, 3=fs deny
    unsigned last_hash;            // DM10.6: FNV hash of /config/domains.json — detect external changes
    int  tab;                      // DM10.7: active right-pane tab (0..N_TABS-1)
    struct gpkg pkgs[MAX_PKGS];    // DM10.7: the repository catalog (/config/packages.json)
    int  n_pkgs;
    unsigned pkg_mask[MAX_DOMS];   // per-domain installed bitmask over the catalog
    struct gtemplate templates[MAX_TMPL];  // DM12: the local signed-template registry
    int  n_templates;
    struct gsysuser sysusers[MAX_SYSUSERS];  // ROADMAP 1.5: Users tab    (/config/users.json)
    int  n_sysusers;
    struct gsyssvc  syssvcs[MAX_SYSSVCS];    // ROADMAP 1.5: Services tab (/config/services.json)
    int  n_syssvcs;
    struct gstartup startup[MAX_STARTUP];    // ROADMAP 1.5: Startup tab  (/desktop.conf)
    int  n_startup;
    // Applications tab: indices into DMAPPS whose binary actually exists, so the list never
    // offers a launch that can only fail with "[exec] not found".
    int  avail[16];
    int  n_avail;
};

static void log_line(const char *s) { fputs(s, stdout); fputc('\n', stdout); fflush(stdout); }

static int create_memfd(const char *name) { return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC); }

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
static void cairo_argb(cairo_t *cr, uint32_t c)
{
    cairo_set_source_rgb(cr, ((c >> 16) & 0xff) / 255.0, ((c >> 8) & 0xff) / 255.0, (c & 0xff) / 255.0);
}

static int load_file(const char *path, unsigned char **out, size_t *out_size)
{
    *out = NULL; *out_size = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0) { close(fd); return -1; }
    unsigned char *buf = malloc((size_t)st.st_size);
    if (!buf) { close(fd); return -1; }
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + got, (size_t)st.st_size - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    *out = buf; *out_size = got;
    return 0;
}

static int init_freetype(struct app *app)
{
    const char *path = "/usr/share/fonts/noto/NotoSans-Regular.ttf";
    if (load_file(path, &app->font_data, &app->font_size) < 0) return -1;
    if (FT_Init_FreeType(&app->ft) != 0) return -1;
    if (FT_New_Memory_Face(app->ft, app->font_data, (FT_Long)app->font_size, 0, &app->face) != 0) return -1;
    app->font_ready = 1;
    printf("DOMAINMGR: loaded %s (%zu bytes)\n", path, app->font_size);
    fflush(stdout);
    return 0;
}

static uint32_t blend_xrgb(uint32_t dst, uint32_t src, unsigned int alpha)
{
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

static void draw_text(struct app *app, const char *text, int x, int y, int max_w, int px, uint32_t color)
{
    if (!app->font_ready || !text || max_w <= 0) return;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0) return;
    int baseline = px;
    if (app->face->size && app->face->size->metrics.ascender > 0)
        baseline = (int)(app->face->size->metrics.ascender >> 6);
    int pen_x = x, pen_y = y + baseline;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        unsigned char ch = *p;
        if (ch < 0x20 || ch >= 0x7f) ch = '?';
        if (FT_Load_Char(app->face, (FT_ULong)ch, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) != 0) continue;
        FT_GlyphSlot g = app->face->glyph;
        int advance = (int)(g->advance.x >> 6);
        if (pen_x + advance > x + max_w) break;
        FT_Bitmap *bm = &g->bitmap;
        int gx = pen_x + g->bitmap_left, gy = pen_y - g->bitmap_top;
        int pitch = bm->pitch;
        const unsigned char *base = bm->buffer;
        if (pitch < 0) { pitch = -pitch; base = bm->buffer - (int)(bm->rows - 1) * pitch; }
        for (int row = 0; row < (int)bm->rows; row++) {
            int pyp = gy + row;
            if (pyp < 0 || pyp >= app->height) continue;
            const unsigned char *src_row = base + row * pitch;
            for (int col = 0; col < (int)bm->width; col++) {
                int pxpos = gx + col;
                if (pxpos < 0 || pxpos >= app->width) continue;
                unsigned int alpha = 0;
                if (bm->pixel_mode == FT_PIXEL_MODE_GRAY) alpha = src_row[col];
                else if (bm->pixel_mode == FT_PIXEL_MODE_MONO) alpha = (src_row[col >> 3] & (0x80 >> (col & 7))) ? 255 : 0;
                uint32_t *dst = &app->pixels[pyp * app->width + pxpos];
                *dst = blend_xrgb(*dst, color, alpha);
            }
        }
        pen_x += advance;
    }
}

// --- control model --------------------------------------------------------

static const char *CTL_LABEL[7] = {
    "Memory cap", "Disk access", "Network", "Clipboard", "Secure IPC", "Shell", "Terminal"
};

static void ctl_value(const struct dconf *c, int i, char *out, size_t n)
{
    switch (i) {
        case 0: snprintf(out, n, "%s", MEM_LBL[c->mem]); break;
        case 1: snprintf(out, n, "%s", DISK_LBL[c->disk]); break;
        case 2: snprintf(out, n, "%s", NET_LBL[c->net]); break;
        case 3: snprintf(out, n, "%s", CLIP_LBL[c->clip]); break;
        case 4: snprintf(out, n, "%s", c->secure_ipc ? "Required" : "Optional"); break;
        case 5: snprintf(out, n, "%s", SHELL_LBL[c->shell]); break;
        case 6: snprintf(out, n, "%s", TERM_LBL[c->term]); break;
        default: out[0] = 0;
    }
}

static void ctl_cycle(struct dconf *c, int i, int dir)
{
    switch (i) {
        case 0: c->mem  = (c->mem  + MEM_N  + dir) % MEM_N;  break;
        case 1: c->disk = (c->disk + DISK_N + dir) % DISK_N; break;
        case 2: c->net  = (c->net  + NET_N  + dir) % NET_N;  break;
        case 3: c->clip = (c->clip + CLIP_N + dir) % CLIP_N; break;
        case 4: c->secure_ipc ^= 1; break;
        case 5: c->shell = (c->shell + SH_N + dir) % SH_N; break;
        case 6: c->term  = (c->term  + TERM_N + dir) % TERM_N; break;
    }
}

// ── DM10.7 tabbed-layout labels + geometry (shared by the draw + click passes) ──────────────
#define N_TOOL 6
static const char *TOOL_LABEL[N_TOOL] = { "+ New", "Clone", "Import", "Marketplace", "Logs", "Run Shell" };
static const char *TAB_LABEL[N_TABS]  = { "Overview","Filesystem","Packages","Network","Permissions","Applications","Appearance",
                                          "Users","Services","Startup" };
enum { TAB_W = (DEFAULT_WIDTH - LIST_W) / N_TABS };   // fixed tab column width

#define N_LIFE 6
static const char *LIFE_LABEL[N_LIFE] = { "Start","Stop","Pause","Resume","Snapshot","Commit" };
static const char *LIFE_VERB [N_LIFE] = { "start","stop","pause","resume","snapshot","commit" };

// The 7th entry is Network (DEVCLASS_NET, 1u<<6).  The kernel bit and its enforcement
// (netProviderConnectGate) already existed, but the class had no name in
// domainDeviceClassByName(), so "devon <domain> net" resolved to 0 and did nothing -- and
// there was no row here to click.  Both ends are wired now, so this row is a REAL per-domain
// network on/off switch: with it cleared, that domain cannot open an AF_INET socket.
// It is NOT the NAT/VPN/Tor NetPolicy vocabulary -- that remains unimplemented.
#define N_DEV 7
static const char    *DEV_LABEL[N_DEV] = { "Keyboard / Mouse","GPU","Camera","Microphone","Audio","USB","Network" };
static const char    *DEV_CLASS[N_DEV] = { "input","gpu","camera","mic","audio","usb","net" };
static const unsigned DEV_BIT  [N_DEV] = { 1u<<0, 1u<<1, 1u<<2, 1u<<3, 1u<<4, 1u<<5, 1u<<6 };

#define N_FSBTN 4
static const char *FSBTN_LABEL[N_FSBTN] = { "+ Allow ro", "+ Allow rw", "+ Deny", "+ Mount" };
static const int   FSBTN_MODE [N_FSBTN] = { 1, 2, 3, 2 };   // edit_mode for the path dialog (Mount == rw)

static void toolbar_btn_rect(int idx, int *x, int *y, int *w, int *h) {
    static const int wd[N_TOOL] = { 74, 70, 74, 110, 56, 100 };
    *y = HEADER_H + 6; *h = TOOLBAR_H - 12;
    int cx = PAD;
    for (int i = 0; i < idx; i++) cx += wd[i] + 8;
    *x = cx; *w = wd[idx];
}
static void tab_rect(int idx, int *x, int *y, int *w, int *h) {
    *y = BODY_Y + DOMHDR_H; *h = TABBAR_H; *x = RP_X + idx * TAB_W; *w = TAB_W;
}
static void delete_btn_rect(struct app *app, int *x, int *y, int *w, int *h) {
    *x = PAD; *w = LIST_W - 2 * PAD; *h = 26; *y = app->height - FOOTER_H - 32;
}
static void life_btn_rect(int idx, int *x, int *y, int *w, int *h) {
    *y = TAB_Y + 196; *h = 30; *w = 92; *x = LABEL_X + idx * (92 + 6);
}
static void fs_btn_rect(int idx, int *x, int *y, int *w, int *h) {
    *y = TAB_Y + 12; *h = 26; *w = 100; *x = LABEL_X + idx * (100 + 6);
}
static void dev_row_rect(int idx, int *x, int *y, int *w, int *h) {   // Permissions device toggle pills
    *y = TAB_Y + 24 + idx * 42; *h = 30; *w = 70; *x = LABEL_X + 240;
}
// DM11: distro selector + package profiles (top of the Packages tab).
#define N_DISTRO 4
static const char *DISTRO_NAME[N_DISTRO] = { "native", "busybox", "nix", "alpine" };
#define N_PROFILE 5
static const char *PROFILE_NAME[N_PROFILE] = { "minimal", "development", "office", "research", "media" };
static void distro_btn_rect(int idx, int *x, int *y, int *w, int *h) {
    *y = TAB_Y + 30; *h = 24; *w = 82; *x = LABEL_X + 150 + idx * (82 + 6);
}
static void profile_btn_rect(int idx, int *x, int *y, int *w, int *h) {
    *y = TAB_Y + 64; *h = 24; *w = 96; *x = LABEL_X + 70 + idx * (96 + 6);
}
static void pkg_row_rect(int idx, int *x, int *y, int *w, int *h) {   // Packages install/remove pills
    *y = TAB_Y + 104 + idx * 30; *h = 26; *w = 92; *x = LABEL_X + 320;
}

// ── Applications tab ─────────────────────────────────────────────────────────
//
// The applications a domain can run, each launched CONFINED into that domain.  The Packages
// tab next door is the repository (install/remove); the Startup tab was a hardcoded stub that
// listed one app and said "(planned)".  Neither was a launcher, so there was no way to open a
// terminal inside a domain from this GUI at all -- which is the whole point of the domain.
//
// There is no shared app registry in the tree: the desktop's own grid hardcodes this list in
// wl-overview.c, so this mirrors it.  Rows are filtered by access(X_OK) at load time, which
// also keeps dead entries (e.g. /gl-term, which has never been built) off the list instead of
// offering a launch that can only fail.
struct dmapp { const char *label; const char *exec; };
static const struct dmapp DMAPPS[] = {
    { "Terminal",       "/hos-wifiterm" },   /* wl-term w/ EPIN_SHELL=light, software-rendered */
    { "Files",          "/wl-files"      },
    { "Text Editor",    "/wl-editor"     },
    { "Calculator",     "/wl-calc"       },
    { "System Monitor", "/wl-sysmon"     },
    { "Image Viewer",   "/wl-imgview"    },
    { "Clocks",         "/wl-clocks"     },
    { "Calendar",       "/wl-calendar"   },
    { "Characters",     "/wl-chars"      },
    { "Screenshot",     "/wl-screenshot" },
    { "Logs",           "/wl-logview"    },
};
enum { N_DMAPP = (int)(sizeof(DMAPPS)/sizeof(DMAPPS[0])) };

static void appl_row_rect(int idx, int *x, int *y, int *w, int *h) {   // Applications Launch pills
    *y = TAB_Y + 40 + idx * 30; *h = 26; *w = 92; *x = LABEL_X + 320;
}

// Build the Applications list once: keep only entries whose binary is actually present and
// executable.  /gl-term is in the desktop's table but has never been built, and offering it
// produced a spawn that failed with "[exec] not found" — filter at the source instead.
static void load_apps(struct app *app)
{
    app->n_avail = 0;
    for (int i = 0; i < N_DMAPP && app->n_avail < (int)(sizeof(app->avail)/sizeof(app->avail[0])); i++)
        if (access(DMAPPS[i].exec, X_OK) == 0)
            app->avail[app->n_avail++] = i;
    printf("DOMAINMGR: %d of %d applications present\n", app->n_avail, N_DMAPP);
    fflush(stdout);
}

static void export_btn_rect(int *x, int *y, int *w, int *h) {   // DM12 Appearance-tab Export button
    *x = LABEL_X; *y = TAB_Y + 100; *w = 240; *h = 28;
}

// DM10.5: evdev keycode → lowercase ASCII (US QWERTY) for the clone-name text field.  The DM gets
// raw evdev codes from wl_keyboard (it ignores the xkb keymap), so we map the printable subset.
static const char EVDEV_CHAR[128] = {
    [2]='1',[3]='2',[4]='3',[5]='4',[6]='5',[7]='6',[8]='7',[9]='8',[10]='9',[11]='0',[12]='-',
    [16]='q',[17]='w',[18]='e',[19]='r',[20]='t',[21]='y',[22]='u',[23]='i',[24]='o',[25]='p',
    [30]='a',[31]='s',[32]='d',[33]='f',[34]='g',[35]='h',[36]='j',[37]='k',[38]='l',
    [44]='z',[45]='x',[46]='c',[47]='v',[48]='b',[49]='n',[50]='m',
    [52]='.',[53]='/',[57]=' ',   // for filesystem paths
};

// --- drawing --------------------------------------------------------------

// --- DM10: load the domains from the DECLARATIVE config (/config/domains.json) ----------------
// The kernel generates that JSON from system.json (DM1's manifest pipeline), so the GUI now
// reflects the declared system config — manifest domains, templates, persist mode, live state —
// instead of a hardcoded list.  Minimal extractor for the controlled flat-array-of-flat-objects.
static int j_field(const char *p, const char *end, const char *key, char *out, int cap)
{
    char pat[40]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *k = strstr(p, pat);
    if (!k || k >= end) { out[0] = 0; return 0; }
    k += strlen(pat);
    while (*k && *k != ':') k++;
    if (*k == ':') k++;
    while (*k == ' ') k++;
    int q = (*k == '"'); if (q) k++;
    int i = 0;
    while (*k && i < cap - 1) {
        if (q && *k == '"') break;
        if (!q && (*k == ',' || *k == '}' || *k == ' ' || *k == '\n')) break;
        out[i++] = *k++;
    }
    out[i] = 0;
    return 1;
}

static void load_domains_fallback(struct app *app)
{
    app->n_doms = N_DOMAINS;
    for (int i = 0; i < N_DOMAINS; i++) {
        struct gdomain *g = &app->doms[i];
        memset(g, 0, sizeof(*g));
        snprintf(g->name, sizeof(g->name), "%s", DOMAINS[i].name);
        g->color = DOMAINS[i].color;
        snprintf(g->identity, sizeof(g->identity), "%s", DOMAINS[i].name);
        snprintf(g->type, sizeof(g->type), "domain");
        snprintf(g->state, sizeof(g->state), "Defined");
        snprintf(g->persist, sizeof(g->persist), "ephemeral");
    }
    printf("DOMAINMGR: /config/domains.json unavailable -- using %d built-in domains\n", app->n_doms);
    fflush(stdout);
}

static void load_domains(struct app *app)
{
    unsigned char *buf; size_t sz;
    app->n_doms = 0;
    if (load_file("/config/domains.json", &buf, &sz) < 0 || sz == 0) { load_domains_fallback(app); return; }
    char *json = malloc(sz + 1);
    if (!json) { free(buf); load_domains_fallback(app); return; }
    memcpy(json, buf, sz); json[sz] = 0; free(buf);

    const char *p = json;
    while (app->n_doms < MAX_DOMS) {
        const char *nm = strstr(p, "\"name\"");
        if (!nm) break;
        const char *objEnd = strstr(nm + 6, "\"name\"");
        if (!objEnd) objEnd = json + sz;
        struct gdomain *g = &app->doms[app->n_doms];
        memset(g, 0, sizeof(*g));
        j_field(nm, objEnd, "name",     g->name,     sizeof(g->name));
        j_field(nm, objEnd, "identity", g->identity, sizeof(g->identity));
        j_field(nm, objEnd, "type",     g->type,     sizeof(g->type));
        j_field(nm, objEnd, "persist",  g->persist,  sizeof(g->persist));
        j_field(nm, objEnd, "state",    g->state,    sizeof(g->state));
        char num[16];
        if (j_field(nm, objEnd, "objId", num, sizeof(num)))    g->objId = (unsigned)strtoul(num, NULL, 10);
        if (j_field(nm, objEnd, "template", num, sizeof(num))) g->templObjId = (unsigned)strtoul(num, NULL, 10);
        if (j_field(nm, objEnd, "color", num, sizeof(num)))    g->color = (uint32_t)strtoul(num, NULL, 16);
        else g->color = 0xFF808080u;
        if (j_field(nm, objEnd, "devices", num, sizeof(num)))  g->devices = (unsigned)strtoul(num, NULL, 16);
        j_field(nm, objEnd, "distro",  g->distro,  sizeof(g->distro));
        j_field(nm, objEnd, "packageManager", g->pkgmgr, sizeof(g->pkgmgr));
        if (g->name[0]) app->n_doms++;
        p = objEnd;
    }
    free(json);
    if (app->n_doms == 0) { load_domains_fallback(app); return; }
    printf("DOMAINMGR: loaded %d domains from /config/domains.json (declarative):", app->n_doms);
    for (int i = 0; i < app->n_doms; i++) printf(" %s[%s dev=0x%x distro=%s]", app->doms[i].name, app->doms[i].type, app->doms[i].devices, app->doms[i].distro);
    printf("\n"); fflush(stdout);
}

// DM10.7: load the software repository (/config/packages.json) — the catalog into pkgs[] and the
// per-domain installed set into pkg_mask[].  Used by the Packages tab.
static void load_packages(struct app *app)
{
    app->n_pkgs = 0;
    for (int i = 0; i < MAX_DOMS; i++) app->pkg_mask[i] = 0;
    unsigned char *buf; size_t sz;
    if (load_file("/config/packages.json", &buf, &sz) < 0 || sz == 0) return;
    char *json = malloc(sz + 1);
    if (!json) { free(buf); return; }
    memcpy(json, buf, sz); json[sz] = 0; free(buf);

    const char *inst = strstr(json, "\"installed\"");
    const char *p = strstr(json, "\"repository\"");
    if (!p) p = json;
    while (app->n_pkgs < MAX_PKGS) {
        const char *nm = strstr(p, "\"name\"");
        if (!nm || (inst && nm > inst)) break;            // catalog entries only
        const char *e = strstr(nm + 6, "\"name\"");
        if (!e || (inst && e > inst)) e = inst ? inst : (json + sz);
        struct gpkg *g = &app->pkgs[app->n_pkgs];
        memset(g, 0, sizeof(*g));
        j_field(nm, e, "name", g->name, sizeof(g->name));
        j_field(nm, e, "version", g->ver, sizeof(g->ver));
        char num[16];
        if (j_field(nm, e, "sizeKb", num, sizeof(num)))       g->sizeKb  = atoi(num);
        if (j_field(nm, e, "requiredCaps", num, sizeof(num))) g->reqCaps = (unsigned)strtoul(num, NULL, 16);
        if (g->name[0]) app->n_pkgs++;
        p = e;
    }
    // installed: for each {domain, packages:[…]}, set the bit for every catalog pkg name present.
    for (const char *q = inst; q; ) {
        const char *dn = strstr(q, "\"domain\"");
        if (!dn) break;
        const char *dEnd = strstr(dn + 8, "\"domain\"");
        if (!dEnd) dEnd = json + sz;
        char dname[32]; j_field(dn, dEnd, "domain", dname, sizeof(dname));
        int di = -1;
        for (int i = 0; i < app->n_doms; i++) if (strcmp(app->doms[i].name, dname) == 0) { di = i; break; }
        if (di >= 0)
            for (int pi = 0; pi < app->n_pkgs; pi++) {
                char pat[40]; snprintf(pat, sizeof(pat), "\"%s\"", app->pkgs[pi].name);
                const char *hit = strstr(dn, pat);
                if (hit && hit < dEnd && hit > dn + 8) app->pkg_mask[di] |= (1u << pi);
            }
        q = dEnd;
    }
    free(json);
    printf("DOMAINMGR: loaded %d packages from /config/packages.json\n", app->n_pkgs); fflush(stdout);
}

// DM12: load the local signed-template registry (/config/templates.json) for the Appearance tab.
static void load_templates(struct app *app)
{
    app->n_templates = 0;
    unsigned char *buf; size_t sz;
    if (load_file("/config/templates.json", &buf, &sz) < 0 || sz == 0) return;
    char *json = malloc(sz + 1);
    if (!json) { free(buf); return; }
    memcpy(json, buf, sz); json[sz] = 0; free(buf);
    const char *p = json;
    while (app->n_templates < MAX_TMPL) {
        const char *nm = strstr(p, "\"name\"");
        if (!nm) break;
        const char *e = strstr(nm + 6, "\"name\"");
        if (!e) e = json + sz;
        struct gtemplate *g = &app->templates[app->n_templates];
        memset(g, 0, sizeof(*g));
        j_field(nm, e, "name", g->name, sizeof(g->name));
        j_field(nm, e, "publisher", g->publisher, sizeof(g->publisher));
        j_field(nm, e, "version", g->ver, sizeof(g->ver));
        if (g->name[0]) app->n_templates++;
        p = e;
    }
    free(json);
    printf("DOMAINMGR: loaded %d templates from /config/templates.json\n", app->n_templates); fflush(stdout);
}

// ── ROADMAP 1.5 loaders ───────────────────────────────────────────────────────────────────
// Same shape as load_packages() above: slurp, NUL-terminate, walk "name" to "name" and pull
// fields out of each record with j_field().  The kernel writes one flat array per file, so the
// record boundary IS the next "name" key; the last record ends at the end of the buffer.

static void load_sysusers(struct app *app)
{
    app->n_sysusers = 0;
    unsigned char *buf; size_t sz;
    if (load_file("/config/users.json", &buf, &sz) < 0 || sz == 0) return;
    char *json = malloc(sz + 1);
    if (!json) { free(buf); return; }
    memcpy(json, buf, sz); json[sz] = 0; free(buf);

    const char *p = json;
    while (app->n_sysusers < MAX_SYSUSERS) {
        const char *nm = strstr(p, "\"name\"");
        if (!nm) break;
        const char *e = strstr(nm + 6, "\"name\"");
        if (!e) e = json + sz;
        struct gsysuser *g = &app->sysusers[app->n_sysusers];
        memset(g, 0, sizeof(*g));
        j_field(nm, e, "name", g->name, sizeof(g->name));
        char num[24];
        if (j_field(nm, e, "uid",    num, sizeof(num))) g->uid    = (unsigned)strtoul(num, NULL, 10);
        if (j_field(nm, e, "gid",    num, sizeof(num))) g->gid    = (unsigned)strtoul(num, NULL, 10);
        if (j_field(nm, e, "rights", num, sizeof(num))) g->rights = (unsigned)strtoul(num, NULL, 16);
        if (g->name[0]) app->n_sysusers++;
        p = e;
    }
    free(json);
    printf("DOMAINMGR: loaded %d users from /config/users.json\n", app->n_sysusers); fflush(stdout);
}

static void load_syssvcs(struct app *app)
{
    app->n_syssvcs = 0;
    unsigned char *buf; size_t sz;
    if (load_file("/config/services.json", &buf, &sz) < 0 || sz == 0) return;
    char *json = malloc(sz + 1);
    if (!json) { free(buf); return; }
    memcpy(json, buf, sz); json[sz] = 0; free(buf);

    const char *p = json;
    while (app->n_syssvcs < MAX_SYSSVCS) {
        const char *nm = strstr(p, "\"name\"");
        if (!nm) break;
        const char *e = strstr(nm + 6, "\"name\"");
        if (!e) e = json + sz;
        struct gsyssvc *g = &app->syssvcs[app->n_syssvcs];
        memset(g, 0, sizeof(*g));
        j_field(nm, e, "name",  g->name,  sizeof(g->name));
        j_field(nm, e, "state", g->state, sizeof(g->state));
        char num[24];
        if (j_field(nm, e, "rights",  num, sizeof(num))) g->rights = (unsigned)strtoul(num, NULL, 16);
        if (j_field(nm, e, "version", num, sizeof(num))) g->ver    = (unsigned)strtoul(num, NULL, 10);
        if (g->name[0]) app->n_syssvcs++;
        p = e;
    }
    free(json);
    printf("DOMAINMGR: loaded %d services from /config/services.json\n", app->n_syssvcs); fflush(stdout);
}

// /desktop.conf is `key = value` lines with '#' comments.  Only the two autostart forms are
// read here; `autostart-live` is flagged because it runs on install media ONLY, and showing it
// identically to a permanent entry would misrepresent what an installed system does at boot.
static void load_startup(struct app *app)
{
    app->n_startup = 0;
    unsigned char *buf; size_t sz;
    if (load_file("/desktop.conf", &buf, &sz) < 0 || sz == 0) return;
    char *txt = malloc(sz + 1);
    if (!txt) { free(buf); return; }
    memcpy(txt, buf, sz); txt[sz] = 0; free(buf);

    for (char *line = strtok(txt, "\n"); line && app->n_startup < MAX_STARTUP;
         line = strtok(NULL, "\n")) {
        while (*line == ' ' || *line == '\t') line++;
        if (*line == '#' || *line == 0) continue;
        int live, klen;
        if      (!strncmp(line, "autostart-live", 14)) { live = 1; klen = 14; }
        else if (!strncmp(line, "autostart",       9)) { live = 0; klen =  9; }
        else continue;
        /* Reject `autostartfoo = x`: the key must end here, at space/tab or the '='. */
        if (line[klen] != ' ' && line[klen] != '\t' && line[klen] != '=') continue;
        const char *eq = strchr(line + klen, '=');
        if (!eq) continue;
        eq++;
        while (*eq == ' ' || *eq == '\t') eq++;
        struct gstartup *g = &app->startup[app->n_startup];
        memset(g, 0, sizeof(*g));
        g->live = live;
        snprintf(g->cmd, sizeof(g->cmd), "%s", eq);
        char *hash = strchr(g->cmd, '#');            /* drop a trailing comment ... */
        if (hash) *hash = 0;
        for (char *t = g->cmd + strlen(g->cmd);      /* ... then any trailing whitespace */
             t > g->cmd && (t[-1]==' '||t[-1]=='\t'||t[-1]=='\r'); t--) t[-1] = 0;
        if (g->cmd[0]) app->n_startup++;
    }
    free(txt);
    printf("DOMAINMGR: loaded %d startup entries from /desktop.conf\n", app->n_startup); fflush(stdout);
}

// Resolve a template objId to its domain name (for display).
static const char *dom_templ_name(struct app *app, unsigned templObjId)
{
    if (templObjId == 0) return "-";
    for (int i = 0; i < app->n_doms; i++)
        if (app->doms[i].objId == templObjId) return app->doms[i].name;
    return "?";
}

// DM10.2: read the selected domain's restricted-FS view (the DM2 RuntimeView) from
// /objects/domains/<name>/filesystem — the resolved, deny-by-default fs policy.
static void refresh_fs_view(struct app *app)
{
    app->fs_view[0] = 0;
    if (app->sel < 0 || app->sel >= app->n_doms) return;
    char path[96];
    snprintf(path, sizeof(path), "/objects/domains/%s/filesystem", app->doms[app->sel].name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { snprintf(app->fs_view, sizeof(app->fs_view), "(no restricted view)"); return; }
    ssize_t n = read(fd, app->fs_view, sizeof(app->fs_view) - 1);
    close(fd);
    app->fs_view[n > 0 ? n : 0] = 0;
    if (n <= 0) snprintf(app->fs_view, sizeof(app->fs_view), "(empty)");
    int binds = 0;
    for (const char *s = app->fs_view; *s; ) {
        if (strncmp(s, "rw", 2) == 0 || strncmp(s, "ro", 2) == 0 || strncmp(s, "deny", 4) == 0) binds++;
        while (*s && *s != '\n') s++;
        if (*s) s++;
    }
    printf("DOMAINMGR: RuntimeView for %s = %zd bytes, %d binding lines\n",
           app->doms[app->sel].name, n, binds); fflush(stdout);
}

// DM10.3: send a "verb name" lifecycle command to the kernel control endpoint
// (/config/domain.action), then re-read the declarative state so the GUI reflects the result.
static void domain_action(struct app *app, const char *verb)
{
    if (app->sel < 0 || app->sel >= app->n_doms) return;
    char cmd[80];
    int len = snprintf(cmd, sizeof(cmd), "%s %s", verb, app->doms[app->sel].name);
    int fd = open("/config/domain.action", O_WRONLY);
    if (fd < 0) { printf("DOMAINMGR: action '%s' open FAILED\n", cmd); fflush(stdout); return; }
    ssize_t w = write(fd, cmd, len);
    close(fd);
    printf("DOMAINMGR: action '%s' -> wrote %zd\n", cmd, w); fflush(stdout);
    int keep = app->sel;
    load_domains(app);                       // re-read state (the kernel may have changed it)
    if (keep < app->n_doms) app->sel = keep;
    refresh_fs_view(app);
}

// DM10.5: commit the Clone dialog — write "clone <src> <newname>" to the control endpoint, then
// re-read so the new domain appears in the list.
static void domain_action_clone(struct app *app)
{
    if (app->sel < 0 || app->sel >= app->n_doms || app->editlen == 0) return;
    char cmd[96];
    int len = snprintf(cmd, sizeof(cmd), "clone %s %s", app->doms[app->sel].name, app->editbuf);
    int fd = open("/config/domain.action", O_WRONLY);
    if (fd < 0) { printf("DOMAINMGR: clone open FAILED\n"); fflush(stdout); return; }
    ssize_t w = write(fd, cmd, len);
    close(fd);
    printf("DOMAINMGR: action '%s' -> wrote %zd\n", cmd, w); fflush(stdout);
    load_domains(app);                       // the clone is a NEW domain — re-read the full list
    load_packages(app);                      // domain indices shifted → re-read installs
    // select the freshly-created clone if present
    for (int i = 0; i < app->n_doms; i++)
        if (strcmp(app->doms[i].name, app->editbuf) == 0) { app->sel = i; break; }
    refresh_fs_view(app);
}

// DM10.7: send a 3-token "verb <domain> <arg>" command (devon/devoff, install/uninstall,
// fsro/fsrw/fsdeny) then re-read declarative state + packages so the tabs reflect the result.
static void domain_action_arg(struct app *app, const char *verb, const char *arg)
{
    if (app->sel < 0 || app->sel >= app->n_doms) return;
    char cmd[160];
    int len = snprintf(cmd, sizeof(cmd), "%s %s %s", verb, app->doms[app->sel].name, arg);
    int fd = open("/config/domain.action", O_WRONLY);
    if (fd < 0) { printf("DOMAINMGR: action open FAILED\n"); fflush(stdout); return; }
    ssize_t w = write(fd, cmd, len);
    close(fd);
    printf("DOMAINMGR: action '%s' -> wrote %zd\n", cmd, w); fflush(stdout);
    int keep = app->sel;
    load_domains(app);
    load_packages(app);
    load_templates(app);
    if (keep < app->n_doms) app->sel = keep;
    refresh_fs_view(app);
}

// Toolbar New (from-scratch Create) / Import (instantiate from the selected as a template).  The
// dialog's editbuf is the NEW domain's name; from_template=1 references the selected domain.
static void domain_create_new(struct app *app, int from_template)
{
    if (app->editlen == 0 || app->sel < 0 || app->sel >= app->n_doms) return;
    char cmd[160];
    if (from_template) snprintf(cmd, sizeof(cmd), "fromtpl %s %s", app->editbuf, app->doms[app->sel].name);
    else               snprintf(cmd, sizeof(cmd), "create %s %s",  app->editbuf, app->doms[app->sel].identity);
    int fd = open("/config/domain.action", O_WRONLY);
    if (fd < 0) { printf("DOMAINMGR: create open FAILED\n"); fflush(stdout); return; }
    ssize_t w = write(fd, cmd, strlen(cmd));
    close(fd);
    printf("DOMAINMGR: action '%s' -> wrote %zd\n", cmd, w); fflush(stdout);
    load_domains(app); load_packages(app); load_templates(app);
    for (int i = 0; i < app->n_doms; i++)
        if (strcmp(app->doms[i].name, app->editbuf) == 0) { app->sel = i; break; }
    refresh_fs_view(app);
}

// DM10.3: one-shot self-test that proves the control-write path end-to-end (open -> write ->
// kernel domainControlWrite) without a side effect — "ping" is a no-op verb.
static void domain_ctl_selftest(struct app *app)
{
    int fd = open("/config/domain.action", O_WRONLY);
    if (fd < 0) { printf("DOMAINMGR: control-write path UNAVAILABLE (open failed)\n"); fflush(stdout); return; }
    const char *name = app->n_doms > 0 ? app->doms[0].name : "System";
    char cmd[64]; int len = snprintf(cmd, sizeof(cmd), "ping %s", name);
    ssize_t w = write(fd, cmd, len);
    close(fd);
    printf("DOMAINMGR: control-write path self-test ('%s') wrote %zd\n", cmd, w); fflush(stdout);
}

static void redraw_commit(struct app *app, const char *marker);   // defined below

// DM10.6: FNV-1a hash of /config/domains.json — cheap change-detection for live updates.
static unsigned domains_hash(void)
{
    unsigned char *buf; size_t sz;
    if (load_file("/config/domains.json", &buf, &sz) < 0) return 0;
    unsigned h = 2166136261u;
    for (size_t i = 0; i < sz; i++) { h ^= buf[i]; h *= 16777619u; }
    free(buf);
    return h;
}

// DM10.6: live update — re-read /config/domains.json on the event-loop timeout; if it changed
// (any actor: another client, the kernel), reload the list + redraw.  Skipped while the clone
// dialog is open so typing isn't disrupted.
static void live_refresh(struct app *app)
{
    if (app->editing) return;
    unsigned h = domains_hash();
    if (h == app->last_hash) return;
    app->last_hash = h;
    int keep = app->sel;
    load_domains(app);
    load_packages(app);
    load_templates(app);
    if (keep < app->n_doms) app->sel = keep;
    refresh_fs_view(app);
    redraw_commit(app, "live update");
    printf("DOMAINMGR: live update — /config/domains.json changed (now %d domains)\n", app->n_doms);
    fflush(stdout);
}

// DM10.6 verification: gated by $HOS_DM_LIVETEST, fork an "external actor" that changes a domain a
// few seconds after the GUI is up (start, then stop) — proving the parent's live_refresh detects a
// change it did NOT initiate.  Off by default (no per-boot side effect).
static void domain_livetest_spawn(struct app *app)
{
    if (!getenv("HOS_DM_LIVETEST")) return;        // opt-in: no per-boot side effect by default
    char name[24];
    snprintf(name, sizeof(name), "%s", app->n_doms > 0 ? app->doms[app->n_doms - 1].name : "DevSandbox");
    pid_t pid = fork();
    if (pid != 0) return;                       // parent (the GUI) continues
    for (int phase = 0; phase < 2; phase++) {
        struct timespec ts = { .tv_sec = phase == 0 ? 4 : 2, .tv_nsec = 0 };
        nanosleep(&ts, NULL);
        int fd = open("/config/domain.action", O_WRONLY);
        if (fd >= 0) { char c[64]; int n = snprintf(c, sizeof(c), "%s %s", phase == 0 ? "start" : "stop", name); write(fd, c, n); close(fd); }
    }
    _exit(0);
}

// ── DM10.7 tab panels.  Each renders BOTH passes: cr != NULL = cairo shapes, cr == NULL = text. ──
#define N_OVPILL 4
static const char *OV_LABEL[N_OVPILL] = { "Shell", "Terminal", "Memory", "Network" };
static const int   OV_CTL  [N_OVPILL] = { 5, 6, 0, 2 };   // index into the cfg control set
static void ov_pill_rect(int idx, int *x, int *y, int *w, int *h) {
    *y = TAB_Y + 64 + idx * 30; *h = 26; *w = 220; *x = LABEL_X + 130;
}

static void tab_overview(struct app *app, cairo_t *cr) {
    struct gdomain *sd = &app->doms[app->sel];
    struct dconf *cc = &app->cfg[app->sel];
    const char *st = sd->state; int running = (st[0]=='R'), paused = (st[0]=='P');
    if (cr) {
        for (int i = 0; i < N_OVPILL; i++) {
            int x,y,w,h; ov_pill_rect(i,&x,&y,&w,&h);
            cairo_set_source_rgb(cr, 0.157,0.184,0.224); rounded_rect(cr,x,y,w,h,6); cairo_fill(cr);
        }
        for (int a = 0; a < N_LIFE; a++) {
            int x,y,w,h; life_btn_rect(a,&x,&y,&w,&h);
            int en = (a==0) ? (!running && !paused) : (a==3) ? paused : (running||paused);
            if (a==0 && en)      cairo_set_source_rgb(cr,0.20,0.52,0.34);
            else if (a==1 && en) cairo_set_source_rgb(cr,0.52,0.26,0.26);
            else if (en)         cairo_set_source_rgb(cr,0.22,0.30,0.42);
            else                 cairo_set_source_rgb(cr,0.16,0.18,0.22);
            rounded_rect(cr,x,y,w,h,7); cairo_fill(cr);
        }
    } else {
        int lx = LABEL_X, ry = TAB_Y + 6; char b[96];
        draw_text(app,"Template",lx,ry,120,14,0xffb7c1d0u);
        snprintf(b,sizeof(b),"%s%s",dom_templ_name(app,sd->templObjId),sd->templObjId?"  (immutable)":"");
        draw_text(app,b,lx+130,ry,360,14,0xfff2f5fau); ry+=22;
        draw_text(app,"Persist",lx,ry,120,14,0xffb7c1d0u);
        draw_text(app,sd->persist,lx+130,ry,140,14,0xfff2f5fau);
        draw_text(app,"Identity",lx+300,ry,80,14,0xffb7c1d0u);
        draw_text(app,sd->identity,lx+380,ry,150,14,0xfff2f5fau); ry+=22;
        draw_text(app,"State",lx,ry,120,14,0xffb7c1d0u);
        draw_text(app,sd->state,lx+130,ry,150,14, running?0xff7fe0a0u:0xffd6deeau);
        for (int i = 0; i < N_OVPILL; i++) {
            int x,y,w,h; ov_pill_rect(i,&x,&y,&w,&h);
            draw_text(app,OV_LABEL[i],lx,y+6,120,13,0xffb7c1d0u);
            char val[48]; ctl_value(cc,OV_CTL[i],val,sizeof(val));
            draw_text(app,val,x+10,y+6,w-16,13,0xfff2f5fau);
        }
        draw_text(app,"Lifecycle",LABEL_X,TAB_Y+178,120,12,0xff8b94a3u);
        for (int a = 0; a < N_LIFE; a++) { int x,y,w,h; life_btn_rect(a,&x,&y,&w,&h);
            draw_text(app,LIFE_LABEL[a],x+8,y+9,w-12,13,0xffe8edf5u); }
    }
}

static void tab_filesystem(struct app *app, cairo_t *cr) {
    if (cr) {
        for (int i = 0; i < N_FSBTN; i++) { int x,y,w,h; fs_btn_rect(i,&x,&y,&w,&h);
            if (i==2) cairo_set_source_rgb(cr,0.44,0.24,0.24); else cairo_set_source_rgb(cr,0.22,0.34,0.30);
            rounded_rect(cr,x,y,w,h,6); cairo_fill(cr); }
    } else {
        for (int i = 0; i < N_FSBTN; i++) { int x,y,w,h; fs_btn_rect(i,&x,&y,&w,&h);
            draw_text(app,FSBTN_LABEL[i],x+8,y+7,w-12,12,0xffe8edf5u); }
        draw_text(app,"Resolved policy (RuntimeView) — grant a REAL path with +Allow/+Mount, restrict with +Deny:",
                  LABEL_X, TAB_Y+48, app->width-LABEL_X-PAD, 12, 0xff8b94a3u);
        const char *s = app->fs_view; int line = 0, fy = TAB_Y + 70;
        while (*s && line < 24) {
            char ln[96]; int i = 0; while (*s && *s!='\n' && i<95) ln[i++]=*s++; ln[i]=0; if (*s=='\n') s++;
            uint32_t col = 0xffaab3c2u;
            if (ln[0]=='#') col=0xff6b7686u;
            else if (!strncmp(ln,"deny",4)) col=0xffe08a8au;
            else if (!strncmp(ln,"rw",2))   col=0xff9fe0a8u;
            else if (!strncmp(ln,"ro",2))   col=0xffd8d09au;
            else if (!strncmp(ln,"defaultPolicy",13)) col=0xffd6deeau;
            draw_text(app,ln,LABEL_X,fy+line*15,app->width-LABEL_X-PAD,12,col); line++;
        }
    }
}

static void tab_packages(struct app *app, cairo_t *cr) {
    struct gdomain *sd = &app->doms[app->sel];
    unsigned mask = app->pkg_mask[app->sel];
    if (cr) {
        for (int i = 0; i < N_DISTRO; i++) { int x,y,w,h; distro_btn_rect(i,&x,&y,&w,&h);  // DM11 distro selector
            if (strcmp(sd->distro, DISTRO_NAME[i]) == 0) cairo_argb(cr, sd->color);
            else cairo_set_source_rgb(cr,0.18,0.22,0.28);
            rounded_rect(cr,x,y,w,h,6); cairo_fill(cr); }
        for (int i = 0; i < N_PROFILE; i++) { int x,y,w,h; profile_btn_rect(i,&x,&y,&w,&h);  // DM11 profiles
            cairo_set_source_rgb(cr,0.22,0.30,0.42); rounded_rect(cr,x,y,w,h,6); cairo_fill(cr); }
        for (int i = 0; i < app->n_pkgs; i++) { int x,y,w,h; pkg_row_rect(i,&x,&y,&w,&h);
            if ((mask>>i)&1) cairo_set_source_rgb(cr,0.46,0.26,0.26); else cairo_set_source_rgb(cr,0.22,0.30,0.42);
            rounded_rect(cr,x,y,w,h,6); cairo_fill(cr); }
    } else {
        char hd[112]; snprintf(hd,sizeof(hd),"Distribution: %s    Package manager: %s    (/linux = RO compat root)",
                               sd->distro[0]?sd->distro:"native", sd->pkgmgr[0]?sd->pkgmgr:"native");
        draw_text(app, hd, LABEL_X, TAB_Y+8, app->width-LABEL_X-PAD, 12, 0xff8b94a3u);
        draw_text(app,"Distro:",LABEL_X,TAB_Y+35,80,13,0xffb7c1d0u);
        for (int i = 0; i < N_DISTRO; i++) { int x,y,w,h; distro_btn_rect(i,&x,&y,&w,&h);
            draw_text(app, DISTRO_NAME[i], x+8, y+5, w-12, 12, 0xffe8edf5u); }
        draw_text(app,"Profiles:",LABEL_X,TAB_Y+69,70,13,0xffb7c1d0u);
        for (int i = 0; i < N_PROFILE; i++) { int x,y,w,h; profile_btn_rect(i,&x,&y,&w,&h);
            draw_text(app, PROFILE_NAME[i], x+6, y+5, w-8, 12, 0xffe8edf5u); }
        draw_text(app,"Repository (cap-gated install per domain):",LABEL_X,TAB_Y+98,420,12,0xff6b7686u);
        for (int i = 0; i < app->n_pkgs; i++) {
            int x,y,w,h; pkg_row_rect(i,&x,&y,&w,&h);
            struct gpkg *p = &app->pkgs[i];
            char nm[64]; snprintf(nm,sizeof(nm),"%s  %s",p->name,p->ver);
            draw_text(app,nm,LABEL_X,y+6,210,13,0xfff2f5fau);
            char sz[24]; snprintf(sz,sizeof(sz),"%d KB",p->sizeKb);
            draw_text(app,sz,LABEL_X+220,y+6,90,12,0xff97a1b0u);
            draw_text(app, ((mask>>i)&1)?"Remove":"Install", x+12, y+5, w-16, 12, 0xffe8edf5u);
        }
    }
}

static void tab_network(struct app *app, cairo_t *cr) {
    struct dconf *cc = &app->cfg[app->sel];
    if (!cr) {
        int ry = TAB_Y + 12; char v[48];
        draw_text(app,"Network policy",LABEL_X,ry,200,14,0xffb7c1d0u);
        ctl_value(cc,2,v,sizeof(v)); draw_text(app,v,LABEL_X+200,ry,220,14,0xfff2f5fau); ry+=28;
        draw_text(app,"Clipboard",LABEL_X,ry,200,14,0xffb7c1d0u);
        ctl_value(cc,3,v,sizeof(v)); draw_text(app,v,LABEL_X+200,ry,220,14,0xfff2f5fau); ry+=28;
        draw_text(app,"Secure IPC",LABEL_X,ry,200,14,0xffb7c1d0u);
        draw_text(app,cc->secure_ipc?"required":"optional",LABEL_X+200,ry,200,14,0xfff2f5fau);
        draw_text(app,"network / clipboard runtime enforcement is the next DM8 surface",LABEL_X,ry+44,560,12,0xff6b7686u);
    }
}

static void tab_permissions(struct app *app, cairo_t *cr) {
    unsigned dev = app->doms[app->sel].devices;
    if (cr) {
        for (int i = 0; i < N_DEV; i++) { int x,y,w,h; dev_row_rect(i,&x,&y,&w,&h);
            int on = (dev & DEV_BIT[i]) != 0;
            if (on) cairo_set_source_rgb(cr,0.20,0.50,0.34); else cairo_set_source_rgb(cr,0.40,0.20,0.20);
            rounded_rect(cr,x,y,w,h,h/2); cairo_fill(cr);
            cairo_set_source_rgb(cr,0.95,0.97,1.0);
            cairo_arc(cr, on?(x+w-h/2):(x+h/2), y+h/2.0, h/2-3, 0, 6.2832); cairo_fill(cr); }
    } else {
        draw_text(app,"Peripheral devices — toggle a class to grant/deny this domain; enforced at open():",
                  LABEL_X, TAB_Y+6, app->width-LABEL_X-PAD, 12, 0xff8b94a3u);
        for (int i = 0; i < N_DEV; i++) { int x,y,w,h; dev_row_rect(i,&x,&y,&w,&h);
            int on = (dev & DEV_BIT[i]) != 0;
            draw_text(app,DEV_LABEL[i],LABEL_X,y+8,230,14,0xffd6deeau);
            draw_text(app, on?"allowed":"denied", x+w+12, y+8, 90,13, on?0xff7fe0a0u:0xffe08a8au); }
    }
}

// Applications installed for this domain.  Clicking Launch spawns the program CONFINED into
// the selected domain (kernel `spawn` verb), so it runs under that domain's namespace, device
// mask and network policy -- not merely with a colour and some environment variables.
//
// This replaces the old "Startup" tab, which drew three static strings (one hardcoded
// "Terminal (gl-term)" and a "(planned)" note) and could not launch anything.
static void tab_applications(struct app *app, cairo_t *cr) {
    struct gdomain *sd = &app->doms[app->sel];
    if (cr) {
        for (int i = 0; i < app->n_avail; i++) {
            int x,y,w,h; appl_row_rect(i,&x,&y,&w,&h);
            cairo_argb(cr, sd->color);
            rounded_rect(cr,x,y,w,h,6); cairo_fill(cr);
        }
    } else {
        char hd[128];
        snprintf(hd,sizeof(hd),"Applications available in '%s' — Launch runs them confined in this domain",
                 sd->name);
        draw_text(app, hd, LABEL_X, TAB_Y+10, app->width-LABEL_X-PAD, 12, 0xff8b94a3u);
        for (int i = 0; i < app->n_avail; i++) {
            int x,y,w,h; appl_row_rect(i,&x,&y,&w,&h);
            const struct dmapp *a = &DMAPPS[app->avail[i]];
            draw_text(app, a->label, LABEL_X, y+6, 200, 13, 0xfff2f5fau);
            draw_text(app, a->exec,  LABEL_X+210, y+7, 200, 12, 0xff97a1b0u);
            draw_text(app, "Launch", x+22, y+5, w-16, 12, 0xffe8edf5u);
        }
        if (app->n_avail == 0)
            draw_text(app,"(no application binaries found on this system)",
                      LABEL_X+10, TAB_Y+44, 420, 13, 0xff8d97a6u);
    }
}

static void tab_appearance(struct app *app, cairo_t *cr) {
    struct gdomain *sd = &app->doms[app->sel];
    if (cr) {
        cairo_argb(cr,sd->color); rounded_rect(cr,LABEL_X+220,TAB_Y+10,64,30,6); cairo_fill(cr);
        int x,y,w,h; export_btn_rect(&x,&y,&w,&h);                       // DM12 Export
        cairo_set_source_rgb(cr,0.22,0.34,0.30); rounded_rect(cr,x,y,w,h,6); cairo_fill(cr);
    } else {
        draw_text(app,"Border color",LABEL_X,TAB_Y+18,200,14,0xffb7c1d0u);
        char c[16]; snprintf(c,sizeof(c),"#%06X",sd->color & 0xffffff);
        draw_text(app,c,LABEL_X+300,TAB_Y+18,120,14,0xfff2f5fau);
        draw_text(app,"Wallpaper",LABEL_X,TAB_Y+58,200,14,0xffb7c1d0u);
        draw_text(app,"(domain default)",LABEL_X+220,TAB_Y+58,200,14,0xff97a1b0u);
        // DM12: export this domain as a signed template + the local template registry
        int x,y,w,h; export_btn_rect(&x,&y,&w,&h);
        draw_text(app,"Export as signed .hosdt template",x+10,y+7,w-14,12,0xffe8edf5u);
        draw_text(app,"Installed signed templates (HMAC-verified, publisher-trusted):",
                  LABEL_X, TAB_Y+142, app->width-LABEL_X-PAD, 12, 0xff8b94a3u);
        for (int i = 0; i < app->n_templates; i++) {
            struct gtemplate *t = &app->templates[i];
            char ln[96]; snprintf(ln,sizeof(ln),"%s  v%s   publisher: %s", t->name, t->ver[0]?t->ver:"?", t->publisher);
            draw_text(app, ln, LABEL_X+10, TAB_Y+166+i*20, app->width-LABEL_X-PAD-10, 13, 0xfff2f5fau);
        }
        if (app->n_templates == 0)
            draw_text(app,"(none yet — click Export to publish this domain)",LABEL_X+10,TAB_Y+166,420,13,0xff8d97a6u);
        draw_text(app,"Marketplace / I2P P2P sharing: out of scope (needs a network stack)",
                  LABEL_X, app->height-FOOTER_H-40, 560, 11, 0xff5b6675u);
    }
}

// ── ROADMAP 1.5 — SYSTEM-scoped tabs ──────────────────────────────────────────────────────
// These three describe the machine, not the selected domain, so each states that in its header
// rather than letting the domain name above the tab bar imply otherwise.  Text-only (the
// cr == NULL pass): they are read-only reports, so there is nothing to draw a button for.
// Making them mutable means a kernel write path (users/services are object tables behind
// capability checks, and /desktop.conf is a read-only boot module), which is a separate job --
// showing a control that silently does nothing is exactly the fake UI this file has already
// had to delete once.

static void tab_users(struct app *app, cairo_t *cr) {
    if (cr) return;
    draw_text(app, "System users — from /config/users.json, the kernel's live User object table",
              LABEL_X, TAB_Y+10, app->width-LABEL_X-PAD, 12, 0xff8b94a3u);
    draw_text(app, "Name",   LABEL_X+10,  TAB_Y+38, 200, 12, 0xffb7c1d0u);
    draw_text(app, "UID",    LABEL_X+230, TAB_Y+38,  60, 12, 0xffb7c1d0u);
    draw_text(app, "GID",    LABEL_X+300, TAB_Y+38,  60, 12, 0xffb7c1d0u);
    draw_text(app, "Rights", LABEL_X+370, TAB_Y+38, 120, 12, 0xffb7c1d0u);
    for (int i = 0; i < app->n_sysusers; i++) {
        const struct gsysuser *u = &app->sysusers[i];
        int y = TAB_Y + 60 + i * 20;
        if (y > app->height - FOOTER_H - 30) break;
        char n[24];
        draw_text(app, u->name, LABEL_X+10, y, 210, 13, 0xfff2f5fau);
        snprintf(n,sizeof(n),"%u",u->uid);    draw_text(app,n,LABEL_X+230,y,60,13,0xff97a1b0u);
        snprintf(n,sizeof(n),"%u",u->gid);    draw_text(app,n,LABEL_X+300,y,60,13,0xff97a1b0u);
        snprintf(n,sizeof(n),"0x%X",u->rights);draw_text(app,n,LABEL_X+370,y,120,13,0xff97a1b0u);
    }
    if (app->n_sysusers == 0)
        draw_text(app, "(no users — /config/users.json is empty or unreadable)",
                  LABEL_X+10, TAB_Y+60, 460, 13, 0xff8d97a6u);
}

static void tab_services(struct app *app, cairo_t *cr) {
    if (cr) return;
    draw_text(app, "System services — from /config/services.json, the kernel's live Service table",
              LABEL_X, TAB_Y+10, app->width-LABEL_X-PAD, 12, 0xff8b94a3u);
    draw_text(app, "Name",    LABEL_X+10,  TAB_Y+38, 240, 12, 0xffb7c1d0u);
    draw_text(app, "State",   LABEL_X+270, TAB_Y+38,  90, 12, 0xffb7c1d0u);
    draw_text(app, "Version", LABEL_X+370, TAB_Y+38,  70, 12, 0xffb7c1d0u);
    draw_text(app, "Rights",  LABEL_X+450, TAB_Y+38, 120, 12, 0xffb7c1d0u);
    for (int i = 0; i < app->n_syssvcs; i++) {
        const struct gsyssvc *s = &app->syssvcs[i];
        int y = TAB_Y + 60 + i * 20;
        if (y > app->height - FOOTER_H - 30) break;
        char n[24];
        int started = !strcmp(s->state, "started");   /* hoscall.d CFG_SERVICES: "started" | "stopped" */
        draw_text(app, s->name, LABEL_X+10, y, 250, 13, 0xfff2f5fau);
        draw_text(app, s->state[0] ? s->state : "?", LABEL_X+270, y, 90, 13,
                  started ? 0xff7fd18cu : 0xffd18c7fu);
        snprintf(n,sizeof(n),"v%u",s->ver);      draw_text(app,n,LABEL_X+370,y,70,13,0xff97a1b0u);
        snprintf(n,sizeof(n),"0x%X",s->rights);  draw_text(app,n,LABEL_X+450,y,120,13,0xff97a1b0u);
    }
    if (app->n_syssvcs == 0)
        draw_text(app, "(no services registered — /config/services.json is empty)",
                  LABEL_X+10, TAB_Y+60, 460, 13, 0xff8d97a6u);
}

static void tab_startup(struct app *app, cairo_t *cr) {
    if (cr) return;
    draw_text(app, "Startup applications — from /desktop.conf, the file the kernel itself parses at boot",
              LABEL_X, TAB_Y+10, app->width-LABEL_X-PAD, 12, 0xff8b94a3u);
    for (int i = 0; i < app->n_startup; i++) {
        const struct gstartup *s = &app->startup[i];
        int y = TAB_Y + 44 + i * 20;
        if (y > app->height - FOOTER_H - 30) break;
        draw_text(app, s->cmd, LABEL_X+10, y, 420, 13, 0xfff2f5fau);
        draw_text(app, s->live ? "install media only" : "every boot",
                  LABEL_X+440, y, 200, 12, s->live ? 0xffd1b87fu : 0xff97a1b0u);
    }
    if (app->n_startup == 0)
        draw_text(app, "(nothing autostarts — no `autostart =` lines in /desktop.conf)",
                  LABEL_X+10, TAB_Y+44, 480, 13, 0xff8d97a6u);
    draw_text(app, "Read-only: /desktop.conf is a boot module, so editing it needs a rebuild of the image.",
              LABEL_X, app->height-FOOTER_H-40, 620, 11, 0xff5b6675u);
}

static void draw_tab(struct app *app, cairo_t *cr) {
    switch (app->tab) {
        case 0: tab_overview(app,cr);    break;
        case 1: tab_filesystem(app,cr);  break;
        case 2: tab_packages(app,cr);    break;
        case 3: tab_network(app,cr);     break;
        case 4: tab_permissions(app,cr); break;
        case 5: tab_applications(app,cr); break;
        case 6: tab_appearance(app,cr);  break;
        case 7: tab_users(app,cr);       break;   // ROADMAP 1.5
        case 8: tab_services(app,cr);    break;   // ROADMAP 1.5
        case 9: tab_startup(app,cr);     break;   // ROADMAP 1.5
    }
}

static void draw_manager(struct app *app)
{
    cairo_surface_t *surface = cairo_image_surface_create_for_data(
        (unsigned char *)app->pixels, CAIRO_FORMAT_RGB24, app->width, app->height, app->stride);
    cairo_t *cr = cairo_create(surface);
    struct gdomain *sd = &app->doms[app->sel];
    int rpw = app->width - RP_X;   // right-pane width

    // Backdrop + left list pane.
    cairo_set_source_rgb(cr, 0.118, 0.137, 0.165); cairo_paint(cr);
    cairo_set_source_rgb(cr, 0.102, 0.118, 0.145);
    cairo_rectangle(cr, 0, BODY_Y, LIST_W, app->height - BODY_Y); cairo_fill(cr);

    // Header band + crest.
    cairo_set_source_rgb(cr, 0.086, 0.102, 0.125);
    cairo_rectangle(cr, 0, 0, app->width, HEADER_H); cairo_fill(cr);
    { double sx = PAD, sy = 14, sw = 22, sh = 28;
      cairo_set_source_rgb(cr, 0.36, 0.62, 0.96);
      cairo_move_to(cr, sx, sy); cairo_line_to(cr, sx + sw, sy);
      cairo_line_to(cr, sx + sw, sy + sh * 0.55);
      cairo_curve_to(cr, sx + sw, sy + sh, sx + sw/2, sy + sh, sx + sw/2, sy + sh);
      cairo_curve_to(cr, sx + sw/2, sy + sh, sx, sy + sh, sx, sy + sh * 0.55);
      cairo_close_path(cr); cairo_fill(cr); }

    // Toolbar band + verb buttons.
    cairo_set_source_rgb(cr, 0.078, 0.094, 0.118);
    cairo_rectangle(cr, 0, HEADER_H, app->width, TOOLBAR_H); cairo_fill(cr);
    for (int i = 0; i < N_TOOL; i++) { int x,y,w,h; toolbar_btn_rect(i,&x,&y,&w,&h);
        cairo_set_source_rgb(cr, 0.18, 0.22, 0.28); rounded_rect(cr,x,y,w,h,6); cairo_fill(cr); }
    cairo_set_source_rgb(cr, 0.22, 0.27, 0.33);
    cairo_rectangle(cr, 0, BODY_Y - 1, app->width, 1); cairo_fill(cr);
    cairo_rectangle(cr, LIST_W, BODY_Y, 1, app->height - BODY_Y); cairo_fill(cr);

    // Domain list (status dots) + Delete.
    for (int i = 0; i < app->n_doms; i++) {
        struct gdomain *d = &app->doms[i];
        int ry = BODY_Y + 4 + i * ROW_H;
        if (i == app->sel) {
            cairo_set_source_rgb(cr, 0.16, 0.20, 0.27); cairo_rectangle(cr, 0, ry, LIST_W, ROW_H); cairo_fill(cr);
            cairo_argb(cr, d->color); cairo_rectangle(cr, 0, ry, 4, ROW_H); cairo_fill(cr);
        }
        double cy = ry + ROW_H / 2.0; int isTpl = (d->type[0] == 't'); cairo_argb(cr, d->color);
        if (isTpl) { cairo_move_to(cr, PAD+8, cy-8); cairo_line_to(cr, PAD+16, cy);
            cairo_line_to(cr, PAD+8, cy+8); cairo_line_to(cr, PAD, cy); cairo_close_path(cr);
            cairo_set_line_width(cr,1.8); cairo_stroke(cr); }
        else { rounded_rect(cr, PAD, cy-8, 16, 16, 5); cairo_fill(cr); }
        int run = (d->state[0]=='R'), pau = (d->state[0]=='P');
        if (run)      cairo_set_source_rgb(cr, 0.30,0.78,0.45);
        else if (pau) cairo_set_source_rgb(cr, 0.92,0.66,0.20);
        else          cairo_set_source_rgb(cr, 0.34,0.40,0.48);
        cairo_arc(cr, LIST_W-18, cy, 4, 0, 6.2832);
        if (run||pau) cairo_fill(cr); else { cairo_set_line_width(cr,1.5); cairo_stroke(cr); }
    }
    { int x,y,w,h; delete_btn_rect(app,&x,&y,&w,&h);
      cairo_set_source_rgb(cr, 0.30,0.18,0.18); rounded_rect(cr,x,y,w,h,6); cairo_fill(cr); }

    // Right pane: domain header (color swatch + status dot) + tab bar.
    cairo_argb(cr, sd->color); rounded_rect(cr, LABEL_X, BODY_Y+11, 14, 14, 4); cairo_fill(cr);
    if (sd->state[0]=='R') cairo_set_source_rgb(cr,0.30,0.78,0.45); else cairo_set_source_rgb(cr,0.5,0.55,0.62);
    cairo_arc(cr, app->width - 150, BODY_Y+18, 5, 0, 6.2832); cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.078, 0.094, 0.118);
    cairo_rectangle(cr, RP_X, BODY_Y+DOMHDR_H, rpw, TABBAR_H); cairo_fill(cr);
    for (int i = 0; i < N_TABS; i++) { int x,y,w,h; tab_rect(i,&x,&y,&w,&h);
        if (i == app->tab) { cairo_set_source_rgb(cr,0.16,0.20,0.27); cairo_rectangle(cr,x,y,w,h); cairo_fill(cr);
            cairo_argb(cr, sd->color); cairo_rectangle(cr,x,y+h-3,w,3); cairo_fill(cr); } }

    draw_tab(app, cr);   // active tab graphics

    // Status bar.
    cairo_set_source_rgb(cr, 0.086, 0.102, 0.125);
    cairo_rectangle(cr, 0, app->height - FOOTER_H, app->width, FOOTER_H); cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.22, 0.27, 0.33);
    cairo_rectangle(cr, 0, app->height - FOOTER_H, app->width, 1); cairo_fill(cr);

    // Text-input dialog (clone name OR a filesystem path).
    if (app->editing) {
        int dw = 460, dh = 130, dx = (app->width-dw)/2, dy = (app->height-dh)/2;
        cairo_set_source_rgba(cr, 0,0,0, 0.45); cairo_rectangle(cr, 0,0, app->width, app->height); cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.16,0.19,0.24); rounded_rect(cr, dx,dy,dw,dh, 12); cairo_fill(cr);
        cairo_argb(cr, sd->color); rounded_rect(cr, dx,dy,dw,5, 12); cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.10,0.12,0.15); rounded_rect(cr, dx+20,dy+56,dw-40,34, 7); cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.30,0.40,0.55); rounded_rect(cr, dx+20,dy+56,dw-40,34, 7);
        cairo_set_line_width(cr, 1.5); cairo_stroke(cr);
    }

    cairo_destroy(cr); cairo_surface_flush(surface); cairo_surface_destroy(surface);

    // ── text pass ──
    draw_text(app, "Domain Manager", PAD + 40, 14, 300, 18, 0xfff2f5fau);
    for (int i = 0; i < N_TOOL; i++) { int x,y,w,h; toolbar_btn_rect(i,&x,&y,&w,&h);
        draw_text(app, TOOL_LABEL[i], x+8, y+7, w-12, 12, 0xffd6deeau); }
    for (int i = 0; i < app->n_doms; i++) { struct gdomain *d = &app->doms[i];
        int ry = BODY_Y + 4 + i * ROW_H; uint32_t nc = 0xff000000u | (d->color & 0xffffff);
        draw_text(app, d->name, PAD+26, ry + (ROW_H-13)/2, 150, 13, nc); }
    { int x,y,w,h; delete_btn_rect(app,&x,&y,&w,&h);
      draw_text(app, "Delete domain", x+14, y+7, w-16, 12, 0xffe0a8a8u); }

    // Domain header + tabs.
    draw_text(app, sd->name, LABEL_X+22, BODY_Y+11, 300, 16, 0xfff0f3f8u);
    { char hs[64]; snprintf(hs,sizeof(hs),"%s   %s", sd->state, sd->type);
      draw_text(app, hs, app->width-140, BODY_Y+12, 130, 13, (sd->state[0]=='R')?0xff7fe0a0u:0xff9aa4b3u); }
    for (int i = 0; i < N_TABS; i++) { int x,y,w,h; tab_rect(i,&x,&y,&w,&h);
        draw_text(app, TAB_LABEL[i], x+10, y+9, w-12, 13, (i==app->tab)?0xfff2f5fau:0xff8d97a6u); }

    draw_tab(app, NULL);   // active tab text

    { char foot[256];
      snprintf(foot, sizeof(foot), "%s  -  identity %s  -  %s  -  devices 0x%X  -  %d packages in repo",
               sd->name, sd->identity, sd->state, sd->devices, app->n_pkgs);
      draw_text(app, foot, PAD, app->height - FOOTER_H + 8, app->width - 2*PAD, 12, 0xff9aa4b3u); }

    if (app->editing) {
        int dw = 460, dh = 130, dx = (app->width-dw)/2, dy = (app->height-dh)/2;
        const char *head = app->edit_mode==0 ? "Clone domain - new name:" :
                           app->edit_mode==1 ? "Grant READ-ONLY filesystem path:" :
                           app->edit_mode==3 ? "DENY filesystem path:" :
                           app->edit_mode==4 ? "Create new domain - name:" :
                           app->edit_mode==5 ? "Instantiate from template - new name:" :
                                               "Grant READ-WRITE filesystem path:";
        char h2[96]; snprintf(h2,sizeof(h2),"%s  (domain %s)", head, sd->name);
        draw_text(app, h2, dx+20, dy+20, dw-40, 14, 0xfff0f3f8u);
        char field[100]; snprintf(field,sizeof(field),"%s_", app->editbuf);
        draw_text(app, field, dx+30, dy+64, dw-60, 16, 0xfff2f5fau);
        draw_text(app, "Enter = apply,  Esc = cancel", dx+20, dy+100, dw-40, 12, 0xff8b94a3u);
    }

    wl_deco_draw(app->pixels, app->width, app->width, app->height, 0xffd0d6e0u);
}

// --- buffer / commit ------------------------------------------------------

// Create the shm buffer ONCE and keep it mapped — app->pixels IS the shared
// memory the compositor reads.  Creating a fresh memfd per frame (the old code)
// leaked the kernel's small pool of memfd slots: the compositor holds each
// buffer's fd, so after a few dozen redraws memfd_create failed and NO client
// could allocate a buffer (the whole desktop froze).  Now: one memfd, draw in
// place, just re-attach+commit each frame.
static int create_buffer_once(struct app *app)
{
    if (app->buffer) return 0;
    int fd = create_memfd("epin-domain-manager");
    if (fd < 0) { perror("DOMAINMGR: memfd_create"); return -1; }
    if (ftruncate(fd, (off_t)app->buffer_size) < 0) { perror("DOMAINMGR: ftruncate"); close(fd); return -1; }
    app->pixels = (uint32_t *)mmap(NULL, app->buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (app->pixels == MAP_FAILED) { perror("DOMAINMGR: mmap"); close(fd); app->pixels = NULL; return -1; }
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int)app->buffer_size);
    app->buffer = wl_shm_pool_create_buffer(pool, 0, app->width, app->height,
                                            app->stride, WL_SHM_FORMAT_XRGB8888);
    wl_shm_pool_destroy(pool);
    close(fd);   // the compositor holds the buffer's reference; this is the only memfd
    if (!app->buffer) { log_line("DOMAINMGR: create_buffer failed"); return -1; }
    return 0;
}

static void redraw_commit(struct app *app, const char *marker)
{
    if (!app->buffer || !app->pixels) return;
    draw_manager(app);                 // draw directly into the persistent shared buffer
    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    if (marker) { printf("DOMAINMGR: %s\n", marker); fflush(stdout); }
}

static int create_shm_buffer(struct app *app, int width, int height)
{
    app->width = width > 0 ? width : DEFAULT_WIDTH;
    app->height = height > 0 ? height : DEFAULT_HEIGHT;
    app->stride = app->width * 4;
    app->buffer_size = (size_t)app->stride * (size_t)app->height;
    if (!app->font_ready) init_freetype(app);
    if (create_buffer_once(app) < 0) return -1;
    draw_manager(app);
    return 0;
}

// Tiling WM support: the compositor dictates our size via a configure event.  Tear
// down the persistent shm buffer + its mapping and rebuild at the new dimensions;
// create_shm_buffer() then reflows the whole UI, whose layout is derived entirely
// from app->width/app->height (draw_manager + the geometry helpers).  Resizes are
// infrequent, so allocating a fresh memfd per resize is fine (unlike per-frame).
static int resize_buffer(struct app *app, int width, int height)
{
    if (width <= 0 || height <= 0) return 0;
    if (app->buffer && width == app->width && height == app->height) return 0;
    if (app->buffer) { wl_buffer_destroy(app->buffer); app->buffer = NULL; }
    if (app->pixels && app->pixels != MAP_FAILED) munmap(app->pixels, app->buffer_size);
    app->pixels = NULL;
    return create_shm_buffer(app, width, height);   // sets width/height/stride, remaps, redraws
}

// --- launch ---------------------------------------------------------------

// DM3: launch a program CONFINED in the selected domain.
//
// Contrast with launch_app() below, which fork()s and execve()s: that child gets environment
// variables and a window border colour, but the KERNEL never learns it belongs to a domain, so
// its Task.domainObjId stays 0 and every policy this GUI can set -- the Filesystem tab's
// fsro/fsrw/fsdeny rules, the Devices tab's toggles including Network -- is evaluated against
// nothing.  Writing the `spawn` verb instead makes the kernel create the task, bind it into a
// private clone of the domain's restricted namespace, and stamp its domainObjId, which is what
// turns all of that policy into something a running process actually feels.
//
// The kernel seeds WAYLAND_DISPLAY for every task it execs (exports.d), and the domain
// namespace binds the compositor socket, so a confined GUI program still gets a window.
static void launch_in_domain(struct app *app, const char *exe)
{
    if (app->sel < 0 || app->sel >= app->n_doms) return;

    // TERM_BIN lists three emulators but only /wl-term and /hos-term are actually staged into
    // the image -- /gl-term has never been built, and it is the default for some domains, so
    // clicking Run Shell produced "[exec] not found: /gl-term" and a failed spawn.  Fall back
    // to a terminal that exists rather than handing the kernel a path that cannot resolve.
    if (access(exe, X_OK) != 0) {
        const char *alt = (access("/wl-term", X_OK) == 0) ? "/wl-term"
                        : (access("/hos-term", X_OK) == 0) ? "/hos-term" : NULL;
        if (!alt) { log_line("Run Shell: no terminal binary available"); return; }
        printf("DOMAINMGR: %s missing -> using %s\n", exe, alt); fflush(stdout);
        exe = alt;
    }

    char cmd[160];
    int len = snprintf(cmd, sizeof(cmd), "spawn %s %s", app->doms[app->sel].name, exe);
    int fd = open("/config/domain.action", O_WRONLY);
    if (fd < 0) {
        log_line("Run Shell: /config/domain.action unavailable");
        printf("DOMAINMGR: spawn open FAILED\n"); fflush(stdout);
        return;
    }
    ssize_t w = write(fd, cmd, len);
    close(fd);
    char m[128];
    snprintf(m, sizeof(m), "spawn %s confined in '%s' (%zd)", exe, app->doms[app->sel].name, w);
    log_line(m);
    printf("DOMAINMGR: %s\n", m); fflush(stdout);
}

static void launch_app(struct app *app, const char *exe)
{
    if (app->sel < 0 || app->sel >= app->n_doms) return;
    int d = app->sel;
    struct gdomain *dm = &app->doms[d];   // DM10: the selected declarative domain
    struct dconf *c = &app->cfg[d];

    pid_t pid = fork();
    if (pid < 0) { perror("DOMAINMGR: fork"); return; }
    if (pid == 0) {
        // The Manager connected via WAYLAND_SOCKET (fd-passing).  Clear it so the
        // child opens a fresh connection to the named wayland-0 socket.
        unsetenv("WAYLAND_SOCKET");
        setenv("WAYLAND_DISPLAY", "wayland-0", 1);
        char buf[40];
        setenv("EPIN_DOMAIN", dm->name, 1);
        snprintf(buf, sizeof(buf), "0x%08x", dm->color); setenv("EPIN_DOMAIN_COLOR", buf, 1);
        setenv("EPIN_SHELL", SHELL_ENV[c->shell], 1);
        snprintf(buf, sizeof(buf), "%ld", MEM_BYTES[c->mem]); setenv("EPIN_MEM_CAP", buf, 1);
        setenv("EPIN_DISK", DISK_ENV[c->disk], 1);
        setenv("EPIN_NET", NET_ENV[c->net], 1);
        setenv("EPIN_CLIP", CLIP_ENV[c->clip], 1);
        setenv("EPIN_SECURE_IPC", c->secure_ipc ? "1" : "0", 1);
        char *argv[] = { (char *)exe, NULL };
        execve(exe, argv, environ);
        _exit(127);
    }
    char m[96];
    snprintf(m, sizeof(m), "launched %s in domain '%s' (pid %d)", exe, dm->name, (int)pid);
    log_line(m);
}

// --- input ----------------------------------------------------------------

static void handle_click(struct app *app)
{
    double x = app->pointer_x, y = app->pointer_y;
    if (app->editing) return;                       // the dialog is modal (keyboard-driven)

    // Toolbar verbs (+New / Clone / Import / Marketplace).
    if (y >= HEADER_H && y < BODY_Y) {
        for (int i = 0; i < N_TOOL; i++) { int bx,by,bw,bh; toolbar_btn_rect(i,&bx,&by,&bw,&bh);
            if (x>=bx && x<=bx+bw && y>=by && y<=by+bh) {
                if (i == 0) {                        // + New → from-scratch Create dialog
                    app->editbuf[0] = 0; app->editlen = 0; app->edit_mode = 4; app->editing = 1;
                } else if (i == 1) {                 // Clone → clone the selected domain
                    snprintf(app->editbuf, sizeof(app->editbuf), "%.18s-clone", app->doms[app->sel].name);
                    app->editlen = (int)strlen(app->editbuf); app->edit_mode = 0; app->editing = 1;
                } else if (i == 2) {                 // Import → instantiate from the selected template
                    snprintf(app->editbuf, sizeof(app->editbuf), "%.16s-instance", app->doms[app->sel].name);
                    app->editlen = (int)strlen(app->editbuf); app->edit_mode = 5; app->editing = 1;
                } else if (i == 4) {                 // Logs → scrollable diagnostic log viewer
                    launch_app(app, "/wl-logview");  // read /run/nm.log etc. (unconfined: it reads /run)
                } else if (i == 5) {                 // Run Shell → a terminal CONFINED in this domain
                    launch_in_domain(app, TERM_BIN[app->cfg[app->sel].term]);
                }
                redraw_commit(app, "toolbar");
                return;                              // Marketplace: out of scope (P2P needs a network stack)
            }
        }
        return;
    }

    // Left pane: Delete + domain selection.
    if (x < RP_X) {
        int dx,dy,dw,dh; delete_btn_rect(app,&dx,&dy,&dw,&dh);
        if (x>=dx && x<=dx+dw && y>=dy && y<=dy+dh) { domain_action(app, "delete"); redraw_commit(app,"delete"); return; }
        int top = BODY_Y + 4;
        if (y >= top && y < top + app->n_doms * ROW_H) {
            int r = (int)((y - top) / ROW_H);
            if (r >= 0 && r < app->n_doms && r != app->sel) {
                app->sel = r; refresh_fs_view(app); redraw_commit(app, "select domain");
            }
        }
        return;
    }

    // Tab bar.
    { int by = BODY_Y + DOMHDR_H;
      if (y >= by && y < by + TABBAR_H) {
          for (int i = 0; i < N_TABS; i++) { int bx,ty,bw,bh; tab_rect(i,&bx,&ty,&bw,&bh);
              if (x>=bx && x<bx+bw) {
                  app->tab = i;
                  // ROADMAP 1.5: refresh the system views when they are SELECTED rather than on
                  // a timer.  Services start and stop at runtime, but live_refresh() only fires
                  // when /config/domains.json changes, so a poll would be the only alternative --
                  // and a client that re-reads and re-commits every second is precisely what made
                  // the compositor repaint the whole screen continuously (see wl-logview).
                  if (i == 7) load_sysusers(app);
                  else if (i == 8) load_syssvcs(app);
                  else if (i == 9) load_startup(app);
                  redraw_commit(app, "tab"); return; } }
          return;
      } }

    // Active-tab content.
    if (app->tab == 0) {                            // Overview: cfg pills + lifecycle
        for (int i = 0; i < N_OVPILL; i++) { int bx,by,bw,bh; ov_pill_rect(i,&bx,&by,&bw,&bh);
            if (x>=bx && x<=bx+bw && y>=by && y<=by+bh) {
                ctl_cycle(&app->cfg[app->sel], OV_CTL[i], 1);
                // The Shell pill has to reach the KERNEL, not just this struct.  A spawned
                // program's EPIN_SHELL is derived from the domain's own mode (kernel side),
                // so a pill that only moved GUI state left "native" doing nothing at all.
                // Pushing it through the `mode` verb keeps the pill, the domain's stored
                // mode, and what a launched shell actually gets in agreement.
                if (OV_CTL[i] == 5)
                    domain_action_arg(app, "mode",
                                      strcmp(SHELL_ENV[app->cfg[app->sel].shell], "native") == 0
                                          ? "native" : "linux");
                redraw_commit(app,"cfg"); return; } }
        for (int a = 0; a < N_LIFE; a++) { int bx,by,bw,bh; life_btn_rect(a,&bx,&by,&bw,&bh);
            if (x>=bx && x<=bx+bw && y>=by && y<=by+bh) { domain_action(app, LIFE_VERB[a]); return; } }
    } else if (app->tab == 1) {                     // Filesystem: +Allow ro/rw / +Deny / +Mount → path dialog
        for (int i = 0; i < N_FSBTN; i++) { int bx,by,bw,bh; fs_btn_rect(i,&bx,&by,&bw,&bh);
            if (x>=bx && x<=bx+bw && y>=by && y<=by+bh) {
                app->edit_mode = FSBTN_MODE[i];
                snprintf(app->editbuf, sizeof(app->editbuf), "/"); app->editlen = 1; app->editing = 1;
                redraw_commit(app, "fs add"); return; } }
    } else if (app->tab == 2) {                     // Packages: distro / profile / install
        for (int i = 0; i < N_DISTRO; i++) { int bx,by,bw,bh; distro_btn_rect(i,&bx,&by,&bw,&bh);
            if (x>=bx && x<=bx+bw && y>=by && y<=by+bh) { domain_action_arg(app, "distro", DISTRO_NAME[i]); return; } }
        for (int i = 0; i < N_PROFILE; i++) { int bx,by,bw,bh; profile_btn_rect(i,&bx,&by,&bw,&bh);
            if (x>=bx && x<=bx+bw && y>=by && y<=by+bh) { domain_action_arg(app, "profile", PROFILE_NAME[i]); return; } }
        for (int i = 0; i < app->n_pkgs; i++) { int bx,by,bw,bh; pkg_row_rect(i,&bx,&by,&bw,&bh);
            if (x>=bx && x<=bx+bw && y>=by && y<=by+bh) {
                int inst = (app->pkg_mask[app->sel] >> i) & 1;
                domain_action_arg(app, inst ? "uninstall" : "install", app->pkgs[i].name); return; } }
    } else if (app->tab == 4) {                     // Permissions: device toggles
        for (int i = 0; i < N_DEV; i++) { int bx,by,bw,bh; dev_row_rect(i,&bx,&by,&bw,&bh);
            if (y>=by-4 && y<=by+bh+4 && x>=LABEL_X) {
                int on = (app->doms[app->sel].devices & DEV_BIT[i]) != 0;
                domain_action_arg(app, on ? "devoff" : "devon", DEV_CLASS[i]); return; } }
    } else if (app->tab == 5) {                     // Applications: Launch confined in this domain
        for (int i = 0; i < app->n_avail; i++) {
            int bx,by,bw,bh; appl_row_rect(i,&bx,&by,&bw,&bh);
            if (x>=bx && x<=bx+bw && y>=by-2 && y<=by+bh+2) {
                launch_in_domain(app, DMAPPS[app->avail[i]].exec);
                redraw_commit(app, "launch");
                return; } }
    } else if (app->tab == 6) {                     // Appearance: Export as a signed template (DM12)
        int bx,by,bw,bh; export_btn_rect(&bx,&by,&bw,&bh);
        if (x>=bx && x<=bx+bw && y>=by && y<=by+bh) {
            domain_action(app, "export"); load_templates(app); redraw_commit(app, "export"); return; }
    }
}

static void pointer_enter(void *data, struct wl_pointer *p, uint32_t serial, struct wl_surface *s, wl_fixed_t sx, wl_fixed_t sy)
{ struct app *app = data; (void)p; (void)serial; (void)s; app->pointer_x = wl_fixed_to_double(sx); app->pointer_y = wl_fixed_to_double(sy); }
static void pointer_leave(void *data, struct wl_pointer *p, uint32_t serial, struct wl_surface *s) { (void)data; (void)p; (void)serial; (void)s; }
static void pointer_motion(void *data, struct wl_pointer *p, uint32_t time, wl_fixed_t sx, wl_fixed_t sy)
{ struct app *app = data; (void)p; (void)time; app->pointer_x = wl_fixed_to_double(sx); app->pointer_y = wl_fixed_to_double(sy); }
static void pointer_button(void *data, struct wl_pointer *p, uint32_t serial, uint32_t time, uint32_t button, uint32_t state)
{
    struct app *app = data; (void)p; (void)time;
    if (button != 0x110 || state != WL_POINTER_BUTTON_STATE_PRESSED) return;
    switch (wl_deco_hit(app->pointer_x, app->pointer_y, app->width)) {
        case 4: app->running = 0; return;                            // close
        case 2: xdg_toplevel_set_minimized(app->toplevel); return;
        case 3: if (app->maximized) { xdg_toplevel_unset_maximized(app->toplevel); app->maximized = 0; }
                else              { xdg_toplevel_set_maximized(app->toplevel);   app->maximized = 1; } return;
        default: break;
    }
    // drag the header strip to move the window
    if (app->pointer_y < HEADER_H) { xdg_toplevel_move(app->toplevel, app->seat, serial); return; }
    handle_click(app);
}
static void pointer_axis(void *data, struct wl_pointer *p, uint32_t time, uint32_t axis, wl_fixed_t value) { (void)data; (void)p; (void)time; (void)axis; (void)value; }
static void pointer_frame(void *data, struct wl_pointer *p) { (void)data; (void)p; }
static void pointer_axis_source(void *data, struct wl_pointer *p, uint32_t s) { (void)data; (void)p; (void)s; }
static void pointer_axis_stop(void *data, struct wl_pointer *p, uint32_t t, uint32_t a) { (void)data; (void)p; (void)t; (void)a; }
static void pointer_axis_discrete(void *data, struct wl_pointer *p, uint32_t a, int32_t d) { (void)data; (void)p; (void)a; (void)d; }
static const struct wl_pointer_listener pointer_listener = {
    .enter = pointer_enter, .leave = pointer_leave, .motion = pointer_motion, .button = pointer_button,
    .axis = pointer_axis, .frame = pointer_frame, .axis_source = pointer_axis_source,
    .axis_stop = pointer_axis_stop, .axis_discrete = pointer_axis_discrete,
};

static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t sz) { (void)d; (void)k; (void)f; (void)sz; if (fd >= 0) close(fd); }
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su, struct wl_array *keys) { (void)d; (void)k; (void)s; (void)su; (void)keys; }
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su) { (void)d; (void)k; (void)s; (void)su; }
static void kb_key(void *data, struct wl_keyboard *k, uint32_t serial, uint32_t time, uint32_t key, uint32_t state)
{
    struct app *app = data; (void)k; (void)serial; (void)time;
    if (state != WL_KEYBOARD_KEY_STATE_PRESSED) return;
    // DM10.5: the clone-name text-input dialog captures the keyboard while open.
    if (app->editing) {
        if (key == 1)        { app->editing = 0; }                         // Esc → cancel
        else if (key == 28)  {                                              // Enter → apply
            app->editing = 0;
            if (app->edit_mode == 0)      domain_action_clone(app);         // clone a domain
            else if (app->edit_mode == 4) domain_create_new(app, 0);        // from-scratch Create
            else if (app->edit_mode == 5) domain_create_new(app, 1);        // instantiate from template
            else if (app->editbuf[0] == '/') {                              // grant/deny a filesystem path
                const char *v = app->edit_mode==1 ? "fsro" : app->edit_mode==3 ? "fsdeny" : "fsrw";
                domain_action_arg(app, v, app->editbuf);
            }
        }
        else if (key == 14)  { if (app->editlen > 0) app->editbuf[--app->editlen] = 0; } // Backspace
        else {
            char c = (key < 128) ? EVDEV_CHAR[key] : 0;
            if (c && app->editlen < (int)sizeof(app->editbuf) - 1) {
                app->editbuf[app->editlen++] = c; app->editbuf[app->editlen] = 0;
            }
        }
        redraw_commit(app, "clone edit");
        return;
    }
    // Up=103 Down=108 Enter=28 Esc=1.
    if (key == 108 && app->sel < app->n_doms - 1) { app->sel++; refresh_fs_view(app); redraw_commit(app, "key"); }
    else if (key == 103 && app->sel > 0)        { app->sel--; refresh_fs_view(app); redraw_commit(app, "key"); }
    // Enter launches the domain's terminal CONFINED (same as the Run Shell button).  This used
    // to call launch_app(), which only set environment variables -- the shell looked like it was
    // "in" the domain but the kernel never bound it, so none of the domain's policy applied.
    else if (key == 28)                         { launch_in_domain(app, TERM_BIN[app->cfg[app->sel].term]); }
    else if (key == 1)                          { app->running = 0; }
}
static void kb_mods(void *d, struct wl_keyboard *k, uint32_t s, uint32_t dep, uint32_t la, uint32_t lo, uint32_t grp) { (void)d; (void)k; (void)s; (void)dep; (void)la; (void)lo; (void)grp; }
static void kb_repeat(void *d, struct wl_keyboard *k, int32_t rate, int32_t delay) { (void)d; (void)k; (void)rate; (void)delay; }
static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = kb_keymap, .enter = kb_enter, .leave = kb_leave, .key = kb_key, .modifiers = kb_mods, .repeat_info = kb_repeat,
};

static void seat_capabilities(void *data, struct wl_seat *seat, uint32_t caps)
{
    struct app *app = data;
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !app->keyboard) {
        app->keyboard = wl_seat_get_keyboard(seat);
        wl_keyboard_add_listener(app->keyboard, &keyboard_listener, app);
    }
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !app->pointer) {
        app->pointer = wl_seat_get_pointer(seat);
        wl_pointer_add_listener(app->pointer, &pointer_listener, app);
    }
}
static void seat_name(void *d, struct wl_seat *s, const char *n) { (void)d; (void)s; (void)n; }
static const struct wl_seat_listener seat_listener = { .capabilities = seat_capabilities, .name = seat_name };

static void wm_base_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial) { (void)data; xdg_wm_base_pong(wm_base, serial); }
static const struct xdg_wm_base_listener wm_base_listener = {.ping = wm_base_ping};

static void toplevel_configure(void *data, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s)
{
    struct app *app = data; (void)t; (void)s;
    // Tiling WM dictates our size here; xdg_surface_configure applies it on ack.
    if (w > 0) app->pending_w = w;
    if (h > 0) app->pending_h = h;
}
static void toplevel_close(void *data, struct xdg_toplevel *t) { struct app *app = data; (void)t; app->running = 0; }
static void toplevel_configure_bounds(void *data, struct xdg_toplevel *t, int32_t w, int32_t h) { (void)data; (void)t; (void)w; (void)h; }
static void toplevel_wm_capabilities(void *data, struct xdg_toplevel *t, struct wl_array *c) { (void)data; (void)t; (void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure = toplevel_configure, .close = toplevel_close,
    .configure_bounds = toplevel_configure_bounds, .wm_capabilities = toplevel_wm_capabilities,
};

static void frame_done(void *data, struct wl_callback *callback, uint32_t time)
{
    struct app *app = data; (void)time;
    if (callback) wl_callback_destroy(callback);
    app->frame_cb = NULL;
    if (app->post_map_frame_done) return;
    app->post_map_frame_done = 1;
    draw_manager(app);
    if (app->buffer) {
        wl_surface_attach(app->surface, app->buffer, 0, 0);
        wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
        wl_surface_commit(app->surface);
    }
    printf("DOMAINMGR: post-map redraw committed %dx%d\n", app->width, app->height);
    fflush(stdout);
}
static const struct wl_callback_listener frame_listener = {.done = frame_done};

static void xdg_surface_configure(void *data, struct xdg_surface *surface, uint32_t serial)
{
    struct app *app = data;
    xdg_surface_ack_configure(surface, serial);

    int want_w = app->pending_w > 0 ? app->pending_w : DEFAULT_WIDTH;
    int want_h = app->pending_h > 0 ? app->pending_h : DEFAULT_HEIGHT;

    // After the first commit, honor compositor-driven resizes (tiling WM): rebuild
    // the shm buffer at the new size and reflow the UI, then re-attach + commit.
    if (app->committed) {
        if (want_w == app->width && want_h == app->height) return;   // size unchanged
        if (resize_buffer(app, want_w, want_h) < 0) { log_line("DOMAINMGR: resize failed"); return; }
        wl_surface_attach(app->surface, app->buffer, 0, 0);
        wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
        wl_surface_commit(app->surface);
        wl_display_flush(app->display);
        printf("DOMAINMGR: resized wl_shm window %dx%d\n", app->width, app->height);
        fflush(stdout);
        return;
    }

    if (create_shm_buffer(app, want_w, want_h) < 0) { log_line("DOMAINMGR: buffer failed"); app->running = 0; return; }
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
    printf("DOMAINMGR: committed wl_shm window %dx%d\n", app->width, app->height);
    fflush(stdout);
}
static const struct xdg_surface_listener xdg_surface_listener = {.configure = xdg_surface_configure};

static void registry_global(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version)
{
    struct app *app = data;
    if (strcmp(interface, wl_compositor_interface.name) == 0)
        app->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, version < 4 ? version : 4);
    else if (strcmp(interface, wl_shm_interface.name) == 0)
        app->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
    else if (strcmp(interface, xdg_wm_base_interface.name) == 0) {
        app->wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface, version < 6 ? version : 6);
        xdg_wm_base_add_listener(app->wm_base, &wm_base_listener, app);
    } else if (strcmp(interface, wl_seat_interface.name) == 0) {
        app->seat = wl_registry_bind(registry, name, &wl_seat_interface, version < 5 ? version : 5);
        wl_seat_add_listener(app->seat, &seat_listener, app);
    }
}
static void registry_global_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener registry_listener = { .global = registry_global, .global_remove = registry_global_remove };

int main(void)
{
    static struct app app;
    memset(&app, 0, sizeof(app));
    app.running = 1;
    app.sel = 0;
    // R4: the GLES2 terminal (gl-term) is the default terminal — the "ratty" realization of R3
    // (the Bevy-based ratty itself can't run on the OS).  The per-domain dropdown still offers
    // wl-term / hos-term.
    for (int i = 0; i < MAX_DOMS; i++) { app.cfg[i] = DEFAULTS[i % N_DOMAINS]; app.cfg[i].term = TERM_GL; }

    // DM10: load the domains from the declarative config (/config/domains.json), generated by the
    // kernel from system.json — the GUI now reflects DM0-DM6 instead of a hardcoded list.
    load_domains(&app);
    load_packages(&app);             // DM10.7: the software repository (Packages tab)
    load_apps(&app);                 // Applications tab: which app binaries are actually present
    load_templates(&app);            // DM12: the local signed-template registry (Appearance tab)
    load_sysusers(&app);             // ROADMAP 1.5: Users tab    (/config/users.json)
    load_syssvcs(&app);              // ROADMAP 1.5: Services tab (/config/services.json)
    load_startup(&app);              // ROADMAP 1.5: Startup tab  (/desktop.conf)
    app.last_hash = domains_hash();  // DM10.6: baseline for live-update change detection
    refresh_fs_view(&app);   // DM10.2: the first selected domain's RuntimeView
    domain_ctl_selftest(&app); // DM10.3: prove the control-write path (ping) at startup

    signal(SIGCHLD, SIG_IGN);   // auto-reap launched apps (no zombies)

    log_line("DOMAINMGR: starting Qubes-style Domain Manager + control panel");
    app.display = wl_display_connect(NULL);
    if (!app.display) { perror("DOMAINMGR: wl_display_connect"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base) { log_line("DOMAINMGR: missing globals"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Domain Manager");
    xdg_toplevel_set_app_id(app.toplevel, "epin-domain-manager");
    // Float instead of tile.  The previous setting (a 480x360 floor and no max) left
    // min != max, so epin_is_tileable() in desktop-shell.c treated this as an ordinary
    // tileable window -- and launching an app from here made the tiler split the screen and
    // resize the Domain Manager to whatever was left (observed: 562x181).  This layout is
    // fixed-pixel and does not reflow, so at that size it collapses to a sliver of toolbar
    // and reads as "the Domain Manager crashed".
    //
    // epin_is_tileable() floats any surface whose min == max (it treats those as
    // popovers/dialogs), which is exactly the right classification for a settings window:
    // it keeps its designed size and stops being collateral damage when a new window opens.
    xdg_toplevel_set_min_size(app.toplevel, DEFAULT_WIDTH, DEFAULT_HEIGHT);
    // KEEP set_max_size.  Removing it (cd7d378b3c) to stop this window floating was wrong:
    // min == max is what makes Hyprland classify it as a fixed-size dialog and float it, and
    // that is the CORRECT classification here -- the layout above is fixed-pixel and does not
    // reflow, so tiling it reproduces the regression documented immediately above (observed
    // 562x181, "reads as the Domain Manager crashed").
    //
    // The justification for removing it was that a floating window has no dwindle node, so
    // predictSizeForNewTarget returns nullopt and later clients inherit a 0x0 initial
    // configure.  That cascade is real in the abstract but does not fire here: this window
    // maps AFTER the tiled clients, so it never poisons their prediction.  And it is moot now
    // that wl-cairo-demo and wl-installer honour post-map configures, which is where the tile
    // actually arrives.
    //
    // If this window is ever genuinely wanted tiled, the layout has to reflow first; a
    // rule-level minsize in system/hypr/custom/rules.lua would then be the lever, not this.
    xdg_toplevel_set_max_size(app.toplevel, DEFAULT_WIDTH, DEFAULT_HEIGHT);
    wl_surface_commit(app.surface);
    wl_display_flush(app.display);

    domain_livetest_spawn(&app);   // DM10.6: optional external-actor verification ($HOS_DM_LIVETEST)

    // DM10.6: poll the Wayland fd with a 1s timeout so the loop wakes periodically to re-check
    // /config/domains.json for changes made by ANY actor (live updates), not just local actions.
    int wlfd = wl_display_get_fd(app.display);
    while (app.running) {
        while (wl_display_prepare_read(app.display) != 0)
            wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);

        struct pollfd pfd = { .fd = wlfd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, 1000);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            wl_display_read_events(app.display);
            wl_display_dispatch_pending(app.display);
        } else {
            wl_display_cancel_read(app.display);
            if (pr < 0) { if (errno == EINTR) continue; perror("DOMAINMGR: poll"); break; }
            if (pr == 0) live_refresh(&app);    // timeout: check for external domain changes
        }
        if (app.sync_after_commit) {
            app.sync_after_commit = 0;
            wl_display_roundtrip(app.display);
        }
    }
    return app.committed ? 0 : 1;
}
