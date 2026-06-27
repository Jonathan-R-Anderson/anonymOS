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
    DEFAULT_WIDTH  = 1180,   // DM10.2: wider, for the Filesystem RuntimeView column
    DEFAULT_HEIGHT = 600,
    HEADER_H       = 70,
    LIST_W         = 300,     // left domain list width
    ROW_H          = 44,      // list row height
    FOOTER_H       = 32,
    PAD            = 20,
};

// Right control-panel geometry.
enum {
    RP_X    = LIST_W,
    LABEL_X = RP_X + 26,
    PILL_X  = RP_X + 196,
    PILL_W  = 250,
    PILL_H  = 28,
    CTL_H   = 42,
    RY0     = HEADER_H + 54,   // first control row y
    N_CTL   = 7,              // cyclable control rows (Memory…Shell + Terminal)
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
};

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
    int committed, font_ready, sync_after_commit;
    int post_map_frame_armed, post_map_frame_done;
    int running;
    double pointer_x, pointer_y;
    int sel;                       // selected domain
    struct dconf cfg[MAX_DOMS];    // per-domain launch settings (mutable)
    struct gdomain doms[MAX_DOMS]; // DM10: the domains, read from the declarative config
    int n_doms;                    // number loaded
    char fs_view[1280];            // DM10.2: the selected domain's restricted-FS RuntimeView
    int  editing;                  // DM10.5: clone-name text-input dialog is open
    char editbuf[24];              // the typed new-domain name (DOM_NAME_MAX)
    int  editlen;
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

static const char *CTL_LABEL[N_CTL] = {
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

// Geometry of the two launch buttons and three device chips (shared by draw + hit).
static void launch_btn_rect(int idx, int *x, int *y, int *w, int *h)
{
    *y = RY0 + (N_CTL + 1) * CTL_H + 8; *h = 38;
    if (idx == 0) { *x = LABEL_X; *w = 200; }
    else          { *x = LABEL_X + 214; *w = 170; }
}
static void dev_chip_rect(int idx, int *x, int *y, int *w, int *h)
{
    *y = RY0 + N_CTL * CTL_H + (CTL_H - 26) / 2; *h = 26; *w = 78;
    *x = PILL_X + idx * (78 + 8);
}
// DM10.3/10.5: the lifecycle action buttons (Start / Stop / Snapshot / Commit / Clone), one row
// below launch.  Clone (idx 4) opens the text-input dialog instead of acting immediately.
#define N_ACTION 5
static const char *ACTION_LABEL[N_ACTION] = { "Start", "Stop", "Snapshot", "Commit", "Clone" };
static const char *ACTION_VERB [N_ACTION] = { "start", "stop", "snapshot", "commit", "clone" };
static void action_btn_rect(int idx, int *x, int *y, int *w, int *h)
{
    *y = RY0 + (N_CTL + 1) * CTL_H + 8 + 48; *h = 30; *w = 84;
    *x = LABEL_X + idx * (84 + 6);
}

// DM10.5: evdev keycode → lowercase ASCII (US QWERTY) for the clone-name text field.  The DM gets
// raw evdev codes from wl_keyboard (it ignores the xkb keymap), so we map the printable subset.
static const char EVDEV_CHAR[128] = {
    [2]='1',[3]='2',[4]='3',[5]='4',[6]='5',[7]='6',[8]='7',[9]='8',[10]='9',[11]='0',[12]='-',
    [16]='q',[17]='w',[18]='e',[19]='r',[20]='t',[21]='y',[22]='u',[23]='i',[24]='o',[25]='p',
    [30]='a',[31]='s',[32]='d',[33]='f',[34]='g',[35]='h',[36]='j',[37]='k',[38]='l',
    [44]='z',[45]='x',[46]='c',[47]='v',[48]='b',[49]='n',[50]='m',
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
        if (g->name[0]) app->n_doms++;
        p = objEnd;
    }
    free(json);
    if (app->n_doms == 0) { load_domains_fallback(app); return; }
    printf("DOMAINMGR: loaded %d domains from /config/domains.json (declarative):", app->n_doms);
    for (int i = 0; i < app->n_doms; i++) printf(" %s[%s]", app->doms[i].name, app->doms[i].type);
    printf("\n"); fflush(stdout);
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
    // select the freshly-created clone if present
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

static void draw_manager(struct app *app)
{
    cairo_surface_t *surface = cairo_image_surface_create_for_data(
        (unsigned char *)app->pixels, CAIRO_FORMAT_RGB24, app->width, app->height, app->stride);
    cairo_t *cr = cairo_create(surface);

    // Backdrop + panes.
    cairo_set_source_rgb(cr, 0.118, 0.137, 0.165); cairo_paint(cr);
    cairo_set_source_rgb(cr, 0.102, 0.118, 0.145);                 // left list pane
    cairo_rectangle(cr, 0, HEADER_H, LIST_W, app->height - HEADER_H); cairo_fill(cr);

    // Header band.
    cairo_set_source_rgb(cr, 0.086, 0.102, 0.125);
    cairo_rectangle(cr, 0, 0, app->width, HEADER_H); cairo_fill(cr);
    { // shield crest
        double sx = PAD + 12, sy = 18, sw = 26, sh = 32;
        cairo_set_source_rgb(cr, 0.36, 0.62, 0.96);
        cairo_move_to(cr, sx, sy); cairo_line_to(cr, sx + sw, sy);
        cairo_line_to(cr, sx + sw, sy + sh * 0.55);
        cairo_curve_to(cr, sx + sw, sy + sh, sx + sw / 2, sy + sh, sx + sw / 2, sy + sh);
        cairo_curve_to(cr, sx + sw / 2, sy + sh, sx, sy + sh, sx, sy + sh * 0.55);
        cairo_close_path(cr); cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.93, 0.96, 1.0); cairo_set_line_width(cr, 2.0);
        cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
        cairo_move_to(cr, sx + sw * 0.30, sy + sh * 0.42);
        cairo_line_to(cr, sx + sw * 0.46, sy + sh * 0.60);
        cairo_line_to(cr, sx + sw * 0.74, sy + sh * 0.26); cairo_stroke(cr);
    }
    cairo_set_source_rgb(cr, 0.22, 0.27, 0.33);
    cairo_rectangle(cr, 0, HEADER_H - 1, app->width, 1); cairo_fill(cr);
    cairo_rectangle(cr, LIST_W, HEADER_H, 1, app->height - HEADER_H); cairo_fill(cr); // pane divider

    // Left: domain list rows (DM10: from the declarative config).
    for (int i = 0; i < app->n_doms; i++) {
        struct gdomain *d = &app->doms[i];
        int ry = HEADER_H + 6 + i * ROW_H;
        if (i == app->sel) {
            cairo_set_source_rgb(cr, 0.16, 0.20, 0.27);
            cairo_rectangle(cr, 0, ry, LIST_W, ROW_H); cairo_fill(cr);
            cairo_argb(cr, d->color);
            cairo_rectangle(cr, 0, ry, 4, ROW_H); cairo_fill(cr);
        }
        double cy = ry + ROW_H / 2.0;
        // template = hollow diamond, domain = filled rounded swatch
        int isTpl = (d->type[0] == 't');
        cairo_argb(cr, d->color);
        if (isTpl) {
            cairo_move_to(cr, PAD + 9, cy - 9); cairo_line_to(cr, PAD + 18, cy);
            cairo_line_to(cr, PAD + 9, cy + 9); cairo_line_to(cr, PAD, cy); cairo_close_path(cr);
            cairo_set_line_width(cr, 1.8); cairo_stroke(cr);
        } else {
            rounded_rect(cr, PAD, cy - 9, 18, 18, 5); cairo_fill(cr);
            cairo_set_source_rgba(cr, 1, 1, 1, 0.18);
            rounded_rect(cr, PAD, cy - 9, 18, 18, 5); cairo_set_line_width(cr, 1.0); cairo_stroke(cr);
        }
        // a live-state dot: green = Running, amber = Paused
        if (d->state[0] == 'R' || d->state[0] == 'P') {
            if (d->state[0] == 'R') cairo_set_source_rgb(cr, 0.30, 0.78, 0.45);
            else                    cairo_set_source_rgb(cr, 0.92, 0.66, 0.20);
            cairo_arc(cr, PAD + 158, cy, 4, 0, 6.2832); cairo_fill(cr);
        }
    }

    // Right: control panel for the selected domain.
    struct dconf *c = &app->cfg[app->sel];
    cairo_argb(cr, app->doms[app->sel].color);           // domain accent dot by panel title
    rounded_rect(cr, LABEL_X, HEADER_H + 18, 14, 14, 4); cairo_fill(cr);

    for (int i = 0; i < N_CTL; i++) {
        int ry = RY0 + i * CTL_H;
        // pill background
        cairo_set_source_rgb(cr, 0.157, 0.184, 0.224);
        rounded_rect(cr, PILL_X, ry + (CTL_H - PILL_H) / 2, PILL_W, PILL_H, 7); cairo_fill(cr);
        // a little colored marker for Secure-IPC-required / shell-unavailable states
        if (i == 4 && c->secure_ipc) { cairo_set_source_rgb(cr, 0.30, 0.78, 0.45); rounded_rect(cr, PILL_X + 8, ry + CTL_H/2 - 4, 8, 8, 2); cairo_fill(cr); }
        if (i == 5 && c->shell != SH_LINUX) { cairo_set_source_rgb(cr, 0.92, 0.55, 0.20); rounded_rect(cr, PILL_X + 8, ry + CTL_H/2 - 4, 8, 8, 2); cairo_fill(cr); }
        if (i == 6 && c->term  != TERM_GL)  { cairo_set_source_rgb(cr, 0.40, 0.62, 0.95); rounded_rect(cr, PILL_X + 8, ry + CTL_H/2 - 4, 8, 8, 2); cairo_fill(cr); }
        // row separator
        cairo_set_source_rgb(cr, 0.10, 0.12, 0.15);
        cairo_rectangle(cr, LABEL_X, ry + CTL_H - 1, app->width - LABEL_X - PAD, 1); cairo_fill(cr);
    }

    // Devices row: three toggle chips.
    {
        int ry = RY0 + N_CTL * CTL_H;
        cairo_set_source_rgb(cr, 0.10, 0.12, 0.15);
        cairo_rectangle(cr, LABEL_X, ry + CTL_H - 1, app->width - LABEL_X - PAD, 1); cairo_fill(cr);
        int on[3] = {c->dev_cam, c->dev_mic, c->dev_usb};
        for (int k = 0; k < 3; k++) {
            int x, y, w, h; dev_chip_rect(k, &x, &y, &w, &h);
            if (on[k]) cairo_set_source_rgb(cr, 0.20, 0.46, 0.34);
            else       cairo_set_source_rgb(cr, 0.157, 0.184, 0.224);
            rounded_rect(cr, x, y, w, h, 7); cairo_fill(cr);
        }
    }

    // Launch buttons.
    for (int b = 0; b < 2; b++) {
        int x, y, w, h; launch_btn_rect(b, &x, &y, &w, &h);
        if (b == 0) cairo_argb(cr, app->doms[app->sel].color);
        else        cairo_set_source_rgb(cr, 0.20, 0.24, 0.30);
        rounded_rect(cr, x, y, w, h, 9); cairo_fill(cr);
    }

    // DM10.3: lifecycle action buttons (Start / Stop / Snapshot / Commit) — tinted by state.
    {
        const char *st = app->doms[app->sel].state;
        int running = (st[0] == 'R'), paused = (st[0] == 'P');
        for (int a = 0; a < N_ACTION; a++) {
            int x, y, w, h; action_btn_rect(a, &x, &y, &w, &h);
            // enabled-state hint: Start only when stopped; Stop/Snapshot/Commit when running/paused
            int enabled = (a == 0) ? (!running && !paused) : (running || paused);
            if (a == 0 && enabled)      cairo_set_source_rgb(cr, 0.20, 0.52, 0.34);  // Start green
            else if (a == 1 && enabled) cairo_set_source_rgb(cr, 0.52, 0.26, 0.26);  // Stop red
            else if (enabled)           cairo_set_source_rgb(cr, 0.22, 0.30, 0.42);  // Snap/Commit blue
            else                        cairo_set_source_rgb(cr, 0.16, 0.18, 0.22);  // disabled
            rounded_rect(cr, x, y, w, h, 7); cairo_fill(cr);
        }
    }

    // Footer band.
    cairo_set_source_rgb(cr, 0.086, 0.102, 0.125);
    cairo_rectangle(cr, 0, app->height - FOOTER_H, app->width, FOOTER_H); cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.22, 0.27, 0.33);
    cairo_rectangle(cr, 0, app->height - FOOTER_H, app->width, 1); cairo_fill(cr);

    // DM10.5: the Clone-name dialog (modal box) — drawn last so it overlays everything.
    if (app->editing) {
        int dw = 440, dh = 130, dx = (app->width - dw) / 2, dy = (app->height - dh) / 2;
        cairo_set_source_rgba(cr, 0, 0, 0, 0.45);                 // dim backdrop
        cairo_rectangle(cr, 0, 0, app->width, app->height); cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.16, 0.19, 0.24);              // dialog body
        rounded_rect(cr, dx, dy, dw, dh, 12); cairo_fill(cr);
        cairo_argb(cr, app->doms[app->sel].color);              // accent strip
        rounded_rect(cr, dx, dy, dw, 5, 12); cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.10, 0.12, 0.15);             // text field
        rounded_rect(cr, dx + 20, dy + 56, dw - 40, 34, 7); cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.30, 0.40, 0.55);
        rounded_rect(cr, dx + 20, dy + 56, dw - 40, 34, 7); cairo_set_line_width(cr, 1.5); cairo_stroke(cr);
    }

    cairo_destroy(cr);
    cairo_surface_flush(surface);
    cairo_surface_destroy(surface);

    // --- text pass ---
    draw_text(app, "Domain Manager", PAD + 52, 14, 360, 22, 0xfff2f5fau);
    draw_text(app, "from /config/domains.json (declarative)  -  diamond = template, green dot = running",
              PAD + 52, 44, app->width - 80, 12, 0xff8b94a3u);

    for (int i = 0; i < app->n_doms; i++) {
        struct gdomain *d = &app->doms[i];
        int ry = HEADER_H + 6 + i * ROW_H;
        uint32_t nameCol = 0xff000000u | (d->color & 0x00ffffffu);
        draw_text(app, d->name, PAD + 30, ry + (ROW_H - 16) / 2 - 5, 140, 14, nameCol);
        draw_text(app, d->identity, PAD + 30, ry + (ROW_H - 16) / 2 + 9, 120, 10, 0xff8d97a6u);
    }

    // Panel title (DM10: the selected declarative domain) + controls text.
    struct gdomain *sd = &app->doms[app->sel];
    char title[96];
    snprintf(title, sizeof(title), "%s  -  %s", sd->name, sd->type);
    draw_text(app, title, LABEL_X + 22, HEADER_H + 16, 360, 17, 0xfff0f3f8u);

    struct dconf *cc = &app->cfg[app->sel];
    for (int i = 0; i < N_CTL; i++) {
        int ry = RY0 + i * CTL_H;
        draw_text(app, CTL_LABEL[i], LABEL_X, ry + (CTL_H - 14) / 2, 170, 14, 0xffb7c1d0u);
        char val[48]; ctl_value(cc, i, val, sizeof(val));
        int vx = PILL_X + ((i == 4 && cc->secure_ipc) || (i == 5 && cc->shell != SH_LINUX) || (i == 6 && cc->term != TERM_GL) ? 24 : 14);
        draw_text(app, val, vx, ry + (CTL_H - 14) / 2, PILL_W - 28, 14, 0xfff2f5fau);
    }

    // Devices row text.
    {
        int ry = RY0 + N_CTL * CTL_H;
        draw_text(app, "Devices", LABEL_X, ry + (CTL_H - 14) / 2, 170, 14, 0xffb7c1d0u);
        const char *names[3] = {"Camera", "Mic", "USB"};
        int on[3] = {cc->dev_cam, cc->dev_mic, cc->dev_usb};
        for (int k = 0; k < 3; k++) {
            int x, y, w, h; dev_chip_rect(k, &x, &y, &w, &h);
            draw_text(app, names[k], x + 10, y + 6, w - 14, 12, on[k] ? 0xffeafff0u : 0xff8d97a6u);
        }
    }

    // Buttons text.
    for (int b = 0; b < 2; b++) {
        int x, y, w, h; launch_btn_rect(b, &x, &y, &w, &h);
        const char *lbl = (b == 0) ? "Launch Terminal" : "Launch Files";
        uint32_t col = (b == 0) ? 0xff10141au : 0xffe8edf5u;
        draw_text(app, lbl, x + 18, y + 12, w - 24, 14, col);
    }

    // DM10.3: action button labels.
    draw_text(app, "Lifecycle", LABEL_X, RY0 + (N_CTL + 1) * CTL_H + 8 + 30, 120, 12, 0xff8b94a3u);
    for (int a = 0; a < N_ACTION; a++) {
        int x, y, w, h; action_btn_rect(a, &x, &y, &w, &h);
        draw_text(app, ACTION_LABEL[a], x + 12, y + 9, w - 16, 13, 0xffe8edf5u);
    }

    // DM10.2: the Restricted Filesystem (RuntimeView) column — the selected domain's resolved,
    // deny-by-default fs policy (DM2), read from /objects/domains/<name>/filesystem.
    {
        int fx = PILL_X + PILL_W + 30;        // right of the control pills
        int fy = RY0 - 30;
        draw_text(app, "Restricted Filesystem  (RuntimeView)", fx, fy, 400, 14, 0xffd6deeau);
        fy += 22;
        const char *s = app->fs_view;
        int line = 0;
        while (*s && line < 22) {
            char ln[96]; int i = 0;
            while (*s && *s != '\n' && i < (int)sizeof(ln) - 1) ln[i++] = *s++;
            ln[i] = 0;
            if (*s == '\n') s++;
            uint32_t col = 0xffaab3c2u;
            if (ln[0] == '#')                       col = 0xff6b7686u;  // comments dim
            else if (strncmp(ln, "deny", 4) == 0)   col = 0xffe08a8au;  // deny  -> red
            else if (strncmp(ln, "rw", 2) == 0)     col = 0xff9fe0a8u;  // rw    -> green
            else if (strncmp(ln, "ro", 2) == 0)     col = 0xffd8d09au;  // ro    -> amber
            else if (strncmp(ln, "defaultPolicy", 13) == 0) col = 0xffd6deeau;
            draw_text(app, ln, fx, fy + line * 16, 410, 13, col);
            line++;
        }
    }

    // Footer: the DECLARATIVE attributes of the selected domain (DM0-DM6, from system.json).
    char foot[256];
    snprintf(foot, sizeof(foot),
             "type %s   |   identity %s   |   template %s   |   persist %s   |   state %s   |   shell %s",
             sd->type, sd->identity, dom_templ_name(app, sd->templObjId), sd->persist, sd->state,
             SHELL_LBL[cc->shell]);
    draw_text(app, foot, PAD, app->height - FOOTER_H + 9, app->width - 2 * PAD, 12, 0xff9aa4b3u);

    // DM10.5: the Clone-name dialog text (over the modal box drawn in the cairo pass).
    if (app->editing) {
        int dw = 440, dh = 130, dx = (app->width - dw) / 2, dy = (app->height - dh) / 2;
        char head[80];
        snprintf(head, sizeof(head), "Clone \"%s\" as a new domain", sd->name);
        draw_text(app, head, dx + 20, dy + 20, dw - 40, 15, 0xfff0f3f8u);
        char field[40];
        snprintf(field, sizeof(field), "%s_", app->editbuf);   // trailing _ = caret
        draw_text(app, field, dx + 30, dy + 64, dw - 60, 16, 0xfff2f5fau);
        draw_text(app, "Type a name  -  Enter = create,  Esc = cancel",
                  dx + 20, dy + 100, dw - 40, 12, 0xff8b94a3u);
    }

    // window-control buttons (minimize / maximize / close) at the top-right.
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

// --- launch ---------------------------------------------------------------

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

    // Left list: select a domain.
    if (x < RP_X) {
        int top = HEADER_H + 6;
        if (y >= top && y < top + app->n_doms * ROW_H) {
            int r = (int)((y - top) / ROW_H);
            if (r >= 0 && r < app->n_doms && r != app->sel) {
                app->sel = r;
                refresh_fs_view(app);   // DM10.2: load the new domain's RuntimeView
                redraw_commit(app, "select domain");
            }
        }
        return;
    }

    struct dconf *c = &app->cfg[app->sel];

    // Cyclable control rows.
    for (int i = 0; i < N_CTL; i++) {
        int ry = RY0 + i * CTL_H;
        if (y >= ry && y < ry + CTL_H && x >= LABEL_X) {
            ctl_cycle(c, i, 1);
            redraw_commit(app, "set control");
            return;
        }
    }
    // Device chips.
    {
        int ry = RY0 + N_CTL * CTL_H;
        if (y >= ry && y < ry + CTL_H) {
            for (int k = 0; k < 3; k++) {
                int bx, by, bw, bh; dev_chip_rect(k, &bx, &by, &bw, &bh);
                if (x >= bx && x <= bx + bw && y >= by && y <= by + bh) {
                    if (k == 0) c->dev_cam ^= 1;
                    else if (k == 1) c->dev_mic ^= 1;
                    else c->dev_usb ^= 1;
                    redraw_commit(app, "toggle device");
                    return;
                }
            }
        }
    }
    // Launch buttons.
    for (int b = 0; b < 2; b++) {
        int bx, by, bw, bh; launch_btn_rect(b, &bx, &by, &bw, &bh);
        if (x >= bx && x <= bx + bw && y >= by && y <= by + bh) {
            launch_app(app, b == 0 ? TERM_BIN[app->cfg[app->sel].term] : "/wl-files");
            redraw_commit(app, "launch");
            return;
        }
    }
    // DM10.3/10.5: lifecycle action buttons.  Clone opens the name dialog; the rest act at once.
    for (int a = 0; a < N_ACTION; a++) {
        int bx, by, bw, bh; action_btn_rect(a, &bx, &by, &bw, &bh);
        if (x >= bx && x <= bx + bw && y >= by && y <= by + bh) {
            if (a == 4) {   // Clone → open the text dialog, pre-filled with "<src>-clone"
                snprintf(app->editbuf, sizeof(app->editbuf), "%.16s-clone", app->doms[app->sel].name);
                app->editlen = strlen(app->editbuf);
                app->editing = 1;
            } else {
                domain_action(app, ACTION_VERB[a]);
            }
            redraw_commit(app, "domain action");
            return;
        }
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
        else if (key == 28)  { app->editing = 0; domain_action_clone(app); } // Enter → commit clone
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
    else if (key == 28)                         { launch_app(app, TERM_BIN[app->cfg[app->sel].term]); }
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

static void toplevel_configure(void *data, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s) { (void)data; (void)t; (void)w; (void)h; (void)s; }
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
    if (app->committed) return;
    if (create_shm_buffer(app, DEFAULT_WIDTH, DEFAULT_HEIGHT) < 0) { log_line("DOMAINMGR: buffer failed"); app->running = 0; return; }
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
    xdg_toplevel_set_min_size(app.toplevel, DEFAULT_WIDTH, DEFAULT_HEIGHT);
    wl_surface_commit(app.surface);
    wl_display_flush(app.display);

    while (app.running) {
        int ret = wl_display_dispatch(app.display);
        if (ret < 0) { perror("DOMAINMGR: dispatch"); break; }
        if (app.sync_after_commit) {
            app.sync_after_commit = 0;
            wl_display_roundtrip(app.display);
        }
    }
    return app.committed ? 0 : 1;
}
