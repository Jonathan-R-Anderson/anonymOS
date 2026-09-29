/*
 * wl-layer-bar.c -- the GNOME-Shell-style top bar for the Hyprland desktop.
 *
 * This is the Hyprland counterpart of the Weston desktop-shell panel (which is a
 * Weston-private toytoolkit widget and cannot be reused on wlroots).  Hyprland
 * implements the standard wlr-layer-shell protocol, so this is a plain Wayland
 * client that anchors a full-width, 28px opaque-black bar to the TOP layer with an
 * exclusive zone (so tiled windows never overlap it).  Look + behaviour mirror the
 * GNOME/Weston bar:
 *
 *   [ Activities ] [#][#][ ][ ] [-][+]      Wed Jul  4  16:30                 wifi vol batt
 *        |              |                         |                              |
 *   /wl-overview    desktops                 /wl-calendar               /wl-wifi-menu (wifi)
 *                                                                 /wl-quicksettings (vol/batt)
 *
 * Desktops: one miniature per Hyprland workspace, with every open window drawn at its real place
 * and size in the colour of the domain that owns it (see "desktops" below).  Click to switch,
 * scroll over the strip to step through them, -/+ to remove or add a desktop.
 *
 * The Wi-Fi indicator reads /run/wifi/networks (same source as the Weston bar) and,
 * clicked, opens /wl-wifi-menu so you can pick a network + enter its password.
 *
 * Hide/show (the config-panel toggle): the bar polls /run/hos-bar.hidden once a
 * second AND toggles on SIGUSR1.  When hidden it unmaps its surface and drops its
 * exclusive zone (windows reclaim the strip); when shown it re-maps.  The Settings
 * panel writes/removes /run/hos-bar.hidden; a Hyprland `bind = SUPER,B,...` can also
 * `kill -USR1` this process.
 *
 * All Wayland scaffolding (registry / seat / double-buffered wl_shm / FreeType text /
 * the full v5 wl_pointer listener) is the proven wl-quicksettings/wl-wifi-menu pattern.
 * Drawing is fill_rect() + draw_text() + a few glyphs, no cairo.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <wayland-client.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include "xdg-shell-client-protocol.h"
#include "wlr-layer-shell-unstable-v1-client-protocol.h"

extern char **environ;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum { BAR_H = 28 };                 /* GNOME top-bar height */

/* opaque-black bar, white text -- matches panel-color=0xff000000 on Weston */
#define COL_BG      0xff000000u
#define COL_TEXT    0xfff2f2f2u
#define COL_DIM     0xff9aa0a6u
#define COL_HOVER   0x22ffffffu      /* (alpha blended) hover pill */
#define COL_NOTICE  0xff5a1e1eu      /* appgate: the "not delegated" notice pill */

/* clickable regions; miniature i (desktop i+1) is R_DESK + i */
enum { R_NONE = 0, R_ACTIVITIES, R_CLOCK, R_WIFI, R_INDICATORS, R_DESK_MINUS, R_DESK_PLUS, R_DESK = 16 };

/* hide-state flag file the Settings panel writes to toggle the bar */
#define HIDE_FLAG "/run/hos-bar.hidden"

/* --- desktops -------------------------------------------------------------------------------------
 * Desktop N is Hyprland workspace N (1..DESK_MAX -- the SUPER+1..0 keybinds).  How many the strip
 * shows is the user's choice (+/-), kept for this session in DESKTOPS_FILE (the live system saves
 * nothing), and it grows by itself when a keybind goes past it (SUPER+6 with four desktops).
 *
 * The window rectangles come from Hyprland, the colours from the kernel: each window's owning pid
 * -> /proc/<pid>/status "DomainColor:", the same identity colour the kernel draws as the window's
 * border.  /proc is bound into no domain namespace, so only unconfined chrome like this bar can
 * read it. */
enum { DESK_MAX = 10, DESK_DEFAULT = 4, MINI_MAX = 64 };
#define DESKTOPS_FILE   "/run/hos-desktops"
#define DESK_SNAPSHOT   "/run/hos-desktops.snap"   /* written by Hyprland's Lua on each refresh */
#define COL_WIN_NEUTRAL 0xff8fbf5fu                /* IDENTITY_BORDER_NEUTRAL: owner has no identity */

struct mini_win {
    int      ws, x, y, w, h;         /* workspace + monitor-relative logical geometry */
    int      focus;                  /* focus history: 0 = most recently focused */
    uint32_t color;                  /* the owning domain's identity colour */
    char     cls[40], dom[24];       /* app class + domain name, for the hover summary */
};

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_seat *seat;
    struct wl_pointer *pointer;
    struct wl_output *output;
    struct zwlr_layer_shell_v1 *layer_shell;
    struct zwlr_layer_surface_v1 *layer_surface;
    struct wl_surface *surface;

    struct { struct wl_buffer *wl; uint32_t *px; int busy; } bufs[2];
    uint32_t *pixels;
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    int font_ready, running, configured;
    double pointer_x, pointer_y;

    /* content state */
    char clock_str[64];
    int  wifi_bars;          /* -1 no adapter, 0..4 signal */
    int  hover;              /* hovered region for highlight */
    int  hidden;             /* bar currently unmapped */
    /* layout hit boxes (computed each redraw) */
    int  act_x0, act_x1;     /* Activities */
    int  clk_x0, clk_x1;     /* Clock */
    int  wifi_x0, wifi_x1;   /* Wi-Fi glyph */
    int  ind_x0, ind_x1;     /* volume+battery */
    /* appgate: a launch the kernel refused (it logs each one in /config/appgate.json) is shown in
     * place of the clock for a few seconds -- otherwise a refused launch from the app grid or a
     * keybind looks exactly like a program that silently failed to start. */
    unsigned gate_seq;       /* last denial sequence number shown */
    int      gate_seen;      /* gate_seq initialised (denials from before the bar started are old news) */
    char     notice[160];
    time_t   notice_until;

    int  dirty;              /* a redraw was wanted while both buffers were with the compositor */

    /* desktops */
    int  desk_count;         /* desktops shown (1..DESK_MAX) */
    int  desk_active;        /* Hyprland's active workspace on the focused monitor */
    int  mon_w, mon_h;       /* logical monitor size the miniatures are scaled from */
    struct mini_win mini[MINI_MAX];
    int  nmini;
    int  desk_x0, desk_w, desk_pitch, desk_x1;   /* strip layout from the last redraw */
    int  minus_x0, minus_x1, plus_x0, plus_x1;
    double axis_acc;         /* scroll accumulated over the strip */
    long long refresh_at;    /* when to take the next snapshot (monotonic ms; 0 = not scheduled) */
    unsigned act_gen;        /* bumped by each desktop action: a snapshot taken before it is stale */
    int  ev_fd;              /* Hyprland's event socket (.socket2.sock), -1 while not connected */
    long long ev_retry_at;
    char ev_line[256];
    size_t ev_len;
};

static volatile sig_atomic_t g_toggle = 0;
static void on_usr1(int s){ (void)s; g_toggle = 1; }

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
static void fill_rect(struct app *app, int x, int y, int w, int h, uint32_t c){
    if (!app->pixels) return;
    unsigned int a = (c >> 24) & 0xff;
    for (int yy = y; yy < y + h; yy++){ if (yy < 0 || yy >= app->height) continue;
        for (int xx = x; xx < x + w; xx++){ if (xx < 0 || xx >= app->width) continue;
            uint32_t *d = &app->pixels[yy*app->width + xx];
            *d = (a >= 255) ? (0xff000000u | (c & 0xffffff)) : blend_xrgb(*d, c & 0xffffff, a); } }
}
/* returns the pixel advance width of `text` at size px (for centering / right-align) */
static int text_width(struct app *app, const char *text, int px){
    if (!app->font_ready || !text) return 0;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0) return 0;
    int w = 0;
    for (const unsigned char *p = (const unsigned char*)text; *p; ++p){
        unsigned char ch = *p; if (ch < 0x20 || ch >= 0x7f) ch = '?';
        if (FT_Load_Char(app->face, ch, FT_LOAD_DEFAULT) != 0) continue;
        w += (int)(app->face->glyph->advance.x >> 6);
    }
    return w;
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

/* --- indicator glyphs (fill_rect only), sized for a 28px bar --- */
static void draw_wifi_glyph(struct app *app, int x, int cy, int bars){
    /* four ascending bars; lit ones bright, unlit dim; a slash when no adapter */
    for (int b = 0; b < 4; b++){
        int bh = 4 + b*3;
        uint32_t c = (bars < 0) ? COL_DIM : (bars >= b+1 ? COL_TEXT : 0xff4a4f55u);
        fill_rect(app, x + b*5, cy + 6 - bh, 3, bh, c);
    }
    if (bars < 0){
        for (int i = 0; i < 14; i++) fill_rect(app, x + i, cy - 6 + i, 2, 2, COL_DIM);
    }
}
static void draw_speaker_glyph(struct app *app, int x, int cy){
    fill_rect(app, x,     cy-3, 4, 6, COL_TEXT);
    fill_rect(app, x+4,   cy-5, 3, 10, COL_TEXT);
    fill_rect(app, x+9,   cy-4, 2, 8, COL_TEXT);
    fill_rect(app, x+12,  cy-6, 2, 12, COL_TEXT);
}
static void draw_battery_glyph(struct app *app, int x, int cy){
    fill_rect(app, x,    cy-5, 22, 11, COL_TEXT);      /* body */
    fill_rect(app, x+1,  cy-4, 20, 9,  COL_BG);        /* interior */
    fill_rect(app, x+22, cy-2, 2, 4,   COL_TEXT);      /* nub */
    fill_rect(app, x+2,  cy-3, 15, 6,  COL_TEXT);      /* ~70% charge */
}

/* signal strength -> 0..4 bars, from the ACTIVE row of /run/wifi/networks
 * (format: '# header' then 'SSID\tSTRENGTH\tSECURITY\tACTIVE\tPATH' rows). */
static int wifi_bars(void){
    FILE *f = fopen("/run/wifi/networks", "r");
    char line[512]; int bars = -1, have_dev = 0;
    if (!f) return -1;
    while (fgets(line, sizeof line, f)){
        char *save = NULL, *strength, *active;
        if (line[0] == '#'){ have_dev = 1; continue; }
        strtok_r(line, "\t", &save);                 /* SSID */
        strength = strtok_r(NULL, "\t", &save);
        strtok_r(NULL, "\t", &save);                 /* SECURITY */
        active = strtok_r(NULL, "\t", &save);
        if (active && (active[0]=='1'||active[0]=='y'||active[0]=='Y'||active[0]=='*')){
            int s = strength ? atoi(strength) : 0;
            bars = s>=80?4 : s>=55?3 : s>=30?2 : s>=5?1 : 0;
        }
    }
    fclose(f);
    if (bars < 0 && have_dev) return 0;
    return bars;
}

static void build_clock(struct app *app){
    time_t t = time(NULL); struct tm tmv;
    if (localtime_r(&t, &tmv)) strftime(app->clock_str, sizeof app->clock_str, "%a %b %e  %H:%M", &tmv);
    else snprintf(app->clock_str, sizeof app->clock_str, "--:--");
}

static long long now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void launch(const char *path){
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0){
        setsid();
        /* a fresh client must not inherit our Wayland connection fd or socket env */
        unsetenv("WAYLAND_SOCKET");
        for (int fd = 3; fd < 64; fd++) close(fd);
        char *const argv[] = { (char*)path, NULL };
        execve(path, argv, environ);
        _exit(127);
    }
}

static void redraw_commit(struct app *app);

/* --- Hyprland IPC, without ever blocking the bar ---------------------------------------------------
 * The bar is one thread driving its own Wayland connection, so it cannot sit inside a request.
 * Hyprland accept()s lazily (from its event loop) and this kernel's AF_UNIX read returns EAGAIN on
 * an empty socket, so a request is: connect + write now, then read the reply from the main poll
 * loop until Hyprland closes the connection.  The connection stays open until then -- a client
 * that hangs up first can lose its request before Hyprland reads it (see wl-quicksettings.c).
 * One request is in flight at a time; actions queue behind it and snapshot refreshes coalesce.
 *
 * The snapshot is a Lua `eval` that WRITES a compact summary to DESK_SNAPSHOT rather than asking
 * for `j/clients`: that JSON is ~1 KB per window and this kernel's socket buffer is 16 KB, while
 * Hyprland gives a full buffer only ~2 ms to drain before it drops the reply (successWrite). */
#define HYPR_DIR "/run/user/1000/hypr"
enum { IPC_QMAX = 6, IPC_TIMEOUT_MS = 3000 };

static struct {
    int       fd;                    /* request in flight, -1 = idle */
    int       is_snapshot;
    unsigned  snap_gen;              /* app->act_gen when this snapshot was requested */
    long long t0;
    char      reply[256];
    size_t    len;
    char      what[48];                /* the request, abbreviated, for the log */
    char      q[IPC_QMAX][1024];     /* queued action commands (ring) */
    int       qh, qn;
    int       want_snapshot;
} g_ipc = { .fd = -1 };

static const char SNAPSHOT_LUA[] =
    "eval local o = {} "
    "local m = hl.get_active_monitor() "
    "if m then local s = m.scale if not s or s <= 0 then s = 1 end local a = m.active_workspace "
      "o[#o + 1] = string.format('M %d %d %d\\n', a and a.id or 0, "
        "math.floor(m.width / s + 0.5), math.floor(m.height / s + 0.5)) end "
    "for _, w in ipairs(hl.get_windows()) do local ws = w.workspace "
      "if ws and not w.hidden then local mo = w.monitor local mx, my = 0, 0 "
        "if mo then mx, my = mo.x, mo.y end "
        "o[#o + 1] = string.format('W %d %d %d %d %d %d %d %s\\n', ws.id, w.at.x - mx, w.at.y - my, "
          "w.size.x, w.size.y, w.pid, w.focus_history_id, (string.gsub(w.class or '', '%s', '_'))) end end "
    "local f = io.open('" DESK_SNAPSHOT "', 'w') if f then f:write(table.concat(o)) f:close() end";

static int hypr_connect(const char *sockname){
    DIR *d = opendir(HYPR_DIR);
    if (!d) return -1;
    char path[256]; int found = 0;
    struct dirent *e;
    while ((e = readdir(d))){                 /* exactly one compositor instance on this system */
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof path, HYPR_DIR "/%s/%s", e->d_name, sockname);
        found = 1; break;
    }
    closedir(d);
    if (!found) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, path, sizeof sa.sun_path - 1);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0){ close(fd); return -1; }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
}

static void desk_schedule(struct app *app, int ms){
    long long t = now_ms() + ms;
    if (!app->refresh_at || t < app->refresh_at) app->refresh_at = t;
}

static void ipc_queue(struct app *app, const char *cmd){
    app->act_gen++;                           /* any snapshot already in flight predates this */
    if (g_ipc.qn >= IPC_QMAX){ log_line("BAR: desktop action dropped (queue full)"); return; }
    snprintf(g_ipc.q[(g_ipc.qh + g_ipc.qn) % IPC_QMAX], sizeof g_ipc.q[0], "%s", cmd);
    g_ipc.qn++;
}

static void ipc_start(struct app *app, const char *cmd, int is_snapshot){
    static int complaints;                    /* why a request could not even be sent, a few times */
    int fd = hypr_connect(".socket.sock");
    if (fd < 0){                              /* compositor not up (yet): the next tick retries */
        if (complaints < 5){ complaints++; char b[96]; snprintf(b, sizeof b, "BAR: desktops: connect to Hyprland failed: %s", strerror(errno)); log_line(b); }
        return;
    }
    size_t len = strlen(cmd);
    ssize_t w = write(fd, cmd, len);
    if (w != (ssize_t)len){
        if (complaints < 5){ complaints++; char b[96]; snprintf(b, sizeof b, "BAR: desktops: request write %zd/%zu: %s", w, len, strerror(errno)); log_line(b); }
        close(fd); return;
    }
    g_ipc.fd = fd; g_ipc.is_snapshot = is_snapshot; g_ipc.snap_gen = app->act_gen;
    g_ipc.t0 = now_ms(); g_ipc.len = 0; g_ipc.reply[0] = 0;
    snprintf(g_ipc.what, sizeof g_ipc.what, "%s", cmd + (strncmp(cmd, "eval ", 5) ? 0 : 5));
}

/* start the next request if none is in flight: queued actions first, then a coalesced snapshot */
static void ipc_pump(struct app *app){
    if (g_ipc.fd >= 0) return;
    if (g_ipc.qn > 0){
        char cmd[sizeof g_ipc.q[0]];
        memcpy(cmd, g_ipc.q[g_ipc.qh], sizeof cmd);
        g_ipc.qh = (g_ipc.qh + 1) % IPC_QMAX; g_ipc.qn--;
        ipc_start(app, cmd, 0);
        return;
    }
    if (g_ipc.want_snapshot){ g_ipc.want_snapshot = 0; ipc_start(app, SNAPSHOT_LUA, 1); }
}

/* the owning domain of a window's process: its identity colour + name (kernel /proc/<pid>/status) */
static void pid_domain(int pid, uint32_t *color, char *dom, size_t domcap){
    *color = COL_WIN_NEUTRAL; dom[0] = 0;
    if (pid <= 0) return;
    char p[40]; snprintf(p, sizeof p, "/proc/%d/status", pid);
    FILE *f = fopen(p, "r");
    if (!f) return;
    char line[128];
    while (fgets(line, sizeof line, f)){
        if (!strncmp(line, "DomainColor:", 12)) *color = 0xff000000u | (uint32_t)strtoul(line + 12, NULL, 16);
        else if (!strncmp(line, "Domain:", 7)){
            char *v = line + 7; v += strspn(v, " \t"); v[strcspn(v, "\r\n")] = 0;
            if (strcmp(v, "-")) snprintf(dom, domcap, "%s", v);
        }
    }
    fclose(f);
}

static void desk_save_count(struct app *app){
    int fd = open(DESKTOPS_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return;
    char b[16]; int n = snprintf(b, sizeof b, "%d\n", app->desk_count);
    if (write(fd, b, (size_t)n) != n){ /* best-effort: the strip still works for this run */ }
    close(fd);
}
static int desk_load_count(void){
    char b[16] = ""; int fd = open(DESKTOPS_FILE, O_RDONLY);
    if (fd >= 0){ if (read(fd, b, sizeof b - 1) < 0) b[0] = 0; close(fd); }
    int n = atoi(b);
    return (n >= 1 && n <= DESK_MAX) ? n : DESK_DEFAULT;
}

static void desk_load_snapshot(struct app *app){
    FILE *f = fopen(DESK_SNAPSHOT, "r");
    if (!f) return;
    static struct mini_win tmp[MINI_MAX];
    memset(tmp, 0, sizeof tmp);
    int n = 0, active = app->desk_active, mw = app->mon_w, mh = app->mon_h;
    char line[256];
    while (fgets(line, sizeof line, f)){
        if (line[0] == 'M'){
            int a, w, h;
            if (sscanf(line + 1, "%d %d %d", &a, &w, &h) == 3){ active = a; if (w > 0 && h > 0){ mw = w; mh = h; } }
        } else if (line[0] == 'W' && n < MINI_MAX){
            struct mini_win *m = &tmp[n];
            int pid = 0; char cls[64] = "";
            if (sscanf(line + 1, "%d %d %d %d %d %d %d %63s", &m->ws, &m->x, &m->y, &m->w, &m->h,
                       &pid, &m->focus, cls) < 7) continue;
            if (m->ws < 1 || m->ws > DESK_MAX || m->w <= 0 || m->h <= 0){   /* special workspaces etc. */
                memset(m, 0, sizeof *m); continue;
            }
            char *at = strchr(cls, '@'); if (at) *at = 0;   /* "<app>@<domain>" app ids */
            snprintf(m->cls, sizeof m->cls, "%s", cls);
            pid_domain(pid, &m->color, m->dom, sizeof m->dom);
            n++;
        }
    }
    fclose(f);
    int changed = n != app->nmini || memcmp(tmp, app->mini, (size_t)n * sizeof tmp[0]) != 0
               || active != app->desk_active || mw != app->mon_w || mh != app->mon_h;
    static int reported = -1;
    if (active != reported){
        char b[80]; snprintf(b, sizeof b, "BAR: desktops: Hyprland shows desktop %d (%d windows)", active, n);
        log_line(b); reported = active;
    }
    memcpy(app->mini, tmp, (size_t)n * sizeof tmp[0]);
    app->nmini = n; app->desk_active = active; app->mon_w = mw; app->mon_h = mh;
    /* the count follows reality: a desktop in use past the end extends it */
    int hi = (active >= 1 && active <= DESK_MAX) ? active : 0;
    for (int i = 0; i < n; i++) if (tmp[i].ws > hi) hi = tmp[i].ws;
    if (hi > app->desk_count){ app->desk_count = hi; desk_save_count(app); changed = 1; }
    if (changed) redraw_commit(app);
}

static void ipc_done(struct app *app, int complete){
    close(g_ipc.fd); g_ipc.fd = -1;
    g_ipc.reply[g_ipc.len < sizeof g_ipc.reply ? g_ipc.len : sizeof g_ipc.reply - 1] = 0;
    const int ok = complete && !strncmp(g_ipc.reply, "ok", 2);
    static int complaints;                    /* say why it failed, a few times, not every second */
    if (!ok && complaints < 5){
        complaints++;
        char b[320];
        snprintf(b, sizeof b, "BAR: desktops %s failed: %s", g_ipc.is_snapshot ? "snapshot" : "action",
                 g_ipc.reply[0] ? g_ipc.reply : (complete ? "(no reply)" : "(timed out)"));
        log_line(b);
    }
    if (g_ipc.is_snapshot){
        if (g_ipc.snap_gen != app->act_gen) desk_schedule(app, 0);   /* raced an action: take a fresh one */
        else if (ok) desk_load_snapshot(app);
    } else {
        if (ok){ char b[96]; snprintf(b, sizeof b, "BAR: desktops action ok (%.40s...)", g_ipc.what); log_line(b); }
        desk_schedule(app, 60);               /* show what the action did */
    }
}

static void ipc_readable(struct app *app){
    for (;;){
        char tmp[512];
        ssize_t n = read(g_ipc.fd, tmp, sizeof tmp);
        if (n > 0){                                      /* keep the head; a long reply is truncated */
            size_t have = g_ipc.len < sizeof g_ipc.reply - 1 ? g_ipc.len : sizeof g_ipc.reply - 1;
            size_t room = sizeof g_ipc.reply - 1 - have;
            memcpy(g_ipc.reply + have, tmp, (size_t)n < room ? (size_t)n : room);
            g_ipc.len += (size_t)n;
            continue;
        }
        if (n == 0){ ipc_done(app, 1); return; }            /* Hyprland replied and hung up */
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) ipc_done(app, 0);
        return;
    }
}

/* Hyprland's event socket: any window/workspace event means the miniatures may be stale.  A
 * "workspace>>N" is applied at once, so the highlight follows SUPER+N without waiting a round trip. */
static void ev_handle(struct app *app, const char *ev){
    if (!strncmp(ev, "workspace>>", 11)){
        int id = atoi(ev + 11);
        if (id >= 1 && id <= DESK_MAX && id != app->desk_active){ app->desk_active = id; redraw_commit(app); }
    }
    desk_schedule(app, 80);
}
static void ev_connect(struct app *app){
    if (app->ev_fd >= 0 || now_ms() < app->ev_retry_at) return;
    app->ev_fd = hypr_connect(".socket2.sock");
    if (app->ev_fd < 0){ app->ev_retry_at = now_ms() + 3000; return; }
    app->ev_len = 0;
    log_line("BAR: following Hyprland events for the desktops strip");
}
static void ev_readable(struct app *app){
    for (;;){
        char buf[1024];
        ssize_t n = read(app->ev_fd, buf, sizeof buf);
        if (n > 0){
            for (ssize_t i = 0; i < n; i++){
                if (buf[i] == '\n'){ app->ev_line[app->ev_len] = 0; ev_handle(app, app->ev_line); app->ev_len = 0; }
                else if (app->ev_len < sizeof app->ev_line - 1) app->ev_line[app->ev_len++] = buf[i];
            }
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        close(app->ev_fd); app->ev_fd = -1;                  /* compositor went away: reconnect later */
        app->ev_retry_at = now_ms() + 3000;
        return;
    }
}

/* --- desktop actions (optimistic: the strip changes now, the next snapshot confirms it) --- */
static void desk_switch(struct app *app, int n){
    if (n < 1 || n > app->desk_count || n == app->desk_active) return;
    char cmd[128];
    snprintf(cmd, sizeof cmd, "eval hl.dispatch(hl.dsp.focus({ workspace = %d }))", n);
    ipc_queue(app, cmd);
    app->desk_active = n;
    redraw_commit(app);
}
static void desk_add(struct app *app){
    if (app->desk_count >= DESK_MAX) return;
    app->desk_count++;
    desk_save_count(app);
    redraw_commit(app);
}
/* Remove the LAST desktop.  Its windows move to the one before it -- removing a desktop never
 * closes or strands a window -- and if it was the active one, that one becomes active. */
static void desk_remove(struct app *app){
    if (app->desk_count <= 1) return;
    const int from = app->desk_count, to = app->desk_count - 1;
    char cmd[1024];
    snprintf(cmd, sizeof cmd,
        "eval for _, w in ipairs(hl.get_windows()) do local ws = w.workspace "
          "if ws and ws.id >= %d and ws.id <= %d then "
            "hl.dispatch(hl.dsp.window.move({ workspace = %d, follow = false, window = 'address:' .. w.address })) end end "
        "local m = hl.get_active_monitor() "
        "if m and m.active_workspace and m.active_workspace.id >= %d and m.active_workspace.id <= %d then "
          "hl.dispatch(hl.dsp.focus({ workspace = %d })) end",
        from, DESK_MAX, to, from, DESK_MAX, to);
    ipc_queue(app, cmd);
    for (int i = 0; i < app->nmini; i++) if (app->mini[i].ws >= from) app->mini[i].ws = to;
    if (app->desk_active >= from) app->desk_active = to;
    app->desk_count = to;
    desk_save_count(app);
    redraw_commit(app);
}

/* "Desktop 2: wl-terminal (Personal), wl-files (Work)" -- shown in place of the clock on hover */
static void desk_summary(struct app *app, int ws, char *out, size_t cap){
    size_t pos = (size_t)snprintf(out, cap, "Desktop %d", ws);
    int shown = 0;
    for (int rank = 0; rank < 64 && pos < cap; rank++){      /* most recently focused first */
        for (int i = 0; i < app->nmini && pos < cap; i++){
            const struct mini_win *m = &app->mini[i];
            if (m->ws != ws || m->focus != rank) continue;
            if (pos + 24 >= cap){ pos += (size_t)snprintf(out + pos, cap - pos, ", ..."); rank = 64; break; }
            pos += (size_t)snprintf(out + pos, cap - pos, "%s%s", shown ? ", " : ": ", m->cls[0] ? m->cls : "window");
            if (m->dom[0] && pos < cap) pos += (size_t)snprintf(out + pos, cap - pos, " (%s)", m->dom);
            shown++;
        }
    }
    if (!shown && pos < cap) snprintf(out + pos, cap - pos, " - empty");
}

/* --- rendering --- */
static uint32_t shade(uint32_t c, int num, int den){
    unsigned r = ((c >> 16) & 0xff) * (unsigned)num / (unsigned)den;
    unsigned g = ((c >> 8) & 0xff) * (unsigned)num / (unsigned)den;
    unsigned b = (c & 0xff) * (unsigned)num / (unsigned)den;
    return 0xff000000u | (r > 255 ? 255 : r) << 16 | (g > 255 ? 255 : g) << 8 | (b > 255 ? 255 : b);
}
static void stroke_rect(struct app *app, int x, int y, int w, int h, uint32_t c){
    fill_rect(app, x, y, w, 1, c); fill_rect(app, x, y + h - 1, w, 1, c);
    fill_rect(app, x, y, 1, h, c); fill_rect(app, x + w - 1, y, 1, h, c);
}

/* The strip: one monitor-shaped miniature per desktop, then [-][+].  Laid out from x0 and kept
 * short of `limit` (the clock), shrinking the miniatures rather than overlapping it. */
static void draw_desktops(struct app *app, int x0, int limit){
    const int n = app->desk_count, mh = app->height - 8, y = 4, gap = 5, btn = 18;
    const int lw = app->mon_w > 0 ? app->mon_w : 1920, lh = app->mon_h > 0 ? app->mon_h : 1080;
    int mw = mh * lw / lh;
    if (mw < 16) mw = 16;
    if (mw > 44) mw = 44;
    while (mw > 12 && x0 + n * (mw + gap) + 2 * btn + 4 > limit) mw--;
    app->desk_x0 = x0; app->desk_w = mw; app->desk_pitch = mw + gap;

    for (int i = 0; i < n; i++){
        const int x = x0 + i * (mw + gap), ws = i + 1;
        const int active = ws == app->desk_active, hover = app->hover == R_DESK + i;
        fill_rect(app, x, y, mw, mh, active ? 0xff3b3f45u : 0xff202226u);
        /* windows, least recently focused first, so the focused one ends up on top */
        int any = 0;
        for (int rank = 63; rank >= 0; rank--){
            for (int k = 0; k < app->nmini; k++){
                const struct mini_win *m = &app->mini[k];
                if (m->ws != ws || (m->focus > 63 ? 63 : m->focus < 0 ? 63 : m->focus) != rank) continue;
                any = 1;
                int rx = x + 1 + (int)((long)m->x * (mw - 2) / lw), ry = y + 1 + (int)((long)m->y * (mh - 2) / lh);
                int rw = (int)((long)m->w * (mw - 2) / lw),         rh = (int)((long)m->h * (mh - 2) / lh);
                if (rw < 3) rw = 3;
                if (rh < 3) rh = 3;
                if (rx < x + 1) rx = x + 1;
                if (ry < y + 1) ry = y + 1;
                if (rx + rw > x + mw - 1) rw = x + mw - 1 - rx;
                if (ry + rh > y + mh - 1) rh = y + mh - 1 - ry;
                if (rw < 2 || rh < 2) continue;
                fill_rect(app, rx, ry, rw, rh, m->color);
                stroke_rect(app, rx, ry, rw, rh, (active && m->focus == 0) ? 0xffffffffu : shade(m->color, 1, 2));
            }
        }
        if (!any){                              /* an empty desktop shows its number, faintly */
            char num[4]; snprintf(num, sizeof num, "%d", ws);
            int tw = text_width(app, num, 10);
            draw_text(app, num, x + (mw - tw) / 2, y + (mh - 12) / 2, tw + 2, 10, 0xff6b7076u);
        }
        stroke_rect(app, x, y, mw, mh, active ? 0xfff2f2f2u : hover ? 0xffb8bcc2u : 0xff4a4e54u);
    }

    int bx = x0 + n * (mw + gap) + 2;
    const int cy = app->height / 2;
    app->minus_x0 = bx; app->minus_x1 = bx + btn;
    app->plus_x0 = bx + btn; app->plus_x1 = bx + 2 * btn;
    const uint32_t cm = n > 1 ? COL_TEXT : 0xff4a4e54u, cp = n < DESK_MAX ? COL_TEXT : 0xff4a4e54u;
    if (app->hover == R_DESK_MINUS && n > 1)
        fill_rect(app, app->minus_x0, 5, btn - 2, app->height - 10, COL_HOVER);
    if (app->hover == R_DESK_PLUS && n < DESK_MAX)
        fill_rect(app, app->plus_x0, 5, btn - 2, app->height - 10, COL_HOVER);
    fill_rect(app, app->minus_x0 + 4, cy - 1, 8, 2, cm);                  /* - */
    fill_rect(app, app->plus_x0 + 4, cy - 1, 8, 2, cp);                   /* + */
    fill_rect(app, app->plus_x0 + 7, cy - 4, 2, 8, cp);
    app->desk_x1 = app->plus_x1;
}

static void draw_bar(struct app *app){
    if (!app->pixels) return;
    fill_rect(app, 0, 0, app->width, app->height, COL_BG);
    int cy = app->height / 2;

    /* Activities (left) */
    const char *act = "Activities";
    int aw = text_width(app, act, 14);
    app->act_x0 = 0; app->act_x1 = 12 + aw + 12;
    if (app->hover == R_ACTIVITIES) fill_rect(app, app->act_x0+3, 3, app->act_x1-6, app->height-6, COL_HOVER);
    draw_text(app, act, 12, cy - 8, aw + 4, 14, COL_TEXT);

    /* Desktops (right of Activities), kept short of where the clock sits */
    int clock_w = text_width(app, app->clock_str, 13);
    draw_desktops(app, app->act_x1 + 4, (app->width - clock_w) / 2 - 20);

    /* Centre: the clock -- or, for a few seconds after a refused launch, the appgate notice; or,
     * while the pointer is on a desktop miniature, what is open on that desktop.  The clickable
     * box is the clock's (or the notice's), never the hover summary's. */
    char summary[160];
    const char *center = app->notice[0] ? app->notice : app->clock_str;
    int cw = text_width(app, center, 13);
    int cx = (app->width - cw) / 2;
    app->clk_x0 = cx - 8; app->clk_x1 = cx + cw + 8;
    if (!app->notice[0] && app->hover >= R_DESK && app->hover < R_DESK + app->desk_count){
        desk_summary(app, app->hover - R_DESK + 1, summary, sizeof summary);
        int sw = text_width(app, summary, 13);
        int sx = (app->width - sw) / 2;
        if (sx < app->desk_x1 + 16) sx = app->desk_x1 + 16;          /* never under the strip */
        draw_text(app, summary, sx, cy - 8, app->width - 100 - sx, 13, COL_TEXT);
    } else {
        if (app->notice[0]) fill_rect(app, app->clk_x0, 3, app->clk_x1-app->clk_x0, app->height-6, COL_NOTICE);
        if (app->hover == R_CLOCK) fill_rect(app, app->clk_x0, 3, app->clk_x1-app->clk_x0, app->height-6, COL_HOVER);
        draw_text(app, center, cx, cy - 8, cw + 4, 13, COL_TEXT);
    }

    /* Indicators (right): battery, volume, wifi -- laid out from the right edge */
    int x = app->width - 14;
    x -= 24; draw_battery_glyph(app, x, cy);   int bat_x = x;
    x -= 22; draw_speaker_glyph(app, x, cy);   int vol_x = x;
    x -= 24; draw_wifi_glyph(app, x, cy, app->wifi_bars);  int wifi_x = x;
    app->wifi_x0 = wifi_x - 4; app->wifi_x1 = wifi_x + 20;
    app->ind_x0 = vol_x - 4;  app->ind_x1 = bat_x + 28;
    if (app->hover == R_WIFI)       fill_rect(app, app->wifi_x0, 3, app->wifi_x1-app->wifi_x0, app->height-6, COL_HOVER);
    else if (app->hover == R_INDICATORS) fill_rect(app, app->ind_x0, 3, app->ind_x1-app->ind_x0, app->height-6, COL_HOVER);
}

static void buffer_release(void *d, struct wl_buffer *wl){ struct app *a = d;
    for (int i=0;i<2;i++) if (a->bufs[i].wl == wl) a->bufs[i].busy = 0;
    if (a->dirty) redraw_commit(a); }
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static int create_buffers(struct app *app){
    int fd = create_memfd("hos-bar");
    if (fd < 0) return -1;
    size_t total = app->buffer_size * 2;
    if (ftruncate(fd, (off_t)total) < 0){ close(fd); return -1; }
    void *data = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED){ close(fd); return -1; }
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int32_t)total);
    for (int i=0;i<2;i++){
        app->bufs[i].wl = wl_shm_pool_create_buffer(pool, (int)((size_t)i*app->buffer_size),
                              app->width, app->height, app->stride, WL_SHM_FORMAT_XRGB8888);
        wl_buffer_add_listener(app->bufs[i].wl, &buffer_listener, app);
        app->bufs[i].px = (uint32_t*)((unsigned char*)data + (size_t)i*app->buffer_size);
        app->bufs[i].busy = 0;
    }
    wl_shm_pool_destroy(pool);
    close(fd);
    return 0;
}

static void redraw_commit(struct app *app){
    if (!app->configured || app->hidden) return;
    int i = app->bufs[0].busy ? 1 : 0;
    if (app->bufs[i].busy){ app->dirty = 1; return; }     /* redrawn when a buffer comes back */
    app->dirty = 0;
    app->pixels = app->bufs[i].px;
    draw_bar(app);
    app->bufs[i].busy = 1;
    wl_surface_attach(app->surface, app->bufs[i].wl, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
}

static void set_hidden(struct app *app, int hide){
    if (hide == app->hidden) return;
    app->hidden = hide;
    if (hide){
        zwlr_layer_surface_v1_set_exclusive_zone(app->layer_surface, 0);
        wl_surface_attach(app->surface, NULL, 0, 0);
        wl_surface_commit(app->surface);
    } else {
        zwlr_layer_surface_v1_set_exclusive_zone(app->layer_surface, BAR_H);
        wl_surface_commit(app->surface);
        redraw_commit(app);
    }
    wl_display_flush(app->display);
}

/* --- pointer --- */
static int hit_region(struct app *app, double px, double py){
    (void)py;
    if (px >= app->act_x0  && px < app->act_x1)  return R_ACTIVITIES;
    if (app->desk_pitch > 0 && px >= app->desk_x0 && px < app->desk_x0 + app->desk_count * app->desk_pitch){
        int i = (int)(px - app->desk_x0) / app->desk_pitch;
        if (px - app->desk_x0 - i * app->desk_pitch < app->desk_w) return R_DESK + i;
        return R_NONE;                                        /* the gap between two miniatures */
    }
    if (px >= app->minus_x0 && px < app->minus_x1) return R_DESK_MINUS;
    if (px >= app->plus_x0  && px < app->plus_x1)  return R_DESK_PLUS;
    if (px >= app->wifi_x0 && px < app->wifi_x1) return R_WIFI;
    if (px >= app->ind_x0  && px < app->ind_x1)  return R_INDICATORS;
    if (px >= app->clk_x0  && px < app->clk_x1)  return R_CLOCK;
    return R_NONE;
}
static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; if (a->hover){ a->hover=R_NONE; redraw_commit(a);} }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y);
    int h = hit_region(a, a->pointer_x, a->pointer_y);
    if (h != a->hover){ a->hover = h; redraw_commit(a); } }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/ || state != 1 /*pressed*/) return;
    int r = hit_region(a, a->pointer_x, a->pointer_y);
    if (r >= R_DESK && r < R_DESK + a->desk_count){ desk_switch(a, r - R_DESK + 1); return; }
    switch (r){
        case R_ACTIVITIES: launch("/wl-overview");      break;
        case R_CLOCK:      launch(a->notice[0] ? "/wl-domain-manager" : "/wl-calendar"); break;
        case R_WIFI:       launch("/wl-wifi-menu");     break;   /* pick network + password */
        case R_INDICATORS: launch("/wl-quicksettings"); break;
        case R_DESK_MINUS: desk_remove(a);              break;
        case R_DESK_PLUS:  desk_add(a);                 break;
        default: break;
    } }
/* the scroll wheel over the desktops strip steps to the previous / next desktop */
static void pointer_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v){ (void)p;(void)t; struct app*a=d;
    if (ax != WL_POINTER_AXIS_VERTICAL_SCROLL) return;
    if (a->pointer_x < a->desk_x0 || a->pointer_x >= a->desk_x1){ a->axis_acc = 0; return; }
    a->axis_acc += wl_fixed_to_double(v);
    if (a->axis_acc >= 10 || a->axis_acc <= -10){
        int to = a->desk_active + (a->axis_acc > 0 ? 1 : -1);
        a->axis_acc = 0;
        if (to >= 1 && to <= a->desk_count) desk_switch(a, to);
    } }
static void pointer_frame(void *d, struct wl_pointer *p){ (void)d;(void)p; }
static void pointer_axis_source(void *d, struct wl_pointer *p, uint32_t s){ (void)d;(void)p;(void)s; }
static void pointer_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t a){ (void)d;(void)p;(void)t;(void)a; }
static void pointer_axis_discrete(void *d, struct wl_pointer *p, uint32_t a, int32_t dsc){ (void)d;(void)p;(void)a;(void)dsc; }
static const struct wl_pointer_listener pointer_listener = {
    .enter=pointer_enter,.leave=pointer_leave,.motion=pointer_motion,.button=pointer_button,.axis=pointer_axis,
    .frame=pointer_frame,.axis_source=pointer_axis_source,.axis_stop=pointer_axis_stop,.axis_discrete=pointer_axis_discrete };

static void seat_caps(void *d, struct wl_seat *seat, uint32_t caps){ struct app*a=d;
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !a->pointer){ a->pointer = wl_seat_get_pointer(seat); wl_pointer_add_listener(a->pointer,&pointer_listener,a); } }
static void seat_name(void *d, struct wl_seat *s, const char *n){ (void)d;(void)s;(void)n; }
static const struct wl_seat_listener seat_listener = { .capabilities=seat_caps, .name=seat_name };

/* --- layer surface --- */
static void layer_configure(void *d, struct zwlr_layer_surface_v1 *s, uint32_t serial, uint32_t w, uint32_t h){
    struct app *a = d;
    { char b[64]; snprintf(b,sizeof b,"BAR: configure %ux%u -> render", w, h); log_line(b); }
    zwlr_layer_surface_v1_ack_configure(s, serial);
    int nw = (int)w, nh = (int)h ? (int)h : BAR_H;
    if (nw <= 0) nw = 1;
    if (!a->configured || nw != a->width){
        a->width = nw; a->height = nh; a->stride = nw*4; a->buffer_size = (size_t)a->stride*nh;
        /* (re)create buffers at the compositor-chosen width */
        for (int i=0;i<2;i++) if (a->bufs[i].wl){ wl_buffer_destroy(a->bufs[i].wl); a->bufs[i].wl=NULL; }
        if (create_buffers(a) < 0){ log_line("BAR: buffer alloc failed"); a->running=0; return; }
    }
    a->configured = 1;
    redraw_commit(a);
}
static void layer_closed(void *d, struct zwlr_layer_surface_v1 *s){ (void)s; struct app*a=d; a->running=0; }
static const struct zwlr_layer_surface_v1_listener layer_listener = { .configure=layer_configure, .closed=layer_closed };

static void registry_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver){ struct app*a=d;
    if (!strcmp(iface, wl_compositor_interface.name)) a->compositor = wl_registry_bind(r,name,&wl_compositor_interface, ver<4?ver:4);
    else if (!strcmp(iface, wl_shm_interface.name)) a->shm = wl_registry_bind(r,name,&wl_shm_interface,1);
    else if (!strcmp(iface, zwlr_layer_shell_v1_interface.name)) a->layer_shell = wl_registry_bind(r,name,&zwlr_layer_shell_v1_interface, ver<4?ver:4);
    else if (!strcmp(iface, wl_output_interface.name) && !a->output) a->output = wl_registry_bind(r,name,&wl_output_interface, ver<2?ver:2);
    else if (!strcmp(iface, wl_seat_interface.name)){ a->seat = wl_registry_bind(r,name,&wl_seat_interface, ver<5?ver:5); wl_seat_add_listener(a->seat,&seat_listener,a); } }
static void registry_remove(void *d, struct wl_registry *r, uint32_t n){ (void)d;(void)r;(void)n; }
static const struct wl_registry_listener registry_listener = { .global=registry_global, .global_remove=registry_remove };

/* appgate: pick up a newly refused launch from /config/appgate.json -- "seq" counts refusals, and
 * "denies" holds the last few as { "seq": N, "image": .., "app": .., "domain": .. }.  Returns 1 when
 * the notice changed. */
static int json_str_after(const char *from, const char *key, char *out, size_t cap){
    char pat[24]; snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *k = strstr(from, pat); if (!k) return 0;
    const char *q1 = strchr(k + strlen(pat), '"'); if (!q1) return 0;
    const char *q2 = strchr(q1 + 1, '"'); if (!q2) return 0;
    size_t n = (size_t)(q2 - q1 - 1); if (n >= cap) n = cap - 1;
    memcpy(out, q1 + 1, n); out[n] = 0;
    return 1;
}
static int poll_appgate(struct app *app){
    unsigned char *buf; size_t sz;
    if (load_file("/config/appgate.json", &buf, &sz) < 0 || sz == 0) return 0;
    char *j = malloc(sz + 1);
    if (!j){ free(buf); return 0; }
    memcpy(j, buf, sz); j[sz] = 0; free(buf);
    int changed = 0;
    const char *sk = strstr(j, "\"seq\"");
    unsigned seq = sk ? (unsigned)strtoul(sk + 6 + strspn(sk + 6, " :"), NULL, 10) : 0;
    if (!app->gate_seen){ app->gate_seen = 1; app->gate_seq = seq; }
    else if (seq > app->gate_seq){
        app->gate_seq = seq;
        /* the newest entry: the last "seq": N inside "denies" */
        const char *d = strstr(j, "\"denies\""), *last = NULL;
        for (const char *p = d ? strstr(d, "{") : NULL; p; p = strstr(p + 1, "{")) last = p;
        char appn[72] = "", dom[40] = "";
        if (last){ json_str_after(last, "label", appn, sizeof appn);
                   if (!appn[0]) json_str_after(last, "app", appn, sizeof appn);
                   if (!appn[0] || !strcmp(appn, "-")) json_str_after(last, "image", appn, sizeof appn);
                   json_str_after(last, "domain", dom, sizeof dom); }
        snprintf(app->notice, sizeof app->notice, "%s is not delegated to %s - click to open the Domain Manager",
                 appn[0] ? appn : "That program", dom[0] ? dom : "this domain");
        app->notice_until = time(NULL) + 6;
        log_line(app->notice);
        changed = 1;
    }
    free(j);
    return changed;
}

/* once-a-second tick: refresh clock + wifi + honour the hide flag file / SIGUSR1 */
static void tick(struct app *app){
    int changed = 0;
    ev_connect(app);
    g_ipc.want_snapshot = 1;                  /* geometry changes (drags, resizes) raise no event */
    if (poll_appgate(app)) changed = 1;
    if (app->notice[0] && time(NULL) >= app->notice_until){ app->notice[0] = 0; changed = 1; }
    char prev[64]; strncpy(prev, app->clock_str, sizeof prev); prev[sizeof prev - 1] = 0;
    build_clock(app);
    if (strcmp(prev, app->clock_str)) changed = 1;
    int nb = wifi_bars();
    if (nb != app->wifi_bars){ app->wifi_bars = nb; changed = 1; }

    struct stat st;
    int want_hidden = (stat(HIDE_FLAG, &st) == 0);
    if (g_toggle){ g_toggle = 0; want_hidden = !app->hidden;      /* SIGUSR1 toggles */
        /* keep the flag file consistent so the Settings panel + bar agree */
        if (want_hidden){ int fd=open(HIDE_FLAG,O_CREAT|O_WRONLY,0644); if (fd>=0) close(fd); }
        else unlink(HIDE_FLAG);
    }
    if (want_hidden != app->hidden) set_hidden(app, want_hidden);
    else if (changed) redraw_commit(app);
}

int main(void){
    static struct app app; memset(&app, 0, sizeof app);
    app.running = 1; app.hover = R_NONE; app.wifi_bars = -1; app.ev_fd = -1;
    app.desk_count = desk_load_count(); app.desk_active = 1;
    signal(SIGCHLD, SIG_IGN);
    signal(SIGUSR1, on_usr1);
    signal(SIGPIPE, SIG_IGN);                 /* a compositor that hangs up on us is not fatal */
    init_freetype(&app);
    build_clock(&app);
    app.wifi_bars = wifi_bars();

    log_line("BAR: starting GNOME-style top bar (wlr-layer-shell)");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("BAR: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.layer_shell){ log_line("BAR: missing globals (need wlr-layer-shell)"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.layer_surface = zwlr_layer_shell_v1_get_layer_surface(app.layer_shell, app.surface,
                            app.output, ZWLR_LAYER_SHELL_V1_LAYER_TOP, "panel");
    zwlr_layer_surface_v1_add_listener(app.layer_surface, &layer_listener, &app);
    zwlr_layer_surface_v1_set_anchor(app.layer_surface,
        ZWLR_LAYER_SURFACE_V1_ANCHOR_TOP | ZWLR_LAYER_SURFACE_V1_ANCHOR_LEFT | ZWLR_LAYER_SURFACE_V1_ANCHOR_RIGHT);
    zwlr_layer_surface_v1_set_size(app.layer_surface, 0, BAR_H);           /* 0 width -> full output width */
    zwlr_layer_surface_v1_set_exclusive_zone(app.layer_surface, BAR_H);    /* reserve the strip */
    zwlr_layer_surface_v1_set_keyboard_interactivity(app.layer_surface, 0);/* never steal focus */
    wl_surface_commit(app.surface);                                        /* triggers the first configure */
    wl_display_flush(app.display);
    log_line("BAR: layer surface committed, awaiting configure");

    /* One loop for the Wayland connection, the Hyprland request in flight and Hyprland's event
     * socket; the timeout is whichever comes first of the 1 s tick, a scheduled desktops
     * snapshot and the request's deadline. */
    int wlfd = wl_display_get_fd(app.display);
    long long next_tick = now_ms();
    while (app.running){
        while (wl_display_prepare_read(app.display) != 0) wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);
        struct pollfd pfd[3]; int nfd = 0, ipc_i = -1, ev_i = -1;
        pfd[nfd++] = (struct pollfd){ .fd = wlfd, .events = POLLIN };
        if (g_ipc.fd >= 0){ ipc_i = nfd; pfd[nfd++] = (struct pollfd){ .fd = g_ipc.fd, .events = POLLIN }; }
        if (app.ev_fd >= 0){ ev_i = nfd; pfd[nfd++] = (struct pollfd){ .fd = app.ev_fd, .events = POLLIN }; }
        long long now = now_ms(), due = next_tick;
        if (app.refresh_at && app.refresh_at < due) due = app.refresh_at;
        if (g_ipc.fd >= 0 && g_ipc.t0 + IPC_TIMEOUT_MS < due) due = g_ipc.t0 + IPC_TIMEOUT_MS;
        int pr = poll(pfd, (nfds_t)nfd, due > now ? (int)(due - now) : 0);
        if (pr > 0 && (pfd[0].revents & POLLIN)){ wl_display_read_events(app.display); wl_display_dispatch_pending(app.display); }
        else { wl_display_cancel_read(app.display); if (pr < 0 && errno != EINTR) break; }
        if (pr > 0 && ipc_i >= 0 && pfd[ipc_i].revents && g_ipc.fd >= 0) ipc_readable(&app);
        if (pr > 0 && ev_i >= 0 && pfd[ev_i].revents && app.ev_fd >= 0) ev_readable(&app);
        now = now_ms();
        if (g_ipc.fd >= 0 && now - g_ipc.t0 >= IPC_TIMEOUT_MS) ipc_done(&app, 0);
        if (app.refresh_at && now >= app.refresh_at){ app.refresh_at = 0; g_ipc.want_snapshot = 1; }
        if (g_toggle || now >= next_tick){ next_tick = now + 1000; tick(&app); }
        ipc_pump(&app);
    }
    return 0;
}
