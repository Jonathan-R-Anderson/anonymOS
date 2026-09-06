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
enum { R_NONE=0, R_CLOSE, R_WIFI, R_SYSTEM, R_SETTINGS, R_LOCK, R_RESTART, R_POWER, R_LOGOUT };

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
    unsigned last_hash;
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
static int hit_region(struct app *app, double px, double py){
    (void)app;
    if (in_rect(px,py,CLOSE_X_OF(app),CLOSE_Y,CLOSE_W,CLOSE_H)) return R_CLOSE;
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
static void draw_menu(struct app *app){
    const uint32_t BG=0xff1b1f27u, TITLE=0xff11141bu, ROW=0xff232834u, ROWH=0xff2d3444u,
                   TXT=0xfff2f5fau, DIM=0xff8b94a3u, ACC=0xff4da3ffu,
                   OK=0xff57d977u, DANGER=0xffe0564au, CLOSEC=0xffe0564au;
    fill_rect(app, 0, 0, app->width, app->height, BG);

    /* --- CSD titlebar --- */
    fill_rect(app, 0, 0, app->width, TITLE_H, TITLE);
    draw_text(app, "System", 14, 7, 200, 15, TXT);
    fill_rect(app, CLOSE_X_OF(app), CLOSE_Y, CLOSE_W, CLOSE_H, (app->hover==R_CLOSE)?CLOSEC:ROWH);
    draw_text(app, "x", CLOSE_X_OF(app)+7, CLOSE_Y+3, 16, 14, TXT);

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
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    /* Presses only.  Without the state check a release re-fires the action, so every click
     * would act twice -- two launches, or two poweroffs. */
    if (button != 0x110 /*BTN_LEFT*/ || state != 1) return;

    switch (hit_region(a, a->pointer_x, a->pointer_y)){
        case R_CLOSE:    exit(0);
        case R_WIFI:     launch("/wl-wifi-menu"); break;
        case R_SYSTEM:   launch("/wl-sysmon"); break;
        case R_SETTINGS: launch("/wl-domain-manager"); break;
        case R_LOCK:     session_action("lock"); break;
        case R_RESTART:  session_action("reboot"); break;
        case R_POWER:    session_action("poweroff"); break;
        case R_LOGOUT:   session_action("logout"); break;
        default: break;
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
static void kb_key(void *d, struct wl_keyboard *k, uint32_t se, uint32_t t, uint32_t key, uint32_t state){ (void)k;(void)se;(void)t; struct app*a=d;
    if (state != 1) return;
    if (key==1) a->running = 0;   /* Esc closes */ }
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
    app.running = 1; app.hover = R_NONE;
    app.width = WIN_W; app.height = WIN_H; app.stride = WIN_W*4; app.buffer_size = (size_t)app.stride*WIN_H;
    signal(SIGCHLD, SIG_IGN);
    init_freetype(&app);
    load_wifi(&app);
    load_identity(&app);
    load_stats(&app);
    publish_state(&app);

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
