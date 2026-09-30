/*
 * wl-dock.c -- the launcher: a Unity-style bar down the left edge of the screen, and the drawer of
 * every installed application that slides out of it.
 *
 * The bar is a translucent strip (wlr-layer-shell, TOP layer, reserving its width so windows tile
 * beside it) holding the pinned applications, top to bottom; it scrolls with the wheel when they do
 * not fit.  At its bottom sits the launcher button.  Clicking it slides the drawer out from the
 * left edge -- an OVERLAY layer surface over the rest of the screen: a search field and a grid of
 * every installed application (the .desktop entries under /usr/share/applications, which the
 * Software Center's packages add to).  Typing filters, Enter or a click starts one, Esc, a click on
 * the dimmed desktop or the button again closes it.  Right-click a drawer tile to pin or unpin it;
 * right-click a bar icon to unpin it.
 *
 * Every icon carries its domain's badge (hos-shell-ui.h): a ring in the colour of the domain the
 * program runs in and the domain's tag at its bottom left.
 *
 * Configuration: ~/.config/anonymos/dock.conf (written with the defaults on first run, re-read when
 * it changes):
 *     pin = <program>             one line per pinned application, as its .desktop Exec= line
 *     launcher-icon = <PNG>       the bottom button's picture (default: a grid of dots)
 *     width = <pixels>            the bar's width (default 64)
 *
 * Self-test: `wl-dock --render-png PREFIX` draws the bar and the open drawer to PREFIX-dock.png and
 * PREFIX-drawer.png without a compositor (size from WLDOCK_SIZE=WxH, fonts from WLDOCK_FONTDIR).
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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
#include "wlr-layer-shell-unstable-v1-client-protocol.h"
#include "hos-shell-ui.h"

extern char **environ;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum { DEF_DOCK_W = 64, ICON = 44, GAP = 10, TOP_PAD = 10, BUTTON_H = 68,
       PANEL_MAX_W = 700, CELL_W = 118, CELL_H = 118, TILE = 56, SEARCH_H = 40, PANEL_PAD = 22,
       ANIM_MS = 170 };

#define APPDIR "/usr/share/applications"

/* ── model ─────────────────────────────────────────────────────────────────────────────────── */
struct appent { char name[96]; char exec[256]; char dom[40]; int glyph; };

struct buf { struct wl_buffer *wl; uint32_t *px; int busy; };
struct surf {
    struct wl_surface *s;
    struct zwlr_layer_surface_v1 *ls;
    struct buf b[2];
    void *map; size_t mapsz;
    int w, h, configured, dirty;
};

struct app {
    struct wl_display *display;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_seat *seat;
    struct wl_pointer *pointer;
    struct wl_keyboard *keyboard;
    struct zwlr_layer_shell_v1 *layer_shell;
    int scale, running, offscreen;

    struct surf dock, drawer, tip;
    char tip_text[128];
    struct wl_surface *ptr_surface;
    double px, py;

    /* config */
    char conf_path[512];
    time_t conf_mtime;
    int dock_w;
    char **pins; int npins;
    char icon_path[512];
    cairo_surface_t *icon_png;

    /* installed applications */
    struct appent *apps; int napps, capps;
    char *appgate;
    struct hos_domain *doms; int ndoms;
    long long refreshed_ms;

    /* the bar */
    int hover_pin;                 /* -1 none, npins = the launcher button */
    int scroll;                    /* pixels the pinned list is scrolled */

    /* the drawer */
    int open;                      /* 1 while shown (including the closing slide) */
    int closing;
    long long anim_t0;
    double anim;                   /* 0 closed .. 1 fully out */
    char search[64]; int searchlen;
    int *filt; int nfilt;
    int sel;                       /* keyboard selection in filt, -1 none */
    int hover_tile;
    int dscroll;                   /* rows scrolled */
    int shift;

    struct hos_font font, bold;
};

static void log_line(const char *s) { fputs(s, stdout); fputc('\n', stdout); fflush(stdout); }
static long long now_ms(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ── configuration ─────────────────────────────────────────────────────────────────────────── */
static const char *DEFAULT_PINS[] = { "/wl-files", "/hos-wifiterm", "/wl-software", "/wl-vmm", "/wl-domain-manager" };

static void conf_write_default(struct app *a)
{
    char dir[512];
    snprintf(dir, sizeof dir, "%s", a->conf_path);
    char *sl = strrchr(dir, '/');
    if (!sl) return;
    *sl = 0;
    char *p2 = strrchr(dir, '/');                   /* ~/.config, then ~/.config/anonymos */
    if (p2) { *p2 = 0; mkdir(dir, 0700); *p2 = '/'; }
    mkdir(dir, 0700);
    FILE *f = fopen(a->conf_path, "w");
    if (!f) return;
    fputs("# The launcher: the bar on the left edge of the screen.  Changes apply as soon as this\n"
          "# file is saved.\n"
          "#\n"
          "#   pin = <program>          a pinned application, as its .desktop Exec= line; top to bottom\n"
          "#   launcher-icon = <PNG>    the picture on the button at the bottom (default: a dot grid)\n"
          "#   width = <pixels>         the bar's width (default 64)\n"
          "#\n"
          "# Right-click an application in the drawer to pin or unpin it without editing this file.\n", f);
    for (size_t i = 0; i < sizeof DEFAULT_PINS / sizeof DEFAULT_PINS[0]; i++) fprintf(f, "pin = %s\n", DEFAULT_PINS[i]);
    fputs("# launcher-icon = /home/user/Pictures/launcher.png\n", f);
    fclose(f);
}

static void pins_clear(struct app *a)
{
    for (int i = 0; i < a->npins; i++) free(a->pins[i]);
    free(a->pins); a->pins = NULL; a->npins = 0;
}
static void pins_add(struct app *a, const char *exec)
{
    char **np = realloc(a->pins, (size_t)(a->npins + 1) * sizeof *np);
    if (!np) return;
    a->pins = np;
    a->pins[a->npins++] = strdup(exec);
}

static void conf_load(struct app *a)
{
    struct stat st;
    if (stat(a->conf_path, &st) != 0) { conf_write_default(a); if (stat(a->conf_path, &st) != 0) st.st_mtime = 0; }
    a->conf_mtime = st.st_mtime;
    pins_clear(a);
    a->dock_w = DEF_DOCK_W;
    char newicon[512] = "";
    FILE *f = fopen(a->conf_path, "r");
    if (!f) {                                          /* unreadable: the built-in defaults */
        for (size_t i = 0; i < sizeof DEFAULT_PINS / sizeof DEFAULT_PINS[0]; i++) pins_add(a, DEFAULT_PINS[i]);
    } else {
        char line[640];
        while (fgets(line, sizeof line, f)) {
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '#' || *p == '\n' || !*p) continue;
            char *eq = strchr(p, '=');
            if (!eq) continue;
            char *ke = eq; while (ke > p && (ke[-1] == ' ' || ke[-1] == '\t')) ke--;
            *ke = 0;
            char *v = eq + 1; while (*v == ' ' || *v == '\t') v++;
            size_t vl = strlen(v); while (vl && (v[vl - 1] == '\n' || v[vl - 1] == '\r' || v[vl - 1] == ' ')) v[--vl] = 0;
            if (!strcmp(p, "pin") && vl) pins_add(a, v);
            else if (!strcmp(p, "launcher-icon")) snprintf(newicon, sizeof newicon, "%s", v);
            else if (!strcmp(p, "width")) { int w = atoi(v); if (w >= 40 && w <= 160) a->dock_w = w; }
        }
        fclose(f);
    }
    if (strcmp(newicon, a->icon_path) != 0 || (newicon[0] && !a->icon_png)) {
        if (a->icon_png) { cairo_surface_destroy(a->icon_png); a->icon_png = NULL; }
        snprintf(a->icon_path, sizeof a->icon_path, "%s", newicon);
        if (newicon[0]) {
            cairo_surface_t *s = cairo_image_surface_create_from_png(newicon);
            if (cairo_surface_status(s) == CAIRO_STATUS_SUCCESS) a->icon_png = s;
            else { cairo_surface_destroy(s); log_line("DOCK: launcher-icon unreadable (a PNG is needed); using the default"); }
        }
    }
}

static void conf_save_pins(struct app *a)
{
    /* Rewrite the pin lines, keeping every other line (comments, the icon, the width) as it was. */
    char *old = hos_read_file(a->conf_path);
    FILE *f = fopen(a->conf_path, "w");
    if (!f) { free(old); return; }
    int wrote = 0;
    for (char *line = old; line && *line; ) {
        char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        const char *p = line; while (*p == ' ' || *p == '\t') p++;
        int is_pin = !strncmp(p, "pin", 3) && (p[3] == ' ' || p[3] == '=' || p[3] == '\t');
        if (is_pin) {
            if (!wrote) { for (int i = 0; i < a->npins; i++) fprintf(f, "pin = %s\n", a->pins[i]); wrote = 1; }
        } else {
            fwrite(line, 1, len, f); fputc('\n', f);
        }
        line = nl ? nl + 1 : line + len;
    }
    if (!wrote) for (int i = 0; i < a->npins; i++) fprintf(f, "pin = %s\n", a->pins[i]);
    fclose(f);
    free(old);
    struct stat st;
    if (stat(a->conf_path, &st) == 0) a->conf_mtime = st.st_mtime;
}

/* ── installed applications ────────────────────────────────────────────────────────────────── */
static void first_word(const char *exec, char *out, size_t cap)
{
    size_t i = 0;
    while (exec[i] && exec[i] != ' ' && i < cap - 1) { out[i] = exec[i]; i++; }
    out[i] = 0;
}
/* Is the program an Exec= line starts present?  (An optional app ships its entry either way.) */
static int exec_installed(const char *exec)
{
    char first[256];
    first_word(exec, first, sizeof first);
    if (first[0] == '/') { char rp[512]; snprintf(rp, sizeof rp, "%s%s", hos_root, first); return access(rp, X_OK) == 0; }
    const char *path = getenv("PATH");
    if (!path) path = "/bin:/usr/bin";
    char dir[256];
    for (const char *p = path; *p; ) {
        const char *e = strchr(p, ':'); size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n && n < sizeof dir - 1) {
            memcpy(dir, p, n); dir[n] = 0;
            char full[600]; snprintf(full, sizeof full, "%s/%s", dir, first);
            if (access(full, X_OK) == 0) return 1;
        }
        p = e ? e + 1 : p + n;
    }
    return 0;
}
/* Drop freedesktop field codes (%U, %f, ...) from an Exec= line. */
static void strip_field_codes(char *s)
{
    char *w = s;
    for (char *r = s; *r; r++) {
        if (r[0] == '%' && r[1]) { r++; if (*r == '%') *w++ = '%'; continue; }
        *w++ = *r;
    }
    *w = 0;
    size_t n = strlen(s); while (n && s[n - 1] == ' ') s[--n] = 0;
}
/* The app grid's rule (appgate): a registry program the desktop may not start is not offered.  An
 * installed package -- a program the registry does not know -- is placed by the kernel instead. */
static int desktop_allows(const char *appgate, const char *exec)
{
    if (!appgate) return 1;
    const char *d = strstr(appgate, "\"desktop\"");
    const char *pl = strstr(appgate, "\"placement\"");
    if (!d) return 1;
    char first[256]; first_word(exec, first, sizeof first);
    const char *b = strrchr(first, '/'); b = b ? b + 1 : first;
    char q[280]; snprintf(q, sizeof q, "\"%s\"", b);
    const char *hit = strstr(d, q);
    if (hit && (!pl || hit < pl)) return 1;
    /* not on the list: a registry program (a root-level image) is refused; a package runs */
    return !(first[0] == '/' && strchr(first + 1, '/') == NULL);
}

static void apps_add(struct app *a, const char *name, const char *exec)
{
    if (a->napps == a->capps) {
        int nc = a->capps ? a->capps * 2 : 64;
        struct appent *nv = realloc(a->apps, (size_t)nc * sizeof *nv);
        if (!nv) return;
        a->apps = nv; a->capps = nc;
    }
    struct appent *e = &a->apps[a->napps++];
    memset(e, 0, sizeof *e);
    snprintf(e->name, sizeof e->name, "%s", name);
    snprintf(e->exec, sizeof e->exec, "%s", exec);
    e->glyph = hos_glyph_for_exec(exec);
    hos_placement_of(a->appgate, exec, e->dom, sizeof e->dom);
}
static int cmp_app(const void *x, const void *y)
{
    return strcasecmp(((const struct appent *)x)->name, ((const struct appent *)y)->name);
}

/* Re-read the application entries, the domains (colours, tags) and the placements. */
static void refresh_world(struct app *a)
{
    free(a->appgate); a->appgate = hos_read_file("/config/appgate.json");
    free(a->doms); a->ndoms = hos_domains_load(&a->doms);
    a->napps = 0;
    char appdir[512];
    snprintf(appdir, sizeof appdir, "%s%s", hos_root, APPDIR);
    DIR *d = opendir(appdir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            size_t l = strlen(e->d_name);
            if (l < 9 || strcmp(e->d_name + l - 8, ".desktop")) continue;
            char path[768]; snprintf(path, sizeof path, "%s/%s", appdir, e->d_name);
            FILE *f = fopen(path, "r");
            if (!f) continue;
            char line[512], name[96] = "", exec[256] = "";
            int hidden = 0, in_entry = 0;
            while (fgets(line, sizeof line, f)) {
                size_t n = strlen(line); while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
                if (line[0] == '[') { in_entry = !strcmp(line, "[Desktop Entry]"); continue; }
                if (!in_entry) continue;
                if (!strncmp(line, "Name=", 5) && !name[0]) snprintf(name, sizeof name, "%s", line + 5);
                else if (!strncmp(line, "Exec=", 5) && !exec[0]) snprintf(exec, sizeof exec, "%s", line + 5);
                else if (!strcmp(line, "NoDisplay=true") || !strcmp(line, "Hidden=true")) hidden = 1;
                else if (!strcmp(line, "Terminal=true")) hidden = 1;   /* a CLI: run it from a terminal */
            }
            fclose(f);
            if (!name[0] || !exec[0] || hidden) continue;
            strip_field_codes(exec);
            if (!exec_installed(exec) || !desktop_allows(a->appgate, exec)) continue;
            int dup = 0;
            for (int i = 0; i < a->napps; i++) if (!strcmp(a->apps[i].exec, exec)) { dup = 1; break; }
            if (!dup) apps_add(a, name, exec);
        }
        closedir(d);
    }
    if (a->napps > 1) qsort(a->apps, (size_t)a->napps, sizeof *a->apps, cmp_app);
    a->refreshed_ms = now_ms();
}

/* The entry for a pinned program (by its Exec= line, else by program name). */
static const struct appent *app_for_exec(struct app *a, const char *exec)
{
    for (int i = 0; i < a->napps; i++) if (!strcmp(a->apps[i].exec, exec)) return &a->apps[i];
    char w1[256], w2[256]; first_word(exec, w1, sizeof w1);
    for (int i = 0; i < a->napps; i++) { first_word(a->apps[i].exec, w2, sizeof w2); if (!strcmp(w1, w2)) return &a->apps[i]; }
    return NULL;
}
static int pinned_index(struct app *a, const char *exec)
{
    for (int i = 0; i < a->npins; i++) if (!strcmp(a->pins[i], exec)) return i;
    return -1;
}

static void recompute_filter(struct app *a)
{
    free(a->filt); a->filt = malloc((size_t)(a->napps ? a->napps : 1) * sizeof *a->filt);
    a->nfilt = 0;
    for (int i = 0; i < a->napps; i++) {
        const char *h = a->apps[i].name, *n = a->search;
        int ok = !n[0];
        for (const char *p = h; !ok && *p; p++) {
            const char *x = p, *y = n;
            while (*x && *y && tolower((unsigned char)*x) == tolower((unsigned char)*y)) { x++; y++; }
            if (!*y) ok = 1;
        }
        if (ok) a->filt[a->nfilt++] = i;
    }
    if (a->sel >= a->nfilt) a->sel = a->nfilt ? 0 : -1;
    if (a->search[0] && a->nfilt && a->sel < 0) a->sel = 0;
    a->dscroll = 0;
}

/* ── launching ─────────────────────────────────────────────────────────────────────────────── */
static void launch(struct app *a, const char *exec)
{
    char m[320]; snprintf(m, sizeof m, "DOCK: launch '%s'", exec); log_line(m);
    if (a->offscreen) return;
    pid_t pid = fork();
    if (pid == 0) {
        for (int fd = 3; fd < 256; fd++) close(fd);       /* the Wayland socket stays with the dock */
        setsid();
        int con = open("/dev/console", O_WRONLY);          /* its output, where every program's goes */
        if (con >= 0) { dup2(con, 1); dup2(con, 2); if (con > 2) close(con); }
        char buf[512]; snprintf(buf, sizeof buf, "%s", exec);
        char *argv[32]; int n = 0;
        for (char *t = strtok(buf, " "); t && n < 31; t = strtok(NULL, " ")) argv[n++] = t;
        argv[n] = NULL;
        if (n) { if (argv[0][0] == '/') execve(argv[0], argv, environ); else execvp(argv[0], argv); }
        _exit(127);
    }
}

/* ── shm buffers ───────────────────────────────────────────────────────────────────────────── */
static void buf_release(void *d, struct wl_buffer *wl)
{
    struct surf *s = d;
    for (int i = 0; i < 2; i++) if (s->b[i].wl == wl) s->b[i].busy = 0;
}
static const struct wl_buffer_listener buf_listener = { .release = buf_release };

static void surf_free_buffers(struct surf *s)
{
    for (int i = 0; i < 2; i++) { if (s->b[i].wl) wl_buffer_destroy(s->b[i].wl); s->b[i].wl = NULL; s->b[i].px = NULL; s->b[i].busy = 0; }
    if (s->map) { if (s->mapsz) munmap(s->map, s->mapsz); else free(s->map); }   /* mapsz 0: offscreen calloc */
    s->map = NULL; s->mapsz = 0;
}
static int surf_alloc(struct app *a, struct surf *s, int w, int h)
{
    surf_free_buffers(s);
    const int pw = w * a->scale, ph = h * a->scale, stride = pw * 4;
    const size_t one = (size_t)stride * (size_t)ph;
    if (a->offscreen) {
        s->map = calloc(1, one * 2); s->mapsz = 0;
        if (!s->map) return -1;
        for (int i = 0; i < 2; i++) s->b[i].px = (uint32_t *)((char *)s->map + one * (size_t)i);
        s->w = w; s->h = h;
        return 0;
    }
    int fd = (int)syscall(SYS_memfd_create, "wl-dock", MFD_CLOEXEC);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)(one * 2)) < 0) { close(fd); return -1; }
    void *m = mmap(NULL, one * 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) { close(fd); return -1; }
    struct wl_shm_pool *pool = wl_shm_create_pool(a->shm, fd, (int)(one * 2));
    for (int i = 0; i < 2; i++) {
        s->b[i].px = (uint32_t *)((char *)m + one * (size_t)i);
        s->b[i].wl = wl_shm_pool_create_buffer(pool, (int)(one * (size_t)i), pw, ph, stride, WL_SHM_FORMAT_ARGB8888);
        wl_buffer_add_listener(s->b[i].wl, &buf_listener, s);
    }
    wl_shm_pool_destroy(pool);
    close(fd);
    s->map = m; s->mapsz = one * 2;
    s->w = w; s->h = h;
    return 0;
}

/* ── drawing ───────────────────────────────────────────────────────────────────────────────── */
static const struct hos_domain *dom_of(struct app *a, const char *dom) { return hos_domain_find(a->doms, a->ndoms, dom); }

/* One application icon (art + initial + domain badge) in an s x s square. */
static void draw_app_icon(struct app *a, cairo_t *cr, const struct appent *e, const char *exec, double x, double y, double s)
{
    const char *name = e ? e->name : exec;
    const int glyph = e ? e->glyph : hos_glyph_for_exec(exec);
    hos_icon_art(cr, glyph, x, y, s, name, NULL, 0);
    if (glyph == HOS_G_LAUNCHER && name[0]) {
        char ch[2] = { (char)toupper((unsigned char)name[0]), 0 };
        hos_text_center(cr, &a->bold, s * 0.46, x + s / 2, y + s * 0.2, 0xffffffu, 1, ch);
    }
    char pl[40] = "";
    if (e) snprintf(pl, sizeof pl, "%s", e->dom); else hos_placement_of(a->appgate, exec, pl, sizeof pl);
    hos_domain_badge(cr, &a->font, x, y, s, dom_of(a, pl));
}

static int pins_area_h(struct app *a, int h) { (void)a; return h - BUTTON_H; }
static int pin_y(struct app *a, int i) { return TOP_PAD + i * (ICON + GAP) - a->scroll; }
static int max_scroll(struct app *a, int h)
{
    const int content = TOP_PAD * 2 + a->npins * (ICON + GAP) - GAP;
    const int m = content - pins_area_h(a, h);
    return m > 0 ? m : 0;
}

static void draw_launcher_button(struct app *a, cairo_t *cr, double x, double y, double s, int hot)
{
    if (hot || a->open) {
        hos_rr_path(cr, x - 5, y - 5, s + 10, s + 10, 12);
        cairo_set_source_rgba(cr, 1, 1, 1, a->open ? 0.22 : 0.12);
        cairo_fill(cr);
    }
    if (a->icon_png) {
        const int iw = cairo_image_surface_get_width(a->icon_png), ih = cairo_image_surface_get_height(a->icon_png);
        cairo_save(cr);
        cairo_translate(cr, x, y);
        const double k = s / (iw > ih ? iw : ih);
        cairo_scale(cr, k, k);
        cairo_set_source_surface(cr, a->icon_png, (iw > ih ? 0 : (ih - iw) / 2.0), (ih > iw ? 0 : (iw - ih) / 2.0));
        cairo_paint(cr);
        cairo_restore(cr);
        return;
    }
    /* the default: a 3 x 3 grid of rounded dots ("all applications") */
    const double d = s * 0.2, g = (s - 3 * d) / 4;
    for (int r = 0; r < 3; r++)
        for (int c = 0; c < 3; c++) {
            hos_rr_path(cr, x + g + c * (d + g), y + g + r * (d + g), d, d, d * 0.3);
            cairo_set_source_rgba(cr, 1, 1, 1, a->open ? 1 : 0.88);
            cairo_fill(cr);
        }
}

static void draw_dock(struct app *a, cairo_t *cr, int w, int h)
{
    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(cr, 0.06, 0.07, 0.09, 0.62);          /* translucent */
    cairo_paint(cr);
    cairo_set_operator(cr, CAIRO_OPERATOR_OVER);
    cairo_rectangle(cr, w - 1, 0, 1, h);                        /* a hairline on the desktop side */
    cairo_set_source_rgba(cr, 1, 1, 1, 0.08);
    cairo_fill(cr);

    const int area = pins_area_h(a, h);
    const double ix = (w - ICON) / 2.0;
    cairo_save(cr);
    cairo_rectangle(cr, 0, 0, w, area);
    cairo_clip(cr);
    for (int i = 0; i < a->npins; i++) {
        const int y = pin_y(a, i);
        if (y + ICON < 0 || y > area) continue;
        if (a->hover_pin == i) {
            hos_rr_path(cr, ix - 5, y - 5, ICON + 10, ICON + 10, 12);
            cairo_set_source_rgba(cr, 1, 1, 1, 0.12);
            cairo_fill(cr);
        }
        draw_app_icon(a, cr, app_for_exec(a, a->pins[i]), a->pins[i], ix, y, ICON);
    }
    cairo_restore(cr);
    /* more above / below: a soft fade says the list scrolls */
    const int ms = max_scroll(a, h);
    if (a->scroll > 0) {
        cairo_pattern_t *g = cairo_pattern_create_linear(0, 0, 0, 18);
        cairo_pattern_add_color_stop_rgba(g, 0, 0.06, 0.07, 0.09, 0.9);
        cairo_pattern_add_color_stop_rgba(g, 1, 0.06, 0.07, 0.09, 0);
        cairo_rectangle(cr, 0, 0, w - 1, 18); cairo_set_source(cr, g); cairo_fill(cr); cairo_pattern_destroy(g);
    }
    if (a->scroll < ms) {
        cairo_pattern_t *g = cairo_pattern_create_linear(0, area - 18, 0, area);
        cairo_pattern_add_color_stop_rgba(g, 0, 0.06, 0.07, 0.09, 0);
        cairo_pattern_add_color_stop_rgba(g, 1, 0.06, 0.07, 0.09, 0.9);
        cairo_rectangle(cr, 0, area - 18, w - 1, 18); cairo_set_source(cr, g); cairo_fill(cr); cairo_pattern_destroy(g);
    }
    /* the launcher button, below a separator */
    cairo_rectangle(cr, 10, area + 0.5, w - 20, 1);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.14);
    cairo_fill(cr);
    const double bs = ICON;
    draw_launcher_button(a, cr, (w - bs) / 2.0, area + (BUTTON_H - bs) / 2.0, bs, a->hover_pin == a->npins);
}

/* drawer geometry (surface coordinates; the panel slides in from x < 0) */
static int panel_w(struct app *a) { int w = a->drawer.w * 55 / 100; if (w > PANEL_MAX_W) w = PANEL_MAX_W; if (w < 300) w = a->drawer.w < 300 ? a->drawer.w : 300; return w; }
static int grid_cols(struct app *a) { int c = (panel_w(a) - 2 * PANEL_PAD) / CELL_W; return c < 1 ? 1 : c; }
static int grid_top(void) { return PANEL_PAD + SEARCH_H + 18; }
static double ease(double t) { return 1 - (1 - t) * (1 - t) * (1 - t); }
static int panel_x(struct app *a) { return (int)((ease(a->anim) - 1) * panel_w(a)); }

static void tile_rect(struct app *a, int pos, int *x, int *y)
{
    const int cols = grid_cols(a);
    const int gx = PANEL_PAD + (panel_w(a) - 2 * PANEL_PAD - cols * CELL_W) / 2;
    *x = panel_x(a) + gx + (pos % cols) * CELL_W;
    *y = grid_top() + (pos / cols - a->dscroll) * CELL_H;
}
static int tile_at(struct app *a, double px, double py)
{
    if (py < grid_top()) return -1;
    for (int pos = 0; pos < a->nfilt; pos++) {
        int x, y; tile_rect(a, pos, &x, &y);
        if (px >= x && px < x + CELL_W && py >= y && py < y + CELL_H) return pos;
    }
    return -1;
}

static void draw_drawer(struct app *a, cairo_t *cr, int w, int h)
{
    const double t = ease(a->anim);
    const int pw = panel_w(a), x0 = panel_x(a);
    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(cr, 0, 0, 0, 0.32 * t);               /* the dimmed desktop */
    cairo_paint(cr);
    cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

    cairo_rectangle(cr, x0, 0, pw, h);
    cairo_set_source_rgba(cr, 0.07, 0.08, 0.10, 0.94);
    cairo_fill(cr);
    cairo_rectangle(cr, x0 + pw - 1, 0, 1, h);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.1);
    cairo_fill(cr);

    /* the search field */
    const double sx = x0 + PANEL_PAD, sy = PANEL_PAD, sw = pw - 2 * PANEL_PAD;
    hos_rr_path(cr, sx, sy, sw, SEARCH_H, 10);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.08);
    cairo_fill_preserve(cr);
    hos_set_rgba(cr, HOS_ACCENT2, a->searchlen ? 0.9 : 0.4);
    cairo_set_line_width(cr, 1.5);
    cairo_stroke(cr);
    /* a magnifier */
    cairo_new_sub_path(cr);
    cairo_arc(cr, sx + 20, sy + SEARCH_H / 2.0 - 2, 6, 0, 2 * M_PI);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.7);
    cairo_set_line_width(cr, 2);
    cairo_stroke(cr);
    cairo_move_to(cr, sx + 24.5, sy + SEARCH_H / 2.0 + 2.5);
    cairo_line_to(cr, sx + 29, sy + SEARCH_H / 2.0 + 7);
    cairo_stroke(cr);
    if (a->searchlen) {
        hos_text(cr, &a->font, 16, sx + 38, sy + 10, 0xf2f5faU, 1, a->search);
        const double cw = hos_text_width(cr, &a->font, 16, a->search);
        cairo_rectangle(cr, sx + 39 + cw, sy + 10, 1.5, 20);            /* caret */
        cairo_set_source_rgba(cr, 1, 1, 1, 0.8);
        cairo_fill(cr);
    } else {
        hos_text(cr, &a->font, 16, sx + 38, sy + 10, 0x8b94a3U, 1, "Search applications");
    }

    /* the grid */
    cairo_save(cr);
    cairo_rectangle(cr, x0, grid_top() - 6, pw, h - grid_top() + 6);
    cairo_clip(cr);
    if (a->nfilt == 0) {
        hos_text_center(cr, &a->font, 15, x0 + pw / 2.0, grid_top() + 30, 0x8b94a3U, 1,
                        a->napps ? "No application matches" : "No applications are installed");
    }
    for (int pos = 0; pos < a->nfilt; pos++) {
        int x, y; tile_rect(a, pos, &x, &y);
        if (y + CELL_H < grid_top() - 6 || y > h) continue;
        const struct appent *e = &a->apps[a->filt[pos]];
        if (pos == a->hover_tile || pos == a->sel) {
            hos_rr_path(cr, x + 4, y + 2, CELL_W - 8, CELL_H - 6, 12);
            cairo_set_source_rgba(cr, 1, 1, 1, pos == a->sel ? 0.14 : 0.08);
            cairo_fill(cr);
        }
        const double tx = x + (CELL_W - TILE) / 2.0, ty = y + 12;
        draw_app_icon(a, cr, e, e->exec, tx, ty, TILE);
        if (pinned_index(a, e->exec) >= 0) {                        /* pinned: a small dot */
            cairo_new_sub_path(cr);
            cairo_arc(cr, tx + TILE - 2, ty + 2, 4, 0, 2 * M_PI);
            hos_set_rgb(cr, HOS_ACCENT2);
            cairo_fill(cr);
        }
        char lab[128];
        hos_text_fit(cr, &a->font, 13, e->name, CELL_W - 10, lab, sizeof lab);
        hos_text_center(cr, &a->font, 13, x + CELL_W / 2.0, ty + TILE + 10, 0xe6ebf2U, 1, lab);
    }
    cairo_restore(cr);
    (void)w;
}

/* the tooltip beside the bar: the hovered program's name */
static void draw_tip(struct app *a, cairo_t *cr, int w, int h, const char *text)
{
    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(cr, 0, 0, 0, 0);
    cairo_paint(cr);
    cairo_set_operator(cr, CAIRO_OPERATOR_OVER);
    hos_rr_path(cr, 0.5, 0.5, w - 1, h - 1, 8);
    cairo_set_source_rgba(cr, 0.09, 0.1, 0.13, 0.95);
    cairo_fill_preserve(cr);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.15);
    cairo_set_line_width(cr, 1);
    cairo_stroke(cr);
    hos_text(cr, &a->font, 14, 12, (h - 18) / 2.0, 0xf2f5faU, 1, text);
}

/* Render a surface into its free buffer and commit it. */
static void surf_render(struct app *a, struct surf *s, void (*fn)(struct app *, cairo_t *, int, int, const void *), const void *arg)
{
    if (!s->configured || !s->b[0].px) return;
    int i = s->b[0].busy ? 1 : 0;
    if (s->b[i].busy) { s->dirty = 1; return; }
    s->dirty = 0;
    const int pw = s->w * a->scale, ph = s->h * a->scale;
    cairo_surface_t *cs = cairo_image_surface_create_for_data((unsigned char *)s->b[i].px, CAIRO_FORMAT_ARGB32, pw, ph, pw * 4);
    cairo_t *cr = cairo_create(cs);
    cairo_scale(cr, a->scale, a->scale);
    fn(a, cr, s->w, s->h, arg);
    cairo_destroy(cr);
    cairo_surface_flush(cs);
    cairo_surface_destroy(cs);
    if (a->offscreen) return;
    s->b[i].busy = 1;
    wl_surface_set_buffer_scale(s->s, a->scale);
    wl_surface_attach(s->s, s->b[i].wl, 0, 0);
    wl_surface_damage_buffer(s->s, 0, 0, pw, ph);
    wl_surface_commit(s->s);
}
static void fn_dock(struct app *a, cairo_t *cr, int w, int h, const void *arg) { (void)arg; draw_dock(a, cr, w, h); }
static void fn_drawer(struct app *a, cairo_t *cr, int w, int h, const void *arg) { (void)arg; draw_drawer(a, cr, w, h); }
static void fn_tip(struct app *a, cairo_t *cr, int w, int h, const void *arg) { draw_tip(a, cr, w, h, arg); }

static void redraw_dock(struct app *a) { surf_render(a, &a->dock, fn_dock, NULL); }
static void redraw_drawer(struct app *a)
{
    if (!a->open) return;
    surf_render(a, &a->drawer, fn_drawer, NULL);
    if (a->offscreen || !a->drawer.configured) return;
    /* input only where the drawer is: everything, once it is out (the dimmed part closes it) */
    struct wl_region *r = wl_compositor_create_region(a->compositor);
    if (a->anim >= 1) wl_region_add(r, 0, 0, a->drawer.w, a->drawer.h);
    else wl_region_add(r, 0, 0, panel_w(a) + panel_x(a), a->drawer.h);
    wl_surface_set_input_region(a->drawer.s, r);
    wl_region_destroy(r);
    wl_surface_commit(a->drawer.s);
}

/* ── layer surfaces ────────────────────────────────────────────────────────────────────────── */
static void ls_configure(void *d, struct zwlr_layer_surface_v1 *ls, uint32_t serial, uint32_t w, uint32_t h);
static void ls_closed(void *d, struct zwlr_layer_surface_v1 *ls);
static const struct zwlr_layer_surface_v1_listener ls_listener = { .configure = ls_configure, .closed = ls_closed };
static struct app *g_app;

static void ls_configure(void *d, struct zwlr_layer_surface_v1 *ls, uint32_t serial, uint32_t w, uint32_t h)
{
    struct surf *s = d;
    struct app *a = g_app;
    zwlr_layer_surface_v1_ack_configure(ls, serial);
    if ((int)w != s->w || (int)h != s->h || !s->b[0].px) {
        if (w == 0 || h == 0) return;
        if (surf_alloc(a, s, (int)w, (int)h) < 0) { log_line("DOCK: buffer allocation failed"); return; }
    }
    s->configured = 1;
    if (s == &a->dock) redraw_dock(a);
    else if (s == &a->drawer) redraw_drawer(a);
    else if (s == &a->tip) surf_render(a, s, fn_tip, a->tip_text);
}
static void ls_closed(void *d, struct zwlr_layer_surface_v1 *ls)
{
    (void)ls;
    struct surf *s = d;
    if (s == &g_app->dock) g_app->running = 0;
}

static void surf_destroy(struct surf *s)
{
    if (s->ls) zwlr_layer_surface_v1_destroy(s->ls);
    if (s->s) wl_surface_destroy(s->s);
    surf_free_buffers(s);
    memset(s, 0, sizeof *s);
}

static void dock_create(struct app *a)
{
    a->dock.s = wl_compositor_create_surface(a->compositor);
    a->dock.ls = zwlr_layer_shell_v1_get_layer_surface(a->layer_shell, a->dock.s, NULL, ZWLR_LAYER_SHELL_V1_LAYER_TOP, "dock");
    zwlr_layer_surface_v1_add_listener(a->dock.ls, &ls_listener, &a->dock);
    zwlr_layer_surface_v1_set_anchor(a->dock.ls, ZWLR_LAYER_SURFACE_V1_ANCHOR_LEFT | ZWLR_LAYER_SURFACE_V1_ANCHOR_TOP |
                                                 ZWLR_LAYER_SURFACE_V1_ANCHOR_BOTTOM);
    zwlr_layer_surface_v1_set_size(a->dock.ls, (uint32_t)a->dock_w, 0);
    zwlr_layer_surface_v1_set_exclusive_zone(a->dock.ls, a->dock_w);   /* windows tile beside it */
    zwlr_layer_surface_v1_set_keyboard_interactivity(a->dock.ls, 0);
    wl_surface_commit(a->dock.s);
}

static void drawer_open(struct app *a)
{
    if (a->open && !a->closing) return;
    if (!a->open) {
        refresh_world(a);
        a->searchlen = 0; a->search[0] = 0; a->sel = -1; a->hover_tile = -1;
        recompute_filter(a);
        a->anim = 0;
    }
    a->open = 1; a->closing = 0; a->anim_t0 = now_ms() - (long long)(a->anim * ANIM_MS);
    if (a->offscreen) { a->anim = 1; return; }
    if (!a->drawer.s) {
        a->drawer.s = wl_compositor_create_surface(a->compositor);
        a->drawer.ls = zwlr_layer_shell_v1_get_layer_surface(a->layer_shell, a->drawer.s, NULL, ZWLR_LAYER_SHELL_V1_LAYER_OVERLAY, "launcher");
        zwlr_layer_surface_v1_add_listener(a->drawer.ls, &ls_listener, &a->drawer);
        zwlr_layer_surface_v1_set_anchor(a->drawer.ls, ZWLR_LAYER_SURFACE_V1_ANCHOR_LEFT | ZWLR_LAYER_SURFACE_V1_ANCHOR_RIGHT |
                                                       ZWLR_LAYER_SURFACE_V1_ANCHOR_TOP | ZWLR_LAYER_SURFACE_V1_ANCHOR_BOTTOM);
        zwlr_layer_surface_v1_set_size(a->drawer.ls, 0, 0);
        zwlr_layer_surface_v1_set_exclusive_zone(a->drawer.ls, 0);    /* beside the bar, below the top bar */
        zwlr_layer_surface_v1_set_keyboard_interactivity(a->drawer.ls, 1);   /* the search field types */
        wl_surface_commit(a->drawer.s);
    }
    redraw_dock(a);
}
static void drawer_close(struct app *a)
{
    if (!a->open || a->closing) return;
    a->closing = 1;
    a->anim_t0 = now_ms() - (long long)((1 - a->anim) * ANIM_MS);
    redraw_dock(a);
}
static void drawer_finish_close(struct app *a)
{
    a->open = 0; a->closing = 0; a->anim = 0;
    surf_destroy(&a->drawer);
    redraw_dock(a);
}
static void drawer_toggle(struct app *a) { if (a->open && !a->closing) drawer_close(a); else drawer_open(a); }

static void tip_show(struct app *a, int idx)
{
    if (a->tip.s) surf_destroy(&a->tip);
    if (idx < 0 || a->offscreen) return;
    const char *text = "Applications";
    if (idx < a->npins) { const struct appent *e = app_for_exec(a, a->pins[idx]); text = e ? e->name : a->pins[idx]; }
    char *tipbuf = a->tip_text;
    snprintf(tipbuf, sizeof a->tip_text, "%s", text);
    /* measure with a scratch surface */
    cairo_surface_t *cs = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 4, 4);
    cairo_t *cr = cairo_create(cs);
    const int tw = (int)hos_text_width(cr, &a->font, 14, tipbuf) + 24;
    cairo_destroy(cr); cairo_surface_destroy(cs);
    const int y = idx < a->npins ? pin_y(a, idx) : a->dock.h - BUTTON_H + (BUTTON_H - ICON) / 2;
    a->tip.s = wl_compositor_create_surface(a->compositor);
    a->tip.ls = zwlr_layer_shell_v1_get_layer_surface(a->layer_shell, a->tip.s, NULL, ZWLR_LAYER_SHELL_V1_LAYER_OVERLAY, "dock-tip");
    zwlr_layer_surface_v1_add_listener(a->tip.ls, &ls_listener, &a->tip);
    zwlr_layer_surface_v1_set_anchor(a->tip.ls, ZWLR_LAYER_SURFACE_V1_ANCHOR_LEFT | ZWLR_LAYER_SURFACE_V1_ANCHOR_TOP);
    zwlr_layer_surface_v1_set_size(a->tip.ls, (uint32_t)tw, 32);
    zwlr_layer_surface_v1_set_margin(a->tip.ls, y + (ICON - 32) / 2, 0, 0, 8);
    zwlr_layer_surface_v1_set_keyboard_interactivity(a->tip.ls, 0);
    struct wl_region *r = wl_compositor_create_region(a->compositor);   /* never takes the pointer */
    wl_surface_set_input_region(a->tip.s, r);
    wl_region_destroy(r);
    wl_surface_commit(a->tip.s);                                        /* drawn on its configure */
}

/* ── input ─────────────────────────────────────────────────────────────────────────────────── */
static int dock_hit(struct app *a, double x, double y)
{
    (void)x;
    const int area = pins_area_h(a, a->dock.h);
    if (y >= area) return a->npins;                       /* the launcher button */
    for (int i = 0; i < a->npins; i++) { const int py = pin_y(a, i); if (y >= py - GAP / 2 && y < py + ICON + GAP / 2) return i; }
    return -1;
}

static void p_enter(void *d, struct wl_pointer *p, uint32_t se, struct wl_surface *s, wl_fixed_t x, wl_fixed_t y)
{ (void)p; (void)se; struct app *a = d; a->ptr_surface = s; a->px = wl_fixed_to_double(x); a->py = wl_fixed_to_double(y); }
static void p_leave(void *d, struct wl_pointer *p, uint32_t se, struct wl_surface *s)
{
    (void)p; (void)se; struct app *a = d;
    if (s == a->dock.s && a->hover_pin != -1) { a->hover_pin = -1; tip_show(a, -1); redraw_dock(a); }
    if (s == a->drawer.s && a->hover_tile != -1) { a->hover_tile = -1; redraw_drawer(a); }
    a->ptr_surface = NULL;
}
static void p_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y)
{
    (void)p; (void)t; struct app *a = d;
    a->px = wl_fixed_to_double(x); a->py = wl_fixed_to_double(y);
    if (a->ptr_surface == a->dock.s) {
        const int h = dock_hit(a, a->px, a->py);
        if (h != a->hover_pin) { a->hover_pin = h; tip_show(a, h); redraw_dock(a); }
    } else if (a->ptr_surface == a->drawer.s) {
        const int h = tile_at(a, a->px, a->py);
        if (h != a->hover_tile) { a->hover_tile = h; redraw_drawer(a); }
    }
}
static void toggle_pin(struct app *a, const char *exec)
{
    const int i = pinned_index(a, exec);
    if (i >= 0) { free(a->pins[i]); memmove(&a->pins[i], &a->pins[i + 1], (size_t)(a->npins - i - 1) * sizeof *a->pins); a->npins--; }
    else pins_add(a, exec);
    conf_save_pins(a);
    const int ms = max_scroll(a, a->dock.h); if (a->scroll > ms) a->scroll = ms;
    redraw_dock(a); redraw_drawer(a);
}
static void p_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state)
{
    (void)p; (void)se; (void)t; struct app *a = d;
    if (state != WL_POINTER_BUTTON_STATE_PRESSED) return;
    const int left = button == 0x110, right = button == 0x111;
    if (a->ptr_surface == a->dock.s) {
        const int h = dock_hit(a, a->px, a->py);
        if (h == a->npins && left) drawer_toggle(a);
        else if (h >= 0 && h < a->npins) {
            if (left) { char ex[256]; snprintf(ex, sizeof ex, "%s", a->pins[h]); if (a->open) drawer_close(a); launch(a, ex); }
            else if (right) { char ex[256]; snprintf(ex, sizeof ex, "%s", a->pins[h]); a->hover_pin = -1; tip_show(a, -1); toggle_pin(a, ex); }
        }
    } else if (a->ptr_surface == a->drawer.s) {
        if (a->px >= panel_w(a) + panel_x(a)) { if (left) drawer_close(a); return; }   /* the dimmed desktop */
        const int pos = tile_at(a, a->px, a->py);
        if (pos < 0) return;
        const struct appent *e = &a->apps[a->filt[pos]];
        char ex[256]; snprintf(ex, sizeof ex, "%s", e->exec);
        if (left) { drawer_close(a); launch(a, ex); }
        else if (right) toggle_pin(a, ex);
    }
}
static void p_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t axis, wl_fixed_t v)
{
    (void)p; (void)t; struct app *a = d;
    if (axis != WL_POINTER_AXIS_VERTICAL_SCROLL) return;
    const double dv = wl_fixed_to_double(v);
    if (a->ptr_surface == a->dock.s) {
        const int ms = max_scroll(a, a->dock.h);
        a->scroll += (int)(dv * 2);
        if (a->scroll < 0) a->scroll = 0;
        if (a->scroll > ms) a->scroll = ms;
        tip_show(a, -1); a->hover_pin = dock_hit(a, a->px, a->py);
        redraw_dock(a);
    } else if (a->ptr_surface == a->drawer.s) {
        const int cols = grid_cols(a), rows = (a->nfilt + cols - 1) / cols;
        const int vis = (a->drawer.h - grid_top()) / CELL_H;
        int maxr = rows - vis; if (maxr < 0) maxr = 0;
        a->dscroll += dv > 0 ? 1 : -1;
        if (a->dscroll < 0) a->dscroll = 0;
        if (a->dscroll > maxr) a->dscroll = maxr;
        a->hover_tile = tile_at(a, a->px, a->py);
        redraw_drawer(a);
    }
}
static void p_frame(void *d, struct wl_pointer *p) { (void)d; (void)p; }
static void p_axis_source(void *d, struct wl_pointer *p, uint32_t s) { (void)d; (void)p; (void)s; }
static void p_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax) { (void)d; (void)p; (void)t; (void)ax; }
static void p_axis_discrete(void *d, struct wl_pointer *p, uint32_t ax, int32_t v) { (void)d; (void)p; (void)ax; (void)v; }
static const struct wl_pointer_listener pointer_listener = {
    .enter = p_enter, .leave = p_leave, .motion = p_motion, .button = p_button, .axis = p_axis,
    .frame = p_frame, .axis_source = p_axis_source, .axis_stop = p_axis_stop, .axis_discrete = p_axis_discrete };

/* raw evdev codes -> characters (the search field); no keymap needed */
static const char EV_CH[128] = {
    [2]='1',[3]='2',[4]='3',[5]='4',[6]='5',[7]='6',[8]='7',[9]='8',[10]='9',[11]='0',[12]='-',[13]='=',
    [16]='q',[17]='w',[18]='e',[19]='r',[20]='t',[21]='y',[22]='u',[23]='i',[24]='o',[25]='p',
    [30]='a',[31]='s',[32]='d',[33]='f',[34]='g',[35]='h',[36]='j',[37]='k',[38]='l',
    [44]='z',[45]='x',[46]='c',[47]='v',[48]='b',[49]='n',[50]='m',[51]=',',[52]='.',[53]='/',[57]=' ' };
static const char EV_SH[128] = {
    [2]='!',[3]='@',[4]='#',[5]='$',[6]='%',[7]='^',[8]='&',[9]='*',[10]='(',[11]=')',[12]='_',[13]='+',
    [16]='Q',[17]='W',[18]='E',[19]='R',[20]='T',[21]='Y',[22]='U',[23]='I',[24]='O',[25]='P',
    [30]='A',[31]='S',[32]='D',[33]='F',[34]='G',[35]='H',[36]='J',[37]='K',[38]='L',
    [44]='Z',[45]='X',[46]='C',[47]='V',[48]='B',[49]='N',[50]='M',[51]='<',[52]='>',[53]='?',[57]=' ' };

static void k_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t sz) { (void)d; (void)k; (void)f; (void)sz; if (fd >= 0) close(fd); }
static void k_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf, struct wl_array *ks) { (void)d; (void)k; (void)s; (void)sf; (void)ks; }
static void k_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf) { (void)d; (void)k; (void)s; (void)sf; }
static void k_key(void *d, struct wl_keyboard *k, uint32_t se, uint32_t t, uint32_t key, uint32_t state)
{
    (void)k; (void)se; (void)t; struct app *a = d;
    if (key == 42 || key == 54) { a->shift = state == 1; return; }
    if (state != 1 || !a->open || a->closing) return;
    const int cols = grid_cols(a);
    switch (key) {
    case 1: drawer_close(a); return;                                      /* Esc */
    case 28: case 96:                                                     /* Enter */
        if (a->nfilt) { const int s = a->sel >= 0 ? a->sel : 0; char ex[256]; snprintf(ex, sizeof ex, "%s", a->apps[a->filt[s]].exec); drawer_close(a); launch(a, ex); }
        return;
    case 14: if (a->searchlen) { a->search[--a->searchlen] = 0; recompute_filter(a); redraw_drawer(a); } return;
    case 105: if (a->sel > 0) a->sel--; redraw_drawer(a); return;         /* arrows move the selection */
    case 106: if (a->sel + 1 < a->nfilt) a->sel++; redraw_drawer(a); return;
    case 103: if (a->sel >= cols) a->sel -= cols; redraw_drawer(a); return;
    case 108: if (a->sel < 0 && a->nfilt) a->sel = 0; else if (a->sel + cols < a->nfilt) a->sel += cols; redraw_drawer(a); return;
    default: break;
    }
    if (key < 128) {
        const char c = a->shift ? EV_SH[key] : EV_CH[key];
        if (c && a->searchlen < (int)sizeof a->search - 1) {
            a->search[a->searchlen++] = c; a->search[a->searchlen] = 0;
            recompute_filter(a); redraw_drawer(a);
        }
    }
}
static void k_mods(void *d, struct wl_keyboard *k, uint32_t s, uint32_t dep, uint32_t lat, uint32_t lo, uint32_t g)
{ (void)d; (void)k; (void)s; (void)dep; (void)lat; (void)lo; (void)g; }
static void k_repeat(void *d, struct wl_keyboard *k, int32_t r, int32_t dl) { (void)d; (void)k; (void)r; (void)dl; }
static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = k_keymap, .enter = k_enter, .leave = k_leave, .key = k_key, .modifiers = k_mods, .repeat_info = k_repeat };

static void seat_caps(void *d, struct wl_seat *seat, uint32_t caps)
{
    struct app *a = d;
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !a->pointer) { a->pointer = wl_seat_get_pointer(seat); wl_pointer_add_listener(a->pointer, &pointer_listener, a); }
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !a->keyboard) { a->keyboard = wl_seat_get_keyboard(seat); wl_keyboard_add_listener(a->keyboard, &keyboard_listener, a); }
}
static void seat_name(void *d, struct wl_seat *s, const char *n) { (void)d; (void)s; (void)n; }
static const struct wl_seat_listener seat_listener = { .capabilities = seat_caps, .name = seat_name };

static void reg_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver)
{
    struct app *a = d;
    if (!strcmp(iface, wl_compositor_interface.name)) a->compositor = wl_registry_bind(r, name, &wl_compositor_interface, ver < 4 ? ver : 4);
    else if (!strcmp(iface, wl_shm_interface.name)) a->shm = wl_registry_bind(r, name, &wl_shm_interface, 1);
    else if (!strcmp(iface, wl_seat_interface.name)) { a->seat = wl_registry_bind(r, name, &wl_seat_interface, ver < 5 ? ver : 5); wl_seat_add_listener(a->seat, &seat_listener, a); }
    else if (!strcmp(iface, zwlr_layer_shell_v1_interface.name)) a->layer_shell = wl_registry_bind(r, name, &zwlr_layer_shell_v1_interface, ver < 4 ? ver : 4);
}
static void reg_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener registry_listener = { .global = reg_global, .global_remove = reg_remove };

/* SIGUSR1 toggles the drawer.  A keybinding runs `wl-dock --toggle`, which sends it: that runs
 * unconfined like the dock, where a confined `pkill` could not see (let alone signal) it. */
static void pid_path(char *out, size_t cap)
{
    const char *rt = getenv("XDG_RUNTIME_DIR");
    snprintf(out, cap, "%s/wl-dock.pid", rt && *rt ? rt : "/run/user/1000");
}
static int toggle_running_dock(void)
{
    char p[512]; pid_path(p, sizeof p);
    FILE *f = fopen(p, "r");
    if (!f) return 1;
    long pid = 0;
    if (fscanf(f, "%ld", &pid) != 1) pid = 0;
    fclose(f);
    return (pid > 1 && kill((pid_t)pid, SIGUSR1) == 0) ? 0 : 1;
}
static volatile sig_atomic_t g_toggle = 0;
static void on_usr1(int s) { (void)s; g_toggle = 1; }

/* ── setup ─────────────────────────────────────────────────────────────────────────────────── */
static void load_fonts(struct app *a)
{
    const char *dir = getenv("WLDOCK_FONTDIR");
    char r1[512], b1[512];
    snprintf(r1, sizeof r1, "%s/NotoSans-Regular.ttf", dir ? dir : "/usr/share/fonts/noto");
    snprintf(b1, sizeof b1, "%s/NotoSans-Bold.ttf", dir ? dir : "/usr/share/fonts/noto");
    const char *reg[] = { r1, "/usr/share/fonts/noto/NotoSans-Regular.ttf", "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf", NULL };
    const char *bold[] = { b1, "/usr/share/fonts/noto/NotoSans-Bold.ttf", "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf", r1, NULL };
    if (hos_font_load_any(&a->font, reg) != 0) log_line("DOCK: no font -- labels will be missing");
    if (hos_font_load_any(&a->bold, bold) != 0) a->bold = a->font;
}

static void conf_path_init(struct app *a)
{
    const char *home = getenv("HOME");
    if (!home || !*home) home = "/home/user";
    snprintf(a->conf_path, sizeof a->conf_path, "%s/.config/anonymos/dock.conf", home);
}

static int render_png(struct app *a, const char *prefix)
{
    int W = 1280, H = 768;
    const char *sz = getenv("WLDOCK_SIZE");
    if (sz) sscanf(sz, "%dx%d", &W, &H);
    a->offscreen = 1;
    if (surf_alloc(a, &a->dock, a->dock_w, H) < 0) return 1;
    a->dock.configured = 1;
    a->hover_pin = 1;
    redraw_dock(a);
    char path[600];
    cairo_surface_t *cs = cairo_image_surface_create_for_data((unsigned char *)a->dock.b[0].px, CAIRO_FORMAT_ARGB32, a->dock.w, a->dock.h, a->dock.w * 4);
    snprintf(path, sizeof path, "%s-dock.png", prefix);
    cairo_surface_write_to_png(cs, path);
    cairo_surface_destroy(cs);
    drawer_open(a);
    if (getenv("WLDOCK_SEARCH")) { snprintf(a->search, sizeof a->search, "%s", getenv("WLDOCK_SEARCH")); a->searchlen = (int)strlen(a->search); recompute_filter(a); }
    if (surf_alloc(a, &a->drawer, W - a->dock_w, H) < 0) return 1;
    a->drawer.configured = 1;
    a->hover_tile = 2;
    redraw_drawer(a);
    cs = cairo_image_surface_create_for_data((unsigned char *)a->drawer.b[0].px, CAIRO_FORMAT_ARGB32, a->drawer.w, a->drawer.h, a->drawer.w * 4);
    snprintf(path, sizeof path, "%s-drawer.png", prefix);
    cairo_surface_write_to_png(cs, path);
    cairo_surface_destroy(cs);
    printf("DOCK: rendered %d pinned, %d applications, %d domains\n", a->npins, a->napps, a->ndoms);
    return 0;
}

int main(int argc, char **argv)
{
    static struct app A;
    struct app *a = &A;
    g_app = a;
    a->running = 1; a->hover_pin = -1; a->hover_tile = -1; a->sel = -1;
    const char *sc = getenv("HOS_DISPLAY_SCALE");
    a->scale = (sc && atoi(sc) == 2) ? 2 : 1;
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, on_usr1);
    if (argc > 1 && !strcmp(argv[1], "--toggle")) return toggle_running_dock();
    if (argc > 2 && !strcmp(argv[1], "--render-png") && getenv("WLDOCK_ROOT")) hos_root = getenv("WLDOCK_ROOT");
    load_fonts(a);
    conf_path_init(a);
    conf_load(a);
    refresh_world(a);
    recompute_filter(a);

    if (argc > 2 && !strcmp(argv[1], "--render-png")) return render_png(a, argv[2]);

    log_line("DOCK: starting the launcher (wlr-layer-shell)");
    a->display = wl_display_connect(NULL);
    if (!a->display) { log_line("DOCK: no wayland display"); return 1; }
    struct wl_registry *reg = wl_display_get_registry(a->display);
    wl_registry_add_listener(reg, &registry_listener, a);
    wl_display_roundtrip(a->display);
    if (!a->compositor || !a->shm || !a->layer_shell) { log_line("DOCK: missing globals (need wlr-layer-shell)"); return 1; }
    dock_create(a);
    wl_display_flush(a->display);
    { char p[512]; pid_path(p, sizeof p); FILE *f = fopen(p, "w"); if (f) { fprintf(f, "%ld\n", (long)getpid()); fclose(f); } }

    const int wlfd = wl_display_get_fd(a->display);
    long long next_check = now_ms() + 2000;
    while (a->running) {
        while (wl_display_prepare_read(a->display) != 0) wl_display_dispatch_pending(a->display);
        wl_display_flush(a->display);
        const int animating = a->open && (a->closing || a->anim < 1);
        long long now = now_ms();
        int timeout = animating ? 16 : (int)(next_check > now ? next_check - now : 0);
        struct pollfd pfd = { .fd = wlfd, .events = POLLIN };
        const int pr = poll(&pfd, 1, timeout);
        if (pr > 0 && (pfd.revents & POLLIN)) { wl_display_read_events(a->display); wl_display_dispatch_pending(a->display); }
        else { wl_display_cancel_read(a->display); if (pr < 0 && errno != EINTR) break; }

        if (g_toggle) { g_toggle = 0; drawer_toggle(a); }
        now = now_ms();
        if (a->open) {                                             /* the slide */
            const double t = (double)(now - a->anim_t0) / ANIM_MS;
            const double v = a->closing ? 1 - t : t;
            a->anim = v < 0 ? 0 : v > 1 ? 1 : v;
            if (a->closing && a->anim <= 0) drawer_finish_close(a);
            else if (a->drawer.dirty || animating) redraw_drawer(a);
        }
        if (a->dock.dirty) redraw_dock(a);
        if (now >= next_check) {                                   /* config edits, new domains/apps */
            next_check = now + 2000;
            struct stat st;
            int changed = 0;
            if (stat(a->conf_path, &st) == 0 && st.st_mtime != a->conf_mtime) {
                const int oldw = a->dock_w;
                conf_load(a); changed = 1;
                if (oldw != a->dock_w) {
                    zwlr_layer_surface_v1_set_size(a->dock.ls, (uint32_t)a->dock_w, 0);
                    zwlr_layer_surface_v1_set_exclusive_zone(a->dock.ls, a->dock_w);
                    wl_surface_commit(a->dock.s);
                }
            }
            if (!a->open && now - a->refreshed_ms > 5000) { refresh_world(a); changed = 1; }
            if (changed) redraw_dock(a);
        }
    }
    return 0;
}
