/*
 * wl-welcome.c -- the overlay an installed system shows on its first boot: every keyboard shortcut and
 * what it does, and how to make the system your own through its configuration files.
 *
 * A full-screen OVERLAY layer surface (wlr-layer-shell): the desktop dimmed, a card in the middle.
 * The shortcuts are the ones the compositor has actually bound -- asked of Hyprland (`j/binds`), so
 * the list follows the user's own keybindings file -- minus the ones that cannot do anything here
 * (a program that is not installed, the dots-hyprland shell's `global` hooks).  "Get started",
 * Enter, Esc or a click outside the card closes it; it then writes ~/.config/anonymos/welcome-done
 * and does not come back by itself.  SUPER+F1 (or `wl-welcome --show`) brings it back any time.
 *
 * Self-test: `wl-welcome --render-png FILE` draws it without a compositor (size from WLDOCK_SIZE=WxH,
 * fonts from WLDOCK_FONTDIR, bindings from WLWELCOME_BINDS=<a j/binds JSON file>).
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include "wlr-layer-shell-unstable-v1-client-protocol.h"
#include "hos-shell-ui.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#define HYPR_DIR "/run/user/1000/hypr"

struct shortcut { char keys[64]; char what[128]; char group[40]; };
struct cfgline { const char *path, *what; };

/* How the system is configured: what a user edits, and what each file decides. */
static const struct cfgline CONFIG[] = {
    { "~/.config/hypr/custom/keybinds.lua",  "Keyboard shortcuts (SUPER + CTRL + ALT + / opens this file)" },
    { "~/.config/hypr/custom/general.lua",   "Windows: gaps, borders, rounding, animations, how they tile" },
    { "~/.config/hypr/custom/rules.lua",     "Window rules: which programs float, size and where they open" },
    { "~/.config/hypr/custom/execs.lua",     "Programs the desktop starts when you log in" },
    { "~/.config/anonymos/dock.conf",        "The launcher bar: pinned applications, its button's picture, its width" },
    { "~/.config/anonymos/domains.conf",     "Each domain's badge tag, the letters on its icons (Personal abbr=PER)" },
    { "~/.dashrc",                           "Your dash functions and object extensions (one per domain, in its home)" },
    { "/desktop.conf",                       "What starts with the desktop, and which folders survive a reboot" },
    { "/display.conf",                       "Screen resolution and scale" },
};
enum { N_CONFIG = (int)(sizeof CONFIG / sizeof CONFIG[0]) };

struct app {
    struct wl_display *display;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_seat *seat;
    struct wl_pointer *pointer;
    struct wl_keyboard *keyboard;
    struct zwlr_layer_shell_v1 *layer_shell;
    struct wl_surface *surface;
    struct zwlr_layer_surface_v1 *ls;
    struct { struct wl_buffer *wl; uint32_t *px; int busy; } b[2];
    void *map; size_t mapsz;
    int w, h, scale, configured, dirty, running, offscreen;
    double px, py;
    int hover_btn;
    int scroll;                     /* shortcut rows scrolled */
    struct shortcut *sc; int nsc;
    struct hos_font font, bold;
};

static void log_line(const char *s) { fputs(s, stdout); fputc('\n', stdout); fflush(stdout); }

/* ── the shortcuts, from the compositor ────────────────────────────────────────────────────── */
#define hypr_request hos_hypr_request

static int json_int(const char *p, const char *end, const char *key)
{
    char k[48]; snprintf(k, sizeof k, "\"%s\"", key);
    const char *q = strstr(p, k);
    if (!q || q >= end) return 0;
    q += strlen(k);
    while (*q == ' ' || *q == ':') q++;
    return atoi(q);
}
static int json_bool(const char *p, const char *end, const char *key)
{
    char k[48]; snprintf(k, sizeof k, "\"%s\"", key);
    const char *q = strstr(p, k);
    if (!q || q >= end) return 0;
    q += strlen(k);
    while (*q == ' ' || *q == ':') q++;
    return !strncmp(q, "true", 4);
}

/* A key's name as a person reads it. */
static void key_name(const char *k, char *out, size_t cap)
{
    static const struct { const char *from, *to; } map[] = {
        { "Return", "Enter" }, { "return", "Enter" }, { "SPACE", "Space" }, { "space", "Space" },
        { "slash", "/" }, { "Slash", "/" }, { "period", "." }, { "Period", "." }, { "comma", "," },
        { "backslash", "\\" }, { "Backslash", "\\" }, { "minus", "-" }, { "equal", "=" },
        { "Tab", "Tab" }, { "Escape", "Esc" }, { "Print", "PrtSc" },
        { "mouse:272", "Left drag" }, { "mouse:273", "Right drag" },
        { "mouse_down", "Wheel down" }, { "mouse_up", "Wheel up" },
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++) if (!strcmp(k, map[i].from)) { snprintf(out, cap, "%s", map[i].to); return; }
    if (strlen(k) == 1) { snprintf(out, cap, "%c", toupper((unsigned char)k[0])); return; }
    snprintf(out, cap, "%s", k);
}
static void combo(int mods, const char *key, char *out, size_t cap)
{
    char kn[40]; key_name(key, kn, sizeof kn);
    snprintf(out, cap, "%s%s%s%s%s",
             (mods & 64) ? "SUPER + " : "", (mods & 4) ? "CTRL + " : "", (mods & 8) ? "ALT + " : "",
             (mods & 1) ? "SHIFT + " : "", kn);
}
/* Does an exec binding's program exist here? */
static int exec_present(const char *arg)
{
    char first[256]; size_t i = 0;
    const char *p = arg;
    while (*p == ' ') p++;
    while (p[i] && p[i] != ' ' && i < sizeof first - 1) { first[i] = p[i]; i++; }
    first[i] = 0;
    if (!first[0]) return 0;
    if (first[0] == '/') return access(first, X_OK) == 0;
    char full[400];
    const char *dirs[] = { "/bin", "/usr/bin", "/sbin", "/usr/sbin", NULL };
    for (int k = 0; dirs[k]; k++) { snprintf(full, sizeof full, "%s/%s", dirs[k], first); if (access(full, X_OK) == 0) return 1; }
    return 0;
}

/* The keybinding files, whole: a Lua binding reaches the IPC as dispatcher "__lua", so what it does
 * -- run a program, poke the dots-hyprland shell -- is read off its line in the source instead. */
static char *g_lua_src;
static void load_lua_sources(void)
{
    const char *home = getenv("HOME");
    const char *files[] = { "/.config/hypr/custom/keybinds.lua", "/.config/hypr/hyprland/keybinds.lua" };
    size_t n = 0;
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        char p[512]; snprintf(p, sizeof p, "%s%s", home && *home ? home : "/home/user", files[i]);
        char *t = hos_read_file(p);
        if (!t) continue;
        size_t tl = strlen(t);
        char *nb = realloc(g_lua_src, n + tl + 2);
        if (nb) { g_lua_src = nb; memcpy(g_lua_src + n, t, tl); n += tl; g_lua_src[n++] = '\n'; g_lua_src[n] = 0; }
        free(t);
    }
}
/* Can the binding described `desc` do anything on this system?  Not when its source calls the absent
 * shell (hl.dsp.global), or runs a program that is not installed (or named by a variable, which is
 * the dots-hyprland config's terminal/browser choices -- not this image's). */
static int lua_bind_works(const char *desc)
{
    if (!g_lua_src) return 1;
    char q[200]; snprintf(q, sizeof q, "\"%s\"", desc);
    const char *d = strstr(g_lua_src, q);
    if (!d) return 1;                                      /* built at run time: a window/workspace loop */
    const char *b = d;                                     /* back to the hl.bind( that owns it */
    for (int k = 0; b > g_lua_src && k < 600; k++, b--) if (!strncmp(b, "hl.bind(", 8)) break;
    char stmt[700]; size_t n = (size_t)(d - b) < sizeof stmt - 1 ? (size_t)(d - b) : sizeof stmt - 1;
    memcpy(stmt, b, n); stmt[n] = 0;
    if (strstr(stmt, "hl.dsp.global(")) return 0;
    const char *ex = strstr(stmt, "exec_cmd(");
    if (ex) {
        ex += 9;
        while (*ex == ' ') ex++;
        if (*ex != '"') return 0;
        /* every command of the line must exist: "killall qs; qs -c ..." needs qs too */
        char cmd[400]; size_t i = 0; ex++;
        while (*ex && *ex != '"' && i < sizeof cmd - 1) cmd[i++] = *ex++;
        cmd[i] = 0;
        for (char *seg = cmd; *seg; ) {
            while (*seg == ' ' || *seg == ';' || *seg == '&' || *seg == '|') seg++;
            if (!*seg) break;
            if (!exec_present(seg)) return 0;
            while (*seg && *seg != ';' && *seg != '&' && *seg != '|') seg++;
        }
        return 1;
    }
    return 1;
}

static void sc_add(struct app *a, const char *keys, const char *what, const char *group)
{
    for (int i = 0; i < a->nsc; i++) if (!strcmp(a->sc[i].what, what)) return;   /* one row per action */
    struct shortcut *nv = realloc(a->sc, (size_t)(a->nsc + 1) * sizeof *nv);
    if (!nv) return;
    a->sc = nv;
    struct shortcut *s = &a->sc[a->nsc++];
    snprintf(s->keys, sizeof s->keys, "%s", keys);
    snprintf(s->what, sizeof s->what, "%s", what);
    snprintf(s->group, sizeof s->group, "%s", group);
}

/* "Workspace: Focus 3" -> group "Workspace", action "Focus 3". */
static void split_desc(const char *desc, char *group, size_t gc, char *what, size_t wc)
{
    const char *c = strstr(desc, ": ");
    if (c && (size_t)(c - desc) < gc) { memcpy(group, desc, (size_t)(c - desc)); group[c - desc] = 0; snprintf(what, wc, "%s", c + 2); }
    else { snprintf(group, gc, "Applications"); snprintf(what, wc, "%s", desc); }
    what[0] = (char)toupper((unsigned char)what[0]);
}

static void load_shortcuts(struct app *a)
{
    const char *f = getenv("WLWELCOME_BINDS");
    char *js = f ? hos_read_file(f) : hypr_request("j/binds");
    if (!js) { log_line("WELCOME: could not ask the compositor for its keybindings"); return; }
    /* Numbered actions ("Workspace: Focus 1" .. "10") collapse into one row: key range + "Focus 1-10". */
    struct { char group[40], base[96], mods[40]; int lo, hi; char klo[8], khi[8]; } runs[16];
    int nruns = 0;
    for (const char *p = js; (p = strchr(p, '{')); ) {
        const char *end = strchr(p, '}');
        if (!end) break;
        char desc[160] = "", key[40] = "", disp[40] = "", arg[256] = "", submap[40] = "";
        hos_json_str(p, end, "description", desc, sizeof desc);
        hos_json_str(p, end, "key", key, sizeof key);
        hos_json_str(p, end, "dispatcher", disp, sizeof disp);
        hos_json_str(p, end, "arg", arg, sizeof arg);
        hos_json_str(p, end, "submap", submap, sizeof submap);
        const int mods = json_int(p, end, "modmask");
        const int hasd = json_bool(p, end, "has_description") || desc[0];
        p = end + 1;
        if (!hasd || !desc[0] || submap[0] || !key[0]) continue;
        if (!strcmp(disp, "global")) continue;                              /* the absent quickshell */
        if (strstr(desc, "[hidden]")) continue;
        if (!strcmp(disp, "exec") && !exec_present(arg)) continue;          /* its program is not here */
        if (!strcmp(disp, "__lua") && !lua_bind_works(desc)) continue;      /* a Lua binding that cannot */
        char group[40], what[128];
        split_desc(desc, group, sizeof group, what, sizeof what);
        /* a numbered action? */
        size_t wl = strlen(what), d0 = wl;
        while (d0 > 0 && isdigit((unsigned char)what[d0 - 1])) d0--;
        if (d0 < wl && d0 > 0 && what[d0 - 1] == ' ' && strlen(key) <= 2) {
            char base[96]; snprintf(base, sizeof base, "%.*s", (int)(d0 - 1), what);
            char mtxt[40]; combo(mods, "", mtxt, sizeof mtxt);
            const int num = atoi(what + d0);
            int r = 0;
            for (; r < nruns; r++) if (!strcmp(runs[r].group, group) && !strcmp(runs[r].base, base) && !strcmp(runs[r].mods, mtxt)) break;
            if (r == nruns && nruns < 16) {
                snprintf(runs[r].group, sizeof runs[r].group, "%s", group);
                snprintf(runs[r].base, sizeof runs[r].base, "%s", base);
                snprintf(runs[r].mods, sizeof runs[r].mods, "%s", mtxt);
                runs[r].lo = runs[r].hi = num;
                snprintf(runs[r].klo, sizeof runs[r].klo, "%s", key); snprintf(runs[r].khi, sizeof runs[r].khi, "%s", key);
                nruns++;
            } else if (r < nruns) {
                if (num < runs[r].lo) { runs[r].lo = num; snprintf(runs[r].klo, sizeof runs[r].klo, "%s", key); }
                if (num > runs[r].hi) { runs[r].hi = num; snprintf(runs[r].khi, sizeof runs[r].khi, "%s", key); }
            }
            continue;
        }
        char keys[64]; combo(mods, key, keys, sizeof keys);
        sc_add(a, keys, what, group);
    }
    for (int r = 0; r < nruns; r++) {
        char keys[64], what[128];
        if (runs[r].lo == runs[r].hi) snprintf(keys, sizeof keys, "%s%s", runs[r].mods, runs[r].klo);
        else snprintf(keys, sizeof keys, "%s%s..%s", runs[r].mods, runs[r].klo, runs[r].khi);
        if (runs[r].lo == runs[r].hi) snprintf(what, sizeof what, "%s %d", runs[r].base, runs[r].lo);
        else snprintf(what, sizeof what, "%s %d-%d", runs[r].base, runs[r].lo, runs[r].hi);
        sc_add(a, keys, what, runs[r].group);
    }
    free(js);
    /* One heading per group: a stable sort by the order the groups were first seen in. */
    char order[32][40]; int ng = 0;
    for (int i = 0; i < a->nsc; i++)          /* the overlay plane leads: it is the desktop's own gesture */
        if (!strcmp(a->sc[i].group, "Overlay")) { snprintf(order[ng++], sizeof order[0], "Overlay"); break; }
    for (int i = 0; i < a->nsc; i++) {
        int k = 0; while (k < ng && strcmp(order[k], a->sc[i].group)) k++;
        if (k == ng && ng < 32) snprintf(order[ng++], sizeof order[0], "%s", a->sc[i].group);
    }
    struct shortcut *sorted = malloc((size_t)(a->nsc ? a->nsc : 1) * sizeof *sorted);
    if (sorted) {
        int n = 0;
        for (int k = 0; k < ng; k++) for (int i = 0; i < a->nsc; i++) if (!strcmp(a->sc[i].group, order[k])) sorted[n++] = a->sc[i];
        for (int i = 0; i < a->nsc; i++) { int k = 0; while (k < ng && strcmp(order[k], a->sc[i].group)) k++; if (k == ng) sorted[n++] = a->sc[i]; }
        free(a->sc); a->sc = sorted;
    }
    char m[80]; snprintf(m, sizeof m, "WELCOME: %d shortcuts", a->nsc); log_line(m);
}

/* ── drawing ───────────────────────────────────────────────────────────────────────────────── */
enum { CARD_MAX_W = 1120, CARD_MAX_H = 760, PAD = 32, ROW_H = 26, BTN_W = 150, BTN_H = 40 };

static void card_rect(struct app *a, double *x, double *y, double *w, double *h)
{
    *w = a->w - 80 < CARD_MAX_W ? a->w - 80 : CARD_MAX_W;
    *h = a->h - 60 < CARD_MAX_H ? a->h - 60 : CARD_MAX_H;
    *x = (a->w - *w) / 2; *y = (a->h - *h) / 2;
}
static void button_rect(struct app *a, double *x, double *y)
{
    double cx, cy, cw, ch; card_rect(a, &cx, &cy, &cw, &ch);
    *x = cx + cw - PAD - BTN_W; *y = cy + ch - PAD - BTN_H + 8;
}
static int list_rows_visible(struct app *a)
{
    double cx, cy, cw, ch; card_rect(a, &cx, &cy, &cw, &ch);
    return (int)((ch - 150 - 64) / ROW_H);
}

static void draw(struct app *a, cairo_t *cr)
{
    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(cr, 0, 0, 0, 0.55);
    cairo_paint(cr);
    cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

    double cx, cy, cw, ch; card_rect(a, &cx, &cy, &cw, &ch);
    hos_rr_path(cr, cx + 2, cy + 6, cw, ch, 18);                  /* shadow */
    cairo_set_source_rgba(cr, 0, 0, 0, 0.35);
    cairo_fill(cr);
    hos_rr_path(cr, cx, cy, cw, ch, 18);
    cairo_set_source_rgba(cr, 0.075, 0.085, 0.11, 0.98);
    cairo_fill_preserve(cr);
    cairo_set_source_rgba(cr, 1, 1, 1, 0.1);
    cairo_set_line_width(cr, 1);
    cairo_stroke(cr);

    hos_text(cr, &a->bold, 26, cx + PAD, cy + PAD - 4, 0xf4f6f9u, 1, "Welcome to anonymOS");
    hos_text(cr, &a->font, 14, cx + PAD, cy + PAD + 34, 0x9aa4b2u, 1,
             "Everything is keyboard-driven.  The bar on the left starts your applications: its bottom button lists them all.");
    hos_text(cr, &a->font, 14, cx + PAD, cy + PAD + 54, 0x9aa4b2u, 1,
             "Every icon wears the colour and tag of the domain it runs in.  SUPER + F1 shows this again.");

    const double top = cy + 120, colw = (cw - 3 * PAD) * 0.54, rx = cx + PAD + colw + PAD, rw = cw - 3 * PAD - colw;
    hos_text(cr, &a->bold, 16, cx + PAD, top, HOS_ACCENT2, 1, "Keyboard shortcuts");
    hos_text(cr, &a->bold, 16, rx, top, HOS_ACCENT2, 1, "Make it yours");

    /* the shortcuts: key pills + what they do, grouped */
    const int vis = list_rows_visible(a);
    double y = top + 32;
    int row = 0, shown = 0;
    char lastg[40] = "";
    cairo_save(cr);
    cairo_rectangle(cr, cx + PAD - 4, top + 28, colw + 8, vis * ROW_H + 4);
    cairo_clip(cr);
    for (int i = 0; i < a->nsc; i++) {
        const int newg = strcmp(lastg, a->sc[i].group) != 0;
        if (newg) {
            snprintf(lastg, sizeof lastg, "%s", a->sc[i].group);
            if (row >= a->scroll && shown < vis) {
                hos_text(cr, &a->bold, 12, cx + PAD, y + 6, 0x6f7a8au, 1, lastg);
                y += ROW_H; shown++;
            }
            row++;
        }
        if (row++ < a->scroll || shown >= vis) continue;
        const double kw = hos_text_width(cr, &a->font, 12.5, a->sc[i].keys) + 14;
        hos_rr_path(cr, cx + PAD, y + 2, kw, ROW_H - 6, 6);
        cairo_set_source_rgba(cr, 1, 1, 1, 0.09);
        cairo_fill_preserve(cr);
        cairo_set_source_rgba(cr, 1, 1, 1, 0.16);
        cairo_stroke(cr);
        hos_text(cr, &a->font, 12.5, cx + PAD + 7, y + 4, 0xe9edf3u, 1, a->sc[i].keys);
        char fit[160];
        const double kx = cx + PAD + (kw > 210 ? kw + 10 : 220);
        hos_text_fit(cr, &a->font, 13.5, a->sc[i].what, cx + PAD + colw - kx, fit, sizeof fit);
        hos_text(cr, &a->font, 13.5, kx, y + 3, 0xc9d1dcu, 1, fit);
        y += ROW_H; shown++;
    }
    cairo_restore(cr);
    if (!a->nsc) hos_text(cr, &a->font, 13.5, cx + PAD, top + 36, 0x9aa4b2u, 1, "(the compositor did not list its keybindings)");
    const int total = row;
    if (total > vis) {
        char more[80];
        snprintf(more, sizeof more, "Scroll for more  (%d-%d of %d)", a->scroll + 1, a->scroll + vis < total ? a->scroll + vis : total, total);
        hos_text(cr, &a->font, 12, cx + PAD, top + 36 + vis * ROW_H, 0x6f7a8au, 1, more);
    }

    /* the configuration files */
    double ry = top + 34;
    for (int i = 0; i < N_CONFIG; i++) {
        hos_text(cr, &a->bold, 13, rx, ry, 0xe9edf3u, 1, CONFIG[i].path);
        char fit[200];
        hos_text_fit(cr, &a->font, 12.5, CONFIG[i].what, rw, fit, sizeof fit);
        hos_text(cr, &a->font, 12.5, rx, ry + 18, 0x9aa4b2u, 1, fit);
        ry += 44;
    }
    const char *note[] = {
        "Files under ~/.config and / belong to the System domain: open Domains, pick System",
        "and start its Terminal (or Text Editor) to change them.  Most apply as soon as you save;",
        "the domains themselves - colour, network, USB, applications - are set in Domains.",
    };
    for (int i = 0; i < 3; i++) hos_text(cr, &a->font, 12, rx, ry + 6 + i * 17, 0x7d8898u, 1, note[i]);

    double bx, by; button_rect(a, &bx, &by);
    hos_rr_path(cr, bx, by, BTN_W, BTN_H, 10);
    hos_set_rgb(cr, a->hover_btn ? HOS_ACCENT2 : HOS_ACCENT);
    cairo_fill(cr);
    hos_text_center(cr, &a->bold, 15, bx + BTN_W / 2.0, by + 10, 0xffffffu, 1, "Get started");
}

/* ── buffers / surface ─────────────────────────────────────────────────────────────────────── */
static void buf_release(void *d, struct wl_buffer *wl)
{
    struct app *a = d;
    for (int i = 0; i < 2; i++) if (a->b[i].wl == wl) a->b[i].busy = 0;
    if (a->dirty) { a->dirty = 0; }
}
static const struct wl_buffer_listener buf_listener = { .release = buf_release };

static int alloc_buffers(struct app *a, int w, int h)
{
    for (int i = 0; i < 2; i++) { if (a->b[i].wl) wl_buffer_destroy(a->b[i].wl); a->b[i].wl = NULL; a->b[i].px = NULL; a->b[i].busy = 0; }
    if (a->map) { if (a->mapsz) munmap(a->map, a->mapsz); else free(a->map); a->map = NULL; }
    const int pw = w * a->scale, ph = h * a->scale, stride = pw * 4;
    const size_t one = (size_t)stride * (size_t)ph;
    a->w = w; a->h = h;
    if (a->offscreen) {
        a->map = calloc(1, one); a->mapsz = 0;
        a->b[0].px = a->map;
        return a->map ? 0 : -1;
    }
    int fd = (int)syscall(SYS_memfd_create, "wl-welcome", MFD_CLOEXEC);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)(one * 2)) < 0) { close(fd); return -1; }
    void *m = mmap(NULL, one * 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) { close(fd); return -1; }
    struct wl_shm_pool *pool = wl_shm_create_pool(a->shm, fd, (int)(one * 2));
    for (int i = 0; i < 2; i++) {
        a->b[i].px = (uint32_t *)((char *)m + one * (size_t)i);
        a->b[i].wl = wl_shm_pool_create_buffer(pool, (int)(one * (size_t)i), pw, ph, stride, WL_SHM_FORMAT_ARGB8888);
        wl_buffer_add_listener(a->b[i].wl, &buf_listener, a);
    }
    wl_shm_pool_destroy(pool);
    close(fd);
    a->map = m; a->mapsz = one * 2;
    return 0;
}
static void redraw(struct app *a)
{
    if (!a->configured || !a->b[0].px) return;
    int i = a->b[0].busy ? 1 : 0;
    if (a->b[i].busy) { a->dirty = 1; return; }
    const int pw = a->w * a->scale, ph = a->h * a->scale;
    cairo_surface_t *cs = cairo_image_surface_create_for_data((unsigned char *)a->b[i].px, CAIRO_FORMAT_ARGB32, pw, ph, pw * 4);
    cairo_t *cr = cairo_create(cs);
    cairo_scale(cr, a->scale, a->scale);
    draw(a, cr);
    cairo_destroy(cr);
    cairo_surface_flush(cs);
    cairo_surface_destroy(cs);
    if (a->offscreen) return;
    a->b[i].busy = 1;
    wl_surface_set_buffer_scale(a->surface, a->scale);
    wl_surface_attach(a->surface, a->b[i].wl, 0, 0);
    wl_surface_damage_buffer(a->surface, 0, 0, pw, ph);
    wl_surface_commit(a->surface);
}

/* Closing: remember it was seen, so the next boot does not show it again. */
static void done(struct app *a)
{
    const char *home = getenv("HOME");
    char p[512];
    snprintf(p, sizeof p, "%s/.config", home ? home : "/home/user"); mkdir(p, 0700);
    snprintf(p, sizeof p, "%s/.config/anonymos", home ? home : "/home/user"); mkdir(p, 0700);
    snprintf(p, sizeof p, "%s/.config/anonymos/welcome-done", home ? home : "/home/user");
    FILE *f = fopen(p, "w");
    if (f) { fputs("The first-boot overlay was shown.  Delete this file to see it at the next boot.\n", f); fclose(f); }
    a->running = 0;
}

static void ls_configure(void *d, struct zwlr_layer_surface_v1 *ls, uint32_t serial, uint32_t w, uint32_t h)
{
    struct app *a = d;
    zwlr_layer_surface_v1_ack_configure(ls, serial);
    if (w && h && ((int)w != a->w || (int)h != a->h || !a->b[0].px)) {
        if (alloc_buffers(a, (int)w, (int)h) < 0) { log_line("WELCOME: buffer allocation failed"); a->running = 0; return; }
    }
    a->configured = 1;
    redraw(a);
}
static void ls_closed(void *d, struct zwlr_layer_surface_v1 *ls) { (void)ls; ((struct app *)d)->running = 0; }
static const struct zwlr_layer_surface_v1_listener ls_listener = { .configure = ls_configure, .closed = ls_closed };

/* ── input ─────────────────────────────────────────────────────────────────────────────────── */
static int in_button(struct app *a) { double bx, by; button_rect(a, &bx, &by); return a->px >= bx && a->px < bx + BTN_W && a->py >= by && a->py < by + BTN_H; }
static int in_card(struct app *a) { double x, y, w, h; card_rect(a, &x, &y, &w, &h); return a->px >= x && a->px < x + w && a->py >= y && a->py < y + h; }
static void p_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y) { (void)p; (void)s; (void)sf; struct app *a = d; a->px = wl_fixed_to_double(x); a->py = wl_fixed_to_double(y); }
static void p_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf) { (void)d; (void)p; (void)s; (void)sf; }
static void p_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y)
{
    (void)p; (void)t; struct app *a = d;
    a->px = wl_fixed_to_double(x); a->py = wl_fixed_to_double(y);
    const int h = in_button(a);
    if (h != a->hover_btn) { a->hover_btn = h; redraw(a); }
}
static void p_button(void *d, struct wl_pointer *p, uint32_t s, uint32_t t, uint32_t b, uint32_t st)
{
    (void)p; (void)s; (void)t; struct app *a = d;
    if (st != WL_POINTER_BUTTON_STATE_PRESSED || b != 0x110) return;
    if (in_button(a) || !in_card(a)) done(a);
}
static void p_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v)
{
    (void)p; (void)t; struct app *a = d;
    if (ax != WL_POINTER_AXIS_VERTICAL_SCROLL) return;
    a->scroll += wl_fixed_to_double(v) > 0 ? 3 : -3;
    int groups = 0; char lg[40] = "";
    for (int i = 0; i < a->nsc; i++) if (strcmp(lg, a->sc[i].group)) { groups++; snprintf(lg, sizeof lg, "%s", a->sc[i].group); }
    int maxs = a->nsc + groups - list_rows_visible(a);
    if (maxs < 0) maxs = 0;
    if (a->scroll > maxs) a->scroll = maxs;
    if (a->scroll < 0) a->scroll = 0;
    redraw(a);
}
static void p_frame(void *d, struct wl_pointer *p) { (void)d; (void)p; }
static void p_axs(void *d, struct wl_pointer *p, uint32_t s) { (void)d; (void)p; (void)s; }
static void p_axstop(void *d, struct wl_pointer *p, uint32_t t, uint32_t a) { (void)d; (void)p; (void)t; (void)a; }
static void p_axd(void *d, struct wl_pointer *p, uint32_t a, int32_t v) { (void)d; (void)p; (void)a; (void)v; }
static const struct wl_pointer_listener pointer_listener = {
    .enter = p_enter, .leave = p_leave, .motion = p_motion, .button = p_button, .axis = p_axis,
    .frame = p_frame, .axis_source = p_axs, .axis_stop = p_axstop, .axis_discrete = p_axd };

static void k_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t s) { (void)d; (void)k; (void)f; (void)s; if (fd >= 0) close(fd); }
static void k_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf, struct wl_array *ks) { (void)d; (void)k; (void)s; (void)sf; (void)ks; }
static void k_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf) { (void)d; (void)k; (void)s; (void)sf; }
static void k_key(void *d, struct wl_keyboard *k, uint32_t s, uint32_t t, uint32_t key, uint32_t st)
{
    (void)k; (void)s; (void)t; struct app *a = d;
    if (st != 1) return;
    if (key == 1 || key == 28 || key == 57 || key == 96) done(a);          /* Esc, Enter, Space */
    else if (key == 108 || key == 109) { a->scroll += key == 109 ? list_rows_visible(a) : 1; p_axis(a, NULL, 0, WL_POINTER_AXIS_VERTICAL_SCROLL, 0); }
    else if (key == 103 || key == 104) { a->scroll -= key == 104 ? list_rows_visible(a) : 1; if (a->scroll < 0) a->scroll = 0; redraw(a); }
}
static void k_mods(void *d, struct wl_keyboard *k, uint32_t s, uint32_t a, uint32_t b, uint32_t c, uint32_t g) { (void)d; (void)k; (void)s; (void)a; (void)b; (void)c; (void)g; }
static void k_rep(void *d, struct wl_keyboard *k, int32_t r, int32_t dl) { (void)d; (void)k; (void)r; (void)dl; }
static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = k_keymap, .enter = k_enter, .leave = k_leave, .key = k_key, .modifiers = k_mods, .repeat_info = k_rep };

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

static void load_fonts(struct app *a)
{
    const char *dir = getenv("WLDOCK_FONTDIR");
    char r1[512], b1[512];
    snprintf(r1, sizeof r1, "%s/NotoSans-Regular.ttf", dir ? dir : "/usr/share/fonts/noto");
    snprintf(b1, sizeof b1, "%s/NotoSans-Bold.ttf", dir ? dir : "/usr/share/fonts/noto");
    const char *reg[] = { r1, "/usr/share/fonts/noto/NotoSans-Regular.ttf", NULL };
    const char *bold[] = { b1, "/usr/share/fonts/noto/NotoSans-Bold.ttf", r1, NULL };
    if (hos_font_load_any(&a->font, reg) != 0) log_line("WELCOME: no font");
    if (hos_font_load_any(&a->bold, bold) != 0) a->bold = a->font;
}

int main(int argc, char **argv)
{
    static struct app A;
    struct app *a = &A;
    a->running = 1;
    const char *sc = getenv("HOS_DISPLAY_SCALE");
    a->scale = (sc && atoi(sc) == 2) ? 2 : 1;
    signal(SIGPIPE, SIG_IGN);
    const int render = argc > 2 && !strcmp(argv[1], "--render-png");
    const int force = render || (argc > 1 && !strcmp(argv[1], "--show"));
    if (!force) {                                   /* the first boot only */
        const char *home = getenv("HOME");
        char p[512]; snprintf(p, sizeof p, "%s/.config/anonymos/welcome-done", home ? home : "/home/user");
        if (access(p, F_OK) == 0) return 0;
    }
    load_fonts(a);
    load_lua_sources();
    load_shortcuts(a);

    if (render) {
        int W = 1280, H = 800;
        const char *sz = getenv("WLDOCK_SIZE");
        if (sz) sscanf(sz, "%dx%d", &W, &H);
        a->offscreen = 1;
        if (alloc_buffers(a, W, H) < 0) return 1;
        a->configured = 1;
        redraw(a);
        cairo_surface_t *cs = cairo_image_surface_create_for_data((unsigned char *)a->b[0].px, CAIRO_FORMAT_ARGB32, W, H, W * 4);
        cairo_surface_write_to_png(cs, argv[2]);
        cairo_surface_destroy(cs);
        return 0;
    }

    a->display = wl_display_connect(NULL);
    if (!a->display) { log_line("WELCOME: no wayland display"); return 1; }
    struct wl_registry *reg = wl_display_get_registry(a->display);
    wl_registry_add_listener(reg, &registry_listener, a);
    wl_display_roundtrip(a->display);
    if (!a->compositor || !a->shm || !a->layer_shell) { log_line("WELCOME: missing globals (need wlr-layer-shell)"); return 1; }
    a->surface = wl_compositor_create_surface(a->compositor);
    a->ls = zwlr_layer_shell_v1_get_layer_surface(a->layer_shell, a->surface, NULL, ZWLR_LAYER_SHELL_V1_LAYER_OVERLAY, "welcome");
    zwlr_layer_surface_v1_add_listener(a->ls, &ls_listener, a);
    zwlr_layer_surface_v1_set_anchor(a->ls, ZWLR_LAYER_SURFACE_V1_ANCHOR_LEFT | ZWLR_LAYER_SURFACE_V1_ANCHOR_RIGHT |
                                            ZWLR_LAYER_SURFACE_V1_ANCHOR_TOP | ZWLR_LAYER_SURFACE_V1_ANCHOR_BOTTOM);
    zwlr_layer_surface_v1_set_size(a->ls, 0, 0);
    zwlr_layer_surface_v1_set_exclusive_zone(a->ls, -1);           /* the whole screen */
    zwlr_layer_surface_v1_set_keyboard_interactivity(a->ls, 1);
    wl_surface_commit(a->surface);
    log_line("WELCOME: showing the first-boot overlay");
    while (a->running && wl_display_dispatch(a->display) != -1) {
        if (a->dirty && (!a->b[0].busy || !a->b[1].busy)) { a->dirty = 0; redraw(a); }
    }
    return 0;
}
