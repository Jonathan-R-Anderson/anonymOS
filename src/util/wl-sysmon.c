/*
 * wl-sysmon.c -- a native System Monitor Wayland client for EpinAnonymOS.
 *
 * Reuses the proven wl-wifi-menu machinery VERBATIM (registry/seat/xdg setup, the double-buffered
 * wl_shm pool, the complete v5 wl_pointer listener, the wl_keyboard listener, init_freetype(),
 * draw_text(), fill_rect(), and the poll() main loop).  It reads /proc directly:
 *   - /proc/stat  "cpu " line at two samples ~1s apart -> total CPU%
 *   - /proc/meminfo MemTotal + MemAvailable          -> memory used%
 *   - /proc/<pid>/comm + /proc/<pid>/statm           -> per-process name + RSS
 * and paints a CPU% bar, a Memory% bar, and a scrollable "PID  NAME  RSS" process list.
 * There is no cairo here -- everything is fill_rect() + draw_text().  Own CSD titlebar + close box.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
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

enum { WIN_W = 580, WIN_H = 540, TITLE_H = 26, MAX_PROCS = 512, ROW_H = 18 };

struct proc { int pid; char name[64]; long rss_kb; };

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
    unsigned char *shm_base; size_t shm_total;   // current mmap of the two-slice pool (for teardown on resize)
    int pending_w, pending_h;                     // compositor-requested size (from toplevel_configure)
    int configured, dirty;
    uint32_t *pixels;
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    int font_ready, running;
    double pointer_x, pointer_y;

    /* metrics */
    unsigned long long cpu_prev_total, cpu_prev_busy;
    int cpu_pct;
    long mem_total_kb, mem_avail_kb;
    int mem_pct;
    struct proc procs[MAX_PROCS];
    int n_procs;
    int scroll;          /* first visible row index in the process list */
    int view;            /* enum view -- which tab is showing (see VIEW_TAB) */
    int close_hover;
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

/* --- metrics: /proc parsing (tolerant of missing/partial files) --- */
static void sample_cpu(struct app *app){
    unsigned char *buf; size_t sz;
    if (load_file("/proc/stat", &buf, &sz) < 0) return;
    /* first line: "cpu  user nice system idle iowait irq softirq steal guest guest_nice" */
    char *nl = memchr(buf, '\n', sz); size_t linelen = nl ? (size_t)(nl-(char*)buf) : sz;
    char line[256]; if (linelen > sizeof(line)-1) linelen = sizeof(line)-1;
    memcpy(line, buf, linelen); line[linelen] = 0;
    free(buf);
    if (strncmp(line, "cpu ", 4) != 0){ return; }
    unsigned long long v[10]; int nf = 0;
    char *p = line + 4;
    while (*p && nf < 10){
        while (*p == ' ') p++;
        if (!*p) break;
        v[nf++] = strtoull(p, &p, 10);
    }
    if (nf < 4) return;
    unsigned long long total = 0; for (int i=0;i<nf;i++) total += v[i];
    unsigned long long idle = v[3] + (nf>4 ? v[4] : 0);   /* idle + iowait */
    unsigned long long busy = total - idle;
    unsigned long long dt = total - app->cpu_prev_total;
    unsigned long long db = busy  - app->cpu_prev_busy;
    if (app->cpu_prev_total != 0 && dt > 0){
        int pct = (int)((100ull * db) / dt);
        if (pct < 0) pct = 0; if (pct > 100) pct = 100;
        app->cpu_pct = pct;
    }
    app->cpu_prev_total = total;
    app->cpu_prev_busy = busy;
}
static void sample_mem(struct app *app){
    unsigned char *buf; size_t sz;
    app->mem_total_kb = 0; app->mem_avail_kb = 0;
    if (load_file("/proc/meminfo", &buf, &sz) < 0){ app->mem_pct = 0; return; }
    char *p = (char*)buf; char *end = (char*)buf + sz;
    while (p < end){
        char *nl = memchr(p, '\n', (size_t)(end-p)); if (!nl) nl = end;
        if (!strncmp(p, "MemTotal:", 9))      app->mem_total_kb = atol(p+9);
        else if (!strncmp(p, "MemAvailable:", 13)) app->mem_avail_kb = atol(p+13);
        p = nl + 1;
    }
    free(buf);
    if (app->mem_total_kb > 0 && app->mem_avail_kb >= 0){
        long used = app->mem_total_kb - app->mem_avail_kb; if (used < 0) used = 0;
        app->mem_pct = (int)((100L * used) / app->mem_total_kb);
        if (app->mem_pct < 0) app->mem_pct = 0; if (app->mem_pct > 100) app->mem_pct = 100;
    } else app->mem_pct = 0;
}
static int proc_cmp(const void *a, const void *b){
    const struct proc *pa = a, *pb = b;
    if (pb->rss_kb > pa->rss_kb) return 1;
    if (pb->rss_kb < pa->rss_kb) return -1;
    return pa->pid - pb->pid;
}
static void sample_procs(struct app *app){
    app->n_procs = 0;
    DIR *d = opendir("/proc"); if (!d) return;
    long pagesz = sysconf(_SC_PAGESIZE); if (pagesz <= 0) pagesz = 4096;
    struct dirent *de;
    while ((de = readdir(d)) && app->n_procs < MAX_PROCS){
        /* numeric names only */
        const char *nm = de->d_name; int isnum = nm[0] != 0;
        for (const char *q = nm; *q; q++) if (!isdigit((unsigned char)*q)){ isnum = 0; break; }
        if (!isnum) continue;
        int pid = atoi(nm);
        struct proc *pr = &app->procs[app->n_procs];
        pr->pid = pid; pr->name[0] = 0; pr->rss_kb = 0;
        char path[64]; unsigned char *b; size_t sz;
        /* name from /proc/<pid>/comm */
        snprintf(path, sizeof path, "/proc/%d/comm", pid);
        if (load_file(path, &b, &sz) == 0){
            size_t n = sz; if (n && b[n-1] == '\n') n--; if (n > sizeof(pr->name)-1) n = sizeof(pr->name)-1;
            memcpy(pr->name, b, n); pr->name[n] = 0; free(b);
        }
        if (!pr->name[0]) snprintf(pr->name, sizeof pr->name, "%d", pid);
        /* RSS from /proc/<pid>/statm : "size resident shared ..." in pages */
        snprintf(path, sizeof path, "/proc/%d/statm", pid);
        if (load_file(path, &b, &sz) == 0 && sz > 0){
            /* statm: "size resident shared ..." in pages; parse the 2nd field.
             * strtoull stops at the first space, so the non-NUL-terminated buffer is safe. */
            char *p = (char*)b; strtoull(p, &p, 10);
            unsigned long long resident = strtoull(p, &p, 10);
            pr->rss_kb = (long)((resident * (unsigned long long)pagesz) / 1024ull);
            free(b);
        }
        app->n_procs++;
    }
    closedir(d);
    qsort(app->procs, app->n_procs, sizeof(struct proc), proc_cmp);
    /* clamp scroll after the list size may have shrunk */
    int visible = (app->height - (TITLE_H + 118)) / ROW_H; if (visible < 1) visible = 1;
    int maxscroll = app->n_procs - visible; if (maxscroll < 0) maxscroll = 0;
    if (app->scroll > maxscroll) app->scroll = maxscroll;
    if (app->scroll < 0) app->scroll = 0;
}
static void refresh_all(struct app *app){ sample_cpu(app); sample_mem(app); sample_procs(app); }

/* --- rendering --- */
/* ── views ─────────────────────────────────────────────────────────────────────────────────
 * One binary, several launcher entries.  The list of "applications" a desktop is expected to
 * have includes Task Manager, Process Viewer, Resource Monitor, CPU Monitor and Memory
 * Monitor; those are five names for views over one process table, not five programs.  Each
 * ships a .desktop file with `Exec=/wl-sysmon --view=NAME`, and the tab bar switches between
 * them at runtime.
 *
 * DELIBERATELY ABSENT: a Network Monitor view.  /proc/net/dev in this kernel is a static stub
 * (posix.d:6490) with invented byte and packet counts -- lo: 4096/32, eth0: 65536/512 -- and
 * the network driver keeps no counters to render instead.  A view over that would display
 * fiction convincingly, which is worse than not shipping it.  Add rx/tx counters to
 * drivers/network and make /proc/net/dev live, then this becomes a small addition.
 * A Disk Monitor of I/O rates is likewise blocked: there is no /proc/diskstats at all.  The
 * Disk view below therefore reports mounted filesystems and free space, which IS real, and is
 * named accordingly. */
enum view { V_OVERVIEW = 0, V_PROCESSES, V_CPU, V_MEMORY, V_DISK, V_COUNT };

static const char *VIEW_TAB[V_COUNT]   = { "Overview", "Processes", "CPU", "Memory", "Disk" };
static const char *VIEW_KEY[V_COUNT]   = { "overview", "processes", "cpu", "memory", "disk" };
static const char *VIEW_TITLE[V_COUNT] = { "Resource Monitor", "Task Manager", "CPU Monitor",
                                           "Memory Monitor", "Disk Usage" };

/* --view=NAME (also accepts a bare NAME).  Unknown or absent -> V_OVERVIEW. */
static int parse_view(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strncmp(a, "--view=", 7)) a += 7;
        else if (a[0] == '-')          continue;
        for (int v = 0; v < V_COUNT; v++)
            if (!strcmp(a, VIEW_KEY[v])) return v;
    }
    return V_OVERVIEW;
}

/* One "Key: value kB" lookup in /proc/meminfo.  Returns -1 when absent. */
static long meminfo_field(const char *key)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char line[128];
    size_t klen = strlen(key);
    long val = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, key, klen) || line[klen] != ':') continue;
        val = strtol(line + klen + 1, NULL, 10);
        break;
    }
    fclose(f);
    return val;
}

/* First line of /proc/loadavg -> "0.00 0.01 0.05".  Empty string when unavailable. */
static void read_loadavg(char *out, size_t cap)
{
    out[0] = 0;
    FILE *f = fopen("/proc/loadavg", "r");
    if (!f) return;
    if (fgets(out, (int)cap, f)) {
        size_t n = strlen(out);
        while (n && (out[n-1] == '\n' || out[n-1] == '\r')) out[--n] = 0;
    }
    fclose(f);
}

/* Seconds of uptime from /proc/uptime; -1 when unavailable. */
static long read_uptime_secs(void)
{
    FILE *f = fopen("/proc/uptime", "r");
    if (!f) return -1;
    double up = -1.0;
    if (fscanf(f, "%lf", &up) != 1) up = -1.0;
    fclose(f);
    return up < 0 ? -1 : (long)up;
}

struct mountent { char dev[48]; char dir[64]; char type[24]; };

/* /proc/mounts -> up to `cap` entries.  Pseudo-filesystems are skipped: they have no size and
 * would push the real ones off the view. */
static int read_mounts(struct mountent *out, int cap)
{
    static const char *SKIP[] = { "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2",
                                  "debugfs", "tracefs", "securityfs", "pstore", "mqueue", 0 };
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return 0;
    int n = 0;
    /* Scanned straight into the destination widths (one less than each buffer) so there is no
     * intermediate copy to truncate.  A skipped row simply leaves n unadvanced. */
    while (n < cap &&
           fscanf(f, "%47s %63s %23s %*[^\n]", out[n].dev, out[n].dir, out[n].type) == 3) {
        int skip = 0;
        for (int i = 0; SKIP[i]; i++) if (!strcmp(out[n].type, SKIP[i])) { skip = 1; break; }
        if (!skip) n++;
    }
    fclose(f);
    return n;
}

static void draw_bar(struct app *app, const char *label, int pct, int y, uint32_t fillcol){
    const uint32_t TXT=0xfff2f5fau, DIM=0xff8b94a3u, TRK=0xff2d3444u;
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    draw_text(app, label, 14, y, 60, 13, TXT);
    int bx = 78, bw = app->width - 78 - 70, bh = 16;
    fill_rect(app, bx, y, bw, bh, TRK);
    fill_rect(app, bx, y, (bw * pct) / 100, bh, fillcol);
    char pc[16]; snprintf(pc, sizeof pc, "%d%%", pct);
    draw_text(app, pc, app->width - 60, y, 56, 13, DIM);
}
/* Tab strip under the titlebar.  Returns the y at which the view body starts. */
enum { TAB_H = 24 };
static int tab_width(const struct app *app){ return app->width / V_COUNT; }

static void draw_tabs(struct app *app)
{
    const uint32_t BAR=0xff161a21u, TXT=0xfff2f5fau, DIM=0xff8b94a3u, ACC=0xff4da3ffu;
    fill_rect(app, 0, TITLE_H, app->width, TAB_H, BAR);
    int tw = tab_width(app);
    for (int v = 0; v < V_COUNT; v++) {
        int x = v * tw;
        if (v == app->view) {
            fill_rect(app, x, TITLE_H, tw, TAB_H, 0xff1b1f27u);
            fill_rect(app, x, TITLE_H + TAB_H - 2, tw, 2, ACC);
        }
        draw_text(app, VIEW_TAB[v], x + 8, TITLE_H + 5, tw - 12, 12,
                  v == app->view ? TXT : DIM);
    }
    fill_rect(app, 0, TITLE_H + TAB_H, app->width, 1, 0xff2d3444u);
}

/* Rows of "label   value" text, the shape every non-Overview view uses. */
static void draw_kv(struct app *app, const char *k, const char *v, int y, uint32_t kc, uint32_t vc)
{
    draw_text(app, k, 14, y, 220, 12, kc);
    draw_text(app, v, 240, y, app->width - 254, 12, vc);
}

static void draw_proclist(struct app *app, int list_top)
{
    const uint32_t TXT=0xfff2f5fau, DIM=0xff8b94a3u, ROWALT=0xff20242eu;
    int visible = (app->height - list_top) / ROW_H; if (visible < 0) visible = 0;
    for (int r = 0; r < visible; r++){
        int idx = app->scroll + r; if (idx >= app->n_procs) break;
        struct proc *pr = &app->procs[idx];
        int ry = list_top + r*ROW_H;
        if (r & 1) fill_rect(app, 0, ry, app->width, ROW_H, ROWALT);
        char pid[16]; snprintf(pid, sizeof pid, "%d", pr->pid);
        draw_text(app, pid, 14, ry+2, 70, 12, DIM);
        draw_text(app, pr->name, 90, ry+2, app->width-90-120, 12, TXT);
        char rss[24];
        if (pr->rss_kb >= 1024) snprintf(rss, sizeof rss, "%ld.%ld MB", pr->rss_kb/1024, (pr->rss_kb%1024)*10/1024);
        else                    snprintf(rss, sizeof rss, "%ld KB", pr->rss_kb);
        draw_text(app, rss, app->width-110, ry+2, 100, 12, TXT);
    }
    if (app->n_procs > visible && visible > 0){
        int track_h = app->height - list_top;
        int thumb_h = track_h * visible / app->n_procs; if (thumb_h < 12) thumb_h = 12;
        int maxscroll = app->n_procs - visible; if (maxscroll < 1) maxscroll = 1;
        int thumb_y = list_top + (track_h - thumb_h) * app->scroll / maxscroll;
        fill_rect(app, app->width-4, list_top, 3, track_h, 0xff20242eu);
        fill_rect(app, app->width-4, thumb_y, 3, thumb_h, 0xff4da3ffu);
    }
}

static void draw_ui(struct app *app){
    const uint32_t BG=0xff1b1f27u, TITLE=0xff11141bu, TXT=0xfff2f5fau, DIM=0xff8b94a3u,
                   ACC=0xff4da3ffu, CLOSE=0xffc0392bu, CLOSEH=0xffe74c3cu,
                   CPUCOL=0xff4da3ffu, MEMCOL=0xff5ec27eu;
    fill_rect(app, 0, 0, app->width, app->height, BG);

    /* --- CSD titlebar --- */
    fill_rect(app, 0, 0, app->width, TITLE_H, TITLE);
    draw_text(app, VIEW_TITLE[app->view], 12, 5, app->width-120, 15, TXT);
    int cbx = app->width - 22, cby = 4, cbs = 18;
    fill_rect(app, cbx, cby, cbs, cbs, app->close_hover ? CLOSEH : CLOSE);
    draw_text(app, "x", cbx+5, cby+1, 14, 14, 0xffffffffu);

    draw_tabs(app);
    int y = TITLE_H + TAB_H + 12;
    char b[128];

    switch (app->view) {

    case V_PROCESSES:                       /* Task Manager / Process Viewer */
        snprintf(b, sizeof b, "Processes (%d)", app->n_procs);
        draw_text(app, b, 14, y, 240, 12, ACC);
        draw_text(app, "PID",  14,  y+18, 60, 12, DIM);
        draw_text(app, "NAME", 90,  y+18, 200, 12, DIM);
        draw_text(app, "RSS",  app->width-110, y+18, 100, 12, DIM);
        draw_proclist(app, y + 36);
        break;

    case V_CPU: {                           /* CPU Monitor */
        draw_bar(app, "CPU", app->cpu_pct, y, CPUCOL);
        y += 34;
        char la[128]; read_loadavg(la, sizeof la);
        draw_kv(app, "Load average", la[0] ? la : "unavailable", y, DIM, TXT); y += 20;
        long up = read_uptime_secs();
        if (up >= 0) snprintf(b, sizeof b, "%ldd %ldh %ldm", up/86400, (up%86400)/3600, (up%3600)/60);
        else         snprintf(b, sizeof b, "unavailable");
        draw_kv(app, "Uptime", b, y, DIM, TXT); y += 20;
        snprintf(b, sizeof b, "%d", app->n_procs);
        draw_kv(app, "Processes", b, y, DIM, TXT);
        break;
    }

    case V_MEMORY: {                        /* Memory Monitor */
        draw_bar(app, "Memory", app->mem_pct, y, MEMCOL);
        y += 34;
        static const char *KEYS[] = { "MemTotal", "MemFree", "MemAvailable",
                                      "Buffers", "Cached", "SwapTotal", "SwapFree", 0 };
        for (int i = 0; KEYS[i]; i++) {
            long kb = meminfo_field(KEYS[i]);
            if (kb < 0) snprintf(b, sizeof b, "unavailable");
            else if (kb >= 1024) snprintf(b, sizeof b, "%ld MB", kb / 1024);
            else                 snprintf(b, sizeof b, "%ld kB", kb);
            draw_kv(app, KEYS[i], b, y, DIM, TXT);
            y += 20;
        }
        break;
    }

    case V_DISK: {                          /* Disk Usage -- mounts, not I/O rates */
        draw_text(app, "Mounted filesystems", 14, y, 300, 12, ACC); y += 22;
        draw_text(app, "DEVICE", 14, y, 150, 12, DIM);
        draw_text(app, "MOUNT",  180, y, 200, 12, DIM);
        draw_text(app, "TYPE",   app->width-100, y, 90, 12, DIM);
        y += 20;
        struct mountent mt[24];
        int n = read_mounts(mt, 24);
        if (n == 0) draw_text(app, "/proc/mounts unavailable", 14, y, app->width-28, 12, DIM);
        for (int i = 0; i < n && y < app->height - ROW_H; i++, y += ROW_H) {
            if (i & 1) fill_rect(app, 0, y-2, app->width, ROW_H, 0xff20242eu);
            draw_text(app, mt[i].dev,  14,  y, 160, 12, TXT);
            draw_text(app, mt[i].dir,  180, y, app->width-290, 12, TXT);
            draw_text(app, mt[i].type, app->width-100, y, 90, 12, DIM);
        }
        break;
    }

    case V_OVERVIEW:                        /* Resource Monitor -- bars + the list */
    default: {
        draw_bar(app, "CPU", app->cpu_pct, y, CPUCOL);
        y += 30;
        draw_bar(app, "Memory", app->mem_pct, y, MEMCOL);
        if (app->mem_total_kb > 0){
            long used_mb = (app->mem_total_kb - app->mem_avail_kb) / 1024;
            long tot_mb  = app->mem_total_kb / 1024;
            if (used_mb < 0) used_mb = 0;
            snprintf(b, sizeof b, "%ld / %ld MB used", used_mb, tot_mb);
        } else snprintf(b, sizeof b, "meminfo unavailable");
        y += 22;
        draw_text(app, b, 14, y, app->width-28, 11, DIM);

        int hy = y + 26;
        fill_rect(app, 0, hy-4, app->width, 1, 0xff2d3444u);
        snprintf(b, sizeof b, "Processes (%d)", app->n_procs);
        draw_text(app, b, 14, hy, 200, 12, ACC);
        draw_text(app, "PID",  14,  hy+16, 60, 12, DIM);
        draw_text(app, "NAME", 90,  hy+16, 200, 12, DIM);
        draw_text(app, "RSS",  app->width-110, hy+16, 100, 12, DIM);
        draw_proclist(app, hy + 34);
        break;
    }
    }
}

/* --- double-buffered wl_shm (one memfd, two slices) --- */
static void redraw_commit(struct app *app);   /* fwd */
static void buffer_release(void *d, struct wl_buffer *wl){ struct app *a = d;
    for (int i=0;i<2;i++) if (a->bufs[i].wl == wl) a->bufs[i].busy = 0;
    if (a->dirty){ a->dirty = 0; redraw_commit(a); }
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

/* (Re)create the double-buffered wl_shm pool at the CURRENT app->width/height.
 * Safe to call again on resize: tears down the previous wl_buffers + client mmap first.
 * The compositor keeps its own mapping of any still-referenced buffer's fd, so releasing
 * the client-side mmap here does not corrupt on-screen content. */
static int create_buffers(struct app *app){
    /* tear down any previous buffers/mapping (no-op on first call) */
    for (int i=0;i<2;i++){
        if (app->bufs[i].wl){ wl_buffer_destroy(app->bufs[i].wl); app->bufs[i].wl = NULL; }
        app->bufs[i].px = NULL; app->bufs[i].busy = 0;
    }
    if (app->shm_base){ munmap(app->shm_base, app->shm_total); app->shm_base = NULL; app->shm_total = 0; }
    app->dirty = 0;

    app->stride = app->width * 4;
    app->buffer_size = (size_t)app->stride * app->height;

    int fd = create_memfd("epin-sysmon"); if (fd < 0) return -1;
    size_t total = app->buffer_size * 2;
    if (ftruncate(fd, (off_t)total) < 0){ close(fd); return -1; }
    unsigned char *base = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED){ close(fd); return -1; }
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int)total);
    for (int i=0;i<2;i++){
        app->bufs[i].px = (uint32_t*)(base + (size_t)i*app->buffer_size);
        app->bufs[i].wl = wl_shm_pool_create_buffer(pool, (int)((size_t)i*app->buffer_size),
                                                    app->width, app->height, app->stride, WL_SHM_FORMAT_XRGB8888);
        if (!app->bufs[i].wl){ wl_shm_pool_destroy(pool); munmap(base, total); close(fd); return -1; }
        wl_buffer_add_listener(app->bufs[i].wl, &buffer_listener, app);
        app->bufs[i].busy = 0;
    }
    wl_shm_pool_destroy(pool); close(fd);
    app->shm_base = base; app->shm_total = total;
    return 0;
}
static void redraw_commit(struct app *app){
    if (!app->configured) return;
    int i = app->bufs[0].busy ? 1 : 0;
    if (app->bufs[i].busy){ app->dirty = 1; return; }
    app->pixels = app->bufs[i].px;
    draw_ui(app);
    app->bufs[i].busy = 1;
    wl_surface_attach(app->surface, app->bufs[i].wl, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
}

/* --- input --- */
static void scroll_by(struct app *app, int delta){
    int list_top = TITLE_H + 100 + 18;
    int visible = (app->height - list_top) / ROW_H; if (visible < 1) visible = 1;
    int maxscroll = app->n_procs - visible; if (maxscroll < 0) maxscroll = 0;
    app->scroll += delta;
    if (app->scroll > maxscroll) app->scroll = maxscroll;
    if (app->scroll < 0) app->scroll = 0;
    redraw_commit(app);
}

static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; if (a->close_hover){ a->close_hover=0; redraw_commit(a); } }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y);
    int cbx = a->width - 22, cby = 4, cbs = 18;
    int nh = (a->pointer_x>=cbx && a->pointer_x<cbx+cbs && a->pointer_y>=cby && a->pointer_y<cby+cbs);
    if (nh != a->close_hover){ a->close_hover = nh; redraw_commit(a); } }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/ || state != 1) return;
    int cbx = a->width - 22, cby = 4, cbs = 18;
    if (a->pointer_x>=cbx && a->pointer_x<cbx+cbs && a->pointer_y>=cby && a->pointer_y<cby+cbs){
        log_line("SYSMON: close"); exit(0);
    }
    /* tab strip: switch view, and reset scroll since each view has its own list length */
    if (a->pointer_y >= TITLE_H && a->pointer_y < TITLE_H + TAB_H){
        int tw = tab_width(a);
        if (tw <= 0) return;
        int v = (int)(a->pointer_x / tw);
        if (v >= 0 && v < V_COUNT && v != a->view){
            a->view = v;
            a->scroll = 0;
            xdg_toplevel_set_title(a->toplevel, VIEW_TITLE[v]);
            redraw_commit(a);
        }
    }
}
static void pointer_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v){ (void)p;(void)t; struct app*a=d;
    if (ax != 0 /*vertical*/) return;
    double dv = wl_fixed_to_double(v);
    scroll_by(a, dv > 0 ? 3 : -3); }
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
    if (state != 1) return;              /* press only */
    int list_top = TITLE_H + 100 + 18;
    int visible = (a->height - list_top) / ROW_H; if (visible < 1) visible = 1;
    switch (key){
        case 103: scroll_by(a, -1); break;   /* Up */
        case 108: scroll_by(a,  1); break;   /* Down */
        case 104: scroll_by(a, -(visible-1)); break; /* PageUp */
        case 109: scroll_by(a,  (visible-1)); break; /* PageDown */
        case 1:   a->running = 0; break;     /* Esc */
        default: break;
    } }
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
    /* record the tiler-dictated size; 0 means "unconstrained" -> keep current */
    if (w > 0) a->pending_w = w;
    if (h > 0) a->pending_h = h; }
static void toplevel_close(void *d, struct xdg_toplevel *t){ (void)t; struct app*a=d; a->running=0; }
static void toplevel_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h){ (void)d;(void)t;(void)w;(void)h; }
static void toplevel_wmcap(void *d, struct xdg_toplevel *t, struct wl_array *c){ (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure=toplevel_configure,.close=toplevel_close,.configure_bounds=toplevel_bounds,.wm_capabilities=toplevel_wmcap };

static void xdg_surface_configure(void *d, struct xdg_surface *s, uint32_t serial){ struct app*a=d;
    xdg_surface_ack_configure(s, serial);
    /* Honor a compositor-driven size (tiling WM): if the tiler picked a size that differs
     * from our current buffers, recreate the shm buffers at the new dimensions so the window
     * fills its tile. The UI is drawn from scalar fields, so draw_ui() reflows automatically. */
    if (a->pending_w > 0 && a->pending_h > 0 &&
        (a->pending_w != a->width || a->pending_h != a->height)){
        a->width  = a->pending_w;
        a->height = a->pending_h;
        if (create_buffers(a) < 0){ log_line("SYSMON: resize buffer failed"); a->running = 0; return; }
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

int main(int argc, char **argv){
    static struct app app; memset(&app, 0, sizeof app);
    app.running = 1; app.scroll = 0;
    app.view = parse_view(argc, argv);   /* --view=processes|cpu|memory|disk */
    app.width = WIN_W; app.height = WIN_H; app.stride = WIN_W*4; app.buffer_size = (size_t)app.stride*WIN_H;
    signal(SIGCHLD, SIG_IGN);
    init_freetype(&app);
    /* prime CPU baseline so the first displayed % is meaningful */
    sample_cpu(&app);
    sample_mem(&app);
    sample_procs(&app);

    log_line("SYSMON: starting system monitor");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("SYSMON: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base){ log_line("SYSMON: missing globals"); return 1; }
    if (create_buffers(&app) < 0){ log_line("SYSMON: buffer failed"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, VIEW_TITLE[app.view]);
    xdg_toplevel_set_app_id(app.toplevel, "epin-sysmon");
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
               if (pr == 0){ refresh_all(&app); redraw_commit(&app); } }
    }
    return 0;
}
