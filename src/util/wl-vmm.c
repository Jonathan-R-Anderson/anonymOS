/*
 * wl-vmm.c -- Virtual Machines: a VirtualBox-style manager for the anonymOS hypervisor.
 *
 * The machine list, the toolbar (New / Settings / Remove / Start / Pause / Reset / ACPI Shutdown /
 * Power Off / Snapshot), per-machine Details, a serial Console, Snapshots and the VMM Log, a New
 * Virtual Machine wizard and a Settings dialog -- over Cloud Hypervisor (/cloud-hypervisor), which
 * runs each machine on the kernel's KVM-compatible hypervisor (/dev/kvm, gated per domain by
 * DEVCLASS_VIRT: Domain Manager > Permissions > Virtualization).
 *
 * One Cloud Hypervisor process per running machine, started with a plain fork + execve so the
 * kernel keeps it in this domain.  It is driven through its REST API (HTTP over the AF_UNIX
 * --api-socket: vm.pause / vm.resume / vm.reboot / vm.power-button / vm.snapshot / vmm.shutdown)
 * and its serial port is a second AF_UNIX socket (--serial socket=) that the Console tab
 * terminal-emulates.  Its own log (stdout/stderr) comes back through a pipe into the Log tab.
 *
 * Machines live in memory for the session (the live system keeps nothing); runtime files go under
 * /tmp/vms.  The bundled guest is Alpine's linux-virt kernel with a busybox initramfs
 * (/vm-alpine.vmlinuz + /vm-alpine.initrd boot modules, built by tests/vmm/linux-guest/build.sh).
 *
 * Rendering follows the Software Center: a wl_shm buffer pair, cairo for shapes, a glyph cache over
 * FreeType for text, redraws drained on the frame callback.
 */
#define _GNU_SOURCE

#include <errno.h>
#include "epin-appid.h"
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <dirent.h>
#include <wayland-client.h>
#include <cairo/cairo.h>
#include <ft2build.h>
#include FT_FREETYPE_H

#include "xdg-shell-client-protocol.h"
#include "wl-deco.h"

extern char **environ;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

/* Overridable (WLVMM_CH / WLVMM_KERNEL / WLVMM_INITRD / WLVMM_RUNDIR) so --selftest also runs on a
 * development host against its own /dev/kvm. */
static const char *CH_PATH = "/cloud-hypervisor";
static const char *BUNDLED_KERNEL = "/vm-alpine.vmlinuz";
static const char *BUNDLED_INITRD = "/vm-alpine.initrd";
#define BUNDLED_CMDLINE "console=ttyS0 panic=-1 no_timer_check"
static const char *RUN_DIR = "/tmp/vms";
/* Firmware-booted guests: Cloud Hypervisor's UEFI (edk2 CloudHv, boot module) and the OPNsense
 * firewall's disk -- downloaded, verified and committed after install by hos-vm-fetch into the VM
 * store (the kernel publishes it at OPNSENSE_DISK once its header is committed), or a test image. */
static const char *FIRMWARE_PATH = "/vm-firmware.fd";
static const char *OPNSENSE_DISK = "/vmstore/opnsense.img";
/* While the image is still on its way: the kernel's empty store and hos-vm-fetch's progress. */
static const char *OPNSENSE_PENDING = "/vmstore/opnsense.img.part";
static const char *OPNSENSE_FETCH_STATUS = "/vmstore/opnsense.status";
static const char *OPNSENSE_TEST_DISK = "/vm-opnsense.qcow2";

enum { DEFAULT_WIDTH = 1120, DEFAULT_HEIGHT = 720, MIN_WIDTH = 900, MIN_HEIGHT = 600 };
enum { TOOLBAR_Y = 0, TOOLBAR_H = 64, SIDEBAR_W = 270, STATUS_H = 26, TAB_H = 34, VMROW_H = 58 };

/* ── colours ───────────────────────────────────────────────────────────────────────────── */
#define C_BG      0x0f1418u
#define C_SIDE    0x151c22u
#define C_BAR     0x121920u
#define C_PANEL   0x131b21u
#define C_CARD    0x19222au
#define C_CARD2   0x1f2a33u
#define C_LINE    0x26313bu
#define C_SEL     0x173a44u
#define C_ACCENT  0x0d8577u
#define C_ACCENT2 0x14a595u
#define C_TEXT    0xe6ecf2u
#define C_DIM     0x8b96a4u
#define C_FAINT   0x5f6b78u
#define C_GREEN   0x57d977u
#define C_YELLOW  0xffd08au
#define C_RED     0xff7b7bu
#define C_BLUE    0x5aa8ffu
#define C_TERM_BG 0x0a0d10u

/* ── model ─────────────────────────────────────────────────────────────────────────────── */
enum { OS_ALPINE, OS_CUSTOM, OS_OPNSENSE };
enum { ST_OFF, ST_STARTING, ST_RUNNING, ST_PAUSED, ST_STOPPING, ST_ABORTED };
static const char *const k_state_name[] = { "Powered Off", "Starting", "Running", "Paused",
                                            "Stopping", "Aborted" };

struct vmcfg {
    char name[48];
    int  os;
    char kernel[160], initrd[160], cmdline[200];
    int  mem_mb, cpus;
    int  disk_mb;            /* 0 = no virtual hard disk */
    char desc[120];
    char firmware[160];      /* UEFI firmware: boot this instead of a kernel */
    char diskimg[160];       /* an existing disk image (qcow2 or raw by extension) */
    int  disk_ro;            /* attach diskimg read-only */
    int  autostart;          /* start headless when anonymOS boots (wl-vmm --autostart) */
    int  net;                /* NET_*: the machine's network card (OPNsense: fixed LAN + WAN) */
};
/* Network cards are vnet TAPs (the kernel's virtual network): "nat*"/"wan*" join the uplink the
 * kernel NATs out through the host; "lan-opnsense*" is the firewall's LAN, which the domains the
 * Domain Manager routes through it join too. */
enum { NET_NONE, NET_NAT, NET_LAN };
static const char *const k_net_name[3] = { "Not attached", "NAT through the host network",
                                           "Behind the OPNsense firewall (its LAN)" };
#define FW_LAN "lan-opnsense"
#define NET_OFFLOADS "offload_tso=off,offload_ufo=off,offload_csum=off"

/* A tiny VT100-ish terminal: a ring of lines, a cursor, CSI parsing (the escapes a shell's line
 * editor and `clear` use). */
enum { TERM_COLS = 160, TERM_CAP = 1200 };
struct term {
    char    *ch;             /* TERM_CAP * TERM_COLS */
    uint8_t *co;             /* colour index per cell */
    int head, n;             /* ring start, lines in use (>= 1) */
    int cx, cy;              /* cursor: column, line (0 .. n-1) */
    int rows;                /* visible rows (for CSI H), set by the drawer */
    int cols;                /* wrap column: the visible width, set by the drawer (<= TERM_COLS) */
    int esc; char eb[40]; int el;
    uint8_t fg;
    int view;                /* lines scrolled back from the bottom */
    int utf8skip;
    int lf_is_crlf;          /* program output (the VMM log) ends lines with a bare LF */
};

struct snap { char name[40]; char path[128]; time_t when; };

struct vm {
    int used, id;
    struct vmcfg cfg;
    int state;
    pid_t pid;
    int serial_fd, log_fd;
    char api_path[96], serial_path[96], disk_path[128];
    time_t started;
    long connect_tries;
    struct term con, log;
    struct snap snaps[8];
    int nsnap;
    int restore_from;        /* snapshot index to restore on next start, -1 = boot normally */
    int exit_status;
    char note[400];          /* last action's outcome */
    long serial_bytes;
    time_t reconnect_at;     /* after the VMM dropped the console: when to try again */
    int  child;              /* this process started the VMM (waitpid works); 0 = re-attached */
    char log_path[96], state_path[96];
    time_t next_alive_check;
};

enum { MAX_VMS = 12 };

/* ── glyph cache ───────────────────────────────────────────────────────────────────────── */
enum { GLYPH_FIRST = 0x20, GLYPH_LAST = 0x7e, GLYPH_CHARS = GLYPH_LAST - GLYPH_FIRST + 1,
       GLYPH_MAX_PX = 40, GLYPH_SIZE_SLOTS = 8 };
struct glyph { int loaded; unsigned char *bitmap; int width, rows, pitch, left, top, advance; };
struct glyph_size { int px; int ascender; struct glyph glyphs[GLYPH_CHARS]; };
struct font { FT_Face face; unsigned char *data; size_t size; struct glyph_size sizes[GLYPH_SIZE_SLOTS];
              int cur_px; int ok; };
enum { F_REG, F_BOLD, F_MONO, F_COUNT };

/* ── UI state ──────────────────────────────────────────────────────────────────────────── */
enum { TAB_DETAILS, TAB_CONSOLE, TAB_SNAPSHOTS, TAB_LOG, TAB_COUNT };
static const char *const k_tab_name[TAB_COUNT] = { "Details", "Console", "Snapshots", "Log" };
enum { VIEW_MACHINE, VIEW_HOST, VIEW_MEDIA };

enum {                                     /* click actions */
    A_NONE, A_NEW, A_SETTINGS, A_DELETE, A_START, A_PAUSE, A_RESET, A_ACPI, A_POWEROFF, A_SNAPSHOT,
    A_SELECT_VM, A_TAB, A_VIEW, A_SNAP_RESTORE, A_SNAP_DELETE, A_CONSOLE,
    A_DLG_NEXT, A_DLG_BACK, A_DLG_CANCEL, A_DLG_OK, A_DLG_FIELD, A_DLG_STEP, A_DLG_CHOICE,
    A_DLG_SECTION, A_DLG_DELETE_OK, A_DLG_TOGGLE,
};
struct hit { int x, y, w, h, action, arg; };

enum { DLG_NONE, DLG_NEW, DLG_SETTINGS, DLG_DELETE };
enum { FLD_NAME, FLD_KERNEL, FLD_INITRD, FLD_CMDLINE, FLD_DESC, FLD_COUNT };
enum { STEP_MEM, STEP_CPU, STEP_DISK };
enum { SEC_GENERAL, SEC_SYSTEM, SEC_STORAGE, SEC_NETWORK, SEC_SERIAL, SEC_DISPLAY, SEC_COUNT };
static const char *const k_sec_name[SEC_COUNT] = { "General", "System", "Storage", "Network", "Serial Port",
                                                   "Display" };

struct dialog {
    int kind, page, section, focus;
    struct vmcfg cfg;
    int target;              /* vm index being edited / removed */
    char err[160];
};

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
    struct wl_callback *frame_cb;

    struct wl_buffer *buffer[2];
    int               busy[2];
    uint32_t         *pixels[2];
    size_t            pool_size;

    FT_Library ft;
    struct font fonts[F_COUNT];

    uint32_t *px;
    cairo_surface_t *cs;
    cairo_t *cr;
    int width, height, stride;
    int maximized;
    int pending_width, pending_height;
    int committed, running, dirty, frame_pending;

    struct hit hits[320];
    int nhits;
    double ptr_x, ptr_y;
    int shift, ctrl;

    struct vm vms[MAX_VMS];
    int sel;                 /* selected vm index, -1 = none */
    int view;                /* VIEW_* */
    int tab;
    int next_id;
    struct dialog dlg;
    char banner[200];        /* status-bar message */
    int banner_kind;         /* 0 info, 1 ok, 2 error */
    int fetch_pending;       /* the firewall image was still downloading at the last check */

    /* host virtualization probe */
    int kvm_ok, kvm_errno, kvm_api;
    int cap_usermem, cap_irqrouting, cap_irqfd, cap_ioeventfd, cap_signalmsi, cap_irqchip;
    int have_ch, have_bundled;
};

static struct app *g_app;
static void autostart_set(const char *name, int on);
static int autostart_listed(const char *name);

/* ── small helpers ─────────────────────────────────────────────────────────────────────── */
static void set_banner(struct app *a, int kind, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vsnprintf(a->banner, sizeof a->banner, fmt, ap);
    va_end(ap);
    a->banner_kind = kind;
    printf("[vmm] %s\n", a->banner);
    fflush(stdout);
}
static void copy_str(char *dst, size_t cap, const char *src) { snprintf(dst, cap, "%s", src ? src : ""); }
static int file_readable(const char *p) { return p && *p && access(p, R_OK) == 0; }
static const char *opnsense_disk(void)
{
    if (file_readable(OPNSENSE_DISK)) return OPNSENSE_DISK;
    if (file_readable(OPNSENSE_TEST_DISK)) return OPNSENSE_TEST_DISK;
    return NULL;
}
/* The firewall download (hos-vm-fetch's status file): "state=... done=... total=... msg=...".
 * Returns 1 and a one-line summary while the image is pending, 0 once it is there or never chosen. */
static int fetch_status(char *out, size_t cap)
{
    if (!file_readable(OPNSENSE_PENDING) && access(OPNSENSE_PENDING, F_OK) != 0) return 0;
    char st[32] = "", msg[200] = "";
    unsigned long long done = 0, total = 0;
    FILE *f = fopen(OPNSENSE_FETCH_STATUS, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof line, f)) {
            line[strcspn(line, "\n")] = 0;
            if (!strncmp(line, "state=", 6)) snprintf(st, sizeof st, "%s", line + 6);
            else if (!strncmp(line, "done=", 5)) done = strtoull(line + 5, NULL, 10);
            else if (!strncmp(line, "total=", 6)) total = strtoull(line + 6, NULL, 10);
            else if (!strncmp(line, "msg=", 4)) snprintf(msg, sizeof msg, "%s", line + 4);
        }
        fclose(f);
    }
    if (!st[0]) snprintf(out, cap, "OPNsense firewall: waiting for the network to download the image");
    else if (!strcmp(st, "downloading") && total)
        snprintf(out, cap, "OPNsense firewall: downloading, %llu of %llu MB (%llu%%)", done >> 20, total >> 20,
                 done * 100 / total);
    else snprintf(out, cap, "OPNsense firewall: %s -- %s", st, msg);
    return 1;
}

static const char *os_name(int os)
{
    switch (os) {
    case OS_ALPINE: return "Alpine Linux 3.19 (bundled)";
    case OS_OPNSENSE: return "OPNsense 26.7 firewall (FreeBSD 15.1)";
    default: return "Linux";
    }
}
static long file_size(const char *p) { struct stat st; return (p && stat(p, &st) == 0) ? (long)st.st_size : -1; }
static const char *basename_of(const char *p) { const char *s = strrchr(p, '/'); return s ? s + 1 : p; }
static void fmt_bytes(long b, char *out, size_t cap)
{
    if (b < 0) snprintf(out, cap, "missing");
    else if (b < 1024) snprintf(out, cap, "%ld B", b);
    else if (b < 1024L * 1024) snprintf(out, cap, "%.1f KB", b / 1024.0);
    else snprintf(out, cap, "%.1f MB", b / (1024.0 * 1024.0));
}

/* ── FreeType ──────────────────────────────────────────────────────────────────────────── */
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

static void init_fonts(struct app *a)
{
    static const char *const paths[F_COUNT] = {
        "/usr/share/fonts/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/noto/NotoSans-Bold.ttf",
        "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
    };
    if (FT_Init_FreeType(&a->ft) != 0) return;
    for (int i = 0; i < F_COUNT; i++) {
        struct font *f = &a->fonts[i];
        if (load_file(paths[i], &f->data, &f->size) < 0) {
            if (i == F_REG) continue;
            *f = a->fonts[F_REG];               /* fall back to the regular face */
            memset(f->sizes, 0, sizeof f->sizes);
            f->cur_px = 0;
            if (f->ok && FT_New_Memory_Face(a->ft, f->data, (FT_Long)f->size, 0, &f->face) != 0) f->ok = 0;
            continue;
        }
        f->ok = FT_New_Memory_Face(a->ft, f->data, (FT_Long)f->size, 0, &f->face) == 0;
    }
}

static inline unsigned int div255(unsigned int x) { return (x + 1 + (x >> 8)) >> 8; }
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

static const struct glyph *cached_glyph(struct font *f, int px, unsigned char ch)
{
    if (!f->ok) return NULL;
    if (ch < GLYPH_FIRST || ch > GLYPH_LAST) ch = '?';
    struct glyph_size *slot = slot_for(f, px);
    if (!slot) return NULL;
    struct glyph *gl = &slot->glyphs[ch - GLYPH_FIRST];
    if (gl->loaded) return gl;
    if (f->cur_px != px) {
        if (FT_Set_Pixel_Sizes(f->face, 0, (FT_UInt)px) != 0) return NULL;
        f->cur_px = px;
    }
    if (slot->ascender == 0 && f->face->size && f->face->size->metrics.ascender > 0)
        slot->ascender = (int)(f->face->size->metrics.ascender >> 6);
    if (FT_Load_Char(f->face, (FT_ULong)ch, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) != 0) return NULL;
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

static void blit_glyph(struct app *a, const struct glyph *gl, int pen_x, int pen_y, uint32_t color,
                       int cx0, int cy0, int cx1, int cy1)
{
    if (!gl->bitmap) return;
    int gx = pen_x + gl->left, gy = pen_y - gl->top;
    for (int row = 0; row < gl->rows; row++) {
        int py = gy + row;
        if (py < cy0 || py >= cy1 || py < 0 || py >= a->height) continue;
        const unsigned char *src = gl->bitmap + (size_t)row * gl->pitch;
        uint32_t *line = &a->px[py * (a->stride / 4)];
        for (int col = 0; col < gl->width; col++) {
            int pxp = gx + col;
            if (pxp < cx0 || pxp >= cx1 || pxp < 0 || pxp >= a->width) continue;
            unsigned int al = src[col];
            if (al) line[pxp] = blend(line[pxp], color, al);
        }
    }
}

static int text_width(struct app *a, int fid, const char *s, int px)
{
    int w = 0;
    if (!s) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p && *p != '\n'; p++) {
        const struct glyph *gl = cached_glyph(&a->fonts[fid], px, *p);
        if (gl) w += gl->advance;
    }
    return w;
}

static int g_clip_x0, g_clip_y0, g_clip_x1 = 1 << 30, g_clip_y1 = 1 << 30;

/* One line of text at (x, y) = top-left, ellipsised at max_w.  Cairo drawing may be interleaved:
 * the surface is flushed before the glyph blit and marked dirty after. */
static int text(struct app *a, int fid, int px, int x, int y, int max_w, uint32_t color, const char *s)
{
    struct font *f = &a->fonts[fid];
    if (!f->ok || !s || max_w <= 0) return 0;
    cairo_surface_flush(a->cs);
    struct glyph_size *slot = slot_for(f, px);
    int baseline = px;
    if (slot) {
        if (slot->ascender == 0) (void)cached_glyph(f, px, 'H');
        if (slot->ascender > 0) baseline = slot->ascender;
    }
    int ell = text_width(a, fid, "...", px);
    int pen = x, pen_y = y + baseline;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char ch = (*p < 0x20 || *p >= 0x7f) ? '?' : *p;
        const struct glyph *gl = cached_glyph(f, px, ch);
        if (!gl) continue;
        if (pen + gl->advance > x + max_w - (p[1] ? ell : 0)) {
            if (p[1])
                for (const char *e = "..."; *e; e++) {
                    const struct glyph *eg = cached_glyph(f, px, (unsigned char)*e);
                    if (!eg || pen + eg->advance > x + max_w) break;
                    blit_glyph(a, eg, pen, pen_y, color, g_clip_x0, g_clip_y0, g_clip_x1, g_clip_y1);
                    pen += eg->advance;
                }
            break;
        }
        blit_glyph(a, gl, pen, pen_y, color, g_clip_x0, g_clip_y0, g_clip_x1, g_clip_y1);
        pen += gl->advance;
    }
    cairo_surface_mark_dirty(a->cs);
    return pen - x;
}
static void text_center(struct app *a, int fid, int px, int x, int y, int w, uint32_t color, const char *s)
{
    int tw = text_width(a, fid, s, px);
    text(a, fid, px, x + (w - tw) / 2, y, w, color, s);
}
static void text_right(struct app *a, int fid, int px, int xr, int y, uint32_t color, const char *s)
{
    int tw = text_width(a, fid, s, px);
    text(a, fid, px, xr - tw, y, tw + text_width(a, fid, "...", px) + 4, color, s);
}
static int textf(struct app *a, int fid, int px, int x, int y, int max_w, uint32_t color, const char *fmt, ...)
{
    char buf[512];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    return text(a, fid, px, x, y, max_w, color, buf);
}
/* Word-wrapped paragraph; returns the height used. */
static int text_wrap(struct app *a, int fid, int px, int x, int y, int max_w, int pitch, int max_lines,
                     uint32_t color, const char *s)
{
    const char *p = s;
    int line = 0;
    while (*p && line < max_lines) {
        const char *brk = NULL, *q = p;
        int w = 0;
        while (*q && *q != '\n') {
            const struct glyph *gl = cached_glyph(&a->fonts[fid], px, (unsigned char)*q);
            int adv = gl ? gl->advance : 0;
            if (w + adv > max_w) break;
            if (*q == ' ') brk = q;
            w += adv; q++;
        }
        int len = (*q && *q != '\n' && brk) ? (int)(brk - p) : (int)(q - p);
        char buf[512];
        if (len > (int)sizeof buf - 1) len = (int)sizeof buf - 1;
        memcpy(buf, p, (size_t)len); buf[len] = 0;
        text(a, fid, px, x, y + line * pitch, max_w, color, buf);
        p += len;
        if (*p == '\n') p++;
        while (*p == ' ') p++;
        line++;
    }
    return line * pitch;
}

/* ── cairo shapes ──────────────────────────────────────────────────────────────────────── */
static void set_rgb(cairo_t *cr, uint32_t c)
{
    cairo_set_source_rgb(cr, ((c >> 16) & 0xff) / 255.0, ((c >> 8) & 0xff) / 255.0, (c & 0xff) / 255.0);
}
static void rr_path(cairo_t *cr, double x, double y, double w, double h, double r)
{
    if (r * 2 > h) r = h / 2;
    if (r * 2 > w) r = w / 2;
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r,     r, -1.5708, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0,       1.5708);
    cairo_arc(cr, x + r,     y + h - r, r, 1.5708,  3.1416);
    cairo_arc(cr, x + r,     y + r,     r, 3.1416,  4.7124);
    cairo_close_path(cr);
}
static void fill(struct app *a, double x, double y, double w, double h, uint32_t c)
{ cairo_rectangle(a->cr, x, y, w, h); set_rgb(a->cr, c); cairo_fill(a->cr); }
static void rfill(struct app *a, double x, double y, double w, double h, double r, uint32_t c)
{ rr_path(a->cr, x, y, w, h, r); set_rgb(a->cr, c); cairo_fill(a->cr); }
static void rstroke(struct app *a, double x, double y, double w, double h, double r, uint32_t c, double lw)
{ rr_path(a->cr, x + 0.5, y + 0.5, w - 1, h - 1, r); set_rgb(a->cr, c); cairo_set_line_width(a->cr, lw); cairo_stroke(a->cr); }
static void line(struct app *a, double x0, double y0, double x1, double y1, uint32_t c, double lw)
{ cairo_move_to(a->cr, x0, y0); cairo_line_to(a->cr, x1, y1); set_rgb(a->cr, c);
  cairo_set_line_width(a->cr, lw); cairo_stroke(a->cr); }
static void disc(struct app *a, double cx, double cy, double r, uint32_t c)
{ cairo_new_sub_path(a->cr); cairo_arc(a->cr, cx, cy, r, 0, 6.2832); set_rgb(a->cr, c); cairo_fill(a->cr); }

static void hit_add(struct app *a, int x, int y, int w, int h, int action, int arg)
{
    if (a->nhits >= (int)(sizeof a->hits / sizeof a->hits[0])) return;
    a->hits[a->nhits++] = (struct hit){ x, y, w, h, action, arg };
}
static int ptr_in(struct app *a, int x, int y, int w, int h)
{ return a->ptr_x >= x && a->ptr_x < x + w && a->ptr_y >= y && a->ptr_y < y + h; }

/* ── icons (drawn, so they scale and need no assets) ───────────────────────────────────── */
enum { IC_NEW, IC_SETTINGS, IC_DELETE, IC_START, IC_PAUSE, IC_RESUME, IC_RESET, IC_ACPI, IC_POWEROFF,
       IC_SNAPSHOT, IC_HOST, IC_MEDIA };
static void icon(struct app *a, int kind, double x, double y, double s, uint32_t c)
{
    cairo_t *cr = a->cr;
    double cx = x + s / 2, cy = y + s / 2, r = s / 2;
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    set_rgb(cr, c);
    cairo_set_line_width(cr, s / 11);
    switch (kind) {
    case IC_NEW:                                           /* a star-burst plus */
        cairo_new_sub_path(cr); cairo_arc(cr, cx, cy, r * 0.82, 0, 6.2832); cairo_stroke(cr);
        cairo_move_to(cr, cx, cy - r * 0.45); cairo_line_to(cr, cx, cy + r * 0.45);
        cairo_move_to(cr, cx - r * 0.45, cy); cairo_line_to(cr, cx + r * 0.45, cy); cairo_stroke(cr);
        break;
    case IC_SETTINGS:                                      /* a gear */
        for (int i = 0; i < 8; i++) {
            double t = i * 0.7854;
            cairo_move_to(cr, cx + cos(t) * r * 0.55, cy + sin(t) * r * 0.55);
            cairo_line_to(cr, cx + cos(t) * r * 0.9, cy + sin(t) * r * 0.9);
        }
        cairo_stroke(cr);
        cairo_new_sub_path(cr); cairo_arc(cr, cx, cy, r * 0.58, 0, 6.2832); cairo_stroke(cr);
        cairo_new_sub_path(cr); cairo_arc(cr, cx, cy, r * 0.22, 0, 6.2832); cairo_stroke(cr);
        break;
    case IC_DELETE:                                        /* a bin */
        cairo_move_to(cr, x + s * 0.18, y + s * 0.26); cairo_line_to(cr, x + s * 0.82, y + s * 0.26);
        cairo_move_to(cr, x + s * 0.4, y + s * 0.26); cairo_line_to(cr, x + s * 0.42, y + s * 0.14);
        cairo_line_to(cr, x + s * 0.58, y + s * 0.14); cairo_line_to(cr, x + s * 0.6, y + s * 0.26);
        cairo_move_to(cr, x + s * 0.26, y + s * 0.3); cairo_line_to(cr, x + s * 0.32, y + s * 0.88);
        cairo_line_to(cr, x + s * 0.68, y + s * 0.88); cairo_line_to(cr, x + s * 0.74, y + s * 0.3);
        cairo_move_to(cr, cx, y + s * 0.42); cairo_line_to(cr, cx, y + s * 0.76);
        cairo_stroke(cr);
        break;
    case IC_START: case IC_RESUME:                         /* a play triangle */
        cairo_move_to(cr, x + s * 0.28, y + s * 0.16); cairo_line_to(cr, x + s * 0.84, cy);
        cairo_line_to(cr, x + s * 0.28, y + s * 0.84); cairo_close_path(cr); cairo_fill(cr);
        break;
    case IC_PAUSE:
        cairo_rectangle(cr, x + s * 0.26, y + s * 0.18, s * 0.16, s * 0.64);
        cairo_rectangle(cr, x + s * 0.58, y + s * 0.18, s * 0.16, s * 0.64); cairo_fill(cr);
        break;
    case IC_RESET:                                         /* a circular arrow */
        cairo_new_sub_path(cr); cairo_arc(cr, cx, cy, r * 0.62, -2.4, 3.0); cairo_stroke(cr);
        cairo_move_to(cr, cx + cos(-2.4) * r * 0.62 - r * 0.28, cy + sin(-2.4) * r * 0.62 - r * 0.02);
        cairo_line_to(cr, cx + cos(-2.4) * r * 0.62, cy + sin(-2.4) * r * 0.62);
        cairo_line_to(cr, cx + cos(-2.4) * r * 0.62 + r * 0.02, cy + sin(-2.4) * r * 0.62 + r * 0.3);
        cairo_stroke(cr);
        break;
    case IC_ACPI:                                          /* the power symbol */
        cairo_new_sub_path(cr); cairo_arc(cr, cx, cy + r * 0.05, r * 0.62, -1.1, 4.24); cairo_stroke(cr);
        cairo_move_to(cr, cx, y + s * 0.1); cairo_line_to(cr, cx, cy); cairo_stroke(cr);
        break;
    case IC_POWEROFF:                                      /* stop square */
        rr_path(cr, x + s * 0.22, y + s * 0.22, s * 0.56, s * 0.56, s * 0.08); cairo_fill(cr);
        break;
    case IC_SNAPSHOT:                                      /* a camera */
        rr_path(cr, x + s * 0.1, y + s * 0.3, s * 0.8, s * 0.52, s * 0.08); cairo_stroke(cr);
        cairo_move_to(cr, x + s * 0.34, y + s * 0.3); cairo_line_to(cr, x + s * 0.4, y + s * 0.18);
        cairo_line_to(cr, x + s * 0.6, y + s * 0.18); cairo_line_to(cr, x + s * 0.66, y + s * 0.3);
        cairo_stroke(cr);
        cairo_new_sub_path(cr); cairo_arc(cr, cx, y + s * 0.56, r * 0.28, 0, 6.2832); cairo_stroke(cr);
        break;
    case IC_HOST:                                          /* a chip */
        rr_path(cr, x + s * 0.24, y + s * 0.24, s * 0.52, s * 0.52, s * 0.06); cairo_stroke(cr);
        for (int i = 0; i < 3; i++) {
            double o = s * (0.34 + i * 0.16);
            cairo_move_to(cr, x + o, y + s * 0.1); cairo_line_to(cr, x + o, y + s * 0.24);
            cairo_move_to(cr, x + o, y + s * 0.76); cairo_line_to(cr, x + o, y + s * 0.9);
            cairo_move_to(cr, x + s * 0.1, y + o); cairo_line_to(cr, x + s * 0.24, y + o);
            cairo_move_to(cr, x + s * 0.76, y + o); cairo_line_to(cr, x + s * 0.9, y + o);
        }
        cairo_stroke(cr);
        break;
    case IC_MEDIA:                                         /* a disc */
        cairo_new_sub_path(cr); cairo_arc(cr, cx, cy, r * 0.8, 0, 6.2832); cairo_stroke(cr);
        cairo_new_sub_path(cr); cairo_arc(cr, cx, cy, r * 0.2, 0, 6.2832); cairo_stroke(cr);
        break;
    }
    cairo_set_line_cap(cr, CAIRO_LINE_CAP_BUTT);
}

/* An OS badge like VirtualBox's type icons: a rounded tile with the distribution's mark. */
static void os_badge(struct app *a, int os, double x, double y, double s)
{
    rfill(a, x, y, s, s, s * 0.22, os == OS_ALPINE ? 0x0d597fu : os == OS_OPNSENSE ? 0xd9480fu : 0x3b4652u);
    cairo_t *cr = a->cr;
    set_rgb(cr, 0xffffffu);
    if (os == OS_OPNSENSE) {                               /* a shield */
        cairo_move_to(cr, x + s * 0.5, y + s * 0.14);
        cairo_line_to(cr, x + s * 0.8, y + s * 0.26);
        cairo_curve_to(cr, x + s * 0.8, y + s * 0.6, x + s * 0.66, y + s * 0.76, x + s * 0.5, y + s * 0.88);
        cairo_curve_to(cr, x + s * 0.34, y + s * 0.76, x + s * 0.2, y + s * 0.6, x + s * 0.2, y + s * 0.26);
        cairo_close_path(cr); cairo_fill(cr);
        set_rgb(cr, 0xd9480fu);
        cairo_set_line_width(cr, s * 0.08);
        cairo_move_to(cr, x + s * 0.38, y + s * 0.5); cairo_line_to(cr, x + s * 0.47, y + s * 0.6);
        cairo_line_to(cr, x + s * 0.64, y + s * 0.38); cairo_stroke(cr);
    } else if (os == OS_ALPINE) {                                 /* two mountain peaks */
        cairo_move_to(cr, x + s * 0.12, y + s * 0.74); cairo_line_to(cr, x + s * 0.4, y + s * 0.3);
        cairo_line_to(cr, x + s * 0.56, y + s * 0.54); cairo_line_to(cr, x + s * 0.66, y + s * 0.4);
        cairo_line_to(cr, x + s * 0.88, y + s * 0.74); cairo_close_path(cr); cairo_fill(cr);
    } else {                                               /* a terminal prompt */
        cairo_set_line_width(cr, s * 0.09);
        cairo_move_to(cr, x + s * 0.24, y + s * 0.34); cairo_line_to(cr, x + s * 0.44, y + s * 0.5);
        cairo_line_to(cr, x + s * 0.24, y + s * 0.66);
        cairo_move_to(cr, x + s * 0.5, y + s * 0.68); cairo_line_to(cr, x + s * 0.76, y + s * 0.68);
        cairo_stroke(cr);
    }
}

static uint32_t state_color(int st)
{
    switch (st) {
    case ST_RUNNING: return C_GREEN;
    case ST_PAUSED: return C_YELLOW;
    case ST_STARTING: case ST_STOPPING: return C_BLUE;
    case ST_ABORTED: return C_RED;
    default: return C_FAINT;
    }
}

/* ── terminal ──────────────────────────────────────────────────────────────────────────── */
static uint32_t k_ansi[16] = {
    0x1b2229, 0xff6b6b, 0x5bd67a, 0xe8c76a, 0x5aa8ff, 0xc792ea, 0x4fd1c5, 0xd7dde4,
    0x5f6b78, 0xff8f8f, 0x7ee89a, 0xffe08a, 0x8cc4ff, 0xdcb2ff, 0x7fe6dc, 0xffffff,
};
static int term_init(struct term *t)
{
    memset(t, 0, sizeof *t);
    t->ch = malloc((size_t)TERM_CAP * TERM_COLS);
    t->co = malloc((size_t)TERM_CAP * TERM_COLS);
    if (!t->ch || !t->co) return -1;
    memset(t->ch, ' ', (size_t)TERM_CAP * TERM_COLS);
    memset(t->co, 7, (size_t)TERM_CAP * TERM_COLS);
    t->n = 1; t->fg = 7; t->rows = 24; t->cols = 100;
    return 0;
}
static void term_reset(struct term *t)
{
    if (!t->ch) return;
    memset(t->ch, ' ', (size_t)TERM_CAP * TERM_COLS);
    memset(t->co, 7, (size_t)TERM_CAP * TERM_COLS);
    t->head = 0; t->n = 1; t->cx = t->cy = 0; t->esc = 0; t->el = 0; t->fg = 7; t->view = 0; t->utf8skip = 0;
}
static char *term_line(struct term *t, int i) { return t->ch + (size_t)((t->head + i) % TERM_CAP) * TERM_COLS; }
static uint8_t *term_col(struct term *t, int i) { return t->co + (size_t)((t->head + i) % TERM_CAP) * TERM_COLS; }
static void term_clear_line(struct term *t, int i, int from, int to)
{
    if (from < 0) from = 0;
    if (to > TERM_COLS) to = TERM_COLS;
    if (from >= to) return;
    memset(term_line(t, i) + from, ' ', (size_t)(to - from));
    memset(term_col(t, i) + from, 7, (size_t)(to - from));
}
static void term_newline(struct term *t)
{
    if (t->cy + 1 < t->n) { t->cy++; return; }
    if (t->n < TERM_CAP) t->n++;
    else t->head = (t->head + 1) % TERM_CAP;
    t->cy = t->n - 1;
    term_clear_line(t, t->cy, 0, TERM_COLS);
    if (t->view > 0 && t->view < t->n) t->view++;          /* keep a scrolled-back view still */
}
static int term_screen_top(struct term *t) { int top = t->n - t->rows; return top < 0 ? 0 : top; }
static int csi_arg(const char *s, int idx, int dflt)
{
    int cur = 0, v = -1;
    for (; *s; s++) {
        if (*s == ';') { if (cur == idx) return v < 0 ? dflt : v; cur++; v = -1; continue; }
        if (*s >= '0' && *s <= '9') v = (v < 0 ? 0 : v * 10) + (*s - '0');
    }
    return (cur == idx && v >= 0) ? v : dflt;
}
/* Feed guest bytes.  `reply_fd` receives answers to device-status queries (ESC[6n). */
static void term_feed(struct term *t, const unsigned char *buf, size_t n, int reply_fd)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char c = buf[i];
        if (t->esc == 1) {                                 /* after ESC */
            if (c == '[') { t->esc = 2; t->el = 0; continue; }
            if (c == '(' || c == ')') { t->esc = 3; continue; }
            t->esc = 0; continue;                          /* ESC 7/8/=/> etc: ignored */
        }
        if (t->esc == 3) { t->esc = 0; continue; }         /* charset designator */
        if (t->esc == 2) {
            if ((c >= 0x30 && c <= 0x3f) || c == ' ') {
                if (t->el < (int)sizeof t->eb - 1) t->eb[t->el++] = (char)c;
                continue;
            }
            t->eb[t->el] = 0;
            t->esc = 0;
            const char *p = t->eb;
            int priv = (*p == '?');
            if (priv) p++;
            int top = term_screen_top(t);
            switch (c) {
            case 'm': {
                if (!*p) { t->fg = 7; break; }
                for (int k = 0; k < 8; k++) {
                    int v = csi_arg(p, k, -1);
                    if (v < 0) break;
                    if (v == 0) t->fg = 7;
                    else if (v == 1 && t->fg < 8) t->fg += 8;
                    else if (v >= 30 && v <= 37) t->fg = (uint8_t)(v - 30 + (t->fg >= 8 ? 8 : 0));
                    else if (v >= 90 && v <= 97) t->fg = (uint8_t)(v - 90 + 8);
                    else if (v == 39) t->fg = 7;
                }
                break;
            }
            case 'K': {
                int mode = csi_arg(p, 0, 0);
                if (mode == 0) term_clear_line(t, t->cy, t->cx, TERM_COLS);
                else if (mode == 1) term_clear_line(t, t->cy, 0, t->cx + 1);
                else term_clear_line(t, t->cy, 0, TERM_COLS);
                break;
            }
            case 'J': {
                int mode = csi_arg(p, 0, 0);
                if (mode == 2 || mode == 3) {                  /* clear: scroll the screen away */
                    for (int k = 0; k < t->rows; k++) term_newline(t);
                    t->cy = term_screen_top(t); t->cx = 0;
                } else if (mode == 0) {
                    term_clear_line(t, t->cy, t->cx, TERM_COLS);
                    for (int k = t->cy + 1; k < t->n; k++) term_clear_line(t, k, 0, TERM_COLS);
                }
                break;
            }
            case 'H': case 'f': {
                int r = csi_arg(p, 0, 1), col = csi_arg(p, 1, 1);
                /* clamp to the screen: line editors probe its size with ESC[999;999H + ESC[6n */
                if (r < 1) r = 1;
                if (r > t->rows) r = t->rows;
                if (col < 1) col = 1;
                if (col > t->cols) col = t->cols;
                while (top + r - 1 >= t->n) { t->cy = t->n - 1; term_newline(t); top = term_screen_top(t); }
                t->cy = top + r - 1; t->cx = col - 1;
                break;
            }
            case 'A': t->cy -= csi_arg(p, 0, 1); if (t->cy < top) t->cy = top; break;
            case 'B': t->cy += csi_arg(p, 0, 1); if (t->cy >= t->n) t->cy = t->n - 1; break;
            case 'C': t->cx += csi_arg(p, 0, 1); break;
            case 'D': t->cx -= csi_arg(p, 0, 1); break;
            case 'G': t->cx = csi_arg(p, 0, 1) - 1; break;
            case 'P': {                                         /* delete chars */
                int k = csi_arg(p, 0, 1);
                char *l = term_line(t, t->cy); uint8_t *co = term_col(t, t->cy);
                if (t->cx < TERM_COLS) {
                    int rest = TERM_COLS - t->cx - k;
                    if (rest > 0) { memmove(l + t->cx, l + t->cx + k, (size_t)rest); memmove(co + t->cx, co + t->cx + k, (size_t)rest); }
                    term_clear_line(t, t->cy, TERM_COLS - k, TERM_COLS);
                }
                break;
            }
            case 'n':
                if (csi_arg(p, 0, 0) == 6 && reply_fd >= 0) {
                    char r[32];
                    int len = snprintf(r, sizeof r, "\033[%d;%dR", t->cy - top + 1,
                                       (t->cx < t->cols ? t->cx : t->cols - 1) + 1);
                    if (write(reply_fd, r, (size_t)len) < 0) { /* the guest will just not get it */ }
                }
                break;
            default: break;                                     /* h/l/r/...: ignored */
            }
            if (t->cx < 0) t->cx = 0;
            if (t->cx >= TERM_COLS) t->cx = TERM_COLS - 1;
            continue;
        }
        if (t->utf8skip > 0) { if ((c & 0xc0) == 0x80) { t->utf8skip--; continue; } t->utf8skip = 0; }
        switch (c) {
        case 0x1b: t->esc = 1; continue;
        case '\r': t->cx = 0; continue;
        case '\n': term_newline(t); if (t->lf_is_crlf) t->cx = 0; continue;
        case '\b': if (t->cx > 0) t->cx--; continue;
        case '\t': t->cx = (t->cx + 8) & ~7; if (t->cx >= TERM_COLS) t->cx = TERM_COLS - 1; continue;
        case 0x07: case 0x00: case 0x0e: case 0x0f: continue;
        default: break;
        }
        if (c < 0x20) continue;
        if (c >= 0x80) {                                   /* UTF-8: one '?' per code point */
            if ((c & 0xe0) == 0xc0) t->utf8skip = 1;
            else if ((c & 0xf0) == 0xe0) t->utf8skip = 2;
            else if ((c & 0xf8) == 0xf0) t->utf8skip = 3;
            c = '?';
        }
        if (t->cx >= t->cols) { term_newline(t); t->cx = 0; }
        term_line(t, t->cy)[t->cx] = (char)c;
        term_col(t, t->cy)[t->cx] = t->fg;
        t->cx++;
    }
}
static void term_puts(struct term *t, const char *s) { term_feed(t, (const unsigned char *)s, strlen(s), -1); }

/* ── KVM probe ─────────────────────────────────────────────────────────────────────────── */
#define KVM_GET_API_VERSION  0xAE00u
#define KVM_CHECK_EXTENSION  0xAE03u
static void probe_host(struct app *a)
{
    a->kvm_ok = 0; a->kvm_errno = 0; a->kvm_api = -1;
    int fd = open("/dev/kvm", O_RDWR);
    if (fd < 0) a->kvm_errno = errno;
    else {
        a->kvm_ok = 1;
        a->kvm_api        = (int)ioctl(fd, KVM_GET_API_VERSION, 0);
        a->cap_usermem    = (int)ioctl(fd, KVM_CHECK_EXTENSION, 3);
        a->cap_irqchip    = (int)ioctl(fd, KVM_CHECK_EXTENSION, 121);   /* KVM_CAP_SPLIT_IRQCHIP */
        a->cap_irqrouting = (int)ioctl(fd, KVM_CHECK_EXTENSION, 25);
        a->cap_irqfd      = (int)ioctl(fd, KVM_CHECK_EXTENSION, 32);
        a->cap_ioeventfd  = (int)ioctl(fd, KVM_CHECK_EXTENSION, 36);
        a->cap_signalmsi  = (int)ioctl(fd, KVM_CHECK_EXTENSION, 77);
        close(fd);
    }
    a->have_ch = access(CH_PATH, X_OK) == 0 || access(CH_PATH, R_OK) == 0;
    a->have_bundled = file_readable(BUNDLED_KERNEL) && file_readable(BUNDLED_INITRD);
}

/* ── Cloud Hypervisor REST API (HTTP/1.1 over AF_UNIX) ─────────────────────────────────── */
static int unix_connect(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { int e = errno; close(fd); errno = e; return -1; }
    return fd;
}

/* One request; returns the HTTP status (or -1) and the body in resp. */
static int api_call(struct vm *v, const char *method, const char *endpoint, const char *body,
                    char *resp, size_t cap, int timeout_ms)
{
    if (resp && cap) resp[0] = 0;
    int fd = unix_connect(v->api_path);
    if (fd < 0) return -1;
    char req[768];
    size_t blen = body ? strlen(body) : 0;
    int n = snprintf(req, sizeof req,
                     "%s /api/v1/%s HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n"
                     "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s",
                     method, endpoint, blen, body ? body : "");
    for (int off = 0; off < n; ) {
        ssize_t w = write(fd, req + off, (size_t)(n - off));
        if (w <= 0) { close(fd); return -1; }
        off += (int)w;
    }
    char buf[8192];
    size_t got = 0;
    long want = -1;
    size_t hdr_end = 0;
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        long el = (now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000;
        if (el >= timeout_ms) break;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, (int)(timeout_ms - el)) <= 0) break;
        ssize_t r = read(fd, buf + got, sizeof buf - 1 - got);
        if (r <= 0) break;
        got += (size_t)r;
        buf[got] = 0;
        if (!hdr_end) {
            char *e = strstr(buf, "\r\n\r\n");
            if (e) {
                hdr_end = (size_t)(e - buf) + 4;
                char *cl = strcasestr(buf, "Content-Length:");
                want = cl ? strtol(cl + 15, NULL, 10) : 0;
            }
        }
        if (hdr_end && (long)(got - hdr_end) >= want) break;
        if (got >= sizeof buf - 1) break;
    }
    close(fd);
    buf[got] = 0;
    int status = -1;
    if (got > 12 && !strncmp(buf, "HTTP/1.", 7)) status = atoi(buf + 9);
    if (resp && cap && hdr_end) copy_str(resp, cap, buf + hdr_end);
    return status;
}

/* ── machine lifecycle ─────────────────────────────────────────────────────────────────── */
static void vm_note(struct vm *v, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vsnprintf(v->note, sizeof v->note, fmt, ap);
    va_end(ap);
    char line[480];
    snprintf(line, sizeof line, "\r\n\033[96m[manager]\033[0m %s\r\n", v->note);
    term_puts(&v->log, line);
}

static void vm_close_fds(struct vm *v)
{
    if (v->serial_fd >= 0) { close(v->serial_fd); v->serial_fd = -1; }
    if (v->log_fd >= 0) {
        /* drain what the VMM wrote before it went away */
        char buf[4096];
        for (int k = 0; k < 64; k++) {
            ssize_t r = read(v->log_fd, buf, sizeof buf);
            if (r <= 0) break;
            term_feed(&v->log, (unsigned char *)buf, (size_t)r, -1);
        }
        close(v->log_fd); v->log_fd = -1;
    }
}

/* ── headless: machines outlive this window ────────────────────────────────────────────────
 * Each running machine has RUN_DIR/vm<id>.state (its configuration + the VMM's pid) and its VMM
 * writes to RUN_DIR/vm<id>.log, so closing Virtual Machines leaves it running; the next launch
 * re-attaches: the console socket takes the new client, the log file is tailed again. */
static void cfg_put(FILE *f, const char *k, const char *v) { fprintf(f, "%s=%s\n", k, v); }
static void vm_write_state(struct vm *v)
{
    if (!v->state_path[0]) return;
    char tmp[112];
    snprintf(tmp, sizeof tmp, "%s.new", v->state_path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    struct vmcfg *c = &v->cfg;
    char n[32];
    cfg_put(f, "name", c->name); cfg_put(f, "desc", c->desc);
    snprintf(n, sizeof n, "%d", c->os); cfg_put(f, "os", n);
    snprintf(n, sizeof n, "%d", c->mem_mb); cfg_put(f, "mem", n);
    snprintf(n, sizeof n, "%d", c->cpus); cfg_put(f, "cpus", n);
    snprintf(n, sizeof n, "%d", c->disk_mb); cfg_put(f, "disk_mb", n);
    snprintf(n, sizeof n, "%d", c->disk_ro); cfg_put(f, "disk_ro", n);
    snprintf(n, sizeof n, "%d", c->autostart); cfg_put(f, "autostart", n);
    snprintf(n, sizeof n, "%d", c->net); cfg_put(f, "net", n);
    cfg_put(f, "kernel", c->kernel); cfg_put(f, "initrd", c->initrd); cfg_put(f, "cmdline", c->cmdline);
    cfg_put(f, "firmware", c->firmware); cfg_put(f, "diskimg", c->diskimg);
    snprintf(n, sizeof n, "%d", (int)v->pid); cfg_put(f, "pid", n);
    snprintf(n, sizeof n, "%ld", (long)v->started); cfg_put(f, "started", n);
    snprintf(n, sizeof n, "%d", v->id); cfg_put(f, "id", n);
    fclose(f);
    rename(tmp, v->state_path);
}
static void vm_drop_state(struct vm *v)
{
    if (v->state_path[0]) unlink(v->state_path);
}

static int vm_start(struct app *a, struct vm *v)
{
    if (v->state != ST_OFF && v->state != ST_ABORTED) return -1;
    probe_host(a);                          /* the Domain Manager may have granted it since */
    if (!a->kvm_ok) {
        vm_note(v, "Cannot start: %s", a->kvm_errno == EACCES
                ? "virtualization is not enabled for this domain (Domain Manager > Permissions > Virtualization)"
                : "/dev/kvm is not available");
        return -1;
    }
    if (!a->have_ch) { vm_note(v, "Cannot start: %s is missing from this image", CH_PATH); return -1; }
    int restoring = v->restore_from >= 0 && v->restore_from < v->nsnap;
    if (!restoring && v->cfg.firmware[0]) {
        if (!file_readable(v->cfg.firmware)) {
            vm_note(v, "Cannot start: the UEFI firmware %s is not in this image", v->cfg.firmware);
            return -1;
        }
        if (!file_readable(v->cfg.diskimg)) {
            vm_note(v, "Cannot start: the disk %s is not there yet%s", v->cfg.diskimg,
                    v->cfg.os == OS_OPNSENSE ? " (it is downloaded after install when the firewall was chosen)" : "");
            return -1;
        }
    } else if (!restoring && !file_readable(v->cfg.kernel)) {
        vm_note(v, "Cannot start: kernel image %s is not readable", v->cfg.kernel);
        return -1;
    }
    mkdir(RUN_DIR, 0700);
    snprintf(v->api_path, sizeof v->api_path, "%s/vm%d.api", RUN_DIR, v->id);
    snprintf(v->serial_path, sizeof v->serial_path, "%s/vm%d.serial", RUN_DIR, v->id);
    unlink(v->api_path);
    unlink(v->serial_path);

    if (v->cfg.disk_mb > 0) {
        snprintf(v->disk_path, sizeof v->disk_path, "%s/vm%d-disk.img", RUN_DIR, v->id);
        struct stat st;
        if (stat(v->disk_path, &st) != 0 || st.st_size != (off_t)v->cfg.disk_mb * 1024 * 1024) {
            int fd = open(v->disk_path, O_RDWR | O_CREAT, 0600);
            if (fd < 0 || ftruncate(fd, (off_t)v->cfg.disk_mb * 1024 * 1024) != 0) {
                vm_note(v, "Cannot create the %d MB virtual disk: %s", v->cfg.disk_mb, strerror(errno));
                if (fd >= 0) close(fd);
                return -1;
            }
            close(fd);
        }
    } else v->disk_path[0] = 0;

    char mem[48], cpus[32], api[128], serial[128], disk[160], restore[180];
    snprintf(mem, sizeof mem, "size=%dM", v->cfg.mem_mb);
    snprintf(cpus, sizeof cpus, "boot=%d", v->cfg.cpus);
    snprintf(api, sizeof api, "path=%s", v->api_path);
    snprintf(serial, sizeof serial, "socket=%s", v->serial_path);
    snprintf(disk, sizeof disk, "path=%s,image_type=raw", v->disk_path);
    char img[240];
    {
        size_t il = strlen(v->cfg.diskimg);
        const int qcow = il > 6 && !strcmp(v->cfg.diskimg + il - 6, ".qcow2");
        snprintf(img, sizeof img, "path=%s,image_type=%s%s", v->cfg.diskimg, qcow ? "qcow2" : "raw",
                 v->cfg.disk_ro ? ",readonly=on" : "");
    }
    const char *argv[32];
    int ac = 0;
    argv[ac++] = CH_PATH;          /* no -v: at INFO it logs every unclaimed port access, and the
                                    * guest then runs at the speed of the log pipe */
    argv[ac++] = "--api-socket"; argv[ac++] = api;
    if (restoring) {
        snprintf(restore, sizeof restore, "source_url=file://%s", v->snaps[v->restore_from].path);
        argv[ac++] = "--restore"; argv[ac++] = restore;
    } else {
        if (v->cfg.firmware[0]) {
            argv[ac++] = "--firmware"; argv[ac++] = v->cfg.firmware;
            argv[ac++] = "--disk"; argv[ac++] = img;
        } else {
            argv[ac++] = "--kernel"; argv[ac++] = v->cfg.kernel;
            if (v->cfg.initrd[0]) { argv[ac++] = "--initramfs"; argv[ac++] = v->cfg.initrd; }
            if (v->cfg.cmdline[0]) { argv[ac++] = "--cmdline"; argv[ac++] = v->cfg.cmdline; }
        }
        argv[ac++] = "--cpus"; argv[ac++] = cpus;
        argv[ac++] = "--memory"; argv[ac++] = mem;
        argv[ac++] = "--serial"; argv[ac++] = serial;
        argv[ac++] = "--console"; argv[ac++] = "off";
        if (v->disk_path[0]) { argv[ac++] = "--disk"; argv[ac++] = disk; }
    }
    char net1[160], net2[160];
    if (!restoring) {
        if (v->cfg.os == OS_OPNSENSE) {                    /* vtnet0 = LAN, vtnet1 = WAN (live-mode order) */
            snprintf(net1, sizeof net1, "tap=" FW_LAN ",mac=52:54:00:a1:01:01," NET_OFFLOADS);
            snprintf(net2, sizeof net2, "tap=wan%d,mac=52:54:00:a0:00:%02x," NET_OFFLOADS, v->id, v->id & 0xff);
            argv[ac++] = "--net"; argv[ac++] = net1;
            argv[ac++] = "--net"; argv[ac++] = net2;
        } else if (v->cfg.net == NET_NAT) {
            snprintf(net1, sizeof net1, "tap=nat%d,mac=52:54:00:a0:01:%02x," NET_OFFLOADS, v->id, v->id & 0xff);
            argv[ac++] = "--net"; argv[ac++] = net1;
        } else if (v->cfg.net == NET_LAN) {
            snprintf(net1, sizeof net1, "tap=" FW_LAN ".%d,mac=52:54:00:a1:02:%02x," NET_OFFLOADS, v->id, v->id & 0xff);
            argv[ac++] = "--net"; argv[ac++] = net1;
        }
    }
    argv[ac++] = "--seccomp"; argv[ac++] = "false";
    argv[ac] = NULL;

    snprintf(v->log_path, sizeof v->log_path, "%s/vm%d.log", RUN_DIR, v->id);
    snprintf(v->state_path, sizeof v->state_path, "%s/vm%d.state", RUN_DIR, v->id);
    int logw = open(v->log_path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0600);
    if (logw < 0) { vm_note(v, "Cannot start: %s: %s", v->log_path, strerror(errno)); return -1; }
    term_reset(&v->con);
    char cmd[640]; size_t cl = 0;
    for (int i = 0; i < ac && cl < sizeof cmd - 2; i++)
        cl += (size_t)snprintf(cmd + cl, sizeof cmd - cl, "%s%s", i ? " " : "", argv[i]);
    vm_note(v, "Starting: %s", cmd);

    pid_t pid = fork();
    if (pid < 0) { close(logw); vm_note(v, "Cannot start: fork: %s", strerror(errno)); return -1; }
    if (pid == 0) {
        /* The VMM writes to a file, not a pipe to this window: it keeps running (headless) when
         * Virtual Machines is closed, and a relaunch tails the same log. */
        int nul = open("/dev/null", O_RDWR);
        if (nul >= 0) dup2(nul, 0);
        dup2(logw, 1);
        dup2(logw, 2);
        /* This kernel has no close-on-exec: close everything else (the Wayland socket included) so
         * the VMM holds nothing of the manager's. */
        for (int fd = 3; fd < 256; fd++) close(fd);
        execve(CH_PATH, (char *const *)argv, environ);
        _exit(127);
    }
    close(logw);
    v->log_fd = open(v->log_path, O_RDONLY);
    v->pid = pid;
    v->child = 1;
    v->state = ST_STARTING;
    v->started = time(NULL);
    v->connect_tries = 0;
    v->exit_status = 0;
    vm_write_state(v);
    return 0;
}

/* The VMM process ended (guest powered off, Power Off, or a failure). */
static void vm_exited(struct vm *v, int status)
{
    vm_close_fds(v);
    v->pid = 0;
    v->child = 0;
    unlink(v->api_path);
    unlink(v->serial_path);
    vm_drop_state(v);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    v->exit_status = code;
    int was = v->state;
    v->state = (code == 0 || was == ST_STOPPING) ? ST_OFF : ST_ABORTED;
    if (v->state == ST_OFF) vm_note(v, "Powered off (the VMM exited cleanly)");
    else vm_note(v, "The VMM exited with status %d -- see the Log tab", code);
    v->restore_from = -1;
    term_puts(&v->con, "\r\n\033[90m-- machine powered off --\033[0m\r\n");
}

static void vm_action(struct app *a, struct vm *v, int action)
{
    char resp[512];
    int st;
    switch (action) {
    case A_PAUSE:
        if (v->state == ST_RUNNING) {
            st = api_call(v, "PUT", "vm.pause", NULL, resp, sizeof resp, 4000);
            if (st >= 200 && st < 300) { v->state = ST_PAUSED; vm_note(v, "Paused"); }
            else vm_note(v, "Pause failed (HTTP %d) %s", st, resp);
        } else if (v->state == ST_PAUSED) {
            st = api_call(v, "PUT", "vm.resume", NULL, resp, sizeof resp, 4000);
            if (st >= 200 && st < 300) { v->state = ST_RUNNING; vm_note(v, "Resumed"); }
            else vm_note(v, "Resume failed (HTTP %d) %s", st, resp);
        }
        break;
    case A_RESET:
        st = api_call(v, "PUT", "vm.reboot", NULL, resp, sizeof resp, 6000);
        if (st >= 200 && st < 300) {
            vm_note(v, "Reset");
            term_puts(&v->con, "\r\n\033[90m-- reset --\033[0m\r\n");
        } else vm_note(v, "Reset failed (HTTP %d) %s", st, resp);
        break;
    case A_ACPI:
        st = api_call(v, "PUT", "vm.power-button", NULL, resp, sizeof resp, 4000);
        if (st >= 200 && st < 300) vm_note(v, "ACPI shutdown signal sent (the guest decides what to do)");
        else vm_note(v, "ACPI shutdown failed (HTTP %d) %s", st, resp);
        break;
    case A_POWEROFF:
        v->state = ST_STOPPING;
        st = api_call(v, "PUT", "vmm.shutdown", NULL, resp, sizeof resp, 3000);
        if (!(st >= 200 && st < 300) && v->pid > 0) kill(v->pid, SIGKILL);
        vm_note(v, "Power off requested");
        break;
    case A_SNAPSHOT: {
        if (v->nsnap >= (int)(sizeof v->snaps / sizeof v->snaps[0])) { vm_note(v, "Snapshot limit reached"); break; }
        struct snap *s = &v->snaps[v->nsnap];
        snprintf(s->path, sizeof s->path, "%s/vm%d-snap%d", RUN_DIR, v->id, v->nsnap + 1);
        snprintf(s->name, sizeof s->name, "Snapshot %d", v->nsnap + 1);
        mkdir(s->path, 0700);
        int was_running = v->state == ST_RUNNING;
        if (was_running && api_call(v, "PUT", "vm.pause", NULL, resp, sizeof resp, 4000) / 100 != 2) {
            vm_note(v, "Snapshot: could not pause the machine (%s)", resp); break;
        }
        char body[200];
        snprintf(body, sizeof body, "{\"destination_url\":\"file://%s\"}", s->path);
        st = api_call(v, "PUT", "vm.snapshot", body, resp, sizeof resp, 60000);
        if (was_running) api_call(v, "PUT", "vm.resume", NULL, NULL, 0, 4000);
        if (st >= 200 && st < 300) {
            s->when = time(NULL);
            v->nsnap++;
            vm_note(v, "Took %s (%s)", s->name, s->path);
        } else vm_note(v, "Snapshot failed (HTTP %d) %s", st, resp);
        break;
    }
    default: break;
    }
    (void)a;
}

/* Service one machine's fds + process each tick. */
static void vm_poll(struct app *a, struct vm *v)
{
    if (!v->used || v->pid <= 0) return;
    char buf[8192];
    if (v->log_fd >= 0)
        for (int k = 0; k < 16; k++) {
            ssize_t r = read(v->log_fd, buf, sizeof buf);
            if (r <= 0) break;
            term_feed(&v->log, (unsigned char *)buf, (size_t)r, -1);
            a->dirty = 1;
        }
    if (v->serial_fd < 0 && (v->state == ST_STARTING || v->state == ST_RUNNING) && time(NULL) >= v->reconnect_at) {
        int fd = unix_connect(v->serial_path);
        if (fd >= 0) {
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
            v->serial_fd = fd;
            if (v->state == ST_STARTING) {
                v->state = ST_RUNNING;
                vm_note(v, "Running (serial console connected)");
                if (v->restore_from >= 0) {
                    char resp[256];
                    int st = api_call(v, "PUT", "vm.resume", NULL, resp, sizeof resp, 4000);
                    vm_note(v, st / 100 == 2 ? "Restored %s and resumed" : "Restored %s (resume failed)",
                            v->snaps[v->restore_from].name);
                    v->restore_from = -1;
                }
                if (a->tab == TAB_DETAILS && a->sel >= 0 && &a->vms[a->sel] == v) a->tab = TAB_CONSOLE;
            }
            a->dirty = 1;
        } else if (++v->connect_tries == 200) {
            vm_note(v, "The serial console has not appeared after 20 s (still trying)");
        }
    }
    if (v->serial_fd >= 0)
        for (int k = 0; k < 16; k++) {
            ssize_t r = read(v->serial_fd, buf, sizeof buf);
            if (r == 0) {                                  /* the VMM closed the console */
                close(v->serial_fd); v->serial_fd = -1;
                v->reconnect_at = time(NULL) + 1;
                vm_note(v, "The serial console closed; reconnecting");
                break;
            }
            if (r < 0) break;
            v->serial_bytes += r;
            term_feed(&v->con, (unsigned char *)buf, (size_t)r, v->serial_fd);
            a->dirty = 1;
        }
    int status = 0;
    if (v->child) {
        pid_t w = waitpid(v->pid, &status, WNOHANG);
        if (w == v->pid) { vm_exited(v, status); a->dirty = 1; }
    } else if (time(NULL) >= v->next_alive_check) {
        /* re-attached: not our child, so no waitpid -- the process and its API socket must both
         * still be there (an exited, unreaped VMM still answers kill(pid, 0)) */
        v->next_alive_check = time(NULL) + 2;
        int fd = unix_connect(v->api_path);
        if (fd >= 0) close(fd);
        if (fd < 0 || (kill(v->pid, 0) != 0 && errno == ESRCH)) {
            vm_exited(v, v->state == ST_STOPPING ? 0 : (1 << 8));
            a->dirty = 1;
        }
    }
}

/* ── machines ──────────────────────────────────────────────────────────────────────────── */
static void cfg_defaults(struct app *a, struct vmcfg *c, int os)
{
    memset(c, 0, sizeof *c);
    c->os = os;
    c->mem_mb = 128;
    c->cpus = 1;
    c->net = NET_NAT;
    if (os == OS_OPNSENSE) {
        const char *d = opnsense_disk();
        copy_str(c->firmware, sizeof c->firmware, FIRMWARE_PATH);
        copy_str(c->diskimg, sizeof c->diskimg, d ? d : OPNSENSE_DISK);
        c->disk_ro = 1;              /* live mode: the root is mounted read-only, config in memory */
        c->mem_mb = 1024;
        copy_str(c->desc, sizeof c->desc, "OPNsense 26.7 firewall, verified release image (live mode)");
    } else if (os == OS_ALPINE) {
        copy_str(c->kernel, sizeof c->kernel, BUNDLED_KERNEL);
        copy_str(c->initrd, sizeof c->initrd, BUNDLED_INITRD);
        copy_str(c->cmdline, sizeof c->cmdline, BUNDLED_CMDLINE);
        copy_str(c->desc, sizeof c->desc, "Alpine Linux linux-virt 6.6 with a busybox userland");
    } else {
        copy_str(c->cmdline, sizeof c->cmdline, "console=ttyS0");
    }
    int n = 1;
    for (;;) {
        char nm[48];
        const char *base = os == OS_ALPINE ? "Alpine Linux" : os == OS_OPNSENSE ? "OPNsense Firewall" : "Linux VM";
        snprintf(nm, sizeof nm, "%s", base);
        if (n > 1) snprintf(nm, sizeof nm, "%s %d", base, n);
        int clash = 0;
        for (int i = 0; i < MAX_VMS; i++) if (a->vms[i].used && !strcmp(a->vms[i].cfg.name, nm)) clash = 1;
        if (!clash) { copy_str(c->name, sizeof c->name, nm); break; }
        n++;
    }
}

static int vm_add(struct app *a, const struct vmcfg *c)
{
    for (int i = 0; i < MAX_VMS; i++) {
        struct vm *v = &a->vms[i];
        if (v->used) continue;
        struct term con = v->con, log = v->log;
        memset(v, 0, sizeof *v);
        v->con = con; v->log = log;
        if (!v->con.ch && term_init(&v->con) < 0) return -1;
        if (!v->log.ch && term_init(&v->log) < 0) return -1;
        term_reset(&v->con); term_reset(&v->log);
        v->log.lf_is_crlf = 1;
        v->used = 1;
        v->id = ++a->next_id;
        v->cfg = *c;
        v->serial_fd = v->log_fd = -1;
        v->restore_from = -1;
        term_puts(&v->con, "\033[90mThe machine is powered off.  Start it to see its serial console here.\033[0m\r\n");
        return i;
    }
    return -1;
}

static void vm_remove(struct app *a, int idx)
{
    struct vm *v = &a->vms[idx];
    if (v->pid > 0) { kill(v->pid, SIGKILL); waitpid(v->pid, NULL, 0); vm_close_fds(v); }
    if (v->disk_path[0]) unlink(v->disk_path);
    v->used = 0;
    if (a->sel == idx) {
        a->sel = -1;
        for (int i = 0; i < MAX_VMS; i++) if (a->vms[i].used) { a->sel = i; break; }
    }
}

static struct vm *cur_vm(struct app *a) { return (a->sel >= 0 && a->vms[a->sel].used) ? &a->vms[a->sel] : NULL; }

/* ── dialogs ───────────────────────────────────────────────────────────────────────────── */
static char *dlg_field(struct app *a, int f, size_t *cap)
{
    struct vmcfg *c = &a->dlg.cfg;
    switch (f) {
    case FLD_NAME: *cap = sizeof c->name; return c->name;
    case FLD_KERNEL: *cap = sizeof c->kernel; return c->kernel;
    case FLD_INITRD: *cap = sizeof c->initrd; return c->initrd;
    case FLD_CMDLINE: *cap = sizeof c->cmdline; return c->cmdline;
    case FLD_DESC: *cap = sizeof c->desc; return c->desc;
    }
    *cap = 0; return NULL;
}

static void dlg_open_new(struct app *a)
{
    memset(&a->dlg, 0, sizeof a->dlg);
    a->dlg.kind = DLG_NEW;
    a->dlg.focus = FLD_NAME;
    cfg_defaults(a, &a->dlg.cfg, a->have_bundled ? OS_ALPINE : OS_CUSTOM);
}
static void dlg_open_settings(struct app *a)
{
    struct vm *v = cur_vm(a);
    if (!v) return;
    memset(&a->dlg, 0, sizeof a->dlg);
    a->dlg.kind = DLG_SETTINGS;
    a->dlg.cfg = v->cfg;
    a->dlg.target = a->sel;
    a->dlg.focus = FLD_NAME;
}

static int dlg_validate(struct app *a)
{
    struct vmcfg *c = &a->dlg.cfg;
    a->dlg.err[0] = 0;
    if (!c->name[0]) { copy_str(a->dlg.err, sizeof a->dlg.err, "The machine needs a name."); return 0; }
    for (int i = 0; i < MAX_VMS; i++)
        if (a->vms[i].used && !strcmp(a->vms[i].cfg.name, c->name)
            && !(a->dlg.kind == DLG_SETTINGS && i == a->dlg.target)) {
            copy_str(a->dlg.err, sizeof a->dlg.err, "A machine with that name already exists.");
            return 0;
        }
    if (!c->kernel[0]) { copy_str(a->dlg.err, sizeof a->dlg.err, "Choose a kernel image to boot."); return 0; }
    return 1;
}

static void dlg_finish(struct app *a)
{
    if (!dlg_validate(a)) return;
    if (a->dlg.kind == DLG_NEW) {
        int i = vm_add(a, &a->dlg.cfg);
        if (i < 0) { copy_str(a->dlg.err, sizeof a->dlg.err, "No room for another machine."); return; }
        a->sel = i; a->view = VIEW_MACHINE; a->tab = TAB_DETAILS;
        set_banner(a, 1, "Created \"%s\"", a->dlg.cfg.name);
    } else if (a->dlg.kind == DLG_SETTINGS) {
        struct vm *v = &a->vms[a->dlg.target];
        if (v->cfg.disk_mb != a->dlg.cfg.disk_mb && v->disk_path[0]) { unlink(v->disk_path); v->disk_path[0] = 0; }
        if (v->cfg.autostart != a->dlg.cfg.autostart || strcmp(v->cfg.name, a->dlg.cfg.name)) {
            autostart_set(v->cfg.name, 0);
            autostart_set(a->dlg.cfg.name, a->dlg.cfg.autostart);
        }
        v->cfg = a->dlg.cfg;
        if (v->pid > 0) vm_write_state(v);
        set_banner(a, 1, "Saved the settings of \"%s\"", v->cfg.name);
    }
    a->dlg.kind = DLG_NONE;
}

static void dlg_step(struct app *a, int which, int dir)
{
    struct vmcfg *c = &a->dlg.cfg;
    if (which == STEP_MEM) {
        c->mem_mb += dir * (c->mem_mb >= 512 ? 128 : 64);
        if (c->mem_mb < 64) c->mem_mb = 64;
        if (c->mem_mb > 2048) c->mem_mb = 2048;
    } else if (which == STEP_CPU) {
        c->cpus = 1;                         /* one vCPU until the hypervisor starts APs (INIT/SIPI) */
    } else if (which == STEP_DISK) {
        c->disk_mb += dir * 8;
        if (c->disk_mb < 0) c->disk_mb = 0;
        if (c->disk_mb > 64) c->disk_mb = 64;
    }
}

/* ── drawing: shared widgets ───────────────────────────────────────────────────────────── */
static void button(struct app *a, int x, int y, int w, int h, const char *label, int primary, int enabled,
                   int action, int arg)
{
    int hover = enabled && ptr_in(a, x, y, w, h);
    uint32_t bg = !enabled ? 0x1c242cu : primary ? (hover ? C_ACCENT2 : C_ACCENT) : (hover ? 0x2c3945u : 0x243039u);
    rfill(a, x, y, w, h, 7, bg);
    text_center(a, F_BOLD, 12, x, y + (h - 16) / 2, w, enabled ? 0xffffff : C_FAINT, label);
    if (enabled) hit_add(a, x, y, w, h, action, arg);
}

static void text_field(struct app *a, int x, int y, int w, int fld, const char *label)
{
    size_t cap;
    char *s = dlg_field(a, fld, &cap);
    text(a, F_REG, 11, x, y, w, C_DIM, label);
    int focused = a->dlg.focus == fld;
    rfill(a, x, y + 17, w, 30, 6, 0x10161bu);
    rstroke(a, x, y + 17, w, 30, 6, focused ? C_ACCENT2 : C_LINE, focused ? 2 : 1);
    int tw = text_width(a, F_REG, s, 13);
    int shown_x = x + 10;
    if (focused && tw > w - 24) shown_x = x + 10 - (tw - (w - 24));  /* keep the caret end visible */
    g_clip_x0 = x + 4; g_clip_x1 = x + w - 4;
    text(a, F_REG, 13, shown_x, y + 24, 4096, C_TEXT, s);
    if (focused) fill(a, shown_x + tw + 1, y + 23, 2, 18, C_ACCENT2);
    g_clip_x0 = 0; g_clip_x1 = 1 << 30;
    hit_add(a, x, y + 17, w, 30, A_DLG_FIELD, fld);
}

static void stepper(struct app *a, int x, int y, const char *label, const char *value, int which, int enabled)
{
    text(a, F_REG, 11, x, y, 260, C_DIM, label);
    rfill(a, x, y + 17, 150, 30, 6, 0x10161bu);
    rstroke(a, x, y + 17, 150, 30, 6, C_LINE, 1);
    text_center(a, F_BOLD, 13, x, y + 24, 110, enabled ? C_TEXT : C_FAINT, value);
    for (int d = 0; d < 2; d++) {
        int bx = x + 150 + 6 + d * 36;
        int hover = enabled && ptr_in(a, bx, y + 17, 30, 30);
        rfill(a, bx, y + 17, 30, 30, 6, !enabled ? 0x1c242cu : hover ? 0x2c3945u : 0x243039u);
        text_center(a, F_BOLD, 16, bx, y + 21, 30, enabled ? C_TEXT : C_FAINT, d ? "+" : "-");
        if (enabled) hit_add(a, bx, y + 17, 30, 30, A_DLG_STEP, which * 2 + d);
    }
}

static void checkbox(struct app *a, int x, int y, int w, int on, const char *label, const char *sub, int arg)
{
    int hover = ptr_in(a, x, y, w, 40);
    rfill(a, x, y + 2, 20, 20, 5, on ? C_ACCENT : 0x10161bu);
    rstroke(a, x, y + 2, 20, 20, 5, on ? C_ACCENT2 : hover ? C_DIM : C_LINE, 1.5);
    if (on) {
        cairo_set_line_width(a->cr, 2.2); set_rgb(a->cr, 0xffffffu);
        cairo_move_to(a->cr, x + 5, y + 12); cairo_line_to(a->cr, x + 9, y + 16); cairo_line_to(a->cr, x + 16, y + 7);
        cairo_stroke(a->cr);
    }
    text(a, F_REG, 13, x + 30, y + 3, w - 30, C_TEXT, label);
    if (sub) text_wrap(a, F_REG, 11, x + 30, y + 22, w - 30, 15, 3, C_DIM, sub);
    hit_add(a, x, y, w, 40, A_DLG_TOGGLE, arg);
}

static void choice_card(struct app *a, int x, int y, int w, int h, int os, const char *title,
                        const char *sub, int selected, int enabled, int arg)
{
    int hover = enabled && ptr_in(a, x, y, w, h);
    rfill(a, x, y, w, h, 8, selected ? C_SEL : hover ? 0x1d2830u : C_CARD);
    rstroke(a, x, y, w, h, 8, selected ? C_ACCENT2 : C_LINE, selected ? 2 : 1);
    os_badge(a, os, x + 14, y + (h - 38) / 2, 38);
    text(a, F_BOLD, 13, x + 64, y + 14, w - 76, enabled ? C_TEXT : C_FAINT, title);
    text_wrap(a, F_REG, 11, x + 64, y + 34, w - 76, 15, 2, enabled ? C_DIM : C_FAINT, sub);
    if (enabled) hit_add(a, x, y, w, h, A_DLG_CHOICE, arg);
}

/* ── drawing: dialogs ──────────────────────────────────────────────────────────────────── */
static void draw_os_page(struct app *a, int x, int y, int w)
{
    struct vmcfg *c = &a->dlg.cfg;
    text_field(a, x, y, w, FLD_NAME, "Name");
    y += 62;
    text(a, F_REG, 11, x, y, w, C_DIM, "Operating system");
    y += 18;
    int cw = (w - 24) / 3;
    choice_card(a, x, y, cw, 76, OS_ALPINE, "Alpine Linux 3.19 (bundled)",
                a->have_bundled ? "linux-virt 6.6 and a busybox shell, included with this system"
                                : "not included in this image (tests/vmm/linux-guest/build.sh)",
                c->os == OS_ALPINE, a->have_bundled, OS_ALPINE);
    choice_card(a, x + cw + 12, y, cw, 76, OS_CUSTOM, "Other Linux kernel",
                "boot any bzImage / vmlinux, with an optional initramfs", c->os == OS_CUSTOM, 1, OS_CUSTOM);
    choice_card(a, x + 2 * (cw + 12), y, cw, 76, OS_OPNSENSE, "OPNsense firewall",
                opnsense_disk() ? "the verified OPNsense 26.7 image on this system"
                                : "choose it in the installer: it is downloaded after install",
                c->os == OS_OPNSENSE, opnsense_disk() != NULL, OS_OPNSENSE);
    y += 92;
    if (c->os == OS_CUSTOM) {
        text_field(a, x, y, w, FLD_KERNEL, "Kernel image (bzImage or ELF vmlinux)");
        y += 58;
        text_field(a, x, y, w, FLD_INITRD, "Initial ramdisk (optional)");
        y += 58;
        text_field(a, x, y, w, FLD_CMDLINE, "Kernel command line");
    } else if (c->os == OS_OPNSENSE) {
        text_wrap(a, F_REG, 12, x, y, w, 17, 5, C_DIM,
                  "OPNsense boots from UEFI in live mode on its serial console (the Console tab).  Its first "
                  "network card is the LAN every routed domain joins (192.168.1.1), the second its WAN.  "
                  "Log in as root / opnsense.");
    } else {
        text_wrap(a, F_REG, 12, x, y, w, 17, 4, C_DIM,
                  "The guest boots Alpine's linux-virt kernel straight into a busybox shell on its serial "
                  "port.  The Console tab is that serial port: type into it once the machine is running.");
    }
}

static void draw_hw_page(struct app *a, int x, int y, int w)
{
    struct vmcfg *c = &a->dlg.cfg;
    char v[48];
    snprintf(v, sizeof v, "%d MB", c->mem_mb);
    stepper(a, x, y, "Base memory", v, STEP_MEM, 1);
    y += 64;
    snprintf(v, sizeof v, "%d", c->cpus);
    stepper(a, x, y, "Processors", v, STEP_CPU, 0);
    text_wrap(a, F_REG, 11, x + 240, y + 20, w - 240, 15, 2, C_FAINT,
              "One vCPU: the hypervisor does not start secondary processors yet.");
    y += 70;
    text_wrap(a, F_REG, 12, x, y, w, 17, 3, C_DIM,
              "Memory comes from this computer's RAM while the machine runs.  128 MB is plenty for the "
              "bundled guest.");
}

static void draw_disk_page(struct app *a, int x, int y, int w)
{
    struct vmcfg *c = &a->dlg.cfg;
    char v[48];
    if (c->disk_mb) snprintf(v, sizeof v, "%d MB", c->disk_mb); else snprintf(v, sizeof v, "None");
    stepper(a, x, y, "Virtual hard disk (virtio-blk, a raw image in RAM)", v, STEP_DISK, 1);
    y += 70;
    text_wrap(a, F_REG, 12, x, y, w, 17, 4, C_DIM,
              "The disk is a raw image the guest sees as /dev/vda.  Like everything on the live system it "
              "lasts until you remove the machine or shut the computer down.");
}

static void summary_row(struct app *a, int x, int *y, int w, const char *k, const char *v)
{
    text(a, F_REG, 12, x, *y, 150, C_DIM, k);
    text(a, F_REG, 12, x + 150, *y, w - 150, C_TEXT, v);
    *y += 22;
}

static void draw_summary_page(struct app *a, int x, int y, int w)
{
    struct vmcfg *c = &a->dlg.cfg;
    char v[200];
    summary_row(a, x, &y, w, "Name", c->name);
    summary_row(a, x, &y, w, "Type", os_name(c->os));
    summary_row(a, x, &y, w, "Kernel", c->kernel[0] ? c->kernel : "(none chosen)");
    summary_row(a, x, &y, w, "Initial ramdisk", c->initrd[0] ? c->initrd : "none");
    summary_row(a, x, &y, w, "Command line", c->cmdline);
    snprintf(v, sizeof v, "%d MB", c->mem_mb);
    summary_row(a, x, &y, w, "Base memory", v);
    snprintf(v, sizeof v, "%d", c->cpus);
    summary_row(a, x, &y, w, "Processors", v);
    if (c->disk_mb) snprintf(v, sizeof v, "%d MB raw image (virtio-blk)", c->disk_mb); else snprintf(v, sizeof v, "none");
    summary_row(a, x, &y, w, "Hard disk", v);
    summary_row(a, x, &y, w, "Serial port", "COM1, connected to the Console tab");
    summary_row(a, x, &y, w, "Network", c->os == OS_OPNSENSE ? "LAN " FW_LAN " + WAN via NAT" : k_net_name[c->net]);
}

static void draw_dialog(struct app *a)
{
    struct dialog *d = &a->dlg;
    cairo_set_source_rgba(a->cr, 0, 0, 0, 0.55);
    cairo_rectangle(a->cr, 0, 0, a->width, a->height);
    cairo_fill(a->cr);
    hit_add(a, 0, 0, a->width, a->height, A_NONE, 0);        /* modal: swallow clicks outside */

    if (d->kind == DLG_DELETE) {
        int w = 460, h = 190, x = (a->width - w) / 2, y = (a->height - h) / 2;
        rfill(a, x, y, w, h, 12, C_PANEL);
        rstroke(a, x, y, w, h, 12, C_LINE, 1);
        struct vm *v = &a->vms[d->target];
        textf(a, F_BOLD, 16, x + 24, y + 22, w - 48, C_TEXT, "Remove \"%s\"?", v->cfg.name);
        text_wrap(a, F_REG, 12, x + 24, y + 56, w - 48, 17, 4, C_DIM,
                  v->pid > 0 ? "The machine is running: it will be powered off first.  Its virtual disk and "
                               "snapshots are deleted too."
                             : "Its virtual disk and snapshots are deleted too.");
        button(a, x + w - 24 - 110, y + h - 54, 110, 34, "Remove", 1, 1, A_DLG_DELETE_OK, 0);
        button(a, x + w - 24 - 230, y + h - 54, 110, 34, "Cancel", 0, 1, A_DLG_CANCEL, 0);
        return;
    }

    int w = 720, h = 500;
    if (w > a->width - 40) w = a->width - 40;
    int x = (a->width - w) / 2, y = (a->height - h) / 2;
    rfill(a, x, y, w, h, 12, C_PANEL);
    rstroke(a, x, y, w, h, 12, C_LINE, 1);

    if (d->kind == DLG_NEW) {
        static const char *const titles[4] = { "Name and operating system", "Hardware", "Virtual hard disk",
                                               "Summary" };
        text(a, F_BOLD, 17, x + 26, y + 20, w - 52, C_TEXT, "Create Virtual Machine");
        textf(a, F_REG, 12, x + 26, y + 46, w - 52, C_DIM, "Step %d of 4 - %s", d->page + 1, titles[d->page]);
        for (int i = 0; i < 4; i++)                           /* progress pips */
            rfill(a, x + w - 26 - (4 - i) * 26, y + 28, 20, 5, 2, i <= d->page ? C_ACCENT2 : C_LINE);
        line(a, x, y + 72, x + w, y + 72, C_LINE, 1);
        int cx = x + 26, cy = y + 92, cw = w - 52;
        switch (d->page) {
        case 0: draw_os_page(a, cx, cy, cw); break;
        case 1: draw_hw_page(a, cx, cy, cw); break;
        case 2: draw_disk_page(a, cx, cy, cw); break;
        case 3: draw_summary_page(a, cx, cy, cw); break;
        }
        if (d->err[0]) text(a, F_REG, 12, x + 26, y + h - 84, w - 52, C_RED, d->err);
        button(a, x + w - 26 - 120, y + h - 56, 120, 36, d->page == 3 ? "Finish" : "Next", 1, 1,
               d->page == 3 ? A_DLG_OK : A_DLG_NEXT, 0);
        button(a, x + w - 26 - 250, y + h - 56, 120, 36, "Back", 0, d->page > 0, A_DLG_BACK, 0);
        button(a, x + 26, y + h - 56, 110, 36, "Cancel", 0, 1, A_DLG_CANCEL, 0);
        return;
    }

    /* Settings: a section list on the left, the section's fields on the right (VirtualBox layout). */
    textf(a, F_BOLD, 17, x + 26, y + 20, w - 52, C_TEXT, "%s - Settings", a->vms[d->target].cfg.name);
    line(a, x, y + 58, x + w, y + 58, C_LINE, 1);
    int running = a->vms[d->target].pid > 0;
    for (int i = 0; i < SEC_COUNT; i++) {
        int sy = y + 72 + i * 38;
        int on = d->section == i;
        if (on) rfill(a, x + 12, sy, 160, 32, 7, C_SEL);
        else if (ptr_in(a, x + 12, sy, 160, 32)) rfill(a, x + 12, sy, 160, 32, 7, 0x1a242cu);
        text(a, on ? F_BOLD : F_REG, 13, x + 26, sy + 8, 140, on ? C_TEXT : C_DIM, k_sec_name[i]);
        hit_add(a, x + 12, sy, 160, 32, A_DLG_SECTION, i);
    }
    line(a, x + 184, y + 58, x + 184, y + h - 72, C_LINE, 1);
    int cx = x + 204, cy = y + 76, cw = w - 204 - 26;
    struct vmcfg *c = &d->cfg;
    char v[64];
    switch (d->section) {
    case SEC_GENERAL:
        text_field(a, cx, cy, cw, FLD_NAME, "Name");
        text_field(a, cx, cy + 62, cw, FLD_DESC, "Description");
        textf(a, F_REG, 12, cx, cy + 132, cw, C_DIM, "Type: %s",
              os_name(c->os));
        checkbox(a, cx, cy + 166, cw, c->autostart, "Start automatically when anonymOS boots (headless)",
                 "The machine runs with no window: closing Virtual Machines never stops it.  Open this "
                 "app any time to reach its console.", 0);
        break;
    case SEC_SYSTEM:
        snprintf(v, sizeof v, "%d MB", c->mem_mb);
        stepper(a, cx, cy, "Base memory", v, STEP_MEM, !running);
        snprintf(v, sizeof v, "%d", c->cpus);
        stepper(a, cx, cy + 62, "Processors", v, STEP_CPU, 0);
        text_field(a, cx, cy + 124, cw, FLD_KERNEL, "Kernel image");
        text_field(a, cx, cy + 182, cw, FLD_INITRD, "Initial ramdisk");
        text_field(a, cx, cy + 240, cw, FLD_CMDLINE, "Kernel command line");
        break;
    case SEC_STORAGE:
        if (c->disk_mb) snprintf(v, sizeof v, "%d MB", c->disk_mb); else snprintf(v, sizeof v, "None");
        stepper(a, cx, cy, "Virtual hard disk (virtio-blk)", v, STEP_DISK, !running);
        text_wrap(a, F_REG, 12, cx, cy + 66, cw, 17, 4, C_DIM,
                  "A raw image in RAM (/tmp/vms), attached as /dev/vda.  Changing its size replaces it.");
        break;
    case SEC_NETWORK:
        if (c->os == OS_OPNSENSE) {
            text(a, F_BOLD, 13, cx, cy, cw, C_TEXT, "Adapter 1: LAN (" FW_LAN ", 192.168.1.1)");
            text(a, F_BOLD, 13, cx, cy + 26, cw, C_TEXT, "Adapter 2: WAN (NAT through the host network, DHCP)");
            text_wrap(a, F_REG, 12, cx, cy + 56, cw, 17, 5, C_DIM,
                      "Domains routed through this firewall in the Domain Manager (Network tab) join its LAN; "
                      "machines set to \"Behind the OPNsense firewall\" too.  Its web interface is "
                      "https://192.168.1.1 from any of them.");
        } else {
            for (int i = 0; i < 3; i++) {
                checkbox(a, cx, cy + i * 48, cw, c->net == i, k_net_name[i],
                         i == NET_NONE ? "no network card" : i == NET_NAT ? "virtio-net on the uplink: a DHCP address in 10.77.0.0/24, NAT out"
                                       : "virtio-net on the firewall's LAN: DHCP from OPNsense, filtered by it", 10 + i);
            }
            text_wrap(a, F_REG, 11, cx, cy + 156, cw, 15, 3, C_FAINT,
                      "Adapter type: virtio-net (paravirtualized), offloads off.");
        }
        break;
    case SEC_SERIAL:
        text(a, F_BOLD, 13, cx, cy, cw, C_TEXT, "Port 1 (COM1, 0x3F8, IRQ 4)");
        text_wrap(a, F_REG, 12, cx, cy + 26, cw, 17, 5, C_DIM,
                  "Connected to this window's Console tab through the VMM's serial socket.  Boot the kernel "
                  "with console=ttyS0 to use it as the machine's terminal.");
        break;
    case SEC_DISPLAY:
        text(a, F_BOLD, 13, cx, cy, cw, C_TEXT, "Graphics controller: none (serial console)");
        text_wrap(a, F_REG, 12, cx, cy + 26, cw, 17, 6, C_DIM,
                  "Cloud Hypervisor has no display device of its own.  The VirtualBox graphics adapter and "
                  "VMMDev (the devices the guest's vboxvideo and vboxguest drivers drive) are the next step "
                  "for an integrated desktop.");
        break;
    }
    if (running)
        text(a, F_REG, 11, cx, y + h - 92, cw, C_YELLOW,
             "The machine is running: hardware changes apply the next time it starts.");
    if (d->err[0]) text(a, F_REG, 12, x + 26, y + h - 72, w - 52, C_RED, d->err);
    button(a, x + w - 26 - 110, y + h - 52, 110, 34, "OK", 1, 1, A_DLG_OK, 0);
    button(a, x + w - 26 - 230, y + h - 52, 110, 34, "Cancel", 0, 1, A_DLG_CANCEL, 0);
}

/* ── drawing: main window ──────────────────────────────────────────────────────────────── */
static void tool_button(struct app *a, int *x, int ic, const char *label, int enabled, int action,
                        uint32_t tint)
{
    int w = text_width(a, F_REG, label, 11) + 22;
    if (w < 62) w = 62;
    int y = TOOLBAR_Y + 4, h = TOOLBAR_H - 8;
    int hover = enabled && ptr_in(a, *x, y, w, h);
    if (hover) rfill(a, *x, y, w, h, 8, 0x1d2831u);
    icon(a, ic, *x + (w - 26) / 2, y + 5, 26, enabled ? tint : 0x3a4550u);
    text_center(a, F_REG, 11, *x, y + 36, w, enabled ? C_TEXT : C_FAINT, label);
    if (enabled) hit_add(a, *x, y, w, h, action, 0);
    *x += w + 2;
}

static void draw_toolbar(struct app *a)
{
    fill(a, 0, TOOLBAR_Y, a->width, TOOLBAR_H, C_BAR);
    line(a, 0, TOOLBAR_Y + TOOLBAR_H - 0.5, a->width, TOOLBAR_Y + TOOLBAR_H - 0.5, C_LINE, 1);
    struct vm *v = a->view == VIEW_MACHINE ? cur_vm(a) : NULL;
    int st = v ? v->state : -1;
    int off = v && (st == ST_OFF || st == ST_ABORTED);
    int live = v && (st == ST_RUNNING || st == ST_PAUSED);
    int x = SIDEBAR_W + 12;
    tool_button(a, &x, IC_NEW, "New", 1, A_NEW, C_BLUE);
    tool_button(a, &x, IC_SETTINGS, "Settings", v != NULL, A_SETTINGS, 0xc8d2dfu);
    tool_button(a, &x, IC_DELETE, "Remove", v != NULL, A_DELETE, 0xc8d2dfu);
    line(a, x + 6, TOOLBAR_Y + 14, x + 6, TOOLBAR_Y + TOOLBAR_H - 14, C_LINE, 1);
    x += 14;
    tool_button(a, &x, IC_START, "Start", off, A_START, C_GREEN);
    tool_button(a, &x, st == ST_PAUSED ? IC_RESUME : IC_PAUSE, st == ST_PAUSED ? "Resume" : "Pause", live,
                A_PAUSE, C_YELLOW);
    tool_button(a, &x, IC_RESET, "Reset", st == ST_RUNNING, A_RESET, 0xc8d2dfu);
    tool_button(a, &x, IC_ACPI, "ACPI Shutdown", st == ST_RUNNING, A_ACPI, 0xc8d2dfu);
    tool_button(a, &x, IC_POWEROFF, "Power Off", live || st == ST_STARTING, A_POWEROFF, C_RED);
    line(a, x + 6, TOOLBAR_Y + 14, x + 6, TOOLBAR_Y + TOOLBAR_H - 14, C_LINE, 1);
    x += 14;
    tool_button(a, &x, IC_SNAPSHOT, "Snapshot", live, A_SNAPSHOT, 0xc8d2dfu);
}

static void draw_sidebar(struct app *a)
{
    int top = TOOLBAR_Y;
    fill(a, 0, top, SIDEBAR_W, a->height - top - STATUS_H, C_SIDE);
    line(a, SIDEBAR_W - 0.5, top, SIDEBAR_W - 0.5, a->height - STATUS_H, C_LINE, 1);
    text(a, F_BOLD, 18, 18, top + 10, SIDEBAR_W - 30, C_TEXT, "Virtual Machines");
    int used = 0, running = 0;
    for (int i = 0; i < MAX_VMS; i++) if (a->vms[i].used) { used++; if (a->vms[i].pid > 0) running++; }
    textf(a, F_REG, 11, 18, top + 36, SIDEBAR_W - 30, C_FAINT, "%d machine%s, %d running", used,
          used == 1 ? "" : "s", running);

    /* tools, like VirtualBox 7's Tools entry */
    int y = top + TOOLBAR_H + 6;
    static const struct { int view, ic; const char *name, *sub; } tools[2] = {
        { VIEW_HOST, IC_HOST, "Hypervisor", "KVM interface and host support" },
        { VIEW_MEDIA, IC_MEDIA, "Media", "kernels, ramdisks and disks" },
    };
    for (int i = 0; i < 2; i++) {
        int on = a->view == tools[i].view;
        int hover = ptr_in(a, 8, y, SIDEBAR_W - 16, 40);
        if (on) rfill(a, 8, y, SIDEBAR_W - 16, 40, 8, C_SEL);
        else if (hover) rfill(a, 8, y, SIDEBAR_W - 16, 40, 8, 0x1a232bu);
        icon(a, tools[i].ic, 18, y + 9, 22, on ? C_TEXT : C_DIM);
        text(a, F_BOLD, 12, 52, y + 4, SIDEBAR_W - 64, on ? C_TEXT : 0xc8d2dfu, tools[i].name);
        text(a, F_REG, 10, 52, y + 22, SIDEBAR_W - 64, C_FAINT, tools[i].sub);
        hit_add(a, 8, y, SIDEBAR_W - 16, 40, A_VIEW, tools[i].view);
        y += 44;
    }
    line(a, 16, y + 4, SIDEBAR_W - 16, y + 4, C_LINE, 1);
    y += 14;
    text(a, F_BOLD, 10, 18, y, SIDEBAR_W - 30, C_FAINT, "MACHINES");
    y += 20;
    int any = 0;
    for (int i = 0; i < MAX_VMS; i++) {
        struct vm *v = &a->vms[i];
        if (!v->used) continue;
        any = 1;
        if (y + VMROW_H > a->height - STATUS_H) break;
        int on = a->view == VIEW_MACHINE && a->sel == i;
        int hover = ptr_in(a, 8, y, SIDEBAR_W - 16, VMROW_H - 4);
        if (on) rfill(a, 8, y, SIDEBAR_W - 16, VMROW_H - 4, 8, C_SEL);
        else if (hover) rfill(a, 8, y, SIDEBAR_W - 16, VMROW_H - 4, 8, 0x1a232bu);
        os_badge(a, v->cfg.os, 18, y + 9, 36);
        text(a, F_BOLD, 13, 64, y + 8, SIDEBAR_W - 78, C_TEXT, v->cfg.name);
        disc(a, 69, y + 36, 4, state_color(v->state));
        text(a, F_REG, 11, 80, y + 29, SIDEBAR_W - 94, state_color(v->state) == C_FAINT ? C_DIM : state_color(v->state),
             k_state_name[v->state]);
        hit_add(a, 8, y, SIDEBAR_W - 16, VMROW_H - 4, A_SELECT_VM, i);
        y += VMROW_H;
    }
    if (!any)
        text_wrap(a, F_REG, 12, 18, y, SIDEBAR_W - 36, 17, 4, C_FAINT,
                  "No machines yet.  New creates one from the bundled Alpine guest or your own kernel.");
}

static void section_card(struct app *a, int x, int y, int w, int h, int ic, const char *title)
{
    rfill(a, x, y, w, h, 10, C_CARD);
    icon(a, ic, x + 14, y + 12, 18, C_ACCENT2);
    text(a, F_BOLD, 13, x + 40, y + 11, w - 54, C_TEXT, title);
    line(a, x + 12, y + 38, x + w - 12, y + 38, C_LINE, 1);
}
static void kv(struct app *a, int x, int *y, int w, const char *k, const char *v, uint32_t vc)
{
    text(a, F_REG, 12, x, *y, 130, C_DIM, k);
    text(a, F_REG, 12, x + 130, *y, w - 130, vc, v);
    *y += 21;
}

static void draw_term(struct app *a, struct term *t, int x, int y, int w, int h, int focused, int live)
{
    rfill(a, x, y, w, h, 8, C_TERM_BG);
    if (focused) rstroke(a, x, y, w, h, 8, C_ACCENT, 1.5);
    const int px = 13;
    const struct glyph *g0 = cached_glyph(&a->fonts[F_MONO], px, 'M');
    int cw = g0 && g0->advance ? g0->advance : 8, lh = 17;
    int rows = (h - 16) / lh;
    if (rows < 1) rows = 1;
    t->rows = rows;
    int cols = (w - 20) / cw;
    if (cols > TERM_COLS) cols = TERM_COLS;
    if (cols < 20) cols = 20;
    t->cols = cols;
    int maxview = t->n - rows; if (maxview < 0) maxview = 0;
    if (t->view > maxview) t->view = maxview;
    int first = t->n - rows - t->view; if (first < 0) first = 0;
    g_clip_x0 = x + 6; g_clip_y0 = y + 4; g_clip_x1 = x + w - 6; g_clip_y1 = y + h - 4;
    cairo_surface_flush(a->cs);
    for (int r = 0; r < rows && first + r < t->n; r++) {
        const char *l = term_line(t, first + r);
        const uint8_t *co = term_col(t, first + r);
        int len = TERM_COLS;
        while (len > 0 && l[len - 1] == ' ') len--;
        int ly = y + 8 + r * lh;
        for (int c = 0; c < len; c++) {
            if (l[c] == ' ') continue;
            const struct glyph *gl = cached_glyph(&a->fonts[F_MONO], px, (unsigned char)l[c]);
            if (!gl) continue;
            struct glyph_size *slot = slot_for(&a->fonts[F_MONO], px);
            int base = slot && slot->ascender ? slot->ascender : px;
            blit_glyph(a, gl, x + 10 + c * cw, ly + base, 0xff000000u | k_ansi[co[c] & 15],
                       g_clip_x0, g_clip_y0, g_clip_x1, g_clip_y1);
        }
    }
    cairo_surface_mark_dirty(a->cs);
    if (live && t->view == 0 && t->cy >= first && t->cy < first + rows) {   /* the cursor */
        int cx = x + 10 + t->cx * cw, cy = y + 8 + (t->cy - first) * lh;
        if (cx < x + w - 8) {
            cairo_set_source_rgba(a->cr, 0.3, 0.85, 0.75, focused ? 0.85 : 0.35);
            cairo_rectangle(a->cr, cx, cy + 1, cw, lh - 2);
            cairo_fill(a->cr);
        }
    }
    g_clip_x0 = 0; g_clip_y0 = 0; g_clip_x1 = 1 << 30; g_clip_y1 = 1 << 30;
    if (t->view > 0) {
        char s[48]; snprintf(s, sizeof s, "scrolled back %d lines", t->view);
        int tw = text_width(a, F_REG, s, 10) + 16;
        rfill(a, x + w - tw - 10, y + 8, tw, 20, 6, 0x2a3540u);
        text(a, F_REG, 10, x + w - tw - 2, y + 11, tw, C_TEXT, s);
    }
}

static void draw_details(struct app *a, struct vm *v, int x, int y, int w, int h)
{
    struct vmcfg *c = &v->cfg;
    int colw = (w - 16) / 2;
    char s[220];
    /* left column */
    int cy = y;
    section_card(a, x, cy, colw, 128, IC_SETTINGS, "General");
    int ky = cy + 50;
    kv(a, x + 16, &ky, colw - 32, "Name", c->name, C_TEXT);
    kv(a, x + 16, &ky, colw - 32, "Operating system", os_name(c->os), C_TEXT);
    kv(a, x + 16, &ky, colw - 32, "Autostart", c->autostart ? "at boot, headless" : "no", C_TEXT);
    cy += 140;
    section_card(a, x, cy, colw, 150, IC_HOST, "System");
    ky = cy + 50;
    snprintf(s, sizeof s, "%d MB", c->mem_mb);
    kv(a, x + 16, &ky, colw - 32, "Base memory", s, C_TEXT);
    snprintf(s, sizeof s, "%d", c->cpus);
    kv(a, x + 16, &ky, colw - 32, "Processors", s, C_TEXT);
    kv(a, x + 16, &ky, colw - 32, "Boot", c->firmware[0] ? "UEFI firmware (Cloud Hypervisor edk2)" : "direct kernel boot (no firmware)", C_TEXT);
    kv(a, x + 16, &ky, colw - 32, "Acceleration", "VT-x/EPT, in-kernel LAPIC, kvmclock", C_TEXT);
    cy += 162;
    section_card(a, x, cy, colw, 128, IC_MEDIA, "Storage");
    ky = cy + 50;
    if (c->firmware[0]) {
        kv(a, x + 16, &ky, colw - 32, "Firmware", basename_of(c->firmware), file_readable(c->firmware) ? C_TEXT : C_RED);
        snprintf(s, sizeof s, "%s%s", file_readable(c->diskimg) ? basename_of(c->diskimg) : "not downloaded yet",
                 c->disk_ro ? " (read-only)" : "");
        kv(a, x + 16, &ky, colw - 32, "System disk", s, file_readable(c->diskimg) ? C_TEXT : C_YELLOW);
    } else {
        kv(a, x + 16, &ky, colw - 32, "Kernel", basename_of(c->kernel), file_readable(c->kernel) ? C_TEXT : C_RED);
        kv(a, x + 16, &ky, colw - 32, "Initial ramdisk", c->initrd[0] ? basename_of(c->initrd) : "none",
           !c->initrd[0] || file_readable(c->initrd) ? C_TEXT : C_RED);
    }
    if (c->disk_mb) snprintf(s, sizeof s, "virtio-blk, %d MB raw image", c->disk_mb); else snprintf(s, sizeof s, "none");
    kv(a, x + 16, &ky, colw - 32, "Hard disk", s, C_TEXT);
    if (cy + 140 < y + h && !c->firmware[0]) {
        cy += 140;
        section_card(a, x, cy, colw, 84, IC_SETTINGS, "Kernel command line");
        text_wrap(a, F_MONO, 11, x + 16, cy + 48, colw - 32, 15, 2, C_DIM, c->cmdline[0] ? c->cmdline : "(empty)");
    }

    /* right column: a live preview, like VirtualBox's */
    int rx = x + colw + 16;
    cy = y;
    section_card(a, rx, cy, colw, 190, IC_START, "Preview");
    {
        struct term *t = &v->con;
        int px = 9, lh = 11;
        int rows = (190 - 56) / lh;
        int first = t->n - rows; if (first < 0) first = 0;
        rfill(a, rx + 12, cy + 46, colw - 24, 134, 6, C_TERM_BG);
        g_clip_x0 = rx + 16; g_clip_x1 = rx + colw - 16; g_clip_y0 = cy + 48; g_clip_y1 = cy + 178;
        for (int r = 0; r < rows && first + r < t->n; r++) {
            char l[TERM_COLS + 1];
            memcpy(l, term_line(t, first + r), TERM_COLS);
            l[TERM_COLS] = 0;
            int len = TERM_COLS; while (len > 0 && l[len - 1] == ' ') len--; l[len] = 0;
            text(a, F_MONO, px, rx + 18, cy + 50 + r * lh, colw - 36, 0xb8c4d0u, l);
        }
        g_clip_x0 = 0; g_clip_y0 = 0; g_clip_x1 = 1 << 30; g_clip_y1 = 1 << 30;
        hit_add(a, rx + 12, cy + 46, colw - 24, 134, A_TAB, TAB_CONSOLE);
    }
    cy += 202;
    section_card(a, rx, cy, colw, 108, IC_SNAPSHOT, "Serial port and network");
    ky = cy + 50;
    kv(a, rx + 16, &ky, colw - 32, "Serial port 1", "COM1, the Console tab", C_TEXT);
    kv(a, rx + 16, &ky, colw - 32, "Network", c->os == OS_OPNSENSE ? "LAN " FW_LAN " + WAN via NAT" : k_net_name[c->net],
       c->net == NET_NONE && c->os != OS_OPNSENSE ? C_DIM : C_TEXT);
    cy += 120;
    section_card(a, rx, cy, colw, 128, IC_ACPI, "Runtime");
    ky = cy + 50;
    kv(a, rx + 16, &ky, colw - 32, "State", k_state_name[v->state], state_color(v->state) == C_FAINT ? C_TEXT : state_color(v->state));
    if (v->pid > 0) {
        long up = (long)(time(NULL) - v->started);
        snprintf(s, sizeof s, "%ld:%02ld:%02ld (VMM pid %d)", up / 3600, (up / 60) % 60, up % 60, (int)v->pid);
        kv(a, rx + 16, &ky, colw - 32, "Uptime", s, C_TEXT);
        kv(a, rx + 16, &ky, colw - 32, "Headless", "keeps running when this window closes", C_DIM);
    } else if (v->state == ST_ABORTED) {
        snprintf(s, sizeof s, "exit status %d", v->exit_status);
        kv(a, rx + 16, &ky, colw - 32, "Last run", s, C_RED);
    }
    if (v->note[0]) text_wrap(a, F_REG, 11, rx + 16, ky + 2, colw - 32, 15, 2, C_DIM, v->note);
}

static void draw_snapshots(struct app *a, struct vm *v, int x, int y, int w, int h)
{
    (void)h;
    text_wrap(a, F_REG, 12, x, y, w, 17, 3, C_DIM,
              "A snapshot saves the running machine's complete state -- memory, vCPU and devices -- "
              "through the VMM (vm.snapshot).  Restore powers the machine off and boots it from that "
              "state instead of its kernel.");
    y += 64;
    rfill(a, x, y, w, 46, 8, C_CARD);
    disc(a, x + 22, y + 23, 6, state_color(v->state));
    textf(a, F_BOLD, 13, x + 40, y + 8, w - 60, C_TEXT, "Current state");
    textf(a, F_REG, 11, x + 40, y + 26, w - 60, C_DIM, "%s%s", k_state_name[v->state],
          v->restore_from >= 0 ? " - the next start restores a snapshot" : "");
    y += 56;
    if (!v->nsnap) {
        text(a, F_REG, 12, x + 4, y + 6, w, C_FAINT, "No snapshots.  Take one from the toolbar while the machine runs.");
        return;
    }
    for (int i = v->nsnap - 1; i >= 0; i--) {
        struct snap *s = &v->snaps[i];
        rfill(a, x + 24, y, w - 24, 52, 8, C_CARD);
        icon(a, IC_SNAPSHOT, x + 36, y + 14, 22, C_ACCENT2);
        text(a, F_BOLD, 13, x + 70, y + 8, w - 360, C_TEXT, s->name);
        struct tm tmv; localtime_r(&s->when, &tmv);
        char when[64]; strftime(when, sizeof when, "%H:%M:%S", &tmv);
        textf(a, F_REG, 11, x + 70, y + 28, w - 360, C_DIM, "taken %s - %s", when, s->path);
        button(a, x + w - 210, y + 10, 96, 32, "Restore", 1, 1, A_SNAP_RESTORE, i);
        button(a, x + w - 106, y + 10, 90, 32, "Delete", 0, 1, A_SNAP_DELETE, i);
        y += 60;
    }
}

static void draw_machine(struct app *a, int x, int y, int w, int h)
{
    struct vm *v = cur_vm(a);
    if (!v) {
        text(a, F_BOLD, 20, x + 8, y + 30, w, C_TEXT, "Welcome to Virtual Machines");
        text_wrap(a, F_REG, 13, x + 8, y + 66, w - 16, 19, 6, C_DIM,
                  "Machines run on this system's own hypervisor through Cloud Hypervisor.  Choose New to "
                  "create one: the bundled Alpine Linux guest boots to a shell in a few seconds, and its "
                  "serial console appears in the Console tab.");
        button(a, x + 8, y + 170, 180, 38, "New machine", 1, 1, A_NEW, 0);
        return;
    }
    /* header */
    os_badge(a, v->cfg.os, x, y + 2, 44);
    text(a, F_BOLD, 19, x + 58, y, w - 60, C_TEXT, v->cfg.name);
    disc(a, x + 63, y + 34, 4, state_color(v->state));
    textf(a, F_REG, 12, x + 74, y + 26, w - 80, C_DIM, "%s%s%s", k_state_name[v->state],
          v->cfg.desc[0] ? "  -  " : "", v->cfg.desc);
    y += 56;
    /* tabs */
    int tx = x;
    for (int i = 0; i < TAB_COUNT; i++) {
        int tw = text_width(a, F_BOLD, k_tab_name[i], 13) + 28;
        int on = a->tab == i;
        if (on) rfill(a, tx, y, tw, TAB_H - 4, 7, C_SEL);
        else if (ptr_in(a, tx, y, tw, TAB_H - 4)) rfill(a, tx, y, tw, TAB_H - 4, 7, 0x1a232bu);
        text_center(a, on ? F_BOLD : F_REG, 13, tx, y + 7, tw, on ? C_TEXT : C_DIM, k_tab_name[i]);
        hit_add(a, tx, y, tw, TAB_H - 4, A_TAB, i);
        tx += tw + 4;
    }
    y += TAB_H + 6;
    h -= 56 + TAB_H + 6;
    switch (a->tab) {
    case TAB_DETAILS: draw_details(a, v, x, y, w, h); break;
    case TAB_CONSOLE: {
        int live = v->serial_fd >= 0;
        draw_term(a, &v->con, x, y, w, h - 24, live, live);
        text(a, F_REG, 11, x + 2, y + h - 18, w, C_FAINT,
             live ? "Typing goes to the guest's serial port (COM1).  Wheel scrolls back."
                  : v->pid > 0 ? "Waiting for the VMM's serial console..." : "The machine is powered off.");
        hit_add(a, x, y, w, h - 24, A_CONSOLE, 0);
        break;
    }
    case TAB_SNAPSHOTS: draw_snapshots(a, v, x, y, w, h); break;
    case TAB_LOG:
        draw_term(a, &v->log, x, y, w, h - 24, 0, 0);
        text(a, F_REG, 11, x + 2, y + h - 18, w, C_FAINT,
             "Cloud Hypervisor's own output (warnings and errors) and the manager's actions.");
        break;
    }
}

static void draw_host(struct app *a, int x, int y, int w)
{
    text(a, F_BOLD, 19, x, y, w, C_TEXT, "Hypervisor");
    text(a, F_REG, 12, x, y + 28, w, C_DIM, "The KVM-compatible interface this domain sees at /dev/kvm");
    y += 60;
    rfill(a, x, y, w, 64, 10, C_CARD);
    disc(a, x + 24, y + 32, 7, a->kvm_ok ? C_GREEN : C_RED);
    if (a->kvm_ok) {
        textf(a, F_BOLD, 14, x + 44, y + 12, w - 60, C_TEXT, "Virtualization available (KVM API v%d)", a->kvm_api);
        text(a, F_REG, 12, x + 44, y + 34, w - 60, C_DIM, "Intel VT-x with EPT, run by the anonymOS kernel's own hypervisor");
    } else {
        text(a, F_BOLD, 14, x + 44, y + 12, w - 60, C_TEXT, "Virtualization is not available here");
        text(a, F_REG, 12, x + 44, y + 34, w - 60, C_DIM, a->kvm_errno == EACCES
             ? "Enable it for this domain: Domain Manager > Permissions > Virtualization"
             : "/dev/kvm is missing (no VT-x, or it is disabled in firmware)");
    }
    y += 78;
    static const char *const names[6] = { "User memory regions", "Split irqchip (userspace IOAPIC)",
                                           "IRQ routing", "irqfd", "ioeventfd", "MSI signalling" };
    int vals[6] = { a->cap_usermem, a->cap_irqchip, a->cap_irqrouting, a->cap_irqfd, a->cap_ioeventfd, a->cap_signalmsi };
    rfill(a, x, y, w, 6 * 26 + 56, 10, C_CARD);
    text(a, F_BOLD, 13, x + 16, y + 12, w, C_TEXT, "Capabilities Cloud Hypervisor needs");
    for (int i = 0; i < 6; i++) {
        int ok = a->kvm_ok && vals[i] > 0;
        disc(a, x + 24, y + 50 + i * 26, 4, ok ? C_GREEN : C_RED);
        text(a, F_REG, 12, x + 38, y + 42 + i * 26, w - 200, C_TEXT, names[i]);
        text_right(a, F_REG, 12, x + w - 18, y + 42 + i * 26, ok ? C_GREEN : C_RED, ok ? "yes" : "no");
    }
    y += 6 * 26 + 70;
    rfill(a, x, y, w, 84, 10, C_CARD);
    text(a, F_BOLD, 13, x + 16, y + 12, w, C_TEXT, "Virtual machine monitor");
    textf(a, F_REG, 12, x + 16, y + 36, w - 32, a->have_ch ? C_TEXT : C_RED, "%s  %s", CH_PATH,
          a->have_ch ? "(Cloud Hypervisor v54, static musl)" : "missing from this image");
    text(a, F_REG, 11, x + 16, y + 56, w - 32, C_DIM,
         "In-kernel: VMX entry, EPT, LAPIC + TSC-deadline timer, kvmclock, CPUID/MSR emulation");
}

static void draw_media(struct app *a, int x, int y, int w)
{
    text(a, F_BOLD, 19, x, y, w, C_TEXT, "Media");
    text(a, F_REG, 12, x, y + 28, w, C_DIM, "Boot images and virtual disks the machines use");
    y += 60;
    struct { const char *path, *kind; } items[16];
    int n = 0;
    items[n++] = (typeof(items[0])){ BUNDLED_KERNEL, "Kernel (bundled)" };
    items[n++] = (typeof(items[0])){ BUNDLED_INITRD, "Initial ramdisk (bundled)" };
    items[n++] = (typeof(items[0])){ FIRMWARE_PATH, "UEFI firmware (bundled)" };
    items[n++] = (typeof(items[0])){ opnsense_disk() ? opnsense_disk() : OPNSENSE_DISK, "OPNsense disk (downloaded)" };
    for (int i = 0; i < MAX_VMS && n < 16; i++) {
        struct vm *v = &a->vms[i];
        if (!v->used) continue;
        if (v->cfg.os == OS_CUSTOM && v->cfg.kernel[0] && n < 16) items[n++] = (typeof(items[0])){ v->cfg.kernel, "Kernel" };
        if (v->disk_path[0] && n < 16) items[n++] = (typeof(items[0])){ v->disk_path, "Hard disk (raw)" };
    }
    for (int i = 0; i < n; i++) {
        long sz = file_size(items[i].path);
        rfill(a, x, y, w, 50, 8, C_CARD);
        icon(a, IC_MEDIA, x + 14, y + 13, 24, sz >= 0 ? C_ACCENT2 : C_RED);
        text(a, F_BOLD, 13, x + 50, y + 8, w - 250, C_TEXT, basename_of(items[i].path));
        text(a, F_REG, 11, x + 50, y + 27, w - 250, C_DIM, items[i].path);
        char b[32]; fmt_bytes(sz, b, sizeof b);
        text_right(a, F_REG, 12, x + w - 16, y + 8, sz >= 0 ? C_TEXT : C_RED, b);
        text_right(a, F_REG, 11, x + w - 16, y + 27, C_FAINT, items[i].kind);
        y += 58;
    }
}

static void draw(struct app *a)
{
    a->nhits = 0;
    fill(a, 0, 0, a->width, a->height, C_BG);
    draw_toolbar(a);
    draw_sidebar(a);
    int x = SIDEBAR_W + 22, y = TOOLBAR_Y + TOOLBAR_H + 14, w = a->width - SIDEBAR_W - 44;
    int h = a->height - y - STATUS_H - 12;
    if (a->view == VIEW_HOST) draw_host(a, x, y, w);
    else if (a->view == VIEW_MEDIA) draw_media(a, x, y, w);
    else draw_machine(a, x, y, w, h);
    /* status bar */
    fill(a, 0, a->height - STATUS_H, a->width, STATUS_H, C_BAR);
    line(a, 0, a->height - STATUS_H + 0.5, a->width, a->height - STATUS_H + 0.5, C_LINE, 1);
    disc(a, 14, a->height - STATUS_H / 2, 4, a->kvm_ok ? C_GREEN : C_RED);
    textf(a, F_REG, 11, 26, a->height - STATUS_H + 6, 330, C_DIM, a->kvm_ok ? "KVM API v%d ready" : "no virtualization in this domain",
          a->kvm_api);
    if (a->banner[0])
        text(a, F_REG, 11, 340, a->height - STATUS_H + 6, a->width - 360,
             a->banner_kind == 2 ? C_RED : a->banner_kind == 1 ? C_GREEN : C_DIM, a->banner);
    if (a->dlg.kind != DLG_NONE) draw_dialog(a);
}

/* ── buffers / commit ──────────────────────────────────────────────────────────────────── */
static void buffer_release(void *data, struct wl_buffer *b)
{
    struct app *a = data;
    for (int i = 0; i < 2; i++) if (a->buffer[i] == b) a->busy[i] = 0;
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static int create_buffers(struct app *a, int w, int h)
{
    a->width = w; a->height = h;
    a->stride = a->width * 4;
    size_t one = (size_t)a->stride * (size_t)a->height;
    a->pool_size = one * 2;
    int fd = (int)syscall(SYS_memfd_create, "epin-vmm", MFD_CLOEXEC);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)a->pool_size) < 0) { close(fd); return -1; }
    void *m = mmap(NULL, a->pool_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) { close(fd); return -1; }
    struct wl_shm_pool *pool = wl_shm_create_pool(a->shm, fd, (int)a->pool_size);
    for (int i = 0; i < 2; i++) {
        a->pixels[i] = (uint32_t *)((char *)m + one * (size_t)i);
        a->buffer[i] = wl_shm_pool_create_buffer(pool, (int32_t)(one * (size_t)i), a->width, a->height,
                                                 a->stride, WL_SHM_FORMAT_XRGB8888);
        a->busy[i] = 0;
        wl_buffer_add_listener(a->buffer[i], &buffer_listener, a);
    }
    wl_shm_pool_destroy(pool);
    close(fd);
    return 0;
}
static void destroy_buffers(struct app *a)
{
    for (int i = 0; i < 2; i++) {
        if (a->buffer[i]) { wl_buffer_destroy(a->buffer[i]); a->buffer[i] = NULL; }
        a->busy[i] = 0;
    }
    if (a->pixels[0]) { munmap(a->pixels[0], a->pool_size); a->pixels[0] = a->pixels[1] = NULL; }
}

static void frame_done(void *data, struct wl_callback *cb, uint32_t t);
static const struct wl_callback_listener frame_listener = { .done = frame_done };

static void render(struct app *a)
{
    if (!a->buffer[0] || !a->buffer[1]) return;
    int idx = -1;
    for (int i = 0; i < 2; i++) if (!a->busy[i]) { idx = i; break; }
    if (idx < 0) return;
    a->px = a->pixels[idx];
    a->cs = cairo_image_surface_create_for_data((unsigned char *)a->px, CAIRO_FORMAT_RGB24,
                                                a->width, a->height, a->stride);
    a->cr = cairo_create(a->cs);
    draw(a);
    cairo_destroy(a->cr); a->cr = NULL;
    cairo_surface_flush(a->cs);
    cairo_surface_destroy(a->cs); a->cs = NULL;
    wl_deco_draw(a->px, a->width, a->width, a->height, 0xffb8c0ccu);
    a->busy[idx] = 1;
    a->dirty = 0;
    wl_surface_attach(a->surface, a->buffer[idx], 0, 0);
    wl_surface_damage_buffer(a->surface, 0, 0, a->width, a->height);
    a->frame_cb = wl_surface_frame(a->surface);
    wl_callback_add_listener(a->frame_cb, &frame_listener, a);
    a->frame_pending = 1;
    wl_surface_commit(a->surface);
    wl_display_flush(a->display);
}
static void frame_done(void *data, struct wl_callback *cb, uint32_t t)
{
    struct app *a = data; (void)t;
    if (cb) wl_callback_destroy(cb);
    a->frame_cb = NULL;
    a->frame_pending = 0;
    if (a->dirty) render(a);
}
static void request_redraw(struct app *a) { a->dirty = 1; if (!a->frame_pending) render(a); }

/* ── actions ───────────────────────────────────────────────────────────────────────────── */
static void do_action(struct app *a, int action, int arg)
{
    struct vm *v = cur_vm(a);
    switch (action) {
    case A_NEW: dlg_open_new(a); break;
    case A_SETTINGS: if (v) dlg_open_settings(a); break;
    case A_DELETE: if (v) { memset(&a->dlg, 0, sizeof a->dlg); a->dlg.kind = DLG_DELETE; a->dlg.target = a->sel; } break;
    case A_START:
        if (v) {
            if (vm_start(a, v) == 0) { set_banner(a, 1, "Starting \"%s\"", v->cfg.name); a->tab = TAB_CONSOLE; }
            else set_banner(a, 2, "%s", v->note);
        }
        break;
    case A_PAUSE: case A_RESET: case A_ACPI: case A_POWEROFF: case A_SNAPSHOT:
        if (v) {
            if (action == A_SNAPSHOT) { set_banner(a, 0, "Taking a snapshot of \"%s\"...", v->cfg.name); }
            vm_action(a, v, action);
            set_banner(a, strstr(v->note, "fail") ? 2 : 1, "%s: %s", v->cfg.name, v->note);
            if (action == A_SNAPSHOT) a->tab = TAB_SNAPSHOTS;
        }
        break;
    case A_SELECT_VM: a->sel = arg; a->view = VIEW_MACHINE; break;
    case A_TAB: a->tab = arg; break;
    case A_VIEW:
        a->view = arg;
        if (arg == VIEW_HOST) {
            probe_host(a);
            if (a->kvm_ok) set_banner(a, 0, "Virtualization available (KVM API v%d)", a->kvm_api);
        }
        break;
    case A_CONSOLE: break;
    case A_SNAP_RESTORE:
        if (v && arg < v->nsnap) {
            if (v->pid > 0) {
                vm_action(a, v, A_POWEROFF);
                for (int k = 0; k < 50 && v->pid > 0; k++) {           /* wait up to 5 s for the exit */
                    int status; pid_t w = waitpid(v->pid, &status, WNOHANG);
                    if (w == v->pid) { vm_exited(v, status); break; }
                    usleep(100000);
                }
                if (v->pid > 0) { kill(v->pid, SIGKILL); int status; waitpid(v->pid, &status, 0); vm_exited(v, status); }
            }
            v->restore_from = arg;
            if (vm_start(a, v) == 0) { set_banner(a, 1, "Restoring %s of \"%s\"", v->snaps[arg].name, v->cfg.name); a->tab = TAB_CONSOLE; }
            else { set_banner(a, 2, "%s", v->note); v->restore_from = -1; }
        }
        break;
    case A_SNAP_DELETE:
        if (v && arg < v->nsnap) {
            char cmd[200];
            snprintf(cmd, sizeof cmd, "%s/config.json", v->snaps[arg].path); unlink(cmd);
            snprintf(cmd, sizeof cmd, "%s/state.json", v->snaps[arg].path); unlink(cmd);
            snprintf(cmd, sizeof cmd, "%s/memory-ranges", v->snaps[arg].path); unlink(cmd);
            rmdir(v->snaps[arg].path);
            for (int i = arg; i + 1 < v->nsnap; i++) v->snaps[i] = v->snaps[i + 1];
            v->nsnap--;
            if (v->restore_from == arg) v->restore_from = -1;
        }
        break;
    case A_DLG_NEXT:
        if (a->dlg.page == 0 && !dlg_validate(a)) break;
        if (a->dlg.page < 3) a->dlg.page++;
        a->dlg.err[0] = 0;
        a->dlg.focus = -1;
        break;
    case A_DLG_BACK: if (a->dlg.page > 0) a->dlg.page--; a->dlg.err[0] = 0; a->dlg.focus = a->dlg.page == 0 ? FLD_NAME : -1; break;
    case A_DLG_CANCEL: a->dlg.kind = DLG_NONE; break;
    case A_DLG_OK: dlg_finish(a); break;
    case A_DLG_FIELD: a->dlg.focus = arg; break;
    case A_DLG_STEP: dlg_step(a, arg / 2, (arg & 1) ? 1 : -1); break;
    case A_DLG_CHOICE: {
        char keep[48];
        copy_str(keep, sizeof keep, a->dlg.cfg.name);
        int renamed = strncmp(keep, "Alpine Linux", 12) && strncmp(keep, "Linux VM", 8);
        cfg_defaults(a, &a->dlg.cfg, arg);
        if (renamed) copy_str(a->dlg.cfg.name, sizeof a->dlg.cfg.name, keep);
        a->dlg.focus = arg == OS_CUSTOM ? FLD_KERNEL : FLD_NAME;
        break;
    }
    case A_DLG_SECTION: a->dlg.section = arg; a->dlg.focus = -1; break;
    case A_DLG_TOGGLE:
        if (arg == 0) a->dlg.cfg.autostart = !a->dlg.cfg.autostart;
        else if (arg >= 10 && arg < 13) a->dlg.cfg.net = arg - 10;
        break;
    case A_DLG_DELETE_OK: {
        char nm[48]; copy_str(nm, sizeof nm, a->vms[a->dlg.target].cfg.name);
        vm_remove(a, a->dlg.target);
        a->dlg.kind = DLG_NONE;
        set_banner(a, 1, "Removed \"%s\"", nm);
        break;
    }
    default: break;
    }
}

/* ── input ─────────────────────────────────────────────────────────────────────────────── */
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

/* A key for the guest's serial port: bytes a VT100 would send. */
static int key_to_serial(struct app *a, uint32_t code, char *out)
{
    switch (code) {
    case 28: case 96: out[0] = '\r'; return 1;             /* Enter */
    case 14: out[0] = 0x7f; return 1;                      /* Backspace */
    case 15: out[0] = '\t'; return 1;
    case 1:  out[0] = 0x1b; return 1;                      /* Esc */
    case 103: memcpy(out, "\033[A", 3); return 3;
    case 108: memcpy(out, "\033[B", 3); return 3;
    case 106: memcpy(out, "\033[C", 3); return 3;
    case 105: memcpy(out, "\033[D", 3); return 3;
    case 102: memcpy(out, "\033[H", 3); return 3;          /* Home */
    case 107: memcpy(out, "\033[F", 3); return 3;          /* End */
    case 111: memcpy(out, "\033[3~", 4); return 4;         /* Delete */
    case 104: memcpy(out, "\033[5~", 4); return 4;
    case 109: memcpy(out, "\033[6~", 4); return 4;
    }
    if (code >= sizeof km_plain) return 0;
    char ch = a->shift ? km_shift[code] : km_plain[code];
    if (!ch) return 0;
    if (a->ctrl) {
        if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 'a' + 1);
        else if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 1);
        else if (ch == '[') ch = 0x1b;
        else if (ch == '\\') ch = 0x1c;
        else if (ch == ']') ch = 0x1d;
        else return 0;
    }
    out[0] = ch;
    return 1;
}

static void kb_key(void *data, struct wl_keyboard *k, uint32_t serial, uint32_t time, uint32_t code, uint32_t state)
{
    struct app *a = data; (void)k; (void)serial; (void)time;
    int down = state == WL_KEYBOARD_KEY_STATE_PRESSED;
    if (code == 42 || code == 54) { a->shift = down; return; }
    if (code == 29 || code == 97) { a->ctrl = down; return; }
    if (!down) return;

    if (a->dlg.kind != DLG_NONE) {
        struct dialog *d = &a->dlg;
        if (code == 1) { d->kind = DLG_NONE; request_redraw(a); return; }
        if (code == 28) {
            if (d->kind == DLG_DELETE) do_action(a, A_DLG_DELETE_OK, 0);
            else if (d->kind == DLG_NEW && d->page < 3) do_action(a, A_DLG_NEXT, 0);
            else do_action(a, A_DLG_OK, 0);
            request_redraw(a); return;
        }
        if (code == 15) {                                     /* Tab: next visible field */
            static const int order_new0[4] = { FLD_NAME, FLD_KERNEL, FLD_INITRD, FLD_CMDLINE };
            int n = (d->kind == DLG_NEW && d->cfg.os == OS_CUSTOM) ? 4 : 1;
            int cur = 0;
            for (int i = 0; i < n; i++) if (order_new0[i] == d->focus) cur = i;
            d->focus = order_new0[(cur + 1) % n];
            request_redraw(a); return;
        }
        if (d->focus >= 0) {
            size_t cap; char *s = dlg_field(a, d->focus, &cap);
            if (s) {
                size_t len = strlen(s);
                if (code == 14) { if (len) s[len - 1] = 0; }
                else if (code < sizeof km_plain) {
                    char ch = a->shift ? km_shift[code] : km_plain[code];
                    if (ch && len + 1 < cap) { s[len] = ch; s[len + 1] = 0; }
                }
                d->err[0] = 0;
            }
        }
        request_redraw(a);
        return;
    }

    struct vm *v = cur_vm(a);
    if (a->view == VIEW_MACHINE && a->tab == TAB_CONSOLE && v && v->serial_fd >= 0) {
        char out[8];
        int n = key_to_serial(a, code, out);
        if (n > 0) {
            if (write(v->serial_fd, out, (size_t)n) < 0) { /* the VMM went away; vm_poll notices */ }
            if (v->con.view) { v->con.view = 0; request_redraw(a); }
        }
        return;
    }
    /* list navigation */
    int step = code == 103 ? -1 : code == 108 ? 1 : 0;
    if (step) {
        int i = a->sel;
        for (int k = 0; k < MAX_VMS; k++) {
            i = (i + step + MAX_VMS) % MAX_VMS;
            if (a->vms[i].used) { a->sel = i; a->view = VIEW_MACHINE; break; }
        }
    } else if (code == 28 && v) do_action(a, A_START, 0);
    else if (code == 49 && a->ctrl) do_action(a, A_NEW, 0);                   /* Ctrl+N */
    else if (code == 1) a->running = 0;
    request_redraw(a);
}
static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t s)
{ (void)d;(void)k;(void)f;(void)s; if (fd >= 0) close(fd); }
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su, struct wl_array *ks)
{ (void)k;(void)s;(void)su;(void)ks; struct app *a = d; a->shift = a->ctrl = 0; }
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su)
{ (void)k;(void)s;(void)su; struct app *a = d; a->shift = a->ctrl = 0; }
static void kb_mods(void *d, struct wl_keyboard *k, uint32_t s, uint32_t dep, uint32_t lat, uint32_t lck, uint32_t g)
{ (void)d;(void)k;(void)s;(void)dep;(void)lat;(void)lck;(void)g; }
static void kb_rep(void *d, struct wl_keyboard *k, int32_t r, int32_t dl) { (void)d;(void)k;(void)r;(void)dl; }
static const struct wl_keyboard_listener kb_listener = {
    .keymap = kb_keymap, .enter = kb_enter, .leave = kb_leave, .key = kb_key, .modifiers = kb_mods, .repeat_info = kb_rep,
};

static void ptr_motion(void *data, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y)
{
    struct app *a = data; (void)p; (void)t;
    int ox = (int)a->ptr_x, oy = (int)a->ptr_y;
    a->ptr_x = wl_fixed_to_double(x); a->ptr_y = wl_fixed_to_double(y);
    /* hover highlights: redraw only when the pointer crosses into a different hit box */
    int before = -1, after = -1;
    for (int i = a->nhits - 1; i >= 0; i--) {
        struct hit *h = &a->hits[i];
        if (before < 0 && ox >= h->x && ox < h->x + h->w && oy >= h->y && oy < h->y + h->h) before = i;
        if (after < 0 && a->ptr_x >= h->x && a->ptr_x < h->x + h->w && a->ptr_y >= h->y && a->ptr_y < h->y + h->h) after = i;
    }
    if (before != after) request_redraw(a);
}
static void ptr_enter(void *data, struct wl_pointer *p, uint32_t s, struct wl_surface *su, wl_fixed_t x, wl_fixed_t y)
{ (void)p;(void)s;(void)su; ptr_motion(data, NULL, 0, x, y); }
static void ptr_leave(void *data, struct wl_pointer *p, uint32_t s, struct wl_surface *su)
{ (void)p;(void)s;(void)su; struct app *a = data; a->ptr_x = a->ptr_y = -1; request_redraw(a); }

static void ptr_button(void *data, struct wl_pointer *p, uint32_t serial, uint32_t time, uint32_t button, uint32_t state)
{
    struct app *a = data; (void)p; (void)time;
    if (button != 0x110 || state != WL_POINTER_BUTTON_STATE_PRESSED) return;
    double x = a->ptr_x, y = a->ptr_y;
    switch (wl_deco_hit(x, y, a->width)) {
    case 4: a->running = 0; return;
    case 2: xdg_toplevel_set_minimized(a->toplevel); return;
    case 3: if (a->maximized) { xdg_toplevel_unset_maximized(a->toplevel); a->maximized = 0; }
            else { xdg_toplevel_set_maximized(a->toplevel); a->maximized = 1; }
            return;
    default: break;
    }
    for (int i = a->nhits - 1; i >= 0; i--) {
        struct hit *h = &a->hits[i];
        if (x >= h->x && x < h->x + h->w && y >= h->y && y < h->y + h->h) {
            do_action(a, h->action, h->arg);
            break;
        }
    }
    request_redraw(a);
}
static void ptr_axis(void *data, struct wl_pointer *p, uint32_t t, uint32_t axis, wl_fixed_t val)
{
    struct app *a = data; (void)p; (void)t;
    if (axis != 0 || a->dlg.kind != DLG_NONE) return;
    struct vm *v = cur_vm(a);
    if (!v || a->view != VIEW_MACHINE) return;
    struct term *term = a->tab == TAB_CONSOLE ? &v->con : a->tab == TAB_LOG ? &v->log : NULL;
    if (!term) return;
    term->view += wl_fixed_to_double(val) > 0 ? -3 : 3;
    if (term->view < 0) term->view = 0;
    request_redraw(a);
}
static void ptr_frame(void *d, struct wl_pointer *p) { (void)d; (void)p; }
static void ptr_axis_src(void *d, struct wl_pointer *p, uint32_t s) { (void)d;(void)p;(void)s; }
static void ptr_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax) { (void)d;(void)p;(void)t;(void)ax; }
static void ptr_axis_disc(void *d, struct wl_pointer *p, uint32_t ax, int32_t v) { (void)d;(void)p;(void)ax;(void)v; }
static const struct wl_pointer_listener ptr_listener = {
    .enter = ptr_enter, .leave = ptr_leave, .motion = ptr_motion, .button = ptr_button,
    .axis = ptr_axis, .frame = ptr_frame, .axis_source = ptr_axis_src, .axis_stop = ptr_axis_stop,
    .axis_discrete = ptr_axis_disc,
};

static void seat_caps(void *data, struct wl_seat *seat, uint32_t caps)
{
    struct app *a = data;
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !a->keyboard) {
        a->keyboard = wl_seat_get_keyboard(seat);
        wl_keyboard_add_listener(a->keyboard, &kb_listener, a);
    }
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !a->pointer) {
        a->pointer = wl_seat_get_pointer(seat);
        wl_pointer_add_listener(a->pointer, &ptr_listener, a);
    }
}
static void seat_name(void *d, struct wl_seat *s, const char *n) { (void)d;(void)s;(void)n; }
static const struct wl_seat_listener seat_listener = { .capabilities = seat_caps, .name = seat_name };

static void wm_ping(void *d, struct xdg_wm_base *b, uint32_t s) { (void)d; xdg_wm_base_pong(b, s); }
static const struct xdg_wm_base_listener wm_listener = { .ping = wm_ping };
static void tl_configure(void *data, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *st)
{ struct app *a = data; (void)t; (void)st; if (w > 0) a->pending_width = w; if (h > 0) a->pending_height = h; }
static void tl_close(void *data, struct xdg_toplevel *t) { (void)t; ((struct app *)data)->running = 0; }
static void tl_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h) { (void)d;(void)t;(void)w;(void)h; }
static void tl_caps(void *d, struct xdg_toplevel *t, struct wl_array *c) { (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener tl_listener = {
    .configure = tl_configure, .close = tl_close, .configure_bounds = tl_bounds, .wm_capabilities = tl_caps,
};
static void surf_configure(void *data, struct xdg_surface *s, uint32_t serial)
{
    struct app *a = data;
    xdg_surface_ack_configure(s, serial);
    int w = a->pending_width > 0 ? a->pending_width : DEFAULT_WIDTH;
    int h = a->pending_height > 0 ? a->pending_height : DEFAULT_HEIGHT;
    if (w < MIN_WIDTH) w = MIN_WIDTH;
    if (h < MIN_HEIGHT) h = MIN_HEIGHT;
    if (a->committed && w == a->width && h == a->height) return;
    destroy_buffers(a);
    if (create_buffers(a, w, h) < 0) { a->running = 0; return; }
    a->committed = 1;
    a->dirty = 1;
    if (!a->frame_pending) render(a);
}
static const struct xdg_surface_listener surf_listener = { .configure = surf_configure };

static void reg_global(void *data, struct wl_registry *reg, uint32_t name, const char *iface, uint32_t ver)
{
    struct app *a = data;
    if (!strcmp(iface, "wl_compositor"))
        a->compositor = wl_registry_bind(reg, name, &wl_compositor_interface, ver < 4 ? ver : 4);
    else if (!strcmp(iface, "wl_shm"))
        a->shm = wl_registry_bind(reg, name, &wl_shm_interface, 1);
    else if (!strcmp(iface, "xdg_wm_base")) {
        a->wm_base = wl_registry_bind(reg, name, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(a->wm_base, &wm_listener, a);
    } else if (!strcmp(iface, "wl_seat")) {
        a->seat = wl_registry_bind(reg, name, &wl_seat_interface, ver < 5 ? ver : 5);
        wl_seat_add_listener(a->seat, &seat_listener, a);
    }
}
static void reg_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d;(void)r;(void)n; }
static const struct wl_registry_listener reg_listener = { .global = reg_global, .global_remove = reg_remove };

/* Headless self-test (`wl-vmm --selftest`): create the bundled machine, boot it, wait for the
 * guest's banner on the serial console, run a command through it, power it off.  Proves the whole
 * path the GUI drives, without a display. */
/* Re-attach to the machines a previous Virtual Machines left running (headless). */
static void vm_reattach_all(struct app *a)
{
    DIR *d = opendir(RUN_DIR);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        int id;
        char tail[16];
        if (sscanf(de->d_name, "vm%d.%15s", &id, tail) != 2 || strcmp(tail, "state")) continue;
        char path[160];
        snprintf(path, sizeof path, "%s/%s", RUN_DIR, de->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        struct vmcfg c;
        memset(&c, 0, sizeof c);
        int pid = 0; long started = 0;
        char line[512];
        while (fgets(line, sizeof line, f)) {
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = 0;
            char *v = eq + 1;
            v[strcspn(v, "\n")] = 0;
            if (!strcmp(line, "name")) copy_str(c.name, sizeof c.name, v);
            else if (!strcmp(line, "desc")) copy_str(c.desc, sizeof c.desc, v);
            else if (!strcmp(line, "os")) c.os = atoi(v);
            else if (!strcmp(line, "mem")) c.mem_mb = atoi(v);
            else if (!strcmp(line, "cpus")) c.cpus = atoi(v);
            else if (!strcmp(line, "disk_mb")) c.disk_mb = atoi(v);
            else if (!strcmp(line, "disk_ro")) c.disk_ro = atoi(v);
            else if (!strcmp(line, "autostart")) c.autostart = atoi(v);
            else if (!strcmp(line, "net")) c.net = atoi(v);
            else if (!strcmp(line, "kernel")) copy_str(c.kernel, sizeof c.kernel, v);
            else if (!strcmp(line, "initrd")) copy_str(c.initrd, sizeof c.initrd, v);
            else if (!strcmp(line, "cmdline")) copy_str(c.cmdline, sizeof c.cmdline, v);
            else if (!strcmp(line, "firmware")) copy_str(c.firmware, sizeof c.firmware, v);
            else if (!strcmp(line, "diskimg")) copy_str(c.diskimg, sizeof c.diskimg, v);
            else if (!strcmp(line, "pid")) pid = atoi(v);
            else if (!strcmp(line, "started")) started = atol(v);
        }
        fclose(f);
        char api[96], ser[96];
        snprintf(api, sizeof api, "%s/vm%d.api", RUN_DIR, id);
        snprintf(ser, sizeof ser, "%s/vm%d.serial", RUN_DIR, id);
        int fd = unix_connect(api);
        if (fd >= 0) close(fd);
        if (pid <= 0 || fd < 0 || (kill(pid, 0) != 0 && errno == ESRCH)) {   /* stale: it is gone */
            unlink(path); unlink(api); unlink(ser);
            continue;
        }
        int i = vm_add(a, &c);
        if (i < 0) continue;
        struct vm *vm = &a->vms[i];
        vm->id = id;
        if (id > a->next_id) a->next_id = id;
        copy_str(vm->api_path, sizeof vm->api_path, api);
        copy_str(vm->serial_path, sizeof vm->serial_path, ser);
        snprintf(vm->log_path, sizeof vm->log_path, "%s/vm%d.log", RUN_DIR, id);
        copy_str(vm->state_path, sizeof vm->state_path, path);
        vm->pid = pid;
        vm->child = 0;
        vm->started = (time_t)started;
        char resp[1024];
        vm->state = ST_RUNNING;
        if (api_call(vm, "GET", "vm.info", NULL, resp, sizeof resp, 3000) / 100 == 2 && strstr(resp, "\"Paused\""))
            vm->state = ST_PAUSED;
        vm->log_fd = open(vm->log_path, O_RDONLY);
        if (vm->log_fd >= 0) {                              /* show the recent part of the log */
            off_t end = lseek(vm->log_fd, 0, SEEK_END);
            lseek(vm->log_fd, end > 16384 ? end - 16384 : 0, SEEK_SET);
        }
        term_reset(&vm->con);
        term_puts(&vm->con, "\033[90m-- re-attached to the running machine; earlier output is in its VMM log --\033[0m\r\n");
        vm_note(vm, "Re-attached: this machine kept running (headless) while Virtual Machines was closed");
        printf("[vmm] re-attached \"%s\" (VMM pid %d)\n", c.name, pid);
    }
    closedir(d);
    fflush(stdout);
}

/* The machines to start headless at boot (Settings > General), one name per line. */
#define AUTOSTART_LIST "/home/user/.config/vms/autostart"
static int autostart_listed(const char *name)
{
    FILE *f = fopen(AUTOSTART_LIST, "r");
    if (!f) return 0;
    char line[64]; int hit = 0;
    while (fgets(line, sizeof line, f)) { line[strcspn(line, "\n")] = 0; if (!strcmp(line, name)) hit = 1; }
    fclose(f);
    return hit;
}
static void autostart_set(const char *name, int on)
{
    char names[16][64]; int n = 0;
    FILE *f = fopen(AUTOSTART_LIST, "r");
    if (f) {
        char line[64];
        while (n < 16 && fgets(line, sizeof line, f)) {
            line[strcspn(line, "\n")] = 0;
            if (line[0] && strcmp(line, name)) copy_str(names[n++], sizeof names[0], line);
        }
        fclose(f);
    }
    if (on && n < 16) copy_str(names[n++], sizeof names[0], name);
    mkdir("/home/user/.config", 0755);
    mkdir("/home/user/.config/vms", 0755);
    f = fopen(AUTOSTART_LIST, "w");
    if (!f) return;
    for (int i = 0; i < n; i++) fprintf(f, "%s\n", names[i]);
    fclose(f);
}

/* `wl-vmm --start-headless NAME` / `wl-vmm --autostart`: start machines with no window at all (boot
 * time, the firewall).  A machine already running (re-attachable) is left alone.  Returns once each
 * VMM's console is up, leaving the VMMs running. */
static int headless_start(struct app *a, const char *name)
{
    for (int i = 0; i < MAX_VMS; i++)
        if (a->vms[i].used && a->vms[i].pid > 0 && !strcmp(a->vms[i].cfg.name, name)) {
            printf("[vmm] \"%s\" is already running (VMM pid %d)\n", name, (int)a->vms[i].pid);
            return 0;
        }
    struct vmcfg c;
    if (!strcasecmp(name, "opnsense") || !strcmp(name, "OPNsense Firewall")) cfg_defaults(a, &c, OS_OPNSENSE);
    else if (!strcasecmp(name, "alpine") || !strcmp(name, "Alpine Linux")) cfg_defaults(a, &c, OS_ALPINE);
    else { printf("[vmm] no machine called \"%s\"\n", name); return 1; }
    c.autostart = autostart_listed(c.name);
    int i = vm_add(a, &c);
    struct vm *v = &a->vms[i];
    if (vm_start(a, v) != 0) { printf("[vmm] %s: %s\n", c.name, v->note); return 1; }
    for (int k = 0; k < 300 && v->pid > 0 && v->serial_fd < 0; k++) { vm_poll(a, v); usleep(100000); }
    if (v->serial_fd >= 0) { close(v->serial_fd); v->serial_fd = -1; }   /* leave the console to the app */
    vm_write_state(v);
    printf("[vmm] \"%s\" %s headless (VMM pid %d)\n", c.name, v->pid > 0 ? "started" : "FAILED to start", (int)v->pid);
    return v->pid > 0 ? 0 : 1;
}

static int selftest(struct app *a)
{
    probe_host(a);
    printf("[vmm-selftest] kvm=%d api=%d ch=%d bundled=%d\n", a->kvm_ok, a->kvm_api, a->have_ch, a->have_bundled);
    if (!a->kvm_ok || !a->have_ch || !a->have_bundled) { printf("[vmm-selftest] FAIL: prerequisites\n"); return 1; }
    struct vmcfg c;
    cfg_defaults(a, &c, OS_ALPINE);
    int i = vm_add(a, &c);
    struct vm *v = &a->vms[i];
    if (vm_start(a, v) != 0) { printf("[vmm-selftest] FAIL: start: %s\n", v->note); return 1; }
    int phase = 0, ok = 0, last_state = -1;
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    long next_report = 5000;
    for (;;) {                                                     /* up to 300 s */
        struct timespec tn; clock_gettime(CLOCK_MONOTONIC, &tn);
        long ms = (tn.tv_sec - t0.tv_sec) * 1000 + (tn.tv_nsec - t0.tv_nsec) / 1000000;
        if (ms > 300000 || v->pid <= 0) break;
        int tick = (int)(ms / 100);
        vm_poll(a, v);
        if (v->state != last_state) {
            printf("[vmm-selftest] t=%d.%ds state=%s serial_fd=%d console_lines=%d\n", tick / 10, tick % 10,
                   k_state_name[v->state], v->serial_fd, v->con.n);
            last_state = v->state;
        }
        if (ms >= next_report) {
            next_report += 5000;
            char l0[TERM_COLS + 1];
            memcpy(l0, term_line(&v->con, v->con.cy), TERM_COLS); l0[TERM_COLS] = 0;
            printf("[vmm-selftest] t=%ds serial_bytes=%ld lines=%d cursor-line: %.80s\n", (tick + 1) / 10,
                   v->serial_bytes, v->con.n, l0);
            for (int l = v->log.n > 3 ? v->log.n - 3 : 0; l < v->log.n; l++) {
                memcpy(l0, term_line(&v->log, l), TERM_COLS); l0[TERM_COLS] = 0;
                printf("[vmm-selftest]   log: %.150s\n", l0);
            }
        }
        char all[TERM_COLS + 1];
        for (int l = 0; l < v->con.n; l++) {
            memcpy(all, term_line(&v->con, l), TERM_COLS); all[TERM_COLS] = 0;
            if (phase == 0 && strstr(all, "anonymOS guest")) {
                printf("[vmm-selftest] guest banner: %.100s\n", all);
                const char *cmd = "echo selftest-$((6*7))\r";
                if (write(v->serial_fd, cmd, strlen(cmd)) < 0) break;
                phase = 1;
            } else if (phase == 1 && strstr(all, "selftest-42")) {
                printf("[vmm-selftest] serial round trip: guest answered selftest-42\n");
                phase = 2;
                break;
            }
        }
        if (phase == 2) {
            char resp[256];
            int st = api_call(v, "PUT", "vm.pause", NULL, resp, sizeof resp, 4000);
            int st2 = api_call(v, "PUT", "vm.resume", NULL, resp, sizeof resp, 4000);
            printf("[vmm-selftest] api pause=%d resume=%d\n", st, st2);
            vm_action(a, v, A_POWEROFF);
            for (int k = 0; k < 100 && v->pid > 0; k++) { vm_poll(a, v); usleep(100000); }
            ok = st / 100 == 2 && st2 / 100 == 2 && v->pid <= 0;
            break;
        }
        /* wait like the GUI does: on the VMM's fds, so the console is drained as soon as it has data
         * (Cloud Hypervisor only retries a buffered serial write when the guest writes again) */
        struct pollfd pf[2]; int np = 0;
        if (v->serial_fd >= 0) pf[np++] = (struct pollfd){ .fd = v->serial_fd, .events = POLLIN };
        poll(pf, (nfds_t)np, 100);
    }
    if (!ok)                                              /* show why: the VMM's log and the console */
        for (int t = 0; t < 2; t++) {
            struct term *tm = t ? &v->con : &v->log;
            int from = tm->n > 40 ? tm->n - 40 : 0;
            for (int l = from; l < tm->n; l++) {
                char buf[TERM_COLS + 1];
                memcpy(buf, term_line(tm, l), TERM_COLS); buf[TERM_COLS] = 0;
                int len = TERM_COLS; while (len > 0 && buf[len - 1] == ' ') len--; buf[len] = 0;
                if (len) printf("[vmm-selftest] %s| %s\n", t ? "con" : "log", buf);
            }
        }
    printf("[vmm-selftest] %s (phase %d, state %s)\n", ok ? "PASS" : "FAIL", phase, k_state_name[v->state]);
    fflush(stdout);
    if (v->pid > 0) { kill(v->pid, SIGKILL); waitpid(v->pid, NULL, 0); }
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    static struct app app;
    struct app *a = &app;
    g_app = a;
    a->running = 1;
    a->sel = -1;
    signal(SIGPIPE, SIG_IGN);
    if (getenv("WLVMM_CH")) CH_PATH = getenv("WLVMM_CH");
    if (getenv("WLVMM_KERNEL")) BUNDLED_KERNEL = getenv("WLVMM_KERNEL");
    if (getenv("WLVMM_INITRD")) BUNDLED_INITRD = getenv("WLVMM_INITRD");
    if (getenv("WLVMM_RUNDIR")) RUN_DIR = getenv("WLVMM_RUNDIR");
    if (argc > 1 && !strcmp(argv[1], "--selftest")) { setvbuf(stdout, NULL, _IOLBF, 0); return selftest(a); }
    if (argc > 2 && !strcmp(argv[1], "--start-headless")) {
        setvbuf(stdout, NULL, _IOLBF, 0);
        probe_host(a);
        vm_reattach_all(a);
        return headless_start(a, argv[2]);
    }
    if (argc > 1 && !strcmp(argv[1], "--autostart")) {
        setvbuf(stdout, NULL, _IOLBF, 0);
        probe_host(a);
        vm_reattach_all(a);
        /* The firewall chosen at install starts with the system until the user unticks it
         * (Settings > General): with no list yet, it is the list. */
        if (access(AUTOSTART_LIST, F_OK) != 0 && opnsense_disk()) {
            struct vmcfg c;
            cfg_defaults(a, &c, OS_OPNSENSE);
            autostart_set(c.name, 1);
        }
        FILE *f = fopen(AUTOSTART_LIST, "r");
        int rc = 0;
        if (f) {
            char line[64];
            while (fgets(line, sizeof line, f)) {
                line[strcspn(line, "\n")] = 0;
                if (line[0]) rc |= headless_start(a, line);
            }
            fclose(f);
        }
        return rc;
    }

    probe_host(a);
    vm_reattach_all(a);                                   /* machines left running headless */
    for (int i = 0; i < MAX_VMS && a->sel < 0; i++) if (a->vms[i].used) a->sel = i;
    int have_opn = 0, have_alpine = 0;
    for (int i = 0; i < MAX_VMS; i++) if (a->vms[i].used) {
        if (a->vms[i].cfg.os == OS_OPNSENSE) have_opn = 1;
        if (a->vms[i].cfg.os == OS_ALPINE) have_alpine = 1;
    }
    if (opnsense_disk() && !have_opn) {                   /* the firewall chosen at install */
        struct vmcfg c;
        cfg_defaults(a, &c, OS_OPNSENSE);
        c.autostart = autostart_listed(c.name);
        int i = vm_add(a, &c);
        if (a->sel < 0) a->sel = i;
    }
    if (a->have_bundled && !have_alpine) {                /* a ready-made machine, like a sample appliance */
        struct vmcfg c;
        cfg_defaults(a, &c, OS_ALPINE);
        int i = vm_add(a, &c);
        if (a->sel < 0) a->sel = i;
    }
    if (!a->kvm_ok) set_banner(a, 2, a->kvm_errno == EACCES
                              ? "Virtualization is not enabled for this domain (Domain Manager > Permissions > Virtualization)"
                              : "/dev/kvm is not available: machines cannot start");
    else set_banner(a, 0, "Ready");

    a->display = wl_display_connect(NULL);
    if (!a->display) { perror("wl-vmm: wl_display_connect"); return 1; }
    a->registry = wl_display_get_registry(a->display);
    wl_registry_add_listener(a->registry, &reg_listener, a);
    wl_display_roundtrip(a->display);
    if (!a->compositor || !a->shm || !a->wm_base) { fprintf(stderr, "wl-vmm: missing Wayland globals\n"); return 1; }
    init_fonts(a);

    a->surface = wl_compositor_create_surface(a->compositor);
    a->xdg_surface = xdg_wm_base_get_xdg_surface(a->wm_base, a->surface);
    xdg_surface_add_listener(a->xdg_surface, &surf_listener, a);
    a->toplevel = xdg_surface_get_toplevel(a->xdg_surface);
    xdg_toplevel_add_listener(a->toplevel, &tl_listener, a);
    xdg_toplevel_set_title(a->toplevel, "Virtual Machines");
    xdg_toplevel_set_app_id(a->toplevel, epin_domain_appid("epinanonymos-vmm"));
    xdg_toplevel_set_min_size(a->toplevel, MIN_WIDTH, MIN_HEIGHT);
    wl_surface_commit(a->surface);
    wl_display_flush(a->display);

    time_t last_sec = 0;
    while (a->running) {
        struct pollfd pfd[1 + 2 * MAX_VMS];
        int np = 0;
        pfd[np++] = (struct pollfd){ .fd = wl_display_get_fd(a->display), .events = POLLIN };
        int active = 0;
        for (int i = 0; i < MAX_VMS; i++) {
            struct vm *v = &a->vms[i];
            if (!v->used || v->pid <= 0) continue;
            active = 1;
            if (v->serial_fd >= 0) pfd[np++] = (struct pollfd){ .fd = v->serial_fd, .events = POLLIN };
        }
        while (wl_display_prepare_read(a->display) != 0) wl_display_dispatch_pending(a->display);
        wl_display_flush(a->display);
        int pr = poll(pfd, (nfds_t)np, active ? 100 : 1000);
        if (pr > 0 && (pfd[0].revents & POLLIN)) wl_display_read_events(a->display);
        else wl_display_cancel_read(a->display);
        if (wl_display_dispatch_pending(a->display) < 0) break;
        for (int i = 0; i < MAX_VMS; i++) vm_poll(a, &a->vms[i]);
        time_t now = time(NULL);
        if (active && now != last_sec && a->view == VIEW_MACHINE && a->tab == TAB_DETAILS) a->dirty = 1;  /* uptime */
        if (now != last_sec) {                            /* the firewall download, while it runs */
            char fs[sizeof a->banner];
            if (fetch_status(fs, sizeof fs)) {
                if (strcmp(fs, a->banner)) { set_banner(a, 0, "%s", fs); a->dirty = 1; }
                a->fetch_pending = 1;
            } else if (a->fetch_pending && opnsense_disk()) {
                a->fetch_pending = 0;
                int have = 0;
                for (int i = 0; i < MAX_VMS; i++) if (a->vms[i].used && a->vms[i].cfg.os == OS_OPNSENSE) have = 1;
                if (!have) {
                    struct vmcfg c;
                    cfg_defaults(a, &c, OS_OPNSENSE);
                    c.autostart = autostart_listed(c.name);
                    vm_add(a, &c);
                }
                set_banner(a, 0, "The OPNsense firewall image is verified and ready");
                a->dirty = 1;
            }
        }
        last_sec = now;
        if (a->dirty && !a->frame_pending) render(a);
    }
    /* Running machines keep running headless: their VMMs are independent processes with their
     * own log files and state files, and the next launch re-attaches to them. */
    for (int i = 0; i < MAX_VMS; i++) {
        struct vm *v = &a->vms[i];
        if (v->used && v->pid > 0) {
            vm_write_state(v);
            printf("[vmm] \"%s\" keeps running headless (VMM pid %d)\n", v->cfg.name, (int)v->pid);
        }
    }
    fflush(stdout);
    return 0;
}
