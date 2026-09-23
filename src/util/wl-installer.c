#define _GNU_SOURCE

#include <cairo.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include <ft2build.h>
#include FT_FREETYPE_H

#include "xdg-shell-client-protocol.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum {
    DEFAULT_WIDTH = 820,
    DEFAULT_HEIGHT = 600,
};

/* The Ubuntu-style page sequence (roadmap §Phase 5):
 * Welcome · Language · Keyboard · Timezone · Network · Disk · Filesystem ·
 * Encryption · (Decoy) · Boot integrity · Account · Identities · Summary · Install. */
enum {
    SCREEN_WELCOME = 0,
    SCREEN_LANGUAGE,
    SCREEN_KEYBOARD,
    SCREEN_TIMEZONE,
    SCREEN_NETWORK,
    SCREEN_DRIVERS,
    SCREEN_DISK,
    SCREEN_FILESYSTEM,
    SCREEN_ENCRYPTION,
    SCREEN_DECOY,
    SCREEN_BOOTINTEGRITY,
    SCREEN_ACCOUNT,
    SCREEN_IDENTITIES,
    SCREEN_REVIEW,
    SCREEN_PROGRESS,
    SCREEN_COUNT,
};

/* Ordered walk through the wizard; SCREEN_DECOY is included only in Hidden-OS mode. */
static const int SCREEN_ORDER[] = {
    SCREEN_WELCOME, SCREEN_LANGUAGE, SCREEN_KEYBOARD, SCREEN_TIMEZONE,
    SCREEN_NETWORK, SCREEN_DRIVERS, SCREEN_DISK, SCREEN_FILESYSTEM, SCREEN_ENCRYPTION,
    SCREEN_DECOY, SCREEN_BOOTINTEGRITY, SCREEN_ACCOUNT, SCREEN_IDENTITIES,
    SCREEN_REVIEW, SCREEN_PROGRESS,
};

enum {
    FIELD_REAL_FULLNAME = 0,
    FIELD_HOSTNAME,
    FIELD_REAL_USER,
    FIELD_REAL_PASSWORD,
    FIELD_REAL_CONFIRM,
    FIELD_HIDDEN_PASSWORD,
    FIELD_HIDDEN_CONFIRM,
    FIELD_OUTER_PASSWORD,
    FIELD_OUTER_CONFIRM,
    FIELD_DECOY_BOOT_PASSWORD,
    FIELD_DECOY_BOOT_CONFIRM,
    FIELD_DECOY_USER,
    FIELD_DECOY_FULLNAME,
    FIELD_DECOY_PASSWORD,
    FIELD_DECOY_HOSTNAME,
    FIELD_KEYTEST,           /* Keyboard page test box: typed, shown, never saved */
    FIELD_COUNT,
};

enum {
    ENC_NONE = 0,
    ENC_FULL,
    ENC_HIDDEN,
};

/* Single-choice option lists (Language/Keyboard/Timezone/Network/Filesystem/Boot integrity).
 * `code` is what lands in install.json; `disabled` greys the row out (unselectable).
 * The subs are user-facing copy; the codes are the contract with the kernel and never
 * change here.  Per-row "About this choice" text comes from opt_detail(): the big
 * tables use one snprintf template each, the short ones have a *_DETAIL array below. */
struct opt {
    const char *label;
    const char *sub;
    const char *code;
    int disabled;
};

static const struct opt LOCALES[] = {
    { "English (US)",          "en_US.UTF-8 (default)", "en_US", 0 },
    { "English (UK)",          "en_GB.UTF-8", "en_GB", 0 },
    { "Spanish",               "es_ES.UTF-8", "es_ES", 0 },
    { "French",                "fr_FR.UTF-8", "fr_FR", 0 },
    { "German",                "de_DE.UTF-8", "de_DE", 0 },
    { "Italian",               "it_IT.UTF-8", "it_IT", 0 },
    { "Portuguese (Brazil)",   "pt_BR.UTF-8", "pt_BR", 0 },
    { "Dutch",                 "nl_NL.UTF-8", "nl_NL", 0 },
    { "Polish",                "pl_PL.UTF-8", "pl_PL", 0 },
    { "Russian",               "ru_RU.UTF-8", "ru_RU", 0 },
    { "Turkish",               "tr_TR.UTF-8", "tr_TR", 0 },
    { "Japanese",              "ja_JP.UTF-8", "ja_JP", 0 },
    { "Chinese (Simplified)",  "zh_CN.UTF-8", "zh_CN", 0 },
    { "Korean",                "ko_KR.UTF-8", "ko_KR", 0 },
    { "Arabic",                "ar_SA.UTF-8", "ar_SA", 0 },
    { "Hindi",                 "hi_IN.UTF-8", "hi_IN", 0 },
};

static const struct opt KEYMAPS[] = {
    { "English (US)",        "QWERTY (default)", "us",      0 },
    { "English (UK)",        "QWERTY",  "gb",      0 },
    { "German",              "QWERTZ",  "de",      0 },
    { "French",              "AZERTY",  "fr",      0 },
    { "Spanish",             "QWERTY",  "es",      0 },
    { "Italian",             "QWERTY",  "it",      0 },
    { "Portuguese (Brazil)", "QWERTY",  "br",      0 },
    { "Russian",             "JCUKEN",  "ru",      0 },
    { "Turkish",             "QWERTY",  "tr",      0 },
    { "Dvorak",              "Simplified Dvorak", "dvorak", 0 },
    { "Colemak",             "Ergonomic",  "colemak", 0 },
    { "Japanese",            "JIS",     "jp",      0 },
};

static const struct opt TIMEZONES[] = {
    { "UTC",                 "Coordinated Universal Time (default)", "UTC",       0 },
    { "America/New_York",    "Eastern Time",   "America/New_York",    0 },
    { "America/Chicago",     "Central Time",   "America/Chicago",     0 },
    { "America/Denver",      "Mountain Time",  "America/Denver",      0 },
    { "America/Los_Angeles", "Pacific Time",   "America/Los_Angeles", 0 },
    { "America/Sao_Paulo",   "Brasilia Time",  "America/Sao_Paulo",   0 },
    { "Europe/London",       "GMT / BST",      "Europe/London",       0 },
    { "Europe/Paris",        "Central European", "Europe/Paris",      0 },
    { "Europe/Berlin",       "Central European", "Europe/Berlin",     0 },
    { "Europe/Madrid",       "Central European", "Europe/Madrid",     0 },
    { "Europe/Moscow",       "Moscow Time",    "Europe/Moscow",       0 },
    { "Africa/Cairo",        "Eastern European", "Africa/Cairo",      0 },
    { "Asia/Dubai",          "Gulf Time",      "Asia/Dubai",          0 },
    { "Asia/Kolkata",        "India Time",     "Asia/Kolkata",        0 },
    { "Asia/Shanghai",       "China Time",     "Asia/Shanghai",       0 },
    { "Asia/Tokyo",          "Japan Time",     "Asia/Tokyo",          0 },
    { "Australia/Sydney",    "AEST",           "Australia/Sydney",    0 },
    { "Pacific/Auckland",    "NZST",           "Pacific/Auckland",    0 },
};

/* The network choice is recorded only (nothing is downloaded, no interface is
 * configured on the installed system); its one live effect is unlocking the
 * zkSync row on the Boot integrity page.  The copy says exactly that. */
static const struct opt NETWORKS[] = {
    { "Offline install",         "Recommended: nothing is fetched during installation (default)", "offline", 0 },
    { "Wired connection (DHCP)", "Note that this machine has a wired Ethernet link",             "wired",   0 },
    { "Wi-Fi",                   "Show the live Wi-Fi status; unlocks the zkSync option",         "wifi",    0 },
};
static const char *const NETWORK_DETAIL[] = {
    ("Recorded as offline. Nothing is downloaded either way and no network is set up on the "
    "installed system. zkSync boot attestation stays unavailable, which is the safe default "
    "because it needs a network at every boot."),
    ("Recorded as wired. Nothing is downloaded and no interface is configured by this choice. "
    "It only unlocks the zkSync option on the Boot integrity page; enable that only on an "
    "always-connected machine."),
    ("Recorded as wifi. The live session brought Wi-Fi up on its own; this choice does not "
    "start or stop it and configures nothing on the installed system."),
};

/* The kernel never formats ext4/btrfs/xfs: every choice writes the same FAT32 boot
 * images and the object store claims the free space at first boot. */
static const struct opt FILESYSTEMS[] = {
    { "ext4",  "Recorded as the preferred data filesystem (default)",  "ext4",  0 },
    { "Btrfs", "Recorded preference: copy-on-write with snapshots",   "btrfs", 0 },
    { "XFS",   "Recorded preference: high-throughput journaling",     "xfs",   0 },
};
static const char *const FILESYSTEM_DETAIL[] = {
    ("Recorded as ext4. Not applied: nothing is formatted with it. The disk gets FAT32 boot "
    "images and the object store takes the free space at first boot, whatever you pick here."),
    ("Recorded as btrfs. Not applied: no snapshots or compression are set up. The disk gets "
    "FAT32 boot images and the object store takes the free space at first boot, whatever "
    "you pick here."),
    ("Recorded as xfs. Not applied: no XFS volume is created. The disk gets FAT32 boot images "
    "and the object store takes the free space at first boot, whatever you pick here."),
};

static const struct opt BOOTINTEGRITY[] = {
    { "Off",                "No boot-time attestation (default, recommended)",             "off",    0 },
    { "zkSync attestation", "Verify the boot files on-chain at every boot; needs network", "zksync", 0 },
};
static const char *const BOOTINTEGRITY_DETAIL[] = {
    ("Recorded as off. The installed system boots without checking its boot files against any "
    "outside record. Safe for a machine that may ever start without a network."),
    ("Every boot hashes the boot files, compares them with the manifest, then checks the zkSync "
    "registry over the network. A mismatch, a missing manifest or no network stops the boot "
    "with a kernel panic."),
};

/* Toggleable identity profiles.  The kernel seeds its own fixed identity set on every
 * install; the ticks are recorded in install.json for when this becomes configurable. */
static const struct opt IDENTITIES[] = {
    { "Personal",   "Everyday browsing and personal files",              "personal",   0 },
    { "Work",       "Work email, documents, and tools",                  "work",       0 },
    { "Banking",    "Locked-down identity for financial sites",          "banking",    0 },
    { "Research",   "Isolated identity for investigations (recorded only)", "research", 0 },
    { "Disposable", "One-shot identity, wiped when closed",              "disposable", 0 },
    { "Anonymous",  "Routed for maximum anonymity (recorded only)",      "anonymous",  0 },
};
static const char *const IDENTITY_DETAIL[] = {
    ("Records 'personal'. Built in on every install: normal network, clipboard sharing asks "
    "first, home devices allowed. Ticking it changes nothing today."),
    ("Records 'work'. Built in on every install: VPN network policy, clipboard shared only "
    "inside Work, work device set. Ticking it changes nothing today."),
    ("Records 'banking'. Built in on every install: VPN network policy, clipboard denied, no "
    "camera, microphone, USB or audio. Ticking it changes nothing today."),
    ("Records 'research'. Not created from this list yet; the identity set is fixed today. The "
    "built-in Untrusted identity (Tor network policy, clipboard denied) covers this use."),
    ("Records 'disposable'. Built in on every install: ephemeral, wiped when closed, clipboard "
    "denied, locked-down devices. Ticking it changes nothing today."),
    ("Records 'anonymous'. Not created from this list yet. The built-in Untrusted identity "
    "routes over Tor and denies the clipboard; use it for anonymity today."),
};

/* Peripheral driver rows.  `code` is the Linux module name recorded in install.json;
 * /config/hardware.detect (PCI IDs found on this machine) pre-ticks matching rows.
 * Nothing is downloaded or installed into either system yet -- the detail template
 * in opt_detail() says so, and DRIVER_WHAT is the plain-words object of "Records X for". */
static const struct opt DRIVERS[] = {
    { "Wi-Fi (Intel)",      "iwlwifi + firmware for Intel AX/AC Wi-Fi",     "iwlwifi",       0 },
    { "Wi-Fi (Realtek)",    "rtw88/rtw89 for Realtek Wi-Fi (USB/PCIe)",     "rtw88",         0 },
    { "Ethernet (Intel)",   "e1000e/igb for Intel wired NICs",              "e1000e",        0 },
    { "Webcam (UVC)",       "uvcvideo for USB webcams",                     "uvcvideo",      0 },
    { "Microphone / Audio", "snd-usb-audio for USB microphones + audio",    "snd-usb-audio", 0 },
    { "Keyboard / Mouse",   "usbhid for USB keyboards + mice",              "usbhid",        0 },
};
static const char *const DRIVER_WHAT[] = {
    "Intel AX/AC Wi-Fi",
    "Realtek Wi-Fi",
    "Intel wired network cards",
    "USB webcams",
    "USB microphones and audio",
    "USB keyboards and mice",
};

#define ARRAY_LEN(a) ((int)(sizeof(a) / sizeof((a)[0])))

static int hex_digit(int c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static int zksync_attestation_has_contract(void)
{
    static int cached = -1;
    if (cached >= 0)
        return cached;

    cached = 0;
    int fd = open("/zksync-attestation.json", O_RDONLY);
    if (fd < 0)
        return 0;

    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = 0;

    char *key = strstr(buf, "\"contractAddress\"");
    if (!key)
        return 0;
    char *addr = strstr(key, "0x");
    if (!addr)
        return 0;

    int nonzero = 0;
    for (int i = 0; i < 40; ++i) {
        int c = addr[2 + i];
        if (!hex_digit(c))
            return 0;
        if (c != '0')
            nonzero = 1;
    }
    cached = nonzero;
    return cached;
}

struct disk_entry {
    int index;
    long size_mib;
    char role[16];
};

/* ── glyph cache ────────────────────────────────────────────────────────────
 * draw_text_ft used to re-render every glyph from its outline on every repaint,
 * calling FT_Set_Pixel_Sizes + FT_Load_Char(FT_LOAD_RENDER) per character per
 * frame (INST-01).  That is the single most expensive thing the installer does
 * on a software-rendered desktop.  Glyphs are cached here lazily, keyed by
 * (pixel size, printable ASCII byte): the 8-bit coverage bitmap is copied out of
 * the FreeType slot ONCE and reused, and FT_Set_Pixel_Sizes is only issued on a
 * cache miss whose size differs from the one the face is currently set to; the
 * per-size ascender is cached alongside so a hit never touches FreeType at all. */
enum {
    GLYPH_FIRST = 0x20,          /* first printable ASCII */
    GLYPH_LAST  = 0x7e,          /* last  printable ASCII */
    GLYPH_CHARS = GLYPH_LAST - GLYPH_FIRST + 1,
    GLYPH_MAX_PX = 32,           /* any px <= this may be cached */
    GLYPH_SIZE_SLOTS = 12,       /* distinct sizes; 7 (11..24) are used today */
};

struct glyph {
    int loaded;                  /* 0 until rendered the first time */
    unsigned char *bitmap;       /* 8-bit coverage, rows*pitch, malloc'd once */
    int width;
    int rows;
    int pitch;
    int left;                    /* FT bitmap_left */
    int top;                     /* FT bitmap_top  */
    int advance;                 /* pen advance in whole pixels */
};

struct glyph_size {
    int px;                      /* 0 == free slot */
    int ascender;                /* face ascender at this px, whole pixels (0 == not read yet) */
    struct glyph glyphs[GLYPH_CHARS];
};

/* One of two shm framebuffers over a single memfd (double buffering, INST-03).
 * `busy` is set when the buffer is attached/committed and cleared by the
 * compositor's wl_buffer.release, so the installer only ever draws into a buffer
 * the compositor is provably done reading. */
struct fbuf {
    struct wl_buffer *buffer;
    uint32_t *pixels;            /* into the shared mapping at `offset` */
    int busy;
};

/* ETA moving-window length, in one-second samples. */
#define RATE_WINDOW 16

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_output *output;
    struct wl_shm *shm;
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    struct wl_pointer *pointer;
    struct xdg_wm_base *wm_base;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;
    struct wl_callback *frame_cb;
    struct fbuf fb[2];                 /* two shm buffers over ONE memfd (double buffering) */
    uint32_t *map_base;                /* base of the 2-frame shared mapping (for munmap) */
    uint32_t *pixels;                  /* the fb currently being drawn into; draw_* target */
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size;
    size_t buffer_size;                /* bytes of ONE frame */
    size_t pool_size;                  /* == 2 * buffer_size */
    struct glyph_size glyph_sizes[GLYPH_SIZE_SLOTS];
    int glyph_cur_px;                  /* px the face is currently set to (0 == none) */
    int width;
    int height;
    int stride;
    int pending_width;
    int pending_height;
    int committed;
    int font_ready;
    int entry_focused;
    int shift;
    int sync_after_commit;
    int dirty;                 /* a repaint is wanted (coalesced; drained in the main loop) */
    int frame_pending;         /* a wl_surface_frame callback is outstanding (frame pacing) */
    int debug;                 /* EPIN_INSTALLER_DEBUG present at startup: verbose ilog */
    int running;
    int screen;
    int installing;
    int install_done;
    int install_failed;
    int install_zero_reads;    /* consecutive polls that read permille 0 (diagnostic only) */
    int progress;
    int focused_field;
    int encryption_mode;
    /* Full disk only: random-fill the WHOLE disk so it is indistinguishable from a Hidden-OS
     * install (hours on a large disk), or only what the layout needs (minutes).  Hidden OS always
     * fills -- there the fill IS what hides the hidden volume. */
    int fill_whole_disk;
    int install_config_written;
    double pointer_x;
    double pointer_y;
    char field_text[FIELD_COUNT][96];
    int field_len[FIELD_COUNT];

    /* single-choice selections (indices into the option arrays) */
    int locale_idx;
    int keymap_idx;
    int timezone_idx;
    int network_idx;
    int filesystem_idx;
    int bootintegrity_idx;

    /* identity profile toggles */
    int identity_on[16];

    /* peripheral driver toggles (SCREEN_DRIVERS) */
    int drivers_on[16];
    unsigned detected_mask;    /* DRIVERS rows /config/hardware.detect reported present */
    int hw_detect_present;     /* /config/hardware.detect was read (else "no scan") */

    /* Toggle lists (Drivers, Identities) keep a keyboard cursor separate from the
     * ticks: Up/Down move it, Space ticks it, and the card describes that row. */
    int list_cursor;

    /* disk enumeration from /config/disks.json; target_sel 0 = automatic */
    struct disk_entry disks[8];
    int disk_count;
    int target_sel;
    int target_index;       /* AHCI index to install to, or -1 for automatic */

    int list_scroll;        /* row offset for the current scrollable list */
    int content_scroll;     /* pixel scroll offset for the form-field content pane */
    int clip_top;           /* draw_text_ft vertical clip window (0/0 == no clip) */
    int clip_bottom;
    char install_cmd[32];   /* "install" or "install <idx>" */
    unsigned long last_done;   /* kernel sector counter, for stall detection */
    int  stall_polls;          /* consecutive polls with no sector progress */
    int  progress_fd;          /* /config/install.progress kept open across polls (-1 == closed) */
    int  install_phase;        /* last parsed phase (hex), for change detection */
    struct timespec last_poll; /* CLOCK_MONOTONIC stamp of the last progress poll (R-01) */
    double axis_accum;         /* accumulated scroll wheel/touchpad delta below one step */

    /* Kernel progress line beyond the permille: "p<phase> d<done> t<total> l<lba>".
     * phase_seen distinguishes "the GPT is being written" (no p yet) from phase 0. */
    int phase_seen;
    unsigned long done_sectors;
    unsigned long total_sectors;
    unsigned long lba;
    struct timespec install_start;   /* CLOCK_MONOTONIC stamp from start_install() */
    struct timespec install_end;     /* frozen at completion / failure ("took m:ss") */
    /* Moving window for the ETA.  A since-start average is wrong here because the phases have
     * wildly different costs (a 512 MiB AES-XTS image write, then a random fill that on a fast
     * erase credits gigabytes at once) -- it drags the slowest phase through the whole install
     * and reports hours when minutes are left.  Sample (second, sectors) once a second and quote
     * the rate over the last RATE_WINDOW samples instead. */
    long rate_t[RATE_WINDOW];        /* elapsed seconds at each sample */
    unsigned long rate_d[RATE_WINDOW]; /* done_sectors at each sample */
    int rate_n;                      /* samples taken (saturates; index is rate_n % RATE_WINDOW) */
    long rate_last_t;                /* elapsed second of the newest sample, -1 == none yet */
    int have_clock;                  /* clock_gettime succeeded at start */
    long last_stats_second;          /* elapsed second last painted (repaint gate) */
    int reboot_denied;               /* reboot(RB_AUTOBOOT) returned: show the fallback */

    /* Cached Wi-Fi link status for the Network page: /run/wifi/dhcp-ok is read at
     * most once per second (and on entry) instead of on every repaint (INST-11). */
    char wifi_ip[48];
    time_t wifi_checked;
};

/* ── geometry ──────────────────────────────────────────────────────────────── */

enum { SIDEBAR_W = 232, CONTENT_X = 264, CONTENT_PAD = 44 };

static int content_w(struct app *app) { return app->width - CONTENT_X - CONTENT_PAD; }

enum { BTN_PRIMARY = 0, BTN_SECONDARY = 1, BTN_BACK = 2 };
static void btn_rect(struct app *app, int which,
                     double *x, double *y, double *w, double *h)
{
    double W = app->width, H = app->height;
    *y = H - 74;
    *h = 46;
    if (which == BTN_BACK) {
        *x = CONTENT_X;
        *w = 124;
        return;
    }
    *w = 176;
    if (which == BTN_SECONDARY)
        *x = W - CONTENT_PAD - *w - 196;
    else
        *x = W - CONTENT_PAD - *w;
}

/* Pages whose main focus is a column of form fields get their own scroll pane so
 * a tall page never spills onto the button bar. */
static int screen_is_form(int screen)
{
    return screen == SCREEN_ACCOUNT || screen == SCREEN_ENCRYPTION ||
           screen == SCREEN_DECOY;
}

/* The "About this choice" card is the one slot every page shares: bottom-anchored,
 * its lower edge always 12px above the button bar.  Form pages and the progress
 * page keep it at 74px (two detail lines) so three field rows still fit at 600
 * tall; every other page gets 92px (three lines) because a list merely loses a
 * row.  Everything above it (lists, form panes) is sized from card_y(). */
static int card_h(struct app *app)
{
    return (screen_is_form(app->screen) || app->screen == SCREEN_PROGRESS) ? 74 : 92;
}
static int card_y(struct app *app) { return app->height - 86 - card_h(app); }
static void card_rect(struct app *app, int *x, int *y, int *w, int *h)
{
    if (x) *x = CONTENT_X;
    if (y) *y = card_y(app);
    if (w) *w = content_w(app);
    if (h) *h = card_h(app);
}

/* List viewport: rows of fixed height between the body paragraph and the card.
 * 5 rows fit at 600 tall (160..412), 7 at 746. */
enum { LIST_ROW_H = 50 };
static int list_top(struct app *app) { (void)app; return 160; }
static int list_bottom(struct app *app) { return card_y(app) - 10; }
static int list_view_h(struct app *app) { return list_bottom(app) - list_top(app); }
static int list_visible_rows(struct app *app)
{
    int r = list_view_h(app) / LIST_ROW_H;
    return r < 1 ? 1 : r;
}
static void list_row_rect(struct app *app, int visible_pos,
                          double *x, double *y, double *w, double *h)
{
    *x = CONTENT_X;
    *y = list_top(app) + visible_pos * LIST_ROW_H;
    *w = content_w(app);
    *h = LIST_ROW_H - 8;
}

/* ── helpers ───────────────────────────────────────────────────────────────── */

/* Install log: every line goes to stdout AND /run/installer.log.  The kernel
 * mirrors each write to a /run *.log file into the klog ring, so these lines
 * show LIVE in the desktop Logs app (filter "INSTALLER") and stay readable as
 * a plain file until reboot.  One persistent fd — the kernel fd pool is tiny
 * (same lesson as wl-files' create_buffer_once). */
static int g_ilog_fd = -2;

static void ilog(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line - 2, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if (n > (int)sizeof line - 2)
        n = (int)sizeof line - 2;
    line[n++] = '\n';
    line[n] = 0;
    if (g_ilog_fd == -2)
        g_ilog_fd = open("/run/installer.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_ilog_fd >= 0) {
        /* runtime .log writes mirror into klog, so skip stdout to avoid double lines */
        const char *p = line;
        size_t left = (size_t)n;
        while (left > 0) {
            ssize_t w = write(g_ilog_fd, p, left);
            if (w <= 0)
                break;
            p += w;
            left -= (size_t)w;
        }
    } else {
        fputs(line, stdout);
        fflush(stdout);
    }
}

static void log_line(const char *s)
{
    ilog("%s", s);
}

static void set_field(struct app *app, int field, const char *value)
{
    if (field < 0 || field >= FIELD_COUNT || !value)
        return;
    size_t n = strlen(value);
    if (n >= sizeof(app->field_text[field]))
        n = sizeof(app->field_text[field]) - 1;
    memcpy(app->field_text[field], value, n);
    app->field_text[field][n] = 0;
    app->field_len[field] = (int)n;
}

static const char *field_label(struct app *app, int field)
{
    switch (field) {
    case FIELD_REAL_FULLNAME: return "Your name";
    case FIELD_HOSTNAME: return "Computer name";
    case FIELD_REAL_USER: return "Username";
    case FIELD_REAL_PASSWORD: return "Password";
    case FIELD_REAL_CONFIRM: return "Confirm password";
    /* Full disk reuses the hidden-password pair for its ONE disk password; the
     * confirm fields on the Encryption page are half-width, so their label is
     * just "Confirm" (the pair's left label says what is being confirmed). */
    case FIELD_HIDDEN_PASSWORD:
        return app->encryption_mode == ENC_FULL ? "Disk encryption password"
                                                : "Hidden OS password";
    case FIELD_HIDDEN_CONFIRM:
        return app->encryption_mode == ENC_FULL ? "Confirm disk password" : "Confirm";
    case FIELD_OUTER_PASSWORD: return "Outer volume password";
    case FIELD_OUTER_CONFIRM: return "Confirm";
    case FIELD_DECOY_BOOT_PASSWORD: return "Decoy OS boot password";
    case FIELD_DECOY_BOOT_CONFIRM: return "Confirm";
    case FIELD_DECOY_USER: return "Decoy username";
    case FIELD_DECOY_FULLNAME: return "Decoy full name";
    case FIELD_DECOY_PASSWORD: return "Decoy login password";
    case FIELD_DECOY_HOSTNAME: return "Decoy computer name";
    default: return "";
    }
}

static int field_secret(int field)
{
    return field == FIELD_REAL_PASSWORD ||
           field == FIELD_REAL_CONFIRM ||
           field == FIELD_HIDDEN_PASSWORD ||
           field == FIELD_HIDDEN_CONFIRM ||
           field == FIELD_OUTER_PASSWORD ||
           field == FIELD_OUTER_CONFIRM ||
           field == FIELD_DECOY_BOOT_PASSWORD ||
           field == FIELD_DECOY_BOOT_CONFIRM ||
           field == FIELD_DECOY_PASSWORD;
}

/* The decoy details are recorded only (the decoy image keeps its built-in
 * account), so none of them is required; the keyboard test box is never saved. */
static int field_optional(int field)
{
    return field == FIELD_REAL_FULLNAME || field == FIELD_DECOY_FULLNAME ||
           field == FIELD_DECOY_USER || field == FIELD_DECOY_PASSWORD ||
           field == FIELD_DECOY_HOSTNAME || field == FIELD_KEYTEST;
}

/* Forward declarations for helpers defined with the disk / progress code below. */
static void fmt_size(long mib, char *buf, size_t cap);
static int auto_disk_index(struct app *app);
static int screen_visible(struct app *app, int s);

static const char *screen_title(struct app *app)
{
    switch (app->screen) {
    case SCREEN_WELCOME: return "Install EpinAnonymOS";
    case SCREEN_LANGUAGE: return "Language";
    case SCREEN_KEYBOARD: return "Keyboard layout";
    case SCREEN_TIMEZONE: return "Time zone";
    case SCREEN_NETWORK: return "Network";
    case SCREEN_DRIVERS: return "Peripheral drivers";
    case SCREEN_DISK: return "Installation disk";
    case SCREEN_FILESYSTEM: return "Filesystem";
    case SCREEN_ENCRYPTION: return "Encryption";
    case SCREEN_DECOY: return "Decoy operating system";
    case SCREEN_BOOTINTEGRITY: return "Boot integrity";
    case SCREEN_ACCOUNT: return "Who are you?";
    case SCREEN_IDENTITIES: return "Identity profiles";
    case SCREEN_REVIEW: return "Ready to install";
    case SCREEN_PROGRESS:
        if (app->install_failed) return "Installation failed";
        if (app->install_done) return "Installation complete";
        return "Installing EpinAnonymOS";
    default: return "Install EpinAnonymOS";
    }
}

/* Which disk the install actually targets, for copy: the chosen row, or what
 * Automatic resolves to (the lowest-index listed disk).  -1 when nothing is listed. */
static int chosen_disk_pos(struct app *app)
{
    if (app->target_sel > 0 && app->target_sel - 1 < app->disk_count)
        return app->target_sel - 1;
    return auto_disk_index(app);
}

/* "Disk 0 (64.0 GB)" for the chosen/auto disk, or `none` when nothing is listed. */
static void chosen_disk_text(struct app *app, char *buf, size_t cap, const char *none)
{
    int pos = chosen_disk_pos(app);
    if (pos < 0) {
        snprintf(buf, cap, "%s", none);
        return;
    }
    char sz[32];
    fmt_size(app->disks[pos].size_mib, sz, sizeof sz);
    snprintf(buf, cap, "Disk %d (%s)", app->disks[pos].index, sz);
}

static const char *layout_name(struct app *app)
{
    if (app->encryption_mode == ENC_HIDDEN) return "Hidden OS layout";
    if (app->encryption_mode == ENC_FULL)
        return app->fill_whole_disk ? "encrypted layout, whole disk erased"
                                    : "encrypted layout, fast erase";
    return "plain A/B layout";
}

/* One line, <= 72 chars, never wraps (drawn with draw_text_clip). */
static const char *screen_subtitle(struct app *app)
{
    static char progress_sub[128];
    switch (app->screen) {
    case SCREEN_WELCOME: return "Nothing is written to any disk until you confirm on the Summary page.";
    case SCREEN_LANGUAGE: return "Choose the language to record for the installed system.";
    case SCREEN_KEYBOARD: return "Record the layout of your keyboard, then test your keys below.";
    case SCREEN_TIMEZONE: return "Record the time zone for the installed system's clock.";
    case SCREEN_NETWORK: return "Networking is optional; nothing is downloaded during installation.";
    case SCREEN_DRIVERS: return "Hardware found on this machine is pre-ticked; tick what to record.";
    case SCREEN_DISK: return "The selected disk is erased completely; choose carefully.";
    case SCREEN_FILESYSTEM: return "A preference for the data area, recorded but not applied yet.";
    case SCREEN_ENCRYPTION: return "Plain install, full-disk encryption, or a Hidden OS with a decoy.";
    case SCREEN_DECOY: return "Details for the decoy Linux you can reveal under coercion.";
    case SCREEN_BOOTINTEGRITY: return "Optionally check the boot files against the zkSync registry at every boot.";
    case SCREEN_ACCOUNT: return "Create your account on the installed system.";
    case SCREEN_IDENTITIES: return "Separate worlds for the separate parts of your life.";
    case SCREEN_REVIEW: return "Check the summary; nothing has been written to the disk yet.";
    case SCREEN_PROGRESS: {
        char disk[48];
        if (app->target_sel == 0)
            snprintf(disk, sizeof disk, "the first disk (Automatic)");
        else
            chosen_disk_text(app, disk, sizeof disk, "the chosen disk");
        snprintf(progress_sub, sizeof progress_sub, "Writing to %s  -  %s", disk, layout_name(app));
        return progress_sub;
    }
    default: return "";
    }
}

/* The 12px paragraph under the subtitle (max 2 lines; Encryption draws its
 * mode-dependent paragraph under the segments instead, Welcome has its own flow). */
static const char *screen_body(struct app *app)
{
    switch (app->screen) {
    case SCREEN_LANGUAGE:
        return "No translations ship yet: the installed system runs in English whatever you pick. "
               "Your choice is saved in install.json for when localisation lands, so any choice is safe.";
    case SCREEN_KEYBOARD:
        return "Saved as the keymap but not applied yet: this session and the installed system both "
               "use the built-in US layout. Type in the box below before you choose any password.";
    case SCREEN_TIMEZONE:
        return "The installed system keeps its clock in UTC for now. Your choice is saved in "
               "install.json and will set the local time once time zone support lands, so any choice is safe.";
    case SCREEN_NETWORK:
        return "Recorded only: it changes nothing on the installed system. It decides whether the "
               "zkSync option on the Boot integrity page can be picked, and Wi-Fi shows the live link status.";
    case SCREEN_DRIVERS:
        return "Pre-ticked from the PCI devices found on this machine and saved as a list in "
               "install.json. No driver or firmware is downloaded or installed into either system yet.";
    case SCREEN_DISK:
        return "Everything on it is lost. A plain install rewrites the first 1.1 GB and leaves the rest "
               "as free space for your data; an encrypted install overwrites every sector.";
    case SCREEN_FILESYSTEM:
        return "No ext4, Btrfs or XFS is formatted: the system lives in FAT32 boot images and the "
               "object store claims the free space at first boot. All three choices write the same disk.";
    case SCREEN_ENCRYPTION:
        if (app->encryption_mode == ENC_HIDDEN)
            return "A decoy Linux, an encrypted outer volume, and the real EpinAnonymOS hidden inside "
                   "it. Three passwords; every sector of the disk is erased first.";
        if (app->encryption_mode == ENC_FULL)
            return "One password, asked at the pre-boot prompt before anything starts. The erase "
                   "mode below is the difference between a few minutes and several hours.";
        return "The system is written unencrypted: a small boot manager plus two identical 512 MB "
               "system slots. Anyone holding the disk can read it, including the password hashes in "
               "install.json. Choose Full disk or Hidden OS to encrypt it.";
    case SCREEN_DECOY:
        return "A prebuilt Linux written encrypted to its own partition and started with the decoy "
               "boot password. The details below are recorded only; the decoy image is not changed.";
    case SCREEN_BOOTINTEGRITY:
        return "Off does nothing. zkSync checks the boot files against the manifest and an on-chain "
               "record at every boot; a mismatch, a missing manifest or no network stops the boot.";
    case SCREEN_ACCOUNT:
        return "Username and computer name are applied at every boot. The password is kept as a hash "
               "only and login does not ask for it yet, so anyone at the keyboard can use the system.";
    case SCREEN_IDENTITIES:
        return "The built-in identities (System, Personal, Work, Banking, Development, Untrusted, "
               "Disposable) are always created. Your ticks are saved for when this becomes configurable.";
    default: return "";
    }
}

static const char *screen_short_name(int s)
{
    switch (s) {
    case SCREEN_WELCOME: return "Welcome";
    case SCREEN_LANGUAGE: return "Language";
    case SCREEN_KEYBOARD: return "Keyboard";
    case SCREEN_TIMEZONE: return "Time zone";
    case SCREEN_NETWORK: return "Network";
    case SCREEN_DRIVERS: return "Drivers";
    case SCREEN_DISK: return "Disk";
    case SCREEN_FILESYSTEM: return "Filesystem";
    case SCREEN_ENCRYPTION: return "Encryption";
    case SCREEN_DECOY: return "Decoy OS";
    case SCREEN_BOOTINTEGRITY: return "Boot integrity";
    case SCREEN_ACCOUNT: return "Account";
    case SCREEN_IDENTITIES: return "Identities";
    case SCREEN_REVIEW: return "Summary";
    case SCREEN_PROGRESS: return "Install";
    default: return "";
    }
}

/* "Step k of N" over the visible SCREEN_ORDER entries (N is 14, or 15 with the
 * Decoy page in Hidden-OS mode); Welcome is step 1, Install is step N. */
static void step_position(struct app *app, int *k, int *n)
{
    int pos = 0, cur = 1;
    for (size_t i = 0; i < sizeof(SCREEN_ORDER) / sizeof(SCREEN_ORDER[0]); i++) {
        int s = SCREEN_ORDER[i];
        if (!screen_visible(app, s))
            continue;
        pos++;
        if (s == app->screen)
            cur = pos;
    }
    *k = cur;
    *n = pos;
}

/* The two key-hint lines under the step counter (each <= 30 chars). */
static void screen_hints(struct app *app, const char **l1, const char **l2)
{
    *l1 = "";
    *l2 = "";
    switch (app->screen) {
    case SCREEN_WELCOME: *l1 = "Enter: begin"; break;
    case SCREEN_KEYBOARD: *l1 = "Up/Down: choose  type to test"; *l2 = "Enter: continue  Esc: back"; break;
    case SCREEN_DRIVERS:
    case SCREEN_IDENTITIES: *l1 = "Up/Down: move  Space: tick"; *l2 = "Enter: continue  Esc: back"; break;
    case SCREEN_ACCOUNT:
    case SCREEN_DECOY: *l1 = "Tab: next field"; *l2 = "Enter: continue  Esc: back"; break;
    /* The erase-mode row says what it does on the row itself, so the hint stays short enough
     * not to be clipped by the sidebar (it was, at "Tab: field..."). */
    case SCREEN_ENCRYPTION: *l1 = "Left/Right: mode  Tab: field"; *l2 = "Enter: continue  Esc: back"; break;
    case SCREEN_REVIEW: *l1 = "Enter: Install Now"; *l2 = "Back: change a choice"; break;
    case SCREEN_PROGRESS: break;
    default: *l1 = "Up/Down: choose"; *l2 = "Enter: continue  Esc: back"; break;
    }
}

static const char *primary_label(struct app *app)
{
    switch (app->screen) {
    case SCREEN_WELCOME: return "Install";
    case SCREEN_REVIEW: return "Install Now";
    case SCREEN_PROGRESS:
        if (app->install_failed) return "Close";
        if (app->install_done) return app->reboot_denied ? "Close" : "Restart now";
        return "Installing";
    default: return "Continue";
    }
}

/* ── option-list dispatch (keeps draw + click in sync per screen) ───────────── */

static int screen_is_list(int s)
{
    return s == SCREEN_LANGUAGE || s == SCREEN_KEYBOARD || s == SCREEN_TIMEZONE ||
           s == SCREEN_NETWORK || s == SCREEN_FILESYSTEM || s == SCREEN_BOOTINTEGRITY;
}

static const struct opt *screen_opts(int s, int *count)
{
    switch (s) {
    case SCREEN_LANGUAGE:      *count = ARRAY_LEN(LOCALES);       return LOCALES;
    case SCREEN_KEYBOARD:      *count = ARRAY_LEN(KEYMAPS);       return KEYMAPS;
    case SCREEN_TIMEZONE:      *count = ARRAY_LEN(TIMEZONES);     return TIMEZONES;
    case SCREEN_NETWORK:       *count = ARRAY_LEN(NETWORKS);      return NETWORKS;
    case SCREEN_FILESYSTEM:    *count = ARRAY_LEN(FILESYSTEMS);   return FILESYSTEMS;
    case SCREEN_BOOTINTEGRITY: *count = ARRAY_LEN(BOOTINTEGRITY); return BOOTINTEGRITY;
    default: *count = 0; return NULL;
    }
}

static int *screen_sel_ptr(struct app *app, int s)
{
    switch (s) {
    case SCREEN_LANGUAGE:      return &app->locale_idx;
    case SCREEN_KEYBOARD:      return &app->keymap_idx;
    case SCREEN_TIMEZONE:      return &app->timezone_idx;
    case SCREEN_NETWORK:       return &app->network_idx;
    case SCREEN_FILESYSTEM:    return &app->filesystem_idx;
    case SCREEN_BOOTINTEGRITY: return &app->bootintegrity_idx;
    default: return NULL;
    }
}

/* Boot-integrity zkSync attestation needs the network step and a deployed registry;
 * the row is greyed out otherwise and the REASON is shown on the row itself
 * (opt_disabled_reason) instead of a bare "unavailable". */
static int opt_is_disabled(struct app *app, int s, int idx)
{
    int count = 0;
    const struct opt *o = screen_opts(s, &count);
    if (!o || idx < 0 || idx >= count)
        return 0;
    if (o[idx].disabled)
        return 1;
    if (s == SCREEN_BOOTINTEGRITY && strcmp(o[idx].code, "zksync") == 0 &&
        strcmp(NETWORKS[app->network_idx].code, "offline") == 0)
        return 1;
    if (s == SCREEN_BOOTINTEGRITY && strcmp(o[idx].code, "zksync") == 0 &&
        !zksync_attestation_has_contract())
        return 1;
    return 0;
}

static const char *opt_disabled_reason(struct app *app, int s, int idx)
{
    int count = 0;
    const struct opt *o = screen_opts(s, &count);
    if (!o || idx < 0 || idx >= count || !opt_is_disabled(app, s, idx))
        return "";
    if (s == SCREEN_BOOTINTEGRITY) {
        if (strcmp(NETWORKS[app->network_idx].code, "offline") == 0)
            return "needs Wired or Wi-Fi";
        return "no registry on this medium";
    }
    return "unavailable";
}

/* ── disk enumeration ──────────────────────────────────────────────────────── */

static void load_disks(struct app *app)
{
    app->disk_count = 0;
    int fd = open("/config/disks.json", O_RDONLY);
    if (fd < 0) {
        ilog("INSTALLER: ERROR /config/disks.json open failed (errno=%d) -- no install targets", errno);
        return;
    }
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        ilog("INSTALLER: ERROR /config/disks.json empty read (n=%zd errno=%d)", n, errno);
        return;
    }
    buf[n] = 0;

    const char *p = buf;
    while (app->disk_count < (int)(sizeof(app->disks) / sizeof(app->disks[0]))) {
        const char *ix = strstr(p, "\"index\":");
        if (!ix)
            break;
        struct disk_entry *d = &app->disks[app->disk_count];
        d->index = (int)strtol(ix + 8, NULL, 10);
        const char *sm = strstr(ix, "\"sizeMiB\":");
        d->size_mib = sm ? strtol(sm + 10, NULL, 10) : 0;
        const char *rl = strstr(ix, "\"role\":");
        d->role[0] = 0;
        if (rl) {
            rl += 7;
            while (*rl == ' ') rl++;
            if (*rl == '"') rl++;
            int k = 0;
            while (*rl && *rl != '"' && k < (int)sizeof(d->role) - 1)
                d->role[k++] = *rl++;
            d->role[k] = 0;
        }
        app->disk_count++;
        ilog("INSTALLER: disk %d: %ld MiB (%s)", d->index, d->size_mib,
             d->role[0] ? d->role : "available");
        p = sm ? sm + 10 : ix + 8;
    }
    ilog("INSTALLER: enumerated %d disk(s) from /config/disks.json", app->disk_count);
}

/* Disk page rows: row 0 is Automatic, rows 1..N are the enumerated disks. */
static int disk_row_count(struct app *app) { return 1 + app->disk_count; }

/* A plain A/B install needs ~1034 MiB (8 MB boot manager + two 512 MB slots +
 * GPT); anything under this is refused by the kernel, so the row is disabled
 * here rather than letting the install fail after the disk was already erased. */
enum { MIN_DISK_MIB = 1040 };

/* "12.3 GB" for >=1 GiB, else "512 MB". */
static void fmt_size(long mib, char *buf, size_t cap)
{
    if (mib >= 1024) {
        long gb10 = mib * 10 / 1024;
        snprintf(buf, cap, "%ld.%ld GB", gb10 / 10, gb10 % 10);
    } else {
        snprintf(buf, cap, "%ld MB", mib);
    }
}

/* Position (in app->disks) of the disk Automatic resolves to: the kernel takes
 * the NVMe drive, otherwise the lowest-numbered SATA disk, which in the listing
 * is simply the lowest index.  -1 when nothing was listed. */
static int auto_disk_index(struct app *app)
{
    int best = -1;
    for (int i = 0; i < app->disk_count; i++)
        if (best < 0 || app->disks[i].index < app->disks[best].index)
            best = i;
    return best;
}

static int disk_row_disabled(struct app *app, int row)
{
    if (row <= 0 || row - 1 >= app->disk_count)
        return 0;
    return app->disks[row - 1].size_mib < MIN_DISK_MIB;
}

static void disk_row_text(struct app *app, int row, char *label, size_t lcap,
                          char *sub, size_t scap)
{
    if (row == 0) {
        snprintf(label, lcap, "Automatic");
        snprintf(sub, scap, "The first disk the firmware boots from (usually Disk 0)");
        return;
    }
    struct disk_entry *d = &app->disks[row - 1];
    char sz[32];
    fmt_size(d->size_mib, sz, sizeof sz);
    snprintf(label, lcap, "Disk %d", d->index);
    /* The store/target role from disks.json is logged but never shown: on live
     * media the "store" is the first disk, which is exactly what Automatic picks. */
    if (d->size_mib < MIN_DISK_MIB)
        snprintf(sub, scap, "%s  -  too small for any install", sz);
    else if (row - 1 == auto_disk_index(app))
        snprintf(sub, scap, "%s  -  first disk in boot order (what Automatic picks)", sz);
    else
        snprintf(sub, scap, "%s  -  additional disk", sz);
}

/* Fixed reserve the kernel's encrypted layout takes before the outer volume: the
 * 512 MB boot partition plus the decoy system partition (64 MB minimum).  Only
 * used for the Decoy page's "rest of the disk" estimate. */
enum { DISK_OVERHEAD_MIB = 576, DISK_DEFAULT_MIB = 65536 /* 64 GiB fallback */ };

static long selected_disk_mib(struct app *app)
{
    if (app->target_sel > 0 && app->target_sel - 1 < app->disk_count) {
        long m = app->disks[app->target_sel - 1].size_mib;
        if (m > 0) return m;
    }
    if (app->disk_count > 0 && app->disks[0].size_mib > 0)
        return app->disks[0].size_mib;
    return DISK_DEFAULT_MIB;
}

/* ── fields per screen ─────────────────────────────────────────────────────── */

/* Order == Tab order == reading order (left to right, top to bottom). */
static int fields_for_screen(struct app *app, int out[], int max)
{
    int n = 0;
    if (app->screen == SCREEN_ACCOUNT) {
        int f[] = { FIELD_REAL_FULLNAME, FIELD_REAL_USER, FIELD_HOSTNAME,
                    FIELD_REAL_PASSWORD, FIELD_REAL_CONFIRM };
        for (size_t i = 0; i < sizeof(f) / sizeof(f[0]) && n < max; i++) out[n++] = f[i];
    } else if (app->screen == SCREEN_ENCRYPTION) {
        if (app->encryption_mode == ENC_FULL) {
            /* Full disk: one password + confirm for the whole system volume. */
            if (n < max) out[n++] = FIELD_HIDDEN_PASSWORD;
            if (n < max) out[n++] = FIELD_HIDDEN_CONFIRM;
        }
        if (app->encryption_mode == ENC_HIDDEN) {
            int f[] = { FIELD_HIDDEN_PASSWORD, FIELD_HIDDEN_CONFIRM,
                        FIELD_OUTER_PASSWORD, FIELD_OUTER_CONFIRM,
                        FIELD_DECOY_BOOT_PASSWORD, FIELD_DECOY_BOOT_CONFIRM };
            for (size_t i = 0; i < sizeof(f) / sizeof(f[0]) && n < max; i++) out[n++] = f[i];
        }
    } else if (app->screen == SCREEN_DECOY) {
        int f[] = { FIELD_DECOY_USER, FIELD_DECOY_FULLNAME, FIELD_DECOY_PASSWORD, FIELD_DECOY_HOSTNAME };
        for (size_t i = 0; i < sizeof(f) / sizeof(f[0]) && n < max; i++) out[n++] = f[i];
    } else if (app->screen == SCREEN_KEYBOARD) {
        if (n < max) out[n++] = FIELD_KEYTEST;
    }
    return n;
}

/* On the Encryption screen the segmented control occupies ordinal 0, fields below it. */
static int field_ordinal_base(struct app *app)
{
    return app->screen == SCREEN_ENCRYPTION ? 1 : 0;
}

/* Paired fields: the right-hand member of a pair shares its predecessor's row in
 * column 1 and both become half-width.  Pairing keeps every form on one screen at
 * 820x600 (no scrolling), and the pairs are the natural ones: a value and its
 * confirmation, a name and its username. */
static int field_pair_right(int f)
{
    return f == FIELD_REAL_USER || f == FIELD_REAL_CONFIRM ||
           f == FIELD_HIDDEN_CONFIRM || f == FIELD_OUTER_CONFIRM ||
           f == FIELD_DECOY_BOOT_CONFIRM || f == FIELD_DECOY_FULLNAME ||
           f == FIELD_DECOY_HOSTNAME;
}

/* Row/column/half for `field` on the current screen; returns 0 if it is not on it. */
static int field_layout(struct app *app, int field, int *row, int *col, int *half)
{
    int fields[8];
    int n = fields_for_screen(app, fields, 8);
    int r = -1;
    for (int i = 0; i < n; i++) {
        int right = i > 0 && field_pair_right(fields[i]);
        if (!right)
            r++;
        if (fields[i] == field) {
            *row = r;
            *col = right ? 1 : 0;
            *half = right || (i + 1 < n && field_pair_right(fields[i + 1]));
            return 1;
        }
    }
    *row = 0; *col = 0; *half = 0;
    return 0;
}

/* Rows of fields start at 172 on Account/Decoy (4px under the body paragraph) and,
 * with the segmented control taking ordinal 0, at 250 on Encryption. */
enum { FIELD_STEP = 66, FIELD_H = 42 };
static int field_y0(struct app *app)
{
    return app->screen == SCREEN_ENCRYPTION ? 184 : 172;
}

static void field_rect(struct app *app, int field,
                       double *x, double *y, double *w, double *h)
{
    int row, col, half;
    field_layout(app, field, &row, &col, &half);
    int cw = content_w(app);
    *x = CONTENT_X + col * ((cw + 12) / 2);
    *w = half ? (cw - 12) / 2 : cw;
    *y = field_y0(app) + (row + field_ordinal_base(app)) * FIELD_STEP - app->content_scroll;
    *h = FIELD_H;
}

/* The erase-mode row on the Encryption page (Full disk only).  It sits in the field pane, one
 * row below the password pair, and is a real clickable control rather than a keyboard-only
 * shortcut: this choice is the difference between a ten-minute install and an all-day one, and
 * a person should not have to discover a hotkey to find it.  Hidden OS does not get the row --
 * there the whole-disk pass IS the concealment, so there is nothing to choose. */
static int erase_row_visible(struct app *app)
{
    return app->screen == SCREEN_ENCRYPTION && app->encryption_mode == ENC_FULL;
}
static void erase_row_rect(struct app *app, double *x, double *y, double *w, double *h)
{
    /* Row 1 of the field pane (the password pair shares row 0). */
    *x = CONTENT_X;
    *w = content_w(app);
    *y = field_y0(app) + (1 + field_ordinal_base(app)) * FIELD_STEP - app->content_scroll;
    *h = FIELD_H;
}

/* ── scrollable form content pane ───────────────────────────────────────────── */
static int content_view_top(struct app *app)
{
    /* Encryption keeps its segmented control + mode paragraph fixed above the pane. */
    return app->screen == SCREEN_ENCRYPTION ? 224 : 152;
}
static int content_view_bottom(struct app *app)
{
    return card_y(app) - 10;   /* clears the card + button bar */
}

static void segment_rect(struct app *app, int which,
                         double *x, double *y, double *w, double *h)
{
    double gap = 10;
    double total = content_w(app);
    *w = (total - 2 * gap) / 3.0;
    *x = CONTENT_X + which * (*w + gap);
    *y = 126;
    *h = 46;
}

/* Decoy page partition readout: header at 300, four rows from 318 pitch 18. */
enum { DECOY_READOUT_Y = 300, DECOY_READOUT_BOTTOM = 392 };

/* Lowest content-space Y (no scroll) the current form page draws to. */
static int content_natural_bottom(struct app *app)
{
    int fields[8];
    int n = fields_for_screen(app, fields, 8);
    int bottom = content_view_top(app);
    if (n > 0) {
        int row, col, half;
        field_layout(app, fields[n - 1], &row, &col, &half);
        bottom = field_y0(app) + (row + field_ordinal_base(app)) * FIELD_STEP + FIELD_H;
    }
    if (app->screen == SCREEN_DECOY && DECOY_READOUT_BOTTOM > bottom)
        bottom = DECOY_READOUT_BOTTOM;
    return bottom;
}

static int content_max_scroll(struct app *app)
{
    if (!screen_is_form(app->screen)) return 0;
    int over = content_natural_bottom(app) - content_view_bottom(app);
    return over > 0 ? over : 0;
}

static void clamp_content_scroll(struct app *app)
{
    int maxs = content_max_scroll(app);
    if (app->content_scroll < 0) app->content_scroll = 0;
    if (app->content_scroll > maxs) app->content_scroll = maxs;
}

/* Scroll so the focused field (and its label 20px above it) is inside the pane. */
static void ensure_field_visible(struct app *app)
{
    if (!screen_is_form(app->screen)) return;
    int f = app->focused_field;
    if (f < 0) { clamp_content_scroll(app); return; }
    int row, col, half;
    if (!field_layout(app, f, &row, &col, &half)) { clamp_content_scroll(app); return; }
    int top = field_y0(app) + (row + field_ordinal_base(app)) * FIELD_STEP;
    int bot = top + FIELD_H;
    int vt = content_view_top(app), vb = content_view_bottom(app);
    if (top - 20 - app->content_scroll < vt)
        app->content_scroll = top - 20 - vt;
    if (bot - app->content_scroll > vb)
        app->content_scroll = bot - vb;
    clamp_content_scroll(app);
}

static void focus_first_field(struct app *app)
{
    int fields[8];
    int n = fields_for_screen(app, fields, 8);
    app->focused_field = n > 0 ? fields[0] : -1;
    ensure_field_visible(app);
}

static void cycle_focus(struct app *app)
{
    int fields[8];
    int n = fields_for_screen(app, fields, 8);
    if (n <= 0) {
        app->focused_field = -1;
        return;
    }
    for (int i = 0; i < n; i++) {
        if (fields[i] == app->focused_field) {
            /* On the Encryption page the erase-mode row is the last stop in the Tab cycle, marked
             * by focused_field == -1.  It needs a place in the cycle because the obvious binding
             * is not available: Space belongs to the passphrase field this page is built around,
             * and a passphrase with spaces in it is good practice, not an edge case.  Without this
             * the row was clickable and nothing else -- unreachable on a machine whose pointer has
             * not come up, which is a live installer's normal failure mode. */
            if (i == n - 1 && erase_row_visible(app)) { app->focused_field = -1; return; }
            app->focused_field = fields[(i + 1) % n];
            ensure_field_visible(app);
            return;
        }
    }
    app->focused_field = fields[0];          /* also the wrap from the erase row back to field 0 */
    ensure_field_visible(app);
}

/* ── validation ────────────────────────────────────────────────────────────── */

/* The kernel silently IGNORES a username or hostname with any other character and
 * keeps its default ("user" / "epin"), so the installer must refuse them here. */
static int valid_username(const char *s)   /* [A-Za-z0-9_-], 1..31 (USER_NAME_MAX-1) */
{
    size_t n = strlen(s);
    if (n < 1 || n > 31) return 0;
    for (; *s; s++) {
        int c = (unsigned char)*s;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

static int valid_hostname(const char *s)   /* [A-Za-z0-9-], 1..64 */
{
    size_t n = strlen(s);
    if (n < 1 || n > 64) return 0;
    for (; *s; s++) {
        int c = (unsigned char)*s;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-'))
            return 0;
    }
    return 1;
}

static int pair_mismatch(struct app *app, int pw, int confirm)
{
    return app->field_len[confirm] > 0 &&
           strcmp(app->field_text[pw], app->field_text[confirm]) != 0;
}

/* Installer rule for Hidden OS: the same password could open the wrong volume at
 * the preboot prompt, so hidden, outer and decoy-boot passwords must all differ. */
static int enc_passwords_distinct(struct app *app)
{
    const char *h = app->field_text[FIELD_HIDDEN_PASSWORD];
    const char *o = app->field_text[FIELD_OUTER_PASSWORD];
    const char *d = app->field_text[FIELD_DECOY_BOOT_PASSWORD];
    if (!h[0] || !o[0] || !d[0])
        return 1;                     /* judged only once all three are typed */
    return strcmp(h, o) != 0 && strcmp(h, d) != 0 && strcmp(o, d) != 0;
}

/* Card detail colours. */
enum {
    COL_DETAIL = 0xffc8d2df,
    COL_RED    = 0xffff8a8a,
    COL_AMBER  = 0xffffd08a,
    COL_GREEN  = 0xff57d977,
    COL_MUTED  = 0xff8b96a4,
};

struct vmsg {
    char text[400];
    uint32_t color;
    int blocking;
};

static void vmsg_set(struct vmsg *m, uint32_t color, int blocking, const char *text)
{
    snprintf(m->text, sizeof m->text, "%s", text);
    m->color = color;
    m->blocking = blocking;
}

/* The one validation message a form page shows (in its card), first match in
 * priority order: blocking red > non-blocking amber > focused-field helper >
 * requirement reminder (muted, blocking) > ready (green).  Continue is disabled
 * exactly when the chosen message is blocking. */
static void form_validate(struct app *app, struct vmsg *m)
{
    int f = app->focused_field;
    m->text[0] = 0;
    m->color = COL_DETAIL;
    m->blocking = 0;

    if (app->screen == SCREEN_ACCOUNT) {
        const char *user = app->field_text[FIELD_REAL_USER];
        const char *host = app->field_text[FIELD_HOSTNAME];
        if (user[0] && !valid_username(user)) {
            vmsg_set(m, COL_RED, 1, "Username: letters, digits, _ and - only, 1-31 characters. "
                     "The kernel would silently keep 'user' otherwise.");
            return;
        }
        if (host[0] && !valid_hostname(host)) {
            vmsg_set(m, COL_RED, 1, "Computer name: letters, digits and - only, 1-64 characters. "
                     "The kernel would silently keep 'epin' otherwise.");
            return;
        }
        if (pair_mismatch(app, FIELD_REAL_PASSWORD, FIELD_REAL_CONFIRM)) {
            vmsg_set(m, COL_RED, 1, "Passwords do not match.");
            return;
        }
        if (!user[0] || !host[0] || app->field_len[FIELD_REAL_PASSWORD] == 0 ||
            app->field_len[FIELD_REAL_CONFIRM] == 0) {
            vmsg_set(m, COL_MUTED, 1, "Username, computer name and password are required.");
            return;
        }
        if (app->field_len[FIELD_REAL_PASSWORD] < 8) {
            vmsg_set(m, COL_AMBER, 0, "Short password: use at least 8 characters.");
            return;
        }
        if (f == FIELD_REAL_FULLNAME)
            vmsg_set(m, COL_DETAIL, 0, "Optional. Recorded in install.json only; it is not shown at login.");
        else if (f == FIELD_REAL_USER)
            snprintf(m->text, sizeof m->text, "Your login name and home folder, /home/%s. "
                     "Letters, digits, _ and -, 1-31 characters. Applied at every boot.", user);
        else if (f == FIELD_HOSTNAME)
            vmsg_set(m, COL_DETAIL, 0, "The name of the installed system on a network. Letters, "
                     "digits and - only, 1-64 characters. Applied at every boot.");
        else if (f == FIELD_REAL_PASSWORD)
            vmsg_set(m, COL_DETAIL, 0, "Stored as an unsalted SHA-512 hash in install.json on the "
                     "boot partition. Not yet used for login, lock screen or sudo.");
        else if (f == FIELD_REAL_CONFIRM)
            vmsg_set(m, COL_DETAIL, 0, "Type the password again.");
        if (m->text[0])
            return;
        snprintf(m->text, sizeof m->text, "Ready: '%s' on '%s'. Remember: login does not ask "
                 "for the password yet.", user, host);
        m->color = COL_GREEN;
        return;
    }

    if (app->screen == SCREEN_ENCRYPTION && app->encryption_mode == ENC_FULL) {
        if (pair_mismatch(app, FIELD_HIDDEN_PASSWORD, FIELD_HIDDEN_CONFIRM)) {
            vmsg_set(m, COL_RED, 1, "Disk passwords do not match.");
            return;
        }
        if (app->field_len[FIELD_HIDDEN_PASSWORD] == 0 || app->field_len[FIELD_HIDDEN_CONFIRM] == 0) {
            vmsg_set(m, COL_MUTED, 1, "The disk password is required; it is asked at every boot "
                     "before EpinAnonymOS starts.");
            return;
        }
        if (app->field_len[FIELD_HIDDEN_PASSWORD] < 8) {
            vmsg_set(m, COL_AMBER, 0, "Short: use at least 8 characters for the disk password.");
            return;
        }
        if (f == FIELD_HIDDEN_PASSWORD) {
            vmsg_set(m, COL_DETAIL, 0, "Unlocks the whole EpinAnonymOS system at the pre-boot prompt. "
                     "Keep it secret: it is never written to the disk, and the kernel wipes it "
                     "from memory when the install ends. No recovery if lost.");
            return;
        }
        /* The erase mode is the difference between minutes and hours on a large disk, so the page
         * says so in its own words rather than leaving it to the Summary. */
        if (app->fill_whole_disk)
            vmsg_set(m, COL_AMBER, 0, "Erase: the WHOLE disk is overwritten with random data, so it "
                     "looks exactly like a Hidden-OS install -- and that is the slow part, roughly "
                     "an hour per 100 GB. Press Space for the fast erase.");
        else
            vmsg_set(m, COL_DETAIL, 0, "Erase: only the encrypted system area is written -- minutes, "
                     "not hours. Just as encrypted; what you give up is the disguise that a hidden "
                     "OS might also be there. Press Space to erase the whole disk instead.");
        if (f == FIELD_HIDDEN_CONFIRM) {
            vmsg_set(m, COL_DETAIL, 0, "Type the same password again.");
            return;
        }
        vmsg_set(m, COL_GREEN, 0, "Ready: one disk password set. Every sector of the disk will be "
                 "erased and random-filled first; without the password there is no recovery.");
        return;
    }

    if (app->screen == SCREEN_ENCRYPTION && app->encryption_mode == ENC_HIDDEN) {
        if (pair_mismatch(app, FIELD_HIDDEN_PASSWORD, FIELD_HIDDEN_CONFIRM)) {
            vmsg_set(m, COL_RED, 1, "Hidden OS passwords do not match.");
            return;
        }
        if (pair_mismatch(app, FIELD_OUTER_PASSWORD, FIELD_OUTER_CONFIRM)) {
            vmsg_set(m, COL_RED, 1, "Outer volume passwords do not match.");
            return;
        }
        if (pair_mismatch(app, FIELD_DECOY_BOOT_PASSWORD, FIELD_DECOY_BOOT_CONFIRM)) {
            vmsg_set(m, COL_RED, 1, "Decoy OS boot passwords do not match.");
            return;
        }
        if (!enc_passwords_distinct(app)) {
            vmsg_set(m, COL_RED, 1, "Hidden, outer and decoy passwords must all differ: the same "
                     "password could open the wrong volume.");
            return;
        }
        int any_empty = 0;
        int all[] = { FIELD_HIDDEN_PASSWORD, FIELD_HIDDEN_CONFIRM, FIELD_OUTER_PASSWORD,
                      FIELD_OUTER_CONFIRM, FIELD_DECOY_BOOT_PASSWORD, FIELD_DECOY_BOOT_CONFIRM };
        for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
            if (app->field_len[all[i]] == 0) any_empty = 1;
        if (any_empty) {
            vmsg_set(m, COL_MUTED, 1, "All three passwords are required; the kernel refuses a "
                     "Hidden OS install with an empty one.");
            return;
        }
        const char *which = NULL;
        if (f == FIELD_HIDDEN_PASSWORD && app->field_len[f] < 8) which = "hidden OS";
        if (f == FIELD_OUTER_PASSWORD && app->field_len[f] < 8) which = "outer volume";
        if (f == FIELD_DECOY_BOOT_PASSWORD && app->field_len[f] < 8) which = "decoy boot";
        if (which) {
            snprintf(m->text, sizeof m->text, "Short: use at least 8 characters for the %s password.", which);
            m->color = COL_AMBER;
            return;
        }
        if (f == FIELD_HIDDEN_PASSWORD)
            vmsg_set(m, COL_DETAIL, 0, "Unlocks the real EpinAnonymOS at the preboot prompt. Keep it "
                     "secret; the kernel wipes it from memory when the install finishes. No recovery if lost.");
        else if (f == FIELD_OUTER_PASSWORD)
            vmsg_set(m, COL_DETAIL, 0, "Opens the outer volume, an encrypted area that shows only free "
                     "space. This is the one you can give up; the hidden system stays locked behind its own password.");
        else if (f == FIELD_DECOY_BOOT_PASSWORD)
            vmsg_set(m, COL_DETAIL, 0, "Starts the decoy Linux from its own encrypted partition. This "
                     "one can be given up too; it shows an ordinary working system.");
        else if (f == FIELD_HIDDEN_CONFIRM || f == FIELD_OUTER_CONFIRM || f == FIELD_DECOY_BOOT_CONFIRM)
            vmsg_set(m, COL_DETAIL, 0, "Type the same password again.");
        if (m->text[0])
            return;
        vmsg_set(m, COL_GREEN, 0, "Ready: three different passwords set. Every sector of the disk "
                 "will be erased.");
        return;
    }

    if (app->screen == SCREEN_DECOY) {
        const char *user = app->field_text[FIELD_DECOY_USER];
        const char *host = app->field_text[FIELD_DECOY_HOSTNAME];
        if ((user[0] && !valid_username(user)) || (host[0] && !valid_hostname(host))) {
            vmsg_set(m, COL_AMBER, 0, "Letters, digits, - and _ only, like the real account (the "
                     "kernel does not use this value yet).");
            return;
        }
        if (f == FIELD_DECOY_USER)
            vmsg_set(m, COL_DETAIL, 0, "Recorded in install.json only. The decoy image keeps its own "
                     "built-in account for now.");
        else if (f == FIELD_DECOY_FULLNAME)
            vmsg_set(m, COL_DETAIL, 0, "Optional. Recorded only; not shown anywhere.");
        else if (f == FIELD_DECOY_PASSWORD)
            vmsg_set(m, COL_DETAIL, 0, "Kept as an unsalted SHA-512 hash in install.json on the plain "
                     "boot partition; not applied to the decoy login.");
        else if (f == FIELD_DECOY_HOSTNAME)
            vmsg_set(m, COL_DETAIL, 0, "Recorded only; the decoy image keeps its own hostname.");
        if (m->text[0])
            return;
        vmsg_set(m, COL_MUTED, 0, "Note: install.json on the plain boot partition records that "
                 "Hidden OS mode was chosen.");
        return;
    }
}

/* Which fields get the red ring (mirrors the blocking cases in form_validate). */
static int field_invalid(struct app *app, int f)
{
    if (app->screen == SCREEN_ACCOUNT) {
        if (f == FIELD_REAL_USER)
            return app->field_len[f] > 0 && !valid_username(app->field_text[f]);
        if (f == FIELD_HOSTNAME)
            return app->field_len[f] > 0 && !valid_hostname(app->field_text[f]);
        if (f == FIELD_REAL_CONFIRM)
            return pair_mismatch(app, FIELD_REAL_PASSWORD, FIELD_REAL_CONFIRM);
        return 0;
    }
    if (app->screen == SCREEN_ENCRYPTION) {
        if (f == FIELD_HIDDEN_CONFIRM) return pair_mismatch(app, FIELD_HIDDEN_PASSWORD, f);
        if (f == FIELD_OUTER_CONFIRM) return pair_mismatch(app, FIELD_OUTER_PASSWORD, f);
        if (f == FIELD_DECOY_BOOT_CONFIRM) return pair_mismatch(app, FIELD_DECOY_BOOT_PASSWORD, f);
        if (app->encryption_mode == ENC_HIDDEN &&
            (f == FIELD_HIDDEN_PASSWORD || f == FIELD_OUTER_PASSWORD || f == FIELD_DECOY_BOOT_PASSWORD))
            return !enc_passwords_distinct(app);
        return 0;
    }
    if (app->screen == SCREEN_DECOY) {
        if (f == FIELD_DECOY_USER)
            return app->field_len[f] > 0 && !valid_username(app->field_text[f]);
        if (f == FIELD_DECOY_HOSTNAME)
            return app->field_len[f] > 0 && !valid_hostname(app->field_text[f]);
    }
    return 0;
}

/* Whether the Continue/Install button should be enabled for the current screen. */
static int screen_can_advance(struct app *app)
{
    if (app->screen == SCREEN_ACCOUNT ||
        (app->screen == SCREEN_ENCRYPTION && app->encryption_mode != ENC_NONE)) {
        struct vmsg m;
        form_validate(app, &m);
        return !m.blocking;
    }
    if (app->screen == SCREEN_DISK)
        return !disk_row_disabled(app, app->target_sel);
    if (app->screen == SCREEN_REVIEW) {
        /* A plain install on a listed disk under the minimum is refused up front;
         * encrypted layouts are size-checked by the kernel (the card warns). */
        int pos = chosen_disk_pos(app);
        if (app->encryption_mode == ENC_NONE && pos >= 0 &&
            app->disks[pos].size_mib < MIN_DISK_MIB)
            return 0;
        return 1;
    }
    if (app->screen == SCREEN_PROGRESS)
        return app->install_done || app->install_failed;
    return 1;
}

/* ── drawing primitives ────────────────────────────────────────────────────── */

static int create_memfd(const char *name)
{
    return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC);
}

static void rounded_rect(cairo_t *cr, double x, double y, double w, double h, double r)
{
    const double pi = 3.14159265358979323846;
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -pi / 2.0, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, pi / 2.0);
    cairo_arc(cr, x + r, y + h - r, r, pi / 2.0, pi);
    cairo_arc(cr, x + r, y + r, r, pi, 3.0 * pi / 2.0);
    cairo_close_path(cr);
}

static int load_file(const char *path, unsigned char **out, size_t *out_size)
{
    *out = NULL;
    *out_size = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    size_t cap = 65536;
    size_t len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) {
        close(fd);
        return -1;
    }

    for (;;) {
        if (len == cap) {
            size_t next = cap * 2;
            unsigned char *nb = realloc(buf, next);
            if (!nb) {
                free(buf);
                close(fd);
                return -1;
            }
            buf = nb;
            cap = next;
        }
        ssize_t n = read(fd, buf + len, cap - len);
        if (n > 0) {
            len += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            free(buf);
            close(fd);
            return -1;
        }
        break;
    }

    close(fd);
    if (len == 0) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_size = len;
    return 0;
}

static int init_freetype(struct app *app)
{
    const char *path = "/usr/share/fonts/noto/NotoSans-Regular.ttf";
    if (load_file(path, &app->font_data, &app->font_size) < 0)
        return -1;
    if (FT_Init_FreeType(&app->ft) != 0)
        return -1;
    if (FT_New_Memory_Face(app->ft, app->font_data, (FT_Long)app->font_size, 0,
                           &app->face) != 0)
        return -1;
    app->font_ready = 1;
    printf("G11FONT: loaded %s (%zu bytes) -- G11 FONT\n", path, app->font_size);
    fflush(stdout);
    return 0;
}

/* Fast (x / 255) for x in [0, 255*255]: exact across that whole range and avoids
 * the integer divide the old blend did three times per covered pixel (INST-01). */
static inline unsigned int div255(unsigned int x)
{
    return (x + 1 + (x >> 8)) >> 8;
}

static uint32_t blend_xrgb(uint32_t dst, uint32_t src, unsigned int alpha)
{
    if (alpha >= 255)
        return src;
    if (alpha == 0)
        return dst;
    unsigned int inv = 255 - alpha;
    unsigned int sr = (src >> 16) & 0xff, sg = (src >> 8) & 0xff, sb = src & 0xff;
    unsigned int dr = (dst >> 16) & 0xff, dg = (dst >> 8) & 0xff, db = dst & 0xff;
    unsigned int r = div255(sr * alpha + dr * inv);
    unsigned int g = div255(sg * alpha + dg * inv);
    unsigned int b = div255(sb * alpha + db * inv);
    return 0xff000000u | (r << 16) | (g << 8) | b;
}

/* Return (allocating on first use) the cache slot for a pixel size, or NULL for
 * an out-of-range size or if every slot is taken.  Slots are matched by value so
 * only the handful of sizes the UI actually uses ever cost anything. */
static struct glyph_size *glyph_slot_for(struct app *app, int px)
{
    if (px <= 0 || px > GLYPH_MAX_PX)
        return NULL;
    struct glyph_size *free_slot = NULL;
    for (int i = 0; i < GLYPH_SIZE_SLOTS; i++) {
        if (app->glyph_sizes[i].px == px)
            return &app->glyph_sizes[i];
        if (!free_slot && app->glyph_sizes[i].px == 0)
            free_slot = &app->glyph_sizes[i];
    }
    if (free_slot)
        free_slot->px = px;
    return free_slot;
}

/* Fetch a rendered glyph from the cache, rendering + copying it out of the FT
 * slot on the first miss.  FT_Set_Pixel_Sizes is issued only when the face is not
 * already at `px`, so a run of same-size text pays for it once. */
static const struct glyph *cached_glyph(struct app *app, int px, unsigned char ch)
{
    if (ch < GLYPH_FIRST || ch > GLYPH_LAST)
        ch = '?';
    struct glyph_size *slot = glyph_slot_for(app, px);
    if (!slot)
        return NULL;
    struct glyph *gl = &slot->glyphs[ch - GLYPH_FIRST];
    if (gl->loaded)
        return gl;

    if (app->glyph_cur_px != px) {
        if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0)
            return NULL;
        app->glyph_cur_px = px;
    }
    /* The ascender is a per-size metric, so it is captured here on the one path
     * that has just set the face size; draw_text_ft reads it from the slot and
     * never touches FreeType on a cache hit (R-03). */
    if (slot->ascender == 0 && app->face->size && app->face->size->metrics.ascender > 0)
        slot->ascender = (int)(app->face->size->metrics.ascender >> 6);
    if (FT_Load_Char(app->face, (FT_ULong)ch, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) != 0)
        return NULL;

    FT_GlyphSlot g = app->face->glyph;
    FT_Bitmap *bm = &g->bitmap;
    /* FreeType: `buffer` is the lowest address of the bitmap and `pitch` is the
     * signed offset that moves one row DOWN, so a negative pitch means the top
     * row sits at buffer + (rows-1)*|pitch| and rows are walked by adding the
     * (negative) pitch.  FT_LOAD_RENDER's smooth renderer always hands out a
     * positive pitch, so this only matters for completeness. */
    int pitch = bm->pitch;
    const unsigned char *base = bm->buffer;
    if (pitch < 0)
        base = bm->buffer + (size_t)(bm->rows - 1) * (size_t)(-pitch);
    gl->width   = (int)bm->width;
    gl->rows    = (int)bm->rows;
    gl->pitch   = (int)bm->width;  /* store tightly packed, one byte of coverage per pixel */
    gl->left    = g->bitmap_left;
    gl->top     = g->bitmap_top;
    gl->advance = (int)(g->advance.x >> 6);

    size_t n = (size_t)gl->rows * (size_t)gl->pitch;
    if (n > 0) {
        gl->bitmap = malloc(n);
        if (!gl->bitmap) {
            gl->loaded = 0;
            return NULL;
        }
        for (int row = 0; row < gl->rows; row++) {
            const unsigned char *src_row = base + row * pitch;
            unsigned char *dst_row = gl->bitmap + (size_t)row * gl->pitch;
            if (bm->pixel_mode == FT_PIXEL_MODE_MONO) {
                for (int col = 0; col < gl->width; col++)
                    dst_row[col] = (src_row[col >> 3] & (0x80 >> (col & 7))) ? 255 : 0;
            } else { /* FT_PIXEL_MODE_GRAY (and anything else treated as gray) */
                memcpy(dst_row, src_row, (size_t)gl->width);
            }
        }
    } else {
        gl->bitmap = NULL;         /* space etc.: advance only, no coverage */
    }
    gl->loaded = 1;
    return gl;
}

/* Blit one cached glyph into app->pixels at pen (pen_x,pen_y == baseline pen),
 * clipped to [clip_lo, clip_hi) vertically and to the surface horizontally. */
static void blit_glyph(struct app *app, const struct glyph *gl,
                       int pen_x, int pen_y, uint32_t color,
                       int clip_lo, int clip_hi)
{
    if (!gl->bitmap)
        return;
    int gx = pen_x + gl->left;
    int gy = pen_y - gl->top;
    for (int row = 0; row < gl->rows; row++) {
        int py = gy + row;
        if (py < 0 || py >= app->height)
            continue;
        if (py < clip_lo || py >= clip_hi)
            continue;
        const unsigned char *src_row = gl->bitmap + (size_t)row * gl->pitch;
        uint32_t *dst_line = &app->pixels[py * app->width];
        for (int col = 0; col < gl->width; col++) {
            int pxpos = gx + col;
            if (pxpos < 0 || pxpos >= app->width)
                continue;
            unsigned int alpha = src_row[col];
            if (alpha)
                dst_line[pxpos] = blend_xrgb(dst_line[pxpos], color, alpha);
        }
    }
}

/* Render a string straight into app->pixels.  Signature and wrapping semantics
 * are unchanged (the UI stage will add word-wrapping helpers on top of the same
 * cache); the outline rasterisation and per-string FT_Set_Pixel_Sizes are gone --
 * every glyph now comes from cached_glyph() and is copied by blit_glyph(). */
static void draw_text_ft(struct app *app, const char *text, int x, int y,
                         int max_w, int px, uint32_t color)
{
    if (!app->font_ready || !text || max_w <= 0)
        return;

    int line_h = px + 6;
    int baseline = px;
    /* The ascender comes from the size slot, filled by cached_glyph() the first
     * time any glyph at this px is rendered; rendering one glyph here on a cold
     * slot is what fills it.  No FT_Set_Pixel_Sizes per string: the list pages
     * alternate 13px labels with 11px subs on every row, and each size switch
     * used to cost a tt_size_request plus a cvt reset (R-03). */
    struct glyph_size *slot = glyph_slot_for(app, px);
    if (slot) {
        if (slot->ascender == 0)
            (void)cached_glyph(app, px, 'H');
        if (slot->ascender > 0)
            baseline = slot->ascender;
    }

    int clip_lo = app->clip_top;
    int clip_hi = app->clip_bottom > 0 ? app->clip_bottom : app->height;

    int pen_x = x;
    int pen_y = y + baseline;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        unsigned char ch = *p;
        if (ch == '\n') {
            pen_x = x;
            pen_y += line_h;
            continue;
        }
        if (ch < 0x20 || ch >= 0x7f)
            ch = '?';
        const struct glyph *gl = cached_glyph(app, px, ch);
        if (!gl)
            continue;
        if (pen_x > x && pen_x + gl->advance > x + max_w) {
            pen_x = x;
            pen_y += line_h;
        }
        blit_glyph(app, gl, pen_x, pen_y, color, clip_lo, clip_hi);
        pen_x += gl->advance;
    }
}

/* Pixel width of one line of `s` (stops at '\n'): the sum of cached advances, so
 * it costs nothing after the first paint and replaces every strlen*8 estimate. */
static int text_width(struct app *app, const char *s, int px)
{
    if (!app->font_ready || !s)
        return 0;
    int w = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p && *p != '\n'; ++p) {
        unsigned char ch = *p;
        if (ch < 0x20 || ch >= 0x7f)
            ch = '?';
        const struct glyph *gl = cached_glyph(app, px, ch);
        if (gl)
            w += gl->advance;
    }
    return w;
}

/* Append `s` to `line` (bounded); returns the new length. */
static int line_append(char *line, size_t cap, int len, const char *s, int n)
{
    if (n < 0) n = (int)strlen(s);
    if (len + n >= (int)cap) n = (int)cap - 1 - len;
    if (n <= 0) return len;
    memcpy(line + len, s, (size_t)n);
    len += n;
    line[len] = 0;
    return len;
}

/* Trim `line` so that line + "..." fits max_w: drop whole words first, then
 * single glyphs (for a line that is one long word); then append the ellipsis. */
static void ellipsize_line(struct app *app, char *line, size_t cap, int max_w, int px)
{
    int len = (int)strlen(line);
    char probe[520];
    for (;;) {
        snprintf(probe, sizeof probe, "%s...", line);
        if (text_width(app, probe, px) <= max_w || len == 0)
            break;
        char *sp = strrchr(line, ' ');
        if (sp && text_width(app, line, px) > max_w / 2)
            *sp = 0;                  /* whole-word trim while plenty remains */
        else
            line[--len] = 0;          /* glyph trim */
        len = (int)strlen(line);
        while (len > 0 && line[len - 1] == ' ')
            line[--len] = 0;
    }
    size_t l = strlen(line);
    if (l + 4 > cap) {                /* cannot happen for a line that fit its buffer */
        l = cap - 4;
        line[l] = 0;
    }
    memcpy(line + l, "...", 4);
}

/* Greedy word wrap into at most max_lines lines of max_w pixels; a single word
 * wider than max_w is broken per glyph, '\n' forces a break, and if text remains
 * after the last line that line is cut at a word boundary with "..." appended.
 * Pitch is px+6.  Returns the number of lines drawn.  Honours clip_top/clip_bottom
 * through draw_text_ft. */
static int draw_text_wrapped(struct app *app, const char *text, int x, int y,
                             int max_w, int px, int max_lines, uint32_t color)
{
    if (!text || !text[0] || max_lines <= 0 || max_w <= 0)
        return 0;
    const char *p = text;
    int lines = 0;
    int pitch = px + 6;
    char line[512];
    while (*p && lines < max_lines) {
        int len = 0;
        line[0] = 0;
        while (*p == ' ') p++;
        for (;;) {
            if (!*p)
                break;
            if (*p == '\n') { p++; break; }
            const char *ws = p;
            while (*p && *p != ' ' && *p != '\n') p++;
            int wl = (int)(p - ws);
            char cand[512];
            int cl = 0;
            cand[0] = 0;
            if (len > 0) {
                cl = line_append(cand, sizeof cand, cl, line, len);
                cl = line_append(cand, sizeof cand, cl, " ", 1);
            }
            cl = line_append(cand, sizeof cand, cl, ws, wl);
            if (text_width(app, cand, px) <= max_w) {
                memcpy(line, cand, (size_t)cl + 1);
                len = cl;
                while (*p == ' ') p++;
                continue;
            }
            if (len == 0) {
                /* one word wider than the line: take the glyphs that fit */
                int take = 0;
                for (int i = 1; i <= wl; i++) {
                    char part[512];
                    int pl = line_append(part, sizeof part, 0, ws, i);
                    (void)pl;
                    if (text_width(app, part, px) > max_w) break;
                    take = i;
                }
                if (take < 1) take = 1;
                len = line_append(line, sizeof line, 0, ws, take);
                p = ws + take;
            } else {
                p = ws;               /* word goes to the next line */
            }
            break;
        }
        while (*p == ' ') p++;
        if (*p && lines == max_lines - 1)
            ellipsize_line(app, line, sizeof line, max_w, px);
        draw_text_ft(app, line, x, y + lines * pitch, max_w + 8, px, color);
        lines++;
    }
    return lines;
}

/* One line, ellipsised with "..." if wider than max_w; never wraps. */
static void draw_text_clip(struct app *app, const char *text, int x, int y,
                           int max_w, int px, uint32_t color)
{
    if (!text || !text[0] || max_w <= 0)
        return;
    if (text_width(app, text, px) <= max_w) {
        draw_text_ft(app, text, x, y, max_w + 8, px, color);
        return;
    }
    char line[512];
    snprintf(line, sizeof line, "%s", text);
    char *nl = strchr(line, '\n');
    if (nl) *nl = 0;
    ellipsize_line(app, line, sizeof line, max_w, px);
    draw_text_ft(app, line, x, y, max_w + 8, px, color);
}

/* Right-aligned single line ending at right_x. */
static void draw_text_right(struct app *app, const char *text, int right_x, int y,
                            int px, uint32_t color)
{
    int w = text_width(app, text, px);
    draw_text_ft(app, text, right_x - w, y, w + 8, px, color);
}

static void draw_button(struct app *app, cairo_t *cr, int which, const char *label, int enabled)
{
    double x, y, w, h;
    btn_rect(app, which, &x, &y, &w, &h);
    rounded_rect(cr, x, y, w, h, 8);
    if (!enabled)
        cairo_set_source_rgb(cr, 0.18, 0.21, 0.25);
    else if (which == BTN_PRIMARY)
        cairo_set_source_rgb(cr, 0.05, 0.52, 0.48);
    else
        cairo_set_source_rgb(cr, 0.24, 0.29, 0.36);
    cairo_fill(cr);
    int tw = text_width(app, label, 14);
    int tx = (int)x + ((int)w - tw) / 2;
    if (tx < (int)x + 14) tx = (int)x + 14;
    draw_text_ft(app, label, tx, (int)y + 16, (int)w - 16, 14,
                 enabled ? 0xffffffffu : 0xff6b7480u);
}

/* The left rail listing every (visible) step, current one highlighted.  The
 * pitch shrinks at 600 tall so 15 rows end above the footer (Step k of N + hints). */
static void draw_steps(struct app *app)
{
    int y = 120;
    int pitch = app->height < 680 ? 26 : 30;
    for (size_t i = 0; i < sizeof(SCREEN_ORDER) / sizeof(SCREEN_ORDER[0]); i++) {
        int s = SCREEN_ORDER[i];
        if (!screen_visible(app, s))
            continue;
        uint32_t color;
        if (s == app->screen)
            color = 0xffffffffu;
        else if (s < app->screen)
            color = 0xff5f6b78u;   /* completed: dim */
        else
            color = 0xff9aa6b4u;   /* upcoming */
        if (s == app->screen) {
            /* accent bar */
            for (int yy = y - 2; yy < y + 18; yy++)
                for (int xx = 44; xx < 48; xx++)
                    if (yy >= 0 && yy < app->height)
                        app->pixels[yy * app->width + xx] = 0xff13b3a3u;
        }
        draw_text_ft(app, screen_short_name(s), 58, y, SIDEBAR_W - 70, 13, color);
        y += pitch;
    }
}

static void draw_sidebar_footer(struct app *app)
{
    int k, n;
    step_position(app, &k, &n);
    char line[32];
    snprintf(line, sizeof line, "Step %d of %d", k, n);
    draw_text_ft(app, line, 44, app->height - 80, SIDEBAR_W - 56, 11, 0xff8b96a4u);
    const char *l1, *l2;
    screen_hints(app, &l1, &l2);
    if (l1[0])
        draw_text_clip(app, l1, 44, app->height - 58, SIDEBAR_W - 56, 11, 0xff5f6b78u);
    if (l2[0])
        draw_text_clip(app, l2, 44, app->height - 40, SIDEBAR_W - 56, 11, 0xff5f6b78u);
}

static void masked_value(struct app *app, int field, char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
        return;
    if (!field_secret(field)) {
        snprintf(out, out_sz, "%s", app->field_text[field]);
        return;
    }
    int n = app->field_len[field];
    if (n <= 0) {
        out[0] = 0;
        return;
    }
    if ((size_t)n >= out_sz)
        n = (int)out_sz - 1;
    for (int i = 0; i < n; i++)
        out[i] = '*';
    out[n] = 0;
}

static void draw_field(struct app *app, cairo_t *cr, int field)
{
    double x, y, w, h;
    field_rect(app, field, &x, &y, &w, &h);
    draw_text_clip(app, field_label(app, field), (int)x, (int)y - 20, (int)w, 12, 0xffc8d2dfu);
    rounded_rect(cr, x, y, w, h, 7);
    if (field == app->focused_field)
        cairo_set_source_rgb(cr, 0.13, 0.21, 0.28);
    else
        cairo_set_source_rgb(cr, 0.09, 0.14, 0.19);
    cairo_fill(cr);
    /* A field the kernel would reject (or a confirm that differs) keeps a red ring
     * even when unfocused, so the problem stays visible while another field is edited. */
    if (field_invalid(app, field)) {
        rounded_rect(cr, x + 0.5, y + 0.5, w - 1, h - 1, 7);
        cairo_set_source_rgb(cr, 0.88, 0.35, 0.31);
        cairo_set_line_width(cr, 1.5);
        cairo_stroke(cr);
    } else if (field == app->focused_field) {
        rounded_rect(cr, x + 0.5, y + 0.5, w - 1, h - 1, 7);
        cairo_set_source_rgb(cr, 0.16, 0.70, 0.62);
        cairo_set_line_width(cr, 1.5);
        cairo_stroke(cr);
    }
    char shown[112];
    masked_value(app, field, shown, sizeof shown);
    if (shown[0]) {
        /* show the tail that fits, so a long entry keeps its cursor end visible */
        const char *s = shown;
        while (*s && text_width(app, s, 14) > (int)w - 28)
            s++;
        draw_text_ft(app, s, (int)x + 14, (int)y + 13, (int)w - 28, 14, 0xffffffffu);
    } else {
        draw_text_ft(app, field_optional(field) ? "Optional" : "Required",
                     (int)x + 14, (int)y + 13, (int)w - 28, 14, 0xff778391u);
    }
}

static void draw_segments(struct app *app, cairo_t *cr)
{
    const char *labels[] = { "None", "Full disk", "Hidden OS" };
    for (int i = 0; i < 3; i++) {
        double x, y, w, h;
        segment_rect(app, i, &x, &y, &w, &h);
        rounded_rect(cr, x, y, w, h, 7);
        if (app->encryption_mode == i)
            cairo_set_source_rgb(cr, 0.05, 0.52, 0.48);
        else
            cairo_set_source_rgb(cr, 0.09, 0.14, 0.19);
        cairo_fill(cr);
        int tw = text_width(app, labels[i], 13);
        int tx = (int)x + ((int)w - tw) / 2;
        if (tx < (int)x + 10) tx = (int)x + 10;
        draw_text_ft(app, labels[i], tx, (int)y + 16, (int)w - 12, 13, 0xffffffffu);
    }
}

/* Draw a row in a list: label + sub, selected highlighted, checkbox for toggles.
 * A disabled row shows its reason right-aligned; the keyboard cursor of a toggle
 * list is a thin teal ring (the fill is reserved for the tick state). */
static void draw_list_row(struct app *app, cairo_t *cr, int visible_pos,
                          const char *label, const char *sub,
                          int selected, int disabled, int checkbox, int cursor,
                          const char *reason)
{
    double x, y, w, h;
    list_row_rect(app, visible_pos, &x, &y, &w, &h);
    rounded_rect(cr, x, y, w, h, 7);
    if (selected && !checkbox)
        cairo_set_source_rgb(cr, 0.10, 0.27, 0.27);
    else
        cairo_set_source_rgb(cr, 0.085, 0.125, 0.165);
    cairo_fill(cr);
    if (selected && !checkbox) {
        rounded_rect(cr, x + 0.5, y + 0.5, w - 1, h - 1, 7);
        cairo_set_source_rgb(cr, 0.10, 0.66, 0.58);
        cairo_set_line_width(cr, 1.5);
        cairo_stroke(cr);
    } else if (cursor) {
        rounded_rect(cr, x + 0.5, y + 0.5, w - 1, h - 1, 7);
        cairo_set_source_rgb(cr, 0.10, 0.66, 0.58);
        cairo_set_line_width(cr, 1.0);
        cairo_stroke(cr);
    }
    int text_x = (int)x + 16;
    if (checkbox) {
        double bx = x + 14, by = y + h / 2 - 9, bs = 18;
        rounded_rect(cr, bx, by, bs, bs, 4);
        if (selected)
            cairo_set_source_rgb(cr, 0.05, 0.62, 0.55);
        else
            cairo_set_source_rgb(cr, 0.16, 0.21, 0.27);
        cairo_fill(cr);
        if (selected) {
            cairo_set_source_rgb(cr, 1, 1, 1);
            cairo_set_line_width(cr, 2.0);
            cairo_move_to(cr, bx + 4, by + 9);
            cairo_line_to(cr, bx + 8, by + 13);
            cairo_line_to(cr, bx + 14, by + 5);
            cairo_stroke(cr);
        }
        text_x = (int)x + 44;
    }
    uint32_t lc = disabled ? 0xff5b6470u : 0xffffffffu;
    uint32_t sc = disabled ? 0xff464e58u : 0xff9aa6b4u;
    int reason_w = (disabled && reason && reason[0]) ? text_width(app, reason, 11) + 14 : 0;
    int text_w = (int)(x + w) - 14 - reason_w - text_x;
    if (sub && sub[0]) {
        draw_text_clip(app, label, text_x, (int)y + 7, text_w, 13, lc);
        draw_text_clip(app, sub, text_x, (int)y + 24, text_w, 11, sc);
    } else {
        draw_text_clip(app, label, text_x, (int)y + 14, text_w, 13, lc);
    }
    if (reason_w > 0)
        draw_text_right(app, reason, (int)(x + w) - 14, (int)y + 14, 11, 0xff5b6470u);
}

/* The erase-mode control.  Same look as the checkbox rows on the Identities page, so it reads as
 * something you can click without needing a legend. */
static void draw_erase_row(struct app *app, cairo_t *cr)
{
    double x, y, w, h;
    erase_row_rect(app, &x, &y, &w, &h);
    if (y + h < content_view_top(app) || y > content_view_bottom(app))
        return;                                  /* scrolled out of the pane */
    const int on = app->fill_whole_disk;
    rounded_rect(cr, x, y, w, h, 7);
    cairo_set_source_rgb(cr, 0.085, 0.125, 0.165);
    cairo_fill(cr);
    if (app->focused_field < 0) {            /* the Tab cycle is parked here: show it */
        rounded_rect(cr, x + 0.5, y + 0.5, w - 1, h - 1, 7);
        cairo_set_source_rgb(cr, 0.10, 0.66, 0.58);
        cairo_set_line_width(cr, 1.5);
        cairo_stroke(cr);
    }
    double bx = x + 14, by = y + h / 2 - 9, bs = 18;
    rounded_rect(cr, bx, by, bs, bs, 4);
    if (on)
        cairo_set_source_rgb(cr, 0.05, 0.62, 0.55);
    else
        cairo_set_source_rgb(cr, 0.16, 0.21, 0.27);
    cairo_fill(cr);
    if (on) {
        cairo_set_source_rgb(cr, 1, 1, 1);
        cairo_set_line_width(cr, 2.0);
        cairo_move_to(cr, bx + 4, by + 9);
        cairo_line_to(cr, bx + 8, by + 13);
        cairo_line_to(cr, bx + 14, by + 5);
        cairo_stroke(cr);
    }
    const int tx = (int)x + 44;
    const int tw = (int)(x + w) - 14 - tx;
    draw_text_clip(app, "Erase the whole disk first", tx, (int)y + 7, tw, 13, 0xffffffffu);
    draw_text_clip(app,
                   on ? "On: looks identical to a Hidden-OS install. Roughly an hour per 100 GB."
                      : "Off: writes only the encrypted system area. Minutes, and just as encrypted.",
                   tx, (int)y + 24, tw, 11, on ? 0xffd7a55cu : 0xff9aa6b4u);
}

static void clamp_scroll(struct app *app, int count)
{
    int vis = list_visible_rows(app);
    int maxs = count - vis;
    if (maxs < 0) maxs = 0;
    if (app->list_scroll > maxs) app->list_scroll = maxs;
    if (app->list_scroll < 0) app->list_scroll = 0;
}

static void draw_scrollbar(struct app *app, cairo_t *cr, int count)
{
    int vis = list_visible_rows(app);
    if (count <= vis)
        return;
    double tx = app->width - CONTENT_PAD + 18;
    double ty = list_top(app);
    double th = vis * LIST_ROW_H - 8;
    double knob_h = th * vis / count;
    if (knob_h < 24) knob_h = 24;
    double maxs = count - vis;
    double knob_y = ty + (th - knob_h) * (maxs > 0 ? app->list_scroll / maxs : 0);
    rounded_rect(cr, tx, ty, 4, th, 2);
    cairo_set_source_rgb(cr, 0.13, 0.17, 0.22);
    cairo_fill(cr);
    rounded_rect(cr, tx, knob_y, 4, knob_h, 2);
    cairo_set_source_rgb(cr, 0.30, 0.36, 0.43);
    cairo_fill(cr);
}

static void draw_choice_list(struct app *app, cairo_t *cr)
{
    int count = 0;
    const struct opt *o = screen_opts(app->screen, &count);
    int *sel = screen_sel_ptr(app, app->screen);
    if (!o || !sel)
        return;
    clamp_scroll(app, count);
    int vis = list_visible_rows(app);
    for (int i = 0; i < vis; i++) {
        int idx = app->list_scroll + i;
        if (idx >= count)
            break;
        draw_list_row(app, cr, i, o[idx].label, o[idx].sub, idx == *sel,
                      opt_is_disabled(app, app->screen, idx), 0, 0,
                      opt_disabled_reason(app, app->screen, idx));
    }
    draw_scrollbar(app, cr, count);
}

/* Drivers and Identities share one toggle-list renderer (cursor ring + ticks). */
static void draw_toggle_list(struct app *app, cairo_t *cr, const struct opt *o,
                             int count, const int *on)
{
    clamp_scroll(app, count);
    int vis = list_visible_rows(app);
    for (int i = 0; i < vis; i++) {
        int idx = app->list_scroll + i;
        if (idx >= count)
            break;
        draw_list_row(app, cr, i, o[idx].label, o[idx].sub, on[idx], 0, 1,
                      idx == app->list_cursor, "");
    }
    draw_scrollbar(app, cr, count);
}

static void draw_disk_list(struct app *app, cairo_t *cr)
{
    int count = disk_row_count(app);
    clamp_scroll(app, count);
    int vis = list_visible_rows(app);
    for (int i = 0; i < vis; i++) {
        int idx = app->list_scroll + i;
        if (idx >= count)
            break;
        char label[48], sub[96];
        disk_row_text(app, idx, label, sizeof label, sub, sizeof sub);
        int dis = disk_row_disabled(app, idx);
        draw_list_row(app, cr, i, label, sub, idx == app->target_sel, dis, 0, 0,
                      dis ? "too small (< 1.1 GB)" : "");
    }
    draw_scrollbar(app, cr, count);
}

static void identities_summary(struct app *app, char *out, size_t cap)
{
    size_t pos = 0;
    out[0] = 0;
    for (int i = 0; i < ARRAY_LEN(IDENTITIES); i++) {
        if (!app->identity_on[i])
            continue;
        int n = snprintf(out + pos, cap - pos, "%s%s",
                         pos ? ", " : "", IDENTITIES[i].label);
        if (n < 0 || (size_t)n >= cap - pos)
            break;
        pos += (size_t)n;
    }
    if (pos == 0)
        snprintf(out, cap, "your account only");
}

static void drivers_summary(struct app *app, char *out, size_t cap)
{
    size_t pos = 0;
    out[0] = 0;
    for (int i = 0; i < ARRAY_LEN(DRIVERS); i++) {
        if (!app->drivers_on[i])
            continue;
        int n = snprintf(out + pos, cap - pos, "%s%s",
                         pos ? ", " : "", DRIVERS[i].code);
        if (n < 0 || (size_t)n >= cap - pos)
            break;
        pos += (size_t)n;
    }
    if (pos == 0)
        snprintf(out, cap, "none");
}

static int toggle_count(const int *on, int count)
{
    int n = 0;
    for (int i = 0; i < count; i++)
        if (on[i]) n++;
    return n;
}

/* ── the "About this choice" card ───────────────────────────────────────────── */

enum card_kind { CARD_INFO = 0, CARD_RECORDED, CARD_CAUTION, CARD_DESTRUCTIVE, CARD_SUCCESS };

struct card {
    int kind;
    char header[160];
    char tag[32];
    char detail[400];
    uint32_t detail_color;
    int max_lines;          /* 0: derived from the card height (74 -> 2, 92 -> 3) */
};

static void card_init(struct card *c, int kind, const char *header, const char *tag)
{
    memset(c, 0, sizeof *c);
    c->kind = kind;
    snprintf(c->header, sizeof c->header, "%s", header);
    snprintf(c->tag, sizeof c->tag, "%s", tag);
    c->detail_color = COL_DETAIL;
}

static void card_detail(struct card *c, uint32_t color, const char *text)
{
    snprintf(c->detail, sizeof c->detail, "%s", text);
    c->detail_color = color;
}

/* Accent colour per kind (the 3px bar and the status tag). */
static void card_accent(int kind, double *r, double *g, double *b, uint32_t *argb)
{
    switch (kind) {
    case CARD_RECORDED:    *r = 0.42; *g = 0.47; *b = 0.53; *argb = 0xff6b7887u; break;
    case CARD_CAUTION:     *r = 1.00; *g = 0.82; *b = 0.54; *argb = 0xffffd08au; break;
    case CARD_DESTRUCTIVE: *r = 0.88; *g = 0.35; *b = 0.31; *argb = 0xffe0594fu; break;
    case CARD_SUCCESS:     *r = 0.34; *g = 0.85; *b = 0.47; *argb = 0xff57d977u; break;
    default:               *r = 0.07; *g = 0.70; *b = 0.64; *argb = 0xff12b2a3u; break;
    }
}

/* Cairo half of the card (call it in the cairo block, BEFORE any card text):
 * the rounded panel, its 1px stroke and the accent bar.  On the Keyboard page it
 * also paints the key-test box, whose glyphs draw_card_text adds later. */
static void draw_card_bg(struct app *app, cairo_t *cr, int kind)
{
    int x, y, w, h;
    card_rect(app, &x, &y, &w, &h);
    double r, g, b;
    uint32_t argb;
    card_accent(kind, &r, &g, &b, &argb);

    rounded_rect(cr, x, y, w, h, 7);
    cairo_set_source_rgb(cr, 0.075, 0.11, 0.145);
    cairo_fill(cr);
    rounded_rect(cr, x + 0.5, y + 0.5, w - 1, h - 1, 7);
    cairo_set_source_rgb(cr, 0.16, 0.21, 0.27);
    cairo_set_line_width(cr, 1.0);
    cairo_stroke(cr);
    rounded_rect(cr, x + 10, y + 10, 3, h - 20, 1.5);
    cairo_set_source_rgb(cr, r, g, b);
    cairo_fill(cr);

    if (app->screen == SCREEN_KEYBOARD) {
        rounded_rect(cr, x + 22, y + 50, w - 36, 30, 6);
        cairo_set_source_rgb(cr, 0.13, 0.21, 0.28);
        cairo_fill(cr);
        rounded_rect(cr, x + 22.5, y + 50.5, w - 37, 29, 6);
        cairo_set_source_rgb(cr, 0.16, 0.70, 0.62);
        cairo_set_line_width(cr, 1.5);
        cairo_stroke(cr);
    }
}

/* Glyph half of the card (overlay block, after cairo_surface_flush). */
static void draw_card_text(struct app *app, const struct card *c)
{
    int x, y, w, h;
    card_rect(app, &x, &y, &w, &h);
    double r, g, b;
    uint32_t tag_color;
    card_accent(c->kind, &r, &g, &b, &tag_color);

    int tag_w = c->tag[0] ? text_width(app, c->tag, 11) : 0;
    draw_text_clip(app, c->header, x + 22, y + 10, w - 36 - tag_w - 12, 13, 0xffffffffu);
    if (c->tag[0])
        draw_text_right(app, c->tag, x + w - 14, y + 12, 11, tag_color);

    if (app->screen == SCREEN_KEYBOARD) {
        draw_text_clip(app, c->detail, x + 22, y + 32, w - 36, 12, c->detail_color);
        const char *typed = app->field_text[FIELD_KEYTEST];
        if (typed[0]) {
            /* show the tail that fits: the last keys typed are the ones being checked */
            const char *s = typed;
            while (*s && text_width(app, s, 12) > w - 60)
                s++;
            draw_text_ft(app, s, x + 34, y + 57, w - 56, 12, 0xffffffffu);
        } else {
            draw_text_ft(app, "Type here to test your keys", x + 34, y + 57, w - 56, 12, 0xff778391u);
        }
        return;
    }
    int max_lines = c->max_lines > 0 ? c->max_lines : (h >= 92 ? 3 : 2);
    draw_text_wrapped(app, c->detail, x + 22, y + 32, w - 36, 12, max_lines, c->detail_color);
}

/* Per-option detail for the list pages: one snprintf template per big table
 * (index 0 is the built-in default and gets its own sentence), fixed strings
 * for the short ones, and the detection sentence for Drivers. */
static void opt_detail(struct app *app, int screen, int idx, char *out, size_t cap)
{
    out[0] = 0;
    switch (screen) {
    case SCREEN_LANGUAGE:
        if (idx == 0)
            snprintf(out, cap, "Recorded in install.json as %s. This is the language the system "
                     "already uses, so nothing changes. The entry is kept so a future update knows "
                     "your choice.", LOCALES[0].code);
        else
            snprintf(out, cap, "Recorded in install.json as %s. Not applied yet: the installed system "
                     "stays in English until translations ship, then switches to %s.",
                     LOCALES[idx].code, LOCALES[idx].label);
        break;
    case SCREEN_KEYBOARD:
        if (idx == 0)
            snprintf(out, cap, "Records keymap %s. This is the built-in layout, so it already matches.",
                     KEYMAPS[0].code);
        else
            snprintf(out, cap, "Records keymap %s. Not applied yet: keys stay US-mapped after install.",
                     KEYMAPS[idx].code);
        break;
    case SCREEN_TIMEZONE:
        if (idx == 0)
            snprintf(out, cap, "Recorded as UTC. This is what the installed clock already uses, so "
                     "nothing changes.");
        else
            snprintf(out, cap, "Recorded in install.json as %s (%s). Not applied yet: the installed "
                     "clock stays in UTC until time zone support lands.",
                     TIMEZONES[idx].code, TIMEZONES[idx].sub);
        break;
    case SCREEN_NETWORK:
        if (idx == 2) {
            if (app->wifi_ip[0])
                snprintf(out, cap, "%s Live status: connected, IP %s", NETWORK_DETAIL[2], app->wifi_ip);
            else
                snprintf(out, cap, "Recorded as wifi. The live session brought Wi-Fi up on its own; "
                         "this choice does not start or stop it. Live status: connecting - waiting "
                         "for a DHCP lease.");
        } else {
            snprintf(out, cap, "%s", NETWORK_DETAIL[idx]);
        }
        break;
    case SCREEN_FILESYSTEM:
        snprintf(out, cap, "%s", FILESYSTEM_DETAIL[idx]);
        break;
    case SCREEN_BOOTINTEGRITY:
        snprintf(out, cap, "%s", BOOTINTEGRITY_DETAIL[idx]);
        break;
    case SCREEN_IDENTITIES:
        snprintf(out, cap, "%s", IDENTITY_DETAIL[idx]);
        break;
    case SCREEN_DRIVERS: {
        const char *det;
        if (!app->hw_detect_present)
            det = "No hardware scan on this boot";
        else if (app->detected_mask & (1u << idx))
            det = "Detected on this machine";
        else
            det = "Not detected on this machine";
        snprintf(out, cap, "Records '%s' for %s. %s. Recorded only: nothing is downloaded or "
                 "installed; both systems boot with the drivers their images ship.",
                 DRIVERS[idx].code, DRIVER_WHAT[idx], det);
        break;
    }
    default:
        break;
    }
}

/* ── Ready-to-install summary ───────────────────────────────────────────────── */

struct review_ctx {
    struct app *app;
    int x, col_w, y, pitch, first;
};

static void review_group(struct review_ctx *c, const char *name)
{
    if (!c->first)
        c->y += 6;
    c->first = 0;
    draw_text_ft(c->app, name, c->x, c->y, c->col_w, 11, 0xff8b96a4u);
    c->y += c->pitch;
}

/* label | value [tag]; the tag is drawn only when it fits before the column edge. */
static void review_row(struct review_ctx *c, const char *label, const char *value, const char *tag)
{
    int vx = c->x + 128;
    int vw = c->col_w - 128;
    draw_text_clip(c->app, label, c->x + 14, c->y, 110, 12, 0xff9aa6b4u);
    draw_text_clip(c->app, value, vx, c->y, vw, 12, 0xffe6ecf2u);
    int vwid = text_width(c->app, value, 12);
    if (vwid > vw) vwid = vw;
    int tx = vx + vwid + 10;
    if (tag && tag[0] && tx + text_width(c->app, tag, 11) <= c->x + c->col_w)
        draw_text_ft(c->app, tag, tx, c->y + 1, c->col_w, 11, 0xff5f6b78u);
    c->y += c->pitch;
}

static const char *encryption_name(struct app *app)
{
    if (app->encryption_mode == ENC_FULL)
        return "Full disk";
    if (app->encryption_mode == ENC_HIDDEN)
        return "Hidden OS";
    return "None";
}

static void review_localisation(struct review_ctx *c)
{
    struct app *app = c->app;
    char v[96];
    review_group(c, "LOCALISATION");
    review_row(c, "Language", LOCALES[app->locale_idx].label, "recorded only");
    snprintf(v, sizeof v, "%s - %s", KEYMAPS[app->keymap_idx].label, KEYMAPS[app->keymap_idx].sub);
    review_row(c, "Keyboard", v, app->keymap_idx == 0 ? "matches today" : "recorded only");
    review_row(c, "Time zone", TIMEZONES[app->timezone_idx].code,
               app->timezone_idx == 0 ? "matches today" : "recorded only");
}

static void review_network(struct review_ctx *c)
{
    struct app *app = c->app;
    char v[96];
    review_group(c, "NETWORK & DRIVERS");
    review_row(c, "Network", NETWORKS[app->network_idx].label, "recorded only");
    drivers_summary(app, v, sizeof v);
    review_row(c, "Drivers", v, "recorded only");
}

static void review_disk(struct review_ctx *c)
{
    struct app *app = c->app;
    char v[96], sz[32];
    review_group(c, "DISK");
    int pos = chosen_disk_pos(app);
    if (app->target_sel > 0 && pos >= 0) {
        fmt_size(app->disks[pos].size_mib, sz, sizeof sz);
        snprintf(v, sizeof v, "Disk %d - %s", app->disks[pos].index, sz);
    } else if (pos >= 0) {
        fmt_size(app->disks[pos].size_mib, sz, sizeof sz);
        snprintf(v, sizeof v, "Automatic - first disk, usually Disk %d (%s)", app->disks[pos].index, sz);
    } else {
        snprintf(v, sizeof v, "Automatic - kernel picks the boot disk");
    }
    review_row(c, "Target", v, "erased");
    if (app->encryption_mode == ENC_HIDDEN)
        snprintf(v, sizeof v, "Hidden OS - decoy + outer volume, 3 passwords");
    else if (app->encryption_mode == ENC_FULL)
        snprintf(v, sizeof v, "Full disk - one password asked at boot");
    else
        snprintf(v, sizeof v, "None - plain; 8 MB boot + two 512 MB slots");
    review_row(c, "Encryption", v, "applied at install");
    review_row(c, "Filesystem", FILESYSTEMS[app->filesystem_idx].label, "recorded only");
    int zk = strcmp(BOOTINTEGRITY[app->bootintegrity_idx].code, "zksync") == 0;
    review_row(c, "Boot check", zk ? "zkSync - checked at every boot, needs network" : "Off",
               zk ? "checked at every boot" : "nothing checked");
}

static void review_accounts(struct review_ctx *c, int show_password)
{
    struct app *app = c->app;
    char v[320];
    review_group(c, "ACCOUNTS");
    if (app->field_len[FIELD_REAL_FULLNAME] > 0)
        snprintf(v, sizeof v, "%s (%s) on %s", app->field_text[FIELD_REAL_USER],
                 app->field_text[FIELD_REAL_FULLNAME], app->field_text[FIELD_HOSTNAME]);
    else
        snprintf(v, sizeof v, "%s on %s", app->field_text[FIELD_REAL_USER],
                 app->field_text[FIELD_HOSTNAME]);
    review_row(c, "Account", v, "applied at every boot");
    if (show_password)
        review_row(c, "Password", "set - hash recorded only, not used for login", "recorded only");
    identities_summary(app, v, sizeof v);
    review_row(c, "Identities", v, "recorded only");
    if (app->encryption_mode == ENC_HIDDEN) {
        const char *du = app->field_text[FIELD_DECOY_USER][0] ? app->field_text[FIELD_DECOY_USER] : "decoy";
        const char *dh = app->field_text[FIELD_DECOY_HOSTNAME][0] ? app->field_text[FIELD_DECOY_HOSTNAME] : "decoy-pc";
        if (app->field_len[FIELD_DECOY_FULLNAME] > 0)
            snprintf(v, sizeof v, "%s (%s) on %s", du, app->field_text[FIELD_DECOY_FULLNAME], dh);
        else
            snprintf(v, sizeof v, "%s on %s", du, dh);
        review_row(c, "Decoy OS", v, "recorded only");
    }
}

/* Grouped key/value summary: one column under 900px of content width, two
 * (localisation + network left, disk + accounts right) above it.  At 600 tall
 * the pitch is 17 and, in Hidden-OS mode, the Password row is dropped so the
 * extra Decoy row still ends above the warning card. */
static void draw_review(struct app *app)
{
    int cw = content_w(app);
    int pitch = app->height < 680 ? 17 : 20;
    int show_password = !(app->height < 680 && app->encryption_mode == ENC_HIDDEN);
    struct review_ctx c = { app, CONTENT_X, cw, 112, pitch, 1 };
    if (cw >= 900) {
        int col_w = (cw - 24) / 2;
        c.col_w = col_w;
        review_localisation(&c);
        review_network(&c);
        struct review_ctx r = { app, CONTENT_X + col_w + 24, col_w, 112, pitch, 1 };
        review_disk(&r);
        review_accounts(&r, 1);
        return;
    }
    review_localisation(&c);
    review_network(&c);
    review_disk(&c);
    review_accounts(&c, show_password);
}

/* ── install phases (progress page) ─────────────────────────────────────────── */

/* Phase numbers are the kernel's INST_PHASE_* values (veracrypt_impl.d) reported
 * as "p<hex>".  Plain A/B installs go p0 -> p6 -> p7; Hidden OS p0 -> p1 -> p2 ->
 * p3 -> p4 -> p5; Full disk p0 -> p1 -> p2 -> p8 -> p5 (INST_PHASE_FDE_IMAGE is 8,
 * taking the place of the decoy + hidden image steps).  These tables must be kept
 * in step with that enum: a phase missing here shows as "Writing (phase N)" with
 * no step count.  The GPT is written synchronously before p0, without progress. */
struct phase_info {
    int phase;
    const char *label;
    const char *explain;
};

static const struct phase_info PHASES_PLAIN[] = {
    { 0, "Writing the system image (slot A)",
         "512 MB boot image with the kernel, modules and boot loader; install.json is added when it completes." },
    { 6, "Writing the system image (slot B)",
         "An identical second copy, so a future update can go into the unused slot." },
    { 7, "Writing the boot manager",
         "8 MB partition that picks the slot to start (slot A first), then the boot-state sector." },
};

static const struct phase_info PHASES_HIDDEN[] = {
    { 0, "Writing the boot partition",
         "Small plain partition with the preboot loader that asks for your password; it is the only unencrypted thing on the disk." },
    { 1, "Randomizing the decoy partition",
         "Filling the decoy system partition with random data before its encrypted image." },
    { 2, "Randomizing the outer volume (the long step)",
         "Every remaining sector of the disk is filled with random data; on a 64 GB disk this is about 97% of the work, so the bar can look still for minutes." },
    { 3, "Writing the encrypted decoy OS",
         "The decoy Linux image, encrypted into its own partition." },
    { 4, "Writing the encrypted hidden OS",
         "The 512 MB EpinAnonymOS image, encrypted and placed inside the outer volume." },
    { 5, "Writing the volume headers",
         "The decoy, outer and hidden volume headers; install.json went inside the encrypted hidden volume with its image." },
};

/* Full disk is the Hidden-OS layout without a decoy: the same partitions and the
 * same random fill (so the two are indistinguishable from the outside), then the
 * EpinAnonymOS image goes encrypted into the system partition (kernel phase 8). */
static const struct phase_info PHASES_FULL[] = {
    { 0, "Writing the boot partition",
         "Small plain partition with the preboot loader that asks for your disk password; it is the only unencrypted thing on the disk." },
    { 1, "Randomizing the system partition",
         "Filling the encrypted system partition with random data before its image." },
    { 2, "Randomizing the rest of the disk (the long step)",
         "Every remaining sector is filled with random data so used and free space look alike; on a large disk this is most of the work." },
    { 8, "Writing the encrypted system image",
         "The 512 MB EpinAnonymOS image, encrypted with the key your disk password unlocks; install.json goes inside it." },
    { 5, "Writing the volume header",
         "One volume header keyed by your disk password; the rest of the disk stays random." },
};

static const struct phase_info *phase_table(struct app *app, int *count)
{
    if (app->encryption_mode == ENC_HIDDEN) { *count = ARRAY_LEN(PHASES_HIDDEN); return PHASES_HIDDEN; }
    if (app->encryption_mode == ENC_FULL)   { *count = ARRAY_LEN(PHASES_FULL);   return PHASES_FULL; }
    *count = ARRAY_LEN(PHASES_PLAIN);
    return PHASES_PLAIN;
}

/* Index of `phase` in the current table, or -1 when unknown. */
static int phase_index(struct app *app, int phase)
{
    int n;
    const struct phase_info *t = phase_table(app, &n);
    for (int i = 0; i < n; i++)
        if (t[i].phase == phase)
            return i;
    return -1;
}

static const char *const SLIDES[] = {
    "Programs on EpinAnonymOS get only the capabilities handed to them; there is no ambient root.",
    "install.json is read at every boot, so you can always inspect exactly what the installer recorded.",
    "Two system slots (A/B) are written so a future update can go into the unused slot; the boot manager starts slot A.",
    "Hidden OS: the real system sits in the outer volume's free space, which reads as random data without its password; install.json is inside it.",
    "On a plain install the password hashes in install.json are unsalted SHA-512 on a readable partition; treat them as public and never reuse those passwords.",
    "The Logs app in the top bar shows this install live: filter for 'install'.",
};

/* Progress-poll cadence while installing: the kernel counter is re-read at most
 * this often, whatever else wakes the main loop (R-01). */
enum { PROGRESS_POLL_MS = 250 };

/* Milliseconds since `t` on CLOCK_MONOTONIC.  A zeroed `t` (never stamped) reads
 * as "long ago" so the first poll is immediate; -1 means the clock is unusable
 * and the caller must fall back to a fixed cadence rather than spin. */
static long ms_since(const struct timespec *t)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    if (t->tv_sec == 0 && t->tv_nsec == 0)
        return 1000000L;
    long ms = (now.tv_sec - t->tv_sec) * 1000L + (now.tv_nsec - t->tv_nsec) / 1000000L;
    return ms < 0 ? 0 : ms;
}

/* Seconds since start_install(); frozen at install_end once done or failed. */
static long elapsed_seconds(struct app *app)
{
    if (!app->have_clock)
        return 0;
    struct timespec now;
    if (app->install_done || app->install_failed)
        now = app->install_end;
    else if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    long s = now.tv_sec - app->install_start.tv_sec;
    if (now.tv_nsec < app->install_start.tv_nsec)
        s--;
    return s < 0 ? 0 : s;
}

/* "812 MB" below 1000 MB, "2.1 GB" above (decimal units, 512-byte sectors). */
static void fmt_bytes_from_sectors(unsigned long sectors, char *buf, size_t cap)
{
    unsigned long long bytes = (unsigned long long)sectors * 512ULL;
    unsigned long mb = (unsigned long)(bytes / 1000000ULL);
    if (mb < 1000)
        snprintf(buf, cap, "%lu MB", mb);
    else
        snprintf(buf, cap, "%lu.%lu GB", mb / 1000, (mb % 1000) / 100);
}

static void fmt_elapsed(long secs, char *buf, size_t cap)
{
    if (secs >= 3600)
        snprintf(buf, cap, "%ld:%02ld:%02ld", secs / 3600, (secs / 60) % 60, secs % 60);
    else
        snprintf(buf, cap, "%ld:%02ld", secs / 60, secs % 60);
}

/* Record one (elapsed second, done_sectors) sample for the ETA window.  Called from the progress
 * poll; cheap enough to call on every poll because it only stores when the second changes. */
static void rate_sample(struct app *app)
{
    long el = elapsed_seconds(app);
    if (el == app->rate_last_t)
        return;
    app->rate_last_t = el;
    app->rate_t[app->rate_n % RATE_WINDOW] = el;
    app->rate_d[app->rate_n % RATE_WINDOW] = app->done_sectors;
    app->rate_n++;
}

/* Sectors per second over the last RATE_WINDOW samples, or 0 if there is not enough history.
 * Uses the oldest sample still in the ring as the baseline, so the window is self-trimming. */
static double rate_windowed(struct app *app)
{
    if (app->rate_n < 2)
        return 0.0;
    int newest = (app->rate_n - 1) % RATE_WINDOW;
    int count  = app->rate_n < RATE_WINDOW ? app->rate_n : RATE_WINDOW;
    int oldest = (app->rate_n - count) % RATE_WINDOW;
    long dt = app->rate_t[newest] - app->rate_t[oldest];
    if (dt < 3)                                  /* too short to quote honestly */
        return 0.0;
    if (app->rate_d[newest] <= app->rate_d[oldest])
        return 0.0;                              /* no progress in the window: say "estimating" */
    return (double)(app->rate_d[newest] - app->rate_d[oldest]) / (double)dt;
}

/* "estimating time..." until the window has enough history, then a coarse remaining-time phrase.
 * The rate is the windowed one so the number tracks the phase actually running -- the phases here
 * differ by more than an order of magnitude, and a since-start average reports the wrong one. */
static void fmt_eta(struct app *app, char *buf, size_t cap)
{
    long el = elapsed_seconds(app);
    if (el < 5 || app->done_sectors == 0 || app->total_sectors <= app->done_sectors) {
        snprintf(buf, cap, "estimating time...");
        return;
    }
    double rate = rate_windowed(app);
    if (rate <= 0.0) {
        if (el < 15) { snprintf(buf, cap, "estimating time..."); return; }
        rate = (double)app->done_sectors / (double)el;         /* fall back to since-start */
    }
    long left = (long)((double)(app->total_sectors - app->done_sectors) / rate);
    if (left < 60)
        snprintf(buf, cap, "under a minute left");
    else if (left < 3600)
        snprintf(buf, cap, "about %ld min left", (left + 30) / 60);
    else
        snprintf(buf, cap, "about %ld h %ld min left", left / 3600, (left % 3600) / 60);
}

/* Scrollbar for the form content pane, drawn on the right gutter when the page's
 * content is taller than the viewport. */
static void draw_content_scrollbar(struct app *app, cairo_t *cr)
{
    int maxs = content_max_scroll(app);
    if (maxs <= 0)
        return;
    int vt = content_view_top(app), vb = content_view_bottom(app);
    double track_h = vb - vt;
    double tx = CONTENT_X + content_w(app) + 10, tw = 5;

    rounded_rect(cr, tx, vt, tw, track_h, 2.5);
    cairo_set_source_rgb(cr, 0.14, 0.18, 0.22);
    cairo_fill(cr);

    double content_h = content_natural_bottom(app) - vt;
    double frac = content_h > 0 ? track_h / content_h : 1.0;
    if (frac > 1) frac = 1;
    double thumb_h = track_h * frac;
    if (thumb_h < 26) thumb_h = 26;
    double sfrac = (double)app->content_scroll / (double)maxs;
    double thumb_y = vt + (track_h - thumb_h) * sfrac;
    rounded_rect(cr, tx, thumb_y, tw, thumb_h, 2.5);
    cairo_set_source_rgb(cr, 0.30, 0.55, 0.52);
    cairo_fill(cr);
}

/* Welcome: three paragraphs (what the wizard does, three bullets, what you need).
 * At >= 680 tall each gap grows by 12px so the page is not top-heavy. */
static void draw_welcome(struct app *app)
{
    int x = CONTENT_X;
    int w = content_w(app);
    int extra = app->height >= 680 ? 12 : 0;
    int y = 112;
    draw_text_wrapped(app,
        "This wizard collects your choices into one file, install.json, then writes EpinAnonymOS "
        "to a disk and makes it bootable. Every page says what its choice really does on the "
        "installed system today.",
        x, y, w, 12, 3, 0xffb9c4d2u);
    y = 178 + extra;
    const char *bullets[] = {
        "- Object-capability kernel: programs get only the rights they are handed",
        "- Optional Hidden OS: a decoy Linux plus an encrypted, hidden EpinAnonymOS",
        "- Your choices stay inspectable: install.json is read at every boot",
    };
    for (int i = 0; i < 3; i++) {
        draw_text_clip(app, bullets[i], x, y, w, 13, 0xffe6ecf2u);
        y += 22;
    }
    y = 256 + 2 * extra;
    draw_text_wrapped(app,
        "You need a disk of at least 1.1 GB that can be erased completely (more for a Hidden OS). "
        "Try Live closes this installer; to install later, reboot from this medium.",
        x, y, w, 12, 3, 0xffb9c4d2u);
}

/* Refresh the cached Wi-Fi link status from /run/wifi/dhcp-ok.  Called from
 * enter_screen() and at most once per second while on the Network page, instead of
 * on every repaint (INST-11 -- an open()/read() on the synchronous serial-logged
 * open path was happening for every frame the Network page was shown).  Returns 1
 * when the status changed (so the caller can request a repaint). */
static int refresh_wifi_status(struct app *app)
{
    char ip[48] = {0};
    int fd = open("/run/wifi/dhcp-ok", O_RDONLY);
    if (fd >= 0) {
        int n = (int)read(fd, ip, sizeof ip - 1);
        if (n > 0) ip[n] = 0;
        for (char *q = ip; *q; q++) if (*q == '\n' || *q == '\r') *q = 0;
        close(fd);
    }
    app->wifi_checked = time(NULL);
    if (strcmp(ip, app->wifi_ip) == 0)
        return 0;
    memcpy(app->wifi_ip, ip, sizeof app->wifi_ip);
    return 1;
}

/* Disk page card: which disk is going to be erased, in plain words. */
static void disk_card(struct app *app, struct card *c)
{
    card_init(c, CARD_DESTRUCTIVE, "", "Erases disk");
    if (app->disk_count == 0) {
        snprintf(c->header, sizeof c->header, "No disks were listed");
        card_detail(c, COL_AMBER, "Nothing was listed in /config/disks.json. Automatic lets the "
                    "kernel search for the firmware boot disk at install time; if it finds none, "
                    "the install fails and the Logs app (filter install) has the reason.");
        return;
    }
    char dt[48];
    chosen_disk_text(app, dt, sizeof dt, "the boot disk");
    if (app->target_sel == 0) {
        snprintf(c->header, sizeof c->header, "Automatic will erase %s", dt);
        snprintf(c->detail, sizeof c->detail, "The kernel picks the disk the firmware boots from: "
                 "the NVMe drive, otherwise the lowest-numbered SATA disk - here %s. Pick a row "
                 "below to choose a different disk explicitly.", dt);
    } else {
        snprintf(c->header, sizeof c->header, "%s will be erased", dt);
        snprintf(c->detail, sizeof c->detail, "%s is erased: its partition table is replaced and it "
                 "is written from the start. A plain install needs 1.1 GB; Full disk and Hidden OS "
                 "need more (the encrypted layout is sized for the decoy image either way) and "
                 "overwrite every sector.", dt);
    }
}

/* Summary page warning card: what Install Now does to the disk plus the one
 * secondary warning that matters most. */
static void review_card(struct app *app, struct card *c)
{
    card_init(c, CARD_DESTRUCTIVE, "", "Cannot be undone");
    int pos = chosen_disk_pos(app);
    char sz[32];
    if (pos >= 0)
        fmt_size(app->disks[pos].size_mib, sz, sizeof sz);
    if (app->target_sel > 0 && pos >= 0)
        snprintf(c->header, sizeof c->header, "Disk %d (%s) will be erased", app->disks[pos].index, sz);
    else if (pos >= 0)
        snprintf(c->header, sizeof c->header, "The first disk (usually Disk %d, %s) will be erased",
                 app->disks[pos].index, sz);
    else
        snprintf(c->header, sizeof c->header, "The disk the kernel picks will be erased");

    /* Both encrypted layouts random-fill the whole disk before their volumes
     * (kernel INST_PHASE_SYS_RANDOM + _OUTER_RANDOM run for Full disk too, so the
     * two modes cannot be told apart from outside); the difference is what is
     * written afterwards. */
    int plain = app->encryption_mode == ENC_NONE;
    int zk = strcmp(BOOTINTEGRITY[app->bootintegrity_idx].code, "zksync") == 0;
    const char *primary = plain
        ? "Install Now replaces the partition table and rewrites the first 1.1 GB; the rest becomes free space for your data."
        : app->encryption_mode == ENC_HIDDEN
        ? "Install Now overwrites every sector with random data, then writes the encrypted decoy and hidden volumes; large disks take a long time."
        : "Install Now overwrites every sector with random data, then writes the encrypted system volume; large disks take a long time.";
    const char *secondary;
    uint32_t color = COL_DETAIL;
    if (plain && pos >= 0 && app->disks[pos].size_mib < MIN_DISK_MIB) {
        secondary = "This disk is too small for the layout; Install Now is disabled.";
        color = COL_RED;
    } else if (zk) {
        secondary = "zkSync is on: the installed system will not boot without a working network.";
        color = COL_AMBER;
    } else if (!plain && pos >= 0 && app->disks[pos].size_mib < 1200) {
        /* Same sizing rule for both encrypted modes: the system partition is
         * sized from the decoy image whether or not it gets written. */
        secondary = "This disk is probably too small for an encrypted layout; the kernel checks the exact size and refuses.";
        color = COL_AMBER;
    } else if (plain) {
        secondary = "No encryption: anyone with the disk can read it, including the password hashes in install.json.";
        color = COL_AMBER;
    } else if (app->encryption_mode == ENC_HIDDEN) {
        secondary = "Without the hidden password there is no recovery; install.json lives inside the encrypted hidden volume.";
    } else {
        secondary = "Without the disk password there is no recovery; the pre-boot prompt asks for it at every start.";
    }
    snprintf(c->detail, sizeof c->detail, "%s %s", primary, secondary);
    c->detail_color = color;
}

static void progress_card(struct app *app, struct card *c)
{
    if (app->install_failed) {
        card_init(c, CARD_DESTRUCTIVE, "The disk may be partially written", "Not bootable");
        card_detail(c, COL_DETAIL, "Passwords have been wiped from memory. To try again, reboot from "
                    "this medium; the installer cannot be reopened from the live desktop.");
        return;
    }
    if (app->install_done) {
        card_init(c, CARD_SUCCESS, "Remove the install medium, then restart", "Done");
        if (app->reboot_denied)
            card_detail(c, COL_AMBER, "Restart was not permitted from here. Hold the power button "
                        "until the machine is off, remove the install medium, then start it again.");
        else
            card_detail(c, COL_DETAIL, "Take out the USB stick or disc, then click Restart now. The "
                        "firmware should boot the new disk; if it does not, pick the disk in the "
                        "firmware boot menu.");
        return;
    }
    int n;
    phase_table(app, &n);
    int idx = app->phase_seen ? phase_index(app, app->install_phase) : -1;
    char tag[32];
    if (idx >= 0)
        snprintf(tag, sizeof tag, "Step %d of %d", idx + 1, n);
    else
        snprintf(tag, sizeof tag, "%d steps", n);
    card_init(c, CARD_INFO, "While you wait", tag);
    /* The slide rotates on elapsed time so it keeps moving through the long
     * random-fill phase; the Hidden-OS slide is skipped on other layouts. */
    int nslides = ARRAY_LEN(SLIDES);
    int hidden = app->encryption_mode == ENC_HIDDEN;
    int s = (int)((elapsed_seconds(app) / 10) % (hidden ? nslides : nslides - 1));
    if (!hidden && s >= 3)
        s++;
    card_detail(c, COL_DETAIL, SLIDES[s]);
}

/* The single dispatcher: what the card says on each page. */
static void screen_card(struct app *app, struct card *c)
{
    char buf[400];
    int count = 0;
    const struct opt *o = screen_opts(app->screen, &count);
    int *sel = screen_sel_ptr(app, app->screen);

    switch (app->screen) {
    case SCREEN_WELCOME: {
        int k, n;
        step_position(app, &k, &n);
        snprintf(buf, sizeof buf, "%d steps", n);
        card_init(c, CARD_INFO, "Before you begin", buf);
        card_detail(c, COL_DETAIL, "Use Back at any time to change a choice; nothing is written until "
                    "you confirm on the Summary page. Keys are read with the US layout in this "
                    "session - check yours on the Keyboard page before typing a password.");
        return;
    }
    case SCREEN_LANGUAGE:
    case SCREEN_KEYBOARD:
    case SCREEN_TIMEZONE:
    case SCREEN_NETWORK:
    case SCREEN_FILESYSTEM:
    case SCREEN_BOOTINTEGRITY: {
        int idx = (o && sel) ? *sel : 0;
        if (idx < 0 || idx >= count) idx = 0;
        int kind = CARD_RECORDED;
        const char *tag = "Recorded only";
        uint32_t color = COL_DETAIL;
        if ((app->screen == SCREEN_KEYBOARD || app->screen == SCREEN_TIMEZONE) && idx == 0) {
            kind = CARD_INFO;
            tag = "Matches today";
        } else if (app->screen == SCREEN_NETWORK && idx == 2) {
            if (app->wifi_ip[0]) { kind = CARD_INFO; tag = "Live: connected"; color = COL_GREEN; }
            else { kind = CARD_CAUTION; tag = "Live: connecting"; color = COL_AMBER; }
        } else if (app->screen == SCREEN_BOOTINTEGRITY) {
            if (idx == 0) { kind = CARD_INFO; tag = "Nothing checked"; }
            else { kind = CARD_CAUTION; tag = "Checked at every boot"; color = COL_AMBER; }
        }
        /* Network and Boot integrity subs are sentences, not codes: "<label>  -  <sub>"
         * would not fit beside the tag at 820px, and the sub is already on the
         * selected row, so the header is the label alone there. */
        if (app->screen == SCREEN_BOOTINTEGRITY || app->screen == SCREEN_NETWORK)
            snprintf(buf, sizeof buf, "%s", o[idx].label);
        else
            snprintf(buf, sizeof buf, "%s  -  %s", o[idx].label, o[idx].sub);
        card_init(c, kind, buf, tag);
        opt_detail(app, app->screen, idx, buf, sizeof buf);
        if (app->screen == SCREEN_BOOTINTEGRITY && idx == 0 && opt_is_disabled(app, app->screen, 1)) {
            size_t l = strlen(buf);
            snprintf(buf + l, sizeof buf - l, " zkSync is unavailable here: %s.",
                     strcmp(NETWORKS[app->network_idx].code, "offline") == 0
                         ? "needs a Wired or Wi-Fi choice on the Network page"
                         : "this medium carries no registry contract");
        }
        card_detail(c, color, buf);
        return;
    }
    case SCREEN_DRIVERS:
    case SCREEN_IDENTITIES: {
        int drivers = app->screen == SCREEN_DRIVERS;
        const int *on = drivers ? app->drivers_on : app->identity_on;
        int total = drivers ? ARRAY_LEN(DRIVERS) : ARRAY_LEN(IDENTITIES);
        int n = toggle_count(on, total);
        char list[200];
        if (drivers) drivers_summary(app, list, sizeof list);
        else identities_summary(app, list, sizeof list);
        if (n == 0 && drivers)
            snprintf(buf, sizeof buf, "0 of %d ticked", total);
        else
            snprintf(buf, sizeof buf, "%d of %d ticked: %s", n, total, list);
        card_init(c, CARD_RECORDED, buf, "Recorded only");
        int cur = app->list_cursor;
        if (cur < 0 || cur >= total) cur = 0;
        opt_detail(app, app->screen, cur, buf, sizeof buf);
        card_detail(c, COL_DETAIL, buf);
        return;
    }
    case SCREEN_DISK:
        disk_card(app, c);
        return;
    case SCREEN_ENCRYPTION: {
        if (app->encryption_mode == ENC_NONE) {
            card_init(c, CARD_CAUTION, "No encryption", "Applied at install");
            card_detail(c, COL_DETAIL, "Nothing on the disk is protected. install.json on the boot "
                        "partition keeps unsalted SHA-512 hashes of every password typed here; do not "
                        "reuse a valuable one.");
            return;
        }
        struct vmsg m;
        form_validate(app, &m);
        card_init(c, CARD_INFO,
                  app->encryption_mode == ENC_FULL ? "Full disk encryption: one password"
                                                   : "Hidden OS: three passwords",
                  "Applied at install");
        card_detail(c, m.color, m.text);
        return;
    }
    case SCREEN_DECOY: {
        struct vmsg m;
        form_validate(app, &m);
        const char *du = app->field_text[FIELD_DECOY_USER];
        const char *dh = app->field_text[FIELD_DECOY_HOSTNAME];
        if (!du[0] && !dh[0])
            snprintf(buf, sizeof buf, "Decoy account (defaults)");
        else
            snprintf(buf, sizeof buf, "Decoy account '%s' on '%s'", du[0] ? du : "decoy",
                     dh[0] ? dh : "decoy-pc");
        card_init(c, CARD_RECORDED, buf, "Recorded only");
        card_detail(c, m.color, m.text);
        return;
    }
    case SCREEN_ACCOUNT: {
        struct vmsg m;
        form_validate(app, &m);
        const char *user = app->field_text[FIELD_REAL_USER];
        const char *host = app->field_text[FIELD_HOSTNAME];
        if (m.blocking && m.color == COL_RED)
            snprintf(buf, sizeof buf, "Fix the highlighted field");
        else if (user[0] && host[0])
            snprintf(buf, sizeof buf, "You will sign in as '%s' on '%s'", user, host);
        else
            snprintf(buf, sizeof buf, "Your account on the installed system");
        card_init(c, CARD_INFO, buf, "Applied at every boot");
        card_detail(c, m.color, m.text);
        return;
    }
    case SCREEN_REVIEW:
        review_card(app, c);
        return;
    case SCREEN_PROGRESS:
        progress_card(app, c);
        return;
    default:
        card_init(c, CARD_INFO, "", "");
        return;
    }
}

/* Decoy page readout (overlay block, inside the form clip): the partition layout
 * the kernel writes.  Sizes are the kernel's own rules; the slider that used to
 * sit here had no effect on them, which is why it is gone. */
static void draw_decoy_readout(struct app *app)
{
    int x = CONTENT_X;
    int cw = content_w(app);
    int vx = x + 300;
    int vw = cw - 300;
    int y = DECOY_READOUT_Y - app->content_scroll;
    draw_text_clip(app, "Partition layout the kernel writes (sizes are fixed by the kernel)",
                   x, y, cw, 12, 0xff9aa6b4u);
    char rest[64], sz[32];
    if (app->disk_count > 0) {
        long m = selected_disk_mib(app) - DISK_OVERHEAD_MIB;
        if (m < 0) m = 0;
        fmt_size(m, sz, sizeof sz);
        snprintf(rest, sizeof rest, "rest of the disk (about %s)", sz);
    } else {
        snprintf(rest, sizeof rest, "rest of the disk");
    }
    const char *labels[] = {
        "Boot partition, plain with the preboot loader",
        "Decoy system, encrypted, random-filled first",
        "Outer volume, encrypted, random-filled first",
        "Hidden EpinAnonymOS, inside the outer volume",
    };
    const char *values[] = { "512 MB", "64 MB, or the decoy image + 2 MB", rest, "about 512 MB" };
    for (int i = 0; i < 4; i++) {
        int ry = y + 18 + i * 18;
        draw_text_clip(app, labels[i], x, ry, 296, 12, 0xffc8d2dfu);
        draw_text_clip(app, values[i], vx, ry, vw, 12, 0xffffffffu);
    }
}

/* Progress page, cairo half: the bar (teal running, green done, red failed). */
static void draw_progress_bg(struct app *app, cairo_t *cr)
{
    double pbx = CONTENT_X, pbw = content_w(app), pbh = 20, pby = 216;
    rounded_rect(cr, pbx, pby, pbw, pbh, 8);
    cairo_set_source_rgb(cr, 0.09, 0.14, 0.19);
    cairo_fill(cr);
    int pg = app->progress; if (pg < 0) pg = 0; if (pg > 1000) pg = 1000;
    if (app->install_done) pg = 1000;
    double fillw = pbw * pg / 1000.0;
    if (fillw > 1.0) {
        rounded_rect(cr, pbx, pby, fillw, pbh, 8);
        if (app->install_failed) cairo_set_source_rgb(cr, 0.80, 0.30, 0.25);
        else if (app->install_done) cairo_set_source_rgb(cr, 0.20, 0.68, 0.45);
        else cairo_set_source_rgb(cr, 0.05, 0.52, 0.48);
        cairo_fill(cr);
    }
}

/* Progress page, glyph half: phase line, explanation, percent, stats,
 * diagnostic and the step checklist, all driven by the kernel's phase. */
static void draw_progress_text(struct app *app)
{
    int x = CONTENT_X;
    int w = content_w(app);
    int n;
    const struct phase_info *t = phase_table(app, &n);
    int idx = app->phase_seen ? phase_index(app, app->install_phase) : -1;
    char line[256], el[24];
    fmt_elapsed(elapsed_seconds(app), el, sizeof el);

    const char *explain;
    if (app->install_failed) {
        if (!app->phase_seen)
            snprintf(line, sizeof line, "Failed before writing");
        else if (idx >= 0)
            snprintf(line, sizeof line, "Failed during: %s (step %d of %d)", t[idx].label, idx + 1, n);
        else
            snprintf(line, sizeof line, "Failed during: phase %d", app->install_phase);
        explain = "The kernel refused or aborted the write. Open the Logs app in the top bar and "
                  "filter 'install' for the FAIL reason; the full log is /run/installer.log.";
    } else if (app->install_done) {
        snprintf(line, sizeof line, "All %d steps finished in %s", n, el);
        if (app->encryption_mode == ENC_HIDDEN)
            explain = "At the preboot prompt the hidden password starts EpinAnonymOS and the decoy "
                      "boot password starts the decoy Linux.";
        else if (app->encryption_mode == ENC_FULL)
            explain = "At the pre-boot prompt the disk password unlocks and starts EpinAnonymOS.";
        else
            explain = "install.json was written into both system slots; the boot manager will start slot A.";
    } else if (!app->phase_seen) {
        snprintf(line, sizeof line, "Preparing the disk: writing the partition table");
        explain = "The partition table is written first; progress starts with the first image.";
    } else if (idx >= 0) {
        snprintf(line, sizeof line, "Step %d of %d: %s", idx + 1, n, t[idx].label);
        explain = t[idx].explain;
    } else {
        snprintf(line, sizeof line, "Writing (phase %d)", app->install_phase);
        explain = "";
    }
    draw_text_clip(app, line, x, 128, w, 15, 0xffffffffu);
    draw_text_wrapped(app, explain, x, 154, w, 13, 2, 0xffc8d2dfu);

    int pg = app->progress; if (pg < 0) pg = 0; if (pg > 1000) pg = 1000;
    if (app->install_done) pg = 1000;
    snprintf(line, sizeof line, "%d%%", pg / 10);
    draw_text_right(app, line, app->width - CONTENT_PAD, 196, 14, 0xffffffffu);

    /* stats: "812 MB of 2.1 GB written  -  elapsed 3:41  -  about 4 min left  -  6.1 MB/s" */
    char written[32], total[32], eta[40];
    fmt_bytes_from_sectors(app->done_sectors, written, sizeof written);
    if (app->total_sectors > 0) {
        fmt_bytes_from_sectors(app->total_sectors, total, sizeof total);
        snprintf(line, sizeof line, "%s of %s written", written, total);
    } else {
        snprintf(line, sizeof line, "%s written", written);
    }
    if (app->have_clock) {
        size_t l = strlen(line);
        int frozen = app->install_done || app->install_failed;
        snprintf(line + l, sizeof line - l, "  -  %s %s", frozen ? "took" : "elapsed", el);
        long es = elapsed_seconds(app);
        if (!frozen && es > 0 && app->done_sectors > 0) {
            fmt_eta(app, eta, sizeof eta);
            unsigned long long tenths = (unsigned long long)app->done_sectors * 512ULL * 10ULL /
                                        ((unsigned long long)es * 1000000ULL);
            l = strlen(line);
            snprintf(line + l, sizeof line - l, "  -  %s  -  %llu.%llu MB/s", eta,
                     tenths / 10, tenths % 10);
        }
    }
    draw_text_clip(app, line, x, 248, w, 12, 0xff9aa6b4u);

    /* diagnostic: exactly what the kernel reports, for the Logs-app cross-check */
    /* When stalled the lba field gives way to the notice: with a 64 GB disk the
     * full line ("sector 134217728 of ..., lba 0x7ffffff, ...") is wider than the
     * 512px content column at 11px, and the notice is the part that matters. */
    int stalled = app->stall_polls >= 40 && !app->install_done && !app->install_failed;
    if (stalled)
        snprintf(line, sizeof line, "phase p%x  sector %lu of %lu  -  stalled? see Logs, filter install",
                 app->install_phase, app->done_sectors, app->total_sectors);
    else
        snprintf(line, sizeof line, "phase p%x  sector %lu of %lu  lba 0x%lx", app->install_phase,
                 app->done_sectors, app->total_sectors, app->lba);
    draw_text_clip(app, line, x, 268, w, 11, stalled ? 0xffffd08au : 0xff5f6b78u);

    /* checklist: the GPT, then one row per step of the current layout */
    int y = 296;
    for (int i = -1; i < n; i++) {
        const char *label = i < 0 ? "Partition table (GPT)" : t[i].label;
        char mark;
        if (i < 0)
            mark = (app->phase_seen || app->install_done) ? '+'
                 : app->install_failed ? 'x' : '>';
        else if (app->install_done)
            mark = '+';
        else if (!app->phase_seen || idx < 0)
            mark = '-';
        else if (i < idx)
            mark = '+';
        else if (i == idx)
            mark = app->install_failed ? 'x' : '>';
        else
            mark = '-';
        uint32_t color = mark == '+' ? 0xff57d977u : mark == '>' ? 0xffffffffu
                       : mark == 'x' ? 0xffff8a8au : 0xff5f6b78u;
        char m[2] = { mark, 0 };
        draw_text_ft(app, m, x, y, 16, 12, color);
        draw_text_clip(app, label, x + 18, y, w - 18, 12, mark == '-' ? 0xff8b96a4u : color);
        y += 20;
    }
}

/* Paint one whole frame into app->pixels.  Two halves, in this order: the cairo
 * block (every filled shape: chrome, buttons, rows, fields, the card panel, the
 * progress bar) and the overlay block (every glyph, written straight into the
 * pixels after cairo_surface_flush).  Nothing in the cairo block may fill over an
 * area the overlay has already written, which is why the card background and its
 * text live in different halves.  Static chrome is redrawn every frame -- with
 * the glyph cache that is cheap, and it keeps the frame a pure function of state. */
static void draw_demo(struct app *app)
{
    cairo_surface_t *surface = cairo_image_surface_create_for_data(
        (unsigned char *)app->pixels,
        CAIRO_FORMAT_RGB24,
        app->width,
        app->height,
        app->stride);
    cairo_t *cr = cairo_create(surface);

    cairo_rectangle(cr, 0, 0, app->width, app->height);
    cairo_set_source_rgb(cr, 0.06, 0.08, 0.10);
    cairo_fill(cr);
    cairo_rectangle(cr, 0, 0, SIDEBAR_W, app->height);
    cairo_set_source_rgb(cr, 0.085, 0.115, 0.15);
    cairo_fill(cr);
    cairo_rectangle(cr, SIDEBAR_W, 0, app->width - SIDEBAR_W, app->height);
    cairo_set_source_rgb(cr, 0.065, 0.09, 0.12);
    cairo_fill(cr);

    /* logo mark */
    rounded_rect(cr, 44, 44, 30, 30, 7);
    cairo_set_source_rgb(cr, 0.05, 0.62, 0.55);
    cairo_fill(cr);

    struct card card;
    screen_card(app, &card);

    int back_enabled = app->screen != SCREEN_WELCOME && app->screen != SCREEN_PROGRESS;
    int primary_enabled = screen_can_advance(app);

    draw_button(app, cr, BTN_PRIMARY, primary_label(app), primary_enabled);
    if (app->screen == SCREEN_WELCOME)
        draw_button(app, cr, BTN_SECONDARY, "Try Live", 1);
    if (back_enabled)
        draw_button(app, cr, BTN_BACK, "Back", 1);

    if (app->screen == SCREEN_ENCRYPTION) {
        draw_segments(app, cr);
        if (erase_row_visible(app))
            draw_erase_row(app, cr);
    }

    if (screen_is_list(app->screen))
        draw_choice_list(app, cr);
    else if (app->screen == SCREEN_DISK)
        draw_disk_list(app, cr);
    else if (app->screen == SCREEN_IDENTITIES)
        draw_toggle_list(app, cr, IDENTITIES, ARRAY_LEN(IDENTITIES), app->identity_on);
    else if (app->screen == SCREEN_DRIVERS)
        draw_toggle_list(app, cr, DRIVERS, ARRAY_LEN(DRIVERS), app->drivers_on);
    else if (app->screen == SCREEN_PROGRESS)
        draw_progress_bg(app, cr);

    int form = screen_is_form(app->screen);
    if (form) {
        /* Clip fields to the scroll pane so scrolled-out rows can't paint over the
         * title, segmented control, card or button bar. clip_top/clip_bottom do the
         * same for the text glyphs drawn straight into app->pixels. */
        clamp_content_scroll(app);
        cairo_save(cr);
        cairo_rectangle(cr, CONTENT_X - 6, content_view_top(app),
                        content_w(app) + 24,
                        content_view_bottom(app) - content_view_top(app));
        cairo_clip(cr);
        app->clip_top = content_view_top(app);
        app->clip_bottom = content_view_bottom(app);

        int fields[8];
        int n = fields_for_screen(app, fields, 8);
        for (int i = 0; i < n; i++)
            draw_field(app, cr, fields[i]);
        if (app->screen == SCREEN_DECOY)
            draw_decoy_readout(app);

        cairo_restore(cr);
        app->clip_top = 0;
        app->clip_bottom = 0;
        draw_content_scrollbar(app, cr);
    }

    /* The card panel is the last shape: everything drawn after it is glyphs. */
    draw_card_bg(app, cr, card.kind);

    cairo_destroy(cr);
    cairo_surface_flush(surface);
    cairo_surface_destroy(surface);

    /* Text overlays (drawn after cairo so glyphs land on the flushed surface). */
    draw_text_ft(app, "EpinAnonymOS", 84, 50, SIDEBAR_W - 90, 17, 0xffffffffu);
    draw_steps(app);
    draw_sidebar_footer(app);
    draw_text_clip(app, screen_title(app), CONTENT_X, 54, content_w(app), 24, 0xffffffffu);
    const char *sub = screen_subtitle(app);
    if (sub[0])
        draw_text_clip(app, sub, CONTENT_X, 90, content_w(app), 13, 0xff9aa6b4u);

    if (app->screen == SCREEN_WELCOME) {
        draw_welcome(app);
    } else if (app->screen == SCREEN_ENCRYPTION) {
        /* the mode paragraph sits under the segments: 3 lines for None (no fields
         * follow), 2 for the modes with fields (they start at 250) */
        draw_text_wrapped(app, screen_body(app), CONTENT_X, 182, content_w(app), 12,
                          app->encryption_mode == ENC_NONE ? 3 : 2, 0xffb9c4d2u);
    } else if (app->screen == SCREEN_REVIEW) {
        draw_review(app);
    } else if (app->screen == SCREEN_PROGRESS) {
        draw_progress_text(app);
    } else {
        draw_text_wrapped(app, screen_body(app), CONTENT_X, 112, content_w(app), 12, 2, 0xffb9c4d2u);
    }

    draw_card_text(app, &card);
}

/* ── buffer / commit ───────────────────────────────────────────────────────── */

/* frame_done()/frame_listener are defined with the Wayland boilerplate below, but
 * render_frame() (here) arms the callback -- forward-declare the listener. */
static const struct wl_callback_listener frame_listener;

/* The compositor is done reading a buffer: mark it drawable again.  Listener data
 * is the fbuf itself, so no per-buffer lookup is needed. */
static void buffer_release(void *data, struct wl_buffer *buffer)
{
    struct fbuf *fb = data;
    (void)buffer;
    fb->busy = 0;
}

static const struct wl_buffer_listener buffer_listener = {
    .release = buffer_release,
};

/* Create BOTH shm buffers ONCE over a single memfd sized for two frames.  The old
 * code created a fresh memfd per redraw, exhausting the process's small fd pool and
 * freezing the installer mid-typing ("memfd_create: No file descriptors available");
 * the interim fix kept ONE buffer and re-attached it every frame while the compositor
 * might still be reading it (a tear/serialise hazard, INST-03).  Two buffers over one
 * lifetime memfd keep the one-memfd-per-lifetime invariant AND let the compositor hold
 * a committed frame while the next is drawn into the other. */
static int create_buffers_once(struct app *app)
{
    if (app->fb[0].buffer)
        return 0;
    app->pool_size = app->buffer_size * 2;
    int fd = create_memfd("epin-installer");
    if (fd < 0) {
        perror("G11CAIRO: memfd_create");
        return -1;
    }
    if (ftruncate(fd, (off_t)app->pool_size) < 0) {
        perror("G11CAIRO: ftruncate");
        close(fd);
        return -1;
    }
    app->map_base = (uint32_t *)mmap(NULL, app->pool_size, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, fd, 0);
    if (app->map_base == MAP_FAILED) {
        perror("G11CAIRO: mmap");
        close(fd);
        app->map_base = NULL;
        return -1;
    }
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int)app->pool_size);
    for (int i = 0; i < 2; i++) {
        app->fb[i].buffer = wl_shm_pool_create_buffer(
            pool, (int)(i * app->buffer_size), app->width, app->height,
            app->stride, WL_SHM_FORMAT_XRGB8888);
        app->fb[i].pixels = app->map_base + (size_t)i * (app->buffer_size / 4);
        app->fb[i].busy = 0;
        if (!app->fb[i].buffer) {
            log_line("G11CAIRO: wl_shm_pool_create_buffer failed");
            wl_shm_pool_destroy(pool);
            close(fd);
            return -1;
        }
        wl_buffer_add_listener(app->fb[i].buffer, &buffer_listener, &app->fb[i]);
    }
    wl_shm_pool_destroy(pool);         /* buffers keep the pool's fd ref; mapping is ours */
    close(fd);
    app->pixels = app->fb[0].pixels;
    return 0;
}

/* Index of a buffer the compositor is not reading, or -1 if both are still busy. */
static int pick_free_fb(struct app *app)
{
    for (int i = 0; i < 2; i++)
        if (app->fb[i].buffer && !app->fb[i].busy)
            return i;
    return -1;
}

/* Paint the current UI into a free buffer, attach/damage/commit it, and arm a
 * wl_surface_frame callback so the next paint is paced to the compositor.  Returns
 * 1 if it committed, 0 if it had to defer (no free buffer -- dirty stays set and a
 * wl_buffer.release will drive the repaint).  This is the single commit path;
 * request_redraw() only marks intent, the main loop and frame_done() call this. */
static int render_frame(struct app *app)
{
    if (!app->fb[0].buffer)
        return 0;
    int i = pick_free_fb(app);
    if (i < 0)
        return 0;                      /* both buffers in flight: keep dirty, wait */

    app->pixels = app->fb[i].pixels;
    draw_demo(app);
    app->dirty = 0;

    wl_surface_attach(app->surface, app->fb[i].buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);

    if (app->frame_cb)
        wl_callback_destroy(app->frame_cb);
    app->frame_cb = wl_surface_frame(app->surface);
    wl_callback_add_listener(app->frame_cb, &frame_listener, app);
    app->frame_pending = 1;

    app->fb[i].busy = 1;
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    return 1;
}

/* Coalesce a redraw: just record intent.  Every event listener calls this instead
 * of committing inline, so a burst of events (a held key, a drag) collapses to one
 * paint per frame (INST-02/04).  The marker is kept for debugging only. */
static void request_redraw(struct app *app, const char *marker)
{
    app->dirty = 1;
    if (app->debug && marker)
        ilog("G11INPUT: %s", marker);
}

/* Force an immediate paint (screen transitions, resize, initial map).  Uses the
 * same paced path; if no buffer is free it stays dirty and the loop repaints. */
static void redraw_now(struct app *app)
{
    app->dirty = 1;
    render_frame(app);
}

/* ── install backend control ───────────────────────────────────────────────── */

/* Freeze the clock for "took m:ss" once the install has ended either way. */
static void stamp_install_end(struct app *app)
{
    if (app->have_clock)
        clock_gettime(CLOCK_MONOTONIC, &app->install_end);
}

/* Poll /config/install.progress ONCE.  The GUI does NOT write install.action here
 * any more: start_install() sends "install" exactly once and the kernel loop drives
 * the whole disk write (INST-09).  The progress fd is opened once and re-read with
 * lseek(0) each poll rather than reopened, and a repaint is requested only when
 * something the page shows actually changed (permille, phase, sector counter, or
 * the elapsed second). */
static void poll_install_progress(struct app *app)
{
    if (app->progress_fd < 0) {
        app->progress_fd = open("/config/install.progress", O_RDONLY);
        if (app->progress_fd < 0) {
            ilog("INSTALLER: ERROR /config/install.progress open failed (errno=%d)", errno);
            return;
        }
    }
    /* posix.d regenerates the line only for a read at offset 0, so a fd whose
     * lseek failed would return 0 bytes forever.  Any failure here drops the fd
     * and the next poll reopens the file at offset 0 (one open() per poll, the
     * pre-INST-09 behaviour) instead of dead-ending with the install invisible. */
    if (lseek(app->progress_fd, 0, SEEK_SET) == (off_t)-1) {
        ilog("INSTALLER: warn /config/install.progress lseek failed (errno=%d); reopening", errno);
        close(app->progress_fd);
        app->progress_fd = -1;
        return;
    }
    char b[128];
    ssize_t n = read(app->progress_fd, b, sizeof b - 1);
    if (n <= 0) {
        ilog("INSTALLER: warn /config/install.progress read returned %zd (errno=%d); reopening", n, errno);
        close(app->progress_fd);
        app->progress_fd = -1;
        return;
    }
    b[n] = 0;

    /* Kernel status contract: "<permille> p<phase-hex> d<done-hex> t<total-hex> l<lba-hex>".
     * -1 = FAILED, 0 = never started, 1..1000 = permille (floored at 1 while active). */
    int next = atoi(b);
    if (next > 1000) next = 1000;
    if (next < 0) {
        if (app->installing) {
            ilog("INSTALLER: FAILED at %d.%d%% -- kernel refused/aborted the install; "
                 "open the Logs app and filter 'install' for the [install] FAIL reason",
                 app->progress / 10, app->progress % 10);
            app->install_failed = 1;
            app->installing = 0;
            stamp_install_end(app);
            request_redraw(app, "install-failed");
        }
        return;
    }

    /* "Never started" is judged on the clock, not on a poll count: the kernel loop
     * publishes its first permille on its own schedule after the single "install"
     * write, and how often this function runs depends on Wayland traffic, so a
     * count of zero reads says nothing.  The kernel floors the permille at 1 as
     * soon as the install is active, so 0 after NEVER_STARTED_S seconds means the
     * command was not picked up (not an install boot). */
    enum { NEVER_STARTED_S = 3 };
    if (app->installing && next == 0) {
        app->install_zero_reads++;
        /* Without a monotonic clock fall back to the poll count; polls are paced
         * at PROGRESS_POLL_MS by the main loop, so 12 of them is about 3 s too. */
        int never_started = app->have_clock ? elapsed_seconds(app) >= NEVER_STARTED_S
                                            : app->install_zero_reads > 12;
        if (never_started) {
            ilog("INSTALLER: FAILED -- install never started (progress stayed 0 for %ld s, %d polls); "
                 "not an install boot?; open the Logs app and filter 'install'",
                 elapsed_seconds(app), app->install_zero_reads);
            app->install_failed = 1;
            app->installing = 0;
            stamp_install_end(app);
            request_redraw(app, "install-failed");
            return;
        }
    } else {
        app->install_zero_reads = 0;
    }
    if (next / 10 != app->progress / 10 && next > 0 && next < 1000)
        ilog("INSTALLER: progress %d%%", next / 10);   /* once-per-percent */

    /* Parse the phase and sector counters that follow the permille.  `d` is the
     * sector counter: if it climbs while the permille does not, the install is fine
     * and the bar is just coarse.  If neither moves, it is stuck -- and the phase
     * (p) says where.  t/l feed the stats and diagnostic lines. */
    const char *pp = strstr(b, " p");
    int phase = pp ? (int)strtoul(pp + 2, NULL, 16) : 0;
    if (pp && next > 0)
        app->phase_seen = 1;
    const char *dp = strstr(b, " d");
    unsigned long done = dp ? strtoul(dp + 2, NULL, 16) : 0;
    const char *tp = strstr(b, " t");
    if (tp)
        app->total_sectors = strtoul(tp + 2, NULL, 16);
    const char *lp = strstr(b, " l");
    if (lp)
        app->lba = strtoul(lp + 2, NULL, 16);
    if (done != app->last_done) {
        app->last_done = done;
        app->stall_polls = 0;
    } else if (++app->stall_polls == 40) {
        ilog("INSTALLER: no sector progress in 40 polls -- kernel says %s", b);
        ilog("INSTALLER: if the phase and d= are unchanged the install is STUCK;");
        ilog("INSTALLER: if d= is climbing it is advancing, just slowly (CPU rendering)");
    }
    if (phase != app->install_phase && pp)
        ilog("INSTALLER: phase p%x (%s)", phase, b);

    /* Repaint when something shown changed: the permille, the phase, the sector
     * counter (MB written) or the elapsed second (clock + slide index).  A stall
     * crossing the 40-poll mark repaints once too, for the amber diagnostic. */
    long es = elapsed_seconds(app);
    if (next != app->progress || phase != app->install_phase ||
        done != app->done_sectors || es != app->last_stats_second ||
        app->stall_polls == 40)
        request_redraw(app, "install-progress");
    app->last_stats_second = es;
    app->progress = next;
    app->install_phase = phase;
    app->done_sectors = done;
    rate_sample(app);            /* feed the ETA window (no-op unless the second changed) */
}

static void write_all_len(int fd, const char *s, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, s, len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return;
        s += n;
        len -= (size_t)n;
    }
}

static void append_mem(char *buf, size_t cap, size_t *pos, const char *s, size_t len)
{
    if (*pos >= cap)
        return;
    if (len > cap - *pos)
        len = cap - *pos;
    memcpy(buf + *pos, s, len);
    *pos += len;
}

static void append_cstr(char *buf, size_t cap, size_t *pos, const char *s)
{
    append_mem(buf, cap, pos, s, strlen(s));
}

static void append_json_string(char *buf, size_t cap, size_t *pos,
                               const char *key, const char *value, int comma)
{
    append_cstr(buf, cap, pos, "  \"");
    append_cstr(buf, cap, pos, key);
    append_cstr(buf, cap, pos, "\": \"");
    for (const unsigned char *p = (const unsigned char *)value; p && *p; p++) {
        char b[8];
        if (*p == '"' || *p == '\\') {
            b[0] = '\\'; b[1] = (char)*p; b[2] = 0;
            append_cstr(buf, cap, pos, b);
        } else if (*p >= 0x20 && *p < 0x7f) {
            b[0] = (char)*p; b[1] = 0;
            append_cstr(buf, cap, pos, b);
        }
    }
    append_cstr(buf, cap, pos, comma ? "\",\n" : "\"\n");
}

#define INSTALL_CONFIG_MAX 4096

/* `redact` replaces every password value with "" -- for the on-disk debug copy in
 * /tmp, which must never hold the one secret that unlocks an encrypted install. */
static size_t build_install_config(struct app *app, char *buf, size_t cap, int redact)
{
    size_t pos = 0;
    if (cap == 0)
        return 0;

    char target[24];
    if (app->target_sel == 0)
        snprintf(target, sizeof target, "auto");
    else
        snprintf(target, sizeof target, "%d", app->disks[app->target_sel - 1].index);

    char ids[160];
    {
        size_t p = 0;
        ids[0] = 0;
        for (int i = 0; i < ARRAY_LEN(IDENTITIES); i++) {
            if (!app->identity_on[i])
                continue;
            int n = snprintf(ids + p, sizeof ids - p, "%s%s",
                             p ? "," : "", IDENTITIES[i].code);
            if (n < 0 || (size_t)n >= sizeof ids - p)
                break;
            p += (size_t)n;
        }
    }

    char drv[160];
    {
        size_t p = 0;
        drv[0] = 0;
        for (int i = 0; i < ARRAY_LEN(DRIVERS); i++) {
            if (!app->drivers_on[i])
                continue;
            int n = snprintf(drv + p, sizeof drv - p, "%s%s",
                             p ? "," : "", DRIVERS[i].code);
            if (n < 0 || (size_t)n >= sizeof drv - p)
                break;
            p += (size_t)n;
        }
    }

    /* Secrets: a password field is emitted only for the mode that uses it, so a
     * password typed under one segment and abandoned under another never leaves
     * the GUI.  That matters because the kernel hashes hiddenPassword/outerPassword/
     * decoyBootPassword (unsalted SHA-512) into the persisted install.json on a
     * plain install -- a Full-disk password typed, then "None" picked, would
     * otherwise land as a crackable hash on the readable disk. */
    const int hidden = app->encryption_mode == ENC_HIDDEN;
    const int full   = app->encryption_mode == ENC_FULL;
#define SECRET(mode_ok, field) \
    ((!redact && (mode_ok)) ? app->field_text[field] : "")
    const char *user_pw   = SECRET(1, FIELD_REAL_PASSWORD);
    const char *disk_pw   = SECRET(full, FIELD_HIDDEN_PASSWORD);
    const char *hidden_pw = SECRET(hidden, FIELD_HIDDEN_PASSWORD);
    const char *outer_pw  = SECRET(hidden, FIELD_OUTER_PASSWORD);
    const char *dboot_pw  = SECRET(hidden, FIELD_DECOY_BOOT_PASSWORD);
    const char *decoy_pw  = SECRET(hidden, FIELD_DECOY_PASSWORD);
#undef SECRET

    append_cstr(buf, cap, &pos, "{\n");
    append_json_string(buf, cap, &pos, "schema", "epin.install.v1", 1);
    append_json_string(buf, cap, &pos, "hostname", app->field_text[FIELD_HOSTNAME], 1);
    append_json_string(buf, cap, &pos, "user", app->field_text[FIELD_REAL_USER], 1);
    append_json_string(buf, cap, &pos, "userFullName", app->field_text[FIELD_REAL_FULLNAME], 1);
    append_json_string(buf, cap, &pos, "userPassword", user_pw, 1);
    append_json_string(buf, cap, &pos, "locale", LOCALES[app->locale_idx].code, 1);
    append_json_string(buf, cap, &pos, "localeName", LOCALES[app->locale_idx].label, 1);
    append_json_string(buf, cap, &pos, "keymap", KEYMAPS[app->keymap_idx].code, 1);
    append_json_string(buf, cap, &pos, "timezone", TIMEZONES[app->timezone_idx].code, 1);
    append_json_string(buf, cap, &pos, "network", NETWORKS[app->network_idx].code, 1);
    append_json_string(buf, cap, &pos, "filesystem", FILESYSTEMS[app->filesystem_idx].code, 1);
    append_json_string(buf, cap, &pos, "targetDisk", target, 1);
    append_json_string(buf, cap, &pos, "bootIntegrity", BOOTINTEGRITY[app->bootintegrity_idx].code, 1);
    append_json_string(buf, cap, &pos, "identities", ids, 1);
    append_json_string(buf, cap, &pos, "drivers", drv, 1);
    append_json_string(buf, cap, &pos, "encryption", encryption_name(app), 1);
    /* Full disk encrypts the whole EpinAnonymOS system volume with one password asked
     * at boot; it is collected in FIELD_HIDDEN_PASSWORD and emitted as diskPassword
     * (veracrypt_impl.d reads diskPassword first, hiddenPassword as a fallback for
     * the older installer).  The hidden/outer/decoy-boot keys are Hidden OS only;
     * every key is always present so the epin.install.v1 shape does not vary. */
    append_json_string(buf, cap, &pos, "diskPassword", disk_pw, 1);
    append_json_string(buf, cap, &pos, "hiddenPassword", hidden_pw, 1);
    append_json_string(buf, cap, &pos, "outerPassword", outer_pw, 1);
    append_json_string(buf, cap, &pos, "decoyBootPassword", dboot_pw, 1);
    append_json_string(buf, cap, &pos, "decoyUser", app->field_text[FIELD_DECOY_USER], 1);
    append_json_string(buf, cap, &pos, "decoyFullName", app->field_text[FIELD_DECOY_FULLNAME], 1);
    append_json_string(buf, cap, &pos, "decoyPassword", decoy_pw, 1);
    /* decoyPercent/decoySizeMiB/hiddenSizeMiB are no longer emitted: the kernel never
     * read them (it sizes the decoy and hidden volumes itself; nothing under src/ or
     * deps/ looks for the keys), so the slider that fed them was removed from the
     * Decoy page.  The schema string stays "epin.install.v1": any v1 consumer must
     * treat those three keys as optional.  decoyHostname is now the last key. */
    append_json_string(buf, cap, &pos, "decoyHostname", app->field_text[FIELD_DECOY_HOSTNAME], 1);
    /* "deniable" = random-fill the whole disk (Hidden OS always does); "fast" = fill only what the
     * layout needs.  The kernel reads this as outerFill (veracrypt_impl.d). */
    append_json_string(buf, cap, &pos, "outerFill",
                       (app->encryption_mode == ENC_HIDDEN || app->fill_whole_disk) ? "deniable" : "fast", 0);
    append_cstr(buf, cap, &pos, "}\n");
    if (pos >= cap)
        pos = cap - 1;
    buf[pos] = 0;
    return pos;
}

static int write_install_config(struct app *app)
{
    char json[INSTALL_CONFIG_MAX];
    char command[INSTALL_CONFIG_MAX + 8];
    const size_t json_len = build_install_config(app, json, sizeof json, 0);
    if (json_len == 0) {
        ilog("INSTALLER: ERROR install config build produced 0 bytes");
        return 0;
    }

    /* Debug copy for the live session: what was sent, minus every password.  The
     * kernel wipes its copy of the secrets from RAM when the install ends, and this
     * file survives until reboot, so it must never hold the disk/hidden passwords. */
    int fd = open("/tmp/install.json", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        char redacted[INSTALL_CONFIG_MAX];
        size_t rlen = build_install_config(app, redacted, sizeof redacted, 1);
        write_all_len(fd, redacted, rlen);
        close(fd);
    } else {
        ilog("INSTALLER: warn /tmp/install.json open failed (errno=%d)", errno);
    }

    memcpy(command, "config ", 7);
    memcpy(command + 7, json, json_len);
    int cfd = open("/config/install.action", O_WRONLY);
    if (cfd < 0) {
        ilog("INSTALLER: ERROR /config/install.action open failed (errno=%d) -- not an install boot?", errno);
        return 0;
    }
    write_all_len(cfd, command, json_len + 7);
    close(cfd);
    app->install_config_written = 1;
    ilog("INSTALLER: install config sent (%zu bytes json)", json_len);
    return 1;
}

static void start_install(struct app *app)
{
    /* Resolve the install command (explicit disk index, or automatic). */
    if (app->target_sel == 0) {
        app->target_index = -1;
        snprintf(app->install_cmd, sizeof app->install_cmd, "install");
    } else {
        app->target_index = app->disks[app->target_sel - 1].index;
        snprintf(app->install_cmd, sizeof app->install_cmd, "install %d", app->target_index);
    }

    ilog("INSTALLER: START install: cmd='%s' encryption=%s target_sel=%d disk=%ld MiB",
         app->install_cmd, encryption_name(app), app->target_sel, selected_disk_mib(app));
    int config_ok = write_install_config(app);
    app->screen = SCREEN_PROGRESS;
    app->progress = 0;
    app->install_phase = 0;
    app->install_done = 0;
    app->install_zero_reads = 0;
    app->last_done = 0;
    app->stall_polls = 0;
    app->phase_seen = 0;
    app->done_sectors = 0;
    app->total_sectors = 0;
    app->lba = 0;
    app->rate_n = 0;
    app->rate_last_t = -1;       /* no ETA samples yet for this install */
    app->last_stats_second = 0;
    app->reboot_denied = 0;
    memset(&app->last_poll, 0, sizeof app->last_poll);   /* first poll is due at once */
    /* Elapsed time / ETA / rate are computed client-side from this stamp; the
     * kernel only reports sectors. */
    app->have_clock = clock_gettime(CLOCK_MONOTONIC, &app->install_start) == 0;
    app->install_end = app->install_start;

    /* Write the install command exactly ONCE.  The kernel loop then drives the
     * whole disk write; the GUI only polls install.progress afterwards (INST-09).
     * The old code re-wrote "install" on every poll, forcing a synchronous 4 MiB
     * kernel batch under the BKL each frame. */
    int fd = config_ok ? open("/config/install.action", O_WRONLY) : -1;
    if (fd >= 0) {
        size_t n = strlen(app->install_cmd);
        ssize_t wn = write(fd, app->install_cmd, n);
        (void)wn;
        close(fd);
        app->installing = 1;
        app->install_failed = 0;
    } else {
        app->installing = 0;
        app->install_failed = 1;
        ilog("INSTALLER: FAILED before start: %s -- boot hos-install.iso; see Logs app, filter 'install'",
             config_ok ? "no /config/install.action" : "config send failed");
    }
    redraw_now(app);
}

/* ── navigation ────────────────────────────────────────────────────────────── */

static int screen_visible(struct app *app, int s)
{
    if (s == SCREEN_DECOY && app->encryption_mode != ENC_HIDDEN)
        return 0;
    return 1;
}

static int order_index_of(int s)
{
    for (size_t i = 0; i < sizeof(SCREEN_ORDER) / sizeof(SCREEN_ORDER[0]); i++)
        if (SCREEN_ORDER[i] == s)
            return (int)i;
    return 0;
}

static void enter_screen(struct app *app)
{
    ilog("INSTALLER: screen -> %s", screen_title(app));
    app->list_scroll = 0;
    app->content_scroll = 0;
    app->list_cursor = 0;
    app->axis_accum = 0;         /* a sub-notch remainder must not bleed into the next page */
    focus_first_field(app);      /* Keyboard page: FIELD_KEYTEST, so typing lands in the test box */
    /* auto-scroll a list to reveal the current selection; a selection that became
     * disabled since it was made (zkSync after Network went back to Offline) falls
     * back to the first row, which is the safe default on every list */
    if (screen_is_list(app->screen)) {
        int *sel = screen_sel_ptr(app, app->screen);
        if (sel) {
            if (opt_is_disabled(app, app->screen, *sel))
                *sel = 0;
            int vis = list_visible_rows(app);
            if (*sel >= vis)
                app->list_scroll = *sel - vis + 1;
        }
    } else if (app->screen == SCREEN_DISK) {
        int vis = list_visible_rows(app);
        if (app->target_sel >= vis)
            app->list_scroll = app->target_sel - vis + 1;
    }
    /* Prime the Wi-Fi status cache on entry so the Network page shows a fresh value
     * without reading the file every frame. */
    if (app->screen == SCREEN_NETWORK)
        refresh_wifi_status(app);
    redraw_now(app);
}

static void go_next(struct app *app)
{
    if (app->screen == SCREEN_REVIEW) {
        start_install(app);
        return;
    }
    int oi = order_index_of(app->screen);
    int total = (int)(sizeof(SCREEN_ORDER) / sizeof(SCREEN_ORDER[0]));
    for (int i = oi + 1; i < total; i++) {
        if (screen_visible(app, SCREEN_ORDER[i])) {
            app->screen = SCREEN_ORDER[i];
            break;
        }
    }
    enter_screen(app);
}

static void go_back(struct app *app)
{
    int oi = order_index_of(app->screen);
    for (int i = oi - 1; i >= 0; i--) {
        if (screen_visible(app, SCREEN_ORDER[i])) {
            app->screen = SCREEN_ORDER[i];
            break;
        }
    }
    enter_screen(app);
}

/* ── shm buffer / wayland boilerplate ──────────────────────────────────────── */

static int create_shm_buffer(struct app *app, int width, int height)
{
    app->width = width > 0 ? width : DEFAULT_WIDTH;
    app->height = height > 0 ? height : DEFAULT_HEIGHT;
    app->stride = app->width * 4;
    app->buffer_size = (size_t)app->stride * (size_t)app->height;

    if (!app->font_ready)
        init_freetype(app);
    if (create_buffers_once(app) < 0)  /* two buffers over ONE lifetime memfd */
        return -1;
    return 0;                          /* the caller paints via render_frame() */
}

static void wm_base_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial)
{
    (void)data;
    xdg_wm_base_pong(wm_base, serial);
}

static const struct xdg_wm_base_listener wm_base_listener = {
    .ping = wm_base_ping,
};

static void toplevel_configure(void *data, struct xdg_toplevel *toplevel,
                               int32_t width, int32_t height, struct wl_array *states)
{
    struct app *app = data;
    (void)toplevel;
    (void)states;
    if (width > 0)
        app->pending_width = width;
    if (height > 0)
        app->pending_height = height;
}

static void toplevel_close(void *data, struct xdg_toplevel *toplevel)
{
    struct app *app = data;
    (void)toplevel;
    app->running = 0;
}

static void toplevel_configure_bounds(void *data, struct xdg_toplevel *toplevel,
                                      int32_t width, int32_t height)
{
    (void)data;
    (void)toplevel;
    (void)width;
    (void)height;
}

static void toplevel_wm_capabilities(void *data, struct xdg_toplevel *toplevel,
                                     struct wl_array *capabilities)
{
    (void)data;
    (void)toplevel;
    (void)capabilities;
}

static const struct xdg_toplevel_listener toplevel_listener = {
    .configure = toplevel_configure,
    .close = toplevel_close,
    .configure_bounds = toplevel_configure_bounds,
    .wm_capabilities = toplevel_wm_capabilities,
};

/* Compositor is ready for the next frame: clear the pending flag and, if a repaint
 * is still wanted, issue it now.  This is the whole frame-pacing loop -- one paint
 * per compositor frame, no busier (INST-03). */
static void frame_done(void *data, struct wl_callback *callback, uint32_t time)
{
    struct app *app = data;
    (void)time;
    if (callback)
        wl_callback_destroy(callback);
    if (app->frame_cb == callback)
        app->frame_cb = NULL;
    app->frame_pending = 0;
    if (app->dirty)
        render_frame(app);
}

static const struct wl_callback_listener frame_listener = {
    .done = frame_done,
};

/* Rebuild BOTH shm buffers at a new size.  create_buffers_once() allocates ONE
 * memfd for the process life -- a fresh memfd per FRAME exhausted the kernel's
 * small memfd pool and froze the desktop.  A resize is not per-frame though; it
 * happens when the layout changes, so tearing down the mapping + both buffers and
 * recreating them ONCE here is bounded and safe. */
static int resize_buffer(struct app *app, int width, int height)
{
    if (width <= 0 || height <= 0) return 0;
    if (app->fb[0].buffer && width == app->width && height == app->height) return 0;
    for (int i = 0; i < 2; i++) {
        if (app->fb[i].buffer) { wl_buffer_destroy(app->fb[i].buffer); app->fb[i].buffer = NULL; }
        app->fb[i].pixels = NULL;
        app->fb[i].busy = 0;
    }
    if (app->map_base && app->map_base != MAP_FAILED) munmap(app->map_base, app->pool_size);
    app->map_base = NULL;
    app->pixels = NULL;
    return create_shm_buffer(app, width, height);
}

static void xdg_surface_configure(void *data, struct xdg_surface *surface,
                                  uint32_t serial)
{
    struct app *app = data;
    xdg_surface_ack_configure(surface, serial);

    /* Take the compositor's size WHENEVER it gives one.  This used to be a shrink-only
     * clamp -- `width = DEFAULT_WIDTH; if (pending < width) width = pending;` -- so the
     * window could never grow beyond its compiled default no matter what Hyprland asked
     * for.  A tile of 1268x788 produced exactly the same commit as a configure of 0x0,
     * which is why every window rendered at its default inside a much larger tile and got
     * scaled. */
    int want_w = app->pending_width  > 0 ? app->pending_width  : DEFAULT_WIDTH;
    int want_h = app->pending_height > 0 ? app->pending_height : DEFAULT_HEIGHT;

    /* Post-map configures used to be acked and DISCARDED (`if (app->committed) return;`).
     * The first, pre-map configure is legitimately 0x0 -- the compositor asking the client
     * to pick a size -- and the real tile geometry only arrives AFTER the window maps.
     * Dropping it meant the tile was acked and then ignored, so Hyprland recorded the
     * acked size while the buffer stayed small. */
    if (app->committed) {
        if (want_w == app->width && want_h == app->height) return;
        if (resize_buffer(app, want_w, want_h) < 0) { log_line("INSTALLER: resize failed"); return; }
        redraw_now(app);               /* paint the new size immediately (forced flush) */
        if (app->debug)
            ilog("INSTALLER: resized wl_shm window %dx%d", app->width, app->height);
        return;
    }

    if (create_shm_buffer(app, want_w, want_h) < 0) {
        app->running = 0;
        return;
    }

    app->committed = 1;
    app->sync_after_commit = 1;
    redraw_now(app);                   /* first map: paint + arm frame pacing */
    if (app->debug)
        ilog("INSTALLER: committed wl_shm window %dx%d", app->width, app->height);
}

static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = xdg_surface_configure,
};

static const char keymap_plain[59] = {
    0,0,'1','2','3','4','5','6','7','8','9','0','-','=',0,0,
    'q','w','e','r','t','y','u','i','o','p','[',']',0,0,'a','s',
    'd','f','g','h','j','k','l',';','\'','`',0,'\\','z','x','c','v',
    'b','n','m',',','.','/',0,0,0,' '
};

static const char keymap_shift[59] = {
    0,0,'!','@','#','$','%','^','&','*','(',')','_','+',0,0,
    'Q','W','E','R','T','Y','U','I','O','P','{','}',0,0,'A','S',
    'D','F','G','H','J','K','L',':','"','~',0,'|','Z','X','C','V',
    'B','N','M','<','>','?',0,0,0,' '
};

/* Keep row `sel` of a list inside the viewport. */
static void list_reveal(struct app *app, int sel)
{
    int vis = list_visible_rows(app);
    if (sel < app->list_scroll) app->list_scroll = sel;
    if (sel >= app->list_scroll + vis) app->list_scroll = sel - vis + 1;
}

/* Move the selection of a single-choice list (skipping disabled options), the
 * disk selection (skipping disks that are too small), or the cursor of a toggle
 * list. */
static void list_move(struct app *app, int delta)
{
    int sel;
    if (app->screen == SCREEN_DISK) {
        int count = disk_row_count(app);
        int v = app->target_sel;
        for (int step = 0; step < count; step++) {
            v += delta;
            if (v < 0 || v >= count) { v = app->target_sel; break; }
            if (!disk_row_disabled(app, v)) break;
        }
        app->target_sel = v;
        sel = v;
    } else if (screen_is_list(app->screen)) {
        int count = 0;
        const struct opt *o = screen_opts(app->screen, &count);
        int *selp = screen_sel_ptr(app, app->screen);
        if (!o || !selp)
            return;
        int v = *selp;
        for (int step = 0; step < count; step++) {
            v += delta;
            if (v < 0 || v >= count) { v = *selp; break; }
            if (!opt_is_disabled(app, app->screen, v)) break;
        }
        *selp = v;
        sel = v;
    } else if (app->screen == SCREEN_IDENTITIES || app->screen == SCREEN_DRIVERS) {
        int count = app->screen == SCREEN_IDENTITIES ? ARRAY_LEN(IDENTITIES) : ARRAY_LEN(DRIVERS);
        app->list_cursor += delta;
        if (app->list_cursor < 0) app->list_cursor = 0;
        if (app->list_cursor >= count) app->list_cursor = count - 1;
        sel = app->list_cursor;
    } else {
        return;
    }
    list_reveal(app, sel);
    request_redraw(app, "list move");
}

/* Space on a toggle list ticks the cursor row. */
static void toggle_cursor_row(struct app *app)
{
    if (app->screen == SCREEN_IDENTITIES) {
        if (app->list_cursor >= 0 && app->list_cursor < ARRAY_LEN(IDENTITIES))
            app->identity_on[app->list_cursor] = !app->identity_on[app->list_cursor];
    } else if (app->screen == SCREEN_DRIVERS) {
        if (app->list_cursor >= 0 && app->list_cursor < ARRAY_LEN(DRIVERS))
            app->drivers_on[app->list_cursor] = !app->drivers_on[app->list_cursor];
    }
    request_redraw(app, "toggle");
}

/* Pick an encryption mode: the field set changes with it, so refocus and rescroll. */
static void enc_set_mode(struct app *app, int mode)
{
    if (mode < ENC_NONE || mode > ENC_HIDDEN || mode == app->encryption_mode)
        return;
    app->encryption_mode = mode;
    app->content_scroll = 0;
    focus_first_field(app);
    request_redraw(app, "encryption mode");
}

/* The primary button on the progress page: Close after a failure (or a denied
 * restart), otherwise Restart now.  reboot() is cap-gated (CAP_RIGHT_ADMIN_REBOOT
 * is PID1-only), so returning from it is the expected case: the card then tells
 * the user to hold the power button and the button becomes Close. */
static void progress_primary(struct app *app)
{
    if (app->installing)
        return;
    if (app->install_failed || app->reboot_denied) {
        app->running = 0;
        return;
    }
    if (app->install_done) {
        ilog("INSTALLER: 'Restart now' -- reboot(RB_AUTOBOOT)");
        reboot(RB_AUTOBOOT);
        app->reboot_denied = 1;
        ilog("INSTALLER: reboot(RB_AUTOBOOT) denied errno=%d", errno);
        request_redraw(app, "reboot denied");
    }
}

static void entry_append_key(struct app *app, uint32_t code)
{
    /* Esc goes back a page, the keyboard counterpart of the Back button.  Without it the wizard
     * was only forward-navigable from the keyboard -- Back existed solely as a pointer hit-test --
     * so anyone without a working mouse could walk into a page and not walk out.
     *
     * It applies even while a text field has the caret.  Guarding it on "no field focused" (the
     * first attempt) disabled it on precisely the pages that HAVE fields, which are the ones worth
     * backing out of, while the footer went on advertising "Esc: back".  Unlike Space, Esc is not
     * a character anyone can be trying to type, so there is nothing to collide with.  The one
     * exception is the progress page: an install is running and there is no page to go back to. */
    if (code == 1 && app->screen != SCREEN_PROGRESS) {
        go_back(app);
        return;
    }

    /* List/disk/toggle screens: arrow keys move, Space ticks, Enter advances.  The
     * Keyboard page is a list too, but its keys also go to the test box, so it
     * handles Up/Down/Enter here and then falls through to the text path. */
    if (screen_is_list(app->screen) || app->screen == SCREEN_DISK ||
        app->screen == SCREEN_IDENTITIES || app->screen == SCREEN_DRIVERS) {
        if (code == 103) { list_move(app, -1); return; }   /* Up */
        if (code == 108) { list_move(app, +1); return; }   /* Down */
        if (code == 28) { if (screen_can_advance(app)) go_next(app); return; } /* Enter */
        if (code == 57 && (app->screen == SCREEN_IDENTITIES || app->screen == SCREEN_DRIVERS)) {
            toggle_cursor_row(app);
            return;
        }
        if (app->screen != SCREEN_KEYBOARD)
            return;
        if (code == 15)                                     /* Tab: nothing to move to */
            return;
    }

    if (app->screen == SCREEN_PROGRESS) {
        if (code == 28)
            progress_primary(app);
        return;
    }

    /* Keyboard accessibility for the segmented control: Left/Right (and Up/Down)
     * pick the encryption mode, so the whole wizard is usable without a pointer. */
    if (app->screen == SCREEN_ENCRYPTION) {
        if (code == 105 || code == 103) {   /* Left / Up */
            enc_set_mode(app, app->encryption_mode - 1);
            return;
        }
        if (code == 106 || code == 108) {   /* Right / Down */
            enc_set_mode(app, app->encryption_mode + 1);
            return;
        }
        /* Space flips the erase mode on Full disk.  Not offered for Hidden OS: there the whole-disk
         * random pass is the mechanism that conceals the hidden volume, not a choice.
         *
         * Only when no text field has focus.  Space is a legal password character -- and the
         * passphrase this page asks for is exactly where someone would use one -- so this must not
         * swallow it while the caret is in a field.  (It also must not be a letter key for the same
         * reason; an earlier version bound 'D' and ate it out of the password.) */
        if (code == 57 && app->encryption_mode == ENC_FULL && app->focused_field < 0) {
            app->fill_whole_disk = !app->fill_whole_disk;
            request_redraw(app, "erase mode");
            return;
        }
    }

    if (!app->entry_focused)
        return;
    if (code == 15) {
        cycle_focus(app);
        request_redraw(app, "field focus");
        return;
    }
    if (code == 14) {
        int f = app->focused_field;
        if (f >= 0 && f < FIELD_COUNT && app->field_len[f] > 0)
            app->field_text[f][--app->field_len[f]] = 0;
        request_redraw(app, "entry edit");
        return;
    }
    if (code == 28) {
        if (screen_can_advance(app))
            go_next(app);
        return;
    }
    int f = app->focused_field;
    if (f < 0 || f >= FIELD_COUNT)
        return;
    if (code >= sizeof(keymap_plain))
        return;
    char ch = app->shift ? keymap_shift[code] : keymap_plain[code];
    if (!ch || app->field_len[f] >= (int)sizeof(app->field_text[f]) - 1)
        return;
    app->field_text[f][app->field_len[f]++] = ch;
    app->field_text[f][app->field_len[f]] = 0;
    request_redraw(app, "entry edit");
}

static void keyboard_keymap(void *data, struct wl_keyboard *keyboard,
                            uint32_t format, int32_t fd, uint32_t size)
{
    (void)data;
    (void)keyboard;
    (void)format;
    (void)size;
    if (fd >= 0)
        close(fd);
}

static void keyboard_enter(void *data, struct wl_keyboard *keyboard,
                           uint32_t serial, struct wl_surface *surface,
                           struct wl_array *keys)
{
    struct app *app = data;
    (void)keyboard;
    (void)serial;
    (void)surface;
    (void)keys;
    /* Focus enter/leave change nothing visible (no focus ring is drawn), so they
     * must NOT trigger a repaint (INST-04). */
    app->entry_focused = 1;
}

static void keyboard_leave(void *data, struct wl_keyboard *keyboard,
                           uint32_t serial, struct wl_surface *surface)
{
    struct app *app = data;
    (void)keyboard;
    (void)serial;
    (void)surface;
    app->entry_focused = 0;   /* no repaint: nothing focus-dependent is drawn */
}

static void keyboard_key(void *data, struct wl_keyboard *keyboard,
                         uint32_t serial, uint32_t time,
                         uint32_t code, uint32_t state)
{
    struct app *app = data;
    (void)keyboard;
    (void)serial;
    (void)time;
    int down = state == WL_KEYBOARD_KEY_STATE_PRESSED;
    if (code == 42 || code == 54) {
        app->shift = down;
        return;
    }
    if (down)
        entry_append_key(app, code);
}

static void keyboard_modifiers(void *data, struct wl_keyboard *keyboard,
                               uint32_t serial, uint32_t depressed,
                               uint32_t latched, uint32_t locked,
                               uint32_t group)
{
    (void)data;
    (void)keyboard;
    (void)serial;
    (void)depressed;
    (void)latched;
    (void)locked;
    (void)group;
}

static void keyboard_repeat_info(void *data, struct wl_keyboard *keyboard,
                                 int32_t rate, int32_t delay)
{
    (void)data;
    (void)keyboard;
    (void)rate;
    (void)delay;
}

static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = keyboard_keymap,
    .enter = keyboard_enter,
    .leave = keyboard_leave,
    .key = keyboard_key,
    .modifiers = keyboard_modifiers,
    .repeat_info = keyboard_repeat_info,
};

static void pointer_enter(void *data, struct wl_pointer *pointer,
                          uint32_t serial, struct wl_surface *surface,
                          wl_fixed_t sx, wl_fixed_t sy)
{
    struct app *app = data;
    (void)pointer;
    (void)serial;
    (void)surface;
    app->pointer_x = wl_fixed_to_double(sx);
    app->pointer_y = wl_fixed_to_double(sy);
}

static void pointer_leave(void *data, struct wl_pointer *pointer,
                          uint32_t serial, struct wl_surface *surface)
{
    (void)data;
    (void)pointer;
    (void)serial;
    (void)surface;
}

static void pointer_motion(void *data, struct wl_pointer *pointer,
                           uint32_t time, wl_fixed_t sx, wl_fixed_t sy)
{
    struct app *app = data;
    (void)pointer;
    (void)time;
    /* Nothing hover-dependent is drawn, so motion never marks the frame dirty. */
    app->pointer_x = wl_fixed_to_double(sx);
    app->pointer_y = wl_fixed_to_double(sy);
}

static int in_rect(struct app *app, double x, double y, double w, double h)
{
    return app->pointer_x >= x && app->pointer_x < x + w &&
           app->pointer_y >= y && app->pointer_y < y + h;
}

/* Which visible list row (if any) is under the pointer; -1 if none. */
static int list_row_under_pointer(struct app *app, int count)
{
    int vis = list_visible_rows(app);
    for (int i = 0; i < vis; i++) {
        int idx = app->list_scroll + i;
        if (idx >= count)
            break;
        double x, y, w, h;
        list_row_rect(app, i, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h))
            return idx;
    }
    return -1;
}

static void pointer_button(void *data, struct wl_pointer *pointer,
                           uint32_t serial, uint32_t time,
                           uint32_t button, uint32_t state)
{
    struct app *app = data;
    (void)pointer;
    (void)serial;
    (void)time;
    if (button != 0x110)
        return;
    if (state != WL_POINTER_BUTTON_STATE_PRESSED)
        return;

    double x, y, w, h;

    if (app->screen == SCREEN_WELCOME) {
        btn_rect(app, BTN_SECONDARY, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h)) {
            printf("INSTALLER: 'Try Live' -- closing to the live desktop\n");
            app->running = 0;
            return;
        }
        btn_rect(app, BTN_PRIMARY, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h)) {
            go_next(app);
            return;
        }
        return;
    }

    if (app->screen == SCREEN_PROGRESS) {
        btn_rect(app, BTN_PRIMARY, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h))
            progress_primary(app);
        return;
    }

    /* Encryption segmented control. */
    if (app->screen == SCREEN_ENCRYPTION) {
        for (int i = 0; i < 3; i++) {
            segment_rect(app, i, &x, &y, &w, &h);
            if (in_rect(app, x, y, w, h)) {
                enc_set_mode(app, i);
                return;
            }
        }
    }

    /* Single-choice option lists; disabled rows ignore the click. */
    if (screen_is_list(app->screen)) {
        int count = 0;
        const struct opt *o = screen_opts(app->screen, &count);
        int *sel = screen_sel_ptr(app, app->screen);
        int row = list_row_under_pointer(app, count);
        if (o && sel && row >= 0) {
            if (!opt_is_disabled(app, app->screen, row)) {
                *sel = row;
                request_redraw(app, "list select");
            }
            return;
        }
    } else if (app->screen == SCREEN_DISK) {
        int row = list_row_under_pointer(app, disk_row_count(app));
        if (row >= 0) {
            if (!disk_row_disabled(app, row)) {
                app->target_sel = row;
                request_redraw(app, "disk select");
            }
            return;
        }
    } else if (app->screen == SCREEN_IDENTITIES || app->screen == SCREEN_DRIVERS) {
        int count = app->screen == SCREEN_IDENTITIES ? ARRAY_LEN(IDENTITIES) : ARRAY_LEN(DRIVERS);
        int row = list_row_under_pointer(app, count);
        if (row >= 0) {
            app->list_cursor = row;      /* the card follows the clicked row */
            toggle_cursor_row(app);
            return;
        }
    }

    /* The erase-mode row, before the text fields: it lives in the same pane and must be clickable. */
    if (erase_row_visible(app)) {
        double x, y, w, h;
        erase_row_rect(app, &x, &y, &w, &h);
        if (y + h >= content_view_top(app) && y <= content_view_bottom(app) &&
            in_rect(app, x, y, w, h)) {
            app->fill_whole_disk = !app->fill_whole_disk;
            request_redraw(app, "erase mode");
            return;
        }
    }

    /* Text fields (the Keyboard test box is always focused; it has no hit-test). */
    if (screen_is_form(app->screen)) {
        int fields[8];
        int n = fields_for_screen(app, fields, 8);
        for (int i = 0; i < n; i++) {
            field_rect(app, fields[i], &x, &y, &w, &h);
            if (y + h < content_view_top(app) || y > content_view_bottom(app))
                continue;            /* scrolled out of the pane: not clickable */
            if (in_rect(app, x, y, w, h)) {
                app->focused_field = fields[i];
                app->entry_focused = 1;
                request_redraw(app, "field focus");
                return;
            }
        }
    }

    btn_rect(app, BTN_BACK, &x, &y, &w, &h);
    if (in_rect(app, x, y, w, h)) {
        go_back(app);
        return;
    }
    btn_rect(app, BTN_PRIMARY, &x, &y, &w, &h);
    if (in_rect(app, x, y, w, h)) {
        if (screen_can_advance(app))
            go_next(app);
        return;
    }
}

/* Scroll wheel / touchpad pans the active list.  The old code stepped (and forced a
 * full repaint) on EVERY axis event, so a fine-grained touchpad produced a storm of
 * full-surface repaints for motion that had not yet crossed a row (INST-06).  The
 * wl_fixed delta is accumulated and a step is taken only when it crosses one notch;
 * sub-notch motion accumulates silently and nothing is marked dirty. */
/* libinput (and so wlroots/Hyprland) report one wheel click as an axis value of
 * 15.0 -- the 15-degree notch angle at scroll_factor 1.0 -- so the step is 15 to
 * keep one row per notch; a 10-unit step made notches alternate 1,2,1,2 rows. */
enum { AXIS_STEP_FIXED = 15 };   /* one wheel notch of accumulated axis value */

static void pointer_axis(void *data, struct wl_pointer *pointer,
                         uint32_t time, uint32_t axis, wl_fixed_t value)
{
    struct app *app = data;
    (void)pointer;
    (void)time;
    if (axis != 0)  /* vertical only */
        return;

    app->axis_accum += wl_fixed_to_double(value);
    int steps = 0;                       /* +ve == scroll down, -ve == scroll up */
    while (app->axis_accum >= AXIS_STEP_FIXED) { app->axis_accum -= AXIS_STEP_FIXED; steps++; }
    while (app->axis_accum <= -AXIS_STEP_FIXED) { app->axis_accum += AXIS_STEP_FIXED; steps--; }
    if (steps == 0)                      /* nothing crossed a step: ignore */
        return;

    /* Form pages scroll their field pane by pixels. */
    if (screen_is_form(app->screen)) {
        if (content_max_scroll(app) <= 0)
            return;
        int before = app->content_scroll;
        app->content_scroll += steps * 28;
        clamp_content_scroll(app);
        if (app->content_scroll != before)
            request_redraw(app, "content scroll");
        return;
    }

    int count = 0;
    if (screen_is_list(app->screen)) {
        screen_opts(app->screen, &count);
    } else if (app->screen == SCREEN_DISK) {
        count = disk_row_count(app);
    } else if (app->screen == SCREEN_IDENTITIES) {
        count = ARRAY_LEN(IDENTITIES);
    } else if (app->screen == SCREEN_DRIVERS) {
        count = ARRAY_LEN(DRIVERS);
    } else {
        return;
    }
    int before = app->list_scroll;
    app->list_scroll += steps;
    clamp_scroll(app, count);
    if (app->list_scroll != before)     /* only repaint if the view actually moved */
        request_redraw(app, "scroll");
}

static void pointer_frame(void *data, struct wl_pointer *p) { (void)data; (void)p; }
static void pointer_axis_source(void *data, struct wl_pointer *p, uint32_t s) { (void)data; (void)p; (void)s; }
static void pointer_axis_stop(void *data, struct wl_pointer *p, uint32_t t, uint32_t a) { (void)data; (void)p; (void)t; (void)a; }
static void pointer_axis_discrete(void *data, struct wl_pointer *p, uint32_t a, int32_t d) { (void)data; (void)p; (void)a; (void)d; }

static const struct wl_pointer_listener pointer_listener = {
    .enter = pointer_enter,
    .leave = pointer_leave,
    .motion = pointer_motion,
    .button = pointer_button,
    .axis = pointer_axis,
    .frame = pointer_frame,
    .axis_source = pointer_axis_source,
    .axis_stop = pointer_axis_stop,
    .axis_discrete = pointer_axis_discrete,
};

static void seat_capabilities(void *data, struct wl_seat *seat, uint32_t caps)
{
    struct app *app = data;
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !app->keyboard) {
        app->keyboard = wl_seat_get_keyboard(seat);
        wl_keyboard_add_listener(app->keyboard, &keyboard_listener, app);
        log_line("G11INPUT: keyboard subscribed");
    }
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !app->pointer) {
        app->pointer = wl_seat_get_pointer(seat);
        wl_pointer_add_listener(app->pointer, &pointer_listener, app);
        log_line("G11INPUT: pointer subscribed");
    }
}

static void seat_name(void *data, struct wl_seat *seat, const char *name)
{
    (void)data;
    (void)seat;
    (void)name;
}

static const struct wl_seat_listener seat_listener = {
    .capabilities = seat_capabilities,
    .name = seat_name,
};

static void output_geometry(void *data, struct wl_output *output,
                            int32_t x, int32_t y,
                            int32_t physical_width, int32_t physical_height,
                            int32_t subpixel,
                            const char *make, const char *model,
                            int32_t transform)
{
    (void)data; (void)output; (void)x; (void)y;
    (void)physical_width; (void)physical_height; (void)subpixel;
    (void)make; (void)model; (void)transform;
}

static void output_mode(void *data, struct wl_output *output,
                        uint32_t flags, int32_t width,
                        int32_t height, int32_t refresh)
{
    (void)data; (void)output; (void)flags;
    (void)width; (void)height; (void)refresh;
}

static void output_done(void *data, struct wl_output *output)
{
    (void)data;
    (void)output;
}

static void output_scale(void *data, struct wl_output *output, int32_t factor)
{
    (void)data;
    (void)output;
    (void)factor;
}

static void output_name(void *data, struct wl_output *output, const char *name)
{
    (void)data;
    (void)output;
    (void)name;
}

static void output_description(void *data, struct wl_output *output,
                               const char *description)
{
    (void)data;
    (void)output;
    (void)description;
}

static const struct wl_output_listener output_listener = {
    .geometry = output_geometry,
    .mode = output_mode,
    .done = output_done,
    .scale = output_scale,
    .name = output_name,
    .description = output_description,
};

static void registry_global(void *data, struct wl_registry *registry, uint32_t name,
                            const char *interface, uint32_t version)
{
    struct app *app = data;
    if (strcmp(interface, wl_compositor_interface.name) == 0) {
        app->compositor = wl_registry_bind(registry, name, &wl_compositor_interface,
                                           version < 4 ? version : 4);
    } else if (strcmp(interface, wl_output_interface.name) == 0 && !app->output) {
        uint32_t bind_version = version < 4 ? version : 4;
        app->output = wl_registry_bind(registry, name, &wl_output_interface,
                                       bind_version);
        wl_output_add_listener(app->output, &output_listener, app);
    } else if (strcmp(interface, wl_shm_interface.name) == 0) {
        app->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
    } else if (strcmp(interface, xdg_wm_base_interface.name) == 0) {
        app->wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface,
                                        version < 6 ? version : 6);
        xdg_wm_base_add_listener(app->wm_base, &wm_base_listener, app);
    } else if (strcmp(interface, wl_seat_interface.name) == 0) {
        app->seat = wl_registry_bind(registry, name, &wl_seat_interface,
                                     version < 5 ? version : 5);
        wl_seat_add_listener(app->seat, &seat_listener, app);
    }
}

static void registry_global_remove(void *data, struct wl_registry *registry,
                                   uint32_t name)
{
    (void)data;
    (void)registry;
    (void)name;
}

/* DRIVERS auto-detect: read the kernel's synthetic /config/hardware.detect (a comma-separated list of
 * the Linux driver codes for the PCI devices actually present, e.g. "iwlwifi,e1000e,snd_hda_intel") and
 * pre-check the matching Drivers rows, so the page opens showing what THIS machine needs.  Absent file
 * (e.g. running outside the installer) just leaves everything unchecked. */
static int code_in_list(const char *code, const char *list)
{
    size_t clen = strlen(code);
    const char *p = list;
    while ((p = strstr(p, code)) != NULL) {
        char before = (p == list) ? ',' : p[-1];
        char after = p[clen];
        if ((before == ',' || before == '\n' || before == '\0') &&
            (after == ',' || after == '\n' || after == '\0'))
            return 1;
        p += clen;
    }
    return 0;
}

static void detect_drivers(struct app *app)
{
    int fd = open("/config/hardware.detect", O_RDONLY);
    if (fd < 0)
        return;
    char buf[512];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return;
    buf[n] = 0;
    app->hw_detect_present = 1;    /* a scan happened: rows can say "not detected" */
    for (int i = 0; i < ARRAY_LEN(DRIVERS); i++) {
        if (code_in_list(DRIVERS[i].code, buf)) {
            app->drivers_on[i] = 1;
            app->detected_mask |= 1u << i;
        }
    }
    log_line("INSTALLER: hardware.detect -> pre-checked present drivers");
}

static const struct wl_registry_listener registry_listener = {
    .global = registry_global,
    .global_remove = registry_global_remove,
};

int main(void)
{
    struct app app;
    memset(&app, 0, sizeof(app));
    app.running = 1;
    app.screen = SCREEN_WELCOME;
    app.focused_field = -1;
    app.encryption_mode = ENC_NONE;
    app.target_sel = 0;
    app.progress_fd = -1;
    app.debug = getenv("EPIN_INSTALLER_DEBUG") != NULL;   /* evaluated once at startup */
    snprintf(app.install_cmd, sizeof app.install_cmd, "install");
    set_field(&app, FIELD_HOSTNAME, "epin");
    set_field(&app, FIELD_REAL_USER, "user");
    set_field(&app, FIELD_DECOY_USER, "decoy");
    set_field(&app, FIELD_DECOY_FULLNAME, "Decoy User");
    set_field(&app, FIELD_DECOY_HOSTNAME, "decoy-pc");
    app.identity_on[0] = 1;   /* Personal enabled by default */
    detect_drivers(&app);     /* pre-check drivers for the PCI hardware actually present */

    log_line("INSTALLER: starting EpinAnonymOS install entry -- D4.1 START");
    load_disks(&app);

    app.display = wl_display_connect(NULL);
    if (!app.display) {
        perror("G11CAIRO: wl_display_connect");
        return 1;
    }

    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);

    if (!app.compositor || !app.shm || !app.wm_base) {
        log_line("G11CAIRO: missing required Wayland globals");
        return 1;
    }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Install EpinAnonymOS to Disk");
    xdg_toplevel_set_app_id(app.toplevel, "epinanonymos-installer");
    xdg_toplevel_set_min_size(app.toplevel, DEFAULT_WIDTH, DEFAULT_HEIGHT);

    wl_surface_commit(app.surface);
    wl_display_flush(app.display);
    log_line("G11CAIRO: requested xdg_toplevel configure");

    /* Event-driven main loop.  It blocks in poll() on the Wayland fd instead of
     * spinning (INST-09): the timeout is only finite when there is periodic work to
     * do -- 250 ms while installing (to re-read install.progress) and 1 s on the
     * Network page (to refresh the Wi-Fi status) -- and is infinite otherwise, so an
     * idle installer costs nothing.  Redraws are coalesced: at most one paint per
     * compositor frame is issued here, driven by app.dirty and app.frame_pending. */
    int wl_fd = wl_display_get_fd(app.display);
    while (app.running) {
        /* Drain any events already queued before deciding to sleep. */
        if (wl_display_dispatch_pending(app.display) < 0) {
            perror("G11CAIRO: wl_display_dispatch_pending");
            break;
        }
        if (!app.running)
            break;

        if (app.sync_after_commit) {
            app.sync_after_commit = 0;
            if (wl_display_roundtrip(app.display) < 0)
                perror("G11CAIRO: post-commit roundtrip");
            else if (app.debug)
                log_line("G11CAIRO: post-commit roundtrip complete -- G11 SYNC");
        }

        int on_network = (app.screen == SCREEN_NETWORK);
        int timeout = on_network ? 1000 : -1;
        long since_poll = -1;
        if (app.installing) {
            /* Sleep only until the next progress poll is due, not a fixed 250 ms
             * from now: with pointer events waking the loop early that would have
             * pushed the poll back indefinitely, and polling on every wakeup instead
             * read the kernel counter (and repainted) per pointer-motion event.
             * Without a usable clock (since_poll < 0) keep the old fixed timeout. */
            since_poll = ms_since(&app.last_poll);
            long remain = since_poll < 0 ? PROGRESS_POLL_MS : PROGRESS_POLL_MS - since_poll;
            if (remain < 0) remain = 0;
            timeout = (int)remain;
        }

        wl_display_flush(app.display);
        struct pollfd pfd = { .fd = wl_fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, timeout);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            perror("G11CAIRO: poll");
            break;
        }
        if (pr > 0 && (pfd.revents & POLLIN)) {
            if (wl_display_dispatch(app.display) < 0) {
                perror("G11CAIRO: wl_display_dispatch");
                break;
            }
        }

        /* Periodic work, on its own cadence regardless of how often Wayland
         * traffic wakes the loop. */
        if (app.installing) {
            since_poll = ms_since(&app.last_poll);
            /* A wakeup from Wayland traffic before the poll is due does nothing. */
            int due = since_poll < 0 || since_poll >= PROGRESS_POLL_MS;
            if (due && since_poll >= 0)
                clock_gettime(CLOCK_MONOTONIC, &app.last_poll);
            if (due)
                poll_install_progress(&app);
            if (due && app.progress >= 1000) {
                app.installing = 0;
                app.install_done = 1;
                stamp_install_end(&app);       /* freezes "took m:ss" */
                request_redraw(&app, "install-done");
                ilog("INSTALLER: install complete (100%%)");
            }
        } else if (on_network) {
            /* Refresh the cached Wi-Fi status at most once per second. */
            if (time(NULL) != app.wifi_checked && refresh_wifi_status(&app))
                request_redraw(&app, "wifi status");
        }

        /* Coalesced repaint: one frame per compositor callback. */
        if (app.dirty && !app.frame_pending)
            render_frame(&app);
    }

    if (app.progress_fd >= 0)
        close(app.progress_fd);
    return app.committed ? 0 : 1;
}
