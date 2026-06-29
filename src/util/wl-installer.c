#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pango/pangocairo.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
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
    SCREEN_NETWORK, SCREEN_DISK, SCREEN_FILESYSTEM, SCREEN_ENCRYPTION,
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
    FIELD_OUTER_PASSWORD,
    FIELD_DECOY_BOOT_PASSWORD,
    FIELD_DECOY_USER,
    FIELD_DECOY_FULLNAME,
    FIELD_DECOY_PASSWORD,
    FIELD_DECOY_HOSTNAME,
    FIELD_COUNT,
};

enum {
    ENC_NONE = 0,
    ENC_FULL,
    ENC_HIDDEN,
};

/* Single-choice option lists (Language/Keyboard/Timezone/Network/Filesystem/Boot integrity).
 * `code` is what lands in install.json; `disabled` greys the row out (unselectable). */
struct opt {
    const char *label;
    const char *sub;
    const char *code;
    int disabled;
};

static const struct opt LOCALES[] = {
    { "English (US)",          "en_US.UTF-8", "en_US", 0 },
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
    { "English (US)",        "QWERTY",  "us",      0 },
    { "English (UK)",        "QWERTY",  "gb",      0 },
    { "German",              "QWERTZ",  "de",      0 },
    { "French",              "AZERTY",  "fr",      0 },
    { "Spanish",             "QWERTY",  "es",      0 },
    { "Italian",             "QWERTY",  "it",      0 },
    { "Portuguese (Brazil)", "QWERTY",  "br",      0 },
    { "Russian",             "JCUKEN",  "ru",      0 },
    { "Turkish",             "QWERTY",  "tr",      0 },
    { "Dvorak",              "Simplified", "dvorak", 0 },
    { "Colemak",             "Ergonomic",  "colemak", 0 },
    { "Japanese",            "JIS",     "jp",      0 },
};

static const struct opt TIMEZONES[] = {
    { "UTC",                 "Coordinated Universal Time", "UTC",                 0 },
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

static const struct opt NETWORKS[] = {
    { "Offline install",        "Configure networking after first boot (default)", "offline", 0 },
    { "Wired connection (DHCP)", "Use the wired Ethernet adapter",                 "wired",   0 },
    { "Wi-Fi",                  "No Wi-Fi driver on this hardware yet",            "wifi",    1 },
};

static const struct opt FILESYSTEMS[] = {
    { "ext4",  "Default, well-tested journaling filesystem",      "ext4",  0 },
    { "Btrfs", "Copy-on-write with snapshots and compression",    "btrfs", 0 },
    { "XFS",   "High-performance journaling filesystem",          "xfs",   0 },
};

static const struct opt BOOTINTEGRITY[] = {
    { "Off",              "No external boot attestation (default)",            "off",    0 },
    { "zkSync attestation", "Anchor /system hashes on-chain (requires network)", "zksync", 0 },
};

/* Toggleable identity profiles (roadmap §Phase 6). The Administrator account on the
 * Account page is always created; these become declarative identity objects at first boot. */
static const struct opt IDENTITIES[] = {
    { "Personal",   "Everyday browsing and personal files",      "personal",   0 },
    { "Work",       "Work email, documents, and tools",          "work",       0 },
    { "Banking",    "Hardened identity for financial sites",      "banking",    0 },
    { "Research",   "Isolated identity for investigations",       "research",   0 },
    { "Disposable", "One-shot identity, wiped on logout",         "disposable", 0 },
    { "Anonymous",  "Routed for maximum anonymity",               "anonymous",  0 },
};

#define ARRAY_LEN(a) ((int)(sizeof(a) / sizeof((a)[0])))

struct disk_entry {
    int index;
    long size_mib;
    char role[16];
};

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
    struct wl_buffer *buffer;          /* ONE persistent shm buffer, re-attached each frame */
    struct wl_callback *frame_cb;
    uint32_t *pixels;                  /* == the buffer's shared memory; drawn into in place */
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size;
    size_t buffer_size;
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
    int post_map_frame_armed;
    int post_map_frame_done;
    int running;
    int screen;
    int installing;
    int install_done;
    int install_failed;
    int progress;
    int focused_field;
    int encryption_mode;
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

    /* disk enumeration from /config/disks.json; target_sel 0 = automatic */
    struct disk_entry disks[8];
    int disk_count;
    int target_sel;
    int target_index;       /* AHCI index to install to, or -1 for automatic */

    int list_scroll;        /* row offset for the current scrollable list */
    char install_cmd[32];   /* "install" or "install <idx>" */
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

/* List viewport: rows of fixed height between the subtitle and the button bar. */
enum { LIST_TOP = 138, LIST_ROW_H = 50 };
static int list_view_h(struct app *app) { return (app->height - 96) - LIST_TOP; }
static int list_visible_rows(struct app *app)
{
    int r = list_view_h(app) / LIST_ROW_H;
    return r < 1 ? 1 : r;
}
static void list_row_rect(struct app *app, int visible_pos,
                          double *x, double *y, double *w, double *h)
{
    *x = CONTENT_X;
    *y = LIST_TOP + visible_pos * LIST_ROW_H;
    *w = content_w(app);
    *h = LIST_ROW_H - 8;
}

/* ── helpers ───────────────────────────────────────────────────────────────── */

static void log_line(const char *s)
{
    fputs(s, stdout);
    fputc('\n', stdout);
    fflush(stdout);
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
    case FIELD_HIDDEN_PASSWORD:
        return app->encryption_mode == ENC_FULL ? "Disk unlock password"
                                                : "Hidden OS boot password";
    case FIELD_OUTER_PASSWORD: return "Outer volume password";
    case FIELD_DECOY_BOOT_PASSWORD: return "Decoy OS boot password";
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
           field == FIELD_OUTER_PASSWORD ||
           field == FIELD_DECOY_BOOT_PASSWORD ||
           field == FIELD_DECOY_PASSWORD;
}

static int field_optional(int field)
{
    return field == FIELD_REAL_FULLNAME || field == FIELD_DECOY_FULLNAME;
}

static const char *screen_title(struct app *app)
{
    switch (app->screen) {
    case SCREEN_WELCOME: return "Install EpinAnonymOS";
    case SCREEN_LANGUAGE: return "Language";
    case SCREEN_KEYBOARD: return "Keyboard layout";
    case SCREEN_TIMEZONE: return "Time zone";
    case SCREEN_NETWORK: return "Network";
    case SCREEN_DISK: return "Installation disk";
    case SCREEN_FILESYSTEM: return "Filesystem";
    case SCREEN_ENCRYPTION: return "Encryption";
    case SCREEN_DECOY: return "Decoy operating system";
    case SCREEN_BOOTINTEGRITY: return "Boot integrity";
    case SCREEN_ACCOUNT: return "Who are you?";
    case SCREEN_IDENTITIES: return "Identity profiles";
    case SCREEN_REVIEW: return "Summary";
    case SCREEN_PROGRESS: return "Installing EpinAnonymOS";
    default: return "Install EpinAnonymOS";
    }
}

static const char *screen_subtitle(struct app *app)
{
    switch (app->screen) {
    case SCREEN_LANGUAGE: return "Choose the language for the installed system.";
    case SCREEN_KEYBOARD: return "Select the layout that matches your keyboard.";
    case SCREEN_TIMEZONE: return "Pick the time zone of the installed system.";
    case SCREEN_NETWORK: return "Networking is optional during installation.";
    case SCREEN_DISK: return "The selected disk will be erased and made bootable.";
    case SCREEN_FILESYSTEM: return "Choose the filesystem for the main partition.";
    case SCREEN_ENCRYPTION: return "Protect the installation with disk encryption.";
    case SCREEN_DECOY: return "Configure the decoy OS revealed under coercion.";
    case SCREEN_BOOTINTEGRITY: return "Optionally anchor system integrity off-machine.";
    case SCREEN_ACCOUNT: return "Create the administrator account for the main OS.";
    case SCREEN_IDENTITIES: return "Enable isolated identity profiles to create at first boot.";
    case SCREEN_REVIEW: return "Review your choices before writing to disk.";
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

static const char *primary_label(struct app *app)
{
    switch (app->screen) {
    case SCREEN_WELCOME: return "Install";
    case SCREEN_REVIEW: return "Install Now";
    case SCREEN_PROGRESS: return app->install_done ? "Done" : "Installing";
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

/* Boot-integrity zkSync attestation needs the network step; grey it out when offline. */
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
    return 0;
}

/* ── disk enumeration ──────────────────────────────────────────────────────── */

static void load_disks(struct app *app)
{
    app->disk_count = 0;
    int fd = open("/config/disks.json", O_RDONLY);
    if (fd < 0)
        return;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return;
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
        const char *rl = strstr(ix, "\"role\":\"");
        d->role[0] = 0;
        if (rl) {
            rl += 8;
            int k = 0;
            while (*rl && *rl != '"' && k < (int)sizeof(d->role) - 1)
                d->role[k++] = *rl++;
            d->role[k] = 0;
        }
        app->disk_count++;
        p = sm ? sm + 10 : ix + 8;
    }
    printf("INSTALLER: enumerated %d disk(s) from /config/disks.json\n", app->disk_count);
    fflush(stdout);
}

/* Disk page rows: row 0 is Automatic, rows 1..N are the enumerated disks. */
static int disk_row_count(struct app *app) { return 1 + app->disk_count; }

static void disk_row_text(struct app *app, int row, char *label, size_t lcap,
                          char *sub, size_t scap)
{
    if (row == 0) {
        snprintf(label, lcap, "Automatic");
        snprintf(sub, scap, "Use the recommended spare disk");
        return;
    }
    struct disk_entry *d = &app->disks[row - 1];
    snprintf(label, lcap, "Disk %d", d->index);
    if (d->size_mib >= 1024)
        snprintf(sub, scap, "%ld GiB  -  %s", d->size_mib / 1024,
                 d->role[0] ? d->role : "available");
    else
        snprintf(sub, scap, "%ld MiB  -  %s", d->size_mib,
                 d->role[0] ? d->role : "available");
}

/* ── fields per screen ─────────────────────────────────────────────────────── */

static int fields_for_screen(struct app *app, int out[], int max)
{
    int n = 0;
    if (app->screen == SCREEN_ACCOUNT) {
        int f[] = { FIELD_REAL_FULLNAME, FIELD_HOSTNAME, FIELD_REAL_USER,
                    FIELD_REAL_PASSWORD, FIELD_REAL_CONFIRM };
        for (size_t i = 0; i < sizeof(f) / sizeof(f[0]) && n < max; i++) out[n++] = f[i];
    } else if (app->screen == SCREEN_ENCRYPTION) {
        if (app->encryption_mode == ENC_FULL && n < max)
            out[n++] = FIELD_HIDDEN_PASSWORD;
        if (app->encryption_mode == ENC_HIDDEN) {
            int f[] = { FIELD_HIDDEN_PASSWORD, FIELD_OUTER_PASSWORD, FIELD_DECOY_BOOT_PASSWORD };
            for (size_t i = 0; i < sizeof(f) / sizeof(f[0]) && n < max; i++) out[n++] = f[i];
        }
    } else if (app->screen == SCREEN_DECOY) {
        int f[] = { FIELD_DECOY_USER, FIELD_DECOY_FULLNAME, FIELD_DECOY_PASSWORD, FIELD_DECOY_HOSTNAME };
        for (size_t i = 0; i < sizeof(f) / sizeof(f[0]) && n < max; i++) out[n++] = f[i];
    }
    return n;
}

/* On the Encryption screen the segmented control occupies ordinal 0, fields below it. */
static int field_ordinal_base(struct app *app)
{
    return app->screen == SCREEN_ENCRYPTION ? 1 : 0;
}

enum { FIELD_Y0 = 134, FIELD_STEP = 66, FIELD_H = 42 };
static void field_rect(struct app *app, int ordinal,
                       double *x, double *y, double *w, double *h)
{
    *x = CONTENT_X;
    *y = FIELD_Y0 + ordinal * FIELD_STEP;
    *w = content_w(app);
    *h = FIELD_H;
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

static void focus_first_field(struct app *app)
{
    int fields[8];
    int n = fields_for_screen(app, fields, 8);
    app->focused_field = n > 0 ? fields[0] : -1;
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
            app->focused_field = fields[(i + 1) % n];
            return;
        }
    }
    app->focused_field = fields[0];
}

static int passwords_match(struct app *app)
{
    return strcmp(app->field_text[FIELD_REAL_PASSWORD],
                  app->field_text[FIELD_REAL_CONFIRM]) == 0;
}

/* Whether the Continue/Install button should be enabled for the current screen. */
static int screen_can_advance(struct app *app)
{
    if (app->screen == SCREEN_ACCOUNT) {
        return app->field_len[FIELD_REAL_USER] > 0 &&
               app->field_len[FIELD_HOSTNAME] > 0 &&
               app->field_len[FIELD_REAL_PASSWORD] > 0 &&
               app->field_len[FIELD_REAL_CONFIRM] > 0 &&
               passwords_match(app);
    }
    if (app->screen == SCREEN_ENCRYPTION) {
        if (app->encryption_mode == ENC_FULL)
            return app->field_len[FIELD_HIDDEN_PASSWORD] > 0;
        if (app->encryption_mode == ENC_HIDDEN)
            return app->field_len[FIELD_HIDDEN_PASSWORD] > 0 &&
                   app->field_len[FIELD_OUTER_PASSWORD] > 0 &&
                   app->field_len[FIELD_DECOY_BOOT_PASSWORD] > 0;
        return 1;
    }
    if (app->screen == SCREEN_DECOY) {
        return app->field_len[FIELD_DECOY_USER] > 0 &&
               app->field_len[FIELD_DECOY_PASSWORD] > 0;
    }
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

static uint32_t blend_xrgb(uint32_t dst, uint32_t src, unsigned int alpha)
{
    if (alpha >= 255)
        return src;
    if (alpha == 0)
        return dst;
    unsigned int inv = 255 - alpha;
    unsigned int sr = (src >> 16) & 0xff, sg = (src >> 8) & 0xff, sb = src & 0xff;
    unsigned int dr = (dst >> 16) & 0xff, dg = (dst >> 8) & 0xff, db = dst & 0xff;
    unsigned int r = (sr * alpha + dr * inv + 127) / 255;
    unsigned int g = (sg * alpha + dg * inv + 127) / 255;
    unsigned int b = (sb * alpha + db * inv + 127) / 255;
    return 0xff000000u | (r << 16) | (g << 8) | b;
}

static void draw_text_ft(struct app *app, const char *text, int x, int y,
                         int max_w, int px, uint32_t color)
{
    if (!app->font_ready || !text || max_w <= 0)
        return;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0)
        return;

    int line_h = px + 6;
    int baseline = px;
    if (app->face->size && app->face->size->metrics.ascender > 0)
        baseline = (int)(app->face->size->metrics.ascender >> 6);

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
        if (FT_Load_Char(app->face, (FT_ULong)ch, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) != 0)
            continue;

        FT_GlyphSlot g = app->face->glyph;
        int advance = (int)(g->advance.x >> 6);
        if (pen_x > x && pen_x + advance > x + max_w) {
            pen_x = x;
            pen_y += line_h;
        }

        FT_Bitmap *bm = &g->bitmap;
        int gx = pen_x + g->bitmap_left;
        int gy = pen_y - g->bitmap_top;
        int pitch = bm->pitch;
        const unsigned char *base = bm->buffer;
        if (pitch < 0) {
            pitch = -pitch;
            base = bm->buffer - (int)(bm->rows - 1) * pitch;
        }

        for (int row = 0; row < (int)bm->rows; row++) {
            int py = gy + row;
            if (py < 0 || py >= app->height)
                continue;
            const unsigned char *src_row = base + row * pitch;
            for (int col = 0; col < (int)bm->width; col++) {
                int pxpos = gx + col;
                if (pxpos < 0 || pxpos >= app->width)
                    continue;
                unsigned int alpha = 0;
                if (bm->pixel_mode == FT_PIXEL_MODE_GRAY)
                    alpha = src_row[col];
                else if (bm->pixel_mode == FT_PIXEL_MODE_MONO)
                    alpha = (src_row[col >> 3] & (0x80 >> (col & 7))) ? 255 : 0;
                uint32_t *dst = &app->pixels[py * app->width + pxpos];
                *dst = blend_xrgb(*dst, color, alpha);
            }
        }
        pen_x += advance;
    }
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
    /* center the label roughly */
    int approx = (int)strlen(label) * 8;
    int tx = (int)x + ((int)w - approx) / 2;
    if (tx < (int)x + 14) tx = (int)x + 14;
    draw_text_ft(app, label, tx, (int)y + 16, (int)w - 16, 14,
                 enabled ? 0xffffffffu : 0xff6b7480u);
}

/* The left rail listing every (visible) step, current one highlighted. */
static void draw_steps(struct app *app)
{
    int y = 120;
    for (size_t i = 0; i < sizeof(SCREEN_ORDER) / sizeof(SCREEN_ORDER[0]); i++) {
        int s = SCREEN_ORDER[i];
        if (s == SCREEN_DECOY && app->encryption_mode != ENC_HIDDEN)
            continue;
        uint32_t color;
        if (s == app->screen)
            color = 0xffffffffu;
        else if (s < app->screen)
            color = 0xff5f6b78u;   /* completed → dim */
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
        y += 30;
    }
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

static void draw_field(struct app *app, cairo_t *cr, int field, int ordinal)
{
    double x, y, w, h;
    field_rect(app, ordinal, &x, &y, &w, &h);
    draw_text_ft(app, field_label(app, field), (int)x, (int)y - 20, (int)w, 12, 0xffc8d2dfu);
    rounded_rect(cr, x, y, w, h, 7);
    if (field == app->focused_field)
        cairo_set_source_rgb(cr, 0.13, 0.21, 0.28);
    else
        cairo_set_source_rgb(cr, 0.09, 0.14, 0.19);
    cairo_fill(cr);
    if (field == app->focused_field) {
        rounded_rect(cr, x + 0.5, y + 0.5, w - 1, h - 1, 7);
        cairo_set_source_rgb(cr, 0.16, 0.70, 0.62);
        cairo_set_line_width(cr, 1.5);
        cairo_stroke(cr);
    }
    char shown[112];
    masked_value(app, field, shown, sizeof shown);
    if (shown[0])
        draw_text_ft(app, shown, (int)x + 14, (int)y + 13, (int)w - 28, 14, 0xffffffffu);
    else
        draw_text_ft(app, field_optional(field) ? "Optional" : "Required",
                     (int)x + 14, (int)y + 13, (int)w - 28, 14, 0xff778391u);
}

static void draw_segments(struct app *app, cairo_t *cr)
{
    const char *labels[] = { "None", "Full Disk", "Hidden OS" };
    for (int i = 0; i < 3; i++) {
        double x, y, w, h;
        segment_rect(app, i, &x, &y, &w, &h);
        rounded_rect(cr, x, y, w, h, 7);
        if (app->encryption_mode == i)
            cairo_set_source_rgb(cr, 0.05, 0.52, 0.48);
        else
            cairo_set_source_rgb(cr, 0.09, 0.14, 0.19);
        cairo_fill(cr);
        int tx = (int)x + ((int)w - (int)strlen(labels[i]) * 8) / 2;
        if (tx < (int)x + 10) tx = (int)x + 10;
        draw_text_ft(app, labels[i], tx, (int)y + 16, (int)w - 12, 13, 0xffffffffu);
    }
}

/* Draw a row in a list: label + sub, selected highlighted, checkbox for toggles. */
static void draw_list_row(struct app *app, cairo_t *cr, int visible_pos,
                          const char *label, const char *sub,
                          int selected, int disabled, int checkbox)
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
    if (sub && sub[0]) {
        draw_text_ft(app, label, text_x, (int)y + 7, (int)w - 40, 13, lc);
        draw_text_ft(app, sub, text_x, (int)y + 24, (int)w - 40, 11, sc);
    } else {
        draw_text_ft(app, label, text_x, (int)y + 14, (int)w - 40, 13, lc);
    }
    if (disabled)
        draw_text_ft(app, "unavailable", (int)(x + w) - 96, (int)y + 14, 86, 11, 0xff5b6470u);
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
    double ty = LIST_TOP;
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
                      opt_is_disabled(app, app->screen, idx), 0);
    }
    draw_scrollbar(app, cr, count);
}

static void draw_identity_list(struct app *app, cairo_t *cr)
{
    int count = ARRAY_LEN(IDENTITIES);
    clamp_scroll(app, count);
    int vis = list_visible_rows(app);
    for (int i = 0; i < vis; i++) {
        int idx = app->list_scroll + i;
        if (idx >= count)
            break;
        draw_list_row(app, cr, i, IDENTITIES[idx].label, IDENTITIES[idx].sub,
                      app->identity_on[idx], 0, 1);
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
        char label[48], sub[64];
        disk_row_text(app, idx, label, sizeof label, sub, sizeof sub);
        draw_list_row(app, cr, i, label, sub, idx == app->target_sel, 0, 0);
    }
    draw_scrollbar(app, cr, count);
    if (app->disk_count == 0)
        draw_text_ft(app, "No spare disks were enumerated; Automatic will pick a target.",
                     CONTENT_X, app->height - 116, content_w(app), 12, 0xffffd08au);
}

static const char *encryption_name(struct app *app)
{
    if (app->encryption_mode == ENC_FULL)
        return "Full disk";
    if (app->encryption_mode == ENC_HIDDEN)
        return "Hidden OS";
    return "None";
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
        snprintf(out, cap, "Administrator only");
}

static void draw_review(struct app *app)
{
    char line[200];
    int x = CONTENT_X;
    int w = content_w(app);
    int y = 132;
    int step = 30;

    snprintf(line, sizeof line, "Language:    %s", LOCALES[app->locale_idx].label);
    draw_text_ft(app, line, x, y, w, 13, 0xffe6ecf2u); y += step;
    snprintf(line, sizeof line, "Keyboard:    %s", KEYMAPS[app->keymap_idx].label);
    draw_text_ft(app, line, x, y, w, 13, 0xffe6ecf2u); y += step;
    snprintf(line, sizeof line, "Time zone:   %s", TIMEZONES[app->timezone_idx].label);
    draw_text_ft(app, line, x, y, w, 13, 0xffe6ecf2u); y += step;
    snprintf(line, sizeof line, "Network:     %s", NETWORKS[app->network_idx].label);
    draw_text_ft(app, line, x, y, w, 13, 0xffe6ecf2u); y += step;
    if (app->target_sel == 0)
        snprintf(line, sizeof line, "Disk:        Automatic");
    else
        snprintf(line, sizeof line, "Disk:        Disk %d", app->disks[app->target_sel - 1].index);
    draw_text_ft(app, line, x, y, w, 13, 0xffe6ecf2u); y += step;
    snprintf(line, sizeof line, "Filesystem:  %s", FILESYSTEMS[app->filesystem_idx].label);
    draw_text_ft(app, line, x, y, w, 13, 0xffe6ecf2u); y += step;
    snprintf(line, sizeof line, "Encryption:  %s", encryption_name(app));
    draw_text_ft(app, line, x, y, w, 13, 0xffe6ecf2u); y += step;
    snprintf(line, sizeof line, "Boot check:  %s", BOOTINTEGRITY[app->bootintegrity_idx].label);
    draw_text_ft(app, line, x, y, w, 13, 0xffe6ecf2u); y += step;
    snprintf(line, sizeof line, "Account:     %s on %s",
             app->field_text[FIELD_REAL_USER], app->field_text[FIELD_HOSTNAME]);
    draw_text_ft(app, line, x, y, w, 13, 0xffe6ecf2u); y += step;
    char ids[160];
    identities_summary(app, ids, sizeof ids);
    snprintf(line, sizeof line, "Identities:  %s", ids);
    draw_text_ft(app, line, x, y, w, 13, 0xffe6ecf2u); y += step;
    if (app->encryption_mode == ENC_HIDDEN) {
        snprintf(line, sizeof line, "Decoy OS:    %s on %s",
                 app->field_text[FIELD_DECOY_USER], app->field_text[FIELD_DECOY_HOSTNAME]);
        draw_text_ft(app, line, x, y, w, 13, 0xffc8d2dfu); y += step;
    }
    draw_text_ft(app, "The selected disk will be erased when you continue.",
                 x, app->height - 108, w, 13, 0xffffd08au);
}

static void draw_welcome(struct app *app)
{
    int x = CONTENT_X;
    int w = content_w(app);
    draw_text_ft(app, "Welcome. This wizard installs EpinAnonymOS to a disk and makes it bootable.",
                 x, 128, w, 15, 0xffe6ecf2u);
    const char *bullets[] = {
        "- Immutable, object-capability kernel with a rootless security model",
        "- Optional plausible-deniability disk encryption with a hidden OS",
        "- Per-identity domains: Personal, Work, Banking, Research, and more",
        "- Declarative install: one install.json describes the whole system",
    };
    int y = 176;
    for (int i = 0; i < 4; i++) {
        draw_text_ft(app, bullets[i], x, y, w, 13, 0xffb9c4d2u);
        y += 30;
    }
    draw_text_ft(app, "Choose Install to begin, or Try Live to explore from the live session first.",
                 x, y + 14, w, 13, 0xff8b96a4u);
}

static void draw_network_note(struct app *app)
{
    draw_text_ft(app,
        "Network access is not required to install. zkSync boot attestation needs it.",
        CONTENT_X, app->height - 116, content_w(app), 12, 0xff8b96a4u);
}

static void draw_progress(struct app *app, cairo_t *cr)
{
    const char *line1, *line2;
    if (app->install_failed) {
        line1 = "Install is unavailable on this image.";
        line2 = "Boot hos-install.iso (it carries the esp-image payload) to install.";
    } else if (app->install_done) {
        line1 = "Installation complete.";
        line2 = "Power off, remove the install medium, then boot the disk.";
    } else {
        line1 = "Installing EpinAnonymOS to the target disk...";
        line2 = "Writing the GPT, EFI System Partition, and boot image.";
    }
    draw_text_ft(app, line1, CONTENT_X, 138, content_w(app), 15, 0xffffffffu);
    draw_text_ft(app, line2, CONTENT_X, 168, content_w(app), 13, 0xffc8d2dfu);

    double pbx = CONTENT_X, pbw = content_w(app), pbh = 20, pby = 232;
    rounded_rect(cr, pbx, pby, pbw, pbh, 8);
    cairo_set_source_rgb(cr, 0.09, 0.14, 0.19);
    cairo_fill(cr);
    int pg = app->progress; if (pg < 0) pg = 0; if (pg > 1000) pg = 1000;
    double fillw = pbw * pg / 1000.0;
    if (fillw > 1.0) {
        rounded_rect(cr, pbx, pby, fillw, pbh, 8);
        if (app->install_failed) cairo_set_source_rgb(cr, 0.80, 0.30, 0.25);
        else if (app->install_done) cairo_set_source_rgb(cr, 0.20, 0.68, 0.45);
        else cairo_set_source_rgb(cr, 0.05, 0.52, 0.48);
        cairo_fill(cr);
    }
    char pct[16];
    int p10 = pg / 10;
    snprintf(pct, sizeof pct, "%d%%", p10 > 100 ? 100 : p10);
    draw_text_ft(app, pct, app->width - 96, 208, 80, 14, 0xffffffffu);

    if (!app->install_failed) {
        const char *slides[] = {
            "Your data, your identities -- isolated by capability, not convention.",
            "The installer only describes; first boot realises the object tree.",
            "Hidden-OS encryption gives you a believable answer under coercion.",
        };
        int s = (pg / 334);
        if (s > 2) s = 2;
        draw_text_ft(app, slides[s], CONTENT_X, pby + 56, content_w(app), 13, 0xff9aa6b4u);
    }
}

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

    int back_enabled = app->screen != SCREEN_WELCOME && app->screen != SCREEN_PROGRESS;
    int primary_enabled =
        (app->screen == SCREEN_PROGRESS) ? app->install_done : screen_can_advance(app);

    draw_button(app, cr, BTN_PRIMARY, primary_label(app), primary_enabled);
    if (app->screen == SCREEN_WELCOME)
        draw_button(app, cr, BTN_SECONDARY, "Try Live", 1);
    if (back_enabled)
        draw_button(app, cr, BTN_BACK, "Back", 1);

    if (app->screen == SCREEN_ENCRYPTION)
        draw_segments(app, cr);

    if (screen_is_list(app->screen))
        draw_choice_list(app, cr);
    else if (app->screen == SCREEN_DISK)
        draw_disk_list(app, cr);
    else if (app->screen == SCREEN_IDENTITIES)
        draw_identity_list(app, cr);

    int fields[8];
    int n = fields_for_screen(app, fields, 8);
    int base = field_ordinal_base(app);
    for (int i = 0; i < n; i++)
        draw_field(app, cr, fields[i], i + base);

    if (app->screen == SCREEN_PROGRESS)
        draw_progress(app, cr);

    cairo_destroy(cr);
    cairo_surface_flush(surface);
    cairo_surface_destroy(surface);

    /* Text overlays (drawn after cairo so glyphs land on the flushed surface). */
    draw_text_ft(app, "EpinAnonymOS", 84, 50, SIDEBAR_W - 90, 17, 0xffffffffu);
    draw_steps(app);
    draw_text_ft(app, screen_title(app), CONTENT_X, 54, content_w(app), 24, 0xffffffffu);
    const char *sub = screen_subtitle(app);
    if (sub[0])
        draw_text_ft(app, sub, CONTENT_X, 90, content_w(app), 13, 0xff9aa6b4u);

    if (app->screen == SCREEN_WELCOME)
        draw_welcome(app);
    else if (app->screen == SCREEN_NETWORK)
        draw_network_note(app);
    else if (app->screen == SCREEN_ENCRYPTION) {
        if (app->encryption_mode == ENC_NONE)
            draw_text_ft(app, "No disk encryption will be configured.",
                         CONTENT_X, 196, content_w(app), 13, 0xffc8d2dfu);
        else if (app->encryption_mode == ENC_HIDDEN)
            draw_text_ft(app,
                "Three passwords: hidden OS (real), outer volume (decoy-sensitive), and decoy OS.",
                CONTENT_X, app->height - 116, content_w(app), 12, 0xff9aa6b4u);
    } else if (app->screen == SCREEN_ACCOUNT) {
        if (app->field_len[FIELD_REAL_CONFIRM] > 0 && !passwords_match(app))
            draw_text_ft(app, "Passwords do not match.",
                         CONTENT_X, app->height - 110, content_w(app), 12, 0xffff8a8au);
    } else if (app->screen == SCREEN_REVIEW) {
        draw_review(app);
    }
}

/* ── buffer / commit ───────────────────────────────────────────────────────── */

/* Create the shm buffer ONCE and keep it mapped — `app->pixels` IS the shared memory, so
 * the UI is drawn directly into it and the same buffer is re-attached every frame.  The old
 * code allocated a fresh memfd per redraw; the compositor holds each buffer's fd until it
 * releases the buffer, so a few dozen redraws exhausted the process's small fd pool and froze
 * the installer mid-typing (seen as "memfd_create: No file descriptors available").  This is
 * the same fix wl-files.c already carries; it does not depend on buffer-release timing. */
static int create_buffer_once(struct app *app)
{
    if (app->buffer)
        return 0;
    int fd = create_memfd("epin-installer");
    if (fd < 0) {
        perror("G11CAIRO: memfd_create");
        return -1;
    }
    if (ftruncate(fd, (off_t)app->buffer_size) < 0) {
        perror("G11CAIRO: ftruncate");
        close(fd);
        return -1;
    }
    app->pixels = (uint32_t *)mmap(NULL, app->buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (app->pixels == MAP_FAILED) {
        perror("G11CAIRO: mmap");
        close(fd);
        app->pixels = NULL;
        return -1;
    }
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int)app->buffer_size);
    app->buffer = wl_shm_pool_create_buffer(pool, 0, app->width, app->height,
                                            app->stride, WL_SHM_FORMAT_XRGB8888);
    wl_shm_pool_destroy(pool);
    close(fd);
    if (!app->buffer) {
        log_line("G11CAIRO: wl_shm_pool_create_buffer failed");
        return -1;
    }
    return 0;
}

static void redraw_commit(struct app *app, const char *marker)
{
    if (!app->buffer || !app->pixels)
        return;
    draw_demo(app);                    /* draw directly into the persistent shared buffer */
    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    if (marker) {
        printf("G11INPUT: %s -- G11 INPUT\n", marker);
        fflush(stdout);
    }
}

/* ── install backend control ───────────────────────────────────────────────── */

static void install_step(struct app *app)
{
    int fd = open("/config/install.action", O_WRONLY);
    if (fd >= 0) {
        size_t n = strlen(app->install_cmd);
        ssize_t wn = write(fd, app->install_cmd, n);
        (void)wn;
        close(fd);
    }
    int pf = open("/config/install.progress", O_RDONLY);
    if (pf >= 0) {
        char b[16];
        ssize_t n = read(pf, b, sizeof b - 1);
        close(pf);
        if (n > 0) { b[n] = 0; app->progress = atoi(b); }
    }
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

static size_t build_install_config(struct app *app, char *buf, size_t cap)
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

    append_cstr(buf, cap, &pos, "{\n");
    append_json_string(buf, cap, &pos, "schema", "epin.install.v1", 1);
    append_json_string(buf, cap, &pos, "hostname", app->field_text[FIELD_HOSTNAME], 1);
    append_json_string(buf, cap, &pos, "user", app->field_text[FIELD_REAL_USER], 1);
    append_json_string(buf, cap, &pos, "userFullName", app->field_text[FIELD_REAL_FULLNAME], 1);
    append_json_string(buf, cap, &pos, "userPassword", app->field_text[FIELD_REAL_PASSWORD], 1);
    append_json_string(buf, cap, &pos, "locale", LOCALES[app->locale_idx].code, 1);
    append_json_string(buf, cap, &pos, "localeName", LOCALES[app->locale_idx].label, 1);
    append_json_string(buf, cap, &pos, "keymap", KEYMAPS[app->keymap_idx].code, 1);
    append_json_string(buf, cap, &pos, "timezone", TIMEZONES[app->timezone_idx].code, 1);
    append_json_string(buf, cap, &pos, "network", NETWORKS[app->network_idx].code, 1);
    append_json_string(buf, cap, &pos, "filesystem", FILESYSTEMS[app->filesystem_idx].code, 1);
    append_json_string(buf, cap, &pos, "targetDisk", target, 1);
    append_json_string(buf, cap, &pos, "bootIntegrity", BOOTINTEGRITY[app->bootintegrity_idx].code, 1);
    append_json_string(buf, cap, &pos, "identities", ids, 1);
    append_json_string(buf, cap, &pos, "encryption", encryption_name(app), 1);
    append_json_string(buf, cap, &pos, "hiddenPassword", app->field_text[FIELD_HIDDEN_PASSWORD], 1);
    append_json_string(buf, cap, &pos, "outerPassword", app->field_text[FIELD_OUTER_PASSWORD], 1);
    append_json_string(buf, cap, &pos, "decoyBootPassword", app->field_text[FIELD_DECOY_BOOT_PASSWORD], 1);
    append_json_string(buf, cap, &pos, "decoyUser", app->field_text[FIELD_DECOY_USER], 1);
    append_json_string(buf, cap, &pos, "decoyFullName", app->field_text[FIELD_DECOY_FULLNAME], 1);
    append_json_string(buf, cap, &pos, "decoyPassword", app->field_text[FIELD_DECOY_PASSWORD], 1);
    append_json_string(buf, cap, &pos, "decoyHostname", app->field_text[FIELD_DECOY_HOSTNAME], 0);
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
    const size_t json_len = build_install_config(app, json, sizeof json);
    if (json_len == 0)
        return 0;

    int fd = open("/tmp/install.json", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        write_all_len(fd, json, json_len);
        close(fd);
    }

    memcpy(command, "config ", 7);
    memcpy(command + 7, json, json_len);
    int cfd = open("/config/install.action", O_WRONLY);
    if (cfd < 0)
        return 0;
    write_all_len(cfd, command, json_len + 7);
    close(cfd);
    app->install_config_written = 1;
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

    int config_ok = write_install_config(app);
    app->screen = SCREEN_PROGRESS;
    app->progress = 0;
    app->install_done = 0;
    int fd = open("/config/install.action", O_WRONLY);
    if (fd >= 0 && config_ok) {
        close(fd);
        app->installing = 1;
        app->install_failed = 0;
        printf("INSTALLER: starting install (%s encryption, target=%s)\n",
               encryption_name(app), app->install_cmd);
    } else {
        if (fd >= 0)
            close(fd);
        app->installing = 0;
        app->install_failed = 1;
        printf("INSTALLER: no /config/install.action (boot hos-install.iso)\n");
    }
    fflush(stdout);
    redraw_commit(app, "install-info");
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
    app->list_scroll = 0;
    focus_first_field(app);
    /* auto-scroll a list to reveal the current selection */
    if (screen_is_list(app->screen)) {
        int *sel = screen_sel_ptr(app, app->screen);
        if (sel) {
            int vis = list_visible_rows(app);
            if (*sel >= vis)
                app->list_scroll = *sel - vis + 1;
        }
    }
    redraw_commit(app, "screen");
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
    if (create_buffer_once(app) < 0)   /* one persistent buffer; app->pixels = its shm */
        return -1;
    draw_demo(app);
    return 0;
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

static void frame_done(void *data, struct wl_callback *callback, uint32_t time)
{
    struct app *app = data;
    (void)time;
    if (callback)
        wl_callback_destroy(callback);
    app->frame_cb = NULL;
    if (app->post_map_frame_done || !app->buffer)
        return;

    app->post_map_frame_done = 1;
    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    printf("G11CAIRO: post-map redraw committed %dx%d -- G11 REDRAW\n",
           app->width, app->height);
    fflush(stdout);
}

static const struct wl_callback_listener frame_listener = {
    .done = frame_done,
};

static void xdg_surface_configure(void *data, struct xdg_surface *surface,
                                  uint32_t serial)
{
    struct app *app = data;
    xdg_surface_ack_configure(surface, serial);
    if (app->committed)
        return;

    int width = DEFAULT_WIDTH;
    int height = DEFAULT_HEIGHT;
    if (app->pending_width > 0 && app->pending_width < width)
        width = app->pending_width;
    if (app->pending_height > 0 && app->pending_height < height)
        height = app->pending_height;
    if (create_shm_buffer(app, width, height) < 0) {
        app->running = 0;
        return;
    }

    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    if (!app->post_map_frame_armed) {
        app->frame_cb = wl_surface_frame(app->surface);
        wl_callback_add_listener(app->frame_cb, &frame_listener, app);
        app->post_map_frame_armed = 1;
    }
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    app->committed = 1;
    app->sync_after_commit = 1;
    printf("G11CAIRO: committed Cairo/FreeType wl_shm window %dx%d -- G11 COMMIT\n",
           app->width, app->height);
    fflush(stdout);
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

/* Move the selection of a single-choice list, skipping disabled options. */
static void list_move(struct app *app, int delta)
{
    if (app->screen == SCREEN_DISK) {
        int count = disk_row_count(app);
        app->target_sel += delta;
        if (app->target_sel < 0) app->target_sel = 0;
        if (app->target_sel >= count) app->target_sel = count - 1;
    } else if (screen_is_list(app->screen)) {
        int count = 0;
        const struct opt *o = screen_opts(app->screen, &count);
        int *sel = screen_sel_ptr(app, app->screen);
        if (!o || !sel)
            return;
        int v = *sel;
        for (int step = 0; step < count; step++) {
            v += delta;
            if (v < 0 || v >= count) { v = *sel; break; }
            if (!opt_is_disabled(app, app->screen, v)) break;
        }
        *sel = v;
    } else if (app->screen == SCREEN_IDENTITIES) {
        /* nothing to move — handled by toggle; use scroll instead */
        app->list_scroll += delta;
        clamp_scroll(app, ARRAY_LEN(IDENTITIES));
        return;
    } else {
        return;
    }
    /* keep the selection visible */
    int sel = (app->screen == SCREEN_DISK) ? app->target_sel : *screen_sel_ptr(app, app->screen);
    int vis = list_visible_rows(app);
    if (sel < app->list_scroll) app->list_scroll = sel;
    if (sel >= app->list_scroll + vis) app->list_scroll = sel - vis + 1;
    redraw_commit(app, "list move");
}

static void entry_append_key(struct app *app, uint32_t code)
{
    /* List/disk/identity screens: arrow keys + space select, Enter advances. */
    if (screen_is_list(app->screen) || app->screen == SCREEN_DISK ||
        app->screen == SCREEN_IDENTITIES) {
        if (code == 103) { list_move(app, -1); return; }   /* Up */
        if (code == 108) { list_move(app, +1); return; }   /* Down */
        if (code == 28) { if (screen_can_advance(app)) go_next(app); return; } /* Enter */
        return;
    }

    if (!app->entry_focused)
        return;
    if (code == 15) {
        cycle_focus(app);
        redraw_commit(app, "field focus");
        return;
    }
    if (code == 14) {
        int f = app->focused_field;
        if (f >= 0 && f < FIELD_COUNT && app->field_len[f] > 0)
            app->field_text[f][--app->field_len[f]] = 0;
        redraw_commit(app, "entry edit");
        return;
    }
    if (code == 28) {
        if (app->screen != SCREEN_PROGRESS && screen_can_advance(app))
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
    redraw_commit(app, "entry edit");
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
    app->entry_focused = 1;
    redraw_commit(app, "keyboard focus");
}

static void keyboard_leave(void *data, struct wl_keyboard *keyboard,
                           uint32_t serial, struct wl_surface *surface)
{
    struct app *app = data;
    (void)keyboard;
    (void)serial;
    (void)surface;
    app->entry_focused = 0;
    redraw_commit(app, "keyboard blur");
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
    if (button != 0x110 || state != WL_POINTER_BUTTON_STATE_PRESSED)
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
        if (app->installing) return;
        btn_rect(app, BTN_PRIMARY, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h)) {
            if (app->install_done) { app->running = 0; return; }
            return;
        }
        return;
    }

    /* Encryption segmented control. */
    if (app->screen == SCREEN_ENCRYPTION) {
        for (int i = 0; i < 3; i++) {
            segment_rect(app, i, &x, &y, &w, &h);
            if (in_rect(app, x, y, w, h)) {
                app->encryption_mode = i;
                focus_first_field(app);
                redraw_commit(app, "encryption");
                return;
            }
        }
    }

    /* Single-choice option lists. */
    if (screen_is_list(app->screen)) {
        int count = 0;
        const struct opt *o = screen_opts(app->screen, &count);
        int *sel = screen_sel_ptr(app, app->screen);
        int row = list_row_under_pointer(app, count);
        if (o && sel && row >= 0) {
            if (!opt_is_disabled(app, app->screen, row)) {
                *sel = row;
                redraw_commit(app, "list select");
            }
            return;
        }
    } else if (app->screen == SCREEN_DISK) {
        int row = list_row_under_pointer(app, disk_row_count(app));
        if (row >= 0) {
            app->target_sel = row;
            redraw_commit(app, "disk select");
            return;
        }
    } else if (app->screen == SCREEN_IDENTITIES) {
        int row = list_row_under_pointer(app, ARRAY_LEN(IDENTITIES));
        if (row >= 0) {
            app->identity_on[row] = !app->identity_on[row];
            redraw_commit(app, "identity toggle");
            return;
        }
    }

    /* Text fields. */
    int fields[8];
    int n = fields_for_screen(app, fields, 8);
    int base = field_ordinal_base(app);
    for (int i = 0; i < n; i++) {
        field_rect(app, i + base, &x, &y, &w, &h);
        if (in_rect(app, x, y, w, h)) {
            app->focused_field = fields[i];
            app->entry_focused = 1;
            redraw_commit(app, "field focus");
            return;
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

/* Scroll wheel pans the active list. */
static void pointer_axis(void *data, struct wl_pointer *pointer,
                         uint32_t time, uint32_t axis, wl_fixed_t value)
{
    struct app *app = data;
    (void)pointer;
    (void)time;
    if (axis != 0)  /* vertical only */
        return;
    int count = 0;
    if (screen_is_list(app->screen)) {
        screen_opts(app->screen, &count);
    } else if (app->screen == SCREEN_DISK) {
        count = disk_row_count(app);
    } else if (app->screen == SCREEN_IDENTITIES) {
        count = ARRAY_LEN(IDENTITIES);
    } else {
        return;
    }
    double v = wl_fixed_to_double(value);
    app->list_scroll += (v > 0) ? 1 : -1;
    clamp_scroll(app, count);
    redraw_commit(app, "scroll");
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
    snprintf(app.install_cmd, sizeof app.install_cmd, "install");
    set_field(&app, FIELD_HOSTNAME, "epin");
    set_field(&app, FIELD_REAL_USER, "user");
    set_field(&app, FIELD_DECOY_USER, "decoy");
    set_field(&app, FIELD_DECOY_FULLNAME, "Decoy User");
    set_field(&app, FIELD_DECOY_HOSTNAME, "decoy-pc");
    app.identity_on[0] = 1;   /* Personal enabled by default */

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

    while (app.running) {
        if (app.installing) {
            install_step(&app);
            redraw_commit(&app, "installing");
            if (wl_display_roundtrip(app.display) < 0) break;
            if (app.progress >= 1000) {
                app.installing = 0;
                app.install_done = 1;
                redraw_commit(&app, "install-done");
                wl_display_roundtrip(app.display);
                printf("INSTALLER: install complete (100%%)\n");
            }
            continue;
        }
        int ret = wl_display_dispatch(app.display);
        if (ret < 0) {
            perror("G11CAIRO: wl_display_dispatch");
            break;
        }
        if (app.sync_after_commit) {
            app.sync_after_commit = 0;
            if (wl_display_roundtrip(app.display) < 0)
                perror("G11CAIRO: post-commit roundtrip");
            else
                log_line("G11CAIRO: post-commit roundtrip complete -- G11 SYNC");
        }
    }

    return app.committed ? 0 : 1;
}
