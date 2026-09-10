/*
 * wl-wallpaper.c -- the desktop background for the EpinAnonymOS Hyprland desktop.
 *
 * Hyprland (wlroots) paints only a solid misc:background_color; it renders no
 * image wallpaper, and this image ships no wallpaper daemon -- quickshell,
 * hyprpaper and swww are all absent.  So the desktop background is drawn here,
 * by a plain wlr-layer-shell client on the BACKGROUND layer, one layer below
 * wl-layer-bar (which uses the same protocol for the top bar).
 *
 * The image is the dendritic network's radial keyspace topology -- the graph
 * the dendritic website embedded (backend/templates/includes/peer-canvas.html).
 * It is rendered to a PNG at build time by tools/wallpaper-gen and shipped both
 * in the Hyprland config tree (~/.config/hypr/wallpapers/dendritic-network.png)
 * and as a boot module (/dendritic-network.png), so at least one path resolves
 * however early this runs.
 *
 * Software only: it decodes the PNG with libpng's simplified API into BGRA --
 * which matches the XRGB8888 wl_shm framebuffer exactly, the same trick
 * wl-imgview uses -- and blits it, scaled to "contain" the output with the
 * image's own dark ground (#0d1117) as the letterbox fill (so the fill is
 * seamless), into a wl_shm buffer.  No GPU and no async resource gatherer, so it
 * is immune to the CAsyncResourceGatherer/mallocng crash that sinks Hyprland's
 * own stock wallpaper under musl (see src/kernel/d/core/exports.d).
 *
 * Non-interactive: no seat, no keyboard; exclusive_zone -1 so it fills the whole
 * output beneath every panel and window and never reserves space or steals
 * input.  Scaffolding (registry / wl_shm / layer surface / prepare_read loop) is
 * the proven wl-layer-bar pattern.
 *
 * Single output: it dresses the first wl_output offered, which is the whole
 * story on the software-rendered single-head VM this targets.  A multi-head
 * host would leave the other outputs on the compositor's solid colour.
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
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <wayland-client.h>
#include <png.h>
#include "xdg-shell-client-protocol.h"
#include "wlr-layer-shell-unstable-v1-client-protocol.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

/* The ground colour of the generated wallpaper (tools/wallpaper-gen: #0d1117).
 * Used as the solid fill before an image loads and as the letterbox colour, so
 * the padding around a non-16:9 output blends into the image edges. */
#define COL_BG 0xff0d1117u

/* Paths tried in order; argv[1] overrides. The config-tree copy is the "real"
 * location; the boot-module copy is the always-present early fallback. */
static const char *DEFAULT_PATHS[] = {
    "/home/user/.config/hypr/wallpapers/dendritic-network.png",
    "/dendritic-network.png",
    NULL,
};

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_output *output;
    struct zwlr_layer_shell_v1 *layer_shell;
    struct wl_surface *surface;
    struct zwlr_layer_surface_v1 *layer_surface;

    int width, height;          /* current surface size (from configure) */
    int configured, running;

    uint32_t *img;              /* decoded BGRA == XRGB8888 pixels, or NULL */
    int iw, ih;
};

/* One shm buffer + its mapping. Freed by its own wl_buffer.release handler when
 * the compositor is done with it, so a reconfigure never frees a buffer the
 * compositor is still scanning out (no use-after-free, no fixed double-buffer). */
struct buffer {
    struct wl_buffer *wl;
    void *data;
    size_t size;
};
static void buffer_release(void *d, struct wl_buffer *wl) {
    (void)wl;
    struct buffer *b = d;
    wl_buffer_destroy(b->wl);
    munmap(b->data, b->size);
    free(b);
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static void log_line(const char *m) { fprintf(stderr, "WALL: %s\n", m); fflush(stderr); }

static int create_memfd(const char *name) { return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC); }

/* Decode a PNG into a freshly malloc'd BGRA buffer (libpng simplified API,
 * exactly as wl-imgview does). Returns 0 on success and fills img/iw/ih. */
static int load_image(struct app *a, const char *path) {
    png_image image;
    memset(&image, 0, sizeof image);
    image.version = PNG_IMAGE_VERSION;
    if (!png_image_begin_read_from_file(&image, path))
        return -1;
    image.format = PNG_FORMAT_BGRA;   /* bytes B,G,R,A == uint32 0xAARRGGBB (LE) */
    size_t sz = PNG_IMAGE_SIZE(image);
    uint32_t *buf = malloc(sz);
    if (!buf) { png_image_free(&image); return -1; }
    if (!png_image_finish_read(&image, NULL /*bg*/, buf, 0 /*stride*/, NULL)) {
        free(buf);
        png_image_free(&image);
        return -1;
    }
    a->img = buf;
    a->iw = (int)image.width;
    a->ih = (int)image.height;
    return 0;
}

/* Bilinear sample of the decoded image at floating (fx,fy), clamped to bounds. */
static uint32_t sample(const struct app *a, double fx, double fy) {
    if (fx < 0) fx = 0;
    if (fy < 0) fy = 0;
    if (fx > a->iw - 1) fx = a->iw - 1;
    if (fy > a->ih - 1) fy = a->ih - 1;
    int x0 = (int)fx, y0 = (int)fy;
    int x1 = x0 + 1 < a->iw ? x0 + 1 : x0;
    int y1 = y0 + 1 < a->ih ? y0 + 1 : y0;
    double tx = fx - x0, ty = fy - y0;
    const uint32_t *im = a->img;
    uint32_t c00 = im[y0 * a->iw + x0], c10 = im[y0 * a->iw + x1];
    uint32_t c01 = im[y1 * a->iw + x0], c11 = im[y1 * a->iw + x1];
    double r = 0, g = 0, b = 0;
    const uint32_t cs[4] = { c00, c10, c01, c11 };
    const double ws[4] = { (1 - tx) * (1 - ty), tx * (1 - ty), (1 - tx) * ty, tx * ty };
    for (int i = 0; i < 4; i++) {
        r += ((cs[i] >> 16) & 0xff) * ws[i];
        g += ((cs[i] >> 8) & 0xff) * ws[i];
        b += (cs[i] & 0xff) * ws[i];
    }
    return 0xff000000u | ((uint32_t)(r + 0.5) << 16) | ((uint32_t)(g + 0.5) << 8) | (uint32_t)(b + 0.5);
}

/* Paint the current surface: a solid ground, then the image scaled to "contain"
 * the output and centred. Allocates a fresh wl_shm buffer sized to the surface,
 * attaches, damages and commits. */
static void render(struct app *a) {
    if (a->width <= 0 || a->height <= 0) return;

    int stride = a->width * 4;
    size_t size = (size_t)stride * a->height;
    int fd = create_memfd("hos-wallpaper");
    if (fd < 0) { log_line("memfd failed"); return; }
    if (ftruncate(fd, (off_t)size) != 0) { close(fd); log_line("ftruncate failed"); return; }
    void *data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED) { close(fd); log_line("mmap failed"); return; }
    struct wl_shm_pool *pool = wl_shm_create_pool(a->shm, fd, (int32_t)size);
    struct wl_buffer *buf = wl_shm_pool_create_buffer(pool, 0, a->width, a->height, stride, WL_SHM_FORMAT_XRGB8888);
    wl_shm_pool_destroy(pool);
    close(fd);
    struct buffer *b = calloc(1, sizeof *b);
    if (!b) { wl_buffer_destroy(buf); munmap(data, size); log_line("oom"); return; }
    b->wl = buf; b->data = data; b->size = size;
    wl_buffer_add_listener(buf, &buffer_listener, b);

    uint32_t *px = (uint32_t *)data;

    if (!a->img) {
        for (size_t i = 0; i < (size_t)a->width * a->height; i++) px[i] = COL_BG;
    } else {
        /* contain: scale so the whole image fits, centre it, fill the rest with
         * the image ground so the letterbox is invisible. */
        double s = (double)a->width / a->iw;
        double sy = (double)a->height / a->ih;
        if (sy < s) s = sy;
        double placedW = a->iw * s, placedH = a->ih * s;
        double ox = (a->width - placedW) / 2.0, oy = (a->height - placedH) / 2.0;
        for (int y = 0; y < a->height; y++) {
            uint32_t *row = px + (size_t)y * a->width;
            double srcy = (y - oy) / s;
            int inRowY = (y >= (int)oy && y < (int)(oy + placedH));
            for (int x = 0; x < a->width; x++) {
                if (inRowY && x >= (int)ox && x < (int)(ox + placedW))
                    row[x] = sample(a, (x - ox) / s, srcy);
                else
                    row[x] = COL_BG;
            }
        }
    }

    wl_surface_attach(a->surface, buf, 0, 0);
    wl_surface_damage_buffer(a->surface, 0, 0, a->width, a->height);
    wl_surface_commit(a->surface);
    wl_display_flush(a->display);
}

static void layer_configure(void *d, struct zwlr_layer_surface_v1 *s, uint32_t serial, uint32_t w, uint32_t h) {
    struct app *a = d;
    zwlr_layer_surface_v1_ack_configure(s, serial);
    if (w) a->width = (int)w;
    if (h) a->height = (int)h;
    { char b[80]; snprintf(b, sizeof b, "configure %dx%d -> render", a->width, a->height); log_line(b); }
    a->configured = 1;
    render(a);
}
static void layer_closed(void *d, struct zwlr_layer_surface_v1 *s) { (void)s; ((struct app *)d)->running = 0; }
static const struct zwlr_layer_surface_v1_listener layer_listener = {
    .configure = layer_configure, .closed = layer_closed,
};

static void registry_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver) {
    struct app *a = d;
    if (!strcmp(iface, wl_compositor_interface.name))
        a->compositor = wl_registry_bind(r, name, &wl_compositor_interface, ver < 4 ? ver : 4);
    else if (!strcmp(iface, wl_shm_interface.name))
        a->shm = wl_registry_bind(r, name, &wl_shm_interface, 1);
    else if (!strcmp(iface, zwlr_layer_shell_v1_interface.name))
        a->layer_shell = wl_registry_bind(r, name, &zwlr_layer_shell_v1_interface, ver < 4 ? ver : 4);
    else if (!strcmp(iface, wl_output_interface.name) && !a->output)
        a->output = wl_registry_bind(r, name, &wl_output_interface, ver < 2 ? ver : 2);
}
static void registry_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener registry_listener = {
    .global = registry_global, .global_remove = registry_remove,
};

static void on_signal(int sig) { (void)sig; /* let the loop notice via running */ }

int main(int argc, char **argv) {
    struct app app;
    memset(&app, 0, sizeof app);
    app.running = 1;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    app.display = wl_display_connect(NULL);
    if (!app.display) { log_line("no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.layer_shell) {
        log_line("missing globals (need wlr-layer-shell) -- exiting");
        return 1;   /* harmless on Weston, which offers no zwlr_layer_shell */
    }

    /* Load the image before the first configure so it is ready to paint. Try the
     * explicit arg, then each default path; a miss just leaves a solid ground. */
    if (argc > 1) load_image(&app, argv[1]);
    for (int i = 0; !app.img && DEFAULT_PATHS[i]; i++) load_image(&app, DEFAULT_PATHS[i]);
    if (app.img) { char b[128]; snprintf(b, sizeof b, "loaded %dx%d", app.iw, app.ih); log_line(b); }
    else log_line("no wallpaper image found -- solid background");

    app.surface = wl_compositor_create_surface(app.compositor);
    app.layer_surface = zwlr_layer_shell_v1_get_layer_surface(
        app.layer_shell, app.surface, app.output,
        ZWLR_LAYER_SHELL_V1_LAYER_BACKGROUND, "wallpaper");
    zwlr_layer_surface_v1_add_listener(app.layer_surface, &layer_listener, &app);
    zwlr_layer_surface_v1_set_anchor(app.layer_surface,
        ZWLR_LAYER_SURFACE_V1_ANCHOR_TOP | ZWLR_LAYER_SURFACE_V1_ANCHOR_BOTTOM |
        ZWLR_LAYER_SURFACE_V1_ANCHOR_LEFT | ZWLR_LAYER_SURFACE_V1_ANCHOR_RIGHT);
    zwlr_layer_surface_v1_set_size(app.layer_surface, 0, 0);                  /* 0,0 -> full output */
    zwlr_layer_surface_v1_set_exclusive_zone(app.layer_surface, -1);         /* span under panels */
    zwlr_layer_surface_v1_set_keyboard_interactivity(app.layer_surface, 0);  /* never take focus */
    wl_surface_commit(app.surface);                                          /* triggers first configure */
    wl_display_flush(app.display);
    log_line("background layer surface committed, awaiting configure");

    int wlfd = wl_display_get_fd(app.display);
    while (app.running) {
        while (wl_display_prepare_read(app.display) != 0) wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);
        struct pollfd pfd = { .fd = wlfd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, 1000);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            wl_display_read_events(app.display);
            wl_display_dispatch_pending(app.display);
        } else {
            wl_display_cancel_read(app.display);
            if (pr < 0 && errno != EINTR) break;
        }
    }
    return 0;
}
