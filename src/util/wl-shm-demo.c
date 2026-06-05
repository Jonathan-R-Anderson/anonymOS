#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <wayland-client.h>

#include "xdg-shell-client-protocol.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum {
    DEFAULT_WIDTH = 640,
    DEFAULT_HEIGHT = 360,
};

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct xdg_wm_base *wm_base;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;
    struct wl_buffer *buffer;
    uint32_t *pixels;
    int width;
    int height;
    int stride;
    int pending_width;
    int pending_height;
    int committed;
    int running;
};

static void log_line(const char *s)
{
    fputs(s, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static int create_memfd(const char *name)
{
    return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC);
}

static void fill_pixels(struct app *app)
{
    const uint32_t bg = 0xff1f4f7a;
    const uint32_t stripe = 0xff28b0a8;
    const uint32_t border = 0xffffd166;

    for (int y = 0; y < app->height; ++y) {
        for (int x = 0; x < app->width; ++x) {
            uint32_t color = bg;
            if (((x + y) / 48) & 1)
                color = stripe;
            if (x < 10 || y < 10 || x >= app->width - 10 || y >= app->height - 10)
                color = border;
            app->pixels[(size_t)y * (size_t)(app->stride / 4) + (size_t)x] = color;
        }
    }
}

static int create_shm_buffer(struct app *app, int width, int height)
{
    app->width = width > 0 ? width : DEFAULT_WIDTH;
    app->height = height > 0 ? height : DEFAULT_HEIGHT;
    app->stride = app->width * 4;
    const size_t size = (size_t)app->stride * (size_t)app->height;

    int fd = create_memfd("epin-g2-wl-shm");
    if (fd < 0) {
        perror("G2SHM: memfd_create");
        return -1;
    }
    if (ftruncate(fd, (off_t)size) < 0) {
        perror("G2SHM: ftruncate");
        close(fd);
        return -1;
    }

    app->pixels = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (app->pixels == MAP_FAILED) {
        perror("G2SHM: mmap");
        close(fd);
        return -1;
    }
    fill_pixels(app);

    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int)size);
    app->buffer = wl_shm_pool_create_buffer(pool, 0, app->width, app->height,
                                            app->stride, WL_SHM_FORMAT_XRGB8888);
    wl_shm_pool_destroy(pool);
    close(fd);

    if (!app->buffer) {
        log_line("G2SHM: wl_shm_pool_create_buffer failed");
        return -1;
    }
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

static void xdg_surface_configure(void *data, struct xdg_surface *surface,
                                  uint32_t serial)
{
    struct app *app = data;
    log_line("G2SHM: xdg_surface configure");
    xdg_surface_ack_configure(surface, serial);

    if (app->committed)
        return;

    int width = app->pending_width > 0 ? app->pending_width : DEFAULT_WIDTH;
    int height = app->pending_height > 0 ? app->pending_height : DEFAULT_HEIGHT;
    if (create_shm_buffer(app, width, height) < 0) {
        app->running = 0;
        return;
    }

    wl_surface_attach(app->surface, app->buffer, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
    app->committed = 1;

    printf("G2SHM: committed wl_shm xdg_toplevel %dx%d -- G2 COMMIT\n",
           app->width, app->height);
    fflush(stdout);
}

static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = xdg_surface_configure,
};

static void registry_global(void *data, struct wl_registry *registry, uint32_t name,
                            const char *interface, uint32_t version)
{
    struct app *app = data;

    if (strcmp(interface, wl_compositor_interface.name) == 0) {
        uint32_t v = version < 4 ? version : 4;
        app->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, v);
        log_line("G2SHM: bound wl_compositor");
    } else if (strcmp(interface, wl_shm_interface.name) == 0) {
        app->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
        log_line("G2SHM: bound wl_shm");
    } else if (strcmp(interface, xdg_wm_base_interface.name) == 0) {
        uint32_t v = version < 6 ? version : 6;
        app->wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface, v);
        xdg_wm_base_add_listener(app->wm_base, &wm_base_listener, app);
        log_line("G2SHM: bound xdg_wm_base");
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

    log_line("G2SHM: starting wl_shm xdg-shell demo");
    app.display = wl_display_connect(NULL);
    if (!app.display) {
        perror("G2SHM: wl_display_connect");
        return 1;
    }
    log_line("G2SHM: connected to Wayland display");

    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    log_line("G2SHM: requesting registry roundtrip");
    int registry_roundtrip = wl_display_roundtrip(app.display);
    printf("G2SHM: registry roundtrip ret=%d\n", registry_roundtrip);
    fflush(stdout);

    if (!app.compositor || !app.shm || !app.wm_base) {
        log_line("G2SHM: missing required Wayland globals");
        return 1;
    }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "EpinAnonymOS G2 wl_shm");
    xdg_toplevel_set_app_id(app.toplevel, "epin-g2-wl-shm");
    xdg_toplevel_set_min_size(app.toplevel, 320, 180);

    wl_surface_commit(app.surface);
    wl_display_flush(app.display);
    log_line("G2SHM: requested xdg_toplevel configure");

    log_line("G2SHM: entering dispatch loop");
    while (app.running) {
        int ret = wl_display_dispatch(app.display);
        if (ret < 0) {
            perror("G2SHM: wl_display_dispatch");
            break;
        }
    }

    return app.committed ? 0 : 1;
}
