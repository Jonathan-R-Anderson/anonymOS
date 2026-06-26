// gl-wl-test.c — R3 foundation: a minimal EGL/GLES2 Wayland client.
//
// Proves the client-side GPU path: connect to Weston, make an EGL *window* surface
// on the Wayland platform (so Mesa renders into a virgl resource and shares it with
// the compositor as a dma-buf/wl_drm buffer), render a GLES2 triangle on the GPU,
// and eglSwapBuffers → Weston's GL renderer composites it. If a coloured triangle
// shows up in the desktop, a guest program renders on the host GPU AND hands the
// result to the GPU compositor — the basis for a GPU-rendered terminal (R3/ratty).
//
// Dynamic musl (dlopens virtio_gpu_dri.so); xdg-shell + wayland-egl + EGL/GLESv2.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wayland-client.h>
#include <wayland-egl.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include "xdg-shell-client-protocol.h"

// The kernel seeds LIBGL_ALWAYS_SOFTWARE / GALLIUM_DRIVER=softpipe / GBM_ALWAYS_SOFTWARE /
// MESA_LOADER_DRIVER_OVERRIDE=kms_swrast into every non-weston program. Clear them (before
// Mesa's lib-init, priority 101) so this client renders on virgl (the GPU), not softpipe.
__attribute__((constructor(101)))
static void use_gpu(void) {
    unsetenv("LIBGL_ALWAYS_SOFTWARE");
    unsetenv("GALLIUM_DRIVER");
    unsetenv("MESA_LOADER_DRIVER_OVERRIDE");
    unsetenv("GBM_ALWAYS_SOFTWARE");
}

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct xdg_wm_base *wm_base;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;
    struct wl_egl_window *egl_window;
    EGLDisplay egl_dpy;
    EGLContext egl_ctx;
    EGLSurface egl_surf;
    GLuint prog;
    int width, height;
    int configured, running, frames;
};

static void wm_base_ping(void *d, struct xdg_wm_base *b, uint32_t s){ (void)d; xdg_wm_base_pong(b,s); }
static const struct xdg_wm_base_listener wm_base_listener = {.ping = wm_base_ping};

static void top_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s){
    struct app *a = d; (void)t; (void)s;
    if (w > 0 && h > 0) { a->width = w; a->height = h; }
}
static void top_close(void *d, struct xdg_toplevel *t){ struct app *a=d; (void)t; a->running=0; }
static void top_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h){ (void)d;(void)t;(void)w;(void)h; }
static void top_caps(void *d, struct xdg_toplevel *t, struct wl_array *c){ (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure = top_configure, .close = top_close,
    .configure_bounds = top_bounds, .wm_capabilities = top_caps,
};

static void render(struct app *a);

static void xdg_surface_configure(void *d, struct xdg_surface *s, uint32_t serial){
    struct app *a = d;
    xdg_surface_ack_configure(s, serial);
    a->configured = 1;
    render(a);   // first paint after the compositor configures us
}
static const struct xdg_surface_listener xdg_surface_listener = {.configure = xdg_surface_configure};

static const struct wl_callback_listener frame_listener;
static void frame_done(void *d, struct wl_callback *cb, uint32_t t){
    struct app *a = d; (void)t; wl_callback_destroy(cb); render(a);
}
static const struct wl_callback_listener frame_listener = {.done = frame_done};

static GLuint mk_shader(GLenum type, const char *src){
    GLuint s = glCreateShader(type);
    glShaderSource(s, 1, &src, NULL); glCompileShader(s);
    GLint ok = 0; glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
    if (!ok) { char log[512]; glGetShaderInfoLog(s, sizeof log, NULL, log); printf("[gl-wl] shader: %s\n", log); }
    return s;
}

static void render(struct app *a){
    if (!a->configured) return;
    eglMakeCurrent(a->egl_dpy, a->egl_surf, a->egl_surf, a->egl_ctx);
    glViewport(0, 0, a->width, a->height);
    // animated teal background so it's obviously live GPU output
    float p = (a->frames % 120) / 120.0f;
    glClearColor(0.0f, 0.30f + 0.2f * p, 0.40f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    // a coloured triangle, rendered by the GPU
    glUseProgram(a->prog);
    static const GLfloat verts[] = { 0.0f,0.6f,  -0.6f,-0.5f,  0.6f,-0.5f };
    static const GLfloat cols[]  = { 1,0,0,  0,1,0,  0,0.4f,1 };
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, verts); glEnableVertexAttribArray(0);
    glVertexAttribPointer(1, 3, GL_FLOAT, GL_FALSE, 0, cols);  glEnableVertexAttribArray(1);
    glDrawArrays(GL_TRIANGLES, 0, 3);

    struct wl_callback *cb = wl_surface_frame(a->surface);
    wl_callback_add_listener(cb, &frame_listener, a);
    eglSwapBuffers(a->egl_dpy, a->egl_surf);   // present to Weston (dma-buf/wl_drm)
    if (a->frames == 0) {
        printf("[gl-wl] GL_RENDERER=%s\n", (const char*)glGetString(GL_RENDERER));
        printf("[gl-wl] first frame presented to the compositor\n");
    }
    a->frames++;
}

static void registry_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver){
    struct app *a = d;
    if (strcmp(iface, wl_compositor_interface.name) == 0)
        a->compositor = wl_registry_bind(r, name, &wl_compositor_interface, ver < 4 ? ver : 4);
    else if (strcmp(iface, xdg_wm_base_interface.name) == 0) {
        a->wm_base = wl_registry_bind(r, name, &xdg_wm_base_interface, ver < 6 ? ver : 6);
        xdg_wm_base_add_listener(a->wm_base, &wm_base_listener, a);
    }
}
static void registry_remove(void *d, struct wl_registry *r, uint32_t n){ (void)d;(void)r;(void)n; }
static const struct wl_registry_listener registry_listener = {.global = registry_global, .global_remove = registry_remove};

int main(void){
    static struct app a; memset(&a, 0, sizeof a);
    a.running = 1; a.width = 640; a.height = 480;

    a.display = wl_display_connect(NULL);
    if (!a.display) { printf("[gl-wl] wl_display_connect failed\n"); return 1; }
    a.registry = wl_display_get_registry(a.display);
    wl_registry_add_listener(a.registry, &registry_listener, &a);
    wl_display_roundtrip(a.display);
    if (!a.compositor || !a.wm_base) { printf("[gl-wl] missing wl_compositor/xdg_wm_base\n"); return 1; }

    // EGL on the Wayland platform — Mesa renders into a virgl resource and shares it.
    PFNEGLGETPLATFORMDISPLAYEXTPROC getPlatformDisplay =
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
    a.egl_dpy = getPlatformDisplay
        ? getPlatformDisplay(EGL_PLATFORM_WAYLAND_EXT, a.display, NULL)
        : eglGetDisplay((EGLNativeDisplayType)a.display);
    EGLint maj, min;
    if (!eglInitialize(a.egl_dpy, &maj, &min)) { printf("[gl-wl] eglInitialize failed 0x%x\n", eglGetError()); return 1; }
    printf("[gl-wl] EGL %d.%d vendor=%s\n", maj, min, eglQueryString(a.egl_dpy, EGL_VENDOR));
    eglBindAPI(EGL_OPENGL_ES_API);
    EGLint cfg_attrs[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8, EGL_NONE
    };
    EGLConfig cfg; EGLint n = 0;
    if (!eglChooseConfig(a.egl_dpy, cfg_attrs, &cfg, 1, &n) || n < 1) { printf("[gl-wl] eglChooseConfig failed\n"); return 1; }
    EGLint ctx_attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    a.egl_ctx = eglCreateContext(a.egl_dpy, cfg, EGL_NO_CONTEXT, ctx_attrs);
    if (a.egl_ctx == EGL_NO_CONTEXT) { printf("[gl-wl] eglCreateContext failed\n"); return 1; }

    a.surface = wl_compositor_create_surface(a.compositor);
    a.xdg_surface = xdg_wm_base_get_xdg_surface(a.wm_base, a.surface);
    xdg_surface_add_listener(a.xdg_surface, &xdg_surface_listener, &a);
    a.toplevel = xdg_surface_get_toplevel(a.xdg_surface);
    xdg_toplevel_add_listener(a.toplevel, &toplevel_listener, &a);
    xdg_toplevel_set_title(a.toplevel, "GL Wayland Test");
    xdg_toplevel_set_app_id(a.toplevel, "epin-gl-wl-test");

    a.egl_window = wl_egl_window_create(a.surface, a.width, a.height);
    a.egl_surf = eglCreateWindowSurface(a.egl_dpy, cfg, (EGLNativeWindowType)a.egl_window, NULL);
    if (a.egl_surf == EGL_NO_SURFACE) { printf("[gl-wl] eglCreateWindowSurface failed 0x%x\n", eglGetError()); return 1; }

    eglMakeCurrent(a.egl_dpy, a.egl_surf, a.egl_surf, a.egl_ctx);
    GLuint vs = mk_shader(GL_VERTEX_SHADER,
        "attribute vec2 pos; attribute vec3 col; varying vec3 vc;"
        "void main(){ vc=col; gl_Position=vec4(pos,0.0,1.0); }");
    GLuint fs = mk_shader(GL_FRAGMENT_SHADER,
        "precision mediump float; varying vec3 vc; void main(){ gl_FragColor=vec4(vc,1.0); }");
    a.prog = glCreateProgram();
    glAttachShader(a.prog, vs); glAttachShader(a.prog, fs);
    glBindAttribLocation(a.prog, 0, "pos"); glBindAttribLocation(a.prog, 1, "col");
    glLinkProgram(a.prog);

    wl_surface_commit(a.surface);
    wl_display_flush(a.display);

    while (a.running && wl_display_dispatch(a.display) >= 0) { }
    return 0;
}
