// drm-gl-test.c — R2.4b-step4 end-to-end test: a real GLES2 program that renders
// through Mesa's virgl driver + the kernel virtio-gpu render node.
//
// Uses EGL on the gbm platform over /dev/dri/renderD128, a surfaceless context,
// an FBO clear to red, and glReadPixels. If GL_RENDERER reports "virgl" and the
// pixel comes back red, the full guest GL -> Mesa virgl -> kernel virtgpu uABI ->
// host GPU path works. Dynamic musl (it dlopens virtio_gpu_dri.so at runtime).

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <gbm.h>
#include <xf86drm.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>

// Set the GPU driver-selection + debug env BEFORE main — priority 101 runs before Mesa's static-lib
// constructors, so the loader actually reads them.  setenv() in main() is too late for env vars that
// Mesa reads at library init (which is why the earlier in-main override silently did nothing).
__attribute__((constructor(101)))
static void force_gpu_env(void) {
    // The kernel seeds LIBGL_ALWAYS_SOFTWARE=1 + GALLIUM_DRIVER=softpipe +
    // MESA_LOADER_DRIVER_OVERRIDE=kms_swrast into EVERY program's env (the CPU/pixman desktop needs
    // software Mesa).  Unset all three so this GL test uses the real virgl HW driver on the render
    // node — otherwise Mesa is hard-forced to softpipe regardless of the device.  (Do NOT set
    // MESA_LOADER_DRIVER_OVERRIDE=virtio_gpu — gbm misreads it as a backend name; just let gbm's dri
    // backend resolve the driver from drmGetVersion -> "virtio_gpu".)
    unsetenv("LIBGL_ALWAYS_SOFTWARE");
    unsetenv("GALLIUM_DRIVER");
    unsetenv("MESA_LOADER_DRIVER_OVERRIDE");
    unsetenv("GBM_ALWAYS_SOFTWARE");   // THE one that forces gbm's sw path (dri_screen_create_sw) — must clear it
}

int main(void) {
    printf("[drm-gl-test] env: OVERRIDE=%s GALLIUM_DRIVER=%s LIBGL_ALWAYS_SOFTWARE=%s\n",
           getenv("MESA_LOADER_DRIVER_OVERRIDE"), getenv("GALLIUM_DRIVER"),
           getenv("LIBGL_ALWAYS_SOFTWARE"));

    int fd = open("/dev/dri/renderD128", O_RDWR);
    if (fd < 0) { printf("[drm-gl-test] open renderD128 failed\n"); return 1; }

    // Mesa's loader picks the DRI driver from drmGetVersion()->name; if it fails, gbm silently
    // falls to software. Print exactly what the kernel reports for the render node.
    drmVersionPtr ver = drmGetVersion(fd);
    if (ver) {
        printf("[drm-gl-test] drmGetVersion: name='%s' (name_len=%d) %d.%d\n",
               ver->name ? ver->name : "(null)", ver->name_len,
               ver->version_major, ver->version_minor);
        drmFreeVersion(ver);
    } else {
        printf("[drm-gl-test] drmGetVersion FAILED -> loader can't find a HW driver -> softpipe\n");
    }

    struct gbm_device *gbm = gbm_create_device(fd);
    if (!gbm) { printf("[drm-gl-test] gbm_create_device failed\n"); return 1; }
    PFNEGLGETPLATFORMDISPLAYEXTPROC getPlatformDisplay =
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
    EGLDisplay dpy = getPlatformDisplay
        ? getPlatformDisplay(EGL_PLATFORM_GBM_KHR, gbm, NULL)
        : eglGetDisplay((EGLNativeDisplayType)gbm);

    EGLint maj = 0, min = 0;
    if (!eglInitialize(dpy, &maj, &min)) {
        printf("[drm-gl-test] eglInitialize failed 0x%x\n", eglGetError()); return 1;
    }
    printf("[drm-gl-test] EGL %d.%d vendor=%s\n", maj, min, eglQueryString(dpy, EGL_VENDOR));

    eglBindAPI(EGL_OPENGL_ES_API);
    EGLint cfg_attrs[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,   // gbm window configs; we render surfaceless to an FBO
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8,
        EGL_NONE
    };
    EGLConfig cfg; EGLint n = 0;
    if (!eglChooseConfig(dpy, cfg_attrs, &cfg, 1, &n) || n < 1) {
        printf("[drm-gl-test] eglChooseConfig failed 0x%x\n", eglGetError()); return 1;
    }
    EGLint ctx_attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    EGLContext ctx = eglCreateContext(dpy, cfg, EGL_NO_CONTEXT, ctx_attrs);
    if (ctx == EGL_NO_CONTEXT) {
        printf("[drm-gl-test] eglCreateContext failed 0x%x\n", eglGetError()); return 1;
    }
    if (!eglMakeCurrent(dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, ctx)) {  // surfaceless
        printf("[drm-gl-test] eglMakeCurrent(surfaceless) failed 0x%x\n", eglGetError()); return 1;
    }

    printf("[drm-gl-test] GL_RENDERER=%s\n", (const char*)glGetString(GL_RENDERER));
    printf("[drm-gl-test] GL_VERSION=%s\n",  (const char*)glGetString(GL_VERSION));

    // Render-to-texture: clear RED, read back.
    GLuint tex = 0, fbo = 0;
    glGenTextures(1, &tex);
    glBindTexture(GL_TEXTURE_2D, tex);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 64, 64, 0, GL_RGBA, GL_UNSIGNED_BYTE, 0);
    glGenFramebuffers(1, &fbo);
    glBindFramebuffer(GL_FRAMEBUFFER, fbo);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tex, 0);
    if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
        printf("[drm-gl-test] FBO incomplete 0x%x\n", glCheckFramebufferStatus(GL_FRAMEBUFFER));
    glViewport(0, 0, 64, 64);
    glClearColor(1.0f, 0.0f, 0.0f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    glFinish();

    unsigned char px[4] = {0};
    glReadPixels(0, 0, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, px);
    printf("[drm-gl-test] readback RGBA = %02x %02x %02x %02x\n", px[0], px[1], px[2], px[3]);

    if (px[0] == 0xff && px[1] == 0x00 && px[2] == 0x00 && px[3] == 0xff)
        printf("[drm-gl-test] RESULT: PASS -- GL rendered RED via Mesa virgl + the node\n");
    else
        printf("[drm-gl-test] RESULT: FAIL -- readback not red\n");
    return 0;
}
