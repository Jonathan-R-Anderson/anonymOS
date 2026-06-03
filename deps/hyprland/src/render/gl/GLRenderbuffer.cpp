#include "GLRenderbuffer.hpp"
#include "../Renderer.hpp"
#include "../OpenGL.hpp"
#include "../../Compositor.hpp"
#include "../Framebuffer.hpp"
#include "GLFramebuffer.hpp"
#include "../Renderbuffer.hpp"
#include <hyprutils/memory/SharedPtr.hpp>
#include <hyprutils/signal/Listener.hpp>
#include <hyprutils/signal/Signal.hpp>

#include <dlfcn.h>
#include <drm_fourcc.h>

using namespace Render::GL;

CGLRenderbuffer::~CGLRenderbuffer() {
    if (!g_pCompositor || g_pCompositor->m_isShuttingDown || !g_pHyprRenderer)
        return;

    g_pHyprOpenGL->makeEGLCurrent();

    if (m_framebuffer) {
        GLFB(m_framebuffer)->unbind();
        m_framebuffer->release();
    }

    if (m_rbo)
        glDeleteRenderbuffers(1, &m_rbo);

    if (m_image != EGL_NO_IMAGE_KHR)
        g_pHyprOpenGL->m_proc.eglDestroyImageKHR(g_pHyprOpenGL->m_eglDisplay, m_image);
}

CGLRenderbuffer::CGLRenderbuffer(SP<Aquamarine::IBuffer> buffer, uint32_t format) : IRenderbuffer(buffer, format) {
    auto dma = buffer->dmabuf();

    if (dma.success)
        m_image = g_pHyprOpenGL->createEGLImage(dma);

    if (m_image == EGL_NO_IMAGE_KHR) {
        if (!(buffer->caps() & Aquamarine::BUFFER_CAPABILITY_DATAPTR)) {
            Log::logger->log(Log::ERR, "rb: createEGLImage failed and buffer has no CPU data pointer");
            return;
        }

        const uint32_t fbFormat = format == DRM_FORMAT_ARGB8888 ? DRM_FORMAT_ARGB8888 : DRM_FORMAT_XRGB8888;

        m_framebuffer = makeShared<CGLFramebuffer>();
        Log::logger->log(Log::WARN, "rb: allocating CPU readback framebuffer {}x{} source fmt 0x{:x} fb fmt 0x{:x}", buffer->size.x, buffer->size.y,
                         dma.success ? dma.format : format, fbFormat);
        if (!m_framebuffer->alloc(buffer->size.x, buffer->size.y, fbFormat)) {
            Log::logger->log(Log::ERR, "rb: failed to allocate CPU readback framebuffer");
            return;
        }

        m_needsCPUCopy = true;
        m_good         = true;

        Log::logger->log(Log::WARN, "rb: dmabuf EGLImage import failed; rendering to GL framebuffer with CPU readback");
        return;
    }

    glGenRenderbuffers(1, &m_rbo);
    glBindRenderbuffer(GL_RENDERBUFFER, m_rbo);
    g_pHyprOpenGL->m_proc.glEGLImageTargetRenderbufferStorageOES(GL_RENDERBUFFER, m_image);
    glBindRenderbuffer(GL_RENDERBUFFER, 0);

    m_framebuffer = makeShared<CGLFramebuffer>();
    glGenFramebuffers(1, &GLFB(m_framebuffer)->m_fb);
    GLFB(m_framebuffer)->m_fbAllocated = true;
    m_framebuffer->m_size              = buffer->size;
    m_framebuffer->m_drmFormat         = dma.format;
    m_framebuffer->bind();
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_RENDERBUFFER, m_rbo);

    if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) {
        Log::logger->log(Log::ERR, "rbo: glCheckFramebufferStatus failed");
        return;
    }

    GLFB(m_framebuffer)->unbind();

    m_listeners.destroyBuffer = buffer->events.destroy.listen([this] { g_pHyprRenderer->onRenderbufferDestroy(this); });

    m_good = true;
}

void CGLRenderbuffer::bind() {
    g_pHyprOpenGL->makeEGLCurrent();
    g_pHyprRenderer->bindFB(m_framebuffer);
}

void CGLRenderbuffer::unbind() {
    if (!m_framebuffer)
        return;

    if (m_needsCPUCopy) {
        const auto buffer = m_hlBuffer.lock();
        if (!buffer)
            Log::logger->log(Log::ERR, "rb: cannot CPU-copy renderbuffer, buffer is gone");
        else if (!GLFB(m_framebuffer)->readPixels(buffer))
            Log::logger->log(Log::ERR, "rb: CPU readback into output buffer failed");
        else {
            static bool logged = false;
            if (!logged) {
                Log::logger->log(Log::DEBUG, "rb: CPU readback into output buffer completed");
                logged = true;
            }
        }
    }

    GLFB(m_framebuffer)->unbind();
}

bool CGLRenderbuffer::needsCPUCopy() const {
    return m_needsCPUCopy;
}
