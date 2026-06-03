#include "GLFramebuffer.hpp"
#include "../OpenGL.hpp"
#include "../Renderer.hpp"
#include "macros.hpp"
#include "../Framebuffer.hpp"
#include <hyprgraphics/egl/Egl.hpp>

using namespace Hyprgraphics::Egl;
using namespace Render::GL;

CGLFramebuffer::CGLFramebuffer() : IFramebuffer() {}
CGLFramebuffer::CGLFramebuffer(const std::string& name) : IFramebuffer(name) {}

bool CGLFramebuffer::internalAlloc(int w, int h, uint32_t drmFormat) {
    g_pHyprOpenGL->makeEGLCurrent();

    if (!m_tex) {
        m_tex = g_pHyprRenderer->createTexture();
        m_tex->allocate({w, h}, drmFormat);
        m_tex->bind();
        m_tex->setTexParameter(GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        m_tex->setTexParameter(GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        m_tex->setTexParameter(GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        m_tex->setTexParameter(GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    }

    if (!m_fbAllocated) {
        glGenFramebuffers(1, &m_fb);
        m_fbAllocated = true;
    }

    const auto format = getPixelFormatFromDRM(drmFormat);
    m_tex->bind();
    glTexImage2D(GL_TEXTURE_2D, 0, format->glInternalFormat ? format->glInternalFormat : format->glFormat, w, h, 0, format->glFormat, format->glType, nullptr);
    glBindFramebuffer(GL_FRAMEBUFFER, m_fb);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, m_tex->m_texID, 0);

    if (m_mirrorTex) {
        const auto format = getPixelFormatFromDRM(m_mirrorTex->m_drmFormat);
        m_mirrorTex->bind();
        glTexImage2D(GL_TEXTURE_2D, 0, format->glInternalFormat ? format->glInternalFormat : format->glFormat, w, h, 0, format->glFormat, format->glType, nullptr);
        glBindFramebuffer(GL_FRAMEBUFFER, m_fb);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT1, GL_TEXTURE_2D, m_mirrorTex->m_texID, 0);
    } else
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT1, GL_TEXTURE_2D, 0, 0);

    if (m_stencilTex && m_stencilTex->ok()) {
        m_stencilTex->bind();
        glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH24_STENCIL8, w, h, 0, GL_DEPTH_STENCIL, GL_UNSIGNED_INT_24_8, nullptr);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT, GL_TEXTURE_2D, m_stencilTex->m_texID, 0);

        glDisable(GL_DEPTH_TEST);
        glDepthMask(GL_FALSE);
    }

    auto status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
    if (status != GL_FRAMEBUFFER_COMPLETE) {
        const auto err = glGetError();
        Log::logger->log(Log::ERR, "Framebuffer \"{}\" incomplete, couldn't create! (FB status: {}, GL Error: 0x{:x})", m_name, status, sc<int>(err));

        if (m_stencilTex && m_stencilTex->ok())
            m_stencilTex->unbind();

        glBindTexture(GL_TEXTURE_2D, 0);
        glBindFramebuffer(GL_FRAMEBUFFER, 0);
        return false;
    }

    if (m_stencilTex && m_stencilTex->ok())
        m_stencilTex->unbind();

    Log::logger->log(Log::DEBUG, "Framebuffer \"{}\" created, status {}", m_name, status);

    glBindTexture(GL_TEXTURE_2D, 0);
    glBindFramebuffer(GL_FRAMEBUFFER, 0);

    return true;
}

void CGLFramebuffer::addStencil(SP<ITexture> tex) {
    if (m_stencilTex == tex)
        return;

    RASSERT(!m_fbAllocated, "Should add stencil tex prior to FB allocation")
    m_stencilTex = tex;
}

void CGLFramebuffer::bind() {
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, m_fb);

    if (g_pHyprOpenGL) {
        const auto& size = g_pHyprRenderer->m_renderData.pMonitor ? g_pHyprRenderer->m_renderData.pMonitor->m_pixelSize : m_size;
        g_pHyprOpenGL->setViewport(0, 0, size.x, size.y);
    } else
        glViewport(0, 0, m_size.x, m_size.y);
}

void CGLFramebuffer::unbind() {
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
}

void CGLFramebuffer::release() {
    if (m_fbAllocated) {
        glBindFramebuffer(GL_FRAMEBUFFER, m_fb);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, 0, 0);
        if (m_mirrorTex)
            glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT1, GL_TEXTURE_2D, 0, 0);
        glBindFramebuffer(GL_FRAMEBUFFER, 0);

        glDeleteFramebuffers(1, &m_fb);
        m_fbAllocated = false;
        m_fb          = 0;
    }

    if (m_tex)
        m_tex.reset();

    m_size = Vector2D();
}

bool CGLFramebuffer::readPixels(CHLBufferReference buffer, uint32_t offsetX, uint32_t offsetY, uint32_t width, uint32_t height) {
    const SP<Aquamarine::IBuffer> aqBuffer = buffer.m_buffer;
    return readPixels(aqBuffer, offsetX, offsetY, width, height);
}

bool CGLFramebuffer::readPixels(SP<Aquamarine::IBuffer> buffer, uint32_t offsetX, uint32_t offsetY, uint32_t width, uint32_t height) {
    if (!buffer) {
        LOGM(Log::ERR, "Can't copy: buffer is null");
        return false;
    }

    auto shm                      = buffer->shm();
    auto [pixelData, fmt, bufLen] = buffer->beginDataPtr(0);

    if (!pixelData) {
        LOGM(Log::ERR, "Can't copy: buffer has no data pointer");
        buffer->endDataPtr();
        return false;
    }

    const uint32_t drmFormat = shm.success ? shm.format : fmt;
    uint32_t       stride    = shm.success ? shm.stride : 0;

    if (!shm.success) {
        const auto dma = buffer->dmabuf();
        if (dma.success)
            stride = dma.strides[0];
    }

    const auto PFORMAT = getPixelFormatFromDRM(drmFormat);
    if (!PFORMAT) {
        LOGM(Log::ERR, "Can't copy: failed to find a pixel format");
        buffer->endDataPtr();
        return false;
    }

    const uint32_t copyWidth  = width > 0 ? width : sc<uint32_t>(m_size.x);
    const uint32_t copyHeight = height > 0 ? height : sc<uint32_t>(m_size.y);
    const uint32_t packStride = minStride(PFORMAT, copyWidth);

    if (!stride)
        stride = packStride;

    if (stride < packStride) {
        LOGM(Log::ERR, "Can't copy: destination stride {} is smaller than packed stride {}", stride, packStride);
        buffer->endDataPtr();
        return false;
    }

    if (bufLen < sc<size_t>(stride) * copyHeight) {
        LOGM(Log::ERR, "Can't copy: destination buffer too small ({} < {})", bufLen, sc<size_t>(stride) * copyHeight);
        buffer->endDataPtr();
        return false;
    }

    g_pHyprOpenGL->makeEGLCurrent();
    glBindFramebuffer(GL_READ_FRAMEBUFFER, getFBID());
    bind();

    glPixelStorei(GL_PACK_ALIGNMENT, 1);

    int glFormat = PFORMAT->glFormat;

    static auto stripSwizzleAlpha = [](std::array<GLint, 4> arr) {
        arr[3] = GL_ONE;
        return arr;
    };

    if (PFORMAT->swizzle.has_value()) {
        if (stripSwizzleAlpha(*PFORMAT->swizzle) == stripSwizzleAlpha(SWIZZLE_RGBA))
            glFormat = GL_RGBA;
        else if (stripSwizzleAlpha(*PFORMAT->swizzle) == stripSwizzleAlpha(SWIZZLE_BGRA))
            glFormat = GL_BGRA_EXT;
        else {
            LOGM(Log::ERR, "Copied frame via shm might be broken or color flipped");
            glFormat = GL_RGBA;
        }
    } else if (glFormat == GL_RGBA)
        glFormat = GL_BGRA_EXT;

    // This could be optimized by using a pixel buffer object to make this async,
    // but really clients should just use a dma buffer anyways.
    if (packStride == stride) {
        glReadPixels(offsetX, offsetY, copyWidth, copyHeight, glFormat, PFORMAT->glType, pixelData);
    } else {
        for (size_t i = 0; i < copyHeight; ++i) {
            uint32_t y = i;
            glReadPixels(offsetX, offsetY + y, copyWidth, 1, glFormat, PFORMAT->glType, pixelData + i * stride);
        }
    }

    unbind();
    glPixelStorei(GL_PACK_ALIGNMENT, 4);

    glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
    buffer->endDataPtr();
    return true;
}

CGLFramebuffer::~CGLFramebuffer() {
    release();
}

GLuint CGLFramebuffer::getFBID() {
    return m_fbAllocated ? m_fb : 0;
}

void CGLFramebuffer::invalidate(const std::vector<GLenum>& attachments) {
    if (!isAllocated())
        return;

    glInvalidateFramebuffer(GL_FRAMEBUFFER, attachments.size(), attachments.data());
    m_cleared = false;
}

void CGLFramebuffer::clearAfterInvalidation() {
    if (m_cleared)
        return;

    m_cleared = true;
    glClearColor(0, 0, 0, 0);
    g_pHyprOpenGL->scissor(nullptr);
    glClear(GL_COLOR_BUFFER_BIT);
}
