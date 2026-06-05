#include "GLRenderer.hpp"
#include <cstdlib>
#include <fcntl.h>      // EpinAnonymOS G5: report window rects to the kernel
#include <unistd.h>
#include <sys/ioctl.h>
#include "decorations/CHyprInnerGlowDecoration.hpp"
#include <aquamarine/output/Output.hpp>
#include "../config/ConfigValue.hpp"
#include "../managers/CursorManager.hpp"
#include "../managers/PointerManager.hpp"
#include "../protocols/SessionLock.hpp"
#include "../protocols/LayerShell.hpp"
#include "../protocols/PresentationTime.hpp"
#include "../protocols/core/DataDevice.hpp"
#include "../protocols/core/Compositor.hpp"
#include "../debug/Overlay.hpp"
#include "../helpers/Monitor.hpp"
#include "pass/TexPassElement.hpp"
#include "pass/SurfacePassElement.hpp"
#include "../debug/log/Logger.hpp"
#include "../protocols/types/ContentType.hpp"
#include "OpenGL.hpp"
#include "Renderer.hpp"
#include "../Compositor.hpp"              // EpinAnonymOS G5: g_pCompositor->m_windows
#include "../desktop/view/Window.hpp"
#include "./gl/GLElementRenderer.hpp"
#include "./gl/GLFramebuffer.hpp"
#include "./gl/GLTexture.hpp"

#include <cstdint>
#include <hyprutils/memory/SharedPtr.hpp>
#include <hyprutils/memory/UniquePtr.hpp>
#include <hyprutils/utils/ScopeGuard.hpp>
using namespace Hyprutils::Utils;
using namespace Hyprutils::OS;
using enum NContentType::eContentType;
using namespace NColorManagement;
using namespace Render;
using namespace Render::GL;

extern "C" {
#include <xf86drm.h>
}

CHyprGLRenderer::CHyprGLRenderer() : IHyprRenderer(), m_elementRenderer(makeUnique<CGLElementRenderer>()) {}

IHyprRenderer::eType CHyprGLRenderer::type() {
    return RT_GL;
}

void CHyprGLRenderer::initRender() {
    g_pHyprOpenGL->makeEGLCurrent();
    g_pHyprRenderer->m_renderData.pMonitor = renderData().pMonitor;
}

bool CHyprGLRenderer::initRenderBuffer(SP<Aquamarine::IBuffer> buffer, uint32_t fmt) {
    try {
        m_currentRenderbuffer = getOrCreateRenderbuffer(m_currentBuffer, fmt);
    } catch (std::exception& e) {
        Log::logger->log(Log::ERR, "getOrCreateRenderbuffer failed for {}", NFormatUtils::drmFormatName(fmt));
        return false;
    }

    return m_currentRenderbuffer;
}

bool CHyprGLRenderer::beginFullFakeRenderInternal(PHLMONITOR pMonitor, CRegion& damage, SP<IFramebuffer> fb, bool simple) {
    initRender();

    RASSERT(fb, "Cannot render FULL_FAKE without a provided fb!");
    bindFB(fb);
    if (simple)
        g_pHyprOpenGL->beginSimple(pMonitor, damage, nullptr, fb);
    else
        g_pHyprOpenGL->begin(pMonitor, damage, fb);
    return true;
}

bool CHyprGLRenderer::beginRenderInternal(PHLMONITOR pMonitor, CRegion& damage, bool simple) {

    m_currentRenderbuffer->bind();
    if (simple)
        g_pHyprOpenGL->beginSimple(pMonitor, damage, m_currentRenderbuffer);
    else
        g_pHyprOpenGL->begin(pMonitor, damage);

    return true;
}

void CHyprGLRenderer::endRender(const std::function<void()>& renderingDoneCallback) {
    const auto  PMONITOR           = g_pHyprRenderer->m_renderData.pMonitor;
    static auto PNVIDIAANTIFLICKER = CConfigValue<Config::INTEGER>("opengl:nvidia_anti_flicker");

    auto cleanup = CScopeGuard([this]() {
        if (m_currentRenderbuffer)
            m_currentRenderbuffer->unbind();
        m_currentRenderbuffer = nullptr;
        m_currentBuffer       = nullptr;
    });

    // EpinAnonymOS: default = the HOS clear-only shortcut (deterministic dark
    // frame), which is verified working and fits in 512 MB.  Rendering the REAL
    // scene (wallpaper/windows) via m_renderPass.render() on the CPU-readback path
    // works conceptually (unbind() reads it back to the dumb buffer) but currently
    // OOMs: a compositor re-init constructs 2-3 instances and the kernel's physical
    // allocator never frees, so the heavier scene render exhausts RAM before a
    // frame completes.  Opt in with HOS_SCENE_RENDER=1 once that memory issue is
    // fixed (free list / single-compositor).
    // EpinAnonymOS GUI roadmap G5: report mapped window rectangles (+ owning pid)
    // to the kernel so the trusted present blit can draw identity-coloured borders.
    // The compositor only reports geometry; the kernel paints the border, so apps
    // cannot spoof it.
    if (PMONITOR) {
        struct SHosWinRect {
            int32_t  x, y, w, h;
            uint32_t pid;
        };
        struct SHosWindows {
            uint32_t   count;
            uint32_t   pad;
            SHosWinRect rects[16];
        };
        static constexpr unsigned long HOS_IOCTL_WINDOWS = _IOW('d', 0xF1, SHosWindows);
        static int                     hosFD             = open("/dev/dri/card0", O_RDWR | O_CLOEXEC);
        if (hosFD >= 0) {
            SHosWindows wins{};
            const auto  MPOS = PMONITOR->m_position;
            for (auto const& w : g_pCompositor->m_windows) {
                if (wins.count >= 16)
                    break;
                if (!w || !w->m_isMapped)
                    continue;
                auto P = w->m_realPosition->value();
                auto S = w->m_realSize->value();
                if (S.x <= 0 || S.y <= 0) { // animation not settled yet → fall back
                    P = w->m_position;
                    S = w->m_size;
                }
                if (S.x <= 0 || S.y <= 0)
                    continue;
                auto& r = wins.rects[wins.count++];
                r.x     = static_cast<int32_t>(P.x - MPOS.x);
                r.y     = static_cast<int32_t>(P.y - MPOS.y);
                r.w     = static_cast<int32_t>(S.x);
                r.h     = static_cast<int32_t>(S.y);
                r.pid   = static_cast<uint32_t>(w->getPID());
            }
            ioctl(hosFD, HOS_IOCTL_WINDOWS, &wins);
        }
    }

    static const bool HOS_SCENE_RENDER = std::getenv("HOS_SCENE_RENDER") != nullptr;
    if (!HOS_SCENE_RENDER && m_renderMode == RENDER_MODE_NORMAL && m_currentRenderbuffer && m_currentRenderbuffer->needsCPUCopy()) {
        static bool logged = false;
        if (!logged) {
            Log::logger->log(Log::WARN, "renderer: using HOS CPU-readback clear frame path");
            logged = true;
        }

        m_renderPass.clear();
        g_pHyprRenderer->bindFB(m_currentRenderbuffer->getFB());
        g_pHyprOpenGL->scissor(nullptr);
        glClearColor(0.06F, 0.09F, 0.12F, 1.F);
        glClear(GL_COLOR_BUFFER_BIT);
        g_pHyprRenderer->m_renderData.damage = CRegion{0, 0, sc<int>(PMONITOR->m_pixelSize.x), sc<int>(PMONITOR->m_pixelSize.y)};
        PMONITOR->m_output->state->setBuffer(m_currentBuffer);

        if ((isNvidia() && *PNVIDIAANTIFLICKER) || isSoftware())
            glFinish();
        else
            glFlush();

        m_usedAsyncBuffers.clear();
        if (renderingDoneCallback)
            renderingDoneCallback();

        return;
    }

    g_pHyprRenderer->m_renderData.damage = m_renderPass.render(g_pHyprRenderer->m_renderData.damage);

    if (m_renderMode != RENDER_MODE_TO_BUFFER_READ_ONLY)
        g_pHyprOpenGL->end();
    else {
        g_pHyprRenderer->m_renderData.pMonitor.reset();
        g_pHyprRenderer->m_renderData.mouseZoomFactor   = 1.f;
        g_pHyprRenderer->m_renderData.mouseZoomUseMouse = true;
    }

    if (m_renderMode == RENDER_MODE_FULL_FAKE)
        return;

    if (m_renderMode == RENDER_MODE_NORMAL)
        PMONITOR->m_output->state->setBuffer(m_currentBuffer);

    if (!explicitSyncSupported()) {
        Log::logger->log(Log::TRACE, "renderer: Explicit sync unsupported, falling back to implicit in endRender");

        // nvidia doesn't have implicit sync, so we have to explicitly wait here, llvmpipe and other software renderer seems to bug out aswell.
        if ((isNvidia() && *PNVIDIAANTIFLICKER) || isSoftware())
            glFinish();
        else
            glFlush(); // mark an implicit sync point

        m_usedAsyncBuffers.clear(); // release all buffer refs and hope implicit sync works
        if (renderingDoneCallback)
            renderingDoneCallback();

        return;
    }

    auto eglSync = createSyncFDManager();
    if LIKELY (eglSync && eglSync->isValid()) {
        for (auto const& buf : m_usedAsyncBuffers) {
            for (const auto& releaser : buf->m_syncReleasers) {
                releaser->addSyncFileFd(eglSync->fd());
            }
        }

        // release buffer refs with release points now, since syncReleaser handles actual buffer release based on EGLSync
        std::erase_if(m_usedAsyncBuffers, [](const auto& buf) { return !buf->m_syncReleasers.empty(); });

        // release buffer refs without release points when EGLSync sync_file/fence is signalled
        g_pEventLoopManager->doOnReadable(eglSync->fd().duplicate(), [renderingDoneCallback, prevbfs = std::move(m_usedAsyncBuffers)]() mutable {
            prevbfs.clear();
            if (renderingDoneCallback)
                renderingDoneCallback();
        });
        m_usedAsyncBuffers.clear();

        if (m_renderMode == RENDER_MODE_NORMAL) {
            PMONITOR->m_inFence = eglSync->takeFd();
            PMONITOR->m_output->state->setExplicitInFence(PMONITOR->m_inFence.get());
        }
    } else {
        Log::logger->log(Log::ERR, "renderer: Explicit sync failed, releasing resources");

        m_usedAsyncBuffers.clear(); // release all buffer refs and hope implicit sync works
        if (renderingDoneCallback)
            renderingDoneCallback();
    }
}

void CHyprGLRenderer::renderOffToMain(SP<IFramebuffer> off) {
    g_pHyprOpenGL->renderOffToMain(off);
}

SP<IRenderbuffer> CHyprGLRenderer::getOrCreateRenderbufferInternal(SP<Aquamarine::IBuffer> buffer, uint32_t fmt) {
    g_pHyprOpenGL->makeEGLCurrent();
    return makeShared<CGLRenderbuffer>(buffer, fmt);
}

UP<ISyncFDManager> CHyprGLRenderer::createSyncFDManager() {
    return CEGLSync::create();
}

SP<ITexture> CHyprGLRenderer::createStencilTexture(const int width, const int height) {
    g_pHyprOpenGL->makeEGLCurrent();
    auto tex = makeShared<CGLTexture>();
    tex->allocate({width, height});

    return tex;
}

SP<ITexture> CHyprGLRenderer::createTexture(bool opaque) {
    g_pHyprOpenGL->makeEGLCurrent();
    return makeShared<CGLTexture>(opaque);
}

SP<ITexture> CHyprGLRenderer::createTexture(uint32_t drmFormat, uint8_t* pixels, uint32_t stride, const Vector2D& size, bool keepDataCopy, bool opaque) {
    g_pHyprOpenGL->makeEGLCurrent();
    return makeShared<CGLTexture>(drmFormat, pixels, stride, size, keepDataCopy, opaque);
}

SP<ITexture> CHyprGLRenderer::createTexture(const Aquamarine::SDMABUFAttrs& attrs, bool opaque) {
    g_pHyprOpenGL->makeEGLCurrent();
    const auto image = g_pHyprOpenGL->createEGLImage(attrs);
    if (!image)
        return nullptr;
    return makeShared<CGLTexture>(attrs, image, opaque);
}

SP<ITexture> CHyprGLRenderer::createTexture(const int width, const int height, unsigned char* const data) {
    g_pHyprOpenGL->makeEGLCurrent();
    SP<ITexture> tex = makeShared<CGLTexture>();

    tex->allocate({width, height}, DRM_FORMAT_ARGB8888); // FIXME assume DRM_FORMAT_ARGB8888

    tex->m_size = {width, height};
    // copy the data to an OpenGL texture we have
    const GLint glFormat = GL_RGBA;
    const GLint glType   = GL_UNSIGNED_BYTE;

    tex->bind();
    tex->setTexParameter(GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    tex->setTexParameter(GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    tex->setTexParameter(GL_TEXTURE_SWIZZLE_R, GL_BLUE);
    tex->setTexParameter(GL_TEXTURE_SWIZZLE_B, GL_RED);

    glTexImage2D(GL_TEXTURE_2D, 0, glFormat, tex->m_size.x, tex->m_size.y, 0, glFormat, glType, data);
    tex->unbind();

    return tex;
}

SP<ITexture> CHyprGLRenderer::createTexture(cairo_surface_t* cairo) {
    g_pHyprOpenGL->makeEGLCurrent();
    const auto CAIROFORMAT = cairo_image_surface_get_format(cairo);
    auto       tex         = makeShared<CGLTexture>();

    tex->allocate({cairo_image_surface_get_width(cairo), cairo_image_surface_get_height(cairo)});

    const GLint glIFormat = CAIROFORMAT == CAIRO_FORMAT_RGB96F ? GL_RGB32F : GL_RGBA;
    const GLint glFormat  = CAIROFORMAT == CAIRO_FORMAT_RGB96F ? GL_RGB : GL_RGBA;
    const GLint glType    = CAIROFORMAT == CAIRO_FORMAT_RGB96F ? GL_FLOAT : GL_UNSIGNED_BYTE;

    const auto  DATA = cairo_image_surface_get_data(cairo);
    tex->bind();
    tex->setTexParameter(GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    tex->setTexParameter(GL_TEXTURE_MIN_FILTER, GL_LINEAR);

    if (CAIROFORMAT != CAIRO_FORMAT_RGB96F) {
        tex->setTexParameter(GL_TEXTURE_SWIZZLE_R, GL_BLUE);
        tex->setTexParameter(GL_TEXTURE_SWIZZLE_B, GL_RED);
        tex->m_drmFormat = DRM_FORMAT_ARGB8888;
    }

    glTexImage2D(GL_TEXTURE_2D, 0, glIFormat, tex->m_size.x, tex->m_size.y, 0, glFormat, glType, DATA);

    return tex;
}

SP<ITexture> CHyprGLRenderer::createTexture(std::span<const float> lut3D, size_t N) {
    g_pHyprOpenGL->makeEGLCurrent();
    return makeShared<CGLTexture>(lut3D, N);
}

bool CHyprGLRenderer::explicitSyncSupported() {
    return g_pHyprOpenGL->explicitSyncSupported();
}

std::vector<SDRMFormat> CHyprGLRenderer::getDRMFormats() {
    return g_pHyprOpenGL->getDRMFormats();
}

std::vector<uint64_t> CHyprGLRenderer::getDRMFormatModifiers(DRMFormat format) {
    return g_pHyprOpenGL->getDRMFormatModifiers(format);
}

SP<IFramebuffer> CHyprGLRenderer::createFB(const std::string& name) {
    g_pHyprOpenGL->makeEGLCurrent();
    return makeShared<CGLFramebuffer>(name);
}

void CHyprGLRenderer::disableScissor() {
    g_pHyprOpenGL->scissor(nullptr);
}

void CHyprGLRenderer::blend(bool enabled) {
    g_pHyprOpenGL->blend(enabled);
}

void CHyprGLRenderer::drawShadow(const CBox& box, int round, float roundingPower, int range, CHyprColor color, float a) {
    g_pHyprOpenGL->renderRoundedShadow(box, round, roundingPower, range, color, a);
}

SP<ITexture> CHyprGLRenderer::blurFramebuffer(SP<IFramebuffer> source, float a, CRegion* originalDamage) {
    auto src = GLFB(source);
    return g_pHyprOpenGL->blurFramebufferWithDamage(a, originalDamage, *src)->getTexture();
}

void CHyprGLRenderer::setViewport(int x, int y, int width, int height) {
    g_pHyprOpenGL->setViewport(x, y, width, height);
}

bool CHyprGLRenderer::reloadShaders(const std::string& path) {
    return g_pHyprOpenGL->initShaders(path);
}

SP<ITexture> CHyprGLRenderer::getBlurTexture(PHLMONITORREF pMonitor) {
    return pMonitor->resources()->m_blurFB->getTexture();
}

void CHyprGLRenderer::unsetEGL() {
    if (!g_pHyprOpenGL)
        return;

    eglMakeCurrent(g_pHyprOpenGL->m_eglDisplay, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
}

WP<IElementRenderer> CHyprGLRenderer::elementRenderer() {
    return m_elementRenderer;
}
