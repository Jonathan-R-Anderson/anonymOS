#include "GLRenderer.hpp"
#include <algorithm>
#include <cstdlib>
#include <fcntl.h>      // EpinAnonymOS G5: report window rects to the kernel
#include <unistd.h>
#include <sys/ioctl.h>
#include <drm_fourcc.h>
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
#include <cstdio>
#include <ctime>
#include <string>
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

namespace {
    constexpr int HOS_PANEL_HEIGHT = 36;
    constexpr int HOS_PANEL_GAP    = 8;

    struct SHosCPUCanvas {
        uint8_t* data   = nullptr;
        uint32_t width  = 0;
        uint32_t height = 0;
        uint32_t stride = 0;
        uint32_t format = DRM_FORMAT_INVALID;
        size_t   size   = 0;
    };

    bool hosFormatIs32(uint32_t format) {
        return format == DRM_FORMAT_XRGB8888 || format == DRM_FORMAT_ARGB8888 || format == DRM_FORMAT_XBGR8888 || format == DRM_FORMAT_ABGR8888;
    }

    uint32_t hosReadXRGB(uint32_t px, uint32_t format) {
        switch (format) {
            case DRM_FORMAT_XBGR8888:
            case DRM_FORMAT_ABGR8888: {
                const uint32_t r = px & 0x000000FFu;
                const uint32_t g = px & 0x0000FF00u;
                const uint32_t b = (px & 0x00FF0000u) >> 16;
                return 0xFF000000u | (r << 16) | g | b;
            }
            default: return 0xFF000000u | (px & 0x00FFFFFFu);
        }
    }

    uint32_t hosWriteFormat(uint32_t xrgb, uint32_t format) {
        switch (format) {
            case DRM_FORMAT_XBGR8888:
            case DRM_FORMAT_ABGR8888: {
                const uint32_t r = (xrgb >> 16) & 0xFFu;
                const uint32_t g = xrgb & 0x0000FF00u;
                const uint32_t b = xrgb & 0x000000FFu;
                return 0xFF000000u | (b << 16) | g | r;
            }
            default: return 0xFF000000u | (xrgb & 0x00FFFFFFu);
        }
    }

    uint8_t hosAlpha(uint32_t px, uint32_t format) {
        if (format == DRM_FORMAT_ARGB8888 || format == DRM_FORMAT_ABGR8888)
            return static_cast<uint8_t>(px >> 24);
        return 0xFF;
    }

    uint32_t hosBlendOver(uint32_t src, uint32_t dst, uint8_t alpha) {
        if (alpha == 0xFF)
            return src;
        if (alpha == 0)
            return dst;

        const uint32_t inv = 255u - alpha;
        const uint32_t sr  = (src >> 16) & 0xFFu;
        const uint32_t sg  = (src >> 8) & 0xFFu;
        const uint32_t sb  = src & 0xFFu;
        const uint32_t dr  = (dst >> 16) & 0xFFu;
        const uint32_t dg  = (dst >> 8) & 0xFFu;
        const uint32_t db  = dst & 0xFFu;
        return 0xFF000000u | (((sr * alpha + dr * inv) / 255u) << 16) | (((sg * alpha + dg * inv) / 255u) << 8) | ((sb * alpha + db * inv) / 255u);
    }

    uint32_t hosMixXRGB(uint32_t a, uint32_t b, uint32_t t, uint32_t denom) {
        if (denom == 0)
            return a;
        if (t > denom)
            t = denom;

        const uint32_t ar = (a >> 16) & 0xFFu;
        const uint32_t ag = (a >> 8) & 0xFFu;
        const uint32_t ab = a & 0xFFu;
        const uint32_t br = (b >> 16) & 0xFFu;
        const uint32_t bg = (b >> 8) & 0xFFu;
        const uint32_t bb = b & 0xFFu;
        const uint32_t inv = denom - t;
        return 0xFF000000u | (((ar * inv + br * t) / denom) << 16) | (((ag * inv + bg * t) / denom) << 8) | ((ab * inv + bb * t) / denom);
    }

    void hosFillRect(const SHosCPUCanvas& canvas, int x, int y, int w, int h, uint32_t xrgb) {
        if (w <= 0 || h <= 0)
            return;
        const int x0 = std::max(0, x);
        const int y0 = std::max(0, y);
        const int x1 = std::min(static_cast<int>(canvas.width), x + w);
        const int y1 = std::min(static_cast<int>(canvas.height), y + h);
        if (x0 >= x1 || y0 >= y1)
            return;

        const uint32_t px = hosWriteFormat(xrgb, canvas.format);
        for (int yy = y0; yy < y1; ++yy) {
            auto row = reinterpret_cast<uint32_t*>(canvas.data + static_cast<size_t>(yy) * canvas.stride);
            for (int xx = x0; xx < x1; ++xx)
                row[xx] = px;
        }
    }

    void hosFillRectBlend(const SHosCPUCanvas& canvas, int x, int y, int w, int h, uint32_t xrgb, uint8_t alpha) {
        if (w <= 0 || h <= 0)
            return;
        const int x0 = std::max(0, x);
        const int y0 = std::max(0, y);
        const int x1 = std::min(static_cast<int>(canvas.width), x + w);
        const int y1 = std::min(static_cast<int>(canvas.height), y + h);
        if (x0 >= x1 || y0 >= y1)
            return;

        for (int yy = y0; yy < y1; ++yy) {
            auto row = reinterpret_cast<uint32_t*>(canvas.data + static_cast<size_t>(yy) * canvas.stride);
            for (int xx = x0; xx < x1; ++xx) {
                const uint32_t dst = hosReadXRGB(row[xx], canvas.format);
                row[xx] = hosWriteFormat(hosBlendOver(xrgb, dst, alpha), canvas.format);
            }
        }
    }

    const uint8_t* hosGlyphRows(char c) {
        static const uint8_t SPACE[7] = {0, 0, 0, 0, 0, 0, 0};
        static const uint8_t A[7] = {0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11};
        static const uint8_t B[7] = {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E};
        static const uint8_t C[7] = {0x0F, 0x10, 0x10, 0x10, 0x10, 0x10, 0x0F};
        static const uint8_t D[7] = {0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E};
        static const uint8_t E[7] = {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F};
        static const uint8_t F[7] = {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10};
        static const uint8_t G[7] = {0x0F, 0x10, 0x10, 0x13, 0x11, 0x11, 0x0F};
        static const uint8_t H[7] = {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11};
        static const uint8_t I[7] = {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1F};
        static const uint8_t K[7] = {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11};
        static const uint8_t L[7] = {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F};
        static const uint8_t M[7] = {0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11};
        static const uint8_t N[7] = {0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11};
        static const uint8_t O[7] = {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E};
        static const uint8_t P[7] = {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10};
        static const uint8_t R[7] = {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11};
        static const uint8_t S[7] = {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E};
        static const uint8_t T[7] = {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
        static const uint8_t U[7] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E};
        static const uint8_t W[7] = {0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11};
        static const uint8_t Y[7] = {0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04};
        static const uint8_t ZERO[7] = {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E};
        static const uint8_t ONE[7] = {0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E};
        static const uint8_t TWO[7] = {0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F};
        static const uint8_t THREE[7] = {0x1E, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1E};
        static const uint8_t FOUR[7] = {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02};
        static const uint8_t FIVE[7] = {0x1F, 0x10, 0x10, 0x1E, 0x01, 0x01, 0x1E};
        static const uint8_t SIX[7] = {0x0F, 0x10, 0x10, 0x1E, 0x11, 0x11, 0x0E};
        static const uint8_t SEVEN[7] = {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08};
        static const uint8_t EIGHT[7] = {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E};
        static const uint8_t NINE[7] = {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x01, 0x1E};
        static const uint8_t COLON[7] = {0x00, 0x04, 0x04, 0x00, 0x04, 0x04, 0x00};
        if (c >= 'a' && c <= 'z')
            c = static_cast<char>(c - 'a' + 'A');
        switch (c) {
            case 'A': return A;
            case 'B': return B;
            case 'C': return C;
            case 'D': return D;
            case 'E': return E;
            case 'F': return F;
            case 'G': return G;
            case 'H': return H;
            case 'I': return I;
            case 'K': return K;
            case 'L': return L;
            case 'M': return M;
            case 'N': return N;
            case 'O': return O;
            case 'P': return P;
            case 'R': return R;
            case 'S': return S;
            case 'T': return T;
            case 'U': return U;
            case 'W': return W;
            case 'Y': return Y;
            case '0': return ZERO;
            case '1': return ONE;
            case '2': return TWO;
            case '3': return THREE;
            case '4': return FOUR;
            case '5': return FIVE;
            case '6': return SIX;
            case '7': return SEVEN;
            case '8': return EIGHT;
            case '9': return NINE;
            case ':': return COLON;
            default: return SPACE;
        }
    }

    void hosDrawTinyText(const SHosCPUCanvas& canvas, int x, int y, std::string text, uint32_t color, int scale = 2, int maxChars = 32) {
        int cursor = x;
        int count  = 0;
        for (char c : text) {
            if (count++ >= maxChars)
                break;
            const uint8_t* rows = hosGlyphRows(c);
            for (int gy = 0; gy < 7; ++gy) {
                for (int gx = 0; gx < 5; ++gx) {
                    if (rows[gy] & (1u << (4 - gx)))
                        hosFillRect(canvas, cursor + gx * scale, y + gy * scale, scale, scale, color);
                }
            }
            cursor += 6 * scale;
        }
    }

    bool hosBeginCanvas(SP<Aquamarine::IBuffer> buffer, SHosCPUCanvas& canvas) {
        if (!buffer || !(buffer->caps() & Aquamarine::BUFFER_CAPABILITY_DATAPTR))
            return false;

        auto attrs                    = buffer->dmabuf();
        auto [pixelData, fmt, bufLen] = buffer->beginDataPtr(0);
        if (!pixelData || !bufLen)
            return false;

        canvas.data   = pixelData;
        canvas.width  = static_cast<uint32_t>(buffer->size.x);
        canvas.height = static_cast<uint32_t>(buffer->size.y);
        canvas.stride = attrs.success && attrs.strides.at(0) ? attrs.strides.at(0) : canvas.width * 4;
        canvas.format = fmt ? fmt : (attrs.success ? attrs.format : DRM_FORMAT_XRGB8888);
        canvas.size   = bufLen;

        if (!canvas.width || !canvas.height || !canvas.stride || !hosFormatIs32(canvas.format) || canvas.stride < canvas.width * 4 ||
            canvas.size < static_cast<size_t>(canvas.stride) * canvas.height) {
            buffer->endDataPtr();
            canvas = {};
            return false;
        }

        return true;
    }

    void hosDrawWallpaper(const SHosCPUCanvas& canvas) {
        if (!canvas.width || !canvas.height)
            return;

        const uint32_t topLeft     = 0xFF102033u;
        const uint32_t centerTeal  = 0xFF0F766Eu;
        const uint32_t lowerPurple = 0xFF7C3AEDu;
        const uint32_t warmLight   = 0xFFE0B341u;
        const uint32_t mist        = 0xFFE2E8F0u;
        const uint32_t ink         = 0xFF0F172Au;
        const uint32_t denomX      = canvas.width > 1 ? canvas.width - 1 : 1;
        const uint32_t denomY      = canvas.height > 1 ? canvas.height - 1 : 1;

        for (uint32_t y = 0; y < canvas.height; ++y) {
            auto row = reinterpret_cast<uint32_t*>(canvas.data + static_cast<size_t>(y) * canvas.stride);
            for (uint32_t x = 0; x < canvas.width; ++x) {
                const uint32_t fx = (x * 1000u) / denomX;
                const uint32_t fy = (y * 1000u) / denomY;
                uint32_t color = hosMixXRGB(topLeft, centerTeal, (fx + fy) / 2u, 1000u);
                color = hosMixXRGB(color, lowerPurple, (fx * fy) / 1000u, 1000u);

                const int32_t dx = static_cast<int32_t>(fx) - 760;
                const int32_t dy = static_cast<int32_t>(fy) - 210;
                const uint32_t dist = static_cast<uint32_t>((dx * dx + dy * dy) > 0 ? (dx * dx + dy * dy) : 0);
                if (dist < 260000u)
                    color = hosBlendOver(warmLight, color, static_cast<uint8_t>((260000u - dist) / 1800u));

                const int32_t centeredX = static_cast<int32_t>(fx) - 500;
                const int32_t wave1 = static_cast<int32_t>(canvas.height * 72u / 100u) -
                                      (centeredX * centeredX * static_cast<int32_t>(canvas.height)) / 4200000;
                const int32_t wave2 = static_cast<int32_t>(canvas.height * 83u / 100u) -
                                      ((centeredX + 180) * (centeredX + 180) * static_cast<int32_t>(canvas.height)) / 5200000;
                if (static_cast<int32_t>(y) > wave1)
                    color = hosBlendOver(mist, color, 42);
                if (static_cast<int32_t>(y) > wave2)
                    color = hosBlendOver(ink, color, 58);

                row[x] = hosWriteFormat(color, canvas.format);
            }
        }
    }

    void hosDrawPanel(const SHosCPUCanvas& canvas, const std::string& activeTitle) {
        const int panelH = std::min(HOS_PANEL_HEIGHT, static_cast<int>(canvas.height));
        if (panelH <= 0)
            return;

        hosFillRectBlend(canvas, 0, 0, static_cast<int>(canvas.width), panelH, 0xFF111827u, 238);
        hosFillRectBlend(canvas, 0, panelH - 1, static_cast<int>(canvas.width), 1, 0xFF38BDF8u, 170);
        hosFillRect(canvas, 14, 9, 18, 18, 0xFF0F766Eu);
        hosFillRect(canvas, 20, 13, 18, 18, 0xFFE0B341u);
        hosDrawTinyText(canvas, 50, 11, activeTitle.empty() ? "EPIN DESKTOP" : activeTitle, 0xFFF8FAFCu, 2, 30);

        const int right = static_cast<int>(canvas.width);
        hosFillRect(canvas, right - 278, 14, 7, 7, 0xFF22C55Eu);
        hosDrawTinyText(canvas, right - 264, 11, "NET", 0xFFCBD5E1u, 2, 3);
        hosFillRect(canvas, right - 216, 14, 7, 7, 0xFF38BDF8u);
        hosDrawTinyText(canvas, right - 202, 11, "PWR", 0xFFCBD5E1u, 2, 3);

        char clockText[6] = "00:00";
        struct timespec ts {};
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            const int minutes = static_cast<int>((ts.tv_sec / 60) % 100);
            const int seconds = static_cast<int>(ts.tv_sec % 60);
            snprintf(clockText, sizeof(clockText), "%02d:%02d", minutes, seconds);
        }
        hosDrawTinyText(canvas, right - 86, 11, clockText, 0xFFFFFFFFu, 2, 5);
    }

    void hosReservePanelSpace(CBox& box, const Vector2D& monitorPos) {
        const double minY = monitorPos.y + HOS_PANEL_HEIGHT + HOS_PANEL_GAP;
        if (box.y >= minY)
            return;
        const double delta = minY - box.y;
        box.y += delta;
        if (box.height > delta + 1.0)
            box.height -= delta;
    }

    bool hosBlitSurface(SP<CWLSurfaceResource> surface, const Vector2D& surfaceOffset, const CBox& windowBox, const Vector2D& monitorPos, const SHosCPUCanvas& dst) {
        if (!surface || !surface->m_current.buffer)
            return false;

        auto srcBuffer = surface->m_current.buffer.m_buffer;
        if (!srcBuffer)
            return false;

        auto shm = srcBuffer->shm();
        if (!shm.success || !hosFormatIs32(shm.format) || shm.stride < static_cast<uint32_t>(shm.size.x) * 4)
            return false;

        auto [srcData, ignoredFmt, srcLen] = srcBuffer->beginDataPtr(0);
        if (!srcData)
            return false;

        const int srcW = static_cast<int>(shm.size.x);
        const int srcH = static_cast<int>(shm.size.y);
        if (srcW <= 0 || srcH <= 0 || srcLen < static_cast<size_t>(shm.stride) * static_cast<size_t>(srcH)) {
            srcBuffer->endDataPtr();
            return false;
        }

        const double scaleX = surface->m_current.size.x > 0.0 ? windowBox.width / surface->m_current.size.x : 1.0;
        const double scaleY = surface->m_current.size.y > 0.0 ? windowBox.height / surface->m_current.size.y : 1.0;
        const int    dstX   = static_cast<int>(windowBox.x - monitorPos.x + surfaceOffset.x * scaleX);
        const int    dstY   = static_cast<int>(windowBox.y - monitorPos.y + surfaceOffset.y * scaleY);
        const int    dstW   = std::max(1, static_cast<int>(surface->m_current.size.x * scaleX));
        const int    dstH   = std::max(1, static_cast<int>(surface->m_current.size.y * scaleY));

        const int x0 = std::max(0, dstX);
        const int y0 = std::max(0, dstY);
        const int x1 = std::min(static_cast<int>(dst.width), dstX + dstW);
        const int y1 = std::min(static_cast<int>(dst.height), dstY + dstH);
        if (x0 >= x1 || y0 >= y1) {
            srcBuffer->endDataPtr();
            return false;
        }

        for (int y = y0; y < y1; ++y) {
            const int sy     = std::clamp(((y - dstY) * srcH) / dstH, 0, srcH - 1);
            auto      srcRow = reinterpret_cast<const uint32_t*>(srcData + static_cast<size_t>(sy) * shm.stride);
            auto      dstRow = reinterpret_cast<uint32_t*>(dst.data + static_cast<size_t>(y) * dst.stride);

            for (int x = x0; x < x1; ++x) {
                const int      sx       = std::clamp(((x - dstX) * srcW) / dstW, 0, srcW - 1);
                const uint32_t rawSrc   = srcRow[sx];
                const uint32_t srcXRGB  = hosReadXRGB(rawSrc, shm.format);
                const uint32_t dstXRGB  = hosReadXRGB(dstRow[x], dst.format);
                const uint32_t outXRGB  = hosBlendOver(srcXRGB, dstXRGB, hosAlpha(rawSrc, shm.format));
                dstRow[x]               = hosWriteFormat(outXRGB, dst.format);
            }
        }

        srcBuffer->endDataPtr();
        return true;
    }

    bool hosComposeShmWindows(SP<Aquamarine::IBuffer> output, PHLMONITORREF monitor) {
        if (!output || !monitor)
            return false;

        SHosCPUCanvas dst;
        if (!hosBeginCanvas(output, dst))
            return false;

        hosDrawWallpaper(dst);

        uint32_t blits = 0;
        std::string activeTitle = "EPIN DESKTOP";
        for (auto const& w : g_pCompositor->m_windows) {
            if (!w || !w->m_isMapped || !w->wlSurface() || !w->wlSurface()->resource())
                continue;
            if (!w->m_title.empty())
                activeTitle = w->m_title;

            CBox box = {w->m_realPosition->value(), w->m_realSize->value()};
            if (box.width <= 0 || box.height <= 0)
                box = {w->m_position, w->m_size};
            if (box.width <= 0 || box.height <= 0)
                continue;

            const auto monitorPos = monitor->m_position;
            hosReservePanelSpace(box, monitorPos);
            struct SBlitCtx {
                const CBox*          box;
                const Vector2D*      monitorPos;
                const SHosCPUCanvas* dst;
                uint32_t*            blits;
            } ctx{&box, &monitorPos, &dst, &blits};

            w->wlSurface()->resource()->breadthfirst(
                [](SP<CWLSurfaceResource> surface, const Vector2D& offset, void* data) {
                    auto* ctx = static_cast<SBlitCtx*>(data);
                    if (hosBlitSurface(surface, offset, *ctx->box, *ctx->monitorPos, *ctx->dst))
                        ++*ctx->blits;
                },
                &ctx);
        }
        hosDrawPanel(dst, activeTitle);

        output->endDataPtr();

        static bool logged = false;
        static bool loggedPositive = false;
        if (!logged || (blits > 0 && !loggedPositive)) {
            Log::logger->log(Log::WARN, "renderer: HOS G6 wl_shm software compositor blitted {} surface(s)", blits);
            logged = true;
            if (blits > 0)
                loggedPositive = true;
        }

        return true;
    }
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
                const double minY = MPOS.y + HOS_PANEL_HEIGHT + HOS_PANEL_GAP;
                if (P.y < minY) {
                    const double delta = minY - P.y;
                    P.y += delta;
                    if (S.y > delta + 1.0)
                        S.y -= delta;
                }
                auto& r = wins.rects[wins.count++];
                r.x     = static_cast<int32_t>(P.x - MPOS.x);
                r.y     = static_cast<int32_t>(P.y - MPOS.y);
                r.w     = static_cast<int32_t>(S.x);
                r.h     = static_cast<int32_t>(S.y);
                r.pid   = static_cast<uint32_t>(w->getPID());
            }
            if (wins.count > 0)
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
        if (hosComposeShmWindows(m_currentBuffer, PMONITOR)) {
            PMONITOR->m_output->state->setBuffer(m_currentBuffer);
            // The wl_shm CPU compositor writes directly into m_currentBuffer.
            // A GL framebuffer readback here re-enters Mesa's swrast path with
            // no useful source pixels and can fault in the sessionless backend.
            m_currentRenderbuffer = nullptr;
            g_pHyprRenderer->m_renderData.damage = CRegion{0, 0, sc<int>(PMONITOR->m_pixelSize.x), sc<int>(PMONITOR->m_pixelSize.y)};
            m_usedAsyncBuffers.clear();
            if (renderingDoneCallback)
                renderingDoneCallback();
            return;
        }

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
