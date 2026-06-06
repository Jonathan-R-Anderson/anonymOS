#include "GLRenderer.hpp"
#include <algorithm>
#include <cstdlib>
#include <fcntl.h>      // EpinAnonymOS G5: report window rects to the kernel
#include <unistd.h>
#include <sys/ioctl.h>
#include <drm_fourcc.h>
#include <cctype>               // EpinAnonymOS G14: title -> dock slot match
#include <cmath>                // EpinAnonymOS G14: Cairo dock geometry
#include <cairo/cairo.h>        // EpinAnonymOS G14: antialiased desktop shell
#include <cairo/cairo-ft.h>     // EpinAnonymOS G14: bundled Noto via FreeType
#include <ft2build.h>
#include FT_FREETYPE_H
#include "HosShell.hpp"        // EpinAnonymOS G15: launcher overlay state
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
#include "../desktop/state/FocusState.hpp" // EpinAnonymOS G16: active-window decoration state
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
    constexpr int    HOS_PANEL_HEIGHT   = 36;
    constexpr int    HOS_PANEL_GAP      = 8;
    constexpr int    HOS_PANEL_STRIP_H  = 40;   // EpinAnonymOS G14: cairo overlay strip
    constexpr int    HOS_DOCK_REGION_H  = 96;   // EpinAnonymOS G14: reserved bottom dock band
    constexpr int    HOS_TITLEBAR_H     = 30;   // EpinAnonymOS G16: window titlebar height
    constexpr int    HOS_WIN_RADIUS     = 10;   // EpinAnonymOS G16: window corner radius
    constexpr double HOS_PI             = 3.14159265358979323846;

    // EpinAnonymOS G16: mirrors the kernel HOS_ID_PALETTE (posix.d) so the
    // titlebar accent matches the trusted, kernel-drawn identity border colour.
    uint32_t hosIdentityColorForPid(uint32_t pid) {
        static const uint32_t PALETTE[8] = {
            0xFF4CC2A8u, 0xFFE0B341u, 0xFF6FA8DCu, 0xFFCC6699u, 0xFF8FBF5Fu, 0xFFE08A4Cu, 0xFFB18FE0u, 0xFFD05757u,
        };
        return PALETTE[pid % 8u];
    }

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

    // Procedural wallpaper colour at a pixel. Exposed so window-corner rounding
    // (G16) can repaint corner pixels back to the exact background.
    uint32_t hosWallpaperColorAt(uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
        const uint32_t topLeft     = 0xFF102033u;
        const uint32_t centerTeal  = 0xFF0F766Eu;
        const uint32_t lowerPurple = 0xFF7C3AEDu;
        const uint32_t warmLight   = 0xFFE0B341u;
        const uint32_t mist        = 0xFFE2E8F0u;
        const uint32_t ink         = 0xFF0F172Au;
        const uint32_t denomX      = width > 1 ? width - 1 : 1;
        const uint32_t denomY      = height > 1 ? height - 1 : 1;

        const uint32_t fx = (x * 1000u) / denomX;
        const uint32_t fy = (y * 1000u) / denomY;
        uint32_t       color = hosMixXRGB(topLeft, centerTeal, (fx + fy) / 2u, 1000u);
        color                = hosMixXRGB(color, lowerPurple, (fx * fy) / 1000u, 1000u);

        const int32_t  dx   = static_cast<int32_t>(fx) - 760;
        const int32_t  dy   = static_cast<int32_t>(fy) - 210;
        const uint32_t dist = static_cast<uint32_t>((dx * dx + dy * dy) > 0 ? (dx * dx + dy * dy) : 0);
        if (dist < 260000u)
            color = hosBlendOver(warmLight, color, static_cast<uint8_t>((260000u - dist) / 1800u));

        const int32_t centeredX = static_cast<int32_t>(fx) - 500;
        const int32_t wave1 = static_cast<int32_t>(height * 72u / 100u) - (centeredX * centeredX * static_cast<int32_t>(height)) / 4200000;
        const int32_t wave2 = static_cast<int32_t>(height * 83u / 100u) - ((centeredX + 180) * (centeredX + 180) * static_cast<int32_t>(height)) / 5200000;
        if (static_cast<int32_t>(y) > wave1)
            color = hosBlendOver(mist, color, 42);
        if (static_cast<int32_t>(y) > wave2)
            color = hosBlendOver(ink, color, 58);
        return color;
    }

    void hosDrawWallpaper(const SHosCPUCanvas& canvas) {
        if (!canvas.width || !canvas.height)
            return;
        for (uint32_t y = 0; y < canvas.height; ++y) {
            auto row = reinterpret_cast<uint32_t*>(canvas.data + static_cast<size_t>(y) * canvas.stride);
            for (uint32_t x = 0; x < canvas.width; ++x)
                row[x] = hosWriteFormat(hosWallpaperColorAt(x, y, canvas.width, canvas.height), canvas.format);
        }
    }

    // Legacy bitmap panel. Retained as a guaranteed fallback for the rare case
    // where the bundled Noto faces fail to load and Cairo text is unavailable.
    void hosDrawPanelBitmap(const SHosCPUCanvas& canvas, const std::string& activeTitle) {
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

    // --- EpinAnonymOS G14: antialiased Cairo desktop shell -------------------

    // Bundled Noto faces loaded through FreeType (bypasses guest fontconfig for
    // determinism), wrapped as Cairo font faces. Loaded once, cached.
    struct SHosFonts {
        FT_Library         lib   = nullptr;
        FT_Face            reg   = nullptr;
        FT_Face            bold  = nullptr;
        cairo_font_face_t* creg  = nullptr;
        cairo_font_face_t* cbold = nullptr;
        bool               tried = false;
    };

    SHosFonts& hosFonts() {
        static SHosFonts f;
        if (!f.tried) {
            f.tried = true;
            if (FT_Init_FreeType(&f.lib) == 0) {
                if (FT_New_Face(f.lib, "/usr/share/fonts/noto/NotoSans-Regular.ttf", 0, &f.reg) == 0)
                    f.creg = cairo_ft_font_face_create_for_ft_face(f.reg, 0);
                if (FT_New_Face(f.lib, "/usr/share/fonts/noto/NotoSans-Bold.ttf", 0, &f.bold) == 0)
                    f.cbold = cairo_ft_font_face_create_for_ft_face(f.bold, 0);
            }
            if (f.creg)
                Log::logger->log(Log::WARN, "renderer: HOS G14 loaded bundled Noto faces for desktop shell");
        }
        return f;
    }

    cairo_font_face_t* hosCairoFace(bool bold) {
        auto& f = hosFonts();
        return bold ? (f.cbold ? f.cbold : f.creg) : f.creg;
    }

    void hosCairoText(cairo_t* cr, double x, double baseline, const std::string& s, double size, uint32_t rgb, double a = 1.0,
                      bool bold = false) {
        cairo_font_face_t* face = hosCairoFace(bold);
        if (face)
            cairo_set_font_face(cr, face);
        else
            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, size);
        cairo_set_source_rgba(cr, ((rgb >> 16) & 0xFF) / 255.0, ((rgb >> 8) & 0xFF) / 255.0, (rgb & 0xFF) / 255.0, a);
        cairo_move_to(cr, x, baseline);
        cairo_show_text(cr, s.c_str());
    }

    void hosRoundRect(cairo_t* cr, double x, double y, double w, double h, double r) {
        r = std::min(r, std::min(w, h) / 2.0);
        cairo_new_sub_path(cr);
        cairo_arc(cr, x + w - r, y + r, r, -90 * HOS_PI / 180.0, 0);
        cairo_arc(cr, x + w - r, y + h - r, r, 0, 90 * HOS_PI / 180.0);
        cairo_arc(cr, x + r, y + h - r, r, 90 * HOS_PI / 180.0, 180 * HOS_PI / 180.0);
        cairo_arc(cr, x + r, y + r, r, 180 * HOS_PI / 180.0, 270 * HOS_PI / 180.0);
        cairo_close_path(cr);
    }

    // Composite a premultiplied-ARGB32 Cairo surface onto the output canvas at
    // (ox, oy), honouring the canvas pixel format and source alpha.
    void hosCompositeCairoSurface(const SHosCPUCanvas& canvas, cairo_surface_t* surf, int ox, int oy) {
        cairo_surface_flush(surf);
        const int            sw     = cairo_image_surface_get_width(surf);
        const int            sh     = cairo_image_surface_get_height(surf);
        const int            sstr   = cairo_image_surface_get_stride(surf);
        const unsigned char* sdata  = cairo_image_surface_get_data(surf);
        if (!sdata)
            return;

        for (int y = 0; y < sh; ++y) {
            const int cy = oy + y;
            if (cy < 0 || cy >= static_cast<int>(canvas.height))
                continue;
            auto srow = reinterpret_cast<const uint32_t*>(sdata + static_cast<size_t>(y) * sstr);
            auto drow = reinterpret_cast<uint32_t*>(canvas.data + static_cast<size_t>(cy) * canvas.stride);
            for (int x = 0; x < sw; ++x) {
                const int cx = ox + x;
                if (cx < 0 || cx >= static_cast<int>(canvas.width))
                    continue;
                const uint32_t sp = srow[x];
                const uint32_t a  = sp >> 24;
                if (a == 0)
                    continue;
                const uint32_t sr = (sp >> 16) & 0xFFu; // already premultiplied
                const uint32_t sg = (sp >> 8) & 0xFFu;
                const uint32_t sb = sp & 0xFFu;
                if (a == 0xFFu) {
                    drow[cx] = hosWriteFormat(0xFF000000u | (sr << 16) | (sg << 8) | sb, canvas.format);
                    continue;
                }
                const uint32_t dst = hosReadXRGB(drow[cx], canvas.format);
                const uint32_t dr  = (dst >> 16) & 0xFFu;
                const uint32_t dg  = (dst >> 8) & 0xFFu;
                const uint32_t db  = dst & 0xFFu;
                const uint32_t inv = 255u - a;
                const uint32_t orr = std::min(255u, sr + dr * inv / 255u);
                const uint32_t og  = std::min(255u, sg + dg * inv / 255u);
                const uint32_t ob  = std::min(255u, sb + db * inv / 255u);
                drow[cx] = hosWriteFormat(0xFF000000u | (orr << 16) | (og << 8) | ob, canvas.format);
            }
        }
    }

    // Top menu bar, rendered with Cairo so the title/status/clock are
    // antialiased Noto text. Geometry/colours match the prior bitmap panel so
    // the desktop reads consistently.
    void hosDrawPanel(const SHosCPUCanvas& canvas, const std::string& activeTitle) {
        const int panelH = std::min(HOS_PANEL_HEIGHT, static_cast<int>(canvas.height));
        if (panelH <= 0)
            return;
        if (!hosCairoFace(false)) {
            hosDrawPanelBitmap(canvas, activeTitle);
            return;
        }

        const int W = static_cast<int>(canvas.width);
        const int H = std::min(HOS_PANEL_STRIP_H, static_cast<int>(canvas.height));
        cairo_surface_t* s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, W, H);
        if (cairo_surface_status(s) != CAIRO_STATUS_SUCCESS) {
            cairo_surface_destroy(s);
            hosDrawPanelBitmap(canvas, activeTitle);
            return;
        }
        cairo_t* cr = cairo_create(s);
        cairo_set_operator(cr, CAIRO_OPERATOR_CLEAR);
        cairo_paint(cr);
        cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

        // Bar background: deep slate with a faint vertical sheen + accent rule.
        cairo_pattern_t* bg = cairo_pattern_create_linear(0, 0, 0, panelH);
        cairo_pattern_add_color_stop_rgba(bg, 0.0, 0.105, 0.118, 0.165, 0.95);
        cairo_pattern_add_color_stop_rgba(bg, 1.0, 0.066, 0.078, 0.118, 0.95);
        cairo_set_source(cr, bg);
        cairo_rectangle(cr, 0, 0, W, panelH);
        cairo_fill(cr);
        cairo_pattern_destroy(bg);
        cairo_set_source_rgba(cr, 0.22, 0.74, 0.97, 0.55);
        cairo_rectangle(cr, 0, panelH - 1, W, 1);
        cairo_fill(cr);

        // Identity logo lozenge (teal + warm gold), matching panel palette.
        hosRoundRect(cr, 14, 9, 18, 18, 4);
        cairo_set_source_rgba(cr, 0.059, 0.463, 0.431, 1.0);
        cairo_fill(cr);
        hosRoundRect(cr, 20, 13, 18, 18, 4);
        cairo_set_source_rgba(cr, 0.878, 0.702, 0.255, 1.0);
        cairo_fill(cr);

        hosCairoText(cr, 50, 24, activeTitle.empty() ? "EPIN DESKTOP" : activeTitle, 15.5, 0xF8FAFCu, 1.0, true);

        // Right-aligned status cluster: NET / PWR pills + clock.
        cairo_set_source_rgba(cr, 0.133, 0.773, 0.369, 1.0);
        cairo_arc(cr, W - 274.5, 18, 4, 0, 2 * HOS_PI);
        cairo_fill(cr);
        hosCairoText(cr, W - 264, 23, "NET", 12.0, 0xCBD5E1u, 1.0, true);
        cairo_set_source_rgba(cr, 0.22, 0.74, 0.97, 1.0);
        cairo_arc(cr, W - 212.5, 18, 4, 0, 2 * HOS_PI);
        cairo_fill(cr);
        hosCairoText(cr, W - 202, 23, "PWR", 12.0, 0xCBD5E1u, 1.0, true);

        char clockText[6] = "00:00";
        struct timespec ts {};
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            const int minutes = static_cast<int>((ts.tv_sec / 60) % 100);
            const int seconds = static_cast<int>(ts.tv_sec % 60);
            snprintf(clockText, sizeof(clockText), "%02d:%02d", minutes, seconds);
        }
        hosCairoText(cr, W - 86, 23, clockText, 14.0, 0xFFFFFFu, 1.0, true);

        cairo_destroy(cr);
        hosCompositeCairoSurface(canvas, s, 0, 0);
        cairo_surface_destroy(s);
    }

    // A single dock app: a vector glyph painted white on a coloured tile.
    enum EHosGlyph { HOS_GLYPH_TERM, HOS_GLYPH_FILES, HOS_GLYPH_SETTINGS, HOS_GLYPH_EDITOR, HOS_GLYPH_MONITOR };
    struct SHosDockApp {
        const char* label;
        double      r0, g0, b0; // gradient top
        double      r1, g1, b1; // gradient bottom
        EHosGlyph   glyph;
    };

    void hosDockGlyph(cairo_t* cr, double x, double y, double s, EHosGlyph glyph) {
        cairo_save(cr);
        cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 0.96);
        cairo_set_line_width(cr, std::max(1.6, s * 0.075));
        cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
        cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
        switch (glyph) {
            case HOS_GLYPH_TERM: {
                cairo_move_to(cr, x + s * 0.30, y + s * 0.34);
                cairo_line_to(cr, x + s * 0.48, y + s * 0.50);
                cairo_line_to(cr, x + s * 0.30, y + s * 0.66);
                cairo_stroke(cr);
                cairo_move_to(cr, x + s * 0.54, y + s * 0.66);
                cairo_line_to(cr, x + s * 0.72, y + s * 0.66);
                cairo_stroke(cr);
                break;
            }
            case HOS_GLYPH_FILES: {
                hosRoundRect(cr, x + s * 0.24, y + s * 0.30, s * 0.52, s * 0.40, s * 0.06);
                cairo_move_to(cr, x + s * 0.24, y + s * 0.36);
                cairo_line_to(cr, x + s * 0.40, y + s * 0.36);
                cairo_line_to(cr, x + s * 0.46, y + s * 0.30);
                cairo_fill(cr);
                break;
            }
            case HOS_GLYPH_SETTINGS: {
                const double cx = x + s * 0.5, cy = y + s * 0.5, rr = s * 0.20;
                cairo_arc(cr, cx, cy, rr, 0, 2 * HOS_PI);
                cairo_stroke(cr);
                for (int i = 0; i < 8; ++i) {
                    const double a = i * HOS_PI / 4.0;
                    cairo_move_to(cr, cx + std::cos(a) * rr, cy + std::sin(a) * rr);
                    cairo_line_to(cr, cx + std::cos(a) * (rr + s * 0.12), cy + std::sin(a) * (rr + s * 0.12));
                }
                cairo_stroke(cr);
                cairo_arc(cr, cx, cy, s * 0.07, 0, 2 * HOS_PI);
                cairo_fill(cr);
                break;
            }
            case HOS_GLYPH_EDITOR: {
                hosRoundRect(cr, x + s * 0.30, y + s * 0.26, s * 0.40, s * 0.48, s * 0.05);
                cairo_stroke(cr);
                for (int i = 0; i < 3; ++i) {
                    const double ly = y + s * (0.38 + i * 0.12);
                    cairo_move_to(cr, x + s * 0.38, ly);
                    cairo_line_to(cr, x + s * 0.62, ly);
                }
                cairo_stroke(cr);
                break;
            }
            case HOS_GLYPH_MONITOR: {
                const double base = y + s * 0.70;
                const double heights[3] = {0.18, 0.30, 0.24};
                for (int i = 0; i < 3; ++i) {
                    const double bx = x + s * (0.30 + i * 0.16);
                    cairo_rectangle(cr, bx, base - s * heights[i], s * 0.10, s * heights[i]);
                }
                cairo_fill(cr);
                break;
            }
        }
        cairo_restore(cr);
    }

    // Bottom dock: a centred, translucent, rounded shelf of launcher tiles with
    // a soft shadow, hover/running highlight, and identity-accent run dots.
    void hosDrawDock(const SHosCPUCanvas& canvas, bool running, int runningSlot, const std::string& /*activeTitle*/) {
        static const SHosDockApp APPS[] = {
            {"Terminal", 0.18, 0.21, 0.27, 0.10, 0.12, 0.16, HOS_GLYPH_TERM},
            {"Files",    0.96, 0.73, 0.27, 0.88, 0.55, 0.18, HOS_GLYPH_FILES},
            {"Settings", 0.62, 0.67, 0.74, 0.36, 0.40, 0.46, HOS_GLYPH_SETTINGS},
            {"Editor",   0.36, 0.62, 1.00, 0.18, 0.42, 0.88, HOS_GLYPH_EDITOR},
            {"Monitor",  0.20, 0.83, 0.60, 0.05, 0.64, 0.44, HOS_GLYPH_MONITOR},
        };
        const int N = static_cast<int>(sizeof(APPS) / sizeof(APPS[0]));

        const int W = static_cast<int>(canvas.width);
        const int H = std::min(HOS_DOCK_REGION_H, static_cast<int>(canvas.height));
        if (W <= 0 || H <= 24)
            return;

        // The dock is vector-only; it does not depend on the bundled font faces.
        cairo_surface_t* s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, W, H);
        if (cairo_surface_status(s) != CAIRO_STATUS_SUCCESS) {
            cairo_surface_destroy(s);
            return;
        }
        cairo_t* cr = cairo_create(s);
        cairo_set_operator(cr, CAIRO_OPERATOR_CLEAR);
        cairo_paint(cr);
        cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

        const double tile   = 48;
        const double gap    = 16;
        const double pad    = 14;
        const double pillW  = N * tile + (N - 1) * gap + 2 * pad;
        const double pillH  = tile + 2 * pad;
        const double pillX  = (W - pillW) / 2.0;
        const double pillB  = H - 12;          // 12px above the screen bottom
        const double pillY  = pillB - pillH;
        const double radius = 22;

        // Soft drop shadow (stacked translucent rounded rects).
        for (int i = 8; i >= 1; --i) {
            hosRoundRect(cr, pillX - i, pillY - i * 0.4 + 5, pillW + 2 * i, pillH + 2 * i, radius + i);
            cairo_set_source_rgba(cr, 0, 0, 0, 0.045);
            cairo_fill(cr);
        }

        // Dock shelf.
        cairo_pattern_t* shelf = cairo_pattern_create_linear(0, pillY, 0, pillY + pillH);
        cairo_pattern_add_color_stop_rgba(shelf, 0.0, 0.13, 0.12, 0.17, 0.74);
        cairo_pattern_add_color_stop_rgba(shelf, 1.0, 0.08, 0.07, 0.11, 0.74);
        hosRoundRect(cr, pillX, pillY, pillW, pillH, radius);
        cairo_set_source(cr, shelf);
        cairo_fill_preserve(cr);
        cairo_pattern_destroy(shelf);
        cairo_set_line_width(cr, 1.0);
        cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 0.10);
        cairo_stroke(cr);

        for (int i = 0; i < N; ++i) {
            const double tx        = pillX + pad + i * (tile + gap);
            const double ty        = pillY + pad;
            const bool   isRunning = running && i == runningSlot;

            if (isRunning) {
                hosRoundRect(cr, tx - 4, ty - 4, tile + 8, tile + 8, 14);
                cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 0.16);
                cairo_fill(cr);
            }

            // Tile with vertical gradient + subtle top sheen.
            cairo_pattern_t* g = cairo_pattern_create_linear(0, ty, 0, ty + tile);
            cairo_pattern_add_color_stop_rgba(g, 0.0, APPS[i].r0, APPS[i].g0, APPS[i].b0, 1.0);
            cairo_pattern_add_color_stop_rgba(g, 1.0, APPS[i].r1, APPS[i].g1, APPS[i].b1, 1.0);
            hosRoundRect(cr, tx, ty, tile, tile, 12);
            cairo_set_source(cr, g);
            cairo_fill(cr);
            cairo_pattern_destroy(g);
            hosRoundRect(cr, tx + 1, ty + 1, tile - 2, tile * 0.45, 11);
            cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 0.10);
            cairo_fill(cr);

            hosDockGlyph(cr, tx, ty, tile, APPS[i].glyph);

            // Identity-accent running indicator.
            if (isRunning) {
                const double dx = tx + tile / 2.0;
                const double dy = pillY + pillH - 5;
                cairo_set_source_rgba(cr, 0.22, 0.74, 0.97, 0.35);
                cairo_arc(cr, dx, dy, 6, 0, 2 * HOS_PI);
                cairo_fill(cr);
                cairo_set_source_rgba(cr, 0.36, 0.84, 1.0, 1.0);
                cairo_arc(cr, dx, dy, 3.0, 0, 2 * HOS_PI);
                cairo_fill(cr);
            }
        }

        cairo_destroy(cr);
        hosCompositeCairoSurface(canvas, s, 0, static_cast<int>(canvas.height) - H);
        cairo_surface_destroy(s);
    }

    // G15 launcher: a centred Spotlight-style search overlay with a query field
    // and the filtered app list, drawn above the desktop when open.
    void hosDrawLauncher(const SHosCPUCanvas& canvas) {
        if (!HosShell::launcherOpen())
            return;

        const auto labels = HosShell::visibleLabels();
        const int  rows   = std::max(1, static_cast<int>(labels.size()));
        const int  W      = 540;
        const int  fieldH = 56;
        const int  rowH   = 40;
        const int  padV   = 16;
        const int  H      = padV + fieldH + 10 + rows * rowH + padV;
        const int  ox     = (static_cast<int>(canvas.width) - W) / 2;
        const int  oy     = std::max(40, static_cast<int>(canvas.height) / 6);
        if (W <= 0 || H <= 0)
            return;

        cairo_surface_t* s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, W, H);
        if (cairo_surface_status(s) != CAIRO_STATUS_SUCCESS) {
            cairo_surface_destroy(s);
            return;
        }
        cairo_t* cr = cairo_create(s);
        cairo_set_operator(cr, CAIRO_OPERATOR_CLEAR);
        cairo_paint(cr);
        cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

        // Drop shadow + panel.
        for (int i = 10; i >= 1; --i) {
            hosRoundRect(cr, i, i + 4, W - 2 * i, H - 2 * i, 18 + i);
            cairo_set_source_rgba(cr, 0, 0, 0, 0.04);
            cairo_fill(cr);
        }
        hosRoundRect(cr, 0, 0, W, H, 18);
        cairo_set_source_rgba(cr, 0.12, 0.12, 0.16, 0.96);
        cairo_fill_preserve(cr);
        cairo_set_line_width(cr, 1.0);
        cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 0.10);
        cairo_stroke(cr);

        // Search field.
        hosRoundRect(cr, padV, padV, W - 2 * padV, fieldH, 12);
        cairo_set_source_rgba(cr, 0.06, 0.06, 0.09, 1.0);
        cairo_fill(cr);
        cairo_set_source_rgba(cr, 0.22, 0.74, 0.97, 1.0);
        cairo_arc(cr, padV + 26, padV + fieldH / 2.0, 8, 0, 2 * HOS_PI);
        cairo_set_line_width(cr, 3.0);
        cairo_stroke(cr);
        cairo_move_to(cr, padV + 33, padV + fieldH / 2.0 + 7);
        cairo_line_to(cr, padV + 40, padV + fieldH / 2.0 + 14);
        cairo_stroke(cr);

        const std::string q = HosShell::query();
        if (q.empty())
            hosCairoText(cr, padV + 56, padV + fieldH / 2.0 + 7, "Search apps…", 19.0, 0x8893A7u, 1.0, false);
        else
            hosCairoText(cr, padV + 56, padV + fieldH / 2.0 + 7, q + "|", 19.0, 0xF8FAFCu, 1.0, false);

        // Result rows.
        const int sel    = HosShell::selection();
        const int rowTop = padV + fieldH + 10;
        for (int i = 0; i < static_cast<int>(labels.size()); ++i) {
            const int ry = rowTop + i * rowH;
            if (i == sel) {
                hosRoundRect(cr, padV, ry, W - 2 * padV, rowH - 4, 10);
                cairo_set_source_rgba(cr, 0.22, 0.74, 0.97, 0.22);
                cairo_fill(cr);
            }
            hosRoundRect(cr, padV + 8, ry + 8, 18, 18, 5);
            cairo_set_source_rgba(cr, 0.30, 0.78, 0.70, 1.0);
            cairo_fill(cr);
            hosCairoText(cr, padV + 38, ry + rowH / 2.0 + 4, labels[i], 17.0, i == sel ? 0xFFFFFFu : 0xD3D9E3u, 1.0, i == sel);
        }

        cairo_destroy(cr);
        hosCompositeCairoSurface(canvas, s, ox, oy);
        cairo_surface_destroy(s);
    }

    // A standard left-pointer arrow cursor, drawn at the global pointer position
    // (the HOS CPU present path bypasses Hyprland's normal cursor plane).
    void hosDrawCursor(const SHosCPUCanvas& canvas, int x, int y) {
        const int sz = 22;
        if (x < -sz || y < -sz || x > static_cast<int>(canvas.width) || y > static_cast<int>(canvas.height))
            return;

        cairo_surface_t* s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, sz, sz);
        if (cairo_surface_status(s) != CAIRO_STATUS_SUCCESS) {
            cairo_surface_destroy(s);
            return;
        }
        cairo_t* cr = cairo_create(s);
        cairo_set_operator(cr, CAIRO_OPERATOR_CLEAR);
        cairo_paint(cr);
        cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

        auto arrow = [&](cairo_t* c) {
            cairo_move_to(c, 1, 1);
            cairo_line_to(c, 1, 16);
            cairo_line_to(c, 4.6, 12.6);
            cairo_line_to(c, 7.2, 18.5);
            cairo_line_to(c, 9.4, 17.5);
            cairo_line_to(c, 6.8, 11.8);
            cairo_line_to(c, 11.5, 11.5);
            cairo_close_path(c);
        };
        arrow(cr);
        cairo_set_source_rgba(cr, 0.05, 0.06, 0.09, 0.95); // dark outline
        cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
        cairo_set_line_width(cr, 2.4);
        cairo_stroke_preserve(cr);
        cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 1.0);     // white fill
        cairo_fill(cr);

        cairo_destroy(cr);
        hosCompositeCairoSurface(canvas, s, x, y);
        cairo_surface_destroy(s);
    }

    // --- EpinAnonymOS G16: modern window decorations -------------------------

    // Soft drop shadow around a window box. Drawn before the client content so
    // only the halo remains visible. The focused window casts a stronger shadow.
    void hosDrawWindowShadow(const SHosCPUCanvas& canvas, int bx, int by, int bw, int bh, bool active) {
        const int M = 28;
        const int W = bw + 2 * M;
        const int H = bh + 2 * M;
        if (W <= 0 || H <= 0)
            return;
        cairo_surface_t* s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, W, H);
        if (cairo_surface_status(s) != CAIRO_STATUS_SUCCESS) {
            cairo_surface_destroy(s);
            return;
        }
        cairo_t* cr = cairo_create(s);
        cairo_set_operator(cr, CAIRO_OPERATOR_CLEAR);
        cairo_paint(cr);
        cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

        const int    layers = active ? 22 : 13;
        const double yoff   = active ? 7.0 : 4.0;
        const double a0     = active ? 0.040 : 0.028;
        for (int i = layers; i >= 1; --i) {
            hosRoundRect(cr, M - i, M - i + yoff, bw + 2 * i, bh + 2 * i, HOS_WIN_RADIUS + i);
            cairo_set_source_rgba(cr, 0, 0, 0, a0);
            cairo_fill(cr);
        }

        cairo_destroy(cr);
        hosCompositeCairoSurface(canvas, s, bx - M, by - M);
        cairo_surface_destroy(s);
    }

    // Titlebar occupying the top strip of the window box: rounded top corners, a
    // gradient that brightens for the focused window, an identity-coloured accent
    // dot, the antialiased window title, and minimize/maximize/close controls.
    void hosDrawTitlebar(const SHosCPUCanvas& canvas, int bx, int by, int bw, int titleH, const std::string& title, bool active, uint32_t pid) {
        if (bw <= 0 || titleH <= 0)
            return;
        cairo_surface_t* s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, bw, titleH);
        if (cairo_surface_status(s) != CAIRO_STATUS_SUCCESS) {
            cairo_surface_destroy(s);
            return;
        }
        cairo_t*     cr = cairo_create(s);
        const double r  = HOS_WIN_RADIUS;
        cairo_set_operator(cr, CAIRO_OPERATOR_CLEAR);
        cairo_paint(cr);
        cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

        // Rounded-top, square-bottom path (bottom meets the client content).
        auto barPath = [&]() {
            cairo_new_sub_path(cr);
            cairo_arc(cr, bw - r, r, r, -90 * HOS_PI / 180.0, 0);
            cairo_line_to(cr, bw, titleH);
            cairo_line_to(cr, 0, titleH);
            cairo_line_to(cr, 0, r);
            cairo_arc(cr, r, r, r, 180 * HOS_PI / 180.0, 270 * HOS_PI / 180.0);
            cairo_close_path(cr);
        };
        cairo_pattern_t* g = cairo_pattern_create_linear(0, 0, 0, titleH);
        if (active) {
            cairo_pattern_add_color_stop_rgba(g, 0.0, 0.176, 0.192, 0.227, 1.0);
            cairo_pattern_add_color_stop_rgba(g, 1.0, 0.114, 0.129, 0.157, 1.0);
        } else {
            cairo_pattern_add_color_stop_rgba(g, 0.0, 0.118, 0.129, 0.149, 1.0);
            cairo_pattern_add_color_stop_rgba(g, 1.0, 0.090, 0.098, 0.118, 1.0);
        }
        barPath();
        cairo_set_source(cr, g);
        cairo_fill(cr);
        cairo_pattern_destroy(g);
        // Top sheen.
        barPath();
        cairo_clip(cr);
        cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, active ? 0.06 : 0.03);
        cairo_rectangle(cr, 0, 0, bw, titleH * 0.5);
        cairo_fill(cr);
        cairo_reset_clip(cr);

        // Identity accent dot (matches the kernel-drawn border colour).
        const uint32_t idc = hosIdentityColorForPid(pid);
        cairo_set_source_rgba(cr, ((idc >> 16) & 0xFF) / 255.0, ((idc >> 8) & 0xFF) / 255.0, (idc & 0xFF) / 255.0, active ? 1.0 : 0.65);
        cairo_arc(cr, 16, titleH / 2.0, 5, 0, 2 * HOS_PI);
        cairo_fill(cr);

        // Title (truncate to fit before the controls).
        std::string t = title.empty() ? "Window" : title;
        const int    maxChars = std::max(0, (bw - 130) / 9);
        if (static_cast<int>(t.size()) > maxChars && maxChars > 1)
            t = t.substr(0, maxChars - 1) + "…";
        hosCairoText(cr, 30, titleH / 2.0 + 5, t, 14.0, active ? 0xF1F3F5u : 0x8A909Au, 1.0, active);

        // Controls (right-aligned): minimize, maximize, close.
        const double cy   = titleH / 2.0;
        const double cr_   = 6.5;
        const uint32_t cols[3] = {0xF4BF4Fu, 0x61C554u, 0xED6A5Eu}; // min, max, close
        for (int i = 0; i < 3; ++i) {
            const double cx = bw - 26 - (2 - i) * 26;
            const uint32_t c = cols[i];
            cairo_set_source_rgba(cr, ((c >> 16) & 0xFF) / 255.0, ((c >> 8) & 0xFF) / 255.0, (c & 0xFF) / 255.0, active ? 1.0 : 0.55);
            cairo_arc(cr, cx, cy, cr_, 0, 2 * HOS_PI);
            cairo_fill(cr);
        }

        cairo_destroy(cr);
        hosCompositeCairoSurface(canvas, s, bx, by);
        cairo_surface_destroy(s);
    }

    // Repaint the window's bottom corners back to the wallpaper so the client
    // content reads as rounded (the kernel draws a matching rounded border).
    void hosRoundBottomCorners(const SHosCPUCanvas& canvas, int bx, int by, int bw, int bh, int r) {
        const int cw = static_cast<int>(canvas.width);
        const int ch = static_cast<int>(canvas.height);
        const int r2 = r * r;
        // bottom-left arc centre, bottom-right arc centre
        const int cx[2] = {bx + r, bx + bw - 1 - r};
        const int cy    = by + bh - 1 - r;
        for (int side = 0; side < 2; ++side) {
            for (int dy = 0; dy <= r; ++dy) {
                for (int dx = 0; dx <= r; ++dx) {
                    if (dx * dx + dy * dy <= r2)
                        continue; // inside the rounded window
                    const int px = side == 0 ? cx[0] - dx : cx[1] + dx;
                    const int py = cy + dy;
                    if (px < 0 || py < 0 || px >= cw || py >= ch)
                        continue;
                    auto row = reinterpret_cast<uint32_t*>(canvas.data + static_cast<size_t>(py) * canvas.stride);
                    row[px]  = hosWriteFormat(hosWallpaperColorAt(static_cast<uint32_t>(px), static_cast<uint32_t>(py), canvas.width, canvas.height), canvas.format);
                }
            }
        }
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

    void hosReserveDockSpace(CBox& box, const Vector2D& monitorPos, double monitorH) {
        const double maxBottom = monitorPos.y + monitorH - (HOS_DOCK_REGION_H + HOS_PANEL_GAP);
        if (box.y + box.height <= maxBottom)
            return;
        box.height = std::max(1.0, maxBottom - box.y);
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
        uint32_t mapped = 0;
        std::string activeTitle = "EPIN DESKTOP";

        const auto FOCUSED = Desktop::focusState() ? Desktop::focusState()->window() : nullptr;
        for (auto const& w : g_pCompositor->m_windows) {
            if (!w || !w->m_isMapped || !w->wlSurface() || !w->wlSurface()->resource())
                continue;
            ++mapped;
            if (!w->m_title.empty())
                activeTitle = w->m_title;

            CBox box = {w->m_realPosition->value(), w->m_realSize->value()};
            if (box.width <= 0 || box.height <= 0)
                box = {w->m_position, w->m_size};
            if (box.width <= 0 || box.height <= 0)
                continue;

            const auto monitorPos = monitor->m_position;
            hosReservePanelSpace(box, monitorPos);
            hosReserveDockSpace(box, monitorPos, dst.height);

            // G16: reserve a titlebar at the top of the window box; the client
            // content fills the remainder, and the kernel identity border wraps
            // the whole decorated box.
            const bool active  = FOCUSED ? (w == FOCUSED) : true;
            const int  titleH  = std::min(HOS_TITLEBAR_H, static_cast<int>(box.height * 0.5));
            const int  bx      = static_cast<int>(box.x - monitorPos.x);
            const int  by      = static_cast<int>(box.y - monitorPos.y);
            const int  bw      = static_cast<int>(box.width);
            const int  bh      = static_cast<int>(box.height);

            CBox contentBox = box;
            contentBox.y += titleH;
            contentBox.height = std::max(1.0, box.height - titleH);

            hosDrawWindowShadow(dst, bx, by, bw, bh, active);

            struct SBlitCtx {
                const CBox*          box;
                const Vector2D*      monitorPos;
                const SHosCPUCanvas* dst;
                uint32_t*            blits;
            } ctx{&contentBox, &monitorPos, &dst, &blits};

            w->wlSurface()->resource()->breadthfirst(
                [](SP<CWLSurfaceResource> surface, const Vector2D& offset, void* data) {
                    auto* ctx = static_cast<SBlitCtx*>(data);
                    if (hosBlitSurface(surface, offset, *ctx->box, *ctx->monitorPos, *ctx->dst))
                        ++*ctx->blits;
                },
                &ctx);

            hosDrawTitlebar(dst, bx, by, bw, titleH, w->m_title, active, static_cast<uint32_t>(w->getPID()));
            hosRoundBottomCorners(dst, bx, by, bw, bh, HOS_WIN_RADIUS);
        }
        hosDrawPanel(dst, activeTitle);

        // Map the active window to a dock slot for the running indicator.
        const bool running     = mapped > 0;
        int        runningSlot = 0; // Terminal by default
        std::string lower;
        lower.reserve(activeTitle.size());
        for (char c : activeTitle)
            lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        if (lower.find("file") != std::string::npos)
            runningSlot = 1;
        else if (lower.find("set") != std::string::npos)
            runningSlot = 2;
        else if (lower.find("edit") != std::string::npos || lower.find("cairo") != std::string::npos || lower.find("demo") != std::string::npos)
            runningSlot = 3;
        else if (lower.find("mon") != std::string::npos)
            runningSlot = 4;
        hosDrawDock(dst, running, runningSlot, activeTitle);

        // G15 launcher overlay above the desktop, then the pointer cursor on top.
        hosDrawLauncher(dst);

        if (g_pPointerManager) {
            const auto cursorPos = g_pPointerManager->position();
            hosDrawCursor(dst, static_cast<int>(cursorPos.x - monitor->m_position.x), static_cast<int>(cursorPos.y - monitor->m_position.y));
        }

        output->endDataPtr();

        static bool logged = false;
        static bool loggedPositive = false;
        if (!logged || (blits > 0 && !loggedPositive)) {
            Log::logger->log(Log::WARN, "renderer: HOS G6 wl_shm software compositor blitted {} surface(s)", blits);
            logged = true;
            if (blits > 0)
                loggedPositive = true;
        }

        static bool dockLogged = false;
        if (!dockLogged) {
            Log::logger->log(Log::WARN, "renderer: HOS G14 dock rendered 5 app(s), running={} slot={}", running ? 1 : 0, runningSlot);
            dockLogged = true;
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
