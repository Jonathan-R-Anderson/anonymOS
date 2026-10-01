#include "CHosTitleBarDecoration.hpp"
#include "../../Compositor.hpp"
#include "../../config/ConfigValue.hpp"
#include "../../desktop/state/FocusState.hpp"
#include "../../event/EventBus.hpp"
#include "../../layout/LayoutManager.hpp"
#include "../../managers/KeybindManager.hpp"
#include "../../managers/XWaylandManager.hpp"
#include "../../managers/input/InputManager.hpp"
#include "../pass/RectPassElement.hpp"
#include "../pass/TexPassElement.hpp"
#include "../Renderer.hpp"
#include <cairo/cairo.h>
#include <cairo/cairo-ft.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <unordered_map>

using namespace Render;

namespace {
    constexpr int HOS_BAR_H  = 30; // titlebar height, logical px
    constexpr int HOS_BTN_W  = 40; // each control's cell (minimize, maximize, close)
    constexpr int HOS_PAD    = 12;
    constexpr int HOS_TEXT_P = 13; // title size, px

    // Everything cached lives at namespace scope: in this freestanding build a function-local static
    // with a constructor re-runs that constructor on every entry (see GLRenderer.cpp's caches).
    struct SHosDomainInfo {
        uint32_t    argb = 0xFF6B7280u; // until the kernel answers: neutral grey
        std::string name;
        uint64_t    stampMs = 0;
    };
    std::unordered_map<pid_t, SHosDomainInfo> g_hosDomains;

    struct SHosBarFonts {
        FT_Library         lib   = nullptr;
        FT_Face            reg   = nullptr, bold = nullptr;
        cairo_font_face_t* creg  = nullptr;
        cairo_font_face_t* cbold = nullptr;
        bool               tried = false;
    } g_hosBarFonts;

    CHyprSignalListener g_hosReleaseListener;
    bool                g_hosDragging = false;

    uint64_t            hosNowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    // The kernel's word on which domain owns pid, and that domain's colour.  Re-read every 2 s, so a
    // colour changed in the Domain Manager reaches open windows.
    const SHosDomainInfo& hosDomainOf(pid_t pid) {
        auto&          d   = g_hosDomains[pid];
        const uint64_t NOW = hosNowMs();
        if (d.stampMs != 0 && NOW - d.stampMs < 2000)
            return d;
        d.stampMs = NOW;
        char path[48];
        snprintf(path, sizeof(path), "/proc/%d/status", sc<int>(pid));
        const int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return d;
        char          buf[1024];
        const ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0)
            return d;
        buf[n] = 0;
        if (const char* c = strstr(buf, "\nDomainColor:\t"))
            d.argb = sc<uint32_t>(strtoul(c + 14, nullptr, 16)) | 0xFF000000u;
        if (const char* m = strstr(buf, "\nDomain:\t")) {
            const char* s = m + 9;
            const char* e = strchr(s, '\n');
            d.name        = e ? std::string(s, e - s) : std::string(s);
            if (d.name == "-")
                d.name.clear();
        }
        return d;
    }

    // The bundled Noto faces, straight through FreeType -- like the shell's other text, independent
    // of the guest's fontconfig.
    void hosBarFontsLoad() {
        auto& f = g_hosBarFonts;
        if (f.tried)
            return;
        f.tried = true;
        if (FT_Init_FreeType(&f.lib) != 0)
            return;
        if (FT_New_Face(f.lib, "/usr/share/fonts/noto/NotoSans-Regular.ttf", 0, &f.reg) == 0)
            f.creg = cairo_ft_font_face_create_for_ft_face(f.reg, 0);
        if (FT_New_Face(f.lib, "/usr/share/fonts/noto/NotoSans-Bold.ttf", 0, &f.bold) == 0)
            f.cbold = cairo_ft_font_face_create_for_ft_face(f.bold, 0);
    }

    void hosSetFont(cairo_t* cr, bool bold, double px) {
        hosBarFontsLoad();
        cairo_font_face_t* face = bold && g_hosBarFonts.cbold ? g_hosBarFonts.cbold : g_hosBarFonts.creg;
        if (face)
            cairo_set_font_face(cr, face);
        else
            cairo_select_font_face(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, px);
    }

    // Light bar colours get dark text, dark ones white.
    bool hosIsLight(uint32_t argb) {
        const double r = (argb >> 16) & 0xFF, g = (argb >> 8) & 0xFF, b = argb & 0xFF;
        return 0.299 * r + 0.587 * g + 0.114 * b > 150.0;
    }

    // `s` cut to fit `room` px with an ellipsis.
    std::string hosFit(cairo_t* cr, const std::string& s, double room) {
        cairo_text_extents_t ex;
        cairo_text_extents(cr, s.c_str(), &ex);
        if (ex.x_advance <= room)
            return s;
        std::string t = s;
        while (!t.empty()) {
            do { // drop one UTF-8 character
                t.pop_back();
            } while (!t.empty() && (sc<unsigned char>(t.back()) & 0xC0) == 0x80);
            const std::string c = t + "…";
            cairo_text_extents(cr, c.c_str(), &ex);
            if (ex.x_advance <= room)
                return c;
        }
        return "";
    }
}

CHosTitleBarDecoration::CHosTitleBarDecoration(PHLWINDOW pWindow) : IHyprWindowDecoration(pWindow), m_window(pWindow) {
    // A drag started on a bar ends on the button's release, wherever the pointer is by then.
    if (!g_hosReleaseListener)
        g_hosReleaseListener = Event::bus()->m_events.input.mouse.button.listen([](IPointer::SButtonEvent e, Event::SCallbackInfo&) {
            if (g_hosDragging && e.state == WL_POINTER_BUTTON_STATE_RELEASED) {
                g_hosDragging = false;
                g_layoutManager->endDragTarget();
            }
        });
}

SDecorationPositioningInfo CHosTitleBarDecoration::getPositioningInfo() {
    SDecorationPositioningInfo info;
    info.policy         = DECORATION_POSITION_STICKY;
    info.edges          = DECORATION_EDGE_TOP;
    info.priority       = 1; // outside a group's tab bar, if there is one
    info.reserved       = true;
    info.desiredExtents = {{0, visible() ? HOS_BAR_H : 0}, {0, 0}};
    return info;
}

void CHosTitleBarDecoration::onPositioningReply(const SDecorationPositioningReply& reply) {
    m_assignedBox = reply.assignedGeometry;
}

eDecorationType CHosTitleBarDecoration::getDecorationType() {
    return DECORATION_CUSTOM;
}

void CHosTitleBarDecoration::updateWindow(PHLWINDOW) {
    damageEntire();
}

void CHosTitleBarDecoration::damageEntire() {
    const auto W = m_window.lock();
    if (!W)
        return;
    auto box = assignedBoxGlobal();
    box.translate(W->m_floatingOffset);
    g_pHyprRenderer->damageBox(box);
}

bool CHosTitleBarDecoration::visible() {
    const auto W = m_window.lock();
    if (!W || !W->m_ruleApplicator->decorate().valueOrDefault())
        return false;
    if (W->isEffectiveInternalFSMode(FSMODE_FULLSCREEN))
        return false;
    if (W->m_isX11 && W->isX11OverrideRedirect())
        return false;
    return true;
}

CBox CHosTitleBarDecoration::assignedBoxGlobal() {
    const auto W = m_window.lock();
    if (!W)
        return {};
    CBox box = m_assignedBox;
    box.translate(g_pDecorationPositioner->getEdgeDefinedPoint(DECORATION_EDGE_TOP, W));
    if (W->m_workspace && !W->m_pinned)
        box.translate(W->m_workspace->m_renderOffset->value());
    return box.round();
}

void CHosTitleBarDecoration::draw(PHLMONITOR pMonitor, float const& a) {
    const bool VISIBLE = visible();
    if (VISIBLE != m_lastVisible) {
        m_lastVisible = VISIBLE;
        g_pDecorationPositioner->repositionDeco(this);
    }
    const auto W = m_window.lock();
    if (!VISIBLE || !W)
        return;

    const auto BOX = assignedBoxGlobal();
    if (BOX.w <= 0 || BOX.h <= 0)
        return;

    static auto PROUNDING = CConfigValue<Config::INTEGER>("decoration:rounding");
    const int   ROUND     = *PROUNDING;
    const float SCALE     = pMonitor->m_scale;

    const auto& DOM    = hosDomainOf(W->getPID());
    const bool  ACTIVE = W == Desktop::focusState()->window();

    // The domain's colour -- darker when the window is not focused; the hue never changes.
    CHyprColor col(sc<uint64_t>(DOM.argb));
    if (!ACTIVE) {
        col.r *= 0.72F;
        col.g *= 0.72F;
        col.b *= 0.72F;
    }
    col.a = a;

    CBox bar = {BOX.x - pMonitor->m_position.x + W->m_floatingOffset.x, BOX.y - pMonitor->m_position.y + W->m_floatingOffset.y, BOX.w, BOX.h};

    // The fill reaches ROUND px under the window, so a rounded window's top corners show the bar's
    // colour rather than the wallpaper (this decoration draws beneath the window surface).
    CBox fill = {bar.x, bar.y, bar.w, bar.h + ROUND};
    fill.scale(SCALE).round();
    CRectPassElement::SRectData rect;
    rect.box   = fill;
    rect.color = col;
    rect.round = sc<int>(ROUND * SCALE);
    g_pHyprRenderer->m_renderPass.add(makeUnique<CRectPassElement>(rect));

    // Title and controls: one texture, redrawn only when what it shows changes.
    const bool        LIGHT = hosIsLight(DOM.argb);
    const uint32_t    FG    = LIGHT ? 0xFF1B1D22u : 0xFFFFFFFFu;
    const std::string KEY   = DOM.name + '\x1f' + W->m_title + (ACTIVE ? "\x1f" "1" : "\x1f" "0");
    const int         PW = sc<int>(std::round(bar.w * SCALE)), PH = sc<int>(std::round(bar.h * SCALE));
    if (!m_titleTex || m_titleFor != KEY || m_titleColor != FG || m_titleRoom != PW) {
        m_titleFor   = KEY;
        m_titleColor = FG;
        m_titleRoom  = PW;
        m_titleTex.reset();
        if (PW > 0 && PH > 0) {
            cairo_surface_t* s  = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, PW, PH);
            cairo_t*         cr = cairo_create(s);
            cairo_scale(cr, SCALE, SCALE);
            const double fr = ((FG >> 16) & 0xFF) / 255.0, fg = ((FG >> 8) & 0xFF) / 255.0, fb = (FG & 0xFF) / 255.0;
            const double fa = ACTIVE ? 1.0 : 0.75;
            cairo_set_source_rgba(cr, fr, fg, fb, fa);

            // "<Domain>  ·  <title>", the domain in bold.
            const double baseline = HOS_BAR_H / 2.0 + HOS_TEXT_P * 0.36;
            double       x        = HOS_PAD;
            const double room     = std::max(0.0, bar.w - 3.0 * HOS_BTN_W - HOS_PAD - x);
            if (!DOM.name.empty()) {
                hosSetFont(cr, true, HOS_TEXT_P);
                const std::string d = hosFit(cr, DOM.name, room);
                cairo_move_to(cr, x, baseline);
                cairo_show_text(cr, d.c_str());
                cairo_text_extents_t ex;
                cairo_text_extents(cr, d.c_str(), &ex);
                x += ex.x_advance;
            }
            if (!W->m_title.empty()) {
                hosSetFont(cr, false, HOS_TEXT_P);
                const std::string t = hosFit(cr, (DOM.name.empty() ? "" : "  ·  ") + W->m_title, std::max(0.0, room - (x - HOS_PAD)));
                cairo_move_to(cr, x, baseline);
                cairo_show_text(cr, t.c_str());
            }

            // Controls, right-aligned: minimize, maximize, close.
            const double cy = HOS_BAR_H / 2.0, g = 5.0;
            const double x0 = bar.w - 3.0 * HOS_BTN_W;
            cairo_set_line_width(cr, 1.5);
            cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
            double cx = x0 + HOS_BTN_W / 2.0; // minimize: a bar
            cairo_move_to(cr, cx - g, cy + 0.5);
            cairo_line_to(cr, cx + g, cy + 0.5);
            cairo_stroke(cr);
            cx += HOS_BTN_W; // maximize: a square
            cairo_rectangle(cr, cx - g + 0.5, cy - g + 0.5, 2 * g - 1, 2 * g - 1);
            cairo_stroke(cr);
            cx += HOS_BTN_W; // close: a cross
            cairo_move_to(cr, cx - g, cy - g);
            cairo_line_to(cr, cx + g, cy + g);
            cairo_move_to(cr, cx + g, cy - g);
            cairo_line_to(cr, cx - g, cy + g);
            cairo_stroke(cr);

            cairo_destroy(cr);
            cairo_surface_flush(s);
            m_titleTex = g_pHyprRenderer->createTexture(s);
            cairo_surface_destroy(s);
        }
    }
    if (m_titleTex && m_titleTex->ok()) {
        CBox tb = bar;
        tb.scale(SCALE).round();
        CTexPassElement::SRenderData data;
        data.tex = m_titleTex;
        data.box = tb;
        data.a   = a;
        g_pHyprRenderer->m_renderPass.add(makeUnique<CTexPassElement>(std::move(data)));
    }
}

void CHosTitleBarDecoration::minimize() {
    // Minimized windows wait on a special workspace; SUPER+M shows them, and a click on one's bar
    // brings it back.
    const auto W = m_window.lock();
    if (!W)
        return;
    g_pKeybindManager->m_dispatchers["movetoworkspacesilent"](std::format("special:minimized,address:0x{:x}", rc<uintptr_t>(W.get())));
}

void CHosTitleBarDecoration::restore() {
    const auto W = m_window.lock();
    if (!W || !W->m_monitor)
        return;
    const auto MON = W->m_monitor.lock();
    if (!MON || !MON->m_activeWorkspace)
        return;
    const auto WSID = MON->m_activeWorkspace->m_id;
    g_pKeybindManager->m_dispatchers["movetoworkspacesilent"](std::format("{},address:0x{:x}", WSID, rc<uintptr_t>(W.get())));
    // Hide the minimized windows again (focusing a regular workspace closes a shown special one).
    g_pKeybindManager->m_dispatchers["workspace"](std::to_string(WSID));
    Desktop::focusState()->rawWindowFocus(W, Desktop::FOCUS_REASON_CLICK);
}

void CHosTitleBarDecoration::toggleMaximize() {
    const auto W = m_window.lock();
    if (!W)
        return;
    g_pCompositor->setWindowFullscreenInternal(W, W->isEffectiveInternalFSMode(FSMODE_MAXIMIZED) ? FSMODE_NONE : FSMODE_MAXIMIZED);
}

bool CHosTitleBarDecoration::onButton(const Vector2D& pos, const IPointer::SButtonEvent& e) {
    const auto W = m_window.lock();
    if (!W)
        return false;
    if (e.button != 0x110 /* BTN_LEFT */)
        return true; // the bar is ours: other buttons do nothing, and never reach the client
    if (e.state != WL_POINTER_BUTTON_STATE_PRESSED)
        return true;

    const auto   BOX = assignedBoxGlobal();
    const double rx  = pos.x - BOX.x;
    const double x0  = BOX.w - 3.0 * HOS_BTN_W;

    if (W->m_workspace && W->m_workspace->m_isSpecialWorkspace && W->m_workspace->m_name == "special:minimized") {
        restore();
        return true;
    }
    if (rx >= x0) {
        const int which = sc<int>((rx - x0) / HOS_BTN_W);
        if (which == 0)
            minimize();
        else if (which == 1)
            toggleMaximize();
        else
            g_pXWaylandManager->sendCloseWindow(W);
        return true;
    }

    if (!g_pCompositor->isWindowActive(W))
        Desktop::focusState()->rawWindowFocus(W, Desktop::FOCUS_REASON_CLICK);
    if (W->m_isFloating)
        g_pCompositor->changeWindowZOrder(W, true);

    const uint64_t NOW = hosNowMs();
    if (NOW - m_lastPressMs < 400) { // double-click
        m_lastPressMs = 0;
        toggleMaximize();
        return true;
    }
    m_lastPressMs = NOW;

    // Drag the window by its bar (not while maximized: there is nowhere to move it).
    if (!W->isFullscreen()) {
        g_layoutManager->beginDragTarget(W->layoutTarget(), MBIND_MOVE);
        g_hosDragging = true;
    }
    return true;
}

bool CHosTitleBarDecoration::onInputOnDeco(const eInputType type, const Vector2D& mouseCoords, std::any data) {
    switch (type) {
        case INPUT_TYPE_BUTTON: return onButton(mouseCoords, std::any_cast<const IPointer::SButtonEvent&>(data));
        case INPUT_TYPE_DRAG_START: {
            // SUPER+drag that starts on the bar: just move the window.
            const auto W = m_window.lock();
            if (!W)
                return false;
            g_layoutManager->beginDragTarget(W->layoutTarget(), MBIND_MOVE);
            return true;
        }
        default: return false;
    }
}

eDecorationLayer CHosTitleBarDecoration::getDecorationLayer() {
    return DECORATION_LAYER_UNDER;
}

uint64_t CHosTitleBarDecoration::getDecorationFlags() {
    return DECORATION_ALLOWS_MOUSE_INPUT | DECORATION_PART_OF_MAIN_WINDOW;
}

std::string CHosTitleBarDecoration::getDisplayName() {
    return "HosTitleBar";
}
