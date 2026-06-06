#include "HosShell.hpp"

#include <xkbcommon/xkbcommon.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include "../Compositor.hpp"
#include "../config/supplementary/executor/Executor.hpp"
#include "../config/shared/actions/ConfigActions.hpp" // G16: window controls
#include "../debug/log/Logger.hpp"
#include "../desktop/view/Window.hpp"
#include "../helpers/Monitor.hpp"

namespace {
    struct SApp {
        std::string label;
        std::string exec;
    };

    // Real launchable guest binaries. Apps without a dedicated binary yet point
    // at the toolkit demo as a placeholder window until they are implemented
    // (tracked alongside G17/G18).
    std::vector<SApp> g_apps = {
        {"Terminal", "wl-term"},
        {"Files", "wl-cairo-demo"},
        {"Settings", "wl-cairo-demo"},
        {"Editor", "wl-cairo-demo"},
        {"Monitor", "wl-cairo-demo"},
    };

    bool        g_open      = false;
    bool        g_superDown = false;
    std::string g_query;
    int         g_sel = 0;

    // Window decoration geometry — MUST stay in sync with GLRenderer.cpp.
    constexpr double PANEL_H     = 36;
    constexpr double PANEL_GAP   = 8;
    constexpr double DOCK_REGION = 96;
    constexpr double TITLEBAR_H  = 30;

    // Dock geometry — MUST stay in sync with hosDrawDock() in GLRenderer.cpp.
    constexpr double DOCK_TILE     = 48;
    constexpr double DOCK_GAP      = 16;
    constexpr double DOCK_PAD      = 14;
    constexpr double DOCK_BOTTOM   = 12;

    std::string lower(std::string s) {
        for (auto& c : s)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }

    std::vector<int> filtered() {
        std::vector<int>  out;
        const std::string q = lower(g_query);
        for (int i = 0; i < static_cast<int>(g_apps.size()); ++i)
            if (q.empty() || lower(g_apps[i].label).find(q) != std::string::npos)
                out.push_back(i);
        return out;
    }

    void requestRedraw() {
        if (!g_pCompositor)
            return;
        for (auto& m : g_pCompositor->m_monitors)
            g_pCompositor->scheduleFrameForMonitor(m);
    }

    void launch(const std::string& exec) {
        Log::logger->log(Log::WARN, "HOS G15: launching '{}'", exec);
        Config::Supplementary::executor()->spawnRaw(exec);
    }

    // Verification hook: /display.conf may carry gui.launcher_demo=1 (built with
    // GUI_LAUNCHER_DEMO=1) to boot with the launcher open so its render path can
    // be checked without synthetic input. Default off.
    void ensureInit() {
        static bool done = false;
        if (done)
            return;
        done = true;
        if (FILE* f = fopen("/display.conf", "r")) {
            char line[256];
            while (fgets(line, sizeof(line), f))
                if (strstr(line, "gui.launcher_demo=1")) {
                    g_open  = true;
                    g_query = "te";
                    Log::logger->log(Log::WARN, "HOS G15: launcher demo flag set; opening launcher at boot");
                }
            fclose(f);
        }
    }
}

namespace HosShell {

    bool launcherOpen() {
        ensureInit();
        return g_open;
    }

    std::string query() {
        return g_query;
    }

    int selection() {
        return g_sel;
    }

    std::vector<std::string> visibleLabels() {
        std::vector<std::string> v;
        for (int i : filtered())
            v.push_back(g_apps[i].label);
        return v;
    }

    int visibleCount() {
        return static_cast<int>(filtered().size());
    }

    int appCount() {
        return static_cast<int>(g_apps.size());
    }

    void launchDockSlot(int slot) {
        if (slot >= 0 && slot < static_cast<int>(g_apps.size()))
            launch(g_apps[slot].exec);
    }

    bool handleKey(uint32_t keycode, bool pressed, xkb_state* state) {
        ensureInit();
        const xkb_keysym_t sym = state ? xkb_state_key_get_one_sym(state, keycode + 8) : XKB_KEY_NoSymbol;

        // Track the Super/Logo modifier ourselves rather than trusting the
        // per-keyboard xkb mod mask (which may not reflect it yet at key time).
        if (sym == XKB_KEY_Super_L || sym == XKB_KEY_Super_R || sym == XKB_KEY_Meta_L || sym == XKB_KEY_Meta_R || keycode == 125 || keycode == 126) {
            g_superDown = pressed;
            if (!g_open)
                return false; // let it still act as a modifier elsewhere
        }
        const bool superHeld = g_superDown || (state && xkb_state_mod_name_is_active(state, XKB_MOD_NAME_LOGO, XKB_STATE_MODS_EFFECTIVE) > 0);

        // Super+Space toggles the launcher from anywhere.
        if (pressed && sym == XKB_KEY_space && superHeld) {
            g_open = !g_open;
            g_query.clear();
            g_sel = 0;
            Log::logger->log(Log::WARN, "HOS G15: launcher {}", g_open ? "opened" : "closed");
            requestRedraw();
            return true;
        }

        if (!g_open)
            return false;

        if (!pressed)
            return true; // swallow releases while the launcher owns the keyboard

        switch (sym) {
            case XKB_KEY_Escape:
                g_open = false;
                requestRedraw();
                return true;
            case XKB_KEY_Return:
            case XKB_KEY_KP_Enter: {
                const auto f = filtered();
                if (!f.empty())
                    launch(g_apps[f[std::clamp(g_sel, 0, static_cast<int>(f.size()) - 1)]].exec);
                g_open = false;
                requestRedraw();
                return true;
            }
            case XKB_KEY_BackSpace:
                if (!g_query.empty())
                    g_query.pop_back();
                g_sel = 0;
                requestRedraw();
                return true;
            case XKB_KEY_Up: {
                const int n = visibleCount();
                if (n > 0)
                    g_sel = (g_sel - 1 + n) % n;
                requestRedraw();
                return true;
            }
            case XKB_KEY_Down:
            case XKB_KEY_Tab: {
                const int n = visibleCount();
                if (n > 0)
                    g_sel = (g_sel + 1) % n;
                requestRedraw();
                return true;
            }
            default: break;
        }

        char      buf[8] = {0};
        const int n      = state ? xkb_state_key_get_utf8(state, keycode + 8, buf, sizeof(buf)) : 0;
        if (n == 1 && static_cast<unsigned char>(buf[0]) >= 0x20 && static_cast<unsigned char>(buf[0]) < 0x7f) {
            g_query.push_back(buf[0]);
            g_sel = 0;
            requestRedraw();
        }
        return true; // launcher owns all keys while open
    }

    bool onPointerButton(double gx, double gy) {
        if (!g_pCompositor)
            return false;

        // A click anywhere dismisses an open launcher.
        if (g_open) {
            g_open = false;
            requestRedraw();
            return true;
        }

        const auto mon = g_pCompositor->getMonitorFromVector({gx, gy});
        if (!mon)
            return false;

        const double W  = mon->m_pixelSize.x;
        const double H  = mon->m_pixelSize.y;
        const double lx = gx - mon->m_position.x;
        const double ly = gy - mon->m_position.y;

        // G16: window titlebar controls (minimize / maximize / close). Geometry
        // mirrors the decoration drawn by hosDrawTitlebar/hosComposeShmWindows.
        for (auto const& w : g_pCompositor->m_windows) {
            if (!w || !w->m_isMapped)
                continue;
            double bxg = w->m_realPosition->value().x, byg = w->m_realPosition->value().y;
            double bwg = w->m_realSize->value().x, bhg = w->m_realSize->value().y;
            if (bwg <= 0 || bhg <= 0) {
                bxg = w->m_position.x; byg = w->m_position.y;
                bwg = w->m_size.x;     bhg = w->m_size.y;
            }
            if (bwg <= 0 || bhg <= 0)
                continue;
            const double minY = mon->m_position.y + PANEL_H + PANEL_GAP;
            if (byg < minY) {
                const double d = minY - byg;
                byg += d;
                if (bhg > d + 1)
                    bhg -= d;
            }
            const double maxBottom = mon->m_position.y + H - (DOCK_REGION + PANEL_GAP);
            if (byg + bhg > maxBottom)
                bhg = std::max(1.0, maxBottom - byg);
            const double titleH = std::min(TITLEBAR_H, bhg * 0.5);
            const double cyG    = byg + titleH / 2.0;
            for (int i = 0; i < 3; ++i) {
                const double cxG = bxg + bwg - 26 - (2 - i) * 26;
                const double dx = gx - cxG, dy = gy - cyG;
                if (dx * dx + dy * dy <= 11.0 * 11.0) {
                    if (i == 2)
                        Config::Actions::closeWindow(w);
                    else if (i == 1)
                        Config::Actions::fullscreenWindow(FSMODE_MAXIMIZED, w);
                    else
                        Log::logger->log(Log::WARN, "HOS G16: minimize requested (no minimize state yet)");
                    requestRedraw();
                    return true;
                }
            }
        }

        const int    N     = appCount();
        const double pillW = N * DOCK_TILE + (N - 1) * DOCK_GAP + 2 * DOCK_PAD;
        const double pillH = DOCK_TILE + 2 * DOCK_PAD;
        const double pillX = (W - pillW) / 2.0;
        const double pillB = H - DOCK_BOTTOM;
        const double pillY = pillB - pillH;
        const double ty    = pillY + DOCK_PAD;

        if (ly < ty || ly > ty + DOCK_TILE)
            return false;

        for (int i = 0; i < N; ++i) {
            const double tx = pillX + DOCK_PAD + i * (DOCK_TILE + DOCK_GAP);
            if (lx >= tx && lx <= tx + DOCK_TILE) {
                launchDockSlot(i);
                requestRedraw();
                return true;
            }
        }
        return false;
    }
}
