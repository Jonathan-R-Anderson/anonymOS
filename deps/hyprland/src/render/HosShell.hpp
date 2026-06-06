// EpinAnonymOS GUI roadmap G15 — desktop shell state shared between the input
// path (keyboard/pointer interception) and the CPU present path (drawing).
//
// The launcher is a compositor-drawn search overlay (Spotlight/KRunner style):
// Super+Space toggles it, typing filters an app registry, Up/Down select, Enter
// launches the selection via Hyprland's process executor, Escape closes. The
// dock tiles are also made clickable through the same registry.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct xkb_state;

namespace HosShell {
    // Keyboard interception. Returns true if the launcher consumed the key, in
    // which case it must not be forwarded to keybinds or the focused client.
    bool handleKey(uint32_t keycode, bool pressed, xkb_state* xkbState);

    // Pointer interception for dock/launcher clicks at a global cursor position.
    // Returns true if the click was consumed by the shell.
    bool onPointerButton(double globalX, double globalY);

    // Launcher draw state (read by the present path).
    bool                     launcherOpen();
    std::string              query();
    int                      selection();
    std::vector<std::string> visibleLabels();
    int                      visibleCount();

    // App registry size (dock tile count is kept in sync with the renderer).
    int  appCount();
    void launchDockSlot(int slot);
}
