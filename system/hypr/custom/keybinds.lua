-- EpinAnonymOS guest-only application binds.
--
-- custom/keybinds.lua is require()d by hyprland.lua AFTER hyprland/keybinds.lua, so these are
-- additive.  The host's own keys are retargeted at guest apps in custom/variables.lua; what is
-- left are the applications this OS has and a desktop Linux does not, which therefore have no
-- key in the host config at all.
--
-- These were the binds carried by the previous kernel-embedded hyprlang config.  Porting the
-- Lua config without them is what took the domain manager off the desktop -- nothing else
-- launches it: the top bar is spawned by the kernel (spawnWaylandProgram("wl-layer-bar") in
-- kernel_main.d), but every application was reachable only through these bindings.

hl.bind("SUPER + SHIFT + D", hl.dsp.exec_cmd("/wl-domain-manager"), { description = "Domain Manager (Qubes-style domains)" })
hl.bind("SUPER + A",         hl.dsp.exec_cmd("/wl-overview"),       { description = "Window overview" })
hl.bind("SUPER + C",         hl.dsp.exec_cmd("/wl-calendar"),       { description = "Calendar" })
hl.bind("SUPER + W",         hl.dsp.exec_cmd("/wl-wifi-menu"),      { description = "Wi-Fi menu" })
hl.bind("SUPER + N",         hl.dsp.exec_cmd("/wl-quicksettings"),  { description = "Quick settings" })
hl.bind("SUPER + ALT + L",   hl.dsp.exec_cmd("/wl-logview"),        { description = "Log viewer" })
hl.bind("SUPER + SHIFT + T", hl.dsp.exec_cmd("/wl-term"),           { description = "Terminal (wl-term)" })
hl.bind("SUPER + SHIFT + F", hl.dsp.exec_cmd("/wl-files"),          { description = "Files" })
hl.bind("SUPER + SHIFT + E", hl.dsp.exec_cmd("/wl-editor"),         { description = "Text editor" })
hl.bind("SUPER + SHIFT + M", hl.dsp.exec_cmd("/wl-sysmon"),         { description = "System monitor" })
hl.bind("SUPER + SHIFT + S", hl.dsp.exec_cmd("/wl-screenshot"),     { description = "Screenshot" })
hl.bind("SUPER + SHIFT + A", hl.dsp.exec_cmd("/store-app"),         { description = "App store" })

-- ROADMAP 2.3: upstream GTK's own demos, unmodified.  The point of binding them is that they are
-- NOT ours -- gtk-hello was written for this OS and so proves only that the toolkit links, while
-- widget-factory exercises most of the widget set, CSS theming and icon lookup in one process.
hl.bind("SUPER + SHIFT + W", hl.dsp.exec_cmd("/gtk3-widget-factory"), { description = "GTK widget factory (upstream)" })
hl.bind("SUPER + SHIFT + G", hl.dsp.exec_cmd("/gtk3-demo"),           { description = "GTK demo (upstream)" })
-- gtk-hello is the CONTROL for the 2.3 investigation: same toolkit, same musl link, but a tiny
-- app.  If it maps a window and widget-factory does not, the difference is the application, not
-- the GTK stack underneath it.
hl.bind("SUPER + SHIFT + H", hl.dsp.exec_cmd("/gtk-hello"),           { description = "gtk-hello (GTK control)" })
-- ROADMAP 2.3: the same client under libwayland's protocol trace.  A launcher binary rather than
-- an env prefix, because Hyprland execs directly (no shell, and no /bin/sh exists) and the
-- kernel's env block does not reach a process Hyprland forked.  Takes NO argument: a keybinding
-- whose command has arguments is routed through a shell, and with no /bin/sh present that execs an
-- empty program name ("[exec] not found: /bin/").  Only single-word commands work here.
hl.bind("SUPER + SHIFT + J", hl.dsp.exec_cmd("/hos-wl-trace"),
        { description = "gtk-hello + wayland protocol trace" })

-- Toggle the kernel-spawned top bar by touching the flag file it polls.
-- STILL BROKEN, and the /busybox swap above does not fix it: a keybinding command with arguments
-- is routed through a shell, and there is no /bin/sh, so it execs an empty program name.  Only
-- single-word commands run here.  This needs the same treatment as hos-wl-trace -- a small
-- launcher binary that does the toggle itself -- rather than a shell one-liner.
hl.bind("SUPER + B", hl.dsp.exec_cmd("/busybox sh -c \"[ -e /run/hos-bar.hidden ] && rm -f /run/hos-bar.hidden || : > /run/hos-bar.hidden\""),
        { description = "Toggle top bar" })

-- Kept from the host's own custom/keybinds.lua.
hl.bind("CTRL + SUPER + ALT + Slash", hl.dsp.exec_cmd("/wl-editor /home/user/.config/hypr/custom/keybinds.lua"),
        { description = "Edit user keybinds" })
