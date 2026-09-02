-- EpinAnonymOS guest startup.
--
-- hyprland.lua require()s custom/execs.lua after hyprland/execs.lua, and hl.on() is ADDITIVE --
-- the host's own startup block still runs.  Everything it launches (quickshell, kitty, hypridle,
-- easyeffects, gnome-keyring, cliphist/wl-paste, dbus-update-activation-environment) is absent
-- from this image, so each of those exec_cmd calls fails harmlessly; they are left in place so
-- hyprland/execs.lua stays a verbatim copy of the host's file.
--
-- The top bar is NOT started here: the kernel spawns it directly
-- (spawnWaylandProgram("wl-layer-bar") in kernel_main.d), independent of the compositor config.

hl.on("hyprland.start", function()
    -- Domain Manager on the desktop at login.
    --
    -- The previous kernel-embedded config reached it only through a keybind, and porting the
    -- host's Lua config dropped every guest bind with it -- which is what took the domain
    -- manager off the desktop.  The binds are restored in custom/keybinds.lua
    -- (SUPER+SHIFT+D), and it is ALSO reachable from /wl-overview and /wl-quicksettings, both
    -- of which list it as "Settings".  Starting it here is what makes it *present* rather than
    -- merely reachable, which is the documented way to get a permanent window --
    -- see src/desktop.conf: "To restore a permanent window, add e.g. autostart = /wl-domain-manager".
    --
    -- Delete this one line for a clean desktop at boot; SUPER+SHIFT+D still opens it.
    hl.exec_cmd("/wl-domain-manager")
end)
