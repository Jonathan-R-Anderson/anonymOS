-- EpinAnonymOS guest app mapping.
--
-- hyprland/keybinds.lua require()s this file at its top (lines 2-4) BEFORE it defines a single
-- bind, and every launcher bind it declares is written in terms of these variables:
--
--     hl.bind("SUPER + Return", hl.dsp.exec_cmd(terminal), ...)
--     hl.bind("SUPER + E",      hl.dsp.exec_cmd(fileManager), ...)
--
-- so redefining them here retargets the host's OWN keys at this guest's own applications,
-- without touching hyprland/keybinds.lua.  That keeps muscle memory intact: the key that opens
-- a terminal on the host opens one here too.
--
-- The host values all route through scripts/launch_first_available.sh with a list of desktop
-- apps (foot, kitty, dolphin, firefox, code, ...).  None of those exist in this image, so every
-- one of those binds would silently do nothing.  These are the binaries actually staged into
-- the ISO by stage-iso-tree.

terminal        = "/hos-wifiterm"
fileManager     = "/wl-files"
textEditor      = "/wl-editor"
codeEditor      = "/wl-editor"
taskManager     = "/wl-sysmon"
settingsApp     = "/wl-quicksettings"

-- No guest equivalent: browser, officeSoftware, volumeMixer.  Left pointing at a no-op rather
-- than at the host's launcher script, so the bind fails silently instead of spawning a shell
-- that probes for a dozen absent binaries on every keypress.
browser         = "true"
officeSoftware  = "true"
volumeMixer     = "true"

workspaceGroupSize = 10
