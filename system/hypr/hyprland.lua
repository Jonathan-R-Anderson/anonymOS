-- This file sources other files in `hyprland` and `custom` folders
-- You wanna add your stuff in files in `custom`

-- Internal stuff --
require("hyprland.lib")
require("hyprland.services")

-- Environment variables --
require("hyprland.env")
if is_file_exists(HOME .. "/.config/hypr/custom/env.lua") then
    require("custom.env")
end

-- Default configurations --
require("hyprland.execs")
require("hyprland.general")
require("hyprland.rules")
require("hyprland.colors")
require("hyprland.keybinds")

-- Custom configurations --
if is_file_exists(HOME .. "/.config/hypr/custom/execs.lua") then
    require("custom.execs")
end
if is_file_exists(HOME .. "/.config/hypr/custom/general.lua") then
    require("custom.general")
end
if is_file_exists(HOME .. "/.config/hypr/custom/rules.lua") then
    require("custom.rules")
end
if is_file_exists(HOME .. "/.config/hypr/custom/keybinds.lua") then
    require("custom.keybinds")
end
-- ROADMAP 3.0b: settings written by wl-quicksettings.  Sourced LAST of the custom/ files on
-- purpose, so a value the user chose in the panel wins over the image's own custom/general.lua.
--
-- This file is deliberately NOT in the image: it is created at runtime under /home, which
-- `persist = /home` (src/desktop.conf) keeps across reboots, and the blob unpack that stages
-- .config/hypr only writes its own files, so a settings.lua next to them survives.  Guarded by
-- is_file_exists like every other require here, so a machine that has never opened the panel
-- behaves exactly as before.
if is_file_exists(HOME .. "/.config/hypr/custom/settings.lua") then
    require("custom.settings")
end

-- nwg-displays support --
if is_file_exists(HOME .. "/.config/hypr/workspaces.lua") then
    require("workspaces")
end
if is_file_exists(HOME .. "/.config/hypr/monitors.lua") then
    require("monitors")
end

-- Shell overrides --
require("hyprland.shellOverrides.main")
