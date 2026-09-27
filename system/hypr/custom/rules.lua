-- Overlay-plane window rules (2026-09-27).
--
-- These apps are FIXED-SIZE utility windows (or belong on the floating overlay layer):
-- the Domain Manager's layout is fixed-pixel and does NOT reflow, so Hyprland correctly
-- floats it (min==max) — but a floating window sitting on top of the tiled workspace is
-- exactly the "the Domain Manager covers everything" problem.  Routing these to the
-- special:overlay workspace (the SUPER+SPACE overlay plane) keeps them OFF the tiled
-- desktop entirely: the normal workspace stays cleanly tiled, and these utilities live
-- on the toggle-able overlay layer instead.
--
-- Normal reflowing apps (Software Center, Editor, Files, …) are deliberately NOT listed,
-- so they keep tiling on the normal workspace.
local overlay_apps = {
    "epin-domain-manager",   -- wl-domain-manager (fixed-pixel layout, must float)
    "epin-g4-term",          -- wl-term  (terminal)
    "epin-sysmon",           -- wl-sysmon (system monitor)
    "epin-calc",             -- wl-calc  (calculator)
}
for _, cls in ipairs(overlay_apps) do
    hl.window_rule({ match = { class = "^(" .. cls .. ")$" }, float     = true })
    hl.window_rule({ match = { class = "^(" .. cls .. ")$" }, workspace = "special:overlay" })
end
