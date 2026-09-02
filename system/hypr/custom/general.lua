-- EpinAnonymOS guest overrides.
--
-- This is dots-hyprland's own override hook: hyprland.lua require()s custom/* AFTER hyprland/*,
-- so anything set here wins without editing the host's files.  The hyprland/ tree is a VERBATIM
-- copy of the host's config and stays that way -- every guest deviation lives in this one file,
-- so the tree remains updatable from the host.
--
-- READ THIS BEFORE TUNING APPEARANCE HERE.  On the default (non-GPU) boot this guest does not
-- run Hyprland's GL renderer at all:
--   * GLRenderer.cpp:1377 sets m_hosCPUFrame when HOS_SCENE_RENDER is off, and
--     Renderer.cpp:2141-2201 wraps the ENTIRE GL scene build in `if (!m_hosCPUFrame)`.
--   * The desktop is painted instead by hardcoded C++ (hosComposeShmWindows and friends).
--     `grep -c CConfigValue GLRenderer.cpp` returns 1, and it is opengl:nvidia_anti_flicker.
--   * `grep -c "m_layers\|LayerSurface" GLRenderer.cpp` returns 0 -- layer-shell surfaces are
--     never composited on that path, so all 74 layer rules in rules.lua are inert and the
--     visible top bar is the hardcoded one, not a config-driven client.
-- So decoration settings below are NOT what makes this desktop look the way it looks, and
-- turning them on would not make it look like the host.  What this config really delivers on
-- the CPU path is behaviour: keybinds, window placement, workspaces, gestures, input, rules.
--
-- The overrides here therefore exist for the GPU path (HOS_SCENE_RENDER=1, set when the
-- compositor comes up on virtio-gpu/virgl), where the GL scene IS built and where this VM's
-- Mesa "softpipe" fallback -- confirmed in the boot log: `Renderer: softpipe`, Mesa's reference
-- rasteriser, slower even than llvmpipe -- would make the host's values unusable.

-- Host runs a HiDPI laptop panel at scale 1.25.  This one is NOT optional: at 1280x800 that
-- gives a cramped 1024x640 logical desktop and puts the CPU compositor's coordinate space on a
-- fractional scale it does not handle cleanly.  Re-declaring the empty-output rule replaces it.
hl.monitor({
    output   = "",
    mode     = "preferred",
    position = "auto",
    scale    = 1
})

hl.config({
    decoration = {
        -- Host: blur { enabled = true, size = 10, passes = 3, xray = true, ... }
        -- Note the host config ALREADY disables window blur itself -- rules.lua:4-7 carries a
        -- catch-all `no_blur = true` for every window, so upstream blur only ever applied to
        -- layer surfaces (their bar/sidebars/overview).  Since this guest composites no layer
        -- surfaces at all, blur is doubly a no-op here.  Kept off so that enabling the GPU path
        -- does not suddenly hand softpipe three full-screen gaussian passes per frame.
        blur = {
            enabled = false
        },

        -- Host: shadow { enabled = true, range = 20, render_power = 10 }.  Unlike blur this is
        -- per-window and not disabled by their rules, so it is the one that would actually bite
        -- on the GPU path with a software rasteriser behind it.
        shadow = {
            enabled = false
        }

        -- Deliberately NOT overridden -- geometry and colour, free on either path, and they are
        -- what carries the host's look if the GL path is ever enabled:
        --   rounding = 18, rounding_power = 2.5
        --   dim_inactive = true, dim_strength = 0.05, dim_special = 0.2
        --   general.gaps_in/out/workspaces, border_size
        --   colors.lua's active/inactive border and background_color (which override the values
        --   in general.lua, because colors.lua is require()d after it)
    },

    -- Host has animations enabled with a full bezier set.  Every animated frame is a full
    -- recomposite; on softpipe a window open would crawl through its curve.  The curves and the
    -- 13 per-leaf animation definitions from general.lua are still parsed and kept -- only
    -- playback is off, so deleting this one block restores the host's exact motion.
    animations = {
        enabled = false
    }
})

-- On real GPU hardware (virtio-gpu with virgl), delete this file: the host's own values then
-- apply unchanged, and the GL path will actually render them.
