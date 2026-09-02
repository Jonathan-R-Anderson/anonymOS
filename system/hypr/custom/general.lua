-- EpinAnonymOS guest overrides.
--
-- This is dots-hyprland's own override hook: hyprland.lua require()s custom/* AFTER
-- hyprland/*, so anything set here wins over the defaults without editing them.  The
-- hyprland/ tree is therefore a VERBATIM copy of the host's config and stays that way,
-- which keeps it updatable -- every guest-specific deviation lives in this one file.
--
-- Everything below is here because the guest renders on Mesa "softpipe" (confirmed in the
-- boot log: `Renderer: softpipe`).  That is Mesa's reference software rasteriser -- not
-- even llvmpipe -- so anything that reads back the full framebuffer per frame costs
-- whole seconds, not milliseconds.  Appearance settings that are just geometry or colour
-- (gaps, border, rounding, dim, all of colors.lua) are FREE here and are left untouched,
-- so the desktop still reads as the host's.

-- Host runs a HiDPI laptop panel at scale 1.25.  This guest is a 1280x800 VM, where 1.25
-- would give a cramped 1024x640 logical desktop AND force softpipe to render at native
-- res then downscale every frame.  Re-declaring the empty-output monitor rule replaces it.
hl.monitor({
    output   = "",
    mode     = "preferred",
    position = "auto",
    scale    = 1
})

hl.config({
    decoration = {
        -- Host: blur { enabled = true, size = 10, passes = 3, xray = true, ... }
        -- Each pass is a full-screen gaussian; 3 passes down+up at 1280x800 on softpipe is
        -- seconds per frame.  This is THE setting that would make the desktop unusable.
        blur = {
            enabled = false
        },

        -- Host: shadow { enabled = true, range = 20, render_power = 10 }
        -- A 20px shadow is another large per-window blur on the same software path.
        shadow = {
            enabled = false
        }

        -- Deliberately NOT overridden, because they are cheap and carry most of the look:
        --   rounding = 18, rounding_power = 2.5
        --   dim_inactive = true, dim_strength = 0.05, dim_special = 0.2
        --   general.gaps_in/out/workspaces, border_size, col.active_border/inactive_border
        --   misc.background_color, and every window/layer rule in rules.lua
    },

    -- Host has animations enabled with a full bezier set.  On softpipe every animated frame
    -- is a full software recomposite, so a window open would crawl through its curve.  The
    -- curves and per-leaf animation definitions from general.lua are still parsed and kept;
    -- only playback is off, so removing this one line restores the host's exact motion.
    animations = {
        enabled = false
    }
})

-- To go fully faithful on better hardware (real GPU / virtio-gpu with virgl), delete this
-- file -- the host's own values then apply unchanged.
