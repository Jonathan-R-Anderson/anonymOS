-- EpinAnonymOS guest overrides.
--
-- This is dots-hyprland's own override hook: hyprland.lua require()s custom/* AFTER hyprland/*,
-- so anything set here wins without editing the host's files.  The hyprland/ tree is a VERBATIM
-- copy of the host's config and stays that way -- every guest deviation lives in this one file,
-- so the tree remains updatable from the host.
--
-- 2026-09-03: the deviations below are now CONDITIONAL on the render path, instead of always on.
-- Two things changed that make that both possible and necessary:
--
--   * a564a31c58 exports HOS_SCENE_RENDER=1 for Hyprland unconditionally, so Hyprland's real GL
--     scene IS built now.  Previously GLRenderer.cpp:1377 set m_hosCPUFrame and the whole scene
--     build was skipped, the desktop being painted by hardcoded C++ (hosComposeShmWindows) -- on
--     that path decoration settings genuinely did nothing.  They do something now.
--
--   * The kernel exports GALLIUM_DRIVER=softpipe ONLY on the no-GPU path (exports.d:1141, inside
--     `if (!isCompositorGpu)`).  That makes it an exact, runtime-accurate test for "am I running
--     on Mesa's reference rasteriser" -- no build-time guessing.
--
-- So: on softpipe the host's blur/shadow/animation values remain unusable and stay off.  Boot
-- with `GPU=1 ./qemu-run.sh` (virtio-gpu-gl + virgl) and this file steps aside, letting the
-- host's own values apply unchanged.  That is what makes the guest look like the host, and it no
-- longer requires deleting this file by hand.

local softpipe = os.getenv("GALLIUM_DRIVER") == "softpipe"

-- Host runs a HiDPI laptop panel at scale 1.25.  Kept at 1 on BOTH paths deliberately: at this
-- VM's 1280x800 a 1.25 scale yields a cramped 1024x640 logical desktop, which looks less like the
-- host rather than more.  To match the host exactly, give the VM a HiDPI-sized mode first and
-- then raise this to 1.25 -- resolution has to come before scale, not after.
hl.monitor({
    output   = "",
    mode     = "preferred",
    position = "auto",
    scale    = 1
})

if softpipe then
    hl.config({
        decoration = {
            -- Host: blur { enabled = true, size = 10, passes = 3, xray = true, ... }
            -- Note the host config ALREADY disables window blur itself -- rules.lua:4-7 carries a
            -- catch-all `no_blur = true` for every window, so upstream blur only ever applied to
            -- layer surfaces (their bar/sidebars/overview).  Three full-screen gaussian passes
            -- per frame on a reference rasteriser is not a tradeoff worth offering.
            blur = {
                enabled = false
            },

            -- Host: shadow { enabled = true, range = 20, render_power = 10 }.  Unlike blur this
            -- is per-window and NOT disabled by their rules, so it is the one that actually bites
            -- with a software rasteriser behind it.
            shadow = {
                enabled = false
            }

            -- Deliberately NOT overridden even here -- geometry and colour are free on either
            -- path, and they are what carries the host's look:
            --   rounding = 18, rounding_power = 2.5
            --   dim_inactive = true, dim_strength = 0.05, dim_special = 0.2
            --   general.gaps_in/out/workspaces, border_size
            --   colors.lua's active/inactive border and background_color (which override the
            --   values in general.lua, because colors.lua is require()d after it)
        },

        -- Host has animations enabled with a full bezier set.  Every animated frame is a full
        -- recomposite; on softpipe a window open would crawl through its curve.  The curves and
        -- the 13 per-leaf animation definitions from general.lua are still parsed and kept --
        -- only playback is off, so on the GPU path the host's exact motion returns untouched.
        animations = {
            enabled = false
        }
    })
end

-- UNCONDITIONAL: this one is a kernel property, not a renderer property.
--
-- The kernel fails DRM_NR_MODE_CURSOR/CURSOR2 with EINVAL on purpose so the compositor
-- composites the pointer itself -- true on the virgl path as much as on softpipe.  The host
-- leaves cursor:no_hardware_cursors at its default 2 ("auto"), which resolves to FALSE here
-- (case 2 is nvidia+mgpu/VRR), so Hyprland would attempt a HARDWARE cursor on every pointer
-- update.  That attempt is not free: attemptHardwareCursor() runs a whole RENDER_MODE_FULL_FAKE
-- pass before drmModeSetCursor fails and it falls back to the software cursor anyway.  It is
-- also the source of the "legacy drm: cursor null failed" spam in the boot log.
--
-- Forcing 1 skips that dead end and routes motion through damageIfSoftware(), so the pointer
-- tracks properly instead of moving at the damage-driven fallback rate.
hl.config({
    cursor = {
        no_hardware_cursors = 1,
        use_cpu_buffer      = 0
    }
})
