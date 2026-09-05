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
            },

            -- 2026-09-04: rounding and dim_inactive are now overridden here too.  The note
            -- this replaces claimed "geometry and colour are free on either path".  Colour is;
            -- ROUNDING IS NOT.  Hyprland implements rounded corners as a per-fragment SDF in
            -- the window shader, and rounding_power = 2.5 (anything other than 2) evaluates a
            -- pow() for EVERY pixel of EVERY window, every frame.  dim_inactive adds a further
            -- full-window pass on top.  On the GPU path those cost nothing measurable; on Mesa
            -- softpipe -- which this image runs WITHOUT LLVM, so llvmpipe's JIT is not there
            -- either (deps/mutter/Makefile:561 builds -Dgallium-drivers=swrast,virgl and its
            -- own comment says "no LLVM") -- every fragment is executed interpreted, on the
            -- compositor's own thread.
            --
            -- Measured, from a full boot's serial.log: the desktop presented 66 frames while
            -- the freeze probe reported 40 stalled seconds -- about ONE FRAME PER SECOND, with
            -- flipQ incrementing by exactly 1 per stall episode.  The freeze probe's CMP= field
            -- read `w0 p0 f0` on every one of those stalls: Hyprland was neither poll-parked
            -- nor futex-parked but RUNNABLE the whole time, i.e. burning a second of CPU per
            -- frame rather than waiting on anything.  That is what the user sees as windows
            -- "disappearing": a desktop that repaints slower than once a second.
            --
            -- rounding = 0 also makes rounding_power moot, so the pow() disappears entirely.
            rounding      = 0,
            dim_inactive  = false

            -- Still deliberately NOT overridden -- these are genuinely free, and they are what
            -- carries the host's look:
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

-- UNCONDITIONAL: a CORRECTNESS setting, not an aesthetic or renderer one, so it is not gated
-- on softpipe.  It changes only how much of a frame is redrawn, never how the result looks.
--
-- THE BUG IT FIXES: "the window borders all load, but the windows themselves disappear after
-- they initially load."
--
-- Hyprland's default is 2 (= DAMAGE_TRACKING_FULL, ConfigValues.cpp:622), which redraws only
-- the damaged sub-region of the frame.  That is only correct if the renderer can tell what the
-- buffer it is drawing into already contains -- and aquamarine hands it a swapchain of THREE
-- rotating buffers ("Swapchain: Reconfigured ... XR24 of length 3"), so the undamaged parts of
-- the frame have to be inherited from a buffer that is two frames stale.  Whatever this stack
-- reports for buffer age, the inheritance does not hold here: the region outside the damage
-- comes back without the window content in it.
--
-- The boot log shows the transition exactly.  Renderer.cpp forces a few full frames at startup
-- and then stops:
--     HOSDBG renderMonitor #1   ... forceFull=5
--     HOSDBG renderMonitor #61  ... forceFull=0
--     HOSDBG renderMonitor #121 ... forceFull=0
-- Windows are present for the forced full frames and vanish once forceFull hits 0 and partial
-- rendering takes over -- i.e. they "disappear after they initially load".  The borders survive
-- because they are NOT drawn by the compositor at all: drmSetHosWindows() in posix.d paints them
-- straight into the framebuffer whenever the window list changes, deliberately "even without a
-- fresh present blit".  So the borders are kernel-drawn and stay; the contents are
-- compositor-drawn and go.
--
-- Mode 1 (= DAMAGE_TRACKING_MONITOR) is the right setting rather than 0:
--   * Renderer.cpp:2217 -- NONE *or* MONITOR adds the whole monitor to the frame damage, so a
--     rendered frame is always complete and the stale-buffer inheritance never applies.
--   * Renderer.cpp:321  -- the "nothing changed, skip this frame" early-out is taken for every
--     mode EXCEPT NONE, so mode 1 still renders NOTHING while the desktop is idle.
-- Mode 0 would also fix the corruption but would redraw unconditionally, forever, which is the
-- opposite of what is wanted here.
--
-- Net effect: no redraw at all unless something is actually damaged, and a whole correct frame
-- when there is.  The finer-grained "redraw only the damaged rectangle" is given up deliberately
-- -- it is the exact path that loses the window contents on this stack.
hl.config({
    debug = {
        damage_tracking = 1
    }
})

-- UNCONDITIONAL: pointer acceleration OFF, so the compositor's pointer tracks the KERNEL's
-- cursor 1:1.
--
-- Two pointers exist in this guest.  The kernel draws its own cursor straight into the
-- framebuffer (cursorSetPos/cursorPaint) so motion stays snappy even when the compositor is
-- busy, and the compositor maintains its own pointer from the evdev stream.  Clicks land where
-- the COMPOSITOR thinks the pointer is, but the user aims with the one the KERNEL draws, so any
-- divergence between them makes clicks miss what they are pointing at.
--
-- The kernel used to avoid that by reporting EV_ABS absolute positions, which no acceleration
-- curve can distort.  That stopped working under Hyprland (clicks reached no client at all --
-- see the note in syscalls/posix.d), so it now reports EV_REL deltas like an ordinary mouse.
-- Relative deltas DO go through libinput's pointer-acceleration filter, which would make the
-- two cursors drift apart the moment the user moves quickly.
--
-- flat + sensitivity 0 is libinput's identity transform: one device unit is one pixel, always.
-- That restores the property the absolute path was chosen for, without needing an absolute
-- device that libinput handles poorly.
hl.config({
    input = {
        accel_profile      = "flat",
        sensitivity        = 0,
        force_no_accel     = true
    }
})
