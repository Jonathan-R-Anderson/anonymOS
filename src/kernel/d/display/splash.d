// splash.d — native boot splash for anonymOS.
//
// Recreates the web3-kinetic-loader React splash natively: a particle-network
// animation + a scrolling boot-log console + a progress bar, drawn directly to
// the framebuffer during boot. No browser/HTML engine needed — this uses the
// kernel's existing canvas/framebuffer drawing primitives.
//
// Runs between initPIT() and kernelLoop() at the tail of d_kernel_main. At that
// point the framebuffer is up, pitMs() is ticking (the only monotonic ms clock
// — there is no sleep()), every subsystem the boot-log names is initialized, and
// the userspace compositor has not presented yet, so this owns the framebuffer.
// On exit kernelLoop() runs and the desktop compositor takes the scanout.
//
// The boot-stage list is a faithful port of web3-kinetic-loader/src/data/
// bootSequence.ts (same hand-sync as the React version; a build-time generator
// from klog calls is the natural follow-up). Visual spec (palette, particle
// params, layout) mirrors web3-kinetic-loader/src/components/{LoadingPage,
// ParticleNetwork}.tsx.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module display.splash;

import display.canvas;
import display.framebuffer : framebufferAvailable, initFramebuffer;
import display.common : glyphWidth, glyphHeight;
import core.console : g_fbConsoleEnabled;
import core.random : rdtsc; // TSC — the only monotonic counter usable with interrupts off
import core.io : klog;
// The bootstrap-level Limine framebuffer pointer (set in bootstrap_kernel
// before d_kernel_main). The display module's own g_fb is NOT initialized until
// the (later, lazy) d_init_display heartbeat, so the splash seeds it itself,
// mirroring exactly what d_init_display does (hs_bridge.d:93-102).
import arch.x86_64.bootstrap : g_fb;

// rdtsc comes from core.random (the kernel's existing TSC helper) — paces the
// splash. pitMs()/IRQ0 is frozen before interrupts come on (at the iretq into
// userspace), so we calibrate TSC against pitMs() (briefly enabling interrupts)
// then run the loop on TSC alone.
// The splash runs BEFORE interrupts are enabled (IF comes on only at the
// iretq into userspace), so pitMs()/IRQ0 is frozen and sti is unsafe (firing
// IRQ0 raw, outside kernelLoop's software dispatch, page-faults). We can't
// calibrate TSC against pitMs either. So pace on TSC with a rough estimate:
// modern x86 (incl. QEMU/KVM host passthrough) is ~2-4 GHz; assume 3 GHz.
// The exact wall-time is cosmetic — what matters is the animation runs then
// ENDS (the prior bug was it never ended). If a host is faster/slower the
// splash is just a touch quicker/longer; it always terminates.
private enum ulong TSC_PER_MS_ESTIMATE = 3_000_000UL;

extern (C) @nogc nothrow:

// ── web3 palette (0xAARRGGBB; ported from index.css / tailwind tokens) ────────
enum uint C_BG       = 0xFF1B1F2E; // web3-dark      hsl(230 23% 14%)
enum uint C_PRIMARY  = 0xFF8B6CE6; // web3-primary   hsl(255 54% 59%)
enum uint C_LIGHT    = 0xFF00A4F9; // web3-light     hsl(196 100% 49%)
enum uint C_HILIGHT  = 0xFF3CC8FB; // web3-highlight hsl(199 89% 57%)
enum uint C_CONN     = 0xFF9B87F5; // particle connection / glow
enum uint C_WHITE    = 0xFFFFFFFF;
enum uint C_WHITE70  = 0xFFB3B3B3; // ~white/70 for log messages
enum uint C_DIM      = 0xFF6B6F80; // tag colour (web3-secondary-ish)
enum uint C_PANEL_BG = 0xE6101422; // black/40-ish translucent panel
enum uint C_BAR_BG   = 0xFF11131F; // progress bar track

// Particle palette (ParticleNetwork.tsx:44).
private enum uint[4] PARTICLE_COLORS = [0xFF9B87F5, 0xFF7E69AB, 0xFF33C3F0, 0xFF1EAEDB];

private enum PARTICLE_COUNT = 50;     // base count (grows with progress up to +30)
private enum CONNECT_DIST   = 250;    // px — edge drawn only if distance < this
private enum SPLASH_DURATION = 6000;  // ms (matches React default)
private enum FRAME_MS        = 33;    // ~30fps pacing

// ── particle simulation (fixed table, deterministic seed) ────────────────────
private struct Particle
{
    short x, y;          // position (fixed-point would be nicer; px is fine here)
    short vx, vy;        // velocity per frame
    ubyte radius;        // 2..5
    ubyte colorIdx;      // index into PARTICLE_COLORS
    ubyte alpha255;      // 0..255 (77..255)
}

private __gshared Particle[PARTICLE_COUNT] g_particles;
private __gshared uint g_seed = 0xA10A5EED; // seed; rewritten to a real value at boot

// Deterministic LCG so the particle field is reproducible (and avoids pulling
// in the kernel's entropy source for a cosmetic boot screen).
private uint randNext()
{
    // xorshift32
    uint x = g_seed;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_seed = x;
    return x;
}

private void seedParticles(uint w, uint h)
{
    g_seed = 0xC0FFEE42; // fixed seed → identical particle field every boot
    foreach (ref p; g_particles)
    {
        p.x = cast(short)(randNext() % (w > 1 ? w - 1 : 1) + 1);
        p.y = cast(short)(randNext() % (h > 1 ? h - 1 : 1) + 1);
        p.radius = cast(ubyte)(2 + randNext() % 4);         // 2..5
        p.vx = cast(short)((randNext() % 2 ? 1 : -1) * (1 + randNext() % 1)); // ±1 px
        p.vy = cast(short)((randNext() % 2 ? 1 : -1) * (1 + randNext() % 1));
        p.colorIdx = cast(ubyte)(randNext() % 4);
        p.alpha255 = cast(ubyte)(77 + randNext() % 179);    // 0.3..1.0 *255
    }
}

private void stepParticles(ref Canvas canvas, uint w, uint h, uint progress255)
{
    // how many particles are "active" — grows with progress (50 → 80)
    uint active = PARTICLE_COUNT + (cast(uint)(progress255) * 30) / 255;
    if (active > g_particles.length) active = g_particles.length;

    // connections first (so bodies draw on top)
    foreach (i; 0 .. active)
    {
        foreach (j; i + 1 .. active)
        {
            int dx = g_particles[i].x - g_particles[j].x;
            int dy = g_particles[i].y - g_particles[j].y;
            uint d2 = cast(uint)(dx * dx + dy * dy);
            if (d2 < CONNECT_DIST * CONNECT_DIST)
            {
                // distance fade: alpha = max(0, 1 - d/250) * 0.5 * progress.
                // Avoid core.stdc.math (c_long undefined under -betterC freestanding):
                // approximate d/250 with d2/250² (close enough for a cosmetic fade,
                // and monotonic so the visual gradient is preserved).
                uint alpha = (CONNECT_DIST * CONNECT_DIST - d2) * 128u /
                             (CONNECT_DIST * CONNECT_DIST);
                alpha = (alpha * progress255) / 255u;
                if (alpha > 255) alpha = 255;
                if (alpha > 6) // ~0.02 * 255
                {
                    uint col = (alpha << 24) | (C_CONN & 0x00FFFFFF);
                    canvasLine(canvas, g_particles[i].x, g_particles[i].y,
                               g_particles[j].x, g_particles[j].y, col);
                }
            }
        }
    }
    // bodies + motion integration + bounce
    foreach (i; 0 .. active)
    {
        ref Particle p = g_particles[i];
        canvasCircle(canvas, p.x, p.y, p.radius, PARTICLE_COLORS[p.colorIdx], true);
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 1 || p.x >= cast(short) w) p.vx = cast(short)(-p.vx);
        if (p.y < 1 || p.y >= cast(short) h) p.vy = cast(short)(-p.vy);
        p.x = p.x < 1 ? 1 : (p.x >= cast(short) w ? cast(short)(w - 1) : p.x);
        p.y = p.y < 1 ? 1 : (p.y >= cast(short) h ? cast(short)(h - 1) : p.y);
    }
}

// ── boot stage data (port of bootSequence.ts) ────────────────────────────────
private struct BootStage { const(char)* tag; const(char)* message; }

// 34 stages + the "ready" line. Kept as a fixed array for @nogc walking.
private __gshared immutable BootStage[35] BOOT_STAGES = [
    { "[core]\0".ptr,    "AnonymOS kernel starting\0".ptr },
    { "[core]\0".ptr,    "Enabling SSE; Limine handoff\0".ptr },
    { "[core]\0".ptr,    "Mapping higher-half direct map\0".ptr },
    { "[dkernel]\0".ptr, "D kernel starting; seeding task 0\0".ptr },
    { "[dkernel]\0".ptr, "Sealing initial untyped budget\0".ptr },
    { "[dkernel]\0".ptr, "Initialising entropy source\0".ptr },
    { "[dkernel]\0".ptr, "Standing up device registry (/dev)\0".ptr },
    { "[dkernel]\0".ptr, "Registering users; flipping init subject\0".ptr },
    { "[dkernel]\0".ptr, "Issuing typed admin capabilities\0".ptr },
    { "[dkernel]\0".ptr, "Mounting system namespace\0".ptr },
    { "[dkernel]\0".ptr, "Opening A/B update slots\0".ptr },
    { "[dkernel]\0".ptr, "Bringing up SATA disk layer\0".ptr },
    { "[dkernel]\0".ptr, "Mounting persisted object store\0".ptr },
    { "[dkernel]\0".ptr, "Starting service manager\0".ptr },
    { "[dkernel]\0".ptr, "Registering framebuffer output\0".ptr },
    { "[dkernel]\0".ptr, "Defining security-domain identities\0".ptr },
    { "[dkernel]\0".ptr, "Compiling identity launch rules\0".ptr },
    { "[dkernel]\0".ptr, "Creating per-identity namespaces\0".ptr },
    { "[dkernel]\0".ptr, "Installing cross-identity IPC gate\0".ptr },
    { "[dkernel]\0".ptr, "Arming unspoofable window borders\0".ptr },
    { "[dkernel]\0".ptr, "Building Linux-compat object subtree\0".ptr },
    { "[dkernel]\0".ptr, "Initialising object reference graph\0".ptr },
    { "[dkernel]\0".ptr, "Spawning validator daemon\0".ptr },
    { "[dkernel]\0".ptr, "Applying verified declarative config\0".ptr },
    { "[dkernel]\0".ptr, "Locating init module\0".ptr },
    { "[dkernel]\0".ptr, "Allocating init address space\0".ptr },
    { "[dkernel]\0".ptr, "Loading init ELF image\0".ptr },
    { "[dkernel]\0".ptr, "Loading dynamic linker\0".ptr },
    { "[dkernel]\0".ptr, "Allocating user stack\0".ptr },
    { "[dkernel]\0".ptr, "Programming IDT + SYSCALL MSRs\0".ptr },
    { "[dkernel]\0".ptr, "Remapping PIC (vectors 32-47)\0".ptr },
    { "[dkernel]\0".ptr, "Starting 1000 Hz PIT tick\0".ptr },
    { "[dkernel]\0".ptr, "Enabling PS/2 mouse\0".ptr },
    { "[g11]\0".ptr,     "Arming GUI client autostart\0".ptr },
    { "[dkernel]\0".ptr, "AnonymOS ready\0".ptr }, // BOOT_COMPLETE (index 34)
];

// (renamed splashCstrLen: a plain splashCstrLen collides with device.d at link)
private size_t splashCstrLen(const(char)* s)
{
    size_t n = 0;
    while (s[n] != 0) ++n;
    return n;
}

// ── layout helpers ───────────────────────────────────────────────────────────
// Draw a centred card with the progress %, current-stage label, progress bar,
// and a scrolling boot-log. Coordinates computed from the screen size so it
// adapts to 1280x800, 1920x1080, etc.
private void drawCard(ref Canvas canvas, uint w, uint h, uint progress255)
{
    uint cardW = w < 520 ? w - 40 : 480;
    if (cardW < 200) cardW = 200;
    uint cardH = 360;
    uint cardX = (w - cardW) / 2;
    uint cardY = (h - cardH) / 2;

    // panel background (translucent dark)
    canvasRect(canvas, cardX, cardY, cardW, cardH, C_PANEL_BG, true);
    // border
    canvasRect(canvas, cardX, cardY, cardW, cardH, C_PRIMARY, false);

    // corner brackets (decorative L-marks at the card corners)
    drawBracket(canvas, cardX, cardY, 1, 1);
    drawBracket(canvas, cardX + cardW - 20, cardY, -1, 1);
    drawBracket(canvas, cardX, cardY + cardH - 20, 1, -1);
    drawBracket(canvas, cardX + cardW - 20, cardY + cardH - 20, -1, -1);

    uint pad = 24;
    uint cx = cardX + pad;
    uint cy = cardY + pad;

    // progress percent
    {
        char[8] pct = void;
        uint pctval = (cast(uint) progress255 * 100) / 255;
        // format "NN%"
        pct[0] = cast(char)('0' + pctval / 10);
        pct[1] = cast(char)('0' + pctval % 10);
        pct[2] = '%';
        canvasText(canvas, null, cx, cy, pct[0 .. 3], C_HILIGHT, C_PANEL_BG, true);
    }
    cy += glyphHeight + 8;

    // current stage label (index = progress * 34, or "ready" at 100%)
    uint stageIdx = (cast(uint) progress255 * 34) / 255;
    if (stageIdx > 34) stageIdx = 34;
    {
        const(char)* tag = BOOT_STAGES[stageIdx].tag;
        const(char)* msg = BOOT_STAGES[stageIdx].message;
        canvasText(canvas, null, cx, cy, tag[0 .. splashCstrLen(tag)], C_DIM, C_PANEL_BG, true);
        uint tw = cast(uint)(glyphWidth / 2) * cast(uint) splashCstrLen(tag) + 6;
        canvasText(canvas, null, cx + tw, cy, msg[0 .. splashCstrLen(msg)], C_WHITE70, C_PANEL_BG, true);
    }
    cy += glyphHeight + 10;

    // progress bar
    uint barW = cardW - pad * 2;
    uint barH = 4;
    canvasRect(canvas, cx, cy, barW, barH, C_BAR_BG, true);
    uint fillW = (barW * progress255) / 255;
    if (fillW > 0) canvasRect(canvas, cx, cy, fillW, barH, C_PRIMARY, true);
    cy += barH + 16;

    // boot log: reveal stages [0 .. stageIdx], newest at bottom, fixed window
    uint logLinesMax = (cardH - (cy - cardY) - pad) / glyphHeight;
    if (logLinesMax == 0) logLinesMax = 1;
    uint firstLine = (stageIdx + 1 > logLinesMax) ? (stageIdx + 1 - logLinesMax) : 0;
    for (uint li = firstLine; li <= stageIdx; ++li)
    {
        const(char)* tag = BOOT_STAGES[li].tag;
        const(char)* msg = BOOT_STAGES[li].message;
        uint lx = cx;
        canvasText(canvas, null, lx, cy, tag[0 .. splashCstrLen(tag)], C_DIM, C_PANEL_BG, true);
        lx += (cast(uint)(glyphWidth / 2)) * cast(uint) splashCstrLen(tag) + 6;
        canvasText(canvas, null, lx, cy, msg[0 .. splashCstrLen(msg)], C_WHITE70, C_PANEL_BG, true);
        // " ok" on the right
        uint okx = cx + barW - (cast(uint)(glyphWidth / 2)) * 3;
        canvasText(canvas, null, okx, cy, "ok\0".ptr[0 .. 2], C_LIGHT, C_PANEL_BG, true);
        cy += glyphHeight;
    }
}

private void drawBracket(ref Canvas canvas, uint x, uint y, int dx, int dy)
{
    enum uint LEN = 20;
    // horizontal arm
    canvasLine(canvas, cast(int) x, cast(int) y, cast(int)(x + cast(uint)(dx * LEN)), cast(int) y, C_PRIMARY);
    // vertical arm
    canvasLine(canvas, cast(int) x, cast(int) y, cast(int) x, cast(int)(y + cast(uint)(dy * LEN)), C_PRIMARY);
}

// ── the entry point ──────────────────────────────────────────────────────────
public void splashRun()
{
    // The display module's g_fb is not initialized until the (later, lazy)
    // d_init_display heartbeat. Seed it now from the bootstrap Limine framebuffer,
    // exactly as hs_bridge.d:d_init_display does, so canvas/framebuffer drawing
    // works during the early-boot splash window.
    if (!framebufferAvailable())
    {
        if (g_fb is null) return; // serial-only/headless: nothing to draw
        const bool isBGR = g_fb.blue_mask_shift > g_fb.red_mask_shift;
        initFramebuffer(cast(const(void)*) g_fb.address,
                        cast(uint) g_fb.width, cast(uint) g_fb.height,
                        cast(uint) g_fb.pitch, cast(uint) g_fb.bpp,
                        isBGR, 0, true);
    }
    if (!framebufferAvailable()) return;

    Canvas canvas = createFramebufferCanvas();
    if (!canvas.available) return;

    // Stop the kernel text console scribbling over our splash (serial keeps
    // logging). The userspace compositor will claim the framebuffer next.
    g_fbConsoleEnabled = false;

    const uint w = canvas.width;
    const uint h = canvas.height;
    seedParticles(w, h);

    // Pace on TSC with the rough estimate (interrupts are off; see note above).
    const ulong cyclesPerMs = TSC_PER_MS_ESTIMATE;
    const ulong durationCycles = cyclesPerMs * SPLASH_DURATION;
    const ulong frameCycles = cyclesPerMs * FRAME_MS;

    const ulong start = rdtsc();
    for (;;)
    {
        ulong elapsed = rdtsc() - start;
        uint progress255; // 0..255
        if (elapsed >= durationCycles)
            progress255 = 255;
        else
            progress255 = cast(uint)((elapsed * 255) / durationCycles);

        // render frame
        canvasFill(canvas, C_BG);
        stepParticles(canvas, w, h, progress255);
        drawCard(canvas, w, h, progress255);

        if (progress255 >= 255) break;

        // pace to ~30fps (busy-wait on TSC — interrupts are off, no pitMs)
        const ulong frameStart = rdtsc();
        while (rdtsc() - frameStart < frameCycles) {}
    }

    // brief hold on the final frame (~400ms via TSC), then hand off to the
    // compositor (kernelLoop → iretq re-enables interrupts normally).
    const ulong holdCycles = cyclesPerMs * 400;
    const ulong doneAt = rdtsc();
    while (rdtsc() - doneAt < holdCycles) {}
}
