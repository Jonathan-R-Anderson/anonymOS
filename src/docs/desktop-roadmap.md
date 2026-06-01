# Desktop And GNOME Roadmap

This document turns the high-level "can HanonymOS run GNOME?" question into a concrete execution plan for the current tree.

## Short Answer

HanonymOS cannot boot GNOME today.

The current tree has:

- a native shell-first boot path built around `esh`
- a minimal Wayland compositor stub
- a minimal X11 server aimed at early bring-up
- partial Linux compatibility intended to make progressively larger userland possible

Those pieces are useful, but they are still several layers below what GNOME requires.

## Current Baseline

The codebase already contains the start of a desktop substrate:

- display protocol selection and compositor scaffolding in `src/kernel/d/display/server/server.d`
- a minimal Wayland compositor in `src/kernel/d/display/wayland/wserver.d`
- a minimal X11 server in `src/kernel/d/display/server/x11_server.d`
- DRM/KMS and framebuffer-facing graphics work in `src/kernel/d/drivers/graphics` and `src/util/display`
- an evolving Linux compatibility layer in `src/kernel/d/core/syscalls/posix.d`

The main constraints visible in the current implementation are:

- the display server layer explicitly says the system still lacks the userspace pieces for a real Wayland or X11 runtime
- the X11 server is still bring-up grade and uses TCP port `6000` because the full Unix-socket/filesystem path is not in place yet
- the Wayland compositor is minimal and currently handles only a narrow subset of the protocol
- the Linux-compat layer still contains startup-oriented stubs such as `futex`, `rseq`, and related plumbing
- boot is still centered on `esh`, not on a graphical session manager

## Recommended Strategy

Do not target GNOME first.

Target a staged progression:

1. Stable native desktop primitives
2. Small graphical apps
3. One simple Linux GUI stack
4. A lightweight compositor or window manager
5. GNOME only after the lower layers are real

The Wayland path is the better long-term target. Maintaining a sufficiently complete X11 server for modern desktop software is more work than bringing up a real Wayland compositor and then using Xwayland later if needed.

## Stage 0: Stabilize The Existing Boot And Session Path

Goal: keep the current `esh` bring-up stable enough that it can launch graphical infrastructure instead of only proving that userspace exists.

Concrete work:

- keep `esh` as the default init target until graphical session bootstrap is reliable
- reduce boot-path debug spam so session and compositor failures are visible
- ensure PS/2 and USB input can block correctly instead of spin-looping
- make process launch, exit, and wait semantics reliable enough to supervise a compositor process

Exit criteria:

- `esh` boots reliably
- input does not busy-spin
- launching a long-lived `/sbin/desktop` process is stable

## Stage 1: Finish The Basic OS Services A Desktop Needs

Goal: provide the kernel and userspace substrate that any modern desktop stack expects before graphics become the bottleneck.

Concrete work:

- Unix domain sockets
  - needed for Wayland, D-Bus, and many desktop services
- runtime filesystem paths
  - at minimum `/run`, `/tmp`, `/dev`, and per-user runtime directories
- shared memory and mapping behavior
  - robust `mmap`, shared mappings, `memfd`-style or shm-backed exchange, and correct protections
- polling and readiness APIs
  - reliable `poll`/`select`, then `epoll`
- PTYs and terminal session support
  - needed even if the desktop launches from a shell first
- signals and process-group behavior
  - enough to manage shells, launchers, session daemons, and crash handling
- thread synchronization
  - replace stubbed `futex` behavior with a real scheduler-backed implementation

Exit criteria:

- a multi-process graphical stack can communicate over AF_UNIX sockets
- shared buffers can be exchanged safely
- threads and event loops work under real contention

## Stage 2: Make Wayland Real Enough For Small Clients

Goal: move the current minimal Wayland compositor from protocol bring-up to usable local GUI infrastructure.

Concrete work:

- replace placeholder framebuffer drawing with tracked surface composition
- add real buffer lifecycle handling
- implement damage tracking and output redraw scheduling
- implement seats, keyboard, pointer, and focus semantics
- expose output geometry and mode information correctly
- support a small client test set
  - terminal
  - simple GTK demo
  - a tiny test app using shared-memory buffers

Exit criteria:

- small Wayland clients can connect, create surfaces, render, receive input, and redraw
- the compositor survives connect/disconnect cycles and multiple surfaces

## Stage 3: Bring Up A Real Text And Font Stack

Goal: support legible desktop rendering instead of framebuffer rectangles and fallback-only text.

Concrete work:

- integrate a real font rasterizer and shaping stack
  - FreeType
  - HarfBuzz
- add UTF-8 text rendering in graphical surfaces
- support cursor themes, basic icons, and scalable UI assets
- validate text rendering in both shell-hosted apps and compositor UI

Exit criteria:

- desktop text is rendered with real fonts
- a basic terminal or launcher UI is readable and input-capable

## Stage 4: Strengthen Linux Userspace Compatibility

Goal: run progressively larger Linux userspace components without patching each one into submission.

Concrete work:

- dynamic linking and loader behavior
- more complete file descriptor semantics
- robust `clone`/threading behavior
- real `futex`
- `epoll`, `eventfd`, `timerfd`, `signalfd`
- session and credential semantics expected by desktop middleware
- enough `/proc` and `/sys` compatibility for desktop probing code

Exit criteria:

- a small modern Linux GUI application stack starts without immediate syscall or libc failures
- event-loop-driven software can remain live under load

## Stage 5: Add The Desktop Middleware Layer

Goal: support the service layer that modern desktop environments expect.

Concrete work:

- D-Bus
- user session bus
- settings and service activation support
- clipboard and drag/drop protocol support
- audio/session integration plan
- login/session ownership model
  - this does not need full `systemd` first, but it does need a coherent session model

Exit criteria:

- desktop services can discover one another
- session-scoped daemons can start and stay alive

## Stage 6: Choose The First Real Desktop Target

Goal: prove the platform with a small target before GNOME.

Recommended order:

1. native HanonymOS launcher or panel
2. one lightweight Wayland client
3. a tiny Linux GUI app
4. a lightweight compositor or WM
5. GNOME components only after the above work

Reason:

- GNOME is not just a window manager
- GNOME pulls in Mutter, GTK, GLib, D-Bus, settings/session services, font rendering, graphics acceleration assumptions, and a much more complete POSIX/Linux environment

Practical first targets:

- a native framebuffer/Wayland launcher
- a minimal terminal emulator on Wayland
- `weston-simple-shm`-style clients
- then a small GTK app

## Stage 7: Prepare For GNOME Specifically

Goal: reach the point where GNOME is a packaging and compatibility project, not a research project.

Concrete work:

- run a real Wayland compositor with stable input, outputs, and surface lifecycle
- support the libraries GNOME expects
  - GLib
  - GTK
  - Cairo/Pango
  - D-Bus
  - fontconfig/FreeType/HarfBuzz
- provide GPU and rendering semantics sufficient for Mutter expectations, or deliberately use a software-rendered bring-up path first
- provide session infrastructure GNOME can start under
- add Xwayland later if legacy X11 applications matter

Exit criteria:

- GTK apps run cleanly
- Mutter or a GNOME session component starts without immediate kernel or libc gaps
- the remaining issues are GNOME-specific rather than platform-foundational

## Work Items Mapped To Current Files

The current tree suggests this ownership split:

- `src/kernel/d/display/server/server.d`
  - keep as the high-level display bootstrap and readiness gate
- `src/kernel/d/display/wayland/wserver.d`
  - primary short-term compositor focus
- `src/kernel/d/display/server/x11_server.d`
  - keep only as a compatibility bring-up path, not the main architectural bet
- `src/kernel/d/core/syscalls/posix.d`
  - remove desktop-blocking Linux syscall stubs
- `src/kernel/d/drivers/graphics`
  - continue DRM/KMS and scanout work
- `src/progs/deps/redepend/esh`
  - keep as the recovery shell and session bootstrap host until a graphical launcher replaces it

## Suggested Milestones For This Repo

### Milestone 1: Native Graphical Shell

Build a tiny native launcher started from `esh` or as `/sbin/desktop`.

Features:

- draws a background
- shows a clock or status text
- launches one graphical test client
- handles keyboard and mouse focus

This proves the basic compositor, input, and font path without waiting on Linux desktop compatibility.

### Milestone 2: Small Wayland Client Bring-Up

Run a small client against the in-tree Wayland server.

Features:

- create surface
- attach shm buffer
- commit updates
- receive input events

This is the first point where the Wayland stack becomes more than a protocol experiment.

### Milestone 3: GTK Smoke Test

Once AF_UNIX, shared memory, event loops, and text rendering are reliable, attempt a tiny GTK app.

This is the right checkpoint before any GNOME packaging effort.

### Milestone 4: Desktop Session Bootstrap

Replace the current shell-first boot target with:

- a small init/session supervisor
- compositor start
- service bus start
- launcher/panel start
- fallback to `esh` on failure

### Milestone 5: GNOME Feasibility Check

At this point, evaluate:

- which GNOME components start unchanged
- which fail due to missing kernel behavior
- whether Mutter is viable yet

Only then should the project claim GNOME as an active porting target.

## Recommended Immediate Next Step

For HanonymOS as it exists today, the next desktop step should be:

1. treat `src/kernel/d/display/wayland/wserver.d` as the primary path
2. replace placeholder drawing with real surface and buffer tracking
3. implement AF_UNIX runtime directories cleanly
4. remove the `futex`/threading stubs that block normal GUI middleware
5. launch a tiny graphical client before attempting any desktop environment

That sequence is realistic for this tree.

Trying to boot GNOME before those steps will turn every failure into an unstructured compatibility chase.
