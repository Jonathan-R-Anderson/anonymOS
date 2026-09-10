# DENDRITIC_NETWORK_ROADMAP — phasing the dendritic anonymous overlay into anonymOS

**Goal.** Run the dendritic anonymous-overlay node (`syndichan-node`) natively inside anonymOS as the
system's anonymizing network layer — the **I2P replacement**. This roadmap covers the *OS-side*
integration and phasing; the overlay protocol itself (AXON) is built in the node and tracked
upstream in `../dendritic/roadmap/` (`axon-overlay-network.md`, `OUTSTANDING.md`).

Conventions follow the other roadmaps here: each phase ends with a **falsifiable exit criterion**,
and unfinished/uncertain work is labelled rather than hidden.

## What this is

`dendritic/dendritic-node` (`syndichan-node`) is a large **Go** program — a storage + HTTPS-gateway
node (libp2p/Kademlia, erasure-coded content store, an Ethereum light client, payment channels). It
anonymises peer traffic; **today it outsources anonymity to I2P** (dials a SAM bridge at
`127.0.0.1:7656` and exits if absent — `dendritic/dendritic-node/internal/config/config.go:582`).

**AXON** is the plan to replace that I2P dependency with a native overlay (onion circuits, tunnel
pools, guard selection, a blinded DHT, on-chain naming). It is **110 outstanding items** upstream.
"Inside the OS" therefore means: host the node in anonymOS, give it a transport, and carry AXON in
as it lands upstream.

## Desktop integration — the network graph as the system wallpaper · ✅ DONE

Independently of the node phases below, the dendritic network's **radial keyspace topology** — the
graph the website embedded (`../dendritic/backend/templates/includes/peer-canvas.html`) — is now the
anonymOS desktop wallpaper. Peers sit on a ring at `sha256(node id)` folded into [0,1) (the DHT's own
placement, so ring neighbours are keyspace neighbours), joined by keyspace-adjacency (Kademlia-finger)
chords bowed through the centre, each node a role-coloured glowing dot on the panel's dark ground
(`#0d1117`). Pipeline:
- `tools/wallpaper-gen/` — a pure-Go renderer (stdlib only) that reproduces peer-canvas.html's palette,
  layout and glow from a **deterministic** synthetic fleet, emitting a PNG. `make wallpaper` regenerates
  it; the PNG is committed (`system/hypr/wallpapers/dendritic-network.png`) so the ISO builds without Go.
- `src/util/wl-wallpaper.c` — a wlr-layer-shell **BACKGROUND** client (software `wl_shm`, libpng, the
  wl-layer-bar + wl-imgview patterns) that blits the PNG "contain"-scaled with the image's own ground as
  seamless letterbox fill. No GPU, no async gatherer — immune to the stock-wallpaper mallocng crash.
- The kernel launches it next to the top bar (`spawnWaylandProgram("wl-wallpaper", "[wall]")`); the PNG
  ships both in the Hyprland config tree and as a `/dendritic-network.png` boot module. Needed because
  Hyprland paints only a solid colour and this image ships no wallpaper daemon (quickshell/hyprpaper/swww
  are all absent).

This is a **visual** integration only: it does not run, replace, or depend on the node — `syndichan-node`
is retained and unchanged. A later step can point the generator at the node's own live peer view instead
of the synthetic fleet, turning the wallpaper into a real network readout.

## Phases

### P0 — Node builds for anonymOS · ✅ DONE
- Cross-compile `syndichan-node` to a **static x86-64 Linux ELF** (`CGO_ENABLED=0`, ~32 MB — no C
  runtime needed at run time on anonymOS).
- Wire it into the anonymOS build **opt-in**: `make syndichan-node`; `stage-iso-tree` stages it as a
  limine boot module (`/syndichan-node`) *only if built*, so a Go-less build host still makes a
  normal ISO.
- **Exit (met):** `make syndichan-node` emits a static ELF64; a normal ISO build lists
  `Included syndichan-node`; the binary runs on real Linux and reaches `starting I2P transport`.

### P1 — Go runtime survives anonymOS · [IN PROGRESS]

**Syscall inventory (done).** `strace -f -c` of a minimal Go binary (`tests/go-runtime/hello.go` —
println + `time.Sleep` + a goroutine/channel) gives the runtime's startup set:
`futex`, **`nanosleep` (×25)**, `clone`, `epoll_create1/ctl/pwait`, `eventfd2`, `mmap/madvise`, the
signal machinery (`rt_sigaction ×114`, `sigaltstack`, `rt_sigprocmask`, `tgkill`, `rt_sigreturn`),
`gettid`, `sched_getaffinity`, `prlimit64`, `prctl`, `arch_prctl`, `fcntl`. anonymOS **dispatches and
implements all of them** — the one real gap was `nanosleep`.

**`nanosleep` fixed (done).** It was a no-op returning 0, so `time.Sleep` returned instantly and the
runtime busy-spun. Now the dispatcher parks the task on a deadline exactly like `poll`'s timed park —
`nanosleep(35)` and relative `clock_nanosleep(230)`; woken by the PIT-tick backstop; a signal
interrupts it with `-EINTR` (`src/kernel/d/core/kernel_main.d`, tag `DENDRITIC_NETWORK_ROADMAP P1`).
Absolute `clock_nanosleep` (TIMER_ABSTIME) is left no-op (its timespec is a clock value, not a
duration).

**Remaining (needs the build host):**
- Boot anonymOS with `tests/go-runtime/hello` staged/launched and confirm `GO-RUNTIME-OK` on serial;
  fix whatever the boot surfaces. `futex`/`clone`/`epoll`/`eventfd2` are real; `sched_getaffinity`
  returns 0 (Go falls back to 1 CPU — fine). **Prime suspect: `sigaltstack` is a stub** (`return 0`
  without installing an alt signal stack), and Go delivers async-preemption `SIGURG` on it — if the
  boot crashes in signal handling, wire `sigaltstack` first.
- Then launch `syndichan-node` and confirm it reaches `starting I2P transport` with no runtime
  panic/hang.
- **Exit:** the trivial Go binary prints `GO-RUNTIME-OK` and exits cleanly on booted anonymOS; then
  `syndichan-node` reaches its transport init.

### P2 — Transport bring-up (direct, non-anonymous, clearly labelled) · [BUILD NOW]
Give the node networking (anonymOS LKL) and remove the hard I2P/SAM exit so it runs end to end.
- Provide a local bridge the node can dial, or a direct/loopback transport for a first bring-up.
- **Exit:** two nodes exchange a stored shard over the direct transport; the dashboard/S3 endpoint is
  reachable from the OS. The path is explicitly marked **non-anonymous** (interim only).

### P3 — Auto-launch as an OS service · [BUILD NOW]
- Kernel launch hook next to the dbus/sshd launchers
  (`spawnWaylandProgram("syndichan-node", "[axon]")` in `kernel_main.d`), a config, and lifecycle
  (restart, logging to `/run`).
- **Exit:** the node comes up at boot without manual steps and survives a compositor stall.

### P4 — AXON anonymizing transport (the actual I2P replacement) · [UPSTREAM, large]
Replace the direct transport with AXON's onion transport. This is the substance of "the I2P
replacement" and the bulk of the work; it is built in the node and tracked in
`../dendritic/roadmap/OUTSTANDING.md` (onion circuits, tunnel pools, guards, blinded DHT, naming).
- **Exit:** peer traffic traverses AXON circuits; no clearnet peer IPs are observable; the SAM/I2P
  dependency is deleted from the node's run path.

### P5 — Deniability + hardening · [NEEDS RESEARCH]
Fit the node to the deniable-OS model: which volume its state lives on (decoy vs hidden), whether it
runs in the decoy at all, resource limits, and **no clearnet leak** that distinguishes a hidden-OS
boot. Coordinate with `INSTALLER` (§H) and `DECOY_SECURITY_REVIEW`.
- **Exit:** a security review confirms running the node adds no hidden-OS tell and no deanonymising
  side channel.

## Build

```sh
make syndichan-node        # static build/syndichan-node (needs a Go toolchain, 1.21+)
make WESTON=0 all          # stages the node if it was built
make hos-install.iso       # ISO carries /syndichan-node as a boot module
```

## Blockers

- **P1–P5 need the kernel/ISO build host** (`192.168.1.181`, D toolchain); the node binary builds
  locally with Go, but nothing boots into anonymOS until that host is up.
- P4 is gated on upstream AXON progress (`../dendritic/roadmap/`).
