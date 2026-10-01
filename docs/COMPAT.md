# Compatibility runtimes — running Windows, macOS and Android software in a domain

anonymOS runs programs built for its own musl Linux personality. Software for other platforms runs
through a **compatibility runtime** installed in a domain:

| Platform | Runtime | Handles | Launcher |
|---|---|---|---|
| Windows | **Wine** (wine-mirror/wine) | PE `.exe`/`.dll` | `hos-wine` |
| macOS | **Darling** (VibeDarling/darling) | Mach-O, `.app` | `hos-darling` |
| Android | **Waydroid** (waydroid/waydroid) | `.apk` | `hos-waydroid` |

The design mirrors how everything else runs here: a runtime is **an application the Domain Manager
delegates to a domain**, and the foreign program then runs *inside that domain* — isolated, badged
and network-routed like any native program in it. Nothing runs in a VM.

## The launcher — `hos-compat` (`src/util/hos-compat.c`)

One small static binary, staged under three names (`hos-wine`, `hos-darling`, `hos-waydroid`); the
name it is run as picks the runtime. Run as the generic `hos-compat <file>` it reads the file's
header and picks the runtime from it (`MZ` → Wine, Mach-O magic → Darling, a Zip `PK` `.apk` →
Waydroid). It finds the runtime the domain already has and execs it; when the runtime is absent it
says which package or build step provides it and exits — it never runs a foreign binary as native.

The three are registered as delegable apps in `src/kernel/d/core/appreg.d` and listed in the Domain
Manager's Applications tab (`src/util/wl-domain-manager.c`), so they are delegated exactly like the
Terminal or Files. The OS image stages the launcher as a boot module (the Makefile).

## Configuring from the Domain Manager

1. Open the **Domain Manager → Applications**.
2. Delegate **Windows apps (Wine)**, **macOS apps (Darling)** or **Android apps (Waydroid)** to the
   domain that should run that platform's software.
3. Install the runtime into that domain (below).
4. Run a program in the domain: `hos-wine program.exe` (from that domain's terminal, or as a file
   handler). The program's own window appears, badged with the domain's colour.

## Installing the runtimes

- **Wine — supported today.** Alpine packages Wine built against musl, so install the `wine` package
  from the **Software Center** into the domain, the same way any tool is installed
  ([[software-center-apk-install]] path). `scripts/build-wine.sh` is only for building a patched or
  newer upstream Wine against this tree's musl sysroot; prefer the package.
- **Darling — build from source.** Not in Alpine. `scripts/build-darling.sh` clones the pinned
  upstream (with submodules, source not vendored) and builds it. See *Porting status*.
- **Waydroid — build from source.** `scripts/build-waydroid.sh` fetches the tooling; the Android
  system image is fetched by Waydroid at init. See *Porting status*.

Each dep follows the Cloud Hypervisor convention: the source is **not vendored**, a pinned commit is
fetched and built by its script, and `deps/{wine,darling,waydroid}/` is git-ignored.

## Porting status (honest)

- **Wine** runs on musl today via Alpine's package; this is the one that works now.
- **Darling** historically needed a Linux kernel module; the project is moving its Mach/BSD
  emulation to usermode. anonymOS is a custom kernel with a musl Linux *personality*, so the
  usermode build is the only viable target, and the Darwin syscalls it relies on (Mach traps, the
  commpage, dyld behaviour) are a bring-up task. Until that lands, `hos-darling` reports
  Darling-not-installed rather than faking a run.
- **Waydroid** needs kernel features anonymOS does not yet provide — `binder` and `ashmem` (Android's
  IPC and shared-memory drivers) and the LXC/namespace stack it containers Android with. That is a
  kernel bring-up task; the tooling and the Domain Manager integration are in place for when it
  exists, and `hos-waydroid` reports Waydroid-not-installed until then.

The integration — delegation, the launcher, the per-domain model — is uniform across all three; what
differs is how much of each runtime can execute today.
