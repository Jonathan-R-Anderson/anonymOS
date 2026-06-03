# Hyprland HanonymOS Port

Hyprland is vendored at `../hyprland` with upstream submodules checked out.
This directory contains HanonymOS-specific build glue so the upstream checkout
can stay clean.

Build entry points:

```bash
make -C deps hyprland-status
make deps-hyprland
```

The port is not expected to build until the musl sysroot has Hyprland's current
dependency stack:

- Aquamarine, hyprlang, hyprutils, hyprcursor, hyprgraphics
- hyprwayland-scanner and hyprland-protocols
- wayland-protocols >= 1.47, xkbcommon >= 1.11, libinput >= 1.29
- glslang, re2, muparser, Lua 5.5-compatible headers/libs

Runtime blockers in HanonymOS remain `fork`/`clone`/`execve`, writable
`/run`/`$XDG_RUNTIME_DIR`, real `futex` blocking, signal delivery, and enough
DRM/GBM/EGL behavior for Aquamarine's backend.
