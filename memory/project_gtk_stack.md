---
name: GTK3 / GLib / GIO support
description: GTK3 + GLib + GIO + Pango + Cairo integration into HanonymOS
type: project
---

Full GTK3 support layer integrated on top of the musl/busybox/OpenRC/elogind stack.

**Kernel syscall additions** — `src/kernel/d/core/syscalls/posix.d`:

*epoll / eventfd / socketpair (GLib main loop):*
- `linux_sys_epoll_create1` / `epoll_ctl` / `epoll_pwait` — real implementations backed by `EpollInst[16]` global table; `epoll_pwait` does synchronous readability poll via `fdReadable`/`fdWritable` helpers
- `linux_sys_eventfd2` — counter-based eventfd with `EFD_SEMAPHORE` flag, backed by `g_eventfd_counters[32]` globals
- `linux_sys_socketpair` — unidirectional pipe pair (covers GLib wakeup write+poll pattern)
- `FD_EPOLL` / `FD_EVENTFD` FileType enum values; `allocFd()` helper added

*xattr group (188–199):* All return ENOTSUP/0 (list* return 0 = empty)

*Other GTK syscalls:*
- `linux_sys_readlinkat` (267) — delegates to `linux_sys_readlink` for absolute paths
- `linux_sys_mremap` (25) — ENOSYS (GLib falls back to malloc)
- `linux_sys_recvmmsg` (299), `linux_sys_sendmmsg` (308) — ENOSYS
- `linux_sys_copy_file_range` (326) — ENOSYS
- `linux_sys_faccessat2` (439) — delegates to `linux_sys_access`
- `linux_sys_name_to_handle_at` (303), `linux_sys_open_by_handle_at` (304) — ENOSYS

**Virtual filesystem additions** — new entries in `g_vfs`:
- `/etc/fonts/fonts.conf` — fontconfig config pointing to `/usr/share/fonts`
- `/etc/gtk-3.0/settings.ini` — GTK theme/font settings (hicolor, Sans 10)
- `/usr/lib/pango/1.0/modules.cache` — empty (Pango skips module scan)
- `/usr/share/glib-2.0/schemas/gschemas.compiled` — empty (GLib uses defaults)
- `/etc/locale.conf`, `/usr/share/locale/locale.alias` — C locale
- `/usr/share/mime/mime.cache` — empty (GIO falls back to sniffing)
- `/proc/self/environ` — basic env vars (HOME, PATH, WAYLAND_DISPLAY, XDG_RUNTIME_DIR, LANG)
- `/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache` — empty

**Synthetic directory paths** (`isSyntheticDirectoryPath` / `isVirtualDirectoryPath`):
- Added: `/etc/fonts`, `/etc/gtk-3.0`, `/usr/share/glib-2.0/schemas`, `/usr/lib/pango/1.0`, `/usr/lib/gdk-pixbuf-2.0/2.10.0`, `/usr/share/fonts`, `/usr/share/icons`, `/usr/share/themes`, `/usr/share/mime`, `/usr/share/locale`, `/usr/share/X11/xkb`, `/usr/lib/girepository-1.0`, `/usr/share`, `/var/cache/fontconfig`
- Prefix patterns also added to `isVirtualDirectoryPath`

**Haskell dispatch** — `src/kernel/hs/Hos/LinuxCompat.hs`:
- 23 new `foreign import ccall` declarations for GTK-layer syscalls
- New dispatch cases: 25, 188–199, 267, 299, 303, 304, 308, 326
- Fixed case 439: was `newfstatat` (wrong), corrected to `faccessat2`

**Build infrastructure**:
- `deps/gtk-stack/Makefile` — 18-package GTK3 static build chain against musl-clang:
  zlib → libffi → pcre2 → libpng → pixman → bzip2 → freetype → expat →
  fontconfig → harfbuzz → glib → wayland (client) → xkbcommon → cairo →
  pango → gdk-pixbuf → atk → gtk3
- All packages built static (`--disable-shared` / `-Ddefault_library=static`)
- Output: `deps/gtk-stack/sysroot/` (libs + headers) + `deps/gtk-stack/gtk-hello` (test binary)
- `deps/Makefile` — added `gtk-stack` target (depends on `musl`)
- Root `Makefile` — ISO build copies `gtk-hello` to `cd/` if present
- `src/boot/limine.conf` — added `module_path: boot():/gtk-hello`

**Why:** GTK apps need epoll (GLib main loop), eventfd (GLib wakeup), fontconfig (text rendering), Wayland connection to `/run/user/1000/wayland-0` (served by wserver.d). Fully functional once fork/execve are implemented in the Haskell scheduler.

**How to apply:** When adding more GTK/GLib features, check that `/run/user/1000/wayland-0` socket path is still served by wserver.d. The Wayland backend connects there at startup.
