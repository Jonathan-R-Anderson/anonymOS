# Graphical Applications Roadmap

**Goal:** the 124 listed graphical applications available by default, running on the Linux
layers.

**Thesis:** do not hand-write 124 Wayland clients. The 18 that exist today are bespoke C
clients (`src/util/wl-*.c`), each ~1–3k lines against raw `wl_compositor` + Cairo. That
approach does not scale to 124, and it is no longer necessary: **GTK 3 with the Wayland
backend is already built for musl in `deps/gtk-stack/sysroot`** (`gtk+-wayland-3.0.pc`,
`gdk-wayland-3.0.pc`), `gtk-hello` already runs as a boot module, and a static Qt 6 stack
exists at `deps/qt-stack`. The work is therefore to **finish the Linux application runtime**
and then bring up real upstream applications on it — writing new native clients only where
an app must talk to kernel objects that no upstream program knows about.

---

## Status summary

| | Count |
|---|---|
| Shipping today | 18 |
| Reachable by extending an existing client | 17 |
| Blocked only on the app runtime (Stage A) | 54 |
| Blocked on a device/driver capability | 21 |
| Large ports, deliberately last | 14 |
| **Total** | **124** |

---

## Stage A — Application runtime

Everything in Stages C–E is blocked here. Nothing else should start until A is green.

- **A1. Dynamic loading for arbitrary binaries.** `ld-musl-x86_64.so.1` is staged and
  Hyprland is dynamically linked, so the loader works. Verify a *non-staged* binary can be
  `execve`'d from `/compat/linux` rather than only from a boot module, and that `dlopen` of a
  library not present at link time resolves.
- **A2. Filesystem the apps expect.** `/compat/linux/{bin,sbin,usr,lib}` per
  `OBJECT_FILESYSTEM_ROADMAP.md`, plus `/proc/self/*`, `/sys/class/*`, `/dev/{null,zero,urandom,dri/*,input/*}`,
  `/etc/{passwd,group,localtime,fonts}`, `$XDG_RUNTIME_DIR`. Most monitor-type apps read
  `/proc` and nothing else — A2 alone unblocks a large fraction of Stage C.
- **A3. Syscall surface.** Audit against `roadmap/syscalls_roadmap.md`. GTK needs
  `inotify`, `eventfd`, `signalfd`, `timerfd`, `memfd_create`, `poll/ppoll`, `mmap` with
  `MAP_SHARED`. Record which are missing rather than discovering them one crash at a time —
  the `[exec] not found:` and `ENOSYS` lines in `serial.log` are the instrument.
- **A4. GTK 3 app that is not `gtk-hello`.** Bring up one real upstream GTK app end-to-end
  (suggest `gnome-calculator` — small, pure GTK, no D-Bus requirement). This is the gate for
  Stage C; until one real app runs, every estimate below is speculation.
- **A5. Font/icon/theme resolution.** `fonts.blob`, `icons.blob`, `themes.blob` are staged;
  confirm `fontconfig` and `gtk-icon-theme` actually resolve from them inside a GTK process.
- **A6. App registration.** `wl-overview`'s grid is a hardcoded C array
  (`src/util/wl-overview.c`). Replace with a scan of `/usr/share/applications/*.desktop` so a
  new app appears by shipping a file, not by editing and recompiling the launcher.
- **A7. D-Bus session bus.** `hos-dbus-launch` exists. Many GTK apps degrade gracefully
  without it but some hard-fail; establish which.

## Stage B — Extend existing clients

Cheap: each is a tab or view on a client that already exists, not a new program.

- **B1. `wl-sysmon`** → Task Manager, Process Viewer, Resource Monitor, Memory Monitor,
  CPU Monitor, Disk Monitor, Network Monitor. One process table plus per-resource views;
  seven list entries, one program.
- **B2. `wl-quicksettings`** → Volume Control, Power Manager, Display Manager, Keyboard/
  Mouse/Touchpad Settings, Date/Time, Language/Region, Appearance/Theme. These are panels
  over existing kernel config objects.
- **B3. `wl-domain-manager`** → User Manager, Startup Applications, Service Manager. It
  already renders domains/identities; these are adjacent views on the same objects.
- **B4. `wl-logview`** → System Log Viewer (done), Notification Manager.
- **B5. `wl-files`** → File Search, Disk Usage Analyzer.
- **B6. `wl-editor`** → Hex Editor, Code Editor (syntax highlighting), System Configuration
  Editor.

## Stage C — Upstream apps on the runtime

Gated on A4. Each is "cross-build an existing GTK app", not "write an app". Ordered by
build weight.

- **C1. `/proc` readers** — Hardware Information Viewer, System Information, USB/PCI Device
  Manager, Sensor Monitor, Battery Monitor, Network Connections Viewer, Routing Table Viewer.
  These need A2 and little else.
- **C2. Small GTK apps** — Notes, To-Do, Contacts, Alarm/Timer, Color Picker, Font Viewer,
  Archive Manager, Screen Recorder, Audio Recorder, Clipboard Manager, On-Screen Keyboard.
- **C3. Document/media viewers** — PDF Viewer, Document Viewer, Photo Manager, Media/Audio/
  Video Player. Need poppler and a codec stack; `libjxl`, `libwebp`, `libjpeg`, `libpng` and
  `cairo` are already in the sysroot.
- **C4. Network clients** — SSH Client (`dropbear` and `scp` already ship), FTP/SFTP, VPN,
  Remote Desktop, Torrent, Network Diagnostic Tool, DNS Configuration, Serial Terminal.
- **C5. Security** — Password Manager, Keyring Manager, Certificate Manager, GPG Key Manager
  (`gpgv` already ships), Firewall Manager, Firewall Monitor, Disk Encryption Manager
  (`deps/veracrypt` exists).
- **C6. Disk** — Disk Utility, Partition Editor, Disk Health Monitor. The GPT code in the
  kernel (`[diskpart] GPT proof PASS`) already does the hard part; these are front-ends.
- **C7. Developer tools** — Git Client, Diff/Merge Tool, Debugger, Desktop Search.
- **C8. Graphics** — Paint, Image Editor, Vector Graphics Editor, PDF Editor, 3D Model Viewer.
- **C9. Accessibility** — Screen Magnifier, Screen Reader, Text-to-Speech. Screen Reader and
  TTS need an audio path (E-tier) and an accessibility bus.

## Stage D — Device-blocked

Not runtime work — these need a driver or subsystem that does not exist yet.

- **D1. Audio** — Audio Mixer, Volume Control (real), Audio Player, Audio Recorder. Needs an
  audio driver plus PipeWire; `deps/pipewire` exists but is unwired to any hardware.
- **D2. Bluetooth Manager** — needs a Bluetooth stack. LKL is the plausible route
  (`BARE_METAL_ROADMAP.md`).
- **D3. Printer/Scanner Manager** — CUPS/SANE, or defer indefinitely.
- **D4. Webcam Viewer, CD/DVD Burner** — V4L2 and optical drivers via LKL.
- **D5. GPU Monitor** — needs virgl/DRM counters; ties into `VIRGL_BLOB_ROADMAP.md`.
- **D6. Network Manager (full)** — partially present (`hos-nm-launch`, `wl-wifi-menu`);
  see `NETWORK_AND_MARKETPLACE_ROADMAP.md` and `WIFI_AUTODRIVER_ROADMAP.md`.

## Stage E — Large ports, last

Each is a project in itself. Listed so the estimate is honest, not to be started soon.

- **E1. Web Browser.** The single largest item by an order of magnitude. Needs a full
  JS engine, network stack, and GPU compositing. Nothing else here is comparable.
- **E2. Office Suite** — Word Processor, Spreadsheet, Presentation Editor.
- **E3. IDE** — depends on C7.
- **E4. Virtual Machine Manager / Container Manager.** anonymOS has no hypervisor (no
  VT-x/VMCS/EPT anywhere in `src/kernel/d`), so VM management means managing *domains*, not
  guests — likely a `wl-domain-manager` view rather than a port. Container Manager maps onto
  the existing domain/template machinery.
- **E5. Email Client, Cloud Storage Client, File Synchronization Client, CAD.**
- **E6. Window Manager / Desktop Environment.** Already satisfied by Hyprland + the
  `wl-*` suite; listed for completeness. The host's own shell is **quickshell** (Qt6/QML,
  `qs -c $qsConfig`), which is the real gap if host parity is the goal.

---

## Inventory

Status: **✅** shipping · **B** Stage B extension · **C** Stage C port · **D** device-blocked
· **E** large port

| # | Application | Status | Vehicle |
|---|---|---|---|
| 1 | Terminal Emulator | ✅ | `wl-term`, `hos-term`, `gl-term` |
| 2 | File Manager | ✅ | `wl-files` |
| 3 | Text Editor | ✅ | `wl-editor` |
| 4 | Calculator | ✅ | `wl-calc` |
| 5 | System Monitor | ✅ | `wl-sysmon` |
| 6 | Task Manager | B1 | `wl-sysmon` |
| 7 | Settings | ✅ | `wl-quicksettings` |
| 8 | Control Center | ✅ | `wl-domain-manager` |
| 9 | Display Manager | B2 | `wl-quicksettings` |
| 10 | Keyboard Settings | B2 | `wl-quicksettings` |
| 11 | Mouse Settings | B2 | `wl-quicksettings` |
| 12 | Touchpad Settings | B2 | `wl-quicksettings` |
| 13 | Audio Mixer | D1 | audio driver + PipeWire |
| 14 | Volume Control | D1 | audio driver + PipeWire |
| 15 | Network Manager | D6 | `hos-nm-launch` (partial) |
| 16 | Wi-Fi Manager | ✅ | `wl-wifi-menu` |
| 17 | Bluetooth Manager | D2 | LKL Bluetooth |
| 18 | Power Manager | B2 | `wl-quicksettings` |
| 19 | Printer Manager | D3 | CUPS |
| 20 | Scanner Manager | D3 | SANE |
| 21 | User Manager | B3 | `wl-domain-manager` |
| 22 | Date/Time Manager | B2 | `wl-quicksettings` |
| 23 | Language/Region Settings | B2 | `wl-quicksettings` + `xkb.blob` |
| 24 | Accessibility Settings | B2 | `wl-quicksettings` |
| 25 | Appearance Settings | B2 | `themes.blob` |
| 26 | Theme Manager | B2 | `themes.blob` |
| 27 | Window Manager | ✅ | Hyprland |
| 28 | Desktop Environment | ✅ | Hyprland + `wl-*` |
| 29 | Screenshot Utility | ✅ | `wl-screenshot` |
| 30 | Screen Recorder | C2 | wlr-screencopy |
| 31 | Clipboard Manager | C2 | `wl_data_device` |
| 32 | Archive Manager | C2 | `bsdtar`, `libarchive` present |
| 33 | Disk Utility | C6 | kernel GPT engine |
| 34 | Disk Usage Analyzer | B5 | `wl-files` |
| 35 | Partition Editor | C6 | kernel GPT engine |
| 36 | File Search | B5 | `wl-files` |
| 37 | PDF Viewer | C3 | poppler |
| 38 | Document Viewer | C3 | poppler |
| 39 | Image Viewer | ✅ | `wl-imgview` |
| 40 | Photo Manager | C3 | |
| 41 | Media Player | C3 | codecs |
| 42 | Audio Player | D1 | audio driver |
| 43 | Video Player | C3 | codecs |
| 44 | Webcam Viewer | D4 | V4L2 via LKL |
| 45 | Audio Recorder | D1 | audio driver |
| 46 | CD/DVD Burner | D4 | optical via LKL |
| 47 | Web Browser | E1 | — |
| 48 | Email Client | E5 | |
| 49 | Calendar | ✅ | `wl-calendar` |
| 50 | Contacts | C2 | |
| 51 | Notes | C2 | |
| 52 | To-Do Manager | C2 | |
| 53 | Clock | ✅ | `wl-clocks` |
| 54 | Alarm/Timer | C2 | `wl-clocks` adjacent |
| 55 | Remote Desktop Client | C4 | |
| 56 | SSH Client | C4 | `dropbear`, `ssh`, `scp` staged |
| 57 | FTP/SFTP Client | C4 | |
| 58 | Torrent Client | C4 | |
| 59 | VPN Client | C4 | |
| 60 | Network Diagnostic Tool | C4 | `hos-nettest` |
| 61 | Serial Terminal | C4 | kernel already drives COM1/COM2 |
| 62 | Hex Editor | B6 | `wl-editor` |
| 63 | Code Editor | B6 | `wl-editor` |
| 64 | IDE | E3 | |
| 65 | Git Client | C7 | |
| 66 | Diff/Merge Tool | C7 | |
| 67 | Debugger | C7 | |
| 68 | System Log Viewer | ✅ | `wl-logview` |
| 69 | Hardware Information Viewer | C1 | `/proc`, `/sys` |
| 70 | USB Device Manager | C1 | LKL xHCI |
| 71 | PCI Device Manager | C1 | kernel enumerates PCI |
| 72 | Disk Health Monitor | C6 | SMART via AHCI |
| 73 | Sensor Monitor | C1 | |
| 74 | GPU Monitor | D5 | virgl counters |
| 75 | Battery Monitor | C1 | ACPI |
| 76 | Font Viewer | C2 | `fonts.blob` |
| 77 | Character Map | ✅ | `wl-chars` |
| 78 | Color Picker | C2 | |
| 79 | Password Manager | C5 | |
| 80 | Keyring Manager | C5 | |
| 81 | Certificate Manager | C5 | |
| 82 | Firewall Manager | C5 | |
| 83 | GPG Key Manager | C5 | `gpgv` staged |
| 84 | Disk Encryption Manager | C5 | `deps/veracrypt` |
| 85 | Paint Application | C8 | Cairo |
| 86 | Image Editor | C8 | |
| 87 | Vector Graphics Editor | C8 | `librsvg` present |
| 88 | PDF Editor | C8 | poppler |
| 89 | 3D Model Viewer | C8 | GLES |
| 90 | CAD Application | E5 | |
| 91 | Office Suite | E2 | |
| 92 | Word Processor | E2 | |
| 93 | Spreadsheet | E2 | |
| 94 | Presentation Editor | E2 | |
| 95 | File Synchronization Client | E5 | |
| 96 | Cloud Storage Client | E5 | |
| 97 | Virtual Machine Manager | E4 | domains, not guests |
| 98 | Container Manager | E4 | domain/template engine |
| 99 | Package Manager | ✅ | `store-app` + kernel pkg engine |
| 100 | Application Manager | ✅ | `store-app` |
| 101 | Software Center | ✅ | `store-app` |
| 102 | Update Manager | C2 | kernel A/B update engine exists |
| 103 | Process Viewer | B1 | `wl-sysmon` |
| 104 | Service Manager | B3 | kernel service engine exists |
| 105 | Startup Applications Manager | B3 | `spawnWaylandClients()` |
| 106 | Notification Manager | B4 | |
| 107 | Screen Magnifier | C9 | |
| 108 | Screen Reader | C9 | needs D1 |
| 109 | On-Screen Keyboard | C2 | |
| 110 | Text-to-Speech Manager | C9 | needs D1 |
| 111 | Desktop Search | C7 | |
| 112 | Application Launcher | ✅ | `wl-overview` |
| 113 | System Information | C1 | |
| 114 | System Configuration Editor | B6 | `/config/*.json` |
| 115 | Registry/Configuration Editor | B6 | object store |
| 116 | Network Connections Viewer | C1 | |
| 117 | Routing Table Viewer | C1 | |
| 118 | DNS Configuration Tool | C4 | |
| 119 | Firewall Monitor | C5 | |
| 120 | Resource Monitor | B1 | `wl-sysmon` |
| 121 | Memory Monitor | B1 | `wl-sysmon` |
| 122 | CPU Monitor | B1 | `wl-sysmon` |
| 123 | Network Monitor | B1 | `wl-sysmon` |
| 124 | Disk Monitor | B1 | `wl-sysmon` |

---

## Order of work

1. **A6** — `.desktop` scanning. Cheapest item here and it decouples every later stage from
   editing `wl-overview.c`.
2. **B1** — seven list entries from one `wl-sysmon` process table.
3. **A2 + A4** — the runtime gate. Until one real upstream GTK app runs, Stage C is unproven.
4. **B2/B3** — the settings surface.
5. **C1** — `/proc` readers, once A2 lands.
6. Everything else in Stage order.

**Do not** start Stage E until A–C are green.
