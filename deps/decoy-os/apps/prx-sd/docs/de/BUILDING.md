> Dieses Dokument ist eine deutsche Ubersetzung der [English](../BUILDING.md) Version.

# Aus dem Quellcode bauen

## Voraussetzungen

### Erforderlich

- **Rust** 1.70+ (Installation ueber [rustup](https://rustup.rs/))
- **pkg-config**
- **OpenSSL-Entwicklungsheader** (fuer reqwest/TLS)

### Optional

- **Node.js** 18+ und **npm** (fuer die GUI)
- **Tauri CLI** (`cargo install tauri-cli`) (fuer die GUI)

### Plattformspezifisch

**Debian/Ubuntu:**
```bash
sudo apt install -y build-essential pkg-config libssl-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install -y gcc pkg-config openssl-devel
```

**macOS:**
```bash
xcode-select --install
brew install pkg-config openssl
```

**Windows:**
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) installieren
- [vcpkg](https://github.com/microsoft/vcpkg) installieren und ausfuehren: `vcpkg install openssl`

## CLI bauen

```bash
git clone https://github.com/openprx/prx-sd.git
cd prx-sd

# Debug-Build
cargo build

# Release-Build (optimiert)
cargo build --release

# Die Binaerdatei befindet sich unter:
#   Debug:   target/debug/sd
#   Release: target/release/sd
```

### Feature-Flags

```bash
# Mit ONNX-ML-Modellunterstuetzung bauen
cargo build --release --features onnx

# Ohne WASM-Plugin-Unterstuetzung bauen (kleinere Binaerdatei)
cargo build --release --no-default-features
```

| Feature | Standard | Beschreibung |
|---------|----------|--------------|
| `wasm-runtime` | Ja | WebAssembly-Plugin-Unterstuetzung (Wasmtime) |
| `onnx` | Nein | ONNX-ML-Modellinferenz (tract-onnx) |

## GUI bauen

Die Desktop-GUI verwendet Tauri 2 (Rust) + Vue 3 (TypeScript).

```bash
# Frontend-Abhaengigkeiten installieren
cd gui
npm install

# Entwicklungsmodus (Hot Reload)
npm run tauri dev

# Produktions-Build
npm run tauri build
```

Die erstellte Anwendung befindet sich in `gui/src-tauri/target/release/bundle/`.

## Update-Server bauen

```bash
cargo build --release --manifest-path update-server/Cargo.toml
```

## Tests ausfuehren

```bash
# Alle Tests ausfuehren
cargo test

# Tests fuer ein bestimmtes Crate ausfuehren
cargo test -p prx-sd-core
cargo test -p prx-sd-signatures

# Integrationstests ausfuehren
cargo test --test '*'
```

## Codequalitaet

```bash
# Auf Kompilierungsfehler pruefen (schnell, kein Linking)
cargo check

# Automatische Korrekturen anwenden
cargo fix --allow-dirty

# Code formatieren
cargo fmt

# Lint-Pruefung
cargo clippy -- -D warnings
```

## Cross-Compilation

Das Projekt enthaelt Cross-Compilation-Konfiguration in `.cargo/config.toml`.

### Linux ARM64 (aarch64)

```bash
# Zielplattform installieren
rustup target add aarch64-unknown-linux-gnu

# Cross-Compilation-Toolchain installieren
sudo apt install -y gcc-aarch64-linux-gnu

# Bauen
cargo build --release --target aarch64-unknown-linux-gnu
```

### macOS (von Linux aus)

Cross-Compilation nach macOS von Linux erfordert [osxcross](https://github.com/tpoechtrager/osxcross).

### Windows (von Linux aus)

```bash
# Zielplattform installieren
rustup target add x86_64-pc-windows-gnu

# Cross-Compilation-Toolchain installieren
sudo apt install -y gcc-mingw-w64-x86-64

# Bauen
cargo build --release --target x86_64-pc-windows-gnu
```

## Paketierung

Vorgefertigte Paketierungsskripte befinden sich in `tools/`:

```bash
# Debian-Paket (.deb)
./tools/build-deb.sh

# macOS-Disk-Image (.dmg)
./tools/build-dmg.sh

# Windows-Installer (.msi)
./tools/build-msi.sh

# Linux AppImage
./tools/build-appimage.sh
```

Plattformspezifische Paketierungskonfigurationen befinden sich in `packaging/`:

```
packaging/
├── appimage/       # Linux AppImage
├── completions/    # Shell-Vervollstaendigungen (bash, zsh, fish)
├── desktop/        # .desktop-Dateien
├── filemanager/    # Dateimanager-Integrationsskripte
├── homebrew/       # Homebrew-Formel
├── launchd/        # macOS-Launch-Agent-plist
├── systemd/        # Linux-systemd-Diensteinheit
├── udev/           # Linux-udev-Regeln (USB-Auto-Scan)
└── windows/        # WiX-MSI-Installer-Konfiguration
```

## Projektstruktur

```
prx-sd/
├── Cargo.toml          # Workspace-Stammverzeichnis
├── Cargo.lock          # Abhaengigkeits-Sperrdatei
├── crates/
│   ├── cli/            # sd-Binaerdatei
│   ├── core/           # Scan-Engine
│   ├── signatures/     # Signaturdatenbank
│   ├── parsers/        # Parser fuer Binaerformate
│   ├── heuristic/      # Heuristische + ML-Erkennung
│   ├── realtime/       # Echtzeituberwachung
│   ├── quarantine/     # Quarantaenetresor
│   ├── remediation/    # Bedrohungsbehandlung
│   ├── sandbox/        # Prozess-Sandboxing
│   ├── plugins/        # WASM-Plugin-System
│   └── updater/        # Update-Client
├── update-server/      # Signaturverteilungsserver
├── gui/                # Tauri + Vue 3 Desktop-Anwendung
├── drivers/            # Betriebssystem-Kerneltreiber
├── signatures-db/      # Eingebettete Signaturen
├── tests/              # Integrationstests
├── tools/              # Build-Skripte
└── packaging/          # Distributionspaketierung
```
