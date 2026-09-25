> Ce document est une traduction en francais de la version [English](../BUILDING.md).

# Compilation depuis les sources

## Prerequis

### Requis

- **Rust** 1.70+ (installer via [rustup](https://rustup.rs/))
- **pkg-config**
- **En-tetes de developpement OpenSSL** (pour reqwest/TLS)

### Optionnels

- **Node.js** 18+ et **npm** (pour l'interface graphique)
- **Tauri CLI** (`cargo install tauri-cli`) (pour l'interface graphique)

### Specifiques a la plateforme

**Debian/Ubuntu :**
```bash
sudo apt install -y build-essential pkg-config libssl-dev
```

**Fedora/RHEL :**
```bash
sudo dnf install -y gcc pkg-config openssl-devel
```

**macOS :**
```bash
xcode-select --install
brew install pkg-config openssl
```

**Windows :**
- Installer [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- Installer [vcpkg](https://github.com/microsoft/vcpkg) et executer : `vcpkg install openssl`

## Compilation du CLI

```bash
git clone https://github.com/openprx/prx-sd.git
cd prx-sd

# Debug build
cargo build

# Release build (optimized)
cargo build --release

# The binary is at:
#   Debug:   target/debug/sd
#   Release: target/release/sd
```

### Drapeaux de fonctionnalites

```bash
# Build with ONNX ML model support
cargo build --release --features onnx

# Build without WASM plugin support (smaller binary)
cargo build --release --no-default-features
```

| Fonctionnalite | Par defaut | Description |
|-----------------|------------|-------------|
| `wasm-runtime` | Oui | Prise en charge des plugins WebAssembly (Wasmtime) |
| `onnx` | Non | Inference de modeles ML ONNX (tract-onnx) |

## Compilation de l'interface graphique

L'interface graphique de bureau utilise Tauri 2 (Rust) + Vue 3 (TypeScript).

```bash
# Install frontend dependencies
cd gui
npm install

# Development mode (hot reload)
npm run tauri dev

# Production build
npm run tauri build
```

L'application compilee se trouve dans `gui/src-tauri/target/release/bundle/`.

## Compilation du serveur de mise a jour

```bash
cargo build --release --manifest-path update-server/Cargo.toml
```

## Execution des tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p prx-sd-core
cargo test -p prx-sd-signatures

# Run integration tests
cargo test --test '*'
```

## Qualite du code

```bash
# Check for compilation errors (fast, no linking)
cargo check

# Apply automatic fixes
cargo fix --allow-dirty

# Format code
cargo fmt

# Lint
cargo clippy -- -D warnings
```

## Compilation croisee

Le projet inclut une configuration de compilation croisee dans `.cargo/config.toml`.

### Linux ARM64 (aarch64)

```bash
# Install target
rustup target add aarch64-unknown-linux-gnu

# Install cross-compilation toolchain
sudo apt install -y gcc-aarch64-linux-gnu

# Build
cargo build --release --target aarch64-unknown-linux-gnu
```

### macOS (depuis Linux)

La compilation croisee vers macOS depuis Linux necessite [osxcross](https://github.com/tpoechtrager/osxcross).

### Windows (depuis Linux)

```bash
# Install target
rustup target add x86_64-pc-windows-gnu

# Install cross-compilation toolchain
sudo apt install -y gcc-mingw-w64-x86-64

# Build
cargo build --release --target x86_64-pc-windows-gnu
```

## Empaquetage

Des scripts d'empaquetage pre-configures sont disponibles dans `tools/` :

```bash
# Debian package (.deb)
./tools/build-deb.sh

# macOS disk image (.dmg)
./tools/build-dmg.sh

# Windows installer (.msi)
./tools/build-msi.sh

# Linux AppImage
./tools/build-appimage.sh
```

Les configurations d'empaquetage specifiques a chaque plateforme se trouvent dans `packaging/` :

```
packaging/
├── appimage/       # Linux AppImage
├── completions/    # Completions shell (bash, zsh, fish)
├── desktop/        # Fichiers .desktop
├── filemanager/    # Scripts d'integration au gestionnaire de fichiers
├── homebrew/       # Formule Homebrew
├── launchd/        # Plist d'agent de lancement macOS
├── systemd/        # Unite de service systemd Linux
├── udev/           # Regles udev Linux (analyse automatique USB)
└── windows/        # Configuration de l'installateur WiX MSI
```

## Structure du projet

```
prx-sd/
├── Cargo.toml          # Racine de l'espace de travail
├── Cargo.lock          # Fichier de verrouillage des dependances
├── crates/
│   ├── cli/            # Binaire sd
│   ├── core/           # Moteur d'analyse
│   ├── signatures/     # Base de donnees de signatures
│   ├── parsers/        # Analyseurs de formats binaires
│   ├── heuristic/      # Detection heuristique + ML
│   ├── realtime/       # Surveillance en temps reel
│   ├── quarantine/     # Coffre-fort de quarantaine
│   ├── remediation/    # Reponse aux menaces
│   ├── sandbox/        # Sandboxing de processus
│   ├── plugins/        # Systeme de plugins WASM
│   └── updater/        # Client de mise a jour
├── update-server/      # Serveur de distribution des signatures
├── gui/                # Application de bureau Tauri + Vue 3
├── drivers/            # Pilotes noyau du systeme d'exploitation
├── signatures-db/      # Signatures integrees
├── tests/              # Tests d'integration
├── tools/              # Scripts de compilation
└── packaging/          # Empaquetage pour la distribution
```
