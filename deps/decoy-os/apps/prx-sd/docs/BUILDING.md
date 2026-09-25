# Building from Source

## Prerequisites

### Required

- **Rust** 1.70+ (install via [rustup](https://rustup.rs/))
- **pkg-config**
- **OpenSSL development headers** (for reqwest/TLS)

### Optional

- **Node.js** 18+ and **npm** (for GUI)
- **Tauri CLI** (`cargo install tauri-cli`) (for GUI)

### Platform-specific

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
- Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- Install [vcpkg](https://github.com/microsoft/vcpkg) and run: `vcpkg install openssl`

## Building the CLI

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

### Feature Flags

```bash
# Build with ONNX ML model support
cargo build --release --features onnx

# Build without WASM plugin support (smaller binary)
cargo build --release --no-default-features
```

| Feature | Default | Description |
|---------|---------|-------------|
| `wasm-runtime` | Yes | WebAssembly plugin support (Wasmtime) |
| `onnx` | No | ONNX ML model inference (tract-onnx) |

## Building the GUI

The desktop GUI uses Tauri 2 (Rust) + Vue 3 (TypeScript).

```bash
# Install frontend dependencies
cd gui
npm install

# Development mode (hot reload)
npm run tauri dev

# Production build
npm run tauri build
```

The built application will be in `gui/src-tauri/target/release/bundle/`.

## Building the Update Server

```bash
cargo build --release --manifest-path update-server/Cargo.toml
```

## Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p prx-sd-core
cargo test -p prx-sd-signatures

# Run integration tests
cargo test --test '*'
```

## Code Quality

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

## Cross-Compilation

The project includes cross-compilation config in `.cargo/config.toml`.

### Linux ARM64 (aarch64)

```bash
# Install target
rustup target add aarch64-unknown-linux-gnu

# Install cross-compilation toolchain
sudo apt install -y gcc-aarch64-linux-gnu

# Build
cargo build --release --target aarch64-unknown-linux-gnu
```

### macOS (from Linux)

Cross-compiling to macOS from Linux requires [osxcross](https://github.com/tpoechtrager/osxcross).

### Windows (from Linux)

```bash
# Install target
rustup target add x86_64-pc-windows-gnu

# Install cross-compilation toolchain
sudo apt install -y gcc-mingw-w64-x86-64

# Build
cargo build --release --target x86_64-pc-windows-gnu
```

## Packaging

Pre-built packaging scripts are in `tools/`:

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

Platform-specific packaging configs are in `packaging/`:

```
packaging/
├── appimage/       # Linux AppImage
├── completions/    # Shell completions (bash, zsh, fish)
├── desktop/        # .desktop files
├── filemanager/    # File manager integration scripts
├── homebrew/       # Homebrew formula
├── launchd/        # macOS launch agent plist
├── systemd/        # Linux systemd service unit
├── udev/           # Linux udev rules (USB auto-scan)
└── windows/        # WiX MSI installer config
```

## Project Structure

```
prx-sd/
├── Cargo.toml          # Workspace root
├── Cargo.lock          # Dependency lock file
├── crates/
│   ├── cli/            # sd binary
│   ├── core/           # Scan engine
│   ├── signatures/     # Signature database
│   ├── parsers/        # Binary format parsers
│   ├── heuristic/      # Heuristic + ML detection
│   ├── realtime/       # Real-time monitoring
│   ├── quarantine/     # Quarantine vault
│   ├── remediation/    # Threat response
│   ├── sandbox/        # Process sandboxing
│   ├── plugins/        # WASM plugin system
│   └── updater/        # Update client
├── update-server/      # Signature distribution server
├── gui/                # Tauri + Vue 3 desktop app
├── drivers/            # OS kernel drivers
├── signatures-db/      # Embedded signatures
├── tests/              # Integration tests
├── tools/              # Build scripts
└── packaging/          # Distribution packaging
```
