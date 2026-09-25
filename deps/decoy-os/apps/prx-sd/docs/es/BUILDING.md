> Este documento es una traduccion al espanol de la version en [English](../BUILDING.md).

# Compilacion desde el Codigo Fuente

## Requisitos Previos

### Obligatorios

- **Rust** 1.70+ (instalar mediante [rustup](https://rustup.rs/))
- **pkg-config**
- **Cabeceras de desarrollo de OpenSSL** (para reqwest/TLS)

### Opcionales

- **Node.js** 18+ y **npm** (para la GUI)
- **Tauri CLI** (`cargo install tauri-cli`) (para la GUI)

### Especificos por Plataforma

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
- Instalar [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- Instalar [vcpkg](https://github.com/microsoft/vcpkg) y ejecutar: `vcpkg install openssl`

## Compilacion de la CLI

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

| Feature | Por defecto | Descripcion |
|---------|-------------|-------------|
| `wasm-runtime` | Si | Soporte de plugins WebAssembly (Wasmtime) |
| `onnx` | No | Inferencia de modelos ML con ONNX (tract-onnx) |

## Compilacion de la GUI

La interfaz grafica de escritorio utiliza Tauri 2 (Rust) + Vue 3 (TypeScript).

```bash
# Install frontend dependencies
cd gui
npm install

# Development mode (hot reload)
npm run tauri dev

# Production build
npm run tauri build
```

La aplicacion compilada estara en `gui/src-tauri/target/release/bundle/`.

## Compilacion del Servidor de Actualizaciones

```bash
cargo build --release --manifest-path update-server/Cargo.toml
```

## Ejecucion de Pruebas

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p prx-sd-core
cargo test -p prx-sd-signatures

# Run integration tests
cargo test --test '*'
```

## Calidad de Codigo

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

## Compilacion Cruzada

El proyecto incluye configuracion de compilacion cruzada en `.cargo/config.toml`.

### Linux ARM64 (aarch64)

```bash
# Install target
rustup target add aarch64-unknown-linux-gnu

# Install cross-compilation toolchain
sudo apt install -y gcc-aarch64-linux-gnu

# Build
cargo build --release --target aarch64-unknown-linux-gnu
```

### macOS (desde Linux)

La compilacion cruzada a macOS desde Linux requiere [osxcross](https://github.com/tpoechtrager/osxcross).

### Windows (desde Linux)

```bash
# Install target
rustup target add x86_64-pc-windows-gnu

# Install cross-compilation toolchain
sudo apt install -y gcc-mingw-w64-x86-64

# Build
cargo build --release --target x86_64-pc-windows-gnu
```

## Empaquetado

Los scripts de empaquetado preconfigurados estan en `tools/`:

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

Las configuraciones de empaquetado especificas por plataforma estan en `packaging/`:

```
packaging/
├── appimage/       # Linux AppImage
├── completions/    # Completaciones de shell (bash, zsh, fish)
├── desktop/        # Archivos .desktop
├── filemanager/    # Scripts de integracion con el administrador de archivos
├── homebrew/       # Formula de Homebrew
├── launchd/        # Plist del agente de inicio de macOS
├── systemd/        # Unidad de servicio systemd de Linux
├── udev/           # Reglas udev de Linux (escaneo automatico de USB)
└── windows/        # Configuracion del instalador WiX MSI
```

## Estructura del Proyecto

```
prx-sd/
├── Cargo.toml          # Raiz del workspace
├── Cargo.lock          # Archivo de bloqueo de dependencias
├── crates/
│   ├── cli/            # Binario sd
│   ├── core/           # Motor de escaneo
│   ├── signatures/     # Base de datos de firmas
│   ├── parsers/        # Analizadores de formatos binarios
│   ├── heuristic/      # Deteccion heuristica + ML
│   ├── realtime/       # Monitoreo en tiempo real
│   ├── quarantine/     # Boveda de cuarentena
│   ├── remediation/    # Respuesta a amenazas
│   ├── sandbox/        # Aislamiento de procesos
│   ├── plugins/        # Sistema de plugins WASM
│   └── updater/        # Cliente de actualizaciones
├── update-server/      # Servidor de distribucion de firmas
├── gui/                # Aplicacion de escritorio Tauri + Vue 3
├── drivers/            # Controladores del kernel del SO
├── signatures-db/      # Firmas embebidas
├── tests/              # Pruebas de integracion
├── tools/              # Scripts de compilacion
└── packaging/          # Empaquetado para distribucion
```
