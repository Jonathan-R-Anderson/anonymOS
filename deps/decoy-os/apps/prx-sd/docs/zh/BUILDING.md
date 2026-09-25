> 本文档为 [English](../BUILDING.md) 版本的中文翻译。

# 从源码构建

## 前提条件

### 必需

- **Rust** 1.70+（通过 [rustup](https://rustup.rs/) 安装）
- **pkg-config**
- **OpenSSL 开发头文件**（用于 reqwest/TLS）

### 可选

- **Node.js** 18+ 和 **npm**（用于 GUI）
- **Tauri CLI**（`cargo install tauri-cli`）（用于 GUI）

### 平台特定依赖

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
- 安装 [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- 安装 [vcpkg](https://github.com/microsoft/vcpkg) 并运行：`vcpkg install openssl`

## 构建 CLI

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

### 特性标志

```bash
# Build with ONNX ML model support
cargo build --release --features onnx

# Build without WASM plugin support (smaller binary)
cargo build --release --no-default-features
```

| 特性 | 默认启用 | 说明 |
|------|----------|------|
| `wasm-runtime` | 是 | WebAssembly 插件支持 (Wasmtime) |
| `onnx` | 否 | ONNX ML 模型推理 (tract-onnx) |

## 构建 GUI

桌面 GUI 使用 Tauri 2 (Rust) + Vue 3 (TypeScript)。

```bash
# Install frontend dependencies
cd gui
npm install

# Development mode (hot reload)
npm run tauri dev

# Production build
npm run tauri build
```

构建产物位于 `gui/src-tauri/target/release/bundle/`。

## 构建更新服务器

```bash
cargo build --release --manifest-path update-server/Cargo.toml
```

## 运行测试

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p prx-sd-core
cargo test -p prx-sd-signatures

# Run integration tests
cargo test --test '*'
```

## 代码质量

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

## 交叉编译

项目在 `.cargo/config.toml` 中包含交叉编译配置。

### Linux ARM64 (aarch64)

```bash
# Install target
rustup target add aarch64-unknown-linux-gnu

# Install cross-compilation toolchain
sudo apt install -y gcc-aarch64-linux-gnu

# Build
cargo build --release --target aarch64-unknown-linux-gnu
```

### macOS（从 Linux 交叉编译）

从 Linux 交叉编译到 macOS 需要 [osxcross](https://github.com/tpoechtrager/osxcross)。

### Windows（从 Linux 交叉编译）

```bash
# Install target
rustup target add x86_64-pc-windows-gnu

# Install cross-compilation toolchain
sudo apt install -y gcc-mingw-w64-x86-64

# Build
cargo build --release --target x86_64-pc-windows-gnu
```

## 打包

预构建的打包脚本位于 `tools/` 目录：

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

平台特定的打包配置位于 `packaging/` 目录：

```
packaging/
├── appimage/       # Linux AppImage
├── completions/    # Shell 补全脚本 (bash, zsh, fish)
├── desktop/        # .desktop 文件
├── filemanager/    # 文件管理器集成脚本
├── homebrew/       # Homebrew formula
├── launchd/        # macOS launch agent plist
├── systemd/        # Linux systemd 服务单元
├── udev/           # Linux udev 规则（USB 自动扫描）
└── windows/        # WiX MSI 安装程序配置
```

## 项目结构

```
prx-sd/
├── Cargo.toml          # 工作区根配置
├── Cargo.lock          # 依赖锁定文件
├── crates/
│   ├── cli/            # sd 二进制程序
│   ├── core/           # 扫描引擎
│   ├── signatures/     # 签名数据库
│   ├── parsers/        # 二进制格式解析器
│   ├── heuristic/      # 启发式 + ML 检测
│   ├── realtime/       # 实时监控
│   ├── quarantine/     # 隔离区
│   ├── remediation/    # 威胁响应
│   ├── sandbox/        # 进程沙箱
│   ├── plugins/        # WASM 插件系统
│   └── updater/        # 更新客户端
├── update-server/      # 签名分发服务器
├── gui/                # Tauri + Vue 3 桌面应用
├── drivers/            # 操作系统内核驱动
├── signatures-db/      # 内嵌签名
├── tests/              # 集成测试
├── tools/              # 构建脚本
└── packaging/          # 分发打包
```
