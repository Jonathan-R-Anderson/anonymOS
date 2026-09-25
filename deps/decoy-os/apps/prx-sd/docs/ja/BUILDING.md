> このドキュメントは [English](../BUILDING.md) 版の日本語訳です。

# ソースからのビルド

## 前提条件

### 必須

- **Rust** 1.70 以上（[rustup](https://rustup.rs/) でインストール）
- **pkg-config**
- **OpenSSL 開発ヘッダー**（reqwest/TLS 用）

### 任意

- **Node.js** 18 以上 および **npm**（GUI 用）
- **Tauri CLI**（`cargo install tauri-cli`）（GUI 用）

### プラットフォーム別

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
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) をインストール
- [vcpkg](https://github.com/microsoft/vcpkg) をインストールし、次を実行: `vcpkg install openssl`

## CLI のビルド

```bash
git clone https://github.com/openprx/prx-sd.git
cd prx-sd

# デバッグビルド
cargo build

# リリースビルド（最適化済み）
cargo build --release

# バイナリの場所:
#   デバッグ:   target/debug/sd
#   リリース:   target/release/sd
```

### フィーチャーフラグ

```bash
# ONNX ML モデルサポート付きでビルド
cargo build --release --features onnx

# WASM プラグインサポートなしでビルド（バイナリサイズ縮小）
cargo build --release --no-default-features
```

| フィーチャー | デフォルト | 説明 |
|--------------|------------|------|
| `wasm-runtime` | あり | WebAssembly プラグインサポート (Wasmtime) |
| `onnx` | なし | ONNX ML モデル推論 (tract-onnx) |

## GUI のビルド

デスクトップ GUI は Tauri 2 (Rust) + Vue 3 (TypeScript) を使用しています。

```bash
# フロントエンド依存関係のインストール
cd gui
npm install

# 開発モード（ホットリロード）
npm run tauri dev

# プロダクションビルド
npm run tauri build
```

ビルドされたアプリケーションは `gui/src-tauri/target/release/bundle/` に出力されます。

## 更新サーバーのビルド

```bash
cargo build --release --manifest-path update-server/Cargo.toml
```

## テストの実行

```bash
# 全テストを実行
cargo test

# 特定のクレートのテストを実行
cargo test -p prx-sd-core
cargo test -p prx-sd-signatures

# 統合テストを実行
cargo test --test '*'
```

## コード品質

```bash
# コンパイルエラーの確認（高速、リンクなし）
cargo check

# 自動修正の適用
cargo fix --allow-dirty

# コードフォーマット
cargo fmt

# リント
cargo clippy -- -D warnings
```

## クロスコンパイル

プロジェクトには `.cargo/config.toml` にクロスコンパイル設定が含まれています。

### Linux ARM64 (aarch64)

```bash
# ターゲットのインストール
rustup target add aarch64-unknown-linux-gnu

# クロスコンパイルツールチェーンのインストール
sudo apt install -y gcc-aarch64-linux-gnu

# ビルド
cargo build --release --target aarch64-unknown-linux-gnu
```

### macOS（Linux から）

Linux から macOS へのクロスコンパイルには [osxcross](https://github.com/tpoechtrager/osxcross) が必要です。

### Windows（Linux から）

```bash
# ターゲットのインストール
rustup target add x86_64-pc-windows-gnu

# クロスコンパイルツールチェーンのインストール
sudo apt install -y gcc-mingw-w64-x86-64

# ビルド
cargo build --release --target x86_64-pc-windows-gnu
```

## パッケージング

ビルド済みパッケージングスクリプトは `tools/` にあります:

```bash
# Debian パッケージ (.deb)
./tools/build-deb.sh

# macOS ディスクイメージ (.dmg)
./tools/build-dmg.sh

# Windows インストーラー (.msi)
./tools/build-msi.sh

# Linux AppImage
./tools/build-appimage.sh
```

プラットフォーム別のパッケージング設定は `packaging/` にあります:

```
packaging/
├── appimage/       # Linux AppImage
├── completions/    # シェル補完 (bash, zsh, fish)
├── desktop/        # .desktop ファイル
├── filemanager/    # ファイルマネージャー統合スクリプト
├── homebrew/       # Homebrew formula
├── launchd/        # macOS launch agent plist
├── systemd/        # Linux systemd サービスユニット
├── udev/           # Linux udev ルール（USB 自動スキャン）
└── windows/        # WiX MSI インストーラー設定
```

## プロジェクト構成

```
prx-sd/
├── Cargo.toml          # ワークスペースルート
├── Cargo.lock          # 依存関係ロックファイル
├── crates/
│   ├── cli/            # sd バイナリ
│   ├── core/           # スキャンエンジン
│   ├── signatures/     # シグネチャデータベース
│   ├── parsers/        # バイナリフォーマットパーサー
│   ├── heuristic/      # ヒューリスティック + ML 検出
│   ├── realtime/       # リアルタイム監視
│   ├── quarantine/     # 隔離ボールト
│   ├── remediation/    # 脅威対応
│   ├── sandbox/        # プロセスサンドボックス
│   ├── plugins/        # WASM プラグインシステム
│   └── updater/        # 更新クライアント
├── update-server/      # シグネチャ配信サーバー
├── gui/                # Tauri + Vue 3 デスクトップアプリ
├── drivers/            # OS カーネルドライバー
├── signatures-db/      # 組み込みシグネチャ
├── tests/              # 統合テスト
├── tools/              # ビルドスクリプト
└── packaging/          # 配布用パッケージング
```
