#!/usr/bin/env bash
#
# Build a .msi installer for PRX-SD on Windows.
#
# Usage:
#   ./tools/build-msi.sh
#
# Requirements:
#   - Windows or WSL with .NET 6+ runtime
#   - WiX Toolset v4: dotnet tool install --global wix
#   - Rust toolchain targeting x86_64-pc-windows-msvc (or -gnu)
#
# Output: target/windows/PRX-SD-<version>.msi
#

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(grep '^version' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/' | tr -d '[:space:]')

OUTPUT_DIR="$PROJECT_DIR/target/windows"
WXS_FILE="$PROJECT_DIR/packaging/windows/prx-sd.wxs"

log()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*"; exit 1; }

# ─── 0. Check for wix ────────────────────────────────────────────────────────
if ! command -v wix >/dev/null 2>&1; then
    err "WiX Toolset not found. Install with: dotnet tool install --global wix"
fi

# ─── 1. Determine target and build ───────────────────────────────────────────
# Detect if we are on native Windows (MSYS/Git Bash/Cygwin) or cross-compiling.
WINDOWS_TARGET=""
if [[ "$(uname -s)" =~ MINGW|MSYS|CYGWIN|Windows_NT ]]; then
    WINDOWS_TARGET="x86_64-pc-windows-msvc"
elif [[ "$(uname -s)" == "Linux" ]]; then
    WINDOWS_TARGET="x86_64-pc-windows-gnu"
    warn "Cross-compiling from Linux — make sure mingw-w64 toolchain is installed."
else
    err "Unsupported platform for MSI build: $(uname -s)"
fi

log "Building PRX-SD v${VERSION} for ${WINDOWS_TARGET}..."
cd "$PROJECT_DIR"
cargo build --release --bin sd --target "$WINDOWS_TARGET" 2>&1 | tail -5

BINARY_DIR="$PROJECT_DIR/target/$WINDOWS_TARGET/release"
if [[ ! -f "$BINARY_DIR/sd.exe" ]]; then
    err "Binary not found at $BINARY_DIR/sd.exe"
fi

ok "Binary built: $(ls -lh "$BINARY_DIR/sd.exe" | awk '{print $5}')"

# ─── 2. Build .msi with WiX ──────────────────────────────────────────────────
log "Building .msi with WiX..."
mkdir -p "$OUTPUT_DIR"

MSI_PATH="$OUTPUT_DIR/PRX-SD-${VERSION}.msi"

wix build \
    -d "Version=${VERSION}" \
    -d "BinaryPath=${BINARY_DIR}" \
    "$WXS_FILE" \
    -o "$MSI_PATH" 2>&1

if [[ -f "$MSI_PATH" ]]; then
    ok "MSI built: $MSI_PATH"
    echo ""
    echo "  Install: msiexec /i $(cygpath -w "$MSI_PATH" 2>/dev/null || echo "$MSI_PATH")"
    echo "  Size:    $(ls -lh "$MSI_PATH" | awk '{print $5}')"
else
    err "MSI build failed"
fi
