#!/usr/bin/env bash
#
# Build an AppImage for PRX-SD antivirus engine.
#
# Usage:
#   ./tools/build-appimage.sh
#
# Requirements:
#   - appimagetool (https://github.com/AppImage/AppImageKit/releases)
#     If not found, the script creates the AppDir structure without
#     producing the final .AppImage file.
#
# Output: target/appimage/PRX-SD-<version>-<arch>.AppImage
#

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(grep '^version' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/' | tr -d '[:space:]')
ARCH=$(uname -m)

APPDIR="$PROJECT_DIR/target/appimage-staging/PRX-SD.AppDir"
OUTPUT_DIR="$PROJECT_DIR/target/appimage"

log()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*"; exit 1; }

# ─── 1. Build release binary ────────────────────────────────────────────────
log "Building PRX-SD v${VERSION} (release)..."
cd "$PROJECT_DIR"
cargo build --release --bin sd 2>&1 | tail -3

BINARY="$PROJECT_DIR/target/release/sd"
if [[ ! -f "$BINARY" ]]; then
    err "Binary not found at $BINARY"
fi

ok "Binary built: $(ls -lh "$BINARY" | awk '{print $5}')"

# ─── 2. Create AppDir structure ──────────────────────────────────────────────
log "Creating AppDir structure..."
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/prx-sd/signatures-db"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# ─── 3. Copy binary ─────────────────────────────────────────────────────────
cp "$BINARY" "$APPDIR/usr/bin/sd"
chmod 755 "$APPDIR/usr/bin/sd"

# ─── 4. Copy signatures ─────────────────────────────────────────────────────
if [[ -d "$PROJECT_DIR/signatures-db/yara" ]]; then
    cp -r "$PROJECT_DIR/signatures-db/yara" "$APPDIR/usr/share/prx-sd/signatures-db/" 2>/dev/null || true
fi
if [[ -d "$PROJECT_DIR/signatures-db/hashes" ]]; then
    cp -r "$PROJECT_DIR/signatures-db/hashes" "$APPDIR/usr/share/prx-sd/signatures-db/" 2>/dev/null || true
fi

# ─── 5. Desktop entry and icon ───────────────────────────────────────────────
ICON_SRC="$PROJECT_DIR/packaging/appimage/prx-sd.svg"
DESKTOP_SRC="$PROJECT_DIR/packaging/appimage/prx-sd.desktop"

cp "$DESKTOP_SRC" "$APPDIR/usr/share/applications/prx-sd.desktop"
cp "$ICON_SRC" "$APPDIR/usr/share/icons/hicolor/256x256/apps/prx-sd.svg"

# Top-level desktop + icon (required by AppImage spec)
cp "$DESKTOP_SRC" "$APPDIR/prx-sd.desktop"
cp "$ICON_SRC" "$APPDIR/prx-sd.svg"

# ─── 6. Create AppRun script ─────────────────────────────────────────────────
cat > "$APPDIR/AppRun" << 'APPRUN_EOF'
#!/usr/bin/env bash
#
# AppRun — entry point for the PRX-SD AppImage.
# Sets up the environment so the bundled sd binary can find its
# signatures database, then forwards all arguments to sd.
#

SELF_DIR="$(dirname "$(readlink -f "$0")")"

# Let sd know where bundled data lives.
export PRX_SD_DATA_DIR="${PRX_SD_DATA_DIR:-$SELF_DIR/usr/share/prx-sd}"
export PRX_SD_SIGNATURES_DIR="${PRX_SD_SIGNATURES_DIR:-$SELF_DIR/usr/share/prx-sd/signatures-db}"

exec "$SELF_DIR/usr/bin/sd" "$@"
APPRUN_EOF
chmod 755 "$APPDIR/AppRun"

ok "AppDir created at $APPDIR"

# ─── 7. Build AppImage ───────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
APPIMAGE_NAME="PRX-SD-${VERSION}-${ARCH}.AppImage"
APPIMAGE_PATH="$OUTPUT_DIR/$APPIMAGE_NAME"

if command -v appimagetool >/dev/null 2>&1; then
    log "Running appimagetool..."
    ARCH="$ARCH" appimagetool "$APPDIR" "$APPIMAGE_PATH" 2>&1
    if [[ -f "$APPIMAGE_PATH" ]]; then
        ok "AppImage built: $APPIMAGE_PATH"
        echo ""
        echo "  Run:  chmod +x $APPIMAGE_PATH && ./$APPIMAGE_NAME"
        echo "  Size: $(ls -lh "$APPIMAGE_PATH" | awk '{print $5}')"
    else
        err "appimagetool failed to produce output"
    fi
else
    warn "appimagetool not found — AppDir structure created but .AppImage not built."
    echo ""
    echo "  To install appimagetool:"
    echo "    wget https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-$(uname -m).AppImage"
    echo "    chmod +x appimagetool-*.AppImage && sudo mv appimagetool-*.AppImage /usr/local/bin/appimagetool"
    echo ""
    echo "  Then re-run: $0"
    echo ""
    echo "  AppDir ready at: $APPDIR"
fi
