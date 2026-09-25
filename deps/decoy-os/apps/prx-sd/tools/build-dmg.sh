#!/usr/bin/env bash
#
# Build a .dmg installer for PRX-SD on macOS.
#
# Usage:
#   ./tools/build-dmg.sh
#
# Requirements:
#   - macOS (uses hdiutil, which is macOS-only)
#   - Rust toolchain
#
# Output: target/macos/PRX-SD-<version>.dmg
#

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(grep '^version' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/' | tr -d '[:space:]')

STAGING_DIR="$PROJECT_DIR/target/macos-staging"
APP_BUNDLE="$STAGING_DIR/PRX-SD.app"
OUTPUT_DIR="$PROJECT_DIR/target/macos"

log()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*"; exit 1; }

# ─── 0. Platform check ──────────────────────────────────────────────────────
if [[ "$(uname -s)" != "Darwin" ]]; then
    err "This script must be run on macOS (hdiutil is required)."
fi

# ─── 1. Build release binary ────────────────────────────────────────────────
log "Building PRX-SD v${VERSION} (release)..."
cd "$PROJECT_DIR"
cargo build --release --bin sd 2>&1 | tail -3

BINARY="$PROJECT_DIR/target/release/sd"
if [[ ! -f "$BINARY" ]]; then
    err "Binary not found at $BINARY"
fi

ok "Binary built: $(ls -lh "$BINARY" | awk '{print $5}')"

# ─── 2. Create .app bundle ──────────────────────────────────────────────────
log "Creating macOS .app bundle..."
rm -rf "$STAGING_DIR"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources/signatures-db"

# Copy binary
cp "$BINARY" "$APP_BUNDLE/Contents/MacOS/sd"
chmod 755 "$APP_BUNDLE/Contents/MacOS/sd"

# Copy signatures
if [[ -d "$PROJECT_DIR/signatures-db/yara" ]]; then
    cp -r "$PROJECT_DIR/signatures-db/yara" "$APP_BUNDLE/Contents/Resources/signatures-db/" 2>/dev/null || true
fi
if [[ -d "$PROJECT_DIR/signatures-db/hashes" ]]; then
    cp -r "$PROJECT_DIR/signatures-db/hashes" "$APP_BUNDLE/Contents/Resources/signatures-db/" 2>/dev/null || true
fi

# ─── 3. Create Info.plist ────────────────────────────────────────────────────
log "Generating Info.plist..."
cat > "$APP_BUNDLE/Contents/Info.plist" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>PRX-SD</string>

    <key>CFBundleDisplayName</key>
    <string>PRX-SD Antivirus</string>

    <key>CFBundleIdentifier</key>
    <string>dev.prx-sd.antivirus</string>

    <key>CFBundleVersion</key>
    <string>${VERSION}</string>

    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>

    <key>CFBundleExecutable</key>
    <string>sd</string>

    <key>CFBundlePackageType</key>
    <string>APPL</string>

    <key>CFBundleSignature</key>
    <string>PRXS</string>

    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>

    <key>NSHighResolutionCapable</key>
    <true/>

    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>

    <key>NSHumanReadableCopyright</key>
    <string>Copyright 2024-2026 PRX-SD Team. All rights reserved.</string>
</dict>
</plist>
PLIST_EOF

ok "App bundle created at $APP_BUNDLE"

# ─── 4. Create symlink to /Applications for drag-to-install ──────────────────
ln -s /Applications "$STAGING_DIR/Applications"

# ─── 5. Build .dmg ──────────────────────────────────────────────────────────
log "Building .dmg..."
mkdir -p "$OUTPUT_DIR"
DMG_PATH="$OUTPUT_DIR/PRX-SD-${VERSION}.dmg"

# Remove old DMG if present (hdiutil -ov handles this, but be explicit).
rm -f "$DMG_PATH"

hdiutil create \
    -volname "PRX-SD ${VERSION}" \
    -srcfolder "$STAGING_DIR" \
    -ov \
    -format UDZO \
    "$DMG_PATH" 2>&1

if [[ -f "$DMG_PATH" ]]; then
    ok "DMG built: $DMG_PATH"
    echo ""
    echo "  Install: Open the .dmg and drag PRX-SD.app to Applications."
    echo "  CLI:     /Applications/PRX-SD.app/Contents/MacOS/sd scan /path"
    echo "  Size:    $(ls -lh "$DMG_PATH" | awk '{print $5}')"
else
    err "DMG build failed"
fi
