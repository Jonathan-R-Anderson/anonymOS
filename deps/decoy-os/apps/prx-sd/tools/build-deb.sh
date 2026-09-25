#!/usr/bin/env bash
#
# Build a .deb package for PRX-SD antivirus engine.
#
# Usage:
#   ./tools/build-deb.sh [--release]
#
# Output: target/debian/prx-sd_<version>_<arch>.deb
#

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(grep '^version' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/' | tr -d '[:space:]')
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")

BUILD_DIR="$PROJECT_DIR/target/debian-staging"
DEB_DIR="$BUILD_DIR/prx-sd_${VERSION}_${ARCH}"

log()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
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

# ─── 2. Create directory structure ──────────────────────────────────────────
log "Creating .deb directory structure..."
rm -rf "$DEB_DIR"
mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$DEB_DIR/usr/local/bin"
mkdir -p "$DEB_DIR/etc/prx-sd"
mkdir -p "$DEB_DIR/etc/prx-sd/yara"
mkdir -p "$DEB_DIR/usr/lib/systemd/system"
mkdir -p "$DEB_DIR/usr/share/applications"
mkdir -p "$DEB_DIR/usr/share/doc/prx-sd"

# ─── 3. Copy files ──────────────────────────────────────────────────────────
log "Copying files..."

# Binary.
cp "$BINARY" "$DEB_DIR/usr/local/bin/sd"
chmod 755 "$DEB_DIR/usr/local/bin/sd"

# Systemd service.
cp "$PROJECT_DIR/packaging/systemd/prx-sd.service" "$DEB_DIR/usr/lib/systemd/system/"

# Desktop entry.
cp "$PROJECT_DIR/packaging/desktop/prx-sd.desktop" "$DEB_DIR/usr/share/applications/"

# Built-in signatures.
cp -r "$PROJECT_DIR/signatures-db/yara/"* "$DEB_DIR/etc/prx-sd/yara/" 2>/dev/null || true
cp "$PROJECT_DIR/signatures-db/hashes/"*.txt "$DEB_DIR/etc/prx-sd/" 2>/dev/null || true

# Update script.
cp "$PROJECT_DIR/tools/update-signatures.sh" "$DEB_DIR/usr/share/doc/prx-sd/"

# ─── 4. DEBIAN control files ────────────────────────────────────────────────
log "Generating DEBIAN control files..."

# Calculate installed size in KB.
INSTALLED_SIZE=$(du -sk "$DEB_DIR" | cut -f1)

cat > "$DEB_DIR/DEBIAN/control" << EOF
Package: prx-sd
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Maintainer: PRX-SD Team <team@prx-sd.dev>
Homepage: https://github.com/prx-sd/prx-sd
Description: Open-source Rust antivirus engine
 PRX-SD is a fast, modular antivirus engine written in Rust. Features:
 hash-based signature matching (LMDB), YARA-X rule scanning, heuristic
 analysis, real-time file monitoring (fanotify), AES-256-GCM quarantine,
 and automatic threat remediation.
EOF

# Post-install script.
cat > "$DEB_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e

# Create data directory.
mkdir -p /etc/prx-sd/signatures
mkdir -p /etc/prx-sd/quarantine
mkdir -p /etc/prx-sd/audit

# Import built-in hashes if sd binary is available.
if command -v sd >/dev/null 2>&1; then
    for f in /etc/prx-sd/sha256_blocklist.txt /etc/prx-sd/md5_blocklist.txt; do
        if [ -f "$f" ]; then
            sd --data-dir /etc/prx-sd --log-level error import "$f" 2>/dev/null || true
        fi
    done
fi

# Reload systemd and enable service.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    echo "PRX-SD installed. Enable real-time protection with:"
    echo "  sudo systemctl enable --now prx-sd"
fi

echo ""
echo "PRX-SD installed successfully!"
echo "  Scan:    sd scan /path/to/check"
echo "  Update:  sd update"
echo "  Monitor: sudo systemctl start prx-sd"
EOF
chmod 755 "$DEB_DIR/DEBIAN/postinst"

# Pre-remove script.
cat > "$DEB_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop prx-sd 2>/dev/null || true
    systemctl disable prx-sd 2>/dev/null || true
fi
EOF
chmod 755 "$DEB_DIR/DEBIAN/prerm"

# Conffiles (prevent overwriting user config on upgrade).
cat > "$DEB_DIR/DEBIAN/conffiles" << 'EOF'
/etc/prx-sd/config.json
EOF

# ─── 5. Build .deb ──────────────────────────────────────────────────────────
log "Building .deb package..."
DEB_OUTPUT="$PROJECT_DIR/target/debian"
mkdir -p "$DEB_OUTPUT"
dpkg-deb --build "$DEB_DIR" "$DEB_OUTPUT/" 2>&1

DEB_FILE="$DEB_OUTPUT/prx-sd_${VERSION}_${ARCH}.deb"
if [[ -f "$DEB_FILE" ]]; then
    ok "Package built: $DEB_FILE"
    echo ""
    echo "  Install: sudo dpkg -i $DEB_FILE"
    echo "  Size:    $(ls -lh "$DEB_FILE" | awk '{print $5}')"
    echo ""
    dpkg-deb --info "$DEB_FILE" 2>/dev/null | head -10
else
    err "Package build failed"
fi
