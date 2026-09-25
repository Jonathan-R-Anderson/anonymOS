#!/usr/bin/env bash
# PRX-SD Installer
# Usage: curl -fsSL https://get.prx-sd.dev | bash
#        or: ./install.sh [--prefix /usr/local] [--uninstall]
#
# Environment variables:
#   PRX_SD_PREFIX   - Installation prefix (default: /usr/local or ~/.local)
#   PRX_SD_DATA_DIR - Data directory (default: ~/.prx-sd)
#   PRX_SD_VERSION  - Version to install (default: latest)

set -euo pipefail

# --- Color helpers -----------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { printf "${CYAN}>>>${RESET} %s\n" "$*"; }
success() { printf "${GREEN}OK${RESET}  %s\n" "$*"; }
warn()    { printf "${YELLOW}!!${RESET}  %s\n" "$*"; }
error()   { printf "${RED}ERR${RESET} %s\n" "$*" >&2; }
die()     { error "$*"; exit 1; }

# --- Argument parsing --------------------------------------------------------

PREFIX=""
UNINSTALL=0
DATA_DIR="${PRX_SD_DATA_DIR:-}"
VERSION="${PRX_SD_VERSION:-latest}"

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            PREFIX="$2"; shift 2 ;;
        --prefix=*)
            PREFIX="${1#*=}"; shift ;;
        --data-dir)
            DATA_DIR="$2"; shift 2 ;;
        --data-dir=*)
            DATA_DIR="${1#*=}"; shift ;;
        --version)
            VERSION="$2"; shift 2 ;;
        --version=*)
            VERSION="${1#*=}"; shift ;;
        --uninstall)
            UNINSTALL=1; shift ;;
        -h|--help)
            cat <<'USAGE'
PRX-SD Installer

Usage:
  install.sh [OPTIONS]

Options:
  --prefix DIR       Installation prefix (default: /usr/local or ~/.local)
  --data-dir DIR     Data directory (default: ~/.prx-sd)
  --version VER      Version to install (default: latest)
  --uninstall        Remove PRX-SD and all associated files
  -h, --help         Show this help
USAGE
            exit 0 ;;
        *)
            die "Unknown option: $1" ;;
    esac
done

# --- Platform detection ------------------------------------------------------

detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="macos" ;;
        *)       die "Unsupported OS: $(uname -s). PRX-SD supports Linux and macOS." ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)    arch="x86_64" ;;
        aarch64|arm64)   arch="aarch64" ;;
        *)               die "Unsupported architecture: $(uname -m). PRX-SD supports x86_64 and aarch64." ;;
    esac

    echo "${os}" "${arch}"
}

read -r OS ARCH <<< "$(detect_platform)"

# --- Resolve paths -----------------------------------------------------------

HAS_SUDO=0
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    HAS_SUDO=1
fi

if [ -z "$PREFIX" ]; then
    if [ "${PRX_SD_PREFIX:-}" != "" ]; then
        PREFIX="$PRX_SD_PREFIX"
    elif [ "$(id -u)" = "0" ] || [ "$HAS_SUDO" = "1" ]; then
        PREFIX="/usr/local"
    else
        PREFIX="${HOME}/.local"
        warn "No sudo access detected. Installing to ${PREFIX}"
    fi
fi

BIN_DIR="${PREFIX}/bin"
DATA_DIR="${DATA_DIR:-${HOME}/.prx-sd}"

MAYBE_SUDO=""
if [ "$(id -u)" != "0" ] && [ "$HAS_SUDO" = "1" ]; then
    # Only use sudo for system directories
    case "$PREFIX" in
        /usr/*|/opt/*)
            MAYBE_SUDO="sudo" ;;
    esac
fi

# --- Uninstall ---------------------------------------------------------------

do_uninstall() {
    info "Uninstalling PRX-SD..."

    # Remove binary
    if [ -f "${BIN_DIR}/sd" ]; then
        $MAYBE_SUDO rm -f "${BIN_DIR}/sd"
        success "Removed ${BIN_DIR}/sd"
    fi

    # Remove systemd service (Linux)
    if [ "$OS" = "linux" ]; then
        local service_file="/etc/systemd/system/prx-sd.service"
        if [ -f "$service_file" ]; then
            $MAYBE_SUDO systemctl stop prx-sd 2>/dev/null || true
            $MAYBE_SUDO systemctl disable prx-sd 2>/dev/null || true
            $MAYBE_SUDO rm -f "$service_file"
            $MAYBE_SUDO systemctl daemon-reload 2>/dev/null || true
            success "Removed systemd service"
        fi
    fi

    # Remove launchd plist (macOS)
    if [ "$OS" = "macos" ]; then
        local plist_file="/Library/LaunchDaemons/com.prxsd.daemon.plist"
        if [ -f "$plist_file" ]; then
            $MAYBE_SUDO launchctl bootout system "$plist_file" 2>/dev/null || true
            $MAYBE_SUDO rm -f "$plist_file"
            success "Removed launchd daemon"
        fi
    fi

    # Remove shell completions
    for f in \
        "/etc/bash_completion.d/sd" \
        "${HOME}/.local/share/bash-completion/completions/sd" \
        "/usr/local/share/zsh/site-functions/_sd" \
        "${HOME}/.zsh/completions/_sd" \
        "/usr/share/fish/vendor_completions.d/sd.fish" \
        "${HOME}/.config/fish/completions/sd.fish"; do
        if [ -f "$f" ]; then
            rm -f "$f" 2>/dev/null || $MAYBE_SUDO rm -f "$f" 2>/dev/null || true
            success "Removed $f"
        fi
    done

    # Remove desktop entry
    local desktop_file="/usr/share/applications/prx-sd.desktop"
    if [ -f "$desktop_file" ]; then
        $MAYBE_SUDO rm -f "$desktop_file"
        success "Removed desktop entry"
    fi

    # Remove data directory
    if [ -d "$DATA_DIR" ]; then
        printf "  Remove data directory %s? [y/N] " "$DATA_DIR"
        read -r reply
        if [ "$reply" = "y" ] || [ "$reply" = "Y" ]; then
            rm -rf "$DATA_DIR"
            success "Removed $DATA_DIR"
        else
            info "Kept $DATA_DIR"
        fi
    fi

    success "PRX-SD has been uninstalled."
    exit 0
}

if [ "$UNINSTALL" = "1" ]; then
    do_uninstall
fi

# --- Download / locate binary ------------------------------------------------

GITHUB_REPO="openprx/prx-sd"
DOWNLOAD_BASE="https://github.com/${GITHUB_REPO}/releases"

resolve_artifact_name() {
    local os_part arch_part
    case "$OS" in
        linux) os_part="linux" ;;
        macos) os_part="macos" ;;
    esac
    arch_part="$ARCH"
    echo "sd-${os_part}-${arch_part}"
}

ARTIFACT_NAME="$(resolve_artifact_name)"

download_binary() {
    local url tmp_dir tmp_file

    if [ "$VERSION" = "latest" ]; then
        url="${DOWNLOAD_BASE}/latest/download/${ARTIFACT_NAME}"
    else
        url="${DOWNLOAD_BASE}/download/${VERSION}/${ARTIFACT_NAME}"
    fi

    tmp_dir="$(mktemp -d)"
    tmp_file="${tmp_dir}/sd"

    info "Downloading PRX-SD (${VERSION}) for ${OS}/${ARCH}..."
    info "  URL: ${url}"

    if command -v curl >/dev/null 2>&1; then
        if ! curl -fSL --progress-bar -o "$tmp_file" "$url"; then
            rm -rf "$tmp_dir"
            die "Download failed. Check that the version and platform are correct."
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -q --show-progress -O "$tmp_file" "$url"; then
            rm -rf "$tmp_dir"
            die "Download failed. Check that the version and platform are correct."
        fi
    else
        rm -rf "$tmp_dir"
        die "Neither curl nor wget found. Please install one and retry."
    fi

    chmod +x "$tmp_file"
    echo "$tmp_file"
}

BINARY_PATH="$(download_binary)"
TEMP_DIR="$(dirname "$BINARY_PATH")"

# Ensure cleanup on exit
cleanup() {
    rm -rf "$TEMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# --- Install binary ----------------------------------------------------------

info "Installing sd to ${BIN_DIR}/sd..."
$MAYBE_SUDO mkdir -p "$BIN_DIR"
$MAYBE_SUDO install -m 755 "$BINARY_PATH" "${BIN_DIR}/sd"
success "Installed ${BIN_DIR}/sd"

# Verify installation
if ! "${BIN_DIR}/sd" --version >/dev/null 2>&1; then
    warn "Binary installed but could not execute. Check your PATH."
fi

# --- Create data directory and run first-time setup --------------------------

info "Creating data directory at ${DATA_DIR}..."
mkdir -p "${DATA_DIR}/signatures" "${DATA_DIR}/yara" "${DATA_DIR}/quarantine"
success "Data directory ready"

# Attempt first-time signature download (non-fatal)
info "Running first-time setup..."
if "${BIN_DIR}/sd" update --data-dir "$DATA_DIR" 2>/dev/null; then
    success "Signature database downloaded"
else
    warn "Could not download signatures (offline?). Run 'sd update' later."
fi

# --- Install systemd service (Linux) ----------------------------------------

install_systemd_service() {
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemctl not found; skipping systemd service installation."
        return
    fi

    local service_file="/etc/systemd/system/prx-sd.service"
    info "Installing systemd service..."

    $MAYBE_SUDO tee "$service_file" > /dev/null <<EOF
[Unit]
Description=PRX-SD Antivirus Real-time Protection
After=network.target
Documentation=https://github.com/openprx/prx-sd

[Service]
Type=simple
ExecStart=${BIN_DIR}/sd monitor /home /tmp /var/tmp --data-dir ${DATA_DIR}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=prx-sd

# Security hardening
ProtectSystem=strict
ReadWritePaths=${DATA_DIR} /tmp /var/tmp
ProtectHome=read-only
NoNewPrivileges=false
PrivateTmp=false

[Install]
WantedBy=multi-user.target
EOF

    $MAYBE_SUDO systemctl daemon-reload
    success "Systemd service installed at ${service_file}"
    info "  Enable with: sudo systemctl enable --now prx-sd"
}

# --- Install launchd plist (macOS) -------------------------------------------

install_launchd_plist() {
    local plist_file="/Library/LaunchDaemons/com.prxsd.daemon.plist"
    info "Installing launchd daemon..."

    $MAYBE_SUDO tee "$plist_file" > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.prxsd.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_DIR}/sd</string>
        <string>monitor</string>
        <string>/Users</string>
        <string>/tmp</string>
        <string>--data-dir</string>
        <string>${DATA_DIR}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/prx-sd.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/prx-sd.err</string>
</dict>
</plist>
EOF

    $MAYBE_SUDO chmod 644 "$plist_file"
    $MAYBE_SUDO chown root:wheel "$plist_file"
    success "Launchd plist installed at ${plist_file}"
    info "  Load with: sudo launchctl bootstrap system ${plist_file}"
}

if [ "$OS" = "linux" ]; then
    install_systemd_service
elif [ "$OS" = "macos" ]; then
    install_launchd_plist
fi

# --- Install shell completions -----------------------------------------------

install_completions() {
    info "Installing shell completions..."

    # Bash completions
    local bash_comp_dir=""
    if [ -d "/etc/bash_completion.d" ]; then
        bash_comp_dir="/etc/bash_completion.d"
    else
        bash_comp_dir="${HOME}/.local/share/bash-completion/completions"
        mkdir -p "$bash_comp_dir"
    fi

    local bash_src=""
    # Try to find shipped completions next to the installer
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
    if [ -f "${script_dir}/packaging/completions/sd.bash" ]; then
        bash_src="${script_dir}/packaging/completions/sd.bash"
    fi

    if [ -n "$bash_src" ]; then
        if [ "$bash_comp_dir" = "/etc/bash_completion.d" ]; then
            $MAYBE_SUDO cp "$bash_src" "${bash_comp_dir}/sd"
        else
            cp "$bash_src" "${bash_comp_dir}/sd"
        fi
        success "Bash completions installed"
    fi

    # Zsh completions
    local zsh_src=""
    if [ -f "${script_dir}/packaging/completions/sd.zsh" ]; then
        zsh_src="${script_dir}/packaging/completions/sd.zsh"
    fi

    if [ -n "$zsh_src" ]; then
        local zsh_comp_dir="/usr/local/share/zsh/site-functions"
        if [ ! -d "$zsh_comp_dir" ] || [ ! -w "$zsh_comp_dir" ]; then
            zsh_comp_dir="${HOME}/.zsh/completions"
            mkdir -p "$zsh_comp_dir"
        fi
        if [ "$zsh_comp_dir" = "/usr/local/share/zsh/site-functions" ]; then
            $MAYBE_SUDO cp "$zsh_src" "${zsh_comp_dir}/_sd"
        else
            cp "$zsh_src" "${zsh_comp_dir}/_sd"
        fi
        success "Zsh completions installed"
    fi

    # Fish completions
    local fish_src=""
    if [ -f "${script_dir}/packaging/completions/sd.fish" ]; then
        fish_src="${script_dir}/packaging/completions/sd.fish"
    fi

    if [ -n "$fish_src" ]; then
        local fish_comp_dir="${HOME}/.config/fish/completions"
        mkdir -p "$fish_comp_dir"
        cp "$fish_src" "${fish_comp_dir}/sd.fish"
        success "Fish completions installed"
    fi
}

install_completions

# --- Summary -----------------------------------------------------------------

echo ""
printf "${GREEN}${BOLD}PRX-SD installed successfully!${RESET}\n"
echo ""
echo "  Binary:    ${BIN_DIR}/sd"
echo "  Data dir:  ${DATA_DIR}"
echo ""
echo "Quick start:"
echo "  sd scan /path/to/check       # Scan files for threats"
echo "  sd monitor /home /tmp         # Start real-time protection"
echo "  sd update                     # Update signature database"
echo "  sd info                       # Show engine status"
echo ""

# Check if binary is on PATH
if ! command -v sd >/dev/null 2>&1; then
    warn "The directory ${BIN_DIR} is not in your PATH."
    echo "  Add it with:  export PATH=\"${BIN_DIR}:\$PATH\""
    echo ""
fi
