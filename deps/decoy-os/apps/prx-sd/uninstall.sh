#!/usr/bin/env bash
# PRX-SD Uninstaller
# Usage: ./uninstall.sh [--yes] [--keep-data]
#
# Removes the PRX-SD binary, services, completions, and optionally data.

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

# --- Arguments ---------------------------------------------------------------

AUTO_YES=0
KEEP_DATA=0

while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)
            AUTO_YES=1; shift ;;
        --keep-data)
            KEEP_DATA=1; shift ;;
        -h|--help)
            cat <<'USAGE'
PRX-SD Uninstaller

Usage:
  uninstall.sh [OPTIONS]

Options:
  --yes, -y       Skip confirmation prompts
  --keep-data     Do not remove the data directory (~/.prx-sd)
  -h, --help      Show this help
USAGE
            exit 0 ;;
        *)
            die "Unknown option: $1" ;;
    esac
done

# --- Platform detection ------------------------------------------------------

case "$(uname -s)" in
    Linux*)  OS="linux" ;;
    Darwin*) OS="macos" ;;
    *)       OS="unknown" ;;
esac

# --- Sudo detection ----------------------------------------------------------

MAYBE_SUDO=""
if [ "$(id -u)" != "0" ]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        MAYBE_SUDO="sudo"
    fi
fi

DATA_DIR="${PRX_SD_DATA_DIR:-${HOME}/.prx-sd}"

# --- Confirmation ------------------------------------------------------------

if [ "$AUTO_YES" != "1" ]; then
    printf "${BOLD}This will uninstall PRX-SD from your system.${RESET}\n"
    printf "Continue? [y/N] "
    read -r reply
    if [ "$reply" != "y" ] && [ "$reply" != "Y" ]; then
        echo "Aborted."
        exit 0
    fi
fi

# --- Stop and remove services ------------------------------------------------

if [ "$OS" = "linux" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet prx-sd 2>/dev/null; then
            info "Stopping prx-sd service..."
            $MAYBE_SUDO systemctl stop prx-sd 2>/dev/null || true
        fi
        if [ -f "/etc/systemd/system/prx-sd.service" ]; then
            info "Removing systemd service..."
            $MAYBE_SUDO systemctl disable prx-sd 2>/dev/null || true
            $MAYBE_SUDO rm -f /etc/systemd/system/prx-sd.service
            $MAYBE_SUDO systemctl daemon-reload 2>/dev/null || true
            success "Removed systemd service"
        fi
    fi
fi

if [ "$OS" = "macos" ]; then
    local_plist="/Library/LaunchDaemons/com.prxsd.daemon.plist"
    if [ -f "$local_plist" ]; then
        info "Removing launchd daemon..."
        $MAYBE_SUDO launchctl bootout system "$local_plist" 2>/dev/null || true
        $MAYBE_SUDO rm -f "$local_plist"
        success "Removed launchd daemon"
    fi
fi

# --- Remove binary -----------------------------------------------------------

BINARY_LOCATIONS=(
    "/usr/local/bin/sd"
    "${HOME}/.local/bin/sd"
    "/usr/bin/sd"
)

for bin_path in "${BINARY_LOCATIONS[@]}"; do
    if [ -f "$bin_path" ]; then
        # Verify it is our binary
        if "$bin_path" --version 2>&1 | grep -q "PRX-SD\|prx-sd\|sd " 2>/dev/null; then
            info "Removing ${bin_path}..."
            $MAYBE_SUDO rm -f "$bin_path" 2>/dev/null || rm -f "$bin_path" 2>/dev/null || true
            success "Removed ${bin_path}"
        else
            warn "Skipping ${bin_path} (does not appear to be PRX-SD)"
        fi
    fi
done

# --- Remove shell completions ------------------------------------------------

COMP_FILES=(
    "/etc/bash_completion.d/sd"
    "${HOME}/.local/share/bash-completion/completions/sd"
    "/usr/local/share/zsh/site-functions/_sd"
    "${HOME}/.zsh/completions/_sd"
    "/usr/share/fish/vendor_completions.d/sd.fish"
    "${HOME}/.config/fish/completions/sd.fish"
)

for comp_file in "${COMP_FILES[@]}"; do
    if [ -f "$comp_file" ]; then
        info "Removing completion ${comp_file}..."
        $MAYBE_SUDO rm -f "$comp_file" 2>/dev/null || rm -f "$comp_file" 2>/dev/null || true
        success "Removed ${comp_file}"
    fi
done

# --- Remove desktop entry (Linux) --------------------------------------------

if [ "$OS" = "linux" ]; then
    desktop_file="/usr/share/applications/prx-sd.desktop"
    if [ -f "$desktop_file" ]; then
        info "Removing desktop entry..."
        $MAYBE_SUDO rm -f "$desktop_file"
        success "Removed desktop entry"
    fi
fi

# --- Remove data directory ---------------------------------------------------

if [ -d "$DATA_DIR" ] && [ "$KEEP_DATA" != "1" ]; then
    if [ "$AUTO_YES" = "1" ]; then
        info "Removing data directory ${DATA_DIR}..."
        rm -rf "$DATA_DIR"
        success "Removed ${DATA_DIR}"
    else
        printf "  Remove data directory %s? [y/N] " "$DATA_DIR"
        read -r reply
        if [ "$reply" = "y" ] || [ "$reply" = "Y" ]; then
            rm -rf "$DATA_DIR"
            success "Removed ${DATA_DIR}"
        else
            info "Kept ${DATA_DIR}"
        fi
    fi
elif [ "$KEEP_DATA" = "1" ] && [ -d "$DATA_DIR" ]; then
    info "Keeping data directory ${DATA_DIR} (--keep-data)"
fi

# --- Done --------------------------------------------------------------------

echo ""
printf "${GREEN}${BOLD}PRX-SD has been uninstalled.${RESET}\n"
echo ""
