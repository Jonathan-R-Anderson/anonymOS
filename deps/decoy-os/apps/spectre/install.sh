#!/bin/bash
set -euo pipefail

# Spectre HIDS - One-line installer
# Usage: curl -sSL https://raw.githubusercontent.com/Aayushbankar/spectre/main/install.sh | bash
#        curl -sSL https://raw.githubusercontent.com/Aayushbankar/spectre/main/install.sh | bash -s -- --version 10.0.0

REPO="Aayushbankar/spectre"
BINARY_NAME="spectre"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/spectre"
LOG_DIR="/var/log/spectre"
DATA_DIR="/var/lib/spectre"
SERVICE_NAME="spectre"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Parse arguments
VERSION="latest"
METHOD="auto"  # auto, pip, docker, binary
FORCE=false
UNINSTALL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --method)
            METHOD="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --uninstall)
            UNINSTALL=true
            shift
            ;;
        --help)
            cat <<EOF
Spectre HIDS Installer

Usage: $0 [OPTIONS]

Options:
    --version VERSION    Version to install (default: latest)
    --method METHOD      Installation method: auto, pip, docker, binary (default: auto)
    --force              Force reinstallation
    --uninstall          Uninstall Spectre
    --help               Show this help

Examples:
    $0                           # Auto-detect best method
    $0 --method pip              # Install via pip
    $0 --method docker           # Install via Docker
    $0 --version 10.0.0          # Install specific version
    $0 --uninstall               # Remove Spectre
EOF
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This installer must be run as root (use sudo)"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    log_info "Detected OS: $OS $OS_VERSION"
}

# Check if running in container
in_container() {
    [[ -f /.dockerenv ]] || grep -q 'docker\|lxc' /proc/1/cgroup 2>/dev/null
}

# Install via pip
install_pip() {
    log_info "Installing via pip..."
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 not found"
        return 1
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if (( $(echo "$PYTHON_VERSION < 3.8" | bc -l) )); then
        log_error "Python 3.8+ required, found $PYTHON_VERSION"
        return 1
    fi
    
    # Install
    if [[ "$VERSION" == "latest" ]]; then
        pip3 install --no-cache-dir "spectre-hids[yara]"
    else
        pip3 install --no-cache-dir "spectre-hids[yara]==$VERSION"
    fi
    
    log_success "Installed via pip"
    return 0
}

# Install via Docker
install_docker() {
    log_info "Installing via Docker..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found"
        return 1
    fi
    
    # Pull image
    if [[ "$VERSION" == "latest" ]]; then
        docker pull ghcr.io/$REPO/hids:latest
    else
        docker pull ghcr.io/$REPO/hids:$VERSION
    fi
    
    # Create systemd service for Docker
    create_docker_service
    
    log_success "Docker image pulled. Service created."
    log_info "Start with: systemctl start spectre"
    return 0
}

# Create systemd service for Docker
create_docker_service() {
    cat > /etc/systemd/system/spectre-docker.service <<EOF
[Unit]
Description=Spectre HIDS (Docker)
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStartPre=-/usr/bin/docker stop %n
ExecStartPre=-/usr/bin/docker rm %n
ExecStart=/usr/bin/docker run --rm \
    --name %n \
    --privileged \
    --pid=host \
    --cgroupns=host \
    -v /:/host:ro \
    -v /var/log/spectre:/var/log/spectre \
    -v /var/lib/spectre:/var/lib/spectre \
    -v /etc/spectre:/etc/spectre \
    ghcr.io/$REPO/hids:${VERSION:-latest} \
    --interval 0.5 \
    --window-size 60 \
    --threshold 15 \
    --log-file /var/log/spectre/alerts.log \
    --db /var/lib/spectre/spectre.db \
    --yara-rules /app/yara_rules \
    --contain kill \
    --api \
    --api-port 8000
ExecStop=/usr/bin/docker stop %n

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

# Install systemd service (native)
create_native_service() {
    cat > /etc/systemd/system/spectre.service <<EOF
[Unit]
Description=Spectre HIDS
After=network.target
Documentation=https://github.com/Aayushbankar/spectre

[Service]
Type=simple
Restart=always
RestartSec=5
User=root
Environment=PYTHONUNBUFFERED=1
ExecStart=$INSTALL_DIR/spectre \
    --interval 0.5 \
    --window-size 60 \
    --threshold 15 \
    --log-file /var/log/spectre/alerts.log \
    --db /var/lib/spectre/spectre.db \
    --yara-rules /usr/share/spectre/yara_rules \
    --contain kill \
    --api \
    --api-port 8000
StandardOutput=journal
StandardError=journal
SyslogIdentifier=spectre

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/spectre /var/lib/spectre /etc/spectre
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SYS_RESOURCE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

# Setup directories and permissions
setup_directories() {
    log_info "Setting up directories..."
    mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    mkdir -p /usr/share/spectre/yara_rules
    chmod 750 "$LOG_DIR" "$DATA_DIR"
    chmod 755 "$CONFIG_DIR"
}

# Install YARA rules
install_yara_rules() {
    log_info "Installing YARA rules..."
    if [[ -d "yara_rules" ]]; then
        cp -r yara_rules/* /usr/share/spectre/yara_rules/
    else
        # Download from repo
        curl -sSL "https://api.github.com/repos/$REPO/contents/yara_rules" | \
            grep '"download_url"' | cut -d'"' -f4 | \
            xargs -I{} curl -sSL {} -o /usr/share/spectre/yara_rules/$(basename {})
    fi
    chmod 644 /usr/share/spectre/yara_rules/*
}

# Main installation flow
main() {
    echo "╔═══════════════════════════════════════════════╗"
    echo "║     Spectre HIDS Installer v10.0.0           ║"
    echo "║     Behavioral Host Intrusion Detection      ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo
    
    if [[ "$UNINSTALL" == "true" ]]; then
        uninstall
        exit 0
    fi
    
    check_root
    detect_os
    
    # Auto-detect method
    if [[ "$METHOD" == "auto" ]]; then
        if in_container; then
            METHOD="pip"
            log_info "Container detected, using pip install"
        elif command -v docker &> /dev/null && systemctl is-active --quiet docker; then
            METHOD="docker"
            log_info "Docker detected, using Docker install"
        else
            METHOD="pip"
            log_info "Using pip install"
        fi
    fi
    
    setup_directories
    install_yara_rules
    
    case $METHOD in
        pip)
            install_pip && create_native_service
            ;;
        docker)
            install_docker
            ;;
        binary)
            log_error "Binary install not yet supported"
            exit 1
            ;;
        *)
            log_error "Unknown method: $METHOD"
            exit 1
            ;;
    esac
    
    echo
    log_success "Installation complete!"
    echo
    echo "Next steps:"
    echo "  1. Review config: $CONFIG_DIR/rules.json"
    echo "  2. Start service: systemctl start spectre"
    echo "  3. Enable on boot: systemctl enable spectre"
    echo "  4. View logs: journalctl -u spectre -f"
    echo "  5. Dashboard: http://localhost:8000 (if --api enabled)"
    echo
    echo "Configuration:"
    echo "  - Log file: $LOG_DIR/alerts.log"
    echo "  - Database: $DATA_DIR/spectre.db"
    echo "  - YARA rules: /usr/share/spectre/yara_rules"
    echo "  - Config: $CONFIG_DIR/rules.json"
}

uninstall() {
    log_info "Uninstalling Spectre HIDS..."
    systemctl stop spectre 2>/dev/null || true
    systemctl disable spectre 2>/dev/null || true
    systemctl stop spectre-docker 2>/dev/null || true
    systemctl disable spectre-docker 2>/dev/null || true
    rm -f /etc/systemd/system/spectre.service
    rm -f /etc/systemd/system/spectre-docker.service
    systemctl daemon-reload
    pip3 uninstall -y spectre-hids 2>/dev/null || true
    docker rmi ghcr.io/$REPO/hids:latest 2>/dev/null || true
    rm -rf "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    rm -rf /usr/share/spectre
    log_success "Uninstall complete"
}

main "$@"