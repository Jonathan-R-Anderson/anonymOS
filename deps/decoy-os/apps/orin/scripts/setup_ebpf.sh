#!/usr/bin/env bash

# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# setup_ebpf.sh - Automated eBPF dependencies setup script for Orin

set -eo pipefail

echo "=== Orin eBPF Real-Time Streamer Setup ==="

# 1. Enforce root privileges
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This setup script must be run as root (or via sudo)."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
EBPF_DIR="$REPO_DIR/ebpf"
VMLINUX_OUT="$EBPF_DIR/vmlinux.h"

# Parse arguments
BUILD_MODE=false
for arg in "$@"; do
    if [ "$arg" = "--build" ] || [ "$arg" = "-b" ]; then
        BUILD_MODE=true
    fi
done

# 2. Check Kernel compatibility
KERNEL_VERSION=$(uname -r)
echo "[*] Detected kernel: $KERNEL_VERSION"

# 3. Detect OS / Package Manager
if [ -f /etc/debian_version ]; then
    OS="debian"
    echo "[*] Detected Debian/Ubuntu-based distribution."
elif [ -f /etc/redhat-release ] || [ -f /etc/fedora-release ]; then
    OS="rhel"
    echo "[*] Detected RedHat/Fedora/Rocky-based distribution."
else
    OS="unknown"
    echo "[!] Warning: Unsupported or undetected Linux distribution. You may need to install packages manually."
fi

# 4. Check & Install Dependencies
echo "[*] Checking dependency packages..."
PACKAGES_TO_INSTALL=()

check_cmd() {
    command -v "$1" &> /dev/null
}

if [ "$BUILD_MODE" = true ]; then
    echo "[*] Running in BUILD/DEVELOPER mode..."
    if ! check_cmd bpftool; then
        PACKAGES_TO_INSTALL+=("bpftool")
    fi
    if ! check_cmd clang; then
        PACKAGES_TO_INSTALL+=("clang")
    fi
    if ! check_cmd llvm-strip && ! check_cmd llvm; then
        PACKAGES_TO_INSTALL+=("llvm")
    fi
    
    if [ "$OS" = "debian" ]; then
        if ! dpkg -l | grep -E -q "libbpf-dev|libbpf[0-9]"; then
            PACKAGES_TO_INSTALL+=("libbpf-dev")
        fi
    elif [ "$OS" = "rhel" ]; then
        if ! rpm -qa | grep -q libbpf; then
            PACKAGES_TO_INSTALL+=("libbpf-devel")
        fi
    fi
else
    echo "[*] Running in TARGET/RUNTIME mode (zero compilation)..."
    # Target mode only requires the system libbpf library
    if [ "$OS" = "debian" ]; then
        if ! dpkg -l | grep -E -q "libbpf-dev|libbpf[0-9]"; then
            PACKAGES_TO_INSTALL+=("libbpf1")
        fi
    elif [ "$OS" = "rhel" ]; then
        if ! rpm -qa | grep -q libbpf; then
            PACKAGES_TO_INSTALL+=("libbpf")
        fi
    fi
fi

if [ ${#PACKAGES_TO_INSTALL[@]} -ne 0 ]; then
    echo "[*] Missing packages: ${PACKAGES_TO_INSTALL[*]}"
    if [ "$OS" = "debian" ]; then
        echo "[*] Running: apt-get update && apt-get install -y ${PACKAGES_TO_INSTALL[*]}"
        apt-get update
        apt-get install -y "${PACKAGES_TO_INSTALL[@]}"
    elif [ "$OS" = "rhel" ]; then
        echo "[*] Running: dnf install -y ${PACKAGES_TO_INSTALL[*]}"
        dnf install -y "${PACKAGES_TO_INSTALL[@]}"
    else
        echo "❌ Error: Cannot automatically install dependencies. Please install required libraries manually."
        exit 1
    fi
else
    echo "[+] All required packages are already installed."
fi

# 5. Check for BTF support
echo "[*] Checking for kernel BTF support..."
BTF_FILE="/sys/kernel/btf/vmlinux"
BTF_CONFIG_CHECK=false

if [ -f "$BTF_FILE" ]; then
    echo "[+] Found kernel BTF structure at $BTF_FILE."
    BTF_CONFIG_CHECK=true
else
    echo "[!] Warning: Kernel BTF structure not found at $BTF_FILE."
    if [ -f "/boot/config-$KERNEL_VERSION" ]; then
        if grep -q "CONFIG_DEBUG_INFO_BTF=y" "/boot/config-$KERNEL_VERSION"; then
            echo "[+] CONFIG_DEBUG_INFO_BTF is set to 'y' in boot config, but /sys/kernel/btf/vmlinux is not mounted or accessible."
            BTF_CONFIG_CHECK=true
        fi
    fi
fi

if [ "$BTF_CONFIG_CHECK" = false ]; then
    echo "❌ Error: eBPF streaming requires BTF (CONFIG_DEBUG_INFO_BTF=y) support."
    exit 1
fi

# 6. Generate vmlinux.h and compile streamer (Build Mode Only)
if [ "$BUILD_MODE" = true ]; then
    echo "[*] Generating vmlinux.h..."
    if [ -f "$BTF_FILE" ]; then
        mkdir -p "$EBPF_DIR"
        if bpftool btf dump file "$BTF_FILE" format c > "$VMLINUX_OUT"; then
            echo "[+] Successfully generated $VMLINUX_OUT"
        else
            echo "❌ Error: bpftool failed to generate vmlinux.h from BTF."
            exit 1
        fi
    else
        echo "❌ Error: BTF file not found. Cannot generate vmlinux.h"
        exit 1
    fi
    
    echo "[*] Compiling eBPF streamer code..."
    if make -C "$EBPF_DIR"; then
        echo "[+] Successfully compiled streamer.bpf.o"
    else
        echo "❌ Error: Compilation of streamer.bpf.o failed."
        exit 1
    fi
fi

echo "========================================"
echo "[+] eBPF setup complete!"
echo "[+] You can now run: sudo orin stream"
echo "========================================"
