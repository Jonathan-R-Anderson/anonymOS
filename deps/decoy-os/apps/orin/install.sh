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
# install.sh - Automated installer for Orin Forensics Engine

set -e

echo "=== Orin Forensics Engine Installer ==="

# 1. Check if pipx is available
if ! command -v pipx &> /dev/null; then
    echo "[*] pipx is not installed. Attempting to install it..."
    if command -v apt-get &> /dev/null; then
        echo "[*] Running: sudo apt-get update && sudo apt-get install -y pipx"
        sudo apt-get update
        sudo apt-get install -y pipx
    else
        echo "[-] Error: pipx is missing and 'apt-get' was not found."
        echo "[-] Please install pipx manually using your package manager, then re-run this script."
        exit 1
    fi
fi

# 2. Install Orin
if [ -f "./orin" ]; then
    echo "[*] Pre-compiled standalone 'orin' binary detected. Installing binary..."
    if [ "$EUID" -eq 0 ]; then
        echo "[*] Running as root. Installing binary to /usr/local/bin/orin..."
        cp ./orin /usr/local/bin/orin
        chmod +x /usr/local/bin/orin
        
        # Install rules to /var/lib/orin/rules
        if [ -d "./rules" ]; then
            echo "[*] Copying default rules to /var/lib/orin/rules..."
            mkdir -p /var/lib/orin/rules
            cp -r ./rules/* /var/lib/orin/rules/
            echo "[+] Default rules installed successfully."
        fi
        
        # Create system-wide config directory and deploy default config template if not present
        if [ ! -f /etc/orin/orin_config.json ]; then
            echo "[*] Copying default configuration to /etc/orin/orin_config.json..."
            mkdir -p /etc/orin
            if [ -f orin_config.json.example ]; then
                cp orin_config.json.example /etc/orin/orin_config.json
            fi
            chmod 600 /etc/orin/orin_config.json
            echo "[+] Default configuration installed securely."
        else
            echo "[*] Existing configuration found at /etc/orin/orin_config.json, skipping overwrite."
        fi
    else
        # If not root, install to user's local bin
        echo "[*] Running as user. Installing binary to $HOME/.local/bin/orin..."
        mkdir -p "$HOME/.local/bin"
        cp ./orin "$HOME/.local/bin/orin"
        chmod +x "$HOME/.local/bin/orin"
        echo "[*] Ensuring local path is in PATH..."
        if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
            echo "[!] Warning: $HOME/.local/bin is not in your PATH. Please add it to your shell profile."
        fi
        
        # Copy rules to ~/.local/share/orin/rules
        if [ -d "./rules" ]; then
            echo "[*] Copying default rules to $HOME/.local/share/orin/rules..."
            mkdir -p "$HOME/.local/share/orin/rules"
            cp -r ./rules/* "$HOME/.local/share/orin/rules/"
            echo "[+] Default rules installed locally."
        fi
        
        # Create user config directory and deploy default config template if not present
        if [ ! -f "$HOME/.config/orin/orin_config.json" ]; then
            echo "[*] Copying default configuration to $HOME/.config/orin/orin_config.json..."
            mkdir -p "$HOME/.config/orin"
            if [ -f orin_config.json.example ]; then
                cp orin_config.json.example "$HOME/.config/orin/orin_config.json"
            fi
            chmod 600 "$HOME/.config/orin/orin_config.json"
            echo "[+] Default configuration installed locally."
        else
            echo "[*] Existing configuration found at $HOME/.config/orin/orin_config.json, skipping overwrite."
        fi
    fi
else
    # Fallback to source installation
    echo "[*] Pre-compiled binary not found. Falling back to Python source installation..."
    if [ "$EUID" -eq 0 ]; then
        echo "[*] Running as root. Installing Orin Forensics Engine globally into the system Python environment..."
        python3 -m pip install . --break-system-packages

        # Create system-wide config directory and deploy default config template if not present
        if [ ! -f /etc/orin/orin_config.json ]; then
            echo "[*] Copying default configuration to /etc/orin/orin_config.json..."
            mkdir -p /etc/orin
            if [ -f orin_config.json.example ]; then
                cp orin_config.json.example /etc/orin/orin_config.json
            elif [ -f orin_config.json ]; then
                cp orin_config.json /etc/orin/orin_config.json
            fi
            chmod 600 /etc/orin/orin_config.json
            echo "[+] Default configuration installed securely."
        else
            echo "[*] Existing configuration found at /etc/orin/orin_config.json, skipping overwrite."
        fi
    else
        # Ensure pipx binary paths are configured in shell profiles
        echo "[*] Ensuring pipx paths are configured..."
        pipx ensurepath

        echo "[*] Installing Orin Forensics Engine locally via pipx..."
        if pipx list | grep -q "orin"; then
            echo "[*] Orin is already installed. Re-installing/upgrading..."
            pipx install --force .
        else
            pipx install .
        fi
    fi
fi

echo "========================================"
echo "[+] Installation complete!"
echo "[+] You can now run the 'orin' command in your terminal."
echo "[+] Note: If this is the first time installing pipx, please restart your terminal session to load the updated PATH."
echo "========================================"