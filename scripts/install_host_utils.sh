#!/bin/sh
# Install standard Linux utilities on the anonymOS host.
# This complements build_rootfs.sh which prepares container images.

set -e

PACKAGES="bash bash-completion coreutils util-linux findutils grep sed gawk"

if command -v apk >/dev/null 2>&1; then
    echo "Installing packages via apk..."
    sudo apk add --no-cache $PACKAGES
elif command -v apt-get >/dev/null 2>&1; then
    echo "Installing packages via apt-get..."
    sudo apt-get update
    sudo apt-get install -y $PACKAGES
elif command -v pacman >/dev/null 2>&1; then
    echo "Installing packages via pacman..."
    sudo pacman -Sy --noconfirm $PACKAGES
else
    echo "No supported package manager found. Please install:\n$PACKAGES"
    exit 1
fi

echo "Host utilities installed."
