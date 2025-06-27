#!/bin/sh
# Build an Alpine root filesystem image for anonymOS containers
# with a standard set of Linux utilities preinstalled.
# Usage: sudo ./scripts/build_rootfs.sh [output_dir]

set -e

OUTPUT_DIR=${1:-/var/images}
IMAGE="${OUTPUT_DIR}/alpine-rootfs.img"
SIZE=512M
PACKAGES="bash bash-completion coreutils util-linux findutils grep sed gawk"

mkdir -p "$OUTPUT_DIR"

if [ ! -f "$IMAGE" ]; then
    dd if=/dev/zero of="$IMAGE" bs=1M count=0 seek=512
    mkfs.ext4 "$IMAGE"
fi

MNT=$(mktemp -d)
mount -o loop "$IMAGE" "$MNT"


# Fetch the latest Alpine mini rootfs and extract it
ROOTFS_TAR="/tmp/alpine-minirootfs.tar.gz"
curl -L https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/alpine-minirootfs-3.19.1-x86_64.tar.gz -o "$ROOTFS_TAR"
tar -xzf "$ROOTFS_TAR" -C "$MNT"

# Install a fuller set of commands inside the chroot
cp /etc/resolv.conf "$MNT/etc/resolv.conf"
chroot "$MNT" /bin/sh -c "apk add --no-cache $PACKAGES"

umount "$MNT"
rm -rf "$MNT" "$ROOTFS_TAR"

echo "Base image with standard utilities created at $IMAGE"

