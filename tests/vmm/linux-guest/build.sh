#!/bin/sh
# Build the minimal Linux guest initramfs used to bring up the in-kernel hypervisor:
# a static busybox + an /init that mounts the pseudo filesystems, prints a banner, and
# runs a shell on the serial console.  The kernel is Alpine's vmlinuz-virt (bzImage).
#   tests/vmm/linux-guest/build.sh  ->  tests/vmm/linux-guest/initramfs.cpio.gz
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
bb="$root/cd/busybox"
[ -f "$bb" ] || bb="$root/build/busybox"
[ -f "$here/vmlinuz-virt" ] || curl -sS -fL -o "$here/vmlinuz-virt" \
    https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/netboot/vmlinuz-virt
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/sbin" "$work/proc" "$work/sys" "$work/dev" "$work/tmp" "$work/etc"
cp "$bb" "$work/bin/busybox"
for a in sh mount echo cat ls uname dmesg ps free sleep poweroff reboot mkdir; do
    ln -s busybox "$work/bin/$a"
done
cat > "$work/init" <<'INIT'
#!/bin/sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sys /sys
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null
echo
echo "=== anonymOS guest: Linux $(uname -r) is up ($(grep -c ^processor /proc/cpuinfo) vCPU, $(grep MemTotal /proc/meminfo | tr -s ' ' | cut -d' ' -f2) kB) ==="
echo
exec /bin/sh
INIT
chmod +x "$work/init"
(cd "$work" && find . | cpio -o -H newc --quiet | gzip -9) > "$here/initramfs.cpio.gz"
ls -la "$here/initramfs.cpio.gz" "$here/vmlinuz-virt"
