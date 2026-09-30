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
mkdir -p "$work/bin" "$work/sbin" "$work/usr/bin" "$work/usr/sbin" "$work/proc" "$work/sys" "$work/dev" \
         "$work/tmp" "$work/etc" "$work/root" "$work/run"
cp "$bb" "$work/bin/busybox"
ln -s busybox "$work/bin/sh"
echo anonymos-guest > "$work/etc/hostname"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$work/etc/passwd"
printf 'export PS1="\\u@\\h:\\w\\$ "\nexport PATH=/bin:/sbin:/usr/bin:/usr/sbin\n' > "$work/etc/profile"
cat > "$work/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /dev/pts && mount -t devpts devpts /dev/pts 2>/dev/null
mount -t tmpfs tmpfs /tmp
hostname -F /etc/hostname
echo
echo "=== anonymOS guest: Linux $(uname -r) is up ($(grep -c ^processor /proc/cpuinfo) vCPU, $(grep MemTotal /proc/meminfo | tr -s ' ' | cut -d' ' -f2) kB) ==="
echo "    Running on the anonymOS hypervisor through Cloud Hypervisor.  'poweroff -f' ends the machine."
echo
cd /root
# A session leader with the serial port as its controlling tty: job control and Ctrl-C work.
while true; do setsid cttyhack sh -l; done
INIT
chmod +x "$work/init"
(cd "$work" && find . | cpio -o -H newc --quiet | gzip -9) > "$here/initramfs.cpio.gz"
ls -la "$here/initramfs.cpio.gz" "$here/vmlinuz-virt"
