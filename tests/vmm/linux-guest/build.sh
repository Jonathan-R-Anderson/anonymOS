#!/bin/sh
# Build the Virtual Machines app's bundled Linux guest: Alpine's linux-virt kernel (bzImage) and a
# busybox initramfs whose /init mounts the pseudo filesystems, loads the network driver, takes a
# DHCP lease, prints a banner and runs a shell on the serial console.
#   tests/vmm/linux-guest/build.sh  ->  initramfs.cpio.gz (+ vmlinuz-virt, modloop-virt: downloads)
#
# The kernel's modules ship separately (Alpine's modloop-virt squashfs); the few the guest needs --
# virtio-net and AF_PACKET for its NIC and DHCP, the VirtualBox guest drivers for display/mouse
# integration -- are copied in with their dependencies.  Kernel and modloop must be the SAME build:
# the version is checked before anything is copied.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
bb="$root/cd/busybox"
[ -f "$bb" ] || bb="$root/build/busybox"
NB=https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/netboot
if [ ! -f "$here/vmlinuz-virt" ] || [ ! -f "$here/modloop-virt" ]; then
    curl -sS -fL -o "$here/vmlinuz-virt" "$NB/vmlinuz-virt"
    curl -sS -fL -o "$here/modloop-virt" "$NB/modloop-virt"
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# ---- modules: the kernel's version must have a directory in the modloop ----
kver=$(strings "$here/vmlinuz-virt" | sed -n 's/^\([0-9][0-9.]*-[0-9]*-virt\) .*/\1/p' | head -1)
[ -n "$kver" ] || { echo "cannot read the kernel version from vmlinuz-virt" >&2; exit 1; }
unsquashfs -q -d "$work/modloop" "$here/modloop-virt" "modules/$kver/modules.dep" \
    "modules/$kver/modules.order" "modules/$kver/modules.builtin" "modules/$kver/kernel" >/dev/null
[ -f "$work/modloop/modules/$kver/modules.dep" ] || { echo "modloop-virt has no modules for $kver" >&2; exit 1; }
dep="$work/modloop/modules/$kver/modules.dep"
want=""
# modload GROUP MODULE...: the load order for MODULE and its dependencies (deps first, as modprobe
# does: the dependency list is loaded last-to-first), written to /etc/modload-GROUP.
loadorder() {
    line=$(grep -E "/$1\.ko(\.[a-z]+)?:" "$dep" | head -1)
    [ -n "$line" ] || { echo "module $1 not in $kver" >&2; exit 1; }
    for d in $(echo ${line#*:} | tr ' ' '\n' | sed '1!G;h;$!d'); do echo "$d"; done
    echo "${line%%:*}"
}
modload() {
    g=$1; shift
    for m in "$@"; do loadorder "$m"; done | awk '!seen[$0]++' > "$work/modload-$g"
    want="$want $(cat "$work/modload-$g" | tr '\n' ' ')"
}
modload net af_packet virtio_net
modload vbox vboxguest vboxvideo

mkdir -p "$work/root-fs"
r="$work/root-fs"
mkdir -p "$r/bin" "$r/sbin" "$r/usr/bin" "$r/usr/sbin" "$r/proc" "$r/sys" "$r/dev" "$r/tmp" "$r/etc" \
         "$r/root" "$r/run" "$r/lib/modules/$kver"
for f in $want; do
    [ -f "$r/lib/modules/$kver/$f" ] && continue
    mkdir -p "$r/lib/modules/$kver/$(dirname "$f")"
    cp "$work/modloop/modules/$kver/$f" "$r/lib/modules/$kver/$f"
done
cp "$dep" "$work/modloop/modules/$kver/modules.builtin" "$r/lib/modules/$kver/" 2>/dev/null || cp "$dep" "$r/lib/modules/$kver/"

cp "$bb" "$r/bin/busybox"
ln -s busybox "$r/bin/sh"
MUSL_GCC="${MUSL_GCC:-$HOME/lkl-build/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc}"
"$MUSL_GCC" -static -Os -s -o "$r/sbin/ginsmod" "$here/ginsmod.c"
for g in net vbox; do sed "s#^#/lib/modules/$kver/#" "$work/modload-$g" > "$r/etc/modload-$g"; done
echo anonymos-guest > "$r/etc/hostname"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$r/etc/passwd"
printf 'export PS1="\\u@\\h:\\w\\$ "\nexport PATH=/bin:/sbin:/usr/bin:/usr/sbin\n' > "$r/etc/profile"
# udhcpc's lease script: address, default route, resolver.
cat > "$r/etc/udhcpc.script" <<'SCRIPT'
#!/bin/sh
case "$1" in
    deconfig) ip addr flush dev "$interface"; ip link set "$interface" up ;;
    bound|renew)
        ip addr flush dev "$interface"
        ip addr add "$ip/${mask:-24}" dev "$interface"
        [ -n "$router" ] && ip route replace default via "${router%% *}" dev "$interface"
        : > /etc/resolv.conf
        for d in $dns; do echo "nameserver $d" >> /etc/resolv.conf; done
        echo "    network: $interface $ip/${mask:-24} via ${router%% *} (dns ${dns:-none})" ;;
esac
SCRIPT
chmod +x "$r/etc/udhcpc.script"
cat > "$r/init" <<'INIT'
#!/bin/sh
/bin/busybox --install -s
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /dev/pts && mount -t devpts devpts /dev/pts 2>/dev/null
mount -t tmpfs tmpfs /tmp
hostname -F /etc/hostname
ip link set lo up
ginsmod $(cat /etc/modload-net) || echo "    network drivers did not load"
if [ -e /sys/class/net/eth0 ]; then
    udhcpc -i eth0 -s /etc/udhcpc.script -q -t 6 -n >/dev/null 2>&1 || echo "    network: eth0 got no DHCP lease"
fi
echo
echo "=== anonymOS guest: Linux $(uname -r) is up ($(grep -c ^processor /proc/cpuinfo) vCPU, $(grep MemTotal /proc/meminfo | tr -s ' ' | cut -d' ' -f2) kB) ==="
echo "    Running on the anonymOS hypervisor through Cloud Hypervisor.  'poweroff -f' ends the machine."
[ -e /sys/class/net/eth0 ] && ip -4 addr show eth0 | sed -n 's/^ *inet /    eth0: /p'
echo
cd /root
# A session leader with the serial port as its controlling tty: job control and Ctrl-C work.
while true; do setsid cttyhack sh -l; done
INIT
chmod +x "$r/init"
(cd "$r" && find . | cpio -o -H newc --quiet | gzip -9) > "$here/initramfs.cpio.gz"
ls -la "$here/initramfs.cpio.gz" "$here/vmlinuz-virt"
echo "modules ($kver):$(echo $want | tr ' ' '\n' | xargs -n1 basename | sort -u | tr '\n' ' ')"
