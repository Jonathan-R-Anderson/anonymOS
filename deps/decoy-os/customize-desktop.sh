#!/bin/bash
# deps/decoy-os/customize-desktop.sh — turn the believable headless decoy rootfs (already built
# by customize.sh: user, history, ssh, git repo, /var/log) into a graphical XFCE daily-driver
# (roadmap/INSTALLER.md §H1). Runs as ROOT (needs chroot for the rendering-cache triggers).
#   args: ROOTFS
#
# The user chose "a real desktop" for the decoy cover story: booting the decoy lands in a normal
# XFCE session for the same account customize.sh set up. firefox-esr is now really installed, so
# the ~/.mozilla profile customize.sh shipped is consistent (no browser-profile-without-browser
# tell). Everything here is deterministic and adds no "*decoy*" artifact (§H4).
set -e
R="$1"
U="${DECOY_USER:-decoyuser}"
H="$R/home/$U"

# ── service accounts apk --no-scripts did not create (dbus/polkit refuse to start without) ──
add_svc(){ grep -q "^$1:" "$R/etc/passwd" || echo "$1:x:$2:$2:$1:/dev/null:/sbin/nologin" >> "$R/etc/passwd"; grep -q "^$1:" "$R/etc/group" || echo "$1:x:$2:" >> "$R/etc/group"; }
add_svc messagebus 990
add_svc polkitd 991
mkdir -p "$R/run/dbus" "$R/var/lib/polkit-1"

# ── the desktop user needs a login shell + the seat/device groups X and the session use ──
# ensure alex's shell is bash (X profile logic uses it) and groups include video/input/…
awk -F: -v u="$U" 'BEGIN{OFS=":"} $1==u{$7="/bin/bash"} {print}' "$R/etc/passwd" > "$R/etc/passwd.n" && mv "$R/etc/passwd.n" "$R/etc/passwd"
for g in video input tty audio wheel usb dbus netdev plugdev; do
  grep -q "^$g:" "$R/etc/group" && awk -F: -v g="$g" -v u="$U" 'BEGIN{OFS=":"} $1==g{ if($4=="")$4=u; else if(index(":"$4":",":"u":")==0)$4=$4","u } {print}' "$R/etc/group" > "$R/etc/group.n" && mv "$R/etc/group.n" "$R/etc/group" || true
done
mkdir -p "$R/run/user/1000"; chown 1000:1000 "$R/run/user/1000" 2>/dev/null || true

# ── autologin alex on tty1 -> startx -> XFCE (busybox login -f; no util-linux agetty) ──
# keep the openrc sysinit/boot/default lines; replace only the tty1 getty with an autologin login.
grep -q 'openrc sysinit' "$R/etc/inittab" || sed -i '1i ::sysinit:/sbin/openrc sysinit\n::sysinit:/sbin/openrc boot\n::wait:/sbin/openrc default' "$R/etc/inittab"
sed -i '/^tty1::/d' "$R/etc/inittab"
echo "tty1::respawn:/bin/login -f $U" >> "$R/etc/inittab"

# alex starts X automatically when he lands on tty1 (append to the believable .profile)
cat >> "$H/.profile" <<'EOF'

# start the graphical session on the console login (a normal desktop autologin)
if [ "$(tty)" = "/dev/tty1" ] && [ -z "$DISPLAY" ]; then
  export XDG_RUNTIME_DIR=/run/user/1000
  exec startx -- vt1 >"$HOME/.xsession.log" 2>&1
fi
EOF
cat > "$H/.xinitrc" <<'EOF'
#!/bin/sh
export XDG_RUNTIME_DIR=/run/user/1000
export XFCE_PANEL_MIGRATE_DEFAULT=1
exec startxfce4
EOF
chmod +x "$H/.xinitrc"
chown 1000:1000 "$H/.profile" "$H/.xinitrc"

# allow the non-root user to start the X server
mkdir -p "$R/etc/X11"
printf 'allowed_users=anybody\nneeds_root_rights=yes\n' > "$R/etc/X11/Xwrapper.config"

# graphics + input modules loaded at boot (bochs for -vga std, virtio_gpu for -vga virtio)
printf 'bochs\nvirtio_gpu\nevdev\n' > "$R/etc/modules"

# ── enable the OpenRC services the desktop needs ──
enable(){ mkdir -p "$R/etc/runlevels/$1"; ln -sf "/etc/init.d/$2" "$R/etc/runlevels/$1/$2" 2>/dev/null || true; }
for s in devfs dmesg mdev hwdrivers; do enable sysinit "$s"; done
for s in modules hwclock modloop bootmisc syslog networking; do enable boot "$s"; done
for s in dbus elogind networkmanager; do enable default "$s"; done

# ── THE critical step apk --no-scripts skipped: rebuild the rendering caches, or the desktop
#    paints nothing (empty gdk-pixbuf loaders.cache -> every image decode returns NULL). Run the
#    Alpine tools inside the rootfs via chroot (same arch, real root). ──
mount -t proc none "$R/proc" 2>/dev/null || true
trig(){ chroot "$R" sh -c "$1" >/dev/null 2>&1 || true; }
trig 'gdk-pixbuf-query-loaders --update-cache'
trig 'glib-compile-schemas /usr/share/glib-2.0/schemas'
trig 'gtk-update-icon-cache -f -t /usr/share/icons/hicolor'
trig 'gtk-update-icon-cache -f -t /usr/share/icons/Adwaita'
trig 'update-mime-database /usr/share/mime'
trig 'fc-cache -f'
umount "$R/proc" 2>/dev/null || true

LC=$(wc -l < "$R/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache" 2>/dev/null || echo 0)
echo "[decoy-os] desktop configured for $U (autologin -> XFCE); gdk-pixbuf loaders.cache=$LC lines"
[ "$LC" -gt 1 ] || { echo "[decoy-os] FATAL: gdk-pixbuf loaders.cache empty — desktop would not paint"; exit 1; }
