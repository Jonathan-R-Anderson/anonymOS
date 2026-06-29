#!/bin/sh
# deps/decoy-os/customize.sh — turn a fresh Alpine minirootfs into a lived-in decoy
# workstation (roadmap/INSTALLER.md §H1). Runs under fakeroot.
#   args: ROOTFS FAKELOGD DECOY_PASSPHRASE
#
# The decoy OS's OWN settings come from the installer (§E6 hidden-OS step) via env vars —
# the decoy is configured in the SAME install flow, not a separate process. Defaults shown:
#   DECOY_USER=decoyuser   DECOY_USER_FULLNAME="Decoy User"   DECOY_HOSTNAME=helix
#   DECOY_USER_PASSWORD=   (empty -> locked account)          DECOY_NOW=<unix time>
set -e
ROOTFS="$1"; FAKELOGD="$2"; PW="$3"
U="${DECOY_USER:-decoyuser}"
FULL="${DECOY_USER_FULLNAME:-Decoy User}"
HN="${DECOY_HOSTNAME:-helix}"
HOME_DIR="/home/$U"

# ── identity (installer-configurable) ────────────────────────────────────────
echo "$HN" > "$ROOTFS/etc/hostname"
printf '127.0.0.1\tlocalhost %s\n::1\tlocalhost %s\n' "$HN" "$HN" > "$ROOTFS/etc/hosts"
echo "Welcome to $HN.  Unauthorized access is prohibited." > "$ROOTFS/etc/motd"

# ── the decoy's user account (installer sets name / full name / password) ─────
# SHA-512 crypt if a password was given + openssl is available, else a locked account.
HASH='!'
if [ -n "$DECOY_USER_PASSWORD" ] && command -v openssl >/dev/null 2>&1; then
  HASH="$(openssl passwd -6 "$DECOY_USER_PASSWORD")"
fi
grep -q "^$U:" "$ROOTFS/etc/passwd" || \
  echo "$U:x:1000:1000:$FULL:$HOME_DIR:/bin/ash" >> "$ROOTFS/etc/passwd"
grep -q "^$U:" "$ROOTFS/etc/group" || echo "$U:x:1000:" >> "$ROOTFS/etc/group"
grep -q "^$U:" "$ROOTFS/etc/shadow" 2>/dev/null || \
  echo "$U:$HASH:19000:0:99999:7:::" >> "$ROOTFS/etc/shadow"
# the plausible service accounts the logs reference — must exist so logins are consistent
for su in deploy backup; do
  grep -q "^$su:" "$ROOTFS/etc/passwd" || \
    echo "$su:x:$((1000 + $(grep -c . "$ROOTFS/etc/passwd"))):100:$su:/home/$su:/sbin/nologin" >> "$ROOTFS/etc/passwd"
done
mkdir -p "$ROOTFS$HOME_DIR/.ssh" "$ROOTFS$HOME_DIR/Documents"

cat > "$ROOTFS$HOME_DIR/.bash_history" <<'EOF'
ls -la
cat /etc/os-release
sudo apk update && sudo apk upgrade
vi ~/Documents/notes.txt
git -C ~/Documents/project status
ssh deploy@server01
df -h
htop
sudo rc-service sshd restart
tail -f /var/log/messages
EOF
cat > "$ROOTFS$HOME_DIR/Documents/notes.txt" <<'EOF'
- renew the TLS cert before the 15th
- ask ops about the staging backup window
- review the apk upgrade list
EOF
cat > "$ROOTFS$HOME_DIR/.profile" <<'EOF'
export PS1='\u@\h:\w\$ '
export EDITOR=vi
alias ll='ls -la'
EOF

# apk world (claimed-installed packages) — consistent with the daemons the logs reference
mkdir -p "$ROOTFS/etc/apk"
printf 'alpine-base\nopenssh\ngit\nvim\nhtop\nsudo\ncurl\ntmux\nchrony\n' > "$ROOTFS/etc/apk/world"

# ── seed deterministic, password-keyed fake /var/log history ending ~now (§G/§H2/F3) ──
# The seed-anchored virtual clock; logs reference the chosen user + hostname.
NOW="${DECOY_NOW:-$(date +%s)}"
mkdir -p "$ROOTFS/var/log"
"$FAKELOGD" "$PW" --root "$ROOTFS" --now "$NOW" --user "$U" --hostname "$HN" >/dev/null

# coherent file mtimes within the recent window (§E7/F3), recorded epoch for the live daemon
RECENT=$((NOW - 2*86400))
for fpath in "$ROOTFS$HOME_DIR/.bash_history" "$ROOTFS$HOME_DIR/Documents/notes.txt" \
             "$ROOTFS$HOME_DIR/.profile" "$ROOTFS$HOME_DIR"; do
  touch -d "@$RECENT" "$fpath" 2>/dev/null || true
done
echo "$NOW" > "$ROOTFS/etc/.decoy-epoch"

echo "$(head -c16 /dev/zero | tr '\0' '0')" > "$ROOTFS/etc/machine-id" 2>/dev/null || true
