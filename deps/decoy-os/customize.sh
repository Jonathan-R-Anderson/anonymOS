#!/bin/sh
# deps/decoy-os/customize.sh — turn a fresh Alpine minirootfs into a lived-in decoy
# workstation (roadmap/INSTALLER.md §H1). Runs under fakeroot. Args: ROOTFS FAKELOGD PW
set -e
ROOTFS="$1"; FAKELOGD="$2"; PW="$3"

# ── identity ────────────────────────────────────────────────────────────────
echo "helix" > "$ROOTFS/etc/hostname"
printf '127.0.0.1\tlocalhost helix\n::1\tlocalhost helix\n' > "$ROOTFS/etc/hosts"
echo "Welcome to helix.  Unauthorized access is prohibited." > "$ROOTFS/etc/motd"

# ── a believable user (locked password; present in passwd/shadow + a real home) ──
grep -q '^decoyuser:' "$ROOTFS/etc/passwd" || \
  echo "decoyuser:x:1000:1000:Decoy User:/home/decoyuser:/bin/ash" >> "$ROOTFS/etc/passwd"
grep -q '^decoyuser:' "$ROOTFS/etc/group" || \
  echo "decoyuser:x:1000:" >> "$ROOTFS/etc/group"
grep -q '^decoyuser:' "$ROOTFS/etc/shadow" 2>/dev/null || \
  echo "decoyuser:!:19000:0:99999:7:::" >> "$ROOTFS/etc/shadow"
for u in deploy backup; do 
  grep -q "^$u:" "$ROOTFS/etc/passwd" || echo "$u:x:$((1000 + $(grep -c . "$ROOTFS/etc/passwd"))):100:$u:/home/$u:/sbin/nologin" >> "$ROOTFS/etc/passwd"; 
done
mkdir -p "$ROOTFS/home/decoyuser/.ssh" "$ROOTFS/home/decoyuser/Documents"

cat > "$ROOTFS/home/decoyuser/.bash_history" <<'EOF'
ls -la
cat /etc/os-release
sudo apk update && sudo apk upgrade
vi ~/Documents/notes.txt
git -C ~/Documents/project status
ssh deploy@server01
df -h
htop
sudo rc-service sshd restart
tail -f /var/log/syslog
EOF
cat > "$ROOTFS/home/decoyuser/Documents/notes.txt" <<'EOF'
- renew the TLS cert before the 15th
- ask ops about the staging backup window
- migrate the cron jobs to systemd timers
EOF
cat > "$ROOTFS/home/decoyuser/.profile" <<'EOF'
export PS1='\u@\h:\w\$ '
export EDITOR=vi
alias ll='ls -la'
EOF

# a plausible installed-package world (Alpine's apk 'world' file)
mkdir -p "$ROOTFS/etc/apk"
cat > "$ROOTFS/etc/apk/world" <<'EOF'
alpine-base
openssh
git
vim
htop
sudo
curl
tmux
EOF

# ── seed deterministic, password-keyed fake /var/log history ending ~now (§G/§H2/F3) ──
# The seed-anchored virtual clock: fakelogd ages the "install date" 6–18 months back and
# runs history up to NOW, so logs end at the present (not a fixed 2024 epoch).
NOW="${DECOY_NOW:-$(date +%s)}"
mkdir -p "$ROOTFS/var/log"
"$FAKELOGD" "$PW" --root "$ROOTFS" --now "$NOW" >/dev/null

# coherent file mtimes: home/recent activity dated within the last few days (NOT 1970/now-
# only), consistent with logs that run up to NOW — closing the §E7/F3 timestamp gap.
RECENT=$((NOW - 2*86400))
for fpath in "$ROOTFS/home/decoyuser/.bash_history" "$ROOTFS/home/decoyuser/Documents/notes.txt" \
             "$ROOTFS/home/decoyuser/.profile" "$ROOTFS/home/decoyuser"; do
  touch -d "@$RECENT" "$fpath" 2>/dev/null || true
done
echo "$NOW" > "$ROOTFS/etc/.decoy-epoch"          # recorded for the live daemon to continue

# a lastlog/wtmp-ish marker + a believable boot id
echo "$(head -c16 /dev/zero | tr '\0' '0')" > "$ROOTFS/etc/machine-id" 2>/dev/null || true
