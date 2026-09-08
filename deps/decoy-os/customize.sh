#!/bin/sh
# deps/decoy-os/customize.sh — turn a fresh Alpine minirootfs (with a REAL toolchain already
# apk-installed by the Makefile) into a lived-in decoy workstation (roadmap/INSTALLER.md §H1).
# Runs under fakeroot on the host.
#   args: ROOTFS FAKELOGD DECOY_PASSPHRASE
#
# The decoy OS's OWN settings come from the installer (§E6 hidden-OS step) via env vars — the
# decoy is configured in the SAME install flow, not a separate process. Defaults:
#   DECOY_USER=decoyuser  DECOY_USER_FULLNAME="$U"  DECOY_HOSTNAME=helix
#   DECOY_USER_PASSWORD=  (empty -> locked)         DECOY_NOW=<unix time>
#
# EVERYTHING here is DETERMINISTIC from the passphrase (SEED below): same decoy password ->
# byte-identical decoy, reboot-stable and reproducible (§G/§H2/E7/F3 determinism rule). The
# believability goal is INTERNAL CONSISTENCY — a coerced examiner with the decoy password and
# root must find a machine whose packages, history, configs, ssh state, git repo, logs and file
# times all corroborate each other. An inconsistency (a claimed tool that isn't installed, a
# history line referencing an absent file, an all-zero machine-id) is a decoy tell.
set -e
ROOTFS="$1"; FAKELOGD="$2"; PW="$3"
U="${DECOY_USER:-decoyuser}"
FULL="${DECOY_USER_FULLNAME:-$U}"   # default GECOS = username (never "Decoy User", §H4)
HN="${DECOY_HOSTNAME:-helix}"
HOME_DIR="/home/$U"
H="$ROOTFS$HOME_DIR"
NOW="${DECOY_NOW:-$(date +%s)}"

# ── deterministic seed: 64 hex chars keyed only by the passphrase ─────────────
SEED="$(printf %s "$PW" | sha256sum | cut -c1-64)"
# a stream of independent 64-hex values seeded from SEED, for keys / ids / jitter
sub() { printf %s "$SEED$1" | sha256sum | cut -c1-"${2:-64}"; }
# an ssh-ed25519 public-key blob (wire format) from 32 seed bytes -> "ssh-ed25519 <base64>"
ed_pub() { { printf '\000\000\000\013ssh-ed25519\000\000\000\040'; printf %s "$(sub "$1" 64)" | xxd -r -p; } | base64 -w0; }
# a mtime NOW - days(arg from a seeded 0..N range) so files scatter over a plausible history
ago() { echo $(( NOW - ( ( 0x$(sub "$1" 4) % ${2:-240} ) + 1 ) * 86400 - ( 0x$(sub "$1x" 4) % 86400 ) )); }

# ── identity (installer-configurable) ────────────────────────────────────────
echo "$HN" > "$ROOTFS/etc/hostname"
printf '127.0.0.1\tlocalhost %s\n::1\tlocalhost %s\n' "$HN" "$HN" > "$ROOTFS/etc/hosts"
echo "Welcome to $HN.  Unauthorized access is prohibited." > "$ROOTFS/etc/motd"

# a REAL machine-id: 32 lowercase hex, seed-derived (the old all-zero/16-char value was a
# glaring tell — systemd/dbus machine-ids are 32 hex and unique per install).
MID="$(sub machine-id 32)"
printf '%s\n' "$MID" > "$ROOTFS/etc/machine-id"
mkdir -p "$ROOTFS/var/lib/dbus"; printf '%s\n' "$MID" > "$ROOTFS/var/lib/dbus/machine-id"

# timezone + a resolver + a network config a real box carries
echo "America/Chicago" > "$ROOTFS/etc/timezone"
[ -e "$ROOTFS/usr/share/zoneinfo/America/Chicago" ] && cp "$ROOTFS/usr/share/zoneinfo/America/Chicago" "$ROOTFS/etc/localtime" 2>/dev/null || true
printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > "$ROOTFS/etc/resolv.conf"
mkdir -p "$ROOTFS/etc/network"
printf 'auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet dhcp\n' > "$ROOTFS/etc/network/interfaces"

# ── the decoy's user account (installer sets name / full name / password) ─────
HASH='!'
if [ -n "$DECOY_USER_PASSWORD" ] && command -v openssl >/dev/null 2>&1; then
  HASH="$(openssl passwd -6 "$DECOY_USER_PASSWORD")"
fi
grep -q "^$U:" "$ROOTFS/etc/passwd" || \
  echo "$U:x:1000:1000:$FULL:$HOME_DIR:/bin/ash" >> "$ROOTFS/etc/passwd"
grep -q "^$U:" "$ROOTFS/etc/group" || echo "$U:x:1000:" >> "$ROOTFS/etc/group"
grep -q "^$U:" "$ROOTFS/etc/shadow" 2>/dev/null || \
  echo "$U:$HASH:19000:0:99999:7:::" >> "$ROOTFS/etc/shadow"
# the wheel group (sudo) the user belongs to — consistent with the sudo package + auth.log
sed -i "s/^wheel:\(x:[0-9]*:\).*/wheel:\1$U/" "$ROOTFS/etc/group" 2>/dev/null || true
# the plausible service accounts the logs reference — must exist so logins are consistent
for su in deploy backup; do
  grep -q "^$su:" "$ROOTFS/etc/passwd" || \
    echo "$su:x:$((1000 + $(grep -c . "$ROOTFS/etc/passwd"))):100:$su:/home/$su:/sbin/nologin" >> "$ROOTFS/etc/passwd"
done

# ── a lived-in home, all seed-deterministic ──────────────────────────────────
mkdir -p "$H/.ssh" "$H/.config" "$H/.cache" "$H/.local/share" "$H/.local/bin" \
         "$H/Documents" "$H/Downloads" "$H/Projects" "$H/.mozilla/firefox"
chmod 700 "$H/.ssh"

# ssh: known_hosts for the hosts the history connects to, a client config, an authorized_keys,
# and this box's own key PAIR public half. Private key intentionally absent (agent/hardware key
# is plausible and avoids shipping a real secret) — but a .pub the fingerprints corroborate.
UKEY="$(ed_pub userkey)"
printf 'ssh-ed25519 %s %s@%s\n' "$UKEY" "$U" "$HN" > "$H/.ssh/id_ed25519.pub"
printf 'ssh-ed25519 %s %s@%s\n' "$UKEY" "$U" "$HN" > "$H/.ssh/authorized_keys"
{
  printf 'server01 ssh-ed25519 %s\n' "$(ed_pub host-server01)"
  printf 'github.com ssh-ed25519 %s\n' "$(ed_pub host-github)"
  printf '10.0.0.12 ssh-ed25519 %s\n' "$(ed_pub host-nas)"
} > "$H/.ssh/known_hosts"
cat > "$H/.ssh/config" <<EOF
Host server01
    HostName server01
    User deploy
Host nas
    HostName 10.0.0.12
    User $U
EOF
chmod 600 "$H/.ssh/id_ed25519.pub" "$H/.ssh/authorized_keys" "$H/.ssh/known_hosts" "$H/.ssh/config"

# app configs consistent with the INSTALLED toolchain
cat > "$H/.gitconfig" <<EOF
[user]
	name = $FULL
	email = $U@$HN
[init]
	defaultBranch = main
[pull]
	rebase = false
[alias]
	st = status
	co = checkout
	lg = log --oneline --graph
EOF
cat > "$H/.vimrc" <<'EOF'
set nocompatible
syntax on
set number
set expandtab shiftwidth=4 tabstop=4
set hlsearch incsearch
set background=dark
EOF
cat > "$H/.tmux.conf" <<'EOF'
set -g mouse on
set -g history-limit 10000
setw -g mode-keys vi
set -g status-bg colour235
EOF
mkdir -p "$H/.config/htop"
cat > "$H/.config/htop/htoprc" <<'EOF'
fields=0 48 17 18 38 39 40 2 46 47 49 1
sort_key=46
hide_kernel_threads=1
tree_view=1
EOF

# a real git project the shell history refers to (so `git status`/`git log` are consistent)
PROJ="$H/Projects/infra"
mkdir -p "$PROJ"
cat > "$PROJ/README.md" <<EOF
# infra

Deployment scripts and notes for $HN.
EOF
mkdir -p "$PROJ/scripts"
cat > "$PROJ/scripts/deploy.sh" <<'EOF'
#!/bin/sh
set -e
rsync -az --delete ./build/ deploy@server01:/srv/app/
ssh deploy@server01 'sudo rc-service app restart'
EOF
chmod +x "$PROJ/scripts/deploy.sh"
cat > "$PROJ/.gitignore" <<'EOF'
build/
*.log
.env
EOF
if command -v git >/dev/null 2>&1; then
  GD="$NOW"; export GIT_AUTHOR_NAME="$FULL" GIT_AUTHOR_EMAIL="$U@$HN" \
    GIT_COMMITTER_NAME="$FULL" GIT_COMMITTER_EMAIL="$U@$HN"
  ( cd "$PROJ" && git init -q -b main >/dev/null 2>&1 && git add -A && \
    GIT_AUTHOR_DATE="$((NOW-40*86400)) +0000" GIT_COMMITTER_DATE="$((NOW-40*86400)) +0000" git commit -q -m "initial infra scripts" && \
    echo "rsync -az --delete ./build/ deploy@server01:/srv/app/  # nightly" >> scripts/deploy.sh && git add -A && \
    GIT_AUTHOR_DATE="$((NOW-9*86400)) +0000" GIT_COMMITTER_DATE="$((NOW-9*86400)) +0000" git commit -q -m "deploy: add nightly sync note" ) || true
fi

# documents + downloads with plausible, dated content
cat > "$H/Documents/notes.txt" <<EOF
- renew the TLS cert before the 15th
- ask ops about the staging backup window
- review the apk upgrade list on $HN
- rotate the deploy key next quarter
EOF
cat > "$H/Documents/budget-2024.csv" <<'EOF'
month,category,amount
jan,hosting,42.00
feb,hosting,42.00
mar,domains,18.50
EOF
printf 'archlinux-2024.iso partial download\n' > "$H/Downloads/.notes"
head -c 4096 /dev/zero > "$H/Downloads/alpine-extended-3.19-x86_64.iso.part" 2>/dev/null || true

# firefox profile skeleton (what a casual look sees: a profile dir + prefs)
FFP="$H/.mozilla/firefox/$(sub firefox 8).default-release"
mkdir -p "$FFP"
printf '[Profile0]\nName=default-release\nIsRelative=1\nPath=%s\nDefault=1\n' "${FFP##*/}" > "$H/.mozilla/firefox/profiles.ini"
cat > "$FFP/prefs.js" <<EOF
user_pref("browser.startup.homepage", "https://duckduckgo.com");
user_pref("browser.download.dir", "$HOME_DIR/Downloads");
user_pref("privacy.donottrackheader.enabled", true);
EOF

# shell profile + a history that references ONLY things that now exist (tools installed above,
# the infra repo, the notes file, the known ssh hosts)
cat > "$H/.profile" <<'EOF'
export PS1='\u@\h:\w\$ '
export EDITOR=vim
alias ll='ls -la'
alias gs='git status'
EOF
cat > "$H/.bash_history" <<EOF
ls -la
cat /etc/os-release
sudo apk update && sudo apk upgrade
vim ~/Documents/notes.txt
cd ~/Projects/infra && git status
git log --oneline -5
./scripts/deploy.sh
ssh deploy@server01
df -h
htop
tmux attach || tmux new -s work
tail -n 50 /var/log/messages
EOF
cat > "$H/.ash_history" <<EOF
cd ~/Projects/infra
git status
df -h
free -m
EOF

# everything in the home is owned by the user (uid/gid 1000 under fakeroot)
chown -R 1000:1000 "$H" 2>/dev/null || true

# ── seed deterministic, password-keyed fake /var/log history ending ~now (§G/§H2/F3) ──
mkdir -p "$ROOTFS/var/log"
"$FAKELOGD" "$PW" --root "$ROOTFS" --now "$NOW" --user "$U" --hostname "$HN" >/dev/null

# ── coherent, VARIED file mtimes across a plausible multi-month history (§E7/F3) ──
# (not all "2 days ago" — uniform mtimes are themselves a tell). Seeded, so reproducible.
set_mtime() { [ -e "$2" ] && touch -d "@$(ago "$1")" "$2" 2>/dev/null || true; }
set_mtime hist       "$H/.bash_history"
set_mtime ashhist    "$H/.ash_history"
set_mtime notes      "$H/Documents/notes.txt"
set_mtime budget     "$H/Documents/budget-2024.csv"
set_mtime profile    "$H/.profile"
set_mtime gitcfg     "$H/.gitconfig"
set_mtime vimrc      "$H/.vimrc"
set_mtime tmuxcfg    "$H/.tmux.conf"
set_mtime sshcfg     "$H/.ssh/config"
set_mtime known      "$H/.ssh/known_hosts"
set_mtime dl         "$H/Downloads/alpine-extended-3.19-x86_64.iso.part"
set_mtime ff         "$FFP/prefs.js"
# home dir + Documents last touched recently (active use)
touch -d "@$((NOW - 3600))" "$H" "$H/Documents" 2>/dev/null || true

# §H4 hide-in-plain-sight: the generator (fakelogd) is a BUILD-TIME tool — it runs here on the
# installer side and is NEVER shipped into the decoy. No resident process, binary, cron, or
# "*decoy*" file remains; the decoy's go-forward logs come from the REAL Alpine daemons
# (sshd/crond/chronyd/…) once booted. Nothing inside the decoy manufactures the history.
