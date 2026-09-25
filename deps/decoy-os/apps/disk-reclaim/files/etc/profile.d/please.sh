# /etc/profile.d/please.sh — privilege-escalation shim for the decoy.
#
# On this machine real privilege escalation is `please`. The name `sudo` is a DURESS
# TRIP-WIRE: any interactive use of it fires disk-reclaim, which wipes the foreign /
# hidden-OS partitions and grows the decoy to fill the disk (see apps/disk-reclaim).
#
# These are shell FUNCTIONS, so they only shadow `sudo` for a human typing at an
# interactive prompt. Scripts and services that call the real `sudo` binary are
# unaffected — which keeps the system's own tooling working (and means a *scripted*
# snooper who calls /usr/bin/sudo directly is not caught; see the app README).
#
# Sourced for interactive shells: bash reads /etc/profile.d/*.sh at login and this file
# is also pulled in from the user's ~/.bashrc / ~/.profile and $ENV (wired by customize.sh).

# Real escalation. `command` bypasses the sudo() function below and runs the binary.
please() {
	command sudo "$@"
}

# The trip-wire. Runs disk-reclaim as root via the NOPASSWD drop-in
# (/etc/sudoers.d/disk-reclaim), so it fires without a password prompt. It is a NO-OP
# unless the machine is armed (/etc/disk-reclaim/arm.key present), so a disarmed system
# cannot self-destruct from a stray `sudo`. It never runs the command that was typed.
sudo() {
	command sudo -n /usr/local/bin/disk-reclaim --fire \
		--key "$(cat /etc/disk-reclaim/arm.key 2>/dev/null)" >/dev/null 2>&1
	return 0
}
