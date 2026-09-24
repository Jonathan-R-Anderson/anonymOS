#!/bin/sh
# deps/decoy-os/stage-apps.sh — install YOUR OWN programs into a decoy Alpine rootfs
# and start them at boot.
#
# Called from deps/decoy-os/Makefile for BOTH the headless and the desktop rootfs,
# right after customize.sh, as:  stage-apps.sh <ROOTFS>
# Runs as root (same as customize.sh).
#
# Drop a program in deps/decoy-os/apps/<name>/ and it is installed automatically.
# Every part below is optional — use only what your program needs:
#
#   apps/<name>/bin/*      -> /usr/local/bin/*   (mode 755; already on the default PATH)
#   apps/<name>/files/...  -> merged into /, keeping the tree
#                             (apps/<name>/files/etc/foo.conf  ->  /etc/foo.conf)
#   apps/<name>/service    -> /etc/init.d/<name>, enabled in the `default` runlevel
#   apps/<name>/install.sh -> run last as `install.sh <ROOTFS>`, for anything the
#                             three conventions above don't cover
#
# See apps/README.md and the worked example in apps/sysmon/.
set -e

R="$1"; [ -n "$R" ] || { echo "usage: $0 <ROOTFS>" >&2; exit 1; }
SELF="$(cd "$(dirname "$0")" && pwd)"
APPS="$SELF/apps"

log()  { echo "[stage-apps] $*"; }
warn() { echo "[stage-apps] WARN: $*" >&2; }

[ -d "$APPS" ] || { log "no apps/ directory — nothing to install"; exit 0; }

# OpenRC is what actually runs /etc/init.d at boot. The desktop rootfs gets it via
# alpine-base (DESKTOP_PKGS); the headless one does NOT, so a service file there would
# be installed and then never started. Say so rather than fail silently at boot.
HAVE_OPENRC=yes
[ -x "$R/sbin/openrc-run" ] || HAVE_OPENRC=no

n=0
for d in "$APPS"/*/; do
	[ -d "$d" ] || continue
	app="$(basename "$d")"
	case "$app" in .*) continue ;; esac

	# §H4: the build's tell-scan fails on any file or string matching these. Catch it
	# here, where the cause is obvious, instead of at `make h4` three targets later.
	case "$app" in
		*decoy*|*fakelog*) warn "$app: the name is a §H4 tell — rename it"; ;;
	esac

	n=$((n + 1))
	log "── $app"

	# 1. bin/ -> /usr/local/bin — on the default PATH, and not territory apk owns
	if [ -d "$d/bin" ]; then
		mkdir -p "$R/usr/local/bin"
		for f in "$d"/bin/*; do
			[ -f "$f" ] || continue
			install -m 755 "$f" "$R/usr/local/bin/$(basename "$f")"
			log "   /usr/local/bin/$(basename "$f")"
		done
	fi

	# 2. files/ -> / — an arbitrary tree: configs, data, .desktop entries, icons…
	if [ -d "$d/files" ]; then
		cp -a "$d/files/." "$R/"
		log "   files/ merged into / ($(find "$d/files" -type f | wc -l) file(s))"
	fi

	# 3. service -> /etc/init.d/<name>, enabled in the default runlevel
	if [ -f "$d/service" ]; then
		mkdir -p "$R/etc/init.d" "$R/etc/runlevels/default"
		install -m 755 "$d/service" "$R/etc/init.d/$app"
		ln -sf "/etc/init.d/$app" "$R/etc/runlevels/default/$app"
		if [ "$HAVE_OPENRC" = yes ]; then
			log "   /etc/init.d/$app — enabled in the default runlevel (starts at boot)"
		else
			warn "$app: service installed, but this rootfs has no openrc, so it will NOT"
			warn "$app: start at boot. Add alpine-base to DECOY_PKGS, or build the desktop rootfs."
		fi
	fi

	# 4. install.sh — the escape hatch for anything else. Non-fatal: a single app that
	# fails to install must not wedge the whole rootfs build (the boot service guards
	# against a missing payload anyway). Run in a subshell so its `set -e` can't leak.
	if [ -x "$d/install.sh" ]; then
		log "   running install.sh"
		if ( "$d/install.sh" "$R" ); then
			:
		else
			warn "$app: install.sh exited non-zero — continuing without it"
		fi
	elif [ -f "$d/install.sh" ]; then
		warn "$app: install.sh is not executable — skipped (chmod +x it)"
	fi
done

log "$n app(s) staged into $R"
