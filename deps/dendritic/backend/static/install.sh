#!/bin/sh
# syndichan-node installer.
#
#     curl -fsSL https://syndichan.org/install.sh | sh
#
# Downloads a prebuilt binary, verifies its published SHA-256, makes sure an I2P
# router with a SAM bridge is running, and installs a systemd service that comes
# back after a reboot. Linux only.
#
# WHY THIS IS SHORT: the installer it replaces BUILT the node, so it also had to
# download a Go toolchain, checksum it, map architectures for go.dev, work
# around GOTOOLCHAIN, find the repository and run `go build` -- about 1500 lines
# whose only purpose was to produce a file the site can simply hand over.
# Fetching that file deletes all of it, leaving the part that was always the
# actual work: the I2P bridge, an unprivileged account, and a unit that does not
# race the router.
#
# STRICTLY POSIX sh, because Alpine ships busybox ash and no bash: no arrays, no
# [[ ]], no `local`, no /dev/tcp, no $'...'. Checked with sh/dash/busybox ash -n.
# The SAM handshake is what used to force bash (for /dev/tcp); here it lives in
# ONE place, the wait-for-sam helper below, run with a budget of 0 to probe and
# by systemd with a real budget to wait. Two copies of it is how one of them
# ends up checking the console port instead.
#
# --check changes nothing. It does GET the published checksum, so it can say
# whether the binary you already have is the current one.

set -eu

# ---------------------------------------------------------------------------
# Where things come from and go
# ---------------------------------------------------------------------------

# Overridable so a mirror or a staging site can be tested. HTTPS is assumed
# everywhere below; see fetch().
BASE_URL="${SYNDICHAN_BASE_URL:-https://syndichan.org}"

NODE_USER="syndichan"
NODE_GROUP="syndichan"
DATA_DIR="/var/lib/syndichan"
CONFIG_FILE="$DATA_DIR/config.json"
BIN_DEST="/usr/local/bin/syndichan-node"
WAIT_HELPER="/usr/local/lib/syndichan/wait-for-sam"
UNIT_PATH="/etc/systemd/system/syndichan-node.service"

# Not tunable. Java I2P delays its SAM client app by 120s and a cold router
# still has tunnels to build after that, so a shorter budget mostly measures how
# fast this gives up on a router that was going to work.
SAM_WAIT=300

MARKER="# managed-by: syndichan install.sh"
ONELINER="curl -fsSL $BASE_URL/install.sh | sh -s --"

DRY_RUN=0
ASSUME_YES=0
PAYOUT=""
CAPACITY_GIB=""
UI_LISTEN=""
ROLES=""

usage() {
  cat <<EOF
syndichan-node installer (Linux)

    curl -fsSL $BASE_URL/install.sh | sh                 # install
    curl -fsSL $BASE_URL/install.sh | sh -s -- --check   # report only

  --check, --dry-run   Print the plan and exit. Changes nothing.
  --yes, -y            Do not ask for consent. Required where there is no
                       terminal to ask on (CI, a docker build).
  --payout 0x...       Payout address. Without one the node earns nothing.
  --capacity-gib N     Disk to donate, whole GiB (node default: 20).
  --ui-listen ADDR     Dashboard address, or "off".
  --role a,b           Roles the node should run. This installer sets up
                       "storage"; any other role is reported as still-yours-to-do
                       rather than quietly skipped. Accepted so the command the
                       /network page builds from its diagram runs as printed.
  -h, --help           This text.

To build from source instead, to install the compute/DCS role, or to install on
a machine running OpenRC rather than systemd, use scripts/install.sh in the
storage-client repository: it does all three and compiles the binary here.

Exit: 0 ok; 1 something required is missing or the install failed; 2 usage.
EOF
}

# A flag whose argument was eaten by the next flag is a silent misconfiguration:
# `--payout --yes` must not save "--yes" as somebody's wallet address.
need_value() {
  case "${2:-}" in ""|-*) echo "install.sh: $1 needs a value" >&2; exit 2 ;; esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check|--dry-run) DRY_RUN=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --payout) need_value "$1" "${2:-}"; PAYOUT="$2"; shift ;;
    --capacity-gib) need_value "$1" "${2:-}"; CAPACITY_GIB="$2"; shift ;;
    --ui-listen) need_value "$1" "${2:-}"; UI_LISTEN="$2"; shift ;;
    --role) need_value "$1" "${2:-}"; ROLES="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "install.sh: unknown option: $1" >&2; echo "Try --help." >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '%s\n' "$*"; }
step() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
run()  { printf '    + %s\n' "$*"; "$@"; }

# One string field out of the node's config.json, without a JSON parser. Every
# value read this way (data_dir, ui_listen, ui_password, payout_address) is
# written by the node itself and cannot contain a quote or a newline.
config_field() { # config_field KEY -- empty when absent or unreadable
  [ -r "$CONFIG_FILE" ] || return 0
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$CONFIG_FILE" | head -n 1
}

WORK=""
cleanup() { [ -n "$WORK" ] && rm -rf -- "$WORK"; return 0; }
trap cleanup EXIT
WORK="$(mktemp -d "${TMPDIR:-/tmp}/syndichan-install.XXXXXX")"

# Every "install"/"fix" row is set in DETECT and consumed by exactly one thing
# in ACT. That parity is the only reason --check is worth reading: a plan that
# under-promises is a lie in a shape nobody thinks to check.
PLAN=""
BLOCKED=0
plan() { # plan STATUS WHAT DETAIL
  PLAN="$PLAN$(printf '  %-8s %-20s %s' "$1" "$2" "$3")
"
}
blocker() { BLOCKED=1; plan cannot "$1" "$2"; }

PKGS=""
DO_CONFIGURE_I2PD=0
DO_START_ROUTER=0
DO_CREATE_USER=0
DO_INSTALL_BINARY=0
INSTALL_SERVICE=0
ROUTER_UNIT=""
I2PD_CONF="/etc/i2pd/i2pd.conf"

# ---------------------------------------------------------------------------
# DETECT -- nothing here writes outside $WORK.
# ---------------------------------------------------------------------------

[ "$(uname -s)" = "Linux" ] ||
  die "this installer supports Linux only (found $(uname -s)). See $BASE_URL/network for other platforms."

# An unknown machine STOPS. Guessing amd64 on something else installs a file
# that will not exec, which is a baffling failure on a machine nobody can see.
MACHINE="$(uname -m)"
case "$MACHINE" in
  x86_64|amd64)         ARCH="amd64" ;;
  aarch64|arm64)        ARCH="arm64" ;;
  armv6l|armv7l|armv8l) ARCH="arm" ;;   # GOARM=6, so it runs on all three
  *) die "no published binary for '$MACHINE'. Build from source: $BASE_URL/network" ;;
esac
BINARY="syndichan-node-linux-$ARCH"
BIN_URL="$BASE_URL/dl/$BINARY"
SUM_URL="$BASE_URL/dl/$BINARY.sha256"

IS_ROOT=0
[ "$(id -u)" = "0" ] && IS_ROOT=1

if have curl; then DOWNLOADER="curl"
elif have wget; then DOWNLOADER="wget"
else DOWNLOADER=""; fi

if have sha256sum; then HASHER="sha256sum"
elif have openssl; then HASHER="openssl"
else HASHER=""; fi

PKG_MGR=""
for m in apk apt-get dnf pacman zypper yum; do
  if have "$m"; then PKG_MGR="$m"; break; fi
done

plan ok "platform" "Linux/$MACHINE -> $BINARY; package manager: ${PKG_MGR:-none}"
[ -n "$DOWNLOADER" ] || blocker "download tool" "neither curl nor wget is here; install one and re-run"
[ -n "$HASHER" ] || blocker "sha256" "neither sha256sum nor openssl is here, so a download could not be verified"

# --- the binary -------------------------------------------------------------

# HTTPS, certificates always verified, https-only across redirects too. If you
# are ever tempted to add -k or --no-check-certificate: this fetches a file that
# is about to be installed as a system service.
CURL_PROTO=""
case "$BASE_URL" in https://*) CURL_PROTO="--proto =https --proto-redir =https" ;; esac
fetch() { # fetch URL OUTFILE
  if [ "$DOWNLOADER" = "curl" ]; then
    # shellcheck disable=SC2086  # CURL_PROTO is a fixed flag pair, never input
    curl -fsSL $CURL_PROTO --tlsv1.2 --max-time 900 --retry 2 -o "$2" "$1"
  else
    wget -q -O "$2" "$1"
  fi
}

sha256_of() { # sha256_of FILE -> hex
  if [ "$HASHER" = "sha256sum" ]; then
    sha256sum "$1" | cut -d' ' -f1
  else
    openssl dgst -sha256 "$1" | sed 's/.*[= ]//'
  fi
}

WANT_SHA=""
if [ "$BLOCKED" = "0" ] && fetch "$SUM_URL" "$WORK/sum" 2>/dev/null; then
  # `<hex>  <name>`, sha256sum's own format, so `sha256sum -c` works on it too.
  WANT_SHA="$(head -n 1 <"$WORK/sum" | cut -d' ' -f1)"
fi
# 64 lowercase hex and nothing else: an error page, a captive portal or a
# truncated response must never become "the expected hash".
if [ "${#WANT_SHA}" != "64" ] || [ -n "$(printf '%s' "$WANT_SHA" | tr -d '0-9a-f')" ]; then
  WANT_SHA=""
fi

if [ -z "$WANT_SHA" ]; then
  [ "$BLOCKED" = "1" ] ||
    blocker "node binary" "$SUM_URL returned no usable checksum: nothing published for linux/$ARCH, or no network. If TLS failed, install ca-certificates."
elif [ -x "$BIN_DEST" ] && [ "$(sha256_of "$BIN_DEST")" = "$WANT_SHA" ]; then
  plan ok "node binary" "$BIN_DEST is already the published $BINARY"
else
  DO_INSTALL_BINARY=1
  plan install "node binary" "$BIN_URL -> $BIN_DEST, sha256 $(printf %s "$WANT_SHA" | cut -c1-16)..."
fi

# --- the I2P router ---------------------------------------------------------

PROBE="$WORK/wait-for-sam"
cat >"$PROBE" <<'HELPER'
#!/bin/sh
# Wait for the local I2P SAM bridge on 127.0.0.1:7656, then exit 0.
#
#   wait-for-sam 300   wait up to 300 seconds
#   wait-for-sam 0     probe once and exit
#
# Run before syndichan-node starts. The node has NO startup retry: connectSAM
# fails and main.go calls logger.Fatal, so a service that starts before the
# bridge is a service that is simply gone. systemd's After= only orders against
# the ROUTER, which is up long before its bridge -- Java I2P ships SAM with
# clientApp.N.delay=120 while its console answers immediately, so anything that
# checks 7657 (or i2pd's 7070) reports success two minutes early and kills the
# node. This is the same HELLO exchange internal/i2p/sam.go performs, against
# 7656 and nothing else, at literal 127.0.0.1 -- where the resolver prefers ::1,
# "localhost" can reach a console on [::1] and miss the bridge entirely.
#
# Exit: 0 ready, 1 not ready within the budget, 2 no way to open a socket,
# 3 something that is not a SAM bridge owns 7656.

# bash first because /dev/tcp answers instantly; busybox nc otherwise, which is
# what Alpine has and where bash does not exist. Between them, every Linux.
# `nc -w 5` costs up to five seconds per probe because SAM does not close the
# connection after replying -- fine for a loop that sleeps anyway.
sam_once() {
  if command -v bash >/dev/null 2>&1; then
    reply="$(bash -c '
      exec 3<>/dev/tcp/127.0.0.1/7656 || exit 1
      printf "HELLO VERSION MIN=3.1 MAX=3.3\n" >&3 || exit 1
      IFS= read -r -t 10 line <&3 || exit 1
      printf "%s\n" "$line"' 2>/dev/null)" || reply=""
  elif command -v nc >/dev/null 2>&1; then
    reply="$(printf 'HELLO VERSION MIN=3.1 MAX=3.3\n' |
             nc -w 5 127.0.0.1 7656 2>/dev/null | head -n 1)" || reply=""
  else
    echo "wait-for-sam: need bash or nc to speak to the SAM bridge" >&2
    exit 2
  fi
  case "$reply" in
    "") return 1 ;;
    "HELLO REPLY"*RESULT=OK*) return 0 ;;
    *) return 3 ;;
  esac
}

budget="${1:-300}"
waited=0
while :; do
  rc=0
  sam_once || rc=$?
  case "$rc" in
    0) [ "$budget" -gt 0 ] && echo "wait-for-sam: SAM bridge ready after ${waited}s"
       exit 0 ;;
    2) exit 2 ;;
    # Waiting cannot fix a port collision, and continuing to wait hides it.
    3) echo "wait-for-sam: 127.0.0.1:7656 answered, but not with a SAM greeting" >&2
       exit 3 ;;
  esac
  [ "$waited" -ge "$budget" ] && break
  sleep 2
  waited=$((waited + 2))
done
echo "wait-for-sam: the I2P SAM bridge did not answer within ${budget}s" >&2
exit 1
HELPER
chmod 0755 "$PROBE"

SAM_RC=0
"$PROBE" 0 >/dev/null 2>&1 || SAM_RC=$?

# Which router is installed, and what this system calls its unit. The packaging
# unit shipped with the node hardcodes Requires=i2pd.service, which fails the
# node outright ("Unit i2pd.service not found") on a machine running the Java
# router as i2p.service. The unit written below names the one actually found.
ROUTER_KIND="none"
if have i2pd || [ -f "$I2PD_CONF" ]; then ROUTER_KIND="i2pd"
elif have i2prouter || [ -d /var/lib/i2p ]; then ROUTER_KIND="java"; fi
for u in i2pd i2p; do
  for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
    if [ -f "$d/$u.service" ]; then ROUTER_UNIT="$u.service"; break; fi
  done
  if [ -n "$ROUTER_UNIT" ]; then
    [ "$u" = "i2pd" ] && ROUTER_KIND="i2pd"
    [ "$ROUTER_KIND" = "none" ] && ROUTER_KIND="java"
    break
  fi
done

case "$SAM_RC" in
  0)
    # A live bridge answers the question completely. Install no router, edit no
    # router config, restart nothing: only one process can hold 7656, and a
    # second router loses the bind and says so in a log nobody is reading.
    plan ok "I2P router (SAM)" "SAM v3 answered RESULT=OK on 127.0.0.1:7656 ($ROUTER_KIND router)"
    ;;
  2) blocker "I2P router (SAM)" "no bash and no nc here, so the SAM bridge cannot be probed or waited for; install either (busybox nc is enough)" ;;
  3) blocker "I2P router (SAM)" "127.0.0.1:7656 is held by something that does not speak SAM -- free that port first" ;;
  *)
    case "$ROUTER_KIND" in
      i2pd)
        DO_CONFIGURE_I2PD=1; DO_START_ROUTER=1
        [ -n "$ROUTER_UNIT" ] || ROUTER_UNIT="i2pd.service"
        plan fix "I2P router (SAM)" "i2pd is installed but SAM is silent: assert [sam] in $I2PD_CONF (backed up) and restart $ROUTER_UNIT" ;;
      java)
        # Deliberately NOT edited: the Java router rewrites clients.config on
        # shutdown, the SAM entry's index differs between the monolithic file
        # and the clients.config.d fragments, and an entry with no startOnLoad
        # line cannot be fixed with sed at all. An installer that tried would
        # stop a working router, change nothing, restart it, and then wait five
        # minutes for a bridge that was never going to appear.
        blocker "I2P router (SAM)" "Java I2P found but SAM is silent: turn it on at http://127.0.0.1:7657/configclients -> 'SAM application bridge' -> Start + Run at Startup, then re-run" ;;
      *)
        if [ -n "$PKG_MGR" ]; then
          PKGS="i2pd"; DO_CONFIGURE_I2PD=1; DO_START_ROUTER=1; ROUTER_UNIT="i2pd.service"
          plan install "I2P router (SAM)" "no router found: install i2pd, assert its SAM bridge, enable+start $ROUTER_UNIT"
          case "$PKG_MGR" in
            dnf|yum) plan manual "i2pd repository" "i2pd is not in Fedora/RHEL's official repos; run 'dnf copr enable supervillain/i2pd' first" ;;
            apk)     plan manual "i2pd repository" "i2pd lives in Alpine's COMMUNITY repository; make sure it is enabled in /etc/apk/repositories" ;;
          esac
        else
          blocker "I2P router (SAM)" "no router, and no package manager to install one; install i2pd with SAM on 127.0.0.1:7656 yourself"
        fi ;;
    esac ;;
esac

# --- the service account and its data directory -----------------------------

if id "$NODE_USER" >/dev/null 2>&1; then
  NODE_GROUP="$(id -gn "$NODE_USER" 2>/dev/null || echo "$NODE_USER")"
  plan ok "service account" "$NODE_USER exists (group $NODE_GROUP)"
else
  DO_CREATE_USER=1
  plan install "service account" "create the system user $NODE_USER -- the node never runs as root"
fi

if [ -L "$DATA_DIR" ] || { [ -e "$DATA_DIR" ] && [ ! -d "$DATA_DIR" ]; }; then
  blocker "data directory" "$DATA_DIR exists and is not a plain directory; refusing to touch it"
elif [ -d "$DATA_DIR" ]; then
  DIR_OWNER="$(stat -c '%U' "$DATA_DIR" 2>/dev/null || echo '?')"
  if [ "$DIR_OWNER" = "$NODE_USER" ] || [ -z "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; then
    plan ok "data directory" "$DATA_DIR (owner $DIR_OWNER)"
  else
    blocker "data directory" "$DATA_DIR is not empty and belongs to '$DIR_OWNER', not '$NODE_USER'; refusing to chown it"
  fi
else
  plan install "data directory" "create $DATA_DIR, mode 0700, owned by $NODE_USER"
fi

# ReadWritePaths must name the DATA DIRECTORIES THEMSELVES and never
# <dir>/storage: i2p.destination, p2p.key and content.key are written BESIDE
# storage/, so a unit that sandboxes only the subdirectory fails with a
# "read-only file system" error naming a filesystem that is mounted rw. An
# existing config may point data_dir somewhere else entirely; that path is
# picked up here and again after the node rewrites the file.
rw_paths() {
  RW_PATHS="\"$DATA_DIR\""
  RUNTIME_DIR="$(config_field data_dir)"
  case "$RUNTIME_DIR" in
    /*) [ "$RUNTIME_DIR" = "$DATA_DIR" ] || RW_PATHS="$RW_PATHS \"$RUNTIME_DIR\"" ;;
    *) RUNTIME_DIR="" ;;
  esac
}
rw_paths
[ -z "$RUNTIME_DIR" ] ||
  plan ok "data_dir in config" "$RUNTIME_DIR -- named in the unit's ReadWritePaths too"

# --- the boot service -------------------------------------------------------

# Whether the installed unit is one an installer wrote, or one somebody edited.
# The marker records the hash of the body it was written with: if the file still
# hashes to that, replacing it loses nothing; if it does not, somebody changed
# it -- possibly to fix something -- and overwriting that silently is how an
# installer destroys a working machine. The pattern also matches the marker the
# older build-from-source installer wrote, so a machine upgrading from it is
# recognised rather than treated as a stranger's.
unit_is_ours() {
  [ -f "$UNIT_PATH" ] || return 0
  RECORDED="$(sed -n "s|^$MARKER[^=]*sha256=||p" "$UNIT_PATH" 2>/dev/null | head -n 1)"
  [ -n "$RECORDED" ] || return 1
  grep -v "^$MARKER" "$UNIT_PATH" >"$WORK/unit-installed" 2>/dev/null || return 1
  [ "$RECORDED" = "$(sha256_of "$WORK/unit-installed")" ]
}

if [ -d /run/systemd/system ] && have systemctl; then
  INSTALL_SERVICE=1
  plan install "boot service" "write and enable $UNIT_PATH; starts after ${ROUTER_UNIT:-the router}, once SAM answers (ReadWritePaths=$RW_PATHS)"
  unit_is_ours ||
    plan manual "boot service" "$UNIT_PATH has been edited since an installer wrote it; it will NOT be overwritten"
else
  plan manual "boot service" "no systemd here, so no service is installed; the command to start it by hand is printed at the end"
fi

# The /network page builds `--role a,b` from the diagram somebody clicked on.
# What this installer sets up is the storage role: it is the one that needs an
# I2P router, a service account and a boot service. The others are a run_mode in
# config.json (GATEWAY.md), plus Docker for compute. Reported rather than
# accepted in silence -- a command that installs less than the page promised is
# worse than one that says so out loud.
EXTRA_ROLES=""
for r in $(printf '%s' "$ROLES" | tr ',' ' '); do
  [ "$r" = "storage" ] || EXTRA_ROLES="$EXTRA_ROLES $r"
done
[ -z "$EXTRA_ROLES" ] ||
  plan manual "roles" "the storage role is installed here; not set up:$EXTRA_ROLES -- set run_mode in $CONFIG_FILE afterwards, see GATEWAY.md"

# ---------------------------------------------------------------------------
# REPORT, then ask
# ---------------------------------------------------------------------------

say "syndichan-node installer"
[ "$DRY_RUN" = "1" ] && say "--check: reporting only. Nothing on this machine will be changed."
say ""
printf '  %-8s %-20s %s\n' "STATUS" "WHAT" "DETAIL"
printf '  %-8s %-20s %s\n' "------" "----" "------"
printf '%s\n' "$PLAN"

if [ "$DRY_RUN" = "1" ]; then
  [ "$BLOCKED" = "0" ] ||
    { say "The install would refuse to run: see the 'cannot' row(s) above."; exit 1; }
  say "Everything required is present. Re-run without --check to install."
  exit 0
fi

[ "$BLOCKED" = "1" ] && die "refusing to install: see the 'cannot' row(s) above. Nothing was changed."
[ "$IS_ROOT" = "1" ] ||
  die "this installer must run as root:  $ONELINER
See the plan without any privilege:   $ONELINER --check"

# Consent for the whole plan, once, after it is printed and before anything is
# touched. Read from /dev/tty, NOT stdin: under `curl ... | sh` stdin is this
# script, so a plain `read` swallows the rest of the file. With no terminal at
# all -- CI, a docker build -- there is nobody to ask, and the honest answer is
# to stop rather than to assume yes.
if [ "$ASSUME_YES" != "1" ]; then
  [ -r /dev/tty ] ||
    die "there is no terminal to ask for consent on. Re-run with --yes if that is what you meant:
    $ONELINER --yes"
  printf 'Proceed with the plan above? [y/N] '
  read -r ANSWER </dev/tty || ANSWER=""
  case "$ANSWER" in
    y|Y|yes|YES) ;;
    *) say "Nothing was changed."; exit 0 ;;
  esac
fi

# ---------------------------------------------------------------------------
# ACT
# ---------------------------------------------------------------------------

if [ -n "$PKGS" ]; then
  step "Installing packages: $PKGS"
  case "$PKG_MGR" in
    apt-get) run apt-get update
             run env DEBIAN_FRONTEND=noninteractive apt-get install -y $PKGS ;;
    apk)     run apk add --no-cache $PKGS ;;
    dnf|yum) run "$PKG_MGR" install -y $PKGS ;;
    pacman)  run pacman -S --needed --noconfirm $PKGS ;;
    zypper)  run zypper --non-interactive install $PKGS ;;
  esac
fi

# i2pd has no conf.d for its main config, so SAM goes into i2pd.conf itself.
# This rewrites one key in one section, uncommenting it if the shipped file has
# it commented (it does, for all of [sam]) and appending the section if absent.
# Writing only on real change is what makes a second run a no-op instead of a
# pile of duplicate keys. Returns 0 if changed, 1 if already correct.
i2pd_set() { # i2pd_set SECTION KEY VALUE
  awk -v sect="$1" -v key="$2" -v val="$3" '
    BEGIN { cur = ""; done = 0 }
    /^[[:space:]]*\[/ {
      if (cur == sect && !done) { print key " = " val; done = 1 }
      s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s); cur = s
      print; next
    }
    {
      if (cur == sect && !done && $0 ~ ("^[[:space:]]*#*[[:space:]]*" key "[[:space:]]*=")) {
        print key " = " val; done = 1; next
      }
      print
    }
    END { if (!done) { if (cur != sect) print "[" sect "]"; print key " = " val } }
  ' "$I2PD_CONF" >"$WORK/i2pd.conf"
  cmp -s "$WORK/i2pd.conf" "$I2PD_CONF" && return 1
  # Mode and owner carried over from the file being replaced: `install -m 0644`
  # would quietly widen a config somebody had deliberately locked down. Numeric
  # ids via chown, because busybox's install takes only names for -o/-g.
  install -m "$(stat -c '%a' "$I2PD_CONF")" "$WORK/i2pd.conf" "$I2PD_CONF"
  chown "$(stat -c '%u:%g' "$I2PD_CONF")" "$I2PD_CONF"
  return 0
}

if [ "$DO_CONFIGURE_I2PD" = "1" ]; then
  if [ ! -f "$I2PD_CONF" ]; then
    warn "$I2PD_CONF is not there after installation; enable SAM by hand: [sam] enabled = true, address = 127.0.0.1, port = 7656"
  else
    step "Configuring i2pd: $I2PD_CONF"
    [ -f "$I2PD_CONF.syndichan.bak" ] || run cp -p "$I2PD_CONF" "$I2PD_CONF.syndichan.bak"
    CHANGED=0
    # SAM is on by default in i2pd >= 2.28, so most of these are assertions.
    # Assert anyway: the failure mode is somebody having uncommented
    # `enabled = false`, invisible from outside until the node dies at startup.
    i2pd_set sam enabled true && CHANGED=1
    i2pd_set sam address 127.0.0.1 && CHANGED=1
    i2pd_set sam port 7656 && CHANGED=1
    # Same daemon, separate switch. SAM on and httpproxy off passes every 7656
    # check and still leaves the node half-blind: the bootstrap document and
    # every .i2p fetch go through 4444.
    i2pd_set httpproxy enabled true && CHANGED=1
    i2pd_set httpproxy address 127.0.0.1 && CHANGED=1
    i2pd_set httpproxy port 4444 && CHANGED=1
    [ "$CHANGED" = "0" ] && note "already configured; nothing changed"
  fi
fi

if [ "$DO_START_ROUTER" = "1" ]; then
  if [ "$INSTALL_SERVICE" = "1" ]; then
    # Enabled, not just started: without this the node reboots into nothing --
    # SAM refused, logger.Fatal, and a unit that looks broken when the router is
    # what never came back.
    step "Enabling and starting $ROUTER_UNIT"
    run systemctl enable "$ROUTER_UNIT" || warn "could not enable $ROUTER_UNIT"
    run systemctl restart "$ROUTER_UNIT" || warn "could not start $ROUTER_UNIT"
  else
    warn "no systemd here; start your I2P router yourself (i2pd --daemon)"
  fi
fi

if [ "$DO_INSTALL_BINARY" = "1" ]; then
  step "Downloading $BIN_URL"
  fetch "$BIN_URL" "$WORK/node" || die "could not download $BIN_URL"
  GOT_SHA="$(sha256_of "$WORK/node")"
  if [ "$GOT_SHA" != "$WANT_SHA" ]; then
    # Loud, and nothing is installed. A root-run script that fetched an
    # executable and got bytes nobody published has no safe way to continue.
    die "CHECKSUM MISMATCH -- what was downloaded is NOT what $SUM_URL says it should be.
    expected $WANT_SHA
    got      $GOT_SHA
Nothing was installed. Do not run that file. Please report this at $BASE_URL."
  fi
  note "sha256 verified: $GOT_SHA"
  # Replacing a running binary in place gives ETXTBSY; the restart at the end
  # brings it back.
  if [ "$INSTALL_SERVICE" = "1" ] && systemctl is-active --quiet syndichan-node.service 2>/dev/null; then
    run systemctl stop syndichan-node.service || true
  fi
  step "Installing $BIN_DEST"
  run install -d -m 0755 /usr/local/bin
  run install -m 0755 "$WORK/node" "$BIN_DEST"
fi

if [ "$DO_CREATE_USER" = "1" ]; then
  step "Creating the system user $NODE_USER"
  NOLOGIN="/usr/sbin/nologin"
  [ -x "$NOLOGIN" ] || NOLOGIN="/sbin/nologin"
  [ -x "$NOLOGIN" ] || NOLOGIN="/bin/false"
  if have useradd; then
    run useradd --system --home-dir "$DATA_DIR" --shell "$NOLOGIN" "$NODE_USER"
  elif adduser --help 2>&1 | grep -q -- '--system'; then
    run adduser --system --home "$DATA_DIR" --no-create-home --disabled-password --shell "$NOLOGIN" "$NODE_USER"
  elif have adduser; then
    # busybox adduser (Alpine): different flags, and the long ones are silently
    # misparsed rather than rejected. -S system, -H no home, -D no password.
    run adduser -S -H -D -h "$DATA_DIR" -s "$NOLOGIN" "$NODE_USER"
  else
    die "no useradd/adduser here; create the $NODE_USER system account yourself and re-run"
  fi
  NODE_GROUP="$(id -gn "$NODE_USER" 2>/dev/null || echo "$NODE_USER")"
fi

step "Preparing $DATA_DIR"
# The LEAF only, never chown -R: even a mistake past every guard above then
# touches exactly one inode. `install -d` then `chown` rather than `install -o`,
# because busybox's install rejects numeric ids for -o/-g.
run install -d -m 0700 "$DATA_DIR"
run chown "$NODE_USER:$NODE_GROUP" "$DATA_DIR"

# Never as root. runuser first (util-linux, present wherever systemd is, and
# needing no sudoers policy), then su -- Alpine has only the latter. HOME is
# always set because config.Default() calls os.UserConfigDir() unconditionally,
# even when -config names an exact path, so a system account with no HOME makes
# the node exit before it reads the file it was pointed at.
as_node() {
  if have runuser; then
    run runuser -u "$NODE_USER" -- env HOME="$DATA_DIR" "$@"
  else
    CMD=""
    for a in "$@"; do CMD="$CMD '$a'"; done
    run su -s /bin/sh -c "env HOME='$DATA_DIR'$CMD" "$NODE_USER"
  fi
}

# Minted BY THE NODE, AS THE SERVICE USER: LoadOrCreate writes config.json mode
# 0600 owned by whoever runs it, points data_dir at the config file's directory,
# and generates both the storage credentials and the dashboard password. A
# root-generated config is a file the service cannot read.
step "Creating $CONFIG_FILE as $NODE_USER"
SET_ARGS=""
[ -n "$PAYOUT" ] && SET_ARGS="$SET_ARGS -payout $PAYOUT"
[ -n "$CAPACITY_GIB" ] && SET_ARGS="$SET_ARGS -capacity-gib $CAPACITY_GIB"
[ -n "$UI_LISTEN" ] && SET_ARGS="$SET_ARGS -ui-listen $UI_LISTEN"
# shellcheck disable=SC2086  # SET_ARGS must split into words
as_node "$BIN_DEST" -config "$CONFIG_FILE" $SET_ARGS -show-config >/dev/null ||
  warn "the node refused that configuration; run it by hand to see why:
    runuser -u $NODE_USER -- env HOME='$DATA_DIR' $BIN_DEST -config '$CONFIG_FILE' -show-config"

step "Installing $WAIT_HELPER"
run install -d -m 0755 "$(dirname "$WAIT_HELPER")"
run install -m 0755 "$PROBE" "$WAIT_HELPER"

# Re-read now that the node has written the file, and make sure every path the
# unit is about to sandbox exists: a ReadWritePaths= entry that does not makes
# systemd refuse to start the unit at all.
rw_paths
if [ -n "$RUNTIME_DIR" ] && [ ! -d "$RUNTIME_DIR" ]; then
  run install -d -m 0700 "$RUNTIME_DIR"
  run chown "$NODE_USER:$NODE_GROUP" "$RUNTIME_DIR"
fi

if [ "$INSTALL_SERVICE" = "1" ]; then
  ORDER="network-online.target"
  [ -n "$ROUTER_UNIT" ] && ORDER="$ORDER $ROUTER_UNIT"
  cat >"$WORK/unit-body" <<EOF
[Unit]
Description=Syndichan encrypted volunteer storage node
Documentation=$BASE_URL/network
# Wants=, not Requires=: Requires=i2pd.service fails the node outright where the
# router is i2p.service, and takes the node down with the router on every
# restart. Ordering plus the readiness wait below does the same job without the
# shared fate.
Wants=$ORDER
After=$ORDER
StartLimitIntervalSec=600
StartLimitBurst=20

[Service]
Type=simple
User=$NODE_USER
Group=$NODE_GROUP
# config.Default() calls os.UserConfigDir() unconditionally, so a missing HOME
# makes the node exit before it reads the -config file it was handed.
Environment="HOME=$DATA_DIR"
# The node has no startup retry. This is what stops systemd racing the router.
ExecStartPre=$WAIT_HELPER $SAM_WAIT
ExecStart=$BIN_DEST -config "$CONFIG_FILE"
Restart=on-failure
RestartSec=15s
# Longer than systemd's 90s default: the wait above legitimately takes ~120s on
# a Java router, and a start job killed mid-wait fails a unit that was fine.
TimeoutStartSec=$((SAM_WAIT + 120))
TimeoutStopSec=75s
LimitNOFILE=65535

# Low-port binding only, and only for the gateway role. The process is not root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
# ProtectSystem=strict makes the WHOLE filesystem read-only to this service,
# mount options be damned, so this list is the only thing that lets the node
# write at all. It names the DATA DIRECTORIES THEMSELVES, never <dir>/storage:
# i2p.destination, p2p.key and content.key are written BESIDE storage/, and a
# unit that lists only the subdirectory fails on the second file, not the first.
ReadWritePaths=$RW_PATHS

[Install]
WantedBy=multi-user.target
EOF
  { printf '%s sha256=%s -- change this with `systemctl edit syndichan-node`\n' \
      "$MARKER" "$(sha256_of "$WORK/unit-body")"
    cat "$WORK/unit-body"; } >"$WORK/unit"

  # The service is enabled and restarted either way below: "your unit, not
  # mine" is not a reason to leave the node dead after a reboot.
  if ! unit_is_ours; then
    cp "$WORK/unit" /run/syndichan-node.service.proposed
    warn "$UNIT_PATH has been edited since an installer wrote it; NOT overwriting it."
    note "what this would have written is at /run/syndichan-node.service.proposed"
    note "compare with: diff -u '$UNIT_PATH' /run/syndichan-node.service.proposed"
  elif [ -f "$UNIT_PATH" ] && cmp -s "$WORK/unit" "$UNIT_PATH"; then
    note "$UNIT_PATH is already current"
  else
    step "Writing $UNIT_PATH"
    run install -m 0644 "$WORK/unit" "$UNIT_PATH"
  fi
  run systemctl daemon-reload

  step "Waiting for the I2P SAM bridge (up to ${SAM_WAIT}s -- normal for a cold router)"
  "$WAIT_HELPER" "$SAM_WAIT" ||
    warn "SAM has not answered yet. The service has the same wait built in and will start on its own once the router is ready."

  step "Enabling syndichan-node on boot"
  run systemctl enable syndichan-node.service
  run systemctl restart syndichan-node.service ||
    warn "the service did not start; see: journalctl -u syndichan-node -n 50"
fi

# ---------------------------------------------------------------------------
# What the operator needs to know now
# ---------------------------------------------------------------------------

# Read back out of the file the node just wrote rather than printed from what
# this script intended: -show-config REDACTS ui_password (it is what people
# paste into support threads), so the config file is the only source for it.
UI_ADDR="$(config_field ui_listen)"
UI_USER="$(config_field ui_username)"
UI_PASS="$(config_field ui_password)"
PAYOUT_SET="$(config_field payout_address)"

say ""
say "Done."
if [ -n "$UI_ADDR" ]; then
  # The node binds 0.0.0.0:9090 by default, on purpose: a node is usually a
  # headless box administered from a laptop. That is why it generates a
  # password, and why this prints it -- there is no other way to learn it.
  case "$UI_ADDR" in
    0.0.0.0:*|:::*|\[::\]:*)
      say "  Dashboard:  http://<this machine's address>:${UI_ADDR##*:}  (every interface)"
      say "              http://127.0.0.1:${UI_ADDR##*:} from the machine itself" ;;
    *) say "  Dashboard:  http://$UI_ADDR" ;;
  esac
  say "  Username:   ${UI_USER:-admin}"
  say "  Password:   ${UI_PASS:-(see $CONFIG_FILE)}"
  note "also in $CONFIG_FILE, mode 0600. It is yours to change."
else
  say "  Dashboard:  disabled. Configure this node by editing $CONFIG_FILE."
fi
if [ "$INSTALL_SERVICE" = "1" ]; then
  say "  systemctl status syndichan-node        # is it up"
  say "  journalctl -u syndichan-node -f        # what is it doing"
else
  say "  No systemd here, so nothing starts at boot. Run it with:"
  say "      su -s /bin/sh -c \"env HOME='$DATA_DIR' $BIN_DEST -config '$CONFIG_FILE'\" $NODE_USER"
fi
if [ -n "$EXTRA_ROLES" ]; then
  say ""
  say "  Still yours to do:$EXTRA_ROLES were asked for and are not set up here."
  say "  Set run_mode in $CONFIG_FILE (see GATEWAY.md) and restart."
fi
if [ -z "$PAYOUT_SET" ]; then
  say ""
  say "  NO PAYOUT ADDRESS IS SET. This node will store and serve, and be paid"
  say "  NOTHING for it. Set payout_address on the dashboard, or:"
  say "      $BIN_DEST -config $CONFIG_FILE -payout 0xYourWallet"
  say "      systemctl restart syndichan-node"
fi
