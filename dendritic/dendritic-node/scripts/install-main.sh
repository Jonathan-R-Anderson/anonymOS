#!/usr/bin/env bash
# Install syndichan-node, its runtime dependencies, and a boot service.
#
# LINUX ONLY -- refused at the top rather than half-supported.
#
# Reached through scripts/install.sh, a POSIX-sh shim that installs bash first
# on systems that have none (Alpine). Run this file directly only if you know
# bash is present.
#
# Two service managers are supported, systemd and OpenRC, because Alpine has no
# systemd and boot-start is the whole point of the default install. Everything
# outside install_unit/start_router/start_docker is manager-agnostic.
#
# BUSYBOX: Alpine's coreutils are busybox applets. That rules out `useradd`,
# `runuser`, `sudo`, GNU-style `adduser` flags, `install -o` with a numeric id,
# and `--` end-of-options on `install`. Each is handled where it appears; none
# of them is assumed.
#
# bash, not sh, for /dev/tcp: the most important check here is a real SAM
# handshake on 127.0.0.1:7656, and bash opens a TCP socket without nc, socat or
# python, none of which are guaranteed on a fresh server.
#
# Shape: DETECT -> REPORT -> ASK -> ACT, never interleaved. Nothing in DETECT
# writes to the machine, which is what makes --check honest: not a second code
# path, just this pass with ACT cut off.
#
# CHECK/ACT PARITY is the property everything rests on. Every "install" row maps
# to one DO_* flag set in DETECT and consumed by one ACT function:
#
#   PKGS[]              -> package rows          -> install_packages
#   DO_CONFIGURE_I2PD   -> I2P router (SAM)      -> configure_i2pd
#   DO_ENABLE_ROUTER    -> I2P router on boot    -> start_router
#   DO_START_ROUTER     -> I2P router (SAM)      -> start_router
#   DO_ENABLE_DOCKER    -> Docker Engine         -> start_docker
#   DO_BOOTSTRAP_GO     -> Go toolchain          -> bootstrap_go
#   DO_BUILD_BINARY     -> syndichan-node binary -> build_binary
#   DO_CREATE_USER      -> service account       -> create_user_and_dirs
#   DO_ADD_DOCKER_GROUP -> docker group          -> add_docker_group,
#                                                    install_compute_dropin
#   INSTALL_SERVICE     -> boot service, SAM readiness helper, data directory
#
# Add an action, add its row. A --check that under-promises is a lie.
#
# The same rule covers VALUES, not just actions: --check prints the data_dir it
# resolved and the exact ReadWritePaths= line the unit will carry. A plan that
# names one directory while the unit sandboxes another is the same lie in a
# shape nobody thinks to check.

# Deliberately NOT `set -o pipefail`. Detection is full of pipelines whose
# reader exits early on purpose (`| grep -q`, `| grep -m1`), sending SIGPIPE to
# the writer, which pipefail then reports as a failed pipeline. Not
# hypothetical: with pipefail on, the /proc/cpuinfo check reported "CPU reports
# no vmx/svm" on a CPU that HAS vmx. -E so the ERR trap reaches functions.
set -eEu

VERSION="2"
PROGRAM="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "$(uname -s)" != "Linux" ]; then
  echo "$PROGRAM: this installer supports Linux only (found $(uname -s))." >&2
  echo "Elsewhere: 'go build ./cmd/syndichan-node' and run it by hand." >&2
  exit 2
fi

# --- abort reporting --------------------------------------------------------
# Guards the failure this script used to have: under `set -e`, a function whose
# last statement is a bare `return` after a failing `&&` returns 1 and kills the
# script with NO output. Every function below ends in an explicit `return 0`,
# but conventions rot; this makes it structural. bash runs the ERR trap under
# exactly the conditions that make `set -e` exit, so it never fires spuriously.
ABORT_LINE=""
trap 'ABORT_LINE="$LINENO"' ERR

WORK=""
workdir() { # private scratch directory, created on first use only
  [ -n "$WORK" ] || WORK="$(mktemp -d "${TMPDIR:-/tmp}/syndichan-install.XXXXXX")"
  printf '%s' "$WORK"
}

on_exit() {
  local rc=$?
  [ -n "$WORK" ] && rm -rf -- "$WORK"
  if [ "$rc" -ne 0 ] && [ -n "$ABORT_LINE" ]; then
    printf 'error: %s aborted unexpectedly at line %s (exit %s).\n' "$PROGRAM" "$ABORT_LINE" "$rc" >&2
    printf 'Nothing further was attempted. Run --check to see the plan.\n' >&2
  fi
  return 0
}
trap on_exit EXIT

# ---------------------------------------------------------------------------
# Options -- deliberately few. Everything the node can configure itself lives
# in its config file; flags here are only for decisions that must be made
# BEFORE the node first runs, or that a headless server cannot make otherwise.
# ---------------------------------------------------------------------------

DRY_RUN=0            # --check / --dry-run
ASSUME_YES=0         # --yes
INSTALL_SERVICE=1    # --no-service
WANT_COMPUTE=0       # --with-compute
BINARY_SRC=""        # --binary PATH
DATA_DIR="/var/lib/syndichan"
PAYOUT=""
CAPACITY_GIB=""
UI_LISTEN=""

NODE_USER="syndichan"
NODE_GROUP="syndichan"
PREFIX="/usr/local"
BIN_DEST="$PREFIX/bin/syndichan-node"
WAIT_HELPER="$PREFIX/lib/syndichan/wait-for-sam"
UNIT_PATH="/etc/systemd/system/syndichan-node.service"
UNIT_DROPIN="/etc/systemd/system/syndichan-node.service.d/10-compute.conf"
OPENRC_PATH="/etc/init.d/syndichan-node"

# Not tunable, on purpose. Java I2P delays its SAM client app by 120s and a cold
# router still has tunnels to build after that, so any budget short enough to be
# worth shortening mostly measures how fast this script gives up on a router
# that was going to work.
SAM_WAIT_SECONDS=300

GO_ROOT_DEST="/usr/local/go"
GO_BIN_LINK="/usr/local/bin/go"
# 1.21 is the first Go that reads the `go` line in go.mod and downloads the
# toolchain it names. go.mod pins 1.25.12, so anything from 1.21 up can build
# this tree and the installer needs no version policy of its own.
GO_MIN_MAJOR=1
GO_MIN_MINOR=21

usage() {
  cat <<'EOF'
syndichan-node installer (Linux)

Start here, and come back here when something breaks:

    ./scripts/install.sh --check

--check runs every detection, prints what is present, missing, installable and
IMPOSSIBLE here, then exits without touching the machine. Same code the
installer itself uses.

To install:

    sudo ./scripts/install.sh                 # asks before changing anything
    sudo ./scripts/install.sh --yes           # same plan, no questions

Options:
  --check, --dry-run   Report only. No packages, no files, no services.
  --yes, -y            Do not prompt for consent.
  --no-service         Do not create/enable the boot service. Boot-start is the
                       DEFAULT; this is the opt-out.
  --with-compute       Also prepare Docker (and the microVM path) for the
                       compute/DCS role. Not needed just to make an EXISTING
                       config work: if config.json already sets dcs.enabled
                       (with dcs.role.worker) or compute.enabled, the installer
                       sees that and fixes the service account's Docker access
                       on its own -- it just will not INSTALL Docker unless you
                       ask here.
  --binary PATH        Use this binary instead of discovering or building one.
  --data-dir PATH      Node data directory (default: /var/lib/syndichan). Must
                       be >=2 components deep, outside system directories, and
                       either new, empty, or already owned by the service user.
  --payout 0x...       Payout address. Without one the node earns nothing, and
                       a headless server has no other way to set it (the
                       management page binds loopback).
  --capacity-gib N     Disk to donate, whole GiB (node default: 20). Checked
                       against real free space, which the node never does.
  --ui-listen ADDR     Management page address, or "off". A port clash here is
                       fatal to the WHOLE node (the listener calls log.Fatal),
                       so this is the escape hatch when 9090 is taken.
  -h, --help           This text.

gateway-only and probe-only nodes are configured by setting run_mode in
config.json (see GATEWAY.md); they need no I2P router and are out of scope here.

Exit: 0 ok; 1 required dependency missing (--check) or install failed; 2 usage.
EOF
}

say()  { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "${C_BLUE:-}${C_BOLD:-}" "${C_RESET:-}" "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '%swarning:%s %s\n' "${C_YELLOW:-}" "${C_RESET:-}" "$*" >&2; }
die()  { ABORT_LINE=""; printf '%serror:%s %s\n' "${C_RED:-}" "${C_RESET:-}" "$*" >&2; exit 1; }
usage_error() { ABORT_LINE=""; echo "$PROGRAM: $*" >&2; exit 2; }

need_value() { # a flag whose argument was eaten by the next flag is a silent
               # misconfiguration, so refuse it
  case "${2:-}" in ""|-*) usage_error "$1 needs a value" ;; esac
  return 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check|--dry-run) DRY_RUN=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --no-service) INSTALL_SERVICE=0 ;;
    --with-compute) WANT_COMPUTE=1 ;;
    --binary) need_value "$1" "${2:-}"; BINARY_SRC="$2"; shift ;;
    --data-dir) need_value "$1" "${2:-}"; DATA_DIR="$2"; shift ;;
    --payout) need_value "$1" "${2:-}"; PAYOUT="$2"; shift ;;
    --capacity-gib) need_value "$1" "${2:-}"; CAPACITY_GIB="$2"; shift ;;
    --ui-listen) need_value "$1" "${2:-}"; UI_LISTEN="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$PROGRAM: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# --- the data directory contract --------------------------------------------
# This is the ONE path the installer takes ownership of (chown to the service
# account, chmod 0700), and it is caller-supplied, so it is validated like an
# attack surface. Four rules, each blocking the worst case on its own:
#   1. absolute, no "..", and only characters a systemd unit can express;
#   2. >=2 components deep, so it can never be a filesystem or mount root;
#   3. not inside a system directory;
#   4. (detect_data_dir) if it exists it must be a real directory that is
#      either EMPTY or ALREADY OWNED by the service account -- the rule that
#      makes "--data-dir /home/alice" impossible rather than discouraged.
# The chown is never recursive, so a mistake past all four touches one inode.
#
# Rules 1-3 are a function rather than a run of `case`s because a SECOND path
# has to pass them: the data_dir read out of a config file that already exists
# (see resolve_runtime_data_dir). One copy of the rules means the config path
# can never be held to a weaker standard than the flag.
data_dir_problem() { # -> the reason this path is unusable, or nothing
  case "$1" in
    /*) ;;
    *) echo "must be an absolute path"; return 0 ;;
  esac
  case "$1" in
    *"/../"*|*"/.."|*"/")
      echo "must be a plain absolute path, no '..', no trailing slash"; return 0 ;;
  esac
  # systemd cannot express these safely: % starts a specifier, and quotes and
  # backslashes break Exec parsing. A SPACE is fine, and is quoted everywhere.
  case "$1" in
    *[!A-Za-z0-9._/+:@" "-]*)
      echo "may contain only letters, digits, spaces and . _ - + : @ /"; return 0 ;;
  esac
  [ "$(dirname "$1")" = "/" ] &&
    { echo "must be at least two components deep (e.g. /srv/syndichan)"; return 0; }
  case "$1" in
    /usr|/usr/*|/etc|/etc/*|/bin|/bin/*|/sbin|/sbin/*|/lib|/lib/*|/lib64|/lib64/*|/boot|/boot/*|/dev|/dev/*|/proc|/proc/*|/sys|/sys/*|/run|/run/*|/root|/root/*)
      echo "is inside a system path"; return 0 ;;
  esac
  return 0
}

DATA_DIR_PROBLEM="$(data_dir_problem "$DATA_DIR")"
[ -n "$DATA_DIR_PROBLEM" ] && usage_error "--data-dir $DATA_DIR_PROBLEM (got: $DATA_DIR)"

case "$CAPACITY_GIB" in
  "") ;;
  *[!0-9]*) usage_error "--capacity-gib must be a whole number of GiB" ;;
  *) [ "$CAPACITY_GIB" -gt 0 ] || usage_error "--capacity-gib must be positive" ;;
esac

# Mirrors config.NormalizePayoutAddress, only so a typo is caught in the first
# second rather than after a five-minute install. The node stays authoritative.
if [ -n "$PAYOUT" ]; then
  case "$PAYOUT" in 0x*) ;; *) usage_error "--payout must start with 0x" ;; esac
  case "${PAYOUT#0x}" in *[!0-9a-fA-F]*) usage_error "--payout is not hexadecimal" ;; esac
  [ "${#PAYOUT}" -eq 42 ] || usage_error "--payout must be 42 characters including 0x"
fi

CONFIG_FILE="$DATA_DIR/config.json"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

# ---------------------------------------------------------------------------
# The plan
#   ok      present and working          fix     this script will install it
#   manual  the operator must do it      cannot  impossible here (hardware)
#   skip    not needed for these options
# ---------------------------------------------------------------------------

PLAN_STATUS=(); PLAN_NAME=(); PLAN_FOR=(); PLAN_DETAIL=()
REQUIRED_MISSING=0
BLOCKED=0

plan() { # plan STATUS NAME FOR DETAIL
  PLAN_STATUS+=("$1"); PLAN_NAME+=("$2"); PLAN_FOR+=("$3"); PLAN_DETAIL+=("$4")
  return 0
}

# A hard stop, recorded as a row rather than raised immediately: --check exists
# to show the WHOLE picture, and dying mid-detection hands the operator a
# truncated table. ACT refuses to start while any of these stand.
blocker() { BLOCKED=1; REQUIRED_MISSING=1; plan cannot "$1" "$2" "$3"; return 0; }

PKGS=()
pkg_add() {
  local p
  for p in ${PKGS[@]+"${PKGS[@]}"}; do [ "$p" = "$1" ] && return 0; done
  PKGS+=("$1")
  return 0
}

DO_CONFIGURE_I2PD=0
DO_ENABLE_ROUTER=0
DO_START_ROUTER=0
DO_ENABLE_DOCKER=0
DO_BOOTSTRAP_GO=0
DO_BUILD_BINARY=0
DO_CREATE_USER=0
DO_ADD_DOCKER_GROUP=0
ROUTER_KIND=""       # i2pd | java | none
ROUTER_UNIT=""
I2PD_CONF=""
DOCKER_UNIT=""
GO_CMD=""
BINARY_RESOLVED=""

# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------

ARCH_RAW="$(uname -m)"
# go.dev publishes linux archives for exactly these names. An architecture not
# in this table STOPS the Go bootstrap; it never picks a near miss, because a
# toolchain for the wrong ISA fails like a corrupt download.
case "$ARCH_RAW" in
  x86_64|amd64)  GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  armv6l|armv7l) GOARCH="armv6l" ;;   # Go ships armv6l; it runs on armv7 too
  i386|i686)     GOARCH="386" ;;
  *)             GOARCH="" ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }

# systemd | openrc | none. /run/systemd/system is the documented "systemd is
# the running init" test; rc-update plus /etc/init.d is OpenRC's. A machine with
# neither still gets a fully installed node, just no boot service.
SERVICE_MGR="none"
if [ -d /run/systemd/system ] && have systemctl; then
  SERVICE_MGR="systemd"
elif have rc-update && have rc-service && [ -d /etc/init.d ]; then
  SERVICE_MGR="openrc"
fi
IS_ROOT=0
[ "$(id -u)" = "0" ] && IS_ROOT=1

PKG_MGR=""
if   have apt-get; then PKG_MGR="apt"
elif have dnf;     then PKG_MGR="dnf"
elif have pacman;  then PKG_MGR="pacman"
elif have zypper;  then PKG_MGR="zypper"
elif have apk;     then PKG_MGR="apk"
elif have yum;     then PKG_MGR="yum"
fi

# Anything absent from this table is reported as a manual step with the command
# spelled out, never guessed at: guessing installs SOMETHING, and the operator
# finds out later it was not what they needed.
pkg_name_for() {
  case "$PKG_MGR:$1" in
    apt:i2pd|dnf:i2pd|yum:i2pd|pacman:i2pd|zypper:i2pd|apk:i2pd) echo "i2pd" ;;
    apt:ca-certificates|dnf:ca-certificates|yum:ca-certificates|pacman:ca-certificates|zypper:ca-certificates|apk:ca-certificates) echo "ca-certificates" ;;
    apt:docker) echo "docker.io" ;;
    dnf:docker|yum:docker) echo "moby-engine" ;;
    pacman:docker|zypper:docker|apk:docker) echo "docker" ;;
    *) echo "" ;;
  esac
  return 0
}

install_cmd_for() {
  case "$PKG_MGR" in
    apt)    echo "apt-get install -y $*" ;;
    dnf)    echo "dnf install -y $*" ;;
    yum)    echo "yum install -y $*" ;;
    pacman) echo "pacman -S --needed --noconfirm $*" ;;
    zypper) echo "zypper --non-interactive install $*" ;;
    apk)    echo "apk add --no-cache $*" ;;
    *)      echo "" ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

# The braces around exec are load-bearing: `exec 3<>/dev/tcp/... 2>/dev/null`
# still prints "connect: Connection refused", because the message comes from the
# shell performing the redirection. Grouping moves it inside the redirect.
tcp_open() {
  if { exec 3<>"/dev/tcp/$1/$2"; } 2>/dev/null; then
    exec 3>&-
    return 0
  fi
  return 1
}

# sam_probe -- the ONLY correct readiness test for the I2P transport.
# 0 = SAM answered RESULT=OK, 1 = nothing listening, 2 = connected but silent,
# 3 = something that is not SAM owns the port. Byte-for-byte what
# internal/i2p/sam.go connectSAM does, so a pass here guarantees the node's own
# handshake passes; a bare TCP connect does not.
#
# NOT THE CONSOLE PORTS. 7657 (Java) and 7070 (i2pd) bind immediately at router
# start, but Java I2P ships SAM with clientApp.N.delay=120, so SAM opens ~2
# minutes later. Checking a console port reports success, systemd starts the
# node, p2p.Open gets ECONNREFUSED, main.go calls logger.Fatal -- the node has NO
# startup retry. Literal 127.0.0.1, never "localhost": where the resolver
# prefers ::1, "localhost" can reach a console on [::1] and miss the bridge.
sam_probe() {
  local line=""
  if ! { exec 3<>"/dev/tcp/127.0.0.1/7656"; } 2>/dev/null; then return 1; fi
  if ! printf 'HELLO VERSION MIN=3.1 MAX=3.3\n' >&3 2>/dev/null; then exec 3>&-; return 2; fi
  if ! IFS= read -r -t 10 line <&3; then exec 3>&-; return 2; fi
  exec 3>&-
  case "$line" in
    "HELLO REPLY"*RESULT=OK*) return 0 ;;
    *) return 3 ;;
  esac
}

# "Fail fast" is wrong here: the thing waited for is known to be slow, and
# giving up early costs an operator who reinstalls a router that was working.
# The one thing that DOES fail fast is a non-SAM reply -- waiting cannot fix a
# port collision, and continuing to wait hides it.
wait_for_sam() {
  local budget="$1" waited=0 rc=0
  while :; do
    rc=0; sam_probe || rc=$?
    case "$rc" in
      0) return 0 ;;
      3) warn "127.0.0.1:7656 answered, but not with a SAM greeting -- something other than an I2P router owns that port"
         return 3 ;;
    esac
    [ "$waited" -ge "$budget" ] && return 1
    if [ "$waited" -gt 0 ] && [ $((waited % 30)) -eq 0 ]; then
      note "still waiting for the SAM bridge (${waited}s of ${budget}s) -- normal for a Java router"
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

free_mib() { # MiB free on the filesystem holding the nearest existing ancestor
  local d="$1"
  while [ ! -d "$d" ] && [ "$d" != "/" ]; do d="$(dirname "$d")"; done
  df -Pk -- "$d" 2>/dev/null | awk 'NR==2 {print int($4/1024)}'
  return 0
}

unit_exists() { # unit_exists NAME.service -- systemd only
  [ "$SERVICE_MGR" = "systemd" ] || return 1
  systemctl list-unit-files "$1" 2>/dev/null | grep -q "^$1"
}

# service_exists NAME (no suffix) -- true if either manager knows the service.
# Sets SERVICE_FOUND to the name this manager uses for it.
SERVICE_FOUND=""
service_exists() {
  case "$SERVICE_MGR" in
    systemd) if unit_exists "$1.service"; then SERVICE_FOUND="$1.service"; return 0; fi ;;
    openrc)  if [ -f "/etc/init.d/$1" ]; then SERVICE_FOUND="$1"; return 0; fi ;;
  esac
  return 1
}

service_is_enabled() { # service_is_enabled NAME-as-this-manager-calls-it
  case "$SERVICE_MGR" in
    systemd) systemctl is-enabled "$1" >/dev/null 2>&1 ;;
    openrc)  rc-update show default 2>/dev/null | grep -q "^ *$1 " ;;
    *) return 1 ;;
  esac
}

service_enable() {
  case "$SERVICE_MGR" in
    systemd) run systemctl enable "$1" ;;
    openrc)  run rc-update add "$1" default ;;
  esac
}

service_start()   { case "$SERVICE_MGR" in systemd) run systemctl start "$1" ;; openrc) run rc-service "$1" start ;; esac; }
service_restart() { case "$SERVICE_MGR" in systemd) run systemctl restart "$1" ;; openrc) run rc-service "$1" restart ;; esac; }

sha_of() { sha256sum | awk '{print $1}'; }
MARKER_PREFIX="# managed-by: syndichan install.sh v$VERSION sha256="

# ---------------------------------------------------------------------------
# DETECT
# ---------------------------------------------------------------------------

detect_platform() {
  if [ -n "$PKG_MGR" ]; then
    plan ok "platform" "all" "Linux/$ARCH_RAW, package manager: $PKG_MGR"
  else
    plan manual "platform" "all" "Linux/$ARCH_RAW, NO known package manager -- commands will be printed, not run"
  fi
  case "$SERVICE_MGR" in
    systemd) plan ok "service manager" "boot service" "systemd" ;;
    openrc)  plan ok "service manager" "boot service" "OpenRC (no systemd here)" ;;
    *)
      if [ "$INSTALL_SERVICE" = "1" ]; then
        REQUIRED_MISSING=1
        plan manual "service manager" "boot service" "neither systemd nor OpenRC found; re-run with --no-service and start the node under your own supervisor"
      fi ;;
  esac
  return 0
}

detect_ca_certs() {
  local f
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    if [ -s "$f" ]; then
      plan ok "CA trust store" "heartbeat, gateway" "$f"
      return 0
    fi
  done
  # Nastier than it looks: the presence heartbeat is a real clearnet HTTPS POST
  # to syndichan.org (Proxy is nil on purpose). With no root certs every
  # peer-to-peer thing works and the node is invisible to the site -- a split
  # brain with no error anywhere the operator is looking.
  REQUIRED_MISSING=1
  local p; p="$(pkg_name_for ca-certificates)"
  if [ -n "$p" ]; then
    pkg_add "$p"
    plan fix "CA trust store" "heartbeat, gateway" "no CA bundle found; will install $p"
  else
    plan manual "CA trust store" "heartbeat, gateway" "no CA bundle found; install your distro's ca-certificates package"
  fi
  return 0
}

detect_router_install() {
  # The shipped packaging unit hardcodes Requires=i2pd.service, which fails the
  # node outright ("Unit i2pd.service not found") on a machine running the Java
  # router as i2p.service, before it ever tries SAM. The generated unit names
  # the router actually found.
  if have i2pd || [ -f /etc/i2pd/i2pd.conf ]; then
    ROUTER_KIND="i2pd"
  elif have i2prouter || [ -f /usr/share/i2p/clients.config ] || [ -d /var/lib/i2p ]; then
    ROUTER_KIND="java"
  else
    ROUTER_KIND="none"
  fi
  local u
  for u in i2pd i2p; do
    if service_exists "$u"; then
      ROUTER_UNIT="$SERVICE_FOUND"
      [ "$u" = "i2pd" ] && ROUTER_KIND="i2pd"
      [ "$u" = "i2p" ] && [ "$ROUTER_KIND" = "none" ] && ROUTER_KIND="java"
      break
    fi
  done
  [ "$ROUTER_KIND" = "i2pd" ] && [ -f /etc/i2pd/i2pd.conf ] && I2PD_CONF="/etc/i2pd/i2pd.conf"
  return 0
}

detect_i2p() {
  local rc=0
  sam_probe || rc=$?
  detect_router_install

  if [ "$rc" = "0" ]; then
    # A live bridge answers the question completely. Install no router, edit no
    # router config, restart nothing: only one process can hold 7656, and a
    # second router loses the bind and says so in a log nobody is reading. An
    # operator's working router is never touched.
    plan ok "I2P router (SAM)" "storage" "SAM v3 answered RESULT=OK on 127.0.0.1:7656 (${ROUTER_KIND:-unknown} router)"
    detect_router_boot
    return 0
  fi

  REQUIRED_MISSING=1
  if [ "$rc" = "3" ]; then
    plan manual "I2P router (SAM)" "storage" "127.0.0.1:7656 is held by something that does not speak SAM -- free that port first"
    return 0
  fi

  case "$ROUTER_KIND" in
    i2pd)
      if [ -n "$I2PD_CONF" ]; then
        DO_CONFIGURE_I2PD=1
        DO_START_ROUTER=1
        plan fix "I2P router (SAM)" "storage" "i2pd installed but SAM silent; will assert [sam]/[httpproxy] in $I2PD_CONF (backed up; mode and owner preserved) and restart ${ROUTER_UNIT:-i2pd}"
      else
        plan manual "I2P router (SAM)" "storage" "i2pd is installed but /etc/i2pd/i2pd.conf is missing; set [sam] enabled = true, address = 127.0.0.1, port = 7656 yourself"
      fi
      ;;
    java)
      # Deliberately NOT edited. The router rewrites clients.config on shutdown;
      # the SAM entry's index differs between the monolithic file and the
      # clients.config.d fragments; and an entry with no startOnLoad line is
      # silently unfixable by sed -- so the old code could stop somebody's
      # router, change nothing, restart it, and then wait five minutes for a
      # bridge that was never going to appear. The two-click fix is honest.
      plan manual "I2P router (SAM)" "storage" "Java I2P found but SAM silent; enable it at http://127.0.0.1:7657/configclients -> 'SAM application bridge' -> Start + 'Run at Startup', then re-run"
      detect_router_boot
      ;;
    *)
      local p; p="$(pkg_name_for i2pd)"
      if [ -n "$p" ]; then
        DO_CONFIGURE_I2PD=1
        DO_ENABLE_ROUTER=1
        DO_START_ROUTER=1
        pkg_add "$p"
        ROUTER_KIND="i2pd"
        I2PD_CONF="/etc/i2pd/i2pd.conf"
        # ROUTER_UNIT is only set where something can actually act on it. With no
        # service manager the plan must not promise "enable+start"; start_router
        # could not deliver it, and that is exactly the kind of quiet gap between
        # --check and ACT this script exists to avoid.
        if [ -z "$ROUTER_UNIT" ] && [ "$SERVICE_MGR" != "none" ]; then
          case "$SERVICE_MGR" in openrc) ROUTER_UNIT="i2pd" ;; *) ROUTER_UNIT="i2pd.service" ;; esac
        fi
        if [ -n "$ROUTER_UNIT" ]; then
          plan fix "I2P router (SAM)" "storage" "no router found; will install $p, set its SAM bridge in /etc/i2pd/i2pd.conf, and enable+start $ROUTER_UNIT"
        else
          DO_ENABLE_ROUTER=0
          DO_START_ROUTER=0
          plan fix "I2P router (SAM)" "storage" "no router found; will install $p and set its SAM bridge in /etc/i2pd/i2pd.conf -- but there is no service manager here, so START IT YOURSELF: i2pd --daemon"
        fi
        case "$PKG_MGR" in
          dnf|yum) plan manual "i2pd repository" "storage" "i2pd is not in Fedora/RHEL's official repos; run 'dnf copr enable supervillain/i2pd' first" ;;
          apk) plan manual "i2pd repository" "storage" "i2pd lives in Alpine's COMMUNITY repository (verified: v3.23/community, i2pd 2.60.0); make sure community is enabled in /etc/apk/repositories" ;;
        esac
      else
        plan manual "I2P router (SAM)" "storage" "no router found and no known package name here; install i2pd with SAM on 127.0.0.1:7656"
      fi
      ;;
  esac
  return 0
}

detect_router_boot() {
  # Without this the node reboots into nothing: SAM refused, logger.Fatal, and a
  # unit that looks broken when the router is what never came back.
  [ -n "$ROUTER_UNIT" ] || return 0
  if service_is_enabled "$ROUTER_UNIT"; then
    plan ok "I2P router on boot" "storage" "$ROUTER_UNIT is enabled"
  else
    DO_ENABLE_ROUTER=1
    case "$SERVICE_MGR" in
      systemd) plan fix "I2P router on boot" "storage" "will run 'systemctl enable $ROUTER_UNIT'" ;;
      openrc)  plan fix "I2P router on boot" "storage" "will run 'rc-update add $ROUTER_UNIT default'" ;;
    esac
  fi
  return 0
}

detect_i2p_proxy() {
  # Same daemon as SAM, separate port, separate config switch. An i2pd with SAM
  # on and httpproxy off passes every 7656 check and still leaves the node
  # half-blind: the bootstrap document and every .i2p fetch go through here.
  if tcp_open 127.0.0.1 4444; then
    plan ok "I2P HTTP proxy" "storage" "127.0.0.1:4444 accepting connections"
  elif [ "$DO_CONFIGURE_I2PD" = "1" ]; then
    # Only claimed when this script actually owns the config it would change.
    plan fix "I2P HTTP proxy" "storage" "127.0.0.1:4444 silent; [httpproxy] will be set in $I2PD_CONF alongside SAM"
  else
    plan manual "I2P HTTP proxy" "storage" "127.0.0.1:4444 silent; enable your router's HTTP proxy on loopback (Java: http://127.0.0.1:7657/i2ptunnelmgr)"
  fi
  return 0
}

# --- the binary, and the toolchain that produces it -------------------------

go_base_version() { # -> "1.22.2", or nothing
  # From / with GOTOOLCHAIN=local, so this reports the toolchain actually
  # INSTALLED. Inside the module directory the default GOTOOLCHAIN=auto makes
  # `go version` report the toolchain go.mod asked for, which is a different
  # question.
  ( cd / && GOTOOLCHAIN=local "$1" version 2>/dev/null ) |
    sed -n 's/^go version go\([0-9][0-9.]*\).*/\1/p'
  return 0
}

go_new_enough() {
  local v="$1" major minor
  major="${v%%.*}"; v="${v#*.}"; minor="${v%%.*}"
  case "$major" in ""|*[!0-9]*) return 1 ;; esac
  case "$minor" in ""|*[!0-9]*) return 1 ;; esac
  [ "$major" -gt "$GO_MIN_MAJOR" ] && return 0
  [ "$major" -eq "$GO_MIN_MAJOR" ] && [ "$minor" -ge "$GO_MIN_MINOR" ] && return 0
  return 1
}

detect_binary() {
  local candidate
  if [ -n "$BINARY_SRC" ]; then
    if [ ! -f "$BINARY_SRC" ] || [ ! -x "$BINARY_SRC" ]; then
      blocker "syndichan-node binary" "all" "--binary $BINARY_SRC is not an executable file"
      return 0
    fi
    BINARY_RESOLVED="$BINARY_SRC"
    plan ok "syndichan-node binary" "all" "$BINARY_RESOLVED (given with --binary)"
    plan skip "Go toolchain" "building" "not needed; --binary was given"
    return 0
  fi
  for candidate in "$REPO_ROOT/syndichan-node" "$REPO_ROOT/dist/syndichan-node-linux-$GOARCH"; do
    if [ -x "$candidate" ]; then
      BINARY_RESOLVED="$candidate"
      plan ok "syndichan-node binary" "all" "$BINARY_RESOLVED"
      plan skip "Go toolchain" "building" "not needed; a built binary is already here"
      return 0
    fi
  done
  if [ ! -f "$REPO_ROOT/go.mod" ]; then
    REQUIRED_MISSING=1
    plan manual "syndichan-node binary" "all" "no binary and no source tree ($REPO_ROOT/go.mod missing); build elsewhere and pass --binary PATH"
    return 0
  fi
  detect_go || return 0
  DO_BUILD_BINARY=1
  plan fix "syndichan-node binary" "all" "will run 'go build ./cmd/syndichan-node' in $REPO_ROOT (as ${SUDO_USER:-the invoking user}, never root)"
  return 0
}

# Decides where the compiler comes from. Non-zero when there is no way to get
# one, having already recorded the reason.
detect_go() {
  local cmd="" ver="" pinned
  if have go; then cmd="$(command -v go)"
  elif [ -x "$GO_ROOT_DEST/bin/go" ]; then cmd="$GO_ROOT_DEST/bin/go"
  fi
  if [ -n "$cmd" ]; then
    ver="$(go_base_version "$cmd")"
    if [ -n "$ver" ] && go_new_enough "$ver"; then
      GO_CMD="$cmd"
      pinned="$(sed -n 's/^go \([0-9][0-9.]*\)$/\1/p' "$REPO_ROOT/go.mod" | head -1)"
      # The build passes GOTOOLCHAIN=auto explicitly, so `go env -w
      # GOTOOLCHAIN=local` on this machine cannot break it. That fetch needs
      # network, which is why it is stated rather than discovered.
      plan ok "Go toolchain" "building" "$cmd (go$ver); will fetch the go${pinned:-1.25.12} toolchain go.mod pins, over the network, unless already cached"
      return 0
    fi
    REQUIRED_MISSING=1
    plan manual "Go toolchain" "building" "$cmd is go${ver:-?}, older than $GO_MIN_MAJOR.$GO_MIN_MINOR and unable to fetch the pinned toolchain; upgrade it or pass --binary PATH"
    plan manual "syndichan-node binary" "all" "cannot be built with the Go on this machine"
    return 1
  fi

  # Nothing usable. Bootstrap from go.dev -- the OFFICIAL source, with the
  # SHA-256 from the same TLS-protected index checked before anything is
  # unpacked. A distro package is deliberately not used: half the supported
  # distros ship a Go too old for the pinned toolchain, and being
  # distro-agnostic is the entire point of this path.
  local blocked=""
  [ -n "$GOARCH" ] || blocked="go.dev publishes no linux toolchain for '$ARCH_RAW'"
  if [ -z "$blocked" ] && ! have curl && ! have wget; then
    blocked="neither curl nor wget is installed, so nothing can be downloaded"
  fi
  if [ -z "$blocked" ] && ! have sha256sum; then
    blocked="sha256sum is missing, and an unverified toolchain will not be installed"
  fi
  [ -z "$blocked" ] && ! have tar && blocked="tar is missing"
  if [ -z "$blocked" ] && [ -e "$GO_ROOT_DEST" ]; then
    blocked="$GO_ROOT_DEST already exists and this installer will not write over somebody else's Go"
  fi
  if [ -n "$blocked" ]; then
    REQUIRED_MISSING=1
    plan manual "Go toolchain" "building" "no usable Go: $blocked. Install Go $GO_MIN_MAJOR.$GO_MIN_MINOR+ yourself, or build elsewhere and pass --binary PATH"
    plan manual "syndichan-node binary" "all" "no binary and no way to build one here"
    return 1
  fi
  DO_BOOTSTRAP_GO=1
  GO_CMD="$GO_ROOT_DEST/bin/go"
  local linking=""
  [ -e "$GO_BIN_LINK" ] || linking=", and symlink $GO_BIN_LINK"
  plan fix "Go toolchain" "building" "no Go here; will read https://go.dev/dl/?mode=json, download the newest stable go*.linux-$GOARCH.tar.gz over HTTPS, VERIFY its SHA-256 against that index, unpack to $GO_ROOT_DEST$linking"
  return 0
}

# --- the configuration that will actually run -------------------------------
#
# ReadWritePaths= and the docker-group decision are properties of the CONFIG THE
# SERVICE WILL LOAD, not of this script's defaults -- and the two stop agreeing
# the moment a config already exists. A node whose config.json says
# "data_dir": "/mnt/backup/website" started, then died with
#
#     open /mnt/backup/website/storage/metadata.db: read-only file system
#
# on a mount that was demonstrably rw, because ProtectSystem=strict makes
# EVERYTHING read-only except ReadWritePaths, and ReadWritePaths named the
# directory this installer had planned to create instead. The error names the
# filesystem, so it sends the operator to check mounts and permissions; nothing
# in it points at systemd. That is what these functions exist to prevent.
#
# NO jq. It is absent on most fresh servers, and an installer that needs a
# JSON parser installed before it can read a config file is not an installer.
# This is a one-pass awk scanner instead: POSIX awk only (Alpine has busybox
# awk, not gawk), no recursion, no regexp cleverness.

CONFIG_STATE="absent"     # absent | parsed | unreadable | unparsable | notools
CONFIG_SCAN=""            # cached "dotted.key<TAB>value" lines
CONFIG_DATA_DIR=""        # data_dir exactly as an existing config states it
RUNTIME_DATA_DIR=""       # where the node will ACTUALLY write. What matters.
RUNTIME_DATA_DIR_WHY=""   # one line for the plan, and for the operator
RUNTIME_DATA_DIR_UNKNOWN=0 # 1 when the config's data_dir could not be honoured
RW_PATHS=""               # the exact text of the unit's ReadWritePaths=

# json_scan FILE -- one "dotted.key<TAB>value" line per scalar, objects only.
#
# Deliberately not a full JSON parser: it decodes ONLY the escape that cannot
# change the meaning of a path (\/ -> /) and leaves every other escape as the
# two literal characters it found. So a value that truly needed unescaping still
# contains a backslash, which data_dir_problem then rejects -- the installer
# refuses to guess rather than writing a path it half-understood. A literal
# newline inside a string (invalid JSON, but files get hand-edited) is turned
# into a visible \n for the same reason: it must not silently split a record.
#
# Values inside arrays are skipped, and a key is only reported when every level
# above it is an object, so `[{"data_dir": "..."}]` cannot masquerade as a
# top-level key.
json_scan() {
  awk '
    function jpath(d,   p, t) {
      p = ""
      for (t = 1; t <= d; t++) { if (p != "") p = p "."; p = p key[t] }
      return p
    }
    function emit(d, v,   t) {
      if (d < 1 || key[d] == "") return
      for (t = 1; t <= d; t++) if (kind[t] != "o") return
      print jpath(d) "\t" v
    }
    { buf = buf $0 "\n" }
    END {
      n = length(buf); i = 1; depth = 0
      while (i <= n) {
        c = substr(buf, i, 1)
        if (c == "\"") {
          val = ""; i++
          while (i <= n) {
            ch = substr(buf, i, 1)
            if (ch == "\\") {
              nx = substr(buf, i + 1, 1)
              if (nx == "/") val = val "/"; else val = val ch nx
              i += 2; continue
            }
            if (ch == "\"") { i++; break }
            if (ch == "\n") { val = val "\\n"; i++; continue }
            val = val ch; i++
          }
          # A string is a KEY only if the next non-space character is a colon.
          j = i
          while (j <= n && index(" \t\r\n", substr(buf, j, 1)) > 0) j++
          if (substr(buf, j, 1) == ":") {
            if (kind[depth] == "o") key[depth] = val
            i = j + 1
            continue
          }
          emit(depth, val)
          continue
        }
        if (c == "{" || c == "[") {
          depth++
          kind[depth] = (c == "{") ? "o" : "a"
          key[depth] = ""
          i++
          continue
        }
        if (c == "}" || c == "]") { if (depth > 0) depth--; i++; continue }
        if (index("-0123456789tfn", c) > 0) {   # number, true, false, null
          val = ""
          while (i <= n) {
            ch = substr(buf, i, 1)
            if (index("-+.eE0123456789abcdefglnrstu", ch) == 0) break
            val = val ch; i++
          }
          emit(depth, val)
          continue
        }
        i++
      }
    }
  ' "$1"
  return 0
}

config_field() { # config_field dotted.key -- empty when absent
  [ -n "$CONFIG_SCAN" ] || return 0
  printf '%s\n' "$CONFIG_SCAN" |
    awk -F '\t' -v k="$1" '$1 == k { print substr($0, length($1) + 2); exit }'
  return 0
}

read_effective_config() {
  CONFIG_SCAN=""
  if [ "$INSTALL_SERVICE" = "0" ]; then CONFIG_STATE="absent"; return 0; fi
  if [ -r "$CONFIG_FILE" ]; then
    :
  elif [ -e "$CONFIG_FILE" ]; then
    CONFIG_STATE="unreadable"; return 0
  elif [ -d "$DATA_DIR" ] && [ ! -x "$DATA_DIR" ]; then
    # 0700 and not ours: a config may well be in there and we cannot even stat
    # it. Reporting "no configuration" here would be a guess presented as a fact.
    CONFIG_STATE="unreadable"; return 0
  else
    CONFIG_STATE="absent"; return 0
  fi
  if ! have awk; then CONFIG_STATE="notools"; return 0; fi
  CONFIG_SCAN="$(json_scan "$CONFIG_FILE" 2>/dev/null)" || CONFIG_SCAN=""
  if [ -z "$CONFIG_SCAN" ]; then
    # An empty scan is either a file that is not JSON at all or a JSON object
    # with nothing in it -- "{}" is a perfectly good config, the node fills the
    # rest in. Only the first is a reason to stop trusting the file.
    if head -c 4096 "$CONFIG_FILE" 2>/dev/null | tr -d ' \t\r\n' | grep -q '^{'; then
      CONFIG_STATE="parsed"
    else
      CONFIG_STATE="unparsable"
    fi
    return 0
  fi
  CONFIG_STATE="parsed"
  CONFIG_DATA_DIR="$(config_field data_dir)"
  return 0
}

# Sets RUNTIME_DATA_DIR (the one directory that MUST be writable) and RW_PATHS.
# Both are reported by --check, because a plan that says one thing and a unit
# that says another is how the failure above stayed confusing for so long.
resolve_runtime_data_dir() {
  read_effective_config
  RUNTIME_DATA_DIR="$DATA_DIR"
  RUNTIME_DATA_DIR_UNKNOWN=0
  case "$CONFIG_STATE" in
    absent)
      RUNTIME_DATA_DIR_WHY="no config yet; the node will create one and use $DATA_DIR" ;;
    unreadable)
      RUNTIME_DATA_DIR_UNKNOWN=1
      RUNTIME_DATA_DIR_WHY="CANNOT READ $CONFIG_FILE as $(id -un 2>/dev/null || echo "this user"), so its data_dir is UNKNOWN; re-run --check as root to resolve it" ;;
    notools)
      RUNTIME_DATA_DIR_UNKNOWN=1
      RUNTIME_DATA_DIR_WHY="no awk on this machine, so $CONFIG_FILE could not be read; its data_dir is UNKNOWN" ;;
    unparsable)
      RUNTIME_DATA_DIR_UNKNOWN=1
      RUNTIME_DATA_DIR_WHY="$CONFIG_FILE is not readable as JSON, so its data_dir is UNKNOWN" ;;
    parsed)
      if [ -z "$CONFIG_DATA_DIR" ]; then
        # Absent key: config.Default() already filled DataDir in, and the unit
        # sets HOME=$DATA_DIR, so os.UserConfigDir() lands UNDER the data dir.
        RUNTIME_DATA_DIR_WHY="$CONFIG_FILE has no data_dir key; the node falls back to \$HOME/.config/Syndichan/storage-node, i.e. inside $DATA_DIR"
      else
        local problem; problem="$(data_dir_problem "$CONFIG_DATA_DIR")"
        if [ -n "$problem" ]; then
          # Refusing beats guessing: this is the one place where writing a path
          # we do not trust would hand systemd a directory nobody vetted.
          RUNTIME_DATA_DIR_UNKNOWN=1
          RUNTIME_DATA_DIR_WHY="data_dir in $CONFIG_FILE $problem, so it will NOT be put in ReadWritePaths (it reads: $CONFIG_DATA_DIR)"
        else
          RUNTIME_DATA_DIR="$CONFIG_DATA_DIR"
          RUNTIME_DATA_DIR_WHY="from data_dir in $CONFIG_FILE"
        fi
      fi ;;
  esac

  # The data dir ITSELF, never <data_dir>/storage: p2p.key, i2p.destination and
  # content.key are written BESIDE storage/, not inside it. Widening to the
  # storage subdirectory is exactly how this bug survived its first fix.
  #
  # $DATA_DIR stays in the list whatever the config says: config.json lives
  # there, config.Save() rewrites it from the management page, and HOME points
  # at it.
  RW_PATHS="\"$DATA_DIR\""
  [ "$RUNTIME_DATA_DIR" != "$DATA_DIR" ] && RW_PATHS="$RW_PATHS \"$RUNTIME_DATA_DIR\""
  return 0
}

# --- service account, data directory, unit ----------------------------------

detect_service_user() {
  if [ "$INSTALL_SERVICE" = "0" ]; then
    plan skip "boot service" "auto-start" "--no-service: nothing written under /etc/systemd"
    plan skip "service account" "boot service" "--no-service: the node runs as you"
    return 0
  fi
  if id "$NODE_USER" >/dev/null 2>&1; then
    local uid; uid="$(id -u "$NODE_USER")"
    if [ "$uid" -ge 1000 ]; then
      # An ordinary login account with this name belongs to somebody, and the
      # data directory is about to be chowned to whatever this name resolves to.
      blocker "service account" "boot service" \
        "an ORDINARY user account named '$NODE_USER' already exists (uid $uid). This installer will not take over a human account, nor chown anything to it"
      return 0
    fi
    NODE_GROUP="$(id -gn "$NODE_USER" 2>/dev/null || echo "$NODE_USER")"
    plan ok "service account" "boot service" "$NODE_USER exists (uid $uid, group $NODE_GROUP)"
  else
    DO_CREATE_USER=1
    plan fix "service account" "boot service" "will create system user $NODE_USER (no shell, no login, home $DATA_DIR)"
  fi

  local target=""
  case "$SERVICE_MGR" in
    systemd) target="$UNIT_PATH" ;;
    openrc)  target="$OPENRC_PATH" ;;
    *) return 0 ;;
  esac
  if [ ! -f "$target" ]; then
    plan fix "boot service" "auto-start" "will write, enable and start $target (runs as $NODE_USER, waits for SAM first, restarts on failure)"
  else
    local recorded body
    recorded="$(sed -n "s|^${MARKER_PREFIX}||p" "$target" | head -1)"
    body="$(grep -v "^${MARKER_PREFIX}" "$target" | sha_of)"
    if [ -n "$recorded" ] && [ "$recorded" = "$body" ]; then
      plan fix "boot service" "auto-start" "$target was written by this installer; will be refreshed if it changed, then enabled and restarted"
    else
      plan manual "boot service" "auto-start" "$target exists and was NOT written by this installer; it will be left alone (but still enabled and restarted)"
    fi
  fi
  if [ "$SERVICE_MGR" = "openrc" ]; then
    plan manual "OpenRC boot delay" "boot service" "start_pre waits up to ${SAM_WAIT_SECONDS}s for SAM. OpenRC starts services serially by default, so a cold router delays the rest of boot; set rc_parallel=YES in /etc/rc.conf if that matters"
  fi
  plan fix "SAM readiness helper" "boot service" "will install $WAIT_HELPER, run before the node starts"
  return 0
}

detect_data_dir() {
  resolve_runtime_data_dir

  # Rule 4 of the data-directory contract: an existing directory is adopted only
  # if it is empty or already ours. That is what makes the chown safe rather
  # than merely guarded.
  if [ -L "$DATA_DIR" ]; then
    blocker "data directory" "storage" "$DATA_DIR is a SYMLINK; refusing to chown through it"
  elif [ -e "$DATA_DIR" ] && [ ! -d "$DATA_DIR" ]; then
    blocker "data directory" "storage" "$DATA_DIR exists and is not a directory"
  elif [ -d "$DATA_DIR" ]; then
    local owner; owner="$(stat -c '%U' "$DATA_DIR" 2>/dev/null || echo "?")"
    if [ "$owner" != "$NODE_USER" ] && [ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; then
      blocker "data directory" "storage" \
        "$DATA_DIR exists, is NOT EMPTY, and is owned by '$owner' rather than '$NODE_USER'. Refusing to take ownership; pass an empty or new --data-dir"
    elif [ "$INSTALL_SERVICE" = "1" ]; then
      plan ok "data directory" "storage" "$DATA_DIR exists, owner $owner; will be chowned to $NODE_USER and chmod 0700 -- the leaf only, never recursively"
    fi
  elif [ "$INSTALL_SERVICE" = "1" ]; then
    plan fix "data directory" "storage" "will create $DATA_DIR owned by $NODE_USER, mode 0700"
  fi

  detect_runtime_data_dir

  # capacity_bytes defaults to 20 GiB and NOTHING in the node compares it to
  # the disk. Measured on the RUNTIME data dir: that is the filesystem the
  # shards land on, and it is routinely a different disk from the one holding
  # config.json -- which is the whole reason a node gets pointed elsewhere.
  local avail want
  avail="$(free_mib "$RUNTIME_DATA_DIR")"
  want="$(( ${CAPACITY_GIB:-20} * 1024 ))"
  if [ -n "$avail" ]; then
    if [ "$avail" -lt "$want" ]; then
      plan manual "free disk" "storage" "$((avail / 1024)) GiB free where $RUNTIME_DATA_DIR will live, but the node would donate $((want / 1024)) GiB; pass --capacity-gib N"
    else
      plan ok "free disk" "storage" "$((avail / 1024)) GiB free on $RUNTIME_DATA_DIR for a $((want / 1024)) GiB donation"
    fi
  fi
  return 0
}

# The row this installer used not to have, and the unit line it produces. Both
# are printed even when they are boring, because the operator's only defence
# against a sandbox that silently excludes the data directory is being told
# which directory the sandbox will actually allow.
detect_runtime_data_dir() {
  [ "$INSTALL_SERVICE" = "1" ] || return 0

  if [ "$RUNTIME_DATA_DIR_UNKNOWN" = "1" ]; then
    plan manual "node data_dir" "storage" \
      "$RUNTIME_DATA_DIR_WHY. ReadWritePaths will name $DATA_DIR only; if the config points data_dir somewhere else, the node will fail to write there and blame the filesystem"
  elif [ "$RUNTIME_DATA_DIR" != "$DATA_DIR" ]; then
    plan ok "node data_dir" "storage" \
      "$RUNTIME_DATA_DIR ($RUNTIME_DATA_DIR_WHY) -- the node writes storage/, p2p.key, i2p.destination and content.key THERE, not in $DATA_DIR"
  elif [ "$CONFIG_STATE" = "parsed" ] && [ -z "$CONFIG_DATA_DIR" ]; then
    plan manual "node data_dir" "storage" "$RUNTIME_DATA_DIR_WHY"
  else
    plan ok "node data_dir" "storage" "$RUNTIME_DATA_DIR ($RUNTIME_DATA_DIR_WHY)"
  fi

  [ "$SERVICE_MGR" = "systemd" ] || return 0
  plan ok "ReadWritePaths" "boot service" \
    "ReadWritePaths=$RW_PATHS -- ProtectSystem=strict makes every other path read-only TO THE SERVICE, whatever the mount says"

  # A directory the config names but nobody has created yet is not a hazard on
  # its own -- create_user_and_dirs makes it, because nothing can be taken over
  # by creating it. It is worth a row because it also explains the chown.
  if [ "$RUNTIME_DATA_DIR" != "$DATA_DIR" ] && [ "$CONFIG_STATE" = "parsed" ]; then
    if [ -L "$RUNTIME_DATA_DIR" ]; then
      plan manual "node data_dir owner" "storage" \
        "$RUNTIME_DATA_DIR is a SYMLINK; it will be left alone (never chowned through), and listed in ReadWritePaths as it stands"
    elif [ -e "$RUNTIME_DATA_DIR" ] && [ ! -d "$RUNTIME_DATA_DIR" ]; then
      blocker "node data_dir owner" "storage" \
        "$RUNTIME_DATA_DIR (data_dir in $CONFIG_FILE) exists and is not a directory"
    elif [ ! -e "$RUNTIME_DATA_DIR" ]; then
      plan fix "node data_dir owner" "storage" \
        "will create $RUNTIME_DATA_DIR owned by $NODE_USER, mode 0700 (it does not exist, so nothing is being taken over)"
    else
      local owner; owner="$(stat -c '%U' "$RUNTIME_DATA_DIR" 2>/dev/null || echo "?")"
      if [ "$owner" = "$NODE_USER" ]; then
        plan ok "node data_dir owner" "storage" "$RUNTIME_DATA_DIR already belongs to $NODE_USER"
      elif [ -z "$(ls -A "$RUNTIME_DATA_DIR" 2>/dev/null)" ]; then
        plan fix "node data_dir owner" "storage" \
          "$RUNTIME_DATA_DIR is empty; will be chowned to $NODE_USER (the leaf only, never recursively)"
      else
        # The same guard --data-dir gets, and it is NOT relaxed just because the
        # path came from a config file. Left alone, said out loud.
        plan manual "node data_dir owner" "storage" \
          "$RUNTIME_DATA_DIR is NOT EMPTY and is owned by '$owner', not '$NODE_USER': it will NOT be chowned. It is in ReadWritePaths, so systemd permits writes -- but check that $NODE_USER can write there, or the node dies at startup"
      fi
    fi
  fi
  return 0
}

detect_state_conflicts() {
  case "$CONFIG_STATE" in
    absent)
      if [ "$INSTALL_SERVICE" = "0" ]; then
        plan skip "configuration" "all" "--no-service: the node creates its own on first run (~/.config/Syndichan/storage-node)"
      else
        plan fix "configuration" "all" "will be created BY THE NODE, running as $NODE_USER, at $CONFIG_FILE"
      fi ;;
    parsed)
      plan ok "configuration" "all" "$CONFIG_FILE exists and was read; only the flags you passed will be applied to it" ;;
    unreadable)
      # Said plainly rather than reported as "no configuration": everything
      # below that depends on the config is a guess while this is true.
      plan manual "configuration" "all" "$CONFIG_FILE (or $DATA_DIR) cannot be read by $(id -un 2>/dev/null || echo "this user"); re-run --check as root to see what the service will actually load" ;;
    *)
      plan manual "configuration" "all" "$CONFIG_FILE exists but could not be parsed here ($CONFIG_STATE); the node stays authoritative, but this script cannot read its data_dir" ;;
  esac
  # Two instances on one data_dir collide on the bbolt flock in
  # <data_dir>/storage/metadata.db.
  if have pgrep && pgrep -f '[s]yndichan-node' >/dev/null 2>&1; then
    plan manual "running node" "all" "a syndichan-node process is already running; make sure it is not using $RUNTIME_DATA_DIR"
  fi
  # serve() calls logger.Fatalf, so a taken port takes down the WHOLE node.
  local port
  for port in 9000 9090; do
    case "$port:$UI_LISTEN" in 9090:off|9090:none|9090:OFF|9090:None) continue ;; esac
    if tcp_open 127.0.0.1 "$port"; then
      if [ "$port" = "9090" ]; then
        plan manual "port 9090" "management page" "already in use; pass --ui-listen 127.0.0.1:PORT or --ui-listen off, or the node exits at startup"
      else
        plan manual "port 9000" "S3 endpoint" "already in use; change s3_listen in $CONFIG_FILE before starting"
      fi
    fi
  done
  # Clock skew silently invalidates gateway registrations and probe results
  # (60-300s validity windows) and breaks clearnet TLS. No rejection message
  # anywhere says "time".
  if have timedatectl; then
    if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo no)" = "yes" ]; then
      plan ok "clock" "heartbeat, gateway" "NTP synchronised"
    else
      plan manual "clock" "heartbeat, gateway" "not NTP-synchronised; enable systemd-timesyncd or chrony"
    fi
  fi
  return 0
}

# --- compute (opt-in) -------------------------------------------------------

DOCKER_OK=0
DOCKER_SOCK="/var/run/docker.sock"
DOCKER_GROUP="docker"   # replaced by the group that actually owns the socket
NEEDS_DOCKER=0
DOCKER_FROM_CONFIG=0

# The flag alone is not enough, and that is BUG-shaped rather than pedantic.
# Whether the node talks to Docker is decided by its CONFIG -- dcs.enabled with
# dcs.role.worker, or compute.enabled -- and an operator who switches DCS on
# from the management page a month after installing never re-runs anything with
# --with-compute. That node logs
#
#   dcs: Docker is not reachable at unix:///var/run/docker.sock
#   (dial unix /var/run/docker.sock: connect: permission denied);
#   worker not started. The node continues as a storage node.
#
# exactly once, at startup, and then quietly stores shards forever. So the
# config is asked as well as the flag.
config_wants_docker() {
  [ "$CONFIG_STATE" = "parsed" ] || return 1
  [ "$(config_field compute.enabled)" = "true" ] && return 0
  [ "$(config_field dcs.enabled)" = "true" ] &&
    [ "$(config_field dcs.role.worker)" = "true" ] && return 0
  return 1
}

detect_docker() {
  if [ "$WANT_COMPUTE" = "1" ]; then
    NEEDS_DOCKER=1
  elif config_wants_docker; then
    NEEDS_DOCKER=1
    DOCKER_FROM_CONFIG=1
  fi
  if [ "$NEEDS_DOCKER" = "0" ]; then
    local basis="not requested (--with-compute)"
    case "$CONFIG_STATE" in
      parsed) basis="$basis, and $CONFIG_FILE leaves dcs.enabled/compute.enabled off" ;;
      unreadable|notools|unparsable)
        basis="$basis; $CONFIG_FILE could not be read here, so if it DOES enable DCS this node will log 'Docker is not reachable' once and run storage-only" ;;
    esac
    plan skip "Docker Engine" "compute, DCS" "$basis"
    return 0
  fi
  # The node CANNOT be trusted to detect this. internal/dcs/runtime.go
  # NewDockerClient only checks that the endpoint starts with "unix://" -- it
  # never touches the socket. The DCS path pings afterwards and disables itself
  # cleanly; the COMPUTE path never pings, so a machine with no daemon stands up
  # the compute endpoints, answers "admitted" to jobs, then fails every one of
  # them at container creation.
  local sock="$DOCKER_SOCK"
  if service_exists docker; then DOCKER_UNIT="$SERVICE_FOUND"; fi

  # The group that owns the socket, not the name "docker" assumed. Rootless and
  # hand-rolled daemons hand it to something else, and adding the service
  # account to a group that does not gate the socket is a fix that changes
  # nothing while looking like it worked.
  if [ -S "$sock" ] && have stat; then
    local g; g="$(stat -c '%G' "$sock" 2>/dev/null || echo "")"
    case "$g" in
      ""|UNKNOWN) ;;
      root) DOCKER_GROUP="" ;;   # no membership can open it; only root can
      *) DOCKER_GROUP="$g" ;;
    esac
  fi

  local why="you passed --with-compute"
  [ "$DOCKER_FROM_CONFIG" = "1" ] && why="$CONFIG_FILE switches DCS/compute on"

  if [ -S "$sock" ] && { { have curl && curl -s -o /dev/null --max-time 5 --unix-socket "$sock" http://localhost/_ping; } ||
                         { have docker && docker info >/dev/null 2>&1; }; }; then
    DOCKER_OK=1
    plan ok "Docker Engine" "compute" "$sock answered ($why)"
    detect_docker_group
    return 0
  fi

  # Docker is INSTALLED only when it was asked for. A config that enables DCS is
  # a statement about this node's role, not consent to install a container
  # runtime on somebody's machine -- and --check must not fail over a dependency
  # nobody asked this script to provide, because the node runs fine without it.
  if [ "$DOCKER_FROM_CONFIG" = "1" ]; then
    if [ ! -S "$sock" ]; then
      plan manual "Docker Engine" "compute" "$why, but there is no $sock. Install Docker, or re-run with --with-compute; until then the node stays storage-only"
    else
      plan manual "Docker Engine" "compute" "$sock exists but did not answer /_ping as $(id -un 2>/dev/null || echo "this user") -- either the daemon is down, or this is the permission problem the docker group row below fixes"
    fi
    detect_docker_group
    return 0
  fi

  REQUIRED_MISSING=1
  if [ ! -S "$sock" ]; then
    local p; p="$(pkg_name_for docker)"
    if [ -n "$p" ] && [ "$SERVICE_MGR" != "none" ]; then
      pkg_add "$p"
      DO_ENABLE_DOCKER=1
      plan fix "Docker Engine" "compute" "no $sock; will install $p, then enable and start it with $SERVICE_MGR"
    elif [ -n "$p" ]; then
      pkg_add "$p"
      plan manual "Docker Engine" "compute" "will install $p, but there is no service manager here to start it -- start dockerd yourself"
    else
      plan manual "Docker Engine" "compute" "no $sock and no known package name here; install docker and start the daemon"
    fi
  elif [ -n "$DOCKER_UNIT" ]; then
    DO_ENABLE_DOCKER=1
    plan fix "Docker Engine" "compute" "$sock exists but did not answer; will enable and start $DOCKER_UNIT with $SERVICE_MGR"
  else
    plan manual "Docker Engine" "compute" "$sock exists but did not answer /_ping -- start the daemon, or this user cannot open the socket"
  fi
  detect_docker_group
  return 0
}

# Its own row because it is not a small thing (the docker group is
# root-equivalent by design) and because it is the step whose ABSENCE is
# invisible: nothing in the node's log says "the service user is not in the
# docker group", only that the socket said permission denied.
detect_docker_group() {
  [ "$NEEDS_DOCKER" = "1" ] || return 0
  [ "$INSTALL_SERVICE" = "1" ] || return 0
  if [ -z "$DOCKER_GROUP" ]; then
    plan manual "docker group" "compute" \
      "$DOCKER_SOCK is owned by group root, so NO group membership can open it. Give the socket a group (dockerd --group) or run the node as root -- this installer will do neither"
    return 0
  fi
  if ! have getent || ! getent group "$DOCKER_GROUP" >/dev/null 2>&1; then
    plan manual "docker group" "compute" "no '$DOCKER_GROUP' group on this machine yet; re-run --check after Docker is installed"
    return 0
  fi
  if id -nG "$NODE_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$DOCKER_GROUP"; then
    plan ok "docker group" "compute" "$NODE_USER is already in the '$DOCKER_GROUP' group"
    return 0
  fi
  DO_ADD_DOCKER_GROUP=1
  local relax=""
  [ "$WANT_COMPUTE" = "1" ] && relax=", which also turns off PrivateDevices and MemoryDenyWriteExecute for the microVM path"
  if [ "$SERVICE_MGR" = "systemd" ]; then
    plan fix "docker group" "compute" \
      "$NODE_USER is NOT in '$DOCKER_GROUP' -- this is what 'Docker is not reachable ... permission denied' in the journal means. Will add it (ROOT-EQUIVALENT) and write $UNIT_DROPIN with SupplementaryGroups=$DOCKER_GROUP$relax"
  else
    plan fix "docker group" "compute" \
      "$NODE_USER is NOT in '$DOCKER_GROUP' -- this is what 'Docker is not reachable ... permission denied' in the journal means. Will add it (ROOT-EQUIVALENT)"
  fi
  return 0
}

detect_catalogue_images() {
  [ "$WANT_COMPUTE" = "1" ] || return 0
  # There is NO ImagePull anywhere in the Go tree and registry.local is not a
  # real registry, so these tags exist only if they were built on THIS machine.
  # Absent, every dispatched job dies "No such image" -- after the submitter was
  # already told the job was admitted.
  if [ "$DOCKER_OK" = "0" ]; then
    plan manual "catalogue images" "compute" "cannot be checked without a working Docker daemon; re-run --check afterwards"
    return 0
  fi
  local missing="" lang
  for lang in python go c embed; do
    docker image inspect "registry.local/compute-$lang:latest" >/dev/null 2>&1 || missing="$missing $lang"
  done
  if [ -z "$missing" ]; then
    plan ok "catalogue images" "compute" "registry.local/compute-{python,go,c,embed}:latest present"
  elif [ -d "$REPO_ROOT/../compute-images" ]; then
    # Not offered as an action: compute-images/build.sh also runs `k3s ctr
    # images import`, which fails on any machine without k3s -- after the docker
    # build succeeded, so the failure looks like a build failure when it is not.
    plan manual "catalogue images" "compute" "missing:$missing -- build with: for l in$missing; do docker build -t registry.local/compute-\$l:latest $(cd "$REPO_ROOT/.." && pwd)/compute-images/\$l; done"
  else
    plan manual "catalogue images" "compute" "missing:$missing -- and compute-images/ is not next to this checkout; fetch it from the maniwani repo and docker build each one"
  fi
  return 0
}

detect_kvm() {
  # DETECTION ONLY, ALWAYS. The CPU either exposes virtualisation or it does
  # not, and on a VPS without nested virt no package changes that.
  [ "$WANT_COMPUTE" = "1" ] || return 0
  # Matched against the flags LINE, not the whole file: "vmx" and "svm" are
  # short enough to appear inside a CPU model name. This is also the pipeline
  # that pipefail broke -- see the note at the top of the file.
  if ! grep -E '^(flags|Features)[[:space:]]*:' /proc/cpuinfo 2>/dev/null |
       grep -qE '(^|[[:space:]])(vmx|svm)([[:space:]]|$)'; then
    plan cannot "/dev/kvm (microVM)" "arbitrary-code compute" "CPU reports no vmx/svm -- CANNOT be installed; enable virtualisation in firmware, or this host offers no nested virt"
  elif [ ! -e /dev/kvm ]; then
    plan cannot "/dev/kvm (microVM)" "arbitrary-code compute" "CPU is capable but /dev/kvm is absent -- load kvm_intel/kvm_amd, or the hypervisor does not pass virt through. Not a package"
  elif { exec 4<>/dev/kvm; } 2>/dev/null; then
    # OPENED, not stat'ed: mode bits and group membership are two independent
    # ways to be wrong about the same question, and a POSIX ACL can grant access
    # neither mentions. internal/compute/microvm_linux.go does exactly this, so
    # this gives the same answer the node will.
    exec 4>&-
    plan ok "/dev/kvm (microVM)" "arbitrary-code compute" "openable read-write by $(id -un)"
  else
    plan manual "/dev/kvm (microVM)" "arbitrary-code compute" "present but not openable by $(id -un); usually: usermod -aG kvm $NODE_USER"
  fi
  if have firecracker; then
    plan ok "firecracker" "arbitrary-code compute" "$(command -v firecracker)"
  else
    plan manual "firecracker" "arbitrary-code compute" "optional; packaged by no distro -- put the release binary from github.com/firecracker-microvm/firecracker in /usr/local/bin"
  fi
  # Never fetched automatically, and that is policy, not an oversight: a node
  # that booted a kernel somebody else chose would have handed over the machine
  # in the act of protecting it.
  plan manual "guest kernel + rootfs" "arbitrary-code compute" "operator-supplied on purpose; set compute.microvm_kernel and compute.microvm_rootfs in $CONFIG_FILE. This installer will never download a kernel"
  return 0
}

# ---------------------------------------------------------------------------
# REPORT
# ---------------------------------------------------------------------------

print_plan() {
  local i status label wrote="" compute="no"
  # The second path is printed only when it differs, and it differs exactly when
  # somebody would otherwise be reading the wrong directory off this line.
  [ -n "$RUNTIME_DATA_DIR" ] && [ "$RUNTIME_DATA_DIR" != "$DATA_DIR" ] &&
    wrote=", node writes to=$RUNTIME_DATA_DIR"
  [ "$WANT_COMPUTE" = "1" ] && compute="yes"
  [ "$DOCKER_FROM_CONFIG" = "1" ] && compute="no, but the config enables DCS"
  printf '\n%sDependency report%s  (compute=%s, boot service=%s, data dir=%s%s)\n\n' \
    "$C_BOLD" "$C_RESET" \
    "$compute" \
    "$([ "$INSTALL_SERVICE" = 1 ] && echo yes || echo no)" \
    "$DATA_DIR" "$wrote"
  printf '  %-8s %-22s %-24s %s\n' "STATUS" "DEPENDENCY" "NEEDED FOR" "DETAIL"
  printf '  %-8s %-22s %-24s %s\n' "------" "----------" "----------" "------"
  i=0
  while [ "$i" -lt "${#PLAN_STATUS[@]}" ]; do
    status="${PLAN_STATUS[$i]}"
    case "$status" in
      ok)     label="${C_GREEN}ok${C_RESET}     " ;;
      fix)    label="${C_YELLOW}install${C_RESET}" ;;
      manual) label="${C_YELLOW}manual${C_RESET} " ;;
      cannot) label="${C_RED}cannot${C_RESET} " ;;
      skip)   label="${C_DIM}skip${C_RESET}   " ;;
      *)      label="$status" ;;
    esac
    printf '  %b %-22s %-24s %s\n' "$label" "${PLAN_NAME[$i]}" "${PLAN_FOR[$i]}" "${PLAN_DETAIL[$i]}"
    i=$((i + 1))
  done
  printf '\n'
  if [ "${#PKGS[@]}" -gt 0 ]; then
    local cmd; cmd="$(install_cmd_for ${PKGS[@]+"${PKGS[@]}"})"
    if [ -n "$cmd" ]; then
      printf '%sPackages to install:%s %s\n  sudo %s\n\n' "$C_BOLD" "$C_RESET" "${PKGS[*]}" "$cmd"
    else
      printf '%sNo known package manager here.%s Install these with whatever your system\nuses, then re-run:\n  %s\n\n' "$C_BOLD" "$C_RESET" "${PKGS[*]}"
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# ACT -- runs as root (checked before consent). Every function is a no-op
# unless its DO_* flag was set during DETECT.
# ---------------------------------------------------------------------------

run() { # echo the command first, so nothing is a surprise
  printf '    %s+%s %s\n' "$C_DIM" "$C_RESET" "$*"
  "$@"
}

# Never as root. runuser first (util-linux, present wherever systemd is, and
# needs no sudoers policy), then sudo, then busybox `su` -- Alpine has ONLY the
# last of those. HOME is always set because config.Default() calls
# os.UserConfigDir() unconditionally, even when -config names an exact path, so
# a system account with no HOME makes the node exit before it reads the file it
# was pointed at.
run_as_node() {
  if have runuser; then
    run runuser -u "$NODE_USER" -- env HOME="$DATA_DIR" "$@"
  elif have sudo; then
    run sudo -u "$NODE_USER" env HOME="$DATA_DIR" "$@"
  elif have su; then
    # busybox su takes a single -c string, so the argument vector has to be
    # re-quoted. Only paths this script controls end up here, and DATA_DIR has
    # already been restricted to characters that survive quoting.
    local cmd="" a
    for a in "$@"; do cmd="$cmd '$a'"; done
    run su -s /bin/sh -c "env HOME='$DATA_DIR'$cmd" "$NODE_USER"
  else
    die "no runuser, sudo or su here; cannot drop privileges to $NODE_USER"
  fi
}

confirm() {
  [ "$ASSUME_YES" = "1" ] && return 0
  local answer=""
  printf '%s%s%s [y/N] ' "$C_BOLD" "$1" "$C_RESET"
  IFS= read -r answer || answer=""
  case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

install_packages() {
  [ "${#PKGS[@]}" -gt 0 ] || return 0
  local cmd; cmd="$(install_cmd_for ${PKGS[@]+"${PKGS[@]}"})"
  if [ -z "$cmd" ]; then
    warn "no package manager here; install these yourself and re-run: ${PKGS[*]}"
    return 0
  fi
  step "Installing packages: ${PKGS[*]}"
  if [ "$PKG_MGR" = "apt" ]; then
    run apt-get update
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y ${PKGS[@]+"${PKGS[@]}"}
  else
    # shellcheck disable=SC2086  # cmd comes from install_cmd_for, not the user
    run $cmd
  fi
  return 0
}

# i2pd has no conf.d for its main config, so settings go INTO i2pd.conf. This
# rewrites one key in one section, uncommenting it if the shipped file has it
# commented (it does, for all of [sam]) and appending the section if absent.
# Writing only on real change is what makes a second run a no-op instead of a
# pile of duplicate keys. Returns 0 if changed, 1 if already correct. The awk is
# verified byte-identical on a second pass -- do not rewrite it casually.
#
# packaging/systemd/i2pd-syndichan.default is NOT used: upstream's unit has no
# EnvironmentFile and hardcodes ExecStart, so $DAEMON_OPTS from /etc/default/i2pd
# is read only by the sysvinit script -- dropping it on a systemd box silently
# applies nothing.
i2pd_set_key() { # SECTION KEY VALUE FILE
  local section="$1" key="$2" value="$3" file="$4" tmp mode uid gid
  tmp="$(workdir)/i2pd.conf.new"
  awk -v sect="$section" -v key="$key" -v val="$value" '
    BEGIN { cur = ""; done = 0 }
    /^[[:space:]]*\[/ {
      if (cur == sect && !done) { print key " = " val; done = 1 }
      s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s)
      cur = s
      print; next
    }
    {
      if (cur == sect && !done && $0 ~ ("^[[:space:]]*#*[[:space:]]*" key "[[:space:]]*=")) {
        print key " = " val; done = 1; next
      }
      print
    }
    END {
      if (!done) {
        if (cur != sect) print "[" sect "]"
        print key " = " val
      }
    }
  ' "$file" >"$tmp"
  cmp -s "$tmp" "$file" && return 1
  # Mode and ownership carried over from the file being replaced. The old code
  # used `install -m 0644`, which quietly WIDENED a config an operator had
  # deliberately locked down, and handed it to root:root besides.
  #
  # install -m then chown, rather than install -o/-g: busybox's install takes
  # only NAMES for -o/-g, and a numeric id there fails on Alpine. chown accepts
  # numeric everywhere, and numeric is what survives an orphaned uid.
  mode="$(stat -c '%a' "$file")"; uid="$(stat -c '%u' "$file")"; gid="$(stat -c '%g' "$file")"
  run install -m "$mode" "$tmp" "$file"
  run chown "$uid:$gid" "$file"
  return 0
}

configure_i2pd() {
  [ "$DO_CONFIGURE_I2PD" = "1" ] || return 0
  [ -n "$I2PD_CONF" ] || I2PD_CONF="/etc/i2pd/i2pd.conf"
  if [ ! -f "$I2PD_CONF" ]; then
    warn "$I2PD_CONF is not there after installation; enable SAM by hand: [sam] enabled = true, address = 127.0.0.1, port = 7656"
    return 0
  fi
  step "Configuring i2pd: $I2PD_CONF"
  [ -f "$I2PD_CONF.syndichan.bak" ] || run cp -p "$I2PD_CONF" "$I2PD_CONF.syndichan.bak"
  local changed=0
  # SAM is on by default in i2pd >= 2.28, so most of these are assertions. Assert
  # anyway: the failure mode is a config where somebody uncommented
  # enabled = false, invisible from outside until the node dies at startup.
  i2pd_set_key sam enabled true "$I2PD_CONF" && changed=1
  i2pd_set_key sam address 127.0.0.1 "$I2PD_CONF" && changed=1
  i2pd_set_key sam port 7656 "$I2PD_CONF" && changed=1
  i2pd_set_key httpproxy enabled true "$I2PD_CONF" && changed=1
  i2pd_set_key httpproxy address 127.0.0.1 "$I2PD_CONF" && changed=1
  i2pd_set_key httpproxy port 4444 "$I2PD_CONF" && changed=1
  # i2pd's stock outproxy is the placeholder http://false.i2p, so clearnet
  # fetches through the proxy fail on a default install even with SAM healthy.
  # Replaced only while it is still that placeholder.
  if grep -qE '^[[:space:]]*outproxy[[:space:]]*=[[:space:]]*http' "$I2PD_CONF" &&
     ! grep -qE '^[[:space:]]*outproxy[[:space:]]*=.*false\.i2p' "$I2PD_CONF"; then
    note "keeping the outproxy already configured in $I2PD_CONF"
  else
    i2pd_set_key httpproxy outproxy http://exit.stormycloud.i2p "$I2PD_CONF" && changed=1
  fi
  [ "$changed" = "0" ] && note "already configured; nothing changed"
  return 0
}

start_router() {
  [ -n "$ROUTER_UNIT" ] || return 0
  [ "$SERVICE_MGR" != "none" ] || { warn "no service manager; start your I2P router yourself"; return 0; }
  if [ "$DO_ENABLE_ROUTER" = "1" ]; then
    step "Enabling $ROUTER_UNIT on boot"
    service_enable "$ROUTER_UNIT" || warn "could not enable $ROUTER_UNIT"
  fi
  [ "$DO_START_ROUTER" = "1" ] || return 0
  # `restart` ONLY when this script actually changed the router's config.
  # Restarting somebody's healthy router drops every tunnel it has built, and
  # "SAM is off" is not a reason to do that to them.
  if [ "$DO_CONFIGURE_I2PD" = "1" ]; then
    step "Restarting $ROUTER_UNIT (its configuration changed)"
    service_restart "$ROUTER_UNIT" || warn "could not restart $ROUTER_UNIT"
  else
    step "Starting $ROUTER_UNIT"
    service_start "$ROUTER_UNIT" || warn "could not start $ROUTER_UNIT"
  fi
  return 0
}

start_docker() {
  [ "$DO_ENABLE_DOCKER" = "1" ] || return 0
  local unit="$DOCKER_UNIT"
  if [ -z "$unit" ]; then
    case "$SERVICE_MGR" in openrc) unit="docker" ;; *) unit="docker.service" ;; esac
  fi
  step "Enabling and starting $unit"
  service_enable "$unit" || warn "could not enable $unit"
  service_start "$unit" || warn "could not start $unit"
  return 0
}

# --- Go bootstrap -----------------------------------------------------------

# HTTPS only, certificates always verified. If you are ever tempted to add -k or
# --no-check-certificate here: this function downloads a compiler, as root.
fetch_to() { # URL OUTFILE
  if have curl; then
    run curl -fsSL --proto '=https' --tlsv1.2 --max-time 900 --retry 2 -o "$2" "$1"
  elif have wget; then
    run wget -q -O "$2" "$1"
  else
    return 127
  fi
}

bootstrap_go() {
  [ "$DO_BOOTSTRAP_GO" = "1" ] || return 0
  local work index entry tarball sha url staging actual spec where want avail

  # ~250 MB compressed, ~1 GB unpacked. A download that runs out of disk halfway
  # hashes to something indistinguishable from tampering, so check first.
  work="$(workdir)"
  for spec in "$work:1500" "/usr/local:1500"; do
    where="${spec%%:*}"; want="${spec##*:}"
    avail="$(free_mib "$where")"
    if [ -n "$avail" ] && [ "$avail" -lt "$want" ]; then
      die "only ${avail} MiB free on the filesystem holding $where; the Go toolchain needs about ${want} MiB. Free space, or build elsewhere and pass --binary PATH."
    fi
  done

  step "Fetching the Go release index from https://go.dev/dl/?mode=json"
  index="$work/go-dl.json"
  fetch_to 'https://go.dev/dl/?mode=json' "$index" ||
    die "could not download the Go release index. This machine needs outbound HTTPS to go.dev, or build elsewhere and pass --binary PATH."
  [ -s "$index" ] || die "the Go release index came back empty"

  # The index is a JSON array of releases, newest stable first, each with a flat
  # "files" array. Stripping whitespace and splitting on '{' puts one file per
  # line, so the FIRST match is the newest stable build for this architecture.
  # `grep -m1` closes the pipe early -- harmless only because pipefail is off.
  entry="$(tr -d ' \n\t' <"$index" | tr '{' '\n' |
    grep -m1 "\"filename\":\"go[0-9][0-9.]*\.linux-$GOARCH\.tar\.gz\",\"os\":\"linux\",\"arch\":\"$GOARCH\",.*\"kind\":\"archive\"")" || true
  [ -n "$entry" ] || die "no linux-$GOARCH archive in the Go release index. Install Go yourself, or pass --binary PATH."

  tarball="$(printf '%s' "$entry" | sed -n 's/.*"filename":"\([^"]*\)".*/\1/p')"
  sha="$(printf '%s' "$entry" | sed -n 's/.*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p')"
  # Nothing from the network is used before it is checked: the filename becomes
  # part of a URL and a path, and the digest is the only thing between a
  # compromised mirror and root on this machine.
  case "$tarball" in
    go[0-9]*".linux-$GOARCH.tar.gz") ;;
    *) die "the Go index offered an unexpected filename: '$tarball'. Refusing to download it." ;;
  esac
  case "$sha" in
    ""|*[!0-9a-f]*) die "the Go index carried no usable SHA-256 for $tarball. Refusing to install an unverified toolchain." ;;
  esac
  [ "${#sha}" -eq 64 ] || die "malformed SHA-256 for $tarball"

  url="https://go.dev/dl/$tarball"
  step "Downloading $tarball"
  note "expected SHA-256: $sha"
  fetch_to "$url" "$work/$tarball" || die "download failed: $url"

  step "Verifying SHA-256"
  actual="$(sha256sum "$work/$tarball" | awk '{print $1}')"
  if [ "$actual" != "$sha" ]; then
    rm -f -- "$work/$tarball"
    die "SHA-256 MISMATCH for $tarball
    expected $sha  (from https://go.dev/dl/?mode=json)
    actual   $actual
The download was discarded and nothing was installed. Do not retry blindly:
this is either a corrupted transfer or a tampered mirror."
  fi
  note "verified: $actual"

  # Unpacked into a staging directory on the same filesystem, then moved, so a
  # failure never leaves a half-populated /usr/local/go that a later run would
  # refuse to touch.
  [ -e "$GO_ROOT_DEST" ] && die "$GO_ROOT_DEST appeared while this was running; refusing to overwrite it"
  # A sibling of the destination, so the final mv is a rename within one
  # filesystem and cannot half-succeed.
  staging="$(dirname "$GO_ROOT_DEST")/.syndichan-go-unpack.$$"
  run rm -rf -- "$staging"
  run mkdir -p -- "$staging"
  step "Unpacking to $GO_ROOT_DEST"
  # The official linux tarballs are statically linked (verified against
  # go1.25.12.linux-amd64: `file bin/go` says "statically linked"), so they run
  # on musl/Alpine as well as glibc. The node is built CGO_ENABLED=0, so no C
  # toolchain is needed either.
  run tar -C "$staging" -xzf "$work/$tarball"
  [ -x "$staging/go/bin/go" ] || { run rm -rf -- "$staging"; die "the Go archive did not contain go/bin/go"; }
  run mv -- "$staging/go" "$GO_ROOT_DEST"
  run rmdir -- "$staging"

  # Only if the name is free. An operator's own Go is never shadowed: detect_go
  # would have used it, and this link is skipped if anything holds the path.
  if [ ! -e "$GO_BIN_LINK" ]; then
    run ln -s "$GO_ROOT_DEST/bin/go" "$GO_BIN_LINK"
    note "$GO_BIN_LINK -> $GO_ROOT_DEST/bin/go (scripts/update-from-github.sh needs go on PATH)"
  else
    note "$GO_BIN_LINK already exists; left alone. Put $GO_ROOT_DEST/bin on PATH yourself."
  fi
  GO_CMD="$GO_ROOT_DEST/bin/go"
  note "installed $("$GO_CMD" version)"
  return 0
}

build_binary() {
  [ "$DO_BUILD_BINARY" = "1" ] || return 0
  [ -n "$GO_CMD" ] || die "internal error: asked to build with no Go toolchain"
  # The build reaches another user's shell through `sh -c`, so paths are
  # single-quoted. A checkout path containing a single quote would escape that.
  case "$REPO_ROOT" in
    *"'"*) die "the checkout path contains a single quote and cannot be built from safely: $REPO_ROOT" ;;
  esac
  step "Building syndichan-node from $REPO_ROOT"
  # GOTOOLCHAIN=auto explicitly, so `go env -w GOTOOLCHAIN=local` on this
  # machine cannot break the build: go.mod pins go 1.25.12 and any Go from 1.21
  # up fetches exactly that on demand.
  local build="cd '$REPO_ROOT' && CGO_ENABLED=0 GOTOOLCHAIN=auto '$GO_CMD' build -trimpath -ldflags='-s -w' -o '$REPO_ROOT/syndichan-node' ./cmd/syndichan-node"
  # As the human who invoked the script, never root: a root-owned GOCACHE and
  # root-owned objects inside somebody's checkout outlive the install and show
  # up later as a build that fails for the account owning the source.
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ] && have runuser; then
    run runuser -u "$SUDO_USER" -- sh -c "$build"
  else
    warn "building as root; the build cache and output will be root-owned"
    run sh -c "$build"
  fi
  BINARY_RESOLVED="$REPO_ROOT/syndichan-node"
  return 0
}

create_user_and_dirs() {
  [ "$INSTALL_SERVICE" = "1" ] || return 0
  if [ "$DO_CREATE_USER" = "1" ]; then
    step "Creating system user $NODE_USER"
    local nologin="/usr/sbin/nologin"
    [ -x "$nologin" ] || nologin="/sbin/nologin"
    [ -x "$nologin" ] || nologin="/bin/false"
    if have useradd; then
      run useradd --system --home-dir "$DATA_DIR" --shell "$nologin" "$NODE_USER"
    elif adduser --help 2>&1 | grep -q -- '--system'; then
      # Debian's adduser (a perl script), which takes long options.
      run adduser --system --home "$DATA_DIR" --no-create-home --disabled-password --shell "$nologin" "$NODE_USER"
    elif have adduser; then
      # busybox adduser (Alpine): completely different flags, and the long ones
      # are silently misparsed rather than rejected. -S system, -H no home dir,
      # -D no password.
      run adduser -S -H -D -h "$DATA_DIR" -s "$nologin" "$NODE_USER"
    else
      die "no useradd/adduser here; create the $NODE_USER system account yourself and re-run"
    fi
    NODE_GROUP="$(id -gn "$NODE_USER" 2>/dev/null || echo "$NODE_USER")"
  fi

  # Re-checked immediately before the only chown this script performs, because
  # DETECT ran minutes ago and the plan the operator agreed to said "empty, or
  # already ours".
  if [ -L "$DATA_DIR" ] || { [ -e "$DATA_DIR" ] && [ ! -d "$DATA_DIR" ]; }; then
    die "$DATA_DIR is not a plain directory; refusing to chown it"
  fi
  if [ -d "$DATA_DIR" ]; then
    local owner; owner="$(stat -c '%U' "$DATA_DIR")"
    if [ "$owner" != "$NODE_USER" ] && [ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; then
      die "$DATA_DIR is not empty and is owned by '$owner'; refusing to chown it"
    fi
  fi

  step "Preparing $DATA_DIR"
  run mkdir -p -- "$(dirname "$DATA_DIR")"
  # The LEAF only. Never chown -R: even a mistake past every guard above then
  # touches exactly one inode. install -d + chown rather than install -d -o/-g
  # because busybox's install rejects some -o/-g forms; chown is universal.
  # No `--`: busybox install does not accept it, and DATA_DIR is absolute.
  run install -d -m 0700 "$DATA_DIR"
  run chown "$NODE_USER:$NODE_GROUP" "$DATA_DIR"

  # The directory an EXISTING config points data_dir at. It is about to be named
  # in ReadWritePaths, so it has to exist -- a ReadWritePaths= entry that does
  # not exist makes systemd refuse to start the unit at all.
  #
  # It gets the SAME guards $DATA_DIR gets, not weaker ones. The difference is
  # what happens when it fails them: this path is the operator's, chosen before
  # this installer ran, usually with the node's own data already in it, so
  # failing a guard means "leave it exactly as it is and say so", not "abort the
  # install". Nothing here is ever chowned recursively either.
  if [ -z "$RUNTIME_DATA_DIR" ] || [ "$RUNTIME_DATA_DIR" = "$DATA_DIR" ]; then
    return 0
  fi
  if [ -L "$RUNTIME_DATA_DIR" ]; then
    warn "data_dir in $CONFIG_FILE ($RUNTIME_DATA_DIR) is a SYMLINK; refusing to chown through it, leaving it alone"
  elif [ -e "$RUNTIME_DATA_DIR" ] && [ ! -d "$RUNTIME_DATA_DIR" ]; then
    die "data_dir in $CONFIG_FILE ($RUNTIME_DATA_DIR) exists and is not a directory"
  elif [ ! -e "$RUNTIME_DATA_DIR" ]; then
    step "Preparing $RUNTIME_DATA_DIR (data_dir from $CONFIG_FILE)"
    run mkdir -p -- "$(dirname "$RUNTIME_DATA_DIR")"
    run install -d -m 0700 "$RUNTIME_DATA_DIR"
    run chown "$NODE_USER:$NODE_GROUP" "$RUNTIME_DATA_DIR"
  else
    local rowner; rowner="$(stat -c '%U' "$RUNTIME_DATA_DIR" 2>/dev/null || echo "?")"
    if [ "$rowner" = "$NODE_USER" ]; then
      note "$RUNTIME_DATA_DIR (data_dir from $CONFIG_FILE) already belongs to $NODE_USER"
    elif [ -z "$(ls -A "$RUNTIME_DATA_DIR" 2>/dev/null)" ]; then
      step "Taking ownership of the empty $RUNTIME_DATA_DIR (data_dir from $CONFIG_FILE)"
      run chown "$NODE_USER:$NODE_GROUP" "$RUNTIME_DATA_DIR"
    else
      # Mode left alone as well: 0700 on a directory somebody else populated is
      # a change they did not ask for and cannot easily notice.
      warn "$RUNTIME_DATA_DIR (data_dir in $CONFIG_FILE) is not empty and is owned by '$rowner', not '$NODE_USER': NOT chowning it."
      note "it IS in the unit's ReadWritePaths, so systemd will allow writes there."
      note "make sure $NODE_USER can write to it: runuser -u $NODE_USER -- test -w '$RUNTIME_DATA_DIR'"
    fi
  fi
  return 0
}

install_binary() {
  [ -n "$BINARY_RESOLVED" ] || return 0
  step "Installing $BIN_DEST"
  # Replacing a running binary in place gives ETXTBSY. The enable/restart at the
  # end brings it back; the "boot service" plan row says so.
  case "$SERVICE_MGR" in
    systemd) systemctl is-active --quiet syndichan-node.service 2>/dev/null &&
               { run systemctl stop syndichan-node.service || true; } ;;
    openrc)  [ -f "$OPENRC_PATH" ] && { run rc-service syndichan-node stop || true; } ;;
  esac
  run install -d -m 0755 "$PREFIX/bin"
  run install -m 0755 "$BINARY_RESOLVED" "$BIN_DEST"
  return 0
}

create_config() {
  [ "$INSTALL_SERVICE" = "1" ] || return 0
  # Minted BY THE NODE, AS THE SERVICE USER. LoadOrCreate writes config.json mode
  # 0600 owned by whoever runs it, sets data_dir to the config file's directory,
  # and generates the S3 credentials -- so a root-generated config is a file the
  # service cannot read, holding keys nobody asked for. -show-config, not
  # -config-path: both create the file without binding a listener, but
  # applyHeadlessFlags checks printPath FIRST and returns before -payout /
  # -capacity-gib / -ui-listen are applied.
  local args=()
  [ -n "$PAYOUT" ] && args+=(-payout "$PAYOUT")
  [ -n "$CAPACITY_GIB" ] && args+=(-capacity-gib "$CAPACITY_GIB")
  [ -n "$UI_LISTEN" ] && args+=(-ui-listen "$UI_LISTEN")
  step "Creating/updating $CONFIG_FILE as $NODE_USER"
  run_as_node "$BIN_DEST" -config "$CONFIG_FILE" ${args[@]+"${args[@]}"} -show-config >/dev/null ||
    warn "the node refused the configuration; run it by hand to see why:
    runuser -u $NODE_USER -- env HOME='$DATA_DIR' $BIN_DEST -config '$CONFIG_FILE' -show-config"
  return 0
}

install_wait_helper() {
  [ "$INSTALL_SERVICE" = "1" ] || return 0
  step "Installing $WAIT_HELPER"
  local tmp; tmp="$(workdir)/wait-for-sam"
  cat >"$tmp" <<'HELPER'
#!/usr/bin/env bash
set -u
# Wait for the local I2P SAM bridge, then exit 0. Run before the node starts.
#
# The node has NO startup retry: p2p.Open -> i2p.Open -> connectSAM fails,
# main.go calls logger.Fatal, and the process is gone. After= only orders
# against the ROUTER, which is up long before its SAM bridge (Java I2P delays
# SAM by 120s while the console answers immediately). So this probes SAM itself
# with the same HELLO exchange internal/i2p/sam.go performs -- never the console
# on 7657/7070. Safe to run by hand: `wait-for-sam 30`.
budget="${1:-300}"
waited=0
while :; do
  line=""
  if { exec 3<>/dev/tcp/127.0.0.1/7656; } 2>/dev/null; then
    if printf 'HELLO VERSION MIN=3.1 MAX=3.3\n' >&3 2>/dev/null && IFS= read -r -t 10 line <&3; then
      exec 3>&-
      case "$line" in
        "HELLO REPLY"*RESULT=OK*)
          echo "syndichan: I2P SAM bridge ready after ${waited}s"
          exit 0 ;;
        *)
          # Something owns 7656 and does not speak SAM. Waiting cannot fix a
          # port collision, and pretending otherwise hides it.
          echo "syndichan: 127.0.0.1:7656 is not a SAM bridge: ${line}" >&2
          exit 1 ;;
      esac
    fi
    exec 3>&-
  fi
  if [ "$waited" -ge "$budget" ]; then
    echo "syndichan: I2P SAM bridge did not answer within ${budget}s" >&2
    exit 1
  fi
  sleep 2
  waited=$((waited + 2))
done
HELPER
  run install -d -m 0755 "$PREFIX/lib/syndichan"
  run install -m 0755 "$tmp" "$WAIT_HELPER"
  return 0
}

# EVERY interpolated path is quoted. systemd honours double quotes in Exec
# lines, Environment= and ReadWritePaths=, and a data directory containing a
# space silently truncated all three before this was fixed. Characters systemd
# cannot express at all (% and quotes and backslashes) are refused at parse time.
generate_unit() {
  local wants="network-online.target"
  [ -n "$ROUTER_UNIT" ] && wants="$wants $ROUTER_UNIT"
  # Defensive: every path in here is one resolve_runtime_data_dir already
  # checked, and a unit rendered without it would silently re-create the exact
  # bug the ReadWritePaths comment below describes.
  local rw="$RW_PATHS" warning=""
  [ -n "$rw" ] || rw="\"$DATA_DIR\""
  if [ "$RUNTIME_DATA_DIR_UNKNOWN" = "1" ]; then
    warning="# WARNING: the data_dir in $CONFIG_FILE could not be
# used when this unit was written ($CONFIG_STATE). If it is NOT $DATA_DIR,
# the node will fail to write with a \"read-only file system\" error that names
# the filesystem and never mentions this sandbox. Fix it with a drop-in rather
# than by editing this file (which the installer would then refuse to refresh):
#   systemctl edit syndichan-node   ->   [Service]
#                                        ReadWritePaths=<the data_dir>
"
  fi
  cat <<EOF
[Unit]
Description=Syndichan encrypted volunteer storage and edge node
Documentation=https://github.com/Jonathan-R-Anderson/syndichan/tree/main/storage-client
Wants=$wants
After=$wants
# Wants=, not Requires=. Requires=i2pd.service (as the shipped packaging unit
# has it) fails the node outright where the router is i2p.service, and takes the
# node down with the router on every restart. Ordering plus the readiness wait
# below does the same job without the shared fate. The rate limit is generous
# because a cold router can outlast the node's 75s SAM timeout building its
# first tunnels.
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
ExecStartPre=$WAIT_HELPER $SAM_WAIT_SECONDS
# The node registers exactly six flags: -config, -payout, -capacity-gib,
# -ui-listen, -show-config, -config-path. -data-dir exits 2.
ExecStart=$BIN_DEST -config "$CONFIG_FILE"
Restart=on-failure
RestartSec=15s
# Longer than systemd's 90s default: the wait above legitimately takes ~120s on
# a Java router, and a start job killed mid-wait fails a unit that was fine.
TimeoutStartSec=$((SAM_WAIT_SECONDS + 120))
TimeoutStopSec=75s
LimitNOFILE=65535

# Only low-port binding, and only for the gateway role. The process is not root.
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
MemoryDenyWriteExecute=true
# ProtectSystem=strict makes the WHOLE filesystem read-only to this service,
# mount options be damned, so this list is the only thing that lets the node
# write at all. It names the DATA DIRECTORIES THEMSELVES, never <dir>/storage:
# i2p.destination, p2p.key and content.key are written BESIDE storage/, and a
# unit that lists only the subdirectory fails on the second file instead of the
# first. The first entry holds config.json (which the management page rewrites)
# and is \$HOME; the second, when present, is the data_dir the config names.
${warning}ReadWritePaths=$rw

[Install]
WantedBy=multi-user.target
EOF
  return 0
}

generate_compute_dropin() {
  # SupplementaryGroups= naming a group that does not exist makes systemd REFUSE
  # TO START the unit, so the list is built from the groups this machine has.
  # The docker group is whatever owns the socket here, not the name "docker"
  # taken on faith.
  local groups="" g wanted="$DOCKER_GROUP"
  # kvm only for the microVM path. A node that merely runs containers has no use
  # for /dev/kvm, and a supplementary group it never needs is privilege granted
  # for the sake of symmetry.
  [ "$WANT_COMPUTE" = "1" ] && wanted="$wanted kvm"
  for g in $wanted; do
    [ -n "$g" ] || continue
    getent group "$g" >/dev/null 2>&1 && groups="$groups $g"
  done
  groups="${groups# }"
  cat <<EOF
# Compute/DCS access for syndichan-node.
#
# HARDENING GIVEN UP HERE, out loud:
#   - the docker group is root-equivalent by design. A node that lends compute
#     is trusting the container runtime with the machine; that is the deal.
#
# SupplementaryGroups= is belt AND braces: the installer also adds the service
# account to the group, but that only takes effect at the next exec, and a unit
# whose access depends on somebody remembering to restart it is the kind of
# thing that comes back as "compute silently stopped working".
[Service]
${groups:+SupplementaryGroups=$groups}
# ProtectSystem=strict leaves /run read-only. Connecting to a unix socket is not
# a filesystem write -- the kernel exempts sockets from the read-only-mount check
# (sb_permission only refuses REG/DIR/LNK), so this line is not what makes the
# socket reachable; group membership is. It is here because "should be fine" is
# not how an operator wants to find out.
#
# The leading '-' is load-bearing: a ReadWritePaths= entry that does not exist
# makes systemd REFUSE TO START the whole unit, and a node that will not boot
# because Docker is not installed yet is a far worse failure than a compute role
# that is switched off. /run/docker.sock, not /var/run/docker.sock: systemd
# resolves the path itself and /var/run is the symlink.
ReadWritePaths=-/run/docker.sock
EOF
  # Only the microVM path needs these, and each one is a real reduction in
  # isolation, so they are not written for a node that merely runs containers.
  [ "$WANT_COMPUTE" = "1" ] && cat <<EOF
# --with-compute (microVM/firecracker) only:
#   - PrivateDevices=true gives a private /dev with no /dev/kvm, so microVM
#     isolation could never be advertised. The service now sees the real /dev.
#   - MemoryDenyWriteExecute: firecracker children need W^X relaxed.
PrivateDevices=false
DeviceAllow=/dev/kvm rw
MemoryDenyWriteExecute=false
EOF
  return 0
}

generate_openrc() {
  # OpenRC equivalent of the systemd unit, with the same three guarantees: runs
  # as the dedicated non-root user, waits for SAM before starting, restarts when
  # it dies. supervise-daemon rather than start-stop-daemon because the node has
  # no internal retry -- it is what Restart=on-failure buys on the systemd side.
  #
  # OpenRC has NO equivalent of the systemd hardening block: ProtectSystem,
  # PrivateDevices and the rest are namespace features systemd sets up itself.
  # Stated rather than faked -- an OpenRC node runs with less isolation.
  cat <<EOF
#!/sbin/openrc-run
name="syndichan-node"
description="Syndichan encrypted volunteer storage and edge node"

command="$BIN_DEST"
command_args="-config '$CONFIG_FILE'"
command_user="$NODE_USER:$NODE_GROUP"
command_background=false
supervisor=supervise-daemon
respawn_delay=15
respawn_max=0
pidfile="/run/syndichan-node.pid"
# config.Default() calls os.UserConfigDir() unconditionally, so a missing HOME
# makes the node exit before it reads the -config file it was handed.
export HOME="$DATA_DIR"

depend() {
	need net
	after $( [ -n "\$ROUTER_UNIT" ] && printf '%s' "i2pd" || printf '%s' "i2pd i2p" )
}

start_pre() {
	# The node has no startup retry: if SAM is not up, it calls log.Fatal and
	# dies. Wait for the bridge itself -- never the console on 7657/7070, which
	# answers up to two minutes before SAM does.
	"$WAIT_HELPER" $SAM_WAIT_SECONDS || return 1
}
EOF
  return 0
}

install_unit() {
  [ "$INSTALL_SERVICE" = "1" ] || { note "skipping the boot service (--no-service)"; return 0; }
  case "$SERVICE_MGR" in
    systemd) install_systemd_unit ;;
    openrc)  install_openrc_service ;;
    *)
      warn "no service manager here. Start the node with:"
      say "    su -s /bin/sh -c \"env HOME='$DATA_DIR' $BIN_DEST -config '$CONFIG_FILE'\" $NODE_USER"
      ;;
  esac
  return 0
}

# install_managed FILE MODE GENERATOR -- write a service file, never over one
# somebody else edited. The marker records the hash of the body we last wrote;
# if the file still hashes to that, this script wrote it and may replace it. If
# not, somebody edited it -- possibly to fix something -- and overwriting that
# silently is how an installer destroys a working machine. Returns 0 if the file
# is ours, 1 if it is the operator's and was left alone.
install_managed() {
  local target="$1" mode="$2" gen="$3" body hash tmp recorded existing
  body="$("$gen")"
  hash="$(printf '%s\n' "$body" | sha_of)"
  if [ -f "$target" ]; then
    recorded="$(sed -n "s|^${MARKER_PREFIX}||p" "$target" | head -1)"
    existing="$(grep -v "^${MARKER_PREFIX}" "$target" | sha_of)"
    if [ -z "$recorded" ] || [ "$recorded" != "$existing" ]; then
      # /run, not the scratch directory, so it outlives this process for the
      # operator to diff, and disappears at reboot rather than accumulating.
      tmp="/run/$(basename "$target").proposed"
      printf '%s\n' "$body" >"$tmp"
      warn "$target was written or edited by somebody else; NOT overwriting it."
      note "the file this installer would write is at: $tmp"
      note "compare with: diff -u '$target' '$tmp'"
      return 1
    fi
    if [ "$existing" = "$hash" ]; then
      note "$target is already current"
      return 0
    fi
  fi
  step "Writing $target"
  tmp="$(workdir)/$(basename "$target")"
  { printf '%s%s\n' "$MARKER_PREFIX" "$hash"; printf '%s\n' "$body"; } >"$tmp"
  run install -m "$mode" "$tmp" "$target"
  return 0
}

install_openrc_service() {
  # Their file is kept if they edited it, but the service is still enabled and
  # started: the operator asked for a node that comes back after a reboot, and
  # refusing to overwrite their script is not a reason to leave it disabled.
  install_managed "$OPENRC_PATH" 0755 generate_openrc || true
  step "Enabling syndichan-node on boot (OpenRC)"
  run rc-update add syndichan-node default || warn "could not 'rc-update add syndichan-node default'"
  run rc-service syndichan-node restart ||
    warn "the service did not start; see /var/log/rc.log and 'rc-service syndichan-node status'"
  return 0
}

install_systemd_unit() {
  # Their unit is kept if they edited it, but the service is still enabled and
  # restarted -- see install_openrc_service for why.
  if install_managed "$UNIT_PATH" 0644 generate_unit; then
    run systemctl daemon-reload
  fi
  # Outside the branch above on purpose: an operator's hand-written unit still
  # runs as $NODE_USER and still needs the socket, and skipping the drop-in
  # because the unit was not ours is how compute ends up half-configured.
  install_compute_dropin
  step "Enabling syndichan-node on boot"
  run systemctl enable syndichan-node.service
  run systemctl restart syndichan-node.service ||
    warn "the service did not start; see: journalctl -u syndichan-node -n 50"
  return 0
}

# systemd only: the drop-in exists to undo systemd's own sandboxing. OpenRC
# applies none of it, so there is nothing to relax there.
install_compute_dropin() {
  [ "$NEEDS_DOCKER" = "1" ] || return 0
  [ "$SERVICE_MGR" = "systemd" ] || return 0
  local tmp; tmp="$(workdir)/10-compute.conf"
  generate_compute_dropin >"$tmp"
  if [ ! -f "$UNIT_DROPIN" ] || ! cmp -s "$tmp" "$UNIT_DROPIN"; then
    step "Writing $UNIT_DROPIN (relaxes hardening for compute -- read the comments in it)"
    run install -d -m 0755 "$(dirname "$UNIT_DROPIN")"
    run install -m 0644 "$tmp" "$UNIT_DROPIN"
  fi
  run systemctl daemon-reload
  return 0
}

# Group membership is what actually opens the docker socket; on systemd the
# drop-in only makes systemd apply it. Manager-independent, so it lives here
# rather than inside the systemd path -- which is where it used to hide, giving
# Alpine a plan row that promised something ACT never did.
add_docker_group() {
  [ "$DO_ADD_DOCKER_GROUP" = "1" ] || return 0
  [ -n "$DOCKER_GROUP" ] || return 0
  step "Adding $NODE_USER to the '$DOCKER_GROUP' group (root-equivalent)"
  if have usermod; then
    run usermod -aG "$DOCKER_GROUP" "$NODE_USER" || warn "could not add $NODE_USER to the '$DOCKER_GROUP' group"
  elif have addgroup; then
    run addgroup "$NODE_USER" "$DOCKER_GROUP" || warn "could not add $NODE_USER to the '$DOCKER_GROUP' group"  # busybox
  else
    warn "no usermod/addgroup here; add $NODE_USER to the '$DOCKER_GROUP' group yourself"
  fi
  # Checked, not assumed. Every one of the three branches above can fail in a
  # way that prints something and continues, and the symptom of the failure --
  # a DCS worker that never starts -- appears once in the journal hours later.
  if id -nG "$NODE_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$DOCKER_GROUP"; then
    note "$NODE_USER is now in: $(id -nG "$NODE_USER" 2>/dev/null | tr ' ' ',')"
  else
    warn "$NODE_USER is STILL not in the '$DOCKER_GROUP' group; the DCS worker will log 'Docker is not reachable ... permission denied' and not start"
  fi
  # Membership is read at exec(), so this only reaches a RUNNING node through
  # the restart install_unit does at the end.
  return 0
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

printf '%ssyndichan-node installer%s\n' "$C_BOLD" "$C_RESET"
if [ "$DRY_RUN" = "1" ]; then
  printf '%s--check: detecting only. Nothing on this machine will be changed.%s\n' "$C_DIM" "$C_RESET"
fi

# Order matters in one place: detect_service_user renders the unit to compare it
# against the installed one, and the unit names the router detect_i2p found.
detect_platform
detect_ca_certs
detect_i2p
detect_i2p_proxy
detect_binary
detect_service_user
detect_data_dir
detect_state_conflicts
detect_docker
detect_catalogue_images
detect_kvm

print_plan

if [ "$DRY_RUN" = "1" ]; then
  if [ "$BLOCKED" = "1" ]; then
    say "Blocked: see the 'cannot' row(s) above. The install would refuse to run as configured."
    exit 1
  fi
  if [ "$REQUIRED_MISSING" = "1" ]; then
    say "Some REQUIRED dependencies are missing. Re-run without --check to install them."
    exit 1
  fi
  say "Everything required is present. Re-run without --check to install the node and its service."
  exit 0
fi

[ "$BLOCKED" = "1" ] && die "refusing to install: see the 'cannot' row(s) above. Nothing was changed."
[ "$IS_ROOT" = "1" ] || die "this installer must run as root. Re-run with sudo, or use --check to see the plan without any privilege."

# Consent is asked once, for the whole plan, AFTER it is printed and BEFORE
# anything is touched. Installing software on somebody's machine without asking
# is not acceptable merely because the thing doing it is called an installer --
# and that covers creating a user, editing a router config and writing a systemd
# unit, not only `apt-get install`.
if ! confirm "Proceed with the plan above?"; then
  say "Nothing was changed."
  exit 0
fi

install_packages
configure_i2pd
start_router      # started early, so the router builds tunnels while Go compiles
start_docker
bootstrap_go
build_binary
create_user_and_dirs
add_docker_group
install_binary
create_config
install_wait_helper

step "Waiting for the I2P SAM bridge on 127.0.0.1:7656 (up to ${SAM_WAIT_SECONDS}s)"
sam_rc=0; wait_for_sam "$SAM_WAIT_SECONDS" || sam_rc=$?
case "$sam_rc" in
  0) note "SAM bridge ready" ;;
  3) warn "not starting the node against a port that is not SAM" ;;
  *) warn "the SAM bridge did not answer in ${SAM_WAIT_SECONDS}s."
     note "the service has the same readiness wait built in and will start on its own once the router is ready."
     note "check the router: ${ROUTER_UNIT:-your I2P router}, and http://127.0.0.1:7657 or :7070" ;;
esac

install_unit

printf '\n%sDone.%s\n' "$C_BOLD" "$C_RESET"
if [ "$INSTALL_SERVICE" = "1" ]; then
  case "$SERVICE_MGR" in
    systemd)
      say "  systemctl status syndichan-node       # is it up"
      say "  journalctl -u syndichan-node -f       # what is it doing" ;;
    openrc)
      say "  rc-service syndichan-node status      # is it up"
      say "  tail -f /var/log/rc.log               # what is it doing" ;;
  esac
fi
case "$UI_LISTEN" in
  off|none|OFF|None) say "  (management page disabled; edit $CONFIG_FILE to configure this node)" ;;
  "")                say "  http://127.0.0.1:9090                 # management page (loopback only)" ;;
  *)                 say "  http://$UI_LISTEN/                    # management page" ;;
esac
say "  $0 --check                            # re-run the detection at any time"
if [ -z "$PAYOUT" ]; then
  say ""
  say "No payout address is set: this node will work and earn nothing. Set one on the"
  say "management page, or re-run with --payout 0x..."
fi
