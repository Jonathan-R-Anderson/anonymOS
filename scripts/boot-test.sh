#!/usr/bin/env bash
# Boot the ISO headless and assert facts about serial.log.  No human reads a log.
#
# This replaces the pattern each scripts/qemu-g*-verify.sh reimplements by hand.  It drives
# ./qemu-run.sh (rather than duplicating its ~90 lines of disk/NVMe/USB/net device setup) with
# HEADLESS=1, so a test boots exactly the machine a person boots.
#
# Usage:
#   scripts/boot-test.sh                        # tests/desktop-smoke.txt
#   scripts/boot-test.sh tests/my-suite.txt
#   TIMEOUT=240 MEM=2048 scripts/boot-test.sh
#   NO_VERIFY=1 scripts/boot-test.sh            # skip the pre-flight ISO marker check
#
# Suite file syntax (one directive per line, '#' comments, blank lines ignored):
#   require  <text>        must appear at least once   (boot waits for ALL of these)
#   forbid   <text>        must never appear
#   atleast  <n> <text>    must appear >= n times
#   atmost   <n> <text>    must appear <= n times
#
# All matching is FIXED-STRING against a NUL-stripped, ANSI-stripped copy of serial.log
# (serial.log contains NUL bytes, so plain grep reports "binary file matches").
#
# COUNTING CAVEAT, learned the hard way: every Hyprland/aquamarine log line appears TWICE in
# serial.log (bursty replay, not adjacent duplication).  Kernel-emitted lines appear once.  So
# prefer `require`/`forbid` over exact counts on compositor lines, and when you must count one,
# remember the real number is half what grep reports.
#
# Exit 0 = all assertions held.  1 = an assertion failed.  2 = boot/timeout/setup problem.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SUITE="${1:-tests/desktop-smoke.txt}"
TIMEOUT="${TIMEOUT:-180}"
SERIAL="$ROOT/serial.log"
CLEAN="${TMPDIR:-/tmp}/boot-test-clean.$$.log"

[ -f "$SUITE" ] || { echo "boot-test: no such suite: $SUITE" >&2; exit 2; }
[ -f "$ROOT/hos-install.iso" ] || { echo "boot-test: hos-install.iso missing — build first" >&2; exit 2; }

# Pre-flight: a stale ISO makes every assertion below a lie about an older build.
if [ "${NO_VERIFY:-0}" != "1" ] && [ -x "$ROOT/scripts/iso-verify.sh" ]; then
    "$ROOT/scripts/iso-verify.sh" || {
        echo "boot-test: refusing to boot a stale ISO (NO_VERIFY=1 to override)" >&2
        exit 2
    }
    echo
fi

# ── parse the suite ───────────────────────────────────────────────────────────────────────
REQ=(); FORBID=(); AL_N=(); AL_S=(); AM_N=(); AM_S=()
while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%$'\r'}"
    case "$line" in ''|'#'*) continue ;; esac
    verb="${line%%[[:space:]]*}"
    rest="${line#"$verb"}"
    rest="${rest#"${rest%%[![:space:]]*}"}"          # ltrim
    case "$verb" in
        require) REQ+=("$rest") ;;
        forbid)  FORBID+=("$rest") ;;
        atleast|atmost)
            num="${rest%%[[:space:]]*}"
            txt="${rest#"$num"}"; txt="${txt#"${txt%%[![:space:]]*}"}"
            case "$num" in ''|*[!0-9]*) echo "boot-test: bad count in: $line" >&2; exit 2 ;; esac
            if [ "$verb" = atleast ]; then AL_N+=("$num"); AL_S+=("$txt")
            else                           AM_N+=("$num"); AM_S+=("$txt"); fi ;;
        *) echo "boot-test: unknown directive '$verb' in: $line" >&2; exit 2 ;;
    esac
done < "$SUITE"

echo "boot-test: suite=$SUITE  timeout=${TIMEOUT}s  require=${#REQ[@]} forbid=${#FORBID[@]}"

# ── boot ──────────────────────────────────────────────────────────────────────────────────
# A previous QEMU still holding hos-disk.img makes the new one exit instantly with
#     -device ide-hd,...: Failed to get "write" lock.  Is another process using the image?
# and the harness would then poll a serial.log that never grows.  Fail fast and say so.
#
# NB: `pkill -x qemu-system-x86_64` does NOT work — the kernel truncates comm to 15 chars, so
# the name never matches and the stale process silently survives.  Match the full cmdline.
if [ -f "$ROOT/hos-disk.img" ] && command -v fuser >/dev/null 2>&1 \
   && fuser "$ROOT/hos-disk.img" >/dev/null 2>&1; then
    echo "boot-test: hos-disk.img is locked by another process — a previous QEMU is still running." >&2
    echo "boot-test: clear it with:  pkill -f 'qemu-system-x86_64 -boot'" >&2
    exit 2
fi

rm -f "$SERIAL"
RUNLOG="${TMPDIR:-/tmp}/boot-test-qemu.$$.log"

# NET is passed through ONLY when the caller sets it, never defaulted.
#
# It used to default to virtio, which made qemu-run.sh request SLIRP user-networking -- and a
# QEMU built locally for virgl may well not have that compiled in:
#     qemu-system-x86_64: -netdev user,id=net0: network backend 'user' is not compiled into
#     this binary
# QEMU then exits instantly, no serial.log is ever created, and the harness sits polling for
# markers that cannot arrive until it times out.  Networking is not needed to boot the desktop,
# so the default is now "whatever qemu-run.sh does on its own".
#
# And qemu-run.sh's own output goes to a LOG, not /dev/null.  Swallowing it is what hid the
# error above through several rounds of "why is there no serial.log?".
# setsid + kill(-pgid): qemu-run.sh exec's nothing, it launches qemu as its last command, so
# killing the script alone would orphan QEMU and the next run would fight it for the disk.
setsid env HEADLESS=1 MEM="${MEM:-2048}" ${NET:+NET="$NET"} ./qemu-run.sh >"$RUNLOG" 2>&1 &
RUNNER=$!
cleanup() {
    kill -- -"$RUNNER" 2>/dev/null || kill "$RUNNER" 2>/dev/null || true
    wait "$RUNNER" 2>/dev/null || true
    rm -f "$CLEAN"
    # RUNLOG is deliberately KEPT on failure — it is the only record of why QEMU refused to start.
}
trap cleanup EXIT INT TERM

strip_log() { tr -d '\000' < "$SERIAL" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' > "$CLEAN"; }

# `grep -c` PRINTS a count and EXITS 1 when that count is zero.  So the obvious
#     grep -acF ... || echo 0
# emits "0" twice on no-match, and every arithmetic test on the result then dies with
# "integer expression expected".  Capture stdout, ignore the exit status, default if empty.
count_in() {
    local n
    n="$(grep -acF -- "$1" "$CLEAN" 2>/dev/null)" || true
    printf '%s' "${n:-0}"
}

deadline=$(( $(date +%s) + TIMEOUT ))
settled=1
while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 3
    [ -f "$SERIAL" ] || continue
    strip_log
    missing=0
    for m in ${REQ+"${REQ[@]}"}; do
        [ "$(count_in "$m")" -gt 0 ] || { missing=1; break; }
    done
    if [ "$missing" -eq 0 ]; then settled=0; break; fi
done

# Give the desktop a moment past the last required marker so count-based assertions see a
# representative window rather than the instant the last marker appeared.
[ "$settled" -eq 0 ] && sleep "${SETTLE:-10}"
strip_log
cleanup_ran=0

if [ ! -s "$CLEAN" ]; then
    echo "boot-test: FAIL — serial.log is empty or absent; the guest produced no output" >&2
    echo "boot-test: qemu-run.sh said:" >&2
    sed 's/^/    | /' "$RUNLOG" 2>/dev/null | tail -15 >&2
    echo "boot-test: (full runner output: $RUNLOG)" >&2
    exit 2
fi

# ── assert ────────────────────────────────────────────────────────────────────────────────
fail=0
echo
for m in ${REQ+"${REQ[@]}"}; do
    n="$(count_in "$m")"
    if [ "$n" -gt 0 ]; then printf '  \033[32mok\033[0m    require  %-52s %sx\n' "$m" "$n"
    else                    printf '  \033[31mFAIL\033[0m  require  %-52s ABSENT\n' "$m"; fail=1; fi
done
for m in ${FORBID+"${FORBID[@]}"}; do
    n="$(count_in "$m")"
    if [ "$n" -eq 0 ]; then printf '  \033[32mok\033[0m    forbid   %-52s absent\n' "$m"
    else                    printf '  \033[31mFAIL\033[0m  forbid   %-52s %sx\n' "$m" "$n"; fail=1; fi
done
i=0
for m in ${AL_S+"${AL_S[@]}"}; do
    want="${AL_N[$i]}"; n="$(count_in "$m")"; i=$((i+1))
    if [ "$n" -ge "$want" ]; then printf '  \033[32mok\033[0m    atleast  %-52s %s >= %s\n' "$m" "$n" "$want"
    else                          printf '  \033[31mFAIL\033[0m  atleast  %-52s %s < %s\n' "$m" "$n" "$want"; fail=1; fi
done
i=0
for m in ${AM_S+"${AM_S[@]}"}; do
    want="${AM_N[$i]}"; n="$(count_in "$m")"; i=$((i+1))
    if [ "$n" -le "$want" ]; then printf '  \033[32mok\033[0m    atmost   %-52s %s <= %s\n' "$m" "$n" "$want"
    else                          printf '  \033[31mFAIL\033[0m  atmost   %-52s %s > %s\n' "$m" "$n" "$want"; fail=1; fi
done

echo
if [ "$settled" -ne 0 ]; then
    echo "boot-test: TIMEOUT after ${TIMEOUT}s — not every 'require' marker appeared." >&2
    echo "boot-test: the assertions above show which; serial.log is kept for inspection." >&2
    exit 1
fi
if [ "$fail" -ne 0 ]; then
    echo "boot-test: FAIL — see the lines marked FAIL above.  serial.log is kept." >&2
    exit 1
fi
echo "boot-test: PASS"
