#!/usr/bin/env bash
# Run one build step for the container build (see Dockerfile), and on failure put
# the evidence at the END of the output — right where a truncated paste or a CI tail
# will still show it:
#
#   * the last 150 lines of this step's own output (the compiler/ninja error), and
#   * the tail of the newest meson-log.txt, which is where `meson setup` hides the
#     failing command line and its stderr (the console only gets a one-line summary).
#
# Usage: scripts/docker-build-step.sh make -C deps gtk-stack
set -uo pipefail

log="$(mktemp)"
"$@" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
[ "$rc" -eq 0 ] && exit 0

echo ""
echo "======== FAILED: $* (exit $rc) ========"
echo "======== last 150 lines of that step ========"
tail -150 "$log"

meson_log="$(find deps -name meson-log.txt -printf '%T@ %p\n' 2>/dev/null \
             | sort -rn | head -1 | cut -d' ' -f2-)"
if [ -n "$meson_log" ]; then
    echo "======== tail of $meson_log ========"
    tail -150 "$meson_log"
fi
exit "$rc"
