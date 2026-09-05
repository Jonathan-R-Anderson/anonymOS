#!/usr/bin/env bash
# Assert that named string literals are present in the built ISO, BEFORE booting it.
#
# Why this exists.  "The change is committed, the ISO is newer than the commit, and the
# behaviour did not change" cost roughly four debugging rounds in one session, every one of
# them spent re-deriving from behaviour whether a build had picked an edit up.
#
# Two other approaches were tried and both FAILED -- do not retry them:
#   * grepping the ISO for a C/D COMMENT.  Comments are stripped at compile time, so the grep
#     always returns 0 and proves nothing.  Grep for a string LITERAL the code passes to klog
#     or printf, or for config text staged verbatim.
#   * a __DATE__/__TIME__ build stamp klog'd at boot.  This build is reproducible
#     (SOURCE_DATE_EPOCH), so those macros are frozen: two ISOs built 13 minutes apart, whose
#     kernels demonstrably differed, both printed 18:09:00.
#
# Usage:
#   scripts/iso-verify.sh                          # check the default marker set
#   scripts/iso-verify.sh 'cmpduty' 'fps_x100'     # check specific markers
#   ISO=other.iso scripts/iso-verify.sh ...
#
# Exit 0 = every marker present.  Exit 1 = at least one missing (do not bother booting).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ISO="${ISO:-hos-install.iso}"

if [ ! -f "$ISO" ]; then
    echo "iso-verify: $ISO does not exist — build first (make -C src/kernel/d clean; HYPRLAND=1 make iso)" >&2
    exit 1
fi

# Default markers: one per subsystem that has silently shipped stale at least once.  Each MUST
# be a string literal that survives compilation, or config text staged verbatim into the image.
DEFAULT_MARKERS=(
    'cmpduty'                 # kernel: the compositor duty-cycle probe   (kernel_main.d)
    'fps_x100'                # kernel: calibration-free frame rate       (posix.d)
    'rounding      = 0'       # config: the softpipe decoration override  (custom/general.lua)
    'damage_tracking = 1'     # config: whole-monitor damage              (custom/general.lua)
)

if [ "$#" -gt 0 ]; then
    MARKERS=("$@")
else
    MARKERS=("${DEFAULT_MARKERS[@]}")
fi

# Report the ISO's age against the newest tracked source, since "ISO older than the edit" is the
# other half of this failure.  Informational: a build racing a commit is legitimate.
if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
    newest_src="$(git ls-files -z -- 'src/*' 'system/*' 2>/dev/null \
                  | xargs -0 -r ls -t 2>/dev/null | head -1)"
    if [ -n "${newest_src:-}" ] && [ "$newest_src" -nt "$ISO" ]; then
        echo "iso-verify: WARNING — $newest_src is NEWER than $ISO; this image predates that edit"
    fi
fi

echo "iso-verify: $ISO ($(date -r "$ISO" '+%Y-%m-%d %H:%M:%S'))"

# Build provenance, from the manifest the Makefile stages into the image (A2).  This is the
# strongest available check: it answers "which commit is this image?" exactly, rather than
# inferring it from mtimes.  Absent on images built before A2 landed — that is not a failure.
if manifest="$(grep -aoF -m1 'HOSBUILD commit=' "$ISO" >/dev/null 2>&1 && \
               grep -ao 'HOSBUILD commit=[0-9a-f]*' "$ISO" 2>/dev/null | head -1)"; then
    if [ -n "${manifest:-}" ]; then
        iso_commit="${manifest#HOSBUILD commit=}"
        head_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
        if [ "$iso_commit" = "$head_commit" ]; then
            echo "  built from ${iso_commit:0:12} (== HEAD)"
        else
            echo "  built from ${iso_commit:0:12}  HEAD is ${head_commit:0:12}  <-- IMAGE IS NOT HEAD"
        fi
        if grep -aq 'HOSBUILD dirty=yes' "$ISO" 2>/dev/null; then
            echo "  built from a DIRTY tree (uncommitted changes were included)"
        fi
    fi
fi

fail=0
for m in "${MARKERS[@]}"; do
    # -a: the ISO is binary.  -c: count, so 0 is unambiguous.  -F: the markers contain spaces
    # and '=' and must not be read as patterns.
    n="$(grep -acF -- "$m" "$ISO" 2>/dev/null || true)"
    n="${n:-0}"
    if [ "$n" -gt 0 ]; then
        printf '  \033[32mok\033[0m    %-24s %s hit(s)\n' "$m" "$n"
    else
        printf '  \033[31mMISS\033[0m  %-24s NOT IN THE IMAGE\n' "$m"
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    cat >&2 <<'EOF'

iso-verify: FAILED — at least one marker is absent, so this ISO does not contain the change
under test.  Booting it will produce a log that describes an older build.

  Rebuild:  make -C src/kernel/d clean && HYPRLAND=1 make iso

`make iso` does re-enter the D sub-make (stage-iso-tree depends on kernel.elf, and
build/libkernel_d.a depends on the phony refresh-d-kernel), so a plain `make iso` is usually
enough; the explicit clean is the belt-and-braces version.
EOF
    exit 1
fi

echo "iso-verify: PASS — all ${#MARKERS[@]} marker(s) present"
