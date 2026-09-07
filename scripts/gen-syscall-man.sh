#!/usr/bin/env bash
# Generate section-2 man pages for every syscall this kernel dispatches.
#
# GENERATED, not hand-written, and deliberately so: docs/SYSCALL_ABI.md was written by hand and
# already claims "160 syscalls" against 177 dispatch arms.  A reference that drifts from the kernel
# is worse than none, because an admin cannot tell which half is lying.  This reads the dispatch
# table and the implementations as the source of truth, so regenerating is the only way to update.
#
#   usage: scripts/gen-syscall-man.sh [outdir]     (default docs/man2)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/docs/man2}"
KM="$ROOT/src/kernel/d/core/kernel_main.d"
PX="$ROOT/src/kernel/d/core/syscalls/posix.d"
mkdir -p "$OUT" "$OUT/../man7"
DATE="$(date +%Y-%m-%d)"

# number -> handler, from the dispatch table.  Handles both "case N: return f(...)" and the
# grouped "case A: case B: return f(...)" form, where several numbers share one handler.
awk '
  /^[ \t]*case [0-9]+:/ {
      n = $0; sub(/^[ \t]*case /, "", n); sub(/:.*/, "", n)
      pending[++np] = n
  }
  /return linux_sys_[a-z0-9_]+/ {
      h = $0; sub(/.*return /, "", h); sub(/\(.*/, "", h)
      for (i = 1; i <= np; i++) print pending[i] "\t" h
      np = 0
  }
  /^[ \t]*case [0-9]+:[ \t]*\{/ { np = np }   # block form: keep collecting
' "$KM" | sort -n -u > /tmp/syscall-map.tsv

COUNT=0
while IFS=$'\t' read -r num handler; do
    [ -z "$handler" ] && continue
    name="${handler#linux_sys_}"
    page="$OUT/${name}.2"
    # The comment block immediately above the implementation is the authored description.
    desc="$(awk -v fn="public long $handler(" '
        index($0, fn) { for (i = 1; i <= nc; i++) print buf[i]; exit }
        /^\/\// || /^[ \t]*\/\// { buf[++nc] = $0; next }
        { nc = 0 }
    ' "$PX" | sed 's|^[ \t]*//[ ]\?||' | head -40)"
    # Fall back to the DISPATCH site: many arms carry the explanatory comment there instead of at
    # the implementation, either as a trailing comment on the case line or a block above it.
    if [ -z "$desc" ]; then
        desc="$(awk -v h="return $handler(" '
            index($0, h) {
                if (match($0, /\/\/.*$/)) print substr($0, RSTART)
                for (i = 1; i <= nc; i++) print buf[i]
                exit
            }
            /^[ \t]*\/\// { buf[++nc] = $0; next }
            /^[ \t]*case [0-9]+:/ { next }          # keep the block across grouped cases
            { nc = 0 }
        ' "$KM" | sed 's|^[ \t]*//[ ]\?||' | head -30)"
    fi
    [ -z "$desc" ] && desc="No implementation notes recorded in the source for this call.  The
call is dispatched and implemented; see IMPLEMENTATION for where, and read the source before
relying on stock Linux semantics."
    {
        echo ".TH ${name^^} 2 \"$DATE\" \"EpinAnonymOS\" \"System Calls\""
        echo ".SH NAME"
        echo "$name \\- Linux syscall $num, as implemented by the EpinAnonymOS kernel"
        echo ".SH SYNOPSIS"
        echo ".B syscall($num, ...)"
        echo ".br"
        echo "kernel handler: \\fB$handler\\fR"
        echo ".SH DESCRIPTION"
        echo "$desc"
        echo ".SH IMPLEMENTATION"
        echo "Dispatched from \\fIsrc/kernel/d/core/kernel_main.d\\fR;"
        echo "implemented in \\fIsrc/kernel/d/core/syscalls/posix.d\\fR."
        echo ".SH CAVEAT"
        echo "This kernel emulates a SUBSET of the Linux ABI.  Behaviour that stock Linux"
        echo "guarantees is not guaranteed here unless the DESCRIPTION says so.  Notably,"
        echo "AF_UNIX reads return EAGAIN on an empty socket rather than blocking, and"
        echo "absolute opens are resolved against the calling task's namespace."
        echo ".SH SEE ALSO"
        echo ".BR anonymos-syscalls (7)"
    } > "$page"
    COUNT=$((COUNT+1))
done < /tmp/syscall-map.tsv

echo "generated $COUNT man pages in $OUT"

# ── the overview page: anonymos-syscalls(7) ────────────────────────────────────────────────────
# An admin needs the map before the individual pages are useful -- which numbers exist at all, and
# which of them this kernel answers differently from Linux.
{
    echo ".TH ANONYMOS-SYSCALLS 7 \"$DATE\" \"EpinAnonymOS\" \"Overview\""
    echo ".SH NAME"
    echo "anonymos-syscalls \\- the syscall surface of the EpinAnonymOS kernel"
    echo ".SH DESCRIPTION"
    echo "This kernel implements a SUBSET of the Linux x86-64 ABI so unmodified Linux binaries run,"
    echo "plus a native object API on a syscall number outside the Linux range."
    echo ".PP"
    echo "Counts below are generated from the kernel source, not maintained by hand, so they cannot"
    echo "drift from what the kernel actually dispatches."
    echo ".SH DEVIATIONS THAT BITE"
    echo "These differ from stock Linux and have each cost real debugging time:"
    echo ".TP"
    echo "AF_UNIX read"
    echo "Returns EAGAIN on an empty socket instead of blocking.  A client that reads once and gives"
    echo "up will lose the race; poll first."
    echo ".TP"
    echo "open(2) on an absolute path"
    echo "Resolved against the CALLING TASK's namespace.  A confined task sees ENOENT for an unbound"
    echo "path and EACCES for an explicitly denied one."
    echo ".TP"
    echo "connect(2) to an AF_UNIX socket"
    echo "Refused with EACCES when it crosses identities without a broker rule.  Connections to a"
    echo "system-trust peer (the compositor) are always allowed."
    echo ".TP"
    echo "inotify"
    echo "Watches only the writable runtime overlay.  A watch on an image file or a synthetic /proc"
    echo "path succeeds and never fires."
    echo ".SH SYSCALL TABLE"
    while IFS=$'\t' read -r num handler; do
        [ -z "$handler" ] && continue
        printf '.TP\n%s\n%s(2)\n' "$num" "${handler#linux_sys_}"
    done < /tmp/syscall-map.tsv
    echo ".SH SEE ALSO"
    echo "The per-call pages in section 2, and \\fIdocs/SYSCALL_ABI.md\\fR for the calling convention"
    echo "and the native object ABI."
} > "$OUT/../man7/anonymos-syscalls.7"
echo "generated overview page anonymos-syscalls(7)"
