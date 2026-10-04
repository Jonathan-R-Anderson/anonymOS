#!/usr/bin/env bash
# N1: prove a dash binary makes no Linux syscalls of its own -- every `syscall` instruction must lie
# inside dash.native's hos_call (the native object ABI multiplexer), and nothing may touch the thread
# pointer (%fs), which only a libc start-up would have set.
set -euo pipefail
bin="$1"
read -r start size < <(nm -S "$bin" | awk '$4 == "hos_call" { print $1, $2 }')
[ -n "${start:-}" ] || { echo "check-native-dash: no hos_call in $bin"; exit 1; }
s=$((16#$start)); e=$((s + 16#$size))
bad=0
while read -r addr; do
    a=$((16#$addr))
    if [ "$a" -lt "$s" ] || [ "$a" -ge "$e" ]; then
        echo "check-native-dash: stray syscall at 0x$addr ($(addr2line -f -e "$bin" "0x$addr" 2>/dev/null | head -1))"
        bad=1
    fi
done < <(objdump -d --no-show-raw-insn "$bin" | awk '/\tsyscall/ { sub(":", "", $1); print $1 }')
if objdump -d --no-show-raw-insn "$bin" | grep -q '%fs:'; then
    echo "check-native-dash: thread-pointer (%fs) access in $bin:"
    objdump -d --no-show-raw-insn "$bin" | grep -B30 '%fs:' | grep -E '^[0-9a-f]+ <' | tail -5
    bad=1
fi
[ "$bad" = 0 ] && echo "check-native-dash: $bin uses the native ABI only (1 syscall site: hos_call)"
exit $bad
