#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT_DIR/build/bin/hello"
mkdir -p "$(dirname "$OUT")"

# Compile hello
ldc2 -betterC -Oz -c "$ROOT_DIR/userspace/hello/hello.d" -of=/tmp/hello.o

# Link: simple linker args (text=0x400000)
ld.lld -nostdlib -e _start --script=/dev/fd/3 /tmp/hello.o -o "$OUT" 3<<'LINK'
SECTIONS {
  . = 0x400000;
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.comment) }
}
LINK

chmod +x "$OUT"
echo "hello user binary -> $OUT" 