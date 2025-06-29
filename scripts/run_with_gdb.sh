#!/bin/sh
# Build the ISO and launch QEMU with GDB attached automatically.
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Build the system
make build

# Start QEMU in debug mode.  Use the default graphical display so the
# emulator output appears in its own window separate from this GDB
# session.
qemu-system-x86_64 -cdrom build/anonymOS.iso -S -s -m 128M -vga std &
QEMU_PID=$!

# Give QEMU time to open the GDB port
sleep 1

# Launch GDB with kernel symbols and connect
gdb -ex "file build/kernel.bin" \
    -ex "target remote localhost:1234" \
    -ex "layout asm" \
    -ex "break _start" \
    -ex "continue"

# When GDB exits, stop QEMU
kill $QEMU_PID
wait $QEMU_PID 2>/dev/null || true
