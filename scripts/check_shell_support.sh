#!/bin/sh
# Check if the kernel provides TTY support needed for the -sh shell
set -e
SCRIPT_DIR="$(dirname "$0")"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

terminal_file="$PROJECT_ROOT/modules/microkernel/kernel/terminal.d"
keyboard_file="$PROJECT_ROOT/modules/microkernel/kernel/keyboard.d"

echo "Checking shell support..."

if [ ! -f "$terminal_file" ]; then
    echo "TTY support missing: $terminal_file not found" >&2
    exit 1
fi

if [ ! -f "$keyboard_file" ]; then
    echo "Keyboard driver missing: $keyboard_file not found" >&2
    exit 1
fi

# Check for required functions
if ! grep -q "terminal_writestring" "$terminal_file"; then
    echo "terminal.d does not define terminal_writestring" >&2
    exit 1
fi

if ! grep -q "keyboard_getchar" "$keyboard_file"; then
    echo "keyboard.d does not define keyboard_getchar" >&2
    exit 1
fi

echo "Shell support confirmed."
exit 0
