#!/bin/sh
# build.sh -- build the Cloud Hypervisor PVH hello guest(s) with host binutils.
#   guest-hello.elf      print, then cli;hlt forever          (EXIT_MODE=0)
#   guest-hello-off.elf  print, then ACPI S5 -> CH exits 0    (EXIT_MODE=1)
#   guest-hello-spin.elf print, then pause;jmp (no exits)     (EXIT_MODE=2)
set -eu
cd "$(dirname "$0")"

AS=${AS:-$(command -v x86_64-linux-gnu-as || command -v as)}
LD=${LD:-$(command -v x86_64-linux-gnu-ld || command -v ld)}

build() {  # $1 = EXIT_MODE, $2 = output name
    "$AS" --64 --defsym EXIT_MODE="$1" -o "guest-$1.o" guest.s
    # -n: no page alignment (keeps the file tiny; linux-loader does not check p_align)
    "$LD" -m elf_x86_64 -n -nostdlib --build-id=none -z noexecstack --no-warn-rwx-segments \
          -T guest.ld -o "$2" "guest-$1.o"
    "${STRIP:-strip}" --strip-all "$2"
    rm -f "guest-$1.o"
    echo "built $2 ($(wc -c < "$2") bytes)"
}

build 0 guest-hello.elf
build 1 guest-hello-off.elf
build 2 guest-hello-spin.elf
