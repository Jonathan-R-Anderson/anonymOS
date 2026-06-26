# LKL integration (bare-metal device drivers — see roadmap/BARE_METAL_ROADMAP.md)

`lkl-boot.c` — the L2 embedder: boots the Linux kernel as a library (LKL) and exercises the
`lkl_sys_*` call-in path. **Validated on the host (boots `Linux version 6.12.0+`, dynamic + static).**

## Build (LKL tree lives outside the repo at `~/lkl-build/linux/tools/lkl`, built per L1)
    # host (glibc) — verify:
    gcc -O2 -o lkl-boot lkl-boot.c -I <lkl>/include <lkl>/liblkl.a -lpthread -lrt
    # static (for EpinAnonymOS) — whole-archive needed for the LKL init sections:
    gcc -O2 -static -o lkl-boot-static lkl-boot.c -I <lkl>/include \
        -Wl,--whole-archive <lkl>/liblkl.a -Wl,--no-whole-archive -lpthread -lrt
    strip lkl-boot-static        # drops debug_info (147MB -> much smaller)

## musl build (EpinAnonymOS is musl-tuned; the glibc build stalls in glibc startup)
    # musl-gcc cross (gcc-based; musl-clang/clang is finicky for the kernel) — musl.cc:
    curl -L https://musl.cc/x86_64-linux-musl-cross.tgz | tar xz        # -> x86_64-linux-musl-gcc
    # patch lkl.h: add `#include <sys/types.h>` after the include guard (musl lacks mode_t/dev_t
    # transitively, unlike glibc), then rebuild liblkl.a with the musl cross:
    make -C <lkl> CC=<...>/x86_64-linux-musl-gcc HOSTCC=gcc   # lib/hijack + dlmopen test fail on
    #   glibc-isms (__pid_t/__THROW/LM_ID_NEWLM) — harmless; liblkl.a still builds (~350MB).
    # link NON-PIE static (EpinAnonymOS wants ET_EXEC, not static-pie):
    <...>/x86_64-linux-musl-gcc -O2 -static -no-pie -o lkl-boot-musl lkl-boot.c -I <lkl>/include \
        -Wl,--whole-archive <lkl>/liblkl.a -Wl,--no-whole-archive -lpthread -lrt && strip lkl-boot-musl
Wired in: Makefile `LKL_BOOT_BIN := $(HOME)/lkl-build/lkl-boot-musl` → staged as the `lkl-boot` boot
module; `maybeSpawnLklTest()` (kernel_main.d) spawns it. **The musl binary LAUNCHES on EpinAnonymOS.**

## The L2 gap (next): LKL's POSIX-timer / signal clock
lkl-boot-musl launches but spins on `ENOSYS 128` (rt_sigtimedwait) + `222` (timer_create). LKL's POSIX
host drives the kernel clock with a POSIX timer that raises a signal and waits via `rt_sigtimedwait` —
EpinAnonymOS stubs rt_sigtimedwait (→EAGAIN, posix.d:8942) and lacks timer_create, so LKL busy-waits for
a timer IRQ that never fires. **Fix:** a CUSTOM LKL timer host-op (a host thread that sleeps via
clock_nanosleep and calls `lkl_trigger_irq` on the timer IRQ) — bypassing POSIX timers + signals — or
implement POSIX timers + real signal delivery in the personality.
Then L3 = a kernel `/dev/vfio` so LKL's `vfio_pci` reaches real PCI (vfio_pci.c is the reference).
