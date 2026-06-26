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

## Next (L2 on-target): run on EpinAnonymOS
Stage the stripped static binary on the AHCI disk (the 32MiB qemu disk is too small — grow it),
run it, and capture how far LKL boots — that reveals the Linux-syscall gaps in EpinAnonymOS's
personality that LKL's POSIX host-ops need (mmap, clone/futex for pthreads, clock_gettime, ...).
Then L3 = implement `lkl_pci_ops` (vfio_pci.c is the reference) for real hardware.
