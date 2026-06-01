---
name: project-d-migration
description: Haskell kernel (hos.o, librts.a, jhc) replaced by pure D; kernel now builds without JHC
metadata:
  type: project
---

The Haskell kernel layer was phased out and replaced by D.

**Why:** User requested removal of Haskell dependency; EpinAnonymOS is the successor to HanonymOS (H=Haskell).

**What changed (2026-05-29):**

New D files in `src/kernel/d/core/`:
- `task.d` — Task struct, address-space region table, 64-task table
- `addrspace.d` — Page-fault handler (COW, demand-zero, Mapped), `walkAndCopyUserPages` for fork
- `elf_loader.d` — ELF64 parser; eagerly copies segments into new physical pages
- `kernel_main.d` — `d_kernel_main()`: replaces `hosMain`+`kernelize`; round-robin scheduler, syscall dispatch to posix.d, fork/exec/exit/wait4 implemented in D

Modified files:
- `arch/x86_64/bootstrap.d` — replaced `jhc_alloc_init()+jhc_hs_init()+_amain()` with `d_kernel_main()`; updated "HaskellOS" strings to "EpinAnonymOS"
- `Makefile` — removed `build/librts.a`, `build/prog-libs/hos-common-0.0.1.hl`, `build/hos.o` targets; kernel link no longer uses `-lrts` or `hos.o`
- `src/boot/limine.conf` — rebranded to EpinAnonymOS

**How to apply:** The kernel builds with `make build/libkernel_d.a kernel.elf`. The userspace progs (init.hs, storage.hs compiled with JHC) are still built separately by `make progs` but are no longer linked into the kernel. `d_kernel_main` scans boot modules for "busybox" first, then "init.elf" as the init process.
