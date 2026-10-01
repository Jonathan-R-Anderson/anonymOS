# macOS (Darling) bring-up — running macOS software natively in a domain

Goal: run macOS software inside an anonymOS domain through **Darling**, with no VM. Darling is a
Darwin translation layer: it runs Mach-O binaries against a reimplemented macOS userland on top of a
host kernel. On Linux it needs Darwin kernel behaviour that the host must provide; this is the
roadmap to provide it in the D kernel.

Large and multi-phase, like the Android bring-up (docs/hw-bringup/ANDROID.md); ordered by what
unblocks the most, each phase with a demonstrable exit criterion.

## Why it cannot run today

A Mach-O process is not a Linux process. To run one, the kernel/runtime must provide:

- **Mach traps** — the `mach_msg`, port, VM and task/thread calls Darwin makes through NEGATIVE
  syscall numbers (e.g. `mach_msg_trap` is -31). anonymOS has no Mach layer.
- **Darwin BSD syscalls** — the positive-numbered macOS syscalls (class `0x2000000`), which differ
  from Linux's in numbering and semantics.
- **The commpage** — a fixed shared page macOS libc reads (timebase, CPU capabilities).
- **dyld** — the Darwin dynamic linker, and a Mach-O loader in the kernel/loader (anonymOS loads ELF
  only today).
- **A macOS userland** — `libSystem` (libc, libpthread, libdispatch, the Mach/BSD shims), then
  `Foundation`, then `AppKit`/Cocoa for GUI apps. This is the bulk of the work and is Darling's to
  provide; the kernel's job is to make its syscalls and loader work.

The modern VibeDarling effort moves much of Mach/BSD emulation into usermode, which is the only
viable target on a non-Linux kernel like this one — but it still relies on the loader and syscall
surface below.

## Phases

| Phase | What | Exit criterion |
|---|---|---|
| **D1 — Mach-O loader** | Load a Mach-O executable and dylibs: `LC_SEGMENT_64`, `LC_MAIN`/`LC_UNIXTHREAD`, `LC_LOAD_DYLINKER`, map the pages, hand control to dyld. | A trivial statically-linked Mach-O runs to a controlled exit. |
| **D2 — commpage + thread state** | Map the Darwin commpage; set up Darwin thread/TLS (`%gs`-based) and the x86-64 Darwin stack/argv layout. | A Mach-O reads the commpage timebase without faulting. |
| **D3 — BSD syscall class** | Route the Darwin BSD class (`0x2000000|n`): file, mmap, signal, process calls, mapped onto the OS's existing VFS/mm. | dyld opens and maps a dylib from the Darling prefix. |
| **D4 — Mach traps** | The negative-number Mach traps: `mach_msg`, `mach_port_*`, `mach_vm_*`, `task_*`, `thread_*`. A Mach port/message layer (an in-kernel or usermode broker). | `mach_msg` round-trips a message between two Darwin threads. |
| **D5 — libSystem** | Darling's `libSystem` and friends run on D1–D4. | a Darwin `hello` using `printf` and pthreads runs. |
| **D6 — Foundation (CLI)** | Darling's Foundation on libSystem. | a Darwin tool using `NSString`/`NSFileManager` runs. |
| **D7 — AppKit / display** | Cocoa/AppKit drawing routed to the domain's Wayland surface (Darling's display path). | a minimal Cocoa window renders in the domain. |

`hos-darling` already dispatches `darling shell <program>` into the domain; D1–D4 are the kernel's
part (loader + syscalls + Mach), D5–D7 are Darling's userland built against them.

## Current status

- Not started. The launcher (`hos-darling`) and Domain Manager delegation are in place
  (docs/COMPAT.md), and `scripts/build-darling.sh` fetches the pinned upstream, but no phase above
  is implemented, so `hos-darling` reports Darling-not-installed rather than faking a run.

Honest state: the integration shell exists; the Darwin kernel surface does not yet.
