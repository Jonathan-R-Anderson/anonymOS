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

## The approach: Darling's usermode architecture

Current Darling (the VibeDarling fork, fetched by `scripts/build-darling.sh`) no longer needs a kernel
module: `mldr` loads Mach-O in userspace, and `darlingserver` implements Mach IPC and the Darwin
syscalls as an ordinary process. Its **non-root mode** (written for Android-style hosts) needs no
namespaces or mounts: the prefix is a plain directory that darlingserver fills with a copy of the
installed system root. So the kernel's part is not a Mach-O loader or Mach traps of its own; it is
the Linux behaviour `darling`, `darlingserver` and `mldr` rely on.

Those three are the only ELF programs Darling installs (everything else is Mach-O). They are rebuilt
as static musl executables (`scripts/darling-musl-host.py`: Darling's own compile commands replayed
with the repo's musl toolchain, plus libucontext and a small glibc-compat shim) and staged with the
Mach-O tree as one tarball (`scripts/darling-stage.sh`). Local fixes to Darling live in
`scripts/darling-patches/`.

## Phases

| Phase | What | Exit criterion |
|---|---|---|
| **D1 — build + stage** | Latest VibeDarling (`COMPONENTS=cli`, x86-64) built on the host; host programs as static musl; one tarball. | done — VibeDarling `81b2bcdd`: 231 MiB tree, 73 MiB tarball, no dynamic ELF. |
| **D2 — host programs start** | The launcher (non-root), darlingserver and mldr run on the Linux personality. | darlingserver binds its socket and spawns launchd through mldr. |
| **D3 — darlingserver's kernel surface** | AF_UNIX datagrams addressed by name, with per-message SCM_CREDENTIALS + SCM_RIGHTS and autobind / abstract names; SOCK_SEQPACKET; pidfd_open / pidfd_send_signal; process_vm_readv / writev; blocking pipe writes. | a guest thread's RPC round-trips through darlingserver. |
| **D4 — launchd + shell** | launchd and shellspawn run; `darling shell <program>` reaches a Mach-O program. | `darling shell /bin/echo hello` prints in the VM. |
| **D5 — libSystem** | Darling's `libSystem` and friends run on D1–D4. | a Darwin `hello` using `printf` and pthreads runs. |
| **D6 — Foundation (CLI)** | Darling's Foundation on libSystem. | a Darwin tool using `NSString`/`NSFileManager` runs. |
| **D7 — AppKit / display** | Cocoa/AppKit drawing routed to the domain's Wayland surface (Darling's Wayland backend). | a minimal Cocoa window renders in the domain. |

`hos-darling` already dispatches `darling shell <program>` into the domain.

## Current status

- D1 done. D3's kernel surface is implemented (datagram queue in posix.d, pidfd as an eventfd that
  process exit makes readable, process_vm_* resolving the target's pages, bounded park for a full
  blocking pipe) and is being verified in VirtualBox with an AUTORUN probe that unpacks the tarball
  and runs `darling shell /bin/echo` in non-root mode.
- The first probe showed a kernel bug outside Darling: a blocking pipe write into a full pipe failed
  EAGAIN (busybox `tar -xz`), now parked.
