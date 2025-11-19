# Namespace and Capability Model

The minimal OS does not provide processes with direct control over physical
pages or global page names.  Instead every process starts with a small set of
capabilities that reference immutable Virtual Memory Objects (VMOs).  Address
spaces are defined entirely by mapping these capabilities, so the only way to
populate memory is by borrowing VMOs from trusted services or by constructing
new ones through the `VmoStore` API described in `docs/VMO.md`.

## Process view

* Processes never name pages.  They can only hold `VmoHandle` capabilities and
  ask the kernel to map them with appropriate permissions.
* Capabilities are transferable.  Passing a handle over IPC immediately grants
  the recipient the ability to map or clone that VMO without duplicating the
  underlying bytes.
* Revocation is explicit.  Once a handle is dropped all existing mappings
  remain valid, but new mappings can no longer be created because the capability
  has been forgotten.

## IO surfaces

All IO abstractions surface their data as VMOs as well:

* **File system** – directory entries resolve to capabilities.  Reading a file is
  equivalent to receiving a VMO reference whose contents match the file’s
  canonical hash.
* **Pipes** – behave as an ordered stream of VMOs.  Writers append immutable
  chunks, readers receive them in FIFO order and map them on demand.
* **Sockets** – mirror the pipe model but deliver VMOs across transport
  boundaries.  The receiving kernel validates the canonical hash before exposing
  the new capability to the destination process.

This approach keeps the namespace uniform: every byte of executable code, every
configuration file, and every IPC payload eventually becomes a VMO that can be
mapped into a process address space.  The absence of named pages means the
kernel never has to track per-process page identities—only which capabilities
were granted and how they are currently mapped.
