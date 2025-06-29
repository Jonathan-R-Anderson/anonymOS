# Distributed Cryptographic Filesystem (D Version)

This directory contains a lightweight Plan9-style filesystem implemented in D.
It reuses ideas from the early `internetcomputer` repository and stores data
blocks in a small disk-backed DHT so state persists between runs. When no DHT
is available, the server can fall back to a simple on-disk store so data still
persists locally.
The server can now derive a filesystem tree from the object-based namespace
defined in the `anonymos-object-tree` project. The generated directories and
files are written to the DHT so they remain available after reboot. Each
process receives a private Plan9-style filesystem that mimics a basic Linux
layout. Processes may share the parent namespace when explicitly requested.

Modules included:

- `fs/` – Plan9-like nodes and helpers
- `client/` – mounting helpers
- `server/` – server entry points
- `network/` – coordination stubs
- `crypto/` – placeholder crypto routines
- `metadata/` – asynchronous metadata buffer
- `storage/` – disk-backed DHT providing RAID-like redundancy with a
  local-store fallback
- `objecttree/` – minimal object namespace derived from `anonymos-object-tree`
- `objectfs/` – converts the object namespace into a directory hierarchy
- `fs/session.d` – per-process namespaces based on Plan9FS

Running `make` builds the server which initializes a small filesystem tree and
stores an example file in the configured storage backend. Call
`startServer(false)` to disable the DHT and use the local disk store only.
