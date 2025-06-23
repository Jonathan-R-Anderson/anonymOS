# Distributed Cryptographic Filesystem

This directory contains an experimental skeleton for a next-generation filesystem that combines ideas from **AsyncFS**, **Mikado**, and **UPSS**.  The goal is to provide a distributed, cryptographically secure storage layer for anonymOS and related projects.

The implementation here is intentionally skeletal.  The focus is on documenting how components fit together rather than providing a complete working system.  Each subdirectory corresponds to a major subsystem:

- `proto/` – gRPC service definitions
- `client/` – client-side libraries and mounting helpers
- `server/` – the core filesystem service
- `network/` – coordination logic using programmable switches
- `crypto/` – encryption, signatures, revision control
- `metadata/` – asynchronous metadata buffering and batching
- `storage/` – pluggable backends (local disk, cloud, etc.)
- `examples/` – illustrative usage and integration tests

To keep the repository small, all source files are heavily commented and include only minimal code.
