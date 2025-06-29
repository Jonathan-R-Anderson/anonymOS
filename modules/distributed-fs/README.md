# distributedFS

This repository contains a minimal Plan9-inspired distributed filesystem implemented in D.
It mirrors the early layout from the `internetcomputer` project and stores file blocks in a
small disk-backed DHT so data survives restarts. When a DHT is not available, it falls
back to a simple on-disk store. The tree contains `/users`, `/dev`, `/proc` and `/hardware`
directories similar to Plan9.

Run `make` to build the server binary using `ldc2`.
