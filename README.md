# anonymOS

anonymOS is an experimental microkernel operating system.  It draws inspiration from Plan9 and NixOS while focusing on capability security and declarative configuration.  The project is in active development and many subsystems are still evolving.

## Implemented Features

- **Microkernel core** written in D with basic scheduling, memory management and IPC.
- **User mode services** for the file server, drivers and process management.
- **Lightweight hypervisor** allowing minimal virtual machines.
- **Container images** built with Alpine Linux utilities.
- **TTY shell** built from the [\-sh](https://github.com/Jonathan-R-Anderson/-sh) project and fetched automatically during the build.

## Planned Features

- Declarative system configuration similar to NixOS generations.
- Blockchain based identity and update verification.
- Integration with decentralized storage for distributing packages and snapshots.
- Graphical environment and additional device drivers.

## Building

Prerequisites include `grub-mkrescue`, `xorriso` and the `ldc2` D compiler.  To build the system and fetch the shell source run:

```bash
make build
```

The resulting ISO image is written to `build/anonymOS.iso`.  Use `make run` to boot it in QEMU.

## Shell Integration

The build pulls the TTY shell from the external repository using `scripts/fetch_shell.sh`.  The shell binary is compiled into the image automatically.

## License

This project is released under the MIT license.  See `LICENSE` for details.
