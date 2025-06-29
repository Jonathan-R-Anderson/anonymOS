# anonymOS

anonymOS is an experimental microkernel operating system.  It draws inspiration from Plan9 and NixOS while focusing on capability security and declarative configuration.  The project is in active development and many subsystems are still evolving.

## DISCORD

<a href="https://discord.gg/GN8qHardT7" target="_blank">
  <img src="https://cdn.icon-icons.com/icons2/2108/PNG/512/discord_icon_130958.png" alt="Join us on Discord" width="64" height="64">
</a>



## Implemented Features

- **Microkernel core** written in D with basic scheduling, memory management and IPC.
- **User mode services** for the file server, drivers and process management.
- **Lightweight hypervisor** allowing minimal virtual machines.
- **Container images** built with Alpine Linux utilities.
- **Object-based namespaces** expose managers like the scheduler and user manager through a unified object tree.
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
For debugging, run `make debug` to build the system, launch QEMU in debug mode and automatically attach GDB.  QEMU
uses a graphical window so the OS output appears separately from the GDB console.  If you prefer to start GDB
manually, run `make run-debug` in one terminal and connect with GDB from another using `target remote localhost:1234`.

To include the stock `dmd` compiler in the image, run `./scripts/build_dmd.sh` before `make build`. The script automatically fetches the upstream sources if they are missing and compiles them with your cross-compiled `ldc2`.

## Shell Integration

The build pulls the TTY shell from the external repository using
`scripts/fetch_shell.sh`. `scripts/check_shell_support.sh` can still be used to
verify that the kernel exposes the required terminal and keyboard drivers, but
the Makefile no longer compiles the shell during ISO creation. Instead the shell
sources are copied to the image under `/third_party/sh` and the actual build is
performed after installation. The shell's prompt dynamically displays the
logged-in user, namespace, current directory and CPU privilege level using the
format `user@namespace:/path(permission)`.

The ISO packages the shell sources in `/third_party/sh` along with a helper
script `install_shell_in_os.sh` located in `/sys/init`.  After installation the
system automatically runs this installer which builds the shell using the
bundled native `dmd` compiler and installs it to `/bin/sh`.  This keeps the raw
sources available while deferring compilation to the installed environment.

## Object Namespace Overview

At boot an object tree is created that exposes kernel services through a single
hierarchy.  The layout is minimal and currently looks like:

```
/
├─sys
│  └─scheduler (methods: create, run)
├─net
├─user
│  └─userManager (methods: createUser, setCurrentUser, getCurrentUser)
├─dev
├─proc
└─srv
```

Objects do not yet enforce permissions or inheritance.  Methods are invoked via
`obj_call(path, method, args)` using the syscall interface.

## Filesystem Layout

If no `fs.img` is present the kernel populates a filesystem with a default set
of directories and configuration files.  Any subsequent changes are immediately
written back to `fs.img` so the state persists across reboots:

```
/
├─sys/{boot,kernel,drivers,init,profiles}
├─apps/
│  ├─coreutils/v1.2.3
│  ├─browser/v105.0
│  └─editor/v3.1
├─users/
│  ├─alice/{bin,cfg,doc,media,projects,vault}
│  └─bob/{bin,cfg,doc,media,projects,vault}
├─srv/{sshd,web,dns,db}
├─cfg/
│  ├─hostname
│  ├─users/{alice.json,bob.json}
│  ├─network/interfaces.json
│  └─system/packages.json
├─vol/{usb0,backup_drive,encrypted_partition}
├─log
├─run
├─tmp
├─dev
└─net/{ip,tcp,dns}
```

Permissions and ownership are not yet implemented—any user may read or write
files.  Newly created users have their own subtrees under `/users` and a JSON
configuration file under `/cfg/users`.

## Example Shell Usage

The built-in shell is based on the `-sh` project and supports a small but
growing set of commands.  Typical interactions might look like:

```bash
$ ls /users
alice bob
$ cd /users/alice
$ echo "hello" > doc/greeting.txt
$ cat doc/greeting.txt
hello
```

The interpreter also provides features such as arithmetic, variables, loops,
background jobs and file utilities like `cp`, `mv` and `mkdir` as described in
the [`-sh` README](https://github.com/Jonathan-R-Anderson/-sh).

## License

This project is released under the MIT license.  See `LICENSE` for details.
