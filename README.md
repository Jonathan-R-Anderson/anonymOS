# anonymOS

anonymOS is an experimental microkernel operating system.  It draws inspiration from Plan9 and NixOS while focusing on capability security and declarative configuration.  The project is in active development and many subsystems are still evolving.

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

## Shell Integration

The build pulls the TTY shell from the external repository using `scripts/fetch_shell.sh`.
Before compiling it, `scripts/check_shell_support.sh` verifies that the kernel provides the
required terminal and keyboard drivers. If these checks fail the build stops and explains what
is missing. Because the `fetch_shell` Makefile target is marked as phony, this step runs on
every build, ensuring the latest shell sources are fetched and compiled into the image
automatically. The shell's prompt now dynamically displays the logged-in user, namespace,
current directory and CPU privilege level using the format `user@namespace:/path(permission)`.

The ISO also packages the shell sources in `/third_party/sh` along with a helper
script `install_shell_in_os.sh` located in `/sys/init`.  Running this script
inside anonymOS compiles the shell with the bundled `dmd` compiler and installs
the result to `/bin/sh`.  This allows the shell to be rebuilt from source during
system setup if desired.

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

If no `fs.img` is present the kernel populates an in-memory filesystem with a
default set of directories and configuration files:

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
