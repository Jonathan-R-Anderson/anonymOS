# AnonymOS

A capability-based operating system built from first principles with object-oriented security, immutable core infrastructure, and advanced isolation mechanisms.

---

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Core Concepts](#core-concepts)
3. [Security Model](#security-model)
4. [System Architecture](#system-architecture)
5. [Comparison with Traditional Systems](#comparison-with-traditional-systems)
6. [Advanced Features](#advanced-features)
7. [Implementation Details](#implementation-details)

---

## High-Level Architecture

### Paradigm Shift: Objects Over Files

AnonymOS fundamentally reimagines the operating system around **capability-based security** and **object-oriented design**. Unlike traditional Unix/Linux systems that organize around files and processes, AnonymOS treats everything as a **typed object** with **explicit capabilities** controlling access.

**Key Architectural Pillars:**

1. **Capability-Based Security**: All access control is mediated through unforgeable capabilities
2. **Object-Oriented Kernel**: Everything is an object (VMOs, Blobs, Directories, Processes, Channels, Devices)
3. **Immutable Core**: System components are read-only with snapshot-based updates
4. **Namespace Isolation**: Per-process namespaces with fine-grained visibility control
5. **Zero-Trust Architecture**: No ambient authority; explicit capability delegation only

---

## Core Concepts

### 1. Object System

The kernel maintains a **global object store** where every resource is a typed object with a unique 128-bit ObjectID:

```
ObjectType:
├── VMO (Virtual Memory Object)    - Raw memory backing store
├── Blob                            - Immutable data (files)
├── Directory                       - Name → Capability mappings
├── Process                         - Execution context
├── BlockDevice                     - Storage device
├── Channel                         - IPC endpoint
├── Socket                          - Network endpoint
├── Window                          - GUI surface
└── Device                          - Hardware device
```

**Key Insight**: Unlike Unix where "everything is a file," AnonymOS has **strongly-typed objects** with **method dispatch** based on type. A Blob is not a Channel; operations are type-safe.

### 2. Capabilities

A **Capability** is an unforgeable token granting specific rights to an object:

```d
struct Capability {
    ObjectID oid;      // Which object
    uint rights;       // What operations (Read, Write, Execute, Grant, Enumerate, Call)
}
```

**Rights Attenuation**: Capabilities can only be **weakened**, never strengthened. If you have Read-only access to a directory, you cannot grant Write access to its children.

**No Ambient Authority**: There is no concept of "root" or "superuser" with universal access. Even the kernel operates through capabilities.

### 3. Namespaces

Each process has its own **namespace** - a private view of the object graph:

```
Process A sees:          Process B sees:
/bin → ObjectID(100)     /bin → ObjectID(200)  (different!)
/home → ObjectID(101)    /tmp → ObjectID(201)
```

**Namespace Types**:
- **Standard**: Full system view (like traditional Unix)
- **Minimal**: Restricted view (no /dev, limited /tmp)
- **Container**: Isolated view (separate /bin, /lib, /usr)
- **Untrusted**: Minimal view (only /bin, tiny /tmp)

**Bind Mounts**: Namespaces are constructed via **bind mounts** that attach objects at specific paths with specific rights.

### 4. Immutable Core

The system partition is **read-only** and **cryptographically verified**:

```
/system/
├── kernel/          (immutable, signed)
├── boot/            (immutable, signed)
├── lib/             (immutable, signed)
└── snapshots/       (versioned, atomic)
```

**Snapshot-Based Updates**:
- System updates create new snapshots
- Atomic switchover on reboot
- Automatic rollback on boot failure
- Maintains last 3 working snapshots

**Verification**: Every system blob has a SHA-256 hash stored in metadata. Boot process verifies integrity before execution.

### 5. Process Model

Processes are **objects** with three key capabilities:

```d
struct ProcessData {
    Capability rootCap;   // Global namespace root
    Capability homeCap;   // Private home directory
    Capability procCap;   // Process's exported objects (/proc/$pid/)
    ObjectID cwd;         // Current working directory
    ulong[16] syscallBitmap;  // Allowed syscalls (1024-bit mask)
}
```

**Syscall Filtering**: Each process has a **bitmap** of allowed syscalls. Untrusted processes can be restricted to safe syscalls only.

---

## Security Model

### Capability-Based Access Control

**Traditional Unix (DAC)**:
```
if (uid == file.owner || uid == 0) allow_access();
```

**AnonymOS (Capabilities)**:
```
if (has_capability(object, required_rights)) allow_access();
```

**Advantages**:
1. **No Confused Deputy**: Cannot be tricked into misusing authority
2. **Least Privilege**: Grant exactly the rights needed, nothing more
3. **Delegation**: Can safely hand out attenuated capabilities
4. **Revocation**: Destroy capability to revoke access
5. **Audit Trail**: Capability chains are traceable

### Sandboxing

**Five Sandbox Levels**:

1. **None**: Full system access (for system services)
2. **Minimal**: Basic restrictions (no /dev, limited /tmp)
3. **Standard**: Read-only system, writable home
4. **Strict**: Read-only everything, tiny namespace
5. **Isolated**: Complete isolation (container-like)

**Example: Web Server Sandbox**
```d
SandboxConfig {
    level: Standard,
    allowNetwork: true,      // Needs to listen on ports
    allowDevices: false,     // No direct hardware access
    allowIPC: true,          // Can log to syslog
    maxMemory: 512MB,
    maxProcesses: 10
}
```

The web server gets:
- Read-only `/bin`, `/lib`, `/usr`
- Read-only `/var/www` (web root)
- Write-only `/var/log` (logging)
- No access to `/home`, `/dev`, `/sys`

### User Authentication

**Session-Based Model**:
```
User → Authenticate → Session → Namespace → Process
```

Each **Session** gets:
- Cloned user namespace
- Home directory capability
- Time-limited validity
- Activity tracking

**No setuid**: Processes cannot change identity. To run with different privileges, spawn a new process with a different session.

---

## System Architecture

### Kernel Components

```
src/anonymos/
├── kernel/
│   ├── physmem.d         # Physical memory allocator (bitmap-based)
│   ├── pagetable.d       # Page table management (4-level paging)
│   ├── vm_map.d          # Virtual memory mapping (per-process)
│   ├── usermode.d        # User/kernel mode switching
│   ├── interrupts.d      # IDT, exception handlers
│   ├── cpu.d             # CPU state management
│   └── heap.d            # Kernel heap allocator
├── syscalls/
│   ├── syscalls.d        # Syscall dispatcher (SYSCALL/SYSRET)
│   ├── linux.d           # Linux-compatible syscalls
│   ├── capabilities.d    # Capability syscalls
│   └── posix.d           # POSIX compatibility layer
├── objects.d             # Object store and methods
├── namespaces.d          # Namespace management
├── security_model.d      # Authentication, sandboxing
├── snapshots.d           # Snapshot management
└── display/              # Display server and compositor
```

### Memory Management

**Three-Level Allocator**:

1. **Physical Memory** (`physmem.d`):
   - Bitmap-based frame allocator
   - 4KB frames
   - Reserves: low memory, kernel, modules, framebuffer

2. **Virtual Memory** (`vm_map.d`):
   - Per-process page tables
   - User/kernel split (0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF user)
   - Kernel at high memory (0xFFFF_8000_0000_0000+)
   - ASLR for stack, heap, mmap, code

3. **Kernel Heap** (`heap.d`):
   - Slab allocator for kernel objects
   - Guard pages between allocations
   - Canary values for overflow detection

### System Call Interface

**SYSCALL/SYSRET** mechanism (x86-64):
```asm
syscallEntry:
    swapgs
    mov [scratch_rsp], rsp
    mov rsp, [kernel_rsp]    ; Switch to kernel stack
    push r11                  ; Save user RFLAGS
    push rcx                  ; Save user RIP
    call handleSyscall        ; Dispatch
    pop rcx
    pop r11
    mov rsp, [scratch_rsp]
    sysretq
```

**Syscall Filtering**: Each process has a 1024-bit bitmap. Syscall N is allowed if bit N is set.

### Display System

**Compositor-Based Architecture**:
```
Hardware Framebuffer
    ↓
GPU Acceleration (modesetting)
    ↓
Compositor (composites windows)
    ↓
Window Manager (i3-compatible)
    ↓
X11 Server (compatibility)
    ↓
Applications
```

**Features**:
- Direct framebuffer access
- GPU-accelerated blitting
- Window damage tracking
- Input pipeline (keyboard, mouse, USB HID)

---

## Comparison with Traditional Systems

### vs. Linux

| Aspect | Linux | AnonymOS |
|--------|-------|----------|
| **Access Control** | DAC (UID/GID) + optional MAC (SELinux) | Capability-based only |
| **File System** | VFS with multiple FS types | Object store (no traditional FS) |
| **Process Model** | fork/exec, PIDs | Object-based, ObjectIDs |
| **IPC** | Pipes, sockets, signals, shared memory | Channels (typed message passing) |
| **Namespaces** | Optional (containers) | Mandatory (every process) |
| **Root User** | UID 0 has all power | No root; capabilities only |
| **System Updates** | Package manager (mutable) | Snapshots (immutable) |
| **Security** | Ambient authority (setuid, sudo) | Zero ambient authority |

**Key Difference**: Linux is **discretionary** (you choose who to trust). AnonymOS is **capability-based** (you can only use what you've been explicitly given).

### vs. DOS

| Aspect | DOS | AnonymOS |
|--------|-----|----------|
| **Protection** | None (single address space) | Full memory protection |
| **Multitasking** | Cooperative (TSR) | Preemptive |
| **File System** | FAT (flat, no permissions) | Object store (typed, capabilities) |
| **Memory Model** | Segmented (640KB barrier) | Flat 64-bit |
| **Drivers** | Direct hardware access | Isolated driver objects |

**Key Difference**: DOS has **no protection**. AnonymOS has **defense in depth** (capabilities + namespaces + sandboxing + immutable core).

### vs. Unix

| Aspect | Unix | AnonymOS |
|--------|------|----------|
| **Philosophy** | "Everything is a file" | "Everything is a typed object" |
| **Permissions** | rwxrwxrwx (9-bit) | Capability rights (extensible) |
| **Directories** | Special files | First-class objects (Name → Capability map) |
| **Devices** | /dev entries | Device objects with methods |
| **IPC** | Pipes, FIFOs, sockets | Channels (capability transfer) |
| **Security** | Trust-based (setuid) | Capability-based (zero trust) |

**Key Difference**: Unix uses **ambient authority** (you have rights based on who you are). AnonymOS uses **object capabilities** (you have rights based on what you hold).

---

## Advanced Features

### 1. Capability Transfer via IPC

Channels can **transfer capabilities**:

```d
struct Message {
    ubyte* data;           // Message payload
    Capability* caps;      // Capabilities being transferred
    size_t capCount;
}
```

**Use Case**: A file server can hand out read-only capabilities to files without giving access to the entire filesystem.

### 2. Cycle Prevention

The object graph is a **DAG** (Directed Acyclic Graph). Adding a directory entry that would create a cycle is **rejected**:

```d
bool wouldCreateCycle(ObjectID parentDir, ObjectID childId) {
    // BFS to check if childId is an ancestor of parentDir
    // Returns true if adding would create a cycle
}
```

**Why**: Prevents infinite loops during path resolution and garbage collection.

### 3. Rights Attenuation

When adding an entry to a directory, child rights are **automatically attenuated**:

```d
uint parentRights = getDirectoryRights(dirId);
if ((cap.rights & ~parentRights) != 0) {
    cap.rights = cap.rights & parentRights;  // Remove excess rights
}
```

**Example**: If parent has Read-only, child cannot have Write, even if the capability originally had it.

### 4. ASLR (Address Space Layout Randomization)

**Randomized Regions**:
- Stack: ±32MB splay
- Heap: ±16MB splay
- Mmap: ±64MB splay
- Code: ±64MB splay
- Shadow stack: ±16MB splay

**Entropy Source**: RDTSC + counter + boot seed

### 5. Shadow Stack

**Return address protection**:
```d
struct Proc {
    ulong shadowBase;      // Shadow stack base
    ulong shadowTop;       // Shadow stack limit
    ulong shadowPtr;       // Current shadow stack pointer
}
```

On function call: push return address to shadow stack
On return: verify return address matches shadow stack

**Prevents**: ROP (Return-Oriented Programming) attacks

### 6. Immutable Snapshots

**Snapshot Structure**:
```
/system/snapshots/
├── snapshot-001/
│   ├── kernel.elf
│   ├── manifest.json    (hashes of all files)
│   └── signature        (cryptographic signature)
├── snapshot-002/
└── current → snapshot-002
```

**Update Process**:
1. Download new snapshot
2. Verify signature
3. Verify all file hashes
4. Atomically update `current` symlink
5. Reboot
6. If boot fails, rollback to previous snapshot

---

## Implementation Details

### Boot Process

1. **GRUB** loads kernel.elf
2. **boot.s** sets up long mode, GDT, IDT
3. **kmain()** initializes:
   - Physical memory allocator
   - Page tables (kernel linear mapping)
   - Interrupts and syscalls
   - Display system
   - Object store
   - Root namespace
4. **userland.d** spawns init process
5. **Init** starts display server, window manager, shell

### Syscall Dispatch

```d
extern(C) void handleSyscall(ulong rax, ulong rdi, ulong rsi, ulong rdx, ulong r10, ulong r8, ulong r9) {
    if (!syscallAllowed(rax)) {
        return -1;  // Syscall not in process bitmap
    }
    
    switch (rax) {
        case SYS_READ:   return sys_read(rdi, rsi, rdx);
        case SYS_WRITE:  return sys_write(rdi, rsi, rdx);
        case SYS_OPEN:   return sys_open(rdi, rsi, rdx);
        // ... 50+ syscalls
        case SYS_CAP_INVOKE: return sys_cap_invoke(rdi, rsi, rdx, r10);
    }
}
```

### Object Lookup

```d
Capability resolvePath(ObjectID startDir, const(char)[] path) {
    ObjectID currentDir = startDir;
    foreach (component in path.split('/')) {
        Capability cap = lookup(currentDir, component);
        if (cap.oid == null) return null;  // Not found
        currentDir = cap.oid;
    }
    return Capability(currentDir, effectiveRights);
}
```

### Namespace Bind Mount

```d
bool bindMount(ObjectID nsId, const(char)[] path, ObjectID targetObj, uint rights) {
    auto ns = getNamespace(nsId);
    auto parentDir = resolvePath(ns.rootDir, dirname(path));
    auto cap = Capability(targetObj, rights);
    return insert(parentDir.oid, basename(path), cap);
}
```

---

## Building and Running

### Prerequisites

- LDC (LLVM D Compiler)
- LLVM toolchain (clang, lld)
- GRUB
- QEMU (for testing)

### Build

```bash
./buildscript.sh
```

This produces `build/os.iso`.

### Run

```bash
qemu-system-x86_64 -cdrom build/os.iso -m 512M -enable-kvm
```

---

## Design Philosophy

**1. Security by Design**: Capabilities are unforgeable and cannot be escalated.

**2. Least Privilege**: Every component runs with minimal necessary rights.

**3. Immutability**: System components cannot be tampered with at runtime.

**4. Isolation**: Processes cannot interfere with each other without explicit capability exchange.

**5. Verifiability**: Cryptographic verification of all system components.

**6. Simplicity**: Clear object model with explicit relationships.

---

## Future Directions

- **Distributed Capabilities**: Extend capabilities across network
- **Persistent Objects**: Object store backed by block device
- **Garbage Collection**: Reclaim unreachable objects
- **Formal Verification**: Prove security properties
- **Microkernel**: Move more functionality to userspace

---

## License

[Specify license]

## Contributors

[Specify contributors]

---

**AnonymOS**: An operating system where security is not an afterthought, but the foundation.
