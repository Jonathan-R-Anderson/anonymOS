# anonymOS

## Introduction

**anonymOS** is a next-generation operating system that fuses together cutting-edge concepts from systems research and modern software practices. It brings the **Plan 9** philosophy of treating *everything as a file* with per-process namespaces, the **NixOS** approach to *declarative configuration* and reproducible builds, and the *immutable, snap-based modularity* of **Ubuntu Core**, all built on a secure **microkernel** foundation. On top of this core, anonymOS integrates decentralized technologies – including **Ethereum** (with layer-2 **zkSync**) and **IPFS** – to provide blockchain-backed integrity, distributed storage, and cryptographic identity. The result is an OS designed for advanced developers and researchers, with a focus on security (capability-based access control, zero-trust messaging), consistency, and global distributed operation.

In this README, we detail the design and architecture of anonymOS. Each section covers a different aspect of the system, from kernel to user space, and from filesystem to networking and security. You will find in-depth technical explanations of how anonymOS’s components work together, along with diagrams illustrating key concepts like the layered architecture, filesystem namespace, capability enforcement, and update flow. A **Quick Start** guide is also provided to help you build and run anonymOS in an emulator or on hardware. This document is written in a professional, technical tone intended for experienced systems developers and researchers who are interested in the internals of a novel OS platform.

## Philosophy & Design Goals

anonymOS’s design is guided by a set of core philosophies and goals derived from its influential predecessors:

* **Everything is a File (Plan 9 inspiration):** The system presents resources uniformly as files or streams, accessible via a common interface. Like Plan 9, anonymOS uses a **per-process namespace** model, meaning each process has its own view of the filesystem and services. This leads to a consistent, orthogonal interface for interacting with devices, network, GUIs, and more – all appear as files that can be read or written. By making “filesystem” the lingua franca, the OS achieves a high degree of simplicity and composability in how programs interact with resources.

* **Distributed by Default:** In Plan 9, a network of machines can function as one system, and resources from remote systems can be transparently integrated by mounting them into a process’s namespace. anonymOS embraces this idea – it’s designed for a world of distributed computing. Out of the box, it can mount remote filesystems or services, use content from IPFS, and verify state via blockchain as if they were local resources. The philosophy is that the *entire world* (or network) can be your computer, securely harnessed.

* **Minimal Trusted Computing Base (Microkernel):** Following microkernel principles, anonymOS keeps only fundamental services in the kernel (CPU scheduling, memory management, IPC). All other drivers and OS services run in user space as isolated components. This design adheres to the *principle of least privilege*, minimizing the code running with full privileges and thus reducing the risk of catastrophic failures or security breaches. It aligns with a “zero trust” philosophy internally – even OS components don’t inherently trust each other’s code, because each is sandboxed.

* **Declarative and Reproducible (NixOS inspiration):** anonymOS is configured declaratively. The entire system – from kernel to applications – is described in a *single configuration manifest*, rather than through ad-hoc imperative changes. Much like NixOS, building a new configuration doesn’t overwrite the old; configurations are *immutable and atomic*. If something goes wrong, you can roll back to a previous build reliably. This ensures that systems are *reproducible* – given the same config, you will get the same system state every time. This functional approach eliminates configuration drift and makes upgrades robust.

* **Immutability and Modular Updates (Ubuntu Core inspiration):** The base system and applications are delivered as self-contained *snaps* (read-only images), enabling transactional updates and strong integrity guarantees. anonymOS’s design keeps the base OS, kernel, and apps in separate *immutable modules* that can be updated independently, with clear separation between them. This not only improves stability (an update can’t partially overwrite critical system files) but also enhances security – the read-only nature of system snaps means critical parts of the system are protected from tampering or corruption.

* **Cryptography & Zero-Trust Security:** anonymOS is built for a hostile world. It assumes no implicit trust between components or network nodes. Security is achieved through *cryptographic means* (signatures, hashes, capabilities) rather than just network perimeter defenses. Every component or message is validated. The OS uses **capability-based security** internally (no process can access a resource without an unforgeable capability reference to it), and it applies **zero-trust principles** to networking – all inter-node messages are authenticated and encrypted. The goal is fine-grained access control and end-to-end verification of actions, eliminating entire classes of attacks (e.g. *confused deputy problems* are prevented by design).

* **Global Integrity via Blockchain:** Borrowing from the blockchain world, anonymOS treats the blockchain as a source of truth for certain system state and updates. For instance, software updates can be cataloged in a public ledger (Ethereum) so that clients can verify they are installing a legitimate update whose hash matches the blockchain record. User identities and credentials can be tied to cryptographic keys (Ethereum addresses), enabling decentralized, tamper-proof authentication across machines. In essence, trust in the system’s most critical operations is anchored in publicly verifiable cryptographic sources rather than any single company or server.

These philosophies drive anonymOS’s architecture. In the following sections, we delve into how these principles are realized in each layer of the system.

## Architecture Overview

&#x20;*Figure 1: Microkernel-based architecture of anonymOS. Only the microkernel (scheduling, memory, IPC) runs in privileged mode, while device drivers, filesystems, and services run as isolated processes in user space. This separation enhances security and stability by containing faults to user space components.*

At the heart of anonymOS lies a **microkernel** that provides the minimal core of the OS. The microkernel handles low-level tasks such as thread scheduling, address space management (memory protection), and inter-process communication (IPC) – and little else. All other functionality resides in user-space servers or daemons. This is a departure from monolithic kernels (like traditional Linux) and is more in line with designs like L4/seL4 or Minix. By pushing virtually all drivers (disk, network, GPU, etc.), protocol stacks, and even filesystems to user mode, the system minimizes what runs with high privilege. The benefit is twofold: better security (less code can compromise the kernel) and modularity (each component can be updated or restarted independently).

On top of the microkernel, anonymOS implements a set of core **system servers** that provide essential OS services in user space:

* A **File Server** that implements the primary filesystem interface. This server exposes a hierarchy of files and directories following the Plan 9 model, and it can delegate portions of the namespace to other specialized servers (for example, a separate server might handle `/dev` devices, another might handle network files under `/net`, etc.).
* A **Network Server** that manages network interfaces and protocols. Rather than the kernel implementing TCP/IP or UDP, a user-space network daemon does so. Applications interact with networking through file descriptors (for example, reading/writing to something like `/net/tcp/clone` to create a socket, similar to Plan 9’s approach).
* Various **Device Drivers** each running as their own process (or lightweight process). For example, there might be a disk driver process that interacts with hardware via IPC calls with the kernel (the kernel mediates access to I/O ports or memory-mapped I/O in a controlled fashion). If a driver crashes, it won’t crash the kernel – it can be restarted in isolation.
* A **Name Resolver and Auth Service** possibly bridging to blockchain: since the OS supports blockchain-based identity, a user-space service might run an Ethereum light client (or connect to one) and handle name resolution (e.g. resolving an Ethereum ENS name to an address) or verifying user signatures for login. (We discuss this more in *Blockchain Integration* section.)

These components communicate strictly through the microkernel’s IPC mechanism. For instance, when an application wants to perform a file operation, it will issue IPC to the file server (the file server exposes a well-defined interface, likely similar to Plan 9’s 9P protocol, though internally it could be optimized). IPC in anonymOS is designed to be fast and secure – using capabilities to ensure that a process can only send messages to servers it’s authorized to talk to.

The **tiered feature stack** of anonymOS can be visualized as layers building on each other:

1. **Hardware** (at the base) – CPU, memory, devices. anonymOS is hardware-agnostic (designed for x86-64 and ARM initially), requiring minimal firmware beyond a standard boot loader.
2. **Microkernel** – running in supervisor mode, providing core primitives (threads, address spaces, IPC, capabilities).
3. **Core OS Servers** – running in user mode. This includes the file server (namespace manager), device drivers, network stack, etc. Collectively, these emulate the traditional OS services but in a distributed fashion. For example, there is no single “monolithic kernel”; instead, if a process wants to open a file, it talks to the file server, which might in turn talk to a disk driver process. Thanks to the “everything is a file” model, even these interactions feel like file reads/writes from the perspective of the client process.
4. **Higher-level Services and Runtimes** – these are not quite applications, but system-level services that provide enhanced functionality. For instance, a **blockchain agent** service runs here (responsible for communicating with Ethereum or IPFS networks), a **security manager** service (enforcing policies, auditing), and possibly language runtimes or container managers. They operate with less privilege and through the standard interfaces. This is the layer where declarative configuration management happens: e.g., a “system builder” service that reads the declarative config and ensures the right snaps or packages are mounted/active (similar to Nix’s `nixos-rebuild` or snapd in Ubuntu Core).
5. **Applications** – user applications, which themselves might be packaged as snaps or similar isolated units. Applications run in user space with minimum privileges by default. They access resources by opening files (which under the hood triggers IPC to the relevant service). For example, a GUI app might open `/dev/fb` (framebuffer) which behind the scenes is provided by a GUI driver service, or a web server app might open `/net/tcp` to establish network connections via the network service.

The architecture is **component-based** and modular. Each piece (be it a driver, a server, or an app) is a replaceable module – often delivered as a snap package – with well-defined interfaces. The microkernel ensures that the only way modules interact is via secure IPC calls or by sharing memory explicitly (and such shared memory is granted via capabilities). This plug-and-play design makes it feasible to update parts of the system independently (e.g. upgrade the TCP/IP stack without rebooting the whole machine, akin to replacing one user-space daemon).

Finally, a note on performance: microkernels have historically been perceived as slower due to overhead of IPC. anonymOS leverages modern optimizations and the fact that hardware is vastly faster today. It employs techniques (like IPC fast paths, and possibly in-process optimizations for certain services) similar to L4 microkernels which demonstrated that IPC can be extremely fast (on the order of a function call in optimized cases). We take care that the security isolation doesn’t unduly sacrifice performance for common operations. Additionally, caching and batched operations mitigate overhead – for example, the file server might batch read-ahead or write-back to minimize round-trips. Overall, the architecture prioritizes correctness and security, but is designed with performance in mind by learning from decades of microkernel research.

## Tiered Feature Stack

Building on the architecture overview, here we detail the *tiered feature stack* of anonymOS – essentially, how each major set of features or concepts maps to layers in the system. anonymOS can be thought of as an **onion of capabilities**, each layer adding functionality on top of the lower ones:

* **Tier 0: Kernel Capabilities and IPC** – The foundational layer is the microkernel’s capability system. At boot, the kernel initializes a root partition of resources and distributes initial capabilities to the first process (often called “init” or a system launcher). Capabilities are secure *tokens* or references that grant a process the authority to access an object (memory page, IPC endpoint, device, etc.). This is the basis for all higher security: if a process has no capability for a resource, it simply cannot even attempt to use it. The kernel’s role is purely to mediate access via these capabilities and to ferry messages (IPC) between processes. It implements scheduling and memory isolation to ensure each process runs in its own address space until explicitly shared.

* **Tier 1: Core OS Servers (Namespace and Device Services)** – The next layer consists of fundamental OS servers launched at system start. The **Namespace Manager / File Server** (Tier 1a) constructs the initial filesystem namespace. It starts with a root filesystem (which could be an in-memory stub that then mounts real resources). This server is responsible for honoring `mount` and `bind` requests – akin to Plan 9’s ability to overlay namespaces. It may integrate multiple file sources: for example, it can mount the *boot snap* (immutable image containing core utilities) at `/`, then overlay a *writable memory filesystem* at specific points (like `/tmp`), and mount a *configuration filesystem* (possibly synthesized from the declarative config) at `/etc`. Additionally, **device servers** (Tier 1b) start up to provide `/dev` entries. Each device server registers itself with the namespace manager (or possibly, the namespace manager simply has a convention to import all active device servers under `/dev`). For instance, a GPU driver process might provide `/dev/fb0`, a keyboard driver provides `/dev/kbd`, etc. The Plan 9 influence is clear here: processes will see devices as files and can interact with them uniformly, while behind the scenes, the device drivers handle the specifics.

* **Tier 2: System Services and Overlays** – On top of the raw device and file namespace, anonymOS runs additional system daemons to enhance functionality. This includes:

  * **Networking Service:** A user-space network stack that exposes sockets or network connections as files. For example, similar to Plan 9’s approach, one might open a file like `/net/tcp/80/ctl` to initiate a TCP connection to port 80, and then read/write data via another file descriptor. Underneath, this service runs a full TCP/IP (or future protocols) implementation, handling packets via the network driver.
  * **Cryptographic Services:** A service might provide encryption, key management, and possibly *Fully Homomorphic Encryption (FHE) stubs*. The “FHE stub” indicates that anonymOS is designed with future cryptographic computing in mind – as FHE technology matures, the OS can offload certain computations on encrypted data to an FHE service without exposing plaintext (currently, FHE is not practical for general use, but the architecture leaves a hook for it).
  * **Identity and Auth Service:** This service ties into Ethereum for identity (more in blockchain section). It can handle “login via Ethereum” where a user proves control of an Ethereum address. It may run an Ethereum light client or communicate with one to verify signatures and perhaps check smart contract-based permissions. It could also coordinate **capability distribution** on login – e.g., when a user authenticates, the system might grant their session process capabilities based on on-chain roles or tokens they hold.
  * **Audit and Logging Service:** Responsible for recording security events, system logs, and optionally anchoring important logs to an immutable store (like writing hashes to a blockchain or storing logs in IPFS for later audit). By having this as a separate service, logs can be handled robustly (and even if one part of the system is compromised, it’s harder to retroactively alter the audit trail, especially if anchored to blockchain).
  * **Update Manager:** The component that checks for system or application updates. This ties into the DHT/blockchain integration tier to fetch updates from IPFS and verify them. It interacts with the file server to swap out old snaps for new ones (carefully, in a transactional way).

* **Tier 3: Declarative Config & Snap Layer** – This is the “self-management” layer of the OS. anonymOS uses a declarative config (inspired by NixOS) which describes what services and apps should be present and their configuration. A **System Build service** reads this configuration (for instance, a file at `/etc/anonymos/config.wc` or an Ethereum-hosted config) and ensures the system’s state matches it. Concretely, if the config specifies “install application X version 1.2”, the build service will retrieve the snap for X\@1.2 (via the DHT/IPFS), verify it, and instruct the file server to mount it in the right place (e.g. under `/apps/X`). The **snap daemon** (analogous to snapd on Ubuntu Core) operates here, managing the mounting and sandboxing of snaps. Snaps are mounted as read-only SquashFS images into the global namespace (or per-app namespaces, if needed for isolation). The declarative model means that, much like NixOS, if you change the config, a new *generation* of system state is realized without disturbing the previous one. The old snaps remain in storage and can be reverted to if needed. This layer is what brings *transactional updates* and *atomic switches* between configurations. It also ensures that on boot, the correct set of snaps and services are activated per the last known good config.

* **Tier 4: Distributed Trust & Connectivity** – The outermost layer of features involves connectivity beyond the single node. Here is where *blockchain and DHT integration* live (though physically, the blockchain client and IPFS node run as user services in Tier 2, their impact is system-wide at this top conceptual layer). In Tier 4, the system reaches out to the decentralized network:

  * It joins an IPFS swarm for distributed data (to fetch or share content by content hash).
  * It connects to Ethereum (and possibly zkSync network) for verifying identities, checking smart contract data (like update manifests or access control policies), and posting audit or telemetry info if configured.
  * Zero-trust networking comes into play strongly here: any communication to other nodes or services (even within a local network) is treated as potentially hostile. Thus, everything is encrypted (likely using keys that could be derived from the user’s Ethereum keys or device keys). Moreover, when connecting to a peer service, anonymOS could use mutual authentication – e.g., using a blockchain registry of device certificates or identities to ensure the node you’re communicating with is legitimate (for example, a cluster of anonymOS nodes might verify each other via signed tokens issued on-chain).

These tiers, while conceptually distinct, work in concert. For example, consider how a new application gets installed:

1. A developer publishes a new version of an app as a snap, with a content hash. They update a smart contract (or a git repo or similar, but ideally a smart contract) with the hash of this snap version.
2. The user’s declarative config is updated (by the user or an admin) to include this new app version. They trigger a “rebuild”.
3. The build service (Tier 3) sees the new app is required. It queries the *update manager* (Tier 2/4) to fetch the snap with that content hash.
4. The update manager uses IPFS (Tier 4) to find and download the snap by its content hash (ensuring data integrity, since IPFS addressing means any tampering would change the hash). It then verifies the hash against the expected value (which could be in the config or looked up via Ethereum).
5. Once downloaded, the snap’s signature is checked (snaps are signed by the publisher’s key, possibly the public key is also registered on Ethereum for additional trust).
6. The snap daemon then mounts this snap in a temporary location, the config builder arranges it into the final namespace (say the app expects to be in `/apps/MyApp` with a certain directory structure).
7. The namespace manager is instructed to union mount/overlay as needed so that the app’s files become live. The service manager starts the app if it’s a service, or it becomes available for user to run.
8. If any step fails verification, the process aborts and the previous state is retained (no partial upgrade occurs, akin to NixOS atomic upgrade or Ubuntu Core’s all-or-nothing OTA update style).

Each layer added specific value: the microkernel provided isolation, the namespace provided flexibility, the snaps provided immutability and easy rollback, and the blockchain/DHT provided integrity and authenticity guarantees beyond the local machine.

## Filesystem and Namespace Inheritance

One of the most distinctive aspects of anonymOS is its **filesystem and namespace model**, heavily inspired by Bell Labs’ Plan 9. In anonymOS, *the filesystem is not just a way to organize disk files; it is the unifying interface to nearly all system resources.* Processes perceive a variety of resources – hardware devices, network connections, other services, etc. – as part of a single hierarchical namespace. Crucially, each process can have its own customized view of this namespace, a concept inherited directly from Plan 9’s per-process namespaces.

When a process is created (forked or spawned), it *inherits* a copy of its parent’s namespace by default. This namespace is essentially a set of mounted filesystems or services. The child can then modify its own namespace (without affecting others) by mounting or unmounting resources, or by overlaying new mounts on existing paths (similar to Plan 9’s `bind` operation). For example, a process could decide to remap its `/tmp` to point to a private scratch directory or mount a testing version of a service at `/service/api` instead of the production one the parent was using. This ability to *rebind and overlay* gives immense flexibility: it allows sandboxing and virtualization-like behavior without needing actual virtual machines. For instance, if you want to “chroot” or isolate an application, you can fork it and in the child’s namespace, mount a minimal set of resources (maybe a read-only view of `/` plus a private `/home`). The process will run with that illusion, and other processes remain unaffected.

Under the hood, the **Namespace Manager** (part of the file server) handles these operations. It keeps a table of mount points for each process (or rather, for each *namespace group* – processes can share a namespace if desired, similar to sharing `CLONE_NS` in Linux). A mount operation essentially tells the namespace manager to attach a new filesystem server at a certain path. The filesystem server could be:

* A *disk filesystem* (e.g., a driver that reads an EXT4 or FAT partition). Notably, in Plan 9 such filesystem drivers ran in userland and spoke the 9P protocol; anonymOS follows suit: there isn’t necessarily VFS code in the kernel as in Unix, but rather the kernel delegates actual file operations to whatever server owns that part of the namespace.
* A *synthetic filesystem service* – e.g., the `/proc` filesystem is provided by a process that produces directories and files representing running processes (just as Plan 9 and Unix do). Or the `/net` directory is provided by the network service.
* A *remote mount* – a key feature of Plan 9 (and thus anonymOS) is that a mount target can be remote. Through the network, you can import a filesystem from another machine. If an authentication protocol and network transport (like Plan 9’s 9P over TCP or even 9P over QUIC) is in place, one machine’s file server can serve files to another machine’s process. anonymOS could mount, say, `tcp!example.com!/export/data` at `/data` in the local namespace, making remote data available as local files. Because all communication is authorized and (in anonymOS’s case) encrypted, this can be done securely over untrusted networks – tying into the zero-trust design. Essentially, the namespace is the fabric unifying local and remote resources.

The **file-everything model** means that things like GUI, networking, etc., are also accessed via files:

* The GUI might be managed by a window system process that provides each GUI application a set of files like `/dev/display`, `/dev/mouse`, `/dev/keyboard` that abstract the user’s I/O. When an app wants to draw to the screen, it might open a drawing context file and write graphical commands. This is exactly how Plan 9’s 8½ and rio window systems worked: e.g., each window had a file that you write text into for display, and the keyboard and mouse were files you read from. anonymOS can extend this – possibly using a modern protocol like Wayland under the hood, but exposed as files/IPC for consistency.
* Networking: as mentioned, under `/net` you might have subdirectories for each protocol. The act of opening a network connection is translated into opening a file or writing to a control file. Plan 9’s convention was e.g. `/net/tcp/clone` (read it to get a new connection id) then write the remote address to `/net/tcp/<N>/ctl` and then data flows through `/net/tcp/<N>/data`. We could follow a similar pattern. This uniformity means a program doesn’t need separate APIs for “open local file” vs “open network socket” – it’s all an open on a path.

Because each process can have a tailored namespace, **namespace inheritance** becomes a security and organizational tool. For example, suppose we have a service that is available at a well-known name (say, `/service/payments` for a payments API, exposed via the filesystem interface). In a multi-tenant scenario, each tenant’s processes could mount a *different* implementation at `/service/payments` – one that is restricted to their data. This way, the code could be the same (always opening `/service/payments/txn` file to do a transaction), but depending on which tenant’s environment it runs in, the file operations are handled by a different backend. This pattern provides a very powerful isolation mechanism: instead of hardcoding references to specific resources, programs use logical paths and the environment decides what those paths refer to.

Another advantage of the Plan 9-style namespace approach is that the **kernel itself stays simple** – it doesn’t need to know about every file system type or device. In Plan 9, even things like FAT or CD-ROM filesystems were implemented in userland servers. anonymOS continues this: the kernel doesn’t have a gigantic VFS or drivers for dozens of filesystems. If you plug in a USB drive with, say, an ext4 partition, a user-space ext4 driver can be spawned (perhaps via a hotplug event) and that driver will present the ext4 content as a 9P server. The namespace manager then mounts it under, say, `/mnt/usb`. If that driver crashes or misbehaves, the kernel and other parts of the system remain safe – you might lose that mount, but not crash the whole OS.

The design also means **network transparency** is baked in. Because the filesystem protocol is message-oriented and designed to potentially go over a network, any resource could be remote. In anonymOS, we leverage this for distributed operation: e.g., IPFS content could be exposed under a mount point like `/ipfs` – when you access `/ipfs/QmXYZ.../file.txt`, a special filesystem handler (backed by an IPFS client service) fetches that content via the DHT and presents it as a normal file. Similarly, perhaps `/eth` could be a filesystem interface to blockchain data (imagine each Ethereum account is a directory and within it files like `nonce`, `balance`, etc., that reading triggers a query to the Ethereum client). While these specific mounts are speculative, they illustrate how powerful the namespace concept is: new services can be cleanly integrated by “mounting” them into the file hierarchy.

In summary, the filesystem and namespace layer of anonymOS provides a **unifying abstraction** and a flexible, safe way to customize resource access:

* It generalizes device and service access to file operations (open, read, write, etc.).
* It allows per-process tailoring (inherit and then mutate namespace), enabling sandboxing, multi-versioning, and testing setups without global impact.
* It makes distribution transparent – local vs remote is mostly just a matter of which server you mount.
* And it simplifies the programming model – developers can use familiar file semantics for a wide array of tasks, with the OS doing the heavy lifting of routing those operations to the correct handlers.

## Security Model: Capability-Based and Zero-Trust

Security in anonymOS is designed from the ground up, not as an afterthought. The system employs a **capability-based security model** at its core, combined with a **zero-trust approach** to all interactions. This ensures *fine-grained access control*, strong isolation, and that *no component is implicitly trusted* simply by virtue of being “inside” the system.

**Capabilities in anonymOS:** A *capability* is essentially an unforgeable token or reference that grants a process the right to use an object or service. In practical terms, in our microkernel, when a process wants to perform an operation (like accessing memory, opening a file, sending a message), it must present a capability that the kernel or relevant service recognizes as valid. For example:

* To allocate memory, a process might invoke a system call with a capability for the memory manager and a request for new pages.
* To communicate with another service, a process needs a communication endpoint capability that was explicitly given to it.
* File descriptors themselves are capabilities: when a process opens a file, what it gets back is a handle (fd) that it can use for reads/writes. Without that handle, it cannot directly name the file. As noted in capability literature, a Unix file descriptor is a kind of capability – it’s a reference to an object with certain allowed operations.

One key property of capabilities is **POLA**: Principle of Least Authority. Processes should only get the capabilities they absolutely need, and no more. In anonymOS, when a process is started (say an application launched by the user), it is by default given a very limited set of capabilities: maybe the capability to communicate with the file server for its own namespace, and nothing else unless requested. If it needs network access, it would need to be granted a capability for the network service (which might be done by a higher-level policy or the user’s action). If it tries to access something without a capability, it simply cannot – the kernel won’t even route the request because the process doesn’t have a handle for that resource. This is starkly different from a traditional OS where any process can attempt to open any file path; in a capability system, if you were not given a capability for a file (or directory), you cannot even attempt to access it. Thus many security issues are prevented by default: an exploit in a text editor, for instance, cannot suddenly open `/etc/passwd` to steal content – that editor process wouldn’t have a capability for that file unless the user explicitly granted it (e.g., via an open dialog that confers the capability).

The microkernel enforces capability checks at the lowest level for operations like IPC or memory mapping. User-space services, following the same model, enforce them for higher-level objects (like files, network connections). This means that **confused deputy** attacks are mitigated: a service cannot be tricked into performing an action on something the caller has no rights to, because the request must carry a valid capability. If a service acts on behalf of a client, it will often use the client’s provided capability to do so, or there is a careful design to avoid ambient authority issues.

**Zero-Trust Messaging:** In line with modern security principles, anonymOS applies a zero-trust philosophy to both internal and external communication. Zero-trust means that *no message or request is trusted just because it originates from inside the system*. Concretely:

* All IPC messages between processes can be authenticated. The microkernel can tag messages with the sender’s identity (and the sender had to have a capability for the recipient’s IPC endpoint to even send it). For further assurance, sensitive communications can be cryptographically signed or use secure channels. For example, if the filesystem service sends a request to the disk driver, it might do so over an encrypted channel if the infrastructure supports it – though one could argue if it’s all in one machine, encryption might not be necessary, authentication via capabilities might suffice. However, if the “disk driver” is actually remote (think network storage), then higher-level encryption kicks in.
* On the network side, *every connection is treated as hostile until proven otherwise*. anonymOS’s network service, when connecting to a remote host or another anonymOS node, will perform mutual authentication whenever possible. If two anonymOS nodes communicate, they can use a shared trust anchor (like a blockchain identity or certificate) to verify each other. All data in transit is encrypted with strong algorithms by default – there’s no plaintext internal protocol that isn’t encrypted or signed. Essentially, it operates as if the network is always the public internet, even if it’s actually a local LAN. This eliminates entire categories of vulnerabilities that rely on being in a “trusted network”.

### Secure IPC Protocol
An additional library implements secure inter-process communication. Services perform a small Diffie-Hellman key exchange to establish a shared secret and validate rendezvous information before exchanging messages. Messages are XOR-encrypted with this secret and signed using a token derived from it. Both sides verify signatures so that IPC fails if tampering occurs or if the wrong endpoint responds.


The OS also institutes **fine-grained access controls** beyond capabilities in a few areas. For example, we integrate a *capability-based userland with higher-level policies*. A user might have a policy that “App X cannot access camera”; under the hood, that means App X’s process never gets a capability for the camera device file. But beyond that, suppose App X is compromised and tries to call a higher privileged service to do something sneaky. The services themselves are built to avoid acting beyond the caller’s authority. This again goes back to not using *ambient identity-based authority* (as in classical OS where if you run as user Alice, any process of Alice can do whatever Alice can). Instead, it’s more object-based: just because process runs as Alice, it doesn’t automatically get all Alice’s access – it only gets what it’s explicitly given. This can be augmented with user-level security policies, but the fundamental mechanism is capabilities.

To further enhance security, anonymOS employs **mandatory access checks** on potentially dangerous operations. For instance, *capability revocation*: pure capability systems historically have the challenge that if you give away a capability, how do you revoke it? Some modern designs solve this by making capabilities reference revocable permissions records. anonymOS’s design allows certain capabilities to be wrapped in a revocable layer – e.g., the system might issue a capability to use the network, but if the user toggles “Airplane mode”, the network service can invalidate those caps or the kernel can block them.

**Audit and Monitoring:** Every security-critical event can be logged to the audit service. Because of the zero-trust mindset, we assume any component *could* be breached, so having an audit trail is key for detection and forensics. Audit logs include things like: process X gained capability Y to resource Z, process X tried to access resource W and was denied, user U (identified by Ethereum address 0xABC…) requested elevation of privilege, etc. These logs themselves can be sensitive, so the audit service may hash or encrypt them (or even directly write a hash on-chain, achieving tamper-evidence). The presence of an audit log anchored in blockchain means that an attacker who somehow gained root access to a node *still cannot cover their tracks* easily – they could alter local logs but not the copy whose hash is secured by the blockchain.

**Secure Boot and Integrity:** The security model begins at boot time. anonymOS supports secure boot mechanisms so that the microkernel and initial userland aren’t tampered with. Because the system packages (snaps) are cryptographically signed and content-hash addressed, the integrity of even optional components is verifiable before use. For instance, when the system loads a snap for a device driver, it verifies the signature and hash; if they don’t match the expected values (like those published on the blockchain for that version), the load is rejected. This chain of trust extends from bootloader to kernel to each user-space module loaded.

In summary, anonymOS’s security model can be characterized by:

* **No ambient authority**: processes can’t do things unless explicitly authorized via capabilities. This minimizes damage from compromised components and supports least-privilege operation everywhere.
* **Isolation by default**: thanks to microkernel design and user-space separation, a fault or attack in one service doesn’t trivially spread to others. Even if a malicious app tries to exploit a device driver, that driver is user-space and largely constrained by the kernel (and possibly formally verified if using something like seL4 in the future).
* **End-to-end cryptographic verification**: whether it’s an inter-process message or a software update, everything is verified. Nothing is trusted just because it comes from “within the house” – the attitude is like verifying the ID of *every* person at the door, even the ones who live there, every single time. It may sound paranoid, but in modern environments with sophisticated threat models (supply chain attacks, insider threats, etc.), this approach dramatically raises the bar for attackers.
* **Auditable and Recoverable**: detect compromises via audit trails, and when something is amiss, revoke capabilities or roll back to a safe state (with the immutable config, rollback is straightforward).

Finally, it’s worth noting that capability-based security has been proven in practice by systems like seL4 (which is formally verified and uses capabilities for everything) and research like **Miller et al.’s “Capability Myths Demolished”**. anonymOS stands on the shoulders of these efforts, adopting what works and integrating it with contemporary tech (blockchain, etc.) to create a robust security posture.

## Blockchain and DHT Integration

One of the defining features of anonymOS is its native integration of blockchain technology and Distributed Hash Tables (DHTs) for various aspects of system operation, from authentication to software updates. This integration is designed to enhance trust, integrity, and decentralization beyond what a single-machine OS typically provides.

**Ethereum Integration (The World Computer meets anonymOS):** anonymOS uses the Ethereum blockchain as a decentralized trust anchor and identity platform. Each user of the system can be mapped to an Ethereum account (public/private key pair). Instead of (or in addition to) traditional username/password or local accounts, a user may authenticate by proving ownership of an Ethereum address – akin to “Sign-in with Ethereum” standards in web applications. Practically, during login, the OS might present a challenge string that the user signs with their private key (often via a wallet). The OS then verifies the signature against the user’s registered Ethereum address. This means authentication is *key-based and decentralized*; there is no central password database that could be stolen, and a user can use the same blockchain identity across multiple devices.

What are the advantages of this? First, the user’s identity can carry embedded credentials or roles through smart contracts or tokens. For example, owning a particular NFT or token could automatically grant certain privileges on the OS (imagine an NFT that acts as a “software license” or an “admin token”). The Ethereum integration enables such checks: the OS’s auth service can query a smart contract to see if address X holds token Y, and then grant capabilities accordingly. Second, it allows global, single sign-on in a secure way – potentially a user could walk up to any anonymOS instance, authenticate with their Ethereum key (e.g., using a hardware wallet or even a brainwallet, though that’s not recommended for security), and bootstrap a session without needing a pre-created local account on that machine.

To make this practical, anonymOS includes or interfaces with an **Ethereum light client**. A light client is a program that connects to the Ethereum network and verifies block headers (often using something like zk-SNARKs or fraud proofs for efficiency) but doesn’t necessarily store the entire chain. The OS can run a light client as a background service, which keeps the OS in sync with the latest state of the Ethereum blockchain (or at least can query it on demand). This way, verifying a signature or retrieving the state (like “does address X have permission Y recorded in contract Z?”) does not require trusting an external server – the OS itself can validate the blockchain data. As an example, the Ethereum-native mobile OS “ethOS” runs an Ethereum light client as a system service to verify blocks itself; anonymOS does similarly for authenticity. (However, running a full node on an OS might be heavy; a light client or zk-sync proof client is more feasible.)

**zkSync and Layer-2:** Ethereum mainnet can be resource-intensive (gas fees, etc.). anonymOS integrates **zkSync**, a prominent layer-2 scaling solution for Ethereum, to handle many blockchain interactions in a cost-efficient manner. zkSync is a ZK-rollup technology that batches transactions off-chain and posts succinct proofs to Ethereum, thereby reducing fees and increasing throughput while inheriting Ethereum’s security. In anonymOS, zkSync might be used for:

* **Micropayments or microtransactions:** If certain OS actions involve blockchain (perhaps purchasing a storage quota, or tipping a developer, or paying for an update service), doing those on Ethereum L1 would be slow and costly for small amounts. Instead, the OS can use zkSync to perform these transactions cheaply and then settle to L1.
* **Identity proof aggregation:** Instead of every device hitting L1 Ethereum to verify a user’s token holdings, there could be a zkSync-based identity registry or attestation service. For example, maybe a user’s roles are attested on zkSync in a contract, and the OS gets a validity proof from zkSync that “User X has Role Y” without going to mainnet every time.
* **Fast consensus for clusters:** If you have a cluster of anonymOS nodes, they might use a private chain or a layer-2 to coordinate state (like a shared filesystem state or replicated log). zkSync tech (zero-knowledge proofs) could help ensure consistency with privacy. This is more speculative, but the point is that any place where we need blockchain benefits (trust, immutability) but faster/cheaper, zkSync is an enabler.

From the user perspective, this integration is mostly invisible – they benefit from the security without having to manage it. Under the hood, the OS has keys and perhaps an on-disk wallet (ideally secured by hardware, like using a TPM or secure enclave to store private keys). The mention of **FHE stub** in security could even indicate that in the future, a user’s private key operations might be done in a way that the OS never sees the raw key (if FHE could be applied, or at least secure enclaves currently).

**IPFS and DHT for storage and updates:** anonymOS offloads large data distribution to the **InterPlanetary File System (IPFS)** or similar DHT-based networks. IPFS provides a content-addressable storage network where each piece of content is identified by a cryptographic hash (CID). anonymOS leverages this in several ways:

* **Software distribution:** As described earlier, system and application updates are retrieved via IPFS. The OS knows the content hash of what it wants (say the hash of version 1.2 of AppX). It asks the IPFS network for that hash; IPFS peers then supply the data. Because the addressing is by hash, the user automatically verifies integrity by recomputing the hash of the received data – if it matches, the content is exactly what was intended. This is a huge win for security: it’s effectively like every download has a built-in checksum verification. It also means that distribution can be decentralized – no official server needed, any peer with the data can supply it (similar to Bittorrent, but content-addressed and permanent). The blockchain comes into play by storing or advertising the *expected hashes*: for instance, an official smart contract might list the current version hash of each component. The OS can query that (via the Ethereum integration) to ensure it’s fetching a trusted version.
* **Global namespace via IPFS:** anonymOS can incorporate IPFS as part of its filesystem. For example, mounting `/ipfs` as mentioned, or using IPFS for user data backup. A user’s home directory could be optionally versioned in IPFS (with proper encryption for privacy), enabling global access to one’s files from anywhere (with your keys). When updates to a file are published, they get a new hash, and maybe those hashes can be noted on blockchain (some people use blockchains to timestamp or index IPFS content for this reason). IPFS ensures data integrity and availability (if pinned by some network nodes).
* **Content distribution resilience:** Using a DHT means the OS is not dependent on a single update server that could be taken down or censored. As long as at least one peer in the world (possibly maintained by the community or the developers) hosts the content, anyone can fetch it by hash. This aligns with the decentralization ethos: control is not centralized.

To ensure authenticity of content, multiple layers are used: content addressing (hash) ensures integrity, and cryptographic signatures (the developer signs the package) ensure the source authenticity. The blockchain can be used to store the signature’s public key or the hash, thus providing an immutable record. In practice, one approach (in a hypothetical scenario) is:

1. Developer builds a new OS release or app snap. It produces a file, which IPFS hash is H.
2. Developer signs H with their private key. They then send a transaction on Ethereum that includes H (and perhaps the signature or a reference) into a smart contract that is recognized as the “update registry”.
3. User’s anonymOS sees there’s an update (either by watching the blockchain event or by other notification). It retrieves the hash H from the smart contract (so it knows this is the blessed update).
4. It then fetches content for H from IPFS. Once downloaded, it hashes it to ensure it indeed is H. Then verifies the developer’s signature (the public key might be known or also on-chain).
5. If all checks out, it installs the update. If not, it rejects it.

Blockchain here provides *tamper-proof, globally synchronized metadata*. No attacker can secretly give you a malicious update without either breaking the crypto or achieving a 51% attack on Ethereum (very impractical). This dramatically reduces the chance of supply chain attacks akin to malicious repository injections, as long as the keys are secure.

Another aspect: **Audit logs to blockchain**. Optionally, anonymOS could periodically write hashes of its audit logs or important state to a blockchain (Ethereum or perhaps a cheaper chain if volume is high). This could be done directly or via a bridging service. The idea is that if the device is later compromised, those prior log hashes on-chain serve as a reference. An admin can compare the logs on device to the hashes on chain to see if logs were tampered. Given Ethereum transaction costs, this might be done sparingly or via an L2 (zkSync could be very useful here to batch many log attestations into one succinct proof).

**Decentralized coordination:** If anonymOS devices form a peer-to-peer network (e.g., a swarm of IoT devices all running anonymOS), they can use DHTs and blockchains to coordinate without a central server. For example, IPFS could be used to broadcast messages or updates among them, and a smart contract could act as a bulletin board for them to discover each other or share status. The *zero-trust messaging* principle ensures even in this scenario, each node verifies everything about others (like requiring signed messages, etc., possibly using the blockchain identities as the key).

**Performance considerations:** Interfacing with a blockchain can be slow (confirmation times) and IPFS can have variable latency (finding peers). anonymOS handles this by not making critical operations synchronously depend on external networks unless necessary. For login, Ethereum verification is quick (a signature check is local crypto, no need to wait for a chain event). For updates, you can continue running while an update downloads and verifies. Most blockchain interactions (like posting an audit log) can be done asynchronously by a background service.

In essence, blockchain and DHT integration gives anonymOS:

* **Decentralized Identity and Auth:** Users and devices have identities not issued by any single OS vendor or authority, but by cryptographic keys recognized globally. This is a step towards self-sovereign computing.
* **Tamper-proof Trusted Data:** The use of Ethereum for storing hashes or decisions means the OS can trust data (like update manifests, security policies, configuration locks) that cannot be locally altered or spoofed. “Trust through consensus” complements local security.
* **Update and Configuration Management at Scale:** Imagine thousands of devices needing an update – instead of all hitting a vendor server, they get it via IPFS from each other, verified by blockchain. It scales and is robust against server outages or targeted attacks.
* **Integration with Web3 ecosystem:** Because anonymOS “speaks” blockchain natively, it can directly interface with decentralized applications. For example, the OS could natively support storing files on Storj or Filecoin, or using smart contracts for licensing. This opens up new avenues (like apps that have on-chain components can be tightly integrated with OS identity).

To draw a real-world parallel, the **ethOS mobile OS** we mentioned demonstrates some of these ideas: it has built-in wallet, light client, IPFS, .eth domain support. anonymOS extends that concept from a single-user phone OS to a general-purpose, possibly server-grade OS with a heavier focus on immutability and formal OS features.

In summary, the blockchain and DHT integration in anonymOS isn’t bolted on as a gimmick; it’s woven into the fabric to enhance security and decentralization:

* Ethereum provides the *consensus truth* for critical records (identities, update hashes, etc.).
* zkSync ensures those truths can be used efficiently and scalably in day-to-day operations.
* IPFS and DHTs provide *efficient content distribution and data integrity*, making the system more resilient and globally accessible.
* The combination ensures that even if you don’t fully trust the machine you’re running (think about cloud deployments, or edge devices that might be captured by bad actors), you can still trust certain operations (like software installs, login) because they are verified by the broader decentralized network.

## Declarative Configuration & Snap System

anonymOS’s approach to system configuration and software management is both **declarative** and **immutable**, combining the strengths of NixOS’s config management with Ubuntu Core’s snap packaging. This means as a developer or admin, you describe *what the system should be*, and the OS ensures itself is in that state by assembling the needed components (snaps), rather than you manually tweaking the system. Furthermore, the use of snaps (read-only system images) ensures that most of the system is immutable during runtime, enabling robust updates and rollbacks.

### Declarative System Configuration

At the heart of configuration is a single file (or a small set of files) – for example, `/etc/anonymos/config.wc`. This is analogous to NixOS’s `/etc/nixos/configuration.nix`. In this config, you declare things like:

* What version of the kernel and core services to use.
* Which system services are enabled (e.g., enable the SSH service, enable an Ethereum client service, set hostname, etc.).
* User accounts or identities (perhaps linking to Ethereum addresses).
* Which applications (snaps) should be installed and their desired versions.
* Resource allocations or device configuration (like “give the VM service 2GB of memory” or “mount a persistent data disk at /data”).

This config is written in a high-level declarative language. It could be a JSON/YAML, but more likely a specialized language (like Nix’s functional language, or Dhall, or maybe a subset of Python – design choice open). The key is that it’s declarative: you specify *the end state*, not the steps to get there.

When you update this config, you don’t manually apt-get or copy files; instead, you run the **anonymOS rebuild** process (similar to `nixos-rebuild`). This invokes the *System Build Service* we mentioned. That service reads the new config and calculates what needs to change compared to the current system state (which was itself built from an older config). Since everything is content-addressed and versioned, it can compute a new system “closure” (the set of snaps/packages needed). For example, if you changed one application’s version, it will identify that the new version’s snap is needed.

The build service then orchestrates fetching any new snaps from the snap store (or IPFS) and preparing a new system profile. On NixOS, this results in a new generation that can be booted or activated. In anonymOS, it results in a new set of snaps and configuration that can be *atomically activated*. Activation means:

* Stopping any services that are being replaced.
* Mounting the new snaps (e.g., the new version of an app).
* Updating symlinks or binding mounts so that `/apps/YourApp` now points to the new version’s files.
* Starting services from the new snaps as needed.
* Possibly updating the kernel or core snap (which might require a reboot if the kernel changes – though Ubuntu Core can even switch kernels atomically on reboot via dual partitions or similar).

The previous configuration isn’t lost: it remains available for rollback. In fact, anonymOS keeps a history of configurations (much like NixOS generations). If the new config has issues, you can reboot or instruct the system to revert to a previous configuration. Because nothing was overwritten (snaps are immutable files, just new ones added), rollback is fast and reliable – you’re just re-pointing what is the active set. NixOS achieves this by generation directories and symlinks; Ubuntu Core does it by having old snaps still present and marking one as active. We incorporate both ideas: *purely functional* config means builds produce side-by-side installs, and *transactional switch* means at any point, only one set is live.

A concrete scenario: Let’s say the config enables SSH. That means the build will include an OpenSSH snap (or package) and generate an SSH config file (perhaps based on options set declaratively). When you `anonymos-rebuild switch`, it ensures the OpenSSH server is running with that config. If later you disable SSH in the config and rebuild, it will stop the SSH service and possibly remove it (or mark it for GC). You didn’t manually do service start/stop – the system orchestrated it from the desired state.

This approach eliminates the class of errors stemming from configuration drift and manual changes. Two machines with the same config file should end up in identical states, which is great for reproducibility and debugging.

### Snap-Based Modular System

anonymOS uses **snaps** (or very similar containerized package images) as the unit of software deployment. A snap is a self-contained SquashFS image that includes an application or service and all its dependencies. In Ubuntu Core, even the kernel and base OS are snaps. We adopt a similar structure:

* **Kernel Snap:** Contains the kernel image and perhaps related firmware or boot scripts.
* **Core System Snap:** This is like the “anonymOS base” – it might include the standard library, basic shell utilities, etc. Alternatively, we might use an existing base snap like Ubuntu Core’s core18 or core20 images as our userland. This core is mounted at the base of the filesystem (e.g., `/usr` etc).
* **Service Snaps:** Each system service (file server, network service, etc.) could be packaged as a snap. They might all be combined in one snap if tightly coupled, but modularity suggests splitting them (for instance, a snap for the file/namespace service, another for the network stack, etc., which allows updating them independently).
* **Application Snaps:** Applications, which could be third-party, are snaps too. These run on top of the core system.

Snaps are *strictly confined* by default – meaning they run with AppArmor or similar sandboxing to limit their access. In anonymOS’s case, the confinement is doubly enforced by capabilities (the snap won’t have access unless given) and by underlying Linux security modules if applicable. The OS uses snap **interfaces** to allow certain snaps to access certain resources (e.g., a snap might declare it needs camera access; the user can connect the “camera” interface to that snap, which under the hood grants the needed capability or permission for `/dev/camera` device).

The filesystem of the running system is essentially an aggregation of mounted snaps:

* The kernel snap is used at boot (it might be handled by the bootloader rather than mounted in fs).
* The core snap is mounted at `/` or appropriate subdirs, providing the root filesystem bulk.
* A gadget snap (Ubuntu Core term for device-specific bits) might provide `/boot` or hardware configs.
* Service snaps are mounted typically under `/snap/<name>/<version>/` and linked to expected locations or launched via symlinks in `/bin` or systemd units.
* Application snaps similarly are mounted in versioned directories and exposed via wrappers.

anonymOS’s namespace mechanism can abstract some of this complexity. For instance, in the namespace, you might see `/apps/MyApp` as a normal directory with the app’s files, but in reality that is a bind mount into the SquashFS content of the snap located somewhere like `/snap/myapp/x1`. This is analogous to how Ubuntu Core works (it mounts snaps under `/snap` and uses symlinks for executables).

**Transactional Updates with Snaps:** When an update occurs, a new snap is downloaded and placed alongside the old one. Then, typically, the system will switch an *alias* or mount to point to the new one. If something fails, it can revert by pointing back to the old snap. This is often near-instant and can even be done on reboot (Ubuntu Core keeps an A/B system for critical snaps so if new one fails to boot, it reverts to old automatically). anonymOS leverages this for reliability. For example, if a core system snap (like the network service) is updated, it might restart that service with the new snap. If it crashes immediately or fails health checks, the OS can quickly roll back to the previous snap version with minimal downtime.

**Integrity and Origins:** All snaps are signed by their publisher’s keys and the system verifies signatures upon installation. Snaps also come with *hashes*, as we discussed, often the store (or IPFS in our case) uses content hash naming which is inherently verified. This means the system knows exactly what version it has and that it hasn’t been corrupted in transit or storage.

**Custom Build vs Upstream Snaps:** If anonymOS is an independent project, it may maintain its own snap store or repository (possibly a decentralized one using blockchain). It could also leverage existing snaps for common software (for example, use the official snap for Firefox if that fits). But often, for tight integration, we might maintain our own variants.

**Example – Boot Sequence with Snaps and Config:**

1. Bootloader loads the kernel (from kernel snap) and an initial RAM disk or initial partition.
2. Kernel (microkernel) starts, looks for the core snap.
3. An initial process (let’s call it “Snap Init”) starts which mounts the core OS snap (providing basic `/` filesystem).
4. Snap Init then spawns the configured system services as per the current config (which might be baked into an early boot config or retrieved from a signed config file).
5. Each service snap is mounted and the service launched. They form the OS runtime.
6. Finally, user shells or GUI login is presented (if applicable).
7. During this, the system might run a “first-boot config apply” if this is first time booting a new config generation – similar to how NixOS rebuild activation scripts run.

**Volume management:** Some parts of the filesystem are writable, usually for data. For instance, in Ubuntu Core, there’s a writable partition mounted at `/writable` or symlinked to traditional paths for things like `/home`. anonymOS also has designated writable areas (for logs, user data, etc.) since snaps themselves can’t be written to. The declarative config might also define how these are set up (e.g. it might declare a ZFS volume for `/data` or that `/home` is bound to a persistent disk, etc.).

**Garbage Collection:** Over time, you might accumulate old snaps from previous versions. The system can garbage-collect those not in use (similar to how Nix GC works or how snapd keeps at most N previous revisions).

**Comparison to NixOS:** In NixOS, packages are in `/nix/store` hashed by content, and profiles select the active ones. In anonymOS, snaps serve a similar role: each snap content hash is like a Nix store path. We could even integrate Nix for building snaps or packages, but we still use snaps as deployment format for easier distribution.

**System Immutability:** By having an immutable system image, anonymOS achieves a *firm* consistency: you can’t have accidental modifications to critical system files, because they reside in read-only mounts. If someone tries to tamper with `/usr/bin/ls` for instance, they can’t – it’s in a squashfs snap. This thwarts many kinds of persistent malware that rely on modifying system binaries. To alter those, an attacker would have to either break out of confinement and remount stuff RW (which is non-trivial with kernel enforcement) or trick the update system to install a compromised snap (which again requires signature and hash, which ties back to needing the signing key or breaking crypto).

**Declarative User Environment:** Not only system services, but users’ environment can be declarative. For example, the config could specify “user Alice’s environment should have these 5 apps installed and these dotfiles and settings.” The system could ensure those by e.g. pulling snaps and placing config files in her home (with templating). This extends the reproducibility to userland.

**Continuous Integration with Source:** Because the config defines the whole system, you can have a GitOps style workflow – store config in git, do code reviews for OS changes, and have automated builds produce new images or deploy new configs to devices. This is especially useful for fleets of devices (IoT, servers) running anonymOS – they all take config updates from a repo or blockchain, and autonomously reconfigure in a controlled way.

In summary, **anonymOS’s declarative, snap-based system gives you the best of both worlds**:

* The *predictability and rollback safety* of NixOS’s functional approach.
* The *modularity, immutability, and security* of Ubuntu Core’s snaps.
* Combined through automation that reads a single source of truth (the config) to build the system state.

For developers, this means less time debugging “it works on my machine” issues – if two devs share the config, they have essentially the same OS setup. For operators, it means confident updates – update the config (or accept one from upstream), and either it works (in which case you’re running the new version) or it fails and you’re automatically back to previous state (no half-upgraded, broken systems). And for security, it means a smaller attack surface (since you’re not leaving random old software lingering, and the system is mostly read-only).

## Developer Quick Start

This section explains how to build and run anonymOS from source for development or testing. It assumes you have a Unix-like development environment (e.g., a Linux machine) with necessary build tools installed.

### Prerequisites

* **Operating System:** Linux (recommended) or macOS as a host. Building on Windows is not currently supported.
* **Dependencies:** You will need GCC or Clang, GNU Make, and standard Unix build utilities. Also install QEMU (if you plan to run in a VM) and Git. If using Debian/Ubuntu as host, you can install dependencies with: `sudo apt-get install build-essential git qemu-system-x86`. For Fedora: `sudo dnf install @development-tools git qemu-system-x86`.
* **Bootloader tools:** Install `grub-mkrescue` and `xorriso` for ISO creation (e.g., `sudo apt-get install grub-pc-bin xorriso mtools`).
* **Rust (optional):** If parts of anonymOS are implemented in Rust (capability system or services), ensure Rust toolchain is installed (via rustup).

### Building from Source

1. **Fetch the Source Code:** Clone the anonymOS repository from the official source.

   ```bash
   git clone https://github.com/anonymOS/anonymOS.git
   cd anonymOS
   ```

2. **Configure Build Options:** anonymOS may provide a `config.mk` or use environment variables to configure optional features. For example, you can set `ENABLE_ETHEREUM=1` to include Ethereum client support (if you have the libraries), or choose a target architecture. By default, the build targets x86\_64. If you need to adjust, open the top-level `Makefile` or config and set variables as needed.

3. **Build the System:** Use the provided Makefile to build the kernel and base system:

   ```bash
   make build
   ```

   This will compile the microkernel and all core user-space components, and then package them into a bootable image. The build system will output two main artifacts:

   * `anonymOS.iso` (or `.img`): a bootable disk image containing the kernel and core snaps.
   * `anonymOS.bin`: the raw kernel binary (for advanced use or direct boot).
     During compilation, you should see messages as it builds the kernel, then each service (file server, etc.), and finally assembles the image.

4. **View Build Output:** If all goes well, the build finishes with a message indicating where the image is. For example:

   ```
   Build complete. Bootable image created at build/anonymOS.iso
   ```

   You can inspect `build/` directory for logs or intermediate files. The snaps or packages that were built will be under `build/snaps/` with their content hashes.

### Running anonymOS (Emulated)

You can test anonymOS in QEMU (an open-source emulator) without installing on real hardware. For extra isolation, you can run the kernel in Docker with `scripts/kernel_isolate.sh` if Docker is installed:

1. **Basic QEMU Run:** Use the provided Make target to run with QEMU:

   ```bash
   make run
   ```

   This typically invokes QEMU with appropriate options, e.g.:

   ```bash
   qemu-system-x86_64 -m 1024 -smp 2 -drive format=raw,file=build/anonymOS.iso,if=virtio -serial stdio
   ```

   This command allocates 1024 MB of RAM, 2 CPU cores, sets up the image as a virtio drive, and connects the VM’s serial console to your terminal (so you can see boot logs).

2. **Boot Process:** Once QEMU starts, you should see the bootloader and then the anonymOS kernel booting. The system now launches the `ttyShelly` shell by default on the serial console. This interactive shell is compiled using the Shelly sources located under `dependencies/ttyShelly`. On first boot, anonymOS might generate some keys (for host identity) – this will be indicated in the log. You might see log lines from the microkernel and then from various services as they start up.

3. **Login:** If prompted to log in and you haven’t configured an Ethereum-based login for testing, use the default development login. The default user is usually `wcuser` with password `wcpass` (these are set in the default config for development mode). Enter those credentials to get a shell. If the system is configured for Ethereum login only, you would instead follow instructions to sign a token – but by default, developer builds have a fallback login.

4. **Explore the System:** Once logged in, you can explore:

   * Run `ls /` to see the top-level filesystem. You’ll find unconventional layout due to namespaces (for instance, `/proc` might be there provided by our process server, `/dev` with device files, etc.).
   * Try basic commands: `echo hello > /dev/cons` (this should print “hello” on the console, since `/dev/cons` is the console output file in Plan9/anonymOS).
   * Check the network: if a userland network stack is running, you can try `ping`. In this early stage it might not be fully set up. If not, you can start the network service manually or ensure QEMU’s networking is enabled (the `make run` uses user networking by default).
   * View logs: `cat /logs/audit` or similar to see if audit logs are being recorded (could be empty if nothing has happened).
   * List snaps: `ls /snap` to see mounted snaps and their versions.

5. **Shut Down:** To exit QEMU, you can either type the shutdown command in the VM (e.g., `sudo halt` or `poweroff` if those are supported) or simply close QEMU. The OS is still in development, so graceful shutdown may not be fully implemented – in many cases, closing the QEMU window or pressing `Ctrl-A X` (if using QEMU monitor hotkeys) will suffice.

### Containerizing Userland with Docker

For additional isolation of user services, a Docker setup is provided. The Docker image uses a minimal Alpine Linux base so only minimal packages are included. Use the helper script to build and run a container containing the anonymOS userland utilities:

```bash
scripts/docker_run.sh --build   # build the Docker image
scripts/docker_run.sh           # run the image interactively
```

Pass `--dry-run` to preview the Docker command without executing it. This container does not run the kernel; it merely hosts userland processes in a secure environment.

### Isolating System Services with Docker

System services can also be launched inside containers for extra security. The
`docker_service.sh` helper runs a service binary using the same Docker image but
shares the host namespaces so Plan 9 style per-process namespaces still work.
The host's Docker socket is mounted so any additional containers or virtual
machines started by these services execute alongside the system container rather
than nested within it.

```bash
scripts/docker_service.sh /path/to/service [args]
```

Use `--dry-run` for debugging to see the exact `docker run` invocation.

### System Configuration and Proxy Setup

anonymOS reads its system configuration from a JSON file located at
`anonymos_config/system.json`.  The configuration follows a declarative
style inspired by NixOS.  Within the `network` section you can specify
whether Tor should be started and provide a list of proxy entries in the
same format as `proxychains`:

```json
{
  "network": {
    "useTor": true,
    "proxyChains": [
      "socks5 127.0.0.1 9050",
      "http 192.0.2.1 8080"
    ],
    "pfsense": {
      "enabled": true,
      "method": "docker",
      "ip": "192.168.100.1"
    }
  }
}
```

The `network_proxy.sh` helper script reads this configuration.  It
generates a temporary proxychains configuration, launches Tor if
requested, and sets the `PROXYCHAINS_CONF` environment variable so that
outgoing connections can be routed through the configured chain.  When
`pfsense.enabled` is present the script also calls `pfsense_setup.sh` to
start the firewall and update the default route.
Pass `--dry-run` to see the commands it would execute.

If the `pfsense.enabled` flag is set, you can start a pfSense firewall
either inside Docker or a lightweight VM using the `pfsense_setup.sh`
helper. After pfSense is launched, the script adjusts the default route
to send all outbound traffic through the firewall's IP address.
This allows anonymOS to route network traffic through an isolated
pfSense instance for additional security.

### Running anonymOS in Virtual Machines

To test with hardware virtualization, use the `virtual_run.sh` script which
invokes QEMU with KVM acceleration when available:

```bash
scripts/virtual_run.sh --dry-run   # show the qemu command
scripts/virtual_run.sh             # boot the ISO with KVM if supported
```
This allows you to run anonymOS in a fast virtual machine environment similar to how RancherOS leverages Docker for services.



### Isolating the Kernel with Docker

To run the kernel itself in a container, use `scripts/kernel_isolate.sh`. This helper boots the ISO inside a Docker container with QEMU installed (from `Dockerfile.kernel`). The image is based on Alpine for minimal size. If Docker is not available, it falls back to `scripts/virtual_run.sh`.

```bash
scripts/kernel_isolate.sh --build   # build the Docker image
scripts/kernel_isolate.sh --dry-run # show the command
scripts/kernel_isolate.sh           # boot inside Docker
```


### Hardware Abstraction and Networking

Hardware drivers are isolated from the host using containers. The helper script
`hardware_isolate.sh` launches a driver inside a Docker container. If Docker is
unavailable, it falls back to an LXC virtual machine. This keeps peripherals
separate from each other and from the main OS.

The networking stack is implemented as one of these isolated drivers. A stub
implementation lives in `kernel/hardware/network.d` and is exercised by a unit
test. In practice, real drivers would run in their own containers using the same
helper.

Example dry run:

```bash
scripts/hardware_isolate.sh --dry-run --device /dev/net/tun net-driver
```

### Process Memory Virtualization

Each process receives a private virtual address space managed by a small
allocator in `kernel/memory/virtmem.d`.  Pages are backed by the host heap and
grow on demand, so from the process perspective the memory appears
effectively unlimited.  Other processes cannot access this memory unless a
capability is explicitly shared. 

### Running on Real Hardware (Experimental)

If you want to try anonymOS on a real machine:

* Write the image to a USB drive:

  ```bash
  sudo dd if=build/anonymOS.iso of=/dev/sdX bs=4M status=progress
  sync
  ```

  (Replace `/dev/sdX` with your USB drive path, be **very careful** to choose the correct drive).
* Boot your target PC from this USB. Ensure secure boot is off (or you have enrolled the test keys, since our build might not have a signed bootloader for Secure Boot).
* The system should boot into the same environment as QEMU. Keep in mind hardware support is limited (only basic virtio, some Intel/AMD chipset devices). This is primarily for developers to experiment; it’s not production-ready on diverse hardware yet.

### Rebuilding and Development Cycle

During development, you might edit parts of the code (say the kernel or a service) and want to rebuild quickly. The build system is incremental; you can run `make` again and it will recompile changed components. Use `make clean` if you want to force a full rebuild.

If you’re hacking on a specific component:

* Kernel: The kernel code is under `kernel/`. After changes, `make build` will produce a new kernel. You can often test it by just running QEMU again (the image includes the kernel, but for speed you could also set QEMU to boot the kernel directly with `-kernel` option).
* Services: Services are usually user-space programs under `services/<name>/`. If you change one, it will rebuild and repack the image. Alternatively, inside a running system, you could compile a service and replace it for quick testing (since we have a dev environment in QEMU).
* Configuration: The default config used for the image build is `anonymos_config/system.json`. Editing this file lets you control which services are enabled and how networking proxies are configured.

For debugging, you can enable verbose logging or use QEMU’s gdb stub to attach a debugger to the kernel. For user-space, since each service is a normal program, you can also run them under gdb inside QEMU if you have the binary and gdb server set up.

The project is evolving rapidly, so for the latest developer documentation (like coding style, etc.), please see the `CONTRIBUTING.md` and `docs/` directory in the repository.

## License and Contribution Guidelines

**License:** anonymOS is an open-source project. All original code in this project is licensed under the **MIT License** (an OSI-approved permissive license) unless otherwise noted. This allows you to use, modify, and distribute the code freely as long as you include the copyright notice. Some components integrated into anonymOS (for example, the Ethereum client library, or any third-party snaps) may be under different licenses (e.g., GPL or Apache); please check the `LICENSES` subdirectory for third-party license notices and ensure compliance if you redistribute.

By contributing to anonymOS, you agree that your contributions will be licensed under the MIT License, so that they can be incorporated into the project under the same terms.

**Contribution Guidelines:** We welcome contributions from the community! To ensure a smooth process, please adhere to the following:

* **Development Workflow:** We use GitHub for our repository and issue tracking. To contribute, fork the repo, create a feature branch (descriptive name please), commit your changes with clear messages, and open a Pull Request (PR) against the `main` branch. Describe your changes thoroughly in the PR description, including the problem and solution.
* **Coding Style:** We follow a strict coding style for C (kernel) and Rust (services) code. Generally, use `clang-format` for C code (style file provided) and `rustfmt` for Rust. Write clear, maintainable code with comments for any complex logic. All public functions should have doc comments.
* **Commit Sign-off:** All commits must be *signed off* (add `Signed-off-by: Your Name <email>` in the commit message) to certify the contribution under the project’s license (this is a Developer Certificate of Origin (DCO) requirement).
* **Discussion and Design:** For significant changes, we encourage discussing in an issue or the Discord/Matrix chat before implementation. This helps ensure the approach aligns with the project’s goals. Design proposals can be added to the `docs/proposals` directory or shared via issue for feedback.
* **Branch Protection:** The `main` branch is protected; all PRs require at least one approval from a core maintainer and a passing CI build.
* **Community Conduct:** We have a Code of Conduct (see `CODE_OF_CONDUCT.md`) to foster a respectful, collaborative environment. Please be kind and professional in all interactions.

By following these guidelines, you help us maintain project quality and velocity. We value every contributor’s effort and look forward to building anonymOS together as a community-driven, next-gen OS platform.

---

*Thank you for exploring anonymOS.* We aimed to create a system that pushes the boundary of what an operating system can do by integrating proven ideas from the past with promising technologies of the present (and future). Whether you’re interested in hacking on the kernel, writing a service, or building decentralized apps that leverage anonymOS’s features, we welcome you. Together, let’s turn the vision of a secure, decentralized, and elegant “world computer” operating system into reality.
