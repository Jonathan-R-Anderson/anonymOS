# Architecture Diagrams

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AnonymOS Boot Flow                          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────┐
│    GRUB     │  Loads kernel.elf from disk
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   boot.s    │  Sets up long mode, GDT, IDT, paging
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          kmain()                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 1. Initialize CPU state                                      │  │
│  │ 2. Probe hardware (multiboot info)                           │  │
│  │ 3. Initialize physical memory allocator                      │  │
│  │ 4. Set up page tables (kernel linear mapping)                │  │
│  │ 5. Initialize PCI bus                                        │  │
│  │ 6. Initialize AHCI (disk controller)                         │  │
│  └──────────────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│           ╔════════════════════════════════════════╗                │
│           ║  BLOCKCHAIN INTEGRITY VALIDATION      ║                │
│           ╚════════════════════════════════════════╝                │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Step 1: Initialize Network                                   │  │
│  │  ├─ Scan PCI for network devices                             │  │
│  │  ├─ Initialize driver (E1000/RTL8139/VirtIO)                 │  │
│  │  └─ Configure MAC address                                    │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           │                                         │
│                           ▼                                         │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Step 2: Initialize zkSync Client                             │  │
│  │  ├─ Configure RPC endpoint (IP:port)                         │  │
│  │  ├─ Set contract address                                     │  │
│  │  └─ Select mainnet/testnet                                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           │                                         │
│                           ▼                                         │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Step 3: Compute System Fingerprint                           │  │
│  │  ├─ SHA-256(kernel.elf)        → kernelHash                  │  │
│  │  ├─ SHA-256(boot.s compiled)   → bootloaderHash             │  │
│  │  ├─ SHA-256(initrd)            → initrdHash                  │  │
│  │  └─ SHA-256(manifest.json)     → manifestHash               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           │                                         │
│                           ▼                                         │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Step 4: Perform Rootkit Scan                                 │  │
│  │  ├─ Verify kernel code sections                              │  │
│  │  ├─ Check IDT integrity                                      │  │
│  │  ├─ Validate syscall table                                   │  │
│  │  └─ Detect hidden processes                                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           │                                         │
│                           ▼                                         │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Step 5: Validate Against Blockchain                          │  │
│  │  ├─ Connect to zkSync RPC                                    │  │
│  │  ├─ Query smart contract                                     │  │
│  │  ├─ Retrieve stored fingerprint                              │  │
│  │  └─ Compare hashes                                           │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           │                                         │
│                           ▼                                         │
│                  ┌────────┴────────┐                                │
│                  │  Validation     │                                │
│                  │  Result         │                                │
│                  └────────┬────────┘                                │
│                           │                                         │
│         ┌─────────────────┼─────────────────┐                       │
│         │                 │                 │                       │
│         ▼                 ▼                 ▼                       │
│    ┌─────────┐      ┌──────────┐     ┌──────────┐                  │
│    │ Success │      │ Mismatch │     │ No Net   │                  │
│    └────┬────┘      └─────┬────┘     └─────┬────┘                  │
│         │                 │                 │                       │
│         ▼                 ▼                 ▼                       │
│  ┌──────────────┐   ┌─────────────────────────┐                    │
│  │ Boot         │   │ Boot Decoy OS           │                    │
│  │ Normally     │   │ (VeraCrypt Hidden)      │                    │
│  └──────────────┘   └─────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Blockchain Integration                         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                         Kernel Layer                                │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    kernel/kernel.d                            │  │
│  │  - Boot orchestration                                         │  │
│  │  - Component initialization                                   │  │
│  │  - Validation integration                                     │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Security Layer                                │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐  │
│  │ integrity.d      │  │ decoy_fallback.d │  │ veracrypt.d     │  │
│  │                  │  │                  │  │                 │  │
│  │ - SHA-256        │  │ - Policy logic   │  │ - Volume unlock │  │
│  │ - Fingerprinting │  │ - Fallback exec  │  │ - Decoy boot    │  │
│  │ - Rootkit detect │  │ - Security warn  │  │ - Password      │  │
│  └──────────────────┘  └──────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Blockchain Layer                               │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    blockchain/zksync.d                        │  │
│  │  - RPC connection                                             │  │
│  │  - Contract queries                                           │  │
│  │  - Fingerprint validation                                     │  │
│  │  - Transaction signing                                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Network Layer                                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    drivers/network.d                          │  │
│  │  - Device detection (PCI scan)                                │  │
│  │  - Driver initialization (E1000/RTL8139/VirtIO)               │  │
│  │  - Ethernet frame TX/RX                                       │  │
│  │  - MAC address management                                     │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Hardware Layer                                │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    Network Adapters                           │  │
│  │  - Intel E1000 (0x8086:0x100E)                                │  │
│  │  - Realtek RTL8139 (0x10EC:0x8139)                            │  │
│  │  - VirtIO Network (0x1AF4:0x1000)                             │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Validation Data Flow                             │
└─────────────────────────────────────────────────────────────────────┘

System Files                    Fingerprint Computation
┌─────────────┐                ┌─────────────────────┐
│ kernel.elf  │───SHA-256────▶ │ kernelHash          │
└─────────────┘                │ (32 bytes)          │
                               └─────────────────────┘
┌─────────────┐                ┌─────────────────────┐
│ boot.s      │───SHA-256────▶ │ bootloaderHash      │
└─────────────┘                │ (32 bytes)          │
                               └─────────────────────┘
┌─────────────┐                ┌─────────────────────┐
│ initrd      │───SHA-256────▶ │ initrdHash          │
└─────────────┘                │ (32 bytes)          │
                               └─────────────────────┘
┌─────────────┐                ┌─────────────────────┐
│ manifest    │───SHA-256────▶ │ manifestHash        │
└─────────────┘                │ (32 bytes)          │
                               └─────────────────────┘
                                        │
                                        ▼
                               ┌─────────────────────┐
                               │ SystemFingerprint   │
                               │ struct              │
                               └──────────┬──────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
                    ▼                     ▼                     ▼
         ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
         │ Local Storage    │  │ Blockchain Query │  │ Comparison       │
         │ (current)        │  │ (stored)         │  │                  │
         └──────────────────┘  └──────────────────┘  └────────┬─────────┘
                                                               │
                                                               ▼
                                                      ┌─────────────────┐
                                                      │ ValidationResult│
                                                      └────────┬────────┘
                                                               │
                                                               ▼
                                                      ┌─────────────────┐
                                                      │ FallbackPolicy  │
                                                      └────────┬────────┘
                                                               │
                                                               ▼
                                                      ┌─────────────────┐
                                                      │ Boot Decision   │
                                                      └─────────────────┘
```

## Network Communication

```
┌─────────────────────────────────────────────────────────────────────┐
│                Network Communication Flow                           │
└─────────────────────────────────────────────────────────────────────┘

AnonymOS                                              zkSync Era
┌─────────────┐                                      ┌─────────────┐
│             │                                      │             │
│  zkSync     │                                      │  RPC Node   │
│  Client     │                                      │             │
│             │                                      │             │
└──────┬──────┘                                      └──────▲──────┘
       │                                                    │
       │  1. TCP SYN                                        │
       ├───────────────────────────────────────────────────▶│
       │                                                    │
       │  2. TCP SYN-ACK                                    │
       │◀───────────────────────────────────────────────────┤
       │                                                    │
       │  3. TCP ACK                                        │
       ├───────────────────────────────────────────────────▶│
       │                                                    │
       │  4. HTTP POST (JSON-RPC)                           │
       │     {                                              │
       │       "jsonrpc": "2.0",                            │
       │       "method": "eth_call",                        │
       │       "params": [{                                 │
       │         "to": "0x...",  // contract address        │
       │         "data": "0x..." // getFingerprint()        │
       │       }],                                          │
       │       "id": 1                                      │
       │     }                                              │
       ├───────────────────────────────────────────────────▶│
       │                                                    │
       │                                    ┌───────────────┤
       │                                    │ Query Smart   │
       │                                    │ Contract      │
       │                                    └───────────────┤
       │                                                    │
       │  5. HTTP 200 OK (JSON-RPC Response)                │
       │     {                                              │
       │       "jsonrpc": "2.0",                            │
       │       "result": "0x...", // fingerprint data       │
       │       "id": 1                                      │
       │     }                                              │
       │◀───────────────────────────────────────────────────┤
       │                                                    │
       │  6. TCP FIN                                        │
       ├───────────────────────────────────────────────────▶│
       │                                                    │
       ▼                                                    ▼
┌─────────────┐                                      ┌─────────────┐
│  Parse      │                                      │             │
│  Response   │                                      │             │
└─────────────┘                                      └─────────────┘
```

## Smart Contract Interaction

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Smart Contract Architecture                        │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                    SystemIntegrity.sol                              │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                      State Variables                          │ │
│  │  - mapping(address => Fingerprint) fingerprints               │ │
│  │  - mapping(address => AuditEntry[]) auditTrail                │ │
│  │  - bool globalFreeze                                          │ │
│  │  - address contractOwner                                      │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                    Public Functions                           │ │
│  │                                                               │ │
│  │  updateFingerprint(...)                                       │ │
│  │    ├─ Validate not frozen                                     │ │
│  │    ├─ Store fingerprint                                       │ │
│  │    ├─ Add to audit trail                                      │ │
│  │    └─ Emit event                                              │ │
│  │                                                               │ │
│  │  getFingerprint(address) → Fingerprint                        │ │
│  │    └─ Return stored fingerprint                               │ │
│  │                                                               │ │
│  │  verifyFingerprint(address, hashes) → bool                    │ │
│  │    ├─ Get stored fingerprint                                  │ │
│  │    ├─ Compare all hashes                                      │ │
│  │    └─ Return match result                                     │ │
│  │                                                               │ │
│  │  freezeFingerprint()                                          │ │
│  │    └─ Set frozen flag                                         │ │
│  │                                                               │ │
│  │  authorizeUpdater(address)                                    │ │
│  │    └─ Add to authorized list                                  │ │
│  │                                                               │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                        Events                                 │ │
│  │  - FingerprintUpdated(owner, kernelHash, timestamp, version)  │ │
│  │  - FingerprintFrozen(owner, timestamp)                        │ │
│  │  - UpdaterAuthorized(owner, updater, timestamp)               │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Security Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Defense in Depth                               │
└─────────────────────────────────────────────────────────────────────┘

Layer 1: Cryptographic Verification
┌─────────────────────────────────────────────────────────────────────┐
│  SHA-256 hashing of all critical system components                 │
│  - Kernel binary                                                    │
│  - Bootloader code                                                  │
│  - Initial ramdisk                                                  │
│  - System manifest                                                  │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
Layer 2: Blockchain Immutability
┌─────────────────────────────────────────────────────────────────────┐
│  Fingerprints stored on zkSync Era blockchain                       │
│  - Cannot be altered once recorded                                  │
│  - Timestamped and auditable                                        │
│  - Decentralized (no single point of failure)                       │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
Layer 3: Rootkit Detection
┌─────────────────────────────────────────────────────────────────────┐
│  Multiple detection techniques                                      │
│  - Kernel code section verification                                 │
│  - IDT integrity checking                                           │
│  - Syscall table validation                                         │
│  - Hidden process detection                                         │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
Layer 4: Automatic Fallback
┌─────────────────────────────────────────────────────────────────────┐
│  Fail-safe boot policy                                              │
│  - Validation failure → Boot decoy OS                               │
│  - No network → Boot decoy OS                                       │
│  - Unknown error → Boot decoy OS                                    │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
Layer 5: Plausible Deniability
┌─────────────────────────────────────────────────────────────────────┐
│  VeraCrypt hidden volume                                            │
│  - Decoy OS appears to be real system                               │
│  - Real system remains encrypted and hidden                         │
│  - Attacker cannot prove existence of real system                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

**Note**: These diagrams are ASCII art representations. For production documentation, consider using tools like PlantUML, Mermaid, or draw.io to create professional diagrams.
