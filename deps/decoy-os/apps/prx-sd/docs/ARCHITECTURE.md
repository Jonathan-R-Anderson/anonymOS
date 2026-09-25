# Architecture

PRX-SD is structured as a Cargo workspace with modular crates, each responsible for a specific domain.

## Workspace Layout

```
prx-sd/
├── crates/
│   ├── cli/           # "sd" binary — command-line interface
│   ├── core/          # Scan engine coordination
│   ├── signatures/    # Hash DB (LMDB) + YARA-X rule engine
│   ├── parsers/       # Binary format parsers
│   ├── heuristic/     # Heuristic scoring + ML inference
│   ├── realtime/      # File system monitoring + network filtering
│   ├── quarantine/    # Encrypted quarantine vault
│   ├── remediation/   # Threat response actions
│   ├── sandbox/       # Process isolation + behavior analysis
│   ├── plugins/       # WebAssembly plugin runtime
│   └── updater/       # Signature update client
├── update-server/     # Signature distribution server (Axum)
├── gui/               # Desktop GUI (Tauri 2 + Vue 3)
├── drivers/           # OS kernel drivers
│   └── windows-minifilter/  # Windows file system minifilter (C)
├── signatures-db/     # Embedded minimal signatures
├── packaging/         # Distribution packaging
├── tests/             # Integration tests
├── tools/             # Build and utility scripts
├── install.sh         # Installation script
└── uninstall.sh       # Uninstallation script
```

## Crate Dependency Graph

```
cli
 ├── core
 │    ├── signatures
 │    │    └── (heed, yara-x, sha2, md5)
 │    ├── parsers
 │    │    └── (goblin)
 │    └── heuristic
 │         └── (tract-onnx [optional])
 ├── realtime
 │    ├── core
 │    └── (notify, nix [linux], adblock)
 ├── quarantine
 │    └── (aes-gcm, rand)
 ├── remediation
 │    ├── quarantine
 │    └── (nix [unix])
 ├── sandbox
 │    └── (nix [unix])
 ├── plugins
 │    └── (wasmtime, wasmtime-wasi)
 └── updater
      └── (ed25519-dalek, zstd, reqwest)
```

## Detection Pipeline

The scan engine (`core`) coordinates a multi-layer detection pipeline:

```
                    ┌──────────────┐
                    │  File Input  │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ Magic Number │  Identify: PE, ELF, MachO,
                    │  Detection   │  PDF, ZIP, Office, unknown
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐    │     ┌──────▼──────┐
       │    Hash      │    │     │   YARA-X    │
       │  Matching    │    │     │   Rules     │
       │  (LMDB)     │    │     │  (38K+)     │
       └──────┬──────┘    │     └──────┬──────┘
              │     ┌─────▼─────┐      │
              │     │ Heuristic │      │
              │     │ Analysis  │      │
              │     └─────┬─────┘      │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │ ML Inference│     │
              │    │  (ONNX)    │     │
              │    └──────┬─────┘     │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │ VirusTotal  │     │
              │    │ Cloud Query │     │
              │    └──────┬─────┘     │
              │           │            │
              └───────────┼────────────┘
                          │
                   ┌──────▼──────┐
                   │  Aggregate  │
                   │   Verdict   │
                   └─────────────┘
                   Clean / Suspicious / Malicious
```

### Layer Details

1. **Hash Matching** — O(1) lookup against LMDB database containing SHA-256 and MD5 hashes from ClamAV, abuse.ch, VirusShare, and custom blocklists.

2. **YARA-X Rules** — Pattern matching using the YARA-X engine (Rust-native YARA implementation). Rules are loaded from embedded defaults and the external signatures repository.

3. **Heuristic Analysis** — File-type-specific analysis:
   - **PE:** Section entropy, suspicious API imports (CreateRemoteThread, VirtualAllocEx), packer detection (UPX, Themida), timestamp anomalies
   - **ELF:** Section entropy, LD_PRELOAD references, cron/systemd persistence, SSH backdoor patterns
   - **MachO:** Section entropy, dylib injection, LaunchAgent persistence, Keychain access

4. **ML Inference** (optional, feature flag `onnx`) — ONNX model evaluation via tract:
   - PE: 64-dimensional feature vector (import table hashes, section entropy, API signatures)
   - ELF: 48-dimensional feature vector (section entropy, symbol table, dynamic libraries)

5. **VirusTotal Cloud** — Fallback for files not matched locally. Queries the VirusTotal API (free tier: 500 queries/day). Results are cached in LMDB.

### Scoring

- Score >= 60: **Malicious**
- Score 30-59: **Suspicious**
- Score < 30: **Clean**

The final verdict is the highest threat level from any detection layer.

## Real-time Protection

The `realtime` crate provides continuous protection through multiple subsystems:

| Subsystem | Linux | macOS | Windows |
|-----------|-------|-------|---------|
| File monitoring | fanotify + epoll | FSEvents (notify) | ReadDirectoryChangesW (notify) |
| Process interception | FAN_OPEN_EXEC_PERM | - | Minifilter (planned) |
| Memory scanning | /proc/pid/mem | - | - |
| Ransomware detection | Write+rename pattern monitoring | Write+rename pattern monitoring | Write+rename pattern monitoring |
| Protected directories | ~/.ssh, /etc/shadow, /etc/systemd | ~/Library, /etc | Registry Run keys |
| DNS filtering | Adblock engine + IOC lists | Adblock engine + IOC lists | Adblock engine + IOC lists |
| Behavior monitoring | /proc + audit (execve/connect/open) | - | - |

## Quarantine Vault

Files are quarantined using AES-256-GCM authenticated encryption:

1. Generate random 256-bit key + 96-bit nonce
2. Encrypt file contents with AES-256-GCM
3. Store encrypted file with UUID filename
4. Save JSON metadata (original path, hash, threat name, timestamp)
5. Restore decrypts and verifies integrity before writing back

## Remediation Pipeline

When `--remediate` is used:

```
Threat Detected
  ├── 1. Kill Process     (SIGKILL on Linux/macOS, TerminateProcess on Windows)
  ├── 2. Quarantine File  (AES-256-GCM encrypted vault)
  └── 3. Clean Persistence
        ├── Linux:   cron jobs, systemd services, LD_PRELOAD
        ├── macOS:   LaunchAgents, plist entries, Keychain
        └── Windows: Run/RunOnce registry, scheduled tasks, services
```

Actions are configurable via `sd policy set`.

## Signature Database

### Embedded Signatures (`signatures-db/`)

Minimal signature set compiled into the `sd` binary via `include_str!`:
- EICAR test signature
- Core YARA rules (ransomware, trojan, backdoor, etc.)
- Known malware hashes (WannaCry, Emotet, NotPetya)

### External Signatures ([prx-sd-signatures](https://github.com/openprx/prx-sd-signatures))

Comprehensive, frequently-updated threat intelligence:
- 38,800+ YARA rules from 9 sources
- Hash blocklists from abuse.ch feeds
- IOC lists: 585K+ malicious IPs, domains, URLs

### Storage

- **Hashes:** LMDB (heed crate) for O(1) key-value lookups
- **YARA rules:** Loaded and compiled by YARA-X at startup
- **IOC lists:** In-memory HashSet for fast IP/domain/URL matching

## Plugin System

PRX-SD supports WebAssembly plugins via Wasmtime:

- Plugins are `.wasm` files with a manifest (`plugin.json`)
- WASI support for file system and environment access
- Plugin registry for discovery and loading
- Host functions exposed to plugins for scan results and configuration

## Update System

The `updater` crate and `update-server` provide a secure update pipeline:

1. Client checks update server for new signature versions
2. Server responds with version info and download URL
3. Client downloads zstd-compressed signature package
4. Package signature verified with Ed25519 (ed25519-dalek)
5. Signatures extracted and loaded into LMDB

## GUI Application

Built with Tauri 2 (Rust backend) + Vue 3 (TypeScript frontend):

- System tray integration with status indicator
- Dashboard with threat statistics
- Drag-and-drop file scanning
- Quarantine browser with restore/delete
- Real-time monitoring controls
- Settings and configuration
- Multi-language support (10 languages)

## Key Dependencies

| Category | Crate | Version | Purpose |
|----------|-------|---------|---------|
| Async | tokio | 1.x | Async runtime |
| Parallelism | rayon | - | Thread pool for scanning |
| YARA | yara-x | 1.14 | Rule matching engine |
| Database | heed | - | LMDB bindings |
| Binary parsing | goblin | 0.9 | PE/ELF/MachO parser |
| Crypto | aes-gcm | - | Quarantine encryption |
| Crypto | ed25519-dalek | - | Update verification |
| ML | tract-onnx | - | ONNX inference (optional) |
| WASM | wasmtime | 29 | Plugin runtime |
| DNS | adblock | 0.12 | Brave adblock engine |
| CLI | clap | 4.x | Argument parsing |
| HTTP | axum | 0.8 | Update server |
