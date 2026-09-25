# PRX-SD

**Open-source antivirus engine for Linux, macOS, and Windows.**

PRX-SD provides multi-layered threat detection combining hash signatures, YARA rules, heuristic analysis, and machine learning — with real-time file system protection, CLI tooling, and a desktop GUI.

## Features

- **Multi-layer Detection** — SHA-256/MD5 hash matching, 38K+ YARA rules (via YARA-X), heuristic scoring, and optional ONNX-based ML inference
- **Real-time Protection** — File system monitoring with process interception (fanotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows); fanotify pre-execution blocking requires root and is Linux only
- **Ransomware Defense** — Detects bulk encryption patterns and auto-blocks malicious processes
- **Memory Scanning** — Scan running process memory for in-memory threats (Linux only, requires root)
- **Network Protection** — IOC-based IP/domain/URL filtering, DNS proxy with adblock engine
- **Automated Response** — Kill processes, quarantine files (AES-256-GCM encrypted vault), clean persistence mechanisms
- **ClamAV Compatible** — Import ClamAV `.cvd`/`.hdb`/`.hsb` signature databases
- **VirusTotal Integration** — Cloud lookup for unknown files (free API, 500 queries/day)
- **Rootkit Detection** — Hidden process detection, kernel module verification, LD_PRELOAD checks (Linux only, requires root)
- **eBPF Runtime Monitoring** — Kernel-level syscall tracing and anomaly detection (Linux only, feature-gated via `--features ebpf`)
- **Sandboxing** — Process isolation via ptrace/seccomp/namespaces with behavior analysis
- **Desktop GUI** — Tauri 2 + Vue 3 application with system tray, drag-and-drop scanning, dashboard
- **Plugin System** — Extend with custom WebAssembly (WASM) plugins
- **Cross-platform** — Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64)

## Installation

### Install Script (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash
```

### Homebrew (macOS / Linux)

```bash
brew install openprx/tap/sd
```

### Scoop (Windows)

```powershell
scoop bucket add openprx https://github.com/openprx/scoop-bucket
scoop install sd
```

### Build from Source

```bash
# Prerequisites: Rust 1.70+, pkg-config, openssl-dev
git clone https://github.com/openprx/prx-sd.git
cd prx-sd
cargo build --release
# Binary: target/release/sd
```

See [Building](docs/BUILDING.md) for full build instructions including GUI and cross-compilation.

## Basic Usage

```bash
# Scan a file
sd scan /path/to/file

# Scan a directory recursively
sd scan /home --recursive

# Scan and auto-quarantine threats
sd scan /tmp --auto-quarantine

# Real-time monitoring
sd monitor /home /tmp

# Run as background daemon
sd daemon /home /tmp

# Update signature database
sd update

# View engine info and signature stats
sd info
```

### Output Formats

```bash
# JSON output (for scripting)
sd scan /path --json

# HTML report
sd scan /path --report report.html
```

## Detection Pipeline

```
File Input -> Magic Number Detection (PE/ELF/MachO/PDF/ZIP/Office)
  |
  +-- 1. Hash Matching     (LMDB O(1) lookup — fastest)
  +-- 2. YARA-X Rules      (38K+ pattern matching rules)
  +-- 3. Heuristic Analysis (entropy, suspicious APIs, packer detection)
  +-- 4. ML Inference       (ONNX models via tract — optional)
  +-- 5. VirusTotal Cloud   (API fallback for unknown files)
  |
  +-> Aggregate -> Verdict: Clean / Suspicious / Malicious
```

## Architecture

PRX-SD is a Cargo workspace with modular crates:

| Crate | Purpose |
|-------|---------|
| `cli` | Command-line interface (`sd` binary) |
| `core` | Scan engine coordination |
| `signatures` | Hash database (LMDB) + YARA-X rule engine |
| `parsers` | Binary format parsers (PE/ELF/MachO/PDF/Office) |
| `heuristic` | Heuristic scoring + ML model inference |
| `realtime` | File system monitoring + ransomware detection |
| `quarantine` | AES-256-GCM encrypted quarantine vault |
| `remediation` | Threat response (kill/quarantine/cleanup) |
| `sandbox` | Process isolation + behavior analysis |
| `plugins` | WebAssembly plugin runtime (Wasmtime) |
| `updater` | Signature update client (Ed25519 verified) |

See [Architecture](docs/ARCHITECTURE.md) for details.

## CLI Reference

PRX-SD provides 20+ commands. Here are the most common ones:

| Command | Description |
|---------|-------------|
| `sd scan <PATH>` | Scan files/directories for threats |
| `sd monitor <PATHS...>` | Real-time file system monitoring |
| `sd daemon [PATHS...]` | Run as background daemon |
| `sd quarantine list\|restore\|delete` | Manage quarantined files |
| `sd update` | Update signature database |
| `sd import <FILE>` | Import custom hash blocklist |
| `sd import-clamav <FILES...>` | Import ClamAV signatures |
| `sd config show\|set\|reset` | Manage configuration |
| `sd schedule add\|remove\|status` | Scheduled scanning |
| `sd policy show\|set\|reset` | Remediation policy |
| `sd scan-memory [--pid PID]` | Scan process memory for in-memory threats (Linux only) |
| `sd check-rootkit` | Detect rootkit indicators (Linux only) |
| `sd scan-usb [DEVICE]` | Scan USB/removable media |
| `sd adblock` | DNS-level ad/malware blocking |
| `sd community` | Community threat intelligence sharing |
| `sd dns-proxy` | Local DNS proxy with filtering |
| `sd info` | Engine and database info |
| `sd status` | Daemon status |
| `sd self-update` | Update the sd binary |

See [CLI Reference](docs/CLI.md) for the full command documentation.

## Signature Database

PRX-SD ships with a minimal embedded signature set for basic detection out of the box. For comprehensive protection, use the [prx-sd-signatures](https://github.com/openprx/prx-sd-signatures) repository which aggregates 38,800+ YARA rules and threat intelligence from multiple sources:

- **abuse.ch** — MalwareBazaar, URLhaus, Feodo Tracker
- **Neo23x0/signature-base** — APT and crime detection rules
- **Yara-Rules/rules** — Community YARA rules
- **ReversingLabs** — Commercial-grade open-source rules
- **Elastic** — Endpoint protection rules
- **ESET** — APT tracking IOCs
- **IOC Feeds** — 585K+ malicious IPs, domains, and URLs

Update signatures:

`sd update` downloads from [openprx/prx-sd-signatures](https://github.com/openprx/prx-sd-signatures) on GitHub by default — no configuration needed. A custom update server URL can be set for air-gapped or mirrored environments.

```bash
# Default: downloads from GitHub (no config needed)
sd update

# Check for updates without downloading
sd update --check-only

# Force re-download
sd update --force

# Use a custom update server (for air-gapped environments)
sd config set update_server_url https://my-mirror.example.com/v1
sd update

# Reset to GitHub default
sd config set update_server_url null
```

## Platform Support

| Platform | File Monitoring | Process Interception | Memory Scan | Remediation |
|----------|----------------|---------------------|-------------|-------------|
| Linux x86_64 | fanotify | FAN_OPEN_EXEC_PERM | /proc/pid/mem | systemd/cron |
| Linux aarch64 | fanotify | FAN_OPEN_EXEC_PERM | /proc/pid/mem | systemd/cron |
| macOS x86_64 | FSEvents | - | - | LaunchAgent |
| macOS aarch64 | FSEvents | - | - | LaunchAgent |
| Windows x86_64 | ReadDirectoryChangesW | Minifilter (planned) | - | Registry/Tasks |

## Uninstall

```bash
# Via install script
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash -s -- --uninstall

# Via Homebrew
brew uninstall sd

# Via Scoop
scoop uninstall sd
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

To report a security vulnerability, please see [SECURITY.md](SECURITY.md).

## License

PRX-SD is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

## Documentation

Documentation is available in 10 languages: [docs/README.md](docs/README.md)

| | | | | |
|---|---|---|---|---|
| [English](docs/CLI.md) | [中文](docs/zh/CLI.md) | [日本語](docs/ja/CLI.md) | [한국어](docs/ko/CLI.md) | [Español](docs/es/CLI.md) |
| [Français](docs/fr/CLI.md) | [Deutsch](docs/de/CLI.md) | [العربية](docs/ar/CLI.md) | [Русский](docs/ru/CLI.md) | [ქართული](docs/ka/CLI.md) |

## Links

- [Documentation](https://docs.openprx.dev/en/prx-sd/) — Full PRX-SD documentation (10 languages)
- [Community](https://community.openprx.dev) — OpenPRX community forum
- [CLI Reference](docs/CLI.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Building](docs/BUILDING.md)
- [Signatures Repository](https://github.com/openprx/prx-sd-signatures)
- [OpenPRX](https://openprx.dev)
