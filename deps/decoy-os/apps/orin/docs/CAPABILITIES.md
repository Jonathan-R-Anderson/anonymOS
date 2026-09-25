# Capability Reference

Complete annotated catalogue of Orin's 57 implemented forensic capabilities, organized by functional domain.

---

## Process & Execution Monitoring

| # | Capability | Description |
|---|---|---|
| 1 | **Process Tree Harvester** | Reads `/proc/[pid]/stat`, `/comm`, `/exe`, and `/cmdline` to build a full PPID-linked process tree. |
| 7 | **In-Memory Executable Recovery** | Resolves `/proc/[pid]/exe` symlinks to detect running processes whose on-disk binaries have been unlinked. Dumps the payload and records MD5 and SHA-256 hashes. |
| 10 | **Hidden Process Detector** | Probes scheduler-active PIDs via null signaling (`os.kill(pid, 0)`) and cross-references against `/proc` to expose kernel rootkit-hidden processes. |
| 20 | **SUID/SGID Binary Monitor** | Discovers executables with SUID/SGID bits set and alerts on any additions or modifications relative to the established baseline. |

---

## Network Telemetry

| # | Capability | Description |
|---|---|---|
| 2 | **Network Socket Auditor** | Parses `/proc/net/{tcp,tcp6,udp,udp6}` for all IPv4/IPv6 listening ports and outbound connections, with socket-to-PID resolution. |
| 8 | **Promiscuous Mode Flag Auditor** | Reads `/sys/class/net/*/flags` and raises alerts when the `IFF_PROMISC` (`0x100`) bit is set on any interface. |
| 31 | **DNS Forensics & Tunneling Detection** | Advanced DNS telemetry with Shannon entropy analysis, DGA domain detection, TXT record abuse detection, per-process DNS profiling, IOC matching, and live `/proc/net` monitoring. |
| 32 | **Triggered PCAP Capture Engine** | Zero-dependency packet capture on forensic trigger events. Scapy-based packet reconstruction when available; raw PCAP as fallback. |

---

## Kernel Integrity

| # | Capability | Description |
|---|---|---|
| 3 | **Kernel Module & Symbol Auditor** | Reads `/proc/modules` and `/proc/kallsyms`. Detects modules hidden from `/proc/modules`, suspicious symbol overrides, credential-manipulation exports in third-party modules, and known rootkit patterns. |
| 22 | **eBPF & File Descriptor Auditor** | Audits loaded eBPF programs, pinned map/program objects under `/sys/fs/bpf`, dynamic linker preloads in `/etc/ld.so.preload`, and suspicious open file descriptors (deleted files, `memfd` anonymous segments). |
| 34 | **Identity, Access & Privilege Tracker** | PAM log parsing, eBPF probe detection, syscall audit analysis, and credential access tracking. Detects auth events, sudo/SSH logins, privilege escalation syscalls (`setuid`, `setgid`, `capset`, `ptrace`), and credential dumping. MITRE-mapped: T1548, T1078, T1552. |
| 35 | **eBPF Ring-Buffer Real-Time Streamer** | Streams real-time security events via kernel ring buffer attached to `sys_enter_execve`, `sys_enter_connect`, and `sys_enter_openat`. Events include PID, UID, command, filename, and nanosecond timestamps, queued to SQLite. Invoked via `orin stream`. |

---

## Persistence Detection

| # | Capability | Description |
|---|---|---|
| 4 | **User & SSH Key Inventory** | Harvests `/etc/passwd` and all `~/.ssh/authorized_keys` files for account enumeration and key fingerprint tracking. |
| 12 | **Scheduled Task Harvester** | Parses user crontabs, `/etc/crontab`, `/etc/cron.d/*`, and timed script directories. Detects cron drift, volatile-path execution, and reverse-shell commands. |
| 21 | **Agentless SSH Fleet Scanner** | Profiles remote hosts over SSH using a stdlib-only Python agent with a pure-Bash fallback. No persistent installation required on target systems. |

---

## File Integrity

| # | Capability | Description |
|---|---|---|
| 5 | **File Integrity Monitor (FIM)** | SHA-256 checksums for configured critical paths with stat-based look-back caching. `os.stat()` metadata (`mtime`, `ctime`, `size`) is compared before any hash is computed; unchanged files are skipped entirely. |
| 11 | **Offline Package Integrity Engine** | Verifies on-disk binaries against Debian `/var/lib/dpkg/info/*.md5sums`. MD5 is checked first; SHA-256 is computed lazily only on confirmed mismatch. |
| 30 | **Embedded YARA Engine** | Offline YARA pattern matching against files and dumped in-memory binaries. Pre-built rule sets for cryptocurrency miners, malware tools, rootkits, webshells, and suspicious strings. FIM-accelerated — only modified files are scanned. |

---

## Log Analysis & Session Auditing

| # | Capability | Description |
|---|---|---|
| 6 | **Auth Log Parser & Sigma Engine** | Scans authentication logs and `journald` records using a zero-dependency Sigma rules evaluator with dynamic MITRE ATT&CK tagging. |
| 9 | **Binary Session Auditor** | Parses `/var/log/wtmp` and `/var/log/lastlog` binary structures to track login/logout lifecycles and detect anti-forensic tampering (zeroed records, epoch resets). |

---

## Threat Detection & Analysis

| # | Capability | Description |
|---|---|---|
| 13 | **Threat Detection Rules Engine** | Evaluates all collected data against rules for masquerade processes, reverse shells, C2 blocklist hits, SSH persistence, FIM changes, unauthorized accounts, and cron anomalies. Supports per-alert suppression and severity overrides. |
| 14 | **Forensic Alert Auto-Resolution** | Automatically closes historical alerts when the anomalous condition is no longer present in subsequent snapshots. |
| 24 | **Local AI Forensic Triage** | Aggregates unresolved alerts across hosts and uses a local Ollama model to generate context-aware correlation briefs and remediation advice. Fully offline. |
| 25 | **Offline Threat Intel Importer** | Multi-format IOC importer: STIX 2.x JSON/XML, CSV, TAXII 2.x, plain-text blocklists. Normalizes indicators to a unified format. Zero network egress. |
| 26 | **MITRE ATT&CK Mapper** | Zero-dependency static lookup mapping Orin event types to ATT&CK technique IDs, tactics, and reference URLs. |
| 27 | **Snapshot Comparator (`orin diff`)** | Compares two forensic snapshots from SQLite vaults or signed JSON exports, producing structured drift reports with integrity verification. |
| 28 | **Timeline Delta Calculator (`orin delta`)** | Computes structural differences between two named snapshot IDs within the vault, surfacing triggered events and port/process/connection deltas. |

---

## Evidence & Cryptography

| # | Capability | Description |
|---|---|---|
| 15 | **Cryptographic Evidence Export** | Serializes snapshots to deterministic JSON, signs with HMAC-SHA256, and wraps in a portable `{signature, data}` bundle verifiable by `orin verify`. |
| 29 | **Encrypted Evidence Vault** | AES-256-GCM authenticated encryption at rest. PBKDF2-HMAC-SHA256 key derivation with 600,000 iterations (backward-compatible with legacy 100,000-iteration vaults). Random salt per vault. |
| 39 | **Secure Credential Handling** | `--passphrase-file` (0600-validated), `--passphrase-prompt` (masked input), `--passphrase-env-var` (evicted from `os.environ` after use). Dashboard token persistence via `--token-file` with 0600 permissions. |
| 40 | **Tool Self-Verification & Signed Releases** | GPG-signed release manifests with SHA-256 checksums, embedded SBOM via `orin version --sbom`, and runtime self-check via `--self-check`. |
| 48 | **Remote Agent Script Signing** | HMAC-SHA256 signing and verification for agentless SSH collection scripts. Dual-layer integrity checks (content hash + HMAC), constant-time comparison, metadata embedding for audit trails. |
| 49 | **Atomic Write Safety** | All encryption and decryption operations use temp-file + atomic rename patterns. No partial or plaintext evidence files are left on disk after a failure. |

---

## Reporting & Dashboard

| # | Capability | Description |
|---|---|---|
| 16 | **Markdown & HTML Reporting** | Generates lightweight Markdown briefings and self-contained dark-mode HTML dashboards with tabbed navigation and severity badges. |
| 17 | **Local Web Dashboard (`orin serve`)** | stdlib HTTP server with a live risk gauge, severity-tiered alert feed with triage actions, Telemetry Explorer, inline process termination (local/remote), and timeline delta shortcuts. Zero external JavaScript dependencies. |
| 19 | **Dashboard Auto-Token Security** | A cryptographically random 256-bit session token (`secrets.token_hex(32)`) is generated on each `orin serve` start and validated via `hmac.compare_digest()`. Ephemeral per restart. |
| 44 | **Dashboard API Endpoints** | `/api/alerts`, `/api/diff`, `/api/telemetry/{snapshot_id}`, `/api/config` — real-time data feeds, risk scoring, process termination, and timeline comparison. |
| 54 | **Health & Readiness Probes** | `/health` (always <1 ms: uptime, version, platform, vault-exists) and `/ready` (four sub-checks: vault exists/readable, has snapshots, `PRAGMA integrity_check`). Unauthenticated, available on both dashboard and hub. |
| 55 | **Operational Metrics Endpoint** | `GET /api/metrics`: process info, vault statistics, alert breakdown, collector row counts, and SQLite performance stats. Read-only, zero-dependency. |

---

## Operations & Infrastructure

| # | Capability | Description |
|---|---|---|
| 18 | **Automated Collection Scheduler** | Installs a system or user cron job running `collect → analyze` on a configurable interval (default: 10 minutes). Logs to syslog. |
| 23 | **Baseline Manager** | Incremental additions (`--user`, `--module`, `--suid`) and comprehensive refreshes (`--force-overwrite`) of system baselines for local and remote hosts. |
| 33 | **Agent Self-Defense Hardening** | AppArmor, SELinux, and Seccomp-BPF profiles that restrict Orin's own attack surface. Profiles enforce least-privilege file access, network restrictions, and syscall allowlists. |
| 36 | **Read-Only & Ephemeral Modes** | `--read-only` prevents vault writes for forensic acquisition on write-protected systems. `--vault-path` decouples the vault from the default path for USB or tmpfs operation. |
| 37 | **Vault Lifecycle Management** | `orin vault stats` shows database size and snapshot counts. `orin vault prune` deletes snapshots by age or count with dry-run support, critical-alert preservation, and automatic vacuuming. |
| 41 | **Centralized Air-Gapped Fleet Hub** | Multi-tenant server with bcrypt admin authentication, per-host API keys, rate limiting, comprehensive audit logging, host registration with heartbeat monitoring, and HTTPS support. |
| 42 | **Structured JSON Logging** | JSON-formatted logs to stderr and/or file with severity levels, rotation, thread-safe operation, and SIEM-friendly fields (timestamp, hostname, component, PID, context). |
| 47 | **Parallel Collection Engine** | `ThreadPoolExecutor`-based concurrent collection via `orin collect --parallel`. Configurable worker pools and per-collector timeouts. Reduces collection time from ~15–20 s to ~1.3 s on multi-core systems. |
| 53 | **Alert Forwarding Framework** | Slack Block Kit, Microsoft Teams Adaptive Cards, generic JSON webhooks, and syslog. Per-channel severity filters, exponential-backoff retry, and an append-only JSONL audit log. stdlib-only. |

---

## Storage & Data Integrity

| # | Capability | Description |
|---|---|---|
| 45 | **SQLite Performance Hardening** | WAL mode, connection pooling, chunked batch inserts (500–1000 records per transaction), and tuned PRAGMAs (64 MB cache, 256 MB mmap, 30 s busy timeout). ~90% reduction in transaction overhead on large imports. |
| 50 | **Thread-Safe Connection Pool** | Lock-ordered, health-checked pool eliminating deadlocks and connection leaks under concurrent load. Stress-tested with a 20-thread × 50-iteration race condition suite. |
| 51 | **Input Validation & Sanitization** | Allowlist-based hostname/IP validation, snapshot ID range checks, path sanitization against directory traversal, and bounded numeric inputs. All queries use parameterized statements. |
| 52 | **Configuration Deep-Copy Isolation** | Deep-copy merging prevents user config from mutating built-in defaults. Config validation rejects out-of-range or type-incorrect values before any collection run. |

---

## Testing

| # | Capability | Description |
|---|---|---|
| 46 | **Comprehensive Test Suite** | 1,026 tests across 52 test files covering all core modules. CI enforces a hard 85% coverage gate. |

---

## System Services & Network Forensics

| # | Capability | Description |
|---|---|---|
| 56 | **System Services Collector** | Gathers systemd unit configurations and states (active, loaded, enabled) and maps service processes to their owning user accounts. |
| 57 | **Network Kill Containment** | One-click process termination from split Listening/Active connection tables in the dashboard, with symbolic Unix permission display and multi-column authentication log triage. |