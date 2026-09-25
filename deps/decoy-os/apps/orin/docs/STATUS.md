# Project Status, Platform Support & Known Limitations

**Version:** 1.2.0
**Status:** Production-Capable
**Last Updated:** June 2026

---

## Project Status Summary

Orin is a **production-capable offline forensic snapshot and integrity engine** for Linux. All core CLI commands (`init`, `collect`, `analyze`, `report`, `serve`, `hub-serve`, `schedule`, `scan`, `baseline`, `diff`, `delta`, `vault`, `rules`) are fully implemented and verified by automated test suites.

All core collectors — Process, Network, Kernel, Users, FIM, Crontabs, Package Integrity, Logs, and Privilege Auditing — are stable and require no external network access or SaaS dependencies.

---

## Platform Support

### Operating System Compatibility

| Distribution | Version | Status | Notes |
|:---|:---|:---|:---|
| **Ubuntu** | 20.04 LTS, 22.04 LTS, 24.04 LTS | 🟢 Fully Supported | Target CI environment |
| **Debian** | 11 (Bullseye), 12 (Bookworm) | 🟢 Fully Supported | Package integrity via `dpkg` |
| **RHEL / Rocky / Alma** | 8.x, 9.x | 🟢 Fully Supported | Verified with Python 3.10+ |
| **Fedora** | 38+ | 🟢 Fully Supported | Fully functional |
| **Arch Linux** | Latest | 🟡 Partially Supported | Package integrity checking does not support Pacman database formats (Debian/Ubuntu `dpkg` only) |
| **macOS / Windows** | Any | ❌ Not Supported | Forensic collection depends on Linux kernel interfaces (`/proc`, `/sys`); porting is an explicit non-goal |

### System Prerequisites

| Requirement | Minimum | Notes |
|:---|:---|:---|
| **Architecture** | x86_64, aarch64 (ARM64) | |
| **Linux kernel** | 4.4 | Kernel 5.4+ recommended for full eBPF and ring-buffer support |
| **Python** | 3.10 | Validated on 3.10, 3.11, and 3.12 |
| **RAM** | ~50 MB (standard) | Up to 256 MB during parallel collection or large YARA scans |
| **Disk** | ~100 MB (installation) | Vault size varies with snapshot frequency and retention policy |

---

## Deployment Assumptions

The following assumptions must be understood before deploying Orin:

**1. Administrative Privileges**
Orin must run as `root` (via `sudo` or as a system service) to perform complete forensic collection. Non-privileged execution is supported as a fallback but cannot access restricted resources such as `/var/log/auth.log`, other users' process descriptors, promiscuous NIC flags, or hidden process signals.

**2. Air-Gapped / Isolated Networks**
Orin is designed for environments with zero external internet connectivity. All threat intelligence files (Sigma rules, YARA rules, IOC feeds) must be imported offline from local directories.

**3. Local Writable Storage**
The target host must have a writable path (local disk, USB media, or `tmpfs`) for the SQLite evidence vault. If host disk writes are restricted, use `--read-only` mode or redirect the vault to an external location with `--vault-path`.

---

## Known Limitations

### eBPF Streaming Prerequisites

Real-time event streaming (`orin stream`) requires a BTF-enabled kernel and the system `libbpf` library. If these prerequisites are absent, streaming will fail to load the BPF program. Point-in-time collection (`orin collect`) remains fully functional as it relies on `/proc` parsing and is not affected.

**Affected command:** `orin stream`
**Workaround:** Use `orin collect` for periodic snapshot-based monitoring.

---

### YARA Scanning Scope

The embedded YARA engine is restricted by default to temporary paths (`/tmp`, `/dev/shm`, `/var/tmp`) and dumped in-memory executables. Full-directory sweeps are disabled by default to prevent significant I/O degradation. Full sweeps must be explicitly enabled in `orin_config.json`.

**Impact:** Malware signatures in non-temporary directories will not be detected without manual configuration.

---

### Triggered PCAP Capture

Automatic packet capture on rule triggers requires the `scapy` Python package for full protocol reconstruction. Without `scapy`, Orin falls back to writing raw socket buffers. The raw format is functional but does not include high-level protocol reconstruction.

**Impact:** PCAP analysis may require additional tooling if `scapy` is unavailable.

---

### Container Namespace Isolation

Orin operates within the host network, PID, and mount namespaces. It reports container processes visible on the host but does not dynamically inspect container-isolated namespaces (Docker, Podman, Kubernetes pods) or associate events with specific container IDs or pod metadata.

**Impact:** Forensic visibility within containers requires running Orin inside the container or granting privileged host access.

---

### Compromised Kernel Trust Boundary

Orin reads process state, network socket information, and loaded modules from `/proc` and `/sys`. A malicious kernel rootkit that intercepts syscalls or hooks the virtual filesystem may return falsified data.

**Mitigation:** Orin exposes rootkits by cross-referencing scheduler-active PIDs via null signaling (`os.kill(pid, 0)`) against `/proc` listings and auditing unlinked kernel symbols. However, a fully compromised kernel remains a fundamental boundary for userspace integrity tools.

---

## Security & Trust Model

**Evidence Integrity**
Snapshots exported via `orin export` are cryptographically signed with HMAC-SHA256. Any post-collection modification is detected immediately by `orin verify`. The SQLite vault itself can be encrypted using AES-256-GCM.

**Agent Confinement**
The installation package includes AppArmor and SELinux templates in `assets/security-profiles/` that restrict Orin's execution path to required system directories and block arbitrary network egress.