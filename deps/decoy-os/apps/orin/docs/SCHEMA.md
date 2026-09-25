# Database Schema Reference

Single SQLite file. Default path: `/var/lib/orin/orin_vault.db`.

---

## Tables

### Core Snapshot Tables

| Table | Description |
|---|---|
| `system_snapshots` | One row per `orin collect` run. Anchor for all other snapshot-scoped tables. |

### Collector Output Tables

Each of the following tables stores data collected during a single snapshot run, linked to `system_snapshots` via `snapshot_id`.

| Table | Description |
|---|---|
| `collected_processes` | Process list with PID, PPID, command line, executable path, and state |
| `collected_ports` | Listening sockets: protocol, local address/port, and associated PID |
| `collected_outbound_connections` | Active outbound TCP sessions |
| `collected_kernel_modules` | Loaded kernel modules (LKMs) from `/proc/modules` |
| `collected_kernel_symbols` | Kernel symbol table entries from `/proc/kallsyms` for rootkit analysis |
| `collected_ssh_keys` | `authorized_keys` inventory across all user accounts |
| `collected_file_hashes` | SHA-256 FIM records with `mtime`, `ctime`, and `size` for stat-cache comparison |
| `collected_users` | `/etc/passwd` account records |
| `collected_deleted_binaries` | Processes whose disk image has been unlinked; includes MD5 and SHA-256 |
| `collected_promisc_interfaces` | Network interfaces with `IFF_PROMISC` flag set |
| `collected_wtmp_sessions` | Parsed binary login/logout records from `/var/log/wtmp` |
| `collected_lastlog_records` | Parsed last-login timestamps from `/var/log/lastlog` |
| `collected_privilege_events` | Privilege escalation and credential access events |
| `collected_pkg_integrity` | dpkg signature mismatch and missing-record findings |
| `collected_crontabs` | Scheduled task records from all crontab locations |
| `collected_suid_binaries` | SUID/SGID binary records |
| `collected_auth_logs` | Fetched system authentication log entries |
| `collected_ebpf_programs` | Loaded eBPF programs |
| `collected_ebpf_pinned` | eBPF program and map pins under `/sys/fs/bpf` |
| `collected_ld_preload` | Library preload entries from `/etc/ld.so.preload` |
| `collected_special_fds` | Process open file descriptors with anomalous properties (memfd, deleted files) |
| `collected_persistence_configs` | Persistence mechanism configurations (rc.local, systemd timers, XDG autostart, etc.) |
| `collected_dns_queries` | DNS query telemetry with tunneling and DGA detection results |
| `collected_yara_scans` | Metadata of YARA scan executions (rules loaded, files/processes scanned, timestamp) |
| `collected_yara_matches` | Detail of individual YARA signature matches (matched rule, string segments, severity, ATT&CK, file/PID) |


### Kernel Analysis Tables

| Table | Description |
|---|---|
| `kernel_analysis_summary` | Kernel integrity analysis summary per snapshot |
| `kernel_rootkit_indicators` | Detected kernel rootkit indicators |
| `kernel_hidden_modules` | Kernel modules detected as hidden from `/proc/modules` |

### Persistent State Tables

| Table | Description |
|---|---|
| `security_events` | Persistent, deduplicated alert ledger across all snapshots |

### Baseline Tables

Set once during `orin init` and updated via `orin baseline`. Used as the trusted reference for drift detection.

| Table | Description |
|---|---|
| `baseline_kernel_modules` | Trusted LKM allowlist |
| `baseline_users` | Trusted user account allowlist |
| `baseline_suid_binaries` | Trusted SUID/SGID binary allowlist |