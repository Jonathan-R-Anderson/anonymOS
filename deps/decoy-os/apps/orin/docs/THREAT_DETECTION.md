# Threat Detection Rules

Orin evaluates collected system state against a multi-domain rule set after every `orin analyze` run. Rules span process behaviour, kernel integrity, persistence mechanisms, network activity, file integrity, and identity/privilege abuse. Each alert is tagged with the corresponding MITRE ATT&CK technique.

---

## Process & Execution Anomalies

| Rule | Description | Severity |
|---|---|---|
| **Kernel thread masquerade** | Processes with kernel worker names (`kworker`, `ksoftirqd`, `kcompactd`, …) but a non-system PPID (not 0 or 2). | Critical |
| **Reverse shell detection** | Dangerous invocation patterns: `python -c`, `bash -i`, `sh -i`, `nc -e`, `socat`, and similar. | Critical |
| **Volatile-directory execution** | Processes whose executable path originates from `/tmp`, `/dev/shm`, or `/var/tmp`. | High |
| **Known-bad binaries** | Presence of `nc`, `ncat`, `netcat`, `socat`, `nmap`, `xmrig`, and other offensive tools. | High |
| **C2 blocklist** | Outbound connections to IPs or domains present in imported offline threat intel feeds. | Critical |
| **In-memory deleted binaries** | Processes whose on-disk executable has been unlinked (visible via `/proc/[pid]/exe`). | Critical |
| **Hidden process detection** | PIDs active in the kernel scheduler (`os.kill(pid, 0)`) that are absent from `/proc`. | Critical |

---

## Kernel & Rootkit Indicators

| Rule | Description | Severity |
|---|---|---|
| **Known rootkit symbols** | `kallsyms` entries matching known rootkit names (e.g. `diamorphine`, `reptile`). | Critical |
| **Credential manipulation symbols** | `commit_creds` or `prepare_kernel_cred` exported by third-party kernel modules. | Critical |
| **Unlinked kernel modules** | Modules exporting symbols but absent from `/proc/modules`. | Critical |
| **eBPF program anomalies** | Non-GPL-compatible eBPF program licenses or suspicious program names. | High |
| **Pinned eBPF objects** | Map or program pins under `/sys/fs/bpf` matching known rootkit patterns. | High |
| **Dynamic linker preload** | Entries present in `/etc/ld.so.preload`. | High |

---

## Persistence & Account Abuse

| Rule | Description | Severity |
|---|---|---|
| **SSH key persistence** | New `authorized_keys` entries appearing between snapshot pairs. | High |
| **Unauthorized user accounts** | UID-0 accounts not recorded in the baseline, or any new user accounts. | Critical |
| **Cron job drift** | Scheduled tasks added or modified since the last snapshot. | Medium |
| **Cron execution anomalies** | Cron jobs executing from volatile directories or containing reverse-shell commands. | Critical |
| **SUID/SGID anomalies** | Modified or new SUID/SGID binaries relative to baseline. | High |
| **Systemd service persistence** | New or modified unit files in monitored directories. | Medium |
| **Persistence configurations** | New or changed entries in `rc.local`, systemd timers, XDG autostart, and similar mechanisms. | Medium |

---

## Network & Communications

| Rule | Description | Severity |
|---|---|---|
| **Promiscuous mode** | Network interface with `IFF_PROMISC` (`0x100`) flag set. | High |
| **DNS tunneling** | High-entropy subdomains, abnormally long domain labels, or TXT record query abuse. | High |
| **DGA detection** | Domain Generation Algorithm patterns identified via Shannon entropy and character distribution analysis. | High |
| **Unexpected outbound connections** | Connections to non-whitelisted IPs or ports. | Medium |
| **C2 beaconing** | Periodic outbound connections to blocklisted destinations at regular intervals. | Critical |

---

## File Integrity & Tampering

| Rule | Description | Severity |
|---|---|---|
| **FIM violations** | SHA-256 hash changes in configured critical paths or directories. | High |
| **Package integrity failure** | MD5 mismatch between an on-disk binary and its dpkg record. | High |
| **Log tampering** | Zeroed records or epoch resets in `wtmp` or `lastlog` binary structures. | High |
| **YARA signature match** | Malware patterns detected in files or active process memory spaces (using native ptrace and `/proc/<pid>/mem` fallbacks). | Critical |
| **Deleted file descriptors** | Processes holding open handles to deleted files in system directories. | Medium |
| **memfd anonymous execution** | Fileless execution via `memfd_create` (processes with no on-disk image). | Critical |

---

## Identity & Privilege Escalation

| Rule | Description | Severity |
|---|---|---|
| **PAM authentication failures** | Repeated authentication failures consistent with brute-force patterns. | Medium |
| **sudo / su escalation** | Privileged command execution recorded in authentication logs. | Medium |
| **Privilege escalation syscalls** | `setuid`, `setgid`, or `capset` syscall activity indicative of privilege elevation (via eBPF or audit). | High |
| **ptrace usage** | `ptrace` system calls that may indicate process injection or credential dumping. | High |
| **Credential access** | Reads of `/etc/shadow`, SSH agent sockets, or Kerberos ticket caches. | High |

---

## Sigma Rules

Orin includes a zero-dependency Sigma rules evaluator. Built-in and custom rules are routed by service category and matched against both log streams (raw log lines) and structured system telemetry (dictionaries of keys/values):

* **Authentication / Logs (`auth`)**: Evaluates raw system auth log lines (e.g. SSH brute force, `su` and `sudo` escalations).
* **File Integrity (`fim`)**: Matches drifts inside system directories (e.g. persistence systemd files modification).
* **eBPF Telemetry (`ebpf`)**: Matches anomalous or suspicious eBPF hooks (non-GPL licenses, rootkit indicators).
* **Network Sockets (`connections`)**: Matches outbound or listening ports against suspicious patterns (e.g. reverse shell/C2 ports).
* **SUID/SGID Configurations (`suid`)**: Matches privilege-related SUID drifts.

Custom Sigma rules are loaded automatically at analysis time from configured rule paths (such as `./rules` or `/var/lib/orin/rules/sigma`).

---

## Alert Suppression & Auto-Resolution

**Suppression rules** silence alerts matching specific criteria — event type, file path, or process name. Configure via the dashboard or directly in `orin_config.json`.

**Severity overrides** raise or lower the default severity of any rule on a per-deployment basis.

**Auto-resolution** automatically closes an alert when the anomalous condition is no longer present in a subsequent snapshot. This reduces noise from transient anomalies while preserving a full audit trail of when the condition was first and last observed.