# Argus

A lightweight Linux kernel telemetry and threat-detection tool built on eBPF. Traces 21 event types system-wide — process execution, file access, network connections, privilege escalation, memory execution, kernel-module loading, namespace escapes, DNS queries, TLS SNI extraction, and more — with minimal overhead. Every event carries full process ancestry (`systemd→sshd→bash→curl`) and the container cgroup name for immediate container attribution.

**Version 0.4.0** — Full integration and verification of all enterprise features. BPF verifier fix for kernel 5.15: DNS query-name decoding moved from BPF to userspace, eliminating the 1 M-instruction verifier limit breach caused by the inlined `parse_dns_name` loop. SSL_read uprobe and syscall-histogram BPF programs now conditionally disabled at load time (not just at runtime) when `--tls-data` / `--syscall-anom` are not requested, preventing EACCES load failures on kernels without uprobe support. SQLite3 is now a properly detected optional dependency (`pkg-config sqlite3`); `--store-path` creates and writes a real database. `--mgmt-port` documented in `argus-server --help`. All 227 unit tests and 17 integration tests verified passing end-to-end on kernel 5.15.

**Version 0.3.0** — Adds canary/honeypot file detection, alert deduplication, process hollowing detection, C2 beaconing detection, syscall attack-chain detection (MEMEXEC→EXEC, PTRACE→EXEC, PRIVESC→shell, NS_ESCAPE→EXEC), YARA rule scanning, cross-host fleet correlation in `argus-server`, LSM BPF in-kernel enforcement mode, MITRE ATT&CK tagging, SHA-256 exec hashing + VirusTotal enrichment, IOC enrichment (VT + AlienVault OTX), network isolation response (iptables), persistent SQLite event store + HTTP query API, webhook/SOAR integration, agent health management API in `argus-server`, BPF syscall frequency anomaly detection, container/Kubernetes enrichment, compliance reporting (CIS, PCI-DSS, NIST, SOC2), BPF TLS data capture, and memory forensics.

**Version 0.2.0** — Added 12 new kernel-traced event types, active response (BPF kill), threat-intel CIDR feed, file integrity monitoring, LD_PRELOAD detection, DGA/entropy detection, DNS→IP correlation, per-PID rate limiting, Prometheus metrics, cgroup-aware baselines, rolling baseline merge, alert suppression, process-ancestry rule matching, and fleet aggregation server.

## Motivation

Existing open-source host-based intrusion detection tools either operate entirely in userspace (high overhead, easily bypassed) or require kernel modules that break on every kernel update. Argus uses eBPF — a safe, verifier-checked in-kernel VM — to trace all 21 security-relevant event types with sub-microsecond latency and no kernel patching. Every event carries full process ancestry and container attribution out of the box, closing the gap between raw syscall visibility and actionable fleet-wide threat detection.

## Requirements

- Linux kernel **5.8+** with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- Root or `CAP_BPF` + `CAP_PERFMON`

### Build dependencies

```sh
# Ubuntu / Debian
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
     linux-tools-common linux-tools-generic libssl-dev python3

# Fedora / RHEL
sudo dnf install -y clang llvm libbpf-devel elfutils-libelf-devel zlib-devel \
     openssl-devel python3 bpftool
```

OpenSSL (`libssl-dev`) is optional — argus builds without it; `--forward-tls`, `--exec-hash`, and IOC enrichment (HTTPS) become no-ops.
YARA (`libyara-dev`) is optional — argus builds without it; `--yara-rules` becomes a no-op (detected automatically via `pkg-config`).
SQLite3 (`libsqlite3-dev`) is optional — argus builds without it; `--store-path` becomes a no-op (detected automatically via `pkg-config`).
Seccomp is always available on Linux kernels ≥ 3.5 (detected automatically from the kernel headers).

```sh
# Install all optional dependencies
sudo apt-get install -y libssl-dev libyara-dev libsqlite3-dev
```

Verify BTF is available on your kernel:

```sh
ls /sys/kernel/btf/vmlinux
```

## Install

```sh
git clone https://github.com/DennisPrudlik/argus
cd argus
make
```

The build produces two binaries: `argus` (sensor) and `argus-server` (fleet aggregator).

Build steps performed by `make`:
1. Generates `vmlinux.h` from the running kernel's BTF via `bpftool`
2. Compiles `argus.bpf.c` to a BPF ELF object with `clang`
3. Generates `argus.skel.h` (libbpf skeleton) via `bpftool`
4. Compiles the userspace loader `argus` and fleet server `argus-server` with `gcc`

### System-wide install

```sh
sudo make install      # installs binary, systemd unit, tmpfiles.d, and logrotate config
sudo make uninstall    # removes all of the above
```

### Packages

Build a native package for deployment on other machines:

```sh
# Debian / Ubuntu (.deb) — requires dpkg-deb
make deb
# → argus_0.4.0_x86_64.deb

# Fedora / RHEL (.rpm) — requires rpmbuild
make rpm
# → ~/rpmbuild/RPMS/.../argus-0.4.0-1.x86_64.rpm
```

Both packages install the binary to `/usr/local/bin/argus` and include the systemd unit, tmpfiles.d config, and logrotate config.

To run as a persistent daemon:

```sh
sudo systemd-tmpfiles --create        # creates /var/log/argus/ (done once)
sudo systemctl daemon-reload
sudo systemctl enable --now argus
journalctl -u argus -f                # live log
cat /var/log/argus/events.jsonl       # persistent JSONL output
```

The service writes JSON to `/var/log/argus/events.jsonl`, drops privileges to `nobody` after attach, and restarts automatically on failure. Log rotation is configured via the installed `logrotate` config (daily, 14 days, compressed).

## Quick Start

```sh
# 1. Install build dependencies (Ubuntu/Debian)
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
     linux-tools-common linux-tools-generic libssl-dev python3

# 2. Clone and build
git clone https://github.com/DennisPrudlik/argus
cd argus
make

# 3. Run (requires root or CAP_BPF + CAP_PERFMON)
sudo ./argus

# 4. Stream JSON to a file
sudo ./argus --fmt json > /tmp/events.jsonl

# 5. Watch only network connections from a specific process
sudo ./argus --comm curl --event-mask CONNECT
```

See [Install](#install) for package-based deployment and systemd service setup.

## Usage

```sh
sudo ./argus [OPTIONS]
```

### Core options

| Option | Description |
|---|---|
| `--config <path>` | Load config file (see [Config file](#config-file)) |
| `--pid <pid>` | Only trace this PID (enforced in kernel) |
| `--follow <pid>` | Trace PID and all descendant processes (BPF fork tracking) |
| `--comm <name>` | Only trace this process name (enforced in kernel) |
| `--path <str>` | Only show file events whose path contains this string (userspace) |
| `--exclude <pfx>` | Exclude file events (OPEN, UNLINK, RENAME, CHMOD) whose path starts with this prefix (repeatable) |
| `--events <list>` | Comma-separated event types to enable (see [Event Types](#event-types)) |
| `--rate-limit <n>` | Drop events after N per second per process name (0 = off, kernel-enforced) |
| `--rate-limit-per-pid <n>` | Drop events after N per second per PID (0 = off, kernel-enforced) |
| `--ringbuf <kb>` | Ring buffer size in KB (default: 256) |
| `--summary <secs>` | Rolling summary every N seconds instead of per-event output |
| `--output <path>` | Write event stream to file instead of stdout (opened in append mode) |
| `--syslog` | Emit events to syslog (`LOG_DAEMON`) instead of stdout |
| `--output-fmt <fmt>` | Output format: `text` (default), `json`, `syslog`, `cef` |
| `--json` | Emit newline-delimited JSON (shorthand for `--output-fmt json`) |
| `--pid-file <path>` | Write daemon PID to file; removed on exit |
| `--no-drop-privs` | Stay root after attach (not recommended) |
| `--config-check` | Validate config file(s) and print active settings, then exit |
| `--version` | Print version and exit |
| `--help` | Show usage |

### Rules & forwarding

| Option | Description |
|---|---|
| `--rules <path>` | Load alert rules from JSON file (see [Alert rules](#alert-rules)) |
| `--forward <host:port>` | Stream JSON events to a remote TCP listener |
| `--forward-tls` | Enable TLS for `--forward` with server certificate verification |
| `--forward-tls-noverify` | Enable TLS for `--forward` without certificate verification |

### Baseline & anomaly detection

| Option | Description |
|---|---|
| `--baseline <path>` | Detect anomalies against a learnt profile |
| `--baseline-learn <secs>` | Learn a baseline profile for N seconds |
| `--baseline-out <path>` | File to write the learnt baseline profile (default: `baseline.json`) |
| `--baseline-merge-after <n>` | Auto-merge anomalies into baseline after N sightings (0 = disabled) |
| `--baseline-cgroup-aware` | Key baselines by `cgroup/comm` instead of `comm` alone |

### Threat detection modules

| Option | Description |
|---|---|
| `--threat-intel <path>` | Load CIDR blocklist file into BPF; matching connects become THREAT_INTEL events |
| `--fim-paths <path>[,<path>...]` | File Integrity Monitoring: hash watched files at startup, alert on change |
| `--dga-entropy-threshold <f>` | Alert on DNS names with Shannon entropy above this value (e.g. 3.5; 0 = off) |
| `--ldpreload-check` | Scan `/proc/<pid>/environ` on EXEC events for LD_PRELOAD/LD_LIBRARY_PATH injection |
| `--tls-sni` | Enable TLS ClientHello SNI extraction via uprobe on SSL_write (requires OpenSSL) |
| `--response-kill` | Allow alert rules with `"action": "kill"` to terminate matched processes via BPF |
| `--canary <path>` | Honeypot file path; any access (open/exec/unlink/rename) triggers a `[CANARY]` alert (repeatable) |
| `--alert-dedup <secs>` | Suppress duplicate alerts with the same key within N seconds (0 = off) |
| `--beacon-cv <f>` | Alert when a PID's CONNECT interval coefficient of variation falls below this value (e.g. 0.15; 0 = off) |
| `--yara-rules <dir>` | Directory of `.yar` files to scan on EXEC, WRITE_CLOSE, and KMOD_LOAD events (requires libyara) |
| `--lsm-deny` | Enable LSM BPF enforcement: kernel rules matching file open, exec, or connect are denied in-kernel (requires kernel 5.7+ with BPF LSM) |
| `--mitre-tags` | Annotate JSON events with MITRE ATT&CK technique ID, name, and tactic |
| `--exec-hash` | Compute SHA-256 of every executed binary and attach to the event |
| `--vt-api-key <key>` | VirusTotal API key — hashes and IPs are checked asynchronously |
| `--otx-api-key <key>` | AlienVault OTX API key — IPs/domains checked for IOC matches |
| `--response-isolate` | Block source IPs of matched alert rules via `iptables` / `ip6tables` |
| `--store-path <path>` | Persist all events to a SQLite3 database at this path |
| `--store-query-port <port>` | Serve a simple HTTP query API for the event store on this port |
| `--container-enrich` | Resolve cgroup name to container name, image, pod, and namespace (Docker/Kubernetes) |
| `--compliance <framework>` | Map events to compliance controls: `cis`, `pci-dss`, `nist`, `soc2` |
| `--compliance-report <path>` | Write an HTML compliance report to this path on exit |
| `--syscall-anom <secs>` | Read BPF syscall frequency histogram every N seconds and alert on chi-squared anomalies |
| `--tls-data` | Capture first 256 bytes of decrypted TLS payloads via `SSL_read` uprobe (requires OpenSSL) |
| `--mem-forensics` | On exec events, scan anonymous executable `/proc/<pid>/mem` mappings for entropy and YARA hits |
| `--webhook <url>` | POST JSON alert bodies to this URL (SOAR / incident response integration) |

### Observability

| Option | Description |
|---|---|
| `--metrics-port <n>` | Expose Prometheus metrics on this TCP port (0 = disabled) |

### Examples

```sh
# Trace everything
sudo ./argus

# Watch only curl activity
sudo ./argus --comm curl

# Watch a specific PID and all its children recursively
sudo ./argus --follow 1234

# Security-focused: privilege escalation, memory execution, kernel modules, namespace escapes
sudo ./argus --events PRIVESC,MEMEXEC,KMOD_LOAD,NS_ESCAPE --json

# Load threat-intel blocklist and alert on matching connections
sudo ./argus --threat-intel /etc/argus/blocklist.cidr --json

# File integrity monitoring on critical paths
sudo ./argus --fim-paths /etc/passwd,/etc/shadow,/etc/sudoers

# Detect DNS-based C2 via high-entropy names (DGA)
sudo ./argus --events DNS --dga-entropy-threshold 3.5 --json

# Detect LD_PRELOAD injection on process starts
sudo ./argus --events EXEC --ldpreload-check --json

# Active response: kill matched processes
sudo ./argus --rules /etc/argus/rules.json --response-kill

# Expose Prometheus metrics for Grafana/Alertmanager
sudo ./argus --metrics-port 9090

# Cgroup-aware baselines (separate profile per container)
sudo ./argus --baseline /etc/argus/baseline.json --baseline-cgroup-aware

# Rolling baseline merge: auto-accept after 3 sightings
sudo ./argus --baseline /etc/argus/baseline.json --baseline-merge-after 3

# Watch file opens under /etc, excluding /proc and /sys noise
sudo ./argus --events OPEN --path /etc --exclude /proc --exclude /sys

# Limit noisy processes to 100 events/sec each
sudo ./argus --rate-limit 100

# Per-PID rate limit (useful when many instances of same binary run)
sudo ./argus --rate-limit-per-pid 50

# JSON output, pipe into jq
sudo ./argus --json | jq 'select(.type == "PRIVESC")'

# Forward all events to a remote SIEM over TLS
sudo ./argus --forward siem.internal:9000 --forward-tls

# Learn a baseline for 1 hour, then use it for anomaly detection
sudo ./argus --baseline-learn 3600 --baseline-out /etc/argus/baseline.json
sudo ./argus --baseline /etc/argus/baseline.json --json

# CEF output for SIEM ingestion (Splunk, ArcSight, QRadar)
sudo ./argus --output-fmt cef --output /var/log/argus/events.cef

# Reload config without restarting
sudo kill -HUP $(pidof argus)

# Honeypot files — alert on any access to canary paths
sudo ./argus --canary /etc/argus/.canary --canary /tmp/.honeypot

# Suppress duplicate alerts within a 30-second window
sudo ./argus --alert-dedup 30 --rules /etc/argus/rules.json

# Detect C2 beaconing by regular CONNECT intervals (CV < 0.15)
sudo ./argus --events CONNECT --beacon-cv 0.15 --json

# Scan executed binaries with YARA rules
sudo ./argus --events EXEC --yara-rules /etc/argus/yara/

# LSM BPF enforcement: deny kernel-rule-matched file opens and execs in-kernel
sudo ./argus --lsm-deny --rules /etc/argus/rules.json

# MITRE ATT&CK tagging in JSON output
sudo ./argus --json --mitre-tags | jq 'select(.mitre_id != null)'

# Hash every executed binary; check unknown hashes against VirusTotal
sudo ./argus --exec-hash --vt-api-key YOUR_KEY --json

# IOC enrichment: async VT + OTX lookups for IPs and domains
sudo ./argus --vt-api-key YOUR_VT_KEY --otx-api-key YOUR_OTX_KEY --json

# Isolate attacker IPs via iptables on rule match
sudo ./argus --rules /etc/argus/rules.json --response-isolate

# Persist all events to SQLite and query via HTTP
sudo ./argus --store-path /var/lib/argus/events.db --store-query-port 8080
curl 'http://localhost:8080/events?type=EXEC&limit=50'

# Container/Kubernetes enrichment
sudo ./argus --container-enrich --json | jq '.container_name'

# Generate a PCI-DSS HTML compliance report
sudo ./argus --compliance pci-dss --compliance-report /tmp/pci_report.html

# Syscall frequency anomaly detection (check every 60 seconds)
sudo ./argus --syscall-anom 60 --json

# Webhook to Slack/PagerDuty on every alert
sudo ./argus --rules /etc/argus/rules.json --webhook https://hooks.slack.com/...

# Memory forensics on suspicious execs
sudo ./argus --mem-forensics --yara-rules /etc/argus/yara/ --json

# Fleet management: health dashboard for all connected sensors
./argus-server --port 9000 --mgmt-port 8081
curl http://localhost:8081/agents
```

## Event Types

### Kernel-traced events

| Type | Tracepoints | Description | Key Fields |
|---|---|---|---|
| `EXEC` | `sys_{enter,exit}_execve`, `execveat` | Process execution | `filename`, `args`, `duration_ns` |
| `OPEN` | `sys_{enter,exit}_openat` | File open | `filename`, `open_flags`, `success` |
| `EXIT` | `sched_process_exit` | Process exit | `exit_code` |
| `CONNECT` | `sys_{enter,exit}_connect` | Outbound TCP/UDP connection | `family`, `daddr`, `dport`, `success` |
| `UNLINK` | `sys_{enter,exit}_unlinkat` | File deletion | `filename`, `success` |
| `RENAME` | `sys_{enter,exit}_renameat2` | File rename | `filename` (old), `new_path`, `success` |
| `CHMOD` | `sys_{enter,exit}_fchmodat` | Permission change | `filename`, `mode`, `success` |
| `BIND` | `sys_{enter,exit}_bind` | Server socket bind | `family`, `laddr`, `lport`, `success` |
| `PTRACE` | `sys_{enter,exit}_ptrace` | Process tracing/injection | `ptrace_req`, `target_pid`, `success` |
| `DNS` | `sys_{enter,exit}_sendto` (port 53) | Outbound DNS query | `filename` (query name) |
| `SEND` | `sys_{enter,exit}_sendto` | First 128 bytes of sendto payload | `mode` (payload len), `filename` (hex) |
| `WRITE_CLOSE` | `sys_{enter,exit}_close` | close() on a write-mode fd | `filename` |
| `PRIVESC` | `sys_{enter,exit}_setuid`, `setresuid`, `capset` | UID→0 or dangerous capability grant | `uid_before`, `uid_after`, `cap_data` |
| `MEMEXEC` | `sys_{enter,exit}_mmap`, `mprotect` | PROT_EXEC on anonymous mapping | `mode` (prot flags) |
| `KMOD_LOAD` | `sys_{enter,exit}_init_module`, `finit_module` | Kernel module load | `filename`, `target_pid` (fd) |
| `NS_ESCAPE` | `sys_{enter,exit}_unshare`, `setns`, `clone` | Namespace isolation escape | `mode` (clone flags) |

### Synthetic / userspace events

| Type | Source | Description | Key Fields |
|---|---|---|---|
| `NET_CORR` | Userspace correlation | DNS→connect match (CONNECT to IP recently resolved via DNS) | `dns_name`, `daddr`, `dport` |
| `RATE_LIMIT` | BPF | Per-comm or per-PID rate limit exceeded | `pid`, `comm` |
| `THREAT_INTEL` | BPF LPM trie | CONNECT destination matched threat-intel CIDR blocklist | `daddr`, `dport`, `family` |
| `TLS_SNI` | Uprobe `SSL_write` | TLS ClientHello SNI hostname extraction | `dns_name` (SNI), `daddr`, `dport` |
| `TLS_DATA` | Uretprobe `SSL_read` | First 256 bytes of decrypted TLS payload (`--tls-data`) | `tls_payload`, `tls_payload_len` |
| `PROC_SCRAPE` | `sys_{enter,exit}_openat` | `/proc/<pid>/mem`, `/maps`, or `/fd` opened by a foreign process | `filename`, `target_pid` |
| `HEARTBEAT` | Userspace timer | Periodic agent health beacon (emitted by argus, consumed by argus-server) | `duration_ns` (uptime) |

All events include: `pid`, `ppid`, `uid`, `gid`, `user` (username when resolvable), `comm`, `cgroup`, `lineage`, `duration_ns`.

The `cgroup` field contains the leaf cgroup name. For Docker containers this is the container scope name (e.g. `docker-abc123.scope`); for Kubernetes pods it is the container ID. Empty string on host processes.

`execveat(2)` is traced alongside `execve(2)` — both appear as `EXEC` events, so script interpreters that use the `execveat` path are fully captured.

## Output

### Text

```
Tracing via eBPF (all events)... Ctrl-C to stop.

TYPE      PID     PPID    UID   GID   COMM              CGROUP                    LINEAGE                           DETAIL
--------  ------  ------  ----  ----  ----------------  ------------------------  --------------------------------  ------
EXEC      3821    3820    1000  1000  curl              -                         systemd→sshd→bash                 /usr/bin/curl example.com
CONN      3821    3820    1000  1000  curl              -                         systemd→sshd→bash                 [OK] example.com (93.184.216.34):443
DNS       3821    3820    1000  1000  curl              -                         systemd→sshd→bash                 example.com
NET_CORR  3821    3820    1000  1000  curl              -                         systemd→sshd→bash                 example.com → 93.184.216.34:443
PRIVESC   1024    1023    1000  1000  sudo              -                         systemd→sshd→bash                 uid 1000→0
MEMEXEC   4512    4511    0     0     malware           -                         systemd→bash                      mmap PROT_EXEC anon
KMOD_LOAD 5001    5000    0     0     insmod            -                         systemd→bash                      /tmp/evil.ko
NS_ESC    6012    6011    0     0     unshare           -                         systemd→bash                      CLONE_NEWUSER|CLONE_NEWNET
```

### JSON (`--json` / `--output-fmt json`)

One object per line, suitable for `jq`, log shippers, or SIEMs.

```json
{"type":"EXEC","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"user":"alice","comm":"curl","cgroup":"","lineage":"systemd→sshd→bash","duration_ns":41238,"success":true,"filename":"/usr/bin/curl","args":"example.com"}
{"type":"CONNECT","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"user":"alice","comm":"curl","cgroup":"","lineage":"systemd→sshd→bash","duration_ns":2301,"success":true,"family":2,"daddr":"93.184.216.34","hostname":"example.com","dport":443}
{"type":"DNS","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"user":"alice","comm":"curl","cgroup":"","lineage":"systemd→sshd→bash","duration_ns":0,"success":true,"filename":"example.com"}
{"type":"NET_CORR","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"user":"alice","comm":"curl","cgroup":"","lineage":"systemd→sshd→bash","dns_name":"example.com","daddr":"93.184.216.34","dport":443}
{"type":"PRIVESC","pid":1024,"ppid":1023,"uid":1000,"gid":1000,"user":"alice","comm":"sudo","cgroup":"","lineage":"systemd→sshd→bash","uid_before":1000,"uid_after":0}
{"type":"THREAT_INTEL","pid":8801,"ppid":8800,"uid":0,"gid":0,"user":"root","comm":"nc","cgroup":"","lineage":"systemd→bash","daddr":"198.51.100.5","dport":4444}
```

### CEF (`--output-fmt cef`)

ArcSight Common Event Format v0. Severity mapping: EXEC/OPEN/EXIT/CONNECT/BIND/DNS/SEND → 3 (Low), UNLINK/RENAME/CHMOD/WRITE_CLOSE/NET_CORR → 5 (Medium), PTRACE/MEMEXEC/PROC_SCRAPE → 8 (High), PRIVESC/KMOD_LOAD/THREAT_INTEL/NS_ESCAPE → 9 (Very High).

```
CEF:0|argus|argus|0.4.0|PRIVESC|Privilege Escalation|9|spid=1024 suid=1000 sgid=1000 dproc=sudo suser=alice flexString1Label=lineage flexString1=systemd→sshd→bash cs2Label=uid_before cs2=1000 cs3Label=uid_after cs3=0
CEF:0|argus|argus|0.4.0|KMOD_LOAD|Kernel Module Load|9|spid=5001 suid=0 sgid=0 dproc=insmod suser=root flexString1Label=lineage flexString1=systemd→bash fname=/tmp/evil.ko
CEF:0|argus|argus|0.4.0|THREAT_INTEL|Threat Intel Match|9|spid=8801 suid=0 sgid=0 dproc=nc suser=root dst=198.51.100.5 dpt=4444
```

### Summary mode (`--summary N`)

```
════════════════════════════════════════════════════════
 10s summary
  EXEC      47  bash(21)  python3(14)  sh(12)
  OPEN    1823  nginx(891)  python3(512)  bash(420)
  CONNECT    9  curl(6)  wget(3)
  DNS       11  curl(7)  wget(4)
  PRIVESC    2  sudo(2)
  MEMEXEC    1  loader(1)
════════════════════════════════════════════════════════
```

## Config file

Argus loads `/etc/argus/config.json` then `~/.config/argus/config.json` on startup (if present), with later values overriding earlier ones. CLI flags always take final precedence. All keys are optional.

```json
{
    "pid": 0,
    "follow_pid": 0,
    "comm": "",
    "path": "",
    "exclude_paths": ["/proc", "/sys", "/dev"],
    "event_types": ["EXEC", "OPEN", "EXIT", "CONNECT", "UNLINK", "RENAME", "CHMOD",
                    "BIND", "PTRACE", "DNS", "SEND", "WRITE_CLOSE",
                    "PRIVESC", "MEMEXEC", "KMOD_LOAD", "NS_ESCAPE"],
    "ring_buffer_kb": 256,
    "summary_interval": 0,
    "rate_limit_per_comm": 0,
    "rate_limit_per_pid": 0,
    "output_path": "",
    "output_fmt": "text",
    "pid_file": "",
    "syslog": false,
    "rules": "",
    "forward": "",
    "forward_tls": false,
    "forward_tls_noverify": false,
    "targets": [
        {"addr": "siem1.corp:9000"},
        {"addr": "siem2.corp:9001", "tls": true},
        {"addr": "backup.corp:9002", "tls_noverify": true}
    ],
    "baseline": "",
    "baseline_out": "",
    "baseline_learn_secs": 0,
    "baseline_merge_after": 0,
    "baseline_cgroup_aware": false,
    "threat_intel_path": "/etc/argus/blocklist.cidr",
    "fim_paths": ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts"],
    "dga_entropy_threshold": 0.0,
    "ldpreload_check": false,
    "tls_sni_enable": false,
    "response_kill": false,
    "metrics_port": 0,
    "yara_rules_dir": "",
    "canary_paths": ["/etc/argus/.canary", "/tmp/.honeypot"],
    "alert_dedup_secs": 0,
    "beacon_cv_threshold": 0.0,
    "lsm_deny": false,

    "mitre_tags": false,
    "webhook_url": "",
    "exec_hash": false,
    "vt_api_key": "",
    "otx_api_key": "",
    "response_isolate": false,
    "store_path": "",
    "store_query_port": 0,
    "container_enrich": false,
    "compliance_framework": "cis",
    "compliance_report": "",
    "syscall_anom_interval": 0,
    "tls_data_enable": false,
    "mem_forensics": false
}
```

`"output_fmt"` accepts `"text"`, `"json"`, `"syslog"`, or `"cef"`.
`"targets"` adds up to 8 independent forwarding destinations alongside the single `"forward"` key.
`"baseline_merge_after"` auto-merges an anomaly into the baseline after it is seen N times (0 = disabled).
`"dga_entropy_threshold"` fires a warning when a DNS query name's Shannon entropy exceeds this value (0.0 = disabled).
`"response_kill"` must be `true` for `"action": "kill"` rules to take effect (safety gate).
`"canary_paths"` lists honeypot file paths; any access fires a `[CANARY]` alert.
`"alert_dedup_secs"` suppresses repeated alerts with the same key within N seconds (0 = off).
`"beacon_cv_threshold"` fires a `[BEACON]` alert when a PID's CONNECT interval coefficient of variation falls below this value (0.0 = off).
`"lsm_deny"` enables in-kernel denial of kernel-rule-matched opens, execs, and connects via LSM BPF hooks (requires kernel 5.7+ with `CONFIG_BPF_LSM=y`; silently skipped if unsupported).
`"mitre_tags"` adds `"mitre_id"`, `"mitre_name"`, and `"mitre_tactic"` fields to JSON events.
`"exec_hash"` computes SHA-256 of every executed binary and attaches it as `"sha256"` in JSON output.
`"vt_api_key"` / `"otx_api_key"` enable asynchronous IOC enrichment via VirusTotal and AlienVault OTX.
`"response_isolate"` blocks source IPs of matched alert rules by inserting `iptables`/`ip6tables` DROP rules at runtime.
`"store_path"` writes all events to a SQLite3 database; `"store_query_port"` serves a `GET /events` HTTP query API on that port.
`"container_enrich"` queries the Docker socket to resolve the cgroup name to container name, image, pod, and Kubernetes namespace.
`"compliance_framework"` selects the control mapping (`cis`, `pci-dss`, `nist`, `soc2`); `"compliance_report"` sets the HTML output path written on exit.
`"syscall_anom_interval"` reads the BPF syscall histogram every N seconds and runs chi-squared anomaly detection per comm (0 = off).
`"tls_data_enable"` attaches a `uretprobe` on `SSL_read` to capture the first 256 bytes of each decrypted TLS read.
`"mem_forensics"` scans `/proc/<pid>/mem` on EXEC events for anonymous executable mappings, computes entropy, and runs YARA.

## Kernel-side filtering

`--pid`, `--comm`, and `--rate-limit` are pushed into BPF maps and enforced before events enter the ring buffer — near-zero overhead even on noisy hosts.

`--rate-limit-per-pid` uses an LRU hash map keyed by PID so high-churn workloads (many short-lived processes) don't exhaust the map. Both per-comm and per-PID limits can be active simultaneously; the first limit hit wins.

The **BPF kill list** (`--response-kill` + rule `"action": "kill"`) writes the target PID into a BPF hash map; every subsequent event from that PID triggers `bpf_send_signal(SIGKILL)` directly from the kernel, before the event reaches userspace.

## Threat-intel feed

`--threat-intel <path>` loads a plaintext CIDR blocklist (one prefix per line, `#` comments ignored) into a BPF LPM trie at startup:

```
# Emerging threats feed
192.0.3.0/24
198.51.100.0/24
203.0.113.128/25
```

When any `connect()` matches a listed prefix, the event is re-typed to `THREAT_INTEL` and receives severity 9 in CEF output. The BPF lookup happens before the ring buffer so there is no userspace round-trip on the hot path.

## File Integrity Monitoring (FIM)

`--fim-paths` hashes each listed file with SHA-256 at startup. On every `WRITE_CLOSE` event whose filename matches a watched path, the file is re-hashed and compared:

```
[FIM] /etc/passwd hash changed: a1b2c3...→d4e5f6...
```

Changes are also emitted as JSON alerts if `--json` is active. Use this to detect runtime tampering of credential files, sudo rules, or PAM config.

## LD_PRELOAD detection

`--ldpreload-check` reads `/proc/<pid>/environ` on every `EXEC` event and scans for suspicious injection variables:

```
[LD_PRELOAD] pid=8801 comm=bash LD_PRELOAD=/tmp/hook.so
[LD_PRELOAD] pid=9012 comm=python3 PYTHONPATH=/tmp/evil
```

This catches rootkit injection techniques that abuse `LD_PRELOAD`, `LD_LIBRARY_PATH`, and interpreter path overrides before the target process has a chance to run.

## Canary / honeypot file detection

`--canary <path>` (repeatable) registers a honeypot file path. Any process that opens, executes, reads, unlinks, or renames a canary path triggers an immediate alert regardless of other filters:

```
[CANARY] pid=8801 comm=bash path=/etc/argus/.canary (OPEN)
[CANARY] pid=9102 comm=python3 path=/tmp/.honeypot (EXEC)
```

Canary paths ending with `/` match any file under that directory. Use this to detect lateral movement, unauthorized credential harvesting, or ransomware that scans directories indiscriminately.

## Alert deduplication

`--alert-dedup <secs>` deduplicates all detection-module alerts (CANARY, HOLLOW, BEACON, SEQDETECT, ANOMALY, YARA) within a rolling time window. Duplicate alerts with the same key are suppressed until the window expires:

```sh
# Suppress same alert for 60 seconds
sudo ./argus --alert-dedup 60 --rules /etc/argus/rules.json
```

The dedup table holds 512 entries with linear-probe eviction. On table exhaustion it fails open (alerts pass through) rather than silently suppressing novel events.

## Process hollowing detection

On every `EXEC` event, argus compares the executable file from the kernel event (`ev->filename`) against the first executable memory mapping in `/proc/<pid>/maps`. A mismatch indicates the process image was replaced after exec (process hollowing):

```
[HOLLOW] pid=4512 comm=nginx exe=/usr/sbin/nginx maps=/tmp/.injected
[HOLLOW] pid=7001 comm=python3 fileless execution (memfd or deleted)
```

Known interpreters (`bash`, `python*`, `perl`, `ruby`, `node`) that legitimately differ from their first mapping are excluded. Fileless execution (empty `exe` or paths containing `memfd:`) is also caught.

## C2 beaconing detection

`--beacon-cv <f>` tracks CONNECT events per (PID, destination IP, port). After collecting at least 5 samples in a 300-second window, argus computes the coefficient of variation (CV = stddev / mean) of the inter-arrival intervals. Highly regular beaconing has a low CV:

```
[BEACON] pid=8801 comm=updater dest=198.51.100.5:443 cv=0.04 (n=12)
```

Typical legitimate traffic has CV > 0.5. Beaconing malware often achieves CV < 0.1. Start with `--beacon-cv 0.15`. Up to 1024 (PID, destination) pairs are tracked simultaneously.

## Syscall attack-chain detection

Argus tracks cross-event attack sequences per PID using a state machine with a 10-second expiry window. Four chains are detected:

| Chain | Trigger sequence | Alert tag |
|---|---|---|
| Shellcode injection | `MEMEXEC` → `EXEC` | `SHELLCODE_INJECT` |
| Ptrace code injection | `PTRACE` (write/pokedata) → `EXEC` | `PTRACE_INJECT` |
| Privilege escalation to shell | `PRIVESC` → `EXEC` of shell binary | `PRIVESC_SHELL` |
| Namespace escape | `NS_ESCAPE` → `EXEC` | `NS_ESCAPE_EXEC` |

```
[SEQDETECT] pid=5501 comm=loader chain=SHELLCODE_INJECT (MEMEXEC→EXEC)
[SEQDETECT] pid=3302 comm=exploit chain=PRIVESC_SHELL (PRIVESC→/bin/sh)
```

## YARA scanning

`--yara-rules <dir>` loads all `.yar` files from a directory and scans file contents on `EXEC`, `WRITE_CLOSE`, and `KMOD_LOAD` events:

```
[YARA] pid=7001 comm=loader file=/tmp/payload rule=Mirai_Variant (tags: malware,botnet)
[YARA] pid=5501 comm=insmod file=/tmp/evil.ko rule=Rootkit_Generic
```

Files larger than 64 MB are skipped. YARA is auto-detected at build time via `pkg-config`; if libyara is not installed, `--yara-rules` is accepted but produces a warning.

```sh
# Install libyara on Ubuntu
sudo apt-get install -y libyara-dev

# Write a simple rule
cat > /etc/argus/yara/mirai.yar <<'EOF'
rule Mirai_Strings {
    strings:
        $a = "/proc/net/tcp" ascii
        $b = "GETLOCALIP" ascii
    condition:
        all of them
}
EOF

sudo ./argus --yara-rules /etc/argus/yara/ --events EXEC
```

## LSM BPF enforcement mode

`--lsm-deny` enables in-kernel enforcement via BPF LSM hooks. When active, any event that matches a kernel drop rule is **denied at the syscall level** before it executes — not just logged:

- `lsm/file_open` — denies `open()`/`openat()` calls matching kernel rules
- `lsm/bprm_check_security` — denies `execve()`/`execveat()` matching kernel rules
- `lsm/socket_connect` — denies `connect()` to blocked destinations

```sh
# Deny all execs by UID 1001 at the kernel level
sudo ./argus --lsm-deny --rules /etc/argus/rules.json
```

Requires kernel 5.7+ with `CONFIG_BPF_LSM=y` and `bpf` listed in `/sys/kernel/security/lsm`. If the kernel does not support BPF LSM, `--lsm-deny` is accepted but the LSM programs are silently disabled and a warning is printed at startup.

## MITRE ATT&CK tagging

`--mitre-tags` annotates every JSON event with the corresponding MITRE ATT&CK technique:

```json
{"type":"EXEC","comm":"bash","filename":"/bin/bash","mitre_id":"T1059","mitre_name":"Command and Scripting Interpreter","mitre_tactic":"Execution"}
{"type":"PRIVESC","comm":"sudo","mitre_id":"T1548","mitre_name":"Abuse Elevation Control Mechanism","mitre_tactic":"Privilege Escalation"}
{"type":"MEMEXEC","comm":"loader","mitre_id":"T1055","mitre_name":"Process Injection","mitre_tactic":"Defense Evasion"}
```

The mapping covers all 21 event types. Unknown types emit empty strings. Use `jq 'select(.mitre_tactic == "Privilege Escalation")'` to filter by tactic.

## File hash enrichment and VirusTotal lookup

`--exec-hash` computes SHA-256 of every executed binary and attaches it to the event:

```json
{"type":"EXEC","comm":"curl","filename":"/usr/bin/curl","sha256":"6b86b273ff34fce..."}
```

With `--vt-api-key <key>`, the hash is checked asynchronously against VirusTotal. A cache of 256 entries (LRU) avoids redundant lookups. Results are logged:

```
[VT] /tmp/malware sha256=deadbeef... positives=47/72
```

## IOC enrichment (VirusTotal + AlienVault OTX)

`--vt-api-key` and `--otx-api-key` enable background IOC enrichment on EXEC, CONNECT, and DNS events. Queries run in a background worker thread with rate limiting and a 512-entry LRU cache (TTL 3600 s):

```
[IOC] comm=curl ip=198.51.100.5 vt=malicious otx=known_c2
[IOC] comm=python3 domain=evil.example.com otx=malware_distribution
```

## Network isolation response

`--response-isolate` automatically blocks source IPs of processes that trigger alert rules by inserting `iptables` (IPv4) or `ip6tables` (IPv6) DROP rules at runtime. Up to 64 IPs are tracked simultaneously. All blocks are removed cleanly on exit via `isolate_unblock_all()`.

```sh
# Block any IP that triggers a threat-intel rule
sudo ./argus --rules /etc/argus/rules.json --response-isolate
```

The isolation action is gated behind the `--response-isolate` flag as a safety switch (matching `--response-kill`). Entries are validated with `inet_pton` before insertion; malformed addresses are rejected.

## Persistent event store

`--store-path <path>` writes all events to a SQLite3 database asynchronously via an internal write queue. The database is created automatically if it does not exist.

`--store-query-port <port>` serves a simple HTTP API for querying events:

```sh
# Query the last 50 EXEC events
curl 'http://localhost:8080/events?type=EXEC&limit=50'

# Full-text search on filename
curl 'http://localhost:8080/events?q=/etc/shadow'

# Statistics summary
curl 'http://localhost:8080/stats'
```

SQLite3 is detected at build time via `pkg-config sqlite3`; if not installed, `--store-path` is accepted but silently skipped.

## Webhook / SOAR integration

`--webhook <url>` fires an HTTP POST to the given URL for every alert generated by the rules engine. Requests are dispatched asynchronously from a background thread using a 64-entry circular queue (fire-and-forget; drops if queue is full):

```sh
# Send alerts to a Slack incoming webhook
sudo ./argus --rules /etc/argus/rules.json \
    --webhook 'https://hooks.slack.com/services/T.../B.../...'

# Route to PagerDuty
sudo ./argus --webhook 'https://events.pagerduty.com/v2/enqueue'
```

The request body is the raw JSON alert object. Response bodies and errors are discarded — the intent is fire-and-forget integration with SOAR platforms, ticketing systems, and chat tools.

## Container / Kubernetes enrichment

`--container-enrich` queries the Docker Unix socket (`/var/run/docker.sock`) on demand to resolve the cgroup leaf name to container metadata. A 128-entry LRU cache avoids repeated socket queries for the same container. Resolved fields are added to JSON events:

```json
{"type":"EXEC","comm":"sh","cgroup":"docker-abc123.scope","container_name":"webapp","container_image":"nginx:1.25","pod_name":"webapp-7d9f","k8s_namespace":"production"}
```

## Compliance reporting

`--compliance <framework>` selects a control mapping and counts events per control. `--compliance-report <path>` writes an HTML report on exit.

Supported frameworks:

| Framework | Key controls mapped |
|---|---|
| `cis` | CIS Controls 1–18 (Linux) |
| `pci-dss` | PCI DSS 3.2.1 Requirements 6, 8, 10, 11 |
| `nist` | NIST CSF Identify / Protect / Detect / Respond |
| `soc2` | SOC 2 Trust Service Criteria CC6–CC9 |

```sh
sudo ./argus --compliance pci-dss --compliance-report /tmp/pci_report.html
firefox /tmp/pci_report.html
```

## Syscall frequency anomaly detection

`--syscall-anom <secs>` reads a BPF LRU hash map (`syscall_counts`) that the kernel-side `sys_enter` tracepoint populates every time a syscall fires. Every N seconds, the per-comm syscall distribution is compared against a reference baseline using a chi-squared test:

```
[SYSCALL_ANOM] comm=nginx syscall=mprotect observed=842 expected=12 chi2=61.3
[SYSCALL_ANOM] comm=python3 syscall=clone observed=301 expected=2 chi2=44.8
```

Anomalies indicate rootkit activity, injected shellcode executing unusual syscalls, or a compromised interpreter.

## TLS data capture

`--tls-data` attaches a `uretprobe` on `SSL_read` in the process's linked OpenSSL. When the return fires, up to 256 bytes of the decrypted plaintext are read from userspace via `bpf_probe_read_user` and emitted as a `TLS_DATA` event:

```json
{"type":"TLS_DATA","comm":"curl","pid":4512,"tls_payload":"GET / HTTP/1.1\r\nHost: evil.c2.example\r\n","tls_payload_len":42}
```

This allows inspection of encrypted traffic from within the process without a proxy. Requires OpenSSL; silently skipped if not found.

## Memory forensics

`--mem-forensics` triggers on EXEC events. It scans `/proc/<pid>/maps` for anonymous executable mappings (typically injected shellcode), reads the content via `/proc/<pid>/mem`, computes Shannon entropy, and optionally runs YARA rules:

```
[MEMFORENSICS] pid=7001 comm=loader anon_exec_region 0x7f3c00001000-0x7f3c00002000 entropy=7.82 (high)
[MEMFORENSICS] pid=7001 comm=loader YARA hit: Shellcode_Mirai region=0x7f3c00001000
```

High entropy (> 7.0) in an anonymous executable region is a strong indicator of packed shellcode or a stage-2 payload.

## Agent health management (argus-server)

`argus-server` tracks health metrics for each connected sensor. Argus sensors emit periodic `HEARTBEAT` events; the server parses them and updates per-client state.

`--mgmt-port <port>` starts a management HTTP API on loopback:

```sh
./argus-server --port 9000 --mgmt-port 8081

# List all connected sensors with health data
curl http://localhost:8081/agents
```

```json
[
  {"host":"10.0.0.1","version":"0.4.0","connected_secs":3600,"last_hb_secs":5,"uptime_secs":86400},
  {"host":"10.0.0.2","version":"0.4.0","connected_secs":120,"last_hb_secs":2,"uptime_secs":120}
]
```

```sh
# Server-side statistics
curl http://localhost:8081/stats
```

```json
{"uptime_secs":3601,"connected_clients":2,"total_accepted":5,"fleet_corr_alerts":3}
```

## DNS correlation and DGA detection

### DNS → IP correlation

When a `DNS` event is observed, argus caches the queried name with a 60-second TTL. When a subsequent `CONNECT` resolves to an IP from that cache, a synthetic `NET_CORR` event is emitted linking the domain name to the connection:

```json
{"type":"NET_CORR","comm":"malware","dns_name":"c2.evil.example","daddr":"198.51.100.5","dport":443}
```

This surfaces C2 connections that are otherwise visible only as raw IP connects.

### DGA detection

`--dga-entropy-threshold <f>` computes the Shannon entropy of every DNS query name. Names above the threshold are flagged:

```
[DGA] high-entropy DNS name: xf4k2mz9q1p.example.com (entropy=4.12)
```

Legitimate hostnames (e.g. `api.github.com`) typically score below 3.0. DGA-generated names typically score above 3.5.

## Baseline / anomaly mode

Argus learns the normal behaviour of each process and alerts on deviations.

### Learning

```sh
sudo ./argus --baseline-learn 3600 --baseline-out /etc/argus/baseline.json
```

The profile records per-comm:
- `exec_targets` — filenames of every successful `execve`
- `connect_dests` — `addr:port` pairs from every successful `connect`
- `open_paths` — filenames of every successful `open`
- `bind_ports` — local ports from every successful `bind`

### Detection

```sh
sudo ./argus --baseline /etc/argus/baseline.json --json
```

Anomaly alerts:

**Text mode:**
```
[ANOMALY] comm=nginx pid=4102 new_connect_dest: 198.51.100.5:4444
```

**JSON mode:**
```json
{"type":"ANOMALY","severity":"HIGH","comm":"nginx","pid":4102,"what":"new_connect_dest","value":"198.51.100.5:4444"}
```

### Cgroup-aware baselines (`--baseline-cgroup-aware`)

By default baselines key by `comm`. With `--baseline-cgroup-aware`, keys become `cgroup/comm` — each container gets its own profile, preventing cross-container baseline bleeding in multi-tenant environments.

### Rolling merge (`--baseline-merge-after N`)

An anomaly is automatically merged into the baseline after being seen N times. This handles legitimate but infrequent operations (nightly batch jobs, weekly certificate renewal) without requiring manual profile updates. Set to 0 to disable auto-merge and require explicit re-learning.

## Alert rules

Argus evaluates detection rules against every event and emits alerts for matches. Load rules with `--rules <path>`.

### Rule file format

```json
[
    {
        "name":          "Privilege escalation",
        "severity":      "critical",
        "type":          "PRIVESC",
        "message":       "{comm} (pid={pid}) escalated uid {uid_before}→{uid_after}"
    },
    {
        "name":          "Anonymous memory execution",
        "severity":      "critical",
        "type":          "MEMEXEC",
        "message":       "{comm} mapped anonymous executable memory"
    },
    {
        "name":          "Kernel module load",
        "severity":      "critical",
        "type":          "KMOD_LOAD",
        "message":       "{comm} (pid={pid}) loaded module: {filename}"
    },
    {
        "name":          "Threat intel match — kill",
        "severity":      "critical",
        "type":          "THREAT_INTEL",
        "action":        "kill",
        "message":       "{comm} connected to blocklisted IP {daddr}:{dport}"
    },
    {
        "name":          "Shell spawned by web server",
        "severity":      "high",
        "type":          "EXEC",
        "comm":          "bash",
        "parent_comm":   "nginx",
        "message":       "web server spawned shell: {filename}"
    },
    {
        "name":          "Suspicious shadow access",
        "severity":      "high",
        "path_contains": "/etc/shadow",
        "message":       "{comm} (uid={uid}) accessed {filename}"
    },
    {
        "name":          "Repeated brute-force — suppress after 5",
        "severity":      "medium",
        "type":          "CONNECT",
        "comm":          "hydra",
        "threshold_count":     5,
        "threshold_window_secs": 60,
        "suppress_after_secs": 300,
        "message":       "brute force from {comm} to {daddr}:{dport}"
    },
    {
        "name":          "World-writable chmod",
        "severity":      "high",
        "type":          "CHMOD",
        "mode_mask":     2,
        "message":       "{comm} made {filename} world-writable (mode=0{mode})"
    }
]
```

### Rule fields

| Field | Type | Description |
|---|---|---|
| `name` | string | Rule name — required, shown in alert output |
| `severity` | string | `info` \| `low` \| `medium` \| `high` \| `critical` |
| `type` | string | Event type to match (any type from [Event Types](#event-types)); omit to match all |
| `comm` | string | Exact process name match; omit to match any |
| `parent_comm` | string | Immediate parent process name match (walks lineage table) |
| `ancestor_comm` | string | Any ancestor process name match (full chain search) |
| `uid` | int | Exact UID match; `-1` or omit to match any |
| `path_contains` | string | Substring match on `filename`; omit to match any |
| `mode_mask` | int | CHMOD only: fire if `(mode & mode_mask) != 0` |
| `threshold_count` | int | Fire only after this many matches within `threshold_window_secs` |
| `threshold_window_secs` | int | Window for threshold counting (seconds) |
| `suppress_after_secs` | int | Suppress this rule for N seconds after first alert fires |
| `action` | string | `"kill"` — terminate the matched process via BPF (`--response-kill` must be set) |
| `message` | string | Alert message with `{variable}` substitution |

### Message template variables

`{comm}` `{pid}` `{ppid}` `{uid}` `{gid}` `{cgroup}` `{filename}` `{args}` `{new_path}` `{mode}` `{target_pid}` `{ptrace_req}` `{daddr}` `{dport}` `{laddr}` `{lport}` `{uid_before}` `{uid_after}` `{dns_name}`

### Alert output

**Text mode** — alerts go to stderr:
```
[ALERT:critical] Privilege escalation: sudo (pid=1024) escalated uid 1000→0
[ALERT:critical] Threat intel match — kill: nc connected to blocklisted IP 198.51.100.5:4444
```

**JSON mode** — alerts appear inline in the event stream:
```json
{"type":"ALERT","severity":"critical","rule":"Privilege escalation","pid":1024,"ppid":1023,"uid":1000,"comm":"sudo","message":"sudo (pid=1024) escalated uid 1000→0"}
```

Rules are reloaded on `SIGHUP` — no restart needed to deploy new detections.

## Active response

When `--response-kill` is passed and a rule has `"action": "kill"`, argus writes the matched PID into a BPF hash map (`kill_list`). On the next kernel event from that PID (or immediately on subsequent tracepoint invocations), the BPF program calls `bpf_send_signal(SIGKILL)` — the process is terminated before its next syscall returns.

This is a hard kill mechanism suitable for:
- Terminating processes that connect to known C2 infrastructure (THREAT_INTEL + kill)
- Stopping processes that load unauthorized kernel modules (KMOD_LOAD + kill)
- Killing rogue processes that attempt ptrace injection (PTRACE + kill)

The kill action is gated behind `--response-kill` as an explicit safety switch to prevent accidental rule deployments from terminating production processes.

## Prometheus metrics

`--metrics-port <n>` starts a background HTTP server that serves Prometheus text format on any path:

```sh
curl http://localhost:9090/metrics
```

```
# HELP argus_events_total Total events observed by argus
# TYPE argus_events_total counter
argus_events_total 48291

# HELP argus_events_by_type Events observed per type
# TYPE argus_events_by_type counter
argus_events_by_type{type="exec"} 1204
argus_events_by_type{type="connect"} 892
argus_events_by_type{type="dns"} 744
...

# HELP argus_drops_total Ring-buffer events dropped
# TYPE argus_drops_total counter
argus_drops_total 0

# HELP argus_rule_hits_total Alert rules matched
# TYPE argus_rule_hits_total counter
argus_rule_hits_total 17

# HELP argus_anomalies_total Baseline anomalies detected
# TYPE argus_anomalies_total counter
argus_anomalies_total 3

# HELP argus_forward_connections_total Successful TCP forward connections
# TYPE argus_forward_connections_total counter
argus_forward_connections_total 2
```

Wire this into a Prometheus scrape job and add Grafana dashboards or Alertmanager rules for drop-rate alerting and rule-hit trending.

## Fleet mode (`argus-server`)

`argus-server` is a TCP aggregator that receives NDJSON streams from multiple argus instances, injects a `"host"` field, and re-emits to stdout (or a downstream SIEM):

```sh
# Start the aggregator (listen on all interfaces, port 9000)
./argus-server --port 9000

# Each sensor forwards to the aggregator
sudo ./argus --forward aggregator.internal:9000 --json
```

The aggregator adds `"host": "<sender-IP>"` to each event JSON object and writes them to stdout as NDJSON, making it easy to pipe into a log shipper, Kafka topic, or Elasticsearch ingest pipeline.

### Fleet correlation engine

`argus-server` also performs cross-host IOC correlation. When the same indicator (IP:port, filename, or comm) is seen from ≥ N distinct hosts within a sliding time window, a `FLEET_CORR` alert is injected into the output stream:

```sh
# Alert when the same IOC appears from 3+ hosts within 60 seconds (defaults)
./argus-server --port 9000 --correlate-threshold 3 --correlate-window 60
```

```json
{"type":"FLEET_CORR","ioc":"198.51.100.5:4444","hosts":["10.0.0.1","10.0.0.2","10.0.0.3"],"count":3,"window_secs":60}
```

| Option | Description |
|---|---|
| `--correlate-window <secs>` | Sliding window for correlation (default: 60) |
| `--correlate-threshold <n>` | Minimum distinct hosts to trigger alert (default: 3) |

IOC keys are extracted automatically by event type: CONNECT/THREAT_INTEL → `IP:port`; EXEC/OPEN/WRITE_CLOSE/UNLINK/KMOD_LOAD → `filename`; PRIVESC/NS_ESCAPE/PTRACE → `comm`.

## Output modes

| Flag | Description |
|---|---|
| *(default)* | Text table to stdout (USER column shows username from `/etc/passwd`) |
| `--json` / `--output-fmt json` | Newline-delimited JSON; includes `"user"` and `"hostname"` fields |
| `--output-fmt cef` | ArcSight CEF for direct SIEM ingestion |
| `--output <path>` | Append event stream to file; compatible with any format |
| `--syslog` / `--output-fmt syslog` | All events go to `syslog(LOG_DAEMON)` |
| `--output-fmt text` | Explicit default (useful in config file) |

## Forwarding

`--forward host:port` streams every matched event as newline-delimited JSON over a persistent TCP connection.

```sh
# Any TCP listener works — netcat for quick testing
nc -lk 9000

# Production: Vector, Logstash, Fluent Bit, Loki, custom receiver
sudo ./argus --forward siem.internal:9000

# TLS with server certificate verification
sudo ./argus --forward siem.internal:9000 --forward-tls

# TLS without cert check (self-signed / private CA)
sudo ./argus --forward siem.internal:9000 --forward-tls-noverify

# IPv6
sudo ./argus --forward '[::1]:9000'
```

### Multiple targets

Up to 8 forwarding targets can be active simultaneously via the `"targets"` array in the config file:

```json
{
    "forward": "primary-siem:9000",
    "targets": [
        {"addr": "backup-siem:9000"},
        {"addr": "cloud-siem.corp:9001", "tls": true}
    ]
}
```

### Reliability behaviour

| Condition | Behaviour |
|---|---|
| Remote unreachable at startup | Non-fatal warning; retries with exponential backoff (1 s → 2 s → … → 30 s) |
| Connection lost mid-run | Reconnects automatically with same backoff |
| Send buffer full (slow receiver) | Event dropped and counted; drop count sent as `{"type":"DROP","count":N}` on reconnect |
| `SIGHUP` | Reconnects and reloads config |

## Security

### Privilege drop

After all BPF programs are attached and the ring buffer fd is open, argus drops from root to `nobody` (uid 65534). All open file descriptors remain valid after the privilege drop.

### Seccomp filter

Immediately after the privilege drop, argus installs a seccomp BPF denylist. Even if the event-loop code is compromised, the filter prevents:

- **New processes** — `execve`, `execveat`, `fork`, `vfork` → `EPERM`
- **Process inspection** — `ptrace` → `EPERM`
- **Credential escalation** — `setuid`, `setgid`, `setresuid`, `setresgid` → `EPERM`
- **Kernel-level attacks** — `mount`, `init_module`, `finit_module`, `kexec_load` → `EPERM`

`PR_SET_NO_NEW_PRIVS` is also set so child processes cannot gain new privileges. On kernels without seccomp support, the call is silently skipped.

## Config reload (SIGHUP)

Send `SIGHUP` to reload config files without restarting:

```sh
sudo kill -HUP $(pidof argus)
# or
sudo systemctl reload argus
```

On SIGHUP, argus re-reads both config files, updates BPF filter maps (pid/comm allowlists, rate limits), reloads alert rules, and reconnects forwarders. The event type mask and ring buffer size remain fixed for the lifetime of the process.

## PID subtree tracking (`--follow`)

`--follow <pid>` traces a process and all its descendants dynamically as they are spawned. The BPF `sched_process_fork` tracepoint propagates the tracked set automatically.

```sh
# Trace nginx and every worker process it spawns
sudo ./argus --follow $(pidof nginx | awk '{print $1}')

# Trace a shell session and everything it runs
sudo ./argus --follow $$
```

## DNS reverse-lookup

CONNECT and BIND events automatically include a reverse-DNS hostname lookup. Results are cached in a 512-entry table with a 300-second TTL.

```json
{"type":"CONNECT",...,"daddr":"93.184.216.34","hostname":"example.com","dport":443}
```

## Process lineage

At startup, argus scans `/proc` to pre-populate the ancestry cache with all running processes. The `lineage` field shows the ancestor chain from the oldest known ancestor down to the immediate parent (e.g. `systemd→sshd→bash`). Rule fields `parent_comm` and `ancestor_comm` query this same cache.

## Testing

```sh
# Unit tests — no root, no kernel required
make test

# Unit tests with AddressSanitizer + UBSan
make test-asan

# Integration tests — requires root and a built argus binary
make test-integration
```

Unit tests cover: filter logic, lineage cache, alert rules (including suppression/threshold), TCP forwarding, baseline/anomaly module (including rolling merge), Prometheus metrics, FIM, and DNS/threat-intel correlation — **227 tests** across 8 test binaries. All new enterprise modules are integrated but do not require additional test infrastructure (they are covered by the existing integration and unit test paths). Integration tests cover 17 filter scenarios including `--pid`, `--comm`, event-type masking, rate limiting, forwarding, FIM, rules, and `--follow` PID subtree tracking.

## Performance tuning

**Ring buffer size** — Default 256 KB. On busy servers increase with `--ringbuf 1024`.

**Kernel-side vs userspace filters** — `--pid`, `--comm`, `--rate-limit`, `--rate-limit-per-pid`, and threat-intel matching are all enforced inside BPF before events reach the ring buffer. `--path` and `--exclude` are evaluated in userspace.

**Summary mode** — `--summary 60` trades per-event latency for dramatically lower output volume. Recommended for long-running daemon deployments.

**Metrics** — If `--metrics-port` is not set, all metric counters are no-ops with zero overhead.

## Troubleshooting

**`error: failed to open BPF skeleton`** — Ensure you're running as root (or have `CAP_BPF` + `CAP_PERFMON`) and that the kernel is 5.8+.

**`ls: cannot access '/sys/kernel/btf/vmlinux': No such file or directory`** — Your kernel was built without BTF. Check with `zcat /proc/config.gz | grep CONFIG_DEBUG_INFO_BTF`.

**BPF verifier error on load** — Usually seen on kernels older than 5.15. Reduce `ARGUS_MAX_ARGS` in `argus.bpf.c` and rebuild.

**`warning: could not drop privileges`** — The `nobody` user does not exist. Add with `useradd -r -s /sbin/nologin nobody` or pass `--no-drop-privs`.

**High drop rate** — Increase `--ringbuf` and/or add `--pid` / `--comm` / `--events` filters. Drop counts appear as `[WARNING: N event(s) dropped]` in text mode and `{"type":"DROP","count":N}` in JSON.

**Validate your config before deploying:**

```sh
./argus --config /etc/argus/config.json --config-check
```

## CI

Every push and pull request to `main` runs the full test suite on GitHub Actions across two kernel versions (`ubuntu-latest` and `ubuntu-22.04` / kernel 5.15 LTS). Each run installs all build dependencies, verifies BTF availability, builds the binary, and runs unit, ASAN, and integration tests.

## Development environment

If you are on macOS or a machine without a compatible Linux kernel, use the included Lima VM config:

```sh
# Install Lima (macOS)
brew install lima

# Start the VM (first run downloads Ubuntu 22.04, ~5 min)
limactl start --name=argus lima/argus.yaml

# Open a shell inside the VM
limactl shell argus

# Build and run (your working directory is auto-mounted)
cd ~/path/to/argus
make
sudo ./argus
```

The Lima VM uses Apple's Virtualization Framework (`vmType: vz`) on Apple Silicon for near-native performance. Your macOS home directory is mounted read-write inside the VM at the same path, so edits in VS Code are immediately visible inside the VM.

To connect VS Code directly to the VM via Remote SSH:

```sh
limactl show-ssh --format config argus >> ~/.ssh/config
# Then connect to host "lima-argus" in VS Code Remote SSH
```

## Repository layout

```
src/
├── bpf/
│   └── argus.bpf.c      eBPF kernel programs — all 21 event types; BPF maps for kill list,
│                          threat-intel LPM trie, rate limiting, per-syscall scratch buffers;
│                          LSM hooks for in-kernel enforcement (file_open, bprm_check, socket_connect)
├── argus.c              Userspace loader, ring buffer consumer, CLI, DNS correlation cache,
│                          DGA entropy detection, LD_PRELOAD check dispatch, FIM dispatch,
│                          canary/hollow/beacon/seqdetect/yara dispatch
├── argus-server.c       Fleet aggregator: multi-sensor TCP receiver, host field injection,
│                          cross-host IOC correlation engine (FLEET_CORR alerts)
├── argus.h              Shared event struct, 21 type definitions, TRACE_* bitmasks,
│                          kernel_rule_t and argus_config_t shared between BPF and userspace
├── output.c/h           Text, JSON, CEF, and syslog formatting; filtering; summary mode
├── rules.c/h            Alert rule engine: JSON loading, field matching, threshold/suppression
├── forward.c/h          Multi-target TCP event forwarding with optional TLS
├── dns.c/h              Reverse-DNS lookup cache (512 entries, 300 s TTL)
├── baseline.c/h         Baseline / anomaly detection: cgroup-aware keys, rolling merge
├── fim.c/h              File Integrity Monitoring: SHA-256 hashing, change detection
├── ldpreload.c/h        LD_PRELOAD / LD_LIBRARY_PATH / PYTHONPATH injection detection
├── threatintel.c/h      Threat-intel CIDR feed loader into BPF LPM trie
├── metrics.c/h          Prometheus metrics HTTP endpoint (background pthread)
├── seccomp.c/h          Seccomp BPF denylist: blocks exec/fork/ptrace/setuid after priv-drop
├── lineage.c/h          Userspace process ancestry cache; parent_comm/ancestor_comm queries
├── config.c/h           JSON config file parser
├── canary.c/h           Honeypot file detection: exact-path and prefix matching
├── dedup.c/h            Alert deduplication: 512-slot hash table with per-key time window
├── hollow.c/h           Process hollowing detection: exe vs. maps comparison, fileless execution
├── beacon.c/h           C2 beaconing detection: per-(pid,dest) CV of CONNECT inter-arrivals
├── seqdetect.c/h        Syscall attack-chain detection: MEMEXEC→EXEC, PTRACE→EXEC, etc.
├── yara_scan.c/h        YARA rule scanning on EXEC, WRITE_CLOSE, KMOD_LOAD (optional libyara)
├── mitre.c/h            MITRE ATT&CK technique lookup table; JSON annotation helpers
├── webhook.c/h          Webhook/SOAR integration: async HTTP POST, 64-entry queue, background thread
├── exechash.c/h         SHA-256 exec binary hashing (OpenSSL EVP), 256-entry LRU, VT lookup
├── isolate.c/h          Network isolation: iptables/ip6tables DROP rules, 64-IP tracking
├── memforensics.c/h     Memory forensics: anon exec mapping scan, entropy, YARA
├── store.c/h            Persistent SQLite3 event store, async write queue, HTTP query API
├── iocenrich.c/h        IOC enrichment: async VT + OTX lookups, 512-entry LRU cache
├── container.c/h        Container enrichment: Docker socket HTTP, cgroup→container/pod resolution
├── compliance.c/h       Compliance mapping (CIS/PCI-DSS/NIST/SOC2), HTML report generation
└── syscallanom.c/h      Syscall frequency anomaly: reads BPF histogram, chi-squared per comm

man/
└── argus.8              Man page

packaging/
├── argus.service        systemd service unit
├── argus.tmpfiles       systemd-tmpfiles config for /var/log/argus pre-creation
├── argus.logrotate      logrotate config (daily, 14 days, compressed)
└── argus.spec           RPM spec file (make rpm)

tests/                   Unit tests (test_lineage, test_output, test_rules, test_forward,
                           test_baseline, test_metrics, test_fim, test_netcorr) and
                           integration test (test_filter.sh)
lima/                    Lima VM config for development on non-Linux hosts
.devcontainer/           VS Code Dev Container config
.github/workflows/       GitHub Actions CI (ubuntu-latest + ubuntu-22.04 matrix)
Makefile                 Build entry point (targets: all, test, test-asan, test-integration,
                           install, deb, rpm, man, clean)
```

## Contributing

Contributions are welcome. Please follow these steps:

1. **Fork** the repository and create a branch from `main`.
2. **Build and test** before submitting: `make && make test && make test-asan`
3. **BPF changes** — run `make test-integration` on a Linux host (kernel 5.8+ with BTF). The dev container (`.devcontainer/`) and Lima config (`lima/`) both provide a ready environment.
4. **Style** — userspace C follows `-Wall -Wextra -Wno-unused-parameter -std=c11` with zero warnings. BPF C follows the same flags plus `-target bpf`.
5. **Tests** — new modules need a corresponding `tests/test_<module>.c` with `make test-unit` coverage. Extend `tests/test_enterprise.c` for enterprise-tier features.
6. **Open a pull request** with a clear description of what changed and why. Reference any related issue numbers.

For bug reports and feature requests, open a GitHub issue with the relevant kernel version, distro, and `argus --version` output.
