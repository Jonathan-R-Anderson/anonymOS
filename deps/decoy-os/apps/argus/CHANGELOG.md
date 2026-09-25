# Changelog

All notable changes to argus are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.0] — 2026-03-22

### Added
- **10 enterprise modules** wired into the main event pipeline:
  - `mitre` — MITRE ATT&CK tactic/technique annotation (`--mitre-tags`)
  - `webhook` — async HTTP POST alert dispatcher (`--webhook`)
  - `exechash` — SHA-256 of executed binaries + VirusTotal lookup (`--exec-hash`, `--vt-api-key`)
  - `isolate` — automatic iptables isolation of threat-intel matches (`--response-isolate`)
  - `memforensics` — Shannon entropy + YARA scan of anonymous exec mappings (`--mem-forensics`)
  - `store` — SQLite3 persistent event store with HTTP query API (`--store-path`, `--store-query-port`)
  - `iocenrich` — VirusTotal + AlienVault OTX IOC enrichment via HTTPS (`--vt-api-key`, `--otx-api-key`)
  - `container` — Docker socket enrichment for container name/image (`--container-enrich`)
  - `compliance` — CIS/PCI-DSS/NIST-CSF/SOC2 control mapping + HTML report (`--compliance`, `--compliance-report`)
  - `syscallanom` — BPF syscall histogram chi-squared anomaly detection (`--syscall-anom`)
- **`EVENT_TLS_DATA`** — decrypted TLS payload capture via OpenSSL uprobe (`--tls-data`)
- **`EVENT_HEARTBEAT`** — agent liveness ping; tracked by argus-server for health monitoring
- **BPF program gating** — SSL uprobe and `handle_sys_enter` programs only load when their feature is enabled, fixing EACCES on kernels without uprobe support
- **`argus-server` HA reconnect** — sensors that crash and reconnect are deduplicated by hostname; stale connections evicted after configurable heartbeat timeout (`--hb-timeout`)
- **`argus-server --hb-timeout`** — CLI option to control heartbeat eviction window (default: 300 s)
- **`argus-server --mgmt-port`** — `GET /agents` and `GET /stats` management API
- **Performance benchmark** — `make bench` builds `argus-bench` tool measuring events/sec for all output formats
- **Prometheus metrics for enterprise modules** — webhook queue depth, posts, drops; IOC cache hit/miss; SQLite insert counters exposed at `--metrics-port`
- **`.deb` packaging** — `make deb` produces an installable Debian package with `postinst`/`prerm` scripts
- **`argus-server.service`** — hardened systemd unit for the fleet aggregation server
- **GitHub Actions CI** — matrix build on ubuntu-22.04/24.04; unit + ASAN + enterprise tests; `.deb` build + artifact upload
- **GitHub Actions release workflow** — auto-publishes tagged `.deb` + standalone binaries to GitHub Releases on `v*` tags
- **Shell completions** — bash (`/etc/bash_completion.d/argus`) and zsh (`_argus`) for all flags
- **`packaging/argus.conf.example`** — fully-commented example config with all options
- **Config key validation** — unknown JSON keys in config files now warn on stderr instead of silently being ignored
- **`man/argus-server.8`** — full man page for the fleet aggregation server
- **`man/argus.8`** — updated with all 14 enterprise flags, 9 new event types, new config keys, new examples

### Fixed
- **BPF verifier E2BIG (-4007) on kernel 5.15** — `parse_dns_name` with 32×63 `#pragma unroll` loops exceeded the 1 M instruction limit; DNS name decoding moved entirely to userspace (`parse_dns_payload()`)
- **SSL uprobe EACCES on load** — uprobe programs were always loaded regardless of `--tls-data`; fixed with `bpf_program__set_autoload(false)` gating
- **SQLite not compiled in** — documented `pkg-config libsqlite3-dev` requirement; added to devcontainer and CI
- **`--mgmt-port` absent from `--help`** — added to `usage()` in `argus-server.c`
- **Dead code warnings** — removed dead `parse_dns_name` BPF function, `dns_name` field in `sendto_start`, dead `dbuf_*` functions in `store.c`

### Changed
- `configure_programs()` now accepts `tls_data_enable` and `syscall_anom_interval` parameters
- Systemd service hardened with `CapabilityBoundingSet`, `AmbientCapabilities`, `MemoryMax=512M`, `LimitMEMLOCK=infinity`, `OOMScoreAdjust=-500`

---

## [0.3.0] — 2025-11-15

### Added
- **Fleet aggregation server** (`argus-server`) — accepts NDJSON streams from multiple sensors, merges with `"host"` field, runs IOC correlation engine (`--correlate-window`, `--correlate-threshold`)
- **CEF output format** (`--output-fmt cef`) — ArcSight Common Event Format v0 for direct SIEM ingestion
- **TLS SNI capture** (`EVENT_TLS_SNI`) — ClientHello SNI via uprobe on `SSL_write`
- **Proc scrape detection** (`EVENT_PROC_SCRAPE`) — foreign reads of `/proc/<pid>/mem|maps|fd`
- **Namespace escape detection** (`EVENT_NS_ESCAPE`) — `setns`/`unshare`/`clone` with `CLONE_NEW*`
- **Threat intelligence blocklist** (`--threat-intel`) — CONNECT events matched against IP blocklist
- **Canary file detection** — inotify-based tripwire files; access generates high-severity alerts
- **Beacon detection** — periodic outbound connections flagged by coefficient-of-variation analysis
- **Alert deduplication** (`--alert-dedup-secs`) — suppress repeated alerts for the same rule+comm
- **LSM BPF enforcement** (`--lsm-deny`) — block execve via LSM hook for rules with `action: deny`
- **Sequence detection** — multi-step attack pattern matching across event chains
- **Process hollowing detection** — detects `PTRACE_POKETEXT` patterns indicative of hollowing
- **DGA entropy scoring** (`--dga-entropy-threshold`) — flag high-entropy DNS query names
- **Prometheus metrics endpoint** (`--metrics-port`) — events/sec, drops, rule hits, anomalies

### Fixed
- Ring buffer overflow handling — `print_drops()` now distinguishes text/JSON/syslog modes
- Lineage cache eviction — LRU eviction prevents unbounded growth on long-running deployments

---

## [0.2.0] — 2025-07-01

### Added
- **Behavioural baseline** (`--baseline`, `--baseline-learn`) — per-comm anomaly detection
- **File Integrity Monitoring** (`--fim-paths`) — inotify-based real-time directory monitoring
- **YARA scanning** (`--yara-rules-dir`) — scan executed binaries and mmap'd regions
- **LD_PRELOAD detection** — flag execve events with suspicious LD_PRELOAD environment variables
- **JSON config file** (`--config`) — load options from `/etc/argus/config.json`
- **Multi-target forwarding** — `"targets"` array in config for up to 4 SIEM endpoints
- **TLS forwarding** (`--forward-tls`) — encrypt the NDJSON forward stream with OpenSSL
- **Rate limiting** (`--rate-limit`) — kernel-side token bucket per comm name
- **Syscall profile interval** — periodic per-PID syscall frequency sampling

---

## [0.1.0] — 2025-03-15

### Added
- Initial release
- eBPF tracing of: EXEC, OPEN, EXIT, CONNECT, UNLINK, RENAME, CHMOD, BIND, PTRACE
- Full process lineage chain on every event
- Container cgroup attribution
- Text, JSON, syslog output formats
- BPF kernel-side pid/comm filter maps
- Alert rules engine (JSON rule files)
- DNS query capture (port-53 sendto)
- Forward stream to remote host:port over TCP
- Man page (`man/argus.8`)
- RPM packaging (`packaging/argus.spec`)
- Seccomp denylist applied after privilege drop
