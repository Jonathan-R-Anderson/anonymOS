# CLI Reference

PRX-SD provides the `sd` command-line tool for threat detection and system protection.

## Global Options

| Flag | Description | Default |
|------|-------------|---------|
| `--log-level <LEVEL>` | Logging verbosity: `trace`, `debug`, `info`, `warn`, `error` | `warn` |
| `--data-dir <PATH>` | Data directory for signatures, quarantine, config | `~/.prx-sd/` |

---

## Scanning

### `sd scan <PATH>`

Scan a file or directory for threats.

```bash
sd scan /path/to/file
sd scan /home --recursive
sd scan /tmp --auto-quarantine --remediate
sd scan /path --json
sd scan /path --report report.html
```

| Option | Description | Default |
|--------|-------------|---------|
| `-r, --recursive <BOOL>` | Recurse into subdirectories | `true` for directories |
| `--json` | Output results as JSON | |
| `-t, --threads <NUM>` | Number of scanner threads | CPU count |
| `--auto-quarantine` | Automatically quarantine malicious files | |
| `--remediate` | Auto-remediate: kill processes, quarantine, clean persistence | |
| `-e, --exclude <PATTERN>` | Glob patterns to exclude (repeatable) | |
| `--report <PATH>` | Export results as self-contained HTML report | |

### `sd scan-memory`

Scan running process memory for threats (Linux only, requires root).

```bash
sudo sd scan-memory
sudo sd scan-memory --pid 1234
sudo sd scan-memory --json
```

| Option | Description |
|--------|-------------|
| `--pid <PID>` | Scan a specific process (omit to scan all) |
| `--json` | Output as JSON |

### `sd scan-usb [DEVICE]`

Scan USB/removable devices.

```bash
sd scan-usb
sd scan-usb /dev/sdb1 --auto-quarantine
```

| Option | Description |
|--------|-------------|
| `--auto-quarantine` | Automatically quarantine detected threats |

### `sd check-rootkit`

Check for rootkit indicators (Linux only).

```bash
sudo sd check-rootkit
sudo sd check-rootkit --json
```

Checks: hidden processes, kernel module integrity, LD_PRELOAD hooks, /proc anomalies.

---

## Real-time Protection

### `sd monitor <PATHS...>`

Real-time file system monitoring.

```bash
sd monitor /home /tmp
sd monitor /home --block
sd monitor /home --daemon
```

| Option | Description |
|--------|-------------|
| `--block` | Block malicious files before access (requires root + fanotify on Linux) |
| `--daemon` | Run as background daemon |

### `sd daemon [PATHS...]`

Run as a background daemon with real-time monitoring and automatic updates.

```bash
sd daemon
sd daemon /home /tmp --update-hours 2
```

| Option | Description | Default |
|--------|-------------|---------|
| `--update-hours <NUM>` | Signature update check interval in hours | `4` |

Default monitored paths: `/home`, `/tmp`.

---

## Quarantine Management

### `sd quarantine <SUBCOMMAND>`

Manage the encrypted quarantine vault (AES-256-GCM).

```bash
sd quarantine list
sd quarantine restore <ID>
sd quarantine restore <ID> --to /safe/path
sd quarantine delete <ID>
sd quarantine delete-all --yes
sd quarantine stats
```

| Subcommand | Description |
|------------|-------------|
| `list` | List all quarantined files |
| `restore <ID>` | Restore a quarantined file (`--to <PATH>` for alternate location) |
| `delete <ID>` | Permanently delete a quarantined file |
| `delete-all` | Delete all quarantined files (`--yes` to skip confirmation) |
| `stats` | Show quarantine statistics |

---

## Signature Database

### `sd update`

Check for and apply signature database updates.

```bash
sd update
sd update --check-only
sd update --force
sd update --server-url https://custom-server.example.com
```

| Option | Description |
|--------|-------------|
| `--check-only` | Only check if an update is available |
| `--force` | Force re-download even if already up to date |
| `--server-url <URL>` | Override the update server URL |

### `sd import <PATH>`

Import hash signatures from a blocklist file.

```bash
sd import /path/to/blocklist.txt
```

File format: one entry per line as `hex_hash malware_name`. Lines starting with `#` are comments.

```
# Example blocklist
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Test
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa Ransom.WannaCry
```

### `sd import-clamav <PATHS...>`

Import ClamAV signature database files.

```bash
sd import-clamav main.cvd daily.cvd
sd import-clamav custom.hdb custom.hsb
```

Supported formats: `.cvd`, `.cld`, `.hdb`, `.hsb`.

### `sd info`

Display engine version, signature database status, and system information.

```bash
sd info
```

Shows: version, YARA rule count, hash signature count, quarantine stats, platform info.

---

## Configuration

### `sd config <SUBCOMMAND>`

Manage engine configuration.

```bash
sd config show
sd config set scan.max_file_size 104857600
sd config set scan.follow_symlinks true
sd config reset
```

| Subcommand | Description |
|------------|-------------|
| `show` | Display current configuration |
| `set <KEY> <VALUE>` | Set a configuration key (dot-separated path) |
| `reset` | Reset to default configuration |

Values support JSON types: boolean (`true`/`false`), numbers, `null`, arrays, objects.

---

## Remediation Policy

### `sd policy <ACTION> [KEY] [VALUE]`

Manage threat remediation policies.

```bash
sd policy show
sd policy set on_malicious "kill,quarantine,clean"
sd policy set on_suspicious "report,quarantine"
sd policy set kill_processes true
sd policy reset
```

| Action | Description |
|--------|-------------|
| `show` | Display current policy |
| `set <KEY> <VALUE>` | Set a policy field |
| `reset` | Reset to default policy |

**Policy keys:**

| Key | Description | Values |
|-----|-------------|--------|
| `on_malicious` | Actions for malicious threats | Comma-separated: `report`, `quarantine`, `block`, `kill`, `clean`, `delete`, `isolate`, `blocklist` |
| `on_suspicious` | Actions for suspicious threats | Same as above |
| `kill_processes` | Kill associated processes | `true` / `false` |
| `clean_persistence` | Clean persistence mechanisms | `true` / `false` |
| `network_isolation` | Isolate network connections | `true` / `false` |
| `audit_logging` | Log all actions to audit trail | `true` / `false` |

---

## Scheduling

### `sd schedule <SUBCOMMAND>`

Manage scheduled scans. Uses platform-native schedulers: systemd timers (Linux), cron (Linux/macOS), launchd (macOS), Task Scheduler (Windows).

```bash
sd schedule add /home --frequency daily
sd schedule add /tmp --frequency hourly
sd schedule status
sd schedule remove
```

| Subcommand | Description |
|------------|-------------|
| `add <PATH>` | Register a recurring scheduled scan |
| `remove` | Remove the scheduled scan |
| `status` | Show current schedule status |

**Frequencies:** `hourly`, `4h`, `12h`, `daily`, `weekly` (default: `weekly`).

---

## Alerting

### `sd webhook <SUBCOMMAND>`

Manage webhook alert endpoints.

```bash
sd webhook list
sd webhook add my-slack https://hooks.slack.com/services/... --format slack
sd webhook add my-discord https://discord.com/api/webhooks/... --format discord
sd webhook add custom https://example.com/alert --format generic
sd webhook remove my-slack
sd webhook test
```

| Subcommand | Description |
|------------|-------------|
| `list` | List configured webhooks |
| `add <NAME> <URL>` | Add a webhook (`--format`: `slack`, `discord`, `generic`) |
| `remove <NAME>` | Remove a webhook by name |
| `test` | Send a test alert to all webhooks |

### `sd email-alert <SUBCOMMAND>`

Manage email alert configuration.

```bash
sd email-alert configure
sd email-alert test
sd email-alert send "Trojan.Generic" "high" "/tmp/malware.exe"
```

| Subcommand | Description |
|------------|-------------|
| `configure` | Create or show SMTP email configuration |
| `test` | Send a test alert email |
| `send <NAME> <LEVEL> <PATH>` | Send a custom alert email |

---

## DNS & Network Filtering

### `sd adblock <SUBCOMMAND>`

Manage adblock and malware domain filtering.

```bash
sd adblock enable
sd adblock disable
sd adblock sync
sd adblock stats
sd adblock check https://suspicious-site.example.com
sd adblock log --count 100
sd adblock add custom-list https://example.com/blocklist.txt --category malware
sd adblock remove custom-list
```

| Subcommand | Description |
|------------|-------------|
| `enable` | Download blocklists and install DNS blocking (`/etc/hosts`) |
| `disable` | Remove DNS blocking entries |
| `sync` | Force re-download all filter lists |
| `stats` | Show filtering statistics |
| `check <URL>` | Check if a URL/domain is blocked |
| `log` | Show recent blocked entries (`-c, --count <NUM>`, default: 50) |
| `add <NAME> <URL>` | Add a custom filter list (`--category`: `ads`, `tracking`, `malware`, `social`) |
| `remove <NAME>` | Remove a filter list |

### `sd dns-proxy`

Start a local DNS proxy with adblock, IOC, and custom blocklist filtering.

```bash
sudo sd dns-proxy
sudo sd dns-proxy --listen 127.0.0.1:5353 --upstream 1.1.1.1:53
```

| Option | Description | Default |
|--------|-------------|---------|
| `--listen <ADDR>` | Listen address | `127.0.0.1:53` |
| `--upstream <ADDR>` | Upstream DNS server | `8.8.8.8:53` |
| `--log-path <PATH>` | JSONL query log path | `/tmp/prx-sd-dns.log` |

---

## Reporting

### `sd report <OUTPUT>`

Generate a self-contained HTML report from JSON scan results.

```bash
sd scan /path --json | sd report report.html
sd report report.html --input results.json
```

| Option | Description | Default |
|--------|-------------|---------|
| `--input <FILE>` | Input JSON file (`-` for stdin) | `-` (stdin) |

### `sd status`

Show daemon status including PID, uptime, signature version, and threats blocked.

```bash
sd status
```

---

## Integration

### `sd install-integration`

Install file manager right-click scan integration.

```bash
sd install-integration
```

Supported file managers:
- **Linux:** Nautilus (GNOME Files), Dolphin (KDE), Nemo (Cinnamon)
- **macOS:** Finder Quick Action

### `sd self-update`

Check for and apply binary updates from GitHub Releases.

```bash
sd self-update
sd self-update --check-only
```

| Option | Description |
|--------|-------------|
| `--check-only` | Only check if an update is available |

---

## Examples

### First-time Setup

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash

# Import additional signatures
sd import my-custom-hashes.txt
sd import-clamav main.cvd daily.cvd

# Verify setup
sd info
```

### Daily Protection

```bash
# Start daemon (monitors /home and /tmp, updates every 4h)
sd daemon

# Or manual scan
sd scan /home --recursive --auto-quarantine

# Check status
sd status
```

### Incident Response

```bash
# Scan with full remediation
sudo sd scan /tmp --auto-quarantine --remediate

# Check memory for in-memory threats
sudo sd scan-memory

# Check for rootkits
sudo sd check-rootkit

# Review quarantine
sd quarantine list
sd quarantine restore <ID> --to /safe/location
```

### Automation

```bash
# Schedule weekly scan
sd schedule add /home --frequency weekly

# Set up alerts
sd webhook add slack https://hooks.slack.com/services/T.../B.../xxx --format slack
sd email-alert configure

# JSON output for scripts
sd scan /path --json | jq '.threats[] | .name'
```
