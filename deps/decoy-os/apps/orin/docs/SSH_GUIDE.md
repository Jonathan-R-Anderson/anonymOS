# SSH Remote Scanning Guide

Orin's agentless scanner (`orin scan`) connects to remote Linux hosts over SSH and executes a self-contained collection script — Python by default, with a pure-Bash fallback. This guide covers connection requirements, privilege levels, host key verification, rate limiting, and best practices.

---

## Connectivity Requirements

- An OpenSSH-compatible daemon on the target host (default port 22).
- SSH key authentication is recommended. Password authentication is not handled directly — use `sshpass` or configure key-based auth beforehand.

---

## Privilege Levels

| Data Category | Non-Root | Root |
|---|---|---|
| Process list | Own processes only | Full list with cmdline and exe paths |
| Listening ports / connections | Yes | Yes, with accurate socket-to-PID mapping |
| Promiscuous interfaces | Yes | Yes |
| User accounts (`/etc/passwd`) | Yes | Yes |
| SSH authorized keys | Own `~/.ssh` only | All users' keys |
| Crontabs | Own crontab + `/etc/crontab` | All user crontabs |
| SUID/SGID binaries | Yes (via `find`) | Yes |
| File integrity hashes | Readable files only | All configured paths |
| Auth logs | Often restricted | Full access |
| Kernel modules / `kallsyms` | Often restricted | Full access |

For complete telemetry — including kernel symbol rootkit analysis, full auth log review, and accurate socket-to-process mapping — connect as root or via passwordless sudo.

```bash
ssh -i /path/to/key root@host
```

If direct root login is disabled, grant the scanning account passwordless sudo on the target:

```
# /etc/sudoers
orin_scanner ALL=(ALL) NOPASSWD: /bin/bash
```

---

## Agent Requirements

**Python agent (primary)** — requires only Python 3.6+ standard library:

```bash
ssh user@host "python3 -c 'import os,sys,json,stat,errno,struct,socket,re,hashlib,pwd,grp,platform; print(\"OK\")'"
```

**Bash agent (fallback)** — used when Python is unavailable. Requires Bash 4.0+ and common coreutils (`hostname`, `uname`, `cat`, `readlink`, `stat`, `find`, `awk`, `grep`, `tail`, a SHA-256 or MD5 tool, `ps`, `ss`/`netstat`, `ip`, `lsmod`). Suitable for routers, Alpine/distroless containers, and embedded systems.

### Platform Compatibility

| System | Python Agent | Bash Agent |
|---|---|---|
| Ubuntu / Debian / RHEL / Fedora / Alpine | ✅ | ✅ |
| BusyBox / OpenWrt / embedded | ❌ | ✅ |
| Docker containers | ✅ | ✅ (depends on base image) |
| macOS / Windows | ❌ | ❌ — not supported |

**Known limitations:** SELinux/AppArmor may restrict `/proc` access even for root. Container namespaces limit host process visibility. Kernels older than 3.x may have incomplete `/proc` interfaces.

---

## Host Key Verification

Configure host key behaviour in the `ssh` section of `orin_config.json`:

```json
{
  "ssh": {
    "strict_host_key_checking": "ask",
    "known_hosts_file": null,
    "connection_timeout": 30,
    "max_retries": 3
  }
}
```

| Option | Default | Description |
|---|---|---|
| `strict_host_key_checking` | `"ask"` | `"yes"` — strict; requires a pre-populated `known_hosts`. `"accept-new"` — auto-trust new hosts. `"ask"` — interactive. `"no"` — no verification (isolated/CI use only). |
| `known_hosts_file` | `null` | Custom `known_hosts` path. `null` uses `~/.ssh/known_hosts`. |
| `connection_timeout` | `30` | Seconds before a connection attempt times out. |
| `max_retries` | `3` | Maps to SSH `ConnectionAttempts`. |

**Production:** Use `"yes"` with a centrally managed `known_hosts_file`, populated via:

```bash
ssh-keyscan -H target >> /etc/orin/known_hosts
```

**Development:** `"accept-new"` trusts new hosts on first contact and remembers them.

**`"no"`** disables host key verification entirely. This is vulnerable to MITM attacks and should only be used on isolated, trusted networks or ephemeral CI environments — never in production.

---

## Rate Limiting

To avoid overwhelming targets, triggering IDS alerts, or generating a DoS-like connection pattern, configure rate limiting under `ssh.rate_limit`:

```json
{
  "ssh": {
    "rate_limit": {
      "enabled": true,
      "max_concurrent_connections": 5,
      "delay_between_scans": 1.0,
      "max_scans_per_minute": 10,
      "backoff_factor": 2.0,
      "max_backoff_delay": 60.0
    }
  }
}
```

| Setting | Description |
|---|---|
| `max_concurrent_connections` | Semaphore-bounded concurrent SSH connections. |
| `delay_between_scans` | Minimum seconds between any two scan initiations. |
| `max_scans_per_minute` | Per-host scan rate cap. |
| `backoff_factor` | Multiplier for exponential backoff on connection failures. |
| `max_backoff_delay` | Maximum backoff delay in seconds. Resets to zero on success. |

### Example Profiles

**Production (conservative):**

```json
{
  "max_concurrent_connections": 3,
  "delay_between_scans": 2.0,
  "max_scans_per_minute": 5,
  "backoff_factor": 2.0,
  "max_backoff_delay": 120.0
}
```

**Lab (aggressive):**

```json
{
  "max_concurrent_connections": 10,
  "delay_between_scans": 0.1,
  "max_scans_per_minute": 60,
  "backoff_factor": 1.5,
  "max_backoff_delay": 10.0
}
```

**Disabled (trusted internal network only):**

```json
{ "enabled": false }
```

All shared state in the rate limiter is thread-safe and supports independent per-host tracking.

---

## Best Practices

- Use a dedicated scanning account with the minimum privileges required for the desired telemetry coverage.
- Constrain SSH key usage with authorized_keys options: `command="...",no-port-forwarding,no-X11-forwarding,no-agent-forwarding`.
- Enable SSH access logging on all target hosts.
- Rotate scanning keys on a defined schedule.
- Initiate scans from a dedicated management network segment isolated from production traffic.

---

## Troubleshooting

| Symptom | Likely Cause / Fix |
|---|---|
| `Permission denied` | Check key permissions (`chmod 600`), target shell access, and sudo configuration. |
| `python3: command not found` | Scanner falls back to the Bash agent automatically. If both fail, install Python or ensure Bash 4+. |
| Incomplete telemetry | Usually a privilege issue. Connect as root or check SELinux/AppArmor restrictions. |
| JSON parse errors | Check stderr on the target for syntax errors. Verify Bash version supports required features. |

**Debug a connection directly:**

```bash
ssh -vvv -i /path/to/key user@host
ssh user@host "cat /proc/net/tcp | head -5"
```