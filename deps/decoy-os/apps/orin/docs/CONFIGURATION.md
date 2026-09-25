# Configuration Reference

Orin searches for `orin_config.json` in `./` then `/etc/orin/`, falling back to built-in defaults if neither is found. The configuration loader deep-copies all defaults, so user-supplied values never mutate the built-in default object.

This page is the consolidated reference for every config key and environment variable. For narrative detail, follow the links to the relevant guide.

---

## Top-Level Keys

```json
{
  "expected_ports": [22, 80, 443, 631, 3306, 5432, 6379, 8080, 8443],
  "whitelisted_processes": ["code", "chrome", "language_server"],
  "critical_paths": ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/crontab"],
  "critical_dirs": ["/etc/cron.d", "/etc/systemd/system"],
  "ssh": { ... },
  "notifications": { ... }
}
```

| Key | Type | Description |
|---|---|---|
| `expected_ports` | `int[]` | Listening ports considered normal. Unexpected open ports raise alerts. |
| `whitelisted_processes` | `string[]` | Process names excluded from masquerade and anomaly checks. |
| `critical_paths` | `string[]` | Individual files monitored by the File Integrity Monitor. |
| `critical_dirs` | `string[]` | Directories monitored by the File Integrity Monitor. |
| `ssh` | `object` | Host key verification and rate limiting. See [SSH Configuration](#ssh-configuration). |
| `notifications` | `object` | Alert forwarding destinations and policy. See [Alert Forwarding](#alert-forwarding). |

YARA full-directory sweeps (disabled by default; restricted to `/tmp`, `/dev/shm`, `/var/tmp`) and alert suppression rules are also configured via `orin_config.json`. See [STATUS.md](STATUS.md) and [THREAT_DETECTION.md](THREAT_DETECTION.md).

---

## SSH Configuration

```json
{
  "ssh": {
    "strict_host_key_checking": "ask",
    "known_hosts_file": null,
    "connection_timeout": 30,
    "max_retries": 3,
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

For a full explanation of each field, security implications, and recommended profiles for production/lab/CI environments, see [SSH_GUIDE.md](SSH_GUIDE.md).

---

## Alert Forwarding

```json
{
  "notifications": {
    "enabled": true,
    "min_severity": "high",
    "syslog": {
      "enabled": true,
      "facility": "LOG_LOCAL0",
      "tag": "orin-alert"
    },
    "webhooks": [
      {
        "name": "ops-slack",
        "url": "http://192.168.1.10:8080/slack-webhook",
        "format": "slack",
        "min_severity": "critical",
        "timeout_seconds": 10,
        "enabled": true
      }
    ],
    "retry": { "max_attempts": 3, "backoff_seconds": 5 },
    "audit_log": "/var/log/orin/notification_audit.log"
  }
}
```

| Key | Type | Description |
|---|---|---|
| `enabled` | `bool` | Master switch for all alert forwarding. |
| `min_severity` | `string` | Global minimum severity: `low`, `medium`, `high`, or `critical`. |
| `syslog.enabled` | `bool` | Send alerts to local syslog. |
| `syslog.facility` | `string` | syslog facility, e.g. `LOG_LOCAL0`. |
| `syslog.tag` | `string` | syslog tag applied to all Orin entries. |
| `webhooks[]` | `object[]` | One entry per webhook destination. |
| `webhooks[].format` | `string` | Payload format: `slack`, `teams`, or `generic`. |
| `webhooks[].min_severity` | `string` | Per-webhook severity override (takes precedence over the global filter). |
| `webhooks[].headers` | `object` | Optional HTTP headers, e.g. authentication tokens. |
| `retry.max_attempts` | `int` | Maximum retry attempts on delivery failure. |
| `retry.backoff_seconds` | `int` | Base delay for exponential backoff retry. |
| `audit_log` | `string` | Path to the append-only JSONL delivery audit log. |

Alert forwarding dispatches automatically after every `orin analyze` run. All transports use the Python standard library (`urllib.request`) — no third-party dependencies. Core module: `orin.core.notifier`.

---

## Environment Variables

| Variable | Used By | Description |
|---|---|---|
| `ORIN_CONFIG_PATH` | `load_config_with_source()` | Overrides the default configuration file search paths with a specific file path. |
| `ORIN_VAULT_PASSPHRASE` | `orin init`, `orin collect`, etc. | Enables AES-256-GCM vault encryption. Without this variable, the vault operates unencrypted. |
| `ORIN_AGENT_SIGNING_KEY` | `orin scan`, `run_remote_scan()` | HMAC-SHA256 key for signing the remote SSH agent script. Minimum 12 characters. See [AGENT_SIGNING_GUIDE.md](AGENT_SIGNING_GUIDE.md). |
| `ORIN_TEST_FAST` | Test suite | Set to `1` to skip slow or integration tests (eBPF loads, heavy subprocess calls, large DB writes). Unset or `0` runs the full suite. See [TESTING.md](TESTING.md). |
| *(custom name)* | `--passphrase-env-var <NAME>` | Passes the vault passphrase via a custom environment variable name instead of `ORIN_VAULT_PASSPHRASE`. |

> **Note:** Some earlier documentation referenced `ORIN_DB_POOL_SIZE` and `ORIN_DB_TIMEOUT` as environment variables. These are not implemented as environment variables — pool size and timeout are constructor parameters of `OrinStorage` (`pool_size`, `pool_timeout`, with defaults of `10` and `30.0` respectively). See [DATABASE_INTERNALS.md](DATABASE_INTERNALS.md).

---

## Secure Credential Input (CLI Flags)

The following flags are available on `orin diff`, `orin export`, `orin verify`, `orin collect`, and similar passphrase-consuming commands.

| Flag | Behavior |
|---|---|
| `--passphrase-file <path>` | Reads passphrase from file. File must have mode `0600`. |
| `--passphrase-prompt` | Interactive masked prompt. Passphrase is never echoed. |
| `--passphrase-env-var <NAME>` | Reads passphrase from the named environment variable, then evicts it from `os.environ`. |
| `--secret-file` / `--secret-prompt` / `--secret-env-var` | Equivalent options for `diff`, `export`, and `verify` operations. |
| `--token-file <path>` | Persists the dashboard session token to a `0600` file rather than printing it to the terminal only. |

---

## Related Documentation

- [SSH_GUIDE.md](SSH_GUIDE.md) — SSH host key verification, rate limiting, and agent requirements
- [AGENT_SIGNING_GUIDE.md](AGENT_SIGNING_GUIDE.md) — Remote agent signing key management
- [DATABASE_INTERNALS.md](DATABASE_INTERNALS.md) — Connection pool tuning and SQLite performance
- [STATUS.md](STATUS.md) — Deployment assumptions and known limitations
- [SECURITY.md](SECURITY.md) — Vulnerability reporting and security design principles