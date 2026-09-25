# Security Policy

## Supported Versions

Orin follows a **rolling release** model. Only the latest version on the `main` branch receives security fixes and patches. Older releases are not actively maintained.

| Version | Supported |
|---|---|
| Latest (`main`) | ✅ |
| Older releases | ❌ |

---

## Scope

This policy covers vulnerabilities in the **Orin engine itself**: its collectors, analysis rules, cryptographic signing logic, database schema, and CLI. It does not cover issues in the underlying operating system, Python runtime, or third-party tools installed on the host.

Because Orin is a **fully offline** forensic tool, there are no cloud endpoints, public APIs, or network services to secure. All data remains on the local machine.

---

## Reporting a Vulnerability

If you discover a security vulnerability in Orin, **do not open a public GitHub issue**. Report it privately using GitHub's built-in security advisory workflow.

**Steps:**

1. Navigate to the [Security tab](../../security) of this repository.
2. Click **"Report a vulnerability"**.
3. Provide: the affected component, steps to reproduce, and potential impact.

You can also reach the maintainer directly at the email address listed on the GitHub profile.

**Response timelines:**

| Step | Timeline |
|---|---|
| Acknowledgement | Within 48 hours |
| Initial assessment and severity triage | Within 5 business days |
| Patch or mitigation | Within 14 days for critical issues |
| Public disclosure | After a fix is merged and released (coordinated with reporter) |

Orin follows **responsible disclosure**: the public release of any advisory will be coordinated with the reporter before publication.

---

## Security Design

Orin is built on the following security principles:

**No network access at runtime.** The engine makes no outbound connections during collection or analysis.

**No remote code execution surface.** All inputs are local filesystem reads. There are no sockets, HTTP handlers, or RPC interfaces exposed.

**Tamper-evident exports.** All snapshot exports are signed with HMAC-SHA256. Any modification to an export file is immediately detected by `orin verify`.

**Minimal privilege surface.** Only specific collectors (e.g. `/var/log/auth.log`, `/var/spool/cron/crontabs/`) require root. The `orin status`, `orin diff`, and `orin report` subcommands operate correctly as a non-root user.

**Zero third-party runtime dependencies.** The entire runtime uses only Python standard library modules, eliminating supply-chain risk from external packages.

---

## Out of Scope

The following are **not** considered vulnerabilities under this policy:

- False positives or false negatives in threat detection rules. These are engine quality issues — file a regular GitHub issue.
- Issues that require physical access to the monitored machine.
- Vulnerabilities in the Python runtime or the Linux kernel itself.