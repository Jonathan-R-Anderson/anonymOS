# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in PRX-SD, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@openprx.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 1 week
- **Fix and disclosure:** Coordinated with reporter

## Scope

The following are in scope for security reports:

- Vulnerabilities in the `sd` CLI binary
- Vulnerabilities in the scan engine (false negatives, bypasses)
- Quarantine vault encryption weaknesses
- Signature update verification bypasses
- Privilege escalation in daemon mode
- Code injection via crafted files (e.g., malicious YARA rules, signature files)

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous release | Security fixes only |
| Older versions | No |

## Security Design

PRX-SD is designed with security in mind:

- **Quarantine:** AES-256-GCM authenticated encryption
- **Updates:** Ed25519 signature verification for all signature packages
- **Sandboxing:** Process isolation via ptrace, seccomp, and namespaces
- **No unsafe without justification:** All `unsafe` blocks require `// SAFETY:` documentation
- **No `unwrap` in production:** All error paths are explicitly handled
- **Parameterized queries:** No SQL injection vectors
