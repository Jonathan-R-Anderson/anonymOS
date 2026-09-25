# Agent Script Signing

Orin signs the remote collection agent with HMAC-SHA256 before transmitting it over SSH. The target host only ever executes code that has passed a local integrity verification step, protecting against tampering, MITM substitution, and unauthorized agent deployment.

---

## Configuration

**Recommended — environment variable:**

```bash
export ORIN_AGENT_SIGNING_KEY="your-secure-passphrase-here"
```

Requirements: minimum 12 characters. Store in a secrets manager and never commit to version control.

**Alternative — explicit parameter (takes precedence over the environment variable):**

```python
from orin.core.scanner import run_remote_scan

result = run_remote_scan(
    host="target.example.com",
    user="forensic-user",
    signing_secret="your-secure-passphrase-here",
    verify_signature=True,
)
```

**Disable for testing only:**

```python
result = run_remote_scan(host="test-host", user="test", verify_signature=False)
```

---

## How It Works

1. Before each scan, the scanner loads `remote_agent.py` and, if signing is enabled, constructs a signature bundle and verifies it locally.
2. The bundle is a JSON structure containing the agent content, its SHA-256 hash, the HMAC-SHA256 signature, a timestamp, and scan metadata:

```json
{
  "version": "1.0.0",
  "signed_at": "2026-01-15T10:30:00Z",
  "agent_name": "remote_agent.py",
  "agent_hash": "<sha256-hash>",
  "algorithm": "sha256",
  "metadata": {
    "source_path": "...",
    "scan_target": "...",
    "initiated_by": "..."
  },
  "content": "<agent script content>",
  "signature": "<hmac-sha256-signature>"
}
```

3. Verification recomputes the content hash and HMAC signature using constant-time comparison. Any mismatch aborts the scan immediately with a `CRITICAL` log entry.
4. Only verified, signed content is piped to the remote Python interpreter via SSH.

---

## What It Protects Against

| Threat | How Signing Helps |
|---|---|
| **Code tampering** | Any modification to the agent script changes the SHA-256 hash and invalidates the signature. |
| **MITM substitution** | The signature is verified before transmission, not after. A modified agent is rejected before it can be sent. |
| **Unauthorized agents** | Only agents signed with the correct key are deployed. |
| **Replay attacks** | The bundle includes a timestamp and target metadata, limiting the usefulness of captured bundles. |

---

## Limitations

- Signing provides **integrity**, not **confidentiality**. The agent content is transmitted in plaintext within the SSH session; SSH itself provides transport encryption.
- A **compromised signing key** allows signing malicious agents. Rotate the key immediately if compromise is suspected.
- Verification occurs **locally** (on the machine running `orin scan`) before transmission, not independently on the remote host. For stronger guarantees, combine with GPG-signed release manifests, HSM or secrets manager key storage, and SSH/TLS transport encryption.

---

## Error Reference

| Message | Cause | Fix |
|---|---|---|
| `Signing passphrase is too short` | Key is fewer than 12 characters | Use a longer passphrase |
| `Agent signature verification failed` | Internal verification error | Check key integrity |
| `CRITICAL: Agent content hash mismatch` | File corruption or tampering detected | Restore the original agent from a trusted source |
| `CRITICAL: Signature verification failed` | Wrong key or content has been tampered | Verify the key matches what was used to sign |
| `WARNING: Agent signing disabled` | No key provided | Set `ORIN_AGENT_SIGNING_KEY` |

---

## API Reference

### `run_remote_scan()` Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `host` | `str` | required | Target hostname or IP address |
| `user` | `str` | required | SSH username |
| `key_path` | `str` | `None` | SSH private key path |
| `port` | `int` | `22` | SSH port |
| `db_path` | `Path` | `orin_vault.db` | SQLite database path |
| `config` | `dict` | `None` | Configuration overrides |
| `signing_secret` | `str` | `None` | HMAC signing key (takes precedence over environment variable) |
| `verify_signature` | `bool` | `True` | Enable signature verification before transmission |

### Related Functions and Classes

| Name | Description |
|---|---|
| `sign_agent_script()` | Sign an agent script file and return a bundle |
| `verify_agent_signature()` | Verify a signature bundle against a key |
| `AgentSigner` | High-level signing interface |
| `save_signed_bundle()` / `load_signed_bundle()` | Persist and load bundles as JSON |
| `extract_verified_agent()` | Verify and extract agent content from a bundle |

---

## Testing

```python
from pathlib import Path
from orin.core.agent_signing import AgentSigner

signer = AgentSigner(secret_key="test-key-12345")
bundle = signer.sign(Path("src/orin/collectors/remote_agent.py"))

# Verify a valid bundle
is_valid, message = signer.verify(bundle)
assert is_valid, f"Verification failed: {message}"

# Verify tamper detection
tampered = bundle.copy()
tampered["content"] += "\n# INJECTED CONTENT"
is_valid, _ = signer.verify(tampered)
assert not is_valid, "Tamper detection failed — this should never succeed"
```