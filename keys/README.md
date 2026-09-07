# Update-signing keys

`dev-release.ed25519.key` is a **DEVELOPMENT** Ed25519 private key, committed on purpose so the
update pipeline is testable end to end: `scripts/mk-hosupd.sh` signs with it and the kernel
verifies against its pinned public half in `core/imgupdate.d`.

**It is not a release key and must never be used as one.** A key in a public repository is a key
everybody has. SYSTEM_UPDATE D3 calls for a pinned root held **offline**; shipping releases means
generating that key off this machine, pinning its public half, and keeping the private half out of
the tree entirely.

This is still strictly better than what it replaces. The previous scheme signed updates with an
HMAC whose key the kernel also holds, so verification proved only that *someone with the image*
made the bundle — the verifier could forge anything it could check. With Ed25519 the kernel holds
only a public key, so swapping in a real offline key is a one-line change and needs no format
change: the bundle already carries `keyId`.
