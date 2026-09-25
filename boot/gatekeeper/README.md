# boot/gatekeeper — IP-gated boot for anonymOS

A minimal-Linux UKI the §E5 pre-boot loader StartImages **first**, before it decrypts either OS. It
enforces the encrypted IP whitelist/blacklist from `contracts/EncryptedAttestationVault.sol` so the
real OS is only decrypted from an allowed network; anything else (or any failure) boots the decoy.

Chosen over a UEFI-firmware check because Tor + an L2 RPC + Argon2/AEAD need a real OS — they can't
run in the pre-boot firmware environment.

## Flow (`init`)
```
password → Argon2id(64MiB,t3) → {id,key}   (salt read locally from the ESP, no network yet)
net up (DHCP) → Tor up → eth_call get(id) over Tor → AES-256-GCM decrypt the record
learn public IP over Tor → classify:
    blacklist match      → DECOY   (armed: a wipe could fire here)
    not in whitelist / empty whitelist → DECOY   (fail-closed)
    whitelist match      → REAL OS
any error (no net / Tor down / RPC fail / decrypt fail / no record) → DECOY
```

## Crypto contract (identical in `scripts/attest-seal.py` and `mobile/attestation-app/`)
Argon2id `t=3, m=64MiB, p=1, len=32, type=id`; `id=SHA256(km‖"anos-id\0")`, `key=SHA256(km‖"anos-enc\0")`;
seal = `0x01 ‖ nonce[12] ‖ AES-256-GCM(key, compact-JSON)`. The **salt is per-install and lives on the
ESP** (needed to derive id/key before any fetch). Record payload: `{v,root,whitelist,blacklist,ts}`.

## ⚠ Status: UNTESTED DRAFT — this is boot-critical
`init` is a reviewable skeleton, not shippable. It must be built into a UKI and iterated against a
**real boot** (that loop is on your hardware). Known work before it can run:

1. **Control transfer** — `boot_real()`/`boot_decoy()` are placeholder shells that must be replaced
   with your loader's actual real/decoy hand-off (kexec the target UKI, or signal the §E5 loader).
   They're also defined below their first use — move them above, or the shell won't find them.
2. **Loader handoff contract** — confirm how the loader passes `gkpass=` (typed password/seed),
   `gkvault=`, `gkrpc=`, `gkipsvc=`, and the real/decoy geometry+keys. Names here mirror
   `init-crypt`'s `decoy*=` params; verify against the real §E5 loader.
3. **`/bin/attest-unseal`** — the compiled counterpart of `scripts/attest-seal.py` (derive-id,
   decode eth_call ABI `bytes`, AES-GCM-decrypt, and `--match <ip>` → ALLOW/DENY/BLACKLIST). Bake it
   into this initramfs. Verify the `get(bytes32)` selector (`0x8eaa6ac0`) against the compiled ABI.
4. **Initramfs contents/build** — a `make` target (mirror decoy-os's UKI build): busybox, the net
   modules, `udhcpc`, a **tor** binary + minimal `torrc` (SocksPort 9050), `wget` with SOCKS,
   `attest-unseal`, kexec-tools, and mounting the ESP to read `attest.salt`.

## Hard operational costs (already accepted in design)
- **No network at boot ⇒ only the decoy boots.** Fail-closed is the guarantee's price.
- Every boot waits on a Tor circuit + an L2 read — tens of seconds of latency, and a boot-time
  (oniony) network event.
- IP is a weak signal (VPN/dynamic IP/adversary-at-your-location). It's a deniability heuristic on
  top of the password, not access control.
