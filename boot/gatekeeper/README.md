# boot/gatekeeper — IP-gated boot for anonymOS

A minimal-Linux UKI the §E5 pre-boot loader StartImages **after it has routed a password to DECOY or
HIDDEN** (`preboot_auth.c` opens the two VeraCrypt headers; the loader holds the matching volume
key). The gatekeeper IP-gates the **hidden** OS and — crucially — runs the **identical** dance on the
**decoy** route, so the two boots are indistinguishable to anyone watching.

Chosen over a UEFI-firmware check because Tor + an L2 RPC + Argon2/AEAD need a real OS.

## Flow (`init`)
```
loader routes the password → gkroute=decoy|hidden (+ the matched volume key/geometry)
ALWAYS (both routes): salt from ESP → Argon2id{id,key} → net (wired→WiFi) → Tor
                      → eth_call get(id) → decrypt record → public IP → classify
decide (no early exits):
    gkroute=decoy                         → DECOY   (verdict ignored; dance was for parity)
    gkroute=hidden AND whitelist match    → REAL OS
    gkroute=hidden AND (blacklist/deny/any error) → REJECT
hold to a fixed deadline (constant time)  → then hand off
```

**Fail-closed = REJECT, not "boot the decoy."** The gatekeeper on the hidden route holds only the
*hidden* key; it cannot decrypt the decoy (separate header/key). So a failed check returns the
loader's **reject** path — indistinguishable from a wrong password (`preboot_auth.c` already makes
wrong ≡ "no hidden OS here"). It never summons the decoy.

## Indistinguishability (enforced in `init`)
The loader already keeps decoy/hidden/reject identical on screen, serial, and *timing*. The
gatekeeper must not break that:
- **Constant time** — every outcome pads to `GK_DEADLINE` (must exceed worst-case Tor+fetch) before
  handing off, so decoy-boot, hidden-boot, and hidden→reject all take the same wall-clock.
- **Same traffic** — the DECOY route runs the same Tor + vault fetch and discards it, so the network
  signature is identical whichever password was typed.
- **Silent** — all logging is redirected to `/run/gk.log` (tmpfs); nothing route/outcome-specific
  ever reaches console or serial.

## Unsolved (needs loader work — flagging honestly)
- **A WRONG password must also produce this exact dance.** Today a wrong password rejects in the
  loader with no network activity; the hidden password now produces a ~`GK_DEADLINE` delay + Tor
  traffic. A coercer who tries a known-wrong password and then the extracted one sees the difference
  and learns the extracted password is *conditional*. Truly closing this means routing **every**
  attempt (including wrong ones) through an identical traffic-producing stage — heavy, and it's the
  deepest part. Until then, the timing is matched but the *traffic-only-on-real-passwords* leak
  remains.
- **The gatekeeper stage itself is a forensic artifact** — a Linux kernel boots before the "OS."
  Uniform across routes it isn't *password*-distinguishing, but its existence is discoverable.

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
4. **Initramfs contents/build** — a `make` target (mirror decoy-os's UKI build): busybox, `udhcpc`,
   a **tor** binary + minimal `torrc` (SocksPort 9050), `wget` with SOCKS, `attest-unseal`,
   kexec-tools, and mounting the ESP to read `attest.salt`. **For WiFi** also: `wpa_supplicant` +
   `wpa_cli`, the **wireless driver modules AND their firmware blobs** (hardware-specific, in
   `/lib/firmware` — this is the bulky, per-NIC part), and the wired NIC modules for Ethernet.

## Network (wired + WiFi), `net_up()`
Brings up whatever link exists, fail-closed to decoy if none:
- **Wired** (Ethernet / USB-NIC / virtio): `udhcpc` on each non-wireless iface. No credentials.
- **WiFi**: for each wireless iface, decrypt the ESP-sealed `wpa_supplicant.conf`
  (`/esp/anonymos/wifi.enc`) with the password key (`attest-unseal --decrypt-file`, verified
  round-trip), then `wpa_supplicant` → wait for `wpa_state=COMPLETED` → `udhcpc`. The plaintext
  config is written to tmpfs and shredded after; no WiFi key is ever stored in the clear on disk.

**Provision the sealed WiFi config** (same password + salt as the record):
```sh
python3 scripts/attest-seal.py --password "$PW" --salt "$SALT" --manifest-root "$ROOT" \
  --wifi-conf wpa_supplicant.conf --wifi-out wifi.enc
cp wifi.enc  <ESP>/anonymos/wifi.enc      # alongside attest.salt
```
If there's no WiFi config and no wired link, the gatekeeper boots the decoy (which is correct —
"can't reach the network to validate" must never reveal the real OS).

## Hard operational costs (already accepted in design)
- **No network at boot ⇒ only the decoy boots.** Fail-closed is the guarantee's price.
- Every boot waits on a Tor circuit + an L2 read — tens of seconds of latency, and a boot-time
  (oniony) network event.
- IP is a weak signal (VPN/dynamic IP/adversary-at-your-location). It's a deniability heuristic on
  top of the password, not access control.
