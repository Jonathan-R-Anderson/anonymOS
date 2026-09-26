# boot/gatekeeper — stage-1 IP gate for anonymOS

A minimal-Linux UKI that boots **first** (the default EFI entry), **before** the VeraCrypt
disk-password loader. It uses Linux for what the EFI loader cannot do — WiFi, Tor, TLS, Argon2 —
to check the machine's network location against an on-chain whitelist, then chains to the loader
for the hidden-vs-decoy password challenge. Off-whitelist, the hidden OS is made unreachable.

This replaces the earlier "loader StartImages the gatekeeper" design, which was blocked: a Linux
gatekeeper cannot launch the real OS (a Limine/D-kernel that needs UEFI boot services), and the EFI
loader cannot do TLS/Tor/Argon2 to run the check itself. Booting the gate **first** and handing back
to the loader via a one-shot reboot resolves both.

## Flow
```
firmware → [STAGE 1: gatekeeper UKI]  (default boot entry)
   bring up network (Ethernet, or WiFi via the connection panel)
   read-only on-chain check with the STORED attestation password (NO wallet):
      Argon2id(pw,salt) → id, kEnc
      eth_call get(id) over Tor → decode bytes → AES-256-GCM decrypt → {root, whitelist, blacklist}
      fetch public IP (direct, NOT via Tor — we need the real egress IP) → match whitelist
   set one-shot EFI var  AnosHiddenUnlock = ALLOW | DENY
   set BootNext = <VeraCrypt loader>  → reboot
                                 │
firmware → [STAGE 2: VeraCrypt loader]  (existing §E5 loader, one small change)
   read + DELETE AnosHiddenUnlock (one-shot)
   password challenge:
      ALLOW      → hidden password opens the hidden OS; decoy password opens the decoy (as today)
      DENY/absent→ DECOY-ONLY: a hidden-password match is treated as REJECT (≡ wrong password)
   boot the chosen OS with full UEFI boot services (works for the Limine/D-kernel real OS)
```
Two boots per start (gate, then loader). The gate stage is a visible artifact (accepted, below).

## Credentials — the gatekeeper holds no wallet
Reading the record is a **permissionless `eth_call`**: no wallet, no gas, no signing. The gatekeeper
stores only the **attestation password** (read/decrypt). The **owner/deploy wallet** (the only key
that can *update* the record or was used to deploy the vault) is separate and never on this stage —
so compromising the gatekeeper yields read access at most, never contract control. (This is the
separation you asked for; because reads need no wallet, it's automatic.)

## Stage-2 loader gate (the one loader change needed)
`deps/veracrypt/efi/efi_main.c` / `efi_vc.c` must, at the `PREBOOT_HIDDEN` decision point
(around the hidden branch), consult the one-shot EFI variable and gate the hidden match:
```
GUID  AnosHiddenUnlock = 8f1e9a2c-6b7d-4e3f-9a0b-1c2d3e4f5a6b
read RuntimeServices->GetVariable("AnosHiddenUnlock", &GUID, ...)
delete it (SetVariable with size 0)   // one-shot
if value != "ALLOW":  treat a PREBOOT_HIDDEN result as PREBOOT_REJECT   // decoy-only, fail-closed
```
**This is now drafted** behind the `PREBOOT_IPGATE` compile flag in `deps/veracrypt/efi/efi_main.c`
(the `anos_hidden_unlocked()` helper + the gate in the `PREBOOT_HIDDEN` branch), with a typed
`EFI_RUNTIME_SERVICES` (GetVariable #7, SetVariable #9). Build the gated loader with
`PREBOOT_IPGATE=1 make -C deps/veracrypt efi` → `build/preboot-ipgate.efi`. The shipped `preboot.efi`
is unchanged until this is boot-tested. It compiles clean (default, `-DPREBOOT_IPGATE`, and both) —
but it is UNTESTED on hardware; a bug here bricks the pre-boot loader, so verify in a throwaway VM.

## Security properties + honest limits
- **IP gate is a heuristic ON TOP of the disk password, not access control.** The hidden password is
  still required in stage 2. `AnosHiddenUnlock` is writable by anything with EFI-var access, so
  forging `ALLOW` only re-enables the *prompt* — it never reveals the hidden OS without the password.
  Its value is off-whitelist coercion defense: forced to type the password in the wrong location, it
  still won't open the hidden OS unless someone also knows to forge the var.
- **Fail-closed** = hidden unreachable, decoy still boots. No network / no Tor / DENY / any error all
  collapse to decoy-only, which reads exactly like a wrong hidden password.
- **Public IP is fetched directly, not over Tor** (Tor would give an exit IP, useless for an egress
  whitelist). The eth_call to the vault IS over Tor, so the RPC doesn't learn your IP↔vault link.
- **Artifacts (unsolved):** the stage-1 gate itself is discoverable (a Linux kernel boots first), and
  the two-boot pattern is observable. Uniform across ALLOW/DENY at the gate, but its existence isn't
  hidden. The stored attestation password on the ESP is extractable (→ read access only); prompting
  for it in the panel instead trades convenience for not storing it.

## Connection panel (WiFi / Ethernet)
`net_up()` brings up Ethernet (DHCP) first. For WiFi it calls an optional `/bin/gk-wifi-panel` (the
graphical SSID picker / key entry — to be built) which writes a `wpa_supplicant.conf` to
`/tmp/wpa.conf`; absent that, it falls back to the ESP-sealed `wifi.enc` (decrypted with the
attestation password) so a known network connects unattended. No WiFi key is ever stored in clear.

## Crypto contract (identical in `scripts/attest-seal.py`, `scripts/attest-unseal.py`, mobile app)
Argon2id `t=3, m=64MiB, p=1, len=32, type=id`; `id=SHA256(km‖"anos-id\0")`, `kEnc=SHA256(km‖"anos-enc\0")`;
record = `0x01 ‖ nonce[12] ‖ AES-256-GCM(kEnc, compact-JSON{v,root,whitelist,blacklist,ts})`. The
per-install salt lives on the ESP (`attest.salt`). Read via `eth_call get(bytes32)`, selector `0x8eaa6ac0`.

## ⚠ Status: UNTESTED DRAFT — boot-critical
`init` is a reviewable stage-1 skeleton. Before it can run it needs, and none is verified on hardware:
1. **The stage-2 loader gate** above (the AnosHiddenUnlock check) — the linchpin.
2. **Build/boot-entry wiring**: the gate installed as the default EFI entry, the loader as a named
   entry (`gkloader=` Boot#### for BootNext), `efibootmgr` + `efivarfs` in the initramfs (build-uki.sh).
3. **`/bin/attest-unseal`** baked in (compiled counterpart of `scripts/attest-unseal.py`).
4. **`/bin/gk-wifi-panel`** (the graphical connection panel) — optional; sealed `wifi.enc` works without it.
5. Provisioning on the ESP: `attest.salt`, the stored `attest.pass`, and (optionally) `wifi.enc`.
