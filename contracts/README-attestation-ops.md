# Attestation ops — deploy, record, manage

**Deploy is now one command** (`scripts/attest-deploy.sh`, over Tor) and the **installer records the
deployed address for you** (it lands in `install.json` as `attestContract`; `boot_integrity.d`
prefers it over the image-baked manifest and verifies against it on-chain). What is still manual:
sealing + submitting the *record* itself (step 2 — `put()`), and hosting the mobile app.

> ⚠ Boot enforcement is NOT live yet. `boot/gatekeeper/` is a skeleton (placeholder transfer logic),
> so a recorded whitelist gates nothing at boot until the gatekeeper is finished. You can still
> deploy/record/manage now to exercise the chain + app; enforcement comes with the gatekeeper.
>
> ℹ Why deploy runs here and not in the installer: signing a deploy tx needs secp256k1 + keccak +
> RLP + a live RPC. The kernel/installer only does read-only `eth_call` (no signing), so the deploy
> uses a real EVM toolchain (Foundry) in a normal userland — never hand-rolled crypto in the boot path.

Prereqs: an L2 wallet with a little test ETH (Base Sepolia faucet), Foundry (`forge`; Remix works as
a fallback), `tor` + `torsocks` (or Orbot), and `pip install argon2-cffi cryptography` for the seal tool.

## 1. Deploy the vault (once), over Tor
```sh
tor &                         # or Tor Browser / Orbot — anything with a SOCKS port on 9050
make attest-deploy            # == scripts/attest-deploy.sh  (Base Sepolia default)
# prompts for your FRESH, Tor-funded deployer key (entered interactively — never in argv/env/disk)
```
It tunnels `forge create` through Tor, prints the deployed address, and writes it to
`build/attest-contract.txt`. Then wire it in **one** way:
- **Live installer (no rebuild):** `cp build/attest-contract.txt /config/attest-contract` on the
  installer/live environment → the installer records it as `attestContract`, and the on-chain
  attestation option un-greys. This is the per-install path.
- **Baked into the image (build time):** `make BOOT_INTEGRITY_CONTRACT_ADDRESS=0x… ATTEST_VAULT_ADDRESS=0x… …`
- Also: the mobile app's "Vault contract address" field, and the gatekeeper cmdline `gkvault=0x…`.

**Remix fallback (zero-install):** open remix.ethereum.org → paste `contracts/EncryptedAttestationVault.sol`
→ compile (0.8.24) → Deploy with "Injected Provider" on **Base Sepolia** (drive the browser through
Tor) → copy the address → wire it in as above.

## 2. Record your install (per machine)
```sh
python3 scripts/attest-seal.py \
  --manifest-root "$(cat build/zksync-attestation.json | jq -r .systemRoot)" \
  --whitelist "203.0.113.7,10.0.0.0/8" --blacklist "" \
  --id-out id.hex --record-out rec.hex --salt-out salt.hex
# put salt.hex on the machine's ESP (the gatekeeper reads it before any network):
cp salt.hex /boot/efi/anonymos/attest.salt      # adjust to your ESP path
# submit the sealed record over Tor with a funded wallet:
torsocks cast send $ATTEST_VAULT_ADDRESS "put(bytes32,bytes)" \
  0x$(cat id.hex) 0x$(cat rec.hex) \
  --rpc-url https://sepolia.base.org --private-key $WALLET_KEY
```
Use a **fresh, single-use, Tor-funded** wallet for `$WALLET_KEY` (it becomes the record's owner and
the only key that can update it). The password is prompted; it never leaves your machine.

## 3. Manage from your phone
The app is a static PWA at `mobile/attestation-app/index.html` — it isn't hosted, so either:
- **Open it in a wallet's dApp browser:** host the file (e.g. `python3 -m http.server` on a trusted
  box, or any static host / IPFS) and open the URL inside MetaMask/Rainbow mobile; or
- open it directly in a mobile browser that has an injected wallet extension.

Enter the RPC (`https://sepolia.base.org`), the vault address, your password, and the salt (hex from
`salt.hex` — paste or QR it over from the machine). It fetches, decrypts, and lets you edit the
whitelist/blacklist and re-submit `put()` signed by the owner wallet.

## What's still required for this to be a real product feature
- **Done:** deploy is one command (`make attest-deploy`, Tor-routed); the installer records the
  deployed address (`attestContract` → `install.json`) and `boot_integrity.d` verifies against it.
- **Still manual — step 2 (`put()`):** the installer does not yet run `attest-seal.py` + `cast send`
  for you (it would need password + whitelist entry screens and a signer, which the install kernel
  lacks). An installing user still records the sealed payload by hand as above.
- **Finish `boot/gatekeeper/`** so the whitelist actually gates boot (see its README).
- **Package/serve the mobile app** (bundle its CDN libs for offline/Tor, ship it somewhere).
