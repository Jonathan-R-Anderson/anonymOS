# Attestation ops — deploy, record, manage (manual, until the installer wires it)

`wl-installer` does **not** yet deploy the vault or record your info, and the mobile app isn't
packaged/served — that integration is unbuilt. Until it exists, this is the manual path that does
the same three things with standard tools.

> ⚠ Boot enforcement is NOT live yet. `boot/gatekeeper/` is a skeleton (placeholder transfer logic),
> so a recorded whitelist gates nothing at boot until the gatekeeper is finished. You can still
> deploy/record/manage now to exercise the chain + app; enforcement comes with the gatekeeper.

Prereqs: an L2 wallet with a little test ETH (Base Sepolia faucet), one of Remix/Foundry, `torsocks`
(or Orbot), and `pip install argon2-cffi cryptography` for the seal tool.

## 1. Deploy the vault (once)
**Remix (zero-install):** open remix.ethereum.org → paste `contracts/EncryptedAttestationVault.sol`
→ compile (0.8.24) → Deploy, environment "Injected Provider" with your wallet on **Base Sepolia**.
Copy the deployed address.

**Foundry (CLI):**
```sh
forge create contracts/EncryptedAttestationVault.sol:EncryptedAttestationVault \
  --rpc-url https://sepolia.base.org --private-key $DEPLOYER_KEY
```
Then set the address everywhere that reads it:
- `Makefile` → `ATTEST_VAULT_ADDRESS := 0x…`
- the mobile app's "Vault contract address" field
- the gatekeeper cmdline `gkvault=0x…` (once it's built)

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
- **Wire steps 1–2 into `wl-installer`** (new screens: password, whitelist, deploy/record) so an
  installing user isn't running `cast` by hand. Substantial C/Wayland work.
- **Finish `boot/gatekeeper/`** so the whitelist actually gates boot (see its README).
- **Package/serve the mobile app** (bundle its CDN libs for offline/Tor, ship it somewhere).
