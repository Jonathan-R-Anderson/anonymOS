# hos-ethsign — on-device Ethereum transaction signer

The signing toolchain the D kernel/installer lacked: **secp256k1 ECDSA + keccak256 + RLP + EIP-1559
(and legacy EIP-155) transaction building + JSON-RPC broadcast**. Built as a static-musl Linux ELF
so it runs under anonymOS's Linux-compat layer (`elf_loader.d` + `posix.d`) exactly like the other
`hos-*` boot tools. Uses audited RustCrypto crates (`k256`, `sha3`) + `bip39`/`bip32` — **no
hand-rolled EC math**, and none of it lives in the D kernel.

This is the on-device counterpart of the host-side `scripts/attest-deploy.sh` (Foundry over Tor):
same job — deploy the `EncryptedAttestationVault` / submit records — but running *inside* anonymOS.

## Why it exists here and not in the kernel
The kernel does only read-only `eth_call` (`boot_integrity.d`); it has no secp256k1/keccak/RLP and
its TLS is stubbed (`openssl_stubs.d`). So signing + TLS are done here in userland with vetted
libraries, and the kernel stays out of the crypto business.

## Commands (secrets via `--mnemonic-file` / `--key-file` / stdin — **never argv**)
```
hos-ethsign address [--mnemonic-file F [--index N] | --key-file F]
hos-ethsign sign    --chain-id N --nonce N --gas-limit N [--to 0x..|omit=create] [--value WEI] [--data 0x..]
                    EIP-1559 (default): --max-fee WEI --max-priority WEI   | legacy: --legacy --gas-price WEI
                    -> rawtx=0x..  hash=0x..
hos-ethsign chainid --rpc URL [--socks H:P]
hos-ethsign nonce   --rpc URL --address 0x.. [--socks H:P]
hos-ethsign gas     --rpc URL [--socks H:P]                 # EIP-1559 fee suggestion
hos-ethsign call    --rpc URL --to 0x.. --data 0x.. [--socks H:P]
hos-ethsign send    --rpc URL --raw 0x.. [--socks H:P]      # eth_sendRawTransaction
hos-ethsign deploy  --rpc URL --bytecode 0x.. [--value WEI] [--gas-limit N] + key [--socks H:P]
                    # fetch chainId+nonce+fees, build+sign a create tx, broadcast, print contract=0x..
```
`--socks H:P` routes the RPC through Tor (SOCKS5, connecting by hostname so DNS resolves at the exit).
The mnemonic is the same seed `scripts/attest-deploy.sh` reveals for cold-storage backup, so the
on-device signer and the host tool control the same owner wallet.

## Build
```
make hos-ethsign          # static musl, NON-PIE -> build/hos-ethsign (staged as a boot module)
make hos-ethsign-test     # cargo test (vectors below)
make hos-ethsign-dyn      # DYNAMIC musl -> build/hos-ethsign-dyn (see "On-device networking")
```
`cargo build` fetches the crates from the network the first time; `stage-iso-tree` skips the module
non-fatally if cargo is absent or offline (deploy still works host-side via Foundry).

## On-device networking (the transport constraint)
anonymOS userland has **no native TCP** (UDP/ICMP only); real outbound TCP is reachable **only**
through `libnshim.so` (an `LD_PRELOAD` socket interposer) → the LKL network provider (`/run/hos-net.sock`),
which needs LKL up with a granted NIC. Because `LD_PRELOAD` requires a dynamic binary:

- **Offline** (`address`, `sign`): the **static** `build/hos-ethsign` runs anywhere — no network.
- **Networked** (`chainid`/`nonce`/`gas`/`call`/`send`/`deploy`): use the **dynamic** build under
  the interposer (the module is staged at `/libnshim.so`, root — not `/lib/`):
  ```
  LD_PRELOAD=/libnshim.so  hos-ethsign-dyn  deploy --rpc https://sepolia.base.org --socks 127.0.0.1:9050 …
  ```
  TLS is terminated in-process by rustls (kernel TLS is stubbed). Tor on-device needs a Tor daemon
  reachable at `--socks` (the gatekeeper UKI bundles one; the hidden OS does not yet — omit `--socks`
  to deploy without Tor).

## One-command on-device deploy (`hos-attest-deploy`)
`src/util/hos-attest-deploy.c` (boot module `/hos-attest-deploy`) is the launcher that ties this to
the installer: it runs `hos-ethsign-dyn deploy` under `LD_PRELOAD=/libnshim.so`, captures the
`contract=0x…` line, and writes it to **`/config/attest-contract`** — which `wl-installer` reads
into `install.json` as `attestContract`, so `boot_integrity.d` verifies against it on-chain. It is
`hos-`-named so it runs unconfined (only such binaries may write `/config`). Run it **before**
"Install to Disk" (the address is captured when the config is built):
```
hos-attest-deploy --mnemonic-file /path/to/seed.txt [--socks 127.0.0.1:9050] [--rpc URL]
# defaults: --rpc https://sepolia.base.org  --bytecode-file /attest-vault.bin  --signer /hos-ethsign-dyn
```
Runtime prereqs (see the map): the LKL network up — **`LIVE_NET=1`** on install media, since LKL is
suppressed on live boots otherwise — a **funded** deployer wallet in `--mnemonic-file`, and (for Tor)
a SOCKS proxy. The vault creation bytecode ships as `/attest-vault.bin`
(`contracts/EncryptedAttestationVault.bin`, produced by `scripts/compile-contracts.sh`).

A clean fallback that avoids all of the above: `sign` offline on-device, carry the `rawtx=0x…` out,
and `send` it from anywhere with a network (host, decoy, phone).

## Verification status
- **Signing — VERIFIED, byte-for-byte.** `cargo test` checks the canonical **EIP-155 spec vector**
  and a **24-word BIP-39 → key+address** vector from Foundry; and `hos-ethsign sign` output is
  **identical to `cast mktx`** for an EIP-1559 tx (see build-verify below).
- **RPC/TLS — VERIFIED on a host.** `chainid`/`gas` succeed against `https://sepolia.base.org`
  (real TCP + rustls TLS + JSON-RPC).
- **On-device network path (libnshim→LKL) and the Tor hop — NOT verified here** (needs a real boot
  with LKL + a NIC). The code is the established pattern, but treat bring-up as unproven until
  tested on hardware.
- **Broadcasting a real deploy — not done here** (spends real testETH; that's the user's call).

### Reproduce the Foundry cross-check
```
KF=$(mktemp); echo 0x4646...4646 > $KF        # any 32-byte key
build/hos-ethsign sign --chain-id 84532 --nonce 3 --gas-limit 21000 \
  --max-priority 1500000000 --max-fee 30000000000 \
  --to 0x3535353535353535353535353535353535353535 --value 1000000000000000 --key-file $KF
cast mktx 0x3535…3535 --private-key 0x4646…4646 --nonce 3 --gas-limit 21000 \
  --priority-gas-price 1500000000 --gas-price 30000000000 --value 1000000000000000 --chain 84532
# the two rawtx values are identical.
```
