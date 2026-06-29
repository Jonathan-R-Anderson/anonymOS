# Boot Integrity Registry

`BootIntegrityRegistry.sol` is the ZKsync Era contract used by the integrated wallet to anchor EpinAnonymOS boot-module hashes.

The wallet deploys the contract with the manifest Merkle root, then stores each file hash in `setFileHashes(bytes32[] pathHashes, bytes32[] contentHashes)`. The kernel validates the staged manifest locally during boot and, when `bootIntegrity=zksync` is selected and networking is available, compares the manifest root with `systemRoot()` by JSON-RPC.

Build bytecode with a Solidity compiler:

```sh
scripts/compile-boot-integrity-contract.sh
```

Then deploy/update it from the wallet page staged at `/system/web/zksync-wallet/index.html`, or from the Nuxt route `/boot-integrity` when building `deps/zksync-wallet-vue`.
