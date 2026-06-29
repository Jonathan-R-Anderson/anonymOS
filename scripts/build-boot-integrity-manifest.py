#!/usr/bin/env python3
"""Build the boot-integrity attestation manifest staged into the ISO.

The kernel verifier intentionally parses a small, deterministic JSON shape:
boot-module basename, SHA-256, path hash, leaf hash, and the Merkle root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path


MODULE_RE = re.compile(r"^\s*module_path:\s*boot\(\):/(.+?)\s*$")
EXCLUDED_MODULES = {
    "esp-image",
    "esp-hidden-image",
    "decoy-linux.ext4",
    "install.json",
    "zksync-attestation.json",
}
LEAF_PREFIX = b"epin-file-v1\0"
EMPTY_ROOT = hashlib.sha256(b"epin-empty-v1").digest()


def hex32(raw: bytes) -> str:
    if len(raw) != 32:
        raise ValueError("expected 32 bytes")
    return "0x" + raw.hex()


def leaf_hash(path: str, digest: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + path.encode("utf-8") + b"\0" + digest).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return EMPTY_ROOT
    level = leaves[:]
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
    return level[0]


def module_names(stage_dir: Path) -> list[str]:
    limine = stage_dir / "boot" / "limine" / "limine.conf"
    names: list[str] = []
    seen: set[str] = set()
    for line in limine.read_text(encoding="utf-8").splitlines():
        match = MODULE_RE.match(line)
        if not match:
            continue
        name = Path(match.group(1).strip()).name
        if name in EXCLUDED_MODULES or name in seen:
            continue
        if not (stage_dir / name).is_file():
            continue
        seen.add(name)
        names.append(name)
    return sorted(names)


def build_manifest(args: argparse.Namespace) -> dict:
    stage_dir = Path(args.stage_dir)
    files = []
    for name in module_names(stage_dir):
        data = (stage_dir / name).read_bytes()
        digest = hashlib.sha256(data).digest()
        ph = hashlib.sha256(name.encode("utf-8")).digest()
        leaf = leaf_hash(name, digest)
        files.append(
            {
                "path": name,
                "pathHash": hex32(ph),
                "sha256": hex32(digest),
                "leaf": hex32(leaf),
                "size": len(data),
            }
        )

    root = merkle_root([bytes.fromhex(item["leaf"][2:]) for item in files])
    canonical = {
        "schema": "epin.boot_integrity.v1",
        "scope": "boot-modules",
        "root": hex32(root),
        "files": files,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()

    return {
        "schema": "epin.boot_integrity.v1",
        "scope": "boot-modules",
        "network": args.network,
        "chainId": args.chain_id,
        "rpcUrl": args.rpc_url,
        "contractAddress": args.contract_address,
        "deploymentTx": args.deployment_tx,
        "contract": {
            "name": "BootIntegrityRegistry",
            "source": "/system/web/zksync-wallet/contracts/BootIntegrityRegistry.sol",
            "abi": "/system/web/zksync-wallet/contracts/BootIntegrityRegistry.abi.json",
        },
        "root": hex32(root),
        "manifestHash": hex32(manifest_hash),
        "fileCount": len(files),
        "files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage_dir")
    parser.add_argument("output")
    parser.add_argument("--network", default=os.environ.get("ZKSYNC_NETWORK", "zksync-sepolia"))
    parser.add_argument("--chain-id", type=int, default=int(os.environ.get("ZKSYNC_CHAIN_ID", "300")))
    parser.add_argument("--rpc-url", default=os.environ.get("ZKSYNC_RPC_URL", "https://sepolia.era.zksync.dev"))
    parser.add_argument("--contract-address", default=os.environ.get("BOOT_INTEGRITY_CONTRACT_ADDRESS", ""))
    parser.add_argument("--deployment-tx", default=os.environ.get("BOOT_INTEGRITY_DEPLOY_TX", ""))
    args = parser.parse_args()

    manifest = build_manifest(args)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"boot-integrity: wrote {out} files={manifest['fileCount']} "
        f"root={manifest['root']} contract={manifest['contractAddress'] or '(unset)'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
