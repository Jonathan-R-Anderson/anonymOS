#!/usr/bin/env python3
"""Pack the integrated ZKsync wallet boot-integrity page into an rtfs blob."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path


def add_tree(entries: list[tuple[str, bytes]], src: Path, prefix: str) -> None:
    for path in sorted(src.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(src).as_posix()
        entries.append((f"{prefix}/{rel}", path.read_bytes()))


def add_file(entries: list[tuple[str, bytes]], src: Path, guest_path: str) -> None:
    if src.is_file():
        entries.append((guest_path, src.read_bytes()))


def write_blob(output: Path, entries: list[tuple[str, bytes]]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as out:
        for guest_path, data in sorted(entries, key=lambda item: item[0]):
            p = guest_path.strip("/").encode("utf-8")
            out.write(struct.pack("<I", len(p)))
            out.write(p)
            out.write(struct.pack("<I", len(data)))
            out.write(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("static_dir")
    parser.add_argument("output")
    parser.add_argument("prefix")
    parser.add_argument("--contract", required=True)
    parser.add_argument("--abi", required=True)
    parser.add_argument("--artifact", default="build/contracts/BootIntegrityRegistry.artifact.json")
    args = parser.parse_args()

    static_dir = Path(args.static_dir)
    if not static_dir.is_dir():
        raise SystemExit(f"pack-zksync-wallet: static directory not found: {static_dir}")

    prefix = args.prefix.strip("/")
    entries: list[tuple[str, bytes]] = []
    add_tree(entries, static_dir, prefix)
    add_file(entries, Path(args.contract), f"{prefix}/contracts/BootIntegrityRegistry.sol")
    add_file(entries, Path(args.abi), f"{prefix}/contracts/BootIntegrityRegistry.abi.json")
    add_file(entries, Path(args.artifact), f"{prefix}/contracts/BootIntegrityRegistry.artifact.json")
    write_blob(Path(args.output), entries)
    print(f"pack-zksync-wallet: wrote {args.output} files={len(entries)} prefix=/{prefix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
