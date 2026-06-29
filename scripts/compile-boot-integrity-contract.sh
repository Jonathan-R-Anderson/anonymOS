#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/installer/contracts/BootIntegrityRegistry.sol"
ABI="$ROOT/installer/contracts/BootIntegrityRegistry.abi.json"
OUT_DIR="$ROOT/build/contracts"
ARTIFACT="$OUT_DIR/BootIntegrityRegistry.artifact.json"

mkdir -p "$OUT_DIR"

if command -v solc >/dev/null 2>&1; then
  solc --optimize --bin --overwrite -o "$OUT_DIR" "$SRC" >/dev/null
  BIN_FILE="$OUT_DIR/BootIntegrityRegistry.bin"
  if [ ! -s "$BIN_FILE" ]; then
    echo "compile-boot-integrity-contract: solc did not produce $BIN_FILE" >&2
    exit 1
  fi
  python3 - "$ABI" "$BIN_FILE" "$ARTIFACT" <<'PY'
import json
import sys
from pathlib import Path

abi = json.loads(Path(sys.argv[1]).read_text())
bytecode = Path(sys.argv[2]).read_text().strip()
if not bytecode.startswith("0x"):
    bytecode = "0x" + bytecode
artifact = {
    "contractName": "BootIntegrityRegistry",
    "abi": abi,
    "bytecode": bytecode,
}
Path(sys.argv[3]).write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
PY
  echo "Wrote $ARTIFACT"
else
  cat >&2 <<EOF
compile-boot-integrity-contract: solc was not found.

Install a Solidity compiler, then rerun:
  scripts/compile-boot-integrity-contract.sh

ZKsync Era supports standard Solidity/EVM bytecode on the Era EVM path, so this
contract intentionally has no framework or OpenZeppelin dependency.
EOF
  exit 1
fi
