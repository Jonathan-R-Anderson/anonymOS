#!/usr/bin/env bash
# Compile EVERY Solidity contract under contracts/ to build/contracts/<Name>.artifact.json
# (ABI + bytecode). Consolidated from the old per-contract compile script so all zkSync
# contracts build the same way. Requires solc; ZKsync Era runs stock EVM bytecode.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT/contracts"
OUT_DIR="$ROOT/build/contracts"
mkdir -p "$OUT_DIR"

if ! command -v solc >/dev/null 2>&1; then
  cat >&2 <<EOF
compile-contracts: solc was not found.

Install a Solidity compiler, then rerun:
  scripts/compile-contracts.sh

ZKsync Era supports standard Solidity/EVM bytecode on the Era EVM path, so these
contracts intentionally have no framework or OpenZeppelin dependency.
EOF
  exit 1
fi

shopt -s nullglob
sols=("$SRC_DIR"/*.sol)
if [ ${#sols[@]} -eq 0 ]; then
  echo "compile-contracts: no .sol files in $SRC_DIR" >&2
  exit 1
fi

for SRC in "${sols[@]}"; do
  NAME="$(basename "$SRC" .sol)"
  ABI="$SRC_DIR/$NAME.abi.json"
  ARTIFACT="$OUT_DIR/$NAME.artifact.json"

  solc --optimize --bin --abi --overwrite -o "$OUT_DIR" "$SRC" >/dev/null
  BIN_FILE="$OUT_DIR/$NAME.bin"
  if [ ! -s "$BIN_FILE" ]; then
    echo "compile-contracts: solc did not produce $BIN_FILE" >&2
    exit 1
  fi
  # Prefer a hand-maintained ABI if present (BootIntegrityRegistry ships one); else use
  # the ABI solc just emitted next to the bin.
  [ -s "$ABI" ] || ABI="$OUT_DIR/$NAME.abi"

  python3 - "$ABI" "$BIN_FILE" "$ARTIFACT" "$NAME" <<'PY'
import json, sys
from pathlib import Path
abi = json.loads(Path(sys.argv[1]).read_text())
bytecode = Path(sys.argv[2]).read_text().strip()
if not bytecode.startswith("0x"):
    bytecode = "0x" + bytecode
Path(sys.argv[3]).write_text(
    json.dumps({"contractName": sys.argv[4], "abi": abi, "bytecode": bytecode},
               indent=2, sort_keys=True) + "\n")
PY
  echo "Wrote $ARTIFACT"
done
