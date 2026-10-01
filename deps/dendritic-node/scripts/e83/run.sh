#!/usr/bin/env bash
# E8.3 — run the cross-implementation comparison end to end.
#
#   scripts/e83/run.sh
#
# Exit status is the comparison's: non-zero if the two implementations disagree
# on behaviour.  Needs python3 and go on PATH; on NixOS:
#
#   nix shell nixpkgs#go nixpkgs#python3 --command scripts/e83/run.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

cd "$here"
python3 corpus.py
cd "$root"
CGO_ENABLED=0 go run ./cmd/e83dump -corpus scripts/e83/corpus.json -out scripts/e83/go.json
cd "$here"
python3 keccak.py >/dev/null   # self-test the hash before trusting its output
exec python3 compare.py
