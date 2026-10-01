#!/usr/bin/env bash
# E15.1 / T15.2 — the empirical half.
#
#   "A build with the token package removed still relays, stores and resolves —
#    falsified by any payment-required error (S10)."
#   "The v1 network runs with the token subsystem disabled and every other exit
#    criterion still passes — falsified by any regression (S10)."
#
# The import audit in audit_test.go proves nothing imports this package. That is
# necessary and not sufficient: a package can be depended on through a build tag,
# a generated file, an embed, or a test fixture the rest of the tree needs. The
# only way to establish removability is to REMOVE IT.
#
# So this deletes the package, builds the whole module, runs every other AXON
# suite plus the storage path, and restores it. A non-zero exit means the
# subsystem is load-bearing and the removability claim is false.
#
#   bash internal/axon/token/removability_test.sh
#
# It is a script rather than a Go test because a Go test cannot delete the
# package it is compiled into.

set -uo pipefail

cd "$(dirname "$0")/../../.." || exit 1
PKG="internal/axon/token"
STASH="$(mktemp -d)"

restore() {
  if [ -d "$STASH/token" ]; then
    rm -rf "$PKG"
    mv "$STASH/token" "$PKG"
  fi
  rm -rf "$STASH"
}
trap restore EXIT

echo "E15.1: removing $PKG"
cp -r "$PKG" "$STASH/token" || exit 1
rm -rf "$PKG"

fail=0

echo "--- build the whole module without it"
if ! go build ./... 2>&1; then
  echo "E15.1 VIOLATED: the module does not build without the token package"
  fail=1
fi

echo "--- vet"
if ! go vet ./internal/... >/dev/null 2>&1; then
  echo "note: go vet reported issues; not treated as an E15.1 failure"
fi

echo "--- every other AXON package, plus the storage path"
if ! go test ./internal/axon/... ./internal/store/... ./internal/placement/... 2>&1 | grep -v '^ok\|no test files'; then
  :
fi
if ! go test ./internal/axon/... ./internal/store/... ./internal/placement/... >/dev/null 2>&1; then
  echo "E15.1 VIOLATED: a suite regressed with the token package absent"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo
  echo "E15.1 HOLDS: the module builds and every data-path suite passes with the"
  echo "token subsystem physically deleted. Payments are removable."
else
  echo
  echo "E15.1 FAILED"
fi

exit "$fail"
