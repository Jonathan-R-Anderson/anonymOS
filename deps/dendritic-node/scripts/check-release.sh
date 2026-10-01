#!/bin/sh
# The credential-free gate to run BEFORE anyone publishes a node release.
#
#   ./scripts/check-release.sh
#
# WHY THIS EXISTS
# ---------------
# The seven-platform release matrix was silently broken for weeks by two
# unrelated additions, neither of which was noticed because nothing ever ran the
# release build:
#
#   2026-07-27  build-release.sh written, CGO_ENABLED=0, seven targets
#   2026-08-04  computeapi.go added, referencing Linux-only symbols with no tag
#   2026-08-12  blst added, which cannot build with cgo disabled
#
# Both were found only when somebody tried to cut a release. This script is the
# check that would have caught either of them the day it landed.
#
# WHAT IT DOES NOT DO
# -------------------
# It publishes nothing. No /admin/node-releases, no object store, no
# SiteSetting, no kubectl, no deploy, no node restart. It needs no credentials
# and contacts no production system. Verification only — the artifacts are left
# in dist/ for a human to decide about.
#
# ON REPRODUCIBILITY
# ------------------
# Two builds of the SAME source commit produce identical bytes. Two builds of
# DIFFERENT commits do not, and that is correct: Go embeds vcs.revision and
# vcs.time, so the binary records which source it came from. Anyone checking a
# published hash has to build the exact commit — the hash proves provenance, not
# just content.
#
# ON AUTOMATIC INVOCATION
# -----------------------
# Deliberately undefined. This repository has no CI, no hooks and no cron, and
# choosing one is an infrastructure decision rather than a code change. The
# script is written to be run by hand today and called unchanged by whatever
# runs it later.

set -eu

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DIST="$ROOT/dist"

# The seven targets are NOT restated here. build-release.sh owns the matrix, and
# a second copy would be a second thing to forget to update. This lists only the
# artifact NAMES it must have produced, which is what "did the matrix succeed"
# actually means.
EXPECTED="syndichan-node-linux-amd64
syndichan-node-linux-arm64
syndichan-node-linux-arm
syndichan-node-darwin-amd64
syndichan-node-darwin-arm64
syndichan-node-windows-amd64.exe
syndichan-node-windows-arm64.exe"

# The GOOS/GOARCH pairs for vet. These DO restate the matrix, because `go vet`
# has to be told a platform and build-release.sh does not expose its list. Kept
# next to EXPECTED so the two are read together and drift is visible.
VET_TARGETS="linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

fail() { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

step "1/6  release matrix (scripts/build-release.sh, CGO_ENABLED=0)"
# The real script, unmodified. If it stops building seven things, this stops.
sh scripts/build-release.sh || fail "the release build did not complete"

step "2/6  artifacts and checksums"
missing=0
for name in $EXPECTED; do
	if [ ! -f "$DIST/$name" ]; then
		printf '  MISSING  %s\n' "$name"
		missing=$((missing + 1))
		continue
	fi
	# Same sidecar format publish-node-release.sh writes, so a release cut
	# either way produces identical files rather than two checksum conventions.
	( cd "$DIST" && sha256sum "$name" >"$name.sha256" )
	printf '  %s\n' "$(cat "$DIST/$name.sha256")"
done
[ "$missing" -eq 0 ] || fail "$missing of 7 release artifacts were not produced"

step "3/6  the release binary must not link BLS"
# blst is cgo and cannot build with CGO_ENABLED=0. It reached the node through
# internal/ethproof and broke four targets. BLS is opt-in under `ethbls`; if it
# comes back into the ordinary graph the release is broken again.
if CGO_ENABLED=0 go list -deps ./cmd/syndichan-node 2>/dev/null | grep -q blst; then
	fail "blst is back in the ordinary node dependency graph; the release build will not cross-compile"
fi
printf '  no blst in the CGO-free node dependency graph\n'

step "4/6  the ethbls capability still works"
# The other half of the boundary: making the release build work must not have
# quietly broken the real verifier that P12 depends on.
go build -tags ethbls ./... || fail "the ethbls build is broken"
go test -tags ethbls ./internal/ethproof || fail "the real BLS tests do not pass"
printf '  ethbls builds and its consensus-spec vectors pass\n'

step "5/6  cross-platform vet"
# Host vet is NOT equivalent: the failures this catches — a Linux-only symbol
# referenced from an untagged file, a stub that stopped matching its Linux
# counterpart — are invisible unless GOOS is set. Vet also compiles the test
# files, which is how a test referencing Linux internals gets caught.
for t in $VET_TARGETS; do
	os=${t%/*}
	arch=${t#*/}
	goarm=""
	[ "$arch" = "arm" ] && goarm=6
	if ! CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOARM="$goarm" go vet ./... >/tmp/vet.$$ 2>&1; then
		sed -n '1,12p' /tmp/vet.$$ >&2
		rm -f /tmp/vet.$$
		fail "go vet failed for $t"
	fi
	printf '  %-16s vet ok\n' "$t"
done
rm -f /tmp/vet.$$

step "6/6  the non-Linux compute boundary"
# What vet already proved above: computeapi_other.go compiles for all four
# non-Linux targets, so the routes exist and nothing references a MicroVMExecutor
# that is not there.
#
# What it CANNOT prove from a Linux host: that those handlers refuse at runtime.
# cmd/syndichan-node/computeapi_other_test.go asserts exactly that — no 2xx, no
# admitted/accepted/done true, no executor field — and it can only EXECUTE on a
# non-Linux machine. Compiled everywhere, run where it applies.
if [ "$(go env GOOS)" = "linux" ]; then
	printf '  compiled for darwin and windows; the refusal tests execute on a non-Linux host\n'
else
	go test ./cmd/syndichan-node/ || fail "the non-Linux compute refusal tests failed"
	printf '  non-Linux compute handlers refuse every request\n'
fi

cat <<EOF

== PASS
Seven artifacts and their .sha256 sidecars are in dist/. NOTHING WAS PUBLISHED.

Hashes are reproducible only against the exact source commit: Go embeds
vcs.revision and vcs.time, so a rebuild of a different commit is expected to
differ. Record the commit alongside any hash you publish.

  commit  $(git rev-parse --short HEAD 2>/dev/null || echo unknown)
  clean   $([ -z "$(git status --porcelain 2>/dev/null)" ] && echo yes || echo 'NO — hashes will not be reproducible by anyone else')
EOF
