#!/usr/bin/env bash
# attest-deploy.sh — deploy the EncryptedAttestationVault to an Ethereum L2, over Tor.
#
# This is the "connect to the chain and deploy the contract" step of the attestation feature.
# It is deliberately NOT done inside the kernel or wl-installer: signing a deploy transaction
# needs secp256k1 + keccak + RLP + a live RPC, none of which the boot/install path has (it only
# does read-only eth_call).  So the deploy runs here, in a normal userland with a real, audited
# EVM toolchain (Foundry), and the installer merely RECORDS the resulting address per-install
# (see read_attest_contract() in src/util/wl-installer.c and installConfigAttestContract() in
# src/kernel/d/core/install_config.d — boot_integrity.d then verifies against it on-chain).
#
# What it does:
#   1. deploys contracts/EncryptedAttestationVault.sol with `forge create`, tunnelled through Tor
#      (torsocks), so the deploy is not linked to your clearnet IP;
#   2. captures the deployed address and writes it where the toolchain reads it:
#        - $OUT_FILE (default build/attest-contract.txt), and
#        - prints the make var line + the /config/attest-contract line for the installer.
#
# Key handling: the deployer key is entered INTERACTIVELY (forge --interactive) by default, so it
# never appears in argv (`ps`), the environment, shell history, or on disk.  Use a FRESH, single-
# use, Tor-funded wallet — it becomes the deployer of a public contract.  YOU fund it.
#
# Prereqs: foundry (`forge`), tor running with a SOCKS port (default 9050), and `torsocks`.
#   Foundry:  curl -L https://foundry.paradigm.xyz | bash && foundryup
#   Tor:      apt/apk install tor torsocks   (or run Tor Browser / Orbot and point --socks at it)
#
# ⚠ Deploys a real transaction that spends real (test)ETH.  Review before running.  Defaults to
#   Base Sepolia (testnet).  To deploy to a different chain, pass --rpc-url / set ZKSYNC_RPC_URL.
set -euo pipefail

# ── config (env overridable; names mirror the Makefile) ──────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACT_SRC="${ATTEST_VAULT_CONTRACT:-$REPO_ROOT/contracts/EncryptedAttestationVault.sol}"
CONTRACT_NAME="EncryptedAttestationVault"
RPC_URL="${ZKSYNC_RPC_URL:-https://sepolia.base.org}"
NETWORK="${ZKSYNC_NETWORK:-base-sepolia}"
SOCKS="${TOR_SOCKS:-127.0.0.1:9050}"
OUT_FILE="${ATTEST_DEPLOY_OUT:-$REPO_ROOT/build/attest-contract.txt}"
USE_TOR=1
EXTRA_ARGS=()

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Usage: $(basename "$0") [--rpc-url URL] [--socks HOST:PORT] [--out FILE] [--no-tor] [-- forge-args…]

  --rpc-url URL     L2 RPC endpoint (default: \$ZKSYNC_RPC_URL or https://sepolia.base.org)
  --socks H:P       Tor SOCKS proxy for torsocks (default: \$TOR_SOCKS or 127.0.0.1:9050)
  --out FILE        where to write the deployed address (default: build/attest-contract.txt)
  --no-tor          DANGER: deploy WITHOUT Tor (links the deploy to your clearnet IP)
  -- forge-args…    anything after -- is passed through to \`forge create\`
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --rpc-url) RPC_URL="$2"; shift 2 ;;
        --socks)   SOCKS="$2"; shift 2 ;;
        --out)     OUT_FILE="$2"; shift 2 ;;
        --no-tor)  USE_TOR=0; shift ;;
        -h|--help) usage; exit 0 ;;
        --)        shift; EXTRA_ARGS=("$@"); break ;;
        *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
    esac
done

die() { echo "attest-deploy: $*" >&2; exit 1; }

# ── preflight ────────────────────────────────────────────────────────────────────────────────
command -v forge >/dev/null 2>&1 || die "\`forge\` not found. Install Foundry:
  curl -L https://foundry.paradigm.xyz | bash && foundryup
(or deploy by hand via Remix — see contracts/README-attestation-ops.md §1.)"
[ -f "$CONTRACT_SRC" ] || die "contract not found: $CONTRACT_SRC"

RUN=()
if [ "$USE_TOR" = 1 ]; then
    command -v torsocks >/dev/null 2>&1 || die "\`torsocks\` not found (install 'torsocks', or pass --no-tor to deploy clearnet).
The user's threat model routes the deploy through Tor; --no-tor links it to your IP."
    host="${SOCKS%%:*}"; port="${SOCKS##*:}"
    # Best-effort check that something is listening on the SOCKS port.
    if command -v nc >/dev/null 2>&1 && ! nc -z "$host" "$port" 2>/dev/null; then
        die "nothing is listening on Tor SOCKS $SOCKS. Start tor (e.g. \`tor &\` or Tor Browser/Orbot) first."
    fi
    export TORSOCKS_CONF_FILE="${TORSOCKS_CONF_FILE:-}"
    TORSOCKS_TOR_ADDRESS="$host" TORSOCKS_TOR_PORT="$port" true
    RUN=(torsocks -a "$host" -p "$port")
    echo "attest-deploy: routing through Tor SOCKS $SOCKS"
else
    echo "attest-deploy: ⚠ --no-tor: deploying over CLEARNET (this links the deploy to your IP)" >&2
fi

# forge v1 requires --broadcast to actually send; older forge broadcasts by default. Add it only
# if this forge understands it, so the same script works on both.
BROADCAST=()
if forge create --help 2>/dev/null | grep -q -- '--broadcast'; then
    BROADCAST=(--broadcast)
fi

echo "attest-deploy: network=$NETWORK rpc=$RPC_URL"
echo "attest-deploy: contract=$CONTRACT_SRC:$CONTRACT_NAME"
echo "attest-deploy: enter your FRESH, Tor-funded deployer key when prompted (it is NOT stored)."

mkdir -p "$(dirname "$OUT_FILE")"
LOG="$(mktemp)"; trap 'rm -f "$LOG"' EXIT

# --interactive: forge prompts for the private key on the tty — never in argv/env/disk/history.
set +e
"${RUN[@]}" forge create "$CONTRACT_SRC:$CONTRACT_NAME" \
    --rpc-url "$RPC_URL" \
    --interactive \
    "${BROADCAST[@]}" \
    "${EXTRA_ARGS[@]}" 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
set -e
[ "$rc" -eq 0 ] || die "forge create failed (exit $rc). See output above."

# Foundry prints "Deployed to: 0x…". Extract + validate (0x + 40 hex).
ADDR="$(grep -oiE 'Deployed to:? *0x[0-9a-fA-F]{40}' "$LOG" | grep -oiE '0x[0-9a-fA-F]{40}' | head -n1 || true)"
[ -n "$ADDR" ] || die "could not parse the deployed address from forge output."
echo "$ADDR" | grep -qiE '^0x[0-9a-fA-F]{40}$' || die "parsed address looks malformed: $ADDR"

printf '%s\n' "$ADDR" > "$OUT_FILE"
chmod 0644 "$OUT_FILE"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
✔ EncryptedAttestationVault deployed
    address : $ADDR
    network : $NETWORK ($RPC_URL)
    written : $OUT_FILE

Wire it in ONE of these ways:

  • Bake into the image (build time) — the address ends up in zksync-attestation.json:
        make BOOT_INTEGRITY_CONTRACT_ADDRESS=$ADDR ATTEST_VAULT_ADDRESS=$ADDR …

  • Feed the live installer (no rebuild) — drop the address where wl-installer reads it, so it is
    recorded in install.json as "attestContract" (boot_integrity.d prefers it over the manifest):
        cp "$OUT_FILE" /config/attest-contract      # on the installer/live environment

  • The boot gatekeeper's cmdline:   gkvault=$ADDR
  • The mobile app's "Vault contract address" field.

Next: record your install (integrity root + IP whitelist), sealed with your password, over Tor —
see contracts/README-attestation-ops.md §2 (attest-seal.py + \`torsocks cast send … put(…)\`).
────────────────────────────────────────────────────────────────────────────
EOF
