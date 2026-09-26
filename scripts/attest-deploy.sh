#!/usr/bin/env bash
# attest-deploy.sh — deploy the EncryptedAttestationVault to an Ethereum L2, over Tor, from a
# fresh RECOVERABLE HD wallet whose seed phrase is revealed to you.
#
# Why a revealed mnemonic (not a throwaway key): the deploying wallet becomes the on-chain OWNER
# of your attestation records — `ownerOf[id] = msg.sender` in the vault — so it is the ONLY key
# that can ever UPDATE your IP whitelist/blacklist later (from the mobile app, or from cold
# storage). You therefore need to keep it recoverable. This tool generates a BIP-39 wallet, shows
# you the seed phrase so you can back it up and move it into a hardware / cold-storage wallet, then
# deploys with it. There is no other copy — if you lose the phrase you lose the ability to update
# your records (the sealed data itself is still keyed by your install password, separately).
#
# It is deliberately NOT done inside the kernel or wl-installer: signing a deploy tx needs
# secp256k1 + keccak + RLP + a live RPC, none of which the boot/install path has (it only does
# read-only eth_call). So the deploy runs here in a normal userland with a real, audited EVM
# toolchain (Foundry), and the installer merely RECORDS the resulting CONTRACT address per-install
# (read_attest_contract() in src/util/wl-installer.c -> install.json "attestContract" ->
# installConfigAttestContract() -> boot_integrity.d verifies against it on-chain).
#
# Flow:
#   1. generate a fresh BIP-39 HD wallet (cast wallet new-mnemonic) and REVEAL the seed phrase;
#   2. you back up the phrase (cold storage) and FUND the shown address with a little (test)ETH;
#   3. deploy contracts/EncryptedAttestationVault.sol with `forge create`, tunnelled through Tor
#      so the deploy is not linked to your clearnet IP;
#   4. write the deployed CONTRACT address to $OUT_FILE + print how to wire it in.
#
# The seed never touches argv/env/history: it is written to a 0600 file in RAM (/dev/shm when
# available) only for the deploy call, and shredded on exit. The private key printed by
# new-mnemonic is captured in memory and never displayed, logged, or persisted.
#
# Prereqs: Foundry (`forge`+`cast`; https://getfoundry.sh — `foundryup`), tor with a SOCKS port
# (default 9050), and `torsocks`. NOTE: on this box a *different* `forge` (ZOE) shadows Foundry on
# PATH — the resolver below prefers $HOME/.foundry/bin and verifies it really is Foundry.
#
# ⚠ Deploys a real transaction spending real (test)ETH. Defaults to Base Sepolia (testnet).
set -euo pipefail

# ── config (env overridable; names mirror the Makefile) ──────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACT_SRC="${ATTEST_VAULT_CONTRACT:-$REPO_ROOT/contracts/EncryptedAttestationVault.sol}"
CONTRACT_NAME="EncryptedAttestationVault"
RPC_URL="${ZKSYNC_RPC_URL:-https://sepolia.base.org}"
NETWORK="${ZKSYNC_NETWORK:-base-sepolia}"
SOCKS="${TOR_SOCKS:-127.0.0.1:9050}"
OUT_FILE="${ATTEST_DEPLOY_OUT:-$REPO_ROOT/build/attest-contract.txt}"
WORDS="${ATTEST_SEED_WORDS:-24}"
USE_TOR=1
FUND_WAIT=1
SEED_OUT=""          # opt-in: also write the seed phrase to this file (0600) — dangerous, off by default
MNEMONIC_FILE=""     # reuse an EXISTING seed (path to a file with the phrase) instead of generating
EXTRA_ARGS=()

usage() {
    cat <<EOF
attest-deploy.sh — deploy EncryptedAttestationVault over Tor from a fresh, recoverable HD wallet.

The deploying wallet OWNS your on-chain records (only it can update the whitelist later), so this
tool reveals its BIP-39 seed phrase for you to back up / move to cold storage. See the header of
this file and contracts/README-attestation-ops.md.

Usage: $(basename "$0") [options] [-- forge-args…]
  --rpc-url URL       L2 RPC (default: \$ZKSYNC_RPC_URL or https://sepolia.base.org)
  --socks H:P         Tor SOCKS proxy (default: \$TOR_SOCKS or 127.0.0.1:9050)
  --out FILE          where to write the deployed CONTRACT address (default: build/attest-contract.txt)
  --words N           seed length: 12 or 24 (default: 24)
  --mnemonic-file F   reuse an EXISTING seed from file F instead of generating a new wallet
  --seed-out FILE     ALSO save the seed phrase to FILE (0600). Off by default; writing a seed to
                      disk is risky — prefer writing it down. Ignored with --mnemonic-file.
  --no-fund-wait      don't pause to fund / don't check balance (deploy immediately)
  --no-tor            DANGER: deploy WITHOUT Tor (links the deploy to your clearnet IP)
  -- forge-args…      passed through to \`forge create\`
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --rpc-url) RPC_URL="$2"; shift 2 ;;
        --socks)   SOCKS="$2"; shift 2 ;;
        --out)     OUT_FILE="$2"; shift 2 ;;
        --words)   WORDS="$2"; shift 2 ;;
        --mnemonic-file) MNEMONIC_FILE="$2"; shift 2 ;;
        --seed-out) SEED_OUT="$2"; shift 2 ;;
        --no-fund-wait) FUND_WAIT=0; shift ;;
        --no-tor)  USE_TOR=0; shift ;;
        -h|--help) usage; exit 0 ;;
        --)        shift; EXTRA_ARGS=("$@"); break ;;
        *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
    esac
done

die() { echo "attest-deploy: $*" >&2; exit 1; }

# ── resolve a genuine Foundry forge + cast (PATH may have an impostor `forge`) ─────────────────
is_foundry() { "$1" --version 2>/dev/null | grep -qiE 'forge Version|cast Version|foundry'; }
resolve_tool() {  # $1=basename (forge|cast), $2=env override
    local name="$1" override="$2" c
    if [ -n "$override" ]; then is_foundry "$override" && { echo "$override"; return; }
        die "$override ($name) is not Foundry (\`$name --version\` didn't identify as Foundry)."; fi
    for c in "$HOME/.foundry/bin/$name" "/usr/local/bin/$name" "/opt/foundry/bin/$name"; do
        [ -x "$c" ] && is_foundry "$c" && { echo "$c"; return; }
    done
    # scan PATH, skipping non-Foundry namesakes (e.g. the ZOE `forge`)
    local IFS=:; for d in $PATH; do
        [ -x "$d/$name" ] && is_foundry "$d/$name" && { echo "$d/$name"; return; }
    done
    die "genuine Foundry \`$name\` not found. Install: curl -L https://foundry.paradigm.xyz | bash && foundryup
(or set ${name^^}=/path/to/$name). A non-Foundry \`$name\` on PATH is ignored."
}
FORGE="$(resolve_tool forge "${FORGE:-}")"
CAST="$(resolve_tool cast "${CAST:-}")"
echo "attest-deploy: forge=$FORGE"
echo "attest-deploy: cast=$CAST"

# ── preflight ────────────────────────────────────────────────────────────────────────────────
[ -f "$CONTRACT_SRC" ] || die "contract not found: $CONTRACT_SRC"
case "$WORDS" in 12|24) ;; *) die "--words must be 12 or 24 (got '$WORDS')";; esac

RUN=()
if [ "$USE_TOR" = 1 ]; then
    command -v torsocks >/dev/null 2>&1 || die "\`torsocks\` not found (install 'torsocks', or pass --no-tor).
The user's threat model routes the deploy through Tor; --no-tor links it to your IP."
    host="${SOCKS%%:*}"; port="${SOCKS##*:}"
    if command -v nc >/dev/null 2>&1 && ! nc -z "$host" "$port" 2>/dev/null; then
        die "nothing is listening on Tor SOCKS $SOCKS. Start tor (\`tor &\`, Tor Browser, or Orbot) first."
    fi
    RUN=(torsocks -a "$host" -p "$port")
    echo "attest-deploy: routing network through Tor SOCKS $SOCKS"
else
    echo "attest-deploy: ⚠ --no-tor: deploying over CLEARNET (this links the deploy to your IP)" >&2
fi

# secure scratch for the seed phrase: RAM-backed if possible, 0600, shredded on exit
scratch_file() { local f; f="$(mktemp "${1:-/tmp}/attdep.XXXXXX")"; chmod 600 "$f"; echo "$f"; }
SCRATCH_DIR=/tmp; [ -d /dev/shm ] && [ -w /dev/shm ] && SCRATCH_DIR=/dev/shm
MN="$(scratch_file "$SCRATCH_DIR")"
LOG="$(scratch_file "$SCRATCH_DIR")"
cleanup() { for f in "$MN" "$LOG"; do [ -n "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; }; done; }
trap cleanup EXIT

is_addr() { echo "$1" | grep -qiE '^0x[0-9a-fA-F]{40}$'; }

# ── 1. obtain the wallet ───────────────────────────────────────────────────────────────────────
ADDR=""
if [ -n "$MNEMONIC_FILE" ]; then
    [ -f "$MNEMONIC_FILE" ] || die "--mnemonic-file not found: $MNEMONIC_FILE"
    # normalise to a 0600 scratch file (also strips accidental trailing junk)
    head -n1 "$MNEMONIC_FILE" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$MN"
    [ -s "$MN" ] || die "no phrase in $MNEMONIC_FILE"
    ADDR="$("$CAST" wallet address --mnemonic "$MN" --mnemonic-index 0 2>/dev/null)" \
        || die "could not derive an address from the supplied mnemonic."
    echo "attest-deploy: reusing supplied seed → $ADDR"
else
    echo "attest-deploy: generating a fresh $WORDS-word HD wallet…"
    gen="$("$CAST" wallet new-mnemonic --words "$WORDS" --accounts 1 2>&1)" \
        || die "cast wallet new-mnemonic failed:
$gen"
    # parse the phrase (line after 'Phrase:') and Account 0 address; the private key is IGNORED
    phrase="$(printf '%s\n' "$gen" | sed -n '/^Phrase:/{n;p;q}' | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    ADDR="$(printf '%s\n' "$gen" | awk '/^Address:/{print $2; exit}')"
    gen=""   # drop the buffer holding the private key
    [ -n "$phrase" ] || die "could not parse the generated seed phrase."
    printf '%s\n' "$phrase" > "$MN"; phrase=""
    # verify the address we'll ask you to fund is EXACTLY the one that will deploy (index 0)
    derived="$("$CAST" wallet address --mnemonic "$MN" --mnemonic-index 0 2>/dev/null)" \
        || die "could not re-derive the address from the generated seed."
    [ "${derived,,}" = "${ADDR,,}" ] || die "internal: parsed address ($ADDR) != derived ($derived); aborting before you fund the wrong wallet."
fi
is_addr "$ADDR" || die "wallet address looks malformed: $ADDR"

# optional (opt-in) seed backup to a file
if [ -n "$SEED_OUT" ] && [ -z "$MNEMONIC_FILE" ]; then
    umask 077; cp "$MN" "$SEED_OUT"; chmod 600 "$SEED_OUT"
    echo "attest-deploy: ⚠ seed phrase written to $SEED_OUT (0600) — move it to secure storage and delete this copy."
fi

# ── 2. REVEAL the seed (this is the whole point of this mode) ───────────────────────────────────
if [ -z "$MNEMONIC_FILE" ]; then
cat <<EOF

╔══════════════════════════════════════════════════════════════════════════════╗
║  BACK UP THIS SEED PHRASE NOW — it is shown ONCE and never stored by this tool ║
╚══════════════════════════════════════════════════════════════════════════════╝
  Seed phrase ($WORDS words):

      $(cat "$MN")

  Wallet address (BIP-44 m/44'/60'/0'/0/0, account 0):
      $ADDR

  • This wallet OWNS your on-chain attestation records — it is the ONLY key that can
    later UPDATE your IP whitelist/blacklist. Guard the phrase like your OS password.
  • Import it into a hardware / cold-storage wallet (and the mobile app) using the phrase.
  • Anyone with this phrase controls your records. Do not photograph or paste it anywhere online.
────────────────────────────────────────────────────────────────────────────────
EOF
fi

# ── 3. fund + confirm the deployer address ──────────────────────────────────────────────────────
if [ "$FUND_WAIT" = 1 ]; then
    cat <<EOF
Fund the deployer with a little $NETWORK ETH (deploy costs gas), then press ENTER:
      $ADDR
  Base Sepolia faucets: https://www.alchemy.com/faucets/base-sepolia
                        https://faucet.quicknode.com/base/sepolia
EOF
    read -r _ </dev/tty || true
    for attempt in 1 2 3 4 5; do
        bal="$("${RUN[@]}" "$CAST" balance "$ADDR" --rpc-url "$RPC_URL" 2>/dev/null || true)"
        if printf '%s' "$bal" | grep -qE '^[0-9]+$' && [ "$bal" != 0 ]; then
            echo "attest-deploy: balance ok ($bal wei). deploying…"; break
        fi
        [ "$attempt" = 5 ] && { echo "attest-deploy: still 0 balance after $attempt checks." >&2; }
        printf 'balance is 0 (or RPC unreachable). Fund it and press ENTER to re-check, or type "go" to deploy anyway: '
        read -r ans </dev/tty || ans=go
        [ "$ans" = go ] && break
    done
fi

# ── 4. deploy (over Tor); seed comes from the file, never argv ──────────────────────────────────
echo "attest-deploy: network=$NETWORK rpc=$RPC_URL"
echo "attest-deploy: deploying $CONTRACT_NAME (first run may fetch solc 0.8.24 — over Tor, can be slow)…"
set +e
"${RUN[@]}" "$FORGE" create "$CONTRACT_SRC:$CONTRACT_NAME" \
    --rpc-url "$RPC_URL" \
    --mnemonic "$MN" --mnemonic-index 0 \
    --broadcast \
    "${EXTRA_ARGS[@]}" 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
set -e
[ "$rc" -eq 0 ] || die "forge create failed (exit $rc). See output above."

CADDR="$(grep -oiE 'Deployed to:? *0x[0-9a-fA-F]{40}' "$LOG" | grep -oiE '0x[0-9a-fA-F]{40}' | head -n1 || true)"
is_addr "$CADDR" || die "could not parse the deployed contract address from forge output."

mkdir -p "$(dirname "$OUT_FILE")"
printf '%s\n' "$CADDR" > "$OUT_FILE"; chmod 0644 "$OUT_FILE"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
✔ EncryptedAttestationVault deployed
    contract : $CADDR        (public — safe to share/commit)
    owner    : $ADDR        (your seed-backed wallet; keep the phrase)
    network  : $NETWORK ($RPC_URL)
    written  : $OUT_FILE

Wire the CONTRACT address in ONE way:
  • Live installer (no rebuild): cp "$OUT_FILE" /config/attest-contract
        → installer records it as install.json "attestContract"; the on-chain option un-greys.
  • Baked at build time: make BOOT_INTEGRITY_CONTRACT_ADDRESS=$CADDR ATTEST_VAULT_ADDRESS=$CADDR …
  • Gatekeeper cmdline: gkvault=$CADDR   • Mobile app "Vault contract address" field.

Next: record your install (integrity root + IP whitelist), sealed with your PASSWORD, submitted by
this SAME owner wallet over Tor — see contracts/README-attestation-ops.md §2 (attest-seal.py +
\`torsocks cast send … put(…)\`). Use the seed above to sign from cold storage or the mobile app.
────────────────────────────────────────────────────────────────────────────
EOF
