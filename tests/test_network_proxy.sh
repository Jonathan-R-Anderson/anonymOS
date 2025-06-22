#!/bin/bash
set -e
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
out=$("$ROOT_DIR"/scripts/network_proxy.sh --dry-run)
[[ $out == *tor* ]]
[[ $out == *PROXYCHAINS_CONF* ]]
[[ $out == *socks5* ]]
echo "network proxy script dry-run passed"
