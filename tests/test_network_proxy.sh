#!/bin/bash
set -e
out=$(scripts/network_proxy.sh --dry-run)
[[ $out == *tor* ]]
[[ $out == *PROXYCHAINS_CONF* ]]
[[ $out == *socks5* ]]
echo "network proxy script dry-run passed"
