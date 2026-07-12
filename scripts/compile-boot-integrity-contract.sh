#!/usr/bin/env bash
# Deprecated shim: contracts were consolidated into contracts/ and now build together.
# Kept so existing callers (Makefile boot-integrity-contract target) keep working.
exec "$(dirname "$0")/compile-contracts.sh" "$@"
