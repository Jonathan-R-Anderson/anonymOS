#!/bin/bash
# Configure proxychains and optional Tor based on anonymOS configuration.
set -e
CONFIG_FILE="anonymos_config/system.json"
DRY_RUN=no

usage() {
    echo "Usage: $0 [--config FILE] [--dry-run]" >&2
}

while [[ "$1" == --* ]]; do
    case "$1" in
        --config) CONFIG_FILE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=yes; shift ;;
        *) usage; exit 1 ;;
    esac
done

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Config file $CONFIG_FILE not found" >&2
    exit 1
fi

USE_TOR=no
if grep -q '"useTor"[[:space:]]*:[[:space:]]*true' "$CONFIG_FILE"; then
    USE_TOR=yes
fi

PROXY_FILE="/tmp/anonymos_proxychains.conf"
PROXIES=$(sed -n '/"proxyChains"/,/]/p' "$CONFIG_FILE" | grep -o '".*"' | tr -d '"')

echo "[ProxyList]" > "$PROXY_FILE"
for p in $PROXIES; do
    echo "$p" >> "$PROXY_FILE"
done

CMD="export PROXYCHAINS_CONF=$PROXY_FILE"
if [ "$USE_TOR" = yes ]; then
    CMD="tor & $CMD"
fi

# Launch pfSense if configured and enabled
if grep -q '"pfsense"' "$CONFIG_FILE" && \
   grep -A3 '"pfsense"' "$CONFIG_FILE" | grep -q '"enabled"[[:space:]]*:[[:space:]]*true'; then
    if [ "$DRY_RUN" = yes ]; then
        CMD="$CMD && scripts/pfsense_setup.sh --dry-run --config \"$CONFIG_FILE\""
    else
        scripts/pfsense_setup.sh --config "$CONFIG_FILE"
    fi
fi

if [ "$DRY_RUN" = yes ]; then
    echo "$CMD"
    cat "$PROXY_FILE"
else
    eval "$CMD"
fi
