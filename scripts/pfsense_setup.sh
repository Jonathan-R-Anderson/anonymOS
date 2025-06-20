#!/bin/bash
# Launch pfSense firewall either in Docker or a virtual machine and route traffic through it.
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
# Check if pfsense enabled
if ! grep -q '"pfsense"' "$CONFIG_FILE"; then
    echo "pfsense config missing" >&2
    exit 1
fi
[ -n "$(grep -o '"enabled"[[:space:]]*:[[:space:]]*true' "$CONFIG_FILE")" ] && ENABLED=true || ENABLED=false
[ "$ENABLED" = "true" ] || exit 0
METHOD=$(grep -o '"method"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" | head -n1 | cut -d '"' -f4)
PFSENSE_IP=$(grep -o '"ip"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" | head -n1 | cut -d '"' -f4)
: ${PFSENSE_IP:=192.168.100.1}
if [ "$METHOD" = "docker" ] && command -v docker >/dev/null 2>&1; then
    RUN_CMD="docker run --rm -d --name anonymos-pfsense pfsense/pfsense"
elif [ "$METHOD" = "vm" ]; then
    RUN_CMD="qemu-system-x86_64 -m 512M -hda pfsense.img -net nic -net user"
else
    echo "Unsupported pfsense method or docker not available" >&2
    exit 1
fi
ROUTE_CMD="ip route replace default via $PFSENSE_IP"
if [ "$DRY_RUN" = yes ]; then
    echo "$RUN_CMD && $ROUTE_CMD"
else
    eval "$RUN_CMD"
    eval "$ROUTE_CMD"
fi
