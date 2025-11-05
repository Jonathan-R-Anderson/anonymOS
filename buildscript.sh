#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONFIG_FILE="${CONFIG_FILE:-toolchain_config.toml}"

if [[ -f "$CONFIG_FILE" ]]; then
    SELECTED_CONFIG="$CONFIG_FILE"
elif [[ -f "$SCRIPT_DIR/$CONFIG_FILE" ]]; then
    SELECTED_CONFIG="$SCRIPT_DIR/$CONFIG_FILE"
else
    SELECTED_CONFIG=""
fi

if [[ ! -x "$SCRIPT_DIR/toolchain_builder.py" ]]; then
    chmod +x "$SCRIPT_DIR/toolchain_builder.py"
fi

if [[ -n "$SELECTED_CONFIG" ]]; then
    echo "Using configuration file: $SELECTED_CONFIG"
    exec "$SCRIPT_DIR/toolchain_builder.py" --config "$SELECTED_CONFIG" "$@"
else
    echo "No configuration file found (looked for $CONFIG_FILE); falling back to CLI arguments" >&2
    exec "$SCRIPT_DIR/toolchain_builder.py" "$@"
fi
