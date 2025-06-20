#!/bin/bash
# anonymOS System Activation Script

# Path to the compiled D activator executable
# Assumes 'dub build' was run in src/user/apps/system_activator/
ACTIVATOR_EXE="./src/user/apps/system_activator/system_activator"
DEFAULT_CONFIG="anonymos_config/system.json"
CONFIG_FILE="$DEFAULT_CONFIG"

if [ ! -f "$ACTIVATOR_EXE" ]; then
    echo "Activator executable not found at $ACTIVATOR_EXE"
    echo "Please build it first (e.g., cd src/user/apps/system_activator && dub build)"
    exit 1
fi

if [ "$#" -gt 0 ]; then
    CONFIG_FILE="$1"
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "System configuration file not found: $CONFIG_FILE"
    exit 1
fi

echo "Running anonymOS Activator with configuration: $CONFIG_FILE"
"$ACTIVATOR_EXE" "$CONFIG_FILE"

echo "Activation script finished."
