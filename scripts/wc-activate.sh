#!/bin/bash
# WorldComputer System Activation Script

# Path to the compiled D activator executable
# Assumes 'dub build' was run in src/activator/
ACTIVATOR_EXE="./src/activator/activator"
DEFAULT_CONFIG="worldcomputer_config/system.json"
CONFIG_FILE="$DEFAULT_CONFIG"

if [ ! -f "$ACTIVATOR_EXE" ]; then
    echo "Activator executable not found at $ACTIVATOR_EXE"
    echo "Please build it first (e.g., cd src/activator && dub build)"
    exit 1
fi

if [ "$#" -gt 0 ]; then
    CONFIG_FILE="$1"
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "System configuration file not found: $CONFIG_FILE"
    exit 1
fi

echo "Running WorldComputer Activator with configuration: $CONFIG_FILE"
"$ACTIVATOR_EXE" "$CONFIG_FILE"

echo "Activation script finished."