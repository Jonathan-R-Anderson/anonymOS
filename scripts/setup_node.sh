#!/bin/bash
set -e
DEST_DIR="$1"
NVM_VERSION="v0.40.3"
NODE_VERSION="v22.16.0"
NVM_DIR="$HOME/.nvm"
NODE_DIR="$NVM_DIR/versions/node/$NODE_VERSION"

if [ ! -d "$NVM_DIR" ]; then
    echo "Installing nvm $NVM_VERSION..."
    curl -o- "https://raw.githubusercontent.com/nvm-sh/nvm/$NVM_VERSION/install.sh" | bash
fi
# shellcheck source=/dev/null
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

if [ ! -d "$NODE_DIR" ]; then
    echo "Installing Node.js $NODE_VERSION..."
    nvm install "${NODE_VERSION#v}"
fi
nvm use "$NODE_VERSION"

npm ci --omit=dev --prefix userland/ink-login

touch "$NODE_DIR/.setup_done"
