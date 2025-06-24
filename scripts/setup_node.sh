#!/bin/bash
set -e
DEST_DIR="$1"
NODE_VERSION="v18.20.0"
NODE_DIST="node-${NODE_VERSION}-linux-x64"
NODE_TAR="${NODE_DIST}.tar.xz"
NODE_URL="https://nodejs.org/dist/${NODE_VERSION}/${NODE_TAR}"
NODE_PATH="${DEST_DIR}/${NODE_DIST}"

mkdir -p "$DEST_DIR"
if [ ! -d "$NODE_PATH" ]; then
    echo "Downloading Node.js ${NODE_VERSION}..."
    curl -L "$NODE_URL" -o "$DEST_DIR/${NODE_TAR}"
    tar -xf "$DEST_DIR/${NODE_TAR}" -C "$DEST_DIR"
fi

# Install login dependencies using the downloaded Node/npm
"${NODE_PATH}/bin/npm" ci --omit=dev --prefix userland/ink-login

touch "${NODE_PATH}/.setup_done"
