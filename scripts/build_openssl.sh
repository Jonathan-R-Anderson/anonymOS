#!/bin/bash
# Build OpenSSL for AnonymOS

set -e

OPENSSL_VERSION="3.2.0"
OPENSSL_DIR="openssl-${OPENSSL_VERSION}"
OPENSSL_ARCHIVE="${OPENSSL_DIR}.tar.gz"
BUILD_DIR="$(pwd)/build/openssl"
INSTALL_DIR="$(pwd)/lib/openssl"

echo "Building OpenSSL ${OPENSSL_VERSION} for AnonymOS..."

# Create directories
mkdir -p "${BUILD_DIR}"
mkdir -p "${INSTALL_DIR}"

# Download OpenSSL if not present
if [ ! -f "${OPENSSL_ARCHIVE}" ]; then
    echo "Downloading OpenSSL ${OPENSSL_VERSION}..."
    wget "https://www.openssl.org/source/${OPENSSL_ARCHIVE}"
fi

# Extract
if [ ! -d "${BUILD_DIR}/${OPENSSL_DIR}" ]; then
    echo "Extracting OpenSSL..."
    tar -xzf "${OPENSSL_ARCHIVE}" -C "${BUILD_DIR}"
fi

cd "${BUILD_DIR}/${OPENSSL_DIR}"

# Configure for bare-metal x86_64
echo "Configuring OpenSSL..."
./Configure \
    no-shared \
    no-threads \
    no-asm \
    no-async \
    no-engine \
    no-hw \
    no-dso \
    no-ui-console \
    --prefix="${INSTALL_DIR}" \
    --openssldir="${INSTALL_DIR}/ssl" \
    -static \
    -fno-stack-protector \
    -nostdlib \
    -ffreestanding \
    linux-x86_64

# Patch for bare-metal (remove system dependencies)
echo "Patching for bare-metal..."
cat > crypto/rand/rand_unix.c << 'EOF'
#include <openssl/rand.h>

// Bare-metal random number generator using RDRAND
static int get_random_bytes(unsigned char *buf, int num) {
    for (int i = 0; i < num; i += 8) {
        unsigned long long val;
        __asm__ volatile("rdrand %0" : "=r"(val));
        int copy_len = (num - i) > 8 ? 8 : (num - i);
        for (int j = 0; j < copy_len; j++) {
            buf[i + j] = (val >> (j * 8)) & 0xFF;
        }
    }
    return 1;
}

int RAND_poll(void) {
    unsigned char buf[32];
    get_random_bytes(buf, sizeof(buf));
    RAND_add(buf, sizeof(buf), sizeof(buf));
    return 1;
}
EOF

# Build
echo "Building OpenSSL..."
make -j$(nproc)

# Install
echo "Installing OpenSSL..."
make install

echo "OpenSSL built successfully!"
echo "Libraries installed to: ${INSTALL_DIR}"
echo ""
echo "Add to your build script:"
echo "  -I${INSTALL_DIR}/include"
echo "  -L${INSTALL_DIR}/lib"
echo "  -lssl -lcrypto"
