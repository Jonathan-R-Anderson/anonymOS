#!/usr/bin/env bash
set -euo pipefail

# Build mbedTLS for AnonymOS kernel
# This script downloads and builds mbedTLS as a static library for freestanding environment

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT="${ROOT:-$SCRIPT_DIR/..}"
cd "$ROOT"

MBEDTLS_VERSION="${MBEDTLS_VERSION:-3.5.1}"
MBEDTLS_DIR="$ROOT/3rdparty/mbedtls"
BUILD_DIR="$ROOT/build/mbedtls"
INSTALL_DIR="$ROOT/build/toolchain/sysroot/usr"

echo "[*] Building mbedTLS ${MBEDTLS_VERSION} for kernel..."

# Download mbedTLS if not present
if [ ! -d "$MBEDTLS_DIR" ]; then
    echo "[*] Downloading mbedTLS..."
    mkdir -p "$ROOT/3rdparty"
    cd "$ROOT/3rdparty"
    
    if command -v wget > /dev/null; then
        wget "https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v${MBEDTLS_VERSION}.tar.gz" -O mbedtls.tar.gz
    elif command -v curl > /dev/null; then
        curl -L "https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v${MBEDTLS_VERSION}.tar.gz" -o mbedtls.tar.gz
    else
        echo "[!] Neither wget nor curl found. Please install one." >&2
        exit 1
    fi
    
    tar xzf mbedtls.tar.gz
    mv "mbedtls-${MBEDTLS_VERSION}" mbedtls
    rm mbedtls.tar.gz
    
    cd "$ROOT"
fi

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure mbedTLS for freestanding environment
cat > config.h << 'EOF'
/* Minimal mbedTLS configuration for freestanding kernel */

/* System support */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

/* Crypto primitives */
#define MBEDTLS_AES_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C

/* Public key crypto */
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C

/* X.509 */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

/* TLS */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2

/* Ciphersuites */
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_PKCS1_V15

/* Disable filesystem */
#undef MBEDTLS_FS_IO

/* Disable threading */
#undef MBEDTLS_THREADING_C

/* Disable time */
#undef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE

/* Disable dynamic allocation (we'll provide custom allocator) */
#define MBEDTLS_PLATFORM_STD_CALLOC   kernel_calloc
#define MBEDTLS_PLATFORM_STD_FREE     kernel_free

EOF

# Copy config to mbedtls include
cp config.h "$MBEDTLS_DIR/include/mbedtls/mbedtls_config.h"

# Compiler flags for freestanding
CFLAGS="-fno-stack-protector -fno-pic -mno-red-zone -mcmodel=kernel -ffreestanding -nostdlib -O2"
CFLAGS="$CFLAGS -DMBEDTLS_CONFIG_FILE='<mbedtls/mbedtls_config.h>'"
CFLAGS="$CFLAGS -I$MBEDTLS_DIR/include"

# Build mbedTLS
echo "[*] Compiling mbedTLS..."

# Collect source files
SOURCES=(
    "$MBEDTLS_DIR/library/aes.c"
    "$MBEDTLS_DIR/library/sha256.c"
    "$MBEDTLS_DIR/library/sha512.c"
    "$MBEDTLS_DIR/library/md.c"
    "$MBEDTLS_DIR/library/cipher.c"
    "$MBEDTLS_DIR/library/cipher_wrap.c"
    "$MBEDTLS_DIR/library/ctr_drbg.c"
    "$MBEDTLS_DIR/library/entropy.c"
    "$MBEDTLS_DIR/library/rsa.c"
    "$MBEDTLS_DIR/library/bignum.c"
    "$MBEDTLS_DIR/library/oid.c"
    "$MBEDTLS_DIR/library/asn1parse.c"
    "$MBEDTLS_DIR/library/asn1write.c"
    "$MBEDTLS_DIR/library/pk.c"
    "$MBEDTLS_DIR/library/pk_wrap.c"
    "$MBEDTLS_DIR/library/pkparse.c"
    "$MBEDTLS_DIR/library/x509.c"
    "$MBEDTLS_DIR/library/x509_crt.c"
    "$MBEDTLS_DIR/library/ssl_tls.c"
    "$MBEDTLS_DIR/library/ssl_cli.c"
    "$MBEDTLS_DIR/library/ssl_msg.c"
    "$MBEDTLS_DIR/library/platform.c"
    "$MBEDTLS_DIR/library/platform_util.c"
)

OBJECTS=()

for src in "${SOURCES[@]}"; do
    if [ ! -f "$src" ]; then
        echo "[!] Warning: Source file not found: $src"
        continue
    fi
    
    obj="$(basename "${src%.c}").o"
    echo "  Compiling $(basename "$src")..."
    clang $CFLAGS -c "$src" -o "$obj"
    OBJECTS+=("$obj")
done

# Create static library
echo "[*] Creating libmbedtls.a..."
if command -v llvm-ar > /dev/null; then
    llvm-ar rcs libmbedtls.a "${OBJECTS[@]}"
else
    ar rcs libmbedtls.a "${OBJECTS[@]}"
fi

# Install
echo "[*] Installing to sysroot..."
mkdir -p "$INSTALL_DIR/lib"
mkdir -p "$INSTALL_DIR/include"

cp libmbedtls.a "$INSTALL_DIR/lib/"
cp -r "$MBEDTLS_DIR/include/mbedtls" "$INSTALL_DIR/include/"

echo "[✓] mbedTLS built and installed successfully"
echo "    Library: $INSTALL_DIR/lib/libmbedtls.a"
echo "    Headers: $INSTALL_DIR/include/mbedtls/"
