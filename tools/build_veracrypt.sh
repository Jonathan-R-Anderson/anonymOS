#!/bin/bash
set -e

# Directory containing VeraCrypt source
VC_ROOT="3rdparty/veracrypt/src"
OUT_DIR="build/veracrypt"

mkdir -p "$OUT_DIR"

# C Flags
# -DTC_MINIMIZE_CODE_SIZE: Optimize for size
# -DTC_NO_COMPILER_INT64: Avoid 64-bit compiler intrinsics if possible (though we are 64-bit)
# -D_WIN32: Some files might expect this, but we should avoid it if possible.
# -DLITTLE_ENDIAN: We are x86_64
CFLAGS="-I$VC_ROOT -I$VC_ROOT/Common -I$VC_ROOT/Crypto -O2 -fPIC -DTC_MINIMIZE_CODE_SIZE -DLITTLE_ENDIAN -DCRYPTOPP_DISABLE_ASM"

# Source files to compile (Crypto)
SOURCES=(
    "$VC_ROOT/Crypto/Aescrypt.c"
    "$VC_ROOT/Crypto/Aeskey.c"
    "$VC_ROOT/Crypto/Aestab.c"
    "$VC_ROOT/Crypto/Twofish.c"
    "$VC_ROOT/Crypto/Serpent.c"
    "$VC_ROOT/Crypto/Sha2Small.c"
)

# Compile each file
OBJECTS=""
for src in "${SOURCES[@]}"; do
    obj="$OUT_DIR/$(basename "${src%.*}").o"
    echo "Compiling $src..."
    
    gcc $CFLAGS -c "$src" -o "$obj"
    OBJECTS="$OBJECTS $obj"
done

# Create static library
ar rcs "$OUT_DIR/libveracrypt_crypto.a" $OBJECTS

echo "Created $OUT_DIR/libveracrypt_crypto.a"
