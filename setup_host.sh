#!/bin/bash
set -e

# setup_host.sh
# Replicates the build environment setup from Dockerfile on the local host.

echo "Setting up Host Environment..."

# 1. Install System Dependencies
echo "[1/6] Installing System Dependencies..."
# apt-get might fail due to unrelated system issues (kernel modules, etc).
# We try to install, but don't exit on failure if the tools are already present.
set +e
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    git \
    wget \
    curl \
    clang \
    lld \
    llvm \
    xorriso \
    ghc \
    cabal-install \
    libncurses5-dev \
    m4 \
    python3 \
    python3-pip \
    ca-certificates \
    libghc-zlib-dev \
    libghc-utf8-string-dev \
    libghc-syb-dev \
    libghc-fgl-dev \
    libghc-random-dev \
    libghc-old-time-dev \
    libghc-regex-compat-dev \
    libghc-hashtables-dev \
    alex \
    happy \
    isolinux \
    syslinux-common \
    ldc
APT_EXIT_CODE=$?
set -e

if [ $APT_EXIT_CODE -ne 0 ]; then
    echo "Warning: apt-get failed with code $APT_EXIT_CODE. Checking for required tools..."
    # Check for critical tools
    REQUIRED_TOOLS="make git wget curl clang lld llvm-config xorriso ghc cabal stack ldc2"
    MISSING_TOOLS=""
    for tool in $REQUIRED_TOOLS; do
        if ! command -v $tool &> /dev/null; then
            MISSING_TOOLS="$MISSING_TOOLS $tool"
        fi
    done
    
    if [ -n "$MISSING_TOOLS" ]; then
        echo "Error: The following required tools are missing and apt-get failed to install them:"
        echo "  $MISSING_TOOLS"
        exit 1
    else
        echo "All required tools are present. Proceeding..."
    fi
fi

# 2. Install Haskell Stack
echo "[2/6] Installing Haskell Stack..."
if ! command -v stack &> /dev/null; then
    curl -sSL https://get.haskellstack.org/ | sh
fi
stack setup
stack install yaml unordered-containers scientific

# 3. Build JHC
echo "[3/6] Building JHC Compiler..."
WORK_DIR=$(pwd)/tools_build
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

if [ ! -d "jhc-components" ]; then
    git clone https://github.com/yobson/jhc-components
fi
cd jhc-components

# Patch jhc-common
sed -i 's|embed/\*|embed/ChangeLog|g' jhc-common/jhc-common.cabal

# Copy Typeable.h
# Assumes we are running from project root
PROJECT_ROOT=$(dirname "$WORK_DIR")
cp "$PROJECT_ROOT/src/libs/ext/patches/Typeable.h" .

# Download and patch libraries
echo "Downloading dependencies..."
if [ ! -f "deepseq-1.2.0.1.tar.gz" ]; then
    wget https://hackage.haskell.org/package/deepseq-1.2.0.1/deepseq-1.2.0.1.tar.gz
    tar xzf deepseq-1.2.0.1.tar.gz
fi
if [ ! -f "containers-0.4.2.1.tar.gz" ]; then
    wget https://hackage.haskell.org/package/containers-0.4.2.1/containers-0.4.2.1.tar.gz
    tar xzf containers-0.4.2.1.tar.gz
fi

cp Typeable.h containers-0.4.2.1/include/Typeable.h
sed -i '/^[[:space:]]\+{-# INLINE/d' containers-0.4.2.1/Data/Sequence.hs
cp -r deepseq-1.2.0.1/* .
cp -r containers-0.4.2.1/* .
cp -r include lib/ext/

# Patch jhc-core
echo "Patching jhc-core..."
sed -i 's/Just nt <- return $ Info.lookup (tvrInfo t)/nt <- maybe (throwError ()) return $ Info.lookup (tvrInfo t)/' jhc-core/src/E/TypeAnalysis.hs
sed -i 's/Just tt <- return $ getTyp (getType t) dataTable nt/tt <- maybe (throwError ()) return $ getTyp (getType t) dataTable nt/' jhc-core/src/E/TypeAnalysis.hs

# Install cpphs and jhc
echo "Installing cpphs and jhc..."
stack install cpphs
stack install

# Move binaries to /usr/local/bin
JHC_BIN=$(stack path --local-bin)/jhc
CPPHS_BIN=$(stack path --local-bin)/cpphs

if [ -f "$JHC_BIN" ]; then
    echo "Installing jhc to /usr/local/bin..."
    sudo cp "$JHC_BIN" /usr/local/bin/jhc
fi

if [ -f "$CPPHS_BIN" ]; then
    echo "Installing cpphs to /usr/local/bin..."
    sudo cp "$CPPHS_BIN" /usr/local/bin/cpphs
fi

# 4. Build JHC Libraries
echo "[4/6] Building JHC Libraries..."
# Setup target directory
sudo mkdir -p /usr/local/lib/jhc-0.8.2
sudo chown -R $USER /usr/local/lib/jhc-0.8.2

jhc -L . --build-hl lib/jhc-prim/jhc-prim.yaml
jhc -L . --build-hl lib/jhc/jhc.yaml
jhc -L . --build-hl lib/haskell-extras/haskell-extras.yaml
jhc -L . --build-hl lib/haskell2010/haskell2010.yaml
jhc -L . --build-hl lib/haskell98/haskell98.yaml
jhc -L . --build-hl lib/applicative/applicative.yaml
jhc -L . --build-hl lib/ext/deepseq.yaml
jhc -L . --build-hl lib/ext/containers.yaml
jhc -L . --build-hl lib/flat-foreign/flat-foreign.yaml

echo "Installing HL files..."
cp *.hl /usr/local/lib/jhc-0.8.2/

# 5. Env Config
echo "[5/6] Generating build.opts..."
cd "$PROJECT_ROOT"

# Detect LLVM Prefix
LLVM_PREFIX=$(llvm-config --prefix 2>/dev/null || echo "/usr")
echo "Detected LLVM Prefix: $LLVM_PREFIX"

cat > build.opts <<EOF
# Project Structure
SRC_ROOT=\$(PROJECT_ROOT)/src
BUILD_ROOT=\$(PROJECT_ROOT)/build

# Host Configuration
CROSSCOMPILE_PREFIX=/usr
LLVM_PREFIX=$LLVM_PREFIX

# Tools
CROSSCOMPILE_LD=ld
CROSSCOMPILE_STRIP=strip
CROSSCOMPILE_AS=as
CROSSCOMPILE_AR=ar
CROSSCOMPILE_CLANG=clang
XORRISO=xorriso
DC=ldc2

# JHC Configuration
JHC=jhc
JHC_LIBS_PREFIX=/usr/local/lib/jhc-0.8.2

TARGET=x86_64
HOST=i386

# Include Paths
RTS_INC=-I\$(SRC_ROOT)/libs/rts -I\$(SRC_ROOT)/libs/rts/rts
CBITS_INC=-I\$(SRC_ROOT)/kernel/d
PROGS_INC=-I\$(SRC_ROOT)/progs/cbits -I\$(SRC_ROOT)/progs/hos

CFLAGS_COMMON=-D _JHC_GC=1 -D _JHC_DEBUG=0 -D _JHC_BAREBONES -fno-pic -fno-pie
JHC_COMMON=-DTARGET=\$(TARGET) -pcontainers -papplicative -fforall
DFLAGS=-betterC -mtriple=x86_64-unknown-none-elf -m64 -O2 -code-model=large

# Kernel CFLAGS
KERNEL_CFLAGS=-m64 \$(CFLAGS_COMMON) -ffreestanding \$(RTS_INC) \$(CBITS_INC) -include d_exports.h -DCOMPILING_HS_KERNEL -mno-red-zone -mcmodel=large -D TARGET=\$(TARGET) -D KERNEL=1 -O2

# User CFLAGS
USER_CFLAGS=-m64 \$(CFLAGS_COMMON) \$(RTS_INC) \$(PROGS_INC) -include hos.h -D TARGET=\$(TARGET) -D HOS_USER=1 -O2

TEST_CFLAGS=\$(CFLAGS_COMMON) -D TARGET=\$(HOST)
EOF

echo "[6/6] Cleanup..."
# rm -rf "$WORK_DIR" # Optional: keep for debugging

echo "Host Environment Setup Complete!"
echo "Run 'make' to build the kernel."
