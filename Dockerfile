FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install dependencies
RUN apt-get update && apt-get install -y \
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
    python \
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
    ldc \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Haskell Stack
RUN curl -sSL https://get.haskellstack.org/ | sh

# Setup global stack environment and install dependencies
WORKDIR /tmp
RUN stack setup && \
    stack install yaml unordered-containers scientific

# Install JHC via modern fork (yobson/jhc-components)
RUN git clone https://github.com/yobson/jhc-components /tmp/jhc-components && \
    cd /tmp/jhc-components && \
    sed -i 's|embed/\*|embed/ChangeLog|g' jhc-common/jhc-common.cabal

COPY src/libs/ext/patches/Typeable.h /tmp/Typeable.h
WORKDIR /tmp/jhc-components

# Download and patch libraries for JHC (using wget to avoid cabal issues)
RUN wget https://hackage.haskell.org/package/deepseq-1.2.0.1/deepseq-1.2.0.1.tar.gz && \
    tar xzf deepseq-1.2.0.1.tar.gz && \
    wget https://hackage.haskell.org/package/containers-0.4.2.1/containers-0.4.2.1.tar.gz && \
    tar xzf containers-0.4.2.1.tar.gz && \
    cp /tmp/Typeable.h containers-0.4.2.1/include/Typeable.h && \
    sed -i '/^[[:space:]]\+{-# INLINE/d' containers-0.4.2.1/Data/Sequence.hs && \
    cp -r deepseq-1.2.0.1/* . && \
    cp -r containers-0.4.2.1/* . && \
    cp -r include lib/ext/
    
RUN sed -i 's/Just nt <- return $ Info.lookup (tvrInfo t)/nt <- maybe (throwError ()) return $ Info.lookup (tvrInfo t)/' jhc-core/src/E/TypeAnalysis.hs && \
    sed -i 's/Just tt <- return $ getTyp (getType t) dataTable nt/tt <- maybe (throwError ()) return $ getTyp (getType t) dataTable nt/' jhc-core/src/E/TypeAnalysis.hs

RUN stack install cpphs --local-bin-path /usr/local/bin && \
    stack install --local-bin-path /usr/local/bin

RUN mkdir -p /usr/local/lib/jhc-0.8.2 && \
    jhc -L . --build-hl lib/jhc-prim/jhc-prim.yaml && \
    jhc -L . --build-hl lib/jhc/jhc.yaml && \
    jhc -L . --build-hl lib/haskell-extras/haskell-extras.yaml && \
    jhc -L . --build-hl lib/haskell2010/haskell2010.yaml && \
    jhc -L . --build-hl lib/haskell98/haskell98.yaml && \
    jhc -L . --build-hl lib/applicative/applicative.yaml && \
    jhc -L . --build-hl lib/ext/deepseq.yaml && \
    jhc -L . --build-hl lib/ext/containers.yaml && \
    jhc -L . --build-hl lib/flat-foreign/flat-foreign.yaml && \
    cp *.hl /usr/local/lib/jhc-0.8.2/ && \
    cd .. && rm -rf jhc-components

# Build Directory
WORKDIR /build

# Build Opts
RUN echo "SRC_ROOT=/build_work/src" > /etc/haskellos_build.opts && \
    echo "BUILD_ROOT=/build_work/build" >> /etc/haskellos_build.opts && \
    echo "CROSSCOMPILE_PREFIX=/usr" >> /etc/haskellos_build.opts && \
    echo "LLVM_PREFIX=/usr/lib/llvm-6.0" >> /etc/haskellos_build.opts && \
    echo "JHC_LIBS_PREFIX=/usr/local/lib/jhc-0.8.2" >> /etc/haskellos_build.opts && \
    echo "JHC=/usr/local/bin/jhc" >> /etc/haskellos_build.opts && \
    echo "" >> /etc/haskellos_build.opts && \
    echo "TARGET=x86_64" >> /etc/haskellos_build.opts && \
    echo "HOST=i386" >> /etc/haskellos_build.opts && \
    echo "" >> /etc/haskellos_build.opts && \
    echo "RTS_INC=-I\$(SRC_ROOT)/libs/rts -I\$(SRC_ROOT)/libs/rts/rts" >> /etc/haskellos_build.opts && \
    echo "CBITS_INC=-I\$(SRC_ROOT)/kernel/c" >> /etc/haskellos_build.opts && \
    echo "PROGS_INC=-I\$(SRC_ROOT)/progs/cbits" >> /etc/haskellos_build.opts && \
    echo "" >> /etc/haskellos_build.opts && \
    echo "CROSSCOMPILE_LD=ld" >> /etc/haskellos_build.opts && \
    echo "CROSSCOMPILE_STRIP=strip" >> /etc/haskellos_build.opts && \
    echo "CROSSCOMPILE_AS=as" >> /etc/haskellos_build.opts && \
    echo "CROSSCOMPILE_AR=ar" >> /etc/haskellos_build.opts && \
    echo "CROSSCOMPILE_CLANG=clang" >> /etc/haskellos_build.opts && \
    echo "XORRISO=xorriso" >> /etc/haskellos_build.opts && \
    echo "DC=ldc2" >> /etc/haskellos_build.opts && \
    echo "CFLAGS_COMMON=-D _JHC_GC=1 -D _JHC_DEBUG=0 -D _JHC_BAREBONES -fno-pic -fno-pie" >> /etc/haskellos_build.opts && \
    echo "JHC_COMMON=-DTARGET=\$(TARGET) -pcontainers -papplicative -fforall" >> /etc/haskellos_build.opts && \
    echo "DFLAGS=-betterC -mtriple=x86_64-unknown-none-elf -m64 -O2" >> /etc/haskellos_build.opts && \
    echo "CFLAGS=-m64 \$(CFLAGS_COMMON) -ffreestanding \$(RTS_INC) \$(CBITS_INC) -include arch.h -include allocator.h -DCOMPILING_HS_KERNEL -mno-red-zone -mcmodel=large -D TARGET=\$(TARGET) -D KERNEL=1 -O2" >> /etc/haskellos_build.opts && \
    echo "CFLAGS_USER=-m64 \$(CFLAGS_COMMON) \$(RTS_INC) \$(CBITS_INC) \$(PROGS_INC) -D TARGET=\$(TARGET) -D HOS_USER=1 -O2" >> /etc/haskellos_build.opts && \
    echo "TEST_CFLAGS=\$(CFLAGS_COMMON) -D TARGET=\$(HOST)" >> /etc/haskellos_build.opts

CMD ["/bin/bash"]
