# ==========================================================================
# deps/veracrypt/Makefile  —  roadmap/INSTALLER.md §E1
#
# Strip the vendored VeraCrypt (../VeraCrypt) down to ONLY the decoy/hidden-OS
# DISK-ENCRYPTION subset and cross-build it static against musl-clang.  E1 starts
# with the crypto core (the ciphers + hashes the system-encryption header/KDF use);
# E1b adds the volume-header + hidden-OS layout; everything else in VeraCrypt (the
# wxWidgets GUI, file containers, the Windows driver, Format/Setup/COM/PKCS11) is
# NOT compiled — "strip" = build only this curated file list.
#
# Output:  sysroot/lib/libvc_crypto.a  (+ headers usable from ../VeraCrypt/src/Crypto)
# ==========================================================================
PROJECT_ROOT ?= $(abspath ../..)
include $(PROJECT_ROOT)/build.opts

SELF    := $(abspath .)
VCSRC   := $(abspath ../VeraCrypt/src)
MUSL    := $(abspath ../musl/install)
CC      := $(MUSL)/bin/musl-clang
AR      := llvm-ar
RANLIB  := llvm-ranlib
SYSROOT := $(SELF)/sysroot
BLD     := $(SELF)/build

# The stripped crypto subset — portable, software-only C (no hw-asm, no SSE/AVX/NEON
# variants, no GUI/OS code).  Confirmed to cross-compile clean against musl with no
# porting defines.  (Camellia/blake2s have minor include quirks; PBKDF2/Pkcs5 pulls in
# Argon2 — both deferred to E2 when the KDF + header are wired.)
CRYPTO_C := Aescrypt Aeskey Aestab Serpent SerpentFast Twofish kuznyechik \
            Sha2 Whirlpool Streebog
CRYPTO_O := $(addprefix $(BLD)/, $(addsuffix .o, $(CRYPTO_C)))

# CRYPTOPP_DISABLE_ASM → NO_OPTIMIZED_VERSIONS: the pure-C transforms, no hw-asm refs and
# no CPU-feature dispatch (so cpu.c / the *_hw / *_simd / *Intel variants aren't needed).
# (Avoid VeraCrypt's _UEFI mode here — it pulls in the EDK2 <Uefi.h> headers.)
VC_CFLAGS := -O2 -DNDEBUG -DCRYPTOPP_DISABLE_ASM -fPIC -I$(VCSRC) -I$(VCSRC)/Crypto

RUN := $(BUILD_RESOURCE_RUN)

.PHONY: all crypto test clean
all: crypto

$(BLD) $(SYSROOT)/lib:
	@mkdir -p $@

$(BLD)/%.o: $(VCSRC)/Crypto/%.c | $(BLD)
	$(CC) -c $(VC_CFLAGS) $< -o $@

crypto: $(SYSROOT)/lib/libvc_crypto.a
$(SYSROOT)/lib/libvc_crypto.a: $(CRYPTO_O) | $(SYSROOT)/lib
	$(AR) rcs $@ $(CRYPTO_O)
	$(RANLIB) $@
	@echo "[veracrypt] libvc_crypto.a built ($$(llvm-nm $@ 2>/dev/null | grep -c ' T ') T symbols)"

# Known-answer test: link the stripped crypto + run NIST AES-256 + SHA-512 vectors.
# musl -static → the binary runs directly on the build host.
test: crypto | $(BLD)
	$(CC) -static -no-pie $(VC_CFLAGS) $(SELF)/test/kat.c \
	    -L$(SYSROOT)/lib -lvc_crypto -o $(BLD)/vc-kat
	$(BLD)/vc-kat

# §E2 — the VeraCrypt volume-header engine on the KAT'd crypto: round-trip + hidden-volume
# deniability. -I$(SELF) so vcheader.h resolves.
header-test: crypto | $(BLD)
	$(CC) -static -no-pie $(VC_CFLAGS) -I$(SELF) \
	    $(SELF)/vcheader.c $(SELF)/test/header_test.c \
	    -L$(SYSROOT)/lib -lvc_crypto -o $(BLD)/vc-header
	$(BLD)/vc-header

# §E2b — cross-validate a KERNEL-written header (on a disk image) vs the host reference.
# Builds the checker; run it as: build/vc-parity <disk-image> [lba]
parity-check: crypto | $(BLD)
	$(CC) -static -no-pie $(VC_CFLAGS) -I$(SELF) \
	    $(SELF)/vcheader.c $(SELF)/test/parity_check.c \
	    -L$(SYSROOT)/lib -lvc_crypto -o $(BLD)/vc-parity
	@echo "[veracrypt] built $(BLD)/vc-parity — run: $(BLD)/vc-parity <disk-image> [lba]"

clean:
	rm -rf $(BLD) $(SYSROOT)
