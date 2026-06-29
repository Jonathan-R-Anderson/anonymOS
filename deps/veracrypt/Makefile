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

.PHONY: all crypto test header-test parity-check layout-check volume-check preboot-check efi cryptdisk mkinstall clean
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

# §E3 — validate the kernel-written decoy/hidden encrypted LAYOUT on a disk image.
layout-check: crypto | $(BLD)
	$(CC) -static -no-pie $(VC_CFLAGS) -I$(SELF) \
	    $(SELF)/vcheader.c $(SELF)/test/layout_check.c \
	    -L$(SYSROOT)/lib -lvc_crypto -o $(BLD)/vc-layout
	@echo "[veracrypt] built $(BLD)/vc-layout — run: $(BLD)/vc-layout <disk-image>"

# §E4a — validate the kernel's multi-sector volume DATA encryption + random free-fill.
volume-check: crypto | $(BLD)
	$(CC) -static -no-pie $(VC_CFLAGS) -I$(SELF) \
	    $(SELF)/vcheader.c $(SELF)/test/volume_check.c \
	    -L$(SYSROOT)/lib -lvc_crypto -lm -o $(BLD)/vc-volume
	@echo "[veracrypt] built $(BLD)/vc-volume — run: $(BLD)/vc-volume <disk-image>"

# §E4c — encrypt a REAL rootfs (the §H1 decoy Linux) into a VeraCrypt volume + round-trip.
#   make veracrypt cryptdisk ROOTFS=deps/decoy-os/build/decoy-rootfs.tar.gz
ROOTFS ?= $(abspath ../decoy-os/build/decoy-rootfs.tar.gz)
cryptdisk: crypto | $(BLD)
	$(CC) -static -no-pie $(VC_CFLAGS) -I$(SELF) \
	    $(SELF)/vcheader.c $(SELF)/test/cryptdisk.c \
	    -L$(SYSROOT)/lib -lvc_crypto -o $(BLD)/vc-cryptdisk
	$(BLD)/vc-cryptdisk $(ROOTFS) decoy-password

# §E7/F2 — assemble a FULL deniable install (GPT + ESP + fully-encrypted system + fully-
# random outer) and prove the entropy map is featureless.
mkinstall: crypto | $(BLD)
	$(CC) -static -no-pie $(VC_CFLAGS) -I$(SELF) \
	    $(SELF)/vcheader.c $(SELF)/test/mkinstall.c \
	    -L$(SYSROOT)/lib -lvc_crypto -o $(BLD)/vc-mkinstall
	@dd if=/dev/zero of=$(BLD)/install.img bs=1M count=512 status=none
	@sgdisk --clear -n 1:0:+64M -t 1:EF00 -n 2:0:+64M -t 2:0700 -n 3:0:0 -t 3:0700 $(BLD)/install.img >/dev/null
	@# fill the ACTUAL partition regions (query the GPT, don't hardcode — keeps F2/H3 consistent)
	@set -e; img=$(BLD)/install.img; \
	  sL=$$(sgdisk -i 2 $$img | awk '/First sector/{print $$3}'); \
	  sS=$$(sgdisk -i 2 $$img | awk '/Partition size/{print $$3}'); \
	  oL=$$(sgdisk -i 3 $$img | awk '/First sector/{print $$3}'); \
	  oS=$$(sgdisk -i 3 $$img | awk '/Partition size/{print $$3}'); \
	  $(BLD)/vc-mkinstall $$img $(ROOTFS) decoy-password $$sL $$sS $$oL $$oS; \
	  echo "--- §F2 entropy map (encrypted partitions must be featureless) ---"; \
	  python3 $(SELF)/test/entropy_scan.py $$img $$sL $$sS $$oL $$oS; \
	  free=$$(sgdisk -p $$img | awk '/Total free space/{print $$5}'); \
	  echo "--- §H3 disk-illusion: $$free sectors free ($$(($$free/2048)) MiB) = normal 1MiB alignment, no partition-sized gap ---"

# §E5 — validate the pre-boot authenticator (decoy vs hidden routing) on a disk image.
preboot-check: crypto | $(BLD)
	$(CC) -static -no-pie $(VC_CFLAGS) -I$(SELF) \
	    $(SELF)/vcheader.c $(SELF)/preboot_auth.c $(SELF)/test/preboot_check.c \
	    -L$(SYSROOT)/lib -lvc_crypto -o $(BLD)/vc-preboot
	@echo "[veracrypt] built $(BLD)/vc-preboot — run: $(BLD)/vc-preboot <disk-image>"

# §E5b — the pre-boot loader as a real UEFI app (PE32+), via clang's PE target + lld-link
# (no gnu-efi needed). Self-contained crypto (efi/efi_vc.c) — no libc/VeraCrypt headers.
EFI      := $(SELF)/efi
EFI_CFLAGS := -target x86_64-unknown-windows -ffreestanding -fshort-wchar -mno-red-zone -O2 -I$(EFI)
efi: | $(BLD)
	clang $(EFI_CFLAGS) -c $(EFI)/efi_main.c -o $(BLD)/efi_main.o
	clang $(EFI_CFLAGS) -c $(EFI)/efi_vc.c   -o $(BLD)/efi_vc_pe.o
	lld-link -subsystem:efi_application -entry:efi_main -nodefaultlib \
	    $(BLD)/efi_main.o $(BLD)/efi_vc_pe.o -out:$(BLD)/preboot.efi
	clang $(EFI_CFLAGS) -c $(EFI)/efi_stage2.c -o $(BLD)/efi_stage2.o
	lld-link -subsystem:efi_application -entry:efi_main -nodefaultlib \
	    $(BLD)/efi_stage2.o -out:$(BLD)/stage2.efi
	@echo "[veracrypt] built $(BLD)/preboot.efi + $(BLD)/stage2.efi"; file $(BLD)/preboot.efi

clean:
	rm -rf $(BLD) $(SYSROOT)
