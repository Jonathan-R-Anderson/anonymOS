# boot/arbiter/Makefile — build the A/B slot-arbiter UEFI app (SYSTEM_UPDATE U1-C).
# Same self-contained clang PE target + lld-link recipe as deps/veracrypt/efi (no gnu-efi,
# no libc). Output: build/arbiter.efi — staged into the installer's ESP-boot partition.
PROJECT_ROOT ?= $(abspath ../..)
BLD := $(PROJECT_ROOT)/build
CFLAGS := -target x86_64-unknown-windows -ffreestanding -fshort-wchar -mno-red-zone -O2
# lld-link — the PE/COFF lld driver; falls back to the Rust toolchain's bundled
# rust-lld (same multiplexed binary; the lld-link name selects the COFF driver).
LLD_LINK := $(shell command -v lld-link 2>/dev/null || { \
  rld="`command -v rust-lld 2>/dev/null || ls $(HOME)/.rustup/toolchains/*/lib/rustlib/*/bin/rust-lld 2>/dev/null | head -1`"; \
  if [ -n "$$rld" ]; then d=$(PROJECT_ROOT)/build/lld-shim; mkdir -p "$$d"; ln -sf "$$rld" "$$d/lld-link"; echo "$$d/lld-link"; fi; })

.PHONY: all clean
all: $(BLD)/arbiter.efi

$(BLD)/arbiter.efi: efi_arbiter.c | $(BLD)
	clang $(CFLAGS) -c efi_arbiter.c -o $(BLD)/efi_arbiter.o
	$(LLD_LINK) -subsystem:efi_application -entry:efi_main -nodefaultlib \
	    $(BLD)/efi_arbiter.o -out:$(BLD)/arbiter.efi
	@echo "[arbiter] built $(BLD)/arbiter.efi"; file $(BLD)/arbiter.efi

$(BLD):
	@mkdir -p $(BLD)

clean:
	rm -f $(BLD)/efi_arbiter.o $(BLD)/arbiter.efi
