obj-m := blackpill.o
blackpill-y := src/lib.o src/hypervisor/capabilities.o src/hypervisor/hypervisor.o

CC = clang
ARCH ?= x86_64
CORES = $(shell expr $$(nproc) - 1 )

# Use CURDIR, not PWD: under recursive `make -C blackpill` (as the parent
# deps/Makefile invokes it) PWD stays at the caller's dir, so $(PWD)/linux would
# point at the wrong tree. CURDIR always tracks this makefile's directory.
KDIR ?= $(CURDIR)/linux
MDIR ?= $(CURDIR)

THIS_FILE := $(lastword $(MAKEFILE_LIST))

SCRIPTS ?= $(CURDIR)/scripts
VM ?= $(CURDIR)/vm
INSTALL_MOD_PATH ?= $(VM)/rootfs

# Use sudo by default; override with `SUDO=` when running as root (e.g. in a
# Docker build stage) or point it at doas.
SUDO ?= sudo

# Alpine (apk) build toolchain required to configure/compile the Rust-enabled
# kernel and the out-of-tree module.
APK_DEPS := \
	rust \
	rust-src \
	cargo \
	clang \
	llvm \
	lld \
	bindgen \
	linux-headers \
	build-base \
	bash \
	git \
	perl \
	python3 \
	flex \
	bison \
	bc \
	openssl-dev \
	elfutils-dev

.PHONY: all default deps first-time-setup kernel install rust-analyzer clean kdoc open-kdoc vm

default:
	@echo "[+] Compiling module"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) modules EXTRA_CFLAGS="-Wno-unused-function"

# `all` is the entry point the parent deps/Makefile invokes (-C blackpill all),
# matching the convention used by every other subdir. It builds the module;
# the kernel must already be configured/built (run `first-time-setup` once).
all: default

deps:
	@echo "[+] Installing Alpine build dependencies"
	$(SUDO) apk add $(APK_DEPS)

first-time-setup: deps
	@echo "[+] Configuring kernel"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) x86_64_defconfig rust.config

	$(MAKE) -f $(THIS_FILE) kernel
	$(MAKE) -f $(THIS_FILE) rust-analyzer

kernel:
	@echo "[+] Compiling kernel"
	$(MAKE) LLVM=1 ARCH=$(ARCH) CC=$(CC) -C $(KDIR) -j $(CORES)

install:
	@echo "[+] Installing modules"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) modules INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) INSTALL_MOD_STRIP=1 EXTRA_CFLAGS="-Wno-unused-function"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) modules_install INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) INSTALL_MOD_STRIP=1

rust-analyzer:
	@echo "[+] Generating rust-project.json"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) rust-analyzer

clean:
	@echo "[+] Cleaning workspace"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) clean
	rm -rf target/
	rm -rf vm/

kdoc:
	@echo "[+] Generating kernel documentation"
	$(MAKE) LLVM=1 -C $(KDIR) rustdoc

open-kdoc:
	xdg-open $(KDIR)/Documentation/output/rust/rustdoc/kernel/index.html

disk:
	@if [ ! -f $(VM)/disk.img ]; then \
		echo "[-] Disk image doesn't exist"; \
		echo "[+] Creating VM image disk"; \
		$(SCRIPTS)/build_image.sh; \
	else \
		echo "[+] Disk image exists"; \
	fi

vm: disk
	@echo "[+] Launching VM with QEMU"
	$(SCRIPTS)/start_vm.sh | tee $(VM)/start_vm.log

