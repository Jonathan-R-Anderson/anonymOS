# =========================================================
# Project Setup
# =========================================================

PROJECT_ROOT := $(CURDIR)
export PROJECT_ROOT

include build.opts

.PHONY: all clean progs-haskell deps-core deps-desktop deps-hyprland
.NOTPARALLEL:

# =========================================================
# Main Build
# =========================================================

all:
	@echo "==== Build Start ===="

	$(MAKE) -j1 build/libkernel_d.a
	$(MAKE) -j1 kernel.elf
	$(MAKE) -j1 hos.iso

	@echo ""
	@echo "✅ Build complete!"

# =========================================================
# D Kernel
# =========================================================

build/libkernel_d.a:
	@echo "==== Building D Kernel ===="
	+$(MAKE) -j1 -C src/kernel/d

# =========================================================
# Kernel Link
# =========================================================

kernel.elf: \
	build/libkernel_d.a \
	src/kernel/d/linker.ld

	@echo "==== Linking Kernel ===="

	$(CROSSCOMPILE_LD) \
		-T src/kernel/d/linker.ld \
		--whole-archive build/libkernel_d.a \
		--no-whole-archive \
		-o kernel.elf

# =========================================================
# ISO Build
# =========================================================

BUSYBOX_BIN   := deps/busybox/busybox
TEST_DRM_BIN  := build/test-drm
COMPOSITOR_BIN := build/compositor
HELLO_GUI_BIN := build/hello-gui
HYPRLAND_BIN := deps/hyprland/Hyprland

FREESTANDING_CFLAGS := -static -nostdlib -nostartfiles -fno-stack-protector \
	-fno-pic -fno-pie -m64 -O2 -e _start

$(TEST_DRM_BIN): src/util/test-drm.c
	@echo "==== Building test-drm ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

$(COMPOSITOR_BIN): src/util/compositor.c
	@echo "==== Building compositor ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

$(HELLO_GUI_BIN): src/util/hello-gui.c
	@echo "==== Building hello-gui ===="
	gcc $(FREESTANDING_CFLAGS) -o $@ $<

hos.iso: kernel.elf $(BUSYBOX_BIN) $(TEST_DRM_BIN) $(COMPOSITOR_BIN) $(HELLO_GUI_BIN) $(wildcard $(HYPRLAND_BIN))
	@echo "==== Building ISO ===="

	rm -rf cd
	mkdir -p cd/boot/limine

	cp kernel.elf cd/boot/kernel.elf

	cp src/boot/limine.conf \
		cd/boot/limine/limine.conf

	cp src/boot/limine-bios.sys \
		src/boot/limine-bios-cd.bin \
		src/boot/limine-uefi-cd.bin \
		cd/boot/limine/

	@if [ -f $(BUSYBOX_BIN) ]; then \
		cp $(BUSYBOX_BIN) cd/busybox; \
		echo "Included busybox"; \
	else \
		echo "❌ busybox missing — run: make deps"; \
	fi

	cp $(TEST_DRM_BIN) cd/test-drm
	@echo "Included test-drm"

	cp $(COMPOSITOR_BIN) cd/compositor
	@echo "Included compositor"

	cp $(HELLO_GUI_BIN) cd/hello-gui
	@echo "Included hello-gui"

	@if [ -n "$(DYNTEST)" ] && [ -f src/test-dyn/dyntest ]; then \
		cp src/test-dyn/dyntest cd/dyntest; \
		cp src/test-dyn/libfoo.so cd/libfoo.so; \
		cp deps/musl/install/lib/libc.so cd/ld-musl-x86_64.so.1; \
		printf '\n    module_path: boot():/dyntest\n    module_path: boot():/libfoo.so\n    module_path: boot():/ld-musl-x86_64.so.1\n' >> cd/boot/limine/limine.conf; \
		echo "Included dynamic-linker test (make DYNTEST=1) — dyntest overrides init"; \
	fi

	@if [ -f $(HYPRLAND_BIN) ]; then \
		cp $(HYPRLAND_BIN) cd/Hyprland; \
		cp deps/musl/install/lib/libc.so cd/ld-musl-x86_64.so.1; \
		cp deps/gtk-stack/sysroot/lib/dri/kms_swrast_dri.so cd/kms_swrast_dri.so; \
		printf '\n    module_path: boot():/Hyprland\n    module_path: boot():/ld-musl-x86_64.so.1\n    module_path: boot():/kms_swrast_dri.so\n' >> cd/boot/limine/limine.conf; \
		echo "Included Hyprland (dynamic) + ld-musl + kms_swrast_dri.so"; \
	else \
		echo "Hyprland not built — run: make deps-hyprland"; \
	fi

	$(XORRISO) -as mkisofs \
		-b boot/limine/limine-bios-cd.bin \
		-no-emul-boot \
		-boot-load-size 4 \
		-boot-info-table \
		--efi-boot boot/limine/limine-uefi-cd.bin \
		-efi-boot-part \
		--efi-boot-image \
		--protective-msdos-label \
		cd \
		-o hos.iso

# =========================================================
# Legacy: Haskell userspace programs (optional, not part of main build)
# =========================================================

progs-haskell: \
	build/librts.a \
	build/prog-libs/hos-common-0.0.1.hl

	@echo "==== Building Haskell Userspace Programs ===="
	+$(MAKE) -j1 -C src/progs

deps-core:
	+$(MAKE) $(MAKE_BUILD_FLAGS) -C deps core

deps-desktop:
	+$(MAKE) $(MAKE_BUILD_FLAGS) -C deps desktop

deps-hyprland:
	+$(MAKE) $(MAKE_BUILD_FLAGS) -C deps hyprland

build/librts.a:
	@echo "==== Building JHC RTS ===="
	+$(MAKE) -j1 -C src/libs/rts

build/prog-libs/hos-common-0.0.1.hl:
	@echo "==== Building JHC Common Library ===="
	+$(MAKE) -j1 -C src/libs/common

# =========================================================
# Cleanup
# =========================================================

clean:
	@echo "==== Cleaning ===="

	rm -rf \
		build \
		cd \
		hos.iso \
		kernel.elf
