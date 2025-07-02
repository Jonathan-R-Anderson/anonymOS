#-------------------------------------------------------------
# Makefile – anonymOS (clean, offline-only build)
#-------------------------------------------------------------
#  * Assumes all sub-projects already exist in the working tree.
#  * Never fetches/clones anything – it only builds.
#  * Keeps directory structure in build/obj.
#-------------------------------------------------------------

# ─────────────── Default target ───────────────
.DEFAULT_GOAL := run-log-int

# ─────────────── Toolchain ─────────────────────
DC            ?= ldc2                 # D compiler
AS            ?= as                   # GNU assembler (AT&T syntax)
LD            ?= ld.lld               # LLVM linker
GRUB_MKRESCUE ?= grub-mkrescue
QEMU          ?= qemu-system-x86_64
QEMU_FLAGS    ?= -nographic

# ─────────────── Flags ─────────────────────────
DFLAGS_BASE      = -betterC -O1 -g -boundscheck=off -output-o
DFLAGS_TARGET_64 ?= -mtriple=x86_64-unknown-elf -mcpu=x86-64
# Include paths note: we need both the root of the kernel repo **and** its nested
# "kernel/" folder so single-segment modules like `io` resolve correctly.
DFLAGS           = $(DFLAGS_BASE) $(DFLAGS_TARGET_64) \
                   -I. \
                   -I$(MICROKERNEL_DIR) \
                   -I$(MICROKERNEL_DIR)/kernel \
                   -I$(MICROKERNEL_DIR)/kernel/include \
                   -I$(HYPERVISOR_DIR) \
                   -I$(OBJECT_TREE_DIR)

ASFLAGS  = --64
LDFLAGS  = -nostdlib -no-pie

# ─────────────── Layout ────────────────────────
BUILD_DIR   := build
OBJ_DIR     := $(BUILD_DIR)/obj
ISO_DIR     := $(BUILD_DIR)/iso
ISO_BOOT    := $(ISO_DIR)/boot
ISO_GRUB    := $(ISO_BOOT)/grub
ISO_BIN     := $(ISO_DIR)/bin

KERNEL_BIN  := $(BUILD_DIR)/kernel.bin
ISO_FILE    := $(BUILD_DIR)/anonymOS.iso
FS_IMG      := $(BUILD_DIR)/fs.img

MICROKERNEL_DIR := kernel
HYPERVISOR_DIR  := hypervisor
OBJECT_TREE_DIR := object-tree
LINKER_SCRIPT   := $(MICROKERNEL_DIR)/arch/x86/linker.ld

# ─────────────── Source discovery ──────────────
# We intentionally skip any *\_debug.s files – they are helpers not meant for the final image.
ASM_SOURCES := \
  $(filter-out %_debug.s $(MICROKERNEL_DIR)/arch/x86/cpu/idt.s,$(shell find $(MICROKERNEL_DIR)/arch/x86 -name '*.s')) \
  $(MICROKERNEL_DIR)/kernel/utils/debug_asm.s

KERNEL_D_SOURCES := \
  $(shell find $(MICROKERNEL_DIR) -name '*.d') \
  $(HYPERVISOR_DIR)/kernel/hypervisor.d \
  $(OBJECT_TREE_DIR)/kernel/object_namespace.d \
  $(OBJECT_TREE_DIR)/kernel/object_validator.d

# Generated ANSI-art module
ANSI_ART_SRC := $(MICROKERNEL_DIR)/kernel/utils/artwork.ans
ANSI_ART_D   := $(MICROKERNEL_DIR)/kernel/utils/ansi_art.d

# ─────────────── Object lists ──────────────────
D_OBJS   := $(patsubst %.d,$(OBJ_DIR)/%.o,$(KERNEL_D_SOURCES))
ASM_OBJS := $(patsubst %.s,$(OBJ_DIR)/%.o,$(ASM_SOURCES))
OBJS     := $(D_OBJS) $(ASM_OBJS)

# ─────────────── Phony targets ─────────────────
.PHONY: all iso build clean run run-debug run-log-int fsimg update-run

all: $(ISO_FILE)
iso: all
build: all

# ─────────────── Kernel + ISO ──────────────────
$(KERNEL_BIN): $(OBJS) $(LINKER_SCRIPT) | $(BUILD_DIR)
	$(LD) $(LDFLAGS) -T $(LINKER_SCRIPT) -o $@ $(OBJS)

$(ISO_FILE): $(KERNEL_BIN) $(FS_IMG)
	@echo ">>> Creating ISO image"
	mkdir -p $(ISO_GRUB) $(ISO_BIN)
	cp $(KERNEL_BIN) $(ISO_BOOT)
	cp $(FS_IMG)     $(ISO_DIR)
	# Minimal grub.cfg
	printf '%s\n' \
	  'set timeout=0' \
	  'set default=0' \
	  '' \
	  'menuentry "anonymOS" {' \
	  '  multiboot2 /boot/kernel.bin' \
	  '  boot' \
	  '}' > $(ISO_GRUB)/grub.cfg
	$(GRUB_MKRESCUE) -o $@ $(ISO_DIR)

# ─────────────── Pattern rules ─────────────────
$(OBJ_DIR)/%.o: %.d
	@mkdir -p $(dir $@)
	$(DC) $(DFLAGS) -c $< -of=$@

$(OBJ_DIR)/%.o: %.s
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $< -o $@

# ─────────────── Generated sources ─────────────
$(ANSI_ART_D): $(ANSI_ART_SRC)
	@echo ">>> Generating ANSI art D module"
	@./scripts/generate_ansi_art.sh $< > $@

# ─────────────── Utilities ─────────────────────
$(BUILD_DIR):
	@mkdir -p $@

fsimg: $(FS_IMG)

$(FS_IMG): scripts/build_fs_img.sh $(SH_BIN)
	@bash scripts/build_fs_img.sh

# ─────────────── QEMU helpers ───────────────────
run: $(ISO_FILE)
	$(QEMU) -cdrom $< -m 512M -serial stdio -display none

run-debug: $(ISO_FILE)
	$(QEMU) -cdrom $< $(QEMU_FLAGS) -S -s

run-log-int: $(ISO_FILE)
	$(QEMU) -cdrom $< $(QEMU_FLAGS) -m 512M -display curses -vga std \
	   -d int,guest_errors,cpu_reset -D qemu.log -debugcon file:qemu.log \
	   -serial file:qemu.log -M smm=off -no-reboot

# ─────────────── Shell binary ─────────────────
SH_BIN := $(BUILD_DIR)/bin/sh

$(SH_BIN): scripts/build_sh_bin.sh third_party/stub_shell.d third_party/sh/build_betterc.sh | $(BUILD_DIR)
	@bash scripts/build_sh_bin.sh $@

# Ensure filesystem image depends on shell binary
# $(FS_IMG): $(SH_BIN)

# ─────────────── Convenience target ──────────
update-run: $(ISO_FILE)
	@echo "Build complete – QEMU run skipped in automated environment."

# ─────────────── House-keeping ──────────────────
clean:
	@rm -rf $(BUILD_DIR)

$(D_OBJS): $(ANSI_ART_D)

# User hello binary
HELLO_BIN := $(BUILD_DIR)/bin/hello

$(HELLO_BIN): scripts/build_user_hello.sh | $(BUILD_DIR)
	@bash scripts/build_user_hello.sh

$(FS_IMG): $(HELLO_BIN)

