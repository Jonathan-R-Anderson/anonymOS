# Makefile for Minimal D OS
.DEFAULT_GOAL := run-log-int

		# Tools
		DC = ldc2           # D Compiler
		AS = as             # GNU Assembler (for AT&T syntax)
	LD = ld.lld         # LLVM Linker
	GRUB_MKRESCUE = grub-mkrescue
	
	# D Compiler Flags
	# -betterC: Enables D subset suitable for freestanding environments (no GC, no DRuntime)
	# -mtriple=x86_64-unknown-elf: Target a 64-bit ELF environment
	# -mcpu=x86-64: Generic 64-bit CPU. Adjust if specific features are needed.
	# -O1: Basic optimizations
	# -g: Debug symbols (optional, but helpful)
	# -output-o: Ensures .o file is output (LDC specific)
	# -I.: Include current directory for imports (if any local modules were used) -disable-asserts: Disable runtime asserts
	DFLAGS_BASE = -betterC -O1 -g -boundscheck=off -output-o
       DFLAGS_TARGET_32 ?= -mtriple=i386-unknown-elf -mcpu=pentium4
       # When using a cross compiler, the target triple is often built-in, so
       # allow overriding this variable to blank it: `make DFLAGS_TARGET_64=""`.
       DFLAGS_TARGET_64 ?= -mtriple=x86_64-unknown-elf -mcpu=x86-64 # Target 64-bit

# Assembler Flags
ASFLAGS = --64 # Tell GNU AS to assemble for 64-bit mode. elf64 is usually inferred.

	# Linker Flags
	# For LLD:
	# --verbose can be removed, LLD is usually informative on errors.
	LDFLAGS = -nostdlib -no-pie # -m elf_x86_64 might be needed if not inferred by lld from object files
	
	# Update DFLAGS for the new directory structure and D module conventions
	# -I. allows `import kernel.core.module;`
	# -Ikernel/include allows `import kernel.types;` for `kernel/include/kernel/types.d`
MICROKERNEL_DIR := modules/microkernel
HYPERVISOR_DIR  := modules/hypervisor
OBJECT_TREE_DIR := modules/object-tree

   DFLAGS := $(DFLAGS_BASE) $(DFLAGS_TARGET_64) -I. \
           -I$(MICROKERNEL_DIR) \
           -I$(MICROKERNEL_DIR)/kernel/include \
           -I$(HYPERVISOR_DIR) -I$(OBJECT_TREE_DIR)
	
# Files and Directories
## D Source Files
KERNEL_D_ARCH_IF_SRC        = $(wildcard $(MICROKERNEL_DIR)/kernel/arch_interface/*.d)
KERNEL_D_CORE_SRC           = $(wildcard $(MICROKERNEL_DIR)/kernel/core/*.d) $(wildcard $(MICROKERNEL_DIR)/kernel/core/stdc/*.d)
KERNEL_D_DEVICE_SRC         = $(wildcard $(MICROKERNEL_DIR)/kernel/device/*.d) $(wildcard $(MICROKERNEL_DIR)/kernel/hardware/*.d) $(wildcard $(MICROKERNEL_DIR)/kernel/memory/*.d)
KERNEL_D_NET_SRC            = $(wildcard $(MICROKERNEL_DIR)/kernel/net/*.d)
KERNEL_D_HOST_SRC           = $(wildcard $(MICROKERNEL_DIR)/kernel/host/*.d)
KERNEL_D_INCLUDE_KERNEL_SRC = $(wildcard $(MICROKERNEL_DIR)/kernel/include/kernel/*.d)
KERNEL_D_LIB_STDC_SRC       = $(wildcard $(MICROKERNEL_DIR)/kernel/lib/stdc/*.d)
KERNEL_D_FS_SRC             = $(MICROKERNEL_DIR)/kernel/fs.d
KERNEL_D_ROOT_SRC           = $(filter-out $(KERNEL_D_FS_SRC),$(wildcard $(MICROKERNEL_DIR)/kernel/*.d))
HYPERVISOR_SRC              = $(HYPERVISOR_DIR)/kernel/hypervisor.d
OBJECT_TREE_SRC             = $(OBJECT_TREE_DIR)/kernel/object_namespace.d $(OBJECT_TREE_DIR)/kernel/object_validator.d
# Note: kernel/utils/ansi_art.d is generated, so it's handled as a target, not a source wildcard here.

ALL_KERNEL_D_SOURCES_NO_GENERATED = \
    $(KERNEL_D_ARCH_IF_SRC) \
    $(KERNEL_D_CORE_SRC) \
    $(KERNEL_D_DEVICE_SRC) \
    $(KERNEL_D_NET_SRC) \
    $(KERNEL_D_HOST_SRC) \
    $(KERNEL_D_INCLUDE_KERNEL_SRC) \
    $(KERNEL_D_LIB_STDC_SRC) \
    $(KERNEL_D_FS_SRC) \
    $(KERNEL_D_ROOT_SRC) \
    $(HYPERVISOR_SRC) \
    $(OBJECT_TREE_SRC)

## Assembly Source Files
BOOT_ASM_SRC                = $(MICROKERNEL_DIR)/arch/x86/boot/boot.s
GDT_ASM_SRC                 = $(MICROKERNEL_DIR)/arch/x86/cpu/gdt.s
IDT_LOADER_ASM_SRC          = $(MICROKERNEL_DIR)/arch/x86/cpu/idt_loader.s
PORTS_ASM_SRC               = $(MICROKERNEL_DIR)/arch/x86/cpu/ports.s
DEBUG_ASM_SRC               = $(MICROKERNEL_DIR)/kernel/utils/debug_asm.s
INTERRUPTS_ASM_SRC          = $(MICROKERNEL_DIR)/arch/x86/cpu/interrupts_asm.s
KEYBOARD_HANDLER_ASM_SRC    = $(MICROKERNEL_DIR)/arch/x86/cpu/keyboard_handler_asm_to_merge.s
TSS_ASM_SRC                 = $(MICROKERNEL_DIR)/arch/x86/cpu/tss.s

ALL_ASM_SOURCES = \
    $(BOOT_ASM_SRC) \
    $(GDT_ASM_SRC) \
    $(IDT_LOADER_ASM_SRC) \
    $(PORTS_ASM_SRC) \
    $(DEBUG_ASM_SRC) \
    $(INTERRUPTS_ASM_SRC) \
    $(KEYBOARD_HANDLER_ASM_SRC) \
    $(TSS_ASM_SRC) \
    $(MICROKERNEL_DIR)/arch/x86/interrupt_stubs.s \
    $(MICROKERNEL_DIR)/arch/x86/cpu/thread_switch.s

## Other Files and Tools
LINKER_SCRIPT               = $(MICROKERNEL_DIR)/arch/x86/linker.ld
ANSI_ART_SRC_FILE           = $(MICROKERNEL_DIR)/kernel/utils/artwork.ans
ANSI_ART_D_TARGET_FILE      = $(MICROKERNEL_DIR)/kernel/utils/ansi_art.d

BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
ISO_DIR = $(BUILD_DIR)/isofiles
ISO_BOOT_DIR = $(ISO_DIR)/boot
ISO_GRUB_DIR = $(ISO_BOOT_DIR)/grub
ISO_BIN_DIR = $(ISO_DIR)/bin
KERNEL_BIN = $(BUILD_DIR)/kernel.bin
ISO_FILE = $(BUILD_DIR)/anonymOS.iso

# Shell sources and target pulled from external repository
SH_DIR = third_party/sh
# All shell modules from the external -sh repository
SH_SOURCES = $(wildcard $(SH_DIR)/src/*.d)
# Include paths so ldc2 can locate shell modules and the bundled mstd library
SH_DFLAGS = -I$(SH_DIR) -I$(SH_DIR)/src
# Original D compiler built with the cross-compiler
DMD_DIR = third_party/dmd
DMD_SRC_DIR = third_party/dmd
DMD_BIN = $(BUILD_DIR)/bin/dmd
SH_BIN = $(BUILD_DIR)/bin/sh





## Object Files (preserving directory structure under OBJ_DIR)
ALL_KERNEL_D_OBJS_NO_GENERATED = $(patsubst %.d,$(OBJ_DIR)/%.o,$(ALL_KERNEL_D_SOURCES_NO_GENERATED))
ANSI_ART_D_OBJ                 = $(patsubst %.d,$(OBJ_DIR)/%.o,$(ANSI_ART_D_TARGET_FILE))
ALL_KERNEL_D_OBJS              = $(ALL_KERNEL_D_OBJS_NO_GENERATED) $(ANSI_ART_D_OBJ)

ALL_ASM_OBJS      = $(patsubst %.s,$(OBJ_DIR)/%.o,$(ALL_ASM_SOURCES))
ALL_OBJS          = $(ALL_ASM_OBJS) $(ALL_KERNEL_D_OBJS)

.PHONY: all build clean run iso kernel_bin dmd fetch_shell fetch_modules fetch_dmd update-run debug


all: $(ISO_FILE)

iso: $(ISO_FILE)

build: $(ISO_FILE)


$(ISO_FILE): $(KERNEL_BIN) $(DMD_BIN) $(SH_BIN) fetch_shell fetch_dmd fetch_modules
	@echo ">>> Creating ISO Image..."
	mkdir -p $(ISO_BOOT_DIR) $(ISO_GRUB_DIR) $(ISO_BIN_DIR) $(ISO_DIR)/third_party $(ISO_DIR)/sys/init
        cp $(KERNEL_BIN) $(ISO_BOOT_DIR)/
        cp $(DMD_BIN) $(ISO_BIN_DIR)/
        cp $(SH_BIN) $(ISO_BIN_DIR)/sh
	rsync -a --exclude='.git' third_party/sh/ $(ISO_DIR)/third_party/sh/
	rsync -a --exclude='.git' $(DMD_SRC_DIR)/ $(ISO_DIR)/third_party/dmd/
	cp scripts/install_shell_in_os.sh $(ISO_DIR)/sys/init/
	cp scripts/install_dmd_in_os.sh $(ISO_DIR)/sys/init/
			# Critical: Ensure the backslash '\' after 'then' on the line below
		# is the *absolute last character* on that line. No trailing spaces.
		# This is the most common cause for the "expecting fi" error on "line 2".
		# The 'if' statement above is treated as a self-contained shell command.
		# The 'fi' correctly terminates it.
		# The following 'echo' commands will be executed as separate shell commands.
		# Ensure all line-continuing backslashes ('\') within the 'if' block are correct.
	echo "Generating $(ISO_GRUB_DIR)/grub.cfg..." # This line and subsequent echos form the grub.cfg
	echo "set timeout=3" > $(ISO_GRUB_DIR)/grub.cfg 
	echo "set default=0" >> $(ISO_GRUB_DIR)/grub.cfg
	echo "" >> $(ISO_GRUB_DIR)/grub.cfg # Add a blank line for readability
	echo "menuentry \"anonymOS\" {" >> $(ISO_GRUB_DIR)/grub.cfg
		# echo "    echo \"Attempting to load kernel: /boot/kernel.bin ...\"" >> $(ISO_GRUB_DIR)/grub.cfg # Debug echo, can be removed
	echo "    multiboot2 /boot/kernel.bin" >> $(ISO_GRUB_DIR)/grub.cfg
		# echo "    echo \"Kernel load attempt finished. Multiboot2 info should be set.\"" >> $(ISO_GRUB_DIR)/grub.cfg # Debug echo, can be removed
	echo "    boot" >> $(ISO_GRUB_DIR)/grub.cfg # The actual boot command
	echo "}" >> $(ISO_GRUB_DIR)/grub.cfg
		command -v xorriso >/dev/null || { echo "Error: xorriso not installed. Please install it (e.g., sudo apt-get install xorriso)."; exit 1; }
		$(GRUB_MKRESCUE) -v -o $@ $(ISO_DIR)
	echo "ISO created: $@ (using grub.cfg in $(ISO_GRUB_DIR)/grub.cfg)"

kernel_bin: $(KERNEL_BIN) # PHONY target now depends on the actual KERNEL_BIN file

# Ensure ANSI art D file is generated before compiling D sources that might depend on it
# or before linking if it's directly part of ALL_OBJS (which it is via KERNEL_D_OBJS)
$(KERNEL_BIN): fetch_modules $(ALL_OBJS) $(LINKER_SCRIPT) | $(BUILD_DIR) # ANSI_ART_D_TARGET_FILE is a dep of its .o file, which is in ALL_OBJS
	mkdir -p $(BUILD_DIR)
	# Removed -lgcc as it's specific to GCC. LDC2/LLD should handle necessary runtime bits or emit self-contained code.
	$(LD) $(LDFLAGS) -T $(LINKER_SCRIPT) -o $@ $(ALL_OBJS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)




# Generic rule for D files (preserves source path under OBJ_DIR)
$(OBJ_DIR)/%.o: %.d
	@mkdir -p $(dir $@)
	$(DC) $(DFLAGS) -c $< -of=$@

# Generic rule for Assembly files (preserves source path under OBJ_DIR)
$(OBJ_DIR)/%.o: %.s
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $< -o $@

$(DMD_BIN): | $(BUILD_DIR)
./scripts/build_dmd.sh

$(SH_BIN): fetch_shell | $(BUILD_DIR)
./scripts/build_shell.sh

dmd: $(DMD_BIN)
sh: $(SH_BIN)

fetch_shell:
	       ./scripts/fetch_shell.sh

fetch_modules:
	       ./scripts/fetch_modules.sh

fetch_dmd:
	       ./scripts/fetch_dmd.sh

run: $(ISO_FILE)
	qemu-system-x86_64 -cdrom $(ISO_FILE) -m 128M -display curses -vga std

# Optional: Run with QEMU paused, waiting for GDB
# In another terminal: i686-elf-gdb -ex "target remote localhost:1234" -ex "symbol-file build/kernel.bin" -ex "layout asm" -ex "break _start"
# In another terminal: gdb -ex "target remote localhost:1234" -ex "symbol-file $(KERNEL_BIN)" -ex "layout asm" -ex "break _start"
# (Adjust gdb command if you use a cross-compiler gdb like i686-elf-gdb)
run-debug: $(ISO_FILE)
	qemu-system-x86_64 -cdrom $< $(QEMU_FLAGS) -S -s

run-log-int: $(ISO_FILE)
	qemu-system-x86_64 -cdrom $< $(QEMU_FLAGS) -m 128M -display curses -vga std \
	-d int,guest_errors,cpu_reset -D qemu.log -debugcon file:qemu.log -serial file:qemu.log \
	-M smm=off -no-reboot -S -s
debug:
	./scripts/run_with_gdb.sh

clean:
	rm -rf $(BUILD_DIR)

update-run:
	git pull
	clear
	bash ./scripts/build_dmd.sh
	$(MAKE) clean
	$(MAKE) run-log-int
	
