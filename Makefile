# Makefile for Minimal D OS

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
	DFLAGS_TARGET_32 = -mtriple=i386-unknown-elf -mcpu=pentium4
	DFLAGS_TARGET_64 = -mtriple=x86_64-unknown-elf -mcpu=x86-64 # Target 64-bit

# Assembler Flags
ASFLAGS = --64 # Tell GNU AS to assemble for 64-bit mode. elf64 is usually inferred.

	# Linker Flags
	# For LLD:
	# --verbose can be removed, LLD is usually informative on errors.
	LDFLAGS = -nostdlib -no-pie # -m elf_x86_64 might be needed if not inferred by lld from object files
	
	# Update DFLAGS for the new directory structure and D module conventions
	# -I. allows `import kernel.core.module;`
	# -Ikernel/include allows `import kernel.types;` for `kernel/include/kernel/types.d`
	DFLAGS := $(DFLAGS_BASE) $(DFLAGS_TARGET_64) -I. -Ikernel/include
	
# Files and Directories
## D Source Files
KERNEL_D_ARCH_IF_SRC        = $(wildcard kernel/arch_interface/*.d)
KERNEL_D_CORE_SRC           = $(wildcard kernel/core/*.d) $(wildcard kernel/core/stdc/*.d)
KERNEL_D_DEVICE_SRC         = $(wildcard kernel/device/*.d) $(wildcard kernel/hardware/*.d) $(wildcard kernel/memory/*.d)
KERNEL_D_INCLUDE_KERNEL_SRC = $(wildcard kernel/include/kernel/*.d)
KERNEL_D_LIB_STDC_SRC       = $(wildcard kernel/lib/stdc/*.d)
KERNEL_D_ROOT_SRC           = $(wildcard kernel/*.d) # e.g. interrupts.d, keyboard.d, terminal.d
# Note: kernel/utils/ansi_art.d is generated, so it's handled as a target, not a source wildcard here.

ALL_KERNEL_D_SOURCES_NO_GENERATED = \
    $(KERNEL_D_ARCH_IF_SRC) \
    $(KERNEL_D_CORE_SRC) \
    $(KERNEL_D_DEVICE_SRC) \
    $(KERNEL_D_INCLUDE_KERNEL_SRC) \
    $(KERNEL_D_LIB_STDC_SRC) \
    $(KERNEL_D_ROOT_SRC)

## Assembly Source Files
BOOT_ASM_SRC                = arch/x86/boot/boot.s
GDT_ASM_SRC                 = arch/x86/cpu/gdt.s
IDT_LOADER_ASM_SRC          = arch/x86/cpu/idt_loader.s
PORTS_ASM_SRC               = arch/x86/cpu/ports.s
DEBUG_ASM_SRC               = kernel/utils/debug_asm.s
INTERRUPTS_ASM_SRC          = arch/x86/cpu/interrupts_asm.s
KEYBOARD_HANDLER_ASM_SRC    = arch/x86/cpu/keyboard_handler_asm_to_merge.s # Adjusted name from tree
TSS_ASM_SRC                 = arch/x86/cpu/tss.s

ALL_ASM_SOURCES = \
    $(BOOT_ASM_SRC) \
    $(GDT_ASM_SRC) \
    $(IDT_LOADER_ASM_SRC) \
    $(PORTS_ASM_SRC) \
    $(DEBUG_ASM_SRC) \
    $(INTERRUPTS_ASM_SRC) \
    $(KEYBOARD_HANDLER_ASM_SRC) \
    $(TSS_ASM_SRC)

## Other Files and Tools
LINKER_SCRIPT               = arch/x86/linker.ld
ANSI_ART_SRC_FILE           = kernel/utils/artwork.ans
ANSI_ART_D_TARGET_FILE      = kernel/utils/ansi_art.d # Generated D file target
PYTHON_SCRIPT_ANSI_TO_D     = scripts/ans_to_d.py
PYTHON_INTERPRETER          = python3

BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
ISO_DIR = $(BUILD_DIR)/isofiles
ISO_BOOT_DIR = $(ISO_DIR)/boot
ISO_GRUB_DIR = $(ISO_BOOT_DIR)/grub
ISO_BIN_DIR = $(ISO_DIR)/bin
KERNEL_BIN = $(BUILD_DIR)/kernel.bin
ISO_FILE = $(BUILD_DIR)/anonymOS.iso

## Userspace Programs
ANON_SHELL_DIR = userland/shell
ANON_SHELL_EXE_NAME = anonym_shell
ANON_SHELL_EXE = $(BUILD_DIR)/$(ANON_SHELL_EXE_NAME)
ANON_TERM_EXE_NAME = anonym_terminal
ANON_TERM_EXE = $(BUILD_DIR)/$(ANON_TERM_EXE_NAME)


QEMU_FLAGS = -cpu qemu64,+lm \
             -m 128M -no-reboot -no-shutdown -d guest_errors \
             -display curses -vga std

## Object Files (preserving directory structure under OBJ_DIR)
ALL_KERNEL_D_OBJS_NO_GENERATED = $(patsubst %.d,$(OBJ_DIR)/%.o,$(ALL_KERNEL_D_SOURCES_NO_GENERATED))
ANSI_ART_D_OBJ                 = $(patsubst %.d,$(OBJ_DIR)/%.o,$(ANSI_ART_D_TARGET_FILE))
ALL_KERNEL_D_OBJS              = $(ALL_KERNEL_D_OBJS_NO_GENERATED) $(ANSI_ART_D_OBJ)

ALL_ASM_OBJS      = $(patsubst %.s,$(OBJ_DIR)/%.o,$(ALL_ASM_SOURCES))
ALL_OBJS          = $(ALL_ASM_OBJS) $(ALL_KERNEL_D_OBJS)

.PHONY: all build clean run iso kernel_bin


all: $(ISO_FILE)

iso: $(ISO_FILE)

build: $(ISO_FILE)


# Rule to build the anonymOS Shell executable.
# This will build for your HOST system, not anonymOS target yet.
$(ANON_SHELL_EXE): $(ANON_SHELL_DIR)/TtyShellyShell.hs $(ANON_SHELL_DIR)/anonym-shell.cabal
	@echo ">>> Building anonymOS Shell (requires GHC and Cabal)..."
	@echo ">>> NOTE: This will build for your HOST system, not anonymOS target yet."
	        @mkdir -p $(dir $@) # Ensure the output directory exists
	cd $(ANON_SHELL_DIR) && cabal update && cabal build --ghc-options="-static" # Attempt static linking using GHC options
# Find the built executable. Path might vary based on cabal version/setup.
# This is a common path pattern. Adjust if necessary.
	@cp $(ANON_SHELL_DIR)/dist-newstyle/build/*/*/anonym-shell-*/x/anonym-shell/build/anonym-shell/anonym-shell $@
	@echo ">>> anonymOS Shell built to $@"

$(ANON_TERM_EXE): $(ANON_SHELL_DIR)/GraphicalTerminal.hs $(ANON_SHELL_DIR)/anonym-shell.cabal
	@echo ">>> Building anonymOS Terminal (requires GHC and Cabal)..."
	@mkdir -p $(dir $@)
	cd $(ANON_SHELL_DIR) && cabal update && cabal build anonym-terminal --ghc-options="-static"
	@cp $(ANON_SHELL_DIR)/dist-newstyle/build/*/*/anonym-shell-*/x/anonym-terminal/build/anonym-terminal/anonym-terminal $@
	@echo ">>> anonymOS Terminal built to $@"

$(ISO_FILE): $(KERNEL_BIN) $(ANON_SHELL_EXE) $(ANON_TERM_EXE)
		@echo ">>> Creating ISO Image..."
		mkdir -p $(ISO_BOOT_DIR) $(ISO_GRUB_DIR) $(ISO_BIN_DIR)
		cp $(KERNEL_BIN) $(ISO_BOOT_DIR)/
		# Critical: Ensure the backslash '\' after 'then' on the line below
		# is the *absolute last character* on that line. No trailing spaces.
		# This is the most common cause for the "expecting fi" error on "line 2".
	@if [ -f "$(ANON_SHELL_EXE)" ]; then \
	echo "Copying '$(ANON_SHELL_EXE)' to '$(strip $(ISO_BIN_DIR))/$(ANON_SHELL_EXE_NAME)'"; \
	cp $(ANON_SHELL_EXE) $(ISO_BIN_DIR)/$(ANON_SHELL_EXE_NAME); \
	else \
	echo "Warning: anonymOS Shell executable not found at $(ANON_SHELL_EXE). ISO will not include it."; \
	fi
	@if [ -f "$(ANON_TERM_EXE)" ]; then \
	echo "Copying '$(ANON_TERM_EXE)' to '$(strip $(ISO_BIN_DIR))/$(ANON_TERM_EXE_NAME)'"; \
	cp $(ANON_TERM_EXE) $(ISO_BIN_DIR)/$(ANON_TERM_EXE_NAME); \
	else \
	echo "Warning: anonymOS Terminal executable not found at $(ANON_TERM_EXE). ISO will not include it."; \
	fi
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
$(KERNEL_BIN): $(ALL_OBJS) $(LINKER_SCRIPT) | $(BUILD_DIR) # ANSI_ART_D_TARGET_FILE is a dep of its .o file, which is in ALL_OBJS
	       mkdir -p $(BUILD_DIR)
	       # Removed -lgcc as it's specific to GCC. LDC2/LLD should handle necessary runtime bits or emit self-contained code.
	       $(LD) $(LDFLAGS) -T $(LINKER_SCRIPT) -o $@ $(ALL_OBJS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Rule to generate the D file from ANSI art
$(ANSI_ART_D_TARGET_FILE): $(ANSI_ART_SRC_FILE) $(PYTHON_SCRIPT_ANSI_TO_D)
	@mkdir -p $(dir $@)
	$(PYTHON_INTERPRETER) $(PYTHON_SCRIPT_ANSI_TO_D) $(ANSI_ART_SRC_FILE) $@

# Generic rule for D files (preserves source path under OBJ_DIR)
$(OBJ_DIR)/%.o: %.d
	@mkdir -p $(dir $@)
	$(DC) $(DFLAGS) -c $< -of=$@

# Generic rule for Assembly files (preserves source path under OBJ_DIR)
$(OBJ_DIR)/%.o: %.s
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $< -o $@

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

clean:
		rm -rf $(BUILD_DIR)
	
