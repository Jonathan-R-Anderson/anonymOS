# Makefile for Minimal D OS

# Tools
DC = ldc2
AS = nasm
LD = ld.lld # More common invocation for LLD, the LLVM linker
GRUB_MKRESCUE = grub-mkrescue

# D Compiler Flags
# -betterC: Enables D subset suitable for freestanding environments (no GC, no DRuntime)
# -mtriple=i386-unknown-elf: Target a 32-bit ELF environment
# -target-cpu=pentium4: A common baseline for 32-bit, adjust if needed
# -O1: Basic optimizations
# -g: Debug symbols (optional, but helpful)
# -output-o: Ensures .o file is output (LDC specific)
# -I.: Include current directory for imports (if any local modules were used) -disable-asserts: Disable runtime asserts
DFLAGS = -betterC -mtriple=i386-unknown-elf -mcpu=pentium4 -O1 -g -boundscheck=off -output-o -Ikernel

# Assembler Flags
ASFLAGS = -f elf32 # Output format: ELF32

# Linker Flags
# For LLD:
# --verbose can be removed, LLD is usually informative on errors.
LDFLAGS = -nostdlib -no-pie

# Update DFLAGS for the new directory structure and D module conventions
# -I. allows `import kernel.core.module;`
# -Ikernel/include allows `import kernel.types;` for `kernel/include/kernel/types.d`
DFLAGS := -betterC -mtriple=i386-unknown-elf -mcpu=pentium4 -O1 -g -boundscheck=off -output-o -I. -Ikernel/include

# Files and Directories
## D Source Files
KERNEL_D_ARCH_IF_SRC        = $(wildcard kernel/arch_interface/*.d)
KERNEL_D_CORE_SRC           = $(wildcard kernel/core/*.d) $(wildcard kernel/core/stdc/*.d)
KERNEL_D_DEVICE_SRC         = $(wildcard kernel/device/*.d)
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

ALL_ASM_SOURCES = \
    $(BOOT_ASM_SRC) \
    $(GDT_ASM_SRC) \
    $(IDT_LOADER_ASM_SRC) \
    $(PORTS_ASM_SRC) \
    $(DEBUG_ASM_SRC) \
    $(INTERRUPTS_ASM_SRC) \
    $(KEYBOARD_HANDLER_ASM_SRC)

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
KERNEL_BIN = $(BUILD_DIR)/kernel.bin
ISO_FILE = $(BUILD_DIR)/gremlinos.iso # Renamed ISO

## Object Files (preserving directory structure under OBJ_DIR)
ALL_KERNEL_D_OBJS_NO_GENERATED = $(patsubst %.d,$(OBJ_DIR)/%.o,$(ALL_KERNEL_D_SOURCES_NO_GENERATED))
ANSI_ART_D_OBJ                 = $(patsubst %.d,$(OBJ_DIR)/%.o,$(ANSI_ART_D_TARGET_FILE))
ALL_KERNEL_D_OBJS              = $(ALL_KERNEL_D_OBJS_NO_GENERATED) $(ANSI_ART_D_OBJ)

ALL_ASM_OBJS      = $(patsubst %.s,$(OBJ_DIR)/%.o,$(ALL_ASM_SOURCES))
ALL_OBJS          = $(ALL_ASM_OBJS) $(ALL_KERNEL_D_OBJS)

.PHONY: all clean run iso kernel_bin

all: $(ISO_FILE)

iso: $(ISO_FILE)

$(ISO_FILE): $(KERNEL_BIN)
	mkdir -p $(ISO_BOOT_DIR) $(ISO_GRUB_DIR)
	cp $(KERNEL_BIN) $(ISO_BOOT_DIR)/
	echo "Generating $(ISO_GRUB_DIR)/grub.cfg..."
	echo "set timeout=3" > $(ISO_GRUB_DIR)/grub.cfg
	echo "set default=0" >> $(ISO_GRUB_DIR)/grub.cfg
	echo "" >> $(ISO_GRUB_DIR)/grub.cfg # Add a blank line for readability
	echo "menuentry \"GremlinOS\" {" >> $(ISO_GRUB_DIR)/grub.cfg
	echo "    multiboot /boot/kernel.bin" >> $(ISO_GRUB_DIR)/grub.cfg # Removed comment for cleaner cfg
	echo "    boot" >> $(ISO_GRUB_DIR)/grub.cfg
	echo "}" >> $(ISO_GRUB_DIR)/grub.cfg
	$(GRUB_MKRESCUE) -v -o $@ $(ISO_DIR)
	echo "ISO created: $@ (using grub.cfg in $(ISO_GRUB_DIR)/grub.cfg)"

kernel_bin: $(KERNEL_BIN) # PHONY target now depends on the actual KERNEL_BIN file

# Ensure ANSI art D file is generated before compiling D sources that might depend on it
# or before linking if it's directly part of ALL_OBJS (which it is via KERNEL_D_OBJS)
$(KERNEL_BIN): $(ALL_OBJS) $(LINKER_SCRIPT) | $(BUILD_DIR) # ANSI_ART_D_TARGET_FILE is a dep of its .o file, which is in ALL_OBJS
	mkdir -p $(BUILD_DIR)
	# Removed -lgcc as it's specific to GCC. LDC2/LLD should handle necessary runtime bits or emit self-contained code.
	$(LD) $(LDFLAGS) -T $(LINKER_SCRIPT) -o $@ $(ALL_OBJS)

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
	qemu-system-i386 -cdrom $(ISO_FILE) -m 128M

# Optional: Run with QEMU paused, waiting for GDB
# In another terminal: i686-elf-gdb -ex "target remote localhost:1234" -ex "symbol-file build/kernel.bin" -ex "layout asm" -ex "break _start"
# In another terminal: gdb -ex "target remote localhost:1234" -ex "symbol-file $(KERNEL_BIN)" -ex "layout asm" -ex "break _start"
# (Adjust gdb command if you use a cross-compiler gdb like i686-elf-gdb)
run-debug: $(ISO_FILE)
	qemu-system-i386 -cdrom $(ISO_FILE) -m 128M -S -s

# Optional: Run with interrupt logging to qemu.log (can show triple faults)
run-log-int: $(ISO_FILE)
	qemu-system-i386 -cdrom $(ISO_FILE) -m 128M -d int -D qemu.log

clean:
	rm -rf $(BUILD_DIR)