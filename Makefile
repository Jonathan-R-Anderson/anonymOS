# Makefile for Minimal D OS

# Tools
DC = ldc2
AS = nasm
LD = i686-linux-gnu-gcc # Use the installed i686-linux-gnu GCC
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
# -nostdlib: Do not use the standard system startup files or libraries when linking.
# -nostartfiles: Do not use the standard system startup files when linking.
# -no-pie: Do not create a position independent executable.
LDFLAGS = --verbose -nostdlib -nostartfiles -no-pie

# Files and Directories
KERNEL_D_FILES = $(wildcard kernel/*.d) # Find all .d files in kernel/
KERNEL_ASM_SRC = boot.s
GDT_ASM_SRC = gdt.s 
# IDT_ASM_SRC = idt.s # This is replaced by idt_loader.s
IDT_LOADER_ASM_SRC = idt_loader.s # New: For lidt instruction
PORTS_ASM_SRC = kernel/ports.s # Added ports.s
DEBUG_STUBS_ASM_SRC = kernel/debug_stubs.s # For assembly stubs
ISR_STUBS_ASM_SRC = isr_stubs.s
KEYBOARD_HANDLER_ASM_SRC = keyboard_handler_asm.s # New: Keyboard ISR assembly
ANSI_ART_SRC = artwork.ans # Source ANSI art file
ANSI_ART_D_TARGET = kernel/ansi_art.d # Generated D file for ANSI art (target)
PYTHON_INTERPRETER = python3 # Adjust if your python3 is just 'python'
LINKER_SCRIPT = linker.ld
# GRUB_CFG = grub.cfg # Not used as a variable directly, cfg is generated

# D sources (now in kernel/ subdirectory)
D_SOURCES = $(wildcard kernel/*.d)

BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
ISO_DIR = $(BUILD_DIR)/isofiles
ISO_BOOT_DIR = $(ISO_DIR)/boot
ISO_GRUB_DIR = $(ISO_BOOT_DIR)/grub

GDT_ASM_OBJ = $(OBJ_DIR)/gdt.o
# IDT_ASM_OBJ = $(OBJ_DIR)/idt.o # For idt.s - REMOVED
IDT_LOADER_ASM_OBJ = $(OBJ_DIR)/idt_loader.o # New: For idt_loader.s
ISR_STUBS_ASM_OBJ = $(OBJ_DIR)/isr_stubs.o
PORTS_ASM_OBJ = $(OBJ_DIR)/ports.o # Added object for ports.s
KEYBOARD_HANDLER_ASM_OBJ = $(OBJ_DIR)/keyboard_handler_asm.o # New: For keyboard_handler_asm.s
DEBUG_STUBS_ASM_OBJ = $(OBJ_DIR)/debug_stubs.o # Object for debug stubs
# Generate object file names based on source files in kernel/
KERNEL_D_OBJS = $(patsubst kernel/%.d,$(OBJ_DIR)/kernel_%.o,$(D_SOURCES))
KERNEL_ASM_OBJ = $(OBJ_DIR)/boot.o
KERNEL_BIN = $(BUILD_DIR)/kernel.bin
ISO_FILE = $(BUILD_DIR)/minimal_d_os.iso

.PHONY: all clean run iso kernel_bin

all: $(ISO_FILE)

iso: $(ISO_FILE)

$(ISO_FILE): $(KERNEL_BIN) # KERNEL_BIN is the main dependency. grub.cfg content is now embedded.
	mkdir -p $(ISO_BOOT_DIR) $(ISO_GRUB_DIR)
	cp $(KERNEL_BIN) $(ISO_BOOT_DIR)/
	echo "Generating $(ISO_GRUB_DIR)/grub.cfg..."
	echo "set timeout=3" > $(ISO_GRUB_DIR)/grub.cfg
	echo "set default=0" >> $(ISO_GRUB_DIR)/grub.cfg
	echo "" >> $(ISO_GRUB_DIR)/grub.cfg
	echo "menuentry \"Minimal D OS\" {" >> $(ISO_GRUB_DIR)/grub.cfg
	echo "    multiboot /boot/kernel.bin  # Path to the kernel binary inside the ISO" >> $(ISO_GRUB_DIR)/grub.cfg
	echo "    boot" >> $(ISO_GRUB_DIR)/grub.cfg
	echo "}" >> $(ISO_GRUB_DIR)/grub.cfg
	$(GRUB_MKRESCUE) -v -o $@ $(ISO_DIR) # Added -v for verbosity, removed @
	echo "ISO created: $@ (using grub.cfg in $(ISO_GRUB_DIR)/grub.cfg)" # Clarified echo message
ALL_OBJS = $(KERNEL_ASM_OBJ) $(GDT_ASM_OBJ) $(IDT_LOADER_ASM_OBJ) $(ISR_STUBS_ASM_OBJ) $(KEYBOARD_HANDLER_ASM_OBJ) $(PORTS_ASM_OBJ) $(DEBUG_STUBS_ASM_OBJ) $(KERNEL_D_OBJS)

kernel_bin: $(KERNEL_BIN) # PHONY target now depends on the actual KERNEL_BIN file

# Ensure ANSI art D file is generated before compiling D sources that might depend on it
# or before linking if it's directly part of ALL_OBJS (which it is via KERNEL_D_OBJS)
$(KERNEL_BIN): $(ALL_OBJS) $(LINKER_SCRIPT) $(ANSI_ART_D_TARGET) | $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)
	$(LD) $(LDFLAGS) -T $(LINKER_SCRIPT) -o $@ $(ALL_OBJS) -lgcc # Added -lgcc

# Rule to generate the D file from ANSI art
$(ANSI_ART_D_TARGET): kernel/$(ANSI_ART_SRC) ans_to_d.py
	$(PYTHON_INTERPRETER) ans_to_d.py kernel/$(ANSI_ART_SRC) $(ANSI_ART_D_TARGET)

# Rule for D files in kernel/ subdirectory
$(OBJ_DIR)/kernel_%.o: kernel/%.d
	mkdir -p $(OBJ_DIR)
	$(DC) $(DFLAGS) -c $< -of=$@

$(KERNEL_ASM_OBJ): $(KERNEL_ASM_SRC)
	mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(GDT_ASM_OBJ): $(GDT_ASM_SRC)
	mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(IDT_LOADER_ASM_OBJ): $(IDT_LOADER_ASM_SRC) | $(OBJ_DIR)
	mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(KEYBOARD_HANDLER_ASM_OBJ): $(KEYBOARD_HANDLER_ASM_SRC) | $(OBJ_DIR)
	mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(ISR_STUBS_ASM_OBJ): $(ISR_STUBS_ASM_SRC)
	mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(PORTS_ASM_OBJ): $(PORTS_ASM_SRC)
	mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(DEBUG_STUBS_ASM_OBJ): $(DEBUG_STUBS_ASM_SRC) | $(OBJ_DIR) # Ensure OBJ_DIR exists
	mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

run: $(ISO_FILE)
	qemu-system-i386 -cdrom $(ISO_FILE) -m 128M

# Optional: Run with QEMU paused, waiting for GDB
# In another terminal: i686-elf-gdb -ex "target remote localhost:1234" -ex "symbol-file build/kernel.bin" -ex "layout asm" -ex "break _start"
run-debug: $(ISO_FILE)
	qemu-system-i386 -cdrom $(ISO_FILE) -m 128M -S -s

# Optional: Run with interrupt logging to qemu.log (can show triple faults)
run-log-int: $(ISO_FILE)
	qemu-system-i386 -cdrom $(ISO_FILE) -m 128M -d int -D qemu.log

clean:
	rm -rf $(BUILD_DIR)