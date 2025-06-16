# Makefile for Minimal D OS

# Tools
DC = ldc2
AS = nasm
LD = ld # Use i686-elf-ld if you have a cross-compiler setup
GRUB_MKRESCUE = grub-mkrescue

# D Compiler Flags
# -betterC: Enables D subset suitable for freestanding environments (no GC, no DRuntime)
# -mtriple=i386-unknown-elf: Target a 32-bit ELF environment
# -target-cpu=pentium4: A common baseline for 32-bit, adjust if needed
# -O1: Basic optimizations
# -g: Debug symbols (optional, but helpful)
# -output-o: Ensures .o file is output (LDC specific)
# -I.: Include current directory for imports (if any local modules were used) -disable-asserts: Disable runtime asserts
DFLAGS = -betterC -mtriple=i386-unknown-elf -mcpu=pentium4 -O1 -g -boundscheck=off -output-o


# Assembler Flags
ASFLAGS = -f elf32 # Output format: ELF32

# Linker Flags
# -m elf_i386: Specify 32-bit ELF output format for GNU ld
# If using i686-elf-ld, this flag might not be needed or might be different.
LDFLAGS = -m elf_i386 --verbose

# Files and Directories
KERNEL_D_SRC = kernel.d
KERNEL_ASM_SRC = boot.s
GDT_ASM_SRC = gdt.s
IDT_ASM_SRC = idt.s
ISR_STUBS_ASM_SRC = isr_stubs.s
LINKER_SCRIPT = linker.ld
GRUB_CFG = grub.cfg

BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
ISO_DIR = $(BUILD_DIR)/isofiles
ISO_BOOT_DIR = $(ISO_DIR)/boot
ISO_GRUB_DIR = $(ISO_BOOT_DIR)/grub

GDT_ASM_OBJ = $(OBJ_DIR)/gdt.o
IDT_ASM_OBJ = $(OBJ_DIR)/idt.o
ISR_STUBS_ASM_OBJ = $(OBJ_DIR)/isr_stubs.o
KERNEL_D_OBJ = $(OBJ_DIR)/kernel_d.o
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

ALL_OBJS = $(KERNEL_ASM_OBJ) $(GDT_ASM_OBJ) $(IDT_ASM_OBJ) $(ISR_STUBS_ASM_OBJ) $(KERNEL_D_OBJ)

kernel_bin: $(KERNEL_BIN) # PHONY target now depends on the actual KERNEL_BIN file

$(KERNEL_BIN): $(ALL_OBJS) $(LINKER_SCRIPT)
	mkdir -p $(BUILD_DIR)
	$(LD) $(LDFLAGS) -T $(LINKER_SCRIPT) -o $@ $(ALL_OBJS) # This rule creates kernel.bin

$(KERNEL_D_OBJ): $(KERNEL_D_SRC)
	mkdir -p $(OBJ_DIR)
	$(DC) $(DFLAGS) -c $< -of=$@

$(KERNEL_ASM_OBJ): $(KERNEL_ASM_SRC)
	mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(GDT_ASM_OBJ): $(GDT_ASM_SRC)
	mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(IDT_ASM_OBJ): $(IDT_ASM_SRC)
	mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(ISR_STUBS_ASM_OBJ): $(ISR_STUBS_ASM_SRC)
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