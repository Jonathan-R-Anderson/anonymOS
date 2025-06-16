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
# -I.: Include current directory for imports (if any local modules were used)
DFLAGS = -betterC -mtriple=i386-unknown-elf -mcpu=pentium4 -O1 -g -output-o
# Assembler Flags
ASFLAGS = -f elf32 # Output format: ELF32

# Linker Flags
# -m elf_i386: Specify 32-bit ELF output format for GNU ld
# If using i686-elf-ld, this flag might not be needed or might be different.
LDFLAGS = -m elf_i386

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

KERNEL_D_OBJ = $(BUILD_DIR)/kernel_d.o
KERNEL_ASM_OBJ = $(BUILD_DIR)/boot.o
KERNEL_BIN = $(BUILD_DIR)/kernel.bin
GDT_ASM_OBJ = $(OBJ_DIR)/gdt.o
IDT_ASM_OBJ = $(OBJ_DIR)/idt.o
ISR_STUBS_ASM_OBJ = $(OBJ_DIR)/isr_stubs.o
ISO_FILE = $(BUILD_DIR)/minimal_d_os.iso

.PHONY: all clean run iso kernel_bin

all: $(ISO_FILE)

iso: $(ISO_FILE)

$(ISO_FILE): kernel_bin $(GRUB_CFG)
	@mkdir -p $(ISO_BOOT_DIR) $(ISO_GRUB_DIR)
	cp $(KERNEL_BIN) $(ISO_BOOT_DIR)/
	cp $(GRUB_CFG) $(ISO_GRUB_DIR)/
	$(GRUB_MKRESCUE) -o $@ $(ISO_DIR)
	@echo "ISO created: $@"

ALL_OBJS = $(KERNEL_ASM_OBJ) $(GDT_ASM_OBJ) $(IDT_ASM_OBJ) $(ISR_STUBS_ASM_OBJ) $(KERNEL_D_OBJ)

kernel_bin: $(ALL_OBJS)

$(KERNEL_BIN): $(ALL_OBJS) $(LINKER_SCRIPT)
	$(LD) $(LDFLAGS) -T $(LINKER_SCRIPT) -o $@ $(ALL_OBJS)

$(KERNEL_D_OBJ): $(KERNEL_D_SRC)
	@mkdir -p $(BUILD_DIR) $(OBJ_DIR)
	$(DC) $(DFLAGS) -c $< -of=$@

$(KERNEL_ASM_OBJ): $(KERNEL_ASM_SRC)
	@mkdir -p $(BUILD_DIR) $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(GDT_ASM_OBJ): $(GDT_ASM_SRC)
	@mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(IDT_ASM_OBJ): $(IDT_ASM_SRC)
	@mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(ISR_STUBS_ASM_OBJ): $(ISR_STUBS_ASM_SRC)
	@mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

run: $(ISO_FILE)
	qemu-system-i386 -cdrom $(ISO_FILE) -m 128M

clean:
	rm -rf $(BUILD_DIR) $(OBJ_DIR)