; boot.s
BITS 32

; Section for the Multiboot v1 header
section .multiboot_header
align 4
    ; Multiboot Magic Number
    MULTIBOOT_HEADER_MAGIC equ 0x1BADB002
    ; Flags:
    ; Bit 0: Align all boot modules on page (4KB) boundaries.
    ; Bit 1: Provide memory map via Multiboot Information structure.
    MULTIBOOT_HEADER_FLAGS equ 0x00000003
    ; Checksum: (MAGIC + FLAGS + CHECKSUM) must be 0
    MULTIBOOT_HEADER_CHECKSUM equ -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)

    ; The header itself
    dd MULTIBOOT_HEADER_MAGIC
    dd MULTIBOOT_HEADER_FLAGS
    dd MULTIBOOT_HEADER_CHECKSUM

    ; --- Optional GRUB Address Fields (if bit 16 of flags is set) ---
    ; If you were to set bit 16 in MULTIBOOT_HEADER_FLAGS, you'd need these:
    ; dd header_addr ; Physical address of this header
    ; dd load_addr   ; Physical address of the start of the .text section
    ; dd load_end_addr ; Physical address of the end of all kernel sections
    ; dd bss_end_addr  ; Physical address of the end of the .bss section
    ; dd entry_addr    ; Physical address of the _start entry point
    ; For now, we keep it simple and don't set bit 16.

section .text
global _start   ; Make _start visible to the linker
extern kmain    ; Declare kmain, which will be defined in D

_start:
    ; At this point, the processor is in 32-bit protected mode.
    ; GRUB has loaded us, and eax contains the multiboot magic (0x2BADB002),
    ; ebx contains the physical address of the Multiboot Information structure.

    cli ; Disable interrupts immediately. We don't have an IDT yet.

    ; Set up the stack.
    ; The stack grows downwards. We point esp to the top of our stack space.
    ; This stack space is defined in the .bss section.
    mov esp, stack_top

    ; Optional: You might want to clear EFLAGS, especially the direction flag.
    ; push eax
    ; mov eax, 0
    ; pushfd
    ; pop eax
    ; and eax, 0xFFBFFFFF ; Clear some flags, like direction flag (DF)
    ; push eax
    ; popfd
    ; pop eax

    ; Call the D kernel's main function.
    ; Ensure kmain is defined in your D code and marked `extern (C)`.
    call kmain

    ; If kmain ever returns (it shouldn't for a kernel), halt the system.
hang:
    cli
    hlt
    jmp hang

section .bss
align 16 ; Align to 16 bytes for performance/compatibility
stack_bottom:
    resb 16384 ; Reserve 16KB for the stack (adjust as needed)
stack_top:    ; Label for the top of the stack (highest address)
