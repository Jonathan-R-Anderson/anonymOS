; boot.s
; Sets up the Multiboot header, stack, and calls kmain.
bits 32 ; Ensure the entire file is assembled in 32-bit mode


; Multiboot header constants
MBALIGN  equ  1<<0            ; Align loaded modules on page boundaries
MEMINFO  equ  1<<1            ; Provide memory map
FLAGS    equ  MBALIGN | MEMINFO ; Our Multiboot header flags
MAGIC    equ  0x1BADB002      ; Multiboot magic number
CHECKSUM equ -(MAGIC + FLAGS) ; Checksum

; Define the Multiboot header in its own section.
; The linker script will place this section correctly.
section .multiboot_header
align 4
    dd MAGIC
    dd FLAGS
    dd CHECKSUM
    ; The following address fields are optional if bit 16 of flags is not set.
    ; We are not setting bit 16, so they are not strictly needed by GRUB
    ; but some people include them for clarity or other bootloaders.
    ; dd 0 ; header_addr (physical address of this header)
    ; dd 0 ; load_addr (physical address of the start of .text)
    ; dd 0 ; load_end_addr (physical address of the end of all kernel sections)
    ; dd 0 ; bss_end_addr (physical address of the end of .bss)
    ; dd _start ; entry_addr (physical address of the _start symbol)

section .bss
align 16
stack_bottom:
    resb 16384 ; 16 KiB stack
stack_top:

section .text._start, "ax", @progbits ; Place _start in its own subsection, "ax" = allocatable, executable

global _start      ; Export the _start symbol
extern kmain       ; kmain is defined in D, ensure it's C-callable

_start:
    ; CPU is in 32-bit protected mode.
    ; GRUB has already set up a GDT. We'll set up our own later in kmain.

    ; Set up the stack
    mov esp, stack_top ; Point ESP to the top of our stack

    ; Push Multiboot magic (EAX) and info structure pointer (EBX) for kmain, if needed.
    ; For now, kmain doesn't expect them, so we can skip.
    ; push eax
    ; push ebx

    call kmain         ; Call the D kernel's main function

    ; If kmain returns (it shouldn't for a kernel), halt the system.
cli_halt_loop:
    cli                ; Disable interrupts
    hlt                ; Halt the CPU
    jmp cli_halt_loop  ; Loop indefinitely

; Add this section to prevent executable stack warnings.
section .note.GNU-stack noalloc noexec nowrite progbits