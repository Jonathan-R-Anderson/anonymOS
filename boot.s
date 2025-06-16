; boot.s
; Multiboot header constants
%define ALIGN    (1<<0)             ; Align loaded modules on page boundaries
%define MEMINFO  (1<<1)             ; Provide memory map
%define FLAGS    (ALIGN | MEMINFO)  ; Multiboot 'flag' field
%define MAGIC    0x1BADB002         ; Magic number for Multiboot
%define CHECKSUM -(MAGIC + FLAGS)   ; Checksum

;
 ; Section for the Multiboot header.
 ; It must be within the first 8KB of the kernel file.
 ; It must be 4-byte aligned.
 ;
section .multiboot_header
align 4
    dd MAGIC
    dd FLAGS
    dd CHECKSUM

;
 ; Define a small stack for our kernel.
 ; This goes into the .bss section (uninitialized data).
;
section .bss
align 16
stack_bottom:
    resb 16384  ; 16 KiB stack
stack_top:

; Kernel entry point
section .text
global _start
; type _start, @function ; NASM doesn't use .type in this way for ELF, it's often implicit.
_start:
    ; Set up the stack pointer. GRUB loads us high enough.
    mov esp, stack_top

    ; Call the D kernel's main function (kmain).
    extern kmain ; Declare kmain as external
    call kmain

    ; If kmain returns (it shouldn't), halt the CPU.
    cli
hang:
    hlt
    jmp hang
; .size _start, . - _start ; NASM doesn't use .size this way. Linker handles symbol size.