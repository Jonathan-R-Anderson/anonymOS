; kernel/debug_stubs.s
; Assembly stubs for functions declared in D code.

section .text
global gdt_debug_print_limit
gdt_debug_print_limit:
    ; This is a stub function for gdt_debug_print_limit.
    ; It's likely called from kernel/gdt.d.
    ; You can add actual debug printing logic here later if needed.
    ret

; Add this section to prevent executable stack warnings.
section .note.GNU-stack noalloc noexec nowrite progbits