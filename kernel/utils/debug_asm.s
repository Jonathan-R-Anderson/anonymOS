# kernel/utils/debug_asm.s (AT&T syntax, 64-bit)
# Assembly stubs for functions declared in D code.

.section .text      # Correct AT&T syntax for section directive
.global gdt_debug_print_limit
.code64
gdt_debug_print_limit:
    # This is a stub function for gdt_debug_print_limit.
    # It's likely called from kernel/gdt.d.
    # You can add actual debug printing logic here later if needed.
    retq

.section .note.GNU-stack, "", @progbits