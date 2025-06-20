# tss.s (AT&T syntax, 64-bit)
# Provides a routine to load the Task Register with the
# selector for our TSS descriptor in the GDT.

.section .text
.code64
.global load_tss
.type load_tss, @function

load_tss:
    # x86-64 System V ABI: first argument is in %di
    movw %di, %ax
    ltr %ax            # Load the Task Register with the selector
    retq

.section .note.GNU-stack, "", @progbits
