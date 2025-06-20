# tss.s - load Task State Segment selector
.section .text
.global tss_flush
.type tss_flush, @function

# Loads the task register with the selector for our TSS descriptor
# Assumes the GDT has the TSS descriptor at index 5 (selector 0x28)
tss_flush:
    movw $0x28, %ax
    ltr %ax
    retq
.size tss_flush, .-tss_flush

.section .note.GNU-stack, "", @progbits
