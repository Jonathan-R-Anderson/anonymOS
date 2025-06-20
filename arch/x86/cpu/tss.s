# tss.s - Task State Segment helpers (AT&T syntax, 64-bit)

.section .text
.code64

## tss_flush()
## Loads the task register with our TSS selector (assumes selector 0x28).
.global tss_flush
.type tss_flush, @function
tss_flush:
    movw $0x28, %ax
    ltr %ax
    retq
.size tss_flush, .-tss_flush

## load_tss(selector)
## Load the task register with the selector passed in DI.
.global load_tss
.type load_tss, @function
load_tss:
    movw %di, %ax
    ltr %ax
    retq

.section .note.GNU-stack, "", @progbits
