# tss.s - Task State Segment helpers (AT&T syntax, 64-bit)

.section .text
.code64

## tss_flush()
## Convenience wrapper that loads the Task Register using the
## TSS descriptor at selector 0x28.  Reuses load_tss so the
## actual register manipulation stays in one place.
.global tss_flush
.type tss_flush, @function
tss_flush:
    movw $0x28, %di
    call load_tss
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
