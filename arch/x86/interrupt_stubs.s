.intel_syntax noprefix

## Simple ISR for the General Protection Fault (#GP)
#
# The previous implementation jumped to itself after halting the CPU,
# which effectively locked the system if a #GP was triggered before the
# full interrupt infrastructure was operational.  When the IDT was
# misconfigured (for example the timer vector accidentally pointing to
# this routine) QEMU would show an endless stream of interrupts and the
# CPU eventually reset.
#
# This stub mirrors the layout used by the generic interrupt stubs in
# `interrupts_asm.s`.  The CPU already pushed the error code for a #GP
# on the stack.  We only need to push the interrupt vector (13) and jump
# to `isr_common_stub` so the D handler can process the fault and return
# cleanly.

.global isr_general_protection
.extern isr_common_stub       # shared interrupt prologue/epilogue

isr_general_protection:
    cli                       # Disable further interrupts
    # error code pushed by CPU; push vector number and run common stub
    pushq $13                 # Interrupt vector
    jmp isr_common_stub
