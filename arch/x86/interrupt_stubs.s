.intel_syntax noprefix
.global isr_general_protection

isr_general_protection:
    cli
    hlt
    jmp isr_general_protection
