# idt_loader.s (AT&T syntax, 64-bit)
# Contains idt_load function to load the IDT.

.section .text
.global idt_load
# idt_ptr is defined in D code; its address will be passed.

.code64
idt_load:
    # x86-64 System V ABI: first argument (pointer to IDTPtr struct) is in %rdi.
    # The IDTPtr struct in D code must have a 64-bit base address for its 'base' field.
    lidt (%rdi)         # Load IDT register using the pointer in %rdi.
    retq                # Return from function.

.section .note.GNU-stack, "", @progbits # Mark stack as non-executable
