# keyboard_handler_asm_to_merge.s (AT&T syntax, 64-bit)
# Low-level ISR for keyboard (IRQ1)

.extern keyboard_interrupt_handler # This is the D function

.global irq1_handler # This is the entry point set in the IDT

.section .text
.code64
irq1_handler:
    # Save registers that might be clobbered by the D function or are needed by this handler.
    # According to x86-64 System V ABI, %rax, %rcx, %rdx, %rsi, %rdi, %r8-%r11 are caller-saved.
    # %rbx, %rbp, %r12-%r15 are callee-saved.
    # Since we call a D function, we should save caller-saved registers we use before the call,
    # or all of them if we want to be very safe or pass a full register struct.
    # For passing just a scancode, we only strictly need to save registers we use here if they
    # are callee-saved and modified.

    pushq %rax          # Save %rax as we use %al
    pushq %rdi          # Save %rdi as we use it for the argument
    pushq %rdx          # Save %rdx as we use it for port I/O (though inb uses %dx implicitly with %al)

    inb $0x60, %al      # Read scan code from keyboard data port (PS/2 port 0x60) into %al

    movzbl %al, %edi    # Zero-extend scancode from %al (8-bit) to %rdi (64-bit)
                        # The D function `keyboard_interrupt_handler(ubyte scancode)`
                        # will take the lower 8 bits of %rdi.

    call keyboard_interrupt_handler # Call the D language handler

    # Send EOI (End Of Interrupt)
    movb $0x20, %al     # EOI command code
    outb %al, $0x20     # Send EOI to Master PIC (port 0x20). IRQ1 is on Master PIC.
    # If IRQ > 7, an EOI would also be sent to the slave PIC (port 0xA0)

    popq %rdx
    popq %rdi
    popq %rax

    iretq               # Return from interrupt

.section .note.GNU-stack, "", @progbits # Mark stack as non-executable