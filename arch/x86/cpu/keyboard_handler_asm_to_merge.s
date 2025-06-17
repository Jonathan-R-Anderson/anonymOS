; keyboard_handler_asm.s
; Low-level ISR for keyboard (IRQ1)
bits 32

extern keyboard_interrupt_handler ; This is the D function

global irq1_handler ; This is the entry point set in the IDT

irq1_handler:
    pusha ; Save all general purpose registers (eax, ecx, edx, ebx, esp, ebp, esi, edi)

    in al, 0x60 ; Read scan code from keyboard data port (PS/2 port 0x60)
    movzx eax, al ; Zero-extend AL into EAX to pass as ubyte/uint argument
    push eax      ; Push scan code onto stack for the D handler

    call keyboard_interrupt_handler ; Call the D language handler
    add esp, 4    ; Clean up stack (remove the pushed scan code)

    mov al, 0x20  ; EOI (End Of Interrupt) command code
    out 0x20, al  ; Send EOI to Master PIC (port 0x20). IRQ1 is on Master PIC.

    popa ; Restore all general purpose registers
    iret ; Return from interrupt

; Add this section to prevent executable stack warnings.
section .note.GNU-stack noalloc noexec nowrite progbits

; Add this section to prevent executable stack warnings.
section .note.GNU-stack noalloc noexec nowrite progbits