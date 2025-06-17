; idt_loader.s
bits 32

global idt_load
idt_load:
    mov eax, [esp+4]  ; Get pointer to IDTPtr struct from stack
    lidt [eax]        ; Load IDT register
    ret

; Add this section to prevent executable stack warnings.
section .note.GNU-stack noalloc noexec nowrite progbits

; Add this section to prevent executable stack warnings.
section .note.GNU-stack noalloc noexec nowrite progbits