; idt.s
global idt_load

idt_load:
    mov eax, [esp+4]  ; Argument: address of IdtPtr
    lidt [eax]        ; Load IDT pointer
    ret