; gdt.s
global gdt_flush

gdt_flush:
    mov eax, [esp+4] ; Argument: address of GdtPtr
    lgdt [eax]       ; Load GDT pointer

    mov ax, 0x10     ; 0x10 is offset of kernel data segment
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    jmp 0x08:.flush  ; 0x08 is offset of kernel code segment. Far jump to reload CS.
.flush:
    ret