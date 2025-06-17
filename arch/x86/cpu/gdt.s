; gdt.s
bits 32

section .text
global gdt_flush

VGA_BASE equ 0xB8000
DEBUG_OFFSET_START equ 30 ; Start assembly debug characters at VGA offset 30
                          ; (e.g., (VGA_BASE + DEBUG_OFFSET_START * 2))
DEBUG_COLOR equ 0x0F00    ; White text on Black background. Add char code to this.



gdt_flush:
    ; Save EAX and EDI as we'll use them for debugging.
    push eax
    push edi

    mov edi, VGA_BASE
    mov word [edi + (DEBUG_OFFSET_START * 2)], DEBUG_COLOR + 'A' ; Mark: Entry

    ; Argument is at [esp + 12] because:
    ; esp -> pushed eax
    ; esp+4 -> pushed edi
    ; esp+8 -> return address
    ; esp+12 -> first argument to gdt_flush
    mov eax, [esp + 12] ; Argument: pointer to GdtPtr structure

    mov word [edi + ((DEBUG_OFFSET_START + 1) * 2)], DEBUG_COLOR + 'B' ; Mark: Before LGDT
    lgdt [eax]          ; Load the new GDT
    mov word [edi + ((DEBUG_OFFSET_START + 2) * 2)], DEBUG_COLOR + 'C' ; Mark: After LGDT

    ; Reload CS register with a far jump
    ; 0x08 is the selector for the kernel code segment (GDT entry 1)
    jmp 0x08:.flush_cs_label

.flush_cs_label:
    ; This code is now executing with the new CS.
    ; Reload edi for VGA writes.
    mov edi, VGA_BASE
    mov word [edi + ((DEBUG_OFFSET_START + 3) * 2)], DEBUG_COLOR + 'D' ; Mark: After far JMP

    mov ax, 0x10
    mov word [edi + ((DEBUG_OFFSET_START + 4) * 2)], DEBUG_COLOR + 'E' ; Mark: Before DS load

    mov ds, ax
    mov word [edi + ((DEBUG_OFFSET_START + 5) * 2)], DEBUG_COLOR + 'F' ; Mark: After DS load

    mov es, ax
    mov word [edi + ((DEBUG_OFFSET_START + 6) * 2)], DEBUG_COLOR + 'G' ; Mark: After ES load

    mov fs, ax
    mov word [edi + ((DEBUG_OFFSET_START + 7) * 2)], DEBUG_COLOR + 'H' ; Mark: After FS load

    mov gs, ax
    mov word [edi + ((DEBUG_OFFSET_START + 8) * 2)], DEBUG_COLOR + 'I' ; Mark: After GS load

    mov ss, ax
    mov word [edi + ((DEBUG_OFFSET_START + 9) * 2)], DEBUG_COLOR + 'J' ; Mark: After SS load


    mov word [edi + ((DEBUG_OFFSET_START + 10) * 2)], DEBUG_COLOR + 'K' ; Mark: Before RET

    pop edi
    pop eax
    ret          ; Return to caller (init_gdt in D)

; Add this section to prevent executable stack warnings.
section .note.GNU-stack noalloc noexec nowrite progbits

; Add this section to prevent executable stack warnings.
section .note.GNU-stack noalloc noexec nowrite progbits
