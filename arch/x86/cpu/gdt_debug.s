; gdt_debug.s
; Assembly routine to print GDT limit details to VGA for debugging.
; extern (C) void gdt_debug_print_limit(ushort limit_val, const char* hex_chars_ptr, uint vga_base, ubyte attr_byte, ubyte char_c);

.section .text
.global gdt_debug_print_limit

gdt_debug_print_limit:
    push ebp
    mov ebp, esp

    ; Argument retrieval from stack (C calling convention, right to left push)
    ; [ebp+8]  -> limit_val (ushort)
    ; [ebp+12] -> hex_chars_ptr (char*)
    ; [ebp+16] -> vga_base (uint)
    ; [ebp+20] -> attr_byte (ubyte)
    ; [ebp+24] -> char_c (ubyte)

    movzx ecx, word [ebp+8]     ; ECX = limit_val (ushort, zero-extended)
    mov esi, [ebp+12]           ; ESI = hex_chars_ptr
    mov edi, [ebp+16]           ; EDI = vga_base
    movzx ebx, byte [ebp+20]    ; EBX = attr_byte (zero-extended to save AH later)
    movzx eax, byte [ebp+24]    ; EAX = char_c (zero-extended to save AL later)

    ; Store attribute and 'C' char for VGA word construction
    mov ah, bl  ; AH = attr_byte
    mov al, al  ; AL = char_c (already there from movzx eax)

    ; Print 'C' at offset 25 (VGA memory: EDI + 50)
    mov word [edi + 50], ax

    ; Save original limit_val (in ECX) as we'll modify EAX for digit calculation
    push ecx

    ; Nibble 3 (bits 12-15 of limit) at offset 26 (VGA: EDI + 52)
    mov ecx, [esp]              ; Get original limit value from stack
    mov eax, ecx                ; EAX = working copy of limit
    shr ax, 12                  ; Shift high nibble (bits 12-15) into lower 4 bits of AL
    and al, 0x0F                ; AL = value of nibble 3 (0-15)
    movzx ebx, al               ; EBX = zero-extended AL (index for hex_chars array)
    mov dl, [esi + ebx]         ; DL = HEX_CHARS_ASM_ARRAY[index] (the character '0'-'F')
    ; Form word for VGA: (attr_byte << 8) | DL
    mov al, dl                  ; AL = hex char
    mov ah, byte [ebp+20]       ; AH = attr_byte
    mov word [edi + 52], ax     ; Write to VGA

    ; Nibble 2 (bits 8-11 of limit) at offset 27 (VGA: EDI + 54)
    mov ecx, [esp]              ; Get original limit value
    mov eax, ecx
    shr ax, 8
    and al, 0x0F
    movzx ebx, al
    mov dl, [esi + ebx]
    mov al, dl
    mov ah, byte [ebp+20]
    mov word [edi + 54], ax

    ; Nibble 1 (bits 4-7 of limit) at offset 28 (VGA: EDI + 56)
    mov ecx, [esp]
    mov eax, ecx
    shr ax, 4
    and al, 0x0F
    movzx ebx, al
    mov dl, [esi + ebx]
    mov al, dl
    mov ah, byte [ebp+20]
    mov word [edi + 56], ax

    ; Nibble 0 (bits 0-3 of limit) at offset 29 (VGA: EDI + 58)
    mov ecx, [esp]
    mov eax, ecx
    and al, 0x0F
    movzx ebx, al
    mov dl, [esi + ebx]
    mov al, dl
    mov ah, byte [ebp+20]
    mov word [edi + 58], ax

    pop ecx                     ; Clean up stack (remove pushed limit_val)

    mov esp, ebp                ; Restore stack pointer
    pop ebp                     ; Restore base pointer
    ret
