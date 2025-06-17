; kernel/debug_utils.s
; Provides utility functions, e.g., for debug printing.

section .text
global gdt_debug_print_limit

; extern (C) void gdt_debug_print_limit(ushort limit_val,
;                                       const char* hex_chars_ptr,
;                                       uint vga_base,
;                                       ubyte attr_byte,
;                                       ubyte char_c);
;
; Stack layout after call and push ebp:
; [ebp + 24] : char_c (1 byte, promoted to 4 bytes on stack)
; [ebp + 20] : attr_byte (1 byte, promoted to 4 bytes on stack)
; [ebp + 16] : vga_base (uint)
; [ebp + 12] : hex_chars_ptr (const char*)
; [ebp + 8]  : limit_val (ushort, promoted to 4 bytes on stack)
; [ebp + 4]  : return address
; [ebp]      : old ebp

gdt_debug_print_limit:
    push ebp
    mov ebp, esp

    ; Save callee-saved registers if modified (esi, edi, ebx are typically callee-saved)
    ; The original inline assembly clobbered eax, ebx, ecx, edx, esi, edi.
    push edi
    push esi
    push ebx
    ; ecx, edx, eax are caller-saved, but we'll push them for safety/simplicity here
    ; matching the clobber list.
    push ecx
    push edx

    ; Load arguments into registers
    movzx cx, word [ebp + 8]    ; cx = limit_val (ushort)
    mov esi, [ebp + 12]         ; esi = hex_chars_ptr
    mov edi, [ebp + 16]         ; edi = vga_base
    mov ah, [ebp + 20]          ; ah = attr_byte (ubyte)
    mov al, [ebp + 24]          ; al = char_c (ubyte)

    ; Write the prefix character (e.g., 'C')
    ; Original: "movw %%ax, 50(%%edi);\n"
    mov [edi + 50], ax          ; Writes char_c (in al) and attr_byte (in ah)

    ; Process limit_val (in cx) nibble by nibble
    ; Nibble 1 (highest: bits 12-15 of limit_val)
    mov ax, cx
    shr ax, 12
    and al, 0x0F
    movzx ebx, al
    mov dl, [esi + ebx]         ; Get hex char
    mov al, dl
    ; ah still contains attr_byte
    mov [edi + 52], ax

    ; Nibble 2 (bits 8-11)
    mov ax, cx
    shr ax, 8
    and al, 0x0F
    movzx ebx, al
    mov dl, [esi + ebx]
    mov al, dl
    mov [edi + 54], ax

    ; Nibble 3 (bits 4-7)
    mov ax, cx
    shr ax, 4
    and al, 0x0F
    movzx ebx, al
    mov dl, [esi + ebx]
    mov al, dl
    mov [edi + 56], ax

    ; Nibble 4 (lowest: bits 0-3)
    mov ax, cx
    and al, 0x0F
    movzx ebx, al
    mov dl, [esi + ebx]
    mov al, dl
    mov [edi + 58], ax

    ; Restore registers
    pop edx
    pop ecx
    pop ebx
    pop esi
    pop edi

    mov esp, ebp
    pop ebp
    ret