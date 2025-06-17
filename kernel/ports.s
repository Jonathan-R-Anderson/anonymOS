; kernel/ports.s
; Low-level port I/O functions

section .text

global outb
global inb

;-----------------------------------------------------------------------------
; void outb(ushort port, ubyte value)
; Writes a byte to an I/O port.
; Arguments (cdecl calling convention):
;   [ebp + 8]: ushort port (port number)
;   [ebp + 12]: ubyte value (byte to write, promoted to 4 bytes on stack)
;-----------------------------------------------------------------------------
outb:
    push ebp
    mov ebp, esp

    mov dx, [ebp + 8]   ; Load port into DX
    mov al, [ebp + 12]  ; Load value into AL

    out dx, al          ; Output byte from AL to port DX
    nop                 ; Short delay, common practice after I/O
    nop

    mov esp, ebp
    pop ebp
    ret

;-----------------------------------------------------------------------------
; ubyte inb(ushort port)
; Reads a byte from an I/O port.
; Arguments (cdecl calling convention):
;   [ebp + 8]: ushort port (port number)
; Returns:
;   ubyte value in AL (D will handle this correctly for ubyte return type)
;-----------------------------------------------------------------------------
inb:
    push ebp
    mov ebp, esp

    mov dx, [ebp + 8]   ; Load port into DX
    in al, dx           ; Input byte from port DX into AL
    nop                 ; Short delay
    nop

    ; Result is in AL. For ubyte return, D expects it here.
    ; movzx eax, al ; Optional: zero-extend AL to EAX if full register needed by ABI,
                    ; but D's extern(C) ubyte return should handle AL directly.

    mov esp, ebp
    pop ebp
    ret