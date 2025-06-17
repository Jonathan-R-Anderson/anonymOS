# ports.s (AT&T syntax, 64-bit)
# Low-level port I/O functions

.section .text
.code64

.global outb
.global inb
.global outw
.global inw
.global outl
.global inl

# void outb(ushort port, ubyte value)
# port in %di, value in %sil
outb:
    movw %di, %dx       # Load port into DX (16-bit)
    movb %sil, %al      # Load value into AL (8-bit)
    outb %al, %dx       # Output byte from AL to port DX
    # nop                 # Optional short delay
    # nop
    retq

# ubyte inb(ushort port)
# port in %di, returns ubyte in %al
inb:
    movw %di, %dx       # Load port into DX
    inb %dx, %al        # Input byte from port DX into AL
    # nop                 # Optional short delay
    # nop
    # Result (ubyte) is already in %al, which is correct for x86-64 System V ABI.
    # movzbl %al, %eax  # Zero-extend if a full 32-bit or 64-bit return was needed,
                        # but for ubyte, %al is sufficient.
    retq

# void outw(ushort port, ushort value)
# port in %di, value in %si
outw:
    movw %di, %dx       # Load port into DX
    movw %si, %ax       # Load value into AX
    outw %ax, %dx       # Output word from AX to port DX
    retq

# ushort inw(ushort port)
# port in %di, returns ushort in %ax
inw:
    movw %di, %dx       # Load port into DX
    inw %dx, %ax        # Input word from port DX into AX
    # Result (ushort) is already in %ax.
    retq

# void outl(ushort port, uint value)
# port in %di, value in %esi
outl:
    movw %di, %dx       # Load port into DX
    movl %esi, %eax     # Load value into EAX
    outl %eax, %dx      # Output dword from EAX to port DX
    retq

# uint inl(ushort port)
# port in %di, returns uint in %eax
inl:
    movw %di, %dx       # Load port into DX
    inl %dx, %eax       # Input dword from port DX into EAX
    # Result (uint) is already in %eax.
    retq

.section .note.GNU-stack, "", @progbits # Mark stack as non-executable