# gdt.s (AT&T syntax, 64-bit)
# Contains gdt_flush function to load the GDT and refresh segment registers.

.section .text
.global gdt_flush

# VGA Debugging Constants
.set DEBUG_VGA_BASE, 0xB8000
.set DEBUG_VGA_ATTR, 0x0F00  # White on Black

gdt_flush:
    # x86-64 System V ABI: first argument (pointer to GdtPtr) is in %rdi
    # Save %rbx as we'll use it for VGA debugging
    pushq %rbx
    movq $DEBUG_VGA_BASE, %rbx
    movw $(DEBUG_VGA_ATTR + 'A'), (%rbx, 20*2) # Marker 'A' at offset 20

    movw $(DEBUG_VGA_ATTR + 'B'), (%rbx, 21*2) # Marker 'B' at offset 21
    lgdt (%rdi)         # Load the GDT pointer. GdtPtr struct in D needs 64-bit base.
    movw $(DEBUG_VGA_ATTR + 'C'), (%rbx, 22*2) # Marker 'C' at offset 22

    # Reload segment registers.
    # In 64-bit long mode, DS, ES, SS are generally implicitly flat or loaded with a null selector.
    # CS is loaded via a far jump/return. FS and GS can be used for OS-specific purposes (e.g., TLS).
    # We'll load 0x10 into data segments, assuming the GDT has a valid 64-bit data segment descriptor there.
    # The GDT itself must define these segments appropriately for long mode.
    movw $0x10, %ax     # Selector for kernel data segment (GDT entry 2)
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw $(DEBUG_VGA_ATTR + 'D'), (%rbx, 23*2) # Marker 'D' at offset 23

    # Far jump to reload CS. 0x08 is the selector for our 64-bit code segment (GDT entry 1).
    # AT&T syntax for far jump: ljmp $segment, $offset
    # A common way to reload CS in 64-bit is to push the new CS selector and a return address, then lretq.
    movw $(DEBUG_VGA_ATTR + 'E'), (%rbx, 24*2) # Marker 'E' at offset 24
    pushq $0x08         # Push new CS selector (kernel code segment)
    pushq $.Lflush_cs_label # Push address of the label to "return" to
    lretq               # Long return; pops RIP, then CS.

.Lflush_cs_label:
    # This code is now executing with the new CS.
    movw $(DEBUG_VGA_ATTR + 'L'), (%rbx, 25*2) # Marker 'L' at offset 25

    movw $(DEBUG_VGA_ATTR + 'R'), (%rbx, 26*2) # Marker 'R' at offset 26
    popq %rbx           # Restore %rbx
    retq                # Return to caller (init_gdt in D)

.section .note.GNU-stack, "", @progbits # Mark stack as non-executable
