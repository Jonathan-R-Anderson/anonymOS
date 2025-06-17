# gdt.s (AT&T syntax, 64-bit)
# Contains gdt_flush function to load the GDT and refresh segment registers.

.section .text
.global gdt_flush

.set VGA_BASE, 0xB8000
.set DEBUG_OFFSET_START, 30
.set DEBUG_COLOR, 0x0F00    # White text on Black background. Add char code to this.

gdt_flush:
    # x86-64 System V ABI: first argument (pointer to GdtPtr) is in %rdi
    # Save callee-saved registers if used, but for this simple function,
    # we only use argument registers and %rax.

    # Debug output (optional, ensure VGA_BASE is accessible and mapped if paging is on)
    # For 64-bit, use 64-bit registers for addresses.
    # movq $VGA_BASE, %rbx # Use rbx as a temporary base for VGA
    # movw $(DEBUG_COLOR + 'A'), (%rbx, $DEBUG_OFFSET_START, 2) # Mark: Entry

    # movq %rdi, %rax # Move GdtPtr* into rax if needed for debug or other ops
    # movw $(DEBUG_COLOR + 'B'), (%rbx, $(DEBUG_OFFSET_START + 1), 2) # Mark: Before LGDT

    lgdt (%rdi)         # Load the GDT pointer. GdtPtr struct in D needs 64-bit base.

    # movw $(DEBUG_COLOR + 'C'), (%rbx, $(DEBUG_OFFSET_START + 2), 2) # Mark: After LGDT

    # Reload segment registers.
    # In 64-bit long mode, DS, ES, SS are generally implicitly flat or loaded with a null selector.
    # CS is loaded via a far jump/return. FS and GS can be used for OS-specific purposes (e.g., TLS).
    # We'll load 0x10 into data segments, assuming the GDT has a valid 64-bit data segment descriptor there.
    # The GDT itself must define these segments appropriately for long mode.

    movw $0x10, %ax     # Selector for kernel data segment (GDT entry 2)
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    # For FS and GS, you might load 0 or a specific selector if used.
    # xorw %ax, %ax # Example: Load 0 into FS/GS
    # movw %ax, %fs
    # movw %ax, %gs

    # movw $(DEBUG_COLOR + 'D'), (%rbx, $(DEBUG_OFFSET_START + 3), 2) # Mark: After DS/ES/SS load

    # Far jump to reload CS. 0x08 is the selector for our 64-bit code segment (GDT entry 1).
    # AT&T syntax for far jump: ljmp $segment, $offset
    # A common way to reload CS in 64-bit is to push the new CS selector and a return address, then lretq.
    pushq $0x08         # Push new CS selector (kernel code segment)
    pushq $.Lflush_cs_label # Push address of the label to "return" to
    lretq               # Long return; pops RIP, then CS.

.Lflush_cs_label:
    # This code is now executing with the new CS.
    # movw $(DEBUG_COLOR + 'E'), (%rbx, $(DEBUG_OFFSET_START + 4), 2) # Mark: After far JMP/lretq

    retq                # Return to caller (init_gdt in D)

.section .note.GNU-stack, "", @progbits # Mark stack as non-executable
