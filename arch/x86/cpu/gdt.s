# gdt.s (AT&T syntax, 64-bit)
# Contains gdt_flush function to load the GDT and refresh segment registers.

.section .text
.global gdt_flush

gdt_flush:
    # x86-64 System V ABI: first argument (pointer to GdtPtr) is in %rdi
    pushq %rbx               # Preserve callee-saved register

    lgdt (%rdi)         # Load the GDT pointer. GdtPtr struct in D needs 64-bit base.

    # Reload segment registers.
    # In 64-bit long mode, DS, ES, SS are generally implicitly flat or loaded with a null selector.
    # CS is loaded via a far jump/return. FS and GS can be used for OS-specific purposes (e.g., TLS).
    # We'll load 0x10 into data segments, assuming the GDT has a valid 64-bit data segment descriptor there.
    # The GDT itself must define these segments appropriately for long mode.
    movw $0x10, %ax     # Selector for kernel data segment (GDT entry 2)
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

    # Far jump to reload CS. 0x08 is the selector for our 64-bit code segment (GDT entry 1).
    # AT&T syntax for far jump: ljmp $segment, $offset
    # A common way to reload CS in 64-bit is to push the new CS selector and a return address, then lretq.
    pushq $0x08         # Push new CS selector (kernel code segment)
    pushq $.Lflush_cs_label # Push address of the label to "return" to
    lretq               # Long return; pops RIP, then CS.

.Lflush_cs_label:
    # This code is now executing with the new CS.
    # %rbx was set after entry to gdt_flush. After lretq, we are in a new context for CS,
    # but other GPRs like %rbx *should* be intact unless lretq itself somehow corrupted them
    # (highly unlikely if GDT is valid).
    # Re-establish rbx for safety if needed, but it should be fine.
    # If 'L' doesn't print, it might indicate %rbx was clobbered or stack issue during lretq.
    # For now, assume %rbx is still valid.

    popq %rbx           # Restore %rbx
    retq                # Return to caller (init_gdt in D)

.section .note.GNU-stack, "", @progbits # Mark stack as non-executable
