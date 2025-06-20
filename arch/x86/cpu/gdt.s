# gdt.s (AT&T syntax, 64-bit)
# Contains gdt_flush function to load the GDT and refresh segment registers.

.section .text
.global gdt_flush
.type gdt_flush, @function

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
    # Using ljmp avoids any stack manipulation quirks that could corrupt the return
    # address when using a lretq based sequence.
    ljmp $0x08, $.Lflush_cs_label

.Lflush_cs_label:
    # Execution continues here with CS reloaded. Other registers are unaffected,
    # so %rbx should still contain the value saved at the start of gdt_flush.

    popq %rbx           # Restore %rbx
    retq                # Return to caller (init_gdt in D)
    .size gdt_flush, .-gdt_flush

.section .note.GNU-stack, "", @progbits # Mark stack as non-executable
