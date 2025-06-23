 # gdt.s (AT&T syntax, 64-bit)
 # Contains gdt_flush function to load the GDT and refresh segment registers.
 
.section .text
.global gdt_flush
.type gdt_flush, @function
.code64

# -----------------------------------------------------------------------------
# Segment selector constants derived from Linux's <asm/segment.h> layout.
# They must match the indices used in kernel.arch_interface.gdt.d
# (null descriptor = 0, kernel code = 1, kernel data = 2).

.set GDT_ENTRY_KERNEL_CODE, 1
.set GDT_ENTRY_KERNEL_DATA, 2
.set __KERNEL_CS, (GDT_ENTRY_KERNEL_CODE * 8)
.set __KERNEL_DS, (GDT_ENTRY_KERNEL_DATA * 8)

 
gdt_flush:
    # x86-64 System V ABI: first argument (pointer to GdtPtr) is in %rdi
    pushq %rbx               # Preserve callee-saved register

    lgdt (%rdi)              # Load the GDT pointer.

     # Reload segment registers.  We use Linux-style selector macros
     # similar to those found in <asm/segment.h> to avoid hard-coded values.
    movw $__KERNEL_DS, %ax   # Selector for kernel data segment
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs

    # Reload CS using a far jump.  This flushes the instruction queue and
    # ensures execution continues in the code segment defined in the new GDT.
    leaq .Lflush_cs_label(%rip), %rax  # Address to continue after CS reload
    # Perform the far jump using `ljmp` rather than a push/lretq sequence.
    # This avoids subtle stack alignment problems seen during early boot.
    ljmp $__KERNEL_CS, $.Lflush_cs_label

.Lflush_cs_label:
    # Execution continues here with CS reloaded.
    # %rbx was saved on entry and should remain intact.
    popq %rbx           # Restore %rbx
    retq                # Return to caller (init_gdt in D)
    .size gdt_flush, .-gdt_flush

 .section .note.GNU-stack, "", @progbits # Mark stack as non-executable
