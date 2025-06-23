.intel_syntax noprefix
# This assembly implements gdt_flush which installs the new
# GDT provided via pointer in RDI.  The previous version kept a
# dummy TSS symbol here and preserved RBX even though the register
# is never touched.  The extra symbol could lead to duplicate
# definitions when linking with other objects and the unnecessary
# push/pop complicates stack alignment.  Both have been removed
# for simplicity and reliability.

.section .text
.global gdt_flush
.type gdt_flush, @function
.code64

# Segment selector constants (must match GDT indices in gdt.d)
.set GDT_ENTRY_KERNEL_CODE, 1
.set GDT_ENTRY_KERNEL_DATA, 2
.set __KERNEL_CS, (GDT_ENTRY_KERNEL_CODE * 8)
.set __KERNEL_DS, (GDT_ENTRY_KERNEL_DATA * 8)

gdt_flush:
    # rdi = pointer to GdtPtr (limit + base)
    lgdt [rdi]                     # Load GDT pointer

    mov ax, __KERNEL_DS
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax

    # Reload CS via far return
    push __KERNEL_CS
    lea rax, [rip + .Lflush_cs_label]
    push rax
    lretq

.Lflush_cs_label:
    ret
    .size gdt_flush, .-gdt_flush

.section .note.GNU-stack, "", @progbits
