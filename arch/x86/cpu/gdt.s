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

     # Far return sequence to reload CS. In 64-bit mode `lretq` pops an 8-byte
     # RIP followed by an 8-byte CS value from the stack.  We therefore push the
     # selector as a full 64-bit quantity so that the stack layout matches what
     # `lretq` expects.
     leaq .Lflush_cs_label(%rip), %rax  # Address to continue after CS reload
     pushq $0x08                       # New CS selector (kernel code segment)
     pushq %rax                        # Target RIP
     lretq                             # Pops RIP then CS

     # Old versions of this file provided a far pointer here for an alternate
     # `ljmp`-based sequence.  It served no purpose and was being disassembled
     # as instructions when debugging.  Removing it keeps the text section
     # clean and ensures the return address points directly to the label below.
 
 .Lflush_cs_label:
     # Execution continues here with CS reloaded.
     # %rbx was saved on entry and should remain intact.
     popq %rbx           # Restore %rbx
     retq                # Return to caller (init_gdt in D)
     .size gdt_flush, .-gdt_flush
 
 .section .note.GNU-stack, "", @progbits # Mark stack as non-executable