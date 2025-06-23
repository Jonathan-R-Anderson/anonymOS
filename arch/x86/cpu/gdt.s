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

# DEBUG OUTPUT ---------------------------------------------------------------
# Debug helper uses QEMU debug port (0xE9) to print characters so we can trace
# execution early in boot without relying on higher level routines.  The helper
# functions defined below allow dumping register state in hexadecimal.

.set DEBUG_PORT, 0xE9

.section .rodata
.align 1
.Lhex_digits:
    .ascii "0123456789ABCDEF"
.Lstr_RAX: .ascii "RAX: "
    .byte 0
.Lstr_RBX: .ascii "RBX: "
    .byte 0
.Lstr_RCX: .ascii "RCX: "
    .byte 0
.Lstr_RDX: .ascii "RDX: "
    .byte 0
.Lstr_RSI: .ascii "RSI: "
    .byte 0
.Lstr_RDI: .ascii "RDI: "
    .byte 0
.Lstr_RSP: .ascii "RSP: "
    .byte 0
.Lstr_RBP: .ascii "RBP: "
    .byte 0
.Lnewline:
    .byte 0x0A, 0
.text
 
gdt_flush:
    # x86-64 System V ABI: first argument (pointer to GdtPtr) is in %rdi
    pushq %rbx               # Preserve callee-saved register
    call debug_dump_state

    lgdt (%rdi)         # Load the GDT pointer. GdtPtr struct in D needs 64-bit base.
    call debug_dump_state

     # Reload segment registers.  We use Linux-style selector macros
     # similar to those found in <asm/segment.h> to avoid hard-coded values.
    movw $__KERNEL_DS, %ax   # Selector for kernel data segment
    call debug_dump_state
    movw %ax, %ds
    call debug_dump_state
    movw %ax, %es
    call debug_dump_state
    movw %ax, %ss
    call debug_dump_state
    movw %ax, %fs
    call debug_dump_state
    movw %ax, %gs
    call debug_dump_state

     # Far return sequence to reload CS. In 64-bit mode `lretq` pops an 8-byte
     # RIP followed by an 8-byte CS value from the stack.  We therefore push the
     # selector as a full 64-bit quantity so that the stack layout matches what
     # `lretq` expects.
    leaq .Lflush_cs_label(%rip), %rax  # Address to continue after CS reload
    call debug_dump_state
    pushq $__KERNEL_CS                # New CS selector (kernel code segment)
    call debug_dump_state
    pushq %rax                        # Target RIP
    call debug_dump_state
    lretq                             # Pops RIP then CS

     # Old versions of this file provided a far pointer here for an alternate
     # `ljmp`-based sequence.  It served no purpose and was being disassembled
     # as instructions when debugging.  Removing it keeps the text section
     # clean and ensures the return address points directly to the label below.
 
.Lflush_cs_label:
    # Execution continues here with CS reloaded.
    # %rbx was saved on entry and should remain intact.
    call debug_dump_state
    popq %rbx           # Restore %rbx
    call debug_dump_state
    retq                # Return to caller (init_gdt in D)
    .size gdt_flush, .-gdt_flush

# ---------------------------------------------------------------------------
# Debug helper routines

.global debug_out_char
.type debug_out_char, @function
debug_out_char:
    push %dx
    mov $DEBUG_PORT, %dx
    outb %al, %dx
    pop %dx
    retq

.global debug_out_string
.type debug_out_string, @function
debug_out_string:
    push %rsi
    push %rax
1:
    movb (%rsi), %al
    test %al, %al
    je 2f
    call debug_out_char
    inc %rsi
    jmp 1b
2:
    pop %rax
    pop %rsi
    retq

.global debug_out_hex64
.type debug_out_hex64, @function
debug_out_hex64:
    push %rax
    push %rbx
    push %rcx
    push %rdx
    mov %rdi, %rax
    mov $'0', %al
    call debug_out_char
    mov $'x', %al
    call debug_out_char
    mov $60, %rcx
3:
    mov %rdi, %rax
    shr %cl, %rax
    and $0xF, %rax
    lea .Lhex_digits(%rip), %rdx
    movb (%rdx,%rax,1), %al
    call debug_out_char
    sub $4, %rcx
    jns 3b
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    retq

.global debug_dump_state
.type debug_dump_state, @function
debug_dump_state:
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %rsp
    mov $.Lnewline, %rsi
    call debug_out_string

    mov $.Lstr_RAX, %rsi
    call debug_out_string
    mov 56(%rsp), %rdi
    call debug_out_hex64
    mov $.Lnewline, %rsi
    call debug_out_string

    mov $.Lstr_RBX, %rsi
    call debug_out_string
    mov 48(%rsp), %rdi
    call debug_out_hex64
    mov $.Lnewline, %rsi
    call debug_out_string

    mov $.Lstr_RCX, %rsi
    call debug_out_string
    mov 40(%rsp), %rdi
    call debug_out_hex64
    mov $.Lnewline, %rsi
    call debug_out_string

    mov $.Lstr_RDX, %rsi
    call debug_out_string
    mov 32(%rsp), %rdi
    call debug_out_hex64
    mov $.Lnewline, %rsi
    call debug_out_string

    mov $.Lstr_RSI, %rsi
    call debug_out_string
    mov 24(%rsp), %rdi
    call debug_out_hex64
    mov $.Lnewline, %rsi
    call debug_out_string

    mov $.Lstr_RDI, %rsi
    call debug_out_string
    mov 16(%rsp), %rdi
    call debug_out_hex64
    mov $.Lnewline, %rsi
    call debug_out_string

    mov $.Lstr_RSP, %rsi
    call debug_out_string
    mov (%rsp), %rdi
    call debug_out_hex64
    mov $.Lnewline, %rsi
    call debug_out_string

    mov $.Lstr_RBP, %rsi
    call debug_out_string
    mov 8(%rsp), %rdi
    call debug_out_hex64
    mov $.Lnewline, %rsi
    call debug_out_string

    pop %rsp
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    retq

 .section .note.GNU-stack, "", @progbits # Mark stack as non-executable
