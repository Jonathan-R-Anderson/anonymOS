.set ALIGN,      1 << 0
.set MEMINFO,    1 << 1
.set FLAGS,      ALIGN | MEMINFO
.set MAGIC,      0x1BADB002
.set CHECKSUM,   -(MAGIC + FLAGS)

.set CODE_SEG,   0x08
.set DATA_SEG,   0x10
.set IA32_EFER,  0xC0000080
.set IA32_FS_BASE, 0xC0000100
.set CR0_PG,     0x80000000
.set CR4_PAE,    0x00000020

.section .multiboot
.align 4
.long MAGIC
.long FLAGS
.long CHECKSUM

.section .bss
.align 16
stack_bottom:
    .skip 16384
stack_top:

.section .text
.code32
.global _start
.type _start, @function
.extern kmain
.extern handleInvalidOpcode
_start:
    cli
    movl %eax, saved_magic
    movl %ebx, saved_info
    mov $stack_top, %esp

    lgdt gdt64_descriptor

    mov %cr4, %eax
    orl $CR4_PAE, %eax
    mov %eax, %cr4

    mov $pml4_table, %eax
    mov %eax, %cr3

    mov $IA32_EFER, %ecx
    rdmsr
    orl $0x00000100, %eax   # enable long mode
    wrmsr

    mov %cr0, %eax
    orl $CR0_PG, %eax
    mov %eax, %cr0

    ljmp $CODE_SEG, $long_mode_entry

.size _start, . - _start

.code64
.type long_mode_entry, @function
long_mode_entry:
    mov $DATA_SEG, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov %ax, %fs
    mov %ax, %gs

    leaq stack_top(%rip), %rsp
    xor %rbp, %rbp

    /* Set up the bootstrap thread's TLS block and FS base. */
    leaq __initial_tcb(%rip), %rax
    mov %rax, %rdi
    mov %rdi, (%rdi)
    mov $IA32_FS_BASE, %ecx
    mov %rdi, %rax
    mov %rax, %rdx
    shr $32, %rdx
    wrmsr

    mov %cr0, %rax
    or $0x22, %rax
    mov %rax, %cr0

    mov %cr4, %rax
    or $0x600, %rax
    mov %rax, %cr4

    movl saved_magic(%rip), %edi
    movl saved_info(%rip), %esi

    call kmain

.hang:
    hlt
    jmp .hang

.size long_mode_entry, . - long_mode_entry

.global invalidOpcodeStub
.type invalidOpcodeStub, @function
invalidOpcodeStub:
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rdi
    pushq %rsi
    pushq %rbp
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax

    mov %rsp, %rdi
    mov 120(%rsp), %rcx
    mov 128(%rsp), %r8
    mov 136(%rsp), %r9
    mov $6, %rsi
    xor %rdx, %rdx

    pushq $0
    call handleInvalidOpcode
    add $8, %rsp

    popq %rax
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    iretq

.size invalidOpcodeStub, . - invalidOpcodeStub

.global loadIDT
.type loadIDT, @function
loadIDT:
    lidt (%rdi)
    ret

.size loadIDT, . - loadIDT
.global stack_top

.section .data
.align 8
saved_magic:
    .quad 0
saved_info:
    .quad 0

.align 16
gdt64:
    .quad 0x0000000000000000
    .quad 0x00AF9A000000FFFF
    .quad 0x00AF92000000FFFF
gdt64_end:

gdt64_descriptor:
    .word gdt64_end - gdt64 - 1
    .long gdt64

.align 4096
pml4_table:
    .quad pdpt_table + 0x03
    .fill 511, 8, 0

.align 4096
pdpt_table:
    .quad pd_table + 0x03
    .fill 511, 8, 0

.align 4096
pd_table:
    .quad 0x0000000000000083
    .fill 511, 8, 0
