.section .multiboot_header
.align 8
multiboot2_header_start:
    .long 0xe85250d6
    .long 0
    .long multiboot2_header_end - multiboot2_header_start
    .long -(0xe85250d6 + (multiboot2_header_end - multiboot2_header_start))
.align 8
    .word 0
    .word 0
    .long 8
multiboot2_header_end:

.section .data
.align 16
stack:
    .space 16384
stack_top = stack + 16384

.section .data
.align 4096
pml4_table:
    .space 4096
.align 4096
pdpt_table:
    .space 4096
.align 4096
pd_table:
    .space 4096

.section .data
.align 8
gdt_start:
    .quad 0x0
    .quad 0x00af9a000000ffff    # 64-bit code segment
    .quad 0x00cf92000000ffff
gdt_end:

gdt_desc:
    .word gdt_end - gdt_start - 1
    .long gdt_start

.section .text
.global _start
.extern kmain
.extern _bss_start
.extern _bss_end

.code32
_start:
    cli
    movl $stack_top, %esp
    lgdt gdt_desc
    call setup_page_tables
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4
    movl $pml4_table, %eax
    movl %eax, %cr3
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x00000100, %eax
    wrmsr
    movl %cr0, %eax
    orl $0x80000000, %eax
    movl %eax, %cr0
    ljmp $0x08, $long_mode_start

setup_page_tables:
    movl $pd_table, %edi
    movl $0x00000083, %eax
    movl %eax, (%edi)
    movl $0, 4(%edi)
    movl $0x00200083, %eax
    movl %eax, 8(%edi)
    movl $0, 12(%edi)
    movl $0x00400083, %eax
    movl %eax, 16(%edi)
    movl $0, 20(%edi)
    movl $pd_table, %eax
    orl $0x3, %eax
    movl $pdpt_table, %edi
    movl %eax, (%edi)
    movl $0, 4(%edi)
    movl $pdpt_table, %eax
    orl $0x3, %eax
    movl $pml4_table, %edi
    movl %eax, (%edi)
    movl $0, 4(%edi)

    # Map higher-half kernel at 0xFFFF800000000000
    movl $pml4_table + 8*256, %edi
    movl %eax, (%edi)
    movl $0, 4(%edi)
    ret

.code64
long_mode_start:
    movq $stack_top, %rsp
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs
    movq %cr0, %rax
    orq $0x22, %rax
    andq $~0x4, %rax
    movq %rax, %cr0
    movq %cr4, %rax
    orq $0x600, %rax
    movq %rax, %cr4
    lea _bss_start(%rip), %rdi
    lea _bss_end(%rip), %rcx
    xor %rax, %rax
1:
    cmp %rcx, %rdi
    jge 2f
    movq %rax, (%rdi)
    add $8, %rdi
    jmp 1b
2:
    movq %rbx, %rdi
    movl %eax, %esi
    call kmain
3:
    cli
    hlt
    jmp 3b
