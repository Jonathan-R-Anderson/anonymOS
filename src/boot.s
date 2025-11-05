.set ALIGN,      1 << 0
.set MEMINFO,    1 << 1
.set FLAGS,      ALIGN | MEMINFO
.set MAGIC,      0x1BADB002
.set CHECKSUM,   -(MAGIC + FLAGS)

.set CODE_SEG,   0x08
.set DATA_SEG,   0x10
.set IA32_EFER,  0xC0000080
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

    movl saved_magic(%rip), %edi
    movl saved_info(%rip), %esi

    call kmain

.hang:
    hlt
    jmp .hang

.size long_mode_entry, . - long_mode_entry
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
