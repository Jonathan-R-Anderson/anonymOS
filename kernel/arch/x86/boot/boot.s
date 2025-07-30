# boot.s (AT&T syntax, 64-bit)
.section .multiboot_header
.align 8
multiboot2_header_start:
    .long 0xe85250d6              # MULTIBOOT2_HEADER_MAGIC
    .long 0                      # MULTIBOOT_ARCHITECTURE_I386
    .long multiboot2_header_end - multiboot2_header_start
    .long -(0xe85250d6 + 0 + (multiboot2_header_end - multiboot2_header_start))

.align 8
    .word 0                      # MULTIBOOT_HEADER_TAG_END
    .word 0
    .long 8
multiboot2_header_end:

.section .bss
.align 16
stack:
    .space 16384
stack_top:

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
    .quad 0x0000000000000000
    .quad 0x00af9a000000ffff     # code
    .quad 0x00cf92000000ffff     # data
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

    # Enable PAE
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4

    # Set CR3
    movl $pml4_table, %eax
    movl %eax, %cr3

    # Enable Long Mode via EFER
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x00000100, %eax
    wrmsr

    # Enable Paging
    movl %cr0, %eax
    orl $0x80000000, %eax
    movl %eax, %cr0

    # Long mode jump
    ljmp $0x08, $long_mode_start

# setup_page_tables - simplified, maps 0–2MiB
setup_page_tables:
    movl $pd_table, %edi
    movl $0x00000083, %eax     # 2MiB page
    movl %eax, (%edi)
    movl $0, 4(%edi)

    movl $pd_table, %eax
    orl $0x3, %eax
    movl %eax, pdpt_table
    movl $0, pdpt_table+4

    movl $pdpt_table, %eax
    orl $0x3, %eax
    movl %eax, pml4_table
    movl $0, pml4_table+4

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

    # Clear BSS
    lea _bss_start(%rip), %rdi
    lea _bss_end(%rip), %rcx
    xor %rax, %rax
.Lclear_bss:
    cmp %rcx, %rdi
    jge .Lbss_done
    movq %rax, (%rdi)
    add $8, %rdi
    jmp .Lclear_bss
.Lbss_done:

    # Multiboot2 info: pass rbx and rax
    movq %rbx, %rdi
    movl %eax, %esi

    call kmain

.Lhalt:
    cli
    hlt
    jmp .Lhalt
