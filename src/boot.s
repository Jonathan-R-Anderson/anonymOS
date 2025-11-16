.set ALIGN,         1 << 0
.set MEMINFO,       1 << 1
.set FLAGS,         ALIGN | MEMINFO
.set MAGIC,         0x1BADB002
.set CHECKSUM,      -(MAGIC + FLAGS)

.set CODE_SEG,      0x08
.set DATA_SEG,      0x10
.set IA32_EFER,     0xC0000080
.set IA32_FS_BASE,  0xC0000100
.set CR0_PG,        0x80000000
.set CR0_EM,        0x00000004
.set CR4_PAE,       0x00000020

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
    .extern __initial_tcb

_start:
    cli

    # Save multiboot magic & info (32-bit values).
    movl %eax, saved_magic
    movl %ebx, saved_info

    # Set 32-bit stack (identity-mapped region).
    mov $stack_top, %esp

    # Load 64-bit GDT (has a 64-bit code segment).
    lgdt gdt64_descriptor

    # Enable PAE.
    mov %cr4, %eax
    orl $CR4_PAE, %eax
    mov %eax, %cr4

    # Load PML4 base into CR3 (identity mapping).
    mov $pml4_table, %eax
    mov %eax, %cr3

    # Enable long mode (LME) in EFER.
    mov $IA32_EFER, %ecx
    rdmsr
    orl $0x00000100, %eax       # set LME
    wrmsr

    # Enable paging (CR0.PG) while PE is already set by GRUB.
    mov %cr0, %eax
    orl $CR0_PG, %eax
    mov %eax, %cr0

    # Far jump into 64-bit mode (uses 64-bit code descriptor).
    ljmp $CODE_SEG, $long_mode_entry

.size _start, . - _start

    .code64
    .type long_mode_entry, @function
long_mode_entry:
    # Flat 64-bit segments.
    mov $DATA_SEG, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov %ax, %fs
    mov %ax, %gs

    # 64-bit stack (must be in identity-mapped region).
    leaq stack_top(%rip), %rsp
    xor %rbp, %rbp

    # --- TLS / FS base setup (can be commented out if debugging) ---
    # Set up bootstrap TCB self-pointer.
    leaq __initial_tcb(%rip), %rax
    mov %rax, %rdi
    mov %rdi, (%rdi)

    # Set IA32_FS_BASE = &__initial_tcb.
    mov $IA32_FS_BASE, %ecx
    mov %rdi, %rax
    mov %rax, %rdx
    shr $32, %rdx
    wrmsr
    # ----------------------------------------------------------------

    # Fix up CR0: clear EM, set MP+NE (0x22).
    mov %cr0, %rax
    andq $~CR0_EM, %rax
    orq  $0x22, %rax
    mov %rax, %cr0

    # Enable SSE/SSE exceptions in CR4 (OSFXSR | OSXMMEXCPT).
    mov %cr4, %rax
    orq $0x600, %rax
    mov %rax, %cr4

    # Load multiboot args into 64-bit calling convention (edi, esi).
    movl saved_magic(%rip), %edi
    movl saved_info(%rip),  %esi

    # Call into the C/D kernel.
    call kmain

.hang:
    hlt
    jmp .hang

.size long_mode_entry, . - long_mode_entry

    .global invalidOpcodeStub
    .type invalidOpcodeStub, @function
invalidOpcodeStub:
    # Push general-purpose registers.
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

    # Arg0: pointer to saved registers (current RSP).
    mov %rsp, %rdi

    # The interrupt frame (RIP, CS, RFLAGS, RSP, SS) is above these pushes.
    mov 120(%rsp), %rcx        # old RIP
    mov 128(%rsp), %r8         # old CS
    mov 136(%rsp), %r9         # old RFLAGS
    mov $6, %rsi               # vector number (invalid opcode)
    xor %rdx, %rdx             # error code = 0 for #UD

    # Align stack for call (push dummy return).
    pushq $0
    call handleInvalidOpcode
    add $8, %rsp

    # Restore registers in reverse order.
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
    .align 4
saved_magic:
    .long 0          # 32-bit multiboot magic
saved_info:
    .long 0          # 32-bit multiboot info pointer

    .align 16
gdt64:
    .quad 0x0000000000000000      # null descriptor
    .quad 0x00AF9A000000FFFF      # 64-bit code segment
    .quad 0x00AF92000000FFFF      # 64-bit data segment
gdt64_end:

gdt64_descriptor:
    .word gdt64_end - gdt64 - 1
    .long gdt64

    .align 4096
pml4_table:
    .quad pdpt_table + 0x03       # present | writable
    .fill 511, 8, 0

    .align 4096
pdpt_table:
    .quad pd_table + 0x03         # present | writable
    .fill 511, 8, 0

    .align 4096
pd_table:
    # Identity-map the first 1 GiB with 2 MiB pages.
    # Trick: (.-pd_table)/8 is the current entry index (0..511).
    .set PAGE_FLAGS, 0x0000000000000083   # present | writable | 2M
    .rept 512
        .quad ( (.-pd_table)/8 * 0x200000 ) + PAGE_FLAGS
    .endr
