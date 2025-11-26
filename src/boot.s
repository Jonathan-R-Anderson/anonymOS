.set ALIGN,         1 << 0
.set MEMINFO,       1 << 1
.set VIDEOMODE,     1 << 2

# Request a graphics mode from the bootloader so we don't depend on its
# defaults. GRUB will attempt to set a VBE/EFI GOP mode matching these
# dimensions before jumping to the kernel.
.set VIDEO_MODE,    1
.set VIDEO_WIDTH,   1024
.set VIDEO_HEIGHT,  768
.set VIDEO_DEPTH,   32

.set FLAGS,         ALIGN | MEMINFO | VIDEOMODE
.set MAGIC,         0x1BADB002
.set CHECKSUM,      -(MAGIC + FLAGS)

.set CODE_SEG,      0x08
.set DATA_SEG,      0x10
.set USER_CODE_SEG, 0x18
.set USER_DATA_SEG, 0x20
.set TSS_SEG,       0x28
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
    .long 0             # header_addr (unused)
    .long 0             # load_addr (unused)
    .long 0             # load_end_addr (unused)
    .long 0             # bss_end_addr (unused)
    .long 0             # entry_addr (unused)
    .long VIDEO_MODE    # mode_type: 0=text, 1=graphics
    .long VIDEO_WIDTH
    .long VIDEO_HEIGHT
    .long VIDEO_DEPTH

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
    .extern kernel_rsp

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
    orl $0x00000001, %eax       # set SCE (enable syscall/sysret)
    orl $0x00000100, %eax       # set LME
    orl $0x00000800, %eax       # set NXE
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
    mov %rsp, kernel_rsp(%rip)
    mov %rsp, tss64_rsp0(%rip)
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

    # Load multiboot args into 64-bit calling convention (rdi, rsi).
    # Use movl to zero-extend the 32-bit values to 64-bit.
    xor %rdi, %rdi
    xor %rsi, %rsi
    movl saved_magic(%rip), %edi
    movl saved_info(%rip),  %esi

    # Initialize TSS descriptor base address at runtime
    leaq tss64(%rip), %rax
    leaq gdt64_tss(%rip), %rdi
    mov %ax, 2(%rdi)        # Base 0-15
    shr $16, %rax
    mov %al, 4(%rdi)        # Base 16-23
    shr $8, %rax
    mov %al, 7(%rdi)        # Base 24-31
    shr $8, %rax
    mov %eax, 8(%rdi)       # Base 32-63

    # Install the task-state segment so privilege transitions land on a
    # known-good kernel stack.
    mov $TSS_SEG, %ax
    ltr %ax

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

    .global timerIsrStub
    .type timerIsrStub, @function
    .extern timerIsrHandler
timerIsrStub:
    # Save caller state
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    subq $16, %rsp
    mov %ds, 8(%rsp)
    mov %es, 0(%rsp)
    mov $DATA_SEG, %ax
    mov %ax, %ds
    mov %ax, %es

    leaq fpu_save_area(%rip), %rax
    fxsave64 (%rax)

    call timerIsrHandler

    fxrstor64 (%rax)

    mov 0(%rsp), %es
    mov 8(%rsp), %ds
    addq $16, %rsp

    # Restore
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %rax
    iretq

.size timerIsrStub, . - timerIsrStub

    .global keyboardIsrStub
    .type keyboardIsrStub, @function
    .extern keyboardIsrHandler
keyboardIsrStub:
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    subq $16, %rsp
    mov %ds, 8(%rsp)
    mov %es, 0(%rsp)
    mov $DATA_SEG, %ax
    mov %ax, %ds
    mov %ax, %es

    leaq fpu_save_area(%rip), %rax
    fxsave64 (%rax)

    call keyboardIsrHandler

    fxrstor64 (%rax)

    mov 0(%rsp), %es
    mov 8(%rsp), %ds
    addq $16, %rsp

    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %rax
    iretq

.size keyboardIsrStub, . - keyboardIsrStub

    .global doubleFaultStub
    .type doubleFaultStub, @function
    .extern doubleFaultHandler
doubleFaultStub:
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    subq $16, %rsp
    mov %ds, 8(%rsp)
    mov %es, 0(%rsp)
    mov $DATA_SEG, %ax
    mov %ax, %ds
    mov %ax, %es

    leaq fpu_save_area(%rip), %rax
    fxsave64 (%rax)

    call doubleFaultHandler

    fxrstor64 (%rax)

    mov 0(%rsp), %es
    mov 8(%rsp), %ds
    addq $16, %rsp

    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %rax
    iretq

.size doubleFaultStub, . - doubleFaultStub

    .global mouseIsrStub
    .type mouseIsrStub, @function
    .extern mouseIsrHandler
mouseIsrStub:
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    subq $16, %rsp
    mov %ds, 8(%rsp)
    mov %es, 0(%rsp)
    mov $DATA_SEG, %ax
    mov %ax, %ds
    mov %ax, %es

    leaq fpu_save_area(%rip), %rax
    fxsave64 (%rax)

    call mouseIsrHandler

    fxrstor64 (%rax)

    mov 0(%rsp), %es
    mov 8(%rsp), %ds
    addq $16, %rsp

    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %rax
    iretq

.size mouseIsrStub, . - mouseIsrStub

    .global pageFaultStub
    .type pageFaultStub, @function
    .extern pageFaultHandler
pageFaultStub:
    # CPU has pushed error code + interrupt frame already.
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    movq %rsp, %rdi          # arg0: pointer to saved regs + fault frame
    call pageFaultHandler

    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %rax
    addq $8, %rsp            # skip error code pushed by CPU
    iretq

.size pageFaultStub, . - pageFaultStub

    .global interruptContextSwitch
    .type interruptContextSwitch, @function
# void interruptContextSwitch(uint64_t* oldSpOut, uint64_t newSp)
# rdi = pointer to store old RSP
# rsi = new RSP to load
interruptContextSwitch:
    mov %rsp, (%rdi)
    mov %rsi, %rsp
    ret

.size interruptContextSwitch, . - interruptContextSwitch

    .global loadIDT
    .type loadIDT, @function
loadIDT:
    lidt (%rdi)
    ret

.size loadIDT, . - loadIDT

    .global updateTssRsp0
    .type updateTssRsp0, @function
# void updateTssRsp0(uint64_t rsp0)
updateTssRsp0:
    mov %rdi, tss64_rsp0(%rip)
    ret

.size updateTssRsp0, . - updateTssRsp0

    .global stack_top

    .section .data
    .align 4
saved_magic:
    .long 0          # 32-bit multiboot magic
saved_info:
    .long 0          # 32-bit multiboot info pointer

    .section .data
    .balign 16
tss64:
    .long 0
tss64_rsp0:
    .quad stack_top
    .quad 0                    # rsp1
    .quad 0                    # rsp2
    .quad 0                    # reserved
    .quad 0                    # ist1
    .quad 0                    # ist2
    .quad 0                    # ist3
    .quad 0                    # ist4
    .quad 0                    # ist5
    .quad 0                    # ist6
    .quad 0                    # ist7
    .quad 0                    # reserved
    .word 0                    # reserved
tss64_iomap:
    .word tss64_end - tss64    # iomap base set past TSS to disable bitmap
tss64_end:

    .section .data
    .balign 16
fpu_save_area:
    .space 512

    .align 16
gdt64:
    .quad 0x0000000000000000      # null descriptor
    .quad 0x00AF9A000000FFFF      # 64-bit code segment
    .quad 0x00AF92000000FFFF      # 64-bit data segment
    .quad 0x00AFFA000000FFFF      # user 64-bit code segment (DPL=3)
    .quad 0x00AFF2000000FFFF      # user data segment (DPL=3)
gdt64_tss:
    .word tss64_end - tss64 - 1   # limit low
    .word 0                       # base low (runtime init)
    .byte 0                       # base middle (runtime init)
    .byte 0x89                    # type=available 64-bit TSS, present
    .byte ((tss64_end - tss64 - 1) >> 16) & 0xFF # limit high
    .byte 0                       # base high (runtime init)
    .quad 0                       # base upper dword (runtime init)
gdt64_end:

gdt64_descriptor:
    .word gdt64_end - gdt64 - 1
    .long gdt64

    .global pml4_table
    .align 4096
pml4_table:
    .quad pdpt_table + 0x03       # present | writable
    .fill 511, 8, 0

    .align 4096
pdpt_table:
    .quad pd_table0 + 0x03        # present | writable
    .quad pd_table1 + 0x03        # present | writable
    .quad pd_table2 + 0x03        # present | writable
    .quad pd_table3 + 0x03        # present | writable
    .fill 508, 8, 0

    .align 4096
pd_table0:
    # Identity-map the first 4 GiB with 2 MiB pages so firmware framebuffers
    # (often placed near 3.5 GiB) remain accessible as soon as paging is on.
    # Trick: (.-pd_tableX)/8 is the current entry index (0..511).
    .set PAGE_FLAGS, 0x0000000000000083   # present | writable | 2M
    .rept 512
        .quad ( (.-pd_table0)/8 * 0x200000 ) + PAGE_FLAGS
    .endr

    .align 4096
pd_table1:
    .set BASE_GB1, 0x0000000040000000
    .rept 512
        .quad BASE_GB1 + ( (.-pd_table1)/8 * 0x200000 ) + PAGE_FLAGS
    .endr

    .align 4096
pd_table2:
    .set BASE_GB2, 0x0000000080000000
    .rept 512
        .quad BASE_GB2 + ( (.-pd_table2)/8 * 0x200000 ) + PAGE_FLAGS
    .endr

    .align 4096
pd_table3:
    .set BASE_GB3, 0x00000000C0000000
    .rept 512
        .quad BASE_GB3 + ( (.-pd_table3)/8 * 0x200000 ) + PAGE_FLAGS
    .endr
