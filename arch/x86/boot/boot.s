# boot.s (AT&T syntax, 64-bit)
# Sets up the Multiboot header, stack, and calls kmain.

# Multiboot2 Header Constants
.set MULTIBOOT2_HEADER_MAGIC,         0xe85250d6 # GRUB magic number
.set MULTIBOOT_ARCHITECTURE_I386,     0          # Architecture i386 (also used for x86_64 by GRUB for MB2)
.set MULTIBOOT_HEADER_TAG_END,        0          # End tag type
.set MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS, 5      # Optional entry address tag type

# Define the Multiboot header.
# GRUB loads the kernel in 32-bit protected mode. The boot code
# below builds page tables and switches to 64-bit long mode itself.
.section .multiboot_header
.align 8  # Multiboot2 header must be 8-byte aligned
multiboot2_header_start:
    .long MULTIBOOT2_HEADER_MAGIC     # Magic number
    .long MULTIBOOT_ARCHITECTURE_I386 # Architecture
    .long multiboot2_header_end - multiboot2_header_start # Header length
    # Checksum: -(magic + architecture + header_length)
    .long -(MULTIBOOT2_HEADER_MAGIC + MULTIBOOT_ARCHITECTURE_I386 + (multiboot2_header_end - multiboot2_header_start))

# Optional Entry Address Tag (for non-ELF kernels, but good practice)
# GRUB uses ELF entry point for ELF files, but this tag can be present.
# .align 8
# .word MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS # type
# .word 0                                  # flags
# .long 24                                 # size (tag + entry_addr + padding)
# .quad _start                             # entry_addr (64-bit)
# .quad 0                                  # padding to make size 24

# End Tag
multiboot2_header_end_tag:
.align 8
    .word MULTIBOOT_HEADER_TAG_END # type
    .word 0                        # flags
    .long 8                        # size
multiboot2_header_end:


.section .bss
.align 16
stack_bottom:
    .space 16384 # 16 KiB stack
stack_top:

.section .data
# Page tables for enabling 64-bit long mode. These must not be zeroed after
# paging is enabled, so keep them out of the BSS section.
.align 4096
pml4_table:
    .space 4096
.align 4096
pdpt_table:
    .space 4096
.align 4096
pd_table:
    .space 4096

# -----------------------------------------------------------------------------
# Minimal IDT to prevent triple faults before the real IDT is set up.
# It contains 256 identical entries that all point to a simple fault handler.
# -----------------------------------------------------------------------------
.align 16
early_idt:
    .space 16 * 256                      # 256 descriptors
early_idt_end:

early_idt_ptr:
    .word early_idt_end - early_idt - 1
    .quad early_idt

# Minimal GDT used to enter long mode
.section .data
.align 8
gdt_start:
    .quad 0x0000000000000000        # Null descriptor
    .quad 0x00af9a000000ffff        # 0x08: Code (DPL=0)
    .quad 0x00cf92000000ffff        # 0x10: Data (DPL=0)
    .quad 0x0000000000000000        # 0x18: Unused (optional)
    .quad 0x0000000000000000        # 0x20: Unused (optional)
    .quad 0x0000000000000067        # 0x28: TSS low (set in next step)
    .quad 0x0000000000000000        # 0x30: TSS high

gdt_end:

.section .bss
.align 16
tss64:
    .space 104  # 64-bit TSS size


.section .data
gdt_desc:
    .word gdt_end - gdt_start - 1
    .long gdt_start

# Begin real code
.section .text
.global _start      # Export the _start symbol
.extern kmain       # kmain is defined in D
.extern _bss_start  # Start of BSS (from linker script)
.extern _bss_end    # End of BSS (from linker script)

.code32             # Initial execution is in 32-bit protected mode
_start:
    cli
    movl $stack_top, %esp
    lgdt gdt_desc

    # The final GDT and TSS are set up later in init_gdt().
    # Loading TR here with a placeholder descriptor causes a GP fault
    # before kmain runs, so defer it until the real GDT is installed.
    # mov $0x28, %ax
    # ltr %ax

    # Setup page tables for identity mapping
    call setup_page_tables

    # Enable PAE
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4

    # Load PML4 address into CR3
    movl $pml4_table, %eax
    movl %eax, %cr3

    # Enable Long Mode in EFER
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x00000100, %eax
    wrmsr

    # Enable paging
    movl %cr0, %eax
    orl $0x80000000, %eax
    movl %eax, %cr0

    # Far jump to flush pipeline and enter 64-bit mode
    ljmp $0x08, $long_mode_start

.code32
setup_page_tables:
    movl $pd_table, %edi
    xorl %ecx, %ecx
    movl $0x00000083, %eax
1:
    movl %eax, (%edi)
    movl $0, 4(%edi)
    addl $0x200000, %eax
    addl $8, %edi
    incl %ecx
    cmpl $512, %ecx
    jne 1b

    movl $pd_table, %eax
    orl $0x3, %eax
    movl %eax, pdpt_table
    movl $0, pdpt_table+4

    movl $pdpt_table, %eax
    orl $0x3, %eax
    movl %eax, pml4_table
    movl $0, pml4_table+4
    ret

.code64             # 64-bit code after long mode is enabled
long_mode_start:
    movq $stack_top, %rsp          # RSP = top of stack
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs

    cli                 # Disable interrupts during boot

    # Zero BSS so all __gshared/uninitialized globals are predictable
    lea _bss_start(%rip), %rdi
    lea _bss_end(%rip), %rcx
    xor %rax, %rax
.Lclear_bss:
    cmp %rcx, %rdi
    jge .Lbss_cleared
    movq %rax, (%rdi)
    add $8, %rdi
    jmp .Lclear_bss
.Lbss_cleared:

    # Build IDT entries pointing to early_fault
    lea early_idt(%rip), %rdi        # Destination table
    mov $256, %ecx                   # Number of entries
1:  lea early_fault(%rip), %rax
    movw %ax, (%rdi)
    movw $0x08, 2(%rdi)
    movb $0,  4(%rdi)
    movb $0x8E, 5(%rdi)
    shr $16, %rax
    movw %ax, 6(%rdi)
    shr $16, %rax
    movl %eax, 8(%rdi)
    movl $0,  12(%rdi)
    add $16, %rdi
    dec %ecx
    jne 1b

    # Load a minimal IDT so unexpected exceptions don't triple fault
    lea early_idt_ptr(%rip), %rax
    lidt (%rax)

    # Enable SSE and FPU for the D runtime
    movq %cr0, %rax
    orq $0x22, %rax          # Set MP (bit1) and NE (bit5)
    andq $~0x4, %rax         # Clear EM (bit2)
    movq %rax, %cr0

    movq %cr4, %rax
    orq $0x600, %rax         # Set OSFXSR (bit9) and OSXMMEXCPT (bit10)
    movq %rax, %cr4
    fninit                   # Initialize FPU state

    # Multiboot info:
    # For Multiboot2, the address of the Multiboot2 info structure is in %rbx.
    # The magic value is in %rax (should be 0x36d76289 for Multiboot2).
    # Pass the Multiboot2 info pointer and magic to kmain
    # The Multiboot2 specification places the info pointer in %rbx and the
    # magic value in %eax when the bootloader jumps to our entry point.  Our
    # kernel's kmain function expects these as the first two arguments (System V
    # AMD64 calling convention uses %rdi and %rsi).
    movq %rbx, %rdi    # First argument: pointer to Multiboot info
    movl %eax, %esi    # Second argument: Multiboot magic (zero-extended)

    call kmain         # Call the D kernel's main function

    # If kmain returns (it shouldn't for a kernel), halt the system.
.Lhalt_loop:
    cli                # Disable interrupts
    hlt                # Halt the CPU
    jmp .Lhalt_loop  # Loop indefinitely

early_fault:
    cli
1:
    hlt
    jmp 1b

.section .note.GNU-stack, "", @progbits # Mark stack as non-executable
