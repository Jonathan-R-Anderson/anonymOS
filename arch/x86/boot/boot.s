# boot.s (AT&T syntax, 64-bit)
# Sets up the Multiboot header, stack, and calls kmain.

# Multiboot2 Header Constants
.set MULTIBOOT2_HEADER_MAGIC,         0xe85250d6 # GRUB magic number
.set MULTIBOOT_ARCHITECTURE_I386,     0          # Architecture i386 (also used for x86_64 by GRUB for MB2)
.set MULTIBOOT_HEADER_TAG_END,        0          # End tag type
.set MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS, 5      # Optional entry address tag type

# Define the Multiboot header.
# For Multiboot2, GRUB will set up 64-bit long mode if the kernel is a 64-bit ELF.
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

# Assumes execution starts in 64-bit long mode.
.section .text
.global _start      # Export the _start symbol
.extern kmain       # kmain is defined in D

.code64             # Assemble for 64-bit mode
_start:
    # Set up the 64-bit stack
    movq $stack_top, %rsp # Point RSP to the top of our stack

    # Multiboot info:
    # For Multiboot2, the address of the Multiboot2 info structure is in %rbx.
    # kmain (D) expects this as its first argument, so it should be in %rdi.
    movq %rbx, %rdi # Pass Multiboot2 info pointer to kmain

    call kmain         # Call the D kernel's main function

    # If kmain returns (it shouldn't for a kernel), halt the system.
.Lhalt_loop:
    cli                # Disable interrupts
    hlt                # Halt the CPU
    jmp .Lhalt_loop  # Loop indefinitely

.section .note.GNU-stack, "", @progbits # Mark stack as non-executable