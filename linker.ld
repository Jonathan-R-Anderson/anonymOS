/* linker.ld - Linker script for the D kernel */

ENTRY(_start) /* The entry point is _start from boot.s */

SECTIONS
{
    /* Kernel code will be loaded by GRUB at 1MB (0x100000) */
    . = 1M;
    KERNEL_LOAD_ADDRESS = .;

    /*
     * The .multiboot_header section must come first and be 4-byte aligned.
     * It contains the Multiboot magic numbers for GRUB.
     */
    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_LOAD_ADDRESS + KERNEL_LOAD_ADDRESS)
    {
        *(.multiboot_header)
        *(.text .text.*)
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_LOAD_ADDRESS + KERNEL_LOAD_ADDRESS)
    {
        *(.rodata .rodata.*)
    }

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_LOAD_ADDRESS + KERNEL_LOAD_ADDRESS)
    {
        *(.data .data.*)
    }

    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_LOAD_ADDRESS + KERNEL_LOAD_ADDRESS)
    {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame)
    }
}