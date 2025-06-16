/* linker.ld */
ENTRY(_start) /* Define the entry point of the kernel */
OUTPUT_FORMAT(elf32-i386) /* Specify the output format */

SECTIONS {
    /* Kernel load address - typically 1MB for GRUB */
    . = 0x00100000;
    KERNEL_LOAD_ADDRESS = .; /* Store the load address for potential use */

    /* Multiboot header section - MUST BE FIRST */
    .multiboot_header : ALIGN(4K) {
        *(.multiboot_header)
    }

    /* Kernel code section */
    .text : ALIGN(4K) {
        *(.text)          /* All .text sections from input files (boot.o first) */
        *(.rodata*)       /* Read-only data */
    }

    /* Kernel initialized data section */
    .data : ALIGN(4K) {
        *(.data)          /* All .data sections */
    }

    /* Kernel uninitialized data section (BSS) */
    /* This is where our stack will be */
    .bss : ALIGN(4K) {
        *(COMMON)         /* Uninitialized data (COMMON symbols) */
        *(.bss)           /* All .bss sections */
        *(.bootstrap_stack) /* If you define a specific stack section name */
    }

    /* End of kernel symbol, useful for memory management later */
    _kernel_end = .;

    /* Discard sections not needed in the final kernel image */
    /DISCARD/ : {
        *(.comment)
        *(.eh_frame) /* Exception handling frames, not typically used in freestanding */
        *(.note.gnu.build-id)
        *(.note.ABI-tag)
    }
}
