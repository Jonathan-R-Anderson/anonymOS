/* linker.ld */
ENTRY(_start) /* Define the entry point of the kernel */
OUTPUT_FORMAT(elf32-i386) /* Specify the output format */

SECTIONS {
    /* Kernel load address - typically 1MB for GRUB */
    . = 0x00100000;
    KERNEL_LOAD_ADDRESS = .; /* Store the load address for potential use */

    /* The main text segment.
     * This section starts at KERNEL_LOAD_ADDRESS.
     * It must begin with the Multiboot header from boot.s,
     * followed by the _start entry point code from boot.s.
     * The Multiboot header data within boot.s should be 4-byte aligned.
     */
    .text : {
        /* These MUST come from boot.o, which MUST be linked first by your Makefile. */
        KEEP(*(.multiboot_header)) /* Multiboot header section from boot.s */
        *(.text._start)            /* _start code section from boot.s (if you name it .text._start) */
                                   /* If _start is just in .text in boot.s, *(.text*) below will catch it first. */
        /* All other code and read-only data sections */
        *(.text*)                  /* Includes .text from boot.s if not in .text._start, and all other .text sections */
        *(.rodata*)       /* Read-only data */
    }

    /* Kernel initialized data section */
    .data : ALIGN(4K) {
        *(.data*)          /* All .data sections */
    }

    /* Kernel uninitialized data section (BSS) */
    /* This is where our stack will be */
    .bss : ALIGN(4K) {
        *(COMMON)         /* Uninitialized data (COMMON symbols) */
        *(.bss*)           /* All .bss sections, including stack from boot.s */
        /* .bootstrap_stack removed as stack in boot.s's .bss is covered by .bss* */
    }

    /* End of kernel symbol, useful for memory management later */
    _kernel_end = .;

    /* Discard sections not needed in the final kernel image */
    /DISCARD/ : {
        *(.comment)             /* Linker comments, version, etc. */
        *(.eh_frame)            /* Exception handling frames, not typically used in freestanding */
        *(.note.gnu.build-id)   /* GNU build ID */
        *(.note.ABI-tag)        /* ABI tag */

        /* Thread-Local Storage sections (if not used by the kernel) */
        *(.tdata*)
        *(.tbss*)

        /* Debugging information sections */
        *(.debug*)              /* Catches .debug_info, .debug_str, .debug_line, etc. */
    }
}
