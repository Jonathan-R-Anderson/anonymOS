/* linker.ld */
ENTRY(_start) /* Define the entry point of the kernel */
OUTPUT_FORMAT(elf64-x86-64) /* Specify the output format for 64-bit */

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
        KEEP(*boot.o(.multiboot_header)) /* Multiboot header from boot.o. KEEP ensures it's included and placed here. */
        KEEP(*boot.o(.text._start))      /* _start code from boot.o's .text._start section. */
        /* If _start is in the main .text of boot.o, you might use KEEP(*boot.o(.text)) instead for the line above, */
        /* or ensure boot.o is the very first input to the linker. */
        *boot.o(.text*)                  /* Other .text sections from boot.o, if any, ensuring they follow _start. */

        /* All other code and read-only data sections */
        *(.text*)                        /* All .text sections from other object files. */
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

        /* Debugging information sections - REMOVED from DISCARD */
        /* *(.debug*) */              /* Catches .debug_info, .debug_str, .debug_line, etc. */
    }

    /* DWARF debug sections. These are not loaded into memory. */
    /* LLD typically handles their placement correctly without explicit addresses */
    /* as long as they are not discarded. */
    .debug_info     0 : { *(.debug_info .gnu.linkonce.wi.*) }
    .debug_abbrev   0 : { *(.debug_abbrev) }
    .debug_line     0 : { *(.debug_line .debug_line.* .debug_line_str) }
    .debug_aranges  0 : { *(.debug_aranges) }
    .debug_str      0 : { *(.debug_str .debug_strtabs .debug_string_offsets) }
    .debug_loc      0 : { *(.debug_loc .debug_loclists) }
    .debug_ranges   0 : { *(.debug_ranges .debug_rnglists) }
    .debug_pubnames 0 : { *(.debug_pubnames) }
    .debug_pubtypes 0 : { *(.debug_pubtypes) }
    .debug_frame    0 : { *(.debug_frame) }

    /* Include .rela.debug_* sections if present and not automatically handled */
    .rela.debug_info   0 : { *(.rela.debug_info) }
    .rela.debug_abbrev 0 : { *(.rela.debug_abbrev) }
    .rela.debug_line  0 : { *(.rela.debug_line) }
    .rela.debug_aranges 0 : { *(.rela.debug_aranges) }
    .rela.debug_loc   0 : { *(.rela.debug_loc) }
    .rela.debug_ranges 0 : { *(.rela.debug_ranges) }
}
