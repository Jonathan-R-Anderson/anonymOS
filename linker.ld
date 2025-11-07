/* Linker script for the freestanding D kernel */
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    /* Load the kernel at 1 MiB, away from real-mode structures. */
    . = 1M;

    .text ALIGN(4K) :
    {
        /* Multiboot header must be within the first 8 KiB. */
        KEEP(*(.multiboot))
        *(.text .text.*)
        *(.rodata .rodata.*)
    }

    /* Thread-local storage image for the bootstrap thread. */
    . = ALIGN(16);
    __tls_start = .;
    .tdata ALIGN(16) :
    {
        *(.tdata .tdata.*)
        *(.gnu.linkonce.td.*)
    }
    __tdata_end = .;

    .tbss ALIGN(16) :
    {
        *(.tbss .tbss.*)
        *(.gnu.linkonce.tb.*)
        . = ALIGN(16);
    }
    __tls_end = .;

    /* Reserve space for the initial thread control block (TCB). */
    .tcb (NOLOAD) :
    {
        __initial_tcb = .;
        . += 16;
        __initial_tcb_end = .;
    }

    . = ALIGN(4K);
    .data ALIGN(4K) :
    {
        *(.data .data.*)
    }

    .bss ALIGN(4K) :
    {
        *(COMMON)
        *(.bss .bss.*)
    }

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.comment)
    }
}
