OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    . = 0xFFFFFFFF80000000;
    
    .text ALIGN(4K) : AT(ADDR(.text) - 0xFFFFFFFF80000000)
    {
        *(.text .text.*)
    }

    .limine_reqs ALIGN(64) : AT(ADDR(.limine_reqs) - 0xFFFFFFFF80000000)
    {
        KEEP(*(.limine_reqs))
    }
    
    .rodata ALIGN(4K) : AT(ADDR(.rodata) - 0xFFFFFFFF80000000)
    {
        *(.rodata .rodata.*)
    }
    
    .data ALIGN(4K) : AT(ADDR(.data) - 0xFFFFFFFF80000000)
    {
        *(.data .data.*)
    }
    
    .bss ALIGN(4K) : AT(ADDR(.bss) - 0xFFFFFFFF80000000)
    {
        *(COMMON)
        *(.bss .bss.*)
    }
    
    /DISCARD/ :
    {
        *(.note .note.*)
        *(.eh_frame)
        *(.comment)
    }
}
