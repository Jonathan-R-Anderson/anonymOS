/*
 * guest.ld -- one PT_LOAD at physical 1 MiB (CH HIGH_RAM_START) + exactly one PT_NOTE.
 * linux-loader overwrites its PVH decision for EVERY PT_NOTE it sees
 * (elf/mod.rs:256-267), so a trailing .note.gnu.property PT_NOTE would hide
 * the Xen note -> all other notes are discarded.
 */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(pvh_start)

PHDRS
{
    image PT_LOAD FLAGS(7);    /* RWX: one segment, no FILEHDR/PHDRS inside it */
    xen   PT_NOTE;
}

SECTIONS
{
    . = 0x100000;

    .text : AT(0x100000) {
        *(.text.entry)
        *(.text .text.*)
    } :image

    .rodata : { *(.rodata .rodata.*) } :image

    .note.Xen : { KEEP(*(.note.Xen)) } :image :xen

    .bss : { *(.bss .bss.*) *(COMMON) } :image

    /DISCARD/ : {
        *(.note.gnu.*) *(.note.GNU-stack) *(.comment) *(.eh_frame*) *(.data .data.*)
    }
}
