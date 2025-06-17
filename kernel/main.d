// kernel/main.d

module kernel.main;

import kernel.types : VGAColor, ErrorCode;
import kernel.terminal; // Imports VGA_ADDRESS, vga_entry, vga_entry_color, terminal_initialize, etc.
import kernel.gdt : init_gdt;
import kernel.idt : init_idt;
// kernel.interrupts is not directly called by kmain but its symbols are needed by IDT setup.
// kernel.panic is used implicitly if needed.

// VGA Constants

// Kernel's main entry point
extern (C) void kmain() {
    ushort* pVGATest = cast(ushort*) VGA_ADDRESS;
    pVGATest[0] = vga_entry('K', vga_entry_color(VGAColor.WHITE, VGAColor.BLUE));
    pVGATest[1] = vga_entry('0', vga_entry_color(VGAColor.WHITE, VGAColor.BLUE));

    // Initialize terminal first for clean output from subsequent init functions
    terminal_initialize();
    terminal_writestring("Terminal Initialized.\n");

    init_gdt();
    pVGATest[2] = vga_entry('G', vga_entry_color(VGAColor.WHITE, VGAColor.BLUE)); // 'G' for GDT done
    terminal_writestring("GDT Initialized.\n"); // Confirm via terminal

    init_idt();
    pVGATest[3] = vga_entry('I', vga_entry_color(VGAColor.WHITE, VGAColor.BLUE)); // 'I' for IDT done
    asm { "sti"; } // Enable interrupts
    pVGATest[4] = vga_entry('S', vga_entry_color(VGAColor.WHITE, VGAColor.BLUE)); // 'S' for STI done
    terminal_writestring("Interrupts Enabled (STI).\n");
    terminal_writestring("Kernel initialization complete. Halting until interrupt...\n");

    while (true) {
        asm { "hlt"; } // Halt until next interrupt
    }
}