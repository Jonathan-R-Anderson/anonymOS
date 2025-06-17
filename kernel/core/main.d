// kernel/main.d

module kernel.main;

import kernel.types : VGAColor, ErrorCode;
import kernel.terminal; // Imports VGA_ADDRESS, vga_entry, vga_entry_color, terminal_initialize, etc.
import kernel.arch_interface.gdt : init_gdt; // Updated import path
import kernel.arch_interface.idt : init_idt; // Updated import path
// kernel.interrupts is not directly called by kmain but its symbols are needed by IDT setup.
// kernel.panic is used implicitly if needed.

// VGA Constants

// Kernel's main entry point
extern (C) void kmain() {
    ushort* pVGATest = cast(ushort*) VGA_ADDRESS;
    pVGATest[0] = vga_entry('K', vga_entry_color(VGAColor.WHITE, VGAColor.BLUE));
    pVGATest[1] = vga_entry('0', vga_entry_color(VGAColor.WHITE, VGAColor.BLUE));

    // Comment out ALL subsequent operations to see if "K0" can remain stable.
    pVGATest[2] = vga_entry('A', vga_entry_color(VGAColor.WHITE, VGAColor.RED)); 
    terminal_initialize(); 
    pVGATest[3] = vga_entry('B', vga_entry_color(VGAColor.WHITE, VGAColor.GREEN)); 
    // terminal_writestring("Terminal Initialized (via func).\n"); 
    // pVGATest[4] = vga_entry('C', vga_entry_color(VGAColor.WHITE, VGAColor.CYAN)); 
    // terminal_writestring("Further init skipped. Halting...\n");
    while (true) {
        asm { "hlt"; } // Halt until next interrupt
    }
}