// kernel/gdt.d

module kernel.gdt;

import kernel.types : VGAColor; // For debug printing
import kernel.terminal : VGA_ADDRESS, vga_entry_color, vga_entry; // For debug printing

public: // Export init_gdt and related types/externs if needed by other modules (not typical)

// GDT Entry Structure
struct GdtEntry {
    ushort limit_low;    // Lower 16 bits of limit
    ushort base_low;     // Lower 16 bits of base
    ubyte  base_middle;  // Next 8 bits of base
    ubyte  access;       // Access flags, determine ring levels, type, etc.
    ubyte  granularity;  // Granularity (limit_high, flags)
    ubyte  base_high;    // Last 8 bits of base
}

// GDT Pointer Structure (for lgdt instruction)
align(1) struct GdtPtr { // Ensure no padding for lgdt
    ushort limit; // Size of GDT - 1
    uint base; // Address of GDT
}

GdtEntry[3] gdt_entries; // 0: Null, 1: Kernel Code, 2: Kernel Data
GdtPtr gdt_ptr;

extern (C) void gdt_flush(uint gdtPtrAddr); // Defined in gdt.s
// Declare the new assembly function
extern (C) void gdt_debug_print_limit(ushort limit_val, const char* hex_chars_ptr, uint vga_base, ubyte attr_byte, ubyte char_c);


private void gdt_set_gate(int num, uint base, uint limit, ubyte access, ubyte gran) {
    gdt_entries[num].base_low    = cast(ushort)(base & 0xFFFF);
    gdt_entries[num].base_middle = cast(ubyte)((base >> 16) & 0xFF);
    gdt_entries[num].base_high   = cast(ubyte)((base >> 24) & 0xFF);

    gdt_entries[num].limit_low   = cast(ushort)(limit & 0xFFFF);
    gdt_entries[num].granularity = cast(ubyte)(((limit >> 16) & 0x0F) | (gran & 0xF0));

    gdt_entries[num].access      = access;
}

void init_gdt() {
    ushort* pDebugVGAMem = cast(ushort*)VGA_ADDRESS;
    pDebugVGAMem[20] = vga_entry('S', vga_entry_color(VGAColor.WHITE, VGAColor.BLACK));

    size_t entry_size = GdtEntry.sizeof;
    size_t num_entries = gdt_entries.length;
    size_t total_gdt_size = entry_size * num_entries;
    ushort calculated_limit = cast(ushort)(total_gdt_size - 1);

    pDebugVGAMem[15] = vga_entry('X', vga_entry_color(VGAColor.MAGENTA, VGAColor.BLACK));
    pDebugVGAMem[16] = vga_entry("0123456789ABCDEF"[entry_size & 0xF], vga_entry_color(VGAColor.MAGENTA, VGAColor.BLACK));
    pDebugVGAMem[17] = vga_entry('Y', vga_entry_color(VGAColor.MAGENTA, VGAColor.BLACK));
    pDebugVGAMem[18] = vga_entry("0123456789ABCDEF"[num_entries & 0xF], vga_entry_color(VGAColor.MAGENTA, VGAColor.BLACK));
    pDebugVGAMem[19] = vga_entry('Z', vga_entry_color(VGAColor.MAGENTA, VGAColor.BLACK));
    pDebugVGAMem[20] = vga_entry("0123456789ABCDEF"[(calculated_limit >> 4) & 0xF], vga_entry_color(VGAColor.MAGENTA, VGAColor.BLACK));
    pDebugVGAMem[21] = vga_entry("0123456789ABCDEF"[calculated_limit & 0xF], vga_entry_color(VGAColor.MAGENTA, VGAColor.BLACK));

    gdt_set_gate(0, 0, 0, 0, 0);
    gdt_set_gate(1, 0, 0xFFFFFFFF, 0x9A, 0xCF);
    gdt_set_gate(2, 0, 0xFFFFFFFF, 0x92, 0xCF);

    gdt_ptr.limit = calculated_limit;
    pDebugVGAMem[22] = vga_entry('B', vga_entry_color(VGAColor.GREEN, VGAColor.BLACK));
    pDebugVGAMem[23] = vga_entry("0123456789ABCDEF"[(gdt_ptr.limit >> 4) & 0xF], vga_entry_color(VGAColor.GREEN, VGAColor.BLACK));
    pDebugVGAMem[24] = vga_entry("0123456789ABCDEF"[gdt_ptr.limit & 0xF], vga_entry_color(VGAColor.GREEN, VGAColor.BLACK));

    ushort limit_val_for_asm = gdt_ptr.limit;
    static immutable char[] HEX_CHARS_ASM_ARRAY = "0123456789ABCDEF";
    enum VGA_BASE_ADDR_CONST = VGA_ADDRESS; // Use imported constant
    enum ATTR_BYTE_CONST = 0x0F;
    char char_C_literal = 'C';
    ubyte char_C_ubyte = char_C_literal;
    
    // Call the external assembly function for debug printing
    gdt_debug_print_limit(
        limit_val_for_asm,
        HEX_CHARS_ASM_ARRAY.ptr,
        VGA_BASE_ADDR_CONST,
        cast(ubyte)ATTR_BYTE_CONST,
        char_C_ubyte
    );

    gdt_ptr.base  = cast(uint)&gdt_entries[0];

    pDebugVGAMem[35] = vga_entry('F', vga_entry_color(VGAColor.RED, VGAColor.BLACK));
    pDebugVGAMem[36] = vga_entry("0123456789ABCDEF"[(gdt_ptr.limit >> 4) & 0xF], vga_entry_color(VGAColor.RED, VGAColor.BLACK));
    pDebugVGAMem[37] = vga_entry("0123456789ABCDEF"[gdt_ptr.limit & 0xF], vga_entry_color(VGAColor.RED, VGAColor.BLACK));

    gdt_flush(cast(uint)&gdt_ptr);
}