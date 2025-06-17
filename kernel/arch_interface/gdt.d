// kernel/gdt.d

module kernel.gdt;

import kernel.types : VGAColor; // For debug printing
import kernel.terminal : terminal_writestring, terminal_write_hex, vga_entry_color, vga_entry, VGA_ADDRESS; // For debug printing and output

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

__gshared GdtEntry[3] gdt_entries; // 0: Null, 1: Kernel Code, 2: Kernel Data
__gshared GdtPtr gdt_ptr;

extern (C) void gdt_flush(uint gdtPtrAddr); // Defined in gdt.s
// extern (C) void gdt_debug_print_limit(ushort limit_val, const char* hex_chars_ptr, uint vga_base, ubyte attr_byte, ubyte char_c); // This was a stub


private void gdt_set_gate(int num, uint base, uint limit, ubyte access, ubyte gran) {
    gdt_entries[num].base_low    = cast(ushort)(base & 0xFFFF);
    gdt_entries[num].base_middle = cast(ubyte)((base >> 16) & 0xFF);
    gdt_entries[num].base_high   = cast(ubyte)((base >> 24) & 0xFF);

    gdt_entries[num].limit_low   = cast(ushort)(limit & 0xFFFF);
    gdt_entries[num].granularity = cast(ubyte)(((limit >> 16) & 0x0F) | (gran & 0xF0));

    gdt_entries[num].access      = access;
}

void init_gdt() {
    terminal_writestring("Initializing GDT...\n");

    size_t entry_size = GdtEntry.sizeof;
    size_t num_entries = gdt_entries.length;
    size_t total_gdt_size = entry_size * num_entries;
    ushort calculated_limit = cast(ushort)(total_gdt_size - 1);

    terminal_writestring("  GDT Entry Size: "); terminal_write_hex(cast(uint)entry_size); terminal_writestring("\n");
    terminal_writestring("  Num GDT Entries: "); terminal_write_hex(cast(uint)num_entries); terminal_writestring("\n");
    terminal_writestring("  Total GDT Size: "); terminal_write_hex(cast(uint)total_gdt_size); terminal_writestring("\n");
    terminal_writestring("  Calculated GDT Limit: "); terminal_write_hex(calculated_limit); terminal_writestring("\n");

    gdt_set_gate(0, 0, 0, 0, 0);
    gdt_set_gate(1, 0, 0xFFFFFFFF, 0x9A, 0xCF);
    gdt_set_gate(2, 0, 0xFFFFFFFF, 0x92, 0xCF);

    gdt_ptr.limit = calculated_limit;
    gdt_ptr.base  = cast(uint)&gdt_entries[0];

    terminal_writestring("  GDT Ptr Limit: "); terminal_write_hex(gdt_ptr.limit); terminal_writestring("\n");
    terminal_writestring("  GDT Ptr Base: "); terminal_write_hex(gdt_ptr.base); terminal_writestring("\n");

    terminal_writestring("Flushing GDT...\n");
    gdt_flush(cast(uint)&gdt_ptr);
    terminal_writestring("GDT flushed.\n");
}