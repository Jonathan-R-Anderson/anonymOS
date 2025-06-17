// kernel/gdt.d

module kernel.gdt;

import kernel.types : VGAColor; // For debug printing
import kernel.terminal : terminal_writestring, terminal_write_hex, vga_entry_color, vga_entry, VGA_ADDRESS; // For debug printing and output

public: // Export init_gdt and related types/externs if needed by other modules (not typical)

// GDT Entry Structure
// For 64-bit Long Mode. Each entry is 8 bytes.
// Base address is ignored for CS/DS/ES/SS in 64-bit mode (treated as 0).
// Limit is also often ignored or set to max for flat model.
align(1) struct GdtEntry {
    ushort limit_0_15;
    ushort base_0_15;
    ubyte  base_16_23;
    ubyte  access_byte;      // P, DPL, S, Type
    ubyte  limit_16_19_flags; // Limit (16-19), AVL, L (Long Mode), D/B, G (Granularity)
    ubyte  base_24_31;
}

// GDT Pointer Structure (for lgdt instruction)
align(1) struct GdtPtr { // Ensure no padding for lgdt
    ushort limit; // Size of GDT - 1
    ulong base; // Address of GDT (64-bit)
}

__gshared GdtEntry[3] gdt_entries; // 0: Null, 1: Kernel Code, 2: Kernel Data
__gshared GdtPtr gdt_ptr;

extern (C) void gdt_flush(GdtPtr* gdtPtrAddr); // Defined in gdt.s, argument is a pointer
// extern (C) void gdt_debug_print_limit(ushort limit_val, const char* hex_chars_ptr, uint vga_base, ubyte attr_byte, ubyte char_c); // This was a stub


private void gdt_set_gate(int num, uint base, uint limit, ubyte access, ubyte gran) {
    // For 64-bit, base is effectively 0 for code/data segments. Limit is often max.
    // The 'base' and 'limit' parameters to this function are now mostly conceptual
    // for a flat 64-bit model, but we'll set them if needed for other segment types.
    // For typical 64-bit code/data segments:
    // base = 0, limit = 0xFFFFF (if G=1, 4KB pages) or 0xFFFFFFFF (if G=0, byte granular, not typical for full range)
    gdt_entries[num].limit_0_15 = cast(ushort)(limit & 0xFFFF);
    gdt_entries[num].base_0_15 = cast(ushort)(base & 0xFFFF);
    gdt_entries[num].base_16_23 = cast(ubyte)((base >> 16) & 0xFF);
    gdt_entries[num].access_byte = access;
    gdt_entries[num].limit_16_19_flags = cast(ubyte)(((limit >> 16) & 0x0F) | (gran & 0xF0));
    gdt_entries[num].base_24_31 = cast(ubyte)((base >> 24) & 0xFF);
}

void init_gdt() {
    terminal_writestring("Initializing GDT...\n");

    size_t entry_size = GdtEntry.sizeof;
    size_t num_entries = gdt_entries.length;
    size_t total_gdt_size = entry_size * num_entries;
    ushort calculated_limit = cast(ushort)(total_gdt_size - 1);

    terminal_writestring("  GDT Entry Size: "); terminal_write_hex(entry_size); terminal_writestring("\n");
    terminal_writestring("  Num GDT Entries: "); terminal_write_hex(num_entries); terminal_writestring("\n");
    terminal_writestring("  Total GDT Size: "); terminal_write_hex(total_gdt_size); terminal_writestring("\n");
    terminal_writestring("  Calculated GDT Limit: "); terminal_write_hex(calculated_limit); terminal_writestring("\n");

    // Entry 0: Null Descriptor
    gdt_set_gate(0, 0, 0, 0, 0); 

    // Entry 1: Kernel Code Segment (64-bit)
    // Access: P=1, DPL=0, S=1 (Code/Data), Type=0xA (Execute/Read, Non-Conforming) -> 0x9A
    // Flags: G=1 (4KB Granularity), L=1 (64-bit Long Mode), D/B=0 (for L=1) -> 0xA0 (for G=1, L=1, D/B=0, AVL=0)
    // Limit for G=1, L=1 should be 0xFFFFF for full 4GB-like range (scaled by 4KB)
    // Base is 0 for 64-bit code/data segments.
    gdt_set_gate(1, 0, 0xFFFFF, 0x9A, 0xA0); // 0xA0 for flags: G=1, L=1

    // Entry 2: Kernel Data Segment (64-bit)
    // Access: P=1, DPL=0, S=1 (Code/Data), Type=0x2 (Read/Write, Expand Up) -> 0x92
    // Flags: G=1 (4KB Granularity), L=0 (not code), D/B=1 (32-bit stack/ops, but L=0 means this is for data) -> 0xC0 (for G=1, D/B=1)
    gdt_set_gate(2, 0, 0xFFFFF, 0x92, 0xC0);

    gdt_ptr.limit = calculated_limit;
    gdt_ptr.base  = cast(ulong)&gdt_entries[0];

    terminal_writestring("  GDT Ptr Limit: "); terminal_write_hex(gdt_ptr.limit); terminal_writestring("\n");
    terminal_writestring("  GDT Ptr Base: "); terminal_write_hex(gdt_ptr.base); terminal_writestring("\n");

    terminal_writestring("Flushing GDT...\n");
    gdt_flush(&gdt_ptr);
    // Add a direct VGA write *after* gdt_flush to see if it returns.
    // Use a distinct character and position.
    ushort* pVGADebug = cast(ushort*) VGA_ADDRESS; 
    pVGADebug[10] = vga_entry('F', vga_entry_color(VGAColor.WHITE, VGAColor.RED)); // 'F' for Flushed, at column 10

    terminal_writestring("GDT flushed.\n");
}