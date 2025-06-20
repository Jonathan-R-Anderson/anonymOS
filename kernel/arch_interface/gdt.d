// kernel/gdt.d

module kernel.arch_interface.gdt;

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

// Global Descriptor Table entries.
// Layout:
//   0: Null
//   1: Kernel Code
//   2: Kernel Data
//   3: User Code
//   4: User Data
//   5-6: 64-bit TSS descriptor
align(8) __gshared GdtEntry[7] gdt_entries;
align(8) __gshared GdtPtr gdt_ptr;

// 64-bit Task State Segment used by the TSS descriptor
align(16) struct Tss64 {
    uint   reserved0;
    ulong  rsp0;
    ulong  rsp1;
    ulong  rsp2;
    ulong  reserved1;
    ulong  ist1;
    ulong  ist2;
    ulong  ist3;
    ulong  ist4;
    ulong  ist5;
    ulong  ist6;
    ulong  ist7;
    ulong  reserved2;
    ushort reserved3;
    ushort io_map_base;
}

align(16) __gshared Tss64 tss;

// Second half of a 64-bit TSS descriptor (base high and reserved fields)
align(1) struct TssDescriptorHigh {
    uint base_32_63;
    uint reserved;
}

extern (C) void gdt_flush(GdtPtr* gdtPtrAddr); // Defined in gdt.s, argument is a pointer
extern (C) void load_tss(ushort selector);    // Defined in tss.s

// Helper to set GDT entries in a provided GdtEntry.
private static void set_gdt_entry(GdtEntry* entry, uint base, uint limit, ubyte access, ubyte gran) {
    entry.limit_0_15 = cast(ushort)(limit & 0xFFFF);
    entry.base_0_15 = cast(ushort)(base & 0xFFFF);
    entry.base_16_23 = cast(ubyte)((base >> 16) & 0xFF);
    entry.access_byte = access;
    entry.limit_16_19_flags = cast(ubyte)(((limit >> 16) & 0x0F) | (gran & 0xF0));
    entry.base_24_31 = cast(ubyte)((base >> 24) & 0xFF);
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
    set_gdt_entry(&gdt_entries[0], 0, 0, 0, 0);

    // Entry 1: Kernel Code Segment (64-bit)
    // Access: P=1, DPL=0, S=1 (Code/Data), Type=0xA (Execute/Read, Non-Conforming) -> 0x9A
    // Flags: G=1 (4KB Granularity), L=1 (64-bit Long Mode), D/B=0 (for L=1) -> 0xA0 (for G=1, L=1, D/B=0, AVL=0)
    // Limit for G=1, L=1 should be 0xFFFFF for full 4GB-like range (scaled by 4KB)
    // Base is 0 for 64-bit code/data segments.
    set_gdt_entry(&gdt_entries[1], 0, 0xFFFFF, 0x9A, 0xA0); // 0xA0 for flags: G=1, L=1

    // Entry 2: Kernel Data Segment (64-bit)
    // Access: P=1, DPL=0, S=1 (Code/Data), Type=0x2 (Read/Write, Expand Up) -> 0x92
    // Flags: G=1 (4KB Granularity), L=0 (not code), D/B=1 (32-bit stack/ops, but L=0 means this is for data) -> 0xC0 (for G=1, D/B=1)
    set_gdt_entry(&gdt_entries[2], 0, 0xFFFFF, 0x92, 0xC0);




    // Entry 3: User Code Segment (64-bit, DPL=3)
    set_gdt_entry(&gdt_entries[3], 0, 0xFFFFF, 0xFA, 0xA0);

    // Entry 4: User Data Segment (64-bit, DPL=3)
    set_gdt_entry(&gdt_entries[4], 0, 0xFFFFF, 0xF2, 0xC0);

    // Entry 5-6: Task State Segment descriptor
    ulong tss_base = cast(ulong)&tss;
    set_gdt_entry(&gdt_entries[5], cast(uint)tss_base, Tss64.sizeof - 1, 0x89, 0);

    // The second 8-byte slot of the TSS descriptor stores only the high 32 bits
    // of the TSS base and a reserved field.  Using a specialised structure here
    // avoids treating it like a normal GDT entry, which previously led to
    // corrupted descriptor contents.
    TssDescriptorHigh* tss_high = cast(TssDescriptorHigh*)&gdt_entries[6];
    tss_high.base_32_63 = cast(uint)(tss_base >> 32);
    tss_high.reserved   = 0;

    gdt_ptr.limit = calculated_limit;
    gdt_ptr.base  = cast(ulong)&gdt_entries[0]; // Address of the first element of the global array

    terminal_writestring("  GDT Ptr Limit: "); terminal_write_hex(gdt_ptr.limit); terminal_writestring("\n");
    terminal_writestring("  GDT Ptr Base: "); terminal_write_hex(gdt_ptr.base); terminal_writestring("\n");

    terminal_writestring("Flushing GDT...\n");
    gdt_flush(&gdt_ptr); // Pass pointer to the global GdtPtr struct
    // Add a direct VGA write *after* gdt_flush to see if it returns.
    // Use a distinct character and position.
    ushort* pVGADebug = cast(ushort*) VGA_ADDRESS; 
    pVGADebug[10] = vga_entry('F', vga_entry_color(VGAColor.WHITE, VGAColor.RED)); // 'F' for Flushed, at column 10

    // Load the Task Register with the selector for our TSS descriptor
    load_tss(0x28); // GDT entry 5

    terminal_writestring("GDT flushed.\n");
}
