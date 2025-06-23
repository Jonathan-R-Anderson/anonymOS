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

// Indices of each descriptor in our table
enum GDT_NULL        = 0;
enum GDT_KERNEL_CODE = 1;
enum GDT_KERNEL_DATA = 2;
enum GDT_USER_CODE   = 3;
enum GDT_USER_DATA   = 4;
enum GDT_TSS_LOW     = 5; // First half of the 64-bit TSS descriptor
enum GDT_TSS_HIGH    = 6; // Second half

enum GDT_ENTRY_SIZE = GdtEntry.sizeof; // 8 bytes per entry

// Segment selectors used elsewhere in the kernel
enum ushort KERNEL_CODE_SELECTOR = cast(ushort)(GDT_KERNEL_CODE * GDT_ENTRY_SIZE);
enum ushort KERNEL_DATA_SELECTOR = cast(ushort)(GDT_KERNEL_DATA * GDT_ENTRY_SIZE);
enum ushort USER_CODE_SELECTOR   = cast(ushort)((GDT_USER_CODE * GDT_ENTRY_SIZE) | 3);
enum ushort USER_DATA_SELECTOR   = cast(ushort)((GDT_USER_DATA * GDT_ENTRY_SIZE) | 3);
enum ushort TSS_SELECTOR         = cast(ushort)(GDT_TSS_LOW * GDT_ENTRY_SIZE);

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


align(16) ubyte[4096] kernel_stack;
align(16) ubyte[4096] ist1_stack;


// Access byte values for common segment types
enum ACCESS_CODE_KERNEL = 0x9A; // Present, ring0, execute/read
enum ACCESS_DATA_KERNEL = 0x92; // Present, ring0, read/write
enum ACCESS_CODE_USER   = 0xFA; // Present, ring3, execute/read
enum ACCESS_DATA_USER   = 0xF2; // Present, ring3, read/write
enum ACCESS_TSS         = 0x89; // Available 64-bit TSS

// Flag byte values (higher 4 bits of the flags/limit byte)
enum FLAGS_CODE = 0xA0; // G=1, D/B=0, L=1
enum FLAGS_DATA = 0xC0; // G=1, D/B=1, L=0
enum FLAGS_TSS  = 0x00;

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

align(16) __gshared Tss64 tss = Tss64.init;

// Second half of a 64-bit TSS descriptor (base high and reserved fields)
align(1) struct TssDescriptorHigh {
    uint base_32_63;
    uint reserved;
}

extern (C) void gdt_flush(GdtPtr* gdtPtrAddr); // Defined in gdt.s
extern (C) void tss_flush();                   // Defined in tss.s – loads TR
extern (C) void load_tss(ushort selector);     // Defined in tss.s


// Helper to set GDT entries in a provided GdtEntry.
void set_idt_entry(size_t vec, void* handler, ubyte ist = 0, ubyte type_attributes = 0x8E) {
    auto offset = cast(ulong)handler;
    idt_entries[vec].offset_low  = cast(ushort)(offset & 0xFFFF);
    idt_entries[vec].selector    = KERNEL_CODE_SELECTOR;
    idt_entries[vec].ist         = ist & 0x07; // Only bits 0–2 valid
    idt_entries[vec].type_attr   = type_attr;
    idt_entries[vec].offset_mid  = cast(ushort)((offset >> 16) & 0xFFFF);
    idt_entries[vec].offset_high = cast(uint)((offset >> 32) & 0xFFFFFFFF);
    idt_entries[vec].zero        = 0;
}

void init_gdt() {
    terminal_writestring("Initializing GDT...\n");

    // Initialize all to dummy handler first (optional)
    foreach (i; 0..idt_entries.length)
        set_idt_entry(i, &default_interrupt_handler);

    // Set double fault (vector 8) to use IST1 (index 1)
    set_idt_entry(0x08, &isr_double_fault, 1); // IST1

    // Optionally: GPF, Page Fault, etc.
    set_idt_entry(0x0D, &isr_general_protection); // no IST
    set_idt_entry(0x0E, &isr_page_fault);         // no IST

    size_t entry_size = GdtEntry.sizeof;
    size_t num_entries = gdt_entries.length;
    size_t total_gdt_size = entry_size * num_entries;
    ushort calculated_limit = cast(ushort)(total_gdt_size - 1);


    // Load IDT
    align(1) struct IdtPtr {
        ushort limit;
        ulong base;
    }

    IdtPtr idt_ptr;
    idt_ptr.limit = cast(ushort)(idt_entries.length * IdtEntry.sizeof - 1);
    idt_ptr.base = cast(ulong)&idt_entries[0];


    // Disable the I/O permission bitmap
    tss.io_map_base = cast(ushort)Tss64.sizeof;

    terminal_writestring("  GDT Entry Size: "); terminal_write_hex(entry_size); terminal_writestring("\n");
    terminal_writestring("  Num GDT Entries: "); terminal_write_hex(num_entries); terminal_writestring("\n");
    terminal_writestring("  Total GDT Size: "); terminal_write_hex(total_gdt_size); terminal_writestring("\n");
    terminal_writestring("  Calculated GDT Limit: "); terminal_write_hex(calculated_limit); terminal_writestring("\n");

    // Entry 0: Null Descriptor
    set_gdt_entry(&gdt_entries[GDT_NULL], 0, 0, 0, 0);
    terminal_writestring("set gdt entry"); terminal_writestring("\n");

    // Entry 1: Kernel Code Segment (64-bit)
    // Access: P=1, DPL=0, S=1 (Code/Data), Type=0xA (Execute/Read, Non-Conforming) -> 0x9A
    // Flags: G=1 (4KB Granularity), L=1 (64-bit Long Mode), D/B=0 (for L=1) -> 0xA0 (for G=1, L=1, D/B=0, AVL=0)
    // Limit for G=1, L=1 should be 0xFFFFF for full 4GB-like range (scaled by 4KB)
    // Base is 0 for 64-bit code/data segments.
    set_gdt_entry(&gdt_entries[GDT_KERNEL_CODE], 0, 0xFFFFF, ACCESS_CODE_KERNEL, FLAGS_CODE);
    terminal_writestring("kernel code segment"); terminal_writestring("\n");

    // Entry 2: Kernel Data Segment (64-bit)
    // Access: P=1, DPL=0, S=1 (Code/Data), Type=0x2 (Read/Write, Expand Up) -> 0x92
    // Flags: G=1 (4KB Granularity), L=0 (not code), D/B=1 (32-bit stack/ops, but L=0 means this is for data) -> 0xC0 (for G=1, D/B=1)
    set_gdt_entry(&gdt_entries[GDT_KERNEL_DATA], 0, 0xFFFFF, ACCESS_DATA_KERNEL, FLAGS_DATA);
    terminal_writestring("kernel data segment"); terminal_writestring("\n");




    // Entry 3: User Code Segment (64-bit, DPL=3)
    set_gdt_entry(&gdt_entries[GDT_USER_CODE], 0, 0xFFFFF, ACCESS_CODE_USER, FLAGS_CODE);
    terminal_writestring("user code segment"); terminal_writestring("\n");

    // Entry 4: User Data Segment (64-bit, DPL=3)
    set_gdt_entry(&gdt_entries[GDT_USER_DATA], 0, 0xFFFFF, ACCESS_DATA_USER, FLAGS_DATA);
    terminal_writestring("user data segment"); terminal_writestring("\n");

    // Entry 5-6: Task State Segment descriptor
    ulong tss_base = cast(ulong)&tss;
    set_gdt_entry(&gdt_entries[GDT_TSS_LOW], cast(uint)tss_base, Tss64.sizeof - 1, ACCESS_TSS, FLAGS_TSS);
    terminal_writestring("task segment descriptor"); terminal_writestring("\n");

    // The second 8-byte slot of the TSS descriptor stores only the high 32 bits
    // of the TSS base and a reserved field.  Using a specialised structure here
    // avoids treating it like a normal GDT entry, which previously led to
    // corrupted descriptor contents.
    TssDescriptorHigh* tss_high = cast(TssDescriptorHigh*)&gdt_entries[GDT_TSS_HIGH];
    tss_high.base_32_63 = cast(uint)(tss_base >> 32);
    tss_high.reserved   = 0;

    gdt_ptr.limit = calculated_limit;
    gdt_ptr.base  = cast(ulong)&gdt_entries[0]; // Address of the first element of the global array

    terminal_writestring("  GDT Ptr Limit: "); terminal_write_hex(gdt_ptr.limit); terminal_writestring("\n");
    terminal_writestring("  GDT Ptr Base: "); terminal_write_hex(gdt_ptr.base); terminal_writestring("\n");
    // Extra diagnostics to verify pointer correctness
    terminal_writestring("  &gdt_entries[0] = ");
    terminal_write_hex(cast(ulong)&gdt_entries[0]);
    terminal_writestring("\n");
    terminal_writestring("  &gdt_ptr = ");
    terminal_write_hex(cast(ulong)&gdt_ptr);
    terminal_writestring("\n");

    terminal_writestring("Flushing GDT...\n");
    gdt_flush(&gdt_ptr); // Pass pointer to the global GdtPtr struct

    tss.rsp0 = cast(ulong)&kernel_stack[$ - 1]; // top of kernel stack
    tss.ist1 = cast(ulong)&ist1_stack[$ - 1];   // top of IST1 stack


    // Load the Task Register using the selector constant so the value
    // stays correct if the GDT layout changes.  Using the helper that
    // accepts a selector avoids hard‑coding 0x28 inside the assembly
    // routine and mirrors the semantics of lgdt.
    load_tss(TSS_SELECTOR);
    // Add a direct VGA write *after* gdt_flush to see if it returns.
    // Use a distinct character and position.
    ushort* pVGADebug = cast(ushort*) VGA_ADDRESS; 
    pVGADebug[10] = vga_entry('F', vga_entry_color(VGAColor.WHITE, VGAColor.RED)); // 'F' for Flushed, at column 10

    terminal_writestring("GDT flushed.\n");
}
