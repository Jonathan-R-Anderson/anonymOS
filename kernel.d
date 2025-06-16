// kernel.d
import core.stdc.stdint; // For C-compatible integer types like uint16_t, etc.

enum VGA_ADDRESS = 0xB8000;
enum VGA_WIDTH = 80;
enum VGA_HEIGHT = 25;

enum PIC1_COMMAND = 0x20;
enum PIC1_DATA = 0x21;
enum PIC2_COMMAND = 0xA0;
enum PIC2_DATA = 0xA1;
enum PIC_EOI = 0x20; // End Of Interrupt command code

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
struct GdtPtr {
    ushort limit; // Size of GDT - 1
    uint base; // Address of GDT
}
ushort* const g_pVGAMemory = cast(ushort*) VGA_ADDRESS; // Pointer is const, data is mutable
size_t g_TerminalRow;
size_t g_TerminalColumn;
ubyte g_TerminalColor;
char[256] scancode_to_char; // Basic scancode map

// VGA color byte: foreground on background
ubyte vga_entry_color(ubyte fg, ubyte bg) {
    return cast(ubyte)(fg | (bg << 4));
}

// VGA character entry: character and color attribute
ushort vga_entry(char uc, ubyte color) {
    return (cast(ushort) uc) | (cast(ushort) color << 8);
}

// --- I/O Port Functions ---
extern (C) void outb(ushort port, ubyte value) {
    asm {
        "mov dx, [ebp+8]";  // port
        "mov al, [ebp+12]"; // value
        "out dx, al";
        "nop"; // Some delay might be needed for older hardware
        "nop";
    }
}

extern (C) ubyte inb(ushort port) {
    ubyte result;
    asm {
        "mov dx, [ebp+8]"; // port
        "in al, dx";
        "mov [ebp-1], al"; // Store result in local variable 'result'
        "nop";
        "nop";
    }
    return result;
}

// --- GDT Setup ---
GdtEntry[3] gdt_entries; // 0: Null, 1: Kernel Code, 2: Kernel Data
GdtPtr gdt_ptr;

extern (C) void gdt_flush(uint gdtPtrAddr); // Defined in gdt.s

void gdt_set_gate(int num, uint base, uint limit, ubyte access, ubyte gran) {
    gdt_entries[num].base_low    = cast(ushort)(base & 0xFFFF);
    gdt_entries[num].base_middle = cast(ubyte)((base >> 16) & 0xFF);
    gdt_entries[num].base_high   = cast(ubyte)((base >> 24) & 0xFF);

    gdt_entries[num].limit_low   = cast(ushort)(limit & 0xFFFF);
    gdt_entries[num].granularity = cast(ubyte)(((limit >> 16) & 0x0F) | (gran & 0xF0));

    gdt_entries[num].access      = access;
}

void init_gdt() {
    gdt_ptr.limit = (GdtEntry.sizeof * gdt_entries.length) - 1;
    gdt_ptr.base  = cast(uint)&gdt_entries[0];

    // Null segment
    gdt_set_gate(0, 0, 0, 0, 0);
    // Code segment: base=0, limit=4GB, access=Kernel Code (0x9A)
    // Granularity: 4KB blocks, 32-bit protected mode (0xCF)
    gdt_set_gate(1, 0, 0xFFFFFFFF, 0x9A, 0xCF);
    // Data segment: base=0, limit=4GB, access=Kernel Data (0x92)
    // Granularity: 4KB blocks, 32-bit protected mode (0xCF)
    gdt_set_gate(2, 0, 0xFFFFFFFF, 0x92, 0xCF);

    gdt_flush(cast(uint)&gdt_ptr);
}

// --- IDT Setup ---
struct IdtEntry {
    ushort base_low;  // Lower 16 bits of handler function address
    ushort selector;  // Code segment selector (0x08 for kernel code)
    ubyte  zero;      // Always zero
    ubyte  type_attr; // Type and attributes (e.g., 0x8E for 32-bit interrupt gate)
    ushort base_high; // Upper 16 bits of handler function address
}

struct IdtPtr {
    ushort limit; // Size of IDT - 1
    uint   base;  // Address of IDT
}
align(1) IdtPtr idt_ptr_struct; // Apply align(1) to the specific instance used for lidt

IdtEntry[256] idt_entries; // Declaration for the IDT entries array

extern (C) void idt_load(uint idtPtrAddr); // Defined in idt.s

// Declare ISR stubs from isr_stubs.s
extern(C) {
    void isr0();  void isr1();  void isr2();  void isr3();  void isr4();
    void isr5();  void isr6();  void isr7();  void isr8();  void isr9();
    void isr10(); void isr11(); void isr12(); void isr13(); void isr14();
    void isr15(); void isr16(); void isr17(); void isr18(); void isr19();
    void isr20(); void isr21(); void isr22(); void isr23(); void isr24();
    void isr25(); void isr26(); void isr27(); void isr28(); void isr29();
    void isr30(); void isr31();
    void isr32(); void isr33(); void isr34(); void isr35(); void isr36();
    void isr37(); void isr38(); void isr39(); void isr40(); void isr41();
    void isr42(); void isr43(); void isr44(); void isr45(); void isr46();
    void isr47();
    void unhandled_interrupt(); // Fallback
}

void terminal_initialize() {
    g_TerminalRow = 0;
    g_TerminalColumn = 0;
    // Light grey foreground, black background
    g_TerminalColor = vga_entry_color(0x0F, 0x00); // White on Black

    for (size_t y = 0; y < VGA_HEIGHT; y++) {
        for (size_t x = 0; x < VGA_WIDTH; x++) {
            const size_t index = y * VGA_WIDTH + x;
            g_pVGAMemory[index] = vga_entry(' ', g_TerminalColor);
        }
    }

    // Basic US QWERTY scancode map (only printable chars for now)
    // Needs to be expanded for shift, ctrl, alt, etc.
    scancode_to_char[0x02] = '1'; scancode_to_char[0x03] = '2'; scancode_to_char[0x04] = '3';
    scancode_to_char[0x05] = '4'; scancode_to_char[0x06] = '5'; scancode_to_char[0x07] = '6';
    scancode_to_char[0x08] = '7'; scancode_to_char[0x09] = '8'; scancode_to_char[0x0A] = '9';
    scancode_to_char[0x0B] = '0'; scancode_to_char[0x10] = 'q'; scancode_to_char[0x11] = 'w';
    scancode_to_char[0x12] = 'e'; scancode_to_char[0x13] = 'r'; scancode_to_char[0x14] = 't';
    scancode_to_char[0x15] = 'y'; scancode_to_char[0x16] = 'u'; scancode_to_char[0x17] = 'i';
    scancode_to_char[0x18] = 'o'; scancode_to_char[0x19] = 'p'; scancode_to_char[0x1E] = 'a';
    // ... and so on for all keys. This is just a small sample.
    scancode_to_char[0x1C] = '\n'; // Enter key
    scancode_to_char[0x39] = ' ';  // Space bar
}

void terminal_scroll() {
    // Move all lines up by one
    for (size_t y = 0; y < VGA_HEIGHT - 1; y++) {
        for (size_t x = 0; x < VGA_WIDTH; x++) {
            g_pVGAMemory[y * VGA_WIDTH + x] = g_pVGAMemory[(y + 1) * VGA_WIDTH + x];
        }
    }
    // Clear the last line
    for (size_t x = 0; x < VGA_WIDTH; x++) {
        g_pVGAMemory[(VGA_HEIGHT - 1) * VGA_WIDTH + x] = vga_entry(' ', g_TerminalColor);
    }
    g_TerminalRow = VGA_HEIGHT - 1; // Reset cursor to the new last line
}

void terminal_putchar(char c) {
    if (c == '\n') {
        g_TerminalColumn = 0;
        g_TerminalRow++;
    } else {
        const size_t index = g_TerminalRow * VGA_WIDTH + g_TerminalColumn;
        g_pVGAMemory[index] = vga_entry(c, g_TerminalColor);
        g_TerminalColumn++;
    }

    if (g_TerminalColumn >= VGA_WIDTH) {
        g_TerminalColumn = 0;
        g_TerminalRow++;
    }

    if (g_TerminalRow >= VGA_HEIGHT) {
        terminal_scroll();
    }
}

void terminal_write_hex(uint n) {
    const(char)* hex_chars = "0123456789ABCDEF";
    terminal_putchar('0');
    terminal_putchar('x');
    bool leading_zeros = true;
    for (int i = 28; i >= 0; i -= 4) {
        ubyte digit = (n >> i) & 0xF;
        if (digit != 0 || !leading_zeros || i == 0) {
            terminal_putchar(hex_chars[digit]);
            leading_zeros = false;
        }
    }
}

void terminal_writestring(const(char)* str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        terminal_putchar(str[i]);
    }
}

// --- PIC Remapping ---
void pic_remap(int offset1, int offset2) {
    ubyte a1, a2;

    a1 = inb(PIC1_DATA);                        // save masks
    a2 = inb(PIC2_DATA);

    outb(PIC1_COMMAND, 0x11);  // starts the initialization sequence (in cascade mode)
    outb(PIC2_COMMAND, 0x11);

    outb(PIC1_DATA, cast(ubyte)offset1); // ICW2: Master PIC vector offset
    outb(PIC2_DATA, cast(ubyte)offset2); // ICW2: Slave PIC vector offset

    outb(PIC1_DATA, 4);                       // ICW3: tell Master PIC that there is a slave PIC at IRQ2 (0000 0100)
    outb(PIC2_DATA, 2);                       // ICW3: tell Slave PIC its cascade identity (0000 0010)

    outb(PIC1_DATA, 0x01);     // ICW4: have the PICs use 8086 mode (and not 8080 mode)
    outb(PIC2_DATA, 0x01);

    outb(PIC1_DATA, a1);   // restore saved masks.
    outb(PIC2_DATA, a2);
}

void idt_set_gate(ubyte num, uint base, ushort sel, ubyte flags) {
    idt_entries[num].base_low = cast(ushort)(base & 0xFFFF);
    idt_entries[num].base_high = cast(ushort)((base >> 16) & 0xFFFF);
    idt_entries[num].selector = sel;
    idt_entries[num].zero = 0;
    idt_entries[num].type_attr = flags; // | 0x60 for user-mode if needed
}

void init_idt() {
    idt_ptr_struct.limit = (IdtEntry.sizeof * 256) - 1;
    idt_ptr_struct.base  = cast(uint)&idt_entries[0];

    // Clear IDT entries to a default handler (e.g., unhandled_interrupt)
    // For now, let's zero them and then set specific ones.
    // A better approach would be to point all to a generic "unhandled interrupt" stub.
    // memset(&idt_entries, 0, IdtEntry.sizeof * 256); // Need memset
    for (int i = 0; i < 256; i++) {
         idt_set_gate(cast(ubyte)i, cast(uint)&unhandled_interrupt, 0x08, 0x8E); // Uses idt_entries via idt_set_gate
    }

    // Remap PIC before setting up IRQ handlers in IDT
    pic_remap(0x20, 0x28); // Remap IRQs to 32-47

    // CPU Exceptions
    idt_set_gate(0, cast(uint)&isr0, 0x08, 0x8E); // Uses idt_entries
    idt_set_gate(1, cast(uint)&isr1, 0x08, 0x8E); // Uses idt_entries
    // ... (set all 32 exception handlers) ...
    idt_set_gate(13, cast(uint)&isr13, 0x08, 0x8E); // General Protection Fault // Uses idt_entries
    idt_set_gate(14, cast(uint)&isr14, 0x08, 0x8E); // Page Fault // Uses idt_entries

    // Hardware IRQs (now at 32-47)
    idt_set_gate(32, cast(uint)&isr32, 0x08, 0x8E); // Timer // Uses idt_entries
    idt_set_gate(33, cast(uint)&isr33, 0x08, 0x8E); // Keyboard // Uses idt_entries
    // ... (set other IRQ handlers as needed) ...

    idt_load(cast(uint)&idt_ptr_struct);
}

// --- Interrupt Handling ---
struct Registers {
    uint ds; // Data segment selector pushed by isr_common_stub
    uint edi, esi, ebp, esp_dummy, ebx, edx, ecx, eax; // Pushed by pusha
    uint int_no, err_code; // Pushed by our specific ISR stubs
    uint eip, cs, eflags, useresp, ss; // Pushed by the processor automatically
}

extern (C) void interrupt_handler_d(Registers* regs) {
    terminal_writestring("Interrupt: ");
    terminal_write_hex(regs.int_no);

    if (regs.err_code != 0) { // Some ISRs push a dummy 0, real error codes are non-zero
        terminal_writestring(", Error Code: ");
        terminal_write_hex(regs.err_code);
    }
    terminal_putchar('\n');

    // Handle keyboard interrupt (IRQ1, which is ISR 33 after remapping)
    if (regs.int_no == 33) {
        ubyte scancode = inb(0x60); // Read scancode from keyboard controller data port
        terminal_writestring("Scancode: ");
        terminal_write_hex(scancode);

        // Very basic scancode to char conversion (only for pressed keys, no release codes)
        if (scancode < scancode_to_char.length && scancode_to_char[scancode] != 0) {
            terminal_writestring(" Char: ");
            terminal_putchar(scancode_to_char[scancode]);
        }
        terminal_putchar('\n');
    }

    // If it's a hardware interrupt (IRQ), we need to send an EOI
    if (regs.int_no >= 32 && regs.int_no <= 47) { // IRQs 0-15
        if (regs.int_no >= 40) { // If interrupt came from slave PIC (IRQ 8-15)
            outb(PIC2_COMMAND, PIC_EOI);
        }
        outb(PIC1_COMMAND, PIC_EOI); // Always send to master
    }

    if (regs.int_no < 32 && regs.int_no != 2) { // CPU Exception, not NMI
        terminal_writestring("CPU Exception. Halting.\n");
        asm { "cli"; "hlt"; }
    }
}

// Kernel's main entry point, called from boot.s
extern (C) void kmain() {
    terminal_initialize();
    init_gdt();
    terminal_writestring("GDT Initialized.\n");
    init_idt();
    terminal_writestring("IDT Initialized, PIC Remapped.\n");

    terminal_writestring("Hello from Minimal D OS!\n");
    terminal_writestring("Running in -betterC mode.\n");
    terminal_writestring("Interrupts are now active. Try typing!\n");

    // Enable interrupts
    asm { "sti"; }

    // Example: Trigger a divide by zero exception
    // int x = 5; int y = 0; int z = x / y; terminal_write_hex(z);

    // Halt loop (interrupts will still occur)
    while (true) {
        asm { "hlt"; } // Halt until next interrupt
    }
}