// kernel.d

// VGA Constants
enum VGA_ADDRESS = 0xB8000;
enum VGA_WIDTH = 80;
enum VGA_HEIGHT = 25;

// PIC Constants
enum PIC1_COMMAND = 0x20;
enum PIC1_DATA = 0x21;
enum PIC2_COMMAND = 0xA0;
enum PIC2_DATA = 0xA1;
enum PIC_EOI = 0x20; // End Of Interrupt command code

// --- Error Handling & Panic ---

// VGA Colors (inspired by OSDev wiki)
enum VGAColor : ubyte {
    BLACK = 0,
    BLUE = 1,
    GREEN = 2,
    CYAN = 3,
    RED = 4,
    MAGENTA = 5,
    BROWN = 6,
    LIGHT_GREY = 7,
    DARK_GREY = 8,
    LIGHT_BLUE = 9,
    LIGHT_GREEN = 10,
    LIGHT_CYAN = 11,
    LIGHT_RED = 12,
    LIGHT_MAGENTA = 13,
    LIGHT_BROWN = 14, // Often Yellow
    WHITE = 15,
}

enum ErrorCode : ubyte {
    NONE = 0,
    GDT_LOAD_FAILURE = 0x01,     // If GDT setup was verified in D
    IDT_INIT_FAILURE = 0x02,
    ISR_INSTALL_FAILURE = 0x03,
    // Add more specific error codes as your kernel grows
    UNKNOWN_FAILURE = 0xFF,
}

// Helper function to get the length of a C-style null-terminated string
size_t strlen_c(const(char)* str) {
    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

// Basic C library function implementations needed by the compiler/runtime
extern (C) void* memset(void* ptr, int value, size_t num) {
    ubyte* p = cast(ubyte*)ptr;
    ubyte val = cast(ubyte)value;
    for (size_t i = 0; i < num; i++) {
        p[i] = val;
    }
    return ptr;
}

// Helper for kernel_panic to write directly to VGA, bypassing terminal functions initially
void panic_vga_writestring(const char* s, size_t r, size_t c, ubyte color) {
    ushort* vga = cast(ushort*)VGA_ADDRESS;
    size_t i = 0;
    while (s[i] != '\0' && (r * VGA_WIDTH + c + i) < (VGA_WIDTH * VGA_HEIGHT)) {
        vga[r * VGA_WIDTH + c + i] = vga_entry(s[i], color);
        i++;
    }
}

extern (C) @noreturn void kernel_panic(const char* message, ErrorCode code) {
    // Attempt to disable interrupts immediately.
    // This might be too late if we're already in a bad state, but it's worth trying.
    asm { "cli"; }

    ubyte panic_color = vga_entry_color(VGAColor.WHITE, VGAColor.RED);

    // Crude initial message directly to VGA, in case terminal functions are broken
    // Clear a portion of the screen for the panic message
    for (size_t y_idx = 0; y_idx < 5; ++y_idx) { // Clear top 5 lines
        for (size_t x_idx = 0; x_idx < VGA_WIDTH; ++x_idx) {
            (cast(ushort*)VGA_ADDRESS)[y_idx * VGA_WIDTH + x_idx] = vga_entry(' ', panic_color);
        }
    }
    panic_vga_writestring("!!! KERNEL PANIC !!!", 0, (VGA_WIDTH - "!!! KERNEL PANIC !!!".length) / 2, panic_color);
    size_t message_len = strlen_c(message);
    panic_vga_writestring(message, 1, (VGA_WIDTH - message_len) / 2, panic_color);

    // Use terminal functions
    g_TerminalColor = panic_color; // White text on Red background for panic
    terminal_initialize(); // Clears screen and resets cursor/color
    g_TerminalRow = VGA_HEIGHT / 2 - 3; // Center message roughly
    g_TerminalColumn = (VGA_WIDTH - "KERNEL PANIC!".length) / 2;
    terminal_writestring("KERNEL PANIC!");
    g_TerminalRow++; g_TerminalColumn = (VGA_WIDTH - message_len) / 2;
    terminal_writestring(message);
    g_TerminalRow++; g_TerminalColumn = (VGA_WIDTH - "Error Code: 0xXX".length) / 2; // Approx. length
    terminal_writestring("Error Code: ");
    terminal_write_hex(cast(uint)code);
    g_TerminalRow+=2; g_TerminalColumn = (VGA_WIDTH - "System Halted.".length) / 2;
    terminal_writestring("System Halted.");

    // Halt the CPU
    while (true) {
        asm { "cli"; "hlt"; }
    }
}


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

// Basic scancode map (US QWERTY, lowercase, no modifiers)
// Initialized globally.
char[256] scancode_to_char = init_scancode_map();

// Helper to initialize scancode_to_char
char[256] init_scancode_map() {
    char[256] map;
    // Initialize all to 0 (no character)
    for (size_t i = 0; i < map.length; i++) {
        map[i] = 0;
    }

    // Based on PS/2 Set 1 Scan Codes (Make codes)
    map[0x02] = '1'; map[0x03] = '2'; map[0x04] = '3'; map[0x05] = '4';
    map[0x06] = '5'; map[0x07] = '6'; map[0x08] = '7'; map[0x09] = '8';
    map[0x0A] = '9'; map[0x0B] = '0'; map[0x0C] = '-'; map[0x0D] = '=';

    map[0x10] = 'q'; map[0x11] = 'w'; map[0x12] = 'e'; map[0x13] = 'r';
    map[0x14] = 't'; map[0x15] = 'y'; map[0x16] = 'u'; map[0x17] = 'i';
    map[0x18] = 'o'; map[0x19] = 'p'; map[0x1A] = '['; map[0x1B] = ']';
    map[0x1E] = 'a'; map[0x1F] = 's'; map[0x20] = 'd'; map[0x21] = 'f';
    map[0x22] = 'g'; map[0x23] = 'h'; map[0x24] = 'j'; map[0x25] = 'k';
    map[0x26] = 'l'; map[0x27] = ';'; map[0x28] = '\''; map[0x29] = '`';

    map[0x2C] = 'z'; map[0x2D] = 'x'; map[0x2E] = 'c'; map[0x2F] = 'v';
    map[0x30] = 'b'; map[0x31] = 'n'; map[0x32] = 'm'; map[0x33] = ',';
    map[0x34] = '.'; map[0x35] = '/';

    map[0x39] = ' '; // Spacebar

    return map;
}

// VGA color byte: foreground on background
ubyte vga_entry_color(VGAColor fg, VGAColor bg) {
    return cast(ubyte)(cast(ubyte)fg | (cast(ubyte)bg << 4));
}
// Overload for raw ubyte colors if needed, though enum is preferred
ubyte vga_entry_color(ubyte fg, ubyte bg) { // Keep this for existing panic call if it uses raw ubytes
    return cast(ubyte)(fg | (bg << 4));
}

// VGA character entry: character and color attribute
ushort vga_entry(char uc, ubyte color) {
    return (cast(ushort) uc) | (cast(ushort) color << 8);
}

// --- I/O Port Functions ---
extern (C) void outb(ushort port, ubyte value) {
    asm {
        // Extended inline assembly: outb source_reg (value in al), dest_port_reg (port in dx)
        "outb %0, %1"
        : // No output operands
        : "a"(value), "d"(port) // Input operands: %0 is value (in al), %1 is port (in dx)
        : // No clobbered registers
        "nop"; // Some delay might be needed for older hardware
        "nop";
    }
}

extern (C) ubyte inb(ushort port) {
    ubyte result;
    asm {
        // Extended inline assembly: inb source_port_reg (port in dx), dest_reg (result in al)
        "inb %1, %0"
        : "=a"(result) // Output operand: %0 is result (in al)
        : "d"(port)    // Input operand: %1 is port (in dx)
        : // No clobbered registers
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
    // Use a known VGA memory pointer for direct debug output.
    // kmain calls terminal_initialize() first, which clears the screen.
    // These writes will appear if terminal_initialize hasn't cleared this specific spot yet,
    // or if init_gdt is called before terminal_initialize (not the case in revised kmain).
    ushort* pDebugVGAMem = cast(ushort*)VGA_ADDRESS;
    pDebugVGAMem[20] = vga_entry('S', vga_entry_color(VGAColor.WHITE, VGAColor.BLACK)); // 'S' for Start

    gdt_ptr.limit = (GdtEntry.sizeof * gdt_entries.length) - 1;
    gdt_ptr.base  = cast(uint)&gdt_entries[0];
    pDebugVGAMem[21] = vga_entry('P', vga_entry_color(VGAColor.WHITE, VGAColor.BLACK)); // 'P' for GdtPtr

    // Null segment
    gdt_set_gate(0, 0, 0, 0, 0);
    pDebugVGAMem[22] = vga_entry('0', vga_entry_color(VGAColor.WHITE, VGAColor.BLACK)); // '0' for gate 0
    // Code segment: base=0, limit=4GB, access=Kernel Code (0x9A)
    // Granularity: 4KB blocks, 32-bit protected mode (0xCF)
    gdt_set_gate(1, 0, 0xFFFFFFFF, 0x9A, 0xCF);
    pDebugVGAMem[23] = vga_entry('1', vga_entry_color(VGAColor.WHITE, VGAColor.BLACK)); // '1' for gate 1
    // Data segment: base=0, limit=4GB, access=Kernel Data (0x92)
    // Granularity: 4KB blocks, 32-bit protected mode (0xCF)
    gdt_set_gate(2, 0, 0xFFFFFFFF, 0x92, 0xCF);
    pDebugVGAMem[24] = vga_entry('2', vga_entry_color(VGAColor.WHITE, VGAColor.BLACK)); // '2' for gate 2

    // This message assumes terminal_initialize has been called.
    terminal_writestring("GDT D_SETUP_OK_PRE_FLUSH\n");
    gdt_flush(cast(uint)&gdt_ptr);
    terminal_writestring("GDT_FLUSH_OK\n");
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

IdtEntry[256] idt_entries; // Declare the IDT array

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

// --- Terminal Printing Utilities (Consolidated) ---
// Use volatile for memory-mapped I/O to prevent unwanted compiler optimizations
// FIXME: The 'volatile' keyword (for volatile(T) type constructor) is reported as an
// "undefined identifier" by the current LDC2 -betterC setup for this target.
// This means memory-mapped I/O to VGA_ADDRESS is NOT guaranteed to be safe from compiler optimizations.
// For true correctness, the compiler issue with 'volatile' needs to be resolved,
// or all accesses to g_pVGAMemory should be done via inline assembly.
ushort* g_pVGAMemory = cast(ushort*) VGA_ADDRESS; // Was PtrToVolatileUshort
size_t g_TerminalRow;
size_t g_TerminalColumn; // Current column
ubyte g_TerminalColor;

// Removed use_pointer_for_side_effects as g_pVGAMemory is now volatile
// (Note: the FIXME about volatile still stands, so this might not be truly volatile)


void terminal_initialize() {
    g_TerminalRow = 0;
    g_TerminalColumn = 0;
    g_TerminalColor = vga_entry_color(VGAColor.LIGHT_GREY, VGAColor.BLACK);

    // Optional: Test write to ensure volatile g_pVGAMemory is working.
    // Clear the entire screen
    for (size_t y = 0; y < VGA_HEIGHT; y++) {
        for (size_t x = 0; x < VGA_WIDTH; x++) {
            const size_t index = y * VGA_WIDTH + x;
            g_pVGAMemory[index] = vga_entry(' ', g_TerminalColor);
        }
    }
    // Reset cursor to top-left after clearing
    g_TerminalRow = 0;
    g_TerminalColumn = 0;
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
        // Basic check for printable ASCII or handle non-printable characters if desired
        // For now, assume 'c' is a printable character
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

    outb(PIC1_COMMAND, 0x11);  // ICW1_INIT | ICW1_ICW4 - starts the initialization sequence (in cascade mode)
    outb(PIC2_COMMAND, 0x11);  // ICW1_INIT | ICW1_ICW4

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

    // Initialize all IDT entries to the unhandled_interrupt handler
    for (int i = 0; i < 256; i++) {
         idt_set_gate(cast(ubyte)i, cast(uint)&unhandled_interrupt, 0x08, 0x8E); // 0x08: KERNEL_CODE_SELECTOR, 0x8E: Present, DPL=0, 32-bit Interrupt Gate
    }

    // Remap PIC before enabling interrupts and setting specific IRQ handlers
    pic_remap(0x20, 0x28); // Remap IRQs to 0x20-0x2F (32-47 decimal)

    // Set up CPU Exception handlers (ISRs 0-31)
    idt_set_gate(0, cast(uint)&isr0, 0x08, 0x8E);
    idt_set_gate(1, cast(uint)&isr1, 0x08, 0x8E);
    idt_set_gate(2, cast(uint)&isr2, 0x08, 0x8E);
    idt_set_gate(3, cast(uint)&isr3, 0x08, 0x8E);
    idt_set_gate(4, cast(uint)&isr4, 0x08, 0x8E);
    idt_set_gate(5, cast(uint)&isr5, 0x08, 0x8E);
    idt_set_gate(6, cast(uint)&isr6, 0x08, 0x8E);
    idt_set_gate(7, cast(uint)&isr7, 0x08, 0x8E);
    idt_set_gate(8, cast(uint)&isr8, 0x08, 0x8E);   // Double Fault
    idt_set_gate(13, cast(uint)&isr13, 0x08, 0x8E); // General Protection Fault
    idt_set_gate(14, cast(uint)&isr14, 0x08, 0x8E); // Page Fault
    // ... Add other specific exception handlers as needed ...
    // For example, ISRs 9-12, 15-19
    idt_set_gate(9, cast(uint)&isr9, 0x08, 0x8E);
    idt_set_gate(10, cast(uint)&isr10, 0x08, 0x8E); idt_set_gate(11, cast(uint)&isr11, 0x08, 0x8E);
    idt_set_gate(12, cast(uint)&isr12, 0x08, 0x8E); idt_set_gate(15, cast(uint)&isr15, 0x08, 0x8E);
    idt_set_gate(16, cast(uint)&isr16, 0x08, 0x8E); idt_set_gate(17, cast(uint)&isr17, 0x08, 0x8E);
    idt_set_gate(18, cast(uint)&isr18, 0x08, 0x8E); idt_set_gate(19, cast(uint)&isr19, 0x08, 0x8E);
    // ISRs 20-31 are reserved by Intel, but we have stubs for them. Unrolled loop:
    idt_set_gate(20, cast(uint)&isr20, 0x08, 0x8E);
    idt_set_gate(21, cast(uint)&isr21, 0x08, 0x8E);
    idt_set_gate(22, cast(uint)&isr22, 0x08, 0x8E);
    idt_set_gate(23, cast(uint)&isr23, 0x08, 0x8E);
    idt_set_gate(24, cast(uint)&isr24, 0x08, 0x8E);
    idt_set_gate(25, cast(uint)&isr25, 0x08, 0x8E);
    idt_set_gate(26, cast(uint)&isr26, 0x08, 0x8E);
    idt_set_gate(27, cast(uint)&isr27, 0x08, 0x8E);
    idt_set_gate(28, cast(uint)&isr28, 0x08, 0x8E);
    idt_set_gate(29, cast(uint)&isr29, 0x08, 0x8E);
    idt_set_gate(30, cast(uint)&isr30, 0x08, 0x8E);
    idt_set_gate(31, cast(uint)&isr31, 0x08, 0x8E);

    // Set up Hardware IRQ handlers (ISRs 32-47 after remapping)
    idt_set_gate(32, cast(uint)&isr32, 0x08, 0x8E); // IRQ0: Timer
    idt_set_gate(33, cast(uint)&isr33, 0x08, 0x8E); // IRQ1: Keyboard
    // idt_set_gate(40, cast(uint)&isr40, 0x08, 0x8E); // IRQ8: RTC (example)

    idt_load(cast(uint)&idt_ptr_struct);
    terminal_writestring("IDT Initialized & Loaded.\n");
}

// --- Interrupt Handling ---
struct Registers {
    uint ds; // Data segment selector pushed by isr_common_stub
    // Pushed by 'pusha' instruction (edi at lowest address, eax at highest for this block)
    uint edi, esi, ebp, esp_dummy, ebx, edx, ecx, eax; // Pushed by pusha
    uint err_code; // Pushed by specific ISR stubs (dummy or real error code)
    uint int_no;   // Pushed by specific ISR stubs (interrupt number)    
    // The following are pushed by the CPU automatically on interrupt/exception
    uint eip, cs, eflags, useresp, ss; // Pushed by the processor automatically
}

extern (C) void interrupt_handler_d(Registers* regs) {
    // Acknowledge interrupt early if it's a hardware IRQ from PIC
    // This must happen AFTER saving registers and setting up D environment if needed.
    if (regs.int_no >= 32 && regs.int_no <= 47) { // IRQs 0-15 remapped
        if (regs.int_no >= 40) { // If interrupt came from slave PIC (IRQ 8-15, remapped to 40-47)
            outb(PIC2_COMMAND, PIC_EOI);
        }
        outb(PIC1_COMMAND, PIC_EOI); // Always send to master for IRQs 0-15
    }

    // For debugging, print EIP to see where the interrupt occurred
    // terminal_writestring("EIP: ");
    // terminal_write_hex(regs.eip);
    // terminal_putchar(' ');

    terminal_writestring("Interrupt: ");
    terminal_write_hex(regs.int_no);

    // Check if the exception is one that pushes an error code.
    // Relevant for 32-bit: #DF(8), #TS(10), #NP(11), #SS(12), #GP(13), #PF(14), #AC(17).
    // Some of these (like #DF, #AC) push an error code of 0.
    bool has_cpu_error_code = (regs.int_no == 8 || (regs.int_no >= 10 && regs.int_no <= 14) || regs.int_no == 17);
    if (has_cpu_error_code) {
        terminal_writestring(", Error Code: ");
        terminal_write_hex(regs.err_code);
    }
    terminal_putchar('\n');

    // Handle keyboard interrupt (IRQ1, which is ISR 33 after remapping)
    if (regs.int_no == 33) {
        ubyte scancode = inb(0x60); // Read scancode from keyboard controller data port
        // Check for key press (MSB is 0 for press, 1 for release in Set 1)
        if (!(scancode & 0x80)) { // Key pressed
            char c = scancode_to_char[scancode];
            if (c != 0) {
                terminal_putchar(c);
            }
        }
    } else if (regs.int_no < 32 && regs.int_no != 1 && regs.int_no != 3) { // CPU Exception (excluding Debug and Breakpoint)
        // For specific faults, print more details if possible
        if (regs.int_no == 13) { // General Protection Fault
            terminal_writestring("General Protection Fault! Selector: ");
            terminal_write_hex(regs.err_code); // Error code is selector index
            terminal_putchar('\n');
        } else if (regs.int_no == 14) { // Page Fault
            terminal_writestring("Page Fault! Details: ");
            terminal_write_hex(regs.err_code); // Error code describes fault
            uint fault_addr;
            // Reading CR2 might only be safe if paging is actually on.
            // For now, let's assume it's okay to try.
            asm { "mov %%cr2, %0" : "=r"(fault_addr); }
            terminal_writestring(" Addr: ");
            terminal_write_hex(fault_addr);
            terminal_putchar('\n');
        }

        // Halt on most CPU exceptions, except for debug/breakpoint ones if you plan to use them.
        // NMI (2) is also special.
        if (regs.int_no != 2) { // Not NMI (already excluded Debug, Breakpoint)
            kernel_panic("CPU Exception Encountered.", cast(ErrorCode)regs.int_no); // Use kernel_panic
        }
    }
}

// Kernel's main entry point
extern (C) void kmain() {
    terminal_initialize();
    terminal_writestring("Terminal Initialized.\n");
    terminal_writestring("Attempting GDT init...\n");
    init_gdt();
    terminal_writestring("GDT Initialized.\n"); // Confirmation after init_gdt returns

    terminal_writestring("Attempting IDT init...\n");
    init_idt(); // This also remaps PICs and prints status.
    terminal_writestring("IDT Initialized. PICs remapped.\n"); // Confirmation

    // Test interrupt (e.g., INT 3 for breakpoint, if handler is safe)
    // asm { "int $3"; } 
    // terminal_writestring("INT 3 test done (if not panicked).\n");
    terminal_writestring("Kernel initialization complete.\n");
    terminal_writestring("Enabling interrupts. Type something:\n");

    // Scancode map is already initialized globally.

    asm { "sti"; } // Enable interrupts

    // Idle loop: halt until an interrupt occurs
    while (true) {
        asm { "hlt"; } // Halt until next interrupt
    }
    // This point should ideally not be reached if interrupts and HLT are working.
    // kernel_panic("Exited main HLT loop unexpectedly.", ErrorCode.UNKNOWN_FAILURE);
}