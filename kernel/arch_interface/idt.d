module kernel.arch_interface.idt;

// Assumed to be available from kernel.ports or similar
extern (C) {
    void idt_load(IDTPtr* idt_p); // Implemented in idt_loader.s
}

// Extern declaration for our keyboard IRQ handler
extern (C) void irq1_handler(); // Implemented in keyboard_handler_asm.s

extern (C) void isr0();
extern (C) void isr1();
extern (C) void isr2();
extern (C) void isr3();
extern (C) void isr4();
extern (C) void isr5();
extern (C) void isr6();
extern (C) void isr7();
extern (C) void isr8();
extern (C) void isr9();
extern (C) void isr10();
extern (C) void isr11();
extern (C) void isr12();
extern (C) void isr13();
extern (C) void isr14();
extern (C) void isr15();
extern (C) void isr16();
extern (C) void isr17();
extern (C) void isr18();
extern (C) void isr19();
extern (C) void isr20();
extern (C) void isr21();
extern (C) void isr22();
extern (C) void isr23();
extern (C) void isr24();
extern (C) void isr25();
extern (C) void isr26();
extern (C) void isr27();
extern (C) void isr28();
extern (C) void isr29();
extern (C) void isr30();
extern (C) void isr31();
extern (C) void isr32();
extern (C) void default_isr();

// 64-bit IDT Entry (Interrupt Gate or Trap Gate). Size is 16 bytes.
align(1)
struct IDTEntry {
    ushort offset_1;        // Offset bits 0-15
    ushort selector;        // Code segment selector in GDT or LDT
    ubyte  ist;             // Interrupt Stack Table offset (0-7), bits 0-2. Bits 3-7 are 0.
    ubyte  type_attributes; // Gate type, DPL, P flag
    ushort offset_2;        // Offset bits 16-31
    uint   offset_3;        // Offset bits 32-63
    uint   reserved;        // Must be zero
}

// IDT Pointer Structure (for lidt instruction)
align(1)
struct IDTPtr {
    ushort limit;
    ulong  base; // 64-bit base address
}

enum MAX_INTERRUPTS = 256;
__gshared IDTEntry[MAX_INTERRUPTS] idt_entries; // The actual IDT
__gshared IDTPtr idt_ptr;

// Define an alias for the C-style function pointer type used for interrupt handlers
alias CInterruptHandler = extern (C) void function();

void idt_set_gate(ubyte num, CInterruptHandler fp, ushort sel, ubyte flags) {
    ulong base = cast(ulong)fp; // Get the 64-bit address of the function

    idt_entries[num].offset_1 = cast(ushort)(base & 0xFFFF);
    idt_entries[num].selector = sel;
    idt_entries[num].ist = 0; // IST = 0 for now
    idt_entries[num].type_attributes = flags; // e.g., 0x8E for 64-bit Interrupt Gate (P=1, DPL=0, Type=0xE)
    idt_entries[num].offset_2 = cast(ushort)((base >> 16) & 0xFFFF);
    idt_entries[num].offset_3 = cast(uint)((base >> 32) & 0xFFFFFFFF);
    idt_entries[num].reserved = 0;
}

public: // Export init_idt
void init_idt() {
    idt_ptr.limit = (MAX_INTERRUPTS * IDTEntry.sizeof) - 1;
    idt_ptr.base  = cast(ulong)&idt_entries[0];

    // Initialize all IDT entries with a safe default handler
    for (int i = 0; i < MAX_INTERRUPTS; i++) {
        idt_set_gate(cast(ubyte)i, &default_isr, 0x08, 0x8E);
    }

    // --- Setup ISRs for CPU exceptions (0-31 decimal, 0x00-0x1F hex) ---
    idt_set_gate(0,  &isr0,  0x08, 0x8E);
    idt_set_gate(1,  &isr1,  0x08, 0x8E);
    idt_set_gate(2,  &isr2,  0x08, 0x8E);
    idt_set_gate(3,  &isr3,  0x08, 0x8E);
    idt_set_gate(4,  &isr4,  0x08, 0x8E);
    idt_set_gate(5,  &isr5,  0x08, 0x8E);
    idt_set_gate(6,  &isr6,  0x08, 0x8E);
    idt_set_gate(7,  &isr7,  0x08, 0x8E);
    idt_set_gate(8,  &isr8,  0x08, 0x8E);
    idt_set_gate(9,  &isr9,  0x08, 0x8E);
    idt_set_gate(10, &isr10, 0x08, 0x8E);
    idt_set_gate(11, &isr11, 0x08, 0x8E);
    idt_set_gate(12, &isr12, 0x08, 0x8E);
    idt_set_gate(13, &isr13, 0x08, 0x8E);
    idt_set_gate(14, &isr14, 0x08, 0x8E);
    idt_set_gate(15, &isr15, 0x08, 0x8E);
    idt_set_gate(16, &isr16, 0x08, 0x8E);
    idt_set_gate(17, &isr17, 0x08, 0x8E);
    idt_set_gate(18, &isr18, 0x08, 0x8E);
    idt_set_gate(19, &isr19, 0x08, 0x8E);
    idt_set_gate(20, &isr20, 0x08, 0x8E);
    idt_set_gate(21, &isr21, 0x08, 0x8E);
    idt_set_gate(22, &isr22, 0x08, 0x8E);
    idt_set_gate(23, &isr23, 0x08, 0x8E);
    idt_set_gate(24, &isr24, 0x08, 0x8E);
    idt_set_gate(25, &isr25, 0x08, 0x8E);
    idt_set_gate(26, &isr26, 0x08, 0x8E);
    idt_set_gate(27, &isr27, 0x08, 0x8E);
    idt_set_gate(28, &isr28, 0x08, 0x8E);
    idt_set_gate(29, &isr29, 0x08, 0x8E);
    idt_set_gate(30, &isr30, 0x08, 0x8E);
    idt_set_gate(31, &isr31, 0x08, 0x8E);
    // --- Setup ISRs for Hardware IRQs (32-47 decimal, 0x20-0x2F hex after remapping) ---
    // IRQ 0 (Timer) -> Interrupt Vector 32 (0x20)
    idt_set_gate(32, &isr32, 0x08, 0x8E);

    // IRQ 1 (Keyboard) -> Interrupt 33 (0x21)
    // 0x08 is the kernel code segment selector
    // For 64-bit interrupt gate: P=1, DPL=0, Type=0xE (Interrupt Gate) -> 0x8E
    idt_set_gate(33, &irq1_handler, 0x08, 0x8E); // 0x8E is still valid for 64-bit interrupt gate

    // Load the IDT
    idt_load(&idt_ptr);
}
