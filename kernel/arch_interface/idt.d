module kernel.idt;

// Assumed to be available from kernel.ports or similar
extern (C) {
    void idt_load(IDTPtr* idt_p); // Implemented in idt_loader.s
}

// Extern declaration for our keyboard IRQ handler
extern (C) void irq1_handler(); // Implemented in keyboard_handler_asm.s

// TODO: Declare other ISRs for exceptions (isr0-isr31) and other IRQs (irq0, irq2-irq15)
// extern (C) void isr0();
// extern (C) void irq0_handler(); // Timer

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

    // TODO: Zero out all IDT entries or set to a default handler
    // for (int i = 0; i < MAX_INTERRUPTS; i++) {
    //    idt_set_gate(i, &default_isr, 0x08, 0x8E);
    // }

    // --- Setup ISRs for CPU exceptions (0-31 decimal, 0x00-0x1F hex) ---
    // Example: idt_set_gate(0, &isr0, 0x08, 0x8E); // Divide by zero

    // --- Setup ISRs for Hardware IRQs (32-47 decimal, 0x20-0x2F hex after remapping) ---
    // IRQ 0 (Timer) -> Interrupt Vector 32 (0x20)
    // idt_set_gate(32, &irq0_handler, 0x08, 0x8E);

    // IRQ 1 (Keyboard) -> Interrupt 33 (0x21)
    // 0x08 is the kernel code segment selector
    // For 64-bit interrupt gate: P=1, DPL=0, Type=0xE (Interrupt Gate) -> 0x8E
    idt_set_gate(33, &irq1_handler, 0x08, 0x8E); // 0x8E is still valid for 64-bit interrupt gate

    // Load the IDT
    idt_load(&idt_ptr);
}