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

align(1)
struct IDTEntry {
    ushort base_lo;    // Lower 16 bits of handler function address
    ushort sel;        // Kernel segment selector (e.g., 0x08)
    ubyte  always0;    // This must always be zero
    ubyte  flags;      // Type and attributes (e.g., 0x8E for 32-bit interrupt gate)
    ushort base_hi;    // Upper 16 bits of handler function address
}

align(1)
struct IDTPtr {
    ushort limit;
    uint   base;
}

enum MAX_INTERRUPTS = 256;
__gshared IDTEntry[MAX_INTERRUPTS] idt_entries; // The actual IDT
__gshared IDTPtr idt_ptr;

// Define an alias for the C-style function pointer type used for interrupt handlers
alias CInterruptHandler = extern (C) void function();

void idt_set_gate(ubyte num, CInterruptHandler fp, ushort sel, ubyte flags) {
    uint base = cast(uint)fp; // Get the address of the function
    idt_entries[num].base_lo = cast(ushort)(base & 0xFFFF);
    idt_entries[num].base_hi = cast(ushort)((base >> 16) & 0xFFFF);
    idt_entries[num].sel     = sel;
    idt_entries[num].always0 = 0;
    idt_entries[num].flags   = flags;
}

public: // Export init_idt
void init_idt() {
    idt_ptr.limit = (MAX_INTERRUPTS * IDTEntry.sizeof) - 1;
    idt_ptr.base  = cast(uint)&idt_entries[0];

    // TODO: Zero out all IDT entries or set to a default handler
    // for (int i = 0; i < MAX_INTERRUPTS; i++) {
    //    idt_set_gate(i, &default_isr, 0x08, 0x8E);
    // }

    // --- Setup ISRs for CPU exceptions (0-31 decimal, 0x00-0x1F hex) ---
    // Example: idt_set_gate(0, &isr0, 0x08, 0x8E); // Divide by zero

    // --- Setup ISRs for Hardware IRQs (32-47 decimal, 0x20-0x2F hex after remapping) ---
    // IRQ 0 (Timer) -> Interrupt 32 (0x20)
    // idt_set_gate(32, &irq0_handler, 0x08, 0x8E);

    // IRQ 1 (Keyboard) -> Interrupt 33 (0x21)
    // 0x08 is the kernel code segment selector
    // 0x8E means: Present=1, DPL=0 (ring 0), Type=0xE (32-bit interrupt gate)
    idt_set_gate(33, &irq1_handler, 0x08, 0x8E);

    // Load the IDT
    idt_load(&idt_ptr);
}