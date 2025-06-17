// kernel/idt.d

module kernel.idt;

import kernel.terminal : terminal_writestring; // For debug printing
import kernel.interrupts : pic_remap; // For remapping PIC

public: // Export init_idt and related types/externs

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
align(1) IdtPtr idt_ptr_struct;

IdtEntry[256] idt_entries;

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

private void idt_set_gate(ubyte num, uint base, ushort sel, ubyte flags) {
    idt_entries[num].base_low = cast(ushort)(base & 0xFFFF);
    idt_entries[num].base_high = cast(ushort)((base >> 16) & 0xFFFF);
    idt_entries[num].selector = sel;
    idt_entries[num].zero = 0;
    idt_entries[num].type_attr = flags;
}

void init_idt() {
    idt_ptr_struct.limit = (IdtEntry.sizeof * 256) - 1;
    idt_ptr_struct.base  = cast(uint)&idt_entries[0];

    for (int i = 0; i < 256; i++) {
         idt_set_gate(cast(ubyte)i, cast(uint)&unhandled_interrupt, 0x08, 0x8E);
    }

    pic_remap(0x20, 0x28);

    idt_set_gate(0, cast(uint)&isr0, 0x08, 0x8E); idt_set_gate(1, cast(uint)&isr1, 0x08, 0x8E);
    idt_set_gate(2, cast(uint)&isr2, 0x08, 0x8E); idt_set_gate(3, cast(uint)&isr3, 0x08, 0x8E);
    idt_set_gate(4, cast(uint)&isr4, 0x08, 0x8E); idt_set_gate(5, cast(uint)&isr5, 0x08, 0x8E);
    idt_set_gate(6, cast(uint)&isr6, 0x08, 0x8E); idt_set_gate(7, cast(uint)&isr7, 0x08, 0x8E);
    idt_set_gate(8, cast(uint)&isr8, 0x08, 0x8E); idt_set_gate(9, cast(uint)&isr9, 0x08, 0x8E);
    idt_set_gate(10, cast(uint)&isr10, 0x08, 0x8E); idt_set_gate(11, cast(uint)&isr11, 0x08, 0x8E);
    idt_set_gate(12, cast(uint)&isr12, 0x08, 0x8E); idt_set_gate(13, cast(uint)&isr13, 0x08, 0x8E);
    idt_set_gate(14, cast(uint)&isr14, 0x08, 0x8E); idt_set_gate(15, cast(uint)&isr15, 0x08, 0x8E);
    idt_set_gate(16, cast(uint)&isr16, 0x08, 0x8E); idt_set_gate(17, cast(uint)&isr17, 0x08, 0x8E);
    idt_set_gate(18, cast(uint)&isr18, 0x08, 0x8E); idt_set_gate(19, cast(uint)&isr19, 0x08, 0x8E);
    idt_set_gate(20, cast(uint)&isr20, 0x08, 0x8E); idt_set_gate(21, cast(uint)&isr21, 0x08, 0x8E);
    idt_set_gate(22, cast(uint)&isr22, 0x08, 0x8E); idt_set_gate(23, cast(uint)&isr23, 0x08, 0x8E);
    idt_set_gate(24, cast(uint)&isr24, 0x08, 0x8E); idt_set_gate(25, cast(uint)&isr25, 0x08, 0x8E);
    idt_set_gate(26, cast(uint)&isr26, 0x08, 0x8E); idt_set_gate(27, cast(uint)&isr27, 0x08, 0x8E);
    idt_set_gate(28, cast(uint)&isr28, 0x08, 0x8E); idt_set_gate(29, cast(uint)&isr29, 0x08, 0x8E);
    idt_set_gate(30, cast(uint)&isr30, 0x08, 0x8E); idt_set_gate(31, cast(uint)&isr31, 0x08, 0x8E);

    idt_set_gate(32, cast(uint)&isr32, 0x08, 0x8E); // IRQ0: Timer
    idt_set_gate(33, cast(uint)&isr33, 0x08, 0x8E); // IRQ1: Keyboard

    idt_load(cast(uint)&idt_ptr_struct);
    terminal_writestring("IDT Initialized & Loaded.\n");
}