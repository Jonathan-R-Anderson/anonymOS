module kernel.arch_interface.idt;

import kernel.arch_interface.gdt : KERNEL_CODE_SELECTOR;
import kernel.terminal : terminal_writestring;

extern (C) void idt_load(IDTPtr* idt_p);         // from idt_loader.s
extern (C) void irq1_handler();                  // from keyboard_handler_asm.s

// Exception handlers
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

// 64-bit IDT entry (16 bytes)
align(1)
struct IDTEntry {
    ushort offset_low;
    ushort selector;
    ubyte  ist;
    ubyte  type_attr;
    ushort offset_mid;
    uint   offset_high;
    uint   zero;
}

// IDT pointer structure (for lidt)
align(1)
struct IDTPtr {
    ushort limit;
    ulong base;
}

enum MAX_INTERRUPTS = 256;
align(16) __gshared IDTEntry[MAX_INTERRUPTS] idt_entries;
__gshared IDTPtr idt_ptr;

// C-compatible interrupt handler pointer type
alias CInterruptHandler = extern (C) void function();

void idt_set_gate(ubyte num, CInterruptHandler fp, ushort sel, ubyte flags) {
    ulong base = cast(ulong)fp;
    idt_entries[num].offset_low  = cast(ushort)(base & 0xFFFF);
    idt_entries[num].selector    = sel;
    idt_entries[num].ist         = 0;
    idt_entries[num].type_attr   = flags;
    idt_entries[num].offset_mid  = cast(ushort)((base >> 16) & 0xFFFF);
    idt_entries[num].offset_high = cast(uint)((base >> 32) & 0xFFFFFFFF);
    idt_entries[num].zero        = 0;
}

void set_idt_entry(size_t vec, void* handler, ubyte ist = 0, ubyte type_attr = 0x8E) {
    auto offset = cast(ulong)handler;
    idt_entries[vec].offset_low  = cast(ushort)(offset & 0xFFFF);
    idt_entries[vec].selector    = KERNEL_CODE_SELECTOR;
    idt_entries[vec].ist         = ist & 0x07;
    idt_entries[vec].type_attr   = type_attr;
    idt_entries[vec].offset_mid  = cast(ushort)((offset >> 16) & 0xFFFF);
    idt_entries[vec].offset_high = cast(uint)((offset >> 32) & 0xFFFFFFFF);
    idt_entries[vec].zero        = 0;
}

public void init_idt() {
    terminal_writestring("Initializing IDT...\n");

    foreach (i; 0 .. MAX_INTERRUPTS)
        set_idt_entry(i, &default_isr);

    // Special handlers
    set_idt_entry(0x08, &isr8, 1);     // IST1
    set_idt_entry(0x0D, &isr13);  // #GP
    set_idt_entry(0x0E, &isr14);          // #PF

    idt_ptr.limit = cast(ushort)(MAX_INTERRUPTS * IDTEntry.sizeof - 1);
    idt_ptr.base  = cast(ulong)&idt_entries[0];

    idt_load(&idt_ptr);

    terminal_writestring("IDT loaded.\n");
}
