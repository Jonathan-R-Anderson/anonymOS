module kernel.arch_interface.idt;

import kernel.arch_interface.gdt : KERNEL_CODE_SELECTOR;
import kernel.terminal : terminal_writestring;
import kernel.logger : log_message, log_hex;

import kernel.arch_interface.ports;


extern (C) void idt_load(IDTPtr* idt_p);         // from idt_loader.s
extern (C) void irq1_handler();                  // from keyboard_handler_asm.s
extern (C) void syscall_stub_asm();


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
// Similar to `GdtPtr` in gdt.d we use an explicit union for the base
// address to avoid any padding that could otherwise be introduced by
// the compiler.  Packing to byte alignment ensures the resulting
// structure is exactly ten bytes as required by the `lidt` instruction.
align(1) struct IDTPtr {
    ushort limit;
    align(1) union {
        ulong base; // canonical 64-bit pointer
        struct {
            uint base_low;  // low 32 bits
            uint base_high; // high 32 bits
        }
    }
}
pragma(msg, "IDTPtr.sizeof = ", IDTPtr.sizeof);
static assert(IDTPtr.sizeof == 10, "IDTPtr must be 10 bytes to match lidt encoding");

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

extern (C) void isr_general_protection(); // You must provide this in asm or D

void set_idt_entry(int vec, void* handler, ushort selector = 0x08) {
    auto entry = &idt_entries[vec];
    auto addr = cast(size_t)handler;
    entry.offset_low = cast(ushort)(addr & 0xFFFF);
    entry.selector = selector;
    entry.ist = 0;
    entry.type_attr = 0x8E;
    entry.offset_mid = cast(ushort)((addr >> 16) & 0xFFFF);
    entry.offset_high = cast(uint)((addr >> 32) & 0xFFFFFFFF);
    entry.zero = 0;
}

void remap_pic() {
    // Start PIC initialization
    outb(0x20, 0x11); // Master: ICW1
    outb(0xA0, 0x11); // Slave: ICW1

    // Set vector offset
    outb(0x21, 0x20); // Master: IRQ0 -> 0x20
    outb(0xA1, 0x28); // Slave: IRQ8 -> 0x28

    // Setup cascading
    outb(0x21, 0x04); // Master: slave at IRQ2
    outb(0xA1, 0x02); // Slave: identity

    // 8086 mode
    outb(0x21, 0x01);
    outb(0xA1, 0x01);

    // Mask all IRQs for now
    outb(0x21, 0xFF);
    outb(0xA1, 0xFF);
}

public void init_idt() {

    terminal_writestring("Calling remap_pic()\n");

    remap_pic();

    foreach (i; 0 .. MAX_INTERRUPTS)
        set_idt_entry(i, &default_isr);

    // Hardware IRQs
    set_idt_entry(0x20, &isr32);       // IRQ0: Timer
    set_idt_entry(0x21, &irq1_handler); // IRQ1: Keyboard

    // Special handlers
    set_idt_entry(0x08, &isr8, 1);     // IST1
    set_idt_entry(0x0D, &isr13);  // #GP
    set_idt_entry(0x0E, &isr14);          // #PF
    set_idt_entry(0x80, &syscall_stub_asm);
    terminal_writestring("Initializing IDT...\n");

    idt_ptr.limit = cast(ushort)(MAX_INTERRUPTS * IDTEntry.sizeof - 1);
    idt_ptr.base  = cast(ulong)&idt_entries[0];
    // Ensure the pointer is canonical (upper bits cleared)
    idt_ptr.base &= 0x0000FFFF_FFFF_FFFFUL;

    log_message("IDTPtr.sizeof=");
    log_hex(IDTPtr.sizeof);
    log_message("\n&idt_ptr=");
    log_hex(cast(ulong)&idt_ptr);
    log_message("\nidt_ptr.base=");
    log_hex(idt_ptr.base);
    log_message(" limit=");
    log_hex(idt_ptr.limit);
    log_message("\n");

    idt_load(&idt_ptr);

    log_message("IDT base loaded: ");
    log_hex(idt_ptr.base);
    log_message("\n");
    terminal_writestring("IDT loaded.\n");
}
