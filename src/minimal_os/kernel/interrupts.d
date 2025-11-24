module minimal_os.kernel.interrupts;

import minimal_os.console : printLine;
import minimal_os.posix : schedYield, schedulerTick;
import minimal_os.kernel.cpu : cpuCurrent;

@nogc nothrow:

private enum ushort PIC1_CMD = 0x20;
private enum ushort PIC1_DATA = 0x21;
private enum ushort PIC2_CMD = 0xA0;
private enum ushort PIC2_DATA = 0xA1;
private enum ushort PIT_CMD  = 0x43;
private enum ushort PIT_DATA = 0x40;

private enum ubyte ICW1_INIT = 0x10;
private enum ubyte ICW1_ICW4 = 0x01;
private enum ubyte ICW4_8086 = 0x01;

// Local APIC MSR and registers
private enum ulong  IA32_APIC_BASE_MSR = 0x1B;
private enum ulong  LAPIC_DEFAULT_BASE = 0xFEE00000;
private enum uint   LAPIC_SVR          = 0xF0;
private enum uint   LAPIC_TPR          = 0x80;
private enum uint   LAPIC_EOI          = 0xB0;

private enum ubyte IDT_TYPE_INTERRUPT = 0x8E; // present, DPL=0, type=14
private enum ushort KERNEL_CS = 0x08;

private struct IDTEntry
{
    ushort offsetLow;
    ushort selector;
    ubyte  ist;
    ubyte  typeAttr;
    ushort offsetMid;
    uint   offsetHigh;
    uint   zero;
}

private struct IDTPointer
{
    ushort limit;
    ulong  base;
}

private __gshared IDTEntry[256] g_idt;
private __gshared IDTPointer g_idtPtr;
private __gshared ulong g_tickCount;

private void outb(ushort port, ubyte value) @nogc nothrow
{
    asm @nogc nothrow
    {
        mov DX, port;
        mov AL, value;
        out DX, AL;
    }
}

private ubyte inb(ushort port) @nogc nothrow
{
    ubyte value;
    asm @nogc nothrow
    {
        mov DX, port;
        in  AL, DX;
        mov value, AL;
    }
    return value;
}

private void picRemap(ubyte offset1, ubyte offset2) @nogc nothrow
{
    const ubyte mask1 = inb(PIC1_DATA);
    const ubyte mask2 = inb(PIC2_DATA);

    outb(PIC1_CMD, cast(ubyte)(ICW1_INIT | ICW1_ICW4));
    outb(PIC2_CMD, cast(ubyte)(ICW1_INIT | ICW1_ICW4));

    outb(PIC1_DATA, offset1);
    outb(PIC2_DATA, offset2);

    outb(PIC1_DATA, 4); // tell master about slave at IRQ2
    outb(PIC2_DATA, 2); // tell slave its cascade identity

    outb(PIC1_DATA, ICW4_8086);
    outb(PIC2_DATA, ICW4_8086);

    // Unmask timer (IRQ0) and keyboard (IRQ1); mask others for now
    outb(PIC1_DATA, 0xFC);
    outb(PIC2_DATA, 0xFF);
}

private void setIdtEntry(ubyte vector, void* handler) @nogc nothrow
{
    const ulong addr = cast(ulong)handler;
    auto entry = &g_idt[vector];
    entry.offsetLow  = cast(ushort)(addr & 0xFFFF);
    entry.selector   = KERNEL_CS;
    entry.ist        = 0;
    entry.typeAttr   = IDT_TYPE_INTERRUPT;
    entry.offsetMid  = cast(ushort)((addr >> 16) & 0xFFFF);
    entry.offsetHigh = cast(uint)((addr >> 32) & 0xFFFF_FFFF);
    entry.zero       = 0;
}

extern(C) @nogc nothrow void timerIsrStub(); // defined in boot.s
extern(C) @nogc nothrow void keyboardIsrStub(); // defined in boot.s
extern(C) @nogc nothrow void pageFaultStub(); // defined in boot.s
extern(C) @nogc nothrow void interruptContextSwitch(ulong* oldSp, ulong newSp); // defined in boot.s

extern(C) @nogc nothrow void timerIsrHandler()
{
    ++g_tickCount;
    auto cpu = cpuCurrent();
    ++cpu.ticks;
    // Update scheduler accounting and preempt if slice expired
    if (schedulerTick())
    {
        schedYield();
    }
    // EOI to PIC
    outb(PIC1_CMD, 0x20);
    // EOI to LAPIC if present (identity-mapped)
    auto lapic = cast(uint*)(LAPIC_DEFAULT_BASE);
    lapic[LAPIC_EOI >> 2] = 0;
}

extern(C) @nogc nothrow void keyboardIsrHandler()
{
    // TODO: hook into keyboard queue once available
    outb(PIC1_CMD, 0x20);
    auto lapic = cast(uint*)(LAPIC_DEFAULT_BASE);
    lapic[LAPIC_EOI >> 2] = 0;
}

extern(C) @nogc nothrow void pageFaultHandler(void* /*frame*/)
{
    printLine("[irq] page fault");
    // Halt for now; proper handler would decode frame and faulting address.
    for (;;)
    {
        asm @nogc nothrow { hlt; }
    }
}

private void lidt(ref IDTPointer ptr) @nogc nothrow
{
    asm @nogc nothrow
    {
        // D inline asm cannot take ref directly; compute address manually
        "lidt (%0)"
        :
        : "r" (&ptr)
        : "memory";
    }
}

private ulong rdmsr(ulong msr) @nogc nothrow
{
    ulong value;
    asm @nogc nothrow
    {
        "rdmsr"
        : "=A" (value)
        : "c" (msr)
        : "memory";
    }
    return value;
}

private void wrmsr(ulong msr, ulong value) @nogc nothrow
{
    asm @nogc nothrow
    {
        "wrmsr"
        :
        : "c" (msr), "A" (value)
        : "memory";
    }
}

private void lapicInit() @nogc nothrow
{
    ulong apicBase = rdmsr(IA32_APIC_BASE_MSR);
    apicBase |= (1u << 11); // enable LAPIC
    wrmsr(IA32_APIC_BASE_MSR, apicBase);

    auto lapic = cast(uint*)(apicBase & ~0xFFF);

    // Set spurious interrupt vector and enable LAPIC (bit 8)
    lapic[LAPIC_SVR >> 2] = 0xFF | (1u << 8);
    // Accept all priorities
    lapic[LAPIC_TPR >> 2] = 0;
}

private void maskPic() @nogc nothrow
{
    outb(PIC1_DATA, 0xFF);
    outb(PIC2_DATA, 0xFF);
}

private void pitInit(uint freqHz) @nogc nothrow
{
    const uint divisor = 1193182 / freqHz;
    outb(PIT_CMD, 0x36); // channel 0, lo/hi, rate generator
    outb(PIT_DATA, cast(ubyte)(divisor & 0xFF));
    outb(PIT_DATA, cast(ubyte)((divisor >> 8) & 0xFF));
}

/// Install a minimal IDT with a PIT timer interrupt at vector 32.
public @nogc nothrow void initializeInterrupts()
{
    // Zero IDT
    foreach (ref entry; g_idt)
    {
        entry = IDTEntry.init;
    }

    setIdtEntry(32, &timerIsrStub);     // PIT timer
    setIdtEntry(33, &keyboardIsrStub);  // Keyboard
    setIdtEntry(14, &pageFaultStub);    // Page fault

    g_idtPtr.limit = cast(ushort)(g_idt.length * IDTEntry.sizeof - 1);
    g_idtPtr.base  = cast(ulong)(&g_idt[0]);

    lidt(g_idtPtr);

    picRemap(32, 40);
    pitInit(100);
    lapicInit();
    maskPic();

    asm @nogc nothrow { sti; }
    printLine("[irq] IDT loaded, PIT started at 100 Hz");
}

/// Interrupt-safe stack/context swap callable from an ISR path. Saves the
/// current stack pointer to `oldSpOut` and installs `newSp` before returning
/// to the caller.
extern(C) @nogc nothrow void arch_isr_context_switch(ulong* oldSpOut, ulong newSp)
{
    if (oldSpOut is null)
    {
        return;
    }
    interruptContextSwitch(oldSpOut, newSp);
}
