module minimal_os.kernel.interrupts;

import minimal_os.console : print, printLine, printHex, printUnsigned;
import minimal_os.posix : schedYield, schedulerTick;
import minimal_os.kernel.cpu : cpuCurrent;
import minimal_os.drivers.usb_hid : ps2IsrEnqueue;

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
public enum ubyte PIC1_DEFAULT_MASK = 0xF8; // unmask IRQ0/1/2
public enum ubyte PIC2_DEFAULT_MASK = 0xEF; // unmask IRQ12 (mouse), mask others

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
    align(1):
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

    // Unmask timer/keyboard/cascade and mouse; leave others masked.
    outb(PIC1_DATA, PIC1_DEFAULT_MASK);
    outb(PIC2_DATA, PIC2_DEFAULT_MASK);
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
extern(C) @nogc nothrow void mouseIsrStub(); // defined in boot.s
extern(C) @nogc nothrow void doubleFaultStub(); // defined in boot.s
extern(C) @nogc nothrow void pageFaultStub(); // defined in boot.s
extern(C) @nogc nothrow void interruptContextSwitch(ulong* oldSp, ulong newSp); // defined in boot.s

extern(C) @nogc nothrow void timerIsrHandler()
{
    ++g_tickCount;
    auto cpu = cpuCurrent();
    ++cpu.ticks;
    // EOI to PIC
    outb(PIC1_CMD, 0x20);
    // Update scheduler accounting and preempt if slice expired
    if (schedulerTick())
    {
        schedYield();
    }
}

extern(C) @nogc nothrow void keyboardIsrHandler()
{
    const ubyte status = inb(0x64);
    const ubyte data = inb(0x60);
    ps2IsrEnqueue(status, data);
    static uint kseen;
    ++kseen;
    if (kseen <= 4 || (kseen & 0xFF) == 0)
    {
        print("[ps2-irq] kbd status=");
        printHex(status);
        print(" data=");
        printHex(data);
        print(" count=");
        printUnsigned(kseen);
        printLine("");
    }
    outb(PIC1_CMD, 0x20);
}

extern(C) @nogc nothrow void mouseIsrHandler()
{
    ubyte status = inb(0x64);
    const ubyte data = inb(0x60);
    // Some controllers may not set the mouse bit; force it so the handler
    // routes bytes correctly.
    status |= 0x20;
    ps2IsrEnqueue(status, data);
    static uint mseen;
    ++mseen;
    if (mseen <= 8 || (mseen & 0xFF) == 0)
    {
        print("[ps2-irq] mouse status=");
        printHex(status);
        print(" data=");
        printHex(data);
        print(" count=");
        printUnsigned(mseen);
        printLine("");
    }
    outb(PIC2_CMD, 0x20);
    outb(PIC1_CMD, 0x20);
}

extern(C) @nogc nothrow void doubleFaultHandler()
{
    printLine("[irq] double fault");
    for (;;)
    {
        asm @nogc nothrow { hlt; }
    }
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
    setIdtEntry(44, &mouseIsrStub);     // PS/2 mouse (IRQ12) masked for now
    setIdtEntry(8,  &doubleFaultStub);  // Double fault
    setIdtEntry(14, &pageFaultStub);    // Page fault

    g_idtPtr.limit = cast(ushort)(g_idt.length * IDTEntry.sizeof - 1);
    g_idtPtr.base  = cast(ulong)(&g_idt[0]);

    lidt(g_idtPtr);

    picRemap(32, 40);
    pitInit(100);
    // lapicInit(); // Disable LAPIC to avoid QEMU "Invalid read" errors and ensure PIC routing
    // Do not enable interrupts here; let the caller enable them after the
    // scheduler and kernel stacks are fully initialised.
    printLine("[irq] IDT loaded, PIT configured (PIC unmasked; IRQs still masked by IF)");
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
