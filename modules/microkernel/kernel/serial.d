module kernel.serial;

pragma(LDC_no_moduleinfo);

import kernel.arch_interface.ports : inb, outb;

public:

enum SERIAL_PORT = 0x3F8; // COM1 base

extern(C) void serial_init()
{
    outb(SERIAL_PORT + 1, 0x00); // Disable all interrupts
    outb(SERIAL_PORT + 3, 0x80); // Enable DLAB
    outb(SERIAL_PORT + 0, 0x03); // Set baud divisor to 3 (38400 baud)
    outb(SERIAL_PORT + 1, 0x00); // High byte of divisor
    outb(SERIAL_PORT + 3, 0x03); // 8 bits, no parity, one stop bit
    outb(SERIAL_PORT + 2, 0xC7); // Enable FIFO, clear them, 14-byte threshold
    outb(SERIAL_PORT + 4, 0x0B); // IRQs enabled, RTS/DSR set
}

extern(C) void serial_putchar(char c)
{
    while ((inb(SERIAL_PORT + 5) & 0x20) == 0) {}
    outb(SERIAL_PORT, cast(ubyte)c);
}
