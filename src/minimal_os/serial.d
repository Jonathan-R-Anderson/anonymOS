module minimal_os.serial;

nothrow:
@nogc:

private enum ushort COM1_BASE = 0x3F8;

private enum ushort REG_DATA = 0;
private enum ushort REG_INTERRUPT_ENABLE = 1;
private enum ushort REG_FIFO_CONTROL = 2;
private enum ushort REG_LINE_CONTROL = 3;
private enum ushort REG_MODEM_CONTROL = 4;
private enum ushort REG_LINE_STATUS = 5;

private enum ubyte LSR_TRANSMIT_EMPTY = 0x20;

private __gshared bool serialReady = false;

extern(C) void initSerial()
{
    if (serialReady)
    {
        return;
    }

    setupPort();
    serialReady = true;
}

void serialWriteByte(ubyte value)
{
    if (!serialReady)
    {
        return;
    }

    while ((inb(COM1_BASE + REG_LINE_STATUS) & LSR_TRANSMIT_EMPTY) == 0) {}
    outb(COM1_BASE + REG_DATA, value);
}

void serialWriteString(const(char)[] text)
{
    if (text is null)
    {
        return;
    }

    foreach (c; text)
    {
        serialWriteByte(cast(ubyte)c);
    }
}

private void setupPort()
{
    outb(COM1_BASE + REG_INTERRUPT_ENABLE, 0x00);
    outb(COM1_BASE + REG_LINE_CONTROL, 0x80);
    outb(COM1_BASE + REG_DATA, 0x03);   // divisor low byte (38400 baud)
    outb(COM1_BASE + REG_INTERRUPT_ENABLE, 0x00); // divisor high byte
    outb(COM1_BASE + REG_LINE_CONTROL, 0x03);     // 8 bits, no parity, one stop
    outb(COM1_BASE + REG_FIFO_CONTROL, 0xC7);     // enable FIFO, clear, 14-byte threshold
    outb(COM1_BASE + REG_MODEM_CONTROL, 0x0B);    // IRQs disabled, RTS/DSR set
}

private void outb(ushort port, ubyte value)
{
    asm
    {
        mov DX, port;
        mov AL, value;
        out DX, AL;
    }
}

private ubyte inb(ushort port)
{
    ubyte value;
    asm
    {
        mov DX, port;
        in AL, DX;
        mov value, AL;
    }
    return value;
}
