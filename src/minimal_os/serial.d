module minimal_os.serial;

private enum ushort COM1_BASE = 0x3F8;

private enum ushort REG_DATA             = 0;
private enum ushort REG_INTERRUPT_ENABLE = 1;
private enum ushort REG_FIFO_CONTROL     = 2;
private enum ushort REG_LINE_CONTROL     = 3;
private enum ushort REG_MODEM_CONTROL    = 4;
private enum ushort REG_LINE_STATUS      = 5;

private enum ubyte LSR_TRANSMIT_EMPTY = 0x20;
private enum ubyte LSR_DATA_READY     = 0x01;

private __gshared bool serialReady = false;

extern(C) @nogc nothrow
void initSerial()
{
    if (serialReady)
    {
        return;
    }

    setupPort();
    serialReady = true;
}

@nogc nothrow
void serialWriteByte(ubyte value)
{
    if (!serialReady)
    {
        return;
    }

    while ((inb(COM1_BASE + REG_LINE_STATUS) & LSR_TRANSMIT_EMPTY) == 0) {}
    outb(COM1_BASE + REG_DATA, value);
}

@nogc nothrow
char serialReadByteBlocking()
{
    if (!serialReady)
    {
        return '\0';
    }

    while ((inb(COM1_BASE + REG_LINE_STATUS) & LSR_DATA_READY) == 0) {}
    return cast(char)inb(COM1_BASE + REG_DATA);
}

@nogc nothrow
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

@nogc nothrow bool serialConsoleReady()
{
    return serialReady;
}

/// Non-blocking serial read - returns 0 if no data available
@nogc nothrow
char serialReadByteNonBlocking()
{
    if (!serialReady)
    {
        return '\0';
    }
    
    // Check if data is ready
    if ((inb(COM1_BASE + REG_LINE_STATUS) & LSR_DATA_READY) == 0)
    {
        return '\0';  // No data available
    }
    
    return cast(char)inb(COM1_BASE + REG_DATA);
}

/// Poll serial port and generate keyboard events from input
@nogc nothrow
void pollSerialInput(InputQueue)(ref InputQueue queue)
{
    import minimal_os.display.input_pipeline : InputEvent, enqueue;
    
    if (!serialReady)
    {
        return;
    }
    
    // Read up to 16 characters per poll to avoid blocking too long
    foreach (i; 0 .. 16)
    {
        char c = serialReadByteNonBlocking();
        if (c == '\0')
        {
            break;  // No more data
        }
        
        // Generate keyboard event for this character
        InputEvent event;
        event.type = InputEvent.Type.keyDown;
        event.data1 = cast(int)c;
        event.data2 = 0;  // No scancode for serial input
        event.data3 = 0;  // No modifiers
        enqueue(queue, event);
        
        // Immediately generate key-up event (serial doesn't have key state)
        event.type = InputEvent.Type.keyUp;
        enqueue(queue, event);
    }
}


@nogc nothrow
private void setupPort()
{
    outb(COM1_BASE + REG_INTERRUPT_ENABLE, 0x00);
    outb(COM1_BASE + REG_LINE_CONTROL,     0x80);
    outb(COM1_BASE + REG_DATA,             0x03); // divisor low byte (38400 baud)
    outb(COM1_BASE + REG_INTERRUPT_ENABLE, 0x00); // divisor high byte
    outb(COM1_BASE + REG_LINE_CONTROL,     0x03); // 8 bits, no parity, one stop
    outb(COM1_BASE + REG_FIFO_CONTROL,     0xC7); // enable FIFO, clear, 14-byte threshold
    outb(COM1_BASE + REG_MODEM_CONTROL,    0x0B); // IRQs disabled, RTS/DSR set
}

@nogc nothrow
private void outb(ushort port, ubyte value)
{
    asm @nogc nothrow
    {
        mov DX, port;
        mov AL, value;
        out DX, AL;
    }
}

@nogc nothrow
private ubyte inb(ushort port)
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
