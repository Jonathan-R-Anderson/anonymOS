module minimal_os.main;

private enum VGA_WIDTH = 80;
private enum VGA_HEIGHT = 25;
private enum DEFAULT_COLOUR = 0x0F;

private __gshared ushort* vgaBuffer = cast(ushort*)0xB8000;
private __gshared size_t cursorRow = 0;
private __gshared size_t cursorCol = 0;

private immutable char[128] scancodeMap = [
    0x01: '\x1B', // escape
    0x02: '1',
    0x03: '2',
    0x04: '3',
    0x05: '4',
    0x06: '5',
    0x07: '6',
    0x08: '7',
    0x09: '8',
    0x0A: '9',
    0x0B: '0',
    0x0C: '-',
    0x0D: '=',
    0x0E: '\b',
    0x0F: '\t',
    0x10: 'q',
    0x11: 'w',
    0x12: 'e',
    0x13: 'r',
    0x14: 't',
    0x15: 'y',
    0x16: 'u',
    0x17: 'i',
    0x18: 'o',
    0x19: 'p',
    0x1A: '[',
    0x1B: ']',
    0x1C: '\n',
    0x1E: 'a',
    0x1F: 's',
    0x20: 'd',
    0x21: 'f',
    0x22: 'g',
    0x23: 'h',
    0x24: 'j',
    0x25: 'k',
    0x26: 'l',
    0x27: ';',
    0x28: '\'',
    0x29: '`',
    0x2B: '\\',
    0x2C: 'z',
    0x2D: 'x',
    0x2E: 'c',
    0x2F: 'v',
    0x30: 'b',
    0x31: 'n',
    0x32: 'm',
    0x33: ',',
    0x34: '.',
    0x35: '/',
    0x39: ' ',
];

extern(C):
nothrow:
@nogc:

private ubyte inb(ushort port)
{
    ubyte value;
    asm @nogc nothrow
    {
        mov DX, port;
        in AL, DX;
        mov value, AL;
    }
    return value;
}

private void clearScreen()
{
    const size_t total = VGA_WIDTH * VGA_HEIGHT;
    for (size_t i = 0; i < total; ++i)
    {
        vgaBuffer[i] = cast(ushort)' ' | (cast(ushort)DEFAULT_COLOUR << 8);
    }
    cursorRow = 0;
    cursorCol = 0;
}

private void scroll()
{
    const size_t rowSize = VGA_WIDTH;
    const size_t total = VGA_WIDTH * VGA_HEIGHT;

    for (size_t i = 0; i < total - rowSize; ++i)
    {
        vgaBuffer[i] = vgaBuffer[i + rowSize];
    }

    for (size_t i = total - rowSize; i < total; ++i)
    {
        vgaBuffer[i] = cast(ushort)' ' | (cast(ushort)DEFAULT_COLOUR << 8);
    }

    cursorRow = VGA_HEIGHT - 1;
    cursorCol = 0;
}

private void newline()
{
    cursorCol = 0;
    if (cursorRow + 1 >= VGA_HEIGHT)
    {
        scroll();
    }
    else
    {
        ++cursorRow;
    }
}

private void putChar(char c)
{
    if (c == '\n')
    {
        newline();
        return;
    }

    if (cursorCol >= VGA_WIDTH)
    {
        newline();
    }

    const size_t index = cursorRow * VGA_WIDTH + cursorCol;
    vgaBuffer[index] = cast(ushort)c | (cast(ushort)DEFAULT_COLOUR << 8);
    ++cursorCol;

    if (cursorCol >= VGA_WIDTH)
    {
        newline();
    }
}

private void backspace()
{
    if (cursorCol == 0)
    {
        if (cursorRow == 0)
        {
            return;
        }

        cursorCol = VGA_WIDTH;
        --cursorRow;
    }

    --cursorCol;
    const size_t index = cursorRow * VGA_WIDTH + cursorCol;
    vgaBuffer[index] = cast(ushort)' ' | (cast(ushort)DEFAULT_COLOUR << 8);
}

private void print(const(char)[] text)
{
    foreach (immutable c; text)
    {
        putChar(c);
    }
}

private void printLine(const(char)[] text)
{
    print(text);
    putChar('\n');
}

private char readKey()
{
    for (;;) // wait for a key press and translate to ASCII
    {
        while ((inb(0x64) & 0x01) == 0) {}

        const ubyte scancode = inb(0x60);

        if ((scancode & 0x80) != 0)
        {
            continue; // ignore key releases
        }

        if (scancode >= scancodeMap.length)
        {
            continue;
        }

        const char mapped = scancodeMap[scancode];
        if (mapped != '\0')
        {
            return mapped;
        }
    }
}

private bool matchesCommand(ref char[128] buffer, size_t length, immutable(char)[] command)
{
    if (length != command.length)
    {
        return false;
    }

    for (size_t i = 0; i < length; ++i)
    {
        if (buffer[i] != command[i])
        {
            return false;
        }
    }

    return true;
}

private void invokeCrossCompiler(ref char[128] args, size_t length)
{
    printLine("[shell] Invoking cross-compiler...");
    if (length > 0)
    {
        print("[shell] Arguments: ");
        for (size_t i = 0; i < length; ++i)
        {
            putChar(args[i]);
        }
        putChar('\n');
    }
    printLine("[shell] Cross-compiler call complete (stub).");
}

private void handleCommand(ref char[128] buffer, size_t length)
{
    size_t start = 0;
    while (start < length && buffer[start] == ' ')
    {
        ++start;
    }

    size_t end = length;
    while (end > start && buffer[end - 1] == ' ')
    {
        --end;
    }

    length = end - start;

    if (length == 0)
    {
        return;
    }

    // shift the trimmed command to the beginning of the buffer for reuse
    if (start != 0 && length != 0)
    {
        for (size_t i = 0; i < length; ++i)
        {
            buffer[i] = buffer[start + i];
        }
    }

    if (matchesCommand(buffer, length, "help"))
    {
        printLine("Available commands:");
        printLine("  help  - Show this help message.");
        printLine("  clear - Clear the screen.");
        printLine("  cross [args] - Invoke the cross-compiler stub.");
        return;
    }

    if (matchesCommand(buffer, length, "clear"))
    {
        clearScreen();
        return;
    }

    immutable crossLiteral = "cross";
    if (length >= crossLiteral.length && matchesCommand(buffer, crossLiteral.length, crossLiteral))
    {
        size_t argStart = crossLiteral.length;
        while (argStart < length && buffer[argStart] == ' ')
        {
            ++argStart;
        }

        size_t argLength = (argStart < length) ? (length - argStart) : 0;

        if (argLength != 0 && argStart != 0)
        {
            for (size_t i = 0; i < argLength; ++i)
            {
                buffer[i] = buffer[argStart + i];
            }
        }

        invokeCrossCompiler(buffer, argLength);
        return;
    }

    print("Unknown command: ");
    for (size_t i = 0; i < length; ++i)
    {
        putChar(buffer[i]);
    }
    putChar('\n');
}

private void runShell()
{
    char[128] buffer;
    size_t length = 0;

    printLine("Simple kernel shell ready.");
    printLine("Type 'help' for a list of commands.");
    print("> ");

    for (;;) // REPL loop
    {
        const char key = readKey();

        if (key == '\n')
        {
            putChar('\n');
            handleCommand(buffer, length);
            length = 0;
            print("> ");
            continue;
        }

        if (key == '\b')
        {
            if (length != 0)
            {
                --length;
                backspace();
            }
            continue;
        }

        if (length < buffer.length)
        {
            buffer[length] = key;
            ++length;
            putChar(key);
        }
    }
}

/// Entry point invoked from boot.s once the CPU is ready to run D code.
/// Initialises the VGA output and starts the interactive shell.
void kmain(ulong magic, ulong info)
{
    cast(void) magic;
    cast(void) info;

    clearScreen();
    runShell();
}
