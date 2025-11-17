module minimal_os.console;

import minimal_os.serial : serialWriteByte, serialConsoleReady, serialReadByteBlocking;

nothrow:
@nogc:

private enum VGA_WIDTH = 80;
private enum VGA_HEIGHT = 25;
private enum DEFAULT_COLOUR = 0x0F;

private __gshared ushort* vgaBuffer = cast(ushort*)0xB8000;
private __gshared size_t cursorRow = 0;
private __gshared size_t cursorCol = 0;
private __gshared bool   g_consoleReady = false;

struct StageSummary
{
    immutable(char)[] title;
    size_t moduleCount;
    size_t statusCount;
    size_t exportCount;
}

private __gshared StageSummary[16] stageSummaries;
private __gshared size_t stageSummaryCount = 0;
private __gshared StageSummary* activeStage = null;

void resetStageSummaries()
{
    stageSummaryCount = 0;
    activeStage = null;
}

void clearActiveStage()
{
    activeStage = null;
}

const(StageSummary)[] stageSummaryData()
{
    return stageSummaries[0 .. stageSummaryCount];
}

void clearScreen()
{
    const size_t total = VGA_WIDTH * VGA_HEIGHT;
    for (size_t i = 0; i < total; ++i)
    {
        vgaBuffer[i] = cast(ushort)' ' | (cast(ushort)DEFAULT_COLOUR << 8);
    }
    cursorRow = 0;
    cursorCol = 0;
    g_consoleReady = true;
}

void scroll()
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

void newline()
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

void putChar(char c)
{
    if (c == '\n')
    {
        newline();
        mirrorToSerial('\n');
        return;
    }

    if (cursorCol >= VGA_WIDTH)
    {
        newline();
    }

    const size_t index = cursorRow * VGA_WIDTH + cursorCol;
    vgaBuffer[index] = cast(ushort)c | (cast(ushort)DEFAULT_COLOUR << 8);
    ++cursorCol;

    mirrorToSerial(c);

    if (cursorCol >= VGA_WIDTH)
    {
        newline();
    }
}

@nogc nothrow bool kernelConsoleReady()
{
    return g_consoleReady;
}

private void mirrorToSerial(char c)
{
    if (c == '\n')
    {
        serialWriteByte('\r');
        serialWriteByte('\n');
        return;
    }

    serialWriteByte(cast(ubyte)c);
}

void backspace()
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

void print(const(char)[] text)
{
    if (text is null)
    {
        return;
    }

    for (size_t index = 0; index < text.length; ++index)
    {
        putChar(text[index]);
    }
}

void printCString(const(char)* text)
{
    if (text is null)
    {
        return;
    }

    size_t index = 0;
    while (text[index] != '\0')
    {
        putChar(text[index]);
        ++index;
    }
}

void printUnsigned(size_t value)
{
    char[20] buffer;
    size_t length = 0;

    do
    {
        buffer[length] = cast(char)('0' + (value % 10));
        ++length;
        value /= 10;
    }
    while (value != 0);

    while (length != 0)
    {
        --length;
        putChar(buffer[length]);
    }
}

void printHex(size_t value, uint digits = size_t.sizeof * 2)
{
    enum hexDigits = "0123456789ABCDEF";
    char[16] buffer;

    if (digits == 0)
    {
        return;
    }

    if (digits > buffer.length)
    {
        digits = cast(uint)buffer.length;
    }

    foreach (index; 0 .. digits)
    {
        const shift = (digits - 1 - index) * 4;
        const nibble = (value >> shift) & 0xF;
        buffer[index] = hexDigits[nibble];
    }

    foreach (index; 0 .. digits)
    {
        putChar(buffer[index]);
    }
}

@nogc nothrow bool hasSerialConsole()
{
    return serialConsoleReady();
}

@nogc nothrow void consoleWriteChar(char c)
{
    if (!hasSerialConsole())
    {
        return;
    }

    if (c == '\n')
    {
        serialWriteByte('\r');
        serialWriteByte('\n');
        return;
    }

    serialWriteByte(cast(ubyte)c);
}

@nogc nothrow char consoleReadCharBlocking()
{
    if (!hasSerialConsole())
    {
        return '\0';
    }

    return serialReadByteBlocking();
}

void printLine(const(char)[] text)
{
    print(text);
    putChar('\n');
}

void printDivider()
{
    char[VGA_WIDTH] divider;
    foreach (index; 0 .. divider.length)
    {
        divider[index] = '-';
    }
    printLine(divider[]);
}

void printStageHeader(immutable(char)[] title)
{
    printLine("");
    printDivider();

    if (stageSummaryCount < stageSummaries.length)
    {
        stageSummaries[stageSummaryCount] = StageSummary(title, 0, 0, 0);
        activeStage = &stageSummaries[stageSummaryCount];
        ++stageSummaryCount;
    }
    else
    {
        activeStage = null;
    }

    print("Stage: ");
    printLine(title);
    printDivider();
}

void printStatus(immutable(char)[] prefix, immutable(char)[] name, immutable(char)[] suffix)
{
    print(prefix);
    print(name);
    printLine(suffix);

    if (activeStage !is null)
    {
        ++activeStage.statusCount;
    }
}

void printStatusValue(immutable(char)[] prefix, long value)
{
    print(prefix);
    printSigned(value);
    putChar('\n');

    if (activeStage !is null)
    {
        ++activeStage.statusCount;
    }
}

void logModuleCompilation(immutable(char)[] stageLabel, immutable(char)[] moduleName)
{
    print("[");
    print(stageLabel);
    print("] Compiled ");
    print(moduleName);
    printLine(" ... ok");

    if (activeStage !is null)
    {
        ++activeStage.moduleCount;
        ++activeStage.statusCount;
    }
}

void logExportValue(immutable(char)[] stageLabel, immutable(char)[] name, long value)
{
    print("[");
    print(stageLabel);
    print("]   ");
    print(name);
    print(" = ");
    printSigned(value);
    putChar('\n');

    if (activeStage !is null)
    {
        ++activeStage.statusCount;
        ++activeStage.exportCount;
    }
}

private void printSigned(long value)
{
    if (value < 0)
    {
        putChar('-');
        value = -value;
    }

    printUnsigned(cast(size_t)value);
}
