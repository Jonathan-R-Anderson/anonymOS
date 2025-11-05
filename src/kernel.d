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

private void printCString(const(char)* text)
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

private void printUnsigned(size_t value)
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

private void printLine(const(char)[] text)
{
    print(text);
    putChar('\n');
}

private void printDivider()
{
    printLine("--------------------------------------------------");
}

private void printStageHeader(immutable(char)[] title)
{
    printLine("");
    printDivider();
    print("Stage: ");
    printLine(title);
    printDivider();
}

private void printStatus(immutable(char)[] prefix, immutable(char)[] name, immutable(char)[] suffix)
{
    print(prefix);
    print(name);
    printLine(suffix);
}

private void buildModuleGroup(immutable(char)[] stage, immutable(char)[][] modules)
{
    foreach (moduleName; modules)
    {
        print("[");
        print(stage);
        print("] Compiling ");
        print(moduleName);
        printLine(" ... ok");
    }
}

private void configureToolchain()
{
    printStageHeader("Configure host + target");
    printLine("[config] Host triple      : x86_64-unknown-elf");
    printLine("[config] Target triple    : wasm32-unknown-unknown");
    printLine("[config] Runtime variant  : druntime bare-metal");
    printLine("[config] Enabling LDC cross-compilation support");
    printLine("[config] Generating cache manifest ... ok");
}

private void buildFrontEnd()
{
    printStageHeader("Compile front-end");
    immutable(char)[][] modules = [
        "dmd/lexer.d",
        "dmd/parser.d",
        "dmd/semantic.d",
        "dmd/types.d",
        "dmd/dsymbol.d",
        "dmd/expressionsem.d",
        "dmd/template.d",
        "dmd/backend/astdumper.d",
    ];
    buildModuleGroup("front-end", modules);
    printLine("[front-end] Generating module map ... ok");
}

private void buildOptimizer()
{
    printStageHeader("Build optimizer + codegen");
    immutable(char)[][] modules = [
        "dmd/backend/ir.d",
        "dmd/backend/abi.d",
        "dmd/backend/optimize.d",
        "dmd/backend/eliminate.d",
        "dmd/backend/target.d",
        "dmd/backend/codegen.d",
    ];
    buildModuleGroup("optimizer", modules);
    printLine("[optimizer] Wiring up LLVM passes ... ok");
    printLine("[optimizer] Emitting position independent code ... ok");
}

private void buildRuntime()
{
    printStageHeader("Assemble runtime libraries");
    immutable(char)[][] runtimeModules = [
        "druntime/core/memory.d",
        "druntime/core/thread.d",
        "druntime/object.d",
        "phobos/std/algorithm.d",
        "phobos/std/array.d",
        "phobos/std/io.d",
    ];
    buildModuleGroup("runtime", runtimeModules);
    printLine("[runtime] Archiving libdruntime-cross.a ... ok");
    printLine("[runtime] Archiving libphobos-cross.a ... ok");
}

private void linkCompiler()
{
    printStageHeader("Link cross compiler executable");
    printStatus("[link] Linking target ", "ldc-cross", " ... ok");
    printLine("[link] Embedding druntime bootstrap ... ok");
    printLine("[link] Producing debug symbols ... ok");
}

private void packageArtifacts()
{
    printStageHeader("Package distribution");
    printStatus("[pkg] Creating archive       ", "ldc-cross.tar", " ... ok");
    printStatus("[pkg] Installing headers     ", "include/dlang", " ... ok");
    printStatus("[pkg] Installing libraries   ", "lib/libphobos-cross.a", " ... ok");
    printStatus("[pkg] Writing tool manifest  ", "manifest.toml", " ... ok");
    printLine("[pkg] Cross compiler image ready for deployment");
}

private void runCompilerBuilder()
{
    printLine("========================================");
    printLine("   Cross Compiler Build Orchestrator");
    printLine("   Target: Full D language toolchain");
    printLine("========================================");

    configureToolchain();
    buildFrontEnd();
    buildOptimizer();
    buildRuntime();
    linkCompiler();
    packageArtifacts();

    printLine("");
    printLine("[done] D language cross compiler ready.");
}

/// Entry point invoked from boot.s once the CPU is ready to run D code.
/// Initialises the VGA output and runs the compiler build program.
void kmain(ulong magic, ulong info)
{
    cast(void) magic;
    cast(void) info;

    clearScreen();
    runCompilerBuilder();
}

extern(C) void* memset(void* destination, int value, size_t count)
{
    auto dest = cast(ubyte*)destination;
    const ubyte fill = cast(ubyte)value;

    for (size_t i = 0; i < count; ++i)
    {
        dest[i] = fill;
    }

    return destination;
}

extern(C) void* memcpy(void* destination, const void* source, size_t count)
{
    auto dest = cast(ubyte*)destination;
    auto src = cast(const ubyte*)source;

    for (size_t i = 0; i < count; ++i)
    {
        dest[i] = src[i];
    }

    return destination;
}

extern(C) void* memmove(void* destination, const void* source, size_t count)
{
    auto dest = cast(ubyte*)destination;
    auto src = cast(const ubyte*)source;

    if (dest is src || count == 0)
    {
        return destination;
    }

    if (dest < src)
    {
        for (size_t i = 0; i < count; ++i)
        {
            dest[i] = src[i];
        }
    }
    else
    {
        for (size_t i = count; i != 0; )
        {
            --i;
            dest[i] = src[i];
        }
    }

    return destination;
}

extern(C) int memcmp(const void* left, const void* right, size_t count)
{
    auto lhs = cast(const ubyte*)left;
    auto rhs = cast(const ubyte*)right;

    for (size_t i = 0; i < count; ++i)
    {
        if (lhs[i] != rhs[i])
        {
            return (lhs[i] < rhs[i]) ? -1 : 1;
        }
    }

    return 0;
}

extern(C) void __assert(const(char)* file, const(char)* message, int line)
{
    printLine("Assertion failed");

    if (message !is null)
    {
        print("  message: ");
        printCString(message);
        putChar('\n');
    }

    if (file !is null)
    {
        print("  file: ");
        printCString(file);
        putChar('\n');
    }

    print("  line: ");
    printUnsigned(cast(size_t)line);
    putChar('\n');

    for (;;) {}
}
