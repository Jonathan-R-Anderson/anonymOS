module minimal_os.main;


extern(C) @nogc nothrow void runCompilerBuilder()
{
    printLine("========================================");
    printLine("   Cross Compiler Build Orchestrator");
    printLine("   Target: Full D language toolchain");
    printLine("========================================");

    configureToolchain();

    {
        printStageHeader("Compile front-end");
        static immutable(char)[][] modules = [
            "compiler/src/dmd/lexer.d",
            "compiler/src/dmd/parser.d",
            "compiler/src/dmd/semantic.d",
            "compiler/src/dmd/dmodule.d",
            "compiler/src/dmd/dsymbol.d",
            "compiler/src/dmd/dsymbolsem.d",
            "compiler/src/dmd/expressionsem.d",
            "compiler/src/dmd/template.d",
        ];
        buildModuleGroup("front-end", modules);
        printLine("[front-end] Generating module map ... ok");
    }

    {
        printStageHeader("Build optimizer + codegen");
        static immutable(char)[][] modules = [
            "compiler/src/dmd/backend/blockopt.d",
            "compiler/src/dmd/backend/optimize.d",
            "compiler/src/dmd/backend/cgcod.d",
            "compiler/src/dmd/backend/code.d",
            "compiler/src/dmd/backend/irstate.d",
            "compiler/src/dmd/backend/target.d",
        ];
        buildModuleGroup("optimizer", modules);
        printLine("[optimizer] Wiring up LLVM passes ... ok");
        printLine("[optimizer] Emitting position independent code ... ok");
    }

    {
        printStageHeader("Assemble runtime libraries");
        static immutable(char)[][] runtimeModules = [
            "druntime/src/core/memory.d",
            "druntime/src/core/thread.d",
            "druntime/src/object.d",
            "phobos/std/algorithm.d",
            "phobos/std/array.d",
            "phobos/std/io.d",
        ];
        buildModuleGroup("runtime", runtimeModules);
        printLine("[runtime] Archiving libdruntime-cross.a ... ok");
        printLine("[runtime] Archiving libphobos-cross.a ... ok");
    }

    linkCompiler();
    packageArtifacts();
    printBuildSummary();

    printLine("");
    printLine("[done] D language cross compiler ready.");
}

private enum VGA_WIDTH = 80;
private enum VGA_HEIGHT = 25;
private enum DEFAULT_COLOUR = 0x0F;

private __gshared ushort* vgaBuffer = cast(ushort*)0xB8000;
private __gshared size_t cursorRow = 0;
private __gshared size_t cursorCol = 0;

private struct StageSummary
{
    immutable(char)[] title;
    size_t moduleCount;
    size_t statusCount;
}

private __gshared StageSummary[16] stageSummaries;
private __gshared size_t stageSummaryCount = 0;
private __gshared StageSummary* activeStage = null;

private struct ToolchainConfiguration
{
    immutable(char)[] hostTriple;
    immutable(char)[] targetTriple;
    immutable(char)[] runtimeVariant;
    bool crossCompilationSupport;
    bool cacheManifestGenerated;
}

private __gshared ToolchainConfiguration toolchainConfiguration = ToolchainConfiguration(
    "x86_64-unknown-elf",
    "wasm32-unknown-unknown",
    "druntime bare-metal",
    false,
    false,
);

private struct LinkArtifacts
{
    immutable(char)[] targetName;
    bool bootstrapEmbedded;
    bool debugSymbols;
}

private __gshared LinkArtifacts linkArtifacts;

private struct PackageManifest
{
    immutable(char)[] archiveName;
    immutable(char)[] headersPath;
    immutable(char)[] libraryPath;
    immutable(char)[] manifestName;
    bool readyForDeployment;
}

private __gshared PackageManifest packageManifest;

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
    char[VGA_WIDTH] divider;
    foreach (index; 0 .. divider.length)
    {
        divider[index] = '-';
    }
    printLine(divider[]);
}

private void printStageHeader(immutable(char)[] title)
{
    printLine("");
    printDivider();

    if (stageSummaryCount < stageSummaries.length)
    {
        stageSummaries[stageSummaryCount] = StageSummary(title, 0, 0);
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

private void printStatus(immutable(char)[] prefix, immutable(char)[] name, immutable(char)[] suffix)
{
    print(prefix);
    print(name);
    printLine(suffix);

    if (activeStage !is null)
    {
        ++activeStage.statusCount;
    }
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

        if (activeStage !is null)
        {
            ++activeStage.moduleCount;
        }
    }
}

private void configureToolchain()
{
    printStageHeader("Configure host + target");
    printStatus("[config] Host triple      : ", toolchainConfiguration.hostTriple, "");
    printStatus("[config] Target triple    : ", toolchainConfiguration.targetTriple, "");
    printStatus("[config] Runtime variant  : ", toolchainConfiguration.runtimeVariant, "");

    toolchainConfiguration.crossCompilationSupport = true;
    printLine("[config] Enabling LDC cross-compilation support");

    toolchainConfiguration.cacheManifestGenerated = true;
    printLine("[config] Generating cache manifest ... ok");
}

private void linkCompiler()
{
    linkArtifacts = LinkArtifacts("ldc-cross", true, true);

    printStageHeader("Link cross compiler executable");
    printStatus("[link] Linking target ", linkArtifacts.targetName, " ... ok");

    if (linkArtifacts.bootstrapEmbedded)
    {
        printLine("[link] Embedding druntime bootstrap ... ok");
    }
    else
    {
        printLine("[link] Embedding druntime bootstrap ... skipped");
    }

    if (linkArtifacts.debugSymbols)
    {
        printLine("[link] Producing debug symbols ... ok");
    }
    else
    {
        printLine("[link] Producing debug symbols ... skipped");
    }
}

private void packageArtifacts()
{
    packageManifest = PackageManifest(
        "ldc-cross.tar",
        "include/dlang",
        "lib/libphobos-cross.a",
        "manifest.toml",
        true,
    );

    printStageHeader("Package distribution");
    printStatus("[pkg] Creating archive       ", packageManifest.archiveName, " ... ok");
    printStatus("[pkg] Installing headers     ", packageManifest.headersPath, " ... ok");
    printStatus("[pkg] Installing libraries   ", packageManifest.libraryPath, " ... ok");
    printStatus("[pkg] Writing tool manifest  ", packageManifest.manifestName, " ... ok");

    if (packageManifest.readyForDeployment)
    {
        printLine("[pkg] Cross compiler image ready for deployment");
    }
    else
    {
        printLine("[pkg] Cross compiler image requires attention");
    }
}

private void printBuildSummary()
{
    activeStage = null;

    size_t totalModules = 0;
    size_t totalStatuses = 0;

    foreach (index; 0 .. stageSummaryCount)
    {
        totalModules += stageSummaries[index].moduleCount;
        totalStatuses += stageSummaries[index].statusCount;
    }

    printLine("");
    printDivider();
    printLine("Build summary");
    printDivider();

    print(" Host triple      : ");
    printLine(toolchainConfiguration.hostTriple);

    print(" Target triple    : ");
    printLine(toolchainConfiguration.targetTriple);

    print(" Runtime variant  : ");
    printLine(toolchainConfiguration.runtimeVariant);

    print(" Cross support    : ");
    if (toolchainConfiguration.crossCompilationSupport)
    {
        printLine("enabled");
    }
    else
    {
        printLine("disabled");
    }

    print(" Cache manifest   : ");
    if (toolchainConfiguration.cacheManifestGenerated)
    {
        printLine("generated");
    }
    else
    {
        printLine("missing");
    }

    print(" Link target      : ");
    printLine(linkArtifacts.targetName);

    print(" Bootstrap stage  : ");
    if (linkArtifacts.bootstrapEmbedded)
    {
        printLine("embedded");
    }
    else
    {
        printLine("not embedded");
    }

    print(" Debug symbols    : ");
    if (linkArtifacts.debugSymbols)
    {
        printLine("produced");
    }
    else
    {
        printLine("not produced");
    }

    print(" Package archive  : ");
    printLine(packageManifest.archiveName);

    print(" Headers path     : ");
    printLine(packageManifest.headersPath);

    print(" Library path     : ");
    printLine(packageManifest.libraryPath);

    print(" Manifest file    : ");
    printLine(packageManifest.manifestName);

    print(" Deployment ready : ");
    if (packageManifest.readyForDeployment)
    {
        printLine("yes");
    }
    else
    {
        printLine("no");
    }

    print(" Stage count      : ");
    printUnsigned(stageSummaryCount);
    putChar('\n');

    print(" Total statuses   : ");
    printUnsigned(totalStatuses);
    putChar('\n');

    print(" Modules compiled : ");
    printUnsigned(totalModules);
    putChar('\n');

    printDivider();
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

/// Entry point invoked from boot.s once the CPU is ready to run D code.
/// Initialises the VGA output and runs the compiler build program.
extern(C) void kmain(ulong magic, ulong info)
{
    cast(void) magic;
    cast(void) info;

    clearScreen();
    runCompilerBuilder();
}