module minimal_os.main;

private enum MAX_MODULES = 16;
private enum MAX_EXPORTS_PER_MODULE = 8;
private enum MAX_SYMBOLS = 128;

private struct ModuleSource
{
    immutable(char)[] expectedName;
    immutable(char)[] source;
}

private struct ExportSymbol
{
    immutable(char)[] name;
    long value;
}

private struct CompiledModule
{
    immutable(char)[] name;
    ExportSymbol[MAX_EXPORTS_PER_MODULE] exports;
    size_t exportCount;
}

private struct Symbol
{
    immutable(char)[] name;
    long value;
}

private struct Parser
{
    immutable(char)[] input;
    size_t index;
    bool failed;
    immutable(char)[] errorMessage;
    immutable(char)[] errorDetail;
}

private immutable ModuleSource[4] frontEndSourcesData = [
    ModuleSource(
        "front_end.lexer",
        "module front_end.lexer;\n" ~
        "export lexer_token_kinds = 128;\n" ~
        "export lexer_state_machine_cells = lexer_token_kinds * 12;\n" ~
        "export lexer_error_codes = 32;\n",
    ),
    ModuleSource(
        "front_end.parser",
        "module front_end.parser;\n" ~
        "export parser_rule_count = lexer_token_kinds * 2 + 64;\n" ~
        "export parser_ast_nodes = parser_rule_count * 5;\n",
    ),
    ModuleSource(
        "front_end.semantic",
        "module front_end.semantic;\n" ~
        "export semantic_checks = parser_rule_count * 3;\n" ~
        "export semantic_issues_detected = semantic_checks / 48;\n",
    ),
    ModuleSource(
        "front_end.templates",
        "module front_end.templates;\n" ~
        "export template_instances = semantic_checks / 2 + 24;\n" ~
        "export template_cache_entries = template_instances * 3 + lexer_error_codes;\n",
    ),
];

private immutable ModuleSource[3] optimizerSourcesData = [
    ModuleSource(
        "optimizer.ir",
        "module optimizer.ir;\n" ~
        "export optimizer_ir_nodes = parser_ast_nodes + semantic_checks;\n" ~
        "export optimizer_liveness_sets = optimizer_ir_nodes / 2 + 12;\n",
    ),
    ModuleSource(
        "optimizer.ssa",
        "module optimizer.ssa;\n" ~
        "export optimizer_ssa_versions = optimizer_ir_nodes * 3;\n" ~
        "export optimizer_pruned_blocks = optimizer_ssa_versions / 16;\n",
    ),
    ModuleSource(
        "optimizer.codegen",
        "module optimizer.codegen;\n" ~
        "export optimizer_codegen_units = optimizer_ir_nodes / 4 + template_instances;\n" ~
        "export optimizer_machine_blocks = optimizer_codegen_units * 2 + optimizer_pruned_blocks;\n",
    ),
];

private immutable ModuleSource[3] runtimeSourcesData = [
    ModuleSource(
        "runtime.memory",
        "module runtime.memory;\n" ~
        "export runtime_heap_segments = optimizer_machine_blocks / 8 + 4;\n" ~
        "export runtime_gc_traces = runtime_heap_segments * 3;\n",
    ),
    ModuleSource(
        "runtime.scheduler",
        "module runtime.scheduler;\n" ~
        "export runtime_thread_count = runtime_heap_segments + optimizer_pruned_blocks / 2;\n" ~
        "export runtime_stack_slots = runtime_thread_count * 64;\n",
    ),
    ModuleSource(
        "runtime.io",
        "module runtime.io;\n" ~
        "export runtime_io_channels = runtime_thread_count / 2 + 6;\n" ~
        "export runtime_device_drivers = runtime_io_channels / 3 + runtime_gc_traces / 6;\n",
    ),
];

extern(C) @nogc nothrow void runCompilerBuilder()
{
    resetBuilderState();

    printLine("========================================");
    printLine("   Cross Compiler Build Orchestrator");
    printLine("   Target: Full D language toolchain");
    printLine("========================================");

    configureToolchain();

    compileStage("Compile front-end", "front-end", frontEndSourcesData[]);
    compileStage("Build optimizer + codegen", "optimizer", optimizerSourcesData[]);
    compileStage("Assemble runtime libraries", "runtime", runtimeSourcesData[]);

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
    size_t exportCount;
}

private __gshared StageSummary[16] stageSummaries;
private __gshared size_t stageSummaryCount = 0;
private __gshared StageSummary* activeStage = null;

private __gshared CompiledModule[MAX_MODULES] compiledModules;
private __gshared size_t compiledModuleCount = 0;

private __gshared Symbol[MAX_SYMBOLS] globalSymbols;
private __gshared size_t globalSymbolCount = 0;

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
private __gshared ubyte[512] linkedArtifactImage;
private __gshared size_t linkedArtifactSize = 0;

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
    if (text is null)
    {
        return;
    }

    for (size_t index = 0; index < text.length; ++index)
    {
        putChar(text[index]);
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

private void printHex(size_t value, uint digits = size_t.sizeof * 2)
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

private void printStatusValue(immutable(char)[] prefix, long value)
{
    print(prefix);
    printSigned(value);
    putChar('\n');

    if (activeStage !is null)
    {
        ++activeStage.statusCount;
    }
}

extern(C) struct InterruptRegisters
{
    size_t rax;
    size_t rbx;
    size_t rcx;
    size_t rdx;
    size_t rbp;
    size_t rsi;
    size_t rdi;
    size_t r8;
    size_t r9;
    size_t r10;
    size_t r11;
    size_t r12;
    size_t r13;
    size_t r14;
    size_t r15;
}

private struct IDTEntry
{
    ushort offsetLow;
    ushort selector;
    ubyte ist;
    ubyte typeAttributes;
    ushort offsetMid;
    uint offsetHigh;
    uint reserved;
}

private struct IDTPointer
{
    ushort limit;
    size_t base;
}

private __gshared IDTEntry[256] interruptDescriptorTable;

extern(C) void invalidOpcodeStub();
extern(C) void loadIDT(const IDTPointer* descriptor);

private void setIDTEntry(size_t vector, extern(C) void function() handler)
{
    const size_t handlerAddress = cast(size_t)handler;

    auto entry = IDTEntry(
        cast(ushort)(handlerAddress & 0xFFFF),
        0x08,
        0,
        0x8E,
        cast(ushort)((handlerAddress >> 16) & 0xFFFF),
        cast(uint)((handlerAddress >> 32) & 0xFFFFFFFF),
        0,
    );

    interruptDescriptorTable[vector] = entry;
}

private void initializeInterrupts()
{
    interruptDescriptorTable[] = IDTEntry.init;

    setIDTEntry(6, &invalidOpcodeStub);

    IDTPointer descriptor;
    descriptor.limit = cast(ushort)(interruptDescriptorTable.length * IDTEntry.sizeof - 1);
    descriptor.base = cast(size_t)interruptDescriptorTable.ptr;

    loadIDT(&descriptor);
}

extern(C) @nogc nothrow void handleInvalidOpcode(
    InterruptRegisters* registers,
    size_t vector,
    size_t errorCode,
    size_t rip,
    size_t cs,
    size_t rflags,
)
{
    printLine("");
    printLine("[interrupt] Invalid opcode (#UD)");

    print("  vector: 0x");
    printHex(vector, 2);
    putChar('\n');

    print("  error: 0x");
    printHex(errorCode, 4);
    putChar('\n');

    print("  RIP:   0x");
    printHex(rip);
    putChar('\n');

    print("  CS:    0x");
    printHex(cs, 4);
    putChar('\n');

    print("  RFLAGS:0x");
    printHex(rflags);
    putChar('\n');

    if (registers !is null)
    {
        print("  RAX:   0x");
        printHex(registers.rax);
        putChar('\n');

        print("  RBX:   0x");
        printHex(registers.rbx);
        putChar('\n');
    }

    printLine("System halted.");

    for (;;)
    {
        // spin forever
    }
}

private void resetBuilderState()
{
    compiledModuleCount = 0;
    globalSymbolCount = 0;
    stageSummaryCount = 0;
    activeStage = null;
    linkedArtifactSize = 0;

    storeGlobalSymbol("builder", "bootstrap", "word_size", 8);
    storeGlobalSymbol("builder", "bootstrap", "pointer_size", 8);
    storeGlobalSymbol("builder", "bootstrap", "vector_alignment", 16);
}

private void compileStage(immutable(char)[] title, immutable(char)[] stageLabel, const ModuleSource[] sources)
{
    printStageHeader(title);

    foreach (moduleSource; sources)
    {
        compileModule(stageLabel, moduleSource);
    }
}

private void compileModule(immutable(char)[] stageLabel, const ModuleSource source)
{
    Parser parser;
    parser.input = source.source;
    parser.index = 0;
    parser.failed = false;
    parser.errorMessage = null;
    parser.errorDetail = null;

    immutable(char)[] moduleName;
    if (!parseModuleHeader(parser, moduleName))
    {
        compilerAbort(stageLabel, source.expectedName, parser);
    }

    if (!stringsEqual(moduleName, source.expectedName))
    {
        parser.failed = true;
        parser.errorMessage = "module name mismatch";
        parser.errorDetail = source.expectedName;
        compilerAbort(stageLabel, moduleName, parser);
    }

    CompiledModule compiledModule;
    compiledModule.name = moduleName;
    compiledModule.exportCount = 0;

    while (true)
    {
        skipWhitespace(parser);
        if (parserAtEnd(parser))
        {
            break;
        }

        if (!parseExport(parser, stageLabel, compiledModule))
        {
            compilerAbort(stageLabel, compiledModule.name, parser);
        }
    }

    addCompiledModule(stageLabel, compiledModule);
    logModuleCompilation(stageLabel, compiledModule.name);
}

private bool parseModuleHeader(ref Parser parser, out immutable(char)[] moduleName)
{
    if (!consumeKeyword(parser, "module"))
    {
        parserError(parser, "expected 'module' declaration");
        return false;
    }

    if (!parseQualifiedIdentifier(parser, moduleName))
    {
        parserError(parser, "expected module name");
        return false;
    }

    if (!expectChar(parser, ';'))
    {
        parserError(parser, "expected ';' after module declaration");
        return false;
    }

    return true;
}

private bool parseExport(ref Parser parser, immutable(char)[] stageLabel, ref CompiledModule compiledModule)
{
    if (!consumeKeyword(parser, "export"))
    {
        parserError(parser, "expected 'export' declaration");
        return false;
    }

    immutable(char)[] exportName;
    if (!parseIdentifier(parser, exportName))
    {
        parserError(parser, "expected symbol name");
        return false;
    }

    if (!expectChar(parser, '='))
    {
        parserError(parser, "expected '=' after export name");
        return false;
    }

    const long value = parseExpression(parser, &compiledModule);
    if (parser.failed)
    {
        return false;
    }

    if (!expectChar(parser, ';'))
    {
        parserError(parser, "expected ';' after export expression");
        return false;
    }

    addModuleExport(stageLabel, compiledModule, exportName, value);
    storeGlobalSymbol(stageLabel, compiledModule.name, exportName, value);
    logExportValue(stageLabel, exportName, value);
    return true;
}

private void addModuleExport(immutable(char)[] stageLabel, ref CompiledModule compiledModule, immutable(char)[] name, long value)
{
    foreach (index; 0 .. compiledModule.exportCount)
    {
        if (stringsEqual(compiledModule.exports[index].name, name))
        {
            compiledModule.exports[index].value = value;
            return;
        }
    }

    if (compiledModule.exportCount >= compiledModule.exports.length)
    {
        builderFatal(stageLabel, compiledModule.name, "module export table exhausted", name);
    }

    compiledModule.exports[compiledModule.exportCount].name = name;
    compiledModule.exports[compiledModule.exportCount].value = value;
    ++compiledModule.exportCount;
}

private void storeGlobalSymbol(immutable(char)[] stageLabel, immutable(char)[] unitName, immutable(char)[] name, long value)
{
    foreach (index; 0 .. globalSymbolCount)
    {
        if (stringsEqual(globalSymbols[index].name, name))
        {
            globalSymbols[index].value = value;
            return;
        }
    }

    if (globalSymbolCount >= globalSymbols.length)
    {
        builderFatal(stageLabel, unitName, "global symbol table exhausted", name);
    }

    globalSymbols[globalSymbolCount].name = name;
    globalSymbols[globalSymbolCount].value = value;
    ++globalSymbolCount;
}

private void addCompiledModule(immutable(char)[] stageLabel, ref CompiledModule compiledModule)
{
    if (compiledModuleCount >= compiledModules.length)
    {
        builderFatal(stageLabel, compiledModule.name, "compiled module buffer exhausted", compiledModule.name);
    }

    compiledModules[compiledModuleCount] = compiledModule;
    ++compiledModuleCount;
}

private void logModuleCompilation(immutable(char)[] stageLabel, immutable(char)[] moduleName)
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

private void logExportValue(immutable(char)[] stageLabel, immutable(char)[] name, long value)
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

private void builderFatal(immutable(char)[] stageLabel, immutable(char)[] unitName, immutable(char)[] message, immutable(char)[] detail)
{
    printLine("");
    printDivider();
    printLine("[builder] fatal error");
    printDivider();
    print(" Stage : ");
    printLine(stageLabel);
    print(" Unit  : ");
    printLine(unitName);
    print(" Error : ");
    printLine(message);

    if (detail !is null && detail.length != 0)
    {
        print(" Detail: ");
        printLine(detail);
    }

    printDivider();

    for (;;)
    {
    }
}

private void compilerAbort(immutable(char)[] stageLabel, immutable(char)[] unitName, Parser parser)
{
    immutable(char)[] message = parser.errorMessage;
    if (message is null || message.length == 0)
    {
        message = "parser failure";
    }

    builderFatal(stageLabel, unitName, message, parser.errorDetail);
}

private void compilerAbort(immutable(char)[] stageLabel, immutable(char)[] unitName, immutable(char)[] message)
{
    builderFatal(stageLabel, unitName, message, null);
}

private void skipWhitespace(ref Parser parser)
{
    while (!parserAtEnd(parser))
    {
        const char ch = parser.input[parser.index];
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
        {
            ++parser.index;
            continue;
        }

        if (ch == '/' && parser.index + 1 < parser.input.length && parser.input[parser.index + 1] == '/')
        {
            parser.index += 2;
            while (!parserAtEnd(parser) && parser.input[parser.index] != '\n')
            {
                ++parser.index;
            }
            continue;
        }

        break;
    }
}

private bool consumeKeyword(ref Parser parser, immutable(char)[] keyword)
{
    skipWhitespace(parser);

    const size_t start = parser.index;
    foreach (index; 0 .. keyword.length)
    {
        if (parserAtEnd(parser) || parser.input[parser.index] != keyword[index])
        {
            parser.index = start;
            return false;
        }

        ++parser.index;
    }

    if (!parserAtEnd(parser))
    {
        const char tail = parser.input[parser.index];
        if (isIdentifierChar(tail))
        {
            parser.index = start;
            return false;
        }
    }

    return true;
}

private bool parseQualifiedIdentifier(ref Parser parser, out immutable(char)[] name)
{
    skipWhitespace(parser);

    const size_t start = parser.index;
    if (!parseIdentifierCore(parser))
    {
        parser.index = start;
        return false;
    }

    while (!parserAtEnd(parser) && parser.input[parser.index] == '.')
    {
        ++parser.index;
        if (!parseIdentifierCore(parser))
        {
            parser.index = start;
            return false;
        }
    }

    const size_t end = parser.index;
    name = parser.input[start .. end];
    return true;
}

private bool parseIdentifier(ref Parser parser, out immutable(char)[] name)
{
    skipWhitespace(parser);

    const size_t start = parser.index;
    if (!parseIdentifierCore(parser))
    {
        parser.index = start;
        return false;
    }

    name = parser.input[start .. parser.index];
    return true;
}

private bool parseIdentifierCore(ref Parser parser)
{
    if (parserAtEnd(parser))
    {
        return false;
    }

    char ch = parser.input[parser.index];
    if (!isIdentifierStart(ch))
    {
        return false;
    }

    ++parser.index;

    while (!parserAtEnd(parser))
    {
        ch = parser.input[parser.index];
        if (!isIdentifierChar(ch))
        {
            break;
        }

        ++parser.index;
    }

    return true;
}

private bool isIdentifierStart(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_';
}

private bool isIdentifierChar(char ch)
{
    return isIdentifierStart(ch) || (ch >= '0' && ch <= '9');
}

private bool expectChar(ref Parser parser, char expected)
{
    skipWhitespace(parser);

    if (parserAtEnd(parser) || parser.input[parser.index] != expected)
    {
        return false;
    }

    ++parser.index;
    return true;
}

private long parseExpression(ref Parser parser, CompiledModule* compiledModule)
{
    long value = parseTerm(parser, compiledModule);

    while (!parser.failed)
    {
        skipWhitespace(parser);
        if (parserAtEnd(parser))
        {
            break;
        }

        const char op = parser.input[parser.index];
        if (op != '+' && op != '-')
        {
            break;
        }

        ++parser.index;
        const long rhs = parseTerm(parser, compiledModule);
        if (parser.failed)
        {
            return 0;
        }

        if (op == '+')
        {
            value += rhs;
        }
        else
        {
            value -= rhs;
        }
    }

    return value;
}

private long parseTerm(ref Parser parser, CompiledModule* compiledModule)
{
    long value = parseFactor(parser, compiledModule);

    while (!parser.failed)
    {
        skipWhitespace(parser);
        if (parserAtEnd(parser))
        {
            break;
        }

        const char op = parser.input[parser.index];
        if (op != '*' && op != '/')
        {
            break;
        }

        ++parser.index;
        const long rhs = parseFactor(parser, compiledModule);
        if (parser.failed)
        {
            return 0;
        }

        if (op == '*')
        {
            value *= rhs;
        }
        else
        {
            if (rhs == 0)
            {
                parserError(parser, "division by zero");
                return 0;
            }

            value /= rhs;
        }
    }

    return value;
}

private long parseFactor(ref Parser parser, CompiledModule* compiledModule)
{
    skipWhitespace(parser);

    if (parserAtEnd(parser))
    {
        parserError(parser, "unexpected end of input");
        return 0;
    }

    const char ch = parser.input[parser.index];

    if (ch == '(')
    {
        ++parser.index;
        const long value = parseExpression(parser, compiledModule);
        if (parser.failed)
        {
            return 0;
        }

        if (!expectChar(parser, ')'))
        {
            parserError(parser, "expected ')' after expression");
            return 0;
        }

        return value;
    }

    if (ch >= '0' && ch <= '9')
    {
        long value;
        if (!parseNumber(parser, value))
        {
            parserError(parser, "invalid numeric literal");
            return 0;
        }

        return value;
    }

    if (isIdentifierStart(ch))
    {
        immutable(char)[] identifier;
        if (!parseIdentifier(parser, identifier))
        {
            parserError(parser, "invalid identifier");
            return 0;
        }

        long resolved;
        if (lookupModuleSymbol(compiledModule, identifier, resolved))
        {
            return resolved;
        }

        if (lookupGlobalSymbol(identifier, resolved))
        {
            return resolved;
        }

        parserError(parser, "unknown identifier");
        parser.errorDetail = identifier;
        return 0;
    }

    parserError(parser, "unexpected token");
    return 0;
}

private bool parseNumber(ref Parser parser, out long value)
{
    long result = 0;
    bool foundDigit = false;

    while (!parserAtEnd(parser))
    {
        const char ch = parser.input[parser.index];
        if (ch < '0' || ch > '9')
        {
            break;
        }

        result = result * 10 + (ch - '0');
        ++parser.index;
        foundDigit = true;
    }

    value = result;
    return foundDigit;
}

private bool lookupModuleSymbol(const CompiledModule* compiledModule, immutable(char)[] name, out long value)
{
    foreach (index; 0 .. compiledModule.exportCount)
    {
        if (stringsEqual(compiledModule.exports[index].name, name))
        {
            value = compiledModule.exports[index].value;
            return true;
        }
    }

    value = 0;
    return false;
}

private bool lookupGlobalSymbol(immutable(char)[] name, out long value)
{
    foreach (index; 0 .. globalSymbolCount)
    {
        if (stringsEqual(globalSymbols[index].name, name))
        {
            value = globalSymbols[index].value;
            return true;
        }
    }

    value = 0;
    return false;
}

private bool stringsEqual(immutable(char)[] left, immutable(char)[] right)
{
    if (left.length != right.length)
    {
        return false;
    }

    foreach (index; 0 .. left.length)
    {
        if (left[index] != right[index])
        {
            return false;
        }
    }

    return true;
}

private bool parserAtEnd(const Parser parser)
{
    return parser.index >= parser.input.length;
}

private void parserError(ref Parser parser, immutable(char)[] message)
{
    if (!parser.failed)
    {
        parser.failed = true;
        parser.errorMessage = message;
        parser.errorDetail = null;
    }
}

private void configureToolchain()
{
    printStageHeader("Configure host + target");
    printStatus("[config] Host triple      : ", toolchainConfiguration.hostTriple, "");
    printStatus("[config] Target triple    : ", toolchainConfiguration.targetTriple, "");
    printStatus("[config] Runtime variant  : ", toolchainConfiguration.runtimeVariant, "");

    long pointerSize;
    if (!lookupGlobalSymbol("pointer_size", pointerSize))
    {
        pointerSize = 0;
    }
    printStatusValue("[config] Pointer bytes    : ", pointerSize);

    long vectorAlignment;
    if (!lookupGlobalSymbol("vector_alignment", vectorAlignment))
    {
        vectorAlignment = 0;
    }
    printStatusValue("[config] Vector alignment : ", vectorAlignment);

    toolchainConfiguration.crossCompilationSupport = (pointerSize >= 8) && (vectorAlignment % (pointerSize == 0 ? 1 : pointerSize) == 0);
    immutable(char)[] crossStatus = toolchainConfiguration.crossCompilationSupport ? "enabled" : "disabled";
    printStatus("[config] Cross-compilation : ", crossStatus, "");

    toolchainConfiguration.cacheManifestGenerated = vectorAlignment >= 16;
    immutable(char)[] manifestStatus = toolchainConfiguration.cacheManifestGenerated ? "generated" : "pending";
    printStatus("[config] Cache manifest   : ", manifestStatus, "");
}

private void linkCompiler()
{
    printStageHeader("Link cross compiler executable");

    long codegenUnits;
    if (!lookupGlobalSymbol("optimizer_codegen_units", codegenUnits))
    {
        codegenUnits = 0;
    }

    long machineBlocks;
    if (!lookupGlobalSymbol("optimizer_machine_blocks", machineBlocks))
    {
        machineBlocks = 0;
    }

    long runtimeSegments;
    if (!lookupGlobalSymbol("runtime_heap_segments", runtimeSegments))
    {
        runtimeSegments = 0;
    }

    long semanticIssues;
    if (!lookupGlobalSymbol("semantic_issues_detected", semanticIssues))
    {
        semanticIssues = 0;
    }

    linkArtifacts.targetName = "ldc-cross";
    linkArtifacts.bootstrapEmbedded = runtimeSegments > 8;
    linkArtifacts.debugSymbols = semanticIssues <= 2;

    linkedArtifactSize = 0;

    immutable(char)[] stageLabel = "link";
    immutable(char)[] unitName = linkArtifacts.targetName;

    void appendByte(ubyte value)
    {
        if (linkedArtifactSize >= linkedArtifactImage.length)
        {
            builderFatal(stageLabel, unitName, "linked image buffer exhausted", null);
        }

        linkedArtifactImage[linkedArtifactSize] = value;
        ++linkedArtifactSize;
    }

    void appendWord(ulong value)
    {
        foreach (shift; 0 .. 8)
        {
            appendByte(cast(ubyte)((value >> (shift * 8)) & 0xFF));
        }
    }

    void appendString(immutable(char)[] text)
    {
        foreach (ch; text)
        {
            appendByte(cast(ubyte)ch);
        }
    }

    appendString("ICLD");
    appendWord(cast(ulong)codegenUnits);
    appendWord(cast(ulong)machineBlocks);
    appendWord(cast(ulong)globalSymbolCount);

    foreach (moduleIndex; 0 .. compiledModuleCount)
    {
        auto moduleInfo = compiledModules[moduleIndex];
        size_t nameLength = moduleInfo.name.length;
        if (nameLength > 255)
        {
            nameLength = 255;
        }

        appendByte(cast(ubyte)nameLength);
        foreach (ch; moduleInfo.name[0 .. nameLength])
        {
            appendByte(cast(ubyte)ch);
        }

        appendByte(cast(ubyte)moduleInfo.exportCount);
        foreach (exportIndex; 0 .. moduleInfo.exportCount)
        {
            appendWord(cast(ulong)moduleInfo.exports[exportIndex].value);
        }
    }

    printStatus("[link] Linking target ", linkArtifacts.targetName, " ... ok");
    printStatusValue("[link] Units linked     : ", codegenUnits);
    printStatusValue("[link] Machine blocks   : ", machineBlocks);
    printStatusValue("[link] Artifact bytes   : ", cast(long)linkedArtifactSize);

    immutable(char)[] bootstrap = linkArtifacts.bootstrapEmbedded ? "embedded" : "skipped";
    printStatus("[link] Bootstrap stage   : ", bootstrap, "");

    immutable(char)[] debugStatus = linkArtifacts.debugSymbols ? "generated" : "skipped";
    printStatus("[link] Debug symbols     : ", debugStatus, "");
}

private void packageArtifacts()
{
    packageManifest = PackageManifest(
        "ldc-cross.tar",
        "include/dlang",
        "lib/libphobos-cross.a",
        "manifest.toml",
        false,
    );

    printStageHeader("Package distribution");
    printStatus("[pkg] Creating archive       ", packageManifest.archiveName, " ... ok");
    printStatus("[pkg] Installing headers     ", packageManifest.headersPath, " ... ok");
    printStatus("[pkg] Installing libraries   ", packageManifest.libraryPath, " ... ok");
    printStatus("[pkg] Writing tool manifest  ", packageManifest.manifestName, " ... ok");

    printStatusValue("[pkg] Module count         : ", compiledModuleCount);
    printStatusValue("[pkg] Exported symbols     : ", globalSymbolCount);
    printStatusValue("[pkg] Artifact bytes       : ", cast(long)linkedArtifactSize);

    long runtimeDrivers;
    if (!lookupGlobalSymbol("runtime_device_drivers", runtimeDrivers))
    {
        runtimeDrivers = 0;
    }
    printStatusValue("[pkg] Runtime drivers      : ", runtimeDrivers);

    packageManifest.readyForDeployment = (linkedArtifactSize >= 64) && (runtimeDrivers >= 6);
    immutable(char)[] deployment = packageManifest.readyForDeployment ? "ready" : "needs review";
    printStatus("[pkg] Deployment status     : ", deployment, "");
}

private void printBuildSummary()
{
    activeStage = null;

    size_t totalModules = 0;
    size_t totalStatuses = 0;
    size_t totalExports = 0;

    foreach (index; 0 .. stageSummaryCount)
    {
        totalModules += stageSummaries[index].moduleCount;
        totalStatuses += stageSummaries[index].statusCount;
        totalExports += stageSummaries[index].exportCount;
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

    print(" Exported symbols : ");
    printUnsigned(totalExports);
    putChar('\n');

    print(" Artifact bytes   : ");
    printUnsigned(linkedArtifactSize);
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
    initializeInterrupts();
    runCompilerBuilder();
}
