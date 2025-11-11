module minimal_os.main;

import sh_metadata : shRepositoryPath, shBinaryName, shRevision, shSourceFileCount, shDocumentedCommandCount, shBinarySizeBytes;

private enum MAX_MODULES = 16;
private enum MAX_EXPORTS_PER_MODULE = 8;
private enum MAX_SYMBOLS = 128;
mixin PosixKernelShim;

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
    integrateShell();
    printBuildSummary();

    printLine("");
    printLine("[done] D language cross compiler ready.");
    if (shellState.shellActivated)
    {
        printLine("[done] 'lfe-sh' interactive shell ready.");
        printLine("");
        printLine("Booting 'lfe-sh' interactive shell...");
        launchInteractiveShell();
    }
    else
    {
        print("[warn] 'lfe-sh' shell unavailable: ");
        if (shellState.failureReason !is null)
        {
            printLine(shellState.failureReason);
        }
        else
        {
            printLine("compiler access is required.");
        }
    }
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

private struct ShellState
{
    immutable(char)[] repository;
    immutable(char)[] revision;
    immutable(char)[] binaryName;
    size_t binaryBytes;
    size_t documentedCommandCount;
    size_t sourceFileCount;
    bool repositoryFetched;
    bool runtimeBound;
    bool compilerAccessible;
    bool shellActivated;
    immutable(char)[] failureReason;
}

private __gshared ShellState shellState = ShellState(
    shRepositoryPath,
    shRevision,
    shBinaryName,
    shBinarySizeBytes,
    shDocumentedCommandCount,
    shSourceFileCount,
    false,
    false,
    false,
    false,
    null,
);

private __gshared bool g_consoleAvailable = false;
private __gshared bool g_shellRegistered = false;
private __gshared bool g_posixConfigured = false;
private __gshared bool g_posixUtilitiesRegistered = false;
private __gshared size_t g_posixUtilityCount = 0;
private __gshared const(char*)[2] g_shellDefaultArgv = [cast(const char*)"/bin/sh\0".ptr, null];
private __gshared const(char*)[1] g_shellDefaultEnvp = [null];

extern(C) @nogc nothrow void shellExecEntry(const char** argv, const char** envp);
extern(C) @nogc nothrow void posixUtilityExecEntry(const char** argv, const char** envp);
extern(C) char* getenv(const char* name);

version (Posix)
{
    extern(C) __gshared char** environ;
}

nothrow:
@nogc:

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

alias InterruptHandler = extern(C) void function();

private void setIDTEntry(size_t vector, InterruptHandler handler)
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

@nogc nothrow private void resetProc(ref Proc p)
{
    if (p.environment !is null)
    {
        releaseEnvironmentTable(p.environment);
        p.environment = null;
    }

    if (g_objectRegistryReady && isProcessObject(p.objectId))
    {
        destroyProcessObject(p.objectId);
    }

    p.pid = 0;
    p.ppid = 0;
    p.state = ProcState.UNUSED;
    p.exitCode = 0;
    p.sigmask = 0;
    foreach (i; 0 .. p.fds.length) p.fds[i] = FD.init;
    p.entry = null;
    p.ctx = null;
    p.kstack = null;
    clearName(p.name);
    p.pendingArgv = null;
    p.pendingEnvp = null;
    p.pendingExec = false;
    p.objectId = INVALID_OBJECT_ID;
    p.environment = null;
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

private bool stringsEqualConst(const(char)[] left, const(char)[] right)
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

private size_t copyToFixedBuffer(const(char)[] source, char[] destination)
{
    size_t count = source.length;
    if (count > destination.length)
    {
        count = destination.length;
    }

    for (size_t index = 0; index < count; ++index)
    {
        destination[index] = source[index];
    }

    if (destination.length != 0)
    {
        if (count < destination.length)
        {
            destination[count] = '\0';
            for (size_t index = count + 1; index < destination.length; ++index)
            {
                destination[index] = '\0';
            }
        }
        else
        {
            destination[destination.length - 1] = '\0';
        }
    }

    return count;
}

private size_t formatUnsignedValue(size_t value, char[] buffer)
{
    if (buffer.length == 0)
    {
        return 0;
    }

    char[20] scratch;
    size_t scratchLength = 0;

    do
    {
        scratch[scratchLength] = cast(char)('0' + (value % 10));
        ++scratchLength;
        value /= 10;
    }
    while (value != 0 && scratchLength < scratch.length);

    size_t index = 0;
    while (scratchLength != 0 && index < buffer.length)
    {
        --scratchLength;
        buffer[index] = scratch[scratchLength];
        ++index;
    }

    if (index < buffer.length)
    {
        buffer[index] = '\0';
    }

    return index;
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

private void integrateShell()
{
    printStageHeader("Integrate 'lfe-sh' shell environment");

    fetchShellSnapshot();
    updateShellBinaryMetrics();
    checkShellRuntimeBindings();
    checkShellCompilerAccess();
    bindPosixUtilitiesToKernel();
    finalizeShellActivation();
}

private void fetchShellSnapshot()
{
    shellState.repositoryFetched = true;
    shellState.revision = shRevision;
    shellState.binaryName = shBinaryName;
    shellState.failureReason = null;

    printStatus("[shell] Source repository : ", shellState.repository, "");
    printStatus("[shell] Revision pinned   : ", shellState.revision, "");
    printStatus("[shell] Shell binary      : ", shellState.binaryName, "");
}

private void updateShellBinaryMetrics()
{
    shellState.binaryBytes = shBinarySizeBytes;
    shellState.documentedCommandCount = shDocumentedCommandCount;
    shellState.sourceFileCount = shSourceFileCount;

    printStatusValue("[shell] Package bytes     : ", cast(long)shBinarySizeBytes);
    printStatusValue("[shell] Documented cmds   : ", cast(long)shDocumentedCommandCount);
    printStatusValue("[shell] Source modules    : ", cast(long)shSourceFileCount);
}

private void checkShellRuntimeBindings()
{
    shellState.runtimeBound = linkArtifacts.bootstrapEmbedded;
    immutable(char)[] runtimeStatus = shellState.runtimeBound ? "connected" : "missing bootstrap";
    printStatus("[shell] Runtime bindings  : ", runtimeStatus, "");

    if (!shellState.runtimeBound && (shellState.failureReason is null || shellState.failureReason.length == 0))
    {
        shellState.failureReason = "runtime bootstrap required";
    }
}

private void checkShellCompilerAccess()
{
    const bool cross = toolchainConfiguration.crossCompilationSupport;
    const bool manifest = toolchainConfiguration.cacheManifestGenerated;
    const bool deployed = packageManifest.readyForDeployment;

    shellState.compilerAccessible = cross && manifest && deployed;

    immutable(char)[] compilerStatus = shellState.compilerAccessible ? "available" : "unavailable";
    immutable(char)[] crossStatus = cross ? "enabled" : "disabled";
    immutable(char)[] manifestStatus = manifest ? "present" : "missing";
    immutable(char)[] deployStatus = deployed ? "ready" : "pending";

    printStatus("[shell] Compiler access   : ", compilerStatus, "");
    printStatus("[shell] Host cross-comp   : ", crossStatus, "");
    printStatus("[shell] Cache manifest    : ", manifestStatus, "");
    printStatus("[shell] Toolchain deploy  : ", deployStatus, "");

    if (!shellState.compilerAccessible && (shellState.failureReason is null || shellState.failureReason.length == 0))
    {
        if (!cross)
        {
            shellState.failureReason = "cross-compiler support disabled";
        }
        else if (!manifest)
        {
            shellState.failureReason = "cache manifest missing";
        }
        else if (!deployed)
        {
            shellState.failureReason = "toolchain deployment incomplete";
        }
        else
        {
            shellState.failureReason = "compiler path inaccessible";
        }
    }
}

private void bindPosixUtilitiesToKernel()
{
    version (Posix)
    {
        if (!g_posixConfigured)
        {
            ensurePosixUtilitiesConfigured();
        }

        const size_t registered = registerPosixUtilities();

        immutable(char)[] status = (registered > 0) ? "available" : "unavailable";
        printStatus("[shell] POSIX utilities  : ", status, "");
        printStatusValue("[shell] POSIX execs    : ", cast(long)registered);

        if (registered == 0 && (shellState.failureReason is null || shellState.failureReason.length == 0))
        {
            shellState.failureReason = "POSIX utilities unavailable";
        }
    }
    else
    {
        printStatus("[shell] POSIX utilities  : ", "unsupported", "");
        printStatusValue("[shell] POSIX execs    : ", 0);
        g_posixUtilitiesRegistered = false;
        g_posixUtilityCount = 0;
        if (shellState.failureReason is null || shellState.failureReason.length == 0)
        {
            shellState.failureReason = "POSIX utilities unsupported";
        }
    }
}

private void finalizeShellActivation()
{
    const bool detectedConsole = detectConsoleAvailability();
    if (detectedConsole)
    {
        if (!g_consoleAvailable)
        {
            g_consoleAvailable = true;
        }

        if (!g_shellRegistered)
        {
            const int registration = registerProcessExecutable("/bin/sh", &shellExecEntry);
            g_shellRegistered = (registration == 0);
        }
    }
    else
    {
        g_consoleAvailable = false;
        g_shellRegistered = false;
    }

    const bool posixReady = g_posixUtilitiesRegistered;
    const bool prerequisitesMet = shellState.compilerAccessible && shellState.runtimeBound && posixReady;
    const bool consoleReady = g_consoleAvailable && g_shellRegistered;

    if (prerequisitesMet && consoleReady)
    {
        shellState.shellActivated = true;
        shellState.failureReason = null;
        printStatus("[shell] Activation        : ", "ready", "");
    }
    else
    {
        shellState.shellActivated = false;

        immutable(char)[] reason = shellState.failureReason;
        if (reason is null || reason.length == 0)
        {
            if (!prerequisitesMet)
            {
                if (!shellState.compilerAccessible || !shellState.runtimeBound)
                {
                    reason = "integration prerequisites missing";
                }
                else if (!posixReady)
                {
                    reason = "POSIX utilities unavailable";
                }
                else
                {
                    reason = "integration prerequisites missing";
                }
            }
            else if (!g_consoleAvailable)
            {
                reason = "console unavailable";
            }
            else if (!g_shellRegistered)
            {
                reason = "shell executable not registered";
            }
            else
            {
                reason = "shell activation blocked";
            }

            shellState.failureReason = reason;
        }

        printStatus("[shell] Activation        : ", "blocked", "");
        printStatus("[shell] Failure reason    : ", reason, "");
    }
}

/*******************************************************
 * POSIX-in-Kernel Shim (minimal, freestanding, D)
 * Drop-in: implements basic types, errno, proc table,
 *          fork/execve/waitpid/exit/getpid/kill/sleep,
 *          and stubs for open/read/write/close.
 *******************************************************/
mixin template PosixKernelShim()
{
    // ---- Basic types (avoid druntime) ----
    alias pid_t   = int;
    alias uid_t   = uint;
    alias gid_t   = uint;
    alias ssize_t = long;
    alias size_t  = ulong;
    alias time_t  = long;

    struct timespec { time_t tv_sec; long tv_nsec; }

    // ---- errno ----
    enum Errno : int {
        EPERM=1, ENOENT=2, ESRCH=3, EINTR=4, EIO=5, ENXIO=6, E2BIG=7, ENOEXEC=8, EBADF=9,
        ECHILD=10, EAGAIN=11, ENOMEM=12, EACCES=13, EFAULT=14, EBUSY=16, EEXIST=17,
        EXDEV=18, ENODEV=19, ENOTDIR=20, EISDIR=21, EINVAL=22, ENFILE=23, EMFILE=24,
        ENOSPC=28, EPIPE=32, EDOM=33, ERANGE=34, ENOSYS=38
    }
    private __gshared int _errno;

    // NOTE: remove @safe; accessing __gshared is not @safe
    @nogc nothrow ref int errnoRef() { return _errno; }
    @nogc nothrow int  setErrno(Errno e){ _errno = e; return -cast(int)e; }

    // ---- Signals (minimal) ----
    enum SIG : int { NONE=0, TERM=15, KILL=9, CHLD=17 }
    alias SigSet = uint;

    // ---- File descriptor stub ----
    enum MAX_FD = 32;
    enum FDFlags : uint { NONE=0 }
    struct FD { int num = -1; FDFlags flags = FDFlags.NONE; }

    // ---- Process table ----
    enum MAX_PROC = 64;

    enum ProcState : ubyte { UNUSED, EMBRYO, READY, RUNNING, SLEEPING, ZOMBIE }

    private struct EnvironmentTable;

    struct Proc {
        pid_t     pid;
        pid_t     ppid;
        ProcState state;
        int       exitCode;
        SigSet    sigmask;
        FD[MAX_FD] fds;
        // Make entry @nogc so sys_execve (also @nogc) can call it
        extern(C) @nogc nothrow void function(const(char*)* argv, const(char*)* envp) entry;
        void*     ctx;    // arch context (opaque to shim)
        void*     kstack; // optional kernel stack
        char[16]  name;
        const(char*)* pendingArgv; // pointer to array of const char*
        const(char*)* pendingEnvp;
        bool          pendingExec;
        size_t        objectId;
        EnvironmentTable* environment;
    }

    private __gshared Proc[MAX_PROC] g_ptable;
    private __gshared pid_t          g_nextPid    = 1;
    private __gshared Proc*          g_current    = null;
    private __gshared bool           g_initialized = false;

    // ---- Object registry ----
    enum KernelObjectKind : ubyte
    {
        Invalid,
        Namespace,
        Executable,
        Process,
        Device,
        Environment,
        Channel,
    }

    private enum MAX_KERNEL_OBJECTS = 256;
    private enum MAX_OBJECT_NAME    = 48;
    private enum MAX_OBJECT_LABEL   = 64;
    private enum MAX_OBJECT_CHILDREN = 8;
    private enum size_t INVALID_OBJECT_ID = size_t.max;

    private struct KernelObject
    {
        bool used;
        KernelObjectKind kind;
        size_t parent;
        size_t childCount;
        size_t[MAX_OBJECT_CHILDREN] children;
        char[MAX_OBJECT_NAME] name;
        char[MAX_OBJECT_NAME] type;
        char[MAX_OBJECT_LABEL] label;
        long primary;
        long secondary;
    }

    private __gshared KernelObject[MAX_KERNEL_OBJECTS] g_objects;
    private __gshared size_t g_objectCount = 0;
    private __gshared bool   g_objectRegistryReady = false;
    private __gshared size_t g_objectRoot = INVALID_OBJECT_ID;
    private __gshared size_t g_objectProcNamespace = INVALID_OBJECT_ID;
    private __gshared size_t g_objectBinNamespace  = INVALID_OBJECT_ID;
    private __gshared size_t g_objectDevNamespace  = INVALID_OBJECT_ID;
    private __gshared size_t g_consoleObject       = INVALID_OBJECT_ID;

    private enum MAX_ENV_ENTRIES        = 64;
    private enum MAX_ENV_NAME_LENGTH    = 64;
    private enum MAX_ENV_VALUE_LENGTH   = 256;
    private enum MAX_ENV_COMBINED_LENGTH = MAX_ENV_NAME_LENGTH + 1 + MAX_ENV_VALUE_LENGTH;

    private struct EnvironmentEntry
    {
        bool used;
        size_t nameLength;
        size_t valueLength;
        size_t combinedLength;
        bool dirty;
        char[MAX_ENV_NAME_LENGTH] name;
        char[MAX_ENV_VALUE_LENGTH] value;
        char[MAX_ENV_COMBINED_LENGTH] combined;
    }

    private struct EnvironmentTable
    {
        bool used;
        pid_t ownerPid;
        size_t objectId;
        size_t entryCount;
        EnvironmentEntry[MAX_ENV_ENTRIES] entries;
        char*[MAX_ENV_ENTRIES + 1] pointerCache;
        size_t pointerCount;
        bool pointerDirty;
    }

    private __gshared EnvironmentTable[MAX_PROC] g_environmentTables;

    @nogc nothrow private void clearBuffer(ref char[MAX_OBJECT_NAME] buffer)
    {
        foreach (i; 0 .. buffer.length)
        {
            buffer[i] = 0;
        }
    }

    @nogc nothrow private void clearLabel(ref char[MAX_OBJECT_LABEL] buffer)
    {
        foreach (i; 0 .. buffer.length)
        {
            buffer[i] = 0;
        }
    }

    @nogc nothrow private void copyBuffer(ref char[MAX_OBJECT_NAME] dst, ref char[MAX_OBJECT_NAME] src)
    {
        foreach (i; 0 .. dst.length)
        {
            dst[i] = (i < src.length) ? src[i] : 0;
        }
    }

    @nogc nothrow private void setBufferFromString(ref char[MAX_OBJECT_NAME] buffer, immutable(char)[] text)
    {
        size_t index = 0;
        foreach (ch; text)
        {
            if (index + 1 >= buffer.length)
            {
                break;
            }

            buffer[index] = cast(char)ch;
            ++index;
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private void setLabelFromString(ref char[MAX_OBJECT_LABEL] buffer, immutable(char)[] text)
    {
        size_t index = 0;
        foreach (ch; text)
        {
            if (index + 1 >= buffer.length)
            {
                break;
            }

            buffer[index] = cast(char)ch;
            ++index;
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private void setBufferFromCString(ref char[MAX_OBJECT_NAME] buffer, const char* text)
    {
        size_t index = 0;
        if (text !is null)
        {
            while (text[index] != 0)
            {
                if (index + 1 >= buffer.length)
                {
                    break;
                }

                buffer[index] = text[index];
                ++index;
            }
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private void setLabelFromCString(ref char[MAX_OBJECT_LABEL] buffer, const char* text)
    {
        size_t index = 0;
        if (text !is null)
        {
            while (text[index] != 0)
            {
                if (index + 1 >= buffer.length)
                {
                    break;
                }

                buffer[index] = text[index];
                ++index;
            }
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private size_t bufferLength(ref char[MAX_OBJECT_NAME] buffer)
    {
        size_t index = 0;
        while (index < buffer.length && buffer[index] != 0)
        {
            ++index;
        }
        return index;
    }

    @nogc nothrow private void appendUnsigned(ref char[MAX_OBJECT_NAME] buffer, size_t value)
    {
        char[20] digits;
        size_t count = 0;
        do
        {
            digits[count] = cast(char)('0' + (value % 10));
            value /= 10;
            ++count;
        }
        while (value != 0 && count < digits.length);

        size_t index = bufferLength(buffer);
        while (count > 0 && index + 1 < buffer.length)
        {
            --count;
            buffer[index] = digits[count];
            ++index;
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private size_t allocateObjectSlot()
    {
        foreach (i, ref objectRef; g_objects)
        {
            if (!objectRef.used)
            {
                return i;
            }
        }

        return INVALID_OBJECT_ID;
    }

    @nogc nothrow private bool isValidObject(size_t index)
    {
        return index != INVALID_OBJECT_ID && index < g_objects.length && g_objects[index].used;
    }

    @nogc nothrow private bool isProcessObject(size_t index)
    {
        return isValidObject(index) && g_objects[index].kind == KernelObjectKind.Process;
    }

    @nogc nothrow private bool buffersEqual(ref char[MAX_OBJECT_NAME] lhs, ref char[MAX_OBJECT_NAME] rhs)
    {
        foreach (i; 0 .. lhs.length)
        {
            if (lhs[i] != rhs[i])
            {
                return false;
            }

            if (lhs[i] == 0)
            {
                return true;
            }
        }

        return true;
    }

    @nogc nothrow private size_t createObjectFromBuffer(KernelObjectKind kind, ref char[MAX_OBJECT_NAME] name, immutable(char)[] type, size_t parent, long primary = 0, long secondary = 0)
    {
        const size_t slot = allocateObjectSlot();
        if (slot == INVALID_OBJECT_ID)
        {
            return INVALID_OBJECT_ID;
        }

        auto obj = &g_objects[slot];
        *obj = KernelObject.init;
        obj.used = true;
        obj.kind = kind;
        obj.parent = parent;
        obj.childCount = 0;
        obj.primary = primary;
        obj.secondary = secondary;
        copyBuffer(obj.name, name);
        setBufferFromString(obj.type, type);
        clearLabel(obj.label);

        if (isValidObject(parent))
        {
            auto parentObj = &g_objects[parent];
            if (parentObj.childCount < parentObj.children.length)
            {
                parentObj.children[parentObj.childCount] = slot;
                ++parentObj.childCount;
            }
        }

        if (g_objectCount < size_t.max)
        {
            ++g_objectCount;
        }

        return slot;
    }

    @nogc nothrow private size_t createObjectLiteral(KernelObjectKind kind, immutable(char)[] name, immutable(char)[] type, size_t parent, long primary = 0, long secondary = 0)
    {
        char[MAX_OBJECT_NAME] buffer;
        clearBuffer(buffer);
        setBufferFromString(buffer, name);
        return createObjectFromBuffer(kind, buffer, type, parent, primary, secondary);
    }

    @nogc nothrow private void detachChild(size_t parent, size_t child)
    {
        if (!isValidObject(parent))
        {
            return;
        }

        auto parentObj = &g_objects[parent];
        foreach (i; 0 .. parentObj.childCount)
        {
            if (parentObj.children[i] == child)
            {
                size_t index = i;
                while (index + 1 < parentObj.childCount)
                {
                    parentObj.children[index] = parentObj.children[index + 1];
                    ++index;
                }
                if (parentObj.childCount > 0)
                {
                    --parentObj.childCount;
                }
                if (parentObj.childCount < parentObj.children.length)
                {
                    parentObj.children[parentObj.childCount] = INVALID_OBJECT_ID;
                }
                return;
            }
        }
    }

    @nogc nothrow private void destroyObject(size_t index)
    {
        if (!isValidObject(index))
        {
            return;
        }

        auto obj = &g_objects[index];
        auto parent = obj.parent;
        if (isValidObject(parent))
        {
            detachChild(parent, index);
        }

        *obj = KernelObject.init;
        if (g_objectCount > 0)
        {
            --g_objectCount;
        }
    }

    @nogc nothrow private void setObjectLabelLiteral(size_t objectId, immutable(char)[] label)
    {
        if (!isValidObject(objectId))
        {
            return;
        }

        setLabelFromString(g_objects[objectId].label, label);
    }

    @nogc nothrow private void setObjectLabelCString(size_t objectId, const char* label)
    {
        if (!isValidObject(objectId))
        {
            return;
        }

        setLabelFromCString(g_objects[objectId].label, label);
    }

    @nogc nothrow private size_t findChildByBuffer(size_t parent, ref char[MAX_OBJECT_NAME] name)
    {
        if (!isValidObject(parent))
        {
            return INVALID_OBJECT_ID;
        }

        auto parentObj = &g_objects[parent];
        foreach (i; 0 .. parentObj.childCount)
        {
            size_t childIndex = parentObj.children[i];
            if (!isValidObject(childIndex))
            {
                continue;
            }

            if (buffersEqual(g_objects[childIndex].name, name))
            {
                return childIndex;
            }
        }

        return INVALID_OBJECT_ID;
    }

    @nogc nothrow private void setBufferFromSlice(ref char[MAX_OBJECT_NAME] buffer, const char* slice, size_t length)
    {
        size_t index = 0;
        while (index < length && index + 1 < buffer.length)
        {
            buffer[index] = slice[index];
            ++index;
        }

        if (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }

        while (index < buffer.length)
        {
            buffer[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private size_t ensureNamespaceChild(size_t parent, const char* name, size_t length)
    {
        char[MAX_OBJECT_NAME] segment;
        clearBuffer(segment);
        setBufferFromSlice(segment, name, length);

        auto existing = findChildByBuffer(parent, segment);
        if (existing != INVALID_OBJECT_ID)
        {
            return existing;
        }

        return createObjectFromBuffer(KernelObjectKind.Namespace, segment, "namespace", parent);
    }

    @nogc nothrow private size_t ensureExecutableObject(size_t parent, const char* name, size_t length, size_t slotIndex)
    {
        char[MAX_OBJECT_NAME] segment;
        clearBuffer(segment);
        setBufferFromSlice(segment, name, length);

        auto existing = findChildByBuffer(parent, segment);
        if (existing != INVALID_OBJECT_ID)
        {
            if (isValidObject(existing))
            {
                g_objects[existing].primary = cast(long)slotIndex;
            }
            return existing;
        }

        auto created = createObjectFromBuffer(KernelObjectKind.Executable, segment, "posix.utility", parent, cast(long)slotIndex);
        if (isValidObject(created))
        {
            setObjectLabelCString(created, segment.ptr);
        }
        return created;
    }

    @nogc nothrow private size_t registerExecutableObject(const char* path, size_t slotIndex)
    {
        if (!g_objectRegistryReady || path is null || path[0] == 0)
        {
            return INVALID_OBJECT_ID;
        }

        size_t parent = g_objectRoot;
        size_t index = 0;

        while (path[index] != 0)
        {
            while (path[index] == '/')
            {
                ++index;
            }

            if (path[index] == 0)
            {
                break;
            }

            const size_t start = index;
            while (path[index] != 0 && path[index] != '/')
            {
                ++index;
            }

            const size_t length = index - start;
            if (length == 0)
            {
                continue;
            }

            const bool isLast = (path[index] == 0);
            if (!isLast)
            {
                parent = ensureNamespaceChild(parent, path + start, length);
            }
            else
            {
                parent = ensureExecutableObject(parent, path + start, length, slotIndex);
            }

            if (parent == INVALID_OBJECT_ID)
            {
                break;
            }
        }

        return parent;
    }

    @nogc nothrow private void initializeObjectRegistry()
    {
        if (g_objectRegistryReady)
        {
            return;
        }

        foreach (ref obj; g_objects)
        {
            obj = KernelObject.init;
        }

        g_objectCount = 0;
        g_objectRoot = createObjectLiteral(KernelObjectKind.Namespace, "/", "namespace", INVALID_OBJECT_ID);
        if (!isValidObject(g_objectRoot))
        {
            return;
        }

        g_objectProcNamespace = createObjectLiteral(KernelObjectKind.Namespace, "proc", "namespace", g_objectRoot);
        g_objectBinNamespace  = createObjectLiteral(KernelObjectKind.Namespace, "bin", "namespace", g_objectRoot);
        g_objectDevNamespace  = createObjectLiteral(KernelObjectKind.Namespace, "dev", "namespace", g_objectRoot);

        if (isValidObject(g_objectDevNamespace))
        {
            g_consoleObject = createObjectLiteral(KernelObjectKind.Device, "console", "device.console", g_objectDevNamespace);
            if (isValidObject(g_consoleObject))
            {
                setObjectLabelLiteral(g_consoleObject, "text-console");
            }
        }

        g_objectRegistryReady = true;
    }

    @nogc nothrow private size_t createProcessObject(pid_t pid)
    {
        if (!g_objectRegistryReady)
        {
            return INVALID_OBJECT_ID;
        }

        char[MAX_OBJECT_NAME] name;
        clearBuffer(name);
        setBufferFromString(name, "process:");
        appendUnsigned(name, cast(size_t)pid);

        auto objectId = createObjectFromBuffer(KernelObjectKind.Process, name, "process", g_objectProcNamespace, cast(long)pid);
        if (isValidObject(objectId))
        {
            setObjectLabelLiteral(objectId, "unnamed");
        }

        return objectId;
    }

    @nogc nothrow private size_t cloneProcessObject(pid_t pid, size_t sourceObject)
    {
        auto objectId = createProcessObject(pid);
        if (isValidObject(objectId) && isValidObject(sourceObject))
        {
            setLabelFromCString(g_objects[objectId].label, g_objects[sourceObject].label.ptr);
        }
        return objectId;
    }

    @nogc nothrow private void destroyProcessObject(size_t objectId)
    {
        if (!g_objectRegistryReady)
        {
            return;
        }

        if (!isProcessObject(objectId))
        {
            return;
        }

        destroyObject(objectId);
    }

    @nogc nothrow private bool isEnvironmentObject(size_t index)
    {
        return isValidObject(index) && g_objects[index].kind == KernelObjectKind.Environment;
    }

    @nogc nothrow private size_t createEnvironmentObject(size_t processObject)
    {
        if (!g_objectRegistryReady || !isProcessObject(processObject))
        {
            return INVALID_OBJECT_ID;
        }

        char[MAX_OBJECT_NAME] name;
        clearBuffer(name);
        setBufferFromString(name, "env");

        auto objectId = createObjectFromBuffer(KernelObjectKind.Environment, name, "process.environment", processObject);
        if (isValidObject(objectId))
        {
            setObjectLabelLiteral(objectId, "environment");
        }

        return objectId;
    }

    @nogc nothrow private void destroyEnvironmentObject(size_t objectId)
    {
        if (!g_objectRegistryReady)
        {
            return;
        }

        if (!isEnvironmentObject(objectId))
        {
            return;
        }

        destroyObject(objectId);
    }

    @nogc nothrow private void clearEnvironmentEntry(ref EnvironmentEntry entry)
    {
        entry = EnvironmentEntry.init;
    }

    @nogc nothrow private void clearEnvironmentTable(EnvironmentTable* table)
    {
        if (table is null)
        {
            return;
        }

        foreach (ref entry; table.entries)
        {
            entry = EnvironmentEntry.init;
        }

        foreach (i; 0 .. table.pointerCache.length)
        {
            table.pointerCache[i] = null;
        }

        table.entryCount = 0;
        table.pointerCount = 0;
        table.pointerDirty = true;
    }

    @nogc nothrow private EnvironmentEntry* findEnvironmentEntry(EnvironmentTable* table, const char* name, size_t nameLength)
    {
        if (table is null || name is null || nameLength == 0)
        {
            return null;
        }

        foreach (ref entry; table.entries)
        {
            if (!entry.used || entry.nameLength != nameLength)
            {
                continue;
            }

            size_t index = 0;
            while (index < nameLength && entry.name[index] == name[index])
            {
                ++index;
            }

            if (index == nameLength)
            {
                return &entry;
            }
        }

        return null;
    }

    @nogc nothrow private EnvironmentEntry* allocateEnvironmentEntry(EnvironmentTable* table)
    {
        if (table is null)
        {
            return null;
        }

        foreach (ref entry; table.entries)
        {
            if (!entry.used)
            {
                entry = EnvironmentEntry.init;
                entry.used = true;
                if (table.entryCount < size_t.max)
                {
                    ++table.entryCount;
                }
                table.pointerDirty = true;
                return &entry;
            }
        }

        return null;
    }

    @nogc nothrow private bool setEnvironmentEntry(EnvironmentTable* table, const char* name, size_t nameLength, const char* value, size_t valueLength, bool overwrite = true)
    {
        if (table is null || name is null)
        {
            return false;
        }

        if (nameLength == 0 || nameLength >= MAX_ENV_NAME_LENGTH)
        {
            return false;
        }

        if (valueLength >= MAX_ENV_VALUE_LENGTH)
        {
            return false;
        }

        auto entry = findEnvironmentEntry(table, name, nameLength);
        if (entry is null)
        {
            entry = allocateEnvironmentEntry(table);
        }
        else
        {
            if (!overwrite)
            {
                return true;
            }
            table.pointerDirty = true;
        }

        if (entry is null)
        {
            return false;
        }

        entry.used = true;
        entry.nameLength = nameLength;
        entry.valueLength = valueLength;
        entry.combinedLength = 0;
        entry.dirty = true;

        foreach (i; 0 .. entry.name.length)
        {
            entry.name[i] = (i < nameLength) ? name[i] : 0;
        }

        foreach (i; 0 .. entry.value.length)
        {
            entry.value[i] = (i < valueLength) ? value[i] : 0;
        }

        foreach (i; 0 .. entry.combined.length)
        {
            entry.combined[i] = 0;
        }

        return true;
    }

    @nogc nothrow private bool unsetEnvironmentEntry(EnvironmentTable* table, const char* name, size_t nameLength)
    {
        auto entry = findEnvironmentEntry(table, name, nameLength);
        if (entry is null)
        {
            return false;
        }

        *entry = EnvironmentEntry.init;
        if (table.entryCount > 0)
        {
            --table.entryCount;
        }
        table.pointerDirty = true;
        return true;
    }

    @nogc nothrow private void refreshEnvironmentEntry(ref EnvironmentEntry entry)
    {
        if (!entry.used)
        {
            return;
        }

        size_t index = 0;
        foreach (i; 0 .. entry.nameLength)
        {
            if (index + 1 >= entry.combined.length)
            {
                break;
            }
            entry.combined[index] = entry.name[i];
            ++index;
        }

        if (index + 1 >= entry.combined.length)
        {
            entry.combined[entry.combined.length - 1] = 0;
            entry.combinedLength = entry.combined.length - 1;
            entry.dirty = false;
            return;
        }

        entry.combined[index] = '=';
        ++index;

        foreach (i; 0 .. entry.valueLength)
        {
            if (index + 1 >= entry.combined.length)
            {
                break;
            }
            entry.combined[index] = entry.value[i];
            ++index;
        }

        if (index >= entry.combined.length)
        {
            index = entry.combined.length - 1;
        }

        entry.combined[index] = 0;
        entry.combinedLength = index;
        entry.dirty = false;
    }

    @nogc nothrow private const char* environmentEntryPair(ref EnvironmentEntry entry)
    {
        if (!entry.used)
        {
            return null;
        }

        if (entry.dirty)
        {
            refreshEnvironmentEntry(entry);
        }

        return entry.combined.ptr;
    }

    @nogc nothrow private void rebuildEnvironmentPointers(EnvironmentTable* table)
    {
        if (table is null || !table.used)
        {
            return;
        }

        if (!table.pointerDirty)
        {
            return;
        }

        size_t index = 0;
        foreach (ref entry; table.entries)
        {
            if (!entry.used)
            {
                continue;
            }

            auto pair = environmentEntryPair(entry);
            if (pair is null)
            {
                continue;
            }

            if (index + 1 >= table.pointerCache.length)
            {
                break;
            }

            table.pointerCache[index] = cast(char*)pair;
            ++index;
        }

        if (index < table.pointerCache.length)
        {
            table.pointerCache[index] = null;
            ++index;
        }

        while (index < table.pointerCache.length)
        {
            table.pointerCache[index] = null;
            ++index;
        }

        table.pointerCount = (index == 0) ? 0 : index - 1;
        table.pointerDirty = false;
    }

    @nogc nothrow private EnvironmentTable* allocateEnvironmentTable(pid_t ownerPid, size_t processObject)
    {
        foreach (ref table; g_environmentTables)
        {
            if (!table.used)
            {
                table = EnvironmentTable.init;
                table.used = true;
                table.ownerPid = ownerPid;
                table.objectId = INVALID_OBJECT_ID;
                clearEnvironmentTable(&table);
                if (g_objectRegistryReady && isProcessObject(processObject))
                {
                    table.objectId = createEnvironmentObject(processObject);
                }
                return &table;
            }
        }

        return null;
    }

    @nogc nothrow private void ensureEnvironmentObject(EnvironmentTable* table, size_t processObject)
    {
        if (table is null)
        {
            return;
        }

        if (table.objectId != INVALID_OBJECT_ID)
        {
            return;
        }

        if (!g_objectRegistryReady || !isProcessObject(processObject))
        {
            return;
        }

        table.objectId = createEnvironmentObject(processObject);
    }

    @nogc nothrow private void releaseEnvironmentTable(EnvironmentTable* table)
    {
        if (table is null || !table.used)
        {
            return;
        }

        if (table.objectId != INVALID_OBJECT_ID)
        {
            destroyEnvironmentObject(table.objectId);
        }

        clearEnvironmentTable(table);
        table.used = false;
        table.ownerPid = 0;
        table.objectId = INVALID_OBJECT_ID;
    }

    @nogc nothrow private void cloneEnvironmentTable(EnvironmentTable* destination, EnvironmentTable* source)
    {
        if (destination is null)
        {
            return;
        }

        clearEnvironmentTable(destination);

        if (source is null || !source.used)
        {
            return;
        }

        foreach (ref entry; source.entries)
        {
            if (!entry.used)
            {
                continue;
            }

            setEnvironmentEntry(destination, entry.name.ptr, entry.nameLength, entry.value.ptr, entry.valueLength);
        }
    }

    @nogc nothrow private void loadEnvironmentFromVector(EnvironmentTable* table, const(char*)* envp)
    {
        if (table is null)
        {
            return;
        }

        clearEnvironmentTable(table);

        if (envp is null)
        {
            return;
        }

        size_t index = 0;
        while (envp[index] !is null)
        {
            auto kv = envp[index];
            if (kv is null)
            {
                ++index;
                continue;
            }

            size_t nameLength = 0;
            while (kv[nameLength] != 0 && kv[nameLength] != '=')
            {
                ++nameLength;
            }

            if (kv[nameLength] != '=' || nameLength == 0)
            {
                ++index;
                continue;
            }

            const char* valuePtr = kv + nameLength + 1;
            size_t valueLength = 0;
            while (valuePtr[valueLength] != 0)
            {
                ++valueLength;
            }

            setEnvironmentEntry(table, kv, nameLength, valuePtr, valueLength);
            ++index;
        }
    }

    @nogc nothrow private void loadEnvironmentFromHost(EnvironmentTable* table)
    {
        if (table is null)
        {
            return;
        }

        clearEnvironmentTable(table);

        version (Posix)
        {
            if (environ is null)
            {
                return;
            }

            int index = 0;
            while (environ[index] !is null)
            {
                auto kv = environ[index];
                if (kv is null)
                {
                    ++index;
                    continue;
                }

                size_t nameLength = 0;
                while (kv[nameLength] != 0 && kv[nameLength] != '=')
                {
                    ++nameLength;
                }

                if (kv[nameLength] != '=' || nameLength == 0)
                {
                    ++index;
                    continue;
                }

                const char* valuePtr = kv + nameLength + 1;
                size_t valueLength = 0;
                while (valuePtr[valueLength] != 0)
                {
                    ++valueLength;
                }

                setEnvironmentEntry(table, kv, nameLength, valuePtr, valueLength);
                ++index;
            }
        }
    }

    @nogc nothrow private const char** getEnvironmentVector(Proc* proc)
    {
        if (proc is null)
        {
            return null;
        }

        auto table = proc.environment;
        if (table is null || !table.used)
        {
            return null;
        }

        rebuildEnvironmentPointers(table);
        return cast(const char**)table.pointerCache.ptr;
    }

    @nogc nothrow private bool setEnvironmentValueForProcess(Proc* proc, const char* name, size_t nameLength, const char* value, size_t valueLength, bool overwrite = true)
    {
        if (proc is null)
        {
            return false;
        }

        auto table = proc.environment;
        if (table is null || !table.used)
        {
            return false;
        }

        return setEnvironmentEntry(table, name, nameLength, value, valueLength, overwrite);
    }

    @nogc nothrow private bool setEnvironmentValueForProcess(Proc* proc, const char* name, const char* value, bool overwrite = true)
    {
        if (name is null)
        {
            return false;
        }

        const size_t nameLength = cStringLength(name);
        const size_t valueLength = (value is null) ? 0 : cStringLength(value);
        return setEnvironmentValueForProcess(proc, name, nameLength, value, valueLength, overwrite);
    }

    @nogc nothrow private const char* readEnvironmentValueFromProcess(Proc* proc, const char* name, size_t nameLength)
    {
        if (proc is null)
        {
            return null;
        }

        auto table = proc.environment;
        if (table is null || !table.used)
        {
            return null;
        }

        auto entry = findEnvironmentEntry(table, name, nameLength);
        if (entry is null)
        {
            return null;
        }

        return entry.value.ptr;
    }

    @nogc nothrow private void updateProcessObjectState(ref Proc proc)
    {
        if (!g_objectRegistryReady)
        {
            return;
        }

        if (!isProcessObject(proc.objectId))
        {
            return;
        }

        g_objects[proc.objectId].secondary = cast(long)proc.state;
    }

    @nogc nothrow private void updateProcessObjectLabel(ref Proc proc, const char* label)
    {
        if (!g_objectRegistryReady)
        {
            return;
        }

        if (!isProcessObject(proc.objectId))
        {
            return;
        }

        setObjectLabelCString(proc.objectId, label);
    }

    @nogc nothrow private void updateProcessObjectLabelLiteral(ref Proc proc, immutable(char)[] label)
    {
        if (!g_objectRegistryReady)
        {
            return;
        }

        if (!isProcessObject(proc.objectId))
        {
            return;
        }

        setObjectLabelLiteral(proc.objectId, label);
    }

    @nogc nothrow private void assignProcessState(ref Proc proc, ProcState state)
    {
        proc.state = state;
        updateProcessObjectState(proc);
    }

    // ---- Executable registration ----
    private enum MAX_EXECUTABLES = 128;
    private enum EXEC_PATH_LENGTH = 64;
    private struct ExecutableSlot
    {
        bool used;
        char[EXEC_PATH_LENGTH] path;
        extern(C) @nogc nothrow void function(const char** argv, const char** envp) entry;
        size_t objectId;
    }

    private __gshared ExecutableSlot[MAX_EXECUTABLES] g_execTable;

    private enum STDIN_FILENO  = 0;
    private enum STDOUT_FILENO = 1;
    private enum STDERR_FILENO = 2;

    @nogc nothrow private bool resolveHostFd(int fd, out int hostFd)
    {
        hostFd = -1;

        if (fd < 0 || fd >= MAX_FD)
        {
            return false;
        }

        auto current = g_current;
        if (current is null)
        {
            return false;
        }

        const int resolved = current.fds[fd].num;
        if (resolved < 0)
        {
            return false;
        }

        hostFd = resolved;
        return true;
    }

    @nogc nothrow private void configureConsoleFor(ref Proc proc)
    {
        foreach (fd; 0 .. 3)
        {
            if (fd >= proc.fds.length)
            {
                break;
            }

            proc.fds[fd].num = fd;
            proc.fds[fd].flags = FDFlags.NONE;
        }
    }

    private enum EnvBool : int
    {
        unspecified,
        truthy,
        falsy,
    }

    @nogc nothrow private char asciiToLower(char value)
    {
        if (value >= 'A' && value <= 'Z')
        {
            return cast(char)(value + ('a' - 'A'));
        }

        return value;
    }

    @nogc nothrow private bool cStringEqualsIgnoreCaseLiteral(const char* lhs, immutable(char)[] rhs)
    {
        if (lhs is null)
        {
            return false;
        }

        size_t index = 0;
        for (; index < rhs.length; ++index)
        {
            const char actual = lhs[index];
            if (actual == '\0')
            {
                return false;
            }

            if (asciiToLower(actual) != asciiToLower(rhs[index]))
            {
                return false;
            }
        }

        return lhs[index] == '\0';
    }

    @nogc nothrow private const(char)* readEnvironmentVariable(const char* name)
    {
        version (Posix)
        {
            if (name is null || name[0] == '\0')
            {
                return null;
            }

            const size_t nameLength = cStringLength(name);
            if (nameLength == 0)
            {
                return null;
            }

            if (g_current !is null)
            {
                auto processValue = readEnvironmentValueFromProcess(g_current, name, nameLength);
                if (processValue !is null)
                {
                    return processValue;
                }
            }

            auto entries = environ;
            if (entries is null)
            {
                return null;
            }

            size_t index = 0;
            while (entries[index] !is null)
            {
                const char* entry = entries[index];
                size_t matchIndex = 0;
                while (matchIndex < nameLength && entry[matchIndex] == name[matchIndex])
                {
                    ++matchIndex;
                }

                if (matchIndex == nameLength && entry[matchIndex] == '=')
                {
                    return entry + nameLength + 1;
                }

                ++index;
            }

            return null;
        }
        else
        {
            return null;
        }
    }

    @nogc nothrow private EnvBool parseEnvBoolean(const char* value)
    {
        if (value is null)
        {
            return EnvBool.unspecified;
        }

        if (cStringEqualsIgnoreCaseLiteral(value, "1")
            || cStringEqualsIgnoreCaseLiteral(value, "true")
            || cStringEqualsIgnoreCaseLiteral(value, "yes")
            || cStringEqualsIgnoreCaseLiteral(value, "on")
            || cStringEqualsIgnoreCaseLiteral(value, "enable")
            || cStringEqualsIgnoreCaseLiteral(value, "enabled"))
        {
            return EnvBool.truthy;
        }

        if (cStringEqualsIgnoreCaseLiteral(value, "0")
            || cStringEqualsIgnoreCaseLiteral(value, "false")
            || cStringEqualsIgnoreCaseLiteral(value, "no")
            || cStringEqualsIgnoreCaseLiteral(value, "off")
            || cStringEqualsIgnoreCaseLiteral(value, "disable")
            || cStringEqualsIgnoreCaseLiteral(value, "disabled"))
        {
            return EnvBool.falsy;
        }

        return EnvBool.unspecified;
    }

    @nogc nothrow private bool detectConsoleAvailability()
    {
        const EnvBool assumeConsole = parseEnvBoolean(readEnvironmentVariable("SH_ASSUME_CONSOLE"));
        if (assumeConsole == EnvBool.truthy)
        {
            return true;
        }
        else if (assumeConsole == EnvBool.falsy)
        {
            return false;
        }

        const EnvBool disableConsole = parseEnvBoolean(readEnvironmentVariable("SH_DISABLE_CONSOLE"));
        if (disableConsole == EnvBool.truthy)
        {
            return false;
        }

        version (Posix)
        {
            // Treat the console as available if any of the standard streams are
            // attached to a TTY.  When the ISO is booted under some hypervisors
            // (for example QEMU with `-serial stdio`), the host may only expose a
            // writable TTY on stdout/stderr while stdin is reported as a pipe.
            // Checking all three descriptors avoids spuriously disabling the
            // interactive shell in those environments.
            return (isatty(STDIN_FILENO) != 0)
                || (isatty(STDOUT_FILENO) != 0)
                || (isatty(STDERR_FILENO) != 0);
        }
        else
        {
            return false;
        }
    }

    // ---- Simple spinlock (stub; replace with real lock in SMP) ----
    private struct Spin { int v; }
    private __gshared Spin g_plock;
    @nogc nothrow private void lock(Spin* /*s*/){ /* UP stub */ }
    @nogc nothrow private void unlock(Spin* /*s*/){}

    // ---- Arch switch hook (single no-op stub; replace in your arch code)
    extern(C) @nogc nothrow void arch_context_switch(Proc* /*oldp*/, Proc* /*newp*/) { /* no-op */ }

    // ---- Helpers ----
    @nogc nothrow private size_t cStringLength(const char* str)
    {
        if (str is null)
        {
            return 0;
        }

        size_t length = 0;
        while (str[length] != 0)
        {
            ++length;
        }

        return length;
    }

    @nogc nothrow private bool cStringEquals(const char* lhs, const char* rhs)
    {
        if (lhs is null || rhs is null)
        {
            return false;
        }

        size_t index = 0;
        for (;;)
        {
            const char a = lhs[index];
            const char b = rhs[index];
            if (a != b)
            {
                return false;
            }

            if (a == 0)
            {
                return true;
            }

            ++index;
        }
    }

    @nogc nothrow private void clearName(ref char[16] name)
    {
        foreach (i; 0 .. name.length)
        {
            name[i] = 0;
        }
    }

    @nogc nothrow private void setNameFromCString(ref char[16] name, const char* source)
    {
        size_t index = 0;

        if (source !is null)
        {
            while (index < name.length - 1)
            {
                const char value = source[index];
                name[index] = value;
                ++index;

                if (value == 0)
                {
                    break;
                }
            }
        }

        if (index >= name.length)
        {
            index = name.length - 1;
        }

        if (name[index] != 0)
        {
            name[index] = 0;
            ++index;
        }

        while (index < name.length)
        {
            name[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private void setNameFromLiteral(ref char[16] name, immutable(char)[] literal)
    {
        size_t index = 0;
        immutable size_t limit = name.length - 1;

        foreach (ch; literal)
        {
            if (index >= limit)
            {
                break;
            }

            name[index] = cast(char)ch;
            ++index;
        }

        if (index <= limit)
        {
            name[index] = 0;
            ++index;
        }

        while (index < name.length)
        {
            name[index] = 0;
            ++index;
        }
    }

    @nogc nothrow private ExecutableSlot* findExecutableSlot(const char* path)
    {
        if (path is null)
        {
            return null;
        }

        foreach (ref slot; g_execTable)
        {
            if (slot.used && cStringEquals(slot.path.ptr, path))
            {
                return &slot;
            }
        }

        return null;
    }

    @nogc nothrow private size_t indexOfExecutableSlot(ExecutableSlot* slot)
    {
        if (slot is null)
        {
            return INVALID_OBJECT_ID;
        }

        foreach (i, ref candidate; g_execTable)
        {
            if ((&candidate) is slot)
            {
                return i;
            }
        }

        return INVALID_OBJECT_ID;
    }

    @nogc nothrow private int encodeExitStatus(int code)
    {
        return (code & 0xFF) << 8;
    }

    @nogc nothrow private int encodeSignalStatus(int sig)
    {
        return (sig & 0x7F) | 0x80;
    }

    // ---- Utility ----
    @nogc nothrow private Proc* findByPid(pid_t pid){
        foreach(ref p; g_ptable) if(p.state!=ProcState.UNUSED && p.pid==pid) return &p;
        return null;
    }
    @nogc nothrow private Proc* allocProc(){
        foreach (ref p; g_ptable) {
            if (p.state == ProcState.UNUSED) {
                resetProc(p);
                p.pid = g_nextPid++;
                p.objectId = createProcessObject(p.pid);
                p.environment = allocateEnvironmentTable(p.pid, p.objectId);
                if (p.environment !is null)
                {
                    ensureEnvironmentObject(p.environment, p.objectId);
                }
                assignProcessState(p, ProcState.EMBRYO);
                return &p;
            }
        }
        return null;
    }

    // ---- Very small round-robin scheduler ----
    @nogc nothrow void schedYield(){
        if(!g_initialized) return;
        if(g_current is null) {
            foreach(ref p; g_ptable){
                if(p.state==ProcState.READY){ g_current = &p; assignProcessState(p, ProcState.RUNNING); break; }
            }
            return;
        }
        lock(&g_plock);
        Proc* oldp = g_current;
        if(oldp.state==ProcState.RUNNING) assignProcessState(*oldp, ProcState.READY);

        size_t idx=0;
        foreach(i, ref p; g_ptable) if((&p) is oldp){ idx=i; break; }
        Proc* next = null;
        foreach(j; 1..MAX_PROC+1){
            auto k = (idx + j) % MAX_PROC;
            if(g_ptable[k].state==ProcState.READY){ next = &g_ptable[k]; break; }
        }
        if(next is null) {
            if(oldp.state!=ProcState.ZOMBIE){ assignProcessState(*oldp, ProcState.RUNNING); unlock(&g_plock); return; }
            foreach(ref p; g_ptable){
                if(p.state==ProcState.READY){ next=&p; break; }
            }
        }
        if(next !is null){
            assignProcessState(*next, ProcState.RUNNING);
            g_current  = next;
            arch_context_switch(oldp, next);
        }
        unlock(&g_plock);
    }

    // ---- POSIX core syscalls (kernel-side) ----
    @nogc nothrow pid_t sys_getpid(){
        return (g_current is null) ? 0 : g_current.pid;
    }

    @nogc nothrow pid_t sys_fork(){
        lock(&g_plock);
        auto np = allocProc();
        if(np is null){ unlock(&g_plock); return setErrno(Errno.EAGAIN); }

        // Duplicate minimal PCB
        np.ppid   = (g_current ? g_current.pid : 0);
        assignProcessState(*np, ProcState.READY);
        np.sigmask= 0;
        np.entry  = (g_current ? g_current.entry : null);
        if (g_current && g_objectRegistryReady && isProcessObject(np.objectId) && isProcessObject(g_current.objectId))
        {
            setObjectLabelCString(np.objectId, g_objects[g_current.objectId].label.ptr);
        }
        if (g_current)
        {
            foreach (i; 0 .. np.fds.length)
            {
                np.fds[i] = g_current.fds[i];
            }
            np.pendingArgv = g_current.pendingArgv;
            np.pendingEnvp = g_current.pendingEnvp;
            np.pendingExec = g_current.pendingExec;
            if (np.environment !is null)
            {
                cloneEnvironmentTable(np.environment, g_current.environment);
                ensureEnvironmentObject(np.environment, np.objectId);
            }
        }
        else if (np.environment !is null)
        {
            clearEnvironmentTable(np.environment);
            ensureEnvironmentObject(np.environment, np.objectId);
        }
        // copy name best-effort
        foreach(i; 0 .. np.name.length) np.name[i] = 0;
        if(g_current) {
            import core.stdc.string : strncpy;
            // Not all kernels have C lib; if not, leave zeros or copy manually
            // Manual copy:
            foreach(i; 0 .. np.name.length) {
                if(i < g_current.name.length) np.name[i] = g_current.name[i];
            }
        }
        unlock(&g_plock);
        return np.pid; // parent gets child's pid
    }

    @nogc nothrow int sys_execve(const char* path, const(char*)* argv, const(char*)* envp)
    {
        // require a current process
        if (g_current is null) return setErrno(Errno.ESRCH);

        // work on a local we can change instead of reassigning the parameter
        const(char)* execPath = path;

        // resolve by path, or fall back to argv[0]
        auto resolved = findExecutableSlot(execPath);
        if (resolved is null && argv !is null && argv[0] !is null) {
            resolved = findExecutableSlot(argv[0]);
            if (resolved !is null) execPath = argv[0];
        }
        if (resolved is null) return setErrno(Errno.ENOENT);
        if (resolved.entry is null) return setErrno(Errno.ENOEXEC);

        // set up current proc and run
        auto cur = g_current;                // pointer to Proc
        (*cur).entry = resolved.entry;
        setNameFromCString((*cur).name, execPath);
        updateProcessObjectLabel(*cur, execPath);

        if (cur.environment !is null)
        {
            if (envp !is null)
            {
                loadEnvironmentFromVector(cur.environment, envp);
            }
            ensureEnvironmentObject(cur.environment, cur.objectId);
        }

        (*cur).entry(argv, envp);            // @nogc nothrow
        sys__exit(0);                        // if it ever returns
        return 0;                            // unreachable
    }



    @nogc nothrow pid_t sys_waitpid(pid_t wpid, int* status, int /*options*/){
        foreach(ref p; g_ptable){
            if(p.state==ProcState.ZOMBIE && (wpid<=0 || p.pid==wpid) && p.ppid==(g_current?g_current.pid:0)){
                if(status) *status = p.exitCode;
                auto pid = p.pid;
                resetProc(p);
                return pid;
            }
        }
        return setErrno(Errno.ECHILD);
    }

    @nogc nothrow void sys__exit(int code){
        if(g_current is null) return;
        g_current.exitCode = encodeExitStatus(code);
        assignProcessState(*g_current, ProcState.ZOMBIE);
        schedYield();
        for(;;){} // shouldn't resume
    }

    @nogc nothrow int sys_kill(pid_t pid, int sig){
        auto p = findByPid(pid);
        if(p is null) return setErrno(Errno.ESRCH);
        // non-final switch to avoid covering all enum members
        switch(sig){
            case SIG.KILL, SIG.TERM:
                p.exitCode = encodeSignalStatus(sig);
                assignProcessState(*p, ProcState.ZOMBIE);
                return 0;
            default:
                return setErrno(Errno.ENOSYS);
        }
    }

    // Naive sleep: cooperatively yield
    @nogc nothrow uint sys_sleep(uint seconds){
        foreach(_; 0 .. seconds * 100) { schedYield(); }
        return 0;
    }

    // ---- FD/IO syscalls (stubs) ----
    @nogc nothrow int     sys_open (const char* /*path*/, int /*flags*/, int /*mode*/){ return setErrno(Errno.ENOSYS); }
    @nogc nothrow int     sys_close(int /*fd*/){ return setErrno(Errno.ENOSYS); }
    @nogc nothrow ssize_t sys_read (int fd, void* buffer, size_t length)
    {
        int hostFd = -1;
        if (!resolveHostFd(fd, hostFd))
        {
            return cast(ssize_t)setErrno(Errno.EBADF);
        }

        version (Posix)
        {
            auto result = read(hostFd, buffer, length);
            if (result < 0)
            {
                _errno = errno;
                return -1;
            }

            return cast(ssize_t)result;
        }
        else
        {
            return cast(ssize_t)setErrno(Errno.ENOSYS);
        }
    }

    @nogc nothrow ssize_t sys_write(int fd, const void* buffer, size_t length)
    {
        int hostFd = -1;
        if (!resolveHostFd(fd, hostFd))
        {
            return cast(ssize_t)setErrno(Errno.EBADF);
        }

        version (Posix)
        {
            auto result = write(hostFd, buffer, length);
            if (result < 0)
            {
                _errno = errno;
                return -1;
            }

            return cast(ssize_t)result;
        }
        else
        {
            return cast(ssize_t)setErrno(Errno.ENOSYS);
        }
    }

    // ---- C ABI glue ----
    extern(C):
    @nogc nothrow pid_t getpid(){ return sys_getpid(); }
    @nogc nothrow pid_t fork(){   return sys_fork();   }
    @nogc nothrow int   execve(const char* p, const char** a, const char** e){ return sys_execve(p,a,e); }
    @nogc nothrow pid_t waitpid(pid_t p, int* s, int o){ return sys_waitpid(p,s,o); }
    @nogc nothrow void  _exit(int c){ sys__exit(c); }
    @nogc nothrow int   kill(pid_t p, int s){ return sys_kill(p,s); }
    @nogc nothrow uint  sleep(uint s){ return sys_sleep(s); }

    // Optional weak-ish symbols for linkage expectations
    __gshared const char** environ;
    __gshared const char** __argv;
    __gshared int          __argc;

    struct ProcessInfo
    {
        pid_t pid;
        pid_t ppid;
        ubyte state;
        char[16] name;
    }

    alias ProcessEntry = extern(C) @nogc nothrow void function(const char** argv, const char** envp);

    @nogc nothrow int registerProcessExecutable(const char* path, ProcessEntry entry)
    {
        if(path is null || entry is null)
        {
            return setErrno(Errno.EINVAL);
        }

        const size_t length = cStringLength(path);
        if(length == 0 || length >= EXEC_PATH_LENGTH)
        {
            return setErrno(Errno.E2BIG);
        }

        auto existing = findExecutableSlot(path);
        if(existing !is null)
        {
            existing.entry = entry;
            if (g_objectRegistryReady)
            {
                const size_t slotIndex = indexOfExecutableSlot(existing);
                if (slotIndex != INVALID_OBJECT_ID)
                {
                    auto objectId = registerExecutableObject(existing.path.ptr, slotIndex);
                    if (objectId != INVALID_OBJECT_ID)
                    {
                        existing.objectId = objectId;
                    }
                }
            }
            return 0;
        }

        foreach(slotIndex, ref slot; g_execTable)
        {
            if(!slot.used)
            {
                slot = ExecutableSlot.init;
                slot.used = true;
                foreach(j; 0 .. slot.path.length) slot.path[j] = 0;
                foreach(j; 0 .. length)
                {
                    slot.path[j] = path[j];
                }
                slot.path[length] = '\0';
                slot.entry = entry;
                slot.objectId = INVALID_OBJECT_ID;
                if (g_objectRegistryReady)
                {
                    auto objectId = registerExecutableObject(slot.path.ptr, slotIndex);
                    if (objectId != INVALID_OBJECT_ID)
                    {
                        slot.objectId = objectId;
                    }
                }
                return 0;
            }
        }

        return setErrno(Errno.ENFILE);
    }

    @nogc nothrow pid_t spawnRegisteredProcess(const char* path, const char** argv, const char** envp)
    {
        auto slot = findExecutableSlot(path);
        if(slot is null)
        {
            return setErrno(Errno.ENOENT);
        }

        lock(&g_plock);
        auto proc = allocProc();
        if(proc is null)
        {
            unlock(&g_plock);
            return setErrno(Errno.EAGAIN);
        }

        proc.ppid   = (g_current ? g_current.pid : 0);
        assignProcessState(*proc, ProcState.READY);
        proc.entry  = slot.entry;
        proc.pendingArgv = argv;
        proc.pendingEnvp = envp;
        proc.pendingExec = true;
        setNameFromCString(proc.name, path);
        updateProcessObjectLabel(*proc, path);
        unlock(&g_plock);
        return proc.pid;
    }

    @nogc nothrow int completeProcess(pid_t pid, int exitCode)
    {
        auto proc = findByPid(pid);
        if(proc is null)
        {
            return setErrno(Errno.ESRCH);
        }

        if(proc.state==ProcState.UNUSED || proc.state==ProcState.ZOMBIE)
        {
            return setErrno(Errno.EINVAL);
        }

        proc.exitCode = encodeExitStatus(exitCode);
        assignProcessState(*proc, ProcState.ZOMBIE);
        proc.pendingArgv = null;
        proc.pendingEnvp = null;
        proc.pendingExec = false;
        return 0;
    }

    @nogc nothrow size_t listProcesses(ProcessInfo* buffer, size_t capacity)
    {
        if(buffer is null || capacity == 0)
        {
            return 0;
        }

        size_t count = 0;
        foreach(ref proc; g_ptable)
        {
            if(proc.state == ProcState.UNUSED)
            {
                continue;
            }

            if(count >= capacity)
            {
                break;
            }

            buffer[count].pid   = proc.pid;
            buffer[count].ppid  = proc.ppid;
            buffer[count].state = cast(ubyte)proc.state;
            foreach(i; 0 .. buffer[count].name.length)
            {
                buffer[count].name[i] = proc.name[i];
            }

            ++count;
        }

        return count;
    }

    // ---- Init hook ----
    @nogc nothrow void posixInit(){
        if(g_initialized) return;
        initializeObjectRegistry();
        foreach(ref p; g_ptable) resetProc(p);
        foreach(ref slot; g_execTable)
        {
            slot = ExecutableSlot.init;
            slot.objectId = INVALID_OBJECT_ID;
        }
        g_nextPid = 1;
        g_current = null;
        g_posixUtilitiesRegistered = false;
        g_posixUtilityCount = 0;
        auto initProc = allocProc();
        if(initProc !is null)
        {
            initProc.ppid  = 0;
            assignProcessState(*initProc, ProcState.RUNNING);
            setNameFromLiteral(initProc.name, "kernel");
            updateProcessObjectLabelLiteral(*initProc, "kernel");
            initProc.pendingArgv = null;
            initProc.pendingEnvp = null;
            initProc.pendingExec = false;
            g_current = initProc;
            if (initProc.environment !is null)
            {
                loadEnvironmentFromHost(initProc.environment);
                ensureEnvironmentObject(initProc.environment, initProc.objectId);
            }
            g_consoleAvailable = detectConsoleAvailability();
            configureConsoleFor(*initProc);
        }
        else
        {
            g_consoleAvailable = detectConsoleAvailability();
        }

        g_shellRegistered = false;
        if (g_consoleAvailable)
        {
            const int registration = registerProcessExecutable("/bin/sh", &shellExecEntry);
            g_shellRegistered = (registration == 0);
        }
        g_initialized = true;
    }
}



version (Posix)
{
    private enum PATH_BUFFER_SIZE = 1024;
    private enum F_OK = 0;

    extern(C) int posix_spawnp(
        int* pid,
        const(char)* file,
        const(void)* file_actions,
        const(void)* attrp,
        char** argv,
        char** envp
    );
    extern(C) int waitpid(int pid, int* status, int options);
    extern(C) int access(const char* pathname, int mode);
    extern(C) int isatty(int fd);
    extern(C) long read(int fd, void* buffer, size_t length);
    extern(C) long write(int fd, const void* buffer, size_t length);
    extern(C) __gshared int errno;
    extern(C) int setenv(const char* name, const char* value, int overwrite);

    private bool applyEnvironmentUpdate(const char* name, size_t nameLength, const char* value, size_t valueLength, bool overwrite = true)
    {
        if (name is null || nameLength == 0)
        {
            return false;
        }

        if (setenv(name, value, overwrite ? 1 : 0) != 0)
        {
            return false;
        }

        if (g_current !is null)
        {
            setEnvironmentValueForProcess(g_current, name, nameLength, value, valueLength, overwrite);
        }

        return true;
    }

    private bool applyEnvironmentUpdate(const char* name, const char* value, bool overwrite = true)
    {
        if (name is null)
        {
            return false;
        }

        const size_t nameLength = cStringLength(name);
        const size_t valueLength = (value is null) ? 0 : cStringLength(value);
        return applyEnvironmentUpdate(name, nameLength, value, valueLength, overwrite);
    }

    private bool copyCString(const char* source, char* buffer, size_t bufferLength, out size_t length)
    {
        if (source is null)
        {
            length = 0;
            return false;
        }

        size_t index = 0;
        while (source[index] != '\0')
        {
            if (index + 1 >= bufferLength)
            {
                length = 0;
                return false;
            }

            buffer[index] = source[index];
            ++index;
        }

        if (index == 0)
        {
            length = 0;
            return false;
        }

        buffer[index] = '\0';
        length = index;
        return true;
    }

    private bool copyDString(immutable(char)[] source, char* buffer, size_t bufferLength, out size_t length)
    {
        if (source.length == 0)
        {
            length = 0;
            return false;
        }

        if (source.length >= bufferLength)
        {
            length = 0;
            return false;
        }

        foreach (i; 0 .. source.length)
        {
            buffer[i] = cast(char)source[i];
        }

        length = source.length;
        buffer[length] = '\0';
        return true;
    }

    private bool appendBinaryName(const char* root, size_t rootLength, char* buffer, size_t bufferLength, out size_t resultLength)
    {
        if (rootLength == 0 || rootLength >= bufferLength)
        {
            resultLength = 0;
            return false;
        }

        size_t index = 0;
        while (index < rootLength)
        {
            buffer[index] = root[index];
            ++index;
        }

        if (buffer[index - 1] != '/')
        {
            if (index + 1 >= bufferLength)
            {
                resultLength = 0;
                return false;
            }

            buffer[index] = '/';
            ++index;
        }

        foreach (i; 0 .. shellState.binaryName.length)
        {
            if (index + 1 >= bufferLength)
            {
                resultLength = 0;
                return false;
            }

            buffer[index] = cast(char)shellState.binaryName[i];
            ++index;
        }

        buffer[index] = '\0';
        resultLength = index;
        return true;
    }

    private bool fileExists(const char* path)
    {
        return access(path, F_OK) == 0;
    }

    @nogc nothrow private bool ensurePathIncludes(const char* candidate)
    {
        if (candidate is null)
        {
            return false;
        }

        const size_t candidateLength = cStringLength(candidate);
        if (candidateLength == 0)
        {
            return false;
        }

        enum PATH_NAME = "PATH\0";

        auto existing = readEnvironmentVariable("PATH");
        if (existing is null || existing[0] == '\0')
        {
            return applyEnvironmentUpdate(PATH_NAME.ptr, PATH_NAME.length - 1, candidate, candidateLength, true);
        }

        size_t index = 0;
        for (;;)
        {
            size_t start = index;
            while (existing[index] != ':' && existing[index] != '\0')
            {
                ++index;
            }

            const size_t segmentLength = index - start;
            if (segmentLength == candidateLength)
            {
                bool matches = true;
                foreach (i; 0 .. segmentLength)
                {
                    if (existing[start + i] != candidate[i])
                    {
                        matches = false;
                        break;
                    }
                }

                if (matches)
                {
                    return true;
                }
            }

            if (existing[index] == '\0')
            {
                break;
            }

            ++index;
        }

        char[PATH_BUFFER_SIZE * 2] combined;
        size_t writeIndex = 0;

        if (candidateLength >= combined.length)
        {
            return false;
        }

        foreach (i; 0 .. candidateLength)
        {
            combined[writeIndex] = candidate[i];
            ++writeIndex;
        }

        if (writeIndex + 1 >= combined.length)
        {
            return false;
        }

        combined[writeIndex] = ':';
        ++writeIndex;

        const size_t existingLength = cStringLength(existing);
        if (writeIndex + existingLength >= combined.length)
        {
            return false;
        }

        foreach (i; 0 .. existingLength)
        {
            combined[writeIndex + i] = existing[i];
        }

        writeIndex += existingLength;
        combined[writeIndex] = '\0';

        return applyEnvironmentUpdate(PATH_NAME.ptr, PATH_NAME.length - 1, combined.ptr, writeIndex, true);
    }

    @nogc nothrow private bool buildSiblingPath(
        const char* root,
        size_t rootLength,
        immutable(char)[] suffix,
        char* buffer,
        size_t bufferLength,
        out size_t resultLength)
    {
        if (root is null || buffer is null || bufferLength == 0)
        {
            resultLength = 0;
            return false;
        }

        size_t length = 0;
        while (length < rootLength && root[length] != '\0')
        {
            if (length + 1 >= bufferLength)
            {
                resultLength = 0;
                return false;
            }

            buffer[length] = root[length];
            ++length;
        }

        if (length == 0)
        {
            resultLength = 0;
            return false;
        }

        while (length > 1 && buffer[length - 1] == '/')
        {
            --length;
        }

        bool foundSlash = false;
        while (length > 0)
        {
            if (buffer[length - 1] == '/')
            {
                foundSlash = true;
                break;
            }

            --length;
        }

        if (!foundSlash)
        {
            resultLength = 0;
            return false;
        }

        size_t suffixIndex = 0;
        if (length > 0 && buffer[length - 1] == '/')
        {
            while (suffixIndex < suffix.length && suffix[suffixIndex] == '/')
            {
                ++suffixIndex;
            }
        }
        else if (suffix.length > 0 && suffix[0] != '/')
        {
            if (length + 1 >= bufferLength)
            {
                resultLength = 0;
                return false;
            }

            buffer[length] = '/';
            ++length;
        }

        while (suffixIndex < suffix.length)
        {
            if (length + 1 >= bufferLength)
            {
                resultLength = 0;
                return false;
            }

            buffer[length] = cast(char)suffix[suffixIndex];
            ++length;
            ++suffixIndex;
        }

        if (length >= bufferLength)
        {
            resultLength = 0;
            return false;
        }

        buffer[length] = '\0';
        resultLength = length;
        return true;
    }

    @nogc nothrow private bool configurePosixUtilities(const char* shellRoot, size_t shellLength)
    {
        if (g_posixConfigured)
        {
            return true;
        }

        enum POSIXUTILS_ROOT = "POSIXUTILS_ROOT\0";

        auto overridePath = readEnvironmentVariable("POSIXUTILS_ROOT");
        if (overridePath !is null && overridePath[0] != '\0')
        {
            const size_t overrideLength = cStringLength(overridePath);
            applyEnvironmentUpdate(POSIXUTILS_ROOT.ptr, POSIXUTILS_ROOT.length - 1, overridePath, overrideLength, true);
            if (access(overridePath, F_OK) == 0 && ensurePathIncludes(overridePath))
            {
                g_posixConfigured = true;
                print("[shell] POSIX utilities path : ");
                printCString(overridePath);
                putChar('\n');
                return true;
            }
        }

        immutable(char)[][] suffixes = [
            "/build/posixutils/bin",
            "/tools/posixutils/bin",
            "/posix/bin",
        ];

        char[PATH_BUFFER_SIZE] candidateBuffer;
        size_t candidateLength = 0;

        foreach (suffix; suffixes)
        {
            if (!buildSiblingPath(shellRoot, shellLength, suffix, candidateBuffer.ptr, candidateBuffer.length, candidateLength))
            {
                continue;
            }

            if (access(candidateBuffer.ptr, F_OK) != 0)
            {
                continue;
            }

            applyEnvironmentUpdate(POSIXUTILS_ROOT.ptr, POSIXUTILS_ROOT.length - 1, candidateBuffer.ptr, candidateLength, true);
            if (!ensurePathIncludes(candidateBuffer.ptr))
            {
                continue;
            }

            g_posixConfigured = true;
            print("[shell] POSIX utilities path : ");
            printLine(candidateBuffer[0 .. candidateLength]);
            return true;
        }

        return false;
    }

    private immutable string[] POSIX_UTILITY_PATHS = [
        "/bin/asa\0",
        "/bin/basename\0",
        "/bin/cat\0",
        "/bin/chown\0",
        "/bin/cksum\0",
        "/bin/cmp\0",
        "/bin/comm\0",
        "/bin/compress\0",
        "/bin/date\0",
        "/bin/df\0",
        "/bin/diff\0",
        "/bin/dirname\0",
        "/bin/echo\0",
        "/bin/env\0",
        "/bin/expand\0",
        "/bin/expr\0",
        "/bin/false\0",
        "/bin/getconf\0",
        "/bin/grep\0",
        "/bin/head\0",
        "/bin/id\0",
        "/bin/ipcrm\0",
        "/bin/ipcs\0",
        "/bin/kill\0",
        "/bin/link\0",
        "/bin/ln\0",
        "/bin/logger\0",
        "/bin/logname\0",
        "/bin/mesg\0",
        "/bin/mkdir\0",
        "/bin/mkfifo\0",
        "/bin/mv\0",
        "/bin/nice\0",
        "/bin/nohup\0",
        "/bin/pathchk\0",
        "/bin/pwd\0",
        "/bin/renice\0",
        "/bin/rm\0",
        "/bin/rmdir\0",
        "/bin/sleep\0",
        "/bin/sort\0",
        "/bin/split\0",
        "/bin/strings\0",
        "/bin/stty\0",
        "/bin/tabs\0",
        "/bin/tee\0",
        "/bin/time\0",
        "/bin/touch\0",
        "/bin/true\0",
        "/bin/tsort\0",
        "/bin/tty\0",
        "/bin/tput\0",
        "/bin/uname\0",
        "/bin/uniq\0",
        "/bin/unlink\0",
        "/bin/uuencode\0",
        "/bin/wc\0",
        "/bin/what\0",
    ];

    @nogc nothrow private bool ensurePosixUtilitiesConfigured()
    {
        if (g_posixConfigured)
        {
            return true;
        }

        char[PATH_BUFFER_SIZE] rootBuffer;
        size_t rootLength = 0;

        immutable(char)[][] roots = [
            shellState.repository,
            "/workspace/internetcomputer/-sh",
            "/workspace/-sh",
            "/-sh",
            "./-sh",
            "-sh",
        ];

        foreach (candidate; roots)
        {
            if (!copyDString(candidate, rootBuffer.ptr, rootBuffer.length, rootLength))
            {
                continue;
            }

            if (configurePosixUtilities(rootBuffer.ptr, rootLength))
            {
                return true;
            }
        }

        return g_posixConfigured;
    }

    @nogc nothrow private size_t countRegisteredPosixUtilities()
    {
        size_t count = 0;
        foreach (ref slot; g_execTable)
        {
            if (slot.used && slot.entry is &posixUtilityExecEntry)
            {
                ++count;
            }
        }

        return count;
    }

    @nogc nothrow private size_t registerPosixUtilities()
    {
        if (!g_objectRegistryReady)
        {
            return g_posixUtilityCount;
        }

        foreach (path; POSIX_UTILITY_PATHS)
        {
            if (path.length == 0)
            {
                continue;
            }

            registerProcessExecutable(path.ptr, &posixUtilityExecEntry);
        }

        g_posixUtilityCount = countRegisteredPosixUtilities();
        g_posixUtilitiesRegistered = (g_posixUtilityCount > 0);
        return g_posixUtilityCount;
    }

    @nogc nothrow private const(char)* extractProgramName(const char* path, char* buffer, size_t bufferLength, out size_t nameLength)
    {
        nameLength = 0;
        if (path is null || bufferLength == 0)
        {
            return null;
        }

        size_t totalLength = 0;
        while (path[totalLength] != '\0')
        {
            ++totalLength;
        }

        if (totalLength == 0)
        {
            return null;
        }

        size_t end = totalLength;
        while (end > 0 && path[end - 1] == '/')
        {
            --end;
        }

        if (end == 0)
        {
            return null;
        }

        size_t start = 0;
        foreach (i; 0 .. end)
        {
            if (path[i] == '/')
            {
                start = i + 1;
            }
        }

        if (end <= start)
        {
            return null;
        }

        nameLength = end - start;
        if (nameLength + 1 > bufferLength)
        {
            nameLength = 0;
            return null;
        }

        foreach (i; 0 .. nameLength)
        {
            buffer[i] = path[start + i];
        }
        buffer[nameLength] = '\0';

        return buffer.ptr;
    }

    private bool spawnAndWait(const(char)* program, char** argv, char** envp, int* exitStatus = null)
    {
        int pid = 0;
        char** environment = null;
        if (envp !is null)
        {
            environment = cast(char**)envp;
        }
        else
        {
            auto vector = getEnvironmentVector(g_current);
            if (vector !is null)
            {
                environment = cast(char**)vector;
            }
            else
            {
                environment = environ;
            }
        }

        const int spawnResult = posix_spawnp(&pid, program, null, null, argv, environment);
        if (spawnResult != 0)
        {
            if (exitStatus !is null)
            {
                *exitStatus = 127;
            }
            return false;
        }

        int status = 0;
        if (waitpid(pid, &status, 0) < 0)
        {
            if (exitStatus !is null)
            {
                *exitStatus = 127;
            }
            return false;
        }

        if ((status & 0x7F) != 0)
        {
            if (exitStatus !is null)
            {
                *exitStatus = 128 + (status & 0x7F);
            }
            return false;
        }

        const int exitCode = (status >> 8) & 0xFF;
        if (exitStatus !is null)
        {
            *exitStatus = exitCode;
        }
        return exitCode == 0;
    }

    private bool ensureShellBuilt(const char* rootPath)
    {
        printLine("[shell] Building 'lfe-sh' binary ...");

        char*[4] args;
        args[0] = cast(char*)"make";
        args[1] = cast(char*)"-C";
        args[2] = cast(char*)rootPath;
        args[3] = null;

        return spawnAndWait("make", args.ptr, environ);
    }

    private bool launchShellProcess(const char* binaryPath, const(char*)* argv, const(char*)* envp)
    {
        printLine("[shell] Launching interactive session ...");

        enum size_t MAX_ARGS = 16;
        char*[MAX_ARGS] args;
        size_t count = 0;

        if (argv !is null)
        {
            while (argv[count] !is null && count + 1 < args.length)
            {
                args[count] = cast(char*)argv[count];
                ++count;
            }
        }

        if (count == 0)
        {
            count = 1;
        }

        args[0] = cast(char*)binaryPath;

        if (count >= args.length)
        {
            count = args.length - 1;
        }

        args[count] = null;

        const char** vector = null;
        if (envp !is null && envp[0] !is null)
        {
            vector = envp;
        }
        else
        {
            vector = getEnvironmentVector(g_current);
        }

        char** environment = (vector !is null) ? cast(char**)vector : null;

        if (spawnAndWait(binaryPath, args.ptr, environment))
        {
            printLine("[shell] Shell session ended.");
            return true;
        }

        printLine("[shell] Failed to execute 'lfe-sh'.");
        return false;
    }

    private bool tryLaunchFromRoot(char* rootBuffer, size_t rootLength, ref bool buildCompleted, const(char*)* argv, const(char*)* envp)
    {
        if (!g_posixConfigured)
        {
            configurePosixUtilities(rootBuffer, rootLength);
        }

        char[PATH_BUFFER_SIZE] binaryBuffer;
        size_t binaryLength = 0;
        if (!appendBinaryName(rootBuffer, rootLength, binaryBuffer.ptr, binaryBuffer.length, binaryLength))
        {
            return false;
        }

        if (!fileExists(binaryBuffer.ptr))
        {
            if (!buildCompleted)
            {
                if (ensureShellBuilt(rootBuffer))
                {
                    buildCompleted = true;
                }
                else
                {
                    printLine("[shell] Build invocation failed.");
                    return false;
                }
            }

            if (!fileExists(binaryBuffer.ptr))
            {
                return false;
            }
        }

        print("[shell] Using binary at     : ");
        printLine(binaryBuffer[0 .. binaryLength]);

        return launchShellProcess(binaryBuffer.ptr, argv, envp);
    }

    private bool runHostShellSession(const(char*)* argv, const(char*)* envp)
    {
        char[PATH_BUFFER_SIZE] rootBuffer;
        size_t rootLength = 0;
        bool buildCompleted = false;

        if (copyCString(readEnvironmentVariable("SH_ROOT"), rootBuffer.ptr, rootBuffer.length, rootLength))
        {
            if (tryLaunchFromRoot(rootBuffer.ptr, rootLength, buildCompleted, argv, envp))
            {
                return true;
            }
        }

        immutable(char)[][] candidateRoots = [
            shellState.repository,
            "/workspace/internetcomputer/-sh",
            "/workspace/-sh",
            "/-sh",
            "./-sh",
            "-sh",
        ];

        foreach (candidate; candidateRoots)
        {
            if (!copyDString(candidate, rootBuffer.ptr, rootBuffer.length, rootLength))
            {
                continue;
            }

            if (tryLaunchFromRoot(rootBuffer.ptr, rootLength, buildCompleted, argv, envp))
            {
                return true;
            }
        }

        printLine("[shell] Unable to locate an executable 'lfe-sh' binary.");
        return false;
    }

    extern(C) @nogc nothrow void shellExecEntry(const char** argv, const char** envp)
    {
        const char** vector = envp;
        if ((vector is null || vector[0] is null) && g_current !is null)
        {
            vector = getEnvironmentVector(g_current);
        }
        runHostShellSession(argv, vector);
    }

    extern(C) @nogc nothrow void posixUtilityExecEntry(const char** argv, const char** envp)
    {
        enum fallbackProgram = "sh\0";

        if (!ensurePosixUtilitiesConfigured())
        {
            printLine("[shell] POSIX utilities unavailable; cannot execute request.");
            sys__exit(127);
        }

        const char* invoked = null;
        if (argv !is null && argv[0] !is null)
        {
            invoked = argv[0];
        }

        char[PATH_BUFFER_SIZE] nameBuffer;
        size_t nameLength = 0;
        auto programName = extractProgramName(invoked, nameBuffer.ptr, nameBuffer.length, nameLength);
        if (programName is null || nameLength == 0)
        {
            if (invoked !is null && invoked[0] != '\0')
            {
                programName = invoked;
            }
            else
            {
                programName = fallbackProgram.ptr;
            }
        }

        enum size_t MAX_ARGS = 16;
        char*[MAX_ARGS] args;
        size_t argCount = 0;

        args[argCount] = cast(char*)programName;
        ++argCount;

        if (argv !is null)
        {
            size_t index = (argv[0] !is null) ? 1 : 0;
            while (argv[index] !is null && argCount + 1 < args.length)
            {
                args[argCount] = cast(char*)argv[index];
                ++argCount;
                ++index;
            }
        }

        if (argCount >= args.length)
        {
            argCount = args.length - 1;
        }
        args[argCount] = null;

        const char** vector = null;
        if (envp !is null && envp[0] !is null)
        {
            vector = envp;
        }
        else
        {
            vector = getEnvironmentVector(g_current);
        }

        char** environment = (vector !is null) ? cast(char**)vector : null;

        int exitCode = 127;
        spawnAndWait(programName, args.ptr, environment, &exitCode);
        sys__exit(exitCode);
    }

    private void launchInteractiveShell()
    {
        if (!g_consoleAvailable)
        {
            printLine("[shell] Interactive console not detected; skipping shell launch.");
            return;
        }

        if (!g_shellRegistered)
        {
            printLine("[shell] Shell executable not registered; cannot launch.");
            return;
        }

        const int execResult = sys_execve("/bin/sh", g_shellDefaultArgv.ptr, g_shellDefaultEnvp.ptr);
        if (execResult < 0)
        {
            const int errValue = errnoRef();
            print("[shell] execve('/bin/sh') failed (errno = ");
            printUnsigned(cast(size_t)errValue);
            printLine(")");
            shellState.shellActivated = false;
            shellState.failureReason = "execve(/bin/sh) failed";
        }
    }
}
else
{
    private bool runHostShellSession(const(char*)* /*argv*/, const(char*)* /*envp*/)
    {
        return false;
    }

    extern(C) @nogc nothrow void shellExecEntry(const char** /*argv*/, const char** /*envp*/)
    {
        printLine("[shell] Interactive shell unavailable: host console support missing.");
    }

    extern(C) @nogc nothrow void posixUtilityExecEntry(const char** /*argv*/, const char** /*envp*/)
    {
        printLine("[shell] POSIX utilities unsupported on this target.");
    }

    private void launchInteractiveShell()
    {
        printLine("[shell] Interactive shell unavailable: host console support missing.");
    }
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

    print(" Shell repository : ");
    printLine(shellState.repository);

    print(" Shell revision   : ");
    printLine(shellState.revision);

    print(" Shell binary     : ");
    printLine(shellState.binaryName);

    print(" Shell package    : ");
    printUnsigned(shellState.binaryBytes);
    putChar('\n');

    print(" Shell commands   : ");
    printUnsigned(shellState.documentedCommandCount);
    putChar('\n');

    print(" Shell source     : ");
    printUnsigned(shellState.sourceFileCount);
    putChar('\n');

    print(" Shell ready      : ");
    if (shellState.shellActivated)
    {
        printLine("yes");
    }
    else
    {
        printLine("no");
    }

    if (!shellState.shellActivated && shellState.failureReason !is null)
    {
        print(" Shell status     : ");
        printLine(shellState.failureReason);
    }

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
    
    posixInit();
    runCompilerBuilder();
}
