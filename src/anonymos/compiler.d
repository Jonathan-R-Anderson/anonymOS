module anonymos.compiler;

import anonymos.console : print, printLine, printDivider, printStageHeader, logModuleCompilation,
    logExportValue, resetStageSummaries;

nothrow:
@nogc:

enum MAX_MODULES = 16;
enum MAX_EXPORTS_PER_MODULE = 8;
enum MAX_SYMBOLS = 128;

struct ModuleSource
{
    immutable(char)[] expectedName;
    immutable(char)[] source;
}

struct ExportSymbol
{
    immutable(char)[] name;
    long value;
}

struct CompiledModule
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

private __gshared CompiledModule[MAX_MODULES] compiledModules;
private __gshared size_t compiledModuleCount = 0;

private __gshared Symbol[MAX_SYMBOLS] globalSymbols;
private __gshared size_t globalSymbolCount = 0;

void resetCompilerState()
{
    compiledModuleCount = 0;
    globalSymbolCount = 0;
    resetStageSummaries();

    storeGlobalSymbol("builder", "bootstrap", "word_size", 8);
    storeGlobalSymbol("builder", "bootstrap", "pointer_size", 8);
    storeGlobalSymbol("builder", "bootstrap", "vector_alignment", 16);
}

const(ModuleSource)[] frontEndSources()
{
    return frontEndSourcesData[];
}

const(ModuleSource)[] optimizerSources()
{
    return optimizerSourcesData[];
}

const(ModuleSource)[] runtimeSources()
{
    return runtimeSourcesData[];
}

const(CompiledModule)[] compiledModuleData()
{
    return compiledModules[0 .. compiledModuleCount];
}

size_t getGlobalSymbolCount()
{
    return globalSymbolCount;
}

void compileStage(immutable(char)[] title, immutable(char)[] stageLabel, const ModuleSource[] sources)
{
    printStageHeader(title);

    foreach (moduleSource; sources)
    {
        compileModule(stageLabel, moduleSource);
    }
}

private void builderFatalImpl(const(char)[] stageLabel, const(char)[] unitName, const(char)[] message, const(char)[] detail)
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
        // spin forever
    }
}

extern(C) void builderFatalC(const(char)* stagePtr, size_t stageLength,
    const(char)* unitPtr, size_t unitLength,
    const(char)* messagePtr, size_t messageLength,
    const(char)* detailPtr, size_t detailLength)
{
    const(char)[] stageLabel = null;
    const(char)[] unitName = null;
    const(char)[] message = null;
    const(char)[] detail = null;

    if (stagePtr !is null && stageLength != 0)
    {
        stageLabel = stagePtr[0 .. stageLength];
    }
    if (unitPtr !is null && unitLength != 0)
    {
        unitName = unitPtr[0 .. unitLength];
    }
    if (messagePtr !is null && messageLength != 0)
    {
        message = messagePtr[0 .. messageLength];
    }
    if (detailPtr !is null && detailLength != 0)
    {
        detail = detailPtr[0 .. detailLength];
    }

    builderFatalImpl(stageLabel, unitName, message, detail);
}

void builderFatal(const(char)[] stageLabel, const(char)[] unitName, const(char)[] message, const(char)[] detail)
{
    builderFatalImpl(stageLabel, unitName, message, detail);
}

bool lookupGlobalSymbol(immutable(char)[] name, out long value)
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

    skipWhitespace(parser);

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

    skipWhitespace(parser);

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

private bool parserAtEnd(ref Parser parser)
{
    return parser.index >= parser.input.length;
}

private void skipWhitespace(ref Parser parser)
{
    while (!parserAtEnd(parser))
    {
        const char ch = parser.input[parser.index];
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
        {
            ++parser.index;
        }
        else
        {
            break;
        }
    }
}

private bool parseIdentifier(ref Parser parser, out immutable(char)[] identifier)
{
    const size_t start = parser.index;
    if (!parserAtEnd(parser) && isIdentifierStart(parser.input[parser.index]))
    {
        ++parser.index;
    }
    else
    {
        identifier = null;
        return false;
    }

    while (!parserAtEnd(parser) && isIdentifierPart(parser.input[parser.index]))
    {
        ++parser.index;
    }

    identifier = parser.input[start .. parser.index];
    return true;
}

private bool parseQualifiedIdentifier(ref Parser parser, out immutable(char)[] identifier)
{
    const size_t start = parser.index;

    immutable(char)[] part;
    if (!parseIdentifier(parser, part))
    {
        identifier = null;
        return false;
    }

    while (!parserAtEnd(parser) && parser.input[parser.index] == '.')
    {
        ++parser.index;

        if (!parseIdentifier(parser, part))
        {
            identifier = null;
            return false;
        }
    }

    identifier = parser.input[start .. parser.index];
    return true;
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

    if (!parserAtEnd(parser) && isIdentifierPart(parser.input[parser.index]))
    {
        parser.index = start;
        return false;
    }

    return true;
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

private bool isIdentifierStart(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_';
}

private bool isIdentifierPart(char ch)
{
    return isIdentifierStart(ch) || (ch >= '0' && ch <= '9');
}

private void parserError(ref Parser parser, immutable(char)[] message)
{
    parser.failed = true;
    parser.errorMessage = message;
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
