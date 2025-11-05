module toolchain_demo.output;

extern(C) @nogc nothrow int printf(const char*, ...);

private enum divider = "--------------------------------------------------";

@nogc nothrow
void logLine(scope const(char)[] text) @system
{
    printf("%.*s\n", cast(int)text.length, text.ptr);
}

@nogc nothrow
void logEmptyLine() @system
{
    printf("\n");
}

@nogc nothrow
void logDivider() @system
{
    logLine(divider);
}

@nogc nothrow
void logStageHeader(scope const(char)[] title) @system
{
    logEmptyLine();
    logDivider();
    printf("Stage: %.*s\n", cast(int)title.length, title.ptr);
    logDivider();
}

@nogc nothrow
void logStatus(
    scope const(char)[] prefix,
    scope const(char)[] name,
    scope const(char)[] suffix,
) @system
{
    printf(
        "%.*s%.*s%.*s\n",
        cast(int)prefix.length,
        prefix.ptr,
        cast(int)name.length,
        name.ptr,
        cast(int)suffix.length,
        suffix.ptr,
    );
}

@nogc nothrow
void logModuleCompilation(scope const(char)[] stage, scope const(char)[] moduleName) @system
{
    printf(
        "[%.*s] Compiling %.*s ... ok\n",
        cast(int)stage.length,
        stage.ptr,
        cast(int)moduleName.length,
        moduleName.ptr,
    );
}

@nogc nothrow
void logTask(scope const(char)[] scopeLabel, scope const(char)[] description) @system
{
    printf(
        "%.*s%.*s\n",
        cast(int)scopeLabel.length,
        scopeLabel.ptr,
        cast(int)description.length,
        description.ptr,
    );
}

@nogc nothrow
void logSummary(scope const(char)[] label, scope const(char)[] value) @system
{
    printf(
        "%.*s%.*s\n",
        cast(int)label.length,
        label.ptr,
        cast(int)value.length,
        value.ptr,
    );
}
