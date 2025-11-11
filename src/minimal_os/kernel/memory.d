module minimal_os.kernel.memory;

static if (!__traits(compiles, { size_t dummy; }))
{
    alias size_t = typeof(int.sizeof);
}
import minimal_os.console : print, printLine, printCString, printUnsigned, putChar;

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
